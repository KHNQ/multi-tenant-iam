/**
 * OpenID Connect, at Keycloak's paths.
 * ─────────────────────────────────────────────────────────────────────────────
 *   GET      /realms/{realm}                                     realm document
 *   GET      /realms/{realm}/.well-known/openid-configuration   discovery
 *   GET/POST /realms/{realm}/protocol/openid-connect/auth        sign-in (code + PKCE S256)
 *   POST     /realms/{realm}/protocol/openid-connect/token       code, refresh_token, client_credentials
 *   GET      /realms/{realm}/protocol/openid-connect/certs       JWKS (active and passive keys)
 *   GET/POST /realms/{realm}/protocol/openid-connect/userinfo
 *   GET/POST /realms/{realm}/protocol/openid-connect/logout      RP-initiated logout
 *   POST     /realms/{realm}/protocol/openid-connect/revoke      RFC 7009
 *   POST     /realms/{realm}/protocol/openid-connect/token/introspect  RFC 7662, confidential clients
 *
 * Applications that build these URLs themselves (rather than reading
 * discovery) therefore work unchanged; only the host differs from the primary
 * system's. Each realm is its own issuer — `{PUBLIC_URL}/realms/{realm}` — so a
 * token of one tenant is never valid for another.
 *
 * Rules that keep a class of mistake out:
 *   - only response_type=code; PKCE with S256 for every client, confidential
 *     ones included; `plain` is refused;
 *   - redirect_uri and post_logout_redirect_uri match a registered value
 *     exactly (the loopback port aside, RFC 8252 §7.3); until they do, an error
 *     is shown, never redirected;
 *   - a code lives 60 seconds and works once; a second use ends the session
 *     the first one bought;
 *   - refresh tokens rotate, and a retired one used again ends the session;
 *   - refresh is refused once the account is disabled, deleted or re-secured.
 */

const express = require('express');
const crypto = require('crypto');
const {
  sha256b64, sameSecret, redirectUriMatches, clientOrigins, createBlobSigner, readCookie, nowSeconds,
} = require('./util');
const pages = require('./pages');
const { passwordProblem } = require('./password-policy');

const AUTH_REQUEST_TTL_SECONDS = 30 * 60;
const CONTINUATION_TTL_SECONDS = 5 * 60;
const SESSION_COOKIE = 'IDP_SESSION';
const CODE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

// Sign-in guessing: per address, per (account, address), and per account.
const LOGIN_IP_LIMIT = { max: 200, windowSeconds: 60 };
const LOGIN_SOURCE_LIMIT = { max: 5, windowSeconds: 15 * 60 };
const TOKEN_IP_LIMIT = { max: Number.parseInt(process.env.IDP_TOKEN_REQUESTS_PER_MINUTE, 10) || 600, windowSeconds: 60 };

function createProtocol({
  store, keyring, sessions, tokens, credentials, mode, limiter, log, metrics, secret, issuerFor, secureCookies,
  onPasswordReplaced = () => {},
}) {
  const blobs = createBlobSigner(secret);
  const cookieKey = Buffer.from(crypto.hkdfSync('sha256', secret, 'iam-idp', 'session-cookie', 32));
  const router = express.Router({ mergeParams: true });
  const form = express.urlencoded({ extended: false, limit: '32kb' });

  const base = (realm) => `${issuerFor(realm)}/protocol/openid-connect`;
  const cookiePath = (realm) => `/realms/${realm}/`;

  // ── realm resolution ──────────────────────────────────────────────────────

  async function loadRealm(req, res, next) {
    const realm = await store.getRealm(req.params.realm);
    if (!realm || realm.enabled === false) {
      return res.status(404).json({ error: 'Realm does not exist', error_description: 'Realm does not exist' });
    }
    req.realm = realm;
    return next();
  }

  // ── session cookie ────────────────────────────────────────────────────────

  const signSid = (sid) => `${sid}.${crypto.createHmac('sha256', cookieKey).update(sid).digest('base64url')}`;
  function sidFromCookie(req) {
    const value = readCookie(req, SESSION_COOKIE);
    if (!value) return null;
    const [sid, mac] = value.split('.');
    if (!sid || !mac) return null;
    return sameSecret(signSid(sid), value) ? sid : null;
  }
  function setSessionCookie(res, realm, sid) {
    res.cookie(SESSION_COOKIE, signSid(sid), { httpOnly: true, secure: secureCookies, sameSite: 'lax', path: cookiePath(realm) });
  }
  function clearSessionCookie(res, realm) {
    res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure: secureCookies, sameSite: 'lax', path: cookiePath(realm) });
  }

  // ── accounts ──────────────────────────────────────────────────────────────

  /**
   * The account as it may be used right now, or null: it exists, is enabled
   * here and in the primary system, is not a service account, and (when
   * `securityVersion` is given) has not been re-secured since.
   */
  async function usableUser(realmName, userId, securityVersion) {
    const user = await store.getUser(realmName, userId);
    if (!user || user.enabled === false || user.serviceAccountClientId) return null;
    const [local, version] = await Promise.all([store.getUserLocal(realmName, userId), store.getSecurityVersion(realmName, userId)]);
    if (local.locked) return null;
    if (securityVersion !== undefined && version !== securityVersion) return null;
    return { user, securityVersion: version };
  }

  async function validSession(realm, sid) {
    const session = await sessions.get(realm.name, realm, sid);
    if (!session) return null;
    const usable = await usableUser(realm.name, session.userId, session.securityVersion);
    if (!usable) {
      await sessions.end(realm.name, sid);
      return null;
    }
    return { session, user: usable.user };
  }

  /**
   * @returns {Promise<{ user, securityVersion } | { refusal: 'invalid'|'locked'|'disabled' }>}
   */
  async function checkCredentials(realm, username, password, ip) {
    const name = username.toLowerCase();
    const ipSlot = await limiter.take(`idp-login-ip:${realm.name}`, ip, LOGIN_IP_LIMIT);
    const sourceSlot = await limiter.take(`idp-login-src:${realm.name}`, `${name}|${ip}`, LOGIN_SOURCE_LIMIT);
    const accountLimit = { max: Math.max(5, Number(realm.failureFactor) || 30), windowSeconds: Math.max(60, Number(realm.maxFailureWaitSeconds) || 900) };
    const accountSlot = realm.bruteForceProtected === false ? { allowed: true } : await limiter.take(`idp-login-acct:${realm.name}`, name, accountLimit);
    if (!ipSlot.allowed || !sourceSlot.allowed || !accountSlot.allowed) {
      metrics.loginFailures.inc({ realm: realm.name, reason: 'locked' });
      log.audit('idp', `Sign-in to realm '${realm.name}' refused: too many failed attempts`, { realm: realm.name, username: name });
      return { refusal: 'locked' };
    }

    let user = await store.findUserByUsername(realm.name, name);
    if (!user && realm.loginWithEmailAllowed !== false && name.includes('@')) user = await store.findUserByEmail(realm.name, name);
    const valid = await credentials.verify(realm.name, user && !user.serviceAccountClientId ? user.id : null, password);
    if (!valid) {
      metrics.loginFailures.inc({ realm: realm.name, reason: 'invalid' });
      log.audit('idp', `Failed sign-in to realm '${realm.name}'`, { realm: realm.name, username: name });
      return { refusal: 'invalid' };
    }
    const usable = await usableUser(realm.name, user.id);
    if (!usable) {
      metrics.loginFailures.inc({ realm: realm.name, reason: 'disabled' });
      log.audit('idp', `Sign-in to realm '${realm.name}' refused: the account is disabled or locked`, { realm: realm.name, username: user.username, userId: user.id });
      return { refusal: 'invalid' };
    }
    await Promise.all([
      limiter.refund(`idp-login-ip:${realm.name}`, ip),
      limiter.refund(`idp-login-src:${realm.name}`, `${name}|${ip}`),
      realm.bruteForceProtected === false ? null : limiter.refund(`idp-login-acct:${realm.name}`, name),
    ]);
    return usable;
  }

  // ── authorization endpoint ────────────────────────────────────────────────

  function authResponse(res, request, params, locale) {
    if (request.responseMode === 'form_post') {
      return pages.formPostPage(res, { locale, redirectUri: request.redirectUri, params });
    }
    const target = new URL(request.redirectUri);
    const target2 = new URLSearchParams();
    for (const [name, value] of Object.entries(params)) if (value !== undefined && value !== null) target2.set(name, value);
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
    if (request.responseMode === 'fragment') {
      target.hash = target2.toString();
    } else {
      for (const [name, value] of target2) target.searchParams.set(name, value);
    }
    return res.redirect(302, target.toString());
  }

  const authError = (res, request, error, description, locale) => authResponse(res, request, {
    error, error_description: description, state: request.state, iss: issuerFor(request.realm),
  }, locale);

  async function completeSignIn(req, res, { realm, client, request, session, acr, locale }) {
    const code = await sessions.issueCode(realm.name, {
      clientId: client.clientId, redirectUri: request.redirectUri, scope: request.scope, nonce: request.nonce,
      challenge: request.challenge, sid: session.sid, acr,
    });
    return authResponse(res, request, { code, state: request.state, session_state: session.sid, iss: issuerFor(realm.name) }, locale);
  }

  async function authorize(req, res) {
    const realm = req.realm;
    const q = { ...req.query, ...(req.method === 'POST' ? req.body : {}) };
    const one = (name) => (typeof q[name] === 'string' ? q[name] : undefined);
    const locale = pages.localeOf(req);

    const client = await store.getClient(realm.name, one('client_id'));
    if (!client || client.enabled === false || client.bearerOnly) {
      return pages.errorPage(res, 400, locale, 'This application is not registered (unknown or disabled client_id).');
    }
    const redirectUri = one('redirect_uri');
    if (!redirectUriMatches(client.redirectUris || [], redirectUri)) {
      return pages.errorPage(res, 400, locale, 'The redirect_uri of this request is not one the application registered.');
    }
    const responseMode = one('response_mode') || 'query';
    const request = {
      kind: 'authorize', realm: realm.name, clientId: client.clientId, redirectUri, responseMode: ['query', 'form_post', 'fragment'].includes(responseMode) ? responseMode : 'query',
      scope: one('scope') || 'openid', state: one('state'), nonce: one('nonce'), challenge: one('code_challenge'),
      prompt: one('prompt'), maxAge: one('max_age'), loginHint: one('login_hint'),
    };
    if ((request.state && request.state.length > 2048) || (request.nonce && request.nonce.length > 2048)) {
      return authError(res, { ...request, state: undefined }, 'invalid_request', 'state and nonce must be at most 2048 characters', locale);
    }
    if (!['query', 'form_post', 'fragment'].includes(responseMode)) {
      return authError(res, request, 'invalid_request', 'Invalid parameter: response_mode', locale);
    }
    if (one('response_type') !== 'code') {
      return authError(res, request, 'unsupported_response_type', 'Only response_type=code is supported', locale);
    }
    if (client.standardFlowEnabled === false) {
      return authError(res, request, 'unauthorized_client', 'Client is not allowed to initiate browser login', locale);
    }
    if (!one('code_challenge_method') || !one('code_challenge')) {
      return authError(res, request, 'invalid_request', 'Missing parameter: code_challenge_method', locale);
    }
    if (one('code_challenge_method') !== 'S256' || !CODE_CHALLENGE.test(one('code_challenge'))) {
      return authError(res, request, 'invalid_request', 'Invalid parameter: code_challenge_method (only S256 is accepted)', locale);
    }

    // Single sign-on: a live session of this realm signs the user in without a prompt.
    const prompts = String(request.prompt || '').split(' ');
    const sid = sidFromCookie(req);
    const current = sid ? await validSession(realm, sid) : null;
    const maxAge = request.maxAge !== undefined ? Number.parseInt(request.maxAge, 10) : null;
    const fresh = current && (maxAge === null || !Number.isFinite(maxAge) || nowSeconds() - current.session.authTime <= maxAge);
    if (current && fresh && !prompts.includes('login')) {
      await sessions.touch(realm.name, realm, current.session);
      log.audit('idp', `Single sign-on to '${client.clientId}' in realm '${realm.name}'`, { realm: realm.name, clientId: client.clientId, userId: current.user.id });
      return completeSignIn(req, res, { realm, client, request, session: current.session, acr: '0', locale });
    }
    if (prompts.includes('none')) {
      return authError(res, request, 'login_required', 'Login is required', locale);
    }
    return pages.loginPage(res, 200, {
      locale, action: req.originalUrl.split('?')[0], blob: blobs.sign(request, AUTH_REQUEST_TTL_SECONDS),
      clientName: client.name || client.clientId, redirectUri, username: request.loginHint || '',
    });
  }

  async function authorizeSubmit(req, res) {
    const realm = req.realm;
    const f = req.body || {};
    const locale = pages.localeOf(req, f.ui_locales);
    const action = req.originalUrl.split('?')[0];
    const request = blobs.read(f.request, 'authorize');
    if (!request || request.realm !== realm.name) return pages.errorPage(res, 400, locale, pages.t(locale, 'expired'));
    const client = await store.getClient(realm.name, request.clientId);
    if (!client || client.enabled === false || !redirectUriMatches(client.redirectUris || [], request.redirectUri)) {
      return pages.errorPage(res, 400, locale, 'This application is no longer registered.');
    }
    const page = (status, message, username = '') => pages.loginPage(res, status, {
      locale, action, blob: f.request, clientName: client.name || client.clientId, redirectUri: request.redirectUri, message, username,
    });

    if (f.step === 'locale') return page(200);

    if (f.step === 'change') {
      const continuation = blobs.read(f.continuation, 'change');
      if (!continuation || continuation.realm !== realm.name) return pages.errorPage(res, 400, locale, pages.t(locale, 'expired'));
      const again = (message) => pages.changePasswordPage(res, 400, {
        locale, action, blob: f.request, continuation: f.continuation, redirectUri: request.redirectUri, message,
      });
      if (typeof f.new_password !== 'string' || f.new_password !== f.confirm_password) return again(pages.t(locale, 'mismatch'));
      const usable = await usableUser(realm.name, continuation.userId, continuation.securityVersion);
      if (!usable) return pages.errorPage(res, 409, locale, pages.t(locale, 'accountChanged'));
      const weak = passwordProblem(realm.passwordPolicy, f.new_password, usable.user);
      if (weak) return again(`The new password ${weak}.`);
      if (await credentials.verify(realm.name, usable.user.id, f.new_password)) return again('The new password must be different from the current one.');
      await credentials.setPassword(realm.name, usable.user.id, f.new_password);
      const updated = await store.updateUser(realm.name, usable.user.id, (user) => ({
        ...user, requiredActions: (user.requiredActions || []).filter((a) => a !== 'UPDATE_PASSWORD'),
      }));
      const securityVersion = await store.bumpSecurityVersion(realm.name, usable.user.id);
      log.audit('idp', `User '${usable.user.username}' replaced their password while signing in to realm '${realm.name}'`, { realm: realm.name, userId: usable.user.id });
      onPasswordReplaced(realm.name, usable.user);
      return finishLogin(req, res, { realm, client, request, user: updated.user || usable.user, securityVersion, locale });
    }

    if (typeof f.username !== 'string' || typeof f.password !== 'string' || !f.username.trim()
        || f.username.length > 256 || f.password.length > 1024) {
      return page(400, pages.t(locale, 'enterBoth'));
    }
    const username = f.username.trim();
    metrics.loginAttempts.inc({ realm: realm.name });
    const outcome = await checkCredentials(realm, username, f.password, req.ip);
    if (outcome.refusal) {
      return page(outcome.refusal === 'locked' ? 429 : 401, pages.t(locale, outcome.refusal === 'locked' ? 'locked' : 'invalidLogin'), username);
    }
    const { user, securityVersion } = outcome;

    if ((user.requiredActions || []).includes('UPDATE_PASSWORD')) {
      // A synchronised account's password belongs to the primary system; while
      // this one is the standby, changing it here would make the two diverge.
      if (user.source !== 'local' && await mode.isStandby()) {
        log.audit('idp', `Sign-in of '${user.username}' to realm '${realm.name}' held: a password change is required and must be made in the primary system`, { realm: realm.name, userId: user.id });
        return pages.errorPage(res, 403, locale, pages.t(locale, 'standbyChange'));
      }
      const continuation = blobs.sign({ kind: 'change', realm: realm.name, userId: user.id, securityVersion }, CONTINUATION_TTL_SECONDS);
      return pages.changePasswordPage(res, 200, { locale, action, blob: f.request, continuation, redirectUri: request.redirectUri });
    }
    return finishLogin(req, res, { realm, client, request, user, securityVersion, locale });
  }

  async function finishLogin(req, res, { realm, client, request, user, securityVersion, locale }) {
    // The same person signing in again (prompt=login, max_age) re-authenticates
    // within their session, so their other applications stay signed in.
    // Anyone else replaces it: one browser, one account per realm.
    const previousSid = sidFromCookie(req);
    const previous = previousSid ? await sessions.get(realm.name, realm, previousSid) : null;
    let session;
    if (previous && previous.userId === user.id) {
      session = await sessions.reauthenticate(realm.name, realm, previous, { securityVersion, ip: req.ip });
    } else {
      if (previousSid) await sessions.end(realm.name, previousSid);
      session = await sessions.create(realm.name, realm, { user, securityVersion, ip: req.ip, acr: '1' });
    }
    setSessionCookie(res, realm.name, session.sid);
    metrics.logins.inc({ realm: realm.name });
    log.audit('idp', `User '${user.username}' signed in to realm '${realm.name}' for '${client.clientId}'`, {
      realm: realm.name, clientId: client.clientId, userId: user.id, username: user.username, sid: session.sid,
    });
    return completeSignIn(req, res, { realm, client, request, session, acr: '1', locale });
  }

  // ── token endpoint ────────────────────────────────────────────────────────

  const tokenError = (res, status, error, description) => res.status(status)
    .set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' })
    .json({ error, error_description: description });

  /**
   * client_secret_basic, client_secret_post, or a public client naming itself.
   * @returns {Promise<{ client } | { error: [status, code, description] }>}
   */
  async function authenticateClient(req, realm) {
    const f = req.body || {};
    let id = typeof f.client_id === 'string' ? f.client_id : undefined;
    let presented = typeof f.client_secret === 'string' ? f.client_secret : undefined;
    const header = req.get('Authorization') || '';
    if (/^Basic /i.test(header)) {
      const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
      const at = decoded.indexOf(':');
      if (at < 0) return { error: [401, 'invalid_client', 'Malformed client credentials'] };
      const decode = (value) => { try { return decodeURIComponent(value.replace(/\+/g, ' ')); } catch { return value; } };
      const basicId = decode(decoded.slice(0, at));
      if (id !== undefined && id !== basicId) return { error: [400, 'invalid_request', 'client_id does not match the Authorization header'] };
      if (presented !== undefined) return { error: [400, 'invalid_request', 'Use one client authentication method, not two'] };
      id = basicId;
      presented = decode(decoded.slice(at + 1));
    }
    if (!id) return { error: [401, 'invalid_client', 'Missing parameter: client_id'] };
    const client = await store.getClient(realm.name, id);
    if (!client || client.enabled === false) return { error: [401, 'invalid_client', 'Invalid client or Invalid client credentials'] };
    if (client.bearerOnly) return { error: [400, 'unauthorized_client', 'Bearer-only clients are not allowed to request tokens'] };
    if (client.publicClient) return { client, authenticated: false };
    if (!presented || !client.secretHash || !sameSecret(sha256b64(presented), client.secretHash)) {
      log.audit('idp', `Client authentication failed for '${id}' in realm '${realm.name}'`, { realm: realm.name, clientId: id });
      return { error: [401, 'invalid_client', 'Invalid client or Invalid client credentials'] };
    }
    return { client, authenticated: true };
  }

  async function corsFor(req, res, realm, client) {
    const origin = req.get('Origin');
    if (!origin || !client) return;
    const origins = clientOrigins(client);
    if (origins.has(origin) || origins.has('*')) {
      res.set({ 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true', Vary: 'Origin' });
    }
  }

  async function preflight(req, res) {
    const origin = req.get('Origin');
    if (origin) {
      const clients = await store.listClients(req.realm.name);
      if (clients.some((client) => client.enabled !== false && (clientOrigins(client).has(origin) || clientOrigins(client).has('*')))) {
        res.set({
          'Access-Control-Allow-Origin': origin,
          'Access-Control-Allow-Credentials': 'true',
          'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Authorization, Content-Type, DPoP',
          'Access-Control-Max-Age': '3600',
          Vary: 'Origin',
        });
      }
    }
    res.status(204).end();
  }

  function tokenResponse(res, { issued, refresh, session }) {
    return res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' }).json({
      access_token: issued.accessToken,
      expires_in: issued.expiresIn,
      refresh_expires_in: refresh ? refresh.expiresIn : 0,
      ...(refresh ? { refresh_token: refresh.token } : {}),
      token_type: 'Bearer',
      ...(issued.idToken ? { id_token: issued.idToken } : {}),
      'not-before-policy': 0,
      ...(session ? { session_state: session.sid } : {}),
      scope: issued.scope,
    });
  }

  async function token(req, res) {
    const realm = req.realm;
    const f = req.body || {};
    const slot = await limiter.take(`idp-token-ip:${realm.name}`, req.ip, TOKEN_IP_LIMIT);
    if (!slot.allowed) {
      res.set('Retry-After', String(slot.retryAfterSeconds));
      return tokenError(res, 429, 'slow_down', 'Too many requests');
    }
    const auth = await authenticateClient(req, realm);
    if (auth.error) {
      if (auth.error[0] === 401 && /^Basic /i.test(req.get('Authorization') || '')) res.set('WWW-Authenticate', `Basic realm="${realm.name}"`);
      return tokenError(res, ...auth.error);
    }
    const { client } = auth;
    await corsFor(req, res, realm, client);

    switch (f.grant_type) {
      case 'authorization_code': return codeGrant(req, res, realm, client);
      case 'refresh_token': return refreshGrant(req, res, realm, client);
      case 'client_credentials': return clientCredentialsGrant(req, res, realm, client, auth.authenticated);
      case undefined: return tokenError(res, 400, 'invalid_request', 'Missing form parameter: grant_type');
      default: return tokenError(res, 400, 'unsupported_grant_type', `Unsupported grant_type: ${String(f.grant_type).slice(0, 64)}`);
    }
  }

  async function codeGrant(req, res, realm, client) {
    const f = req.body;
    if (typeof f.code !== 'string' || !f.code) return tokenError(res, 400, 'invalid_request', 'Missing parameter: code');
    const taken = await sessions.takeCode(realm.name, f.code);
    if (!taken.grant) {
      if (taken.reusedSid) {
        // The code was used before: whoever presented it either time is not who it was issued for.
        await sessions.end(realm.name, taken.reusedSid);
        log.audit('idp', `An authorization code was used twice in realm '${realm.name}'; the session it had bought was ended`, { realm: realm.name, clientId: client.clientId, sid: taken.reusedSid });
      }
      return tokenError(res, 400, 'invalid_grant', 'Code not valid');
    }
    const grant = taken.grant;
    if (grant.clientId !== client.clientId) return tokenError(res, 400, 'invalid_grant', 'Code was issued to another client');
    if (f.redirect_uri !== grant.redirectUri) return tokenError(res, 400, 'invalid_grant', 'Incorrect redirect_uri');
    if (typeof f.code_verifier !== 'string' || !CODE_VERIFIER.test(f.code_verifier)) {
      return tokenError(res, 400, 'invalid_grant', 'PKCE code verifier not specified or invalid');
    }
    if (!sameSecret(sha256b64(f.code_verifier), grant.challenge)) {
      return tokenError(res, 400, 'invalid_grant', 'PKCE verification failed: Code mismatch');
    }
    const current = await validSession(realm, grant.sid);
    if (!current) return tokenError(res, 400, 'invalid_grant', 'Session not active');

    const issued = await tokens.issue({
      realm: realm.name, client, user: current.user, session: current.session, scope: grant.scope, nonce: grant.nonce, acr: grant.acr,
    });
    await sessions.noteClient(realm.name, current.session, client, grant.scope);
    await sessions.noteCodeUsed(realm.name, taken.hash, grant.sid);
    const refresh = await sessions.issueRefresh(realm.name, realm, current.session, {
      clientId: client.clientId, userId: current.user.id, scope: grant.scope,
    });
    log.audit('idp', `Tokens issued to '${client.clientId}' for '${current.user.username}' in realm '${realm.name}'`, {
      realm: realm.name, clientId: client.clientId, userId: current.user.id, sid: grant.sid,
    });
    return tokenResponse(res, { issued, refresh, session: current.session });
  }

  async function refreshGrant(req, res, realm, client) {
    const f = req.body;
    if (typeof f.refresh_token !== 'string' || !f.refresh_token) return tokenError(res, 400, 'invalid_request', 'Missing parameter: refresh_token');
    const peeked = await sessions.peekRefresh(realm.name, f.refresh_token);
    if (!peeked.data) {
      if (peeked.reusedSid) {
        await sessions.end(realm.name, peeked.reusedSid);
        metrics.refreshes.inc({ realm: realm.name, outcome: 'reuse' });
        log.audit('idp', `A retired refresh token was used again in realm '${realm.name}'; its session was revoked`, {
          realm: realm.name, clientId: client.clientId, sid: peeked.reusedSid,
        });
        return tokenError(res, 400, 'invalid_grant', 'Maximum allowed refresh token reuse exceeded');
      }
      metrics.refreshes.inc({ realm: realm.name, outcome: 'invalid' });
      return tokenError(res, 400, 'invalid_grant', 'Invalid refresh token');
    }
    const data = peeked.data;
    if (data.clientId !== client.clientId) {
      metrics.refreshes.inc({ realm: realm.name, outcome: 'invalid' });
      return tokenError(res, 400, 'invalid_grant', 'Invalid refresh token. Token client and authorized client don\'t match');
    }
    const current = await validSession(realm, data.sid);
    if (!current) {
      metrics.refreshes.inc({ realm: realm.name, outcome: 'session' });
      return tokenError(res, 400, 'invalid_grant', 'Session not active');
    }
    const scope = typeof f.scope === 'string' && f.scope ? narrowScope(data.scope, f.scope) : data.scope;
    if (scope === null) return tokenError(res, 400, 'invalid_scope', 'Invalid scopes: the refresh may only narrow the original scope');

    const rotated = await sessions.rotateRefresh(realm.name, realm, current.session, peeked.hash, {
      clientId: client.clientId, userId: current.user.id, scope: data.scope,
    });
    if (!rotated) {
      await sessions.end(realm.name, data.sid);
      metrics.refreshes.inc({ realm: realm.name, outcome: 'reuse' });
      log.audit('idp', `A refresh token was used twice at once in realm '${realm.name}'; its session was revoked`, { realm: realm.name, clientId: client.clientId, sid: data.sid });
      return tokenError(res, 400, 'invalid_grant', 'Maximum allowed refresh token reuse exceeded');
    }
    await sessions.touch(realm.name, realm, current.session);
    const issued = await tokens.issue({ realm: realm.name, client, user: current.user, session: current.session, scope });
    await sessions.noteClient(realm.name, current.session, client, data.scope);
    metrics.refreshes.inc({ realm: realm.name, outcome: 'ok' });
    log.audit('idp', `Tokens refreshed for '${client.clientId}' in realm '${realm.name}'`, { realm: realm.name, clientId: client.clientId, userId: current.user.id, sid: data.sid });
    return tokenResponse(res, { issued, refresh: rotated, session: current.session });
  }

  function narrowScope(original, asked) {
    const allowed = new Set(String(original).split(/\s+/));
    const wanted = String(asked).split(/\s+/).filter(Boolean);
    return wanted.every((s) => allowed.has(s)) ? wanted.join(' ') : null;
  }

  async function clientCredentialsGrant(req, res, realm, client, authenticated) {
    if (!authenticated || client.publicClient) return tokenError(res, 401, 'unauthorized_client', 'Public client not allowed to retrieve service account');
    if (!client.serviceAccountsEnabled || !client.serviceAccountUserId) {
      return tokenError(res, 400, 'unauthorized_client', 'Client not enabled to retrieve service account');
    }
    const user = await store.getUser(realm.name, client.serviceAccountUserId);
    if (!user || user.enabled === false) return tokenError(res, 400, 'invalid_grant', 'The service account is disabled');
    const scope = typeof req.body.scope === 'string' && req.body.scope ? req.body.scope : '';
    const issued = await tokens.issue({
      realm: realm.name, client, user, session: null, scope, acr: '1',
      serviceAccount: { clientHost: req.ip, clientAddress: req.ip },
    });
    log.audit('idp', `Service account token issued to '${client.clientId}' in realm '${realm.name}'`, { realm: realm.name, clientId: client.clientId });
    return tokenResponse(res, { issued, refresh: null, session: null });
  }

  // ── userinfo ──────────────────────────────────────────────────────────────

  /** A bearer access token of this realm that is still good: signature, issuer, expiry, session, denylist. */
  async function activeAccessToken(realm, tokenValue) {
    const claims = await keyring.verify(realm.name, tokenValue, { issuer: issuerFor(realm.name) });
    if (!claims || claims.typ !== 'Bearer') return null;
    if (await sessions.accessTokenRevoked(realm.name, claims.jti)) return null;
    if (claims.sid) {
      const current = await validSession(realm, claims.sid);
      if (!current || current.user.id !== claims.sub) return null;
      return { claims, user: current.user, session: current.session };
    }
    const user = await store.getUser(realm.name, claims.sub);
    if (!user || user.enabled === false) return null;
    return { claims, user, session: null };
  }

  async function userinfo(req, res) {
    const realm = req.realm;
    const header = req.get('Authorization') || '';
    const value = /^Bearer /i.test(header) ? header.slice(7).trim() : (typeof req.body?.access_token === 'string' ? req.body.access_token : null);
    const fail = (description) => res.status(401)
      .set('WWW-Authenticate', `Bearer realm="${realm.name}", error="invalid_token", error_description="${description}"`)
      .json({ error: 'invalid_token', error_description: description });
    if (!value) return fail('Token not provided');
    const active = await activeAccessToken(realm, value);
    if (!active) return fail('Token verification failed');
    const client = await store.getClient(realm.name, active.claims.azp);
    if (!client || client.enabled === false) return fail('Client not found');
    await corsFor(req, res, realm, client);
    res.set('Cache-Control', 'no-store');
    return res.json(await tokens.userInfo({ realm: realm.name, client, user: active.user, session: active.session, scope: active.claims.scope }));
  }

  // ── introspection and revocation ──────────────────────────────────────────

  async function introspect(req, res) {
    const realm = req.realm;
    const auth = await authenticateClient(req, realm);
    if (auth.error) return tokenError(res, ...auth.error);
    if (!auth.authenticated) return tokenError(res, 403, 'invalid_request', 'Client not allowed.');
    const tokenValue = req.body?.token;
    res.set('Cache-Control', 'no-store');
    if (typeof tokenValue !== 'string' || !tokenValue) return res.json({ active: false });
    const active = await activeAccessToken(realm, tokenValue);
    if (active) {
      return res.json({ ...active.claims, active: true, client_id: active.claims.azp, username: active.claims.preferred_username, token_type: 'Bearer' });
    }
    const refresh = await sessions.peekRefresh(realm.name, tokenValue);
    if (refresh.data && await validSession(realm, refresh.data.sid)) {
      return res.json({ active: true, token_type: 'Refresh', client_id: refresh.data.clientId, sub: refresh.data.userId, sid: refresh.data.sid, scope: refresh.data.scope });
    }
    return res.json({ active: false });
  }

  async function revoke(req, res) {
    const realm = req.realm;
    const auth = await authenticateClient(req, realm);
    if (auth.error) return tokenError(res, ...auth.error);
    await corsFor(req, res, realm, auth.client);
    const tokenValue = req.body?.token;
    if (typeof tokenValue !== 'string' || !tokenValue) return tokenError(res, 400, 'invalid_request', 'Missing token parameter');
    const refresh = await sessions.peekRefresh(realm.name, tokenValue);
    if (refresh.data) {
      if (refresh.data.clientId !== auth.client.clientId) return tokenError(res, 400, 'unauthorized_client', 'Unmatching clients');
      await sessions.revokeRefresh(realm.name, tokenValue);
      log.audit('idp', `Refresh token revoked by '${auth.client.clientId}' in realm '${realm.name}'`, { realm: realm.name, clientId: auth.client.clientId, sid: refresh.data.sid });
      return res.status(200).end();
    }
    const claims = await keyring.verify(realm.name, tokenValue, { issuer: issuerFor(realm.name) });
    if (claims?.jti) {
      if (claims.azp !== auth.client.clientId) return tokenError(res, 400, 'unauthorized_client', 'Unmatching clients');
      await sessions.revokeAccessToken(realm.name, claims.jti, claims.exp);
      log.audit('idp', `Access token revoked by '${auth.client.clientId}' in realm '${realm.name}'`, { realm: realm.name, clientId: auth.client.clientId });
    }
    return res.status(200).end();
  }

  // ── logout ────────────────────────────────────────────────────────────────

  function postLogoutAllowed(client, uri) {
    const registered = client.postLogoutRedirectUris || [];
    const list = registered.includes('+') ? [...registered.filter((u) => u !== '+'), ...(client.redirectUris || [])] : registered;
    return redirectUriMatches(list, uri);
  }

  async function logout(req, res) {
    const realm = req.realm;
    const params = { ...req.query, ...(req.method === 'POST' ? req.body : {}) };
    const one = (name) => (typeof params[name] === 'string' && params[name] ? params[name] : undefined);
    const locale = pages.localeOf(req, one('ui_locales'));

    // The confirmation form posted back.
    if (one('confirmation')) {
      const confirmed = blobs.read(one('confirmation'), 'logout');
      if (!confirmed || confirmed.realm !== realm.name) return pages.errorPage(res, 400, locale, pages.t(locale, 'expired'));
      return performLogout(req, res, realm, confirmed, locale);
    }

    let hint = null;
    if (one('id_token_hint')) {
      hint = await keyring.verify(realm.name, one('id_token_hint'), { issuer: issuerFor(realm.name), ignoreExpiration: true });
      if (!hint) return pages.errorPage(res, 400, locale, 'Invalid parameter: id_token_hint');
    }
    const clientId = one('client_id') || hint?.azp;
    if (hint && one('client_id') && hint.azp !== one('client_id')) {
      return pages.errorPage(res, 400, locale, 'Parameter client_id differs from the authorized party of id_token_hint');
    }
    const client = clientId ? await store.getClient(realm.name, clientId) : null;
    if (clientId && !client) return pages.errorPage(res, 400, locale, 'Invalid parameter: client_id');
    const redirect = one('post_logout_redirect_uri');
    if (redirect) {
      if (!client) return pages.errorPage(res, 400, locale, 'Missing parameters: id_token_hint or client_id');
      if (!postLogoutAllowed(client, redirect)) return pages.errorPage(res, 400, locale, 'Invalid redirect uri');
    }
    const plan = {
      kind: 'logout', realm: realm.name, sid: hint?.sid || sidFromCookie(req) || null,
      redirect: redirect || null, state: one('state') || null, clientId: client?.clientId || null,
    };
    // Without proof the request comes from the application (an ID token), ask first:
    // anything on the web could otherwise sign the user out by linking here.
    if (!hint && plan.sid) {
      return pages.confirmLogoutPage(res, {
        locale, action: req.originalUrl.split('?')[0], blob: blobs.sign(plan, 10 * 60),
        clientName: client?.name || client?.clientId || realm.displayName || realm.name, redirectUri: redirect,
      });
    }
    return performLogout(req, res, realm, plan, locale);
  }

  async function performLogout(req, res, realm, plan, locale) {
    const sids = new Set([plan.sid, sidFromCookie(req)].filter(Boolean));
    for (const sid of sids) {
      const ended = await sessions.end(realm.name, sid);
      if (ended) {
        metrics.logouts.inc({ realm: realm.name });
        log.audit('idp', `Session ended by logout in realm '${realm.name}'`, { realm: realm.name, sid, clientId: plan.clientId });
      }
    }
    clearSessionCookie(res, realm.name);
    if (plan.redirect) {
      const target = new URL(plan.redirect);
      if (plan.state) target.searchParams.set('state', plan.state);
      return res.set('Cache-Control', 'no-store').redirect(302, target.toString());
    }
    return pages.loggedOutPage(res, locale);
  }

  // ── documents ─────────────────────────────────────────────────────────────

  function discovery(req, res) {
    const realm = req.realm.name;
    const issuer = issuerFor(realm);
    res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=60' }).json({
      issuer,
      authorization_endpoint: `${base(realm)}/auth`,
      token_endpoint: `${base(realm)}/token`,
      introspection_endpoint: `${base(realm)}/token/introspect`,
      userinfo_endpoint: `${base(realm)}/userinfo`,
      end_session_endpoint: `${base(realm)}/logout`,
      jwks_uri: `${base(realm)}/certs`,
      revocation_endpoint: `${base(realm)}/revoke`,
      response_types_supported: ['code'],
      response_modes_supported: ['query', 'fragment', 'form_post'],
      grant_types_supported: ['authorization_code', 'refresh_token', 'client_credentials'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      introspection_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
      revocation_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      id_token_signing_alg_values_supported: ['RS256'],
      userinfo_signing_alg_values_supported: ['none'],
      subject_types_supported: ['public'],
      scopes_supported: ['openid', 'profile', 'email', 'roles', 'web-origins', 'acr', 'basic', 'offline_access'],
      claims_supported: ['sub', 'iss', 'aud', 'azp', 'exp', 'iat', 'auth_time', 'nonce', 'acr', 'sid', 'preferred_username', 'email', 'email_verified',
        'name', 'given_name', 'family_name', 'realm_access', 'resource_access', 'tenant', 'tenants', 'md_roles'],
      claims_parameter_supported: false,
      request_parameter_supported: false,
      request_uri_parameter_supported: false,
      frontchannel_logout_supported: false,
      backchannel_logout_supported: false,
      prompt_values_supported: ['none', 'login'],
    });
  }

  async function certs(req, res) {
    res.set({ 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'public, max-age=60' }).json(await keyring.jwks(req.realm.name));
  }

  async function realmDocument(req, res) {
    const realm = req.realm.name;
    res.set('Access-Control-Allow-Origin', '*').json({
      realm,
      public_key: await keyring.publicKeyText(realm),
      'token-service': base(realm),
      'account-service': `${issuerFor(realm)}/account`,
      'tokens-not-before': 0,
    });
  }

  // ── routes ────────────────────────────────────────────────────────────────

  const oidc = '/realms/:realm/protocol/openid-connect';
  router.get('/realms/:realm', loadRealm, realmDocument);
  router.get('/realms/:realm/.well-known/openid-configuration', loadRealm, discovery);
  router.get(`${oidc}/certs`, loadRealm, certs);
  router.get(`${oidc}/auth`, loadRealm, authorize);
  router.post(`${oidc}/auth`, loadRealm, form, (req, res) => (req.body?.request ? authorizeSubmit(req, res) : authorize(req, res)));
  router.options(`${oidc}/token`, loadRealm, preflight);
  router.post(`${oidc}/token`, loadRealm, form, token);
  router.options(`${oidc}/token/introspect`, loadRealm, preflight);
  router.post(`${oidc}/token/introspect`, loadRealm, form, introspect);
  router.options(`${oidc}/userinfo`, loadRealm, preflight);
  router.get(`${oidc}/userinfo`, loadRealm, userinfo);
  router.post(`${oidc}/userinfo`, loadRealm, form, userinfo);
  router.options(`${oidc}/revoke`, loadRealm, preflight);
  router.post(`${oidc}/revoke`, loadRealm, form, revoke);
  router.get(`${oidc}/logout`, loadRealm, logout);
  router.post(`${oidc}/logout`, loadRealm, form, logout);

  return { router, activeAccessToken, validSession, sidFromCookie };
}

module.exports = { createProtocol, SESSION_COOKIE };
