/**
 * The console's backend-for-frontend.
 * ─────────────────────────────────────────────────────────────────────────────
 * The administration console (frontend/, Vue) was written against a Spring
 * BFF in front of Keycloak. This module is that BFF's contract, served by this
 * system instead — same paths, same payloads, same cookies — so the console
 * runs unchanged:
 *
 *   GET  /oauth2/authorization/keycloak   start sign-in (?returnTo=/path)
 *   GET  /login/oauth2/code/keycloak      the sign-in callback
 *   POST /logout                          end the session (_csrf, returnTo)
 *   GET  /api/me, /api/status, /api/tenants/…, /api/admin/…
 *   GET  /ui/…                            the console itself
 *
 * The console signs in exactly as it did with Keycloak: as the confidential
 * client `iam-admin-ui` of realm `platform`, with authorization code + PKCE,
 * except that the realm is this system's own. Tokens never reach the browser.
 * The browser holds an HttpOnly session cookie and an XSRF-TOKEN cookie whose
 * value it echoes in X-XSRF-TOKEN (double submit) on every write.
 *
 * Who the operator is, and what they may do, is decided per request from
 * current data — the platform realm's roles and the `tenants` attribute — not
 * from a token taken at sign-in, and the console session lives only as long
 * as the identity provider session behind it.
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { sha256b64, randomToken, sameSecret, readCookie } = require('../idp/util');
const { buildCatalogue, resolve } = require('../idp/roles');
const { PLATFORM_REALM, CONSOLE_CLIENT_ID } = require('../idp/bootstrap');
const { fail, handle } = require('./http');
const { createTenantApi } = require('./tenant-api');
const { createApplicationsApi } = require('./applications');
const { createTenantRegistry } = require('./tenants');
const { createIdpAdminApi } = require('./idp-admin');

const SESSION_COOKIE = 'IAM_CONSOLE_SESSION';
const LOGIN_COOKIE = 'IAM_CONSOLE_LOGIN';
const CSRF_COOKIE = 'XSRF-TOKEN';
const SESSION_IDLE_SECONDS = 30 * 60;
const SESSION_MAX_SECONDS = 10 * 60 * 60;
const LOGIN_TTL_SECONDS = 10 * 60;
const IDEMPOTENCY_TTL_SECONDS = 24 * 60 * 60;
const UNSAFE = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const HIDDEN_TENANTS = new Set([PLATFORM_REALM, 'master']);

/** A path on this origin to come back to, or null. Never another origin. */
function safeReturnTo(value) {
  if (typeof value !== 'string' || !value.startsWith('/') || value.startsWith('//') || value.startsWith('/\\')) return null;
  if (value.length > 2048 || /[\r\n\t]/.test(value)) return null;
  return value;
}

function createConsoleBff({ idp, log, publicUrl, internalUrl, uiDir, fetchImpl = fetch }) {
  const { store, redis } = { store: idp.store, redis: idp.store.redis };
  const router = express.Router();
  const form = express.urlencoded({ extended: false, limit: '16kb' });
  const secure = publicUrl.startsWith('https:');
  const issuer = idp.issuerFor(PLATFORM_REALM);
  const k = {
    session: (id) => `bff:sess:${sha256b64(id)}`,
    login: (state) => `bff:login:${sha256b64(state)}`,
    logout: (state) => `bff:logout:${sha256b64(state)}`,
    idempotency: (user, key) => `bff:idem:${user}:${sha256b64(key)}`,
  };

  // ── CSRF ──────────────────────────────────────────────────────────────────

  function ensureCsrfCookie(req, res) {
    let token = readCookie(req, CSRF_COOKIE);
    if (!token || !/^[A-Za-z0-9_-]{32,64}$/.test(token)) {
      token = randomToken(32);
      // Readable by the console's script (that is the point of double submit); scoped to this origin.
      res.cookie(CSRF_COOKIE, token, { httpOnly: false, secure, sameSite: 'lax', path: '/' });
    }
    return token;
  }

  /**
   * On /api the token is read from the X-XSRF-TOKEN header and nowhere else: a
   * token in a query or form parameter ends up in logs, Referer and history.
   * The sign-out form (`_csrf`) is the one exception, and it is not the API.
   */
  function csrfValid(req, { allowFormField = false } = {}) {
    const cookie = readCookie(req, CSRF_COOKIE);
    const presented = req.get('X-XSRF-TOKEN') || (allowFormField ? req.body?._csrf : undefined);
    return Boolean(cookie && presented && sameSecret(String(presented), cookie));
  }

  // ── sessions ──────────────────────────────────────────────────────────────

  async function readSession(req) {
    const id = readCookie(req, SESSION_COOKIE);
    if (!id || id.length > 128) return null;
    const raw = await redis.hgetall(k.session(id));
    if (!raw?.userId) return null;
    if (Date.now() - Number(raw.created) > SESSION_MAX_SECONDS * 1000) {
      await redis.del(k.session(id));
      return null;
    }
    return { id, ...raw };
  }

  let catalogueCache = { at: 0, value: null };
  async function platformCatalogue() {
    if (catalogueCache.value && Date.now() - catalogueCache.at < 2000) return catalogueCache.value;
    const [realmRoles, clientRoles, groups] = await Promise.all([
      store.listRealmRoles(PLATFORM_REALM), store.listClientRoles(PLATFORM_REALM), store.listGroups(PLATFORM_REALM),
    ]);
    catalogueCache = { at: Date.now(), value: buildCatalogue({ realmRoles, clientRoles, groups }) };
    return catalogueCache.value;
  }

  async function tenantCatalogue() {
    const realms = await store.listRealms();
    return realms.filter((realm) => !HIDDEN_TENANTS.has(realm.name)).map((realm) => realm.name).sort();
  }

  /**
   * The operator behind a console session, evaluated now. Null when the
   * identity provider session has ended or the account can no longer be used.
   */
  async function principal(req) {
    const session = await readSession(req);
    if (!session) return null;
    const realm = await store.getRealm(PLATFORM_REALM);
    if (!realm) return null;
    const live = await idp.protocol.validSession(realm, session.sid);
    if (!live || live.user.id !== session.userId) {
      await redis.del(k.session(session.id));
      return null;
    }
    // Activity in the console keeps the sign-in alive, as token refreshes did.
    if (Date.now() - Number(session.touched || 0) > 60_000) {
      await idp.sessions.touch(PLATFORM_REALM, realm, live.session);
      await redis.multi().hset(k.session(session.id), 'touched', String(Date.now())).expire(k.session(session.id), SESSION_IDLE_SECONDS).exec();
    }
    const user = live.user;
    const roles = [...resolve(await platformCatalogue(), user).values()]
      .filter(({ ref }) => ref.source === 'realm').map(({ ref }) => ref.name);
    const platformAdmin = roles.includes('platform-admin');
    const tenantAdmin = platformAdmin || roles.includes('tenant-admin');
    const all = await tenantCatalogue();
    const assigned = new Set([...(user.attributes?.tenants || []), ...(user.attributes?.tenant || [])]);
    return {
      id: user.id,
      username: user.username,
      email: user.email || null,
      roles: roles.filter((name) => !name.startsWith('default-roles-') && !['offline_access', 'uma_authorization'].includes(name)).sort(),
      permissions: { platformAdmin, tenantAdmin },
      crossTenant: platformAdmin,
      tenants: tenantAdmin ? (platformAdmin ? all : all.filter((name) => assigned.has(name))) : [],
      session,
    };
  }

  const requireSession = handle(async (req, res, next) => {
    const who = await principal(req);
    if (!who) return fail(res, 401, 'unauthenticated');
    req.principal = who;
    log.setActor({ id: who.id, username: who.username });
    return next();
  });

  const requireCsrf = (req, res, next) => (UNSAFE.has(req.method) && !csrfValid(req) ? fail(res, 403, 'access_denied', { reason: 'csrf' }) : next());

  // ── idempotency ───────────────────────────────────────────────────────────

  /**
   * Every write carries an Idempotency-Key and is performed once:
   *   same key, same request   -> the first outcome is replayed;
   *   same key, other request  -> 409 idempotency_key_reuse;
   *   same key, still running  -> 409 idempotency_in_progress.
   * Keys are scoped per caller and per tenant, so one tenant's key cannot
   * replay into another's request.
   */
  const idempotent = handle(async (req, res, next) => {
    if (!UNSAFE.has(req.method)) return next();
    const key = req.get('Idempotency-Key');
    if (!key) return fail(res, 400, 'idempotency_key_required');
    if (key.length > 128) return fail(res, 400, 'invalid_request');
    const tenant = /^\/tenants\/([^/]+)/.exec(req.path)?.[1] || '-';
    const storeKey = k.idempotency(`${req.principal.id}:${tenant}`, key);
    const fingerprint = sha256b64(`${req.method} ${req.originalUrl} ${JSON.stringify(req.body ?? null)}`);
    const claimed = await redis.set(storeKey, JSON.stringify({ fingerprint, pending: true }), 'EX', 120, 'NX');
    if (!claimed) {
      const previous = JSON.parse((await redis.get(storeKey)) || 'null');
      if (!previous) return fail(res, 409, 'idempotency_in_progress');
      if (previous.fingerprint !== fingerprint) return fail(res, 409, 'idempotency_key_reuse');
      if (previous.pending) return fail(res, 409, 'idempotency_in_progress');
      res.set('Idempotent-Replayed', 'true');
      return previous.body === null ? res.status(previous.status).end() : res.status(previous.status).json(previous.body);
    }
    const json = res.json.bind(res);
    const end = res.end.bind(res);
    let recorded = false;
    const record = (body) => {
      if (recorded) return;
      recorded = true;
      if (res.statusCode >= 500) {
        redis.del(storeKey).catch(() => {});
      } else {
        redis.set(storeKey, JSON.stringify({ fingerprint, status: res.statusCode, body }), 'EX', IDEMPOTENCY_TTL_SECONDS).catch(() => {});
      }
    };
    res.json = (body) => { record(body ?? null); return json(body); };
    res.end = (...args) => { record(null); return end(...args); };
    return next();
  });

  // ── sign-in ───────────────────────────────────────────────────────────────

  router.get('/oauth2/authorization/keycloak', handle(async (req, res) => {
    const registered = await idp.ensureConsoleClient();
    if (!registered) {
      log.warn('bff', "Console sign-in is not possible: client 'iam-admin-ui' does not exist in realm 'platform'");
      return res.status(503).type('text/plain').send('The console is not registered with the identity provider yet.');
    }
    const state = randomToken(24);
    const nonce = randomToken(24);
    const verifier = randomToken(48);
    await redis.set(k.login(state), JSON.stringify({ nonce, verifier, returnTo: safeReturnTo(req.query.returnTo) }), 'EX', LOGIN_TTL_SECONDS);
    res.cookie(LOGIN_COOKIE, state, { httpOnly: true, secure, sameSite: 'lax', path: '/login/oauth2/code/keycloak', maxAge: LOGIN_TTL_SECONDS * 1000 });
    const target = new URL(`${issuer}/protocol/openid-connect/auth`);
    target.search = new URLSearchParams({
      response_type: 'code', client_id: CONSOLE_CLIENT_ID, redirect_uri: registered.redirectUri, scope: 'openid profile email',
      state, nonce, code_challenge: sha256b64(verifier), code_challenge_method: 'S256',
    }).toString();
    res.set('Cache-Control', 'no-store').redirect(302, target.toString());
  }));

  router.get('/login/oauth2/code/keycloak', handle(async (req, res) => {
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const cookieState = readCookie(req, LOGIN_COOKIE);
    res.clearCookie(LOGIN_COOKIE, { httpOnly: true, secure, sameSite: 'lax', path: '/login/oauth2/code/keycloak' });
    const home = '/ui/';
    if (!state || !cookieState || !sameSecret(state, cookieState)) return res.redirect(302, home);
    const pending = JSON.parse((await redis.getdel(k.login(state))) || 'null');
    if (!pending) return res.redirect(302, home);
    if (typeof req.query.code !== 'string') {
      log.audit('bff', `Console sign-in did not complete (${String(req.query.error || 'no code').slice(0, 64)})`);
      return res.redirect(302, pending.returnTo || home);
    }

    const secret = await idp.bootstrap.consoleSecret();
    const response = await fetchImpl(`${internalUrl}/realms/${PLATFORM_REALM}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Authorization: `Basic ${Buffer.from(`${encodeURIComponent(CONSOLE_CLIENT_ID)}:${encodeURIComponent(secret || '')}`).toString('base64')}`,
      },
      body: new URLSearchParams({
        grant_type: 'authorization_code', code: req.query.code, redirect_uri: idp.bootstrap.callback, code_verifier: pending.verifier,
      }),
      redirect: 'error',
    });
    const tokens = await response.json().catch(() => ({}));
    if (!response.ok || !tokens.id_token) {
      log.warn('bff', `Console code exchange failed (${tokens.error || response.status})`);
      return res.status(502).type('text/plain').send('Sign-in could not be completed. Go back to the console and try again.');
    }
    const claims = await idp.keyring.verify(PLATFORM_REALM, tokens.id_token, { issuer, audience: CONSOLE_CLIENT_ID });
    if (!claims || claims.nonce !== pending.nonce || !claims.sid) {
      log.audit('bff', 'Console sign-in refused: the ID token did not verify');
      return res.status(502).type('text/plain').send('Sign-in could not be completed. Go back to the console and try again.');
    }

    const id = randomToken(32);
    await redis.multi()
      .hset(k.session(id), {
        userId: claims.sub, username: claims.preferred_username || '', sid: claims.sid, idToken: tokens.id_token,
        created: String(Date.now()), touched: String(Date.now()),
      })
      .expire(k.session(id), SESSION_IDLE_SECONDS)
      .exec();
    res.cookie(SESSION_COOKIE, id, { httpOnly: true, secure, sameSite: 'lax', path: '/' });
    ensureCsrfCookie(req, res);
    log.audit('bff', `Console session started for '${claims.preferred_username}'`, { userId: claims.sub, sid: claims.sid });
    return res.set('Cache-Control', 'no-store').redirect(302, pending.returnTo || home);
  }));

  // ── sign-out ──────────────────────────────────────────────────────────────

  router.post('/logout', form, handle(async (req, res) => {
    if (!csrfValid(req, { allowFormField: true })) return fail(res, 403, 'access_denied', { reason: 'csrf' });
    const session = await readSession(req);
    const returnTo = safeReturnTo(req.body?.returnTo) || '/ui/';
    res.clearCookie(SESSION_COOKIE, { httpOnly: true, secure, sameSite: 'lax', path: '/' });
    if (!session) return res.redirect(302, returnTo);
    await redis.del(k.session(session.id));
    log.audit('bff', `Console session ended for '${session.username}'`, { userId: session.userId });
    const state = randomToken(24);
    await redis.set(k.logout(state), returnTo, 'EX', LOGIN_TTL_SECONDS);
    const target = new URL(`${issuer}/protocol/openid-connect/logout`);
    target.search = new URLSearchParams({
      id_token_hint: session.idToken, post_logout_redirect_uri: idp.bootstrap.logoutDone, state,
    }).toString();
    return res.redirect(302, target.toString());
  }));

  router.get('/logout/complete', handle(async (req, res) => {
    const state = typeof req.query.state === 'string' ? req.query.state : '';
    const returnTo = state ? safeReturnTo(await redis.getdel(k.logout(state))) : null;
    res.set('Cache-Control', 'no-store').redirect(302, returnTo || '/ui/');
  }));

  // ── the API ───────────────────────────────────────────────────────────────

  const api = express.Router();
  api.use((req, res, next) => { res.set('Cache-Control', 'no-store'); ensureCsrfCookie(req, res); next(); });

  api.get('/me', requireSession, handle(async (req, res) => {
    const { session, ...who } = req.principal;
    // The console shows the standby banner and disables editing from this.
    const current = await idp.mode.get();
    res.json({ ...who, mode: current.mode, readOnly: current.mode === 'standby' });
  }));

  api.get('/status', requireSession, handle(async (req, res) => {
    let redisUp = false;
    try { redisUp = (await redis.ping()) === 'PONG'; } catch { redisUp = false; }
    const health = redisUp ? await idp.operations.syncHealth() : null;
    const keysReady = redisUp && (await Promise.all((await store.listRealmNames()).map((name) => idp.keyring.ready(name)))).every(Boolean);
    const dependencies = [
      { name: 'identity-provider', state: !redisUp ? 'unavailable' : keysReady ? 'operational' : 'degraded' },
      { name: 'session-store', state: redisUp ? 'operational' : 'unavailable' },
      {
        name: 'primary-idp-sync',
        state: !health ? 'unavailable' : !health.syncConfigured || health.mode === 'primary' ? 'not_configured' : health.stale ? 'degraded' : 'operational',
      },
    ];
    const relevant = dependencies.filter((d) => d.state !== 'not_configured');
    const overall = relevant.some((d) => d.state === 'unavailable') ? 'unavailable' : relevant.some((d) => d.state === 'degraded') ? 'degraded' : 'operational';
    res.json({ overall, component: 'iam-bff', mode: health?.mode ?? null, lastSuccessfulSync: health?.lastSuccessfulSync ?? null, dependencies });
  }));

  api.use(requireSession, requireCsrf, express.json({ limit: '256kb' }), idempotent);

  const context = { idp, store, redis, log, fail, tenantCatalogue, hiddenTenants: HIDDEN_TENANTS, fetchImpl };
  api.use(createTenantRegistry(context));
  api.use(createIdpAdminApi(context));
  api.use(createApplicationsApi(context));
  api.use(createTenantApi(context));
  api.use((req, res) => fail(res, 404, 'not_found'));

  router.use('/api', api);

  // ── the console ───────────────────────────────────────────────────────────

  const indexFile = path.join(uiDir, 'index.html');
  const uiCsp = [
    "default-src 'self'", "script-src 'self'", "style-src 'self' 'unsafe-inline'", "img-src 'self' data:",
    "font-src 'self' data:", "connect-src 'self'", "base-uri 'self'", "form-action 'self'", "frame-ancestors 'self'", "object-src 'none'",
  ].join('; ');

  // Express matches '/ui' for '/ui/' too; only the bare path is redirected.
  router.get('/ui', (req, res, next) => (req.originalUrl.split('?')[0] === '/ui' ? res.redirect(301, '/ui/') : next()));
  router.use('/ui', (req, res, next) => { ensureCsrfCookie(req, res); next(); });
  router.use('/ui', express.static(uiDir, {
    index: false,
    setHeaders(res, file) {
      const name = path.basename(file);
      if (['remoteEntry.js', 'autoEntry.js', 'iam-release.json'].includes(name)) res.set('Cache-Control', 'no-cache');
      else if (file.includes(`${path.sep}assets${path.sep}`)) res.set('Cache-Control', 'public, max-age=31536000, immutable');
      res.set('X-Content-Type-Options', 'nosniff');
    },
  }));
  // Every other path under /ui is a route of the single-page app.
  router.use('/ui', (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') return res.status(405).end();
    if (!fs.existsSync(indexFile)) {
      return res.status(503).type('text/plain').send('The console has not been built. Run: npm --prefix frontend ci && npm --prefix frontend run build');
    }
    return res.set({
      'Cache-Control': 'no-cache', 'Content-Security-Policy': uiCsp, 'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin', 'X-Frame-Options': 'SAMEORIGIN',
    }).sendFile(indexFile);
  });

  return { router, principal };
}

module.exports = { createConsoleBff, safeReturnTo };
