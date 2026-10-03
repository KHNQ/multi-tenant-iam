/**
 * OpenID Connect provider — Authorization Code flow with PKCE.
 * ─────────────────────────────────────────────────────────────────────────────
 * This gateway holds the accounts, so it is the identity provider: an
 * application that wants to know who someone is sends them here, and gets
 * back a signed statement of who signed in. The application never sees a
 * password.
 *
 *   1. The app sends the browser to GET /oauth/authorize with its client_id,
 *      a redirect_uri it registered, and a PKCE code_challenge — the SHA-256
 *      of a secret (the code_verifier) it has just made up and kept.
 *   2. The user signs in ON THIS ORIGIN, on a page this gateway renders.
 *   3. The browser is sent back to the redirect_uri with a one-time code.
 *   4. The app POSTs the code and the code_verifier to /oauth/token and
 *      receives an access token and an ID token.
 *
 * PKCE is what makes step 4 safe without a client secret: a code that leaks
 * on its way through the browser (history, a log, a malicious app registered
 * for the same URL scheme) is useless to whoever has it, because they do not
 * have the verifier. It is required here, with S256, for every client.
 *
 * Deliberate limits, each of which keeps a class of mistake out:
 *   - redirect URIs are matched exactly, never by prefix or pattern;
 *   - the code lives for 60 seconds, is stored only as a hash, and works
 *     once — a second use is refused and revokes the token the first use got;
 *   - there is no implicit flow, no password grant, and no `plain` challenge;
 *   - ID tokens are signed with an RSA key (RS256) whose public half is
 *     published at /oauth/jwks. The private half is generated once and kept
 *     in Redis encrypted under a key derived from JWT_SECRET, so every
 *     gateway instance signs with the same key and a Redis dump does not
 *     contain a usable one.
 *
 * The access token is the gateway's ordinary session token, so everything
 * else about a session — suspension, revocation, budgets — applies unchanged.
 */

const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const CODE_TTL_SECONDS = 60;
const ID_TOKEN_TTL_SECONDS = 600;
const ACCESS_TOKEN_TTL_SECONDS = 24 * 60 * 60;
const AUTH_REQUEST_TTL_SECONDS = 10 * 60;   // how long a login page stays submittable
const CONTINUATION_TTL_SECONDS = 5 * 60;    // how long "now choose a new password" stays open

const SIGNING_KEY = 'oidc:signing-key';
const CLIENTS_INDEX = 'oidc:clients';
const clientKey = (id) => `oidc:client:${id}`;
const codeKey = (hash) => `oidc:code:${hash}`;
const usedCodeKey = (hash) => `oidc:code-used:${hash}`;

/** The console that ships with the gateway is a client like any other. */
const CONSOLE_CLIENT_ID = 'iam-console';

const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
const sha256 = (value) => crypto.createHash('sha256').update(value).digest();
const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

// RFC 7636 §4.1: 43–128 characters from the unreserved set.
const CODE_VERIFIER = /^[A-Za-z0-9\-._~]{43,128}$/;
// base64url of a SHA-256 is exactly 43 characters.
const CODE_CHALLENGE = /^[A-Za-z0-9_-]{43}$/;

const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

/**
 * A redirect URI an application may register: https anywhere, or http on the
 * loopback interface (a developer's machine, or a native app's local
 * listener). Never a fragment, never credentials.
 * @returns {string|null} what is wrong with it
 */
function redirectUriProblem(value) {
  let url;
  try { url = new URL(value); } catch { return 'is not a valid URL'; }
  if (url.hash) return 'must not contain a fragment';
  if (url.username || url.password) return 'must not contain credentials';
  if (url.protocol === 'https:') return null;
  const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol === 'http:' && loopback) return null;
  return 'must be https (plain http is accepted for localhost only)';
}

/**
 * @param {object} deps
 * @param {import('ioredis').Redis} deps.redis
 * @param {object} deps.log
 * @param {string} deps.issuer          the gateway's public URL
 * @param {string} deps.secret          JWT_SECRET, from which storage and form keys are derived
 * @param {Function} deps.checkCredentials  (username, password, ip) -> { account } | { refusal }
 * @param {Function} deps.issueAccessToken  (account id) -> Promise<{ token, jti, exp, username } | null>
 * @param {Function} deps.revokeAccessToken ({ jti, exp }) -> Promise<void>
 * @param {Function} deps.replaceTemporaryPassword (username, newPassword) -> Promise<string|null> problem
 * @param {Function} deps.passwordProblem   (password) -> string|null
 */
function createOidcProvider({
  redis, log, issuer, secret,
  checkCredentials, issueAccessToken, revokeAccessToken, replaceTemporaryPassword, passwordProblem,
}) {
  const derive = (purpose) => Buffer.from(crypto.hkdfSync('sha256', secret, 'iam-gateway', purpose, 32));
  const storageKey = derive('oidc-signing-key-at-rest');
  const formKey = derive('oidc-signed-forms');

  redis.defineCommand('oidcTakeOnce', {
    numberOfKeys: 1,
    lua: `
      local value = redis.call('GET', KEYS[1])
      if value then redis.call('DEL', KEYS[1]) end
      return value
    `,
  });

  // ── signing key ──────────────────────────────────────────────────────────

  let signing = null; // { kid, privateKey, jwk }

  function seal(plaintext) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', storageKey, iv);
    const data = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    return { iv: b64url(iv), tag: b64url(cipher.getAuthTag()), data: b64url(data) };
  }

  function unseal({ iv, tag, data }) {
    const decipher = crypto.createDecipheriv('aes-256-gcm', storageKey, Buffer.from(iv, 'base64url'));
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([decipher.update(Buffer.from(data, 'base64url')), decipher.final()]).toString('utf8');
  }

  function generateKey() {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' });
    // RFC 7638 thumbprint: the key's own fingerprint is its id.
    const kid = b64url(sha256(JSON.stringify({ e: jwk.e, kty: jwk.kty, n: jwk.n })));
    return { kid, jwk, sealed: seal(privateKey.export({ type: 'pkcs8', format: 'pem' })) };
  }

  /**
   * Loads the shared signing key, creating it if this is the first gateway to
   * boot. SET NX then read back, so instances starting together agree on one.
   */
  async function init() {
    for (let attempt = 0; attempt < 2; attempt++) {
      await redis.set(SIGNING_KEY, JSON.stringify(generateKey()), 'NX');
      const stored = JSON.parse(await redis.get(SIGNING_KEY));
      try {
        signing = { kid: stored.kid, jwk: stored.jwk, privateKey: unseal(stored.sealed) };
        return;
      } catch {
        // Sealed under a different JWT_SECRET: the key cannot be recovered,
        // and nothing signed with it will verify again. Replace it.
        log.warn('oidc', 'The stored OIDC signing key could not be decrypted (JWT_SECRET changed?) — generating a new one');
        await redis.del(SIGNING_KEY);
      }
    }
    throw new Error('Could not establish an OIDC signing key');
  }

  // ── signed, expiring blobs (what a form carries between two requests) ────

  function signBlob(payload, ttlSeconds) {
    const body = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
    return `${body}.${b64url(crypto.createHmac('sha256', formKey).update(body).digest())}`;
  }

  function readBlob(blob, kind) {
    if (typeof blob !== 'string') return null;
    const [body, mac] = blob.split('.');
    if (!body || !mac) return null;
    const expected = crypto.createHmac('sha256', formKey).update(body).digest();
    const given = Buffer.from(mac, 'base64url');
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
    try {
      const payload = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
      return payload.kind === kind && payload.exp > Date.now() / 1000 ? payload : null;
    } catch {
      return null;
    }
  }

  // ── clients ──────────────────────────────────────────────────────────────

  const consoleClient = {
    clientId: CONSOLE_CLIENT_ID,
    name: 'IAM Console',
    redirectUris: [`${issuer}/console`],
    builtIn: true,
  };

  async function getClient(clientId) {
    if (clientId === CONSOLE_CLIENT_ID) return consoleClient;
    if (typeof clientId !== 'string') return null;
    const stored = await redis.hgetall(clientKey(clientId));
    if (!stored?.clientId) return null;
    return { clientId: stored.clientId, name: stored.name, redirectUris: JSON.parse(stored.redirectUris), createdAt: stored.createdAt };
  }

  async function listClients() {
    const ids = await redis.smembers(CLIENTS_INDEX);
    const stored = (await Promise.all(ids.map(getClient))).filter(Boolean);
    return [consoleClient, ...stored.sort((a, b) => a.name.localeCompare(b.name))];
  }

  async function createClient({ name, redirectUris }) {
    const clientId = `app-${randomToken(12)}`;
    await redis.hset(clientKey(clientId), {
      clientId, name, redirectUris: JSON.stringify(redirectUris), createdAt: new Date().toISOString(),
    });
    await redis.sadd(CLIENTS_INDEX, clientId);
    return getClient(clientId);
  }

  async function deleteClient(clientId) {
    const removed = await redis.del(clientKey(clientId));
    await redis.srem(CLIENTS_INDEX, clientId);
    return removed === 1;
  }

  /** Origins that may call the token and userinfo endpoints from a browser. */
  async function isClientOrigin(origin) {
    return (await listClients()).some((client) => client.redirectUris.some((uri) => new URL(uri).origin === origin));
  }

  // ── pages ────────────────────────────────────────────────────────────────

  function sendPage(res, status, title, body, { formActions = [] } = {}) {
    res.status(status).set({
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
      'X-Content-Type-Options': 'nosniff',
      // No script at all. The form may post back here, and the browser must be
      // allowed to follow the redirect that answers it to the client's origin.
      'Content-Security-Policy': "default-src 'none'; style-src 'self'; base-uri 'none'; frame-ancestors 'none'; "
        + `form-action 'self' ${formActions.join(' ')}`.trim(),
    }).send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="/assets/theme.css">
</head>
<body>
<div class="topbar"><div class="brand"><div class="mark">IAM</div><h1>Sign in</h1></div></div>
<div class="card auth">
${body}
</div>
</body>
</html>`);
  }

  const errorPage = (res, status, message) => sendPage(res, status, 'Cannot sign in',
    `<h2>Cannot sign in</h2><p class="muted">${escapeHtml(message)}</p>`);

  // `request` is the validated authorization request; `blob` is the same
  // thing signed, which the form carries back.
  function loginPage(res, status, { request, blob, client }, message = '') {
    sendPage(res, status, 'Sign in', `
  <h2>Sign in</h2>
  <p class="muted">to continue to <strong>${escapeHtml(client.name)}</strong></p>
  ${message ? `<p class="banner err" role="alert">${escapeHtml(message)}</p>` : ''}
  <form method="post" action="/oauth/authorize">
    <input type="hidden" name="request" value="${escapeHtml(blob)}">
    <input type="hidden" name="step" value="login">
    <input name="username" placeholder="username" autocomplete="username" required autofocus>
    <input name="password" placeholder="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in</button>
  </form>
  <p class="muted"><a href="${escapeHtml(issuer)}/console#forgot">Forgot your password?</a></p>`,
    { formActions: [new URL(request.redirectUri).origin] });
  }

  function changePasswordPage(res, status, { request, blob }, continuation, message = '') {
    sendPage(res, status, 'Choose a new password', `
  <h2>Choose a new password</h2>
  <p class="muted">This account was given a temporary password. It has to be replaced before the account can be used.</p>
  ${message ? `<p class="banner err" role="alert">${escapeHtml(message)}</p>` : ''}
  <form method="post" action="/oauth/authorize">
    <input type="hidden" name="request" value="${escapeHtml(blob)}">
    <input type="hidden" name="continuation" value="${escapeHtml(continuation)}">
    <input type="hidden" name="step" value="change">
    <input name="new_password" placeholder="new password" type="password" autocomplete="new-password" required autofocus>
    <input name="confirm_password" placeholder="repeat new password" type="password" autocomplete="new-password" required>
    <button type="submit">Set password and continue</button>
  </form>`,
    { formActions: [new URL(request.redirectUri).origin] });
  }

  // ── /oauth/authorize ─────────────────────────────────────────────────────

  /** Sends the browser back to the client with an OAuth error (RFC 6749 §4.1.2.1). */
  function redirectError(res, redirectUri, state, error, description) {
    const target = new URL(redirectUri);
    target.searchParams.set('error', error);
    target.searchParams.set('error_description', description);
    if (state) target.searchParams.set('state', state);
    res.set('Cache-Control', 'no-store').redirect(303, target.toString());
  }

  /** GET /oauth/authorize — validates the request and shows the sign-in page. */
  async function authorize(req, res) {
    const q = req.query;
    const one = (name) => (typeof q[name] === 'string' ? q[name] : undefined);

    // Until the client and its redirect URI are known to be genuine, nothing
    // is sent anywhere: an error here is shown, not redirected.
    const client = await getClient(one('client_id'));
    if (!client) return errorPage(res, 400, 'This application is not registered with the gateway (unknown client_id).');
    const redirectUri = one('redirect_uri');
    if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
      return errorPage(res, 400, 'The redirect_uri in this request is not one the application registered.');
    }

    const state = one('state');
    const nonce = one('nonce');
    const scope = one('scope') || '';
    if ((state && state.length > 512) || (nonce && nonce.length > 512)) {
      return redirectError(res, redirectUri, undefined, 'invalid_request', 'state and nonce must be at most 512 characters');
    }
    if (one('response_type') !== 'code') {
      return redirectError(res, redirectUri, state, 'unsupported_response_type', "Only response_type=code is supported");
    }
    if (one('response_mode') && one('response_mode') !== 'query') {
      return redirectError(res, redirectUri, state, 'invalid_request', 'Only response_mode=query is supported');
    }
    if (!scope.split(' ').includes('openid')) {
      return redirectError(res, redirectUri, state, 'invalid_scope', "The scope must include 'openid'");
    }
    if (one('code_challenge_method') !== 'S256' || !CODE_CHALLENGE.test(one('code_challenge') || '')) {
      return redirectError(res, redirectUri, state, 'invalid_request',
        'PKCE is required: send code_challenge (base64url SHA-256 of the code_verifier) with code_challenge_method=S256');
    }
    // There is no session cookie here to sign anyone in silently with.
    if (one('prompt') === 'none') {
      return redirectError(res, redirectUri, state, 'login_required', 'The user has to sign in');
    }

    const request = {
      kind: 'authorize', clientId: client.clientId, redirectUri, scope, state, nonce, challenge: one('code_challenge'),
    };
    return loginPage(res, 200, { request, blob: signBlob(request, AUTH_REQUEST_TTL_SECONDS), client });
  }

  async function issueCode(res, request, userId) {
    const code = randomToken();
    await redis.set(codeKey(b64url(sha256(code))), JSON.stringify({
      clientId: request.clientId, redirectUri: request.redirectUri, scope: request.scope,
      nonce: request.nonce, challenge: request.challenge, userId, authTime: Math.floor(Date.now() / 1000),
    }), 'EX', CODE_TTL_SECONDS);

    const target = new URL(request.redirectUri);
    target.searchParams.set('code', code);
    if (request.state) target.searchParams.set('state', request.state);
    res.set({ 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' }).redirect(303, target.toString());
  }

  /** POST /oauth/authorize — the sign-in form, and the forced password change after it. */
  async function authorizeSubmit(req, res) {
    const form = req.body || {};
    const request = readBlob(form.request, 'authorize');
    if (!request) return errorPage(res, 400, 'This sign-in page has expired. Go back to the application and start again.');
    const client = await getClient(request.clientId);
    if (!client) return errorPage(res, 400, 'This application is no longer registered with the gateway.');

    if (form.step === 'change') {
      const continuation = readBlob(form.continuation, 'change');
      if (!continuation) return errorPage(res, 400, 'This page has expired. Go back to the application and sign in again.');

      const again = (message) => changePasswordPage(res, 400, { request, blob: form.request }, form.continuation, message);
      if (typeof form.new_password !== 'string' || form.new_password !== form.confirm_password) {
        return again('The two passwords do not match.');
      }
      const weak = passwordProblem(form.new_password);
      if (weak) return again(`The new password ${weak}.`);
      const problem = await replaceTemporaryPassword(continuation.username, form.new_password);
      if (problem) return again(problem);
      return issueCode(res, request, continuation.userId);
    }

    if (typeof form.username !== 'string' || typeof form.password !== 'string'
        || !form.username.trim() || form.username.length > 128 || form.password.length > 1024) {
      return loginPage(res, 400, { request, blob: form.request, client }, 'Enter your username and password.');
    }
    const { account, refusal } = await checkCredentials(form.username.trim(), form.password, req.ip);
    if (refusal) return loginPage(res, refusal.status, { request, blob: form.request, client }, refusal.error);

    if (account.mustChangePassword === '1') {
      const continuation = signBlob({ kind: 'change', userId: account.id, username: account.username }, CONTINUATION_TTL_SECONDS);
      return changePasswordPage(res, 200, { request, blob: form.request }, continuation);
    }
    return issueCode(res, request, account.id);
  }

  // ── /oauth/token ─────────────────────────────────────────────────────────

  const tokenError = (res, error, description, status = 400) => res.status(status)
    .set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' })
    .json({ error, error_description: description });

  /** POST /oauth/token — trades a code and its verifier for tokens. */
  async function token(req, res) {
    const form = req.body || {};
    if (form.grant_type !== 'authorization_code') {
      return tokenError(res, 'unsupported_grant_type', 'Only grant_type=authorization_code is supported');
    }
    for (const field of ['code', 'redirect_uri', 'client_id', 'code_verifier']) {
      if (typeof form[field] !== 'string' || !form[field]) return tokenError(res, 'invalid_request', `${field} is required`);
    }
    if (!CODE_VERIFIER.test(form.code_verifier)) {
      return tokenError(res, 'invalid_request', 'code_verifier must be 43-128 characters of A-Z a-z 0-9 - . _ ~');
    }

    const hash = b64url(sha256(form.code));
    const stored = await redis.oidcTakeOnce(codeKey(hash));
    if (!stored) {
      // A code presented a second time means it leaked: whoever used it first
      // (or second) is not who it was issued for. Withdraw what it bought.
      const issued = await redis.oidcTakeOnce(usedCodeKey(hash));
      if (issued) {
        await revokeAccessToken(JSON.parse(issued));
        log.audit('oidc', 'An authorization code was presented twice; the token it had been exchanged for was revoked', { clientId: form.client_id });
      }
      return tokenError(res, 'invalid_grant', 'The authorization code is invalid, expired or already used');
    }

    const grant = JSON.parse(stored);
    if (grant.clientId !== form.client_id || grant.redirectUri !== form.redirect_uri) {
      return tokenError(res, 'invalid_grant', 'client_id or redirect_uri does not match the authorization request');
    }
    const challenge = Buffer.from(b64url(sha256(form.code_verifier)));
    if (!crypto.timingSafeEqual(challenge, Buffer.from(grant.challenge))) {
      return tokenError(res, 'invalid_grant', 'code_verifier does not match the code_challenge');
    }

    const accessToken = await issueAccessToken(grant.userId);
    if (!accessToken) return tokenError(res, 'invalid_grant', 'The account can no longer sign in');
    // Remembered for a while, as the token's id only — enough to revoke it
    // if this code turns up again, and not a credential in itself.
    await redis.set(usedCodeKey(hash), JSON.stringify({ jti: accessToken.jti, exp: accessToken.exp }), 'EX', 10 * 60);

    const now = Math.floor(Date.now() / 1000);
    const idToken = jwt.sign({
      iss: issuer,
      sub: grant.userId,
      aud: grant.clientId,
      iat: now,
      exp: now + ID_TOKEN_TTL_SECONDS,
      auth_time: grant.authTime,
      ...(grant.nonce ? { nonce: grant.nonce } : {}),
      // Left half of the access token's hash (OIDC Core §3.1.3.6): lets the
      // client check the two tokens were issued together.
      at_hash: b64url(sha256(accessToken.token).subarray(0, 16)),
      ...(grant.scope.split(' ').includes('profile') ? { preferred_username: accessToken.username } : {}),
    }, signing.privateKey, { algorithm: 'RS256', keyid: signing.kid });

    log.audit('oidc', `Tokens issued to client '${grant.clientId}' for '${accessToken.username}'`, {
      clientId: grant.clientId, username: accessToken.username,
    });
    return res.set({ 'Cache-Control': 'no-store', Pragma: 'no-cache' }).json({
      access_token: accessToken.token,
      token_type: 'Bearer',
      expires_in: ACCESS_TOKEN_TTL_SECONDS,
      id_token: idToken,
      scope: grant.scope,
    });
  }

  // ── documents ────────────────────────────────────────────────────────────

  const discoveryDocument = () => ({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    userinfo_endpoint: `${issuer}/oauth/userinfo`,
    jwks_uri: `${issuer}/oauth/jwks`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile'],
    token_endpoint_auth_methods_supported: ['none'],
    code_challenge_methods_supported: ['S256'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'at_hash', 'preferred_username'],
  });

  const jwks = () => ({ keys: [{ ...signing.jwk, alg: 'RS256', use: 'sig', kid: signing.kid }] });

  /**
   * CORS for the endpoints a browser-based client calls directly. Only the
   * origins of registered redirect URIs are answered; credentials are never
   * allowed, because nothing here is authenticated by a cookie.
   */
  async function cors(req, res, next) {
    const origin = req.get('Origin');
    if (origin && await isClientOrigin(origin)) {
      res.set({
        'Access-Control-Allow-Origin': origin,
        Vary: 'Origin',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Authorization, Content-Type',
        'Access-Control-Max-Age': '600',
      });
    }
    if (req.method === 'OPTIONS') return res.status(204).end();
    return next();
  }

  return {
    init, authorize, authorizeSubmit, token, cors,
    discoveryDocument, jwks,
    getClient, listClients, createClient, deleteClient,
    CONSOLE_CLIENT_ID,
  };
}

module.exports = { createOidcProvider, redirectUriProblem, CONSOLE_CLIENT_ID };
