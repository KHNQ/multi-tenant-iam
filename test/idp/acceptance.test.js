/**
 * Acceptance tests for the failover IdP (specification §13), run against a
 * real gateway process, a throwaway Redis and a stand-in Keycloak Admin API.
 * The stand-in can be taken down: everything after the first synchronisation
 * is expected to keep working without it.
 *
 *   node --test test/idp/
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  startStack, redisAvailable, Browser, parseForm, pkce, decodeJwt, signIn, tokenRequest, waitFor, sleep,
} = require('./harness');
const { createMockKeycloak, keycloakCredential } = require('./mock-keycloak');

const skip = !redisAvailable() && 'redis-server is not installed';
const IMPORT_TOKEN = crypto.randomBytes(24).toString('hex');
const PASSWORDS = {
  padmin: 'Padmin-Passw0rd-1', tadmin: 'Tadmin-Passw0rd-1', operator1: 'Operator-Passw0rd-1',
  noroles: 'Noroles-Passw0rd-1', alice: 'Alice-Passw0rd-123', bob: 'Bob-Passw0rd-1234',
};
const MD = 'samta-mapdashboard-web-poc';
const MD_REDIRECT = 'https://mapdashboard.internal/signin-oidc';
const REACT = 'tenant-alpha.react-reference.poc';
const NATIVE = 'tenant-alpha.python-native.poc';

let kc;
let stack;
let consoleBrowser;
const secrets = {};

async function importCredentials(entries, token = IMPORT_TOKEN) {
  const res = await fetch(`${stack.url}/admin/sync/credentials`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(entries),
  });
  return { status: res.status, json: await res.json().catch(() => null) };
}

async function credentialFor(realm, username) {
  const user = kc.state.realms[realm].users.find((u) => u.username === username);
  return { realm, userId: user.id, type: 'password', createdDate: Date.now(), ...(await keycloakCredential(PASSWORDS[username])) };
}

async function consoleSignIn(browser, username) {
  let res = await browser.request('/oauth2/authorization/keycloak?returnTo=/ui/users');
  assert.equal(res.status, 302);
  res = await browser.request(res.location);
  const login = parseForm(res.text);
  res = await browser.request(login.action, { method: 'POST', form: { ...login.fields, username, password: PASSWORDS[username] } });
  assert.equal(res.status, 302, res.text.slice(0, 300));
  res = await browser.request(res.location);
  assert.equal(res.status, 302);
  assert.equal(res.location, '/ui/users');
  return browser;
}

const syncNow = async () => {
  const res = await consoleBrowser.api('POST', '/api/admin/idp/sync');
  assert.equal(res.status, 200, res.text);
  return res.json;
};

async function mdTokens(browser = new Browser(stack.url), extra = {}) {
  const flow = await signIn(browser, { realm: 'samta', clientId: MD, redirectUri: MD_REDIRECT, username: 'operator1', password: PASSWORDS.operator1, extra });
  const tokens = await tokenRequest(stack.url, 'samta', {
    grant_type: 'authorization_code', code: flow.code, redirect_uri: MD_REDIRECT, code_verifier: flow.verifier, client_id: MD, client_secret: secrets.md,
  });
  return { flow, tokens, browser };
}

before(async () => {
  if (skip) return;
  kc = createMockKeycloak();
  const kcPort = await kc.listen();
  stack = await startStack({
    env: {
      KEYCLOAK_URL: `http://127.0.0.1:${kcPort}`,
      KEYCLOAK_SYNC_CLIENT_ID: 'iam-failover-sync',
      KEYCLOAK_SYNC_CLIENT_SECRET: 'sync-secret',
      KEYCLOAK_SYNC_REALMS: 'platform,samta,tenant-alpha',
      KEYCLOAK_SYNC_INTERVAL_SECONDS: '3600',
      IDP_CREDENTIAL_IMPORT_TOKEN: IMPORT_TOKEN,
      IDP_CREDENTIAL_IMPORT_ALLOWED_CIDRS: '127.0.0.1/32,::1/128',
      MAPDASHBOARD_PERMISSION_CATALOG_URL: `http://127.0.0.1:${kcPort}/no-catalog`,
    },
  });
  await waitFor(async () => {
    const res = await fetch(`${stack.url}/health/sync`);
    const body = await res.json();
    return ['platform', 'samta', 'tenant-alpha'].every((r) => body.realms[r]?.ok);
  }, { what: 'the first synchronisation' });
});

after(async () => {
  if (stack) await stack.stop();
  if (kc) await kc.close();
});

// ── synchronisation and credentials ────────────────────────────────────────

test('the first sync brings every realm, in standby, with discovery and keys of its own', { skip }, async () => {
  const health = await (await fetch(`${stack.url}/health/sync`)).json();
  assert.equal(health.mode, 'standby');
  assert.equal(health.realms.samta.users, 2);
  assert.equal(health.realms['tenant-alpha'].users, 2);
  for (const realm of ['platform', 'samta', 'tenant-alpha']) {
    const discovery = await (await fetch(`${stack.url}/realms/${realm}/.well-known/openid-configuration`)).json();
    assert.equal(discovery.issuer, `${stack.url}/realms/${realm}`);
    assert.equal(discovery.token_endpoint, `${stack.url}/realms/${realm}/protocol/openid-connect/token`);
    assert.deepEqual(discovery.code_challenge_methods_supported, ['S256']);
    const jwks = await (await fetch(discovery.jwks_uri)).json();
    assert.equal(jwks.keys.length, 1);
    assert.equal(jwks.keys[0].alg, 'RS256');
    assert.ok(jwks.keys[0].kid);
  }
  assert.equal((await fetch(`${stack.url}/realms/nope/.well-known/openid-configuration`)).status, 404);
});

test('credential import: Keycloak argon2 hashes, by token and address only', { skip }, async () => {
  assert.equal((await importCredentials([], 'wrong')).status, 401);
  const entries = [
    await credentialFor('platform', 'padmin'), await credentialFor('platform', 'tadmin'), await credentialFor('samta', 'operator1'),
    await credentialFor('samta', 'noroles'), await credentialFor('tenant-alpha', 'alice'), await credentialFor('tenant-alpha', 'bob'),
    { realm: 'samta', userId: crypto.randomUUID(), type: 'password', ...(await keycloakCredential('x')) },
    { ...(await credentialFor('samta', 'operator1')), credentialData: { algorithm: 'pbkdf2-sha512', hashIterations: 27500 } },
  ];
  const result = await importCredentials(entries);
  assert.equal(result.status, 200);
  assert.equal(result.json.imported, 6);
  assert.equal(result.json.rejected.length, 2);
  assert.match(result.json.rejected[0].reason, /unknown user/);
  assert.match(result.json.rejected[1].reason, /unsupported algorithm 'pbkdf2-sha512'/);
  assert.ok(!stack.output().includes(entries[0].secretData.value), 'a hash must never be logged');
});

// ── the console ────────────────────────────────────────────────────────────

test('the console signs in through the platform realm and sees the session the BFF built', { skip }, async () => {
  consoleBrowser = await consoleSignIn(new Browser(stack.url), 'padmin');
  const me = await consoleBrowser.api('GET', '/api/me');
  assert.equal(me.status, 200);
  assert.equal(me.json.username, 'padmin');
  assert.equal(me.json.mode, 'standby');
  assert.equal(me.json.readOnly, true);
  assert.deepEqual(me.json.permissions, { platformAdmin: true, tenantAdmin: true });
  assert.deepEqual(me.json.tenants, ['samta', 'tenant-alpha']);
  assert.ok(me.json.roles.includes('platform-admin'));
  assert.ok(consoleBrowser.cookie('XSRF-TOKEN'));
  assert.ok(!me.text.includes('eyJ'), 'no token reaches the browser');

  const status = await consoleBrowser.api('GET', '/api/status');
  assert.equal(status.json.overall, 'operational');
  assert.deepEqual(status.json.dependencies.map((d) => d.name), ['identity-provider', 'session-store', 'primary-idp-sync']);

  for (const route of ['/ui/', '/ui/users/abc']) {
    const ui = await consoleBrowser.request(route);
    assert.ok([200, 503].includes(ui.status), `${route} answered ${ui.status}`);
  }
  assert.equal((await consoleBrowser.request('/ui')).location, '/ui/');
  assert.equal((await new Browser(stack.url).api('GET', '/api/me')).status, 401);
});

test('writes need the CSRF header (never a form field) and an Idempotency-Key', { skip }, async () => {
  const path = '/api/tenants/samta/clients/samta-mapdashboard-web-poc/secret';
  const noHeader = await consoleBrowser.request(path, { method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() } });
  assert.equal(noHeader.status, 403);
  const asField = await consoleBrowser.request(path, {
    method: 'POST', headers: { 'Idempotency-Key': crypto.randomUUID() }, form: { _csrf: consoleBrowser.cookie('XSRF-TOKEN') },
  });
  assert.equal(asField.status, 403, 'a _csrf parameter is not accepted on the API');
  const noKey = await consoleBrowser.api('POST', path, undefined, { idempotencyKey: null });
  assert.equal(noKey.status, 400);
  assert.equal(noKey.json.error, 'idempotency_key_required');
  assert.ok(noKey.json.correlationId);
  assert.equal(noKey.headers.get('x-correlation-id'), noKey.json.correlationId);
});

test('lists page with first/max and say what was applied', { skip }, async () => {
  const all = await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users?max=9999');
  assert.deepEqual(Object.keys(all.json), ['tenant', 'count', 'first', 'limit', 'total', 'hasMore', 'users']);
  assert.equal(all.json.limit, 100, 'clamped, not refused');
  assert.equal(all.json.hasMore, false);
  const one = await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users?max=1');
  assert.deepEqual([one.json.count, one.json.total, one.json.hasMore, one.json.users[0].username], [1, 2, true, 'alice']);
  const next = await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users?max=1&first=1');
  assert.deepEqual([next.json.first, next.json.hasMore, next.json.users[0].username], [1, false, 'bob']);
  const past = await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users?first=50&max=-3');
  assert.deepEqual([past.json.count, past.json.users.length, past.json.limit], [0, 0, 20]);
  const clients = await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/clients?max=2');
  assert.equal(clients.json.total, undefined, 'no total for clients');
  assert.equal(clients.json.hasMore, true);
  const roles = await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/roles?search=user');
  assert.equal(roles.json.total, undefined, 'no total for roles');
  assert.deepEqual(roles.json.roles.map((r) => r.name), ['tenant-user']);
});

test('a tenant admin sees only their own tenants', { skip }, async () => {
  const tadmin = await consoleSignIn(new Browser(stack.url), 'tadmin');
  const me = await tadmin.api('GET', '/api/me');
  assert.deepEqual(me.json.tenants, ['tenant-alpha']);
  assert.equal(me.json.permissions.platformAdmin, false);
  assert.equal((await tadmin.api('GET', '/api/tenants/samta/users')).status, 403);
  assert.equal((await tadmin.api('GET', '/api/admin/tenants')).status, 403);
  const users = await tadmin.api('GET', '/api/tenants/tenant-alpha/users');
  assert.deepEqual(users.json.users.map((u) => u.username), ['alice', 'bob']);
});

test('standby: changes are refused; this system\'s own client secrets can be issued', { skip }, async () => {
  const refused = await consoleBrowser.api('POST', '/api/tenants/samta/users', { username: 'new', email: 'new@x.local' });
  assert.equal(refused.status, 409);
  assert.equal(refused.json.reason, 'standby_read_only');
  for (const [name, clientId] of [['md', MD], ['svc', 'tenant-alpha.wiztest-svc']]) {
    const realm = clientId === MD ? 'samta' : 'tenant-alpha';
    const res = await consoleBrowser.api('POST', `/api/tenants/${realm}/clients/${clientId}/secret`, undefined, { idempotencyKey: crypto.randomUUID() });
    assert.equal(res.status, 200, res.text);
    assert.equal(res.json.secretShownOnce, true);
    secrets[name] = res.json.secret;
  }
  const listed = await consoleBrowser.api('GET', '/api/tenants/samta/clients');
  assert.ok(!listed.text.includes(secrets.md), 'a secret is shown once, never listed');
});

// ── MapDashboard: the strictest consumer ───────────────────────────────────

test('MapDashboard: code + PKCE + secret, the token contract, refresh with client_secret_post', { skip }, async () => {
  const { tokens, flow } = await mdTokens(new Browser(stack.url), { response_mode: 'form_post' });
  assert.equal(flow.res.status, 200, 'form_post answers with a self-submitting form');
  assert.equal(tokens.status, 200, JSON.stringify(tokens.json));
  const t = tokens.json;
  assert.equal(t.token_type, 'Bearer');
  assert.equal(t.expires_in, 300);
  assert.ok(t.refresh_expires_in > 0 && t.refresh_expires_in <= 1800);
  assert.ok(t.refresh_token && t.id_token);

  const access = decodeJwt(t.access_token);
  assert.equal(access.iss, `${stack.url}/realms/samta`);
  assert.equal(access.sub, '8f1e2a7c-3b4d-4e5f-9a0b-1c2d3e4f5a6b', 'sub is the Keycloak user id');
  assert.equal(access.azp, MD);
  assert.equal(access.typ, 'Bearer');
  assert.equal(access.preferred_username, 'operator1');
  assert.equal(access.email, 'operator1@example.local');
  assert.equal(access.email_verified, true);
  assert.equal(access.name, 'Operator One');
  assert.equal(access.scope, 'openid profile email');
  assert.ok(access.sid);
  assert.equal(access.exp - access.iat, 300);
  assert.deepEqual(access.md_roles.sort(), ['perm:layers.view', 'perm:objects.read', 'role:operator']);
  assert.deepEqual(access.resource_access[MD].roles.sort(), ['perm:layers.view', 'perm:objects.read', 'role:operator']);
  assert.deepEqual(access.resource_access.account.roles.sort(), ['manage-account', 'view-profile']);
  assert.deepEqual(access.realm_access.roles.sort(), ['default-roles-samta', 'offline_access', 'uma_authorization']);
  assert.equal(access.aud, 'account', 'audience resolve, written as Keycloak writes a single audience');
  assert.deepEqual(access['allowed-origins'], ['https://mapdashboard.internal', 'https://localhost:5173']);

  const id = decodeJwt(t.id_token);
  assert.equal(id.typ, 'ID');
  assert.equal(id.aud, MD);
  assert.equal(id.nonce, flow.nonce);
  assert.equal(id.sid, access.sid);
  assert.ok(Array.isArray(id.md_roles) && id.md_roles.includes('role:operator'));
  assert.equal(id.realm_access, undefined, 'realm roles are not in the ID token unless a mapper puts them there');

  const header = JSON.parse(Buffer.from(t.access_token.split('.')[0], 'base64url'));
  assert.equal(header.alg, 'RS256');
  assert.ok(header.kid);

  const refreshed = await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: MD, client_secret: secrets.md });
  assert.equal(refreshed.status, 200);
  assert.notEqual(refreshed.json.refresh_token, t.refresh_token);
  const again = decodeJwt(refreshed.json.access_token);
  for (const claim of ['sub', 'iss', 'azp', 'sid']) assert.equal(again[claim], access[claim]);
  assert.ok(Array.isArray(again.md_roles));

  // The retired token, used again: the whole session goes.
  const reused = await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: MD, client_secret: secrets.md });
  assert.equal(reused.status, 400);
  assert.equal(reused.json.error, 'invalid_grant');
  const afterTheft = await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: refreshed.json.refresh_token, client_id: MD, client_secret: secrets.md });
  assert.equal(afterTheft.status, 400);
});

test('client authentication: basic and post work, a missing or wrong secret does not', { skip }, async () => {
  const flow = await signIn(new Browser(stack.url), { realm: 'samta', clientId: MD, redirectUri: MD_REDIRECT, username: 'operator1', password: PASSWORDS.operator1 });
  const base = { grant_type: 'authorization_code', code: flow.code, redirect_uri: MD_REDIRECT, code_verifier: flow.verifier };
  assert.equal((await tokenRequest(stack.url, 'samta', { ...base, client_id: MD })).status, 401);
  assert.equal((await tokenRequest(stack.url, 'samta', { ...base, client_id: MD, client_secret: 'wrong' })).status, 401);
  const ok = await tokenRequest(stack.url, 'samta', base, { basic: [MD, secrets.md] });
  assert.equal(ok.status, 200);
  // The same code a second time: refused, and the session it bought ends.
  const twice = await tokenRequest(stack.url, 'samta', base, { basic: [MD, secrets.md] });
  assert.equal(twice.json.error, 'invalid_grant');
  const refresh = await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: ok.json.refresh_token }, { basic: [MD, secrets.md] });
  assert.equal(refresh.status, 400);
});

test('PKCE is required with S256; an unregistered redirect is shown, never followed', { skip }, async () => {
  const browser = new Browser(stack.url);
  const { challenge } = pkce();
  const q = (extra) => `/realms/samta/protocol/openid-connect/auth?${new URLSearchParams({ response_type: 'code', client_id: MD, redirect_uri: MD_REDIRECT, scope: 'openid', state: 's', ...extra })}`;
  const plain = await browser.request(q({ code_challenge: challenge, code_challenge_method: 'plain' }));
  assert.equal(plain.status, 302);
  assert.equal(new URL(plain.location).searchParams.get('error'), 'invalid_request');
  const missing = await browser.request(q({}));
  assert.equal(new URL(missing.location).searchParams.get('error'), 'invalid_request');
  const implicit = await browser.request(q({ code_challenge: challenge, code_challenge_method: 'S256', response_type: 'token' }));
  assert.equal(new URL(implicit.location).searchParams.get('error'), 'unsupported_response_type');
  const evil = await browser.request(q({ code_challenge: challenge, code_challenge_method: 'S256', redirect_uri: 'https://evil.example/signin-oidc' }));
  assert.equal(evil.status, 400);
  assert.equal(evil.location, null);
  const prefix = await browser.request(q({ code_challenge: challenge, code_challenge_method: 'S256', redirect_uri: `${MD_REDIRECT}/extra` }));
  assert.equal(prefix.status, 400);
});

// ── tenant-alpha: React, native, service account ───────────────────────────

test('React (public): composite and group roles expanded, tenant and audiences, CORS', { skip }, async () => {
  const browser = new Browser(stack.url);
  const flow = await signIn(browser, { realm: 'tenant-alpha', clientId: REACT, redirectUri: 'https://localhost:5173/auth/callback', username: 'alice', password: PASSWORDS.alice });
  const res = await fetch(`${stack.url}/realms/tenant-alpha/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://localhost:5173' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: flow.code, redirect_uri: 'https://localhost:5173/auth/callback', code_verifier: flow.verifier, client_id: REACT }),
  });
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('access-control-allow-origin'), 'https://localhost:5173');
  const t = await res.json();
  const id = decodeJwt(t.id_token);
  assert.equal(id.tenant, 'tenant-alpha');
  // alice is in /administrators/ops; /administrators carries tenant-admin, a composite of tenant-user.
  assert.ok(id.realm_access.roles.includes('tenant-admin'));
  assert.ok(id.realm_access.roles.includes('tenant-user'));
  const access = decodeJwt(t.access_token);
  assert.equal(access.tenant, 'tenant-alpha');
  assert.equal(access.authz_version, 0);
  assert.ok(access.aud.includes('business-api'));
  assert.ok(access.aud.includes('react-reference-api'));
  assert.deepEqual(access.resource_access[NATIVE].roles, ['reader']);
  assert.equal(access.scope, 'openid profile email business-api');

  const info = await fetch(`${stack.url}/realms/tenant-alpha/protocol/openid-connect/userinfo`, { headers: { Authorization: `Bearer ${t.access_token}`, Origin: 'https://localhost:5173' } });
  assert.equal(info.status, 200);
  const claims = await info.json();
  assert.equal(claims.sub, access.sub);
  assert.equal(claims.tenant, 'tenant-alpha');
  assert.ok(claims.realm_access.roles.includes('tenant-admin'));

  const denied = await fetch(`${stack.url}/realms/tenant-alpha/protocol/openid-connect/token`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://evil.example' },
    body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: t.refresh_token, client_id: REACT }),
  });
  assert.equal(denied.headers.get('access-control-allow-origin'), null);
  const rotatedRefresh = (await denied.json()).refresh_token;

  // Single sign-on: a second client of the realm, no password asked.
  const sso = await signIn(browser, { realm: 'tenant-alpha', clientId: NATIVE, redirectUri: 'http://127.0.0.1:40111/callback', username: 'alice', password: 'not-needed' });
  assert.ok(sso.code, 'signed in from the session');
  const prompted = await browser.request(`/realms/tenant-alpha/protocol/openid-connect/auth?${new URLSearchParams({
    response_type: 'code', client_id: NATIVE, redirect_uri: 'http://127.0.0.1:40111/callback', scope: 'openid', prompt: 'login',
    code_challenge: pkce().challenge, code_challenge_method: 'S256',
  })}`);
  assert.equal(prompted.status, 200);
  assert.ok(prompted.text.includes('name="password"'));
  // Re-authenticating keeps the session: the React client's refresh token still works.
  const login = parseForm(prompted.text);
  const again = await browser.request(login.action, { method: 'POST', form: { ...login.fields, username: 'alice', password: PASSWORDS.alice } });
  assert.equal(again.status, 302);
  const stillValid = await tokenRequest(stack.url, 'tenant-alpha', { grant_type: 'refresh_token', refresh_token: rotatedRefresh, client_id: REACT });
  assert.equal(stillValid.status, 200);
  assert.equal(decodeJwt(stillValid.json.access_token).sid, access.sid);
});

test('native: a dynamic loopback port and a private-use scheme, audience python-demo-api', { skip }, async () => {
  const loop = await signIn(new Browser(stack.url), { realm: 'tenant-alpha', clientId: NATIVE, redirectUri: 'http://127.0.0.1:53122/callback', username: 'bob', password: PASSWORDS.bob, scope: 'openid profile' });
  assert.equal(loop.location.port, '53122');
  const t = await tokenRequest(stack.url, 'tenant-alpha', { grant_type: 'authorization_code', code: loop.code, redirect_uri: 'http://127.0.0.1:53122/callback', code_verifier: loop.verifier, client_id: NATIVE });
  const access = decodeJwt(t.json.access_token);
  assert.ok([].concat(access.aud).includes('python-demo-api'));
  assert.equal(access.azp, NATIVE);
  assert.deepEqual(access.resource_access[NATIVE].roles, ['reader']);

  const scheme = await signIn(new Browser(stack.url), { realm: 'tenant-alpha', clientId: NATIVE, redirectUri: 'com.samta.pydemo:/callback', username: 'bob', password: PASSWORDS.bob });
  assert.equal(scheme.res.status, 302);
  assert.ok(scheme.res.location.startsWith('com.samta.pydemo:/callback?code='));
  const other = await new Browser(stack.url).request(`/realms/tenant-alpha/protocol/openid-connect/auth?${new URLSearchParams({
    response_type: 'code', client_id: NATIVE, redirect_uri: 'http://192.168.1.5:53122/callback', code_challenge: pkce().challenge, code_challenge_method: 'S256',
  })}`);
  assert.equal(other.status, 400, 'only loopback ignores the port');
});

test('client credentials: for a service account client only', { skip }, async () => {
  const ok = await tokenRequest(stack.url, 'tenant-alpha', { grant_type: 'client_credentials' }, { basic: ['tenant-alpha.wiztest-svc', secrets.svc] });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(ok.json.refresh_token, undefined);
  const claims = decodeJwt(ok.json.access_token);
  assert.equal(claims.preferred_username, 'service-account-tenant-alpha.wiztest-svc');
  assert.equal(claims.sub, kc.state.realms['tenant-alpha'].serviceAccounts.values().next().value.id);
  assert.ok([].concat(claims.aud).includes('tenant-alpha.wiztest-api'));
  assert.equal(claims.client_id, 'tenant-alpha.wiztest-svc');
  const publicClient = await tokenRequest(stack.url, 'tenant-alpha', { grant_type: 'client_credentials', client_id: REACT });
  assert.equal(publicClient.json.error, 'unauthorized_client');
  const noServiceAccount = await tokenRequest(stack.url, 'samta', { grant_type: 'client_credentials' }, { basic: [MD, secrets.md] });
  assert.equal(noServiceAccount.json.error, 'unauthorized_client');
  const password = await tokenRequest(stack.url, 'samta', { grant_type: 'password', username: 'operator1', password: PASSWORDS.operator1 }, { basic: [MD, secrets.md] });
  assert.equal(password.json.error, 'unsupported_grant_type');
});

test('logout: ends the session and its refresh tokens; only a registered post-logout URI', { skip }, async () => {
  const { tokens } = await mdTokens();
  const hint = tokens.json.id_token;
  const bad = await fetch(`${stack.url}/realms/samta/protocol/openid-connect/logout?${new URLSearchParams({ id_token_hint: hint, post_logout_redirect_uri: 'https://mapdashboard.internal/elsewhere' })}`, { redirect: 'manual' });
  assert.equal(bad.status, 400);
  const good = await fetch(`${stack.url}/realms/samta/protocol/openid-connect/logout?${new URLSearchParams({
    id_token_hint: hint, post_logout_redirect_uri: 'https://mapdashboard.internal/signout-callback-oidc', state: 'xyz',
  })}`, { redirect: 'manual' });
  assert.equal(good.status, 302);
  assert.equal(good.headers.get('location'), 'https://mapdashboard.internal/signout-callback-oidc?state=xyz');
  const refresh = await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: tokens.json.refresh_token, client_id: MD, client_secret: secrets.md });
  assert.equal(refresh.json.error, 'invalid_grant');

  // The primary system's wildcard is not honoured here.
  const wildcard = await fetch(`${stack.url}/realms/platform/protocol/openid-connect/logout?${new URLSearchParams({
    client_id: 'iam-admin-ui', post_logout_redirect_uri: 'https://mapdashboard.internal/anything',
  })}`, { redirect: 'manual' });
  assert.equal(wildcard.status, 400);
});

test('sessions expire after the idle timeout and the maximum lifespan', { skip }, async () => {
  const idle = await mdTokens();
  const sid = decodeJwt(idle.tokens.json.access_token).sid;
  await stack.redis.pexpire(`idp:samta:sess:${sid}`, 50);
  await sleep(150);
  assert.equal((await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: idle.tokens.json.refresh_token, client_id: MD, client_secret: secrets.md })).json.error, 'invalid_grant');

  const old = await mdTokens();
  const sid2 = decodeJwt(old.tokens.json.access_token).sid;
  await stack.redis.hset(`idp:samta:sess:${sid2}`, 'created', String(Date.now() - 36001 * 1000));
  assert.equal((await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: old.tokens.json.refresh_token, client_id: MD, client_secret: secrets.md })).json.error, 'invalid_grant');
});

test('introspection (confidential clients) and revocation', { skip }, async () => {
  const { tokens } = await mdTokens();
  const introspect = (token, auth) => fetch(`${stack.url}/realms/samta/protocol/openid-connect/token/introspect`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Authorization: `Basic ${Buffer.from(auth.join(':')).toString('base64')}` },
    body: new URLSearchParams({ token }),
  }).then((r) => r.json());
  const active = await introspect(tokens.json.access_token, [MD, secrets.md]);
  assert.equal(active.active, true);
  assert.equal(active.client_id, MD);
  assert.equal((await introspect('garbage', [MD, secrets.md])).active, false);

  const revoked = await fetch(`${stack.url}/realms/samta/protocol/openid-connect/revoke`, {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ token: tokens.json.refresh_token, client_id: MD, client_secret: secrets.md }),
  });
  assert.equal(revoked.status, 200);
  assert.equal((await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: tokens.json.refresh_token, client_id: MD, client_secret: secrets.md })).json.error, 'invalid_grant');
});

test('key rotation: two keys published, a token from the passive one still verifies', { skip }, async () => {
  const { tokens } = await mdTokens();
  const oldKid = JSON.parse(Buffer.from(tokens.json.access_token.split('.')[0], 'base64url')).kid;
  const rotated = await consoleBrowser.api('POST', '/api/admin/idp/realms/samta/keys/rotate');
  assert.equal(rotated.status, 200);
  await sleep(50);
  const jwks = await (await fetch(`${stack.url}/realms/samta/protocol/openid-connect/certs`)).json();
  assert.equal(jwks.keys.length, 2);
  assert.ok(jwks.keys.some((k) => k.kid === oldKid));
  const info = await fetch(`${stack.url}/realms/samta/protocol/openid-connect/userinfo`, { headers: { Authorization: `Bearer ${tokens.json.access_token}` } });
  assert.equal(info.status, 200);
  const fresh = await mdTokens();
  assert.notEqual(JSON.parse(Buffer.from(fresh.tokens.json.access_token.split('.')[0], 'base64url')).kid, oldKid);
});

// ── changes arriving by sync, and the primary going away ───────────────────

test('a user disabled in Keycloak loses refresh at the next sync; a deleted one is removed', { skip }, async () => {
  const browser = new Browser(stack.url);
  const flow = await signIn(browser, { realm: 'tenant-alpha', clientId: NATIVE, redirectUri: 'http://127.0.0.1:1/callback', username: 'bob', password: PASSWORDS.bob });
  const t = await tokenRequest(stack.url, 'tenant-alpha', { grant_type: 'authorization_code', code: flow.code, redirect_uri: 'http://127.0.0.1:1/callback', code_verifier: flow.verifier, client_id: NATIVE });
  assert.equal(t.status, 200);

  const alpha = kc.state.realms['tenant-alpha'];
  alpha.users.find((u) => u.username === 'bob').enabled = false;
  const samta = kc.state.realms.samta;
  samta.users = samta.users.filter((u) => u.username !== 'noroles');
  const result = await syncNow();
  assert.equal(result.ok, true, JSON.stringify(result));

  const refresh = await tokenRequest(stack.url, 'tenant-alpha', { grant_type: 'refresh_token', refresh_token: t.json.refresh_token, client_id: NATIVE });
  assert.equal(refresh.json.error, 'invalid_grant');
  const users = await consoleBrowser.api('GET', '/api/tenants/samta/users');
  assert.deepEqual(users.json.users.map((u) => u.username), ['operator1']);
  alpha.users.find((u) => u.username === 'bob').enabled = true;
});

test('Keycloak down or failing halfway: nothing is deleted, the realm reports stale', { skip }, async () => {
  const before = (await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users')).json.users.length;
  kc.state.failOn = /\/users\/[^/]+\/role-mappings/;
  kc.state.realms['tenant-alpha'].users = [];
  const failed = await syncNow();
  assert.equal(failed.ok, false);
  assert.equal((await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users')).json.users.length, before);

  kc.state.failOn = null;
  kc.state.down = true;
  const down = await syncNow();
  assert.equal(down.ok, false);
  const health = await fetch(`${stack.url}/health/sync`);
  assert.equal(health.status, 503);
  assert.equal((await health.json()).stale, true);

  // Everything keeps working without the primary.
  const { tokens } = await mdTokens();
  assert.equal(tokens.status, 200);
  const refreshed = await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: tokens.json.refresh_token, client_id: MD, client_secret: secrets.md });
  assert.equal(refreshed.status, 200);
  assert.equal((await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users')).json.users.length, before);
});

test('standby: an emergency lock and session termination still work', { skip }, async () => {
  const users = (await consoleBrowser.api('GET', '/api/tenants/samta/users')).json.users;
  const operator = users.find((u) => u.username === 'operator1');
  const { tokens } = await mdTokens();
  const sessions = await consoleBrowser.api('GET', `/api/tenants/samta/users/${operator.id}/sessions`);
  assert.ok(sessions.json.sessions.length >= 1);
  assert.ok(sessions.json.sessions.some((s) => s.clients[MD] === MD && s.ipAddress && s.started && s.lastAccess));

  const locked = await consoleBrowser.api('PUT', `/api/tenants/samta/users/${operator.id}/enabled`, { enabled: false });
  assert.equal(locked.status, 200);
  assert.equal(locked.json.enabled, false);
  assert.equal((await tokenRequest(stack.url, 'samta', { grant_type: 'refresh_token', refresh_token: tokens.json.refresh_token, client_id: MD, client_secret: secrets.md })).status, 400);
  const blocked = await signIn(new Browser(stack.url), { realm: 'samta', clientId: MD, redirectUri: MD_REDIRECT, username: 'operator1', password: PASSWORDS.operator1 });
  assert.equal(blocked.res.status, 401);
  assert.equal((await consoleBrowser.api('PUT', `/api/tenants/samta/users/${operator.id}/enabled`, { enabled: true })).json.enabled, true);

  await mdTokens();
  const terminated = await consoleBrowser.api('POST', `/api/tenants/samta/users/${operator.id}/sessions/terminate-all`, { reason: 'test' });
  assert.equal(terminated.status, 200);
  assert.ok(terminated.json.terminated >= 1);
  assert.equal((await consoleBrowser.api('GET', `/api/tenants/samta/users/${operator.id}/sessions`)).json.sessions.length, 0);
});

test('the access test shows the sign-in checks and the claims each token would carry', { skip }, async () => {
  const operator = (await consoleBrowser.api('GET', '/api/tenants/samta/users?search=operator')).json.users[0];
  const result = await consoleBrowser.api('POST', `/api/tenants/samta/users/${operator.id}/access-test`, { clientId: MD, scope: 'openid profile email' });
  assert.equal(result.status, 200, result.text);
  assert.equal(result.json.allowed, true, JSON.stringify(result.json.checks));
  assert.ok(result.json.checks.some((c) => c.key === 'md_roles_role' && c.ok));
  assert.ok(result.json.accessToken.md_roles.includes('role:operator'));
  assert.equal(result.json.accessToken.iss, `${stack.url}/realms/samta`);
  assert.ok(result.json.idToken.md_roles);
  assert.equal(result.json.userinfo.sub, operator.id);
  assert.ok(!result.text.includes('eyJ'), 'nothing is signed or issued');
  const tooFew = await consoleBrowser.api('POST', `/api/tenants/samta/users/${operator.id}/access-test`, { clientId: 'nope' });
  assert.equal(tooFew.json.error, 'validation_failed');
});

test('the console shows application access and effective access with every reason', { skip }, async () => {
  const roles = await consoleBrowser.api('GET', `/api/tenants/samta/applications/${MD}/roles`);
  assert.deepEqual(roles.json.map((r) => [r.name, r.system, r.permissions]), [
    ['admin', true, ['layers.view', 'objects.read']], ['operator', false, ['layers.view', 'objects.read']],
  ]);
  const permissions = await consoleBrowser.api('GET', `/api/tenants/samta/applications/${MD}/permissions`);
  assert.deepEqual(permissions.json, [
    { key: 'layers.view', category: 'Layers', description: 'View layers.' },
    { key: 'objects.read', category: 'Objects', description: 'View objects.' },
  ]);
  const operator = (await consoleBrowser.api('GET', '/api/tenants/samta/users?search=operator')).json.users[0];
  const access = await consoleBrowser.api('GET', `/api/tenants/samta/applications/${MD}/users/${operator.id}/effective-access`);
  assert.deepEqual(access.json.directRoles, ['operator']);
  assert.deepEqual(access.json.permissionOrigins['objects.read'], ['direct:operator']);
  const preview = await consoleBrowser.api('POST', `/api/tenants/samta/applications/${MD}/users/${operator.id}/role-changes/preview`, { role: 'operator', action: 'revoke' });
  assert.deepEqual(preview.json.permissionsLost, ['layers.view', 'objects.read']);
  assert.equal((await consoleBrowser.api('GET', '/api/tenants/samta/applications/unknown-app/roles')).json.error, 'APPLICATION_ACCESS_NOT_CONFIGURED');

  const alice = (await consoleBrowser.api('GET', '/api/tenants/tenant-alpha/users?search=alice')).json.users[0];
  const effective = await consoleBrowser.api('GET', `/api/tenants/tenant-alpha/users/${alice.id}/effective-access`);
  const tenantUser = effective.json.access.find((r) => r.name === 'tenant-user');
  assert.deepEqual(tenantUser.origins.sort(), ['composite', 'direct']);
  assert.deepEqual(effective.json.groups, ['/administrators/ops']);
  assert.ok(effective.json.access.find((r) => r.name === 'tenant-admin').grants.some((g) => g.origin === 'group' && g.via === '/administrators'));
});

test('primary mode: sync stops and the console can change things, once per idempotency key', { skip }, async () => {
  kc.state.down = false;
  const switched = await consoleBrowser.api('POST', '/api/admin/idp/mode', { mode: 'primary' });
  assert.equal(switched.json.mode, 'primary');
  await sleep(2100);
  assert.equal((await syncNow()).skipped, 'primary_mode');

  const key = crypto.randomUUID();
  const created = await consoleBrowser.api('POST', '/api/tenants/samta/users', { username: 'newcomer', email: 'newcomer@samta.local', firstName: 'New' }, { idempotencyKey: key });
  assert.equal(created.status, 201, created.text);
  const replay = await consoleBrowser.api('POST', '/api/tenants/samta/users', { username: 'newcomer', email: 'newcomer@samta.local', firstName: 'New' }, { idempotencyKey: key });
  assert.equal(replay.status, 201);
  assert.equal(replay.json.id, created.json.id);
  const reuse = await consoleBrowser.api('POST', '/api/tenants/samta/users', { username: 'other', email: 'other@samta.local' }, { idempotencyKey: key });
  assert.equal(reuse.json.error, 'idempotency_key_reuse');
  const duplicate = await consoleBrowser.api('POST', '/api/tenants/samta/users', { username: 'newcomer', email: 'x@samta.local' }, { idempotencyKey: crypto.randomUUID() });
  assert.equal(duplicate.json.error, 'conflict');

  const weak = await consoleBrowser.api('PUT', `/api/tenants/samta/users/${created.json.id}/credential`, { password: 'short' });
  assert.equal(weak.json.error, 'validation_failed');
  const temporary = 'Temporary-Passw0rd-42';
  const reset = await consoleBrowser.api('PUT', `/api/tenants/samta/users/${created.json.id}/credential`, { password: temporary });
  assert.equal(reset.status, 204, 'no credential material comes back');
  assert.equal(reset.text, '');
  await consoleBrowser.api('PUT', `/api/tenants/samta/users/${created.json.id}/required-actions`, { actions: ['UPDATE_PASSWORD'] });
  const grant = await consoleBrowser.api('POST', `/api/tenants/samta/applications/${MD}/users/${created.json.id}/role-changes/preview`, { role: 'operator', action: 'assign' });
  const applied = await consoleBrowser.api('POST', `/api/tenants/samta/applications/${MD}/users/${created.json.id}/role-changes`, { role: 'operator', action: 'assign', fingerprint: grant.json.fingerprint });
  assert.deepEqual(applied.json.effectiveRoles, ['operator']);
  const stale = await consoleBrowser.api('POST', `/api/tenants/samta/applications/${MD}/users/${created.json.id}/role-changes`, { role: 'operator', action: 'revoke', fingerprint: grant.json.fingerprint });
  assert.equal(stale.json.error, 'stale_preview');

  // The temporary password must be replaced at the first sign-in.
  const flow = await signIn(new Browser(stack.url), {
    realm: 'samta', clientId: MD, redirectUri: MD_REDIRECT, username: 'newcomer', password: temporary, newPassword: 'Chosen-Passw0rd-77',
  });
  assert.ok(flow.code, flow.res.text?.slice(0, 300));
  const t = await tokenRequest(stack.url, 'samta', { grant_type: 'authorization_code', code: flow.code, redirect_uri: MD_REDIRECT, code_verifier: flow.verifier, client_id: MD, client_secret: secrets.md });
  assert.ok(decodeJwt(t.json.access_token).md_roles.includes('role:operator'));
});

test('the tenant catalogue lists synced realms and provisions an approved one', { skip }, async () => {
  const list = await consoleBrowser.api('GET', '/api/admin/tenants');
  assert.deepEqual(list.json.tenants.map((t) => [t.tenantKey, t.status, t.provisioningStatus, t.driftStatus]), [
    ['samta', 'APPROVED', 'READY', 'IN_SYNC'], ['tenant-alpha', 'APPROVED', 'READY', 'IN_SYNC'],
  ]);
  const requested = await consoleBrowser.api('POST', '/api/admin/tenants', { tenantKey: 'tenant-gamma', displayName: 'Gamma', realmName: 'tenant-gamma' }, { idempotencyKey: crypto.randomUUID() });
  assert.equal(requested.status, 201);
  assert.equal((await consoleBrowser.api('POST', '/api/admin/tenants/tenant-gamma/reject', { reason: '' })).json.error, 'reason_required');
  const approved = await consoleBrowser.api('POST', '/api/admin/tenants/tenant-gamma/approve', { reason: 'Approved for pilot' });
  assert.equal(approved.json.provisioningStatus, 'READY');
  assert.equal(approved.json.driftStatus, 'IN_SYNC');
  const discovery = await fetch(`${stack.url}/realms/tenant-gamma/.well-known/openid-configuration`);
  assert.equal(discovery.status, 200);
  assert.ok((await consoleBrowser.api('GET', '/api/me')).json.tenants.includes('tenant-gamma'));
});

test('console sign-out ends the IdP session and returns to the console', { skip }, async () => {
  const browser = await consoleSignIn(new Browser(stack.url), 'tadmin');
  const res = await browser.request('/logout', { method: 'POST', form: { _csrf: browser.cookie('XSRF-TOKEN'), returnTo: '/ui/' } });
  assert.equal(res.status, 302);
  const idpLogout = await browser.request(res.location);
  assert.equal(idpLogout.status, 302);
  const done = await browser.request(idpLogout.location);
  assert.equal(done.location, '/ui/');
  assert.equal((await browser.api('GET', '/api/me')).status, 401);
  const relogin = await browser.request('/oauth2/authorization/keycloak');
  const page = await browser.request(relogin.location);
  assert.ok(page.text.includes('name="password"'), 'the IdP session is gone too');
});
