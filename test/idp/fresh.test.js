/**
 * A deployment with no primary IdP behind it (or after the primary has been
 * retired): the platform realm is created here, its first administrator signs
 * in to the console with a one-time password and must replace it, and the
 * console provisions and administers tenants itself.
 */

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const crypto = require('crypto');
const { startStack, redisAvailable, Browser, parseForm, decodeJwt, signIn, tokenRequest } = require('./harness');

const skip = !redisAvailable() && 'redis-server is not installed';
let stack;
let admin;

before(async () => { if (!skip) stack = await startStack(); });
after(async () => { if (stack) await stack.stop(); });

test('a fresh deployment is primary, with a platform realm and no sync', { skip }, async () => {
  const health = await (await fetch(`${stack.url}/health/sync`)).json();
  assert.equal(health.mode, 'primary');
  assert.equal(health.syncConfigured, false);
  assert.equal(health.stale, false);
  assert.equal(health.realms.platform.source, 'local');
  const mode = fs.statSync(stack.files.consoleAdmin).mode & 0o777;
  assert.equal(mode, 0o600, 'the one-time password is readable by its owner only');
  assert.ok(!stack.output().includes(fs.readFileSync(stack.files.consoleAdmin, 'utf8').trim()), 'and never printed');
});

test('the first administrator replaces the one-time password while signing in to the console', { skip }, async () => {
  admin = new Browser(stack.url);
  const oneTime = fs.readFileSync(stack.files.consoleAdmin, 'utf8').trim();
  let res = await admin.request('/oauth2/authorization/keycloak');
  res = await admin.request(res.location);
  const login = parseForm(res.text);
  res = await admin.request(login.action, { method: 'POST', form: { ...login.fields, username: 'padmin', password: oneTime } });
  assert.equal(res.status, 200);
  const change = parseForm(res.text);
  assert.ok('new_password' in change.fields);
  const weak = await admin.request(change.action, { method: 'POST', form: { ...change.fields, new_password: 'weak', confirm_password: 'weak' } });
  assert.equal(weak.status, 400);
  res = await admin.request(change.action, { method: 'POST', form: { ...change.fields, new_password: 'Console-Admin-Passw0rd', confirm_password: 'Console-Admin-Passw0rd' } });
  assert.equal(res.status, 302);
  res = await admin.request(res.location);
  assert.equal(res.location, '/ui/');
  await new Promise((resolve) => { setTimeout(resolve, 200); });
  assert.equal(fs.existsSync(stack.files.consoleAdmin), false, 'the one-time password file goes once it is replaced');
  const me = await admin.api('GET', '/api/me');
  assert.equal(me.json.username, 'padmin');
  assert.equal(me.json.permissions.platformAdmin, true);
  assert.deepEqual(me.json.tenants, []);
  const status = await admin.api('GET', '/api/status');
  assert.equal(status.json.overall, 'operational');
  assert.equal(status.json.dependencies.find((d) => d.name === 'primary-idp-sync').state, 'not_configured');
});

test('the console provisions a tenant and administers it end to end', { skip }, async () => {
  const key = () => crypto.randomUUID();
  assert.equal((await admin.api('POST', '/api/admin/tenants', { tenantKey: 'acme', displayName: 'Acme', realmName: 'acme' }, { idempotencyKey: key() })).status, 201);
  const approved = await admin.api('POST', '/api/admin/tenants/acme/approve', { reason: 'go' }, { idempotencyKey: key() });
  assert.equal(approved.json.provisioningStatus, 'READY');
  assert.deepEqual((await admin.api('GET', '/api/me')).json.tenants, ['acme']);

  const created = await admin.api('POST', '/api/tenants/acme/clients', {
    clientId: 'acme.web', name: 'Acme web', kind: 'public', standardFlow: true,
    redirectUris: ['https://acme.example/cb'], webOrigins: ['https://acme.example'], postLogoutRedirectUris: ['https://acme.example/'],
  }, { idempotencyKey: key() });
  assert.equal(created.status, 201, created.text);
  assert.equal(created.json.secret, undefined, 'a public client has no secret');
  const unsafe = await admin.api('POST', '/api/tenants/acme/clients', {
    clientId: 'acme.bad', kind: 'public', standardFlow: true, redirectUris: ['https://acme.example/*'],
  }, { idempotencyKey: key() });
  assert.equal(unsafe.json.error, 'invalid_request');
  assert.match(unsafe.json.fields.redirectUris, /^entry 1 .*wildcard/);
  assert.ok(!unsafe.text.includes('acme.example/*'), 'fields name the rule, never the value sent');
  const service = await admin.api('POST', '/api/tenants/acme/clients', { clientId: 'acme.svc', kind: 'confidential', standardFlow: false }, { idempotencyKey: key() });
  assert.equal(service.status, 201);
  assert.ok(service.json.secret);
  const cc = await tokenRequest(stack.url, 'acme', { grant_type: 'client_credentials' }, { basic: ['acme.svc', service.json.secret] });
  assert.equal(decodeJwt(cc.json.access_token).preferred_username, 'service-account-acme.svc');

  const user = await admin.api('POST', '/api/tenants/acme/users', { username: 'wile', email: 'wile@acme.example', firstName: 'Wile', lastName: 'Coyote' }, { idempotencyKey: key() });
  assert.equal(user.status, 201);
  await admin.api('PUT', `/api/tenants/acme/users/${user.json.id}/credential`, { password: 'Temporary-Passw0rd-1' }, { idempotencyKey: key() });
  const catalogue = await admin.api('GET', '/api/tenants/acme/roles');
  const tenantUser = catalogue.json.roles.find((r) => r.name === 'tenant-user');
  assert.equal(tenantUser.assignable, true);
  assert.equal(catalogue.json.roles.find((r) => r.name === 'tenant-admin').assignable, false);
  const granted = await admin.api('POST', `/api/tenants/acme/users/${user.json.id}/role-mappings`, { add: [{ source: 'realm', name: 'tenant-user' }] }, { idempotencyKey: key() });
  assert.equal(granted.json.assigned, 1);
  const refusedAdmin = await admin.api('POST', `/api/tenants/acme/users/${user.json.id}/role-mappings`, { add: [{ source: 'realm', name: 'tenant-admin' }] }, { idempotencyKey: key() });
  assert.equal(refusedAdmin.status, 403, 'an administrative role is never grantable');
  assert.equal(refusedAdmin.json.error, 'access_denied');

  const group = await admin.api('POST', '/api/tenants/acme/groups', { name: 'engineering', parentId: null }, { idempotencyKey: key() });
  assert.equal(group.json.path, '/engineering');
  await admin.api('PUT', `/api/tenants/acme/groups/${group.json.id}/members/${user.json.id}`, undefined, { idempotencyKey: key() });
  assert.deepEqual((await admin.api('GET', `/api/tenants/acme/groups/${group.json.id}/members`)).json.members.map((m) => m.username), ['wile']);

  const flow = await signIn(new Browser(stack.url), {
    realm: 'acme', clientId: 'acme.web', redirectUri: 'https://acme.example/cb', username: 'wile', password: 'Temporary-Passw0rd-1', newPassword: 'Chosen-Passw0rd-123',
  });
  assert.ok(flow.code);
  assert.equal(flow.state, flow.sentState);
  const t = await tokenRequest(stack.url, 'acme', { grant_type: 'authorization_code', code: flow.code, redirect_uri: 'https://acme.example/cb', code_verifier: flow.verifier, client_id: 'acme.web' });
  const access = decodeJwt(t.json.access_token);
  assert.equal(access.iss, `${stack.url}/realms/acme`);
  assert.ok(access.realm_access.roles.includes('tenant-user'));
  assert.ok(access.realm_access.roles.includes('default-roles-acme'));
  assert.equal(decodeJwt(t.json.id_token).preferred_username, 'wile');

  // A token of one tenant is no good at another's endpoints.
  const cross = await fetch(`${stack.url}/realms/platform/protocol/openid-connect/userinfo`, { headers: { Authorization: `Bearer ${t.json.access_token}` } });
  assert.equal(cross.status, 401);

  const disabled = await admin.api('PUT', `/api/tenants/acme/users/${user.json.id}/enabled`, { enabled: false }, { idempotencyKey: key() });
  assert.equal(disabled.json.enabled, false);
  assert.equal((await tokenRequest(stack.url, 'acme', { grant_type: 'refresh_token', refresh_token: t.json.refresh_token, client_id: 'acme.web' })).json.error, 'invalid_grant');
});

test('signing in is throttled per account and address', { skip }, async () => {
  const browser = new Browser(stack.url);
  let last;
  for (let i = 0; i < 6; i++) {
    last = await signIn(browser, { realm: 'platform', clientId: 'iam-admin-ui', redirectUri: `${stack.url}/login/oauth2/code/keycloak`, username: 'padmin', password: `wrong-${i}` });
  }
  assert.equal(last.res.status, 429);
  const right = await signIn(browser, { realm: 'platform', clientId: 'iam-admin-ui', redirectUri: `${stack.url}/login/oauth2/code/keycloak`, username: 'padmin', password: 'Console-Admin-Passw0rd' });
  assert.equal(right.res.status, 429, 'locked out from this address for the window, even with the right password');
});
