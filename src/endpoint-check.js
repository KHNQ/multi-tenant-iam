#!/usr/bin/env node
/**
 * Endpoint coverage check
 * ─────────────────────────────────────────────────────────────────────────────
 * Answers one question honestly: "does every endpoint this system defines
 * actually work right now?"
 *
 * It does NOT work from a hand-maintained list of endpoints — that is exactly
 * the list that goes stale and lets a broken route sit unnoticed. Instead it
 *
 *   1. parses the route table straight out of the source (every `app.get(...)`,
 *      `app.post(...)`, ... in main.reg.js and registery.js),
 *   2. probes each route with a realistic, correctly-authorised request,
 *   3. fails loudly on any route it parsed but has no probe for.
 *
 * So adding a route to the gateway without adding a probe here is itself a
 * reported failure, and the coverage number cannot quietly drift.
 *
 * Prerequisites: the whole stack up (./start.sh).
 * Run: ADMIN_PASSWORD=<platform admin password> node src/endpoint-check.js
 */

require('./local-env'); // .env, when run by hand
const fs = require('fs');
const path = require('path');
const http = require('http');
const { randomUUID, randomBytes, createHash } = require('crypto');

const GATEWAY = process.env.GATEWAY_URL || 'http://localhost:3000';
const REGISTRY = process.env.REGISTRY_URL || 'http://localhost:3001';
const ADMIN = { username: process.env.ADMIN_USERNAME || 'admin', password: process.env.ADMIN_PASSWORD };

// What the registry was started with; needed to register the throwaway service
// the registry probes use (it creates records only for authenticated callers).
const ENROLLMENT_TOKEN = process.env.REGISTRY_ENROLLMENT_TOKEN;

if (!ADMIN.password) {
  console.error('ADMIN_PASSWORD is not set. Run as:  ADMIN_PASSWORD=<platform admin password> npm run check:endpoints   (or put it in .env)');
  process.exit(1);
}
if (!ENROLLMENT_TOKEN) {
  console.error('REGISTRY_ENROLLMENT_TOKEN is not set. It is the value the registry was started with — normally in .env, which this check reads.');
  process.exit(1);
}

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
};

// ─── HTTP ────────────────────────────────────────────────────────────────────

function request(method, url, { body, form, token, headers = {}, timeout = 8000 } = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    // `form` sends application/x-www-form-urlencoded — what the OIDC endpoints take.
    const payload = form ? new URLSearchParams(form).toString()
      : body === undefined ? undefined : JSON.stringify(body);

    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'Content-Type': form ? 'application/x-www-form-urlencoded' : 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
    }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        let parsedBody = raw;
        try { parsedBody = JSON.parse(raw); } catch { /* not json */ }
        resolve({ status: res.statusCode, body: parsedBody, raw, headers: res.headers });
      });
    });

    req.setTimeout(timeout, () => { req.destroy(new Error(`timeout after ${timeout}ms`)); });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ─── ROUTE INVENTORY (parsed from source) ────────────────────────────────────

/**
 * Pulls every route out of a source file. `app.use('/prefix', ...)` counts too
 * — /gateway/:serviceName is mounted that way and is the most important route
 * in the system.
 */
function parseRoutes(file, label) {
  const src = fs.readFileSync(path.join(__dirname, file), 'utf8');
  const re = /app\.(get|post|put|patch|delete|use)\(\s*'([^']+)'/g;
  const routes = new Set();
  let m;
  while ((m = re.exec(src)) !== null) {
    routes.add(`${m[1].toUpperCase()} ${m[2]}`);
  }
  return [...routes].sort().map((r) => ({ route: r, app: label }));
}

// ─── RESULTS ─────────────────────────────────────────────────────────────────

const results = [];
const covered = new Set();

/**
 * @param {string} route  the source route this probe covers, e.g. "GET /me"
 * @param {string} what   human description
 * @param {() => Promise<{status:number}>} fn
 * @param {number[]} expect acceptable status codes
 */
async function probe(route, what, fn, expect) {
  covered.add(route);
  try {
    const res = await fn();
    const ok = expect.includes(res.status);
    results.push({
      route, what, ok, status: res.status, expect,
      detail: ok ? '' : `expected ${expect.join('/')}, got ${res.status} ${JSON.stringify(res.body).slice(0, 160)}`,
    });
  } catch (err) {
    results.push({ route, what, ok: false, status: 'ERR', expect, detail: err.message });
  }
}

// ─── STATE ───────────────────────────────────────────────────────────────────

const S = {
  adminToken: null,
  ownerUser: null, ownerToken: null,
  memberUser: null, memberToken: null,
  outsiderUser: null, outsiderToken: null,
  tenantId: null,
  serviceUrl: null,
  requestId: null,
  platformRequestId: null,
  throwawayUser: null,
  // Cleaned up in teardown() — a check that silts the registry and tenant list
  // up a little more on every run stops being run.
  createdServices: [],
  createdTenants: [],
};

async function signupAndLogin(prefix) {
  const username = `${prefix}_${randomUUID().slice(0, 8)}`;
  const password = 'checkpass123';
  await request('POST', `${GATEWAY}/auth/signup`, { body: { username, password } });
  const login = await request('POST', `${GATEWAY}/auth/login`, { body: { username, password } });
  return { username, password, token: login.body.token };
}

/**
 * Taking access away from an account ends its sessions, so a probe that does
 * that has to sign the account back in before the next probe uses it.
 */
async function freshToken(username, password) {
  const login = await request('POST', `${GATEWAY}/auth/login`, { body: { username, password } });
  return login.body.token;
}

// A tiny stand-in service so the tenant under test has something real to
// front — a probe of /gateway that can only ever 502 proves nothing.
function startFixtureService(port, name) {
  const endpoints = [`/${name}/alpha`, `/${name}/beta`];
  const server = http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/catalog') {
      return res.end(JSON.stringify({ name, baseUrl: `http://localhost:${port}`, version: 'v1', owner: 'endpoint_check', endpoints }));
    }
    if (endpoints.includes(req.url)) return res.end(JSON.stringify({ source: name, path: req.url }));
    res.statusCode = 404;
    res.end(JSON.stringify({ error: 'not found' }));
  });
  return new Promise((resolve) => server.listen(port, () => resolve({ server, endpoints })));
}

// ─── PROBES ──────────────────────────────────────────────────────────────────

async function run() {
  console.log(`\n${C.bold}Endpoint check${C.reset} ${C.dim}— gateway ${GATEWAY}, registry ${REGISTRY}${C.reset}\n`);

  const port = 9400 + Math.floor(Math.random() * 90);
  const fixtureName = `epcheck${Math.floor(Math.random() * 100000)}`;
  const fixture = await startFixtureService(port, fixtureName);
  S.tenantId = fixtureName;
  S.serviceUrl = `http://localhost:${port}`;

  // ── auth ──────────────────────────────────────────────────────────────────
  await probe('POST /auth/signup', 'signup creates an account',
    () => request('POST', `${GATEWAY}/auth/signup`, { body: { username: `epc_${randomUUID().slice(0, 8)}`, password: 'checkpass123' } }), [201]);

  await probe('POST /auth/login', 'admin login',
    async () => {
      const res = await request('POST', `${GATEWAY}/auth/login`, { body: ADMIN });
      S.adminToken = res.body.token;
      return res;
    }, [200]);

  if (!S.adminToken) {
    console.error(`${C.red}Cannot continue: admin login failed.${C.reset}`);
    fixture.server.close();
    process.exit(1);
  }

  const owner = await signupAndLogin('epc_owner');
  const member = await signupAndLogin('epc_member');
  const outsider = await signupAndLogin('epc_outsider');
  Object.assign(S, {
    ownerUser: owner.username, ownerToken: owner.token,
    memberUser: member.username, memberToken: member.token, memberPassword: member.password,
    outsiderUser: outsider.username, outsiderToken: outsider.token,
  });

  // ── registry ──────────────────────────────────────────────────────────────
  await probe('GET /health', 'registry health',
    () => request('GET', `${REGISTRY}/health`), [200]);
  await probe('GET /services', 'registry service list',
    () => request('GET', `${REGISTRY}/services`), [200]);
  await probe('GET /services/:name', 'registry single service',
    () => request('GET', `${REGISTRY}/services/llm`), [200, 404]);
  await probe('POST /register', 'register a service with no reachable catalog (used to be a hard 502)',
    async () => {
      const name = `epcoffline${Math.floor(Math.random() * 100000)}`;
      S.createdTenants.push(name); // the gateway provisions a tenant for it on sync
      const res = await request('POST', `${REGISTRY}/register`, {
        body: { name, baseUrl: 'http://localhost:9999' }, headers: { 'X-Enrollment-Token': ENROLLMENT_TOKEN },
      });
      // Issued once. Without it this check could never clean the record up.
      S.createdServices.push({ name, token: res.body?.serviceToken });
      return res;
    }, [201]);
  await probe('POST /services/:name/heartbeat', 'a service renews its registration with its token',
    () => {
      const { name, token } = S.createdServices[0];
      return request('POST', `${REGISTRY}/services/${name}/heartbeat`, { headers: { 'X-Service-Token': token } });
    }, [200]);
  await probe('PATCH /services/:name', 'registry rejects a configuration edit with no service token',
    () => request('PATCH', `${REGISTRY}/services/llm`, { body: { version: 'nope' } }), [403, 404]);
  await probe('DELETE /services/:name', 'registry refuses to deregister a service for someone who does not own it',
    () => request('DELETE', `${REGISTRY}/services/${S.createdServices[0].name}`), [403]);
  await probe('GET /docs.json', 'registry OpenAPI spec',
    () => request('GET', `${REGISTRY}/docs.json`), [200]);
  await probe('USE /docs', 'registry swagger UI',
    () => request('GET', `${REGISTRY}/docs/`), [200, 301]);

  // ── tenant registration (the front door) ──────────────────────────────────
  await probe('POST /tenants/register', 'owner registers a service and becomes its tenant admin',
    () => request('POST', `${GATEWAY}/tenants/register`, {
      token: S.ownerToken,
      body: { name: S.tenantId, baseUrl: S.serviceUrl, catalogUrl: `${S.serviceUrl}/catalog`, displayName: 'Endpoint Check Service' },
    }), [201]);

  // ── tenant discovery ──────────────────────────────────────────────────────
  await probe('GET /tenants', 'tenant catalogue',
    () => request('GET', `${GATEWAY}/tenants`, { token: S.memberToken }), [200]);
  await probe('GET /tenants/mine', 'my tenants',
    () => request('GET', `${GATEWAY}/tenants/mine`, { token: S.ownerToken }), [200]);
  await probe('GET /tenants/:tenantId', 'tenant detail (as its admin)',
    () => request('GET', `${GATEWAY}/tenants/${S.tenantId}`, { token: S.ownerToken }), [200]);
  await probe('PATCH /tenants/:tenantId', 'tenant admin edits the tenant',
    () => request('PATCH', `${GATEWAY}/tenants/${S.tenantId}`, { token: S.ownerToken, body: { description: 'checked by endpoint-check' } }), [200]);

  // ── tenant roles ──────────────────────────────────────────────────────────
  await probe('POST /tenants/:tenantId/roles', 'define a tenant role',
    () => request('POST', `${GATEWAY}/tenants/${S.tenantId}/roles`, { token: S.ownerToken, body: { role: 'reader' } }), [201]);
  await probe('GET /tenants/:tenantId/roles', 'list tenant roles',
    () => request('GET', `${GATEWAY}/tenants/${S.tenantId}/roles`, { token: S.ownerToken }), [200]);

  // ── tenant policies ───────────────────────────────────────────────────────
  await probe('POST /tenants/:tenantId/policies', 'attach a policy inside the tenant',
    () => request('POST', `${GATEWAY}/tenants/${S.tenantId}/policies`, {
      token: S.ownerToken, body: { role: 'reader', resource: fixture.endpoints[0], action: 'get' },
    }), [201]);
  await probe('GET /tenants/:tenantId/policies', 'list tenant policies',
    () => request('GET', `${GATEWAY}/tenants/${S.tenantId}/policies`, { token: S.ownerToken }), [200]);

  // ── tenant users ──────────────────────────────────────────────────────────
  await probe('POST /tenants/:tenantId/users', 'add a member with a role',
    () => request('POST', `${GATEWAY}/tenants/${S.tenantId}/users`, {
      token: S.ownerToken, body: { username: S.memberUser, role: 'reader' },
    }), [201]);
  await probe('GET /tenants/:tenantId/users', 'tenant tracks its users',
    () => request('GET', `${GATEWAY}/tenants/${S.tenantId}/users`, { token: S.ownerToken }), [200]);
  await probe('POST /tenants/:tenantId/users/:username/roles', 'grant a second role',
    async () => {
      await request('POST', `${GATEWAY}/tenants/${S.tenantId}/roles`, { token: S.ownerToken, body: { role: 'writer' } });
      return request('POST', `${GATEWAY}/tenants/${S.tenantId}/users/${S.memberUser}/roles`, { token: S.ownerToken, body: { role: 'writer' } });
    }, [200]);
  await probe('DELETE /tenants/:tenantId/users/:username/roles/:role', 'revoke a role',
    () => request('DELETE', `${GATEWAY}/tenants/${S.tenantId}/users/${S.memberUser}/roles/writer`, { token: S.ownerToken }), [200]);
  await probe('POST /tenants/:tenantId/users/:username/admin', 'promote a member to tenant admin',
    () => request('POST', `${GATEWAY}/tenants/${S.tenantId}/users/${S.memberUser}/admin`, { token: S.ownerToken }), [200]);
  await probe('DELETE /tenants/:tenantId/users/:username/admin', 'demote them again',
    () => request('DELETE', `${GATEWAY}/tenants/${S.tenantId}/users/${S.memberUser}/admin`, { token: S.ownerToken }), [200]);
  await probe('PUT /tenants/:tenantId/users/:username/permissions', 'delegate one part of administering the tenant, then take it back',
    async () => {
      const url = `${GATEWAY}/tenants/${S.tenantId}/users/${S.memberUser}/permissions`;
      const given = await request('PUT', url, { token: S.ownerToken, body: { permissions: ['policies'] } });
      if (given.status !== 200) return given;
      return request('PUT', url, { token: S.ownerToken, body: { permissions: [] } });
    }, [200]);
  // Revoking a role and removing admin rights both ended the member's sessions.
  S.memberToken = await freshToken(S.memberUser, S.memberPassword);
  await probe('POST /tenants/:tenantId/users/:username/test-access', 'tenant-scoped access test (evaluated, no token issued)',
    () => request('POST', `${GATEWAY}/tenants/${S.tenantId}/users/${S.memberUser}/test-access`, { token: S.ownerToken }), [200]);

  // ── the point of all of it: the proxy ─────────────────────────────────────
  await probe('USE /gateway/:serviceName', 'member reaches the tenant service through the gateway',
    () => request('GET', `${GATEWAY}/gateway${fixture.endpoints[0]}`, { token: S.memberToken }), [200]);

  // ── self-service ──────────────────────────────────────────────────────────
  await probe('GET /me', 'identity + per-tenant roles',
    () => request('GET', `${GATEWAY}/me`, { token: S.memberToken }), [200]);
  await probe('GET /catalog/services', 'service catalogue',
    () => request('GET', `${GATEWAY}/catalog/services`, { token: S.memberToken }), [200]);
  await probe('GET /catalog/roles', 'platform role catalogue',
    () => request('GET', `${GATEWAY}/catalog/roles`, { token: S.memberToken }), [200]);
  await probe('POST /requests', 'outsider requests a tenant role',
    async () => {
      const res = await request('POST', `${GATEWAY}/requests`, {
        token: S.outsiderToken, body: { tenant: S.tenantId, role: 'reader', note: 'endpoint-check' },
      });
      S.requestId = res.body?.request?.id;
      return res;
    }, [201]);
  await probe('GET /requests/me', 'my own requests',
    () => request('GET', `${GATEWAY}/requests/me`, { token: S.outsiderToken }), [200]);
  await probe('POST /me/test-access', 'a user tests their own access and sees the whole exchange',
    () => request('POST', `${GATEWAY}/me/test-access`, { token: S.memberToken }), [200]);

  // ── tenant request queue ──────────────────────────────────────────────────
  await probe('GET /tenants/:tenantId/requests', "the tenant's own request queue",
    () => request('GET', `${GATEWAY}/tenants/${S.tenantId}/requests?status=pending`, { token: S.ownerToken }), [200]);
  await probe('POST /tenants/:tenantId/requests/:id/approve', 'tenant admin approves a request',
    () => request('POST', `${GATEWAY}/tenants/${S.tenantId}/requests/${S.requestId}/approve`, { token: S.ownerToken, body: { role: 'reader' } }), [200]);
  await probe('POST /tenants/:tenantId/requests/:id/reject', 'tenant admin rejects a request',
    async () => {
      const made = await request('POST', `${GATEWAY}/requests`, {
        token: S.outsiderToken, body: { tenant: S.tenantId, service: S.tenantId, note: 'to be rejected' },
      });
      return request('POST', `${GATEWAY}/tenants/${S.tenantId}/requests/${made.body.request.id}/reject`, { token: S.ownerToken });
    }, [200]);

  // ── tenant service metadata ───────────────────────────────────────────────
  await probe('PATCH /tenants/:tenantId/service', 'tenant edits its own service metadata',
    () => request('PATCH', `${GATEWAY}/tenants/${S.tenantId}/service`, { token: S.ownerToken, body: { version: 'v1.1' } }), [200]);

  // ── session ───────────────────────────────────────────────────────────────
  await probe('POST /auth/change-password', 'self-service password change',
    async () => {
      const u = await signupAndLogin('epc_pwd');
      return request('POST', `${GATEWAY}/auth/change-password`, {
        token: u.token, body: { currentPassword: u.password, newPassword: 'checkpass456' },
      });
    }, [200]);
  await probe('POST /auth/logout', 'logout revokes the token',
    async () => {
      const u = await signupAndLogin('epc_out');
      return request('POST', `${GATEWAY}/auth/logout`, { token: u.token });
    }, [200]);
  await probe('POST /auth/logout-all', 'signing out everywhere ends every session of the account',
    async () => {
      const u = await signupAndLogin('epc_outall');
      const other = await freshToken(u.username, u.password);
      const res = await request('POST', `${GATEWAY}/auth/logout-all`, { token: u.token });
      if (res.status !== 200) return res;
      const after = await request('GET', `${GATEWAY}/me`, { token: other });
      return after.status === 401 ? res : { status: 500, body: { error: `the other session still answers ${after.status}` } };
    }, [200]);
  await probe('POST /auth/password-recovery', 'asking for recovery answers the same for any name',
    async () => {
      const real = await request('POST', `${GATEWAY}/auth/password-recovery`, { body: { username: S.memberUser } });
      const ghost = await request('POST', `${GATEWAY}/auth/password-recovery`, { body: { username: `epc_ghost_${randomUUID().slice(0, 8)}` } });
      if (real.status !== ghost.status || JSON.stringify(real.body) !== JSON.stringify(ghost.body)) {
        return { status: 500, body: { error: 'the answer differs between a real and an unknown account' } };
      }
      return real;
    }, [202]);

  // ── platform admin ────────────────────────────────────────────────────────
  await probe('GET /admin/users', 'platform user list',
    () => request('GET', `${GATEWAY}/admin/users`, { token: S.adminToken }), [200]);
  await probe('GET /admin/users/:username', 'single platform user',
    () => request('GET', `${GATEWAY}/admin/users/${S.memberUser}`, { token: S.adminToken }), [200]);
  await probe('GET /admin/roles', 'platform roles',
    () => request('GET', `${GATEWAY}/admin/roles`, { token: S.adminToken }), [200]);
  await probe('POST /admin/roles/define', 'define a platform role',
    () => request('POST', `${GATEWAY}/admin/roles/define`, { token: S.adminToken, body: { role: `epc_role_${randomUUID().slice(0, 6)}` } }), [201]);
  await probe('POST /admin/roles', 'assign a platform role',
    () => request('POST', `${GATEWAY}/admin/roles`, { token: S.adminToken, body: { username: S.memberUser, role: 'blue_role' } }), [200]);
  await probe('DELETE /admin/roles', 'revoke a platform role',
    () => request('DELETE', `${GATEWAY}/admin/roles`, { token: S.adminToken, body: { username: S.memberUser, role: 'blue_role' } }), [200]);
  await probe('GET /admin/policies', 'platform policies',
    () => request('GET', `${GATEWAY}/admin/policies`, { token: S.adminToken }), [200]);
  await probe('POST /admin/policies', 'add a platform policy',
    () => request('POST', `${GATEWAY}/admin/policies`, { token: S.adminToken, body: { subject: 'epc_subject', resource: '/epc/thing', action: 'get' } }), [200]);
  await probe('DELETE /admin/policies', 'remove a platform policy',
    () => request('DELETE', `${GATEWAY}/admin/policies`, { token: S.adminToken, body: { subject: 'epc_subject', resource: '/epc/thing', action: 'get' } }), [200]);
  await probe('GET /admin/services', 'registry view for admins',
    () => request('GET', `${GATEWAY}/admin/services`, { token: S.adminToken }), [200]);
  await probe('GET /admin/requests', 'platform request queue',
    () => request('GET', `${GATEWAY}/admin/requests`, { token: S.adminToken }), [200]);
  await probe('POST /admin/requests/:id/approve', 'platform admin approves a platform request',
    async () => {
      const u = await signupAndLogin('epc_req');
      const made = await request('POST', `${GATEWAY}/requests`, { token: u.token, body: { role: 'blue_role' } });
      return request('POST', `${GATEWAY}/admin/requests/${made.body.request.id}/approve`, { token: S.adminToken, body: { role: 'blue_role' } });
    }, [200]);
  await probe('POST /admin/requests/:id/reject', 'platform admin rejects a platform request',
    async () => {
      const u = await signupAndLogin('epc_rej');
      const made = await request('POST', `${GATEWAY}/requests`, { token: u.token, body: { role: 'green_role' } });
      return request('POST', `${GATEWAY}/admin/requests/${made.body.request.id}/reject`, { token: S.adminToken });
    }, [200]);
  await probe('POST /admin/users/:username/reset-password', 'admin force-resets a password',
    async () => {
      const u = await signupAndLogin('epc_reset');
      return request('POST', `${GATEWAY}/admin/users/${u.username}/reset-password`, { token: S.adminToken, body: { newPassword: 'checkpass789' } });
    }, [200]);
  await probe('POST /admin/users/:username/suspend', 'admin suspends an account',
    async () => {
      const u = await signupAndLogin('epc_susp');
      S.suspendedUser = u.username;
      return request('POST', `${GATEWAY}/admin/users/${u.username}/suspend`, { token: S.adminToken });
    }, [200]);
  await probe('POST /admin/users/:username/reactivate', 'admin reactivates it',
    async () => {
      const res = await request('POST', `${GATEWAY}/admin/users/${S.suspendedUser}/reactivate`, { token: S.adminToken });
      await request('DELETE', `${GATEWAY}/admin/users/${S.suspendedUser}`, { token: S.adminToken });
      return res;
    }, [200]);
  await probe('POST /admin/users/:username/revoke-sessions', 'admin ends every session of an account',
    async () => {
      const u = await signupAndLogin('epc_revoke');
      const res = await request('POST', `${GATEWAY}/admin/users/${u.username}/revoke-sessions`, { token: S.adminToken });
      if (res.status !== 200) return res;
      const after = await request('GET', `${GATEWAY}/me`, { token: u.token });
      return after.status === 401 ? res : { status: 500, body: { error: `the session still answers ${after.status}` } };
    }, [200]);
  await probe('POST /admin/users/:username/recovery-link', 'admin issues a one-time recovery link',
    async () => {
      const u = await signupAndLogin('epc_recover');
      S.recovering = u;
      const res = await request('POST', `${GATEWAY}/admin/users/${u.username}/recovery-link`, { token: S.adminToken });
      S.recoveryToken = res.status === 200 ? new URL(res.body.link).hash.replace('#recover=', '') : null;
      return res;
    }, [200]);
  await probe('POST /auth/password-recovery/complete', 'the link sets a new password once, and only once',
    async () => {
      const complete = () => request('POST', `${GATEWAY}/auth/password-recovery/complete`, {
        body: { token: S.recoveryToken, newPassword: 'recovered-pass-1' },
      });
      const first = await complete();
      if (first.status !== 200) return first;
      const again = await complete();
      if (again.status !== 400) return { status: 500, body: { error: `the same link worked twice (${again.status})` } };
      const login = await request('POST', `${GATEWAY}/auth/login`, { body: { username: S.recovering.username, password: 'recovered-pass-1' } });
      return login.status === 200 ? first : login;
    }, [200]);
  await probe('PUT /admin/users/:username/attributes', 'admin sets the attributes conditions are evaluated against',
    () => request('PUT', `${GATEWAY}/admin/users/${S.recovering.username}/attributes`, {
      token: S.adminToken, body: { attributes: { department: 'radiology', clearance: 2 } },
    }), [200]);
  await probe('POST /admin/users/:username/test-access', 'admin-wide access test',
    () => request('POST', `${GATEWAY}/admin/users/${S.memberUser}/test-access`, { token: S.adminToken }), [200]);
  await probe('DELETE /admin/users/:username', 'admin deletes an account',
    async () => {
      const u = await signupAndLogin('epc_doomed');
      return request('DELETE', `${GATEWAY}/admin/users/${u.username}`, { token: S.adminToken });
    }, [200]);

  // ── platform admin: tenants ───────────────────────────────────────────────
  await probe('GET /admin/tenants', 'all tenants',
    () => request('GET', `${GATEWAY}/admin/tenants`, { token: S.adminToken }), [200]);
  await probe('POST /admin/tenants', 'create a tenant AND register its service in one call',
    () => {
      const id = `epctenant${Math.floor(Math.random() * 100000)}`;
      S.createdTenants.push(id);
      return request('POST', `${GATEWAY}/admin/tenants`, {
        token: S.adminToken,
        body: {
          id, displayName: 'Created by endpoint-check',
          baseUrl: 'http://localhost:9998', endpoints: [`/${id}/thing`],
        },
      });
    }, [201]);
  await probe('POST /admin/tenants/:tenantId/owner', 'assign a tenant owner',
    async () => {
      const id = `epcowned${Math.floor(Math.random() * 100000)}`;
      S.createdTenants.push(id);
      await request('POST', `${GATEWAY}/admin/tenants`, { token: S.adminToken, body: { id } });
      return request('POST', `${GATEWAY}/admin/tenants/${id}/owner`, { token: S.adminToken, body: { username: S.ownerUser } });
    }, [200]);
  await probe('DELETE /admin/tenants/:tenantId', 'delete a tenant',
    async () => {
      const id = `epcdoomed${Math.floor(Math.random() * 100000)}`;
      await request('POST', `${GATEWAY}/admin/tenants`, { token: S.adminToken, body: { id } });
      return request('DELETE', `${GATEWAY}/admin/tenants/${id}`, { token: S.adminToken });
    }, [200]);

  // ── remaining tenant teardown routes ──────────────────────────────────────
  await probe('DELETE /tenants/:tenantId/policies', 'remove a tenant policy',
    () => request('DELETE', `${GATEWAY}/tenants/${S.tenantId}/policies`, {
      token: S.ownerToken, body: { role: 'reader', resource: fixture.endpoints[0], action: 'get' },
    }), [200]);
  await probe('DELETE /tenants/:tenantId/roles/:role', 'delete a tenant role',
    () => request('DELETE', `${GATEWAY}/tenants/${S.tenantId}/roles/writer`, { token: S.ownerToken }), [200]);
  await probe('DELETE /tenants/:tenantId/users/:username', 'remove a member',
    () => request('DELETE', `${GATEWAY}/tenants/${S.tenantId}/users/${S.memberUser}`, { token: S.ownerToken }), [200]);

  // ── OpenID Connect ────────────────────────────────────────────────────────
  // One sign-in, walked end to end: each probe is one step of the code flow.
  const oidc = { redirectUri: 'https://epcheck.example.test/callback' };
  const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
  oidc.verifier = b64url(randomBytes(48));
  oidc.challenge = b64url(createHash('sha256').update(oidc.verifier).digest());

  await probe('GET /.well-known/openid-configuration', 'discovery document',
    async () => {
      const res = await request('GET', `${GATEWAY}/.well-known/openid-configuration`);
      if (res.status === 200 && !(res.body.code_challenge_methods_supported || []).includes('S256')) {
        return { status: 500, body: { error: 'the provider does not advertise PKCE S256' } };
      }
      return res;
    }, [200]);
  await probe('GET /oauth/jwks', 'signing keys',
    async () => {
      const res = await request('GET', `${GATEWAY}/oauth/jwks`);
      // A private member in here would be the signing key itself.
      if (res.status === 200 && res.body.keys.some((k) => k.d || k.p || k.q)) {
        return { status: 500, body: { error: 'the JWKS document contains private key material' } };
      }
      return res;
    }, [200]);
  await probe('POST /admin/oidc/clients', 'admin registers an application',
    async () => {
      const res = await request('POST', `${GATEWAY}/admin/oidc/clients`, {
        token: S.adminToken, body: { name: 'Endpoint check', redirectUris: [oidc.redirectUri] },
      });
      oidc.clientId = res.body.client?.clientId;
      return res;
    }, [201]);
  await probe('GET /admin/oidc/clients', 'registered applications',
    () => request('GET', `${GATEWAY}/admin/oidc/clients`, { token: S.adminToken }), [200]);
  await probe('GET /oauth/authorize', 'the sign-in page for a registered application',
    async () => {
      const res = await request('GET', `${GATEWAY}/oauth/authorize?${new URLSearchParams({
        response_type: 'code', client_id: oidc.clientId, redirect_uri: oidc.redirectUri, scope: 'openid',
        state: 'epc-state', code_challenge: oidc.challenge, code_challenge_method: 'S256',
      })}`);
      oidc.request = (res.raw.match(/name="request" value="([^"]+)"/) || [])[1];
      return res;
    }, [200]);
  await probe('POST /oauth/authorize', 'signing in sends the browser back with a code',
    async () => {
      const res = await request('POST', `${GATEWAY}/oauth/authorize`, {
        form: { request: oidc.request, step: 'login', username: S.outsiderUser, password: 'checkpass123' },
      });
      oidc.code = res.headers.location ? new URL(res.headers.location).searchParams.get('code') : null;
      return res;
    }, [303]);
  await probe('POST /oauth/token', 'the code and its verifier are exchanged for tokens',
    async () => {
      const res = await request('POST', `${GATEWAY}/oauth/token`, {
        form: {
          grant_type: 'authorization_code', code: oidc.code, redirect_uri: oidc.redirectUri,
          client_id: oidc.clientId, code_verifier: oidc.verifier,
        },
      });
      oidc.accessToken = res.body.access_token;
      return res;
    }, [200]);
  await probe('GET /oauth/userinfo', 'who the access token belongs to',
    async () => {
      const res = await request('GET', `${GATEWAY}/oauth/userinfo`, { token: oidc.accessToken });
      if (res.status === 200 && res.body.preferred_username !== S.outsiderUser) {
        return { status: 500, body: { error: `userinfo names ${res.body.preferred_username}` } };
      }
      return res;
    }, [200]);
  await probe('DELETE /admin/oidc/clients/:clientId', 'admin removes the application',
    () => request('DELETE', `${GATEWAY}/admin/oidc/clients/${oidc.clientId}`, { token: S.adminToken }), [200]);

  // ── operations ────────────────────────────────────────────────────────────
  // Off unless the gateway was started with METRICS_TOKEN; either way it must
  // never answer someone who does not hold the token.
  await probe('GET /metrics', 'metrics are closed to anyone without the scrape token',
    async () => {
      const anonymous = await request('GET', `${GATEWAY}/metrics`);
      const asAdmin = await request('GET', `${GATEWAY}/metrics`, { token: S.adminToken });
      if (asAdmin.status === 200) return { status: 500, body: { error: 'an admin session was accepted as a scrape token' } };
      if (anonymous.status !== asAdmin.status) return asAdmin;
      if (!process.env.METRICS_TOKEN || anonymous.status === 404) return anonymous;
      const scraped = await request('GET', `${GATEWAY}/metrics`, { token: process.env.METRICS_TOKEN });
      if (scraped.status !== 200) return scraped;
      return scraped.raw.includes('iam_redis_up') ? anonymous : { status: 500, body: { error: 'the scrape has no iam_redis_up' } };
    }, [401, 404]);

  // ── docs + static UIs ─────────────────────────────────────────────────────
  await probe('GET /docs.json', 'gateway OpenAPI spec',
    () => request('GET', `${GATEWAY}/docs.json`), [200]);
  await probe('USE /docs', 'gateway swagger UI',
    () => request('GET', `${GATEWAY}/docs/`), [200, 301]);
  // One console, reachable from every entry point the system has ever had.
  const consoleProbe = (route, path_) => probe(route, `console is served at ${path_}`,
    async () => {
      const res = await request('GET', `${GATEWAY}${path_}`);
      // A 200 that is not the console means a static file is shadowing the route.
      if (res.status === 200 && !res.raw.includes('id="auth"')) {
        return { status: 500, body: { error: `${path_} served something that is not the console` } };
      }
      return res;
    }, [200]);

  await consoleProbe('GET /', '/');
  await consoleProbe('GET /console', '/console');
  await consoleProbe('GET /admin-ui', '/admin-ui');
  await consoleProbe('GET /admin-ui/admin.html', '/admin-ui/admin.html');
  await consoleProbe('GET /tenant-ui', '/tenant-ui');
  await consoleProbe('GET /tenant-ui/index.html', '/tenant-ui/index.html');
  await consoleProbe('GET /portal', '/portal');
  await consoleProbe('GET /portal/index.html', '/portal/index.html');
  await probe('USE /assets', 'shared theme + modules are served to the console',
    async () => {
      // One 404 here and every console renders unstyled or dead, with nothing
      // in the server log to say so.
      for (const file of ['theme.css', 'app.js', 'tenant-panel.js']) {
        const res = await request('GET', `${GATEWAY}/assets/${file}`);
        if (res.status !== 200) return res;
      }
      return { status: 200 };
    }, [200]);

  // ── cleanup ───────────────────────────────────────────────────────────────
  await teardown();
  fixture.server.close();

  report();
}

// ─── TEARDOWN ────────────────────────────────────────────────────────────────

/**
 * Removes every tenant and service this run created, including the accounts,
 * so the registry and tenant list look the same after the check as before it.
 */
async function teardown() {
  const tenants = [S.tenantId, ...S.createdTenants];
  for (const id of tenants) {
    await request('DELETE', `${GATEWAY}/admin/tenants/${encodeURIComponent(id)}?deregister=true`, { token: S.adminToken })
      .catch(() => {});
  }
  for (const { name, token } of S.createdServices) {
    await request('DELETE', `${REGISTRY}/services/${encodeURIComponent(name)}`, { headers: { 'X-Service-Token': token } })
      .catch(() => {});
  }
  for (const username of [S.ownerUser, S.memberUser, S.outsiderUser].filter(Boolean)) {
    await request('DELETE', `${GATEWAY}/admin/users/${encodeURIComponent(username)}`, { token: S.adminToken })
      .catch(() => {});
  }
}

// ─── REPORT ──────────────────────────────────────────────────────────────────

function report() {
  const inventory = [
    ...parseRoutes('main.reg.js', 'gateway'),
    ...parseRoutes('registery.js', 'registry'),
  ];
  // Both apps define GET /docs.json and USE /docs; one probe each covers both.
  const inventoryRoutes = [...new Set(inventory.map((i) => i.route))];
  const unprobed = inventoryRoutes.filter((r) => !covered.has(r));

  const passed = results.filter((r) => r.ok);
  const failed = results.filter((r) => !r.ok);

  console.log(`${C.bold}${C.cyan}── Results ────────────────────────────────────────────────${C.reset}`);
  for (const r of results) {
    const mark = r.ok ? `${C.green}✅${C.reset}` : `${C.red}❌${C.reset}`;
    console.log(`  ${mark} ${r.route.padEnd(48)} ${C.dim}${r.what}${C.reset}`);
    if (!r.ok) console.log(`     ${C.red}${r.detail}${C.reset}`);
  }

  console.log(`\n${C.bold}${C.cyan}── Route coverage ─────────────────────────────────────────${C.reset}`);
  console.log(`  ${inventoryRoutes.length} routes defined across main.reg.js + registery.js`);
  console.log(`  ${covered.size} probed`);
  if (unprobed.length) {
    console.log(`  ${C.red}${unprobed.length} route(s) defined but never probed — add a probe in src/endpoint-check.js:${C.reset}`);
    unprobed.forEach((r) => console.log(`     ${C.red}· ${r}${C.reset}`));
  } else {
    console.log(`  ${C.green}every defined route is probed${C.reset}`);
  }

  const allGood = failed.length === 0 && unprobed.length === 0;
  console.log(`\n${C.bold}${allGood ? C.green : C.red}` +
    `  ${passed.length} passed   ${failed.length} failed   ${unprobed.length} unprobed${C.reset}\n`);

  process.exit(allGood ? 0 : 1);
}

run().catch((err) => {
  console.error(`\n${C.red}Endpoint check crashed: ${err.stack}${C.reset}`);
  process.exit(1);
});
