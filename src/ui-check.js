#!/usr/bin/env node
/**
 * UI contract check
 * ─────────────────────────────────────────────────────────────────────────────
 * The three consoles are hand-written ES modules driving live DOM. Two classes
 * of bug account for nearly all breakage in that setup, and neither shows up in
 * a syntax check:
 *
 *   1. the script reaches for an element id the HTML does not define
 *      (or defines one nothing uses) — a silent null dereference on load;
 *   2. the script reads a response field the API does not actually return —
 *      a panel that renders empty or "undefined" with no error anywhere.
 *
 * This checks both: ids are cross-referenced statically between each page's
 * markup and its script, and every field path the UI depends on is asserted
 * against a live response from the running gateway.
 *
 * Run: ADMIN_PASSWORD=<platform admin password> node src/ui-check.js      (stack must be up)
 */

require('./local-env'); // .env, when run by hand
const fs = require('fs');
const path = require('path');
const http = require('http');

const GATEWAY = process.env.GATEWAY_URL || 'http://localhost:3000';
const ADMIN = { username: process.env.ADMIN_USERNAME || 'admin', password: process.env.ADMIN_PASSWORD };

if (!ADMIN.password) {
  console.error('ADMIN_PASSWORD is not set. Run as:  ADMIN_PASSWORD=<platform admin password> npm run check:ui   (or put it in .env)');
  process.exit(1);
}

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
};

const failures = [];
const notes = [];
function check(label, condition, detail) {
  if (condition) {
    console.log(`  ${C.green}✅${C.reset} ${label}`);
  } else {
    console.log(`  ${C.red}❌${C.reset} ${label}`);
    if (detail) console.log(`     ${C.red}${detail}${C.reset}`);
    failures.push({ label, detail });
  }
}

// ─── HTTP ────────────────────────────────────────────────────────────────────

function request(method, url, { body, token } = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const req = http.request({
      hostname: u.hostname, port: u.port, path: u.pathname + u.search, method,
      headers: {
        'Content-Type': 'application/json',
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        let parsed = raw;
        try { parsed = JSON.parse(raw); } catch { /* not json */ }
        resolve({ status: res.statusCode, body: parsed, raw });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

// ─── 1. STATIC: element ids ──────────────────────────────────────────────────

const PAGES = [
  { name: 'console', file: 'public/console.html' },
];

function auditIds() {
  console.log(`\n${C.bold}${C.cyan}── Element ids: markup vs script ──────────────────────────${C.reset}`);

  for (const page of PAGES) {
    const html = fs.readFileSync(path.join(__dirname, page.file), 'utf8');
    const script = (html.match(/<script type="module">([\s\S]*?)<\/script>/) || [, ''])[1];
    const markup = html.replace(/<script type="module">[\s\S]*?<\/script>/, '');

    const defined = new Set([...markup.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
    const referenced = new Set([
      ...script.matchAll(/\$\('([^']+)'\)/g),
      ...script.matchAll(/getElementById\('([^']+)'\)/g),
    ].map((m) => m[1]));

    // Ids the shared modules or this page's own render functions create at
    // runtime, so they are legitimately absent from the static markup.
    const runtime = new Set(['banners', 'test-backdrop', 'out', 'own-picker']);

    const missing = [...referenced].filter((id) => !defined.has(id) && !runtime.has(id));
    check(`${page.name}: every id the script reaches for exists in its markup`,
      missing.length === 0,
      missing.length ? `script references ids that are never defined: ${missing.join(', ')}` : '');

    const unused = [...defined].filter((id) => !referenced.has(id));
    if (unused.length) {
      notes.push(`${page.name}: ids defined but not referenced by \`$()\` (may be styled or queried another way): ${unused.join(', ')}`);
    }
  }
}

// ─── 2. STATIC: API paths the UI calls ───────────────────────────────────────

function routeTable() {
  const src = fs.readFileSync(path.join(__dirname, 'main.reg.js'), 'utf8');
  const routes = [];
  const re = /app\.(get|post|put|patch|delete|use)\(\s*'([^']+)'/g;
  let m;
  while ((m = re.exec(src)) !== null) routes.push({ method: m[1].toUpperCase(), path: m[2] });
  return routes;
}

/**
 * Pulls the literal path out of every `api(...)` / `fetch(...)` call.
 *
 * A regex cannot do this: the paths are template literals that themselves
 * contain template literals inside `${...}` (the `?status=` suffixes), so
 * matching to the next backtick stops in the wrong place. This walks the
 * literal instead, tracking `${}` depth, and collapses each interpolation to
 * a single wildcard segment.
 */
function extractCallPaths(src) {
  const paths = [];
  const re = /\b(?:api|fetch)\(\s*([`'])/g;
  let m;
  while ((m = re.exec(src)) !== null) {
    const quote = m[1];
    let i = m.index + m[0].length;
    let depth = 0;
    let out = '';
    for (; i < src.length; i++) {
      const ch = src[i];
      if (ch === '\\') { i++; continue; }
      if (depth === 0 && ch === quote) break;
      if (quote === '`' && ch === '$' && src[i + 1] === '{') { depth++; i++; out += 'X'; continue; }
      if (depth > 0) {
        if (ch === '{') depth++;
        else if (ch === '}') depth--;
        continue;              // everything inside ${...} is already an 'X'
      }
      out += ch;
    }
    if (!out.startsWith('/')) continue;
    // A wildcard glued to the end of a segment is a suffix the call builds at
    // runtime — `/admin/requests${f ? '?status=…' : ''}` — not a path segment
    // of its own. One preceded by '/' is a real segment and must stay.
    out = out.replace(/([^/])X+$/, '$1').split('?')[0];
    paths.push(out);
  }
  return paths;
}

/** Does a concrete request path match a route pattern with :params? */
function matchesRoute(routePath, actual) {
  const rx = new RegExp(`^${routePath.replace(/:[^/]+/g, '[^/]+').replace(/\//g, '\\/')}(\\/|$)`);
  return rx.test(actual);
}

function auditApiPaths() {
  console.log(`\n${C.bold}${C.cyan}── API paths the UI calls ─────────────────────────────────${C.reset}`);
  const routes = routeTable();

  const sources = [
    ...PAGES.map((p) => ({ name: p.name, src: fs.readFileSync(path.join(__dirname, p.file), 'utf8') })),
    { name: 'tenant-panel.js', src: fs.readFileSync(path.join(__dirname, 'public/assets/tenant-panel.js'), 'utf8') },
  ];

  for (const { name, src } of sources) {
    const called = new Set();
    for (const raw of extractCallPaths(src)) called.add(raw);

    const unknown = [...called].filter((p) => !routes.some((r) => matchesRoute(r.path, p)));

    check(`${name}: every path it calls exists in the gateway route table`,
      unknown.length === 0,
      unknown.length ? `no such route: ${unknown.join(', ')}` : '');
  }
}

// ─── 3. LIVE: response shapes the UI depends on ──────────────────────────────

/**
 * Reads a dotted field path against a response.
 *
 *   `items[].name`   every element of `items` must have `name`
 *   `service?.host`  `service` may be null — if it is, the rest is not required
 *
 * Arrays are checked element by element rather than only at index 0: a field
 * present on the first row and missing on the rest is a real rendering bug,
 * and sampling one row would miss it.
 */
function readPath(obj, spec) {
  const parts = spec.split('.');

  function walk(cur, idx) {
    if (idx === parts.length) return { ok: true };
    let part = parts[idx];

    const nullable = part.endsWith('?');
    if (nullable) part = part.slice(0, -1);

    const isArray = part.endsWith('[]');
    if (isArray) part = part.slice(0, -2);

    if (cur === undefined || cur === null) {
      return nullable ? { ok: true } : { ok: false, reason: 'parent missing' };
    }
    if (part && !(part in cur)) return { ok: false, reason: `missing '${part}'` };

    const value = part ? cur[part] : cur;
    if (value === null || value === undefined) {
      // A nullable leaf, or a nullable parent whose children are then moot.
      if (nullable || idx === parts.length - 1) return { ok: true };
      return { ok: false, reason: `'${part}' is null` };
    }

    if (isArray) {
      if (!Array.isArray(value)) return { ok: false, reason: `'${part}' is not an array` };
      if (value.length === 0) return { ok: true, empty: true };
      for (let i = 0; i < value.length; i++) {
        const r = walk(value[i], idx + 1);
        if (!r.ok) return { ok: false, reason: `${r.reason} (element ${i})` };
      }
      return { ok: true };
    }
    return walk(value, idx + 1);
  }

  return walk(obj, 0);
}

async function auditShapes() {
  console.log(`\n${C.bold}${C.cyan}── Live response shapes ───────────────────────────────────${C.reset}`);

  const login = await request('POST', `${GATEWAY}/auth/login`, { body: ADMIN });
  if (login.status !== 200) {
    check('admin login (prerequisite)', false, `got ${login.status} — is the stack up?`);
    return;
  }
  const token = login.body.token;

  // Stand up a tenant with a role, a policy and a member so the shapes below
  // are exercised with real content rather than empty arrays.
  const id = `uicheck${Math.floor(Math.random() * 100000)}`;
  const user = `uicheck_user_${Math.floor(Math.random() * 100000)}`;
  await request('POST', `${GATEWAY}/auth/signup`, { body: { username: user, password: 'uicheckpass1' } });
  await request('POST', `${GATEWAY}/admin/tenants`, {
    token,
    body: { id, displayName: 'UI Check', baseUrl: 'http://localhost:9899', endpoints: [`/${id}/alpha`], owner: user },
  });
  await request('POST', `${GATEWAY}/tenants/${id}/roles`, { token, body: { role: 'checker' } });
  await request('POST', `${GATEWAY}/tenants/${id}/policies`, {
    token, body: { role: 'checker', resource: `/${id}/alpha`, action: 'get' },
  });
  await request('POST', `${GATEWAY}/tenants/${id}/users/${user}/roles`, { token, body: { role: 'checker' } });
  // A pending request needs someone who does NOT already hold the role —
  // otherwise POST /requests 409s and the requests[] shape is never exercised.
  const asker = `uicheck_asker_${Math.floor(Math.random() * 100000)}`;
  await request('POST', `${GATEWAY}/auth/signup`, { body: { username: asker, password: 'uicheckpass1' } });
  const askerLogin = await request('POST', `${GATEWAY}/auth/login`, { body: { username: asker, password: 'uicheckpass1' } });
  await request('POST', `${GATEWAY}/requests`, {
    token: askerLogin.body.token,
    body: { tenant: id, role: 'checker', note: 'ui-check' },
  });

  // What each console reads out of each response. This is the contract; if the
  // API stops returning one of these, a panel silently renders blank.
  const contracts = [
    ['GET', '/me', ['username', 'role', 'isPlatformAdmin', 'tenants[].id', 'tenants[].displayName', 'tenants[].roles', 'tenants[].isAdmin']],
    ['GET', '/admin/tenants', ['count', 'tenants[].id', 'tenants[].displayName', 'tenants[].owner', 'tenants[].status',
      'tenants[].roles', 'tenants[].admins', 'tenants[].memberCount',
      // A tenant may legitimately exist before its service does, so the whole
      // service object is nullable — the panel renders "no service" for it.
      'tenants[].service?.baseUrl', 'tenants[].service?.catalogUrl', 'tenants[].service?.health',
      'tenants[].service?.version', 'tenants[].service?.endpoints']],
    ['GET', `/tenants/${id}`, ['id', 'displayName', 'owner', 'status', 'isAdmin', 'roles', 'admins', 'memberCount',
      'service?.baseUrl', 'service?.catalogUrl', 'service?.version', 'service?.health', 'service?.endpoints']],
    ['GET', `/tenants/${id}/roles`, ['tenant', 'roles[].role', 'roles[].members', 'roles[].policies']],
    ['GET', `/tenants/${id}/policies`, ['tenant', 'policies[].role', 'policies[].resource', 'policies[].action']],
    ['GET', `/tenants/${id}/users`, ['tenant', 'users[].username', 'users[].roles', 'users[].isAdmin']],
    ['GET', `/tenants/${id}/requests`, ['tenant', 'requests[].id', 'requests[].username', 'requests[].status', 'requests[].requestedAt']],
    ['GET', '/tenants/mine', ['tenants[].id', 'tenants[].displayName', 'tenants[].roles', 'tenants[].isAdmin']],
    ['GET', '/catalog/services', ['services[].name', 'services[].endpoints', 'services[].tenant.id',
      'services[].tenant.displayName', 'services[].tenant.roles', 'services[].tenant.joined']],
    ['GET', '/catalog/roles', ['roles']],
    ['GET', '/requests/me', ['requests']],
    ['GET', '/admin/users', ['users[].username', 'users[].role', 'users[].status', 'users[].roles']],
    ['GET', '/admin/roles', ['roles[].role', 'roles[].users']],
    ['GET', '/admin/policies', ['policies[].subject', 'policies[].resource', 'policies[].action']],
    ['GET', '/admin/requests', ['requests']],
  ];

  for (const [method, p, fields] of contracts) {
    const res = await request(method, `${GATEWAY}${p}`, { token });
    if (res.status !== 200) {
      check(`${method} ${p}`, false, `HTTP ${res.status}`);
      continue;
    }
    const bad = fields
      .map((f) => ({ f, r: readPath(res.body, f) }))
      .filter((x) => !x.r.ok);
    const empty = fields
      .map((f) => ({ f, r: readPath(res.body, f) }))
      .filter((x) => x.r.ok && x.r.empty);

    check(`${method} ${p} returns every field the UI reads`,
      bad.length === 0,
      bad.map((x) => `${x.f} (${x.r.reason})`).join(', '));
    if (empty.length) notes.push(`${method} ${p}: ${empty.map((x) => x.f).join(', ')} were empty arrays — shape not exercised`);
  }

  // The access-test inspector renders far more than a status code, so its
  // shape is checked field by field — a missing field here renders a blank
  // panel with nothing in the console to explain it. There are two shapes,
  // because there are two kinds of test (see assets/access-test.js).
  const sharedFields = [
    'username', 'testedAt', 'mode',
    'services[].service', 'services[].allowedCount', 'services[].totalCount',
    'services[].endpoints[].endpoint', 'services[].endpoints[].decision',
  ];
  // Testing yourself: a real call with your own token, so the whole exchange.
  const liveCallFields = [
    ...sharedFields,
    'token.value', 'token.header', 'token.claims', 'token.note',
    'services[].endpoints[].status', 'services[].endpoints[].latencyMs',
    'services[].endpoints[].request.method', 'services[].endpoints[].request.url',
    'services[].endpoints[].request.headers',
    'services[].endpoints[].response?.status', 'services[].endpoints[].response?.headers',
  ];
  // Testing someone else: the gateway's decision only — nothing was sent.
  const evaluationFields = [...sharedFields, 'note'];

  for (const [label, path_, fields, mode] of [
    ['POST /tenants/:id/users/:u/test-access', `/tenants/${id}/users/${user}/test-access`,
      [...evaluationFields, 'tenant', 'roles'], 'policy-evaluation'],
    ['POST /admin/users/:u/test-access', `/admin/users/${user}/test-access`,
      [...evaluationFields, 'roles'], 'policy-evaluation'],
    ['POST /me/test-access', '/me/test-access', [...liveCallFields, 'roles', 'tenants'], 'live-call'],
  ]) {
    const res = await request('POST', `${GATEWAY}${path_}`, { token });
    if (res.status !== 200) { check(label, false, `HTTP ${res.status}`); continue; }
    const bad = fields
      .map((f) => ({ f, r: readPath(res.body, f) }))
      .filter((x) => !x.r.ok);
    check(`${label} returns everything the inspector renders`,
      bad.length === 0, bad.map((x) => `${x.f} (${x.r.reason})`).join(', '));
    check(`${label} declares mode '${mode}', which picks the inspector's renderer`,
      res.body.mode === mode, `mode=${res.body.mode}`);
  }

  await request('DELETE', `${GATEWAY}/admin/tenants/${id}?deregister=true`, { token });
  await request('DELETE', `${GATEWAY}/admin/users/${user}`, { token });
  await request('DELETE', `${GATEWAY}/admin/users/${asker}`, { token });
}

// ─── 4b. UNIT: the render helpers that produce clickable data ────────────────

/**
 * `chips()` builds remove buttons, and a remove button usually needs two
 * pieces of data — whose chip is this, and which chip. They shipped as
 * `data-user` and a generic `data-value`, and the handler read
 * `dataset.user || dataset.value`: with both present that always picks the
 * user, so "remove role engineer from alice" sent alice as the role and the
 * server correctly answered "alice does not have role alice".
 *
 * These are pure string functions, so the exact markup can be asserted
 * directly rather than inferred from a click.
 */
async function auditRenderHelpers() {
  console.log(`\n${C.bold}${C.cyan}── Chip markup carries unambiguous data ───────────────────${C.reset}`);

  const appJs = fs.readFileSync(path.join(__dirname, 'public/assets/app.js'), 'utf8');
  const { chips } = await import(`data:text/javascript;base64,${Buffer.from(appJs).toString('base64')}`);

  const html = chips(['engineer', 'persian_res'], {
    removable: true,
    data: { act: 'revoke', user: 'mex@gmail.com' },
    valueAttr: 'role',
  });

  check('a removable chip carries the subject and the value under DIFFERENT names',
    /data-user="mex@gmail\.com"/.test(html) && /data-role="engineer"/.test(html),
    `markup was: ${html.slice(0, 220)}`);

  check('the chip value is the role, never the username',
    !/data-role="mex@gmail\.com"/.test(html) && !/data-user="engineer"/.test(html),
    'the two values are crossed over');

  check('each chip carries its own value',
    /data-role="engineer"/.test(html) && /data-role="persian_res"/.test(html),
    'a chip is missing its own value');

  check('the username is HTML-escaped in the markup',
    chips(['x'], { removable: true, data: { user: '<img src=x>' }, valueAttr: 'role' })
      .includes('&lt;img src=x&gt;'),
    'a username is interpolated raw into the button');

  // And the handler must read that named attribute, not fall back to a
  // generic one — the fallback is what made the two interchangeable.
  const panel = fs.readFileSync(path.join(__dirname, 'public/assets/tenant-panel.js'), 'utf8');
  check('the revoke handler reads the role from its own named attribute',
    /const role = btn\.dataset\.role/.test(panel)
      && !/btn\.dataset\.user \|\| btn\.dataset\.value/.test(panel),
    'the handler still collapses subject and value into one variable');
}

// ─── 5b. LIVE: an access test must not create a credential for someone else ──

/**
 * Testing another account's access used to mint a short-lived token for them
 * and replay it through the proxy. The copy in the response was masked, but
 * the real one still went to every upstream service on the way — including a
 * service operated by the very tenant admin running the test — and it was
 * good for everything that account could do anywhere. So an admin-run test
 * now involves no token at all, and this proves it: nothing token-shaped comes
 * back, and nothing the report does contain authenticates.
 */
async function auditTokenExposure() {
  console.log(`\n${C.bold}${C.cyan}── Access test does not create a token for anyone else ────${C.reset}`);

  const admin = (await request('POST', `${GATEWAY}/auth/login`, { body: ADMIN })).body.token;
  const rand = Math.floor(Math.random() * 100000);
  const victim = `uicheck_victim_${rand}`;
  await request('POST', `${GATEWAY}/auth/signup`, { body: { username: victim, password: 'uicheckpass1' } });
  await request('POST', `${GATEWAY}/admin/roles`, { token: admin, body: { username: victim, role: 'green_role' } });

  const probe = await request('POST', `${GATEWAY}/admin/users/${victim}/test-access`, { token: admin });
  const report = JSON.stringify(probe.body ?? {});

  check('an admin testing someone else gets no token field at all',
    probe.status === 200 && !('token' in (probe.body || {})),
    `status=${probe.status}, token=${JSON.stringify(probe.body?.token)}`);

  check('nothing shaped like a JWT appears anywhere in the report',
    !/eyJ[\w-]+\.[\w-]+\.[\w-]+/.test(report),
    'the report contains a JWT');

  check('no request or response was recorded, because none was made',
    (probe.body?.services || []).every((s) => s.endpoints.every((e) => !('request' in e) && !('response' in e))),
    'an endpoint result carries a request/response — something was sent on the user\'s behalf');

  check('the report still explains each decision, so a denial can be debugged',
    (probe.body?.services || []).flatMap((s) => s.endpoints).every((e) =>
      (e.decision === 'allowed' ? Boolean(e.grantedBy) : typeof e.explanation === 'string')),
    'an endpoint result has neither grantedBy nor an explanation');

  // Testing yourself is different: it is your own session token, already in
  // your browser, and replaying it is just making the call you would make.
  const victimToken = (await request('POST', `${GATEWAY}/auth/login`,
    { body: { username: victim, password: 'uicheckpass1' } })).body.token;
  const selfProbe = await request('POST', `${GATEWAY}/me/test-access`, { token: victimToken });
  check('testing your own access shows your own token — the one you sent, not a new one',
    selfProbe.body?.token?.value === victimToken,
    'self-test returned a token other than the caller\'s own');

  check('a self-test reports the caller, not whoever they asked about',
    selfProbe.body?.username === victim, `got ${selfProbe.body?.username}`);

  await request('DELETE', `${GATEWAY}/admin/users/${victim}`, { token: admin });
}

// ─── 5. LIVE: the right account sees the right console ───────────────────────

/**
 * One sign-in serves three audiences, so the interesting question is not "does
 * the admin see the platform console" but "does a plain member see ONLY their
 * own access". This exercises the real `entitledViews` the page imports —
 * against three real accounts and their live /me + /tenants/mine responses —
 * rather than a copy of the rule that could drift from it.
 *
 * Note what this does and does not prove: it is about what is *rendered*.
 * Authorisation itself is server-side on every endpoint, and the e2e suite
 * covers that; a tampered client gets an empty, 403-ing shell.
 */
async function auditEntitlement() {
  console.log(`\n${C.bold}${C.cyan}── Who sees which console ─────────────────────────────────${C.reset}`);

  const appJs = fs.readFileSync(path.join(__dirname, 'public/assets/app.js'), 'utf8');
  const mod = await import(`data:text/javascript;base64,${Buffer.from(appJs).toString('base64')}`);
  const { entitledViews, defaultView } = mod;

  const admin = (await request('POST', `${GATEWAY}/auth/login`, { body: ADMIN })).body.token;

  // A plain member, and an owner of one tenant.
  const rand = Math.floor(Math.random() * 100000);
  const member = `uicheck_member_${rand}`;
  const owner = `uicheck_owner_${rand}`;
  const tenantId = `uicheckent${rand}`;
  const pw = 'uicheckpass1';
  const tokens = {};
  for (const u of [member, owner]) {
    await request('POST', `${GATEWAY}/auth/signup`, { body: { username: u, password: pw } });
    tokens[u] = (await request('POST', `${GATEWAY}/auth/login`, { body: { username: u, password: pw } })).body.token;
  }
  await request('POST', `${GATEWAY}/tenants/register`, {
    token: tokens[owner],
    body: { name: tenantId, baseUrl: 'http://localhost:9897', endpoints: [`/${tenantId}/x`] },
  });

  const cases = [
    { who: 'the platform admin', token: admin, expect: ['access', 'platform'], lands: 'platform' },
    { who: 'a service owner', token: tokens[owner], expect: ['access', 'services'], lands: 'services' },
    { who: 'a plain member', token: tokens[member], expect: ['access'], lands: 'access' },
  ];

  for (const c of cases) {
    const me = (await request('GET', `${GATEWAY}/me`, { token: c.token })).body;
    const mine = (await request('GET', `${GATEWAY}/tenants/mine`, { token: c.token })).body;
    const ids = entitledViews(me, mine.tenants).map((v) => v.id);

    check(`${c.who} sees exactly [${c.expect.join(', ')}]`,
      ids.length === c.expect.length && c.expect.every((v, i) => ids[i] === v),
      `got [${ids.join(', ')}]`);
    check(`${c.who} lands on '${c.lands}'`,
      defaultView(entitledViews(me, mine.tenants)) === c.lands,
      `landed on '${defaultView(entitledViews(me, mine.tenants))}'`);
  }

  // The rule must not be fooled by a tampered client object either — a member
  // who forges isPlatformAdmin locally still gets a shell with no data, but
  // the rule itself should key off nothing but the server's answer.
  const forged = entitledViews({ isPlatformAdmin: false }, [{ isAdmin: false }, { isAdmin: false }]);
  check('membership without admin rights grants no extra console',
    forged.length === 1 && forged[0].id === 'access',
    `got [${forged.map((v) => v.id).join(', ')}]`);

  await request('DELETE', `${GATEWAY}/admin/tenants/${tenantId}?deregister=true`, { token: admin });
  for (const u of [member, owner]) {
    await request('DELETE', `${GATEWAY}/admin/users/${u}`, { token: admin });
  }
}

// ─── 4. STATIC: shared assets are referenced consistently ────────────────────

/**
 * Every "show this after sign-in" element in the console is toggled with the
 * `hidden` attribute. The browser's own `[hidden] { display: none }` is an
 * element-less rule with no !important, so ANY author rule that sets `display`
 * — `main { display: flex }` is enough — outruns it and the element renders
 * anyway. That shipped once: the whole platform console painted before anyone
 * had signed in. A stylesheet-level `!important` reset is the only thing that
 * reliably wins, so assert it exists rather than trusting it to stay.
 */
function auditHiddenAttribute() {
  console.log(`\n${C.bold}${C.cyan}── Pre-auth concealment ───────────────────────────────────${C.reset}`);
  const css = fs.readFileSync(path.join(__dirname, 'public/assets/theme.css'), 'utf8');

  const resetRule = /\[hidden\]\s*\{[^}]*display\s*:\s*none\s*!important/.test(css);
  check('stylesheet forces [hidden] to display:none !important',
    resetRule,
    'without it, any rule setting `display` makes a hidden element render — the console '
    + 'would paint before sign-in');

  for (const page of PAGES) {
    const html = fs.readFileSync(path.join(__dirname, page.file), 'utf8');
    const markup = html.replace(/<script type="module">[\s\S]*?<\/script>/, '');

    // The panels must start hidden in the markup itself, not be hidden by a
    // script that has not run yet.
    check(`${page.name}: <main> starts hidden in the markup`,
      /<main[^>]*\shidden[^>]*>/.test(markup),
      'the app container is not marked hidden, so it shows before sign-in');

    check(`${page.name}: the sign-in card starts visible`,
      /id="auth"(?![^>]*\shidden)/.test(markup),
      'the auth card is hidden in markup, so a logged-out visitor sees nothing at all');

    // Each privileged view must be independently hidden, so a stale token or a
    // failed /me never leaves one of them on screen.
    for (const view of ['view-access', 'view-services', 'view-platform']) {
      check(`${page.name}: #${view} starts hidden`,
        new RegExp(`id="${view}"[^>]*\\shidden`).test(markup),
        `#${view} is not hidden in markup`);
    }
  }
}

function auditAssets() {
  console.log(`\n${C.bold}${C.cyan}── Shared assets ──────────────────────────────────────────${C.reset}`);
  for (const page of PAGES) {
    const html = fs.readFileSync(path.join(__dirname, page.file), 'utf8');
    check(`${page.name} uses the shared stylesheet`,
      html.includes('/assets/theme.css'),
      'no <link> to /assets/theme.css — it will render unstyled');
    check(`${page.name} has no leftover inline <style> block`,
      !/<style>/.test(html),
      'an inline <style> block survives; the design system should be the single source');
  }
  for (const f of ['public/assets/theme.css', 'public/assets/app.js', 'public/assets/tenant-panel.js']) {
    check(`${f} exists`, fs.existsSync(path.join(__dirname, f)));
  }
}

// ─── RUN ─────────────────────────────────────────────────────────────────────

(async () => {
  console.log(`\n${C.bold}UI contract check${C.reset} ${C.dim}— ${GATEWAY}${C.reset}`);
  auditIds();
  auditApiPaths();
  auditHiddenAttribute();
  auditAssets();
  await auditRenderHelpers();
  await auditShapes();
  await auditTokenExposure();
  await auditEntitlement();

  if (notes.length) {
    console.log(`\n${C.bold}${C.cyan}── Notes ──────────────────────────────────────────────────${C.reset}`);
    notes.forEach((n) => console.log(`  ${C.dim}· ${n}${C.reset}`));
  }

  console.log(`\n${C.bold}${failures.length ? C.red : C.green}  ${failures.length} failure(s)${C.reset}\n`);
  process.exit(failures.length ? 1 : 0);
})().catch((e) => {
  console.error(`${C.red}ui-check crashed: ${e.stack}${C.reset}`);
  process.exit(1);
});
