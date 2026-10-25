/**
 * A stand-in for Keycloak's Admin REST API, serving the representations the
 * real one returns (field names, protocol mapper models and their config keys,
 * paging), for the realms the specification inventories: platform (the
 * console), samta (MapDashboard) and tenant-alpha (business-api, the React
 * and native samples, a service account). It can be taken down, or made to
 * fail on one path, to show that a failed sync changes nothing.
 */

const http = require('http');
const crypto = require('crypto');
const argon2 = require('argon2');

const uuid = () => crypto.randomUUID();

// ── Keycloak's built-in client scopes, as it represents them ───────────────

const pm = (name, protocolMapper, config) => ({ id: uuid(), name, protocol: 'openid-connect', protocolMapper, config });
const claims = (claim, extra = {}) => ({
  'claim.name': claim, 'access.token.claim': 'true', 'id.token.claim': 'true', 'userinfo.token.claim': 'true', 'introspection.token.claim': 'true', ...extra,
});

function standardScopes() {
  return [
    {
      id: uuid(), name: 'profile', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'true' },
      protocolMappers: [
        pm('username', 'oidc-usermodel-property-mapper', claims('preferred_username', { 'user.attribute': 'username', 'jsonType.label': 'String' })),
        pm('given name', 'oidc-usermodel-property-mapper', claims('given_name', { 'user.attribute': 'firstName', 'jsonType.label': 'String' })),
        pm('family name', 'oidc-usermodel-property-mapper', claims('family_name', { 'user.attribute': 'lastName', 'jsonType.label': 'String' })),
        pm('full name', 'oidc-full-name-mapper', { 'access.token.claim': 'true', 'id.token.claim': 'true', 'userinfo.token.claim': 'true' }),
        pm('locale', 'oidc-usermodel-attribute-mapper', claims('locale', { 'user.attribute': 'locale', 'jsonType.label': 'String' })),
      ],
    },
    {
      id: uuid(), name: 'email', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'true' },
      protocolMappers: [
        pm('email', 'oidc-usermodel-property-mapper', claims('email', { 'user.attribute': 'email', 'jsonType.label': 'String' })),
        pm('email verified', 'oidc-usermodel-property-mapper', claims('email_verified', { 'user.attribute': 'emailVerified', 'jsonType.label': 'boolean' })),
      ],
    },
    {
      id: uuid(), name: 'roles', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'false' },
      protocolMappers: [
        pm('realm roles', 'oidc-usermodel-realm-role-mapper', { 'claim.name': 'realm_access.roles', 'access.token.claim': 'true', 'introspection.token.claim': 'true', multivalued: 'true', 'jsonType.label': 'String' }),
        pm('client roles', 'oidc-usermodel-client-role-mapper', { 'claim.name': 'resource_access.${client_id}.roles', 'access.token.claim': 'true', 'introspection.token.claim': 'true', multivalued: 'true', 'jsonType.label': 'String' }),
        pm('audience resolve', 'oidc-audience-resolve-mapper', { 'access.token.claim': 'true', 'introspection.token.claim': 'true' }),
      ],
    },
    {
      id: uuid(), name: 'web-origins', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'false' },
      protocolMappers: [pm('allowed web origins', 'oidc-allowed-origins-mapper', { 'access.token.claim': 'true', 'introspection.token.claim': 'true' })],
    },
    {
      id: uuid(), name: 'acr', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'false' },
      protocolMappers: [pm('acr loa level', 'oidc-acr-mapper', { 'access.token.claim': 'true', 'id.token.claim': 'true', 'introspection.token.claim': 'true' })],
    },
    {
      id: uuid(), name: 'basic', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'false' },
      protocolMappers: [
        pm('sub', 'oidc-sub-mapper', { 'access.token.claim': 'true', 'introspection.token.claim': 'true' }),
        pm('auth_time', 'oidc-usersessionmodel-note-mapper', { 'user.session.note': 'AUTH_TIME', 'claim.name': 'auth_time', 'id.token.claim': 'true', 'access.token.claim': 'true', 'introspection.token.claim': 'true', 'jsonType.label': 'long' }),
      ],
    },
    { id: uuid(), name: 'offline_access', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'true' }, protocolMappers: [] },
    { id: uuid(), name: 'saml_organization', protocol: 'saml', attributes: {}, protocolMappers: [] },
  ];
}

const DEFAULT_SCOPES = ['web-origins', 'acr', 'profile', 'roles', 'basic', 'email'];

function client(clientId, fields = {}) {
  return {
    id: uuid(), clientId, name: fields.name || '', enabled: true, publicClient: false, bearerOnly: false,
    standardFlowEnabled: true, directAccessGrantsEnabled: false, serviceAccountsEnabled: false, implicitFlowEnabled: false,
    fullScopeAllowed: true, redirectUris: [], webOrigins: [], protocol: 'openid-connect',
    attributes: { 'pkce.code.challenge.method': 'S256' }, protocolMappers: [],
    defaultClientScopes: [...DEFAULT_SCOPES], optionalClientScopes: ['offline_access'], ...fields,
  };
}

function role(name, fields = {}) {
  return { id: uuid(), name, description: fields.description || '', composite: false, clientRole: false, attributes: {}, ...fields };
}

/** Keycloak's argon2 credential for a password, in its own two halves. */
async function keycloakCredential(password) {
  const salt = crypto.randomBytes(16);
  const hash = await argon2.hash(password, {
    raw: true, salt, type: argon2.argon2id, memoryCost: 7168, timeCost: 5, parallelism: 1, hashLength: 32, version: 0x13,
  });
  return {
    credentialData: {
      hashIterations: 5, algorithm: 'argon2',
      additionalParameters: { hashLength: ['32'], memory: ['7168'], type: ['id'], version: ['1.3'], parallelism: ['1'] },
    },
    secretData: { value: hash.toString('base64'), salt: salt.toString('base64'), additionalParameters: {} },
  };
}

function buildRealms() {
  const realms = {};

  function realmOf(name, extra = {}) {
    const r = {
      rep: {
        id: uuid(), realm: name, enabled: true, accessTokenLifespan: 300, ssoSessionIdleTimeout: 1800, ssoSessionMaxLifespan: 36000,
        revokeRefreshToken: true, refreshTokenMaxReuse: 0, bruteForceProtected: true, failureFactor: 30,
        passwordPolicy: 'length(12) and upperCase(1) and lowerCase(1) and digits(1) and notUsername(undefined)',
        defaultRole: { name: `default-roles-${name}` }, loginWithEmailAllowed: true, ...extra,
      },
      clients: [], realmRoles: [], clientRoles: new Map(), composites: new Map(), scopes: standardScopes(), groups: [], users: [], mappings: new Map(),
      memberships: new Map(), serviceAccounts: new Map(),
    };
    const account = client('account', { name: '${client_account}', publicClient: true, redirectUris: [`/realms/${name}/account/*`] });
    r.clients.push(account);
    const viewProfile = role('view-profile', { clientRole: true, containerId: account.id });
    const manageAccount = role('manage-account', { clientRole: true, containerId: account.id });
    r.clientRoles.set(account.id, [viewProfile, manageAccount]);
    const offline = role('offline_access', { description: '${role_offline-access}' });
    const uma = role('uma_authorization', { description: '${role_uma_authorization}' });
    const defaults = role(`default-roles-${name}`, { composite: true, description: '${role_default-roles}' });
    r.realmRoles.push(offline, uma, defaults);
    r.composites.set(defaults.id, [offline, uma, viewProfile, manageAccount]);
    r.defaults = defaults;
    realms[name] = r;
    return r;
  }

  function addUser(r, fields, { realmRoles = [], clientRoles = {}, groups = [] } = {}) {
    const user = {
      id: fields.id || uuid(), username: fields.username, email: fields.email, emailVerified: true, firstName: fields.firstName, lastName: fields.lastName,
      enabled: true, attributes: fields.attributes || {}, requiredActions: [], createdTimestamp: Date.now(), ...fields,
    };
    r.users.push(user);
    r.mappings.set(user.id, { realmRoles: [r.defaults, ...realmRoles], clientRoles });
    r.memberships.set(user.id, groups);
    return user;
  }

  // ── platform ─────────────────────────────────────────────────────────────
  const platform = realmOf('platform');
  const platformAdmin = role('platform-admin');
  const tenantAdmin = role('tenant-admin');
  const approver = role('approve-permissions:samta-mapdashboard-web-poc');
  platform.realmRoles.push(platformAdmin, tenantAdmin, approver);
  platform.clients.push(client('iam-admin-ui', {
    redirectUris: ['https://iam.internal/login/oauth2/code/keycloak'],
    attributes: { 'post.logout.redirect.uris': 'https://iam.internal/ui/##https://mapdashboard.internal/*', 'pkce.code.challenge.method': 'S256' },
    webOrigins: ['https://iam.internal'],
    protocolMappers: [
      pm('realm roles', 'oidc-usermodel-realm-role-mapper', claims('realm_access.roles', { multivalued: 'true' })),
      pm('tenants', 'oidc-usermodel-attribute-mapper', claims('tenants', { 'user.attribute': 'tenants', multivalued: 'true' })),
    ],
  }));
  addUser(platform, { id: '0b0c3d58-1111-4000-8000-00000000a001', username: 'padmin', email: 'padmin@iam.poc.local', firstName: 'Platform', lastName: 'Admin' },
    { realmRoles: [platformAdmin, approver] });
  addUser(platform, { id: '0b0c3d58-1111-4000-8000-00000000a002', username: 'tadmin', email: 'tadmin@iam.poc.local', attributes: { tenants: ['tenant-alpha'] } },
    { realmRoles: [tenantAdmin] });

  // ── samta (MapDashboard) ─────────────────────────────────────────────────
  const samta = realmOf('samta');
  samta.scopes.push({
    id: uuid(), name: 'mapdashboard-roles', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'false' },
    protocolMappers: [pm('md roles', 'oidc-usermodel-client-role-mapper', {
      'usermodel.clientRoleMapping.clientId': 'samta-mapdashboard-web-poc', 'claim.name': 'md_roles', multivalued: 'true',
      'access.token.claim': 'true', 'id.token.claim': 'true', 'userinfo.token.claim': 'false', 'jsonType.label': 'String',
    })],
  });
  const md = client('samta-mapdashboard-web-poc', {
    redirectUris: ['https://mapdashboard.internal/signin-oidc', 'https://localhost:5173/signin-oidc'],
    attributes: {
      'post.logout.redirect.uris': 'https://mapdashboard.internal/signout-callback-oidc##https://localhost:5173/signout-callback-oidc',
      'pkce.code.challenge.method': 'S256',
    },
    webOrigins: ['https://mapdashboard.internal', 'https://localhost:5173'],
    defaultClientScopes: [...DEFAULT_SCOPES, 'mapdashboard-roles'],
  });
  samta.clients.push(md);
  const read = role('perm:objects.read', { clientRole: true, containerId: md.id, description: 'View objects.', attributes: { category: ['Objects'] } });
  const layers = role('perm:layers.view', { clientRole: true, containerId: md.id, description: 'View layers.', attributes: { category: ['Layers'] } });
  const operator = role('role:operator', { clientRole: true, containerId: md.id, composite: true, description: 'Operators' });
  const mdAdmin = role('role:admin', { clientRole: true, containerId: md.id, composite: true, attributes: { system: ['true'] } });
  samta.clientRoles.set(md.id, [read, layers, operator, mdAdmin]);
  samta.composites.set(operator.id, [read, layers]);
  samta.composites.set(mdAdmin.id, [read, layers]);
  const operatorUser = addUser(samta, { id: '8f1e2a7c-3b4d-4e5f-9a0b-1c2d3e4f5a6b', username: 'operator1', email: 'operator1@example.local', firstName: 'Operator', lastName: 'One' },
    { clientRoles: { [md.id]: [operator] } });
  addUser(samta, { username: 'noroles', email: 'noroles@example.local' });

  // ── tenant-alpha ─────────────────────────────────────────────────────────
  const alpha = realmOf('tenant-alpha');
  alpha.scopes.push({
    id: uuid(), name: 'business-api', protocol: 'openid-connect', attributes: { 'include.in.token.scope': 'true' },
    protocolMappers: [
      pm('business-api audience', 'oidc-audience-mapper', { 'included.custom.audience': 'business-api', 'access.token.claim': 'true', 'id.token.claim': 'false' }),
      pm('authz version', 'oidc-hardcoded-claim-mapper', { 'claim.name': 'authz_version', 'claim.value': '0', 'jsonType.label': 'int', 'access.token.claim': 'true', 'id.token.claim': 'false' }),
      pm('tenant', 'oidc-hardcoded-claim-mapper', { 'claim.name': 'tenant', 'claim.value': 'tenant-alpha', 'jsonType.label': 'String', 'access.token.claim': 'true', 'id.token.claim': 'true' }),
    ],
  });
  const tenantUser = role('tenant-user');
  const alphaAdmin = role('tenant-admin', { composite: true });
  alpha.realmRoles.push(tenantUser, alphaAdmin);
  alpha.composites.set(alphaAdmin.id, [tenantUser]);
  alpha.clients.push(client('tenant-alpha.react-reference.poc', {
    publicClient: true,
    redirectUris: ['https://localhost:5173/auth/callback'],
    attributes: { 'post.logout.redirect.uris': 'https://localhost:5173/' },
    webOrigins: ['https://localhost:5173'],
    defaultClientScopes: [...DEFAULT_SCOPES, 'business-api'],
    protocolMappers: [
      pm('realm roles', 'oidc-usermodel-realm-role-mapper', claims('realm_access.roles', { multivalued: 'true' })),
      pm('react api audience', 'oidc-audience-mapper', { 'included.custom.audience': 'react-reference-api', 'access.token.claim': 'true', 'id.token.claim': 'false' }),
      pm('tenant', 'oidc-hardcoded-claim-mapper', claims('tenant', { 'claim.value': 'tenant-alpha', 'jsonType.label': 'String' })),
    ],
  }));
  const native = client('tenant-alpha.python-native.poc', {
    publicClient: true,
    redirectUris: ['http://127.0.0.1/callback', 'com.samta.pydemo:/callback'],
    attributes: { 'post.logout.redirect.uris': 'http://127.0.0.1/logged-out' },
    protocolMappers: [
      pm('client roles', 'oidc-usermodel-client-role-mapper', claims('resource_access.${client_id}.roles', { 'usermodel.clientRoleMapping.clientId': 'tenant-alpha.python-native.poc', multivalued: 'true' })),
      pm('python api audience', 'oidc-audience-mapper', { 'included.custom.audience': 'python-demo-api', 'access.token.claim': 'true', 'id.token.claim': 'false' }),
    ],
  });
  alpha.clients.push(native);
  const nativeReader = role('reader', { clientRole: true, containerId: native.id });
  alpha.clientRoles.set(native.id, [nativeReader]);
  const wizApi = client('tenant-alpha.wiztest-api', { bearerOnly: true, standardFlowEnabled: false });
  alpha.clients.push(wizApi);
  const svc = client('tenant-alpha.wiztest-svc', {
    standardFlowEnabled: false, serviceAccountsEnabled: true,
    protocolMappers: [pm('wiztest api', 'oidc-audience-mapper', { 'included.client.audience': 'tenant-alpha.wiztest-api', 'access.token.claim': 'true', 'id.token.claim': 'false' })],
  });
  alpha.clients.push(svc);
  const svcUser = { id: uuid(), username: 'service-account-tenant-alpha.wiztest-svc', enabled: true, serviceAccountClientId: 'tenant-alpha.wiztest-svc', attributes: {} };
  alpha.serviceAccounts.set(svc.id, svcUser);
  alpha.mappings.set(svcUser.id, { realmRoles: [alpha.defaults], clientRoles: {} });
  const admins = { id: uuid(), name: 'administrators', path: '/administrators', subGroupCount: 1, subGroups: [], realmRoles: ['tenant-admin'], clientRoles: {}, attributes: {} };
  const ops = { id: uuid(), name: 'ops', path: '/administrators/ops', subGroupCount: 0, subGroups: [], realmRoles: [], clientRoles: { 'tenant-alpha.python-native.poc': ['reader'] }, attributes: {} };
  alpha.groups.push(admins);
  alpha.children = new Map([[admins.id, [ops]]]);
  addUser(alpha, { username: 'alice', email: 'alice@alpha.local', firstName: 'Alice', lastName: 'Alpha' }, { realmRoles: [tenantUser], groups: [ops] });
  addUser(alpha, { username: 'bob', email: 'bob@alpha.local' }, { clientRoles: { [native.id]: [nativeReader] } });

  return { realms, operatorUser };
}

/**
 * @param {object} [options]
 * @param {(req) => Promise<{status, body}|null>} [options.extra] routes of the caller's own,
 *   tried first (the runnable stand-in adds health, a credential export and a catalogue)
 */
function createMockKeycloak({ extra } = {}) {
  const state = { ...buildRealms(), down: false, failOn: null, requests: [] };
  const clientIdOf = (r, uuidValue) => r.clients.find((c) => c.id === uuidValue)?.clientId;

  function roleMappings(r, userId) {
    const m = r.mappings.get(userId) || { realmRoles: [], clientRoles: {} };
    const clientMappings = {};
    for (const [cuuid, roles] of Object.entries(m.clientRoles)) {
      const clientId = clientIdOf(r, cuuid);
      clientMappings[clientId] = { id: cuuid, client: clientId, mappings: roles.map((x) => ({ ...x })) };
    }
    return { realmMappings: m.realmRoles.map((x) => ({ ...x })), clientMappings };
  }

  function route(method, url) {
    const u = new URL(url, 'http://x');
    const p = u.pathname;
    const first = Number(u.searchParams.get('first') || 0);
    const max = Number(u.searchParams.get('max') || 100);
    const page = (list) => list.slice(first, first + max);
    let m;
    if (method === 'POST' && /^\/realms\/master\/protocol\/openid-connect\/token$/.test(p)) return { status: 200, body: { access_token: 'mock-admin-token', expires_in: 300 } };
    if (p === '/admin/realms') return { status: 200, body: Object.values(state.realms).map((r) => r.rep) };
    if (!(m = /^\/admin\/realms\/([^/]+)(\/.*)?$/.exec(p))) return { status: 404, body: { error: 'not found' } };
    const r = state.realms[decodeURIComponent(m[1])];
    if (!r) return { status: 404, body: { error: 'Realm not found.' } };
    const rest = m[2] || '';
    if (rest === '') return { status: 200, body: r.rep };
    if (rest === '/clients') return { status: 200, body: page(r.clients) };
    if (rest === '/roles') return { status: 200, body: page(r.realmRoles) };
    if ((m = /^\/roles-by-id\/([^/]+)\/composites$/.exec(rest))) return { status: 200, body: r.composites.get(m[1]) || [] };
    if ((m = /^\/clients\/([^/]+)\/roles$/.exec(rest))) return { status: 200, body: r.clientRoles.get(m[1]) || [] };
    if ((m = /^\/clients\/([^/]+)\/scope-mappings$/.exec(rest))) return { status: 200, body: {} };
    if ((m = /^\/clients\/([^/]+)\/service-account-user$/.exec(rest))) {
      const sa = r.serviceAccounts.get(m[1]);
      return sa ? { status: 200, body: sa } : { status: 404, body: {} };
    }
    if (rest === '/client-scopes') return { status: 200, body: r.scopes };
    if (rest === '/groups') return { status: 200, body: page(r.groups) };
    if ((m = /^\/groups\/([^/]+)\/children$/.exec(rest))) return { status: 200, body: page(r.children?.get(m[1]) || []) };
    if (rest === '/users') return { status: 200, body: page(r.users) };
    if ((m = /^\/users\/([^/]+)\/role-mappings$/.exec(rest))) return { status: 200, body: roleMappings(r, m[1]) };
    if ((m = /^\/users\/([^/]+)\/groups$/.exec(rest))) return { status: 200, body: (r.memberships.get(m[1]) || []).map((g) => ({ id: g.id, name: g.name, path: g.path })) };
    return { status: 404, body: { error: 'not found' } };
  }

  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', async () => {
      state.requests.push(`${req.method} ${req.url}`);
      if (state.down) { req.socket.destroy(); return; }
      const own = extra ? await extra(req).catch(() => ({ status: 500, body: {} })) : null;
      if (own) {
        res.writeHead(own.status, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(own.body));
        return;
      }
      if (state.failOn && state.failOn.test(req.url)) { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end('{}'); return; }
      if (req.url.startsWith('/admin/') && req.headers.authorization !== 'Bearer mock-admin-token') { res.writeHead(401); res.end(); return; }
      const out = route(req.method, req.url);
      res.writeHead(out.status, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(out.body));
    });
  });

  return {
    state,
    keycloakCredential,
    listen: (port = 0) => new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(port, '127.0.0.1', () => resolve(server.address().port));
    }),
    close: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(() => resolve()); }),
  };
}

module.exports = { createMockKeycloak, keycloakCredential };
