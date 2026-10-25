const argon2 = require('argon2');
const crypto = require('crypto');
const { redirectUriMatches, redirectUriProblem, webOriginProblem, clientOrigins } = require('../../src/idp/util');
const { passwordProblem, DEFAULT_POLICY } = require('../../src/idp/password-policy');
const {
  claimPath, activeScopes, mapClaims, audienceValue, fromKeycloakMapper, STANDARD_SCOPES,
} = require('../../src/idp/mappers');
const { buildCatalogue, resolve, tokenRoles, isAdministrative } = require('../../src/idp/roles');
const { phcFromKeycloak } = require('../../src/idp/credentials');

describe('redirect URIs', () => {
  const registered = ['https://app.example/cb', 'http://127.0.0.1/callback', 'com.samta.pydemo:/callback', 'https://mapdashboard.internal/*'];

  test('match exactly, never by prefix or wildcard', () => {
    expect(redirectUriMatches(registered, 'https://app.example/cb')).toBe(true);
    expect(redirectUriMatches(registered, 'https://app.example/cb/')).toBe(false);
    expect(redirectUriMatches(registered, 'https://app.example/cb?x=1')).toBe(false);
    expect(redirectUriMatches(registered, 'https://mapdashboard.internal/anything')).toBe(false);
    expect(redirectUriMatches(registered, 'com.samta.pydemo:/callback')).toBe(true);
  });

  test('ignore the port on the loopback interface only (RFC 8252 §7.3)', () => {
    expect(redirectUriMatches(registered, 'http://127.0.0.1:53122/callback')).toBe(true);
    expect(redirectUriMatches(registered, 'http://127.0.0.1:53122/other')).toBe(false);
    expect(redirectUriMatches(registered, 'http://localhost:53122/callback')).toBe(false);
    expect(redirectUriMatches(['https://app.example/cb'], 'https://app.example:8443/cb')).toBe(false);
  });

  test('registration rules', () => {
    expect(redirectUriProblem('https://a.example/cb')).toBeNull();
    expect(redirectUriProblem('http://127.0.0.1/cb')).toBeNull();
    expect(redirectUriProblem('com.example.app:/cb')).toBeNull();
    expect(redirectUriProblem('http://a.example/cb')).toMatch(/https/);
    expect(redirectUriProblem('https://a.example/*')).toMatch(/wildcard/);
    expect(redirectUriProblem('https://a.example/cb#x')).toMatch(/fragment/);
    expect(redirectUriProblem('javascript:alert(1)')).toMatch(/https/);
    expect(webOriginProblem('https://a.example')).toBeNull();
    expect(webOriginProblem('https://a.example/path')).toMatch(/origin only/);
    expect([...clientOrigins({ webOrigins: ['+'], redirectUris: ['https://a.example/cb', 'com.x.y:/cb'] })]).toEqual(['https://a.example']);
  });
});

describe('password policy (Keycloak syntax)', () => {
  test.each([
    ['short1A', /at least 12 characters/],
    ['alllowercase1234', /uppercase/],
    ['ALLUPPERCASE1234', /lowercase/],
    ['NoDigitsAtAllHere', /digit/],
  ])('%s is refused', (password, problem) => {
    expect(passwordProblem(DEFAULT_POLICY, password, { username: 'alice' })).toMatch(problem);
  });

  test('a password may not be the username; unknown policies are ignored', () => {
    expect(passwordProblem(DEFAULT_POLICY, 'Alice-Passw0rd', { username: 'alice-passw0rd' })).toMatch(/username/);
    expect(passwordProblem(`${DEFAULT_POLICY} and passwordHistory(3)`, 'Good-Passw0rd-1', { username: 'alice' })).toBeNull();
  });
});

describe('claim paths', () => {
  test('nest on dots, keep escaped dots and a dotted client id as one segment', () => {
    expect(claimPath('realm_access.roles')).toEqual(['realm_access', 'roles']);
    expect(claimPath('a\\.b.c')).toEqual(['a.b', 'c']);
    expect(claimPath('resource_access.${client_id}.roles', { clientId: 'tenant-alpha.python-native.poc' }))
      .toEqual(['resource_access', 'tenant-alpha.python-native.poc', 'roles']);
  });
});

describe('the token contract', () => {
  const scopes = new Map(STANDARD_SCOPES.map((s) => [s.name, s]));
  scopes.set('mapdashboard-roles', {
    name: 'mapdashboard-roles', includeInTokenScope: false,
    mappers: [{ type: 'client-roles', clientId: 'md', claim: 'md_roles', multivalued: true, tokens: ['access', 'id'] }],
  });
  scopes.set('business-api', {
    name: 'business-api', includeInTokenScope: true,
    mappers: [
      { type: 'audience', audience: 'business-api', tokens: ['access'] },
      { type: 'hardcoded', claim: 'authz_version', value: '0', jsonType: 'int', tokens: ['access'] },
    ],
  });
  const catalogue = buildCatalogue({
    realmRoles: [
      { name: 'default-roles-x', composites: { realm: ['offline_access'], client: {} } },
      { name: 'offline_access', composites: { realm: [], client: {} } },
      { name: 'tenant-admin', composites: { realm: ['tenant-user'], client: {} } },
      { name: 'tenant-user', composites: { realm: [], client: {} } },
    ],
    clientRoles: [
      { clientId: 'md', name: 'role:operator', composites: { realm: [], client: { md: ['perm:objects.read'] } } },
      { clientId: 'md', name: 'perm:objects.read', composites: { realm: [], client: {} } },
      { clientId: 'account', name: 'view-profile', composites: { realm: [], client: {} } },
    ],
    groups: [{ id: 'g1', path: '/admins', realmRoles: ['tenant-admin'], clientRoles: {} }],
  });
  const user = {
    id: 'u1', username: 'op', email: 'op@x', emailVerified: true, firstName: 'Op', lastName: 'One',
    realmRoles: ['default-roles-x'], clientRoles: { md: ['role:operator'], account: ['view-profile'] }, groups: ['g1'], attributes: { tenants: ['a', 'b'] },
  };
  const client = {
    clientId: 'md', defaultClientScopes: ['profile', 'email', 'roles', 'web-origins', 'basic', 'mapdashboard-roles'],
    optionalClientScopes: ['business-api'], webOrigins: ['https://md.example'],
    mappers: [{ type: 'user-attribute', claim: 'tenants', attribute: 'tenants', multivalued: true, tokens: ['id'] }],
  };

  test('access token claims come from the active scopes and the client', () => {
    const { active, scopeClaim } = activeScopes(client, scopes, 'openid business-api');
    expect(scopeClaim).toBe('openid profile email business-api');
    const { claims, audience } = mapClaims({ client, user, catalogue, activeScopeList: active, clientsById: new Map(), authTime: 1 }, 'access');
    expect(claims.preferred_username).toBe('op');
    expect(claims.name).toBe('Op One');
    expect(claims.email_verified).toBe(true);
    expect(claims.realm_access.roles.sort()).toEqual(['default-roles-x', 'offline_access', 'tenant-admin', 'tenant-user']);
    expect(claims.resource_access.md.roles.sort()).toEqual(['perm:objects.read', 'role:operator']);
    expect(claims.md_roles.sort()).toEqual(['perm:objects.read', 'role:operator']);
    expect(claims.authz_version).toBe(0);
    expect(claims['allowed-origins']).toEqual(['https://md.example']);
    expect(claims.tenants).toBeUndefined();
    expect(audience.sort()).toEqual(['account', 'business-api']);
  });

  test('the ID token gets only what its mappers allow', () => {
    const { active } = activeScopes(client, scopes, 'openid');
    const { claims } = mapClaims({ client, user, catalogue, activeScopeList: active, clientsById: new Map() }, 'id');
    expect(claims.realm_access).toBeUndefined();
    expect(claims.md_roles).toBeDefined();
    expect(claims.tenants).toEqual(['a', 'b']);
    expect(claims.authz_version).toBeUndefined();
  });

  test('a single audience is a string, none is absent (as Keycloak writes them)', () => {
    expect(audienceValue([])).toBeUndefined();
    expect(audienceValue(['a'])).toBe('a');
    expect(audienceValue(['a', 'b'])).toEqual(['a', 'b']);
  });

  test('roles carry every reason they are held', () => {
    const held = resolve(catalogue, user);
    expect(held.get('realm:tenant-user').grants).toEqual([{ origin: 'composite', via: 'realm:tenant-admin' }]);
    expect(held.get('realm:tenant-admin').grants).toEqual([{ origin: 'group', via: '/admins' }]);
    expect(isAdministrative(catalogue, { source: 'realm', name: 'tenant-admin' })).toBe(true);
    expect(isAdministrative(catalogue, { source: 'realm', name: 'tenant-user' })).toBe(false);
  });

  test('a client without full scope sees only its own roles and its scope mappings', () => {
    const limited = { ...client, fullScopeAllowed: false, scopeMappings: { realmRoles: ['tenant-user'] } };
    const roles = tokenRoles(catalogue, user, limited);
    expect(roles.realm).toEqual(['tenant-user']);
    expect(Object.keys(roles.clients)).toEqual(['md']);
  });
});

describe('Keycloak protocol mappers', () => {
  test('converted with Keycloak\'s defaults for absent flags', () => {
    const { mapper } = fromKeycloakMapper({
      name: 'realm roles', protocolMapper: 'oidc-usermodel-realm-role-mapper',
      config: { 'claim.name': 'realm_access.roles', 'access.token.claim': 'true', multivalued: 'true' },
    });
    expect(mapper).toMatchObject({ type: 'realm-roles', claim: 'realm_access.roles', tokens: ['access', 'introspection'] });
    const audience = fromKeycloakMapper({ name: 'a', protocolMapper: 'oidc-audience-mapper', config: { 'included.client.audience': 'svc', 'access.token.claim': 'true' } });
    expect(audience.mapper).toMatchObject({ type: 'audience', audienceClient: 'svc', tokens: ['access', 'introspection'] });
    expect(fromKeycloakMapper({ name: 'x', protocolMapper: 'oidc-script-mapper', config: {} }).skipped).toMatch(/not supported/);
  });
});

describe('Keycloak argon2 credentials', () => {
  test('become a PHC string that verifies the same password', async () => {
    const salt = crypto.randomBytes(16);
    const hash = await argon2.hash('Same-Passw0rd-1', {
      raw: true, salt, type: argon2.argon2id, memoryCost: 7168, timeCost: 5, parallelism: 1, hashLength: 32, version: 0x13,
    });
    const built = phcFromKeycloak(
      { hashIterations: 5, algorithm: 'argon2', additionalParameters: { hashLength: ['32'], memory: ['7168'], type: ['id'], version: ['1.3'], parallelism: ['1'] } },
      JSON.stringify({ value: hash.toString('base64'), salt: salt.toString('base64'), additionalParameters: {} }),
    );
    expect(built.phc).toMatch(/^\$argon2id\$v=19\$m=7168,t=5,p=1\$/);
    expect(await argon2.verify(built.phc, 'Same-Passw0rd-1')).toBe(true);
    expect(await argon2.verify(built.phc, 'other')).toBe(false);
  });

  test('parameters are taken from the credential, and unknown algorithms are refused', () => {
    const value = Buffer.alloc(64, 1).toString('base64');
    const salt = Buffer.alloc(16, 2).toString('base64');
    const built = phcFromKeycloak({ hashIterations: 3, algorithm: 'argon2', additionalParameters: { hashLength: ['64'], memory: ['65536'], type: ['i'], version: ['1.3'], parallelism: ['2'] } }, { value, salt });
    expect(built.phc.startsWith('$argon2i$v=19$m=65536,t=3,p=2$')).toBe(true);
    expect(phcFromKeycloak({ algorithm: 'pbkdf2-sha512', hashIterations: 27500 }, { value, salt }).problem).toMatch(/unsupported algorithm/);
    expect(phcFromKeycloak({ hashIterations: 3, algorithm: 'argon2', additionalParameters: { hashLength: ['32'], memory: ['7168'], type: ['id'], parallelism: ['1'] } }, { value, salt }).problem).toMatch(/hash length/);
  });
});
