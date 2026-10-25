/**
 * The token contract: which claims go into which token.
 * ─────────────────────────────────────────────────────────────────────────────
 * Applications that trust the primary IdP must accept this one's tokens
 * unchanged, so claims are produced the way Keycloak produces them: from
 * *mappers*, attached either to a client or to a client scope. A client has
 * default scopes (always applied) and optional ones (applied when requested in
 * `scope`); a scope's mappers run only while it is active. Nothing about a
 * particular application is written in code — `md_roles`, `tenant`, `tenants`,
 * extra audiences are all data, synchronised from the primary system or
 * configured here.
 *
 * Mapper shape (one JSON object, `tokens` says where its claim goes):
 *   { type: 'hardcoded',       claim, value, jsonType? }
 *   { type: 'user-attribute',  claim, attribute, multivalued?, jsonType? }
 *   { type: 'user-property',   claim, property }        username | email | firstName | lastName | emailVerified
 *   { type: 'full-name',       claim? }
 *   { type: 'realm-roles',     claim?, prefix?, multivalued? }
 *   { type: 'client-roles',    claim?, clientId?, prefix?, multivalued? }
 *   { type: 'audience',        audience? | audienceClient? }
 *   { type: 'audience-resolve' }   every other client the user holds roles of
 *   { type: 'allowed-origins' }    the client's web origins
 *   { type: 'acr' } { type: 'sub' } { type: 'auth-time' }
 *   { type: 'group-membership', claim?, fullPath? }
 *   tokens: subset of ['access', 'id', 'userinfo', 'introspection']
 *
 * Claim names may be nested ("realm_access.roles", a literal dot written
 * "\.") and may contain ${client_id}.
 */

const { tokenRoles } = require('./roles');
const { clientOrigins } = require('./util');

const ALL = ['access', 'id', 'userinfo', 'introspection'];

// ── Keycloak's built-in client scopes, as mappers ───────────────────────────

const attr = (claim, attribute, tokens = ['access', 'id', 'userinfo', 'introspection']) => ({ type: 'user-attribute', claim, attribute, tokens });

const STANDARD_SCOPES = [
  {
    name: 'profile', includeInTokenScope: true, builtIn: true,
    mappers: [
      { type: 'user-property', claim: 'preferred_username', property: 'username', tokens: ALL },
      { type: 'user-property', claim: 'given_name', property: 'firstName', tokens: ALL },
      { type: 'user-property', claim: 'family_name', property: 'lastName', tokens: ALL },
      { type: 'full-name', claim: 'name', tokens: ALL },
      attr('nickname', 'nickname'), attr('middle_name', 'middleName'), attr('picture', 'picture'),
      attr('website', 'website'), attr('gender', 'gender'), attr('birthdate', 'birthdate'),
      attr('zoneinfo', 'zoneinfo'), attr('locale', 'locale'), attr('profile', 'profile'),
    ],
  },
  {
    name: 'email', includeInTokenScope: true, builtIn: true,
    mappers: [
      { type: 'user-property', claim: 'email', property: 'email', tokens: ALL },
      { type: 'user-property', claim: 'email_verified', property: 'emailVerified', jsonType: 'boolean', tokens: ALL },
    ],
  },
  {
    name: 'roles', includeInTokenScope: false, builtIn: true,
    mappers: [
      { type: 'realm-roles', claim: 'realm_access.roles', multivalued: true, tokens: ['access', 'introspection'] },
      { type: 'client-roles', claim: 'resource_access.${client_id}.roles', multivalued: true, tokens: ['access', 'introspection'] },
      { type: 'audience-resolve', tokens: ['access', 'introspection'] },
    ],
  },
  { name: 'web-origins', includeInTokenScope: false, builtIn: true, mappers: [{ type: 'allowed-origins', tokens: ['access', 'introspection'] }] },
  { name: 'acr', includeInTokenScope: false, builtIn: true, mappers: [{ type: 'acr', tokens: ['access', 'id', 'introspection'] }] },
  {
    name: 'basic', includeInTokenScope: false, builtIn: true,
    mappers: [{ type: 'sub', tokens: ['access', 'introspection'] }, { type: 'auth-time', tokens: ['access', 'id', 'introspection'] }],
  },
  { name: 'offline_access', includeInTokenScope: true, builtIn: true, mappers: [] },
];

const DEFAULT_DEFAULT_SCOPES = ['profile', 'email', 'roles', 'web-origins', 'acr', 'basic'];
const DEFAULT_OPTIONAL_SCOPES = ['offline_access'];

// ── claim paths ─────────────────────────────────────────────────────────────

function claimPath(name, client) {
  // As Keycloak does: the client id is one path segment even when it contains
  // dots (resource_access["tenant-alpha.python-native.poc"].roles).
  const resolved = String(name).replace(/\$\{client_id\}/g, () => String(client?.clientId ?? '').replace(/\./g, '\\.'));
  const parts = [];
  let current = '';
  for (let i = 0; i < resolved.length; i++) {
    if (resolved[i] === '\\' && resolved[i + 1] === '.') { current += '.'; i++; continue; }
    if (resolved[i] === '.') { parts.push(current); current = ''; continue; }
    current += resolved[i];
  }
  parts.push(current);
  return parts.filter((part) => part !== '');
}

function setClaim(target, path, value, { merge = false } = {}) {
  if (!path.length || value === undefined || value === null) return;
  let node = target;
  for (const part of path.slice(0, -1)) {
    if (typeof node[part] !== 'object' || node[part] === null || Array.isArray(node[part])) node[part] = {};
    node = node[part];
  }
  const last = path[path.length - 1];
  if (merge && Array.isArray(node[last]) && Array.isArray(value)) {
    node[last] = [...new Set([...node[last], ...value])];
  } else {
    node[last] = value;
  }
}

function convert(value, jsonType) {
  if (value === undefined || value === null) return value;
  switch ((jsonType || '').toLowerCase()) {
    case 'int':
    case 'long': {
      const number = Number(value);
      return Number.isFinite(number) ? Math.trunc(number) : undefined;
    }
    case 'boolean':
      return value === true || value === 'true';
    case 'json':
      if (typeof value !== 'string') return value;
      try { return JSON.parse(value); } catch { return undefined; }
    case 'string':
      return String(value);
    default:
      return value;
  }
}

// ── scopes in force for one request ─────────────────────────────────────────

/**
 * @param {object} client
 * @param {Map<string, object>} scopes realm's client scopes by name
 * @param {string} requested the request's `scope` parameter
 * @returns {{ active: object[], scopeClaim: string }}
 */
function activeScopes(client, scopes, requested = '') {
  const asked = new Set(String(requested || '').split(/\s+/).filter(Boolean));
  const names = [...(client.defaultClientScopes || [])];
  for (const name of client.optionalClientScopes || []) if (asked.has(name)) names.push(name);
  const active = names.map((name) => scopes.get(name)).filter(Boolean);
  const inClaim = active.filter((scope) => scope.includeInTokenScope !== false).map((scope) => scope.name);
  const scopeClaim = [...(asked.has('openid') ? ['openid'] : []), ...inClaim].join(' ');
  return { active, scopeClaim };
}

// ── the claims ──────────────────────────────────────────────────────────────

/**
 * Runs every mapper in force for `kind` and returns the claims they produce,
 * plus what affects `aud`.
 *
 * @param {object} ctx
 * @param {object} ctx.client  the client the token is for
 * @param {object} ctx.user    the account (current data, never a previous token)
 * @param {object} ctx.catalogue roles.buildCatalogue(...) of the realm
 * @param {object[]} ctx.activeScopeList from activeScopes()
 * @param {Map<string, object>} ctx.clientsById all clients of the realm, for audienceClient
 * @param {string} ctx.acr
 * @param {number} ctx.authTime
 * @param {'access'|'id'|'userinfo'|'introspection'} kind
 */
function mapClaims(ctx, kind) {
  const { client, user, catalogue } = ctx;
  const claims = {};
  const audience = [];
  const roles = tokenRoles(catalogue, user, client);
  const mappers = [
    ...ctx.activeScopeList.flatMap((scope) => scope.mappers || []),
    ...(client.mappers || []),
  ];

  for (const mapper of mappers) {
    if (!(mapper.tokens || ALL).includes(kind)) continue;
    const path = mapper.claim ? claimPath(mapper.claim, client) : null;
    switch (mapper.type) {
      case 'hardcoded':
        setClaim(claims, path, convert(mapper.value, mapper.jsonType));
        break;
      case 'user-attribute': {
        const values = []
          .concat(user.attributes?.[mapper.attribute] ?? [])
          .filter((value) => value !== null && value !== undefined);
        if (!values.length) break;
        const typed = values.map((value) => convert(value, mapper.jsonType)).filter((value) => value !== undefined);
        setClaim(claims, path, mapper.multivalued ? typed : typed[0], { merge: Boolean(mapper.multivalued) });
        break;
      }
      case 'user-property': {
        const value = user[mapper.property];
        if (value === undefined || value === null || value === '') break;
        setClaim(claims, path, convert(value, mapper.jsonType));
        break;
      }
      case 'full-name': {
        const name = [user.firstName, user.lastName].filter(Boolean).join(' ');
        if (name) setClaim(claims, path || ['name'], name);
        break;
      }
      case 'realm-roles': {
        const names = roles.realm.map((name) => `${mapper.prefix || ''}${name}`);
        if (!names.length) break;
        setClaim(claims, path || ['realm_access', 'roles'], mapper.multivalued === false ? names.join(',') : names, { merge: true });
        break;
      }
      case 'client-roles': {
        const targets = mapper.clientId ? [mapper.clientId] : Object.keys(roles.clients);
        for (const clientId of targets) {
          const names = (roles.clients[clientId] || []).map((name) => `${mapper.prefix || ''}${name}`);
          if (!names.length) continue;
          const target = claimPath(mapper.claim || 'resource_access.${client_id}.roles', { clientId });
          setClaim(claims, target, mapper.multivalued === false ? names.join(',') : names, { merge: true });
        }
        break;
      }
      case 'audience':
        if (mapper.audience) audience.push(mapper.audience);
        if (mapper.audienceClient && ctx.clientsById?.has(mapper.audienceClient)) audience.push(mapper.audienceClient);
        break;
      case 'audience-resolve':
        for (const clientId of Object.keys(roles.clients)) if (clientId !== client.clientId) audience.push(clientId);
        break;
      case 'allowed-origins': {
        const origins = [...clientOrigins(client)];
        if (origins.length) setClaim(claims, ['allowed-origins'], origins);
        break;
      }
      case 'acr':
        if (ctx.acr !== undefined) setClaim(claims, ['acr'], ctx.acr);
        break;
      case 'sub':
        setClaim(claims, ['sub'], user.id);
        break;
      case 'auth-time':
        if (ctx.authTime) setClaim(claims, ['auth_time'], ctx.authTime);
        break;
      case 'group-membership': {
        const paths = (user.groups || []).map((id) => catalogue.groups.get(id)).filter(Boolean)
          .map((group) => (mapper.fullPath === false ? group.name : group.path));
        if (paths.length) setClaim(claims, path || ['groups'], paths);
        break;
      }
      default:
        break;
    }
  }
  return { claims, audience: [...new Set(audience)] };
}

/** Keycloak writes a one-element audience as a string, and omits an empty one. */
const audienceValue = (list) => (list.length === 0 ? undefined : list.length === 1 ? list[0] : list);

// ── converting Keycloak's protocol mapper models ────────────────────────────

const yes = (value) => value === true || value === 'true';

// Keycloak reads a missing access/id/userinfo flag as false, and a missing
// introspection flag (added in 25) as true.
function tokensFromConfig(config, defaults = { access: false, id: false, userinfo: false, introspection: true }) {
  const flag = (key, fallback) => (config[key] === undefined ? fallback : yes(config[key]));
  return [
    flag('access.token.claim', defaults.access) && 'access',
    flag('id.token.claim', defaults.id) && 'id',
    flag('userinfo.token.claim', defaults.userinfo) && 'userinfo',
    flag('introspection.token.claim', defaults.introspection) && 'introspection',
  ].filter(Boolean);
}

/**
 * One Keycloak ProtocolMapperRepresentation, in this system's terms.
 * @returns {{ mapper: object } | { skipped: string }}
 */
function fromKeycloakMapper(pm) {
  const c = pm.config || {};
  const tokens = tokensFromConfig(c);
  const base = { name: pm.name, tokens };
  switch (pm.protocolMapper) {
    case 'oidc-hardcoded-claim-mapper':
      return { mapper: { ...base, type: 'hardcoded', claim: c['claim.name'], value: c['claim.value'], jsonType: c['jsonType.label'] } };
    case 'oidc-usermodel-attribute-mapper':
      return {
        mapper: {
          ...base, type: 'user-attribute', claim: c['claim.name'], attribute: c['user.attribute'],
          multivalued: yes(c.multivalued), jsonType: c['jsonType.label'],
        },
      };
    case 'oidc-usermodel-property-mapper':
      return { mapper: { ...base, type: 'user-property', claim: c['claim.name'], property: c['user.attribute'], jsonType: c['jsonType.label'] } };
    case 'oidc-full-name-mapper':
      return { mapper: { ...base, type: 'full-name', claim: 'name' } };
    case 'oidc-usermodel-realm-role-mapper':
      return {
        mapper: {
          ...base, type: 'realm-roles', claim: c['claim.name'] || 'realm_access.roles',
          prefix: c['usermodel.realmRoleMapping.rolePrefix'] || '', multivalued: c.multivalued === undefined ? true : yes(c.multivalued),
        },
      };
    case 'oidc-usermodel-client-role-mapper':
      return {
        mapper: {
          ...base, type: 'client-roles', claim: c['claim.name'] || 'resource_access.${client_id}.roles',
          clientId: c['usermodel.clientRoleMapping.clientId'] || undefined,
          prefix: c['usermodel.clientRoleMapping.rolePrefix'] || '', multivalued: c.multivalued === undefined ? true : yes(c.multivalued),
        },
      };
    case 'oidc-audience-mapper':
      return {
        mapper: {
          ...base, type: 'audience',
          audience: c['included.custom.audience'] || undefined,
          audienceClient: c['included.client.audience'] || undefined,
        },
      };
    case 'oidc-audience-resolve-mapper':
      return { mapper: { ...base, type: 'audience-resolve' } };
    case 'oidc-allowed-origins-mapper':
      return { mapper: { ...base, type: 'allowed-origins' } };
    case 'oidc-acr-mapper':
      return { mapper: { ...base, type: 'acr' } };
    case 'oidc-sub-mapper':
      return { mapper: { ...base, type: 'sub' } };
    case 'oidc-group-membership-mapper':
      return { mapper: { ...base, type: 'group-membership', claim: c['claim.name'] || 'groups', fullPath: c['full.path'] === undefined ? true : yes(c['full.path']) } };
    case 'oidc-usersessionmodel-note-mapper':
      if (c['user.session.note'] === 'AUTH_TIME') return { mapper: { ...base, type: 'auth-time' } };
      // clientId / clientHost / clientAddress of the service_account scope are emitted
      // natively for client_credentials tokens.
      if (['clientId', 'clientHost', 'clientAddress', 'client_id'].includes(c['user.session.note'])) return { skipped: 'session-note (native)' };
      return { skipped: `session note '${c['user.session.note']}' is not available here` };
    default:
      return { skipped: `mapper type '${pm.protocolMapper}' is not supported` };
  }
}

module.exports = {
  STANDARD_SCOPES, DEFAULT_DEFAULT_SCOPES, DEFAULT_OPTIONAL_SCOPES,
  claimPath, setClaim, convert, activeScopes, mapClaims, audienceValue, fromKeycloakMapper,
};
