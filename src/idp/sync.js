/**
 * Synchronisation from the primary IdP (Keycloak), one way.
 * ─────────────────────────────────────────────────────────────────────────────
 * A worker reads each realm through the Keycloak Admin REST API, with a
 * read-only service account (view-realm, view-users, view-clients,
 * query-groups — never manage-*), every KEYCLOAK_SYNC_INTERVAL_SECONDS
 * (default 300) and on demand. It never writes to Keycloak.
 *
 * A realm is applied only once ALL of it has been read: realm settings,
 * roles and their composites, clients and their mappers and roles, client
 * scopes, groups, users and their role mappings and group memberships. Then
 * it replaces the realm here in one transaction. If anything fails — Keycloak
 * down, a timeout, a 403 halfway through the users — nothing is applied and
 * nothing is deleted; the realm's status says when it last succeeded, and the
 * health check reports it stale.
 *
 * A user who is gone from a complete snapshot is deleted here, and their
 * sessions end; one whose account was disabled there has their sessions ended
 * here too. Password hashes are not available through this API: they arrive
 * through POST /admin/sync/credentials (see credentials.js).
 *
 * Only one gateway instance syncs at a time (a Redis lease), and only in
 * standby mode.
 */

const { fromKeycloakMapper, STANDARD_SCOPES } = require('./mappers');
const { REALM_NAME } = require('./store');

const STATUS_KEY = 'idp:sync:status';
const LEASE_KEY = 'idp:sync:lease';
const PAGE = 100;
const CONCURRENCY = 6;
const TIMEOUT_MS = 15_000;

const DEFAULT_EXCLUDE = ['master', 't-test', 'tenant-accept-*', 'tenant-provision-*'];

function globMatcher(patterns) {
  const regexes = patterns.map((p) => new RegExp(`^${p.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*')}$`));
  return (name) => regexes.some((re) => re.test(name));
}

function listFromEnv(value) {
  return String(value || '').split(',').map((s) => s.trim()).filter(Boolean);
}

async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  async function worker() {
    while (next < items.length) {
      const index = next++;
      out[index] = await fn(items[index], index);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return out;
}

function syncConfigFromEnv(env = process.env) {
  const url = (env.KEYCLOAK_URL || '').replace(/\/+$/, '');
  return {
    configured: Boolean(url && env.KEYCLOAK_SYNC_CLIENT_ID && env.KEYCLOAK_SYNC_CLIENT_SECRET),
    url,
    tokenRealm: env.KEYCLOAK_SYNC_TOKEN_REALM || 'master',
    clientId: env.KEYCLOAK_SYNC_CLIENT_ID,
    clientSecret: env.KEYCLOAK_SYNC_CLIENT_SECRET,
    realms: listFromEnv(env.KEYCLOAK_SYNC_REALMS),
    exclude: env.KEYCLOAK_SYNC_EXCLUDE !== undefined ? listFromEnv(env.KEYCLOAK_SYNC_EXCLUDE) : DEFAULT_EXCLUDE,
    intervalSeconds: Math.max(30, Number.parseInt(env.KEYCLOAK_SYNC_INTERVAL_SECONDS, 10) || 300),
  };
}

/** A minimal Admin REST API client: one token, refreshed before it expires. */
function createAdminClient(config, fetchImpl = fetch) {
  let accessToken = null;
  let expiresAt = 0;

  async function request(url, init = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
    try {
      return await fetchImpl(url, { ...init, redirect: 'error', signal: controller.signal });
    } finally {
      clearTimeout(timer);
    }
  }

  async function token() {
    if (accessToken && Date.now() < expiresAt - 10_000) return accessToken;
    const res = await request(`${config.url}/realms/${encodeURIComponent(config.tokenRealm)}/protocol/openid-connect/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: config.clientId, client_secret: config.clientSecret }),
    });
    if (!res.ok) throw new Error(`the sync service account could not sign in to Keycloak (HTTP ${res.status})`);
    const body = await res.json();
    accessToken = body.access_token;
    expiresAt = Date.now() + (Number(body.expires_in) || 60) * 1000;
    return accessToken;
  }

  async function get(path) {
    const res = await request(`${config.url}/admin/realms${path}`, { headers: { Authorization: `Bearer ${await token()}`, Accept: 'application/json' } });
    if (res.status === 401) {
      accessToken = null;
      throw new Error(`Keycloak refused the sync token for ${path.split('?')[0]} (HTTP 401)`);
    }
    if (!res.ok) throw new Error(`GET ${path.split('?')[0]} answered HTTP ${res.status}`);
    return res.json();
  }

  async function paged(path) {
    const all = [];
    const sep = path.includes('?') ? '&' : '?';
    for (let first = 0; ; first += PAGE) {
      const page = await get(`${path}${sep}first=${first}&max=${PAGE}`);
      if (!Array.isArray(page)) throw new Error(`GET ${path.split('?')[0]} did not return a list`);
      all.push(...page);
      if (page.length < PAGE) return all;
    }
  }

  return { get, paged };
}

// ── converting Keycloak representations ─────────────────────────────────────

const splitHashes = (value) => String(value || '').split('##').map((s) => s.trim()).filter(Boolean);

function convertRole(rep, composites, clientIdByUuid) {
  const out = { realm: [], client: {} };
  for (const child of composites || []) {
    if (child.clientRole) {
      const clientId = clientIdByUuid.get(child.containerId);
      if (clientId) (out.client[clientId] ||= []).push(child.name);
    } else {
      out.realm.push(child.name);
    }
  }
  return {
    id: rep.id, name: rep.name, description: rep.description || null, composite: Boolean(rep.composite),
    composites: out, attributes: rep.attributes || {}, source: 'sync',
  };
}

function convertClient(rep, report) {
  const mappers = [];
  for (const pm of rep.protocolMappers || []) {
    const converted = fromKeycloakMapper(pm);
    if (converted.mapper) mappers.push(converted.mapper);
    else if (converted.skipped !== 'session-note (native)') report.skippedMappers.push({ client: rep.clientId, mapper: pm.name, reason: converted.skipped });
  }
  const attrs = rep.attributes || {};
  return {
    id: rep.id,
    clientId: rep.clientId,
    name: rep.name || null,
    description: rep.description || null,
    enabled: rep.enabled !== false,
    publicClient: Boolean(rep.publicClient),
    bearerOnly: Boolean(rep.bearerOnly),
    standardFlowEnabled: rep.standardFlowEnabled !== false,
    serviceAccountsEnabled: Boolean(rep.serviceAccountsEnabled),
    directAccessGrantsEnabled: Boolean(rep.directAccessGrantsEnabled),
    implicitFlowEnabled: Boolean(rep.implicitFlowEnabled),
    fullScopeAllowed: rep.fullScopeAllowed !== false,
    redirectUris: rep.redirectUris || [],
    postLogoutRedirectUris: splitHashes(attrs['post.logout.redirect.uris']),
    webOrigins: rep.webOrigins || [],
    pkceRequired: true,
    defaultClientScopes: rep.defaultClientScopes || [],
    optionalClientScopes: rep.optionalClientScopes || [],
    mappers,
    attributes: Object.fromEntries(Object.entries(attrs).filter(([key]) => ['access.token.lifespan', 'pkce.code.challenge.method'].includes(key))),
    source: 'sync',
  };
}

function convertScope(rep, report) {
  const mappers = [];
  for (const pm of rep.protocolMappers || []) {
    const converted = fromKeycloakMapper(pm);
    if (converted.mapper) mappers.push(converted.mapper);
    else if (converted.skipped !== 'session-note (native)') report.skippedMappers.push({ scope: rep.name, mapper: pm.name, reason: converted.skipped });
  }
  return {
    id: rep.id, name: rep.name, protocol: rep.protocol || 'openid-connect',
    includeInTokenScope: (rep.attributes || {})['include.in.token.scope'] !== 'false',
    mappers, source: 'sync',
  };
}

function convertUser(rep, mappings, groups) {
  const clientRoles = {};
  for (const [clientId, entry] of Object.entries(mappings?.clientMappings || {})) {
    const names = (entry.mappings || []).map((role) => role.name);
    if (names.length) clientRoles[clientId] = names;
  }
  return {
    id: rep.id,
    username: rep.username,
    email: rep.email || null,
    emailVerified: Boolean(rep.emailVerified),
    firstName: rep.firstName || null,
    lastName: rep.lastName || null,
    enabled: rep.enabled !== false,
    attributes: rep.attributes || {},
    requiredActions: rep.requiredActions || [],
    createdTimestamp: rep.createdTimestamp || null,
    realmRoles: (mappings?.realmMappings || []).map((role) => role.name),
    clientRoles,
    groups: (groups || []).map((group) => group.id),
    ...(rep.serviceAccountClientId ? { serviceAccountClientId: rep.serviceAccountClientId } : {}),
    source: 'sync',
  };
}

function convertRealm(rep, existing) {
  return {
    name: rep.realm,
    id: rep.id,
    displayName: rep.displayName || null,
    enabled: rep.enabled !== false,
    accessTokenLifespan: rep.accessTokenLifespan ?? 300,
    ssoSessionIdleTimeout: rep.ssoSessionIdleTimeout ?? 1800,
    ssoSessionMaxLifespan: rep.ssoSessionMaxLifespan ?? 36000,
    revokeRefreshToken: true,
    refreshTokenMaxReuse: 0,
    passwordPolicy: rep.passwordPolicy || '',
    bruteForceProtected: rep.bruteForceProtected !== false,
    failureFactor: rep.failureFactor ?? 30,
    maxFailureWaitSeconds: rep.maxFailureWaitSeconds ?? 900,
    loginWithEmailAllowed: rep.loginWithEmailAllowed !== false,
    defaultRole: rep.defaultRole?.name || `default-roles-${rep.realm}`,
    source: 'sync',
    managedBy: existing?.managedBy || null,
  };
}

// ── the worker ──────────────────────────────────────────────────────────────

function createSync({ store, sessions, keyring, mode, log, metrics, config, fetchImpl }) {
  const { redis } = store;
  const admin = config.configured ? createAdminClient(config, fetchImpl) : null;
  const excluded = globMatcher(config.exclude);
  let timer = null;
  let running = null;

  async function realmsToSync() {
    if (config.realms.length) return config.realms.filter((name) => REALM_NAME.test(name));
    const all = await admin.get('');
    return all.map((rep) => rep.realm).filter((name) => REALM_NAME.test(name) && !excluded(name));
  }

  /** Reads one realm completely. Throws if any part of it cannot be read. */
  async function fetchRealm(name) {
    const r = `/${encodeURIComponent(name)}`;
    const report = { skippedMappers: [], warnings: [] };
    const realmRep = await admin.get(r);
    const clientsRep = await admin.paged(`${r}/clients`);
    const clientIdByUuid = new Map(clientsRep.map((c) => [c.id, c.clientId]));

    const realmRolesRep = await admin.paged(`${r}/roles?briefRepresentation=false`);
    const realmRoles = await mapLimit(realmRolesRep, CONCURRENCY, async (role) => convertRole(role,
      role.composite ? await admin.get(`${r}/roles-by-id/${role.id}/composites`) : [], clientIdByUuid));

    const clientRoles = [];
    const clients = [];
    const serviceAccounts = [];
    await mapLimit(clientsRep, CONCURRENCY, async (rep) => {
      const client = convertClient(rep, report);
      const roles = await admin.get(`${r}/clients/${rep.id}/roles?briefRepresentation=false`);
      for (const role of roles) {
        const composites = role.composite ? await admin.get(`${r}/roles-by-id/${role.id}/composites`) : [];
        clientRoles.push({ ...convertRole(role, composites, clientIdByUuid), clientId: rep.clientId });
      }
      if (client.fullScopeAllowed === false) {
        const scope = await admin.get(`${r}/clients/${rep.id}/scope-mappings`);
        client.scopeMappings = {
          realmRoles: (scope.realmMappings || []).map((role) => role.name),
          clientRoles: Object.fromEntries(Object.entries(scope.clientMappings || {}).map(([cid, e]) => [cid, (e.mappings || []).map((role) => role.name)])),
        };
      }
      if (rep.serviceAccountsEnabled && !rep.bearerOnly && !rep.publicClient) {
        const sa = await admin.get(`${r}/clients/${rep.id}/service-account-user`);
        const mappings = await admin.get(`${r}/users/${sa.id}/role-mappings`);
        serviceAccounts.push(convertUser({ ...sa, serviceAccountClientId: rep.clientId }, mappings, []));
        client.serviceAccountUserId = sa.id;
      }
      clients.push(client);
    });

    const scopesRep = await admin.get(`${r}/client-scopes`);
    const scopes = scopesRep.filter((s) => (s.protocol || 'openid-connect') === 'openid-connect').map((s) => convertScope(s, report));
    // Keycloak versions before 25 have no 'basic' scope; sub and auth_time are emitted regardless.
    for (const standard of STANDARD_SCOPES) if (!scopes.some((s) => s.name === standard.name) && standard.name === 'basic') scopes.push({ ...standard, source: 'builtin' });

    const groups = [];
    async function walkGroups(list, parentId) {
      for (const g of list) {
        groups.push({
          id: g.id, name: g.name, path: g.path, parentId: parentId || null,
          realmRoles: g.realmRoles || [], clientRoles: g.clientRoles || {}, attributes: g.attributes || {}, source: 'sync',
        });
        // Before Keycloak 23 the list carries the whole tree; from 23 on, children are fetched per group.
        const children = g.subGroups?.length ? g.subGroups
          : g.subGroupCount > 0 ? await admin.paged(`${r}/groups/${g.id}/children?briefRepresentation=false`) : [];
        await walkGroups(children, g.id);
      }
    }
    await walkGroups(await admin.paged(`${r}/groups?briefRepresentation=false`), null);

    const usersRep = (await admin.paged(`${r}/users?briefRepresentation=false`)).filter((u) => !u.serviceAccountClientId && !String(u.username).startsWith('service-account-'));
    const users = await mapLimit(usersRep, CONCURRENCY, async (rep) => {
      const [mappings, memberOf] = await Promise.all([
        admin.get(`${r}/users/${rep.id}/role-mappings`),
        admin.get(`${r}/users/${rep.id}/groups?briefRepresentation=true`),
      ]);
      return convertUser(rep, mappings, memberOf);
    });

    return { realmRep, realmRoles, clientRoles, clients, scopes, groups, users: [...users, ...serviceAccounts], report };
  }

  async function applyRealm(name, fetched) {
    const existingRealm = await store.getRealm(name);
    if (existingRealm && existingRealm.source === 'local') {
      throw new Error(`realm '${name}' was created in this system and is not overwritten by sync`);
    }
    const before = new Map((await store.listUsers(name)).map((u) => [u.id, u]));
    const after = new Map(fetched.users.map((u) => [u.id, u]));
    const removed = [...before.keys()].filter((id) => !after.has(id));
    const bump = [...after.values()].filter((u) => before.has(u.id) && before.get(u.id).enabled !== false && u.enabled === false).map((u) => u.id);

    await store.replaceRealmSnapshot({
      realm: convertRealm(fetched.realmRep, existingRealm),
      users: fetched.users, realmRoles: fetched.realmRoles, clientRoles: fetched.clientRoles,
      clients: fetched.clients, scopes: fetched.scopes, groups: fetched.groups,
    }, { bump, removed });
    for (const id of [...removed, ...bump]) await sessions.endAllForUser(name, id);
    await keyring.ensure(name);
    return { removed, disabled: bump };
  }

  async function syncRealm(name) {
    const started = Date.now();
    const previous = JSON.parse((await redis.hget(STATUS_KEY, name)) || '{}');
    try {
      const fetched = await fetchRealm(name);
      const { removed, disabled } = await applyRealm(name, fetched);
      const status = {
        realm: name, ok: true, lastAttempt: new Date(started).toISOString(), lastSuccess: new Date().toISOString(),
        durationMs: Date.now() - started, error: null,
        counts: {
          users: fetched.users.filter((u) => !u.serviceAccountClientId).length, serviceAccounts: fetched.users.filter((u) => u.serviceAccountClientId).length,
          realmRoles: fetched.realmRoles.length, clientRoles: fetched.clientRoles.length, clients: fetched.clients.length,
          scopes: fetched.scopes.length, groups: fetched.groups.length, credentials: await store.countCredentials(name),
        },
        removedUsers: removed.length, disabledUsers: disabled.length, skippedMappers: fetched.report.skippedMappers,
      };
      await redis.hset(STATUS_KEY, name, JSON.stringify(status));
      log.audit('idp', `Synchronised realm '${name}' from the primary IdP`, { realm: name, ...status.counts, removedUsers: removed.length, disabledUsers: disabled.length });
      for (const skipped of fetched.report.skippedMappers) log.warn('idp', `Mapper not carried over in realm '${name}': ${skipped.mapper} (${skipped.reason})`, { realm: name, ...skipped });
      return status;
    } catch (err) {
      metrics.syncErrors.inc({ realm: name });
      const status = { ...previous, realm: name, ok: false, lastAttempt: new Date(started).toISOString(), error: err.message };
      await redis.hset(STATUS_KEY, name, JSON.stringify(status));
      log.error('idp', `Synchronising realm '${name}' failed; nothing was changed: ${err.message}`, { realm: name });
      return status;
    }
  }

  /** One pass over every realm, unless another instance holds the lease or this is not standby. */
  async function runOnce({ actor = 'schedule' } = {}) {
    if (!admin) return { skipped: 'not_configured' };
    if (!(await mode.isStandby())) return { skipped: 'primary_mode' };
    if (running) return running;
    running = (async () => {
      const lease = await redis.set(LEASE_KEY, String(process.pid), 'EX', 600, 'NX');
      if (!lease) return { skipped: 'another_instance' };
      try {
        let names;
        try {
          names = await realmsToSync();
        } catch (err) {
          metrics.syncErrors.inc({ realm: '*' });
          log.error('idp', `Could not list realms on the primary IdP; nothing was changed: ${err.message}`);
          await redis.hset(STATUS_KEY, '*', JSON.stringify({ ok: false, lastAttempt: new Date().toISOString(), error: err.message }));
          return { ok: false, error: err.message };
        }
        log.info('idp', `Synchronisation started (${actor}) for ${names.join(', ')}`);
        const results = [];
        for (const name of names) results.push(await syncRealm(name));
        await redis.hset(STATUS_KEY, '*', JSON.stringify({ ok: results.every((s) => s.ok), lastAttempt: new Date().toISOString(), error: null }));
        return { ok: results.every((s) => s.ok), realms: results };
      } finally {
        await redis.del(LEASE_KEY);
      }
    })();
    try { return await running; } finally { running = null; }
  }

  async function status() {
    const all = await redis.hgetall(STATUS_KEY);
    const realms = {};
    for (const [name, raw] of Object.entries(all)) if (name !== '*') realms[name] = JSON.parse(raw);
    return { configured: config.configured, intervalSeconds: config.intervalSeconds, overall: all['*'] ? JSON.parse(all['*']) : null, realms };
  }

  function start() {
    if (!admin || timer) return;
    const tick = () => runOnce().catch((err) => log.error('idp', `Synchronisation pass failed: ${err.message}`));
    setTimeout(tick, 2000).unref();
    timer = setInterval(tick, config.intervalSeconds * 1000);
    timer.unref();
  }

  function stop() {
    if (timer) clearInterval(timer);
    timer = null;
  }

  return { runOnce, syncRealm, status, start, stop, configured: config.configured };
}

module.exports = { createSync, syncConfigFromEnv, convertClient, convertUser, convertRole, STATUS_KEY };
