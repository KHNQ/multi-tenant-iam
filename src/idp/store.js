/**
 * The identity provider's data, in Redis.
 * ─────────────────────────────────────────────────────────────────────────────
 * One namespace per realm (`idp:{realm}:…`). Each kind of object is one hash
 * whose fields are JSON documents, so that a realm's whole configuration can be
 * replaced in a single MULTI/EXEC when it is synchronised from the primary
 * system: either every user, role and client of the new snapshot is in place,
 * or none of it is — a partial sync never leaves a user without a role.
 *
 * What the primary system does not own is kept apart, in keys the sync never
 * writes, so that replacing a snapshot cannot undo it:
 *   - `creds`        password hashes (imported or set here), sealed at rest;
 *   - `secver`       each account's security version — moved whenever its
 *                    sessions must end (disabled, password changed, deleted);
 *   - `user-local`   an emergency lock placed in this system;
 *   - `client-local` this system's own client secret, and redirect URIs and
 *                    origins added here (this system's own host names);
 *   - `keys`         this system's signing keys, which are never shared.
 *
 * Writes to one document are compare-and-set (a Lua script), so two
 * administrators — or two gateway instances — cannot overwrite each other.
 */

const REALM_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const SEP = '\u001f';

const k = {
  realms: 'idp:realms',
  realm: (r) => `idp:realm:${r}`,
  users: (r) => `idp:${r}:users`,
  usernames: (r) => `idp:${r}:usernames`,
  emails: (r) => `idp:${r}:emails`,
  userLocal: (r) => `idp:${r}:user-local`,
  secver: (r) => `idp:${r}:secver`,
  creds: (r) => `idp:${r}:creds`,
  roles: (r) => `idp:${r}:roles`,
  clientRoles: (r) => `idp:${r}:client-roles`,
  clients: (r) => `idp:${r}:clients`,
  clientLocal: (r) => `idp:${r}:client-local`,
  scopes: (r) => `idp:${r}:scopes`,
  groups: (r) => `idp:${r}:groups`,
  keys: (r) => `idp:${r}:keys`,
  keysVersion: (r) => `idp:${r}:keys:version`,
};

const LUA = {
  cas: `
    local cur = redis.call('HGET', KEYS[1], ARGV[1])
    if (cur or '') ~= ARGV[2] then return 0 end
    if ARGV[3] == '' then redis.call('HDEL', KEYS[1], ARGV[1]) else redis.call('HSET', KEYS[1], ARGV[1], ARGV[3]) end
    return 1
  `,
  // KEYS: users, usernames, emails   ARGV: id, json, username(lower), email(lower or '')
  createUser: `
    if redis.call('HEXISTS', KEYS[2], ARGV[3]) == 1 then return 'username' end
    if ARGV[4] ~= '' and redis.call('HEXISTS', KEYS[3], ARGV[4]) == 1 then return 'email' end
    if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return 'id' end
    redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
    redis.call('HSET', KEYS[2], ARGV[3], ARGV[1])
    if ARGV[4] ~= '' then redis.call('HSET', KEYS[3], ARGV[4], ARGV[1]) end
    return 'ok'
  `,
  // KEYS: users, emails   ARGV: id, expected json, new json, old email(lower), new email(lower)
  updateUser: `
    local cur = redis.call('HGET', KEYS[1], ARGV[1])
    if not cur then return 'missing' end
    if cur ~= ARGV[2] then return 'stale' end
    if ARGV[5] ~= ARGV[4] and ARGV[5] ~= '' then
      local owner = redis.call('HGET', KEYS[2], ARGV[5])
      if owner and owner ~= ARGV[1] then return 'email' end
    end
    redis.call('HSET', KEYS[1], ARGV[1], ARGV[3])
    if ARGV[5] ~= ARGV[4] then
      if ARGV[4] ~= '' and redis.call('HGET', KEYS[2], ARGV[4]) == ARGV[1] then redis.call('HDEL', KEYS[2], ARGV[4]) end
      if ARGV[5] ~= '' then redis.call('HSET', KEYS[2], ARGV[5], ARGV[1]) end
    end
    return 'ok'
  `,
};

const parse = (raw) => (raw ? JSON.parse(raw) : null);
const lower = (value) => String(value || '').toLowerCase();

class StaleWrite extends Error {}

function createStore(redis) {
  redis.defineCommand('idpCas', { numberOfKeys: 1, lua: LUA.cas });
  redis.defineCommand('idpCreateUser', { numberOfKeys: 3, lua: LUA.createUser });
  redis.defineCommand('idpUpdateUser', { numberOfKeys: 2, lua: LUA.updateUser });

  /**
   * Read-modify-write of one JSON field, retried while somebody else wins.
   * `mutate` returns the new document, or undefined to leave it unchanged,
   * or null to delete it.
   */
  async function updateField(key, field, mutate) {
    for (let attempt = 0; attempt < 8; attempt++) {
      const raw = await redis.hget(key, field);
      const current = parse(raw);
      const next = await mutate(current);
      if (next === undefined) return current;
      const ok = await redis.idpCas(key, field, raw || '', next === null ? '' : JSON.stringify(next));
      if (ok === 1) return next;
    }
    throw new StaleWrite(`Too many concurrent changes to ${key} ${field}`);
  }

  const hvals = async (key) => (await redis.hvals(key)).map((raw) => JSON.parse(raw));
  const hgetJson = async (key, field) => parse(await redis.hget(key, field));

  // ── realms ────────────────────────────────────────────────────────────────

  const listRealmNames = async () => (await redis.smembers(k.realms)).sort();
  const getRealm = async (name) => (REALM_NAME.test(name || '') ? parse(await redis.get(k.realm(name))) : null);
  async function listRealms() {
    const names = await listRealmNames();
    return (await Promise.all(names.map(getRealm))).filter(Boolean);
  }
  async function putRealm(realm) {
    if (!REALM_NAME.test(realm.name)) throw new Error(`'${realm.name}' is not a valid realm name`);
    await redis.multi().set(k.realm(realm.name), JSON.stringify(realm)).sadd(k.realms, realm.name).exec();
    return realm;
  }

  // ── users ─────────────────────────────────────────────────────────────────

  const getUser = (realm, id) => (typeof id === 'string' && id ? hgetJson(k.users(realm), id) : null);
  async function findUserByUsername(realm, username) {
    const id = await redis.hget(k.usernames(realm), lower(username));
    return id ? getUser(realm, id) : null;
  }
  async function findUserByEmail(realm, email) {
    const id = await redis.hget(k.emails(realm), lower(email));
    return id ? getUser(realm, id) : null;
  }
  const listUsers = (realm) => hvals(k.users(realm));

  /** @returns {Promise<'ok'|'username'|'email'|'id'>} */
  async function createUser(realm, user) {
    return redis.idpCreateUser(k.users(realm), k.usernames(realm), k.emails(realm),
      user.id, JSON.stringify(user), lower(user.username), user.email ? lower(user.email) : '');
  }

  /**
   * @param {(user) => object|undefined} mutate the new document, or undefined for no change
   * @returns {Promise<{ user?: object, problem?: 'missing'|'email' }>}
   */
  async function updateUser(realm, id, mutate) {
    for (let attempt = 0; attempt < 8; attempt++) {
      const raw = await redis.hget(k.users(realm), id);
      if (!raw) return { problem: 'missing' };
      const current = JSON.parse(raw);
      const next = await mutate(current);
      if (next === undefined) return { user: current };
      const outcome = await redis.idpUpdateUser(k.users(realm), k.emails(realm), id, raw, JSON.stringify(next),
        current.email ? lower(current.email) : '', next.email ? lower(next.email) : '');
      if (outcome === 'ok') return { user: next };
      if (outcome !== 'stale') return { problem: outcome };
    }
    throw new StaleWrite(`Too many concurrent changes to user ${id}`);
  }

  async function deleteUser(realm, id) {
    const user = await getUser(realm, id);
    if (!user) return false;
    const multi = redis.multi().hdel(k.users(realm), id).hdel(k.creds(realm), id).hdel(k.userLocal(realm), id)
      .hincrby(k.secver(realm), id, 1);
    if ((await redis.hget(k.usernames(realm), lower(user.username))) === id) multi.hdel(k.usernames(realm), lower(user.username));
    if (user.email && (await redis.hget(k.emails(realm), lower(user.email))) === id) multi.hdel(k.emails(realm), lower(user.email));
    await multi.exec();
    return true;
  }

  const getSecurityVersion = async (realm, id) => Number(await redis.hget(k.secver(realm), id)) || 0;
  const bumpSecurityVersion = (realm, id) => redis.hincrby(k.secver(realm), id, 1);

  const getUserLocal = async (realm, id) => (await hgetJson(k.userLocal(realm), id)) || {};
  const updateUserLocal = (realm, id, mutate) => updateField(k.userLocal(realm), id, async (cur) => mutate(cur || {}));

  // ── credentials (sealed by the caller) ────────────────────────────────────

  const getCredential = (realm, id) => redis.hget(k.creds(realm), id);
  const setCredential = (realm, id, sealed) => redis.hset(k.creds(realm), id, sealed);
  const hasCredential = async (realm, id) => (await redis.hexists(k.creds(realm), id)) === 1;
  const countCredentials = (realm) => redis.hlen(k.creds(realm));

  // ── roles ─────────────────────────────────────────────────────────────────

  const listRealmRoles = (realm) => hvals(k.roles(realm));
  const getRealmRole = (realm, name) => hgetJson(k.roles(realm), name);
  const putRealmRole = (realm, role) => redis.hset(k.roles(realm), role.name, JSON.stringify(role));
  const updateRealmRole = (realm, name, mutate) => updateField(k.roles(realm), name, mutate);

  const clientRoleField = (clientId, name) => `${clientId}${SEP}${name}`;
  async function listClientRoles(realm, clientId) {
    const all = await hvals(k.clientRoles(realm));
    return clientId === undefined ? all : all.filter((role) => role.clientId === clientId);
  }
  const getClientRole = (realm, clientId, name) => hgetJson(k.clientRoles(realm), clientRoleField(clientId, name));
  const putClientRole = (realm, role) => redis.hset(k.clientRoles(realm), clientRoleField(role.clientId, role.name), JSON.stringify(role));
  const updateClientRole = (realm, clientId, name, mutate) => updateField(k.clientRoles(realm), clientRoleField(clientId, name), mutate);

  /**
   * Deletes a client role and every reference to it — user and group
   * mappings, and other roles' composites — as Keycloak does.
   */
  async function deleteClientRole(realm, clientId, name) {
    const drop = (holder) => {
      const names = holder?.clientRoles?.[clientId];
      if (!names?.includes(name)) return undefined;
      const rest = names.filter((n) => n !== name);
      const clientRoles = { ...holder.clientRoles };
      if (rest.length) clientRoles[clientId] = rest; else delete clientRoles[clientId];
      return { ...holder, clientRoles };
    };
    const dropComposite = (role) => {
      const names = role?.composites?.client?.[clientId];
      if (!names?.includes(name)) return undefined;
      const client = { ...role.composites.client, [clientId]: names.filter((n) => n !== name) };
      return { ...role, composites: { ...role.composites, client } };
    };
    for (const user of await listUsers(realm)) await updateUser(realm, user.id, drop);
    for (const group of await listGroups(realm)) await updateGroup(realm, group.id, drop);
    for (const role of await listRealmRoles(realm)) await updateRealmRole(realm, role.name, dropComposite);
    for (const role of await listClientRoles(realm)) await updateClientRole(realm, role.clientId, role.name, dropComposite);
    return (await redis.hdel(k.clientRoles(realm), clientRoleField(clientId, name))) === 1;
  }

  // ── clients ───────────────────────────────────────────────────────────────

  /** A client as the protocol sees it: the synced definition plus this system's overlay. */
  function withOverlay(client, overlay) {
    if (!client) return null;
    const o = overlay || {};
    const union = (a, b) => [...new Set([...(a || []), ...(b || [])])];
    return {
      ...client,
      redirectUris: union(client.redirectUris, o.extraRedirectUris),
      postLogoutRedirectUris: union(client.postLogoutRedirectUris, o.extraPostLogoutRedirectUris),
      webOrigins: union(client.webOrigins, o.extraWebOrigins),
      secretHash: o.secretHash || null,
      secretRotatedAt: o.secretRotatedAt || null,
    };
  }

  async function getClient(realm, clientId) {
    if (typeof clientId !== 'string' || !clientId) return null;
    const [raw, overlay] = await Promise.all([redis.hget(k.clients(realm), clientId), redis.hget(k.clientLocal(realm), clientId)]);
    return withOverlay(parse(raw), parse(overlay));
  }
  async function listClients(realm) {
    const [clients, overlays] = await Promise.all([redis.hgetall(k.clients(realm)), redis.hgetall(k.clientLocal(realm))]);
    return Object.entries(clients).map(([id, raw]) => withOverlay(JSON.parse(raw), parse(overlays[id])));
  }
  const putClient = (realm, client) => redis.hset(k.clients(realm), client.clientId, JSON.stringify(client));
  async function createClient(realm, client) {
    return (await redis.hsetnx(k.clients(realm), client.clientId, JSON.stringify(client))) === 1;
  }
  const updateClient = (realm, clientId, mutate) => updateField(k.clients(realm), clientId, mutate);
  const updateClientLocal = (realm, clientId, mutate) => updateField(k.clientLocal(realm), clientId, async (cur) => mutate(cur || {}));

  // ── client scopes ─────────────────────────────────────────────────────────

  const listScopes = (realm) => hvals(k.scopes(realm));
  const putScope = (realm, scope) => redis.hset(k.scopes(realm), scope.name, JSON.stringify(scope));

  // ── groups ────────────────────────────────────────────────────────────────

  const listGroups = (realm) => hvals(k.groups(realm));
  const getGroup = (realm, id) => (id ? hgetJson(k.groups(realm), id) : null);
  const putGroup = (realm, group) => redis.hset(k.groups(realm), group.id, JSON.stringify(group));
  const updateGroup = (realm, id, mutate) => updateField(k.groups(realm), id, mutate);

  // ── snapshot replacement ──────────────────────────────────────────────────

  /**
   * Replaces everything the primary system owns in one realm, atomically.
   *
   * @param {object} snapshot { realm, users, realmRoles, clientRoles, clients, scopes, groups }
   * @param {object} effects  { bump: user ids whose sessions must end, removed: user ids no longer present }
   */
  async function replaceRealmSnapshot(snapshot, { bump = [], removed = [] } = {}) {
    const r = snapshot.realm.name;
    const multi = redis.multi();
    multi.set(k.realm(r), JSON.stringify(snapshot.realm)).sadd(k.realms, r);

    const put = (key, entries) => {
      multi.del(key);
      if (entries.length) multi.hset(key, ...entries.flat());
    };
    put(k.users(r), snapshot.users.map((u) => [u.id, JSON.stringify(u)]));
    put(k.usernames(r), snapshot.users.map((u) => [lower(u.username), u.id]));
    put(k.emails(r), snapshot.users.filter((u) => u.email).map((u) => [lower(u.email), u.id]));
    put(k.roles(r), snapshot.realmRoles.map((role) => [role.name, JSON.stringify(role)]));
    put(k.clientRoles(r), snapshot.clientRoles.map((role) => [clientRoleField(role.clientId, role.name), JSON.stringify(role)]));
    put(k.clients(r), snapshot.clients.map((c) => [c.clientId, JSON.stringify(c)]));
    put(k.scopes(r), snapshot.scopes.map((s) => [s.name, JSON.stringify(s)]));
    put(k.groups(r), snapshot.groups.map((g) => [g.id, JSON.stringify(g)]));

    for (const id of new Set([...bump, ...removed])) multi.hincrby(k.secver(r), id, 1);
    if (removed.length) multi.hdel(k.creds(r), ...removed).hdel(k.userLocal(r), ...removed);

    const results = await multi.exec();
    const failed = results.find(([err]) => err);
    if (failed) throw failed[0];
  }

  return {
    keys: k,
    redis,
    updateField,
    listRealmNames, listRealms, getRealm, putRealm,
    getUser, findUserByUsername, findUserByEmail, listUsers, createUser, updateUser, deleteUser,
    getSecurityVersion, bumpSecurityVersion, getUserLocal, updateUserLocal,
    getCredential, setCredential, hasCredential, countCredentials,
    listRealmRoles, getRealmRole, putRealmRole, updateRealmRole,
    listClientRoles, getClientRole, putClientRole, updateClientRole, deleteClientRole,
    getClient, listClients, putClient, createClient, updateClient, updateClientLocal,
    listScopes, putScope,
    listGroups, getGroup, putGroup, updateGroup,
    replaceRealmSnapshot,
  };
}

module.exports = { createStore, REALM_NAME, StaleWrite };
