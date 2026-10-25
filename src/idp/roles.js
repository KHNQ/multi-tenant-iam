/**
 * Effective roles: everything an account holds, and every reason it holds it.
 * ─────────────────────────────────────────────────────────────────────────────
 * Keycloak puts a user's *effective* roles in a token — the ones mapped to the
 * user directly, the ones its groups (and their parent groups) carry, and,
 * transitively, every role a composite among those contains. Applications
 * check for the contained role, so leaving composites unexpanded would quietly
 * deny access the primary system grants.
 *
 * The same walk feeds the administration panel, which must show each role with
 * all of its reasons: a role held both directly and through a group needs two
 * removals, and reporting one of them would be a lie of exactly the shape that
 * causes an incident.
 */

const SEP = '\u001f';

const qualify = (ref) => (ref.source === 'client' ? `client:${ref.client}/${ref.name}` : `realm:${ref.name}`);

/** Indexes a realm's catalogue for the walk. */
function buildCatalogue({ realmRoles = [], clientRoles = [], groups = [] }) {
  return {
    realm: new Map(realmRoles.map((role) => [role.name, role])),
    client: new Map(clientRoles.map((role) => [`${role.clientId}${SEP}${role.name}`, role])),
    groups: new Map(groups.map((group) => [group.id, group])),
  };
}

function lookup(catalogue, ref) {
  return ref.source === 'client' ? catalogue.client.get(`${ref.client}${SEP}${ref.name}`) : catalogue.realm.get(ref.name);
}

function childRefs(role) {
  const out = [];
  for (const name of role?.composites?.realm || []) out.push({ source: 'realm', name });
  for (const [client, names] of Object.entries(role?.composites?.client || {})) {
    for (const name of names) out.push({ source: 'client', client, name });
  }
  return out;
}

function mappedRefs(holder) {
  const out = [];
  for (const name of holder?.realmRoles || []) out.push({ source: 'realm', name });
  for (const [client, names] of Object.entries(holder?.clientRoles || {})) {
    for (const name of names) out.push({ source: 'client', client, name });
  }
  return out;
}

/** The group and every ancestor of it, nearest first. */
function groupLineage(catalogue, groupId) {
  const lineage = [];
  const seen = new Set();
  let group = catalogue.groups.get(groupId);
  while (group && !seen.has(group.id)) {
    seen.add(group.id);
    lineage.push(group);
    group = group.parentId ? catalogue.groups.get(group.parentId) : null;
  }
  return lineage;
}

/**
 * @returns {Map<string, { ref, role, grants: Array<{ origin: 'direct'|'group'|'composite', via: string|null }> }>}
 *   keyed by qualified name; roles that are mapped but no longer defined are left out
 */
function resolve(catalogue, user) {
  const held = new Map();
  const queue = [];

  function add(ref, grant) {
    const role = lookup(catalogue, ref);
    if (!role) return;
    const key = qualify(ref);
    let entry = held.get(key);
    if (!entry) {
      entry = { ref: { source: ref.source, client: ref.source === 'client' ? ref.client : null, name: ref.name }, role, grants: [] };
      held.set(key, entry);
      queue.push(entry);
    }
    if (!entry.grants.some((g) => g.origin === grant.origin && g.via === grant.via)) entry.grants.push(grant);
  }

  for (const ref of mappedRefs(user)) add(ref, { origin: 'direct', via: null });
  for (const groupId of user?.groups || []) {
    for (const group of groupLineage(catalogue, groupId)) {
      for (const ref of mappedRefs(group)) add(ref, { origin: 'group', via: group.path });
    }
  }
  while (queue.length) {
    const entry = queue.shift();
    for (const child of childRefs(entry.role)) add(child, { origin: 'composite', via: qualify(entry.ref) });
  }
  return held;
}

/** Every role reachable from one role through composites, the role itself included. */
function closure(catalogue, ref) {
  const out = new Map();
  const queue = [ref];
  while (queue.length) {
    const next = queue.shift();
    const key = qualify(next);
    const role = lookup(catalogue, next);
    if (!role || out.has(key)) continue;
    out.set(key, { ...next, client: next.source === 'client' ? next.client : null });
    queue.push(...childRefs(role));
  }
  return out;
}

/**
 * Splits effective roles into what a token carries: realm role names, and
 * role names per client. With `client.fullScopeAllowed === false` only the
 * client's own roles and its scope mappings may appear (Keycloak's role scope).
 */
function tokenRoles(catalogue, user, client) {
  const held = resolve(catalogue, user);
  let allowed = null;
  if (client && client.fullScopeAllowed === false) {
    allowed = new Set();
    for (const ref of mappedRefs(client.scopeMappings || {})) {
      for (const key of closure(catalogue, ref).keys()) allowed.add(key);
    }
  }
  const realm = [];
  const clients = {};
  for (const [key, { ref }] of held) {
    const ownRole = client && ref.source === 'client' && ref.client === client.clientId;
    if (allowed && !ownRole && !allowed.has(key)) continue;
    if (ref.source === 'realm') realm.push(ref.name);
    else (clients[ref.client] ||= []).push(ref.name);
  }
  return { realm, clients };
}

const SYSTEM_CLIENTS = new Set(['realm-management', 'account', 'account-console', 'broker', 'admin-cli', 'security-admin-console']);
const ADMIN_REALM_ROLES = new Set(['platform-admin', 'tenant-admin', 'admin', 'realm-admin']);

/**
 * An administrative role is one that lets its holder change who may do what:
 * the realm-management client's roles, the platform's admin roles, permission
 * approvers, and any composite that drags one of those in.
 */
function isAdministrative(catalogue, ref) {
  for (const reached of closure(catalogue, ref).values()) {
    if (reached.source === 'client' && reached.client === 'realm-management') return true;
    if (reached.source === 'realm' && (ADMIN_REALM_ROLES.has(reached.name) || reached.name.startsWith('approve-permissions:'))) return true;
  }
  return false;
}

module.exports = {
  qualify, buildCatalogue, lookup, childRefs, resolve, closure, tokenRoles, isAdministrative, groupLineage, SYSTEM_CLIENTS,
};
