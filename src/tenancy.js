/**
 * Multi-tenancy data layer.
 * ─────────────────────────────────────────────────────────────────────────────
 * Every registered service is a TENANT. A tenant owns:
 *   - its own set of role names          (tenant:{id}:roles)
 *   - its own membership list            (tenant:{id}:members)
 *   - its own administrators             (tenant:{id}:admins)
 *   - who may do which part of administering it  (tenant:{id}:perm:{permission})
 *   - the Casbin policies for its URL prefix  (/{id}/...)
 *
 * IDENTITY IS GLOBAL, MEMBERSHIP IS PER-TENANT.
 * One person = one `user:{username}` account = one password = one JWT. That
 * same identity can be a member of several tenants with a *different* set of
 * roles in each. This is what lets the gateway stay a single login surface
 * while each service still governs its own users — the alternative (a separate
 * user table per tenant) would mean a person needs one account per service and
 * the JWT would have to name a tenant, which defeats the point of a shared
 * gateway.
 *
 * Casbin naming
 * ─────────────
 * Casbin has ONE flat subject space, and `g(x, x)` is true for any x. So if a
 * user and a role can ever be spelled the same way, the user IS the role: an
 * account that signs up as `blue_role` inherits blue_role's policies, and one
 * that signs up as `platform_admin` inherits the platform. Every subject is
 * therefore written with a prefix the gateway adds itself, and nothing a
 * person types is ever used as a subject on its own:
 *
 *     u:{userId}                    a user — userId is a server-generated UUID,
 *                                   never the username
 *     r:{roleName}                  a platform role      e.g.  r:blue_role
 *     t:{tenantId}:{roleName}       a tenant role        e.g.  t:llm:engineer
 *
 * The three prefixes are disjoint by construction, and role and tenant names
 * are validated to contain no ':' so one namespace cannot be spelled from
 * inside another. `g(u:…, t:llm:engineer)` and
 * `p(t:llm:engineer, /llm/claude, get)` are ordinary Casbin rows; cross-tenant
 * leakage stays structurally impossible because a tenant can only write
 * policies whose resource sits under its own `/{id}/` prefix (enforced by
 * ownsResource below) and can only grant subjects carrying its own `t:{id}:`
 * prefix.
 */

// --- KEYS ---

const TENANTS_INDEX_KEY = 'tenants:index';

/** Seeded into every new tenant: blanket read access to that tenant's own paths. */
const DEFAULT_TENANT_ROLE = 'service_user';

const tenantKey = (id) => `tenant:${id}`;
const tenantRolesKey = (id) => `tenant:${id}:roles`;
const tenantMembersKey = (id) => `tenant:${id}:members`;
const tenantAdminsKey = (id) => `tenant:${id}:admins`;
const tenantPermissionKey = (id, permission) => `tenant:${id}:perm:${permission}`;

// Administering a tenant is four different jobs, and "tenant admin" used to
// mean all of them at once: whoever could add a colleague could also repoint
// the service at another host. Each is now its own grant.
//
//   members        who belongs to the tenant
//   roles          which roles exist, and who holds them
//   policies       what each role may reach
//   destinations   where the service lives (its baseUrl, catalogUrl, endpoints)
//
// A full administrator (tenant:{id}:admins) holds all four, and is the only
// one who can hand them out or change the tenant itself.
const TENANT_PERMISSIONS = ['members', 'roles', 'policies', 'destinations'];
// Deliberately NOT `user:{username}:tenants`: the gateway backfills its user
// index from a `user:*` key scan, so anything hung off that prefix gets read
// back as a username. Its own namespace keeps the two apart.
const userTenantsKey = (username) => `usertenants:${username}`;
const tenantRequestsKey = (id) => `requests:tenant:${id}`;

// --- NAMING RULES ---

// Tenant ids double as URL path segments (/gateway/{id}/...) and as Casbin
// subject fragments (t:{id}:{role}), so ':' and '/' must be impossible.
const TENANT_ID_RE = /^[a-z0-9][a-z0-9_-]{1,62}$/;
const ROLE_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$/;
// Usernames are Redis key fragments (user:{username}) and URL path segments.
// They are never Casbin subjects (see userSubject below), so this is about
// keeping keys and paths unambiguous, not about authorization. Wide enough for
// an email address; no ':' '/' ',' or whitespace.
const USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._@+-]{1,63}$/;

// Path segments the gateway already routes itself — a tenant with one of these
// ids would shadow a real endpoint.
const RESERVED_TENANT_IDS = new Set([
  'admin', 'admin-ui', 'auth', 'catalog', 'docs', 'docs.json', 'gateway',
  'health', 'me', 'mine', 'portal', 'public', 'register', 'requests',
  'service', 'services', 'tenant-ui', 'tenants',
]);

function validateTenantId(id) {
  if (typeof id !== 'string' || !TENANT_ID_RE.test(id)) {
    return 'Tenant/service id must be 2-63 chars, lowercase letters, digits, "-" or "_", starting with a letter or digit';
  }
  if (RESERVED_TENANT_IDS.has(id)) {
    return `'${id}' is a reserved name`;
  }
  return null;
}

function validateRoleName(role) {
  if (typeof role !== 'string' || !ROLE_NAME_RE.test(role)) {
    return 'Role name must be 1-63 chars: letters, digits, "-" or "_", starting with a letter or digit';
  }
  return null;
}

function validateUsername(username) {
  if (typeof username !== 'string' || !USERNAME_RE.test(username)) {
    return 'Username must be 2-64 chars: letters, digits, ".", "_", "-", "+" or "@", starting with a letter or digit';
  }
  return null;
}

// --- CASBIN SUBJECT NAMING ---

const USER_SUBJECT_PREFIX = 'u:';
const PLATFORM_ROLE_PREFIX = 'r:';

/** The Casbin subject for an account. Built from its immutable id, not its name. */
const userSubject = (userId) => `${USER_SUBJECT_PREFIX}${userId}`;

/** Inverse of userSubject. Returns null for anything that is not a user subject. */
function parseUserSubject(subject) {
  if (typeof subject !== 'string' || !subject.startsWith(USER_SUBJECT_PREFIX)) return null;
  return subject.slice(USER_SUBJECT_PREFIX.length) || null;
}

/** The Casbin subject for a platform (non-tenant) role. */
const platformRoleSubject = (role) => `${PLATFORM_ROLE_PREFIX}${role}`;

/** Inverse of platformRoleSubject. Returns null for anything that is not a platform role. */
function parsePlatformRole(subject) {
  if (typeof subject !== 'string' || !subject.startsWith(PLATFORM_ROLE_PREFIX)) return null;
  return subject.slice(PLATFORM_ROLE_PREFIX.length) || null;
}

const qualifyRole = (tenantId, role) => `t:${tenantId}:${role}`;

/** Inverse of qualifyRole. Returns null for user and platform-role subjects. */
function parseQualifiedRole(subject) {
  if (typeof subject !== 'string' || !subject.startsWith('t:')) return null;
  const sep = subject.indexOf(':', 2);
  if (sep === -1) return null;
  const tenantId = subject.slice(2, sep);
  const role = subject.slice(sep + 1);
  if (!tenantId || !role) return null;
  return { tenantId, role };
}

/**
 * Is this resource path inside the tenant's own namespace?
 * The gateway routes /gateway/{serviceName}/... to the service registered
 * under that name, so "/{id}" and everything beneath it is exactly the surface
 * this tenant is responsible for — and nothing else is.
 */
function ownsResource(tenantId, resource) {
  return resource === `/${tenantId}` || resource.startsWith(`/${tenantId}/`);
}

// --- FACTORY ---

/** A tenant's resource attributes, as stored (JSON) -> an object; {} if unset or unreadable. */
function parseAttributes(raw) {
  try {
    const parsed = JSON.parse(raw || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

/**
 * @param {object} deps
 * @param {import('ioredis').Redis} deps.redis
 * @param {(fn: Function) => Promise<any>} deps.withCasbin  serialises model access
 * @param {() => object} deps.getEnforcer                   resolves the live enforcer
 * @param {(username: string) => Promise<string|null>} deps.userSubjectFor
 *   resolves an account's Casbin subject (u:{id}), or null if there is no such
 *   account. Membership Sets are keyed by username; Casbin rows never are.
 * @param {(subject: string, resource: string, action: string, condition: object|null) => Promise<boolean>} deps.addPolicyRow
 *   adds one policy row, stored together with its attribute condition if it has one
 */
function createTenancy({ redis, withCasbin, getEnforcer, userSubjectFor, addPolicyRow }) {
  const casbin = (fn) => withCasbin(() => fn(getEnforcer()));

  /** Every Casbin subject this account holds; none if the account is gone. */
  async function subjectsHeldBy(username) {
    const subject = await userSubjectFor(username);
    if (!subject) return [];
    return casbin((e) => e.getRolesForUser(subject));
  }

  // --- TENANT CRUD ---

  function normalizeTenant(hash) {
    if (!hash || !hash.id) return null;
    return {
      id: hash.id,
      displayName: hash.displayName || hash.id,
      description: hash.description || '',
      baseUrl: hash.baseUrl || '',
      owner: hash.owner || null,
      // What attribute conditions see as resource.* for this tenant's service.
      attributes: parseAttributes(hash.attributes),
      status: hash.status || 'active',
      source: hash.source || 'manual',
      createdAt: hash.createdAt,
      updatedAt: hash.updatedAt || hash.createdAt,
    };
  }

  async function tenantExists(id) {
    return (await redis.sismember(TENANTS_INDEX_KEY, id)) === 1;
  }

  async function getTenant(id) {
    return normalizeTenant(await redis.hgetall(tenantKey(id)));
  }

  async function listTenantIds() {
    return redis.smembers(TENANTS_INDEX_KEY);
  }

  async function listTenants() {
    const ids = await listTenantIds();
    const tenants = (await Promise.all(ids.map(getTenant))).filter(Boolean);
    tenants.sort((a, b) => a.id.localeCompare(b.id));
    return tenants;
  }

  /**
   * Creates a tenant. Idempotent by design: a service that re-registers on
   * every restart must not wipe the roles and memberships its admins built up,
   * so an existing tenant is refreshed (baseUrl/displayName) rather than reset.
   *
   * @returns {Promise<{ tenant: object, created: boolean }>}
   */
  async function createTenant({ id, displayName, description, baseUrl, owner, source = 'manual', seedDefaults = true }) {
    const now = new Date().toISOString();
    // Claimed atomically: of two callers creating the same tenant at once
    // (a registration and the periodic sync, say), exactly one creates it and
    // the other takes the existing-tenant path below — so an owner written by
    // one can never be overwritten by the other's blank record.
    const claimed = await redis.hsetnx(tenantKey(id), 'id', id);
    const existing = claimed ? null : await getTenant(id);

    if (existing) {
      const patch = {};
      if (baseUrl && baseUrl !== existing.baseUrl) patch.baseUrl = baseUrl;
      if (displayName && displayName !== existing.displayName) patch.displayName = displayName;
      // An unowned auto-provisioned tenant can still be claimed by its first
      // real owner; an owned one never changes hands implicitly.
      if (owner && !existing.owner) patch.owner = owner;

      // Only write when something actually differs. This path runs for every
      // service on every sync tick, and stamping updatedAt each time would
      // both churn Redis and make the field mean "last sync" rather than
      // "last change".
      if (Object.keys(patch).length > 0) {
        await redis.hset(tenantKey(id), { ...patch, updatedAt: now });
      }
      if (owner && !existing.owner) await addTenantAdmin(id, owner);
      return { tenant: await getTenant(id), created: false };
    }

    await redis.hset(tenantKey(id), {
      id,
      displayName: displayName || id,
      description: description || '',
      baseUrl: baseUrl || '',
      status: 'active',
      source,
      createdAt: now,
      updatedAt: now,
    });
    // Never over an owner a concurrent caller has already set on this tenant.
    await redis.hsetnx(tenantKey(id), 'owner', owner || '');
    await redis.sadd(TENANTS_INDEX_KEY, id);

    if (seedDefaults) {
      // Every new tenant starts with one role and one matching policy, so a
      // freshly registered service is usable immediately instead of needing
      // three more calls before anything works.
      //
      // Named `service_user`, not `member`: membership and roles are separate
      // gates here (you can be a member of a tenant holding no role at all,
      // which is exactly what a tenant admin who only administers looks like),
      // and calling the role "member" made two different things share a word.
      await defineTenantRole(id, DEFAULT_TENANT_ROLE);
      await casbin((e) => e.addPolicy(qualifyRole(id, DEFAULT_TENANT_ROLE), `/${id}/*`, 'get'));
    }

    if (owner) await addTenantAdmin(id, owner);

    return { tenant: await getTenant(id), created: true };
  }

  async function updateTenant(id, patch) {
    const fields = { updatedAt: new Date().toISOString() };
    for (const key of ['displayName', 'description', 'baseUrl', 'status', 'owner']) {
      if (patch[key] !== undefined) fields[key] = patch[key] === null ? '' : String(patch[key]);
    }
    if (patch.attributes !== undefined) fields.attributes = JSON.stringify(patch.attributes);
    await redis.hset(tenantKey(id), fields);
    return getTenant(id);
  }

  /**
   * Deletes a tenant and everything Casbin knows about it: every policy whose
   * subject carries this tenant's prefix, and every grant of those roles. A
   * leftover `g(alice, t:gone:admin)` row would otherwise silently re-grant
   * access if the tenant name were ever reused.
   */
  async function deleteTenant(id) {
    const roles = await listTenantRoles(id);

    for (const role of roles) {
      const subject = qualifyRole(id, role);
      await casbin((e) => e.removeFilteredPolicy(0, subject));
      await casbin((e) => e.removeFilteredGroupingPolicy(1, subject));
    }
    // Sweep any policy still pointing at this tenant's URL namespace
    // (a platform-level rule, or one written before a role was renamed).
    const stalePolicies = (await casbin((e) => e.getPolicy()))
      .filter(([, resource]) => ownsResource(id, resource));
    for (const [subject, resource, action] of stalePolicies) {
      await casbin((e) => e.removePolicy(subject, resource, action));
    }

    const members = await listTenantMembers(id);
    const pipeline = redis.pipeline();
    for (const username of members) pipeline.srem(userTenantsKey(username), id);
    pipeline.del(tenantKey(id), tenantRolesKey(id), tenantMembersKey(id), tenantAdminsKey(id), tenantRequestsKey(id));
    pipeline.del(...TENANT_PERMISSIONS.map((permission) => tenantPermissionKey(id, permission)));
    pipeline.srem(TENANTS_INDEX_KEY, id);
    await pipeline.exec();
  }

  // --- ROLES ---

  async function listTenantRoles(id) {
    const roles = await redis.smembers(tenantRolesKey(id));
    return roles.sort();
  }

  async function tenantRoleExists(id, role) {
    return (await redis.sismember(tenantRolesKey(id), role)) === 1;
  }

  async function defineTenantRole(id, role) {
    await redis.sadd(tenantRolesKey(id), role);
  }

  /** Drops the role, its policies, and every grant of it. */
  async function deleteTenantRole(id, role) {
    const subject = qualifyRole(id, role);
    await casbin((e) => e.removeFilteredPolicy(0, subject));
    await casbin((e) => e.removeFilteredGroupingPolicy(1, subject));
    await redis.srem(tenantRolesKey(id), role);
  }

  /** Role names this user holds *within* one tenant, unqualified. */
  async function getUserTenantRoles(id, username) {
    const all = await subjectsHeldBy(username);
    return all
      .map(parseQualifiedRole)
      .filter((parsed) => parsed && parsed.tenantId === id)
      .map((parsed) => parsed.role)
      .sort();
  }

  /** Every tenant role this user holds, grouped by tenant id. */
  async function getUserRolesByTenant(username) {
    const all = await subjectsHeldBy(username);
    const byTenant = {};
    for (const subject of all) {
      const parsed = parseQualifiedRole(subject);
      if (!parsed) continue;
      (byTenant[parsed.tenantId] ||= []).push(parsed.role);
    }
    for (const roles of Object.values(byTenant)) roles.sort();
    return byTenant;
  }

  async function grantTenantRole(id, username, role) {
    const subject = await userSubjectFor(username);
    // Refuse rather than fall back to the name: a grant written against a
    // username would attach to whoever holds that name next.
    if (!subject) throw new Error(`Cannot grant a role to '${username}': no such account`);
    await casbin((e) => e.addRoleForUser(subject, qualifyRole(id, role)));
    await addTenantMember(id, username);
  }

  async function revokeTenantRole(id, username, role) {
    const subject = await userSubjectFor(username);
    if (!subject) return false;
    return casbin((e) => e.deleteRoleForUser(subject, qualifyRole(id, role)));
  }

  async function hasTenantRole(id, username, role) {
    const subject = await userSubjectFor(username);
    if (!subject) return false;
    return casbin((e) => e.hasRoleForUser(subject, qualifyRole(id, role)));
  }

  // --- MEMBERSHIP ---

  async function listTenantMembers(id) {
    const members = await redis.smembers(tenantMembersKey(id));
    return members.sort();
  }

  async function isTenantMember(id, username) {
    return (await redis.sismember(tenantMembersKey(id), username)) === 1;
  }

  async function addTenantMember(id, username) {
    await redis.sadd(tenantMembersKey(id), username);
    await redis.sadd(userTenantsKey(username), id);
  }

  /** Removing a member strips their roles too — membership is the outer gate. */
  async function removeTenantMember(id, username) {
    for (const role of await getUserTenantRoles(id, username)) {
      await revokeTenantRole(id, username, role);
    }
    await redis.srem(tenantMembersKey(id), username);
    await redis.srem(tenantAdminsKey(id), username);
    for (const permission of TENANT_PERMISSIONS) await redis.srem(tenantPermissionKey(id, permission), username);
    await redis.srem(userTenantsKey(username), id);
  }

  /** Called when a user account is deleted platform-wide. */
  async function purgeUserFromAllTenants(username) {
    const ids = await redis.smembers(userTenantsKey(username));
    const pipeline = redis.pipeline();
    for (const id of ids) {
      pipeline.srem(tenantMembersKey(id), username);
      pipeline.srem(tenantAdminsKey(id), username);
      for (const permission of TENANT_PERMISSIONS) pipeline.srem(tenantPermissionKey(id, permission), username);
    }
    pipeline.del(userTenantsKey(username));
    await pipeline.exec();
    return ids;
  }

  // --- TENANT ADMINISTRATORS ---
  //
  // Tenant-admin is an *API surface* permission ("may call /tenants/llm/users"),
  // not a gateway-resource permission, so it lives in Redis rather than as a
  // Casbin role: authorizing an admin call stays a single SISMEMBER instead of
  // queueing behind the enforcer's serialisation chain, and there is exactly
  // one place to look to answer "who can administer this tenant".

  async function listTenantAdmins(id) {
    const admins = await redis.smembers(tenantAdminsKey(id));
    return admins.sort();
  }

  async function isTenantAdmin(id, username) {
    return (await redis.sismember(tenantAdminsKey(id), username)) === 1;
  }

  async function addTenantAdmin(id, username) {
    await addTenantMember(id, username);
    await redis.sadd(tenantAdminsKey(id), username);
  }

  async function removeTenantAdmin(id, username) {
    await redis.srem(tenantAdminsKey(id), username);
  }

  // --- DELEGATED PERMISSIONS ---
  //
  // Same storage decision as the admin set above, for the same reason: these
  // are API-surface permissions, resolved from Redis on every call so that
  // taking one away takes effect at once on every gateway instance.

  /** The permissions this user has been given individually (not counting full admin). */
  async function getDelegatedPermissions(id, username) {
    const held = await Promise.all(
      TENANT_PERMISSIONS.map((permission) => redis.sismember(tenantPermissionKey(id, permission), username)),
    );
    return TENANT_PERMISSIONS.filter((_, i) => held[i] === 1);
  }

  /** What this user may actually do here: everything if a full admin, else what was delegated. */
  async function getTenantPermissions(id, username) {
    if (await isTenantAdmin(id, username)) return [...TENANT_PERMISSIONS];
    return getDelegatedPermissions(id, username);
  }

  /**
   * Replaces the user's delegated permissions with exactly `permissions`.
   * @returns {Promise<{ granted: string[], revoked: string[] }>}
   */
  async function setDelegatedPermissions(id, username, permissions) {
    const before = await getDelegatedPermissions(id, username);
    const granted = permissions.filter((permission) => !before.includes(permission));
    const revoked = before.filter((permission) => !permissions.includes(permission));

    await addTenantMember(id, username);
    for (const permission of granted) await redis.sadd(tenantPermissionKey(id, permission), username);
    for (const permission of revoked) await redis.srem(tenantPermissionKey(id, permission), username);
    return { granted, revoked };
  }

  /** Tenants this user belongs to, each annotated with their standing in it. */
  async function listTenantsForUser(username) {
    const ids = await redis.smembers(userTenantsKey(username));
    const rolesByTenant = await getUserRolesByTenant(username);
    const tenants = await Promise.all(ids.map(async (id) => {
      const tenant = await getTenant(id);
      if (!tenant) return null;
      return {
        ...tenant,
        roles: rolesByTenant[id] || [],
        isAdmin: await isTenantAdmin(id, username),
        permissions: await getTenantPermissions(id, username),
      };
    }));
    return tenants.filter(Boolean).sort((a, b) => a.id.localeCompare(b.id));
  }

  // --- POLICIES ---

  /** Casbin rows whose subject belongs to this tenant. */
  async function listTenantPolicies(id) {
    const rules = await casbin((e) => e.getPolicy());
    return rules
      .map(([subject, resource, action]) => ({ subject, resource, action }))
      .filter((p) => {
        const parsed = parseQualifiedRole(p.subject);
        return parsed && parsed.tenantId === id;
      })
      .map((p) => ({ ...p, role: parseQualifiedRole(p.subject).role }));
  }

  async function addTenantPolicy(id, role, resource, action, condition = null) {
    return addPolicyRow(qualifyRole(id, role), resource, action, condition);
  }

  async function removeTenantPolicy(id, role, resource, action) {
    return casbin((e) => e.removePolicy(qualifyRole(id, role), resource, action));
  }

  return {
    // keys + naming (exported so callers can build their own queries)
    TENANTS_INDEX_KEY, tenantRequestsKey, userTenantsKey,
    userSubject, parseUserSubject, platformRoleSubject, parsePlatformRole,
    qualifyRole, parseQualifiedRole, ownsResource,
    validateTenantId, validateRoleName, validateUsername, RESERVED_TENANT_IDS, DEFAULT_TENANT_ROLE,

    // tenants
    tenantExists, getTenant, listTenants, listTenantIds,
    createTenant, updateTenant, deleteTenant,

    // roles
    listTenantRoles, tenantRoleExists, defineTenantRole, deleteTenantRole,
    getUserTenantRoles, getUserRolesByTenant,
    grantTenantRole, revokeTenantRole, hasTenantRole,

    // membership
    listTenantMembers, isTenantMember, addTenantMember, removeTenantMember,
    purgeUserFromAllTenants, listTenantsForUser,

    // admins
    listTenantAdmins, isTenantAdmin, addTenantAdmin, removeTenantAdmin,

    // delegated permissions
    TENANT_PERMISSIONS, getDelegatedPermissions, getTenantPermissions, setDelegatedPermissions,

    // policies
    listTenantPolicies, addTenantPolicy, removeTenantPolicy,
  };
}

module.exports = {
  createTenancy,
  // Pure helpers, usable without a Redis client (the registry validates
  // service names with the same rules the gateway validates tenant ids).
  validateTenantId,
  validateRoleName,
  validateUsername,
  userSubject,
  parseUserSubject,
  platformRoleSubject,
  parsePlatformRole,
  qualifyRole,
  parseQualifiedRole,
  ownsResource,
  RESERVED_TENANT_IDS,
  DEFAULT_TENANT_ROLE,
  TENANT_PERMISSIONS,
};
