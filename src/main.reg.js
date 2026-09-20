
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const Redis = require('ioredis');
const { newEnforcer, newModelFromString, Helper } = require('casbin');
const { createProxyMiddleware } = require('http-proxy-middleware');
const swaggerUi = require('swagger-ui-express');
const { spec } = require('./swagger');
const { createLogger } = require('./logger');
const { createTenancy, validateTenantId, validateRoleName, ownsResource } = require('./tenancy');

const log = createLogger('gateway');

const app = express();
app.use(express.json());
app.use(log.requestLogger());
app.use('/docs', swaggerUi.serve, swaggerUi.setup(spec, { customSiteTitle: 'IAM Gateway API' }));
app.get('/docs.json', (req, res) => res.json(spec));
// --- CONSOLE ---
// One page, one sign-in. Which panels it shows is decided by the server's
// answer to /me, not by the URL: opening /admin-ui grants nothing, and there
// is no view here that a bare fetch of the page could reveal. The old
// per-audience URLs still resolve so existing links and bookmarks keep
// working — they were three copies of the same login screen, which is what
// made one product feel like three.
const CONSOLE_PAGE = path.join(__dirname, 'public', 'console.html');
const serveConsole = (req, res) => res.sendFile(CONSOLE_PAGE);

// Written out one per line rather than looped over an array: the route
// inventory in endpoint-check.js is parsed out of this file, and a route
// registered from a variable is invisible to it — which would mean the
// console's own URLs silently stop being covered.
app.get('/', serveConsole);
app.get('/console', serveConsole);
app.get('/admin-ui', serveConsole);
app.get('/admin-ui/admin.html', serveConsole);
app.get('/tenant-ui', serveConsole);
app.get('/tenant-ui/index.html', serveConsole);
app.get('/portal', serveConsole);
app.get('/portal/index.html', serveConsole);

// Registered after the routes above so those exact paths are never shadowed
// by a file of the same name.
app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));


// --- CONFIGURATION ---
const JWT_SECRET = process.env.JWT_SECRET || 'super-secret-production-key';
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:7000';
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:3001';
const GATEWAY_PORT = process.env.PORT || 3000;
const SERVICE_SYNC_INTERVAL_MS = 20000;

// --- LOGIN RATE LIMITING ---
// Both thresholds count FAILED login attempts only (see rationale above
// the helpers below) — successful logins never contribute to either.
const LOGIN_IP_WINDOW_SECONDS = 60;
const LOGIN_IP_MAX_ATTEMPTS = 200; // failed attempts per IP, per window, across all usernames
const LOGIN_LOCKOUT_WINDOW_SECONDS = 15 * 60;
const LOGIN_LOCKOUT_MAX_FAILURES = 5; // failed attempts per username, before temporary lockout

// Redis key namespace for Casbin policies
// Keeping it explicit so it never collides with user: or registry: keys
const CASBIN_POLICY_KEY = 'casbin:policies';

// Index Sets so we can enumerate users/roles without SCANning user:* hashes
const USERS_INDEX_KEY = 'users:index';
const ROLES_INDEX_KEY = 'roles:index';
const DEFAULT_ROLES = ['user', 'admin', 'blue_role', 'red_role', 'green_role'];

// --- SHARED REDIS CLIENT (ioredis) ---
// One client, used for: user hashes, Casbin policies, any future caching
const redis = new Redis(REDIS_URL, {
  retryStrategy(times) {
    const delay = Math.min(times * 200, 5000);
    console.warn(`[Redis] Reconnecting... attempt ${times} (delay ${delay}ms)`);
    return delay;
  },
});

redis.on('connect', () => console.log('[Redis] Connected'));
redis.on('error', (err) => console.error('[Redis] Error:', err.message));

// ---------------------------------------------------------------------------
// CUSTOM CASBIN REDIS ADAPTER
// ---------------------------------------------------------------------------
// Casbin adapters must implement: loadPolicy(model) and savePolicy(model)
// Optional: addPolicy, removePolicy, removeFilteredPolicy
//
// Storage layout:
//   casbin:policies  →  Redis List of JSON strings
//   Each element: { "ptype": "p"|"g", "rule": ["sub","obj","act"] }
//
// Why a List?
//   - Preserves insertion order (useful for debugging)
//   - RPUSH / LRANGE / DEL are all O(1) or O(N) — perfectly adequate
//   - Simple to inspect with `redis-cli LRANGE casbin:policies 0 -1`
// ---------------------------------------------------------------------------
class CasbinRedisAdapter {
  constructor(redisClient, policyKey = CASBIN_POLICY_KEY) {
    this.redis = redisClient;
    this.policyKey = policyKey;
  }

  /**
   * Loads all policies from Redis into the Casbin model.
   * Called by enforcer.loadPolicy() and enforcer.loadPolicyFromDatabase().
   *
   * @param {Model} model - Casbin internal model object
   */
  async loadPolicy(model) {
    const entries = await this.redis.lrange(this.policyKey, 0, -1);

    for (const entry of entries) {
      let parsed;
      try {
        parsed = JSON.parse(entry);
      } catch {
        console.warn('[Casbin] Skipping malformed policy entry:', entry);
        continue;
      }

      // Helper.loadPolicyLine expects a CSV string like "p, sub, obj, act"
      // or "g, user, role"
      const line = [parsed.ptype, ...parsed.rule].join(', ');
      Helper.loadPolicyLine(line, model);
    }

    console.log(`[Casbin] Loaded ${entries.length} policy entries from Redis`);
  }

  /**
   * Persists the entire current model state to Redis.
   * Casbin calls this after any addPolicy / removePolicy operation
   * when using non-auto-save adapters. We enable autoSave so Casbin
   * calls addPolicy/removePolicy directly instead.
   *
   * @param {Model} model
   */
  async savePolicy(model) {
    const pipeline = this.redis.pipeline();
    pipeline.del(this.policyKey);

    // Iterate policy sections: p (policy), g (role)
    for (const [ptype, assertions] of Object.entries(model.model)) {
      // ptype is the section letter: 'p' or 'g'
      for (const [, assertion] of Object.entries(assertions)) {
        for (const rule of assertion.policy) {
          pipeline.rpush(
            this.policyKey,
            JSON.stringify({ ptype, rule }),
          );
        }
      }
    }

    await pipeline.exec();
    console.log('[Casbin] Policies saved to Redis');
  }

  /**
   * Adds a single policy rule.
   * Called by enforcer.addPolicy() / enforcer.addRoleForUser()
   * when autoSave is true (the default).
   *
   * @param {string} sec   - section: 'p' or 'g'
   * @param {string} ptype - policy type: 'p' or 'g'
   * @param {string[]} rule
   */
  async addPolicy(sec, ptype, rule) {
    await this.redis.rpush(
      this.policyKey,
      JSON.stringify({ ptype, rule }),
    );
  }

  /**
   * Removes a single policy rule (exact match).
   * Called by enforcer.removePolicy() / enforcer.deleteRoleForUser().
   *
   * Strategy: load all → filter out the target → rewrite the list.
   * This is O(N) but Casbin policy lists are typically tiny (<1000 rows).
   *
   * @param {string} sec
   * @param {string} ptype
   * @param {string[]} rule
   */
  async removePolicy(sec, ptype, rule) {
    const entries = await this.redis.lrange(this.policyKey, 0, -1);
    const targetJson = JSON.stringify({ ptype, rule });

    // Filter out the first matching entry
    let removed = false;
    const remaining = entries.filter((e) => {
      if (!removed && e === targetJson) {
        removed = true;
        return false; // drop it
      }
      return true;
    });

    if (!removed) return; // nothing to do

    const pipeline = this.redis.pipeline();
    pipeline.del(this.policyKey);
    for (const entry of remaining) {
      pipeline.rpush(this.policyKey, entry);
    }
    await pipeline.exec();
  }

  /**
   * Removes all policy rules that match a partial filter.
   * Called by enforcer.deleteRolesForUser(), removeFilteredPolicy(), etc.
   *
   * @param {string} sec
   * @param {string} ptype
   * @param {number} fieldIndex - which rule index to start matching from
   * @param {...string} fieldValues - values to match (empty string = wildcard)
   */
  async removeFilteredPolicy(sec, ptype, fieldIndex, ...fieldValues) {
    const entries = await this.redis.lrange(this.policyKey, 0, -1);

    const remaining = entries.filter((e) => {
      let parsed;
      try {
        parsed = JSON.parse(e);
      } catch {
        return true; // keep unparseable entries (shouldn't happen)
      }

      if (parsed.ptype !== ptype) return true; // different section, keep it

      // Check whether every provided fieldValue matches at the right index
      const matches = fieldValues.every((val, i) => {
        const ruleIndex = fieldIndex + i;
        // Empty string acts as a wildcard (Casbin convention)
        return val === '' || parsed.rule[ruleIndex] === val;
      });

      return !matches; // keep entries that do NOT match the filter
    });

    const pipeline = this.redis.pipeline();
    pipeline.del(this.policyKey);
    for (const entry of remaining) {
      pipeline.rpush(this.policyKey, entry);
    }
    await pipeline.exec();
  }
}

// --- CASBIN SETUP ---
let enforcer;

// --- MULTI-TENANCY ---
// Populated by initIAM() once the enforcer is live, because every tenant
// operation that touches roles or policies goes through the same serialised
// Casbin chain as the rest of the gateway (see withCasbin below).
let tenancy;

// --- CASBIN CONCURRENCY GUARD ---
//
// Casbin's in-memory policy model is a set of plain JS arrays mutated in
// place by addPolicy/removePolicy/addRoleForUser/deleteRoleForUser/etc,
// and enforce() iterates those same arrays via an internal async
// generator (coreEnforcer.js's privateEnforce). Node is single-threaded,
// but these calls are all async (they await the adapter's Redis I/O) —
// so a policy mutation triggered by one request and an enforce() call
// triggered by another can interleave. If a mutation splices an array
// out from under an in-flight enforce() iteration, Casbin throws
// "Cannot read properties of undefined (reading '0')" and the request
// fails with a 500 (see README §3.5 / load-test findings). Casbin has
// no built-in locking for this, so every operation that touches the
// shared model is funneled through this single promise chain instead.
// This is cheap: a single enforce()/addPolicy() call is pure in-memory
// CPU work taking microseconds, so serializing them doesn't become a
// throughput bottleneck even at high request concurrency — it just
// guarantees no two model-touching calls are ever mid-flight together.
let casbinChain = Promise.resolve();
function withCasbin(fn) {
  const run = casbinChain.then(fn, fn);
  casbinChain = run.then(() => {}, () => {});
  return run;
}

const rbacModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && r.act == p.act || r.sub == "admin" || g(r.sub, "platform_admin")
`;

// --- SERVICE REGISTRY CLIENT ---

/**
 * Fetches all active services from the Service Registry.
 * @returns {Promise<Map<string, object>>}
 */
async function fetchServicesFromRegistry() {
  const { default: fetch } = await import('node-fetch');

  const response = await fetch(`${REGISTRY_URL}/services?status=active`);
  if (!response.ok) {
    throw new Error(`Registry responded with HTTP ${response.status}`);
  }

  const { services } = await response.json();

  const serviceMap = new Map();
  for (const svc of services) {
    serviceMap.set(svc.name, {
      baseUrl: svc.baseUrl,
      catalogUrl: svc.catalogUrl || '',
      version: svc.version,
      owner: svc.owner,
      status: svc.status,
      health: svc.health,
      displayName: svc.displayName || svc.name,
      description: svc.description || '',
      endpoints: svc.endpoints,
    });
  }

  return serviceMap;
}

// --- IN-MEMORY SERVICE CACHE ---
let serviceCache = new Map();
let lastSyncTime = null;

/**
 * Syncs the local service cache from the remote registry.
 */
async function syncServicesFromRegistry() {
  try {
    serviceCache = await fetchServicesFromRegistry();
    lastSyncTime = new Date().toISOString();

    const names = Array.from(serviceCache.keys()).join(', ') || '(none)';
    console.log(`[Gateway] Service cache synced. Active: [${names}]`);
  } catch (err) {
    console.warn(`[Gateway] ⚠️  Registry sync failed: ${err.message}`);
    console.warn(`[Gateway]    Using stale cache (${serviceCache.size} services)`);
  }
}

/**
 * Every registered service IS a tenant. This is the bridge between the two
 * halves of the system: the registry owns routing (where does /llm go), the
 * gateway owns identity (who may call it), and a service that exists in one
 * but not the other is a service nobody can administer. Provisioning is
 * idempotent and never resets an existing tenant, so the services that
 * self-register on every restart don't wipe the roles and memberships their
 * admins built up.
 *
 * Tenants provisioned this way start unowned — a machine registering itself
 * has no user identity to hand ownership to. A platform admin assigns an owner
 * (POST /admin/tenants/:id/owner), or the service is registered through
 * POST /tenants/register instead, which makes the caller its first admin.
 */
async function provisionTenantsFromServices() {
  if (!tenancy) return { created: [], total: 0 };

  const created = [];
  for (const [name, cfg] of serviceCache.entries()) {
    if (validateTenantId(name)) continue; // not a legal tenant id — skip quietly
    const result = await tenancy.createTenant({
      id: name,
      displayName: cfg.displayName || name,
      baseUrl: cfg.baseUrl,
      source: 'registry',
    });
    if (result.created) {
      created.push(name);
      log.audit('tenant', `Tenant '${name}' auto-provisioned from the service registry`, { tenant: name });
    }
  }
  return { created, total: serviceCache.size };
}

/** Cache refresh plus tenant provisioning — the periodic/boot path. */
async function syncAndProvision() {
  await syncServicesFromRegistry();
  await provisionTenantsFromServices().catch((err) =>
    log.error('tenant', `Tenant provisioning failed: ${err.message}`, { error: err.message }));
}

/**
 * Looks up a service from cache, falling back to a live registry fetch.
 * @param {string} serviceName
 * @returns {Promise<object|null>}
 */
async function getServiceConfig(serviceName) {
  if (serviceCache.has(serviceName)) {
    return serviceCache.get(serviceName);
  }

  console.log(`[Gateway] Cache miss for '${serviceName}', hitting registry...`);

  try {
    const { default: fetch } = await import('node-fetch');
    const response = await fetch(`${REGISTRY_URL}/services/${serviceName}`);

    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`HTTP ${response.status}`);

    const svc = await response.json();
    if (svc.status !== 'active') return null;

    serviceCache.set(serviceName, svc);
    return svc;
  } catch (err) {
    console.error(`[Gateway] Registry lookup failed for '${serviceName}': ${err.message}`);
    return null;
  }
}

// --- IAM INITIALIZATION ---
async function initIAM() {
  // Wait for Redis to be ready before proceeding
  await new Promise((resolve, reject) => {
    if (redis.status === 'ready') return resolve();
    redis.once('ready', resolve);
    redis.once('error', reject);
  });

  console.log('[IAM] Redis connection confirmed');

  const adapter = new CasbinRedisAdapter(redis);
  const model = newModelFromString(rbacModel);
  enforcer = await newEnforcer(model, adapter);
  await withCasbin(() => enforcer.loadPolicy());

  tenancy = createTenancy({
    redis,
    withCasbin,
    getEnforcer: () => enforcer,
  });

  console.log('[IAM] Casbin Authorization Engine Initialized');
  console.log('[IAM] Multi-tenancy layer ready');
}

// --- REDIS USER HELPERS ---
// Thin wrappers so route handlers don't speak raw Redis commands

async function userExists(username) {
  return (await redis.hexists(`user:${username}`, 'password')) === 1;
}

async function getUser(username) {
  return redis.hgetall(`user:${username}`);
}

async function createUser(username, passwordHash, role = 'user') {
  await redis.hset(`user:${username}`, {
    password: passwordHash,
    role,
  });
  await redis.sadd(USERS_INDEX_KEY, username);
}

async function setUserRole(username, role) {
  await redis.hset(`user:${username}`, 'role', role);
}

async function deleteUser(username) {
  await redis.del(`user:${username}`);
  await redis.srem(USERS_INDEX_KEY, username);
}

async function listAllUsernames() {
  return redis.smembers(USERS_INDEX_KEY);
}

/**
 * Backfills the users:index Set from any pre-existing user:* hashes.
 * Only needed once per fresh Redis population; SADD is idempotent so
 * running it on every boot is harmless.
 */
async function backfillUserIndex() {
  const keys = await redis.keys('user:*');
  if (keys.length === 0) return 0;

  // Only Hashes are user records. A `user:*` key of any other type belongs to
  // some other feature that hung its data off this prefix, and adding it here
  // would put a non-username into the index — every later getUser() on it then
  // fails with WRONGTYPE and takes GET /admin/users down with it.
  const types = await Promise.all(keys.map((k) => redis.type(k)));
  const usernames = keys
    .filter((_, i) => types[i] === 'hash')
    .map((k) => k.slice('user:'.length));

  if (usernames.length === 0) return 0;
  await redis.sadd(USERS_INDEX_KEY, ...usernames);
  return usernames.length;
}

/**
 * Drops index entries that don't resolve to a real user Hash. Self-heals an
 * index polluted by an earlier backfill (see above) instead of leaving
 * /admin/users permanently broken.
 */
async function pruneUserIndex() {
  const names = await redis.smembers(USERS_INDEX_KEY);
  const types = await Promise.all(names.map((n) => redis.type(`user:${n}`)));
  const stale = names.filter((_, i) => types[i] !== 'hash');
  if (stale.length) {
    await redis.srem(USERS_INDEX_KEY, ...stale);
    log.warn('iam', `Pruned ${stale.length} non-user entr(ies) from the user index`, { stale });
  }
  return stale.length;
}

async function addRoleToIndex(role) {
  await redis.sadd(ROLES_INDEX_KEY, role);
}

async function listAllRoles() {
  return redis.smembers(ROLES_INDEX_KEY);
}

async function roleIsDefined(role) {
  return (await redis.sismember(ROLES_INDEX_KEY, role)) === 1;
}

// --- ACCESS REQUESTS (self-service role/service requests, admin-approved) ---
//
// Regular users can't call /admin/roles themselves, so this is the queue
// that lets them ask for a role (or access to a service, which the UI
// resolves to one of that service's rolesWithAccess) without an admin
// having to hand out credentials out-of-band. Approving a request performs
// the exact same grant /admin/roles does; rejecting just closes it out.
// Stored the same way as users/roles: a Hash per request plus Sets for
// enumeration, so it survives restarts without a new storage engine.

const REQUESTS_INDEX_KEY = 'requests:index';
function requestKey(id) { return `request:${id}`; }
function userRequestsKey(username) { return `requests:user:${username}`; }
function tenantRequestsKey(tenantId) { return `requests:tenant:${tenantId}`; }

function normalizeRequest(data) {
  return {
    id: data.id,
    username: data.username,
    // null tenant = a platform-level request (a global role like blue_role),
    // which only the platform admin can resolve. A tenant id routes the
    // request to that tenant's own admins instead.
    tenant: data.tenant || null,
    role: data.role || null,
    service: data.service || null,
    note: data.note || '',
    status: data.status,
    requestedAt: data.requestedAt,
    resolvedAt: data.resolvedAt || null,
    resolvedBy: data.resolvedBy || null,
    grantedRole: data.grantedRole || null,
  };
}

async function createAccessRequest({ username, tenant, role, service, note }) {
  const id = crypto.randomUUID();
  await redis.hset(requestKey(id), {
    id, username, tenant: tenant || '', role: role || '', service: service || '', note: note || '',
    status: 'pending', requestedAt: new Date().toISOString(),
    resolvedAt: '', resolvedBy: '', grantedRole: '',
  });
  await redis.sadd(REQUESTS_INDEX_KEY, id);
  await redis.sadd(userRequestsKey(username), id);
  if (tenant) await redis.sadd(tenantRequestsKey(tenant), id);
  return getAccessRequest(id);
}

async function getAccessRequest(id) {
  const data = await redis.hgetall(requestKey(id));
  if (!data || !data.id) return null;
  return normalizeRequest(data);
}

async function listAccessRequests({ username, status, tenant } = {}) {
  const ids = username
    ? await redis.smembers(userRequestsKey(username))
    : tenant
      ? await redis.smembers(tenantRequestsKey(tenant))
      : await redis.smembers(REQUESTS_INDEX_KEY);
  const requests = (await Promise.all(ids.map(getAccessRequest))).filter(Boolean);
  let filtered = status ? requests.filter((r) => r.status === status) : requests;
  // A username lookup returns that user's requests across every tenant, so the
  // tenant filter still has to be applied on the way out.
  if (tenant && username) filtered = filtered.filter((r) => r.tenant === tenant);
  filtered.sort((a, b) => new Date(b.requestedAt) - new Date(a.requestedAt));
  return filtered;
}

async function resolveAccessRequest(id, status, resolvedBy, grantedRole = '') {
  await redis.hset(requestKey(id), {
    status, resolvedAt: new Date().toISOString(), resolvedBy, grantedRole,
  });
  return getAccessRequest(id);
}

// --- PASSWORD HASHING (Argon2, with lazy migration from legacy bcrypt) ---
//
// Every password hashed by this codebase from now on uses Argon2id
// (memory-hard, GPU/ASIC-resistant — the current OWASP-recommended
// default for new systems, see README §3.6). Accounts created before
// this change still have bcrypt hashes ($2a$/$2b$/$2y$ prefix) sitting
// in Redis; rather than a one-off migration script (which would need
// plaintext passwords it doesn't have), we verify those with bcrypt on
// their next successful login and transparently re-hash with Argon2,
// so the whole user base migrates itself off bcrypt over time with no
// forced resets and no dual-write complexity.

function isBcryptHash(hash) {
  return typeof hash === 'string' && /^\$2[aby]\$/.test(hash);
}

async function hashPassword(password) {
  return argon2.hash(password);
}

/**
 * Verifies a password against a stored hash of either format.
 * @returns {Promise<{ valid: boolean, rehash: string|null }>}
 *   rehash is set when a legacy bcrypt hash just verified successfully,
 *   so the caller can persist the upgraded Argon2 hash.
 */
async function verifyPassword(password, storedHash) {
  if (isBcryptHash(storedHash)) {
    const valid = await bcrypt.compare(password, storedHash);
    if (!valid) return { valid: false, rehash: null };
    const rehash = await hashPassword(password);
    return { valid: true, rehash };
  }

  const valid = await argon2.verify(storedHash, password).catch(() => false);
  return { valid, rehash: null };
}

// --- TOKEN VERSIONING / REVOCATION ---
//
// JWTs are stateless by design (§3.5 of the README) — the gateway
// never has to touch Redis to authenticate a request, which is exactly
// what lets it re-evaluate role/policy on every call cheaply. But that
// same statelessness means a token is valid for its full lifetime no
// matter what happens to the account afterwards. tokenVersion closes
// that gap for the one scenario that matters most (a credential reset
// after suspected compromise) without turning every request back into
// a Redis round trip for *validity* — it's a single extra HGET, already
// paid for by getUser() elsewhere in the same request in most routes.
async function getTokenVersion(username) {
  const v = await redis.hget(`user:${username}`, 'tokenVersion');
  return v ? parseInt(v, 10) : 0;
}

async function bumpTokenVersion(username) {
  await redis.hincrby(`user:${username}`, 'tokenVersion', 1);
}

function revokedJtiKey(jti) {
  return `revoked:jti:${jti}`;
}

async function revokeJti(jti, ttlSeconds) {
  if (ttlSeconds <= 0) return;
  await redis.set(revokedJtiKey(jti), '1', 'EX', ttlSeconds);
}

async function isJtiRevoked(jti) {
  return (await redis.exists(revokedJtiKey(jti))) === 1;
}

// --- RATE LIMITING (Redis-backed, correct across multiple gateway instances) ---
//
// express-rate-limit's default store is in-process memory, which is
// wrong here: this gateway is explicitly designed to run as multiple
// instances behind a load balancer (README §4). Counting in Redis
// means every instance shares the same view of "how many failed
// attempts has this IP/username made", so horizontal scaling doesn't
// quietly disable the limiter.
//
// Both counters count FAILURES, not total requests: a legitimate user
// (or a test suite) logging in successfully many times in a row should
// never be throttled — only repeated wrong-password/unknown-user
// attempts, which is the actual credential-stuffing signal.

function failureKey(scope, id) {
  return `ratelimit:login:${scope}:${id}`;
}

async function getFailureCount(scope, id) {
  const key = failureKey(scope, id);
  const [count, ttl] = await Promise.all([redis.get(key), redis.ttl(key)]);
  return { count: count ? parseInt(count, 10) : 0, retryAfterSeconds: ttl > 0 ? ttl : 0 };
}

async function recordFailure(scope, id, windowSeconds) {
  const key = failureKey(scope, id);
  const count = await redis.incr(key);
  if (count === 1) {
    await redis.expire(key, windowSeconds);
  }
  return count;
}

async function clearFailures(scope, id) {
  await redis.del(failureKey(scope, id));
}

// --- VALIDATION HELPERS ---

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

// --- AUTHENTICATION ROUTES ---

/**
 * Signs a token carrying the account's current tokenVersion and a
 * unique jti, so it can later be invalidated either by revoking that
 * one jti (logout) or by bumping tokenVersion (password change/reset,
 * which invalidates every outstanding token for the account at once).
 */
function signToken(username, role, tokenVersion, expiresIn = '24h') {
  const jti = crypto.randomUUID();
  return jwt.sign({ username, role, tokenVersion, jti }, JWT_SECRET, { expiresIn });
}

app.post('/auth/signup', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  if (await userExists(username)) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const hash = await hashPassword(password);
  await createUser(username, hash, 'user');
  await withCasbin(() => enforcer.addRoleForUser(username, 'user'));

  log.audit('auth', `User '${username}' signed up`, { username, ip: req.ip });
  res.status(201).json({ message: 'User registered successfully' });
});

app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;

  if (typeof username !== 'string' || typeof password !== 'string' ||
      !username.trim() || !password.trim()) {
    return res.status(400).json({ error: 'Missing credentials' });
  }

  const ipFailures = await getFailureCount('ip', req.ip);
  if (ipFailures.count >= LOGIN_IP_MAX_ATTEMPTS) {
    log.warn('auth', `Login rate limit exceeded for IP`, { ip: req.ip, failures: ipFailures.count });
    res.set('Retry-After', String(ipFailures.retryAfterSeconds));
    return res.status(429).json({ error: 'Too many failed login attempts from this address, try again later' });
  }

  const userFailures = await getFailureCount('user', username);
  if (userFailures.count >= LOGIN_LOCKOUT_MAX_FAILURES) {
    log.warn('auth', `Login blocked: account temporarily locked`, { username, ip: req.ip, failures: userFailures.count });
    res.set('Retry-After', String(userFailures.retryAfterSeconds));
    return res.status(429).json({ error: 'Account temporarily locked due to repeated failed logins, try again later' });
  }

  const userData = await getUser(username);
  if (!userData?.password) {
    await Promise.all([
      recordFailure('ip', req.ip, LOGIN_IP_WINDOW_SECONDS),
      recordFailure('user', username, LOGIN_LOCKOUT_WINDOW_SECONDS),
    ]);
    log.audit('auth', `Login failed: unknown user`, { username, ip: req.ip });
    return res.status(401).json({ error: 'Invalid user' });
  }

  const { valid, rehash } = await verifyPassword(password, userData.password);
  if (!valid) {
    await Promise.all([
      recordFailure('ip', req.ip, LOGIN_IP_WINDOW_SECONDS),
      recordFailure('user', username, LOGIN_LOCKOUT_WINDOW_SECONDS),
    ]);
    log.audit('auth', `Login failed: bad password`, { username, ip: req.ip });
    return res.status(401).json({ error: 'Invalid password' });
  }

  await clearFailures('user', username);
  if (rehash) {
    // Legacy bcrypt hash just verified successfully — migrate it to Argon2
    // transparently now that we have the plaintext in hand.
    await redis.hset(`user:${username}`, 'password', rehash);
    log.info('auth', `Password hash migrated from bcrypt to Argon2`, { username });
  }

  const tokenVersion = await getTokenVersion(username);
  const token = signToken(username, userData.role, tokenVersion);

  log.audit('auth', `User '${username}' logged in`, { username, ip: req.ip });
  res.json({ token, message: 'Login successful' });
});

// --- MIDDLEWARES ---

const authenticateJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Missing or invalid token' });
  }

  let payload;
  try {
    payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET);
  } catch {
    return res.status(403).json({ error: 'Token expired or invalid' });
  }

  // Explicit revocation (logout) — checked by unique token id.
  if (payload.jti && (await isJtiRevoked(payload.jti))) {
    return res.status(401).json({ error: 'Token has been revoked, please log in again' });
  }

  // Blanket revocation (password change/reset) — checked by version stamp.
  // Tokens issued before this endpoint existed have no tokenVersion claim;
  // treat that as version 0 so they keep working until the first bump.
  const currentVersion = await getTokenVersion(payload.username);
  if ((payload.tokenVersion ?? 0) !== currentVersion) {
    return res.status(401).json({ error: 'Token has been revoked, please log in again' });
  }

  req.user = payload;
  next();
};

const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  next();
};

// --- SELF-SERVICE ROUTES (any authenticated user) ---
// The browsing + request-submission side of the access-request workflow —
// counterpart to the admin queue under "-- Requests (admin) --" below.
// Deliberately excludes baseUrl from the service listing: that's an
// internal routing detail a regular user has no reason to see.

app.get('/me', authenticateJWT, async (req, res) => {
  const { username } = req.user;
  const userData = await getUser(username);
  const roles = await withCasbin(() => enforcer.getRolesForUser(username));
  const tenants = await tenancy.listTenantsForUser(username);
  res.json({
    username,
    role: userData.role,
    // Every Casbin subject the account holds, tenant-qualified ones included —
    // kept as-is so existing clients see no change...
    roles,
    isPlatformAdmin: userData.role === 'admin',
    // ...and the same information split by tenant, which is what a portal or a
    // tenant console actually needs to render.
    tenants: tenants.map((t) => ({ id: t.id, displayName: t.displayName, roles: t.roles, isAdmin: t.isAdmin })),
  });
});

/**
 * POST /me/test-access — "what do I actually get?"
 *
 * The counterpart to the admin and tenant-admin access tests, for the person
 * whose access it is. It replays the caller's OWN bearer token rather than
 * minting an impersonation one, so what comes back is literally what their
 * current session gets — including, if their token is stale or revoked, the
 * 401 they would really see.
 *
 * Because the token is the caller's own and already sits in their browser,
 * it is returned in full here; the admin-facing tests mask it, since there
 * the token belongs to somebody else.
 */
app.post('/me/test-access', authenticateJWT, async (req, res) => {
  const { username } = req.user;
  await syncServicesFromRegistry();

  const services = Array.from(serviceCache.entries()).map(([name, cfg]) => ({ name, ...cfg }));
  const ownToken = req.headers.authorization.slice('Bearer '.length);
  const probe = await probeServiceAccessAs(username, services, { token: ownToken, reveal: true });

  log.audit('self-service', `User '${username}' tested their own access`, { username });

  res.json({
    username,
    roles: await withCasbin(() => enforcer.getRolesForUser(username)),
    tenants: (await tenancy.listTenantsForUser(username)).map((t) => ({ id: t.id, roles: t.roles })),
    testedAt: new Date().toISOString(),
    token: probe.token,
    services: probe.services,
  });
});

app.get('/catalog/services', authenticateJWT, async (req, res) => {
  await syncServicesFromRegistry();
  const rules = await withCasbin(() => enforcer.getPolicy());
  const policies = rules.map(([subject, resource, action]) => ({ subject, resource, action }));

  const myTenants = new Set((await tenancy.listTenantsForUser(req.user.username)).map((t) => t.id));

  const services = await Promise.all(Array.from(serviceCache.entries()).map(async ([name, cfg]) => {
    const tenant = await tenancy.getTenant(name);
    return {
      name,
      owner: cfg.owner,
      version: cfg.version,
      status: cfg.status,
      endpoints: cfg.endpoints || [],
      // Platform-level subjects, unchanged for existing clients.
      rolesWithAccess: [...new Set(policiesForService(name, cfg.endpoints, policies).map((p) => p.subject))],
      // ...plus the tenant that governs this service, and the role names to
      // ask it for. A tenant role is what a request against this service
      // should target now; the platform roles above are the legacy path.
      tenant: tenant ? {
        id: tenant.id,
        displayName: tenant.displayName,
        status: tenant.status,
        roles: await tenancy.listTenantRoles(tenant.id),
        joined: myTenants.has(tenant.id),
      } : null,
    };
  }));

  res.json({ count: services.length, services });
});

app.get('/catalog/roles', authenticateJWT, async (req, res) => {
  const roles = await listAllRoles();
  res.json({ count: roles.length, roles });
});

app.get('/requests/me', authenticateJWT, async (req, res) => {
  const requests = await listAccessRequests({ username: req.user.username });
  res.json({ count: requests.length, requests });
});

app.post('/requests', authenticateJWT, async (req, res) => {
  const { username } = req.user;
  const tenantId = isNonEmptyString(req.body?.tenant) ? req.body.tenant.trim() : null;
  const role = isNonEmptyString(req.body?.role) ? req.body.role.trim() : null;
  const service = isNonEmptyString(req.body?.service) ? req.body.service.trim() : null;
  const note = isNonEmptyString(req.body?.note) ? req.body.note.trim() : '';

  if (!role && !service && !tenantId) {
    return res.status(400).json({ error: 'Provide a role, a service and/or a tenant to request' });
  }

  // A request naming a tenant is validated against THAT tenant's roles and is
  // resolved by its admins; one without a tenant stays a platform request
  // against the global role list, as before.
  if (tenantId) {
    const tenant = await tenancy.getTenant(tenantId);
    if (!tenant) return res.status(404).json({ error: `Tenant '${tenantId}' does not exist` });
    if (tenant.status !== 'active') {
      return res.status(409).json({ error: `Tenant '${tenantId}' is not accepting requests (status: ${tenant.status})` });
    }
    if (role) {
      if (!(await tenancy.tenantRoleExists(tenantId, role))) {
        return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
      }
      if (await tenancy.hasTenantRole(tenantId, username, role)) {
        return res.status(409).json({ error: `You already have role '${role}' in tenant '${tenantId}'` });
      }
    }
    const pending = await listAccessRequests({ username, status: 'pending' });
    if (pending.some((r) => r.tenant === tenantId && r.role === role)) {
      return res.status(409).json({ error: `You already have a pending request for this in tenant '${tenantId}'` });
    }
  } else if (role) {
    if (!(await roleIsDefined(role))) {
      return res.status(404).json({ error: `Role '${role}' does not exist` });
    }
    if (await withCasbin(() => enforcer.hasRoleForUser(username, role))) {
      return res.status(409).json({ error: `You already have role '${role}'` });
    }
    const pending = await listAccessRequests({ username, status: 'pending' });
    if (pending.some((r) => !r.tenant && r.role === role)) {
      return res.status(409).json({ error: `You already have a pending request for role '${role}'` });
    }
  }

  const request = await createAccessRequest({ username, tenant: tenantId, role, service, note });
  log.audit('request', `User '${username}' requested ${role ? `role '${role}'` : `access to service '${service}'`}${tenantId ? ` in tenant '${tenantId}'` : ''}`, {
    username, tenant: tenantId, role, service,
  });
  res.status(201).json({ message: 'Request submitted', request });
});

// --- SESSION MANAGEMENT (revocation) ---
// Placed after authenticateJWT so both routes can use it as ordinary
// middleware, same as every other authenticated route in this file.

app.post('/auth/change-password', authenticateJWT, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!isNonEmptyString(currentPassword) || !isNonEmptyString(newPassword)) {
    return res.status(400).json({ error: 'currentPassword and newPassword are required' });
  }

  const { username } = req.user;
  const userData = await getUser(username);
  const { valid } = await verifyPassword(currentPassword, userData.password);
  if (!valid) {
    log.audit('auth', `Password change rejected: wrong current password`, { username, ip: req.ip });
    return res.status(401).json({ error: 'Current password is incorrect' });
  }

  const hash = await hashPassword(newPassword);
  await redis.hset(`user:${username}`, 'password', hash);
  await bumpTokenVersion(username);

  log.audit('auth', `User '${username}' changed their password`, { username, ip: req.ip });
  res.json({ message: 'Password changed; all existing sessions have been invalidated' });
});

app.post('/auth/logout', authenticateJWT, async (req, res) => {
  const { jti, exp, username } = req.user;
  if (jti && exp) {
    const ttlSeconds = exp - Math.floor(Date.now() / 1000);
    await revokeJti(jti, ttlSeconds);
  }
  log.audit('auth', `User '${username}' logged out`, { username, ip: req.ip });
  res.json({ message: 'Logged out' });
});

// --- ADMIN ROUTES ---

// -- Users --

app.get('/admin/users', authenticateJWT, requireAdmin, async (req, res) => {
  const usernames = await listAllUsernames();

  const users = await Promise.all(
    usernames.map(async (username) => {
      const userData = await getUser(username);
      const roles = await withCasbin(() => enforcer.getRolesForUser(username));
      return { username, role: userData.role, roles };
    }),
  );

  res.json({ count: users.length, users });
});

app.get('/admin/users/:username', authenticateJWT, requireAdmin, async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const userData = await getUser(username);
  const roles = await withCasbin(() => enforcer.getRolesForUser(username));
  res.json({ username, role: userData.role, roles });
});

app.delete('/admin/users/:username', authenticateJWT, requireAdmin, async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  await withCasbin(() => enforcer.deleteRolesForUser(username));
  // deleteRolesForUser drops the Casbin grants (tenant-qualified ones
  // included); the membership Sets are ours to clean up.
  const purgedFrom = await tenancy.purgeUserFromAllTenants(username);
  await deleteUser(username);

  log.audit('admin', `Admin '${req.user.username}' deleted user '${username}'`, {
    purgedFromTenants: purgedFrom,
    actor: req.user.username, target: username,
  });
  res.json({ message: `User '${username}' deleted` });
});

app.post('/admin/users/:username/reset-password', authenticateJWT, requireAdmin, async (req, res) => {
  const { username } = req.params;
  const { newPassword } = req.body;

  if (!isNonEmptyString(newPassword)) {
    return res.status(400).json({ error: 'newPassword is required' });
  }

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const hash = await hashPassword(newPassword);
  await redis.hset(`user:${username}`, 'password', hash);
  await bumpTokenVersion(username);

  log.audit('admin', `Admin '${req.user.username}' reset password for '${username}'`, {
    actor: req.user.username, target: username,
  });
  res.json({ message: `Password reset for '${username}'; all their existing sessions have been invalidated` });
});

// -- Roles --

app.post('/admin/roles', authenticateJWT, requireAdmin, async (req, res) => {
  const { username, role } = req.body;

  if (!isNonEmptyString(username) || !isNonEmptyString(role)) {
    return res.status(400).json({ error: 'username and role are required' });
  }

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  await setUserRole(username, role);
  await withCasbin(() => enforcer.addRoleForUser(username, role));
  await addRoleToIndex(role);

  log.audit('admin', `Admin '${req.user.username}' assigned role '${role}' to '${username}'`, {
    actor: req.user.username, target: username, role,
  });
  res.json({ message: `Role '${role}' assigned to '${username}'` });
});

app.delete('/admin/roles', authenticateJWT, requireAdmin, async (req, res) => {
  const { username, role } = req.body;

  if (!isNonEmptyString(username) || !isNonEmptyString(role)) {
    return res.status(400).json({ error: 'username and role are required' });
  }

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const hadRole = await withCasbin(() => enforcer.hasRoleForUser(username, role));
  if (!hadRole) {
    return res.status(404).json({ error: `User '${username}' does not have role '${role}'` });
  }

  await withCasbin(() => enforcer.deleteRoleForUser(username, role));

  // The Redis 'role' field is a single flat value used only for the JWT's
  // admin gate; keep it in sync with whatever role (if any) remains. Every
  // account also carries the baseline 'user' role from signup, so prefer a
  // more specific remaining role over that baseline when one exists.
  const remainingRoles = await withCasbin(() => enforcer.getRolesForUser(username));
  const specificRole = remainingRoles.find((r) => r !== 'user');
  await setUserRole(username, specificRole || remainingRoles[0] || 'user');

  log.audit('admin', `Admin '${req.user.username}' removed role '${role}' from '${username}'`, {
    actor: req.user.username, target: username, role,
  });
  res.json({ message: `Role '${role}' removed from '${username}'` });
});

app.get('/admin/roles', authenticateJWT, requireAdmin, async (req, res) => {
  const roleNames = await listAllRoles();

  const roles = await Promise.all(
    roleNames.map(async (role) => ({
      role,
      users: await withCasbin(() => enforcer.getUsersForRole(role)).catch(() => []),
    })),
  );

  res.json({ count: roles.length, roles });
});

app.post('/admin/roles/define', authenticateJWT, requireAdmin, async (req, res) => {
  const { role } = req.body;

  if (!isNonEmptyString(role)) {
    return res.status(400).json({ error: 'role is required' });
  }

  if (await roleIsDefined(role)) {
    return res.status(409).json({ error: `Role '${role}' already exists` });
  }

  await addRoleToIndex(role);
  log.audit('admin', `Admin '${req.user.username}' defined new role '${role}'`, {
    actor: req.user.username, role,
  });
  res.status(201).json({ message: `Role '${role}' defined` });
});

// -- Policies --

app.get('/admin/policies', authenticateJWT, requireAdmin, async (req, res) => {
  const rules = await withCasbin(() => enforcer.getPolicy());
  const policies = rules.map(([subject, resource, action]) => ({ subject, resource, action }));
  res.json({ count: policies.length, policies });
});

app.post('/admin/policies', authenticateJWT, requireAdmin, async (req, res) => {
  const { subject, resource, action } = req.body;

  if (!isNonEmptyString(subject) || !isNonEmptyString(resource) || !isNonEmptyString(action)) {
    return res.status(400).json({ error: 'subject, resource and action are required' });
  }

  await withCasbin(() => enforcer.addPolicy(subject, resource, action));
  log.audit('admin', `Admin '${req.user.username}' added policy`, {
    actor: req.user.username, subject, resource, action,
  });
  res.json({ message: `Policy added: ${subject} can ${action} on ${resource}` });
});

app.delete('/admin/policies', authenticateJWT, requireAdmin, async (req, res) => {
  const { subject, resource, action } = req.body;

  if (!isNonEmptyString(subject) || !isNonEmptyString(resource) || !isNonEmptyString(action)) {
    return res.status(400).json({ error: 'subject, resource and action are required' });
  }

  const removed = await withCasbin(() => enforcer.removePolicy(subject, resource, action));
  if (!removed) {
    return res.status(404).json({ error: 'Policy rule not found' });
  }

  log.audit('admin', `Admin '${req.user.username}' removed policy`, {
    actor: req.user.username, subject, resource, action,
  });
  res.json({ message: `Policy removed: ${subject} can ${action} on ${resource}` });
});

// -- Services --

/**
 * Matches Casbin policy rows to a service: either an exact hit against one
 * of the service's advertised endpoints, or a `/serviceName/...` prefix
 * (covers policies written for a path the registry hasn't listed yet).
 * Used to answer "which roles can reach this service" for the admin UI's
 * Services panel.
 */
function policiesForService(name, endpoints, policies) {
  const endpointSet = new Set(endpoints || []);
  const prefix = `/${name}/`;
  return policies.filter((p) => endpointSet.has(p.resource) || p.resource.startsWith(prefix));
}

app.get('/admin/services', authenticateJWT, requireAdmin, async (req, res) => {
  await syncServicesFromRegistry();

  const rules = await withCasbin(() => enforcer.getPolicy());
  const policies = rules.map(([subject, resource, action]) => ({ subject, resource, action }));

  const services = Array.from(serviceCache.entries()).map(([name, cfg]) => {
    const servicePolicies = policiesForService(name, cfg.endpoints, policies);
    return {
      name,
      ...cfg,
      policies: servicePolicies,
      rolesWithAccess: [...new Set(servicePolicies.map((p) => p.subject))],
    };
  });

  res.json({ lastSyncTime, registryUrl: REGISTRY_URL, count: services.length, services });
});

// -- Requests (admin) --
// Counterpart to the self-service /requests routes above — this is the
// queue an admin works through to approve or reject them.

app.get('/admin/requests', authenticateJWT, requireAdmin, async (req, res) => {
  const status = typeof req.query.status === 'string' ? req.query.status : undefined;
  const requests = await listAccessRequests({ status });
  res.json({ count: requests.length, requests });
});

app.post('/admin/requests/:id/approve', authenticateJWT, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const request = await getAccessRequest(id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request already ${request.status}` });
  }

  // A pure service request may not carry a role (the service had no
  // rolesWithAccess yet when the user submitted it) — the admin picks one.
  const role = isNonEmptyString(req.body?.role) ? req.body.role.trim() : request.role;
  if (!isNonEmptyString(role)) {
    return res.status(400).json({ error: 'This request has no role attached — specify one in the body to approve with' });
  }
  if (!(await userExists(request.username))) {
    return res.status(404).json({ error: `User '${request.username}' no longer exists` });
  }

  if (request.tenant) {
    // Tenant-scoped request: grant the role inside that tenant, not globally.
    // The tenant's own admins can do this too (POST /tenants/:id/requests/:id/
    // approve); the platform admin can resolve any tenant's queue as a backstop.
    if (!(await tenancy.tenantExists(request.tenant))) {
      return res.status(404).json({ error: `Tenant '${request.tenant}' no longer exists` });
    }
    if (!(await tenancy.tenantRoleExists(request.tenant, role))) {
      return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${request.tenant}'` });
    }
    await tenancy.grantTenantRole(request.tenant, request.username, role);
    const tenantResolved = await resolveAccessRequest(id, 'approved', req.user.username, role);
    log.audit('admin', `Admin '${req.user.username}' approved request ${id} — granted '${role}' to '${request.username}' in tenant '${request.tenant}'`, {
      actor: req.user.username, target: request.username, tenant: request.tenant, role, requestId: id,
    });
    return res.json({
      message: `Request approved — '${role}' granted to '${request.username}' in tenant '${request.tenant}'`,
      request: tenantResolved,
    });
  }

  if (!(await roleIsDefined(role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist` });
  }

  await setUserRole(request.username, role);
  await withCasbin(() => enforcer.addRoleForUser(request.username, role));
  await addRoleToIndex(role);
  const resolved = await resolveAccessRequest(id, 'approved', req.user.username, role);

  log.audit('admin', `Admin '${req.user.username}' approved request ${id} — granted '${role}' to '${request.username}'`, {
    actor: req.user.username, target: request.username, role, requestId: id,
  });
  res.json({ message: `Request approved — '${role}' granted to '${request.username}'`, request: resolved });
});

app.post('/admin/requests/:id/reject', authenticateJWT, requireAdmin, async (req, res) => {
  const { id } = req.params;
  const request = await getAccessRequest(id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request already ${request.status}` });
  }

  const resolved = await resolveAccessRequest(id, 'rejected', req.user.username);
  log.audit('admin', `Admin '${req.user.username}' rejected request ${id} from '${request.username}'`, {
    actor: req.user.username, target: request.username, requestId: id,
  });
  res.json({ message: 'Request rejected', request: resolved });
});

// -- User access test --
//
// "Assign a role, then hit Test" only means something if it exercises the
// SAME code path a real client would: authenticateJWT -> enforce() ->
// proxy. So this mints a short-lived token for the target user (an
// explicit, audited admin impersonation action) and calls the gateway's
// own /gateway/:serviceName routes over loopback HTTP for every endpoint
// every active service advertises, exactly like an external caller would.
// A re-implementation of the policy check here would only prove the
// policy table is self-consistent, not that the user can actually reach
// the service.
const TEST_ACCESS_TIMEOUT_MS = 4000;
// An impersonation token exists only to make one loopback call. Minting it
// for 24 hours like a login token would mean every access test quietly
// produces a day-long credential for somebody else.
const TEST_TOKEN_TTL_SECONDS = 60;
// Enough to read a real response, small enough that a streaming or binary
// endpoint cannot turn a test into a memory problem.
const TEST_BODY_LIMIT = 8192;

/**
 * Shows the shape of a token without handing over a usable one.
 * The decoded claims are the informative part and are returned in full; the
 * signature is what makes it a credential, so the raw value is cut.
 */
function maskToken(token) {
  return `${token.slice(0, 16)}…${token.slice(-8)}`;
}

/** Header + claims, so a tester can see exactly what the gateway will read. */
function describeToken(token, { reveal }) {
  const decoded = jwt.decode(token, { complete: true }) || {};
  const claims = decoded.payload || {};
  return {
    value: reveal ? token : maskToken(token),
    masked: !reveal,
    header: decoded.header || null,
    claims,
    expiresInSeconds: claims.exp ? Math.max(0, claims.exp - Math.floor(Date.now() / 1000)) : null,
    note: reveal
      ? 'This is your own session token — the same one your browser is already using.'
      : 'Claims are shown in full; the raw token is cut short on purpose. A complete one would be a '
        + "working credential for this account across every tenant they belong to, not just this one.",
  };
}

// What each stopping point means, in the terms of the person debugging it.
// The distinction that matters most: did authorization refuse this, or did it
// pass and something further along fail? Those send you to opposite ends of
// the system, and a status code alone does not separate them.
const OUTCOME_EXPLANATIONS = {
  'gateway-policy':
    'The gateway refused it. No policy grants this user that action on this path, so the '
    + 'request never reached the service.',
  'gateway-authentication':
    'The token was missing, expired, or revoked. This is authentication, not permissions.',
  'gateway-tenant-suspended':
    'The tenant is suspended, so the gateway is refusing all traffic to it regardless of policy.',
  upstream:
    'Authorization passed and the request was proxied — the service itself refused it.',
  'upstream-missing-endpoint':
    'Authorization passed and the request WAS proxied, but the service returned 404: it does not '
    + 'serve this path. The endpoint is advertised in the registry and not implemented by the '
    + 'service. Nothing is wrong with the role or the policy.',
  'upstream-error':
    'Authorization passed; the service itself failed while handling the request.',
  'upstream-unreachable':
    'Authorization passed, but the service could not be reached at its registered base URL.',
  'service-registry':
    'The service is not registered, or is not active, so the gateway had nowhere to send it.',
  timeout: 'The service did not respond in time.',
  network: 'The request never completed.',
};

/**
 * Why did this call end the way it did?
 *
 * `decision` is deliberately three-valued rather than allowed/denied. A 404
 * from the service behind the gateway is not a denial — authorization passed
 * and the request was proxied — and calling it one sends whoever is debugging
 * straight to the roles and policies, which are fine. That mislabelling cost
 * real time, so an upstream failure is now `error`, distinct from `denied`.
 */
function classifyOutcome(status, body) {
  const at = (decision, by) => ({ decision, by, explanation: OUTCOME_EXPLANATIONS[by] });

  if (status === null) return at('error', 'network');
  if (status < 400) return at('allowed', 'upstream');

  if (status === 401) return at('denied', 'gateway-authentication');
  if (status === 403 && typeof body?.error === 'string') {
    if (/suspended/i.test(body.error)) return at('denied', 'gateway-tenant-suspended');
    if (/lack clearance/i.test(body.error)) return at('denied', 'gateway-policy');
  }
  if (status === 403) return at('denied', 'upstream');

  // The gateway's own "service not found or inactive" reply carries a hint;
  // a bare 404 came from the service itself.
  if (status === 404 && body?.hint) return at('error', 'service-registry');
  if (status === 404) return at('error', 'upstream-missing-endpoint');

  if (status === 502) return at('error', 'upstream-unreachable');
  if (status >= 500) return at('error', 'upstream-error');
  return at('error', 'upstream');
}

/**
 * Calls every endpoint of the given services as `username` and records the
 * whole exchange — the token used, the request that was sent, and the status,
 * headers and body that came back.
 *
 * It goes over loopback HTTP through the gateway's own /gateway routes rather
 * than re-reading the policy table, so the result reflects the real
 * authenticate -> enforce -> proxy path. Re-implementing the check here would
 * only prove the policy table is self-consistent with itself.
 *
 * @param {string} username
 * @param {object[]} services
 * @param {object} [opts]
 * @param {string} [opts.token]  use this token instead of minting one (self-tests)
 * @param {boolean} [opts.reveal] return the raw token (only ever for the caller's own)
 */
async function probeServiceAccessAs(username, services, { token, reveal = false } = {}) {
  let testToken = token;
  if (!testToken) {
    const userData = await getUser(username);
    const tokenVersion = await getTokenVersion(username);
    testToken = signToken(username, userData.role, tokenVersion, TEST_TOKEN_TTL_SECONDS);
  }

  const { default: fetch } = await import('node-fetch');
  const sentHeaders = {
    Authorization: `Bearer ${testToken}`,
    Accept: 'application/json',
  };
  // What the tester is shown was built from what was actually sent, so the two
  // cannot drift.
  const shownHeaders = { ...sentHeaders, Authorization: `Bearer ${reveal ? testToken : maskToken(testToken)}` };

  const serviceResults = await Promise.all(services.map(async (svc) => {
    const endpoints = svc.endpoints || [];

    const endpointResults = await Promise.all(endpoints.map(async (endpoint) => {
      const url = `http://localhost:${GATEWAY_PORT}/gateway${endpoint}`;
      const started = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TEST_ACCESS_TIMEOUT_MS);

      const request = { method: 'GET', url, headers: shownHeaders };

      try {
        const response = await fetch(url, { headers: sentHeaders, signal: controller.signal });

        const raw = await response.text();
        const truncated = raw.length > TEST_BODY_LIMIT;
        let body = truncated ? raw.slice(0, TEST_BODY_LIMIT) : raw;
        let parsed = null;
        if (!truncated) {
          try { parsed = JSON.parse(raw); body = null; } catch { /* keep the text */ }
        }

        const outcome = classifyOutcome(response.status, parsed);
        return {
          endpoint,
          action: 'get',
          status: response.status,
          allowed: response.status < 400,
          decision: outcome.decision,
          stoppedBy: outcome.decision === 'allowed' ? null : outcome.by,
          // Kept for clients written against the first version of this shape.
          deniedBy: outcome.decision === 'allowed' ? null : outcome.by,
          explanation: outcome.decision === 'allowed' ? null : outcome.explanation,
          latencyMs: Date.now() - started,
          request,
          response: {
            status: response.status,
            statusText: response.statusText,
            headers: Object.fromEntries(response.headers),
            json: parsed,
            text: body,
            truncated,
          },
          error: response.status >= 400 ? ((parsed && parsed.error) || response.statusText) : null,
        };
      } catch (err) {
        const aborted = err.name === 'AbortError';
        return {
          endpoint,
          action: 'get',
          status: null,
          allowed: false,
          decision: 'error',
          stoppedBy: aborted ? 'timeout' : 'network',
          deniedBy: aborted ? 'timeout' : 'network',
          explanation: OUTCOME_EXPLANATIONS[aborted ? 'timeout' : 'network'],
          latencyMs: Date.now() - started,
          request,
          response: null,
          error: aborted ? `Timed out after ${TEST_ACCESS_TIMEOUT_MS}ms` : err.message,
        };
      } finally {
        clearTimeout(timer);
      }
    }));

    return {
      service: svc.name,
      baseUrl: svc.baseUrl,
      allowedCount: endpointResults.filter((e) => e.allowed).length,
      totalCount: endpointResults.length,
      endpoints: endpointResults,
    };
  }));

  return { token: describeToken(testToken, { reveal }), services: serviceResults };
}

app.post('/admin/users/:username/test-access', authenticateJWT, requireAdmin, async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const userData = await getUser(username);
  const roles = await withCasbin(() => enforcer.getRolesForUser(username));

  await syncServicesFromRegistry();
  const services = Array.from(serviceCache.entries()).map(([name, cfg]) => ({ name, ...cfg }));
  const probe = await probeServiceAccessAs(username, services);

  log.audit('admin', `Admin '${req.user.username}' ran an access test for '${username}' (impersonation token minted)`, {
    actor: req.user.username, target: username, roles,
  });

  res.json({
    username,
    role: userData.role,
    roles,
    testedAt: new Date().toISOString(),
    token: probe.token,
    services: probe.services,
  });
});

// ═══════════════════════════════════════════════════════════════════════════
// MULTI-TENANCY
// ═══════════════════════════════════════════════════════════════════════════
//
// Every registered service is a tenant that governs its own corner of the
// system: its own role names, its own membership list, its own administrators,
// and the policies covering its own /{tenantId}/ URL namespace. Two layers of
// administration, deliberately not one:
//
//   platform admin  — tenant lifecycle and cross-tenant oversight
//                     (/admin/*). Sees everything, owns nothing day to day.
//   tenant admin    — everything inside one tenant (/tenants/:id/*).
//                     Cannot see or touch another tenant.
//
// Isolation is structural rather than a matter of checking a flag carefully:
// a tenant's roles only exist in Casbin as `t:{id}:{role}`, and every write
// path below re-derives that prefix from the URL's :tenantId (which the
// middleware has already authorised) instead of trusting anything in the body.
// There is no request shape that lets tenant A name a subject or a resource
// belonging to tenant B.

function isPlatformAdmin(req) {
  return req.user?.role === 'admin';
}

/** Loads :tenantId into req.tenant, 404ing if it doesn't exist. */
const loadTenant = async (req, res, next) => {
  const tenant = await tenancy.getTenant(req.params.tenantId);
  if (!tenant) {
    return res.status(404).json({ error: `Tenant '${req.params.tenantId}' not found` });
  }
  req.tenant = tenant;
  next();
};

/**
 * Tenant administration gate. The platform admin passes for every tenant;
 * everyone else must be listed as an admin of this specific one. Deliberately
 * resolved from Redis on every call rather than from a JWT claim: a tenant
 * admin who is demoted should lose access immediately, not whenever their
 * 24-hour token happens to expire.
 */
const requireTenantAdmin = async (req, res, next) => {
  if (isPlatformAdmin(req)) return next();
  if (await tenancy.isTenantAdmin(req.params.tenantId, req.user.username)) return next();
  return res.status(403).json({
    error: `You are not an administrator of tenant '${req.params.tenantId}'`,
  });
};

/** Membership gate — for read-only views a plain member may see. */
const requireTenantMember = async (req, res, next) => {
  if (isPlatformAdmin(req)) return next();
  const { tenantId } = req.params;
  const { username } = req.user;
  if (await tenancy.isTenantMember(tenantId, username)) return next();
  return res.status(403).json({ error: `You are not a member of tenant '${tenantId}'` });
};

/** Shape one tenant member for the tenant console's user table. */
async function describeMember(tenantId, username) {
  const userData = await getUser(username);
  return {
    username,
    exists: Boolean(userData?.password),
    platformRole: userData?.role || null,
    roles: await tenancy.getUserTenantRoles(tenantId, username),
    isAdmin: await tenancy.isTenantAdmin(tenantId, username),
  };
}

// --- REGISTRY CALLS MADE ON A TENANT'S BEHALF -------------------------------
// The service token the registry issues is the proof of ownership of a service
// name. Users never see it: it is stored on the tenant record and replayed by
// the gateway whenever a tenant admin edits their own service, so the tenant
// console needs no credential handling of its own.

// The registry will accept a mutation from the gateway on the strength of
// this shared secret, which lives in the Redis both processes already share
// (see registery.js). It is what lets an authorised human edit a service
// whose own token the gateway never saw — anything that self-registered,
// which includes every service that existed before tenancy. Without it, the
// admin panel could show those services but never edit them.
const REGISTRY_ADMIN_TOKEN_KEY = 'registry:admin-token';
let registryAdminToken = null;

async function getRegistryAdminToken() {
  if (registryAdminToken) return registryAdminToken;
  // SETNX so gateway-first and registry-first boots converge on one value.
  await redis.set(REGISTRY_ADMIN_TOKEN_KEY, crypto.randomBytes(32).toString('hex'), 'NX');
  registryAdminToken = await redis.get(REGISTRY_ADMIN_TOKEN_KEY);
  return registryAdminToken;
}

/**
 * @param {object} options
 * @param {boolean} [options.asPlatform] attach the override token — set only
 *   on a path that has already authorised the caller for this tenant.
 */
async function registryFetch(path, options = {}) {
  const { default: fetch } = await import('node-fetch');
  const { asPlatform, ...init } = options;
  const headers = { 'Content-Type': 'application/json', ...(init.headers || {}) };
  if (asPlatform) headers['X-Registry-Admin-Token'] = await getRegistryAdminToken();

  const response = await fetch(`${REGISTRY_URL}${path}`, { ...init, headers });
  let body = null;
  try { body = await response.json(); } catch { /* no body */ }
  return { ok: response.ok, status: response.status, body };
}

const tenantServiceTokenKey = (id) => `tenant:${id}`;

async function storeServiceToken(tenantId, token) {
  if (token) await redis.hset(tenantServiceTokenKey(tenantId), 'serviceToken', token);
}

async function readServiceToken(tenantId) {
  return redis.hget(tenantServiceTokenKey(tenantId), 'serviceToken');
}

// --- TENANT DISCOVERY (any authenticated user) ------------------------------

/**
 * GET /tenants — every active tenant, as a catalogue to request access from.
 * Intentionally omits baseUrl and membership: which hosts back a service, and
 * who else can reach it, are not a non-member's business.
 */
app.get('/tenants', authenticateJWT, async (req, res) => {
  const tenants = await tenancy.listTenants();
  const mine = new Set((await tenancy.listTenantsForUser(req.user.username)).map((t) => t.id));

  const visible = await Promise.all(
    tenants.filter((t) => t.status === 'active').map(async (t) => ({
      id: t.id,
      displayName: t.displayName,
      description: t.description,
      owner: t.owner,
      roles: await tenancy.listTenantRoles(t.id),
      endpoints: serviceCache.get(t.id)?.endpoints || [],
      joined: mine.has(t.id),
    })),
  );

  res.json({ count: visible.length, tenants: visible });
});

/** GET /tenants/mine — the tenants I belong to, and my standing in each. */
app.get('/tenants/mine', authenticateJWT, async (req, res) => {
  const tenants = await tenancy.listTenantsForUser(req.user.username);
  res.json({ count: tenants.length, tenants });
});

/**
 * POST /tenants/register — register a service AND become its tenant admin.
 *
 * This is the front door for onboarding a service: one authenticated call that
 * registers it with the registry, provisions its tenant, and makes the caller
 * its first administrator. The registry's service token is captured and stored
 * on the tenant, so the caller never has to handle it.
 */
app.post('/tenants/register', authenticateJWT, async (req, res) => {
  const { name, baseUrl, catalogUrl, endpoints, version, displayName, description } = req.body || {};

  if (!isNonEmptyString(name) || !isNonEmptyString(baseUrl)) {
    return res.status(400).json({ error: 'name and baseUrl are required' });
  }

  const idError = validateTenantId(name);
  if (idError) return res.status(400).json({ error: idError });

  // A tenant that already exists belongs to someone; registering over it is how
  // one tenant would take another's traffic.
  const existing = await tenancy.getTenant(name);
  if (existing && existing.owner && existing.owner !== req.user.username && !isPlatformAdmin(req)) {
    return res.status(409).json({ error: `Tenant '${name}' already exists and is owned by someone else` });
  }

  const registration = await registryFetch('/register', {
    method: 'POST',
    headers: { ...(await readServiceToken(name) ? { 'X-Service-Token': await readServiceToken(name) } : {}) },
    body: JSON.stringify({
      name, baseUrl, catalogUrl, endpoints, version, displayName, description,
      owner: req.user.username,
    }),
  });

  if (!registration.ok) {
    return res.status(registration.status).json({
      error: registration.body?.error || 'Registry rejected the registration',
      hint: registration.body?.hint,
    });
  }

  const { tenant, created } = await tenancy.createTenant({
    id: name,
    displayName: displayName || name,
    description: description || '',
    baseUrl,
    owner: req.user.username,
    source: 'self-service',
  });

  await storeServiceToken(name, registration.body.serviceToken);
  await syncServicesFromRegistry();

  log.audit('tenant', `User '${req.user.username}' registered service '${name}' and became its tenant admin`, {
    actor: req.user.username, tenant: name, baseUrl, created,
  });

  res.status(201).json({
    message: `Service '${name}' registered — you are now an administrator of tenant '${name}'`,
    tenant,
    service: registration.body.service,
    warnings: registration.body.warnings || [],
  });
});

// --- ONE TENANT -------------------------------------------------------------

app.get('/tenants/:tenantId', authenticateJWT, loadTenant, requireTenantMember, async (req, res) => {
  const { tenantId } = req.params;
  const service = serviceCache.get(tenantId) || null;

  res.json({
    ...req.tenant,
    isAdmin: isPlatformAdmin(req) || (await tenancy.isTenantAdmin(tenantId, req.user.username)),
    roles: await tenancy.listTenantRoles(tenantId),
    admins: await tenancy.listTenantAdmins(tenantId),
    memberCount: (await tenancy.listTenantMembers(tenantId)).length,
    service: service
      ? {
        baseUrl: service.baseUrl,
        catalogUrl: service.catalogUrl || '',
        status: service.status,
        health: service.health,
        version: service.version,
        endpoints: service.endpoints || [],
      }
      : null,
  });
});

app.patch('/tenants/:tenantId', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const patch = {};
  for (const field of ['displayName', 'description']) {
    if (req.body?.[field] !== undefined) patch[field] = String(req.body[field]);
  }
  // Suspending a tenant is a kill switch: the gateway stops routing to it
  // immediately, without anyone having to unpick its policies.
  if (req.body?.status !== undefined) {
    if (!['active', 'suspended'].includes(req.body.status)) {
      return res.status(400).json({ error: "status must be 'active' or 'suspended'" });
    }
    patch.status = req.body.status;
  }
  if (Object.keys(patch).length === 0) {
    return res.status(400).json({ error: 'Nothing to update — send displayName, description or status' });
  }

  const tenant = await tenancy.updateTenant(req.params.tenantId, patch);
  log.audit('tenant', `Tenant '${req.params.tenantId}' updated by '${req.user.username}'`, {
    actor: req.user.username, tenant: req.params.tenantId, fields: Object.keys(patch),
  });
  res.json({ message: 'Tenant updated', tenant });
});

/**
 * PATCH /tenants/:tenantId/service — edit the backing service's routing
 * metadata (endpoints, baseUrl, catalogUrl, version) without the tenant admin
 * ever handling the registry's service token.
 */
app.patch('/tenants/:tenantId/service', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId } = req.params;
  // Prefer the tenant's own service token; fall back to vouching for the
  // caller, who requireTenantAdmin has already established may administer
  // this tenant. A service that self-registered never handed its token to
  // the gateway, and refusing to edit it for that reason would mean the
  // admin panel can display a service it can never change.
  const token = await readServiceToken(tenantId);

  const allowed = {};
  for (const field of ['endpoints', 'baseUrl', 'catalogUrl', 'version', 'displayName', 'description', 'status']) {
    if (req.body?.[field] !== undefined) allowed[field] = req.body[field];
  }
  if (Object.keys(allowed).length === 0) {
    return res.status(400).json({ error: 'Nothing to update' });
  }

  const result = await registryFetch(`/services/${encodeURIComponent(tenantId)}`, {
    method: 'PATCH',
    asPlatform: !token,
    headers: token ? { 'X-Service-Token': token } : {},
    body: JSON.stringify(allowed),
  });

  // A tenant can exist before its service does (created by the platform
  // admin, or left behind by a deregistration). Supplying a baseUrl here is
  // how it gets one, so treat this as create-or-update rather than making
  // the caller know which of two endpoints to reach for.
  if (result.status === 404) {
    if (!isNonEmptyString(allowed.baseUrl)) {
      return res.status(404).json({
        error: `Tenant '${tenantId}' has no service registered yet`,
        hint: 'Include a baseUrl to register one now',
      });
    }
    const created = await registryFetch('/register', {
      method: 'POST',
      asPlatform: true,
      body: JSON.stringify({ ...allowed, name: tenantId, owner: req.tenant.owner || req.user.username }),
    });
    if (!created.ok) {
      return res.status(created.status).json({ error: created.body?.error || 'Registry rejected the registration' });
    }
    await storeServiceToken(tenantId, created.body.serviceToken);
    await syncAndProvision();
    log.audit('tenant', `Service registered for tenant '${tenantId}' by '${req.user.username}'`, {
      actor: req.user.username, tenant: tenantId, baseUrl: allowed.baseUrl,
    });
    return res.json({
      message: `Service registered for '${tenantId}'`,
      service: created.body.service,
      warnings: created.body.warnings || [],
    });
  }

  if (!result.ok) {
    return res.status(result.status).json({ error: result.body?.error || 'Registry rejected the update' });
  }

  await syncServicesFromRegistry();
  log.audit('tenant', `Tenant '${tenantId}' service metadata updated by '${req.user.username}'`, {
    actor: req.user.username, tenant: tenantId, fields: Object.keys(allowed),
  });
  res.json({ message: 'Service updated', service: result.body.service, warnings: [] });
});

// --- TENANT USERS -----------------------------------------------------------

app.get('/tenants/:tenantId/users', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId } = req.params;
  const members = await tenancy.listTenantMembers(tenantId);
  const users = await Promise.all(members.map((u) => describeMember(tenantId, u)));
  res.json({ tenant: tenantId, count: users.length, users });
});

/**
 * POST /tenants/:tenantId/users — add an existing platform account as a member.
 *
 * Deliberately not a signup endpoint: a tenant admin grants access to an
 * identity, they don't mint one. Letting tenants create accounts would mean a
 * tenant admin could create a username, then have it recognised by every other
 * tenant on the platform — identity has to stay a platform concern.
 */
app.post('/tenants/:tenantId/users', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId } = req.params;
  const username = isNonEmptyString(req.body?.username) ? req.body.username.trim() : null;
  const role = isNonEmptyString(req.body?.role) ? req.body.role.trim() : null;

  if (!username) return res.status(400).json({ error: 'username is required' });
  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' does not have a platform account — they must sign up first` });
  }
  if (role && !(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }

  await tenancy.addTenantMember(tenantId, username);
  if (role) await tenancy.grantTenantRole(tenantId, username, role);

  log.audit('tenant', `'${req.user.username}' added '${username}' to tenant '${tenantId}'${role ? ` with role '${role}'` : ''}`, {
    actor: req.user.username, tenant: tenantId, target: username, role,
  });
  res.status(201).json({ message: `'${username}' added to tenant '${tenantId}'`, user: await describeMember(tenantId, username) });
});

app.delete('/tenants/:tenantId/users/:username', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username } = req.params;

  if (!(await tenancy.isTenantMember(tenantId, username))) {
    return res.status(404).json({ error: `'${username}' is not a member of tenant '${tenantId}'` });
  }
  if (req.tenant.owner === username) {
    return res.status(409).json({ error: `'${username}' owns this tenant — transfer ownership before removing them` });
  }

  await tenancy.removeTenantMember(tenantId, username);
  log.audit('tenant', `'${req.user.username}' removed '${username}' from tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });
  res.json({ message: `'${username}' removed from tenant '${tenantId}' (all their roles here were revoked)` });
});

app.post('/tenants/:tenantId/users/:username/roles', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username } = req.params;
  const role = isNonEmptyString(req.body?.role) ? req.body.role.trim() : null;

  if (!role) return res.status(400).json({ error: 'role is required' });
  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });
  if (!(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }
  if (await tenancy.hasTenantRole(tenantId, username, role)) {
    return res.status(409).json({ error: `'${username}' already has role '${role}' in tenant '${tenantId}'` });
  }

  await tenancy.grantTenantRole(tenantId, username, role);
  log.audit('tenant', `'${req.user.username}' granted '${role}' to '${username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username, role,
  });
  res.json({ message: `Role '${role}' granted to '${username}' in tenant '${tenantId}'`, user: await describeMember(tenantId, username) });
});

app.delete('/tenants/:tenantId/users/:username/roles/:role', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username, role } = req.params;

  if (!(await tenancy.hasTenantRole(tenantId, username, role))) {
    return res.status(404).json({ error: `'${username}' does not have role '${role}' in tenant '${tenantId}'` });
  }

  await tenancy.revokeTenantRole(tenantId, username, role);
  log.audit('tenant', `'${req.user.username}' revoked '${role}' from '${username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username, role,
  });
  res.json({ message: `Role '${role}' revoked from '${username}' in tenant '${tenantId}'`, user: await describeMember(tenantId, username) });
});

app.post('/tenants/:tenantId/users/:username/admin', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username } = req.params;
  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });

  await tenancy.addTenantAdmin(tenantId, username);
  log.audit('tenant', `'${req.user.username}' made '${username}' an admin of tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });
  res.json({ message: `'${username}' is now an administrator of tenant '${tenantId}'` });
});

app.delete('/tenants/:tenantId/users/:username/admin', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username } = req.params;

  if (req.tenant.owner === username) {
    return res.status(409).json({ error: `'${username}' owns this tenant and cannot be demoted` });
  }
  // A tenant with no administrators can only be rescued by the platform admin,
  // so refuse to remove the last one.
  const admins = await tenancy.listTenantAdmins(tenantId);
  if (admins.length <= 1 && admins.includes(username)) {
    return res.status(409).json({ error: 'This is the last administrator of the tenant — appoint another one first' });
  }

  await tenancy.removeTenantAdmin(tenantId, username);
  log.audit('tenant', `'${req.user.username}' removed admin rights from '${username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });
  res.json({ message: `'${username}' is no longer an administrator of tenant '${tenantId}'` });
});

/** Same loopback probe the platform admin gets, scoped to this tenant's service. */
app.post('/tenants/:tenantId/users/:username/test-access', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username } = req.params;
  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });

  await syncServicesFromRegistry();
  const cfg = serviceCache.get(tenantId);
  const services = cfg ? [{ name: tenantId, ...cfg }] : [];
  const probe = await probeServiceAccessAs(username, services);

  log.audit('tenant', `'${req.user.username}' ran an access test for '${username}' in tenant '${tenantId}' (impersonation token minted)`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });

  res.json({
    tenant: tenantId,
    username,
    roles: await tenancy.getUserTenantRoles(tenantId, username),
    testedAt: new Date().toISOString(),
    token: probe.token,
    services: probe.services,
  });
});

// --- TENANT ROLES -----------------------------------------------------------

app.get('/tenants/:tenantId/roles', authenticateJWT, loadTenant, requireTenantMember, async (req, res) => {
  const { tenantId } = req.params;
  const names = await tenancy.listTenantRoles(tenantId);
  const policies = await tenancy.listTenantPolicies(tenantId);

  const roles = await Promise.all(names.map(async (role) => ({
    role,
    members: (await withCasbin(() => enforcer.getUsersForRole(tenancy.qualifyRole(tenantId, role))).catch(() => [])),
    policies: policies.filter((p) => p.role === role).map(({ resource, action }) => ({ resource, action })),
  })));

  res.json({ tenant: tenantId, count: roles.length, roles });
});

app.post('/tenants/:tenantId/roles', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId } = req.params;
  const role = isNonEmptyString(req.body?.role) ? req.body.role.trim() : null;

  if (!role) return res.status(400).json({ error: 'role is required' });
  const roleError = validateRoleName(role);
  if (roleError) return res.status(400).json({ error: roleError });
  if (await tenancy.tenantRoleExists(tenantId, role)) {
    return res.status(409).json({ error: `Role '${role}' already exists in tenant '${tenantId}'` });
  }

  await tenancy.defineTenantRole(tenantId, role);
  log.audit('tenant', `'${req.user.username}' defined role '${role}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, role,
  });
  res.status(201).json({ message: `Role '${role}' defined in tenant '${tenantId}'` });
});

app.delete('/tenants/:tenantId/roles/:role', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, role } = req.params;

  if (!(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }

  await tenancy.deleteTenantRole(tenantId, role);
  log.audit('tenant', `'${req.user.username}' deleted role '${role}' from tenant '${tenantId}' (policies and grants removed)`, {
    actor: req.user.username, tenant: tenantId, role,
  });
  res.json({ message: `Role '${role}' deleted from tenant '${tenantId}', along with its policies and grants` });
});

// --- TENANT POLICIES --------------------------------------------------------

app.get('/tenants/:tenantId/policies', authenticateJWT, loadTenant, requireTenantMember, async (req, res) => {
  const policies = await tenancy.listTenantPolicies(req.params.tenantId);
  res.json({ tenant: req.params.tenantId, count: policies.length, policies });
});

/**
 * POST /tenants/:tenantId/policies — { role, resource, action }
 *
 * The subject is built from the URL's tenant id, never from the body, and the
 * resource is checked against the tenant's own /{id}/ prefix. Together those
 * two lines are what make cross-tenant policy writes impossible rather than
 * merely discouraged.
 */
app.post('/tenants/:tenantId/policies', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId } = req.params;
  const { role, resource, action } = req.body || {};

  if (!isNonEmptyString(role) || !isNonEmptyString(resource) || !isNonEmptyString(action)) {
    return res.status(400).json({ error: 'role, resource and action are required' });
  }
  if (!(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }
  if (!ownsResource(tenantId, resource)) {
    return res.status(403).json({
      error: `Tenant '${tenantId}' can only write policies for its own paths — '${resource}' must start with '/${tenantId}/'`,
    });
  }

  const added = await tenancy.addTenantPolicy(tenantId, role.trim(), resource.trim(), action.trim().toLowerCase());
  if (!added) {
    return res.status(409).json({ error: 'That policy already exists' });
  }

  log.audit('tenant', `'${req.user.username}' added policy in tenant '${tenantId}': ${role} can ${action} ${resource}`, {
    actor: req.user.username, tenant: tenantId, role, resource, action,
  });
  res.status(201).json({ message: `Policy added: '${role}' can ${action} ${resource}` });
});

app.delete('/tenants/:tenantId/policies', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId } = req.params;
  const { role, resource, action } = req.body || {};

  if (!isNonEmptyString(role) || !isNonEmptyString(resource) || !isNonEmptyString(action)) {
    return res.status(400).json({ error: 'role, resource and action are required' });
  }

  const removed = await tenancy.removeTenantPolicy(tenantId, role.trim(), resource.trim(), action.trim().toLowerCase());
  if (!removed) return res.status(404).json({ error: 'Policy rule not found in this tenant' });

  log.audit('tenant', `'${req.user.username}' removed policy in tenant '${tenantId}': ${role} can ${action} ${resource}`, {
    actor: req.user.username, tenant: tenantId, role, resource, action,
  });
  res.json({ message: `Policy removed: '${role}' can ${action} ${resource}` });
});

// --- TENANT ACCESS REQUESTS -------------------------------------------------

app.get('/tenants/:tenantId/requests', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const status = typeof req.query.status === 'string' && req.query.status ? req.query.status : undefined;
  const requests = await listAccessRequests({ tenant: req.params.tenantId, status });
  res.json({ tenant: req.params.tenantId, count: requests.length, requests });
});

app.post('/tenants/:tenantId/requests/:id/approve', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, id } = req.params;
  const request = await getAccessRequest(id);

  if (!request || request.tenant !== tenantId) {
    return res.status(404).json({ error: 'Request not found in this tenant' });
  }
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request already ${request.status}` });
  }

  const role = isNonEmptyString(req.body?.role) ? req.body.role.trim() : request.role;
  if (!isNonEmptyString(role)) {
    return res.status(400).json({ error: 'This request has no role attached — specify one in the body to approve with' });
  }
  if (!(await userExists(request.username))) {
    return res.status(404).json({ error: `User '${request.username}' no longer exists` });
  }
  if (!(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }

  await tenancy.grantTenantRole(tenantId, request.username, role);
  const resolved = await resolveAccessRequest(id, 'approved', req.user.username, role);

  log.audit('tenant', `'${req.user.username}' approved request ${id} — granted '${role}' to '${request.username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: request.username, role, requestId: id,
  });
  res.json({ message: `Request approved — '${role}' granted to '${request.username}'`, request: resolved });
});

app.post('/tenants/:tenantId/requests/:id/reject', authenticateJWT, loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, id } = req.params;
  const request = await getAccessRequest(id);

  if (!request || request.tenant !== tenantId) {
    return res.status(404).json({ error: 'Request not found in this tenant' });
  }
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request already ${request.status}` });
  }

  const resolved = await resolveAccessRequest(id, 'rejected', req.user.username);
  log.audit('tenant', `'${req.user.username}' rejected request ${id} from '${request.username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: request.username, requestId: id,
  });
  res.json({ message: 'Request rejected', request: resolved });
});

// --- PLATFORM ADMIN: TENANT LIFECYCLE ---------------------------------------

app.get('/admin/tenants', authenticateJWT, requireAdmin, async (req, res) => {
  const tenants = await tenancy.listTenants();
  const detailed = await Promise.all(tenants.map(async (t) => ({
    ...t,
    roles: await tenancy.listTenantRoles(t.id),
    admins: await tenancy.listTenantAdmins(t.id),
    memberCount: (await tenancy.listTenantMembers(t.id)).length,
    // Everything the merged admin panel renders for a tenant row, so it does
    // not have to fan out one request per tenant just to draw the list.
    service: serviceCache.get(t.id)
      ? {
        baseUrl: serviceCache.get(t.id).baseUrl,
        catalogUrl: serviceCache.get(t.id).catalogUrl || '',
        status: serviceCache.get(t.id).status,
        health: serviceCache.get(t.id).health,
        version: serviceCache.get(t.id).version,
        endpoints: serviceCache.get(t.id).endpoints || [],
      }
      : null,
  })));
  res.json({ count: detailed.length, tenants: detailed });
});

/**
 * POST /admin/tenants — create a tenant AND register its service in one call.
 *
 * A tenant and the service behind it are the same thing seen from two sides,
 * so creating one without the other is a half-finished object that the admin
 * then has to go and complete somewhere else. Supplying `baseUrl` registers
 * the service here; omitting it creates a tenant whose service can be filled
 * in later via PATCH /tenants/:id/service.
 */
app.post('/admin/tenants', authenticateJWT, requireAdmin, async (req, res) => {
  const { id, displayName, description, baseUrl, catalogUrl, endpoints, version, owner } = req.body || {};
  const warnings = [];

  if (!isNonEmptyString(id)) return res.status(400).json({ error: 'id is required' });
  const idError = validateTenantId(id);
  if (idError) return res.status(400).json({ error: idError });
  if (await tenancy.tenantExists(id)) {
    return res.status(409).json({ error: `Tenant '${id}' already exists` });
  }
  if (owner && !(await userExists(owner))) {
    return res.status(404).json({ error: `User '${owner}' not found` });
  }
  if (endpoints !== undefined && (!Array.isArray(endpoints) || endpoints.some((e) => typeof e !== 'string'))) {
    return res.status(400).json({ error: 'endpoints must be an array of path strings' });
  }

  let service = null;
  let serviceToken = null;
  if (isNonEmptyString(baseUrl)) {
    const registration = await registryFetch('/register', {
      method: 'POST',
      asPlatform: true,
      body: JSON.stringify({
        name: id, baseUrl, catalogUrl, endpoints, version,
        displayName, description, owner: owner || req.user.username,
      }),
    });
    // The service is the substance of the tenant; if it will not register,
    // creating the tenant anyway would leave a shell whose failure the admin
    // only discovers later.
    if (!registration.ok) {
      return res.status(registration.status).json({
        error: registration.body?.error || 'Registry rejected the service registration',
        hint: registration.body?.hint,
      });
    }
    service = registration.body.service;
    serviceToken = registration.body.serviceToken;
    warnings.push(...(registration.body.warnings || []));
  }

  const { tenant } = await tenancy.createTenant({
    id, displayName, description, baseUrl, owner, source: 'platform-admin',
  });
  // Keep the token on the tenant so its owner can edit the service later
  // without ever being shown a credential.
  await storeServiceToken(id, serviceToken);
  await syncServicesFromRegistry();

  log.audit('admin', `Admin '${req.user.username}' created tenant '${id}'`, {
    actor: req.user.username, tenant: id, owner: owner || null, registeredService: Boolean(service),
  });
  res.status(201).json({ message: `Tenant '${id}' created`, tenant, service, warnings });
});

app.post('/admin/tenants/:tenantId/owner', authenticateJWT, requireAdmin, loadTenant, async (req, res) => {
  const { tenantId } = req.params;
  const username = isNonEmptyString(req.body?.username) ? req.body.username.trim() : null;

  if (!username) return res.status(400).json({ error: 'username is required' });
  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });

  await tenancy.updateTenant(tenantId, { owner: username });
  await tenancy.addTenantAdmin(tenantId, username);

  log.audit('admin', `Admin '${req.user.username}' made '${username}' the owner of tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });
  res.json({ message: `'${username}' now owns tenant '${tenantId}'`, tenant: await tenancy.getTenant(tenantId) });
});

/**
 * DELETE /admin/tenants/:tenantId
 * Drops the tenant and every Casbin row carrying its prefix.
 *
 * Without `?deregister=true` the backing service stays in the registry — and
 * because a registered service is by definition a tenant (§4.1), the next sync
 * tick provisions a blank one back under the same id. That is a *reset*, not a
 * deletion, and the response says so rather than letting the tenant silently
 * reappear a few seconds later looking like a bug.
 */
app.delete('/admin/tenants/:tenantId', authenticateJWT, requireAdmin, loadTenant, async (req, res) => {
  const { tenantId } = req.params;
  const deregisterRequested = req.query.deregister === 'true';

  await tenancy.deleteTenant(tenantId);

  let deregistered = false;
  if (deregisterRequested) {
    const result = await registryFetch(`/services/${encodeURIComponent(tenantId)}`, { method: 'DELETE' });
    deregistered = result.ok;
  }
  await syncServicesFromRegistry();

  const stillRegistered = serviceCache.has(tenantId);

  log.audit('admin', `Admin '${req.user.username}' deleted tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, deregistered, willBeReprovisioned: stillRegistered,
  });
  res.json({
    message: stillRegistered
      ? `Tenant '${tenantId}' reset — its roles, policies and members are gone, but the service is still registered so a blank tenant will be re-provisioned within ${SERVICE_SYNC_INTERVAL_MS / 1000}s`
      : `Tenant '${tenantId}' deleted`,
    deregisteredService: deregistered,
    willBeReprovisioned: stillRegistered,
  });
});

// --- DYNAMIC API GATEWAY (AuthZ + Proxy) ---



app.use('/gateway/:serviceName', authenticateJWT, async (req, res, next) => {
  const { serviceName } = req.params;
  const { username } = req.user;

  const targetResource = `/${serviceName}${req.path}`;
  const action = req.method.toLowerCase();

  const isAllowed = await withCasbin(() => enforcer.enforce(username, targetResource, action));
  if (!isAllowed) {
    log.audit('gateway', `Denied ${username} -> ${targetResource}`, { username, resource: targetResource, action });
    return res.status(403).json({
      error: `Forbidden: You lack clearance for ${targetResource}`,
    });
  }

  // A suspended tenant is a kill switch: traffic stops immediately, without
  // anyone having to unpick the policies that reference it first.
  const tenant = await tenancy.getTenant(serviceName);
  if (tenant && tenant.status !== 'active') {
    log.warn('gateway', `Blocked ${username} -> ${targetResource}: tenant suspended`, { username, serviceName, status: tenant.status });
    return res.status(403).json({ error: `Service '${serviceName}' is suspended by its owner` });
  }

  const serviceConfig = await getServiceConfig(serviceName);
  if (!serviceConfig || serviceConfig.status !== 'active') {
    log.warn('gateway', `Service unavailable for ${username} -> ${targetResource}`, { username, serviceName });
    return res.status(404).json({
      error: `Service '${serviceName}' not found or inactive`,
      hint: `Check registry at ${REGISTRY_URL}/services`,
    });
  }

  log.audit('gateway', `Granted ${username} -> ${targetResource} -> ${serviceConfig.baseUrl}`, {
    username, resource: targetResource, action, target: serviceConfig.baseUrl,
  });

  // ✅ FIX: Express strips the "/gateway/:serviceName" mount prefix, so
  // req.url is just "/claude" here, not "/llm/claude". Downstream services
  // expose the FULL path (e.g. /llm/claude), so we must restore it before
  // proxying — otherwise http-proxy-middleware forwards the wrong path
  // and downstream returns 404.
  req.url = targetResource;

  const proxy = createProxyMiddleware({
    target: serviceConfig.baseUrl,
    changeOrigin: true,
    on: {
      proxyReq: (proxyReq, req) => {
        log.info('proxy', `${req.method} ${serviceConfig.baseUrl}${proxyReq.path}`, {
          method: req.method, target: `${serviceConfig.baseUrl}${proxyReq.path}`,
        });
      },
      error: (err, req, res) => {
        log.error('proxy', `Proxy error -> ${serviceConfig.baseUrl}: ${err.message}`, {
          target: serviceConfig.baseUrl, error: err.message,
        });
        if (!res.headersSent) {
          res.status(502).json({
            error: 'Bad Gateway — upstream service error',
            detail: err.message,
          });
        }
      },
    },
  });

  return proxy(req, res, next);
});

// --- CENTRALIZED ERROR HANDLER ---
// Express 5 forwards rejected async route handlers here automatically.
// Without this, failures fall through to Express's default HTML/stack-trace
// response instead of the JSON shape every other error in this API uses.
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  log.error('unhandled', `Unhandled error on ${req.method} ${req.originalUrl}: ${err.message}`, {
    method: req.method, path: req.originalUrl, stack: err.stack,
  });
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error' });
});

// --- BOOT SEQUENCE ---
async function boot() {
  console.log('\n[Gateway] Initializing IAM...');
  await initIAM();

  console.log('[Gateway] Performing initial service discovery...');
  await syncServicesFromRegistry();
  setInterval(syncAndProvision, SERVICE_SYNC_INTERVAL_MS);
  console.log(`[Gateway] Cache refresh every ${SERVICE_SYNC_INTERVAL_MS / 1000}s`);

  // Backfill users:index from any pre-existing user:* hashes, then seed
  // the default role names (both operations are idempotent)
  const backfilled = await backfillUserIndex();
  const pruned = await pruneUserIndex();
  console.log(`[IAM] Users index backfilled (${backfilled} user(s)${pruned ? `, pruned ${pruned} stale entr(ies)` : ''})`);
  await redis.sadd(ROLES_INDEX_KEY, ...DEFAULT_ROLES);

  // Seed admin user (idempotent)
  if (!(await userExists('admin'))) {
    const adminHash = await hashPassword('adminpass');
    await createUser('admin', adminHash, 'admin');
    console.log('[IAM] Admin user seeded');
  }
  // Ensure the admin user always carries the 'admin' Casbin role too — not
  // strictly required for enforcement (the matcher also bypasses on
  // r.sub == "admin" directly), but keeps /admin/roles' membership listing
  // and getRolesForUser(...) honest for the seeded account. Idempotent, so
  // safe to run unconditionally (self-heals pre-existing Redis data too).
  await withCasbin(() => enforcer.addRoleForUser('admin', 'admin'));
  // The platform bypass in the RBAC matcher is a ROLE, not a hard-coded
  // username, so operating the platform no longer requires sharing one
  // account: any number of accounts can hold 'platform_admin'. The legacy
  // `r.sub == "admin"` clause stays in the matcher so tokens and policies
  // written before this change keep working.
  await withCasbin(() => enforcer.addRoleForUser('admin', 'platform_admin'));

  // Seed Casbin policies (addPolicy is idempotent — Casbin skips duplicates)
  await withCasbin(() => enforcer.addPolicy('green_role', '/llm/gemini', 'get'));
  await withCasbin(() => enforcer.addPolicy('blue_role', '/llm/claude', 'get'));
  await withCasbin(() => enforcer.addPolicy('blue_role', '/vision/service1', 'get'));
  await withCasbin(() => enforcer.addPolicy('red_role', '/vision/service3', 'get'));

  // Turn every discovered service into a tenant. Idempotent: existing tenants
  // keep their roles, members and admins.
  const { created, total } = await provisionTenantsFromServices();
  console.log(`[IAM] Tenants: ${total} service(s) known${created.length ? `, provisioned ${created.join(', ')}` : ''}`);

  app.listen(GATEWAY_PORT, () => {
    console.log(`\n🚀 API Gateway running on port ${GATEWAY_PORT}`);
    console.log(`📋 Service Registry at ${REGISTRY_URL}`);
    console.log(`\n--- STARTUP ORDER ---`);
    console.log(`  1. node registry.js   (port 3001)`);
    console.log(`  2. node llm.js        (port 8080, auto-registers)`);
    console.log(`  3. node vision.js     (port 8081, auto-registers)`);
    console.log(`  4. node main.js       (port 3000, fetches from registry)`);
    console.log(`\n--- TEST FLOW ---`);
    console.log(`  POST /auth/signup    {"username":"blue_user","password":"123"}`);
    console.log(`  POST /auth/login     {"username":"blue_user","password":"123"}`);
    console.log(`  POST /admin/roles    {"username":"blue_user","role":"blue_role"}`);
    console.log(`  GET  /gateway/llm/claude   (Authorization: Bearer <token>)`);
    console.log(`  GET  /admin/services       (see live registry state)`);
    console.log(`\n--- MULTI-TENANCY ---`);
    console.log(`  POST /tenants/register     {"name":"payments","baseUrl":"http://localhost:9090"}`);
    console.log(`  GET  /tenants/mine         (tenants you belong to)`);
    console.log(`  POST /tenants/:id/roles    {"role":"engineer"}`);
    console.log(`  POST /tenants/:id/users    {"username":"alice","role":"engineer"}`);
    console.log(`  Console:         http://localhost:${GATEWAY_PORT}/  (one sign-in; panels follow your account)`);
    console.log(`  POST /auth/logout          (revoke the current token)`);
    console.log(`  POST /auth/change-password (self-service, revokes all sessions)`);
    console.log(`  Logs: ${path.join(__dirname, '..', 'logs')}`);
  });
}

// Graceful shutdown
async function shutdown(signal) {
  log.info('lifecycle', `${signal} received, shutting down`);
  await redis.quit();
  console.log('[Redis] Connection closed');
  process.exit(0);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

boot().catch((err) => {
  console.error('[Gateway] Fatal boot error:', err);
  process.exit(1);
});
