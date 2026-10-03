
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const Redis = require('ioredis');
const { newEnforcer, newModelFromString } = require('casbin');
const { createProxyMiddleware } = require('http-proxy-middleware');
const swaggerUi = require('swagger-ui-express');
const { spec } = require('./swagger');
const { createLogger } = require('./logger');
const {
  createTenancy, validateTenantId, validateRoleName, ownsResource, TENANT_PERMISSIONS,
  userSubject, parseUserSubject, platformRoleSubject, parsePlatformRole, parseQualifiedRole,
} = require('./tenancy');
const { createDestinationGuardFromEnv, DESTINATION_NOT_ALLOWED } = require('./netguard');
const { createRateLimiter } = require('./ratelimit');
const { createPolicyStore, POLICY_KEY: CASBIN_POLICY_KEY, VERSION_KEY: POLICY_VERSION_KEY } = require('./policy-store');
const { rebuildTarget, upstreamRequestTarget, resendConsumedBody } = require('./proxy-request');
const { evaluateCondition } = require('./abac');
const { createMetrics, CONTENT_TYPE: METRICS_CONTENT_TYPE } = require('./metrics');
const { createOidcProvider, redirectUriProblem } = require('./oidc');
const { v, validate, bodyParseErrors, JSON_BODY_LIMIT } = require('./validation');

const log = createLogger('gateway');

// --- SIGNING KEY ---
// Resolved before anything else in this file runs, and deliberately without a
// fallback. A default here is a key published in the repository: anyone who
// has read this file could mint a platform-admin token for every deployment
// that forgot to override it. So a missing or unusable key stops the process
// before it opens a port or a Redis connection, instead of booting into
// something that only looks secure.
const JWT_ALGORITHM = 'HS256';
// HS256 needs a key at least as long as its 256-bit output (RFC 7518 §3.2).
const JWT_SECRET_MIN_BYTES = 32;

function loadJwtSecret() {
  const secret = process.env.JWT_SECRET;
  let problem = null;
  if (typeof secret !== 'string' || secret.length === 0) {
    problem = 'JWT_SECRET is not set';
  } else if (Buffer.byteLength(secret) < JWT_SECRET_MIN_BYTES) {
    problem = `JWT_SECRET is too short (${Buffer.byteLength(secret)} bytes; ${JWT_ALGORITHM} needs at least ${JWT_SECRET_MIN_BYTES})`;
  } else if (new Set(secret).size < 8) {
    // Long enough but obviously not key material ("aaaa…", "12121212…").
    problem = 'JWT_SECRET is a repeated pattern, not a random key';
  }
  if (!problem) return secret;

  console.error(`[Gateway] Refusing to start: ${problem}.`);
  console.error('[Gateway] Set JWT_SECRET to a random value, for example:  openssl rand -base64 48');
  process.exit(1);
}

const JWT_SECRET = loadJwtSecret();

// Where a request may be proxied to. Built here, next to the signing key, for
// the same reason: a malformed allowlist stops the process rather than leaving
// it running with no rule.
const destinations = createDestinationGuardFromEnv();

const app = express();
// Rate limits are keyed by req.ip. Behind a load balancer that is the
// balancer's address unless Express is told how many proxies to trust — and
// then every client shares one limit. TRUST_PROXY is how many proxies are in
// front ("1"), or the subnets they connect from; unset means "no proxy".
if (process.env.TRUST_PROXY) {
  const hops = Number(process.env.TRUST_PROXY);
  app.set('trust proxy', Number.isInteger(hops) ? hops : process.env.TRUST_PROXY);
}
// --- METRICS ---
// What an operator needs to see from outside: how often requests fail, how far
// behind the shared policy this instance is, and whether Redis — on which all
// of it depends — is healthy. Exposed at GET /metrics for a scraper holding
// METRICS_TOKEN; with no token configured the endpoint is off.
//
// Labels are deliberately coarse (an area of the API, never a path or a
// username): each distinct label set is a time series somebody has to store.
const METRICS_TOKEN = process.env.METRICS_TOKEN || null;
const metrics = createMetrics();

const httpRequests = metrics.counter('iam_http_requests_total',
  'Requests answered, by area of the API, method and status code. The error rate is the 5xx share of this.',
  ['area', 'method', 'status']);
const httpDuration = metrics.histogram('iam_http_request_duration_seconds',
  'Time taken to answer a request, by area of the API', ['area']);
const authEvents = metrics.counter('iam_auth_events_total',
  'Authentication outcomes: logins that succeeded or failed, tokens that were refused', ['event']);
const rateLimited = metrics.counter('iam_rate_limited_total',
  'Requests refused by a rate limit, by which limit', ['bucket']);
const gatewayDecisions = metrics.counter('iam_gateway_decisions_total',
  'What the gateway decided about each proxied request: allowed, or what stopped it', ['outcome']);
const proxyErrors = metrics.counter('iam_proxy_errors_total',
  'Proxied requests that were authorised but did not reach the service', ['reason']);
const policyReloads = metrics.counter('iam_policy_reloads_total',
  'Times this instance reloaded the policy to catch up with a change made by another');
const policyReloadDuration = metrics.histogram('iam_policy_reload_duration_seconds',
  'How long reloading the policy took');
const policySyncLatency = metrics.histogram('iam_policy_sync_latency_seconds',
  'From a policy change being written by any instance to this instance enforcing it (Redis clock)',
  [], [0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60]);

const METRIC_AREAS = new Set(['auth', 'oauth', 'me', 'catalog', 'requests', 'admin', 'tenants', 'gateway', 'docs', 'assets', 'metrics']);
function metricArea(path) {
  const first = (path.split('/')[1] || '').toLowerCase();
  if (first === '.well-known') return 'oauth';
  return METRIC_AREAS.has(first) ? first : 'other';
}

// First in the chain, so it also counts requests that never get past the body
// parser or the rate limiter.
app.use((req, res, next) => {
  const started = process.hrtime.bigint();
  const area = metricArea(req.path);
  res.on('finish', () => {
    httpRequests.inc({ area, method: req.method, status: res.statusCode });
    httpDuration.observe({ area }, Number(process.hrtime.bigint() - started) / 1e9);
  });
  next();
});

// --- BODY PARSING ---
// For the gateway's own API only. A request under /gateway is on its way to a
// service, and its body is that service's business: reading it here would
// take it off the socket before the proxy could pass it on (the service then
// waits for a body that never arrives), would cap it at this API's 64 kB, and
// would have the gateway answering 400 for JSON it was never asked to judge.
// Proxied bodies are therefore left on the stream and piped through.
//
// The test is case-insensitive because Express's route matching is: a parser
// that skipped /gateway but ran on /GATEWAY would bring the problem back for
// anyone who asked for it.
const PROXIED_PATH = /^\/gateway(\/|$)/i;
const parseJson = express.json({
  limit: JSON_BODY_LIMIT,
  // The bytes as they arrived, so that a body read here can still be sent on
  // exactly — see resendConsumedBody in proxy-request.js.
  verify: (req, res, buffer) => { req.rawBody = buffer; },
});
app.use((req, res, next) => (PROXIED_PATH.test(req.path) ? next() : parseJson(req, res, next)));
app.use(bodyParseErrors);
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
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:7000';
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:3001';
const GATEWAY_PORT = process.env.PORT || 3000;
// The address users reach this gateway at. It is the OIDC issuer, and the
// base of every link the gateway hands out (a password-recovery link, say),
// so it is configuration — never read back from a request's Host header,
// which the sender controls.
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${GATEWAY_PORT}`).replace(/\/+$/, '');
const SERVICE_SYNC_INTERVAL_MS = 20000;

// --- RATE LIMITS ---
// Every one of these is a slot taken BEFORE the work is done (see ratelimit.js
// and the limiter further down). A successful login hands its slots back, so
// what accumulates against the two login limits is failures.
const LOGIN_IP_LIMIT = { max: 200, windowSeconds: 60 }; // per address, across all usernames
const LOGIN_USER_LIMIT = { max: 5, windowSeconds: 15 * 60 }; // per username, before temporary lockout
// Wrong `currentPassword` on change-password: a stolen token must not turn
// that route into an unthrottled password oracle.
const PASSWORD_CHECK_LIMIT = { max: 5, windowSeconds: 15 * 60 }; // per account
const perMinute = (envName, fallback) => ({
  max: Number.parseInt(process.env[envName], 10) || fallback,
  windowSeconds: 60,
});
// Asking for a recovery link, and trying one. The per-username limit is
// applied silently (the answer is the same either way), so it cannot be used
// to find out which usernames exist.
// The per-username limit is the one that matters (it is what stops somebody
// filling a victim's inbox). A recovery token is 256 random bits, so the
// per-address limits are there to bound noise, not guessing.
const RECOVERY_REQUEST_IP_LIMIT = { max: 120, windowSeconds: 60 * 60 };
const RECOVERY_REQUEST_USER_LIMIT = { max: 3, windowSeconds: 60 * 60 };
const RECOVERY_ATTEMPT_IP_LIMIT = { max: 120, windowSeconds: 15 * 60 };
// Each signup costs one Argon2 hash and one account. The default is sized so
// the test suites pass from a single address; a public deployment should set
// it far lower (SIGNUP_MAX_PER_MINUTE).
const SIGNUP_IP_LIMIT = perMinute('SIGNUP_MAX_PER_MINUTE', 300);
// Every authenticated request draws on its ACCOUNT's budget — keyed by the
// account id, so it follows the account across addresses and tokens, and one
// account cannot spend another's. Two budgets, because they are two different
// things to run out of: calls to this gateway's own API, and calls proxied
// through it to a service (which is somebody else's capacity being spent).
// The defaults leave the busiest account in the test suites a little over
// twice the room it uses; they are a ceiling on a runaway or hostile client,
// not a quota, and a deployment should set its own.
const API_REQUEST_LIMIT = { bucket: 'api', ...perMinute('API_REQUESTS_PER_MINUTE', 1200) };
const GATEWAY_REQUEST_LIMIT = { bucket: 'gateway', ...perMinute('GATEWAY_REQUESTS_PER_MINUTE', 1200) };

// Services that receive the caller's own bearer token. Empty by default: see
// the proxy route for why a token is not something to hand downstream.
const FORWARD_AUTHORIZATION_TO = new Set(
  (process.env.FORWARD_AUTHORIZATION_TO || '').split(',').map((name) => name.trim()).filter(Boolean),
);

// Index Sets so we can enumerate users/roles without SCANning user:* hashes
const USERS_INDEX_KEY = 'users:index';
const ROLES_INDEX_KEY = 'roles:index';
const DEFAULT_ROLES = ['user', 'admin', 'blue_role', 'red_role', 'green_role'];
// Hash of user id -> username: the way back from a Casbin subject (u:{id}) to
// the account it belongs to, for every listing that shows who holds a role.
const USER_IDS_KEY = 'users:ids';

// The one role the matcher treats as a blanket allow. It is reachable only as
// a grant on an account's id — never by being called something.
const PLATFORM_ADMIN_ROLE = 'platform_admin';
const PLATFORM_ADMIN_SUBJECT = platformRoleSubject(PLATFORM_ADMIN_ROLE);

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

// --- CASBIN POLICY STORAGE ---
// The policy lives in Redis as a versioned list that every gateway instance
// shares; each change to it is one atomic script. See policy-store.js.
const policyStore = createPolicyStore(redis);

// How far behind this instance was each time it caught up.
let lastPolicySyncLatency = null;
policyStore.onReload = (seconds) => {
  lastPolicySyncLatency = seconds;
  policySyncLatency.observe(seconds);
};

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

// --- KEEPING UP WITH THE OTHER INSTANCES ---
//
// The model above is this process's private copy. When another gateway
// changes the policy, the copy here is out of date, and nothing in Casbin
// will ever notice. What tells this instance is the policy VERSION in Redis:
// it moves with every change, from any instance (policy-store.js).
//
// A reload re-reads the whole policy, on the same chain as every other use of
// the model, so nothing is evaluated against a half-loaded one. Concurrent
// callers share one reload rather than queueing one each.
let policyReload = null;
function reloadPolicy() {
  if (!policyReload) {
    policyReload = withCasbin(async () => {
      const started = process.hrtime.bigint();
      await enforcer.loadPolicy();
      policyReloads.inc();
      policyReloadDuration.observe(Number(process.hrtime.bigint() - started) / 1e9);
    }).finally(() => { policyReload = null; });
  }
  return policyReload;
}

/**
 * Brings this instance up to (at least) the given policy version before the
 * caller goes on. `current` is the version Redis reported a moment ago —
 * authenticate() reads it on the round trip it already makes, so being
 * current costs a request nothing unless there is something to catch up on.
 *
 * Only ever "behind", never "different": a request that read the version just
 * before this instance made a change of its own carries an older number than
 * the one now held, and that is not a reason to reload.
 */
async function followPolicyVersion(current) {
  // A loop, because the reload already in flight may have taken its snapshot
  // before the change this caller has seen.
  while (current > policyStore.loadedVersion) await reloadPolicy();
}

/**
 * The same check without a request to hang it on — run on the periodic sync,
 * so an idle instance does not drift, and strict about it: a version LOWER
 * than the one held means the store was reset or restored underneath us.
 */
async function followPolicyStore() {
  if ((await policyStore.currentVersion()) !== policyStore.loadedVersion) await reloadPolicy();
}

// RBAC, with one extension: a request also carries a context (the attributes
// of the caller, the resource and the request itself), and a policy row may
// carry a condition over those attributes (abac.js). conditionHolds() is true
// for every row that has no condition, so until somebody writes one this is
// the plain role model it always was.
const rbacModel = `
[request_definition]
r = sub, obj, act, ctx

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && keyMatch(r.obj, p.obj) && r.act == p.act && conditionHolds(r.ctx, p.sub, p.obj, p.act) || g(r.sub, "${PLATFORM_ADMIN_SUBJECT}")
`;

/** The matcher's conditionHolds(): does this policy row's condition (if any) hold for this request? */
function conditionHolds(context, subject, resource, action) {
  const condition = policyStore.conditionFor([subject, resource, action]);
  return condition === undefined ? true : evaluateCondition(condition, context);
}

/**
 * Adds one policy row together with its condition, in one step (see
 * policy-store.js for why they must not be written separately).
 * @returns {Promise<boolean>} false if the row already existed
 */
function addPolicyRow(subject, resource, action, condition = null) {
  return withCasbin(() => policyStore.withCondition(condition, () => enforcer.addPolicy(subject, resource, action)));
}

/**
 * What an attribute condition is evaluated against for one request.
 * Built-in names win over custom attributes of the same name, so an attribute
 * called `id` or `path` cannot be used to misdescribe the request.
 */
function buildAccessContext(account, serviceName, resource, tenant, request) {
  const now = new Date();
  return {
    subject: { ...(account.attributes || {}), id: account.id, username: account.username },
    resource: { ...(tenant?.attributes || {}), service: serviceName, path: resource },
    request: { method: request.method, ...(request.ip ? { ip: request.ip } : {}) },
    env: { time: now.toISOString(), hour: now.getUTCHours(), weekday: now.getUTCDay() },
  };
}

function parseAccountAttributes(raw) {
  try {
    const parsed = JSON.parse(raw || '{}');
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

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
  await followPolicyStore().catch((err) =>
    log.error('iam', `Policy refresh failed: ${err.message}`, { error: err.message }));
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

  // Must finish before the enforcer reads the policy list: rows written by an
  // older gateway name users and roles by their bare names, and loading those
  // under the current matcher would silently grant nobody anything.
  const idByUsername = await ensureUserIds();
  await migrateCasbinSubjects(idByUsername);

  const model = newModelFromString(rbacModel);
  enforcer = await newEnforcer(model, policyStore);
  enforcer.addFunction('conditionHolds', conditionHolds);
  await withCasbin(() => enforcer.loadPolicy());

  tenancy = createTenancy({
    redis,
    withCasbin,
    getEnforcer: () => enforcer,
    userSubjectFor,
    addPolicyRow,
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

/**
 * Creates an account and returns its id, or null if the username is taken.
 *
 * The id is what every Casbin row about this account is written against, so
 * it is generated here and never accepted from a caller. HSETNX on it is also
 * what makes creation atomic: two signups racing for one username cannot both
 * win and leave the second one's password on the first one's account.
 *
 * @param {object} [extra] additional hash fields (e.g. mustChangePassword)
 */
async function createUser(username, passwordHash, role = 'user', extra = {}) {
  const id = crypto.randomUUID();
  const claimed = await redis.hsetnx(`user:${username}`, 'id', id);
  if (!claimed) return null;

  await redis.hset(`user:${username}`, { password: passwordHash, role, ...extra });
  await redis.hset(USER_IDS_KEY, id, username);
  await redis.sadd(USERS_INDEX_KEY, username);
  return id;
}

async function getUserId(username) {
  return redis.hget(`user:${username}`, 'id');
}

/** The Casbin subject for this account, or null if there is no such account. */
async function userSubjectFor(username) {
  const id = await getUserId(username);
  return id ? userSubject(id) : null;
}

async function setUserRole(username, role) {
  await redis.hset(`user:${username}`, 'role', role);
}

// An account with no `status` field predates the field and is active.
const ACCOUNT_STATUS = { active: 'active', suspended: 'suspended' };

async function setAccountStatus(username, status) {
  await redis.hset(`user:${username}`, 'status', status);
}

/**
 * Records a newly granted platform role in the account's flat `role` field,
 * which is what the admin gate reads. An account that is an admin stays one
 * when it is granted something else as well: the field used to be simply "the
 * last role assigned", so giving an admin `blue_role` silently demoted them.
 */
async function noteGrantedRole(username, role) {
  const current = await redis.hget(`user:${username}`, 'role');
  if (current === 'admin' && role !== 'admin') return;
  await setUserRole(username, role);
}

async function deleteUser(username) {
  const id = await getUserId(username);
  await redis.del(`user:${username}`);
  await redis.srem(USERS_INDEX_KEY, username);
  if (id) await redis.hdel(USER_IDS_KEY, id);
}

// --- CASBIN SUBJECTS <-> THE NAMES THE API SPEAKS ---
//
// Casbin rows are written against prefixed subjects (see tenancy.js): u:{id}
// for an account, r:{name} for a platform role, t:{tenant}:{name} for a tenant
// role. The API keeps speaking plain names — a role is still "blue_role" on
// the wire — and these translate at the edge, so the prefix is something the
// gateway adds and a caller can never supply.

/** Usernames for a list of user subjects, in order; null where the account is gone. */
async function usernamesForSubjects(subjects) {
  const ids = subjects.map(parseUserSubject);
  const known = ids.filter(Boolean);
  if (known.length === 0) return ids.map(() => null);
  const names = await redis.hmget(USER_IDS_KEY, known);
  const byId = new Map(known.map((id, i) => [id, names[i]]));
  return ids.map((id) => (id ? byId.get(id) || null : null));
}

/** Platform role names as the API shows them; tenant roles keep their t: form. */
function presentRoles(subjects) {
  return subjects.map((s) => parsePlatformRole(s) ?? s);
}

/** Every role an account holds, as the API shows them. */
async function rolesHeldBy(username) {
  const subject = await userSubjectFor(username);
  if (!subject) return [];
  return presentRoles(await withCasbin(() => enforcer.getRolesForUser(subject)));
}

/** Usernames holding a role (given as its Casbin subject). */
async function usernamesHolding(roleSubject) {
  const holders = await withCasbin(() => enforcer.getUsersForRole(roleSubject)).catch(() => []);
  return (await usernamesForSubjects(holders)).filter(Boolean);
}

/**
 * Policy subjects as the API shows them: a role by its name, an account as
 * `user:{username}`. The explicit `user:` marker is the point — a bare name is
 * always a role, so the two can no longer be confused in either direction.
 */
async function presentPolicies(rules) {
  const usernames = await usernamesForSubjects(rules.map(([subject]) => subject));
  return rules.map(([subject, resource, action], i) => {
    const isUser = parseUserSubject(subject) !== null;
    const condition = policyStore.conditionFor([subject, resource, action]);
    return {
      subject: isUser ? `user:${usernames[i] ?? '(deleted)'}` : (parsePlatformRole(subject) ?? subject),
      resource,
      action,
      ...(condition ? { condition } : {}),
    };
  });
}

/**
 * Resolves a policy subject from a request body to its Casbin subject.
 *
 *   blue_role         -> a platform role
 *   t:llm:engineer    -> a tenant role
 *   user:alice        -> that account (and only that account)
 *
 * @returns {Promise<{ subject?: string, error?: string, status?: number }>}
 */
async function resolvePolicySubject(input) {
  const value = input.trim();

  if (value.startsWith('user:')) {
    const subject = await userSubjectFor(value.slice('user:'.length));
    return subject ? { subject } : { status: 404, error: `User '${value.slice('user:'.length)}' not found` };
  }
  if (parseQualifiedRole(value)) return { subject: value };

  const roleError = validateRoleName(value);
  if (roleError) {
    return { status: 400, error: `subject must be a role name, 't:{tenant}:{role}' or 'user:{username}' — ${roleError}` };
  }
  return { subject: platformRoleSubject(value) };
}

/**
 * Gives every existing account an id. New accounts get one in createUser();
 * this covers accounts written before ids existed. Idempotent and cheap, so it
 * runs on every boot.
 *
 * @returns {Promise<Map<string, string>>} username -> id
 */
async function ensureUserIds() {
  const keys = await redis.keys('user:*');

  // Same rule as backfillUserIndex below: only a Hash with a password is an account.
  const types = await Promise.all(keys.map((k) => redis.type(k)));
  const hashKeys = keys.filter((_, i) => types[i] === 'hash');
  const hasPassword = await Promise.all(hashKeys.map((k) => redis.hexists(k, 'password')));
  const accountKeys = hashKeys.filter((_, i) => hasPassword[i] === 1);
  if (accountKeys.length === 0) return new Map();

  // HSETNX then read back, so two gateways booting together agree on one id.
  await Promise.all(accountKeys.map((k) => redis.hsetnx(k, 'id', crypto.randomUUID())));
  const ids = await Promise.all(accountKeys.map((k) => redis.hget(k, 'id')));
  const usernames = accountKeys.map((k) => k.slice('user:'.length));

  await redis.hset(USER_IDS_KEY, Object.fromEntries(ids.map((id, i) => [id, usernames[i]])));
  return new Map(usernames.map((username, i) => [username, ids[i]]));
}

// --- ONE-TIME MIGRATION: BARE NAMES -> PREFIXED SUBJECTS ---
//
// Older gateways wrote Casbin rows against bare names: g(alice, blue_role),
// p(blue_role, /llm/claude, get). Because a username and a role name were the
// same kind of string, an account called `blue_role` held blue_role. This
// rewrites the stored rows once so that every user is u:{id} and every
// platform role is r:{name}; tenant roles were already namespaced.
//
// Where an old row is ambiguous it is resolved toward the role, which is the
// reading that removes access nobody granted rather than the one that keeps it.
const SUBJECT_SCHEMA_KEY = 'casbin:subjects:schema';
const SUBJECT_SCHEMA_VERSION = '2';

async function migrateCasbinSubjects(idByUsername) {
  if ((await redis.get(SUBJECT_SCHEMA_KEY)) === SUBJECT_SCHEMA_VERSION) return;

  const rows = [];
  for (const entry of await redis.lrange(CASBIN_POLICY_KEY, 0, -1)) {
    try {
      const parsed = JSON.parse(entry);
      if (Array.isArray(parsed.rule)) rows.push(parsed);
    } catch { /* unparseable rows were already being skipped on load */ }
  }

  // Anything that has been used as a role is a role, whatever else shares its name.
  const roleNames = new Set(await redis.smembers(ROLES_INDEX_KEY));
  for (const { ptype, rule } of rows) if (ptype === 'g') roleNames.add(rule[1]);

  const roleSubject = (name) => (parseQualifiedRole(name) ? name : platformRoleSubject(name));
  const migrated = new Set(); // insertion-ordered, so duplicates collapse and order is kept
  let orphanedGrants = 0;

  for (const { ptype, rule } of rows) {
    let next;
    if (ptype === 'g') {
      const id = idByUsername.get(rule[0]);
      // A grant to an account that no longer exists would otherwise be picked
      // up by whoever registers that name next.
      if (!id) { orphanedGrants += 1; continue; }
      next = [userSubject(id), roleSubject(rule[1])];
    } else {
      const [subject, ...rest] = rule;
      const directToUser = !roleNames.has(subject) && !parseQualifiedRole(subject) && idByUsername.has(subject);
      next = [directToUser ? userSubject(idByUsername.get(subject)) : roleSubject(subject), ...rest];
    }
    migrated.add(JSON.stringify({ ptype, rule: next }));
  }

  const multi = redis.multi();
  multi.del(CASBIN_POLICY_KEY);
  for (const json of migrated) multi.rpush(CASBIN_POLICY_KEY, json);
  multi.incr(POLICY_VERSION_KEY); // the policy changed: any instance already running must reload
  multi.set(SUBJECT_SCHEMA_KEY, SUBJECT_SCHEMA_VERSION);
  await multi.exec();

  if (rows.length > 0) {
    log.audit('iam', `Casbin subjects migrated to prefixed identifiers (${rows.length} row(s) read, ${migrated.size} written)`, {
      read: rows.length, written: migrated.size, orphanedGrantsDropped: orphanedGrants,
    });
  }
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

// --- SECURITY VERSION / REVOCATION ---
//
// A JWT says "this was issued to account X". It does not say X is still the
// same account it was then. `tokenVersion` is the account's security version:
// a counter on the account that every token carries a copy of, checked on
// every request. Move the counter and every token issued before that moment
// stops authenticating — wherever it is, and without knowing how many exist.
//
// It moves whenever the account becomes LESS than it was when those tokens
// were issued: its password is changed or reset, it is suspended, or any
// access is taken away from it (a platform role, a tenant role, a tenant
// membership, tenant-admin rights). Access checks are evaluated live, so a
// revoked role stops working at once either way; ending the sessions as well
// means nothing issued under the old standing survives it. Deleting an
// account needs no version at all — its id is gone, and a token is only ever
// looked up by id.
async function getTokenVersion(username) {
  const version = await redis.hget(`user:${username}`, 'tokenVersion');
  return version ? parseInt(version, 10) : 0;
}

async function bumpTokenVersion(username) {
  // HINCRBY creates the hash it is asked to increment, so on a name with no
  // account it would leave a stray `user:` key behind.
  if (await userExists(username)) await redis.hincrby(`user:${username}`, 'tokenVersion', 1);
}

/** Ends every session of each of these accounts. */
async function endSessions(usernames) {
  await Promise.all([...new Set(usernames)].map(bumpTokenVersion));
}

function revokedJtiKey(jti) {
  return `revoked:jti:${jti}`;
}

async function revokeJti(jti, ttlSeconds) {
  if (ttlSeconds <= 0) return;
  await redis.set(revokedJtiKey(jti), '1', 'EX', ttlSeconds);
}

// --- RATE LIMITING (Redis-backed, correct across multiple gateway instances) ---
//
// express-rate-limit's default store is in-process memory, which is
// wrong here: this gateway is explicitly designed to run as multiple
// instances behind a load balancer (README §4). Counting in Redis
// means every instance shares the same view of "how many attempts has
// this IP/username made", so horizontal scaling doesn't quietly
// disable the limiter. The counting itself is atomic — see ratelimit.js.
const limiter = createRateLimiter(redis, { onLimited: (bucket) => rateLimited.inc({ bucket }) });

/** Answers 429 with the wait the limiter reported. */
// The code lets a client tell "slow down" apart from every other refusal.
const RATE_LIMITED = 'RATE_LIMITED';

function tooManyRequests(res, slot, message) {
  res.set('Retry-After', String(slot.retryAfterSeconds));
  return res.status(429).json({ error: message, code: RATE_LIMITED });
}

// --- VALIDATION HELPERS ---

function isNonEmptyString(value) {
  return typeof value === 'string' && value.trim().length > 0;
}

// Request shapes shared by more than one route.
const usernameParam = { username: v.accountName };
const tenantParam = { tenantId: v.tenantId };
const tenantUserParams = { tenantId: v.tenantId, username: v.accountName };
const requestIdParam = { id: v.requestId };

// --- AUTHENTICATION ROUTES ---

/**
 * Signs a token for an account that has just proved its password. Nothing
 * mints one on someone else's behalf.
 *
 * It carries three things and nothing else:
 *   sub           the account's id — immutable, server-generated, and the only
 *                 thing the account is ever looked up by
 *   tokenVersion  the account's security version at the moment of issue
 *   jti           this token's own id, so it alone can be revoked (logout)
 *
 * No username and no role. Both can change after the token is issued, and
 * anything a token asserts about its holder is something a later request
 * might believe instead of checking.
 */
function signToken({ id, tokenVersion }) {
  const jti = crypto.randomUUID();
  return jwt.sign({ sub: id, tokenVersion, jti }, JWT_SECRET, {
    algorithm: JWT_ALGORITHM, expiresIn: '24h',
  });
}

app.post('/auth/signup', validate({
  body: { username: v.newUsername, password: v.newPassword },
}), async (req, res) => {
  const { username, password } = req.body;

  const slot = await limiter.take('signup:ip', req.ip, SIGNUP_IP_LIMIT);
  if (!slot.allowed) {
    log.warn('auth', 'Signup rate limit exceeded for IP', { ip: req.ip, count: slot.count });
    return tooManyRequests(res, slot, 'Too many signups from this address, try again later');
  }

  if (await userExists(username)) {
    return res.status(409).json({ error: 'User already exists' });
  }

  const hash = await hashPassword(password);
  const id = await createUser(username, hash, 'user');
  // Lost a race with another signup for the same name.
  if (!id) return res.status(409).json({ error: 'User already exists' });
  await withCasbin(() => enforcer.addRoleForUser(userSubject(id), platformRoleSubject('user')));

  log.audit('auth', `User '${username}' signed up`, { username, ip: req.ip });
  res.status(201).json({ message: 'User registered successfully' });
});

// What a failed login says, whatever the reason. "No such user" and "wrong
// password" used to be two different messages, which made the login form a
// way to find out which usernames exist.
const LOGIN_FAILED = 'Invalid username or password';

// A login for a username that does not exist still verifies a password —
// against this — so it takes as long as one that does. Otherwise the answer
// the message no longer gives away could be read off the response time.
const dummyPasswordHash = hashPassword(crypto.randomBytes(24).toString('hex'));

/**
 * The one place a username and password are checked. Both ways of signing in
 * go through it — the token API below and the OIDC sign-in page — so the
 * limits, the single failure answer and the timing are the same whichever
 * door is used.
 *
 * @returns {Promise<{ account: object } | { refusal: { status: number, error: string, code?: string, retryAfterSeconds?: number } }>}
 */
async function checkCredentials(username, password, ip) {
  // Slots are taken before the password is looked at, so the limits bound
  // ATTEMPTS — including ones still in flight. Counting failures afterwards
  // let any number of parallel guesses through before the first was recorded.
  const ipSlot = await limiter.take('login:ip', ip, LOGIN_IP_LIMIT);
  if (!ipSlot.allowed) {
    log.warn('auth', 'Login rate limit exceeded for IP', { ip, count: ipSlot.count });
    return {
      refusal: {
        status: 429, error: 'Too many login attempts from this address, try again later',
        code: RATE_LIMITED, retryAfterSeconds: ipSlot.retryAfterSeconds,
      },
    };
  }

  // Keyed by the name as typed, whether or not such an account exists, so
  // being locked out says nothing about that either.
  const userSlot = await limiter.take('login:user', username, LOGIN_USER_LIMIT);
  if (!userSlot.allowed) {
    log.warn('auth', 'Login blocked: too many attempts for this username', { username, ip, count: userSlot.count });
    return {
      refusal: {
        status: 429, error: 'Too many failed login attempts for this username, try again later',
        code: RATE_LIMITED, retryAfterSeconds: userSlot.retryAfterSeconds,
      },
    };
  }

  const userData = await getUser(username);
  const known = Boolean(userData?.password);
  const { valid, rehash } = await verifyPassword(password, known ? userData.password : await dummyPasswordHash);

  if (!known || !valid) {
    // The reason is for the audit log only; the caller gets one answer.
    authEvents.inc({ event: 'login_failed' });
    log.audit('auth', 'Login failed', { username, ip, reason: known ? 'bad-password' : 'unknown-user' });
    return { refusal: { status: 401, error: LOGIN_FAILED } };
  }

  // The password was right: this attempt should not count against anyone.
  await Promise.all([limiter.reset('login:user', username), limiter.refund('login:ip', ip)]);

  // Said only to someone who has just proved they hold the password.
  if (userData.status === ACCOUNT_STATUS.suspended) {
    log.audit('auth', `Login refused: account '${username}' is suspended`, { username, ip });
    return { refusal: { status: 403, error: 'This account is suspended', code: ACCOUNT_SUSPENDED } };
  }

  if (rehash) {
    // Legacy bcrypt hash just verified successfully — migrate it to Argon2
    // transparently now that we have the plaintext in hand.
    await redis.hset(`user:${username}`, 'password', rehash);
    log.info('auth', `Password hash migrated from bcrypt to Argon2`, { username });
  }

  authEvents.inc({ event: 'login_succeeded' });
  return { account: { ...userData, username } };
}

/**
 * POST /auth/login — username and password in, session token out.
 *
 * The direct door, for scripts, services and tests. A person in a browser
 * signs in through /oauth/authorize instead (oidc.js), where the password is
 * typed into a page this gateway renders rather than handed to the
 * application's own JavaScript.
 */
app.post('/auth/login', validate({
  body: { username: v.accountName, password: v.presentedPassword },
}), async (req, res) => {
  const { account, refusal } = await checkCredentials(req.body.username, req.body.password, req.ip);
  if (refusal) {
    if (refusal.retryAfterSeconds) res.set('Retry-After', String(refusal.retryAfterSeconds));
    return res.status(refusal.status).json({ error: refusal.error, ...(refusal.code ? { code: refusal.code } : {}) });
  }

  const tokenVersion = await getTokenVersion(account.username);
  const token = signToken({ id: account.id, tokenVersion });
  const mustChangePassword = account.mustChangePassword === '1';

  log.audit('auth', `User '${account.username}' logged in`, { username: account.username, ip: req.ip, mustChangePassword });
  res.json({
    token,
    message: mustChangePassword
      ? 'Login successful — this password is temporary and must be changed (POST /auth/change-password) before the account can be used'
      : 'Login successful',
    ...(mustChangePassword ? { mustChangePassword: true } : {}),
  });
});

// --- MIDDLEWARES ---

// Returned to an account that is signed in but still holds a password someone
// else knows. The code is for clients to branch on; the console uses it to
// show the change-password form instead of an error.
const PASSWORD_CHANGE_REQUIRED = 'PASSWORD_CHANGE_REQUIRED';

// Returned to a token whose account has been suspended. (A suspension also
// moves the account's security version, so its existing tokens fail earlier
// than this; this is what a token issued in the instant around it would hit.)
const ACCOUNT_SUSPENDED = 'ACCOUNT_SUSPENDED';

// One answer for every way a token stops being good — logged out, superseded
// by a newer security version, or its account gone. The code lets a client
// tell "sign in again" apart from any other 401.
const SESSION_ENDED = 'SESSION_ENDED';
const REVOKED = { error: 'Token has been revoked, please log in again', code: SESSION_ENDED };

/**
 * Authenticates a request, and then re-establishes — from current state, on
 * every request — everything the rest of the gateway will rely on.
 *
 * A valid signature proves only that this gateway issued the token. From the
 * token it takes exactly one identity claim, `sub`: the account's immutable
 * id. With that id it asks Redis, now:
 *
 *   - does this account still exist?           (deleted accounts' tokens die)
 *   - is it active?                            (suspended accounts are refused)
 *   - is this token from its current security version?
 *   - what is its role?                        (admin-ness is never read from
 *                                               the token — see requireAdmin)
 *
 * `req.user` is built from those answers. Nothing in it is a claim the token
 * made about its holder, so nothing downstream can act on a stale one.
 *
 * Last, the request is counted against the account's budget. That happens
 * only once everything above has passed, so a revoked or forged token cannot
 * use up the budget of the account it names.
 *
 * @param {object} [opts]
 * @param {boolean} [opts.allowPendingPasswordChange] let an account that still
 *   has to change its password through. Only the two routes such an account
 *   needs — changing the password, and logging out — set this.
 * @param {{ bucket: string, max: number, windowSeconds: number }|null} [opts.budget]
 *   which per-account budget this request draws on; null for none.
 */
function authenticate({ allowPendingPasswordChange = false, budget = API_REQUEST_LIMIT } = {}) {
  return async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or invalid token' });
    }

    let payload;
    try {
      payload = jwt.verify(authHeader.split(' ')[1], JWT_SECRET, { algorithms: [JWT_ALGORITHM] });
    } catch {
      authEvents.inc({ event: 'token_invalid' });
      return res.status(403).json({ error: 'Token expired or invalid' });
    }
    if (typeof payload.sub !== 'string' || typeof payload.jti !== 'string') {
      authEvents.inc({ event: 'token_revoked' });
      return res.status(401).json(REVOKED);
    }

    // Explicit revocation (logout) by token id, and the id -> account lookup.
    // The policy version rides along: it costs nothing here, and it is how
    // this instance learns that another one has changed the policy.
    const [[, jtiRevoked], [, username], [, policyVersion]] = await redis.pipeline()
      .exists(revokedJtiKey(payload.jti))
      .hget(USER_IDS_KEY, payload.sub)
      .get(POLICY_VERSION_KEY)
      .exec();
    if (jtiRevoked === 1 || !username) {
      authEvents.inc({ event: 'token_revoked' });
      return res.status(401).json(REVOKED);
    }

    const [id, status, role, tokenVersion, mustChangePassword, attributes] = await redis.hmget(
      `user:${username}`, 'id', 'status', 'role', 'tokenVersion', 'mustChangePassword', 'attributes',
    );

    // The record found under that id must name the same id back. It does not
    // if the account was deleted and the username taken by someone else.
    // Blanket revocation — the account's security version has moved on.
    if (id !== payload.sub || (payload.tokenVersion ?? 0) !== (tokenVersion ? parseInt(tokenVersion, 10) : 0)) {
      authEvents.inc({ event: 'token_revoked' });
      return res.status(401).json(REVOKED);
    }

    // From here on, every log entry this request produces names the account.
    log.setActor({ id, username });

    if (status === ACCOUNT_STATUS.suspended) {
      return res.status(403).json({ error: 'This account is suspended', code: ACCOUNT_SUSPENDED });
    }

    if (mustChangePassword === '1' && !allowPendingPasswordChange) {
      return res.status(403).json({
        error: 'This account must change its password before it can be used',
        code: PASSWORD_CHANGE_REQUIRED,
        hint: 'POST /auth/change-password with currentPassword and newPassword',
      });
    }

    // Everything after this point may consult the policy — roles, tenant
    // roles, the proxy's authorization — so catch up first if another
    // instance has changed it.
    await followPolicyVersion(Number(policyVersion) || 0);

    if (budget) {
      // One atomic take per request (ratelimit.js): the count this request is
      // handed either fits or it does not, however many arrive together.
      const slot = await limiter.take(budget.bucket, id, budget);
      res.set({
        'RateLimit-Limit': String(budget.max),
        'RateLimit-Remaining': String(Math.max(0, budget.max - slot.count)),
        'RateLimit-Reset': String(slot.retryAfterSeconds),
      });
      if (!slot.allowed) {
        log.warn('ratelimit', `Account '${username}' is over its ${budget.bucket} request budget`, {
          username, bucket: budget.bucket, count: slot.count, max: budget.max,
        });
        return tooManyRequests(res, slot, 'Too many requests from this account, slow down');
      }
    }

    req.user = {
      id,
      username,
      role: role || 'user',
      // What attribute conditions see as subject.* (set by a platform admin).
      attributes: parseAccountAttributes(attributes),
      // What authorization is evaluated against — the id, never the name.
      subject: userSubject(id),
      // Kept for logout, which revokes this one token for its remaining life.
      jti: payload.jti,
      exp: payload.exp,
    };
    next();
  };
}

const authenticateJWT = authenticate();
// Calls proxied to a service are budgeted separately from calls to the gateway's own API.
const authenticateProxied = authenticate({ budget: GATEWAY_REQUEST_LIMIT });
// Changing a password has its own, much tighter limit; logging out should
// never be refused for being busy.
const authenticateForPasswordChange = authenticate({ allowPendingPasswordChange: true, budget: null });

/**
 * Platform-admin gate. `req.user.role` is the account's role as authenticate()
 * just read it from Redis — not a claim carried in the token — so removing
 * someone's admin role locks them out of this surface on their very next
 * request, on every gateway instance, rather than when their token expires.
 */
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
  const roles = await rolesHeldBy(username);
  const tenants = await tenancy.listTenantsForUser(username);
  res.json({
    username,
    role: userData.role,
    // Every role the account holds: platform roles by name, tenant roles in
    // their t:{tenant}:{role} form — the shape existing clients already read...
    roles,
    isPlatformAdmin: isPlatformAdmin(req),
    // ...and the same information split by tenant, which is what a portal or a
    // tenant console actually needs to render.
    tenants: tenants.map((t) => ({
      id: t.id, displayName: t.displayName, roles: t.roles, isAdmin: t.isAdmin, permissions: t.permissions,
    })),
  });
});

/**
 * POST /me/test-access — "what do I actually get?"
 *
 * The counterpart to the admin and tenant-admin access tests, for the person
 * whose access it is. It replays the caller's OWN bearer token, so what comes
 * back is literally what their current session gets — including, if their
 * token is stale or revoked, the 401 they would really see.
 *
 * This is the only access test that makes real calls. The token is the
 * caller's own and already sits in their browser, so it is shown in full; the
 * admin-facing tests involve no token at all (see "Access tests" below).
 */
app.post('/me/test-access', authenticateJWT, async (req, res) => {
  const { username } = req.user;
  await syncServicesFromRegistry();

  const services = Array.from(serviceCache.entries()).map(([name, cfg]) => ({ name, ...cfg }));
  const ownToken = req.headers.authorization.slice('Bearer '.length);
  const probe = await probeOwnAccess(ownToken, services);

  log.audit('self-service', `User '${username}' tested their own access`, { username });

  res.json({
    username,
    mode: 'live-call',
    roles: await rolesHeldBy(username),
    tenants: (await tenancy.listTenantsForUser(username)).map((t) => ({ id: t.id, roles: t.roles })),
    testedAt: new Date().toISOString(),
    token: probe.token,
    services: probe.services,
  });
});

app.get('/catalog/services', authenticateJWT, async (req, res) => {
  await syncServicesFromRegistry();
  const rules = await withCasbin(() => enforcer.getPolicy());
  // Roles only: this listing is visible to every signed-in user, and a policy
  // written for one specific account is not something to advertise to them.
  const policies = (await presentPolicies(rules.filter(([subject]) => parseUserSubject(subject) === null)));

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

app.post('/requests', authenticateJWT, validate({
  body: {
    tenant: v.optional(v.tenantId),
    role: v.optional(v.roleName),
    service: v.optional(v.tenantId),
    note: v.optional(v.text(500)),
  },
}), async (req, res) => {
  const { username } = req.user;
  const tenantId = req.body.tenant || null;
  const role = req.body.role || null;
  const service = req.body.service || null;
  const note = req.body.note || '';

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
    if (await withCasbin(() => enforcer.hasRoleForUser(req.user.subject, platformRoleSubject(role)))) {
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

app.post('/auth/change-password', authenticateForPasswordChange, validate({
  body: { currentPassword: v.presentedPassword, newPassword: v.newPassword },
}), async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { username } = req.user;

  // A token is enough to reach this route, so without a limit a stolen one
  // could be used to guess the account's password as fast as Argon2 allows.
  const slot = await limiter.take('password:user', req.user.id, PASSWORD_CHECK_LIMIT);
  if (!slot.allowed) {
    log.warn('auth', 'Password change blocked: too many wrong attempts', { username, ip: req.ip, count: slot.count });
    return tooManyRequests(res, slot, 'Too many incorrect password attempts, try again later');
  }

  const userData = await getUser(username);
  const { valid } = await verifyPassword(currentPassword, userData.password);
  if (!valid) {
    log.audit('auth', `Password change rejected: wrong current password`, { username, ip: req.ip });
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  await limiter.reset('password:user', req.user.id);
  // "Changing" a password to itself would satisfy a mandatory change without
  // changing anything, so it is not a change.
  if (newPassword === currentPassword) {
    return res.status(400).json({ error: 'The new password must be different from the current one' });
  }

  const hash = await hashPassword(newPassword);
  const wasMandatory = userData.mustChangePassword === '1';
  await redis.multi()
    .hset(`user:${username}`, 'password', hash)
    .hdel(`user:${username}`, 'mustChangePassword')
    .exec();
  await bumpTokenVersion(username);
  // The temporary password no longer opens anything, so its file can go.
  if (wasMandatory && username === BOOTSTRAP_ADMIN_USERNAME) removeInitialAdminPasswordFile();

  log.audit('auth', `User '${username}' changed their password`, { username, ip: req.ip, wasMandatory });
  res.json({ message: 'Password changed; all existing sessions have been invalidated' });
});

app.post('/auth/logout', authenticateForPasswordChange, async (req, res) => {
  const { jti, exp, username } = req.user;
  if (jti && exp) {
    const ttlSeconds = exp - Math.floor(Date.now() / 1000);
    await revokeJti(jti, ttlSeconds);
  }
  log.audit('auth', `User '${username}' logged out`, { username, ip: req.ip });
  res.json({ message: 'Logged out' });
});

/**
 * POST /auth/logout-all — sign out everywhere.
 * Moves the account's security version, so every token it has ever been
 * issued — on any device, including the one making this call — stops working.
 */
app.post('/auth/logout-all', authenticateForPasswordChange, async (req, res) => {
  await bumpTokenVersion(req.user.username);
  log.audit('auth', `User '${req.user.username}' ended all of their sessions`, { username: req.user.username, ip: req.ip });
  res.json({ message: 'Signed out everywhere; every existing session has been ended' });
});

// --- PASSWORD RECOVERY ---
//
// A forgotten password is replaced by proving possession of a one-time token,
// never by an administrator choosing a password for someone:
//
//   - the token is 256 random bits, single-use, and expires in 30 minutes;
//   - only its SHA-256 is stored, so a Redis dump contains nothing that
//     resets anybody's password;
//   - issuing a new one cancels the old one;
//   - using it sets the password, ends every session the account has, and
//     clears its login lockout.
//
// It reaches its owner one of two ways: an administrator issues it and hands
// it over out of band (POST /admin/users/:username/recovery-link), or the
// user asks for it themselves and the gateway passes it to the operator's
// notification service (PASSWORD_RECOVERY_WEBHOOK_URL), which is what knows
// how to reach a person — by email, SMS, or whatever the organisation uses.
// The gateway has no mail transport of its own, and without that webhook
// self-service requests are recorded and answered, but nothing is sent.
const RECOVERY_TOKEN_TTL_SECONDS = 30 * 60;
const RECOVERY_WEBHOOK_URL = process.env.PASSWORD_RECOVERY_WEBHOOK_URL || null;
const RECOVERY_WEBHOOK_TOKEN = process.env.PASSWORD_RECOVERY_WEBHOOK_TOKEN || null;

const sha256Hex = (value) => crypto.createHash('sha256').update(value).digest('hex');
const recoveryTokenKey = (tokenHash) => `recovery:token:${tokenHash}`;
const recoveryAccountKey = (id) => `recovery:account:${id}`;

// Reads a key and deletes it in one step, so a token presented twice at the
// same moment is honoured once.
redis.defineCommand('takeOnce', {
  numberOfKeys: 1,
  lua: `
    local value = redis.call('GET', KEYS[1])
    if value then redis.call('DEL', KEYS[1]) end
    return value
  `,
});

/** Issues the account's (only) recovery token and returns it, with the link that carries it. */
async function issueRecoveryToken(username) {
  const id = await getUserId(username);
  const token = crypto.randomBytes(32).toString('base64url');

  const previous = await redis.get(recoveryAccountKey(id));
  const write = redis.multi();
  if (previous) write.del(recoveryTokenKey(previous));
  write.set(recoveryTokenKey(sha256Hex(token)), id, 'EX', RECOVERY_TOKEN_TTL_SECONDS);
  write.set(recoveryAccountKey(id), sha256Hex(token), 'EX', RECOVERY_TOKEN_TTL_SECONDS);
  await write.exec();

  return {
    token,
    // In the fragment, which browsers send to no server and put in no Referer.
    link: `${PUBLIC_URL}/console#recover=${token}`,
    expiresAt: new Date(Date.now() + RECOVERY_TOKEN_TTL_SECONDS * 1000).toISOString(),
  };
}

/** Hands a recovery link to the operator's notifier. Never throws. */
async function deliverRecoveryLink(username, recovery) {
  if (!RECOVERY_WEBHOOK_URL) {
    log.audit('auth', `Password recovery requested for '${username}', but no delivery channel is configured`, {
      username, hint: 'set PASSWORD_RECOVERY_WEBHOOK_URL, or have an admin issue a recovery link',
    });
    return;
  }
  try {
    const { default: fetch } = await import('node-fetch');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(RECOVERY_WEBHOOK_URL, {
      method: 'POST',
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...(RECOVERY_WEBHOOK_TOKEN ? { Authorization: `Bearer ${RECOVERY_WEBHOOK_TOKEN}` } : {}),
      },
      body: JSON.stringify({ event: 'password-recovery', username, link: recovery.link, expiresAt: recovery.expiresAt }),
    }).finally(() => clearTimeout(timer));
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    log.audit('auth', `Password recovery link for '${username}' handed to the notification service`, { username });
  } catch (err) {
    log.error('auth', `Could not deliver the password recovery link for '${username}': ${err.message}`, { username });
  }
}

/**
 * POST /auth/password-recovery — { username }
 * "I have forgotten my password." Always answers the same way, immediately,
 * whether or not there is such an account: the work happens after the
 * response, so neither the answer nor how long it took says anything.
 */
app.post('/auth/password-recovery', validate({ body: { username: v.accountName } }), async (req, res) => {
  const { username } = req.body;

  const ipSlot = await limiter.take('recovery:ip', req.ip, RECOVERY_REQUEST_IP_LIMIT);
  if (!ipSlot.allowed) return tooManyRequests(res, ipSlot, 'Too many recovery requests from this address, try again later');

  res.status(202).json({ message: 'If that account exists, recovery instructions have been sent' });

  try {
    const userSlot = await limiter.take('recovery:user', username, RECOVERY_REQUEST_USER_LIMIT);
    const userData = await getUser(username);
    if (!userSlot.allowed || !userData?.password || userData.status === ACCOUNT_STATUS.suspended) {
      log.audit('auth', 'Password recovery request not acted on', {
        username, ip: req.ip,
        reason: !userSlot.allowed ? 'rate-limited' : !userData?.password ? 'unknown-user' : 'suspended',
      });
      return;
    }
    await deliverRecoveryLink(username, await issueRecoveryToken(username));
  } catch (err) {
    log.error('auth', `Password recovery request failed: ${err.message}`, { username });
  }
});

/**
 * POST /auth/password-recovery/complete — { token, newPassword }
 * Trades a recovery token for a new password.
 */
app.post('/auth/password-recovery/complete', validate({
  body: { token: v.string({ min: 20, max: 200 }), newPassword: v.newPassword },
}), async (req, res) => {
  const { token, newPassword } = req.body;

  const slot = await limiter.take('recovery-attempt:ip', req.ip, RECOVERY_ATTEMPT_IP_LIMIT);
  if (!slot.allowed) return tooManyRequests(res, slot, 'Too many attempts from this address, try again later');

  const invalid = () => res.status(400).json({ error: 'This recovery link is not valid or has expired — request a new one' });

  const id = await redis.takeOnce(recoveryTokenKey(sha256Hex(token)));
  if (!id) return invalid();
  const username = await redis.hget(USER_IDS_KEY, id);
  if (!username) return invalid();
  if ((await redis.hget(`user:${username}`, 'status')) === ACCOUNT_STATUS.suspended) {
    return res.status(403).json({ error: 'This account is suspended', code: ACCOUNT_SUSPENDED });
  }

  await redis.multi()
    .hset(`user:${username}`, 'password', await hashPassword(newPassword))
    .hdel(`user:${username}`, 'mustChangePassword')
    .del(recoveryAccountKey(id))
    .exec();
  await bumpTokenVersion(username);
  // Whoever locked the account out with wrong guesses does not get to keep it locked.
  await limiter.reset('login:user', username);

  log.audit('auth', `Password of '${username}' reset with a recovery token`, { username, ip: req.ip });
  res.json({ message: 'Password changed; every existing session has been ended. You can sign in with the new password.' });
});

// --- ADMIN ROUTES ---

// -- Users --

app.get('/admin/users', authenticateJWT, requireAdmin, async (req, res) => {
  const usernames = await listAllUsernames();

  const users = await Promise.all(
    usernames.map(async (username) => {
      const userData = await getUser(username);
      const roles = await rolesHeldBy(username);
      return {
        username, role: userData.role, status: userData.status || ACCOUNT_STATUS.active, roles,
        attributes: parseAccountAttributes(userData.attributes),
      };
    }),
  );

  res.json({ count: users.length, users });
});

app.get('/admin/users/:username', authenticateJWT, requireAdmin, validate({ params: usernameParam }), async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const userData = await getUser(username);
  const roles = await rolesHeldBy(username);
  res.json({
    username, role: userData.role, status: userData.status || ACCOUNT_STATUS.active, roles,
    attributes: parseAccountAttributes(userData.attributes),
  });
});

/**
 * PUT /admin/users/:username/attributes — { attributes: { department: "finance", clearance: 3 } }
 *
 * Replaces the attributes attribute conditions see as subject.* for this
 * account. They describe the person to every tenant's policies, so only a
 * platform admin sets them — a tenant admin cannot raise somebody's clearance.
 */
app.put('/admin/users/:username/attributes', authenticateJWT, requireAdmin, validate({
  params: usernameParam,
  body: { attributes: v.attributes },
}), async (req, res) => {
  const { username } = req.params;
  const { attributes } = req.body;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  await redis.hset(`user:${username}`, 'attributes', JSON.stringify(attributes));
  // An attribute can be what a condition was granting on, so changing them
  // may be taking access away. Treated like any other downgrade.
  await bumpTokenVersion(username);

  log.audit('admin', `Admin '${req.user.username}' set attributes of '${username}'`, {
    actor: req.user.username, target: username, attributes,
  });
  res.json({ message: `Attributes of '${username}' updated; their sessions have been ended`, attributes });
});

app.delete('/admin/users/:username', authenticateJWT, requireAdmin, validate({ params: usernameParam }), async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const subject = await userSubjectFor(username);
  // Every grant this account holds (tenant-qualified ones included) and any
  // policy written for it directly; the membership Sets are ours to clean up.
  await withCasbin(() => enforcer.deleteRolesForUser(subject));
  await withCasbin(() => enforcer.removeFilteredPolicy(0, subject));
  const purgedFrom = await tenancy.purgeUserFromAllTenants(username);
  // Removes the id -> account mapping every token is looked up by, so the
  // account's tokens stop authenticating with this write.
  await deleteUser(username);

  log.audit('admin', `Admin '${req.user.username}' deleted user '${username}'`, {
    purgedFromTenants: purgedFrom,
    actor: req.user.username, target: username,
  });
  res.json({ message: `User '${username}' deleted` });
});

/**
 * POST /admin/users/:username/suspend
 * Switches an account off without destroying it: it can no longer sign in,
 * and every session it has is ended at once. Its roles, memberships and
 * requests stay exactly as they are, so reactivating it restores it whole.
 */
app.post('/admin/users/:username/suspend', authenticateJWT, requireAdmin, validate({ params: usernameParam }), async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }
  // The one account an admin cannot get back into to undo it.
  if (username === req.user.username) {
    return res.status(409).json({ error: 'You cannot suspend your own account' });
  }

  await setAccountStatus(username, ACCOUNT_STATUS.suspended);
  await bumpTokenVersion(username);

  log.audit('admin', `Admin '${req.user.username}' suspended account '${username}'`, {
    actor: req.user.username, target: username,
  });
  res.json({ message: `Account '${username}' suspended; all its sessions have been ended` });
});

app.post('/admin/users/:username/reactivate', authenticateJWT, requireAdmin, validate({ params: usernameParam }), async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  await setAccountStatus(username, ACCOUNT_STATUS.active);

  log.audit('admin', `Admin '${req.user.username}' reactivated account '${username}'`, {
    actor: req.user.username, target: username,
  });
  res.json({ message: `Account '${username}' reactivated` });
});

app.post('/admin/users/:username/reset-password', authenticateJWT, requireAdmin, validate({
  params: usernameParam,
  body: { newPassword: v.newPassword },
}), async (req, res) => {
  const { username } = req.params;
  const { newPassword } = req.body;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  // A password an administrator chose is one an administrator knows. It gets
  // the account's owner back in and no further: it has to be replaced at the
  // next sign-in before the account can do anything else. (A recovery link —
  // below — avoids the administrator ever knowing a password at all.)
  const hash = await hashPassword(newPassword);
  await redis.hset(`user:${username}`, { password: hash, mustChangePassword: '1' });
  await bumpTokenVersion(username);

  log.audit('admin', `Admin '${req.user.username}' reset password for '${username}'`, {
    actor: req.user.username, target: username,
  });
  res.json({
    message: `Temporary password set for '${username}'; all their existing sessions have been invalidated, and they must choose a new password at next sign-in`,
  });
});

/**
 * POST /admin/users/:username/revoke-sessions
 * Ends every session the account has without otherwise touching it — for a
 * lost device or a suspected leak, where suspending the person is too much.
 */
app.post('/admin/users/:username/revoke-sessions', authenticateJWT, requireAdmin, validate({ params: usernameParam }), async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  await bumpTokenVersion(username);
  log.audit('admin', `Admin '${req.user.username}' ended all sessions of '${username}'`, {
    actor: req.user.username, target: username,
  });
  res.json({ message: `All sessions of '${username}' have been ended` });
});

/**
 * POST /admin/users/:username/recovery-link
 * Issues a one-time password-recovery link for the account, to be handed to
 * its owner out of band. The token is shown here once and stored nowhere in
 * a usable form; the administrator never learns or sets a password.
 */
app.post('/admin/users/:username/recovery-link', authenticateJWT, requireAdmin, validate({ params: usernameParam }), async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const recovery = await issueRecoveryToken(username);
  log.audit('admin', `Admin '${req.user.username}' issued a password recovery link for '${username}'`, {
    actor: req.user.username, target: username, expiresAt: recovery.expiresAt,
  });
  res.json({
    message: `Recovery link issued for '${username}'. It works once and expires in ${RECOVERY_TOKEN_TTL_SECONDS / 60} minutes; any earlier link is cancelled.`,
    ...recovery,
  });
});

// -- Roles --

app.post('/admin/roles', authenticateJWT, requireAdmin, validate({
  body: { username: v.accountName, role: v.roleName },
}), async (req, res) => {
  const { username, role } = req.body;

  const subject = await userSubjectFor(username);
  if (!subject) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  await noteGrantedRole(username, role);
  await withCasbin(() => enforcer.addRoleForUser(subject, platformRoleSubject(role)));
  await addRoleToIndex(role);

  log.audit('admin', `Admin '${req.user.username}' assigned role '${role}' to '${username}'`, {
    actor: req.user.username, target: username, role,
  });
  res.json({ message: `Role '${role}' assigned to '${username}'` });
});

app.delete('/admin/roles', authenticateJWT, requireAdmin, validate({
  body: { username: v.accountName, role: v.roleName },
}), async (req, res) => {
  const { username, role } = req.body;

  const subject = await userSubjectFor(username);
  if (!subject) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const hadRole = await withCasbin(() => enforcer.hasRoleForUser(subject, platformRoleSubject(role)));
  if (!hadRole) {
    return res.status(404).json({ error: `User '${username}' does not have role '${role}'` });
  }

  await withCasbin(() => enforcer.deleteRoleForUser(subject, platformRoleSubject(role)));

  // The Redis 'role' field is a single flat value, and it is what the admin
  // gate reads on every request; keep it in sync with whatever role (if any)
  // remains. 'admin' wins while the account still holds it. Otherwise every
  // account also carries the baseline 'user' role from signup, so prefer a
  // more specific remaining role over that baseline when one exists.
  const remainingRoles = await rolesHeldBy(username);
  const specificRole = remainingRoles.includes('admin') ? 'admin' : remainingRoles.find((r) => r !== 'user');
  await setUserRole(username, specificRole || remainingRoles[0] || 'user');
  // The account is now less than it was when its tokens were issued.
  await bumpTokenVersion(username);

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
      users: await usernamesHolding(platformRoleSubject(role)),
    })),
  );

  res.json({ count: roles.length, roles });
});

app.post('/admin/roles/define', authenticateJWT, requireAdmin, validate({
  body: { role: v.roleName },
}), async (req, res) => {
  const { role } = req.body;

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
  const policies = await presentPolicies(rules);
  // The version of the policy this instance is enforcing. Every instance
  // reports the same number once it has seen the same changes.
  res.json({ count: policies.length, version: policyStore.loadedVersion, policies });
});

const policyRuleBody = { subject: v.policySubject, resource: v.resourcePath, action: v.action };

app.post('/admin/policies', authenticateJWT, requireAdmin, validate({
  // `condition` makes the rule apply only while it holds (abac.js).
  body: { ...policyRuleBody, condition: v.optional(v.condition) },
}), async (req, res) => {
  const { subject, resource, action, condition = null } = req.body;

  const resolved = await resolvePolicySubject(subject);
  if (resolved.error) return res.status(resolved.status).json({ error: resolved.error });

  const added = await addPolicyRow(resolved.subject, resource, action, condition);
  // An existing rule keeps the condition it has (or its lack of one); saying
  // "added" would leave the caller believing theirs is now in force.
  if (!added && (condition || policyStore.conditionFor([resolved.subject, resource, action]))) {
    return res.status(409).json({
      error: 'That policy already exists with a different condition — remove it first, then add it with the new one',
    });
  }
  log.audit('admin', `Admin '${req.user.username}' added policy`, {
    actor: req.user.username, subject, resource, action,
  });
  res.json({ message: `Policy added: ${subject} can ${action} on ${resource}` });
});

app.delete('/admin/policies', authenticateJWT, requireAdmin, validate({ body: policyRuleBody }), async (req, res) => {
  const { subject, resource, action } = req.body;

  const resolved = await resolvePolicySubject(subject);
  if (resolved.error) return res.status(resolved.status).json({ error: resolved.error });

  const removed = await withCasbin(() => enforcer.removePolicy(resolved.subject, resource, action));
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
  const policies = await presentPolicies(rules);

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

app.get('/admin/requests', authenticateJWT, requireAdmin, validate({
  query: { status: v.optional(v.requestStatus) },
}), async (req, res) => {
  const { status } = req.query;
  const requests = await listAccessRequests({ status });
  res.json({ count: requests.length, requests });
});

app.post('/admin/requests/:id/approve', authenticateJWT, requireAdmin, validate({
  params: requestIdParam,
  body: { role: v.optional(v.roleName) },
}), async (req, res) => {
  const { id } = req.params;
  const request = await getAccessRequest(id);
  if (!request) return res.status(404).json({ error: 'Request not found' });
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request already ${request.status}` });
  }

  // A pure service request may not carry a role (the service had no
  // rolesWithAccess yet when the user submitted it) — the admin picks one.
  const role = req.body.role || request.role;
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

  const requesterSubject = await userSubjectFor(request.username);
  await noteGrantedRole(request.username, role);
  await withCasbin(() => enforcer.addRoleForUser(requesterSubject, platformRoleSubject(role)));
  await addRoleToIndex(role);
  const resolved = await resolveAccessRequest(id, 'approved', req.user.username, role);

  log.audit('admin', `Admin '${req.user.username}' approved request ${id} — granted '${role}' to '${request.username}'`, {
    actor: req.user.username, target: request.username, role, requestId: id,
  });
  res.json({ message: `Request approved — '${role}' granted to '${request.username}'`, request: resolved });
});

app.post('/admin/requests/:id/reject', authenticateJWT, requireAdmin, validate({ params: requestIdParam }), async (req, res) => {
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

// -- Access tests --
//
// "Assign a role, then hit Test." Two different questions hide behind that
// button, and they are answered in two different ways:
//
//   What can SOMEONE ELSE reach?  (platform admin, tenant admin)
//     Answered in-process by decideGatewayAccess() — the same function the
//     proxy route calls before forwarding a real request. No token is minted
//     and nothing is sent anywhere. An earlier version signed a short-lived
//     token for the target user and replayed it through the proxy; that
//     handed the user's credential to every upstream service on the way,
//     including one the tester themselves operates, and it was good for every
//     tenant the user belonged to. An admin has no business holding another
//     account's token, however briefly, so there is no longer any code that
//     can produce one.
//
//   What do I reach?  (the account itself)
//     Still a real call, with the caller's own token over loopback, because
//     here there is no one to impersonate: it is the request they would send
//     anyway, and seeing the service's actual reply is the point.
const TEST_ACCESS_TIMEOUT_MS = 4000;
// Enough to read a real response, small enough that a streaming or binary
// endpoint cannot turn a test into a memory problem.
const TEST_BODY_LIMIT = 8192;

/** Header + claims of the caller's own token, so they can see what the gateway reads. */
function describeOwnToken(token) {
  const decoded = jwt.decode(token, { complete: true }) || {};
  const claims = decoded.payload || {};
  return {
    value: token,
    masked: false,
    header: decoded.header || null,
    claims,
    expiresInSeconds: claims.exp ? Math.max(0, claims.exp - Math.floor(Date.now() / 1000)) : null,
    note: 'This is your own session token — the same one your browser is already using.',
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
  'destination-not-allowed':
    'Authorization passed, but the service is registered at an address outside the networks this '
    + 'gateway is permitted to connect to, so the request was not sent.',
  'rate-limited':
    'The gateway refused it because this account is over its request budget for the moment. It says '
    + 'nothing about access: wait for the window to reset and test again.',
  'account-suspended':
    'The account is suspended. It cannot sign in, so it cannot reach anything, whatever its roles say.',
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
  if (status === 429) return at('error', 'rate-limited');
  if (status === 403 && typeof body?.error === 'string') {
    if (/suspended/i.test(body.error)) return at('denied', 'gateway-tenant-suspended');
    if (/lack clearance/i.test(body.error)) return at('denied', 'gateway-policy');
  }
  if (status === 403) return at('denied', 'upstream');

  // The gateway's own "service not found or inactive" reply carries a hint;
  // a bare 404 came from the service itself.
  if (status === 404 && body?.hint) return at('error', 'service-registry');
  if (status === 404) return at('error', 'upstream-missing-endpoint');

  if (status === 502 && /not permitted to reach/i.test(body?.error || '')) return at('error', 'destination-not-allowed');
  if (status === 502) return at('error', 'upstream-unreachable');
  if (status >= 500) return at('error', 'upstream-error');
  return at('error', 'upstream');
}

/**
 * Calls every endpoint of the given services with the CALLER'S OWN token and
 * records the whole exchange — the request that was sent, and the status,
 * headers and body that came back.
 *
 * It goes over loopback HTTP through the gateway's own /gateway routes, so the
 * result is the real authenticate -> authorize -> proxy path for the session
 * the caller is actually using.
 *
 * @param {string} ownToken the bearer token the caller presented — never one
 *   made for them, and never anyone else's
 * @param {object[]} services
 */
async function probeOwnAccess(ownToken, services) {
  const { default: fetch } = await import('node-fetch');
  const sentHeaders = {
    Authorization: `Bearer ${ownToken}`,
    Accept: 'application/json',
  };

  const serviceResults = await Promise.all(services.map(async (svc) => {
    const endpoints = svc.endpoints || [];

    const endpointResults = await Promise.all(endpoints.map(async (endpoint) => {
      const url = `http://localhost:${GATEWAY_PORT}/gateway${endpoint}`;
      const started = Date.now();
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), TEST_ACCESS_TIMEOUT_MS);

      const request = { method: 'GET', url, headers: sentHeaders };

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

  return { token: describeOwnToken(ownToken), services: serviceResults };
}

/**
 * The gateway's authorization decision for one call, and the only place it is
 * made. The proxy route asks this before forwarding a request; the admin
 * access tests ask the same function about somebody else. Sharing it is what
 * lets a test be trusted without replaying a token: it cannot report anything
 * the live path would not do, because it is the live path's own decision.
 *
 * @param {{ id: string, username: string, attributes: object }} account the caller
 * @param {string} serviceName  first path segment after /gateway
 * @param {string} resource     /{serviceName}/...
 * @param {string} action       lower-cased HTTP method
 * @param {{ ip?: string }} [request] what is known about the request itself
 * @returns {Promise<
 *   { allowed: true, serviceConfig: object, matchedPolicy: string[] } |
 *   { allowed: false, status: number, stoppedBy: string, body: object }>}
 */
async function decideGatewayAccess(account, serviceName, resource, action, request = {}) {
  // Loaded first: its attributes are what conditions see as resource.*.
  const tenant = await tenancy.getTenant(serviceName);
  const context = buildAccessContext(account, serviceName, resource, tenant, { method: action, ip: request.ip });

  const [permitted, matchedPolicy] = await withCasbin(
    () => enforcer.enforceEx(userSubject(account.id), resource, action, context),
  );
  if (!permitted) {
    return {
      allowed: false, status: 403, stoppedBy: 'gateway-policy',
      body: { error: `Forbidden: You lack clearance for ${resource}` },
    };
  }

  // A suspended tenant is a kill switch: traffic stops immediately, without
  // anyone having to unpick the policies that reference it first.
  if (tenant && tenant.status !== 'active') {
    return {
      allowed: false, status: 403, stoppedBy: 'gateway-tenant-suspended',
      body: { error: `Service '${serviceName}' is suspended by its owner` },
    };
  }

  const serviceConfig = await getServiceConfig(serviceName);
  if (!serviceConfig || serviceConfig.status !== 'active') {
    return {
      allowed: false, status: 404, stoppedBy: 'service-registry',
      body: {
        error: `Service '${serviceName}' not found or inactive`,
        hint: `Check registry at ${REGISTRY_URL}/services`,
      },
    };
  }

  // The registry record says where the service lives; that does not make it
  // somewhere this gateway should connect to. (A hostname passing here is
  // checked again, by address, when the connection is made.)
  if (destinations.check(serviceConfig.baseUrl)) {
    return {
      allowed: false, status: 502, stoppedBy: 'destination-not-allowed',
      body: { error: `Service '${serviceName}' is registered at a destination this gateway is not permitted to reach` },
    };
  }

  return { allowed: true, serviceConfig, matchedPolicy };
}

const ACCESS_EVALUATION_NOTE =
  'Evaluated by the gateway against its live policy. No token was issued for this account and '
  + 'no request was sent to any service, so this shows whether the gateway would let each call '
  + 'through — not what the service would then answer.';

/**
 * What can `username` reach? Asks decideGatewayAccess() about every endpoint
 * of the given services, in-process.
 *
 * @param {string} username  an existing account
 * @param {object[]} services
 */
async function evaluateAccessFor(username, services) {
  const subject = await userSubjectFor(username);

  // Policy is only half of "can they reach it": a suspended account is turned
  // away before any policy is consulted, and a report that said "allowed"
  // would be describing roles, not access.
  if ((await redis.hget(`user:${username}`, 'status')) === ACCOUNT_STATUS.suspended) {
    return services.map((svc) => ({
      service: svc.name,
      baseUrl: svc.baseUrl,
      allowedCount: 0,
      totalCount: (svc.endpoints || []).length,
      endpoints: (svc.endpoints || []).map((endpoint) => ({
        endpoint, action: 'get', allowed: false, decision: 'denied', status: 403,
        stoppedBy: 'account-suspended', deniedBy: 'account-suspended',
        explanation: OUTCOME_EXPLANATIONS['account-suspended'],
        error: 'This account is suspended', grantedBy: null,
      })),
    }));
  }
  // With the platform bypass every policy row "matches", so the row Casbin
  // reports would be an arbitrary one. Name the real reason instead.
  const bypass = await withCasbin(() => enforcer.hasRoleForUser(subject, PLATFORM_ADMIN_SUBJECT));

  // Conditions are evaluated with the account's own attributes and the
  // current time. Where the request would come from is not known here, so a
  // condition on request.ip does not hold in this report.
  const stored = await getUser(username);
  const account = { id: stored.id, username, attributes: parseAccountAttributes(stored.attributes) };

  return Promise.all(services.map(async (svc) => {
    const endpoints = await Promise.all((svc.endpoints || []).map(async (endpoint) => {
      // The proxy route reads /gateway{endpoint} the same way: the first path
      // segment names the service, and the whole path is the resource.
      const serviceName = endpoint.split('/')[1] || svc.name;
      const outcome = await decideGatewayAccess(account, serviceName, endpoint, 'get');

      if (outcome.allowed) {
        const [grantedBy] = bypass || !outcome.matchedPolicy?.length
          ? [{ bypass: PLATFORM_ADMIN_ROLE }]
          : await presentPolicies([outcome.matchedPolicy]);
        return {
          endpoint, action: 'get', allowed: true, decision: 'allowed',
          // The gateway would forward this call; what the service then
          // answers is not something an evaluation can know.
          status: null, stoppedBy: null, deniedBy: null, explanation: null, grantedBy,
        };
      }

      return {
        endpoint,
        action: 'get',
        allowed: false,
        // Having nowhere it may be sent is a routing fault, not a refusal —
        // the same three-way split classifyOutcome() makes for a live call.
        decision: ['service-registry', 'destination-not-allowed'].includes(outcome.stoppedBy) ? 'error' : 'denied',
        status: outcome.status,
        stoppedBy: outcome.stoppedBy,
        // Kept for clients written against the first version of this shape.
        deniedBy: outcome.stoppedBy,
        explanation: OUTCOME_EXPLANATIONS[outcome.stoppedBy],
        error: outcome.body.error,
        grantedBy: null,
      };
    }));

    return {
      service: svc.name,
      baseUrl: svc.baseUrl,
      allowedCount: endpoints.filter((e) => e.allowed).length,
      totalCount: endpoints.length,
      endpoints,
    };
  }));
}

app.post('/admin/users/:username/test-access', authenticateJWT, requireAdmin, validate({ params: usernameParam }), async (req, res) => {
  const { username } = req.params;

  if (!(await userExists(username))) {
    return res.status(404).json({ error: `User '${username}' not found` });
  }

  const userData = await getUser(username);
  const roles = await rolesHeldBy(username);

  await syncServicesFromRegistry();
  const services = Array.from(serviceCache.entries()).map(([name, cfg]) => ({ name, ...cfg }));
  const evaluated = await evaluateAccessFor(username, services);

  log.audit('admin', `Admin '${req.user.username}' ran an access test for '${username}'`, {
    actor: req.user.username, target: username, roles,
  });

  res.json({
    username,
    role: userData.role,
    roles,
    testedAt: new Date().toISOString(),
    mode: 'policy-evaluation',
    note: ACCESS_EVALUATION_NOTE,
    services: evaluated,
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
 * What the caller may do in :tenantId, resolved from Redis on every call
 * rather than from a token claim: someone whose permission is taken away
 * should lose it immediately, not whenever their token happens to expire.
 * The platform admin holds everything in every tenant.
 */
async function loadTenantStanding(req) {
  if (req.tenantStanding) return req.tenantStanding;
  const isAdmin = isPlatformAdmin(req) || (await tenancy.isTenantAdmin(req.params.tenantId, req.user.username));
  req.tenantStanding = {
    isAdmin,
    permissions: isAdmin
      ? [...TENANT_PERMISSIONS]
      : await tenancy.getDelegatedPermissions(req.params.tenantId, req.user.username),
  };
  return req.tenantStanding;
}

/**
 * FULL tenant administration: changing the tenant itself, and deciding who
 * else may administer it. Everything narrower goes through
 * requireTenantPermission below.
 */
const requireTenantAdmin = async (req, res, next) => {
  if ((await loadTenantStanding(req)).isAdmin) return next();
  return res.status(403).json({
    error: `You are not an administrator of tenant '${req.params.tenantId}'`,
  });
};

/**
 * One part of administering a tenant. "Tenant admin" used to be a single
 * switch — whoever could add a colleague could also rewrite policies and
 * repoint the service at another host. The four jobs are separate grants now
 * (see TENANT_PERMISSIONS in tenancy.js), and each route asks for the one it
 * actually performs.
 *
 * @param {...string} permissions any ONE of which is enough
 */
const requireTenantPermission = (...permissions) => async (req, res, next) => {
  const standing = await loadTenantStanding(req);
  if (permissions.some((permission) => standing.permissions.includes(permission))) return next();
  return res.status(403).json({
    error: `This needs the '${permissions.join("' or '")}' permission in tenant '${req.params.tenantId}'`,
    required: permissions,
  });
};

/**
 * For the routes that do two jobs at once (adding a member WITH a role, say):
 * answers 403 and returns false unless the caller also holds `permission`.
 */
function alsoRequires(req, res, permission, why) {
  if (req.tenantStanding.permissions.includes(permission)) return true;
  res.status(403).json({
    error: `${why} also needs the '${permission}' permission in tenant '${req.params.tenantId}'`,
    required: [permission],
  });
  return false;
}

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
    // What they have been given individually; a full admin needs none.
    permissions: await tenancy.getDelegatedPermissions(tenantId, username),
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
// What a service's configuration may contain, wherever it is being set.
const serviceConfigBody = {
  catalogUrl: v.optional(v.httpUrl({ allowEmpty: true })),
  endpoints: v.optional(v.endpoints),
  version: v.optional(v.shortText),
  displayName: v.optional(v.shortText),
  description: v.optional(v.text(500)),
};

app.post('/tenants/register', authenticateJWT, validate({
  body: { name: v.newTenantId, baseUrl: v.httpUrl(), ...serviceConfigBody },
}), async (req, res) => {
  const { name, baseUrl, catalogUrl, endpoints, version, displayName, description } = req.body;

  // A tenant that already exists belongs to someone; registering over it is how
  // one tenant would take another's traffic.
  const existing = await tenancy.getTenant(name);
  if (existing && existing.owner && existing.owner !== req.user.username && !isPlatformAdmin(req)) {
    return res.status(409).json({ error: `Tenant '${name}' already exists and is owned by someone else` });
  }

  // The registry creates a record only for a caller it can authenticate, and
  // this caller is one the gateway has: it vouches for them (asPlatform).
  //
  // What it vouches for differs, though. Anyone signed in may CREATE a service.
  // Replacing an existing one is for whoever owns it — the gateway holds that
  // tenant's token — or a platform admin. For everyone else the request is
  // marked createOnly, and the registry refuses it if the name is taken. That
  // is decided there, in the same step as the write, so there is no moment
  // between "it didn't exist" and "create it" for a record to appear in; and
  // it is what stops a signed-in user claiming an unowned, self-registered
  // service by re-registering its (public) name and baseUrl.
  const storedToken = await readServiceToken(name);
  const mayReplace = Boolean(storedToken) || isPlatformAdmin(req);
  const registration = await registryFetch('/register', {
    method: 'POST',
    asPlatform: true,
    headers: storedToken ? { 'X-Service-Token': storedToken } : {},
    body: JSON.stringify({
      name, baseUrl, catalogUrl, endpoints, version, displayName, description,
      owner: req.user.username,
      createOnly: !mayReplace,
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

app.get('/tenants/:tenantId', authenticateJWT, validate({ params: tenantParam }), loadTenant, requireTenantMember, async (req, res) => {
  const { tenantId } = req.params;
  const service = serviceCache.get(tenantId) || null;

  res.json({
    ...req.tenant,
    isAdmin: (await loadTenantStanding(req)).isAdmin,
    // The parts of administering this tenant the caller may perform — what
    // the console uses to decide which sections to offer.
    permissions: (await loadTenantStanding(req)).permissions,
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

app.patch('/tenants/:tenantId', authenticateJWT, validate({
  params: tenantParam,
  body: {
    displayName: v.optional(v.shortText),
    description: v.optional(v.text(500)),
    // Suspending a tenant is a kill switch: the gateway stops routing to it
    // immediately, without anyone having to unpick its policies.
    status: v.optional(v.oneOf(['active', 'suspended'])),
    // What attribute conditions see as resource.* for this tenant's service.
    attributes: v.optional(v.attributes),
  },
}), loadTenant, requireTenantAdmin, async (req, res) => {
  const patch = req.body;
  if (Object.keys(patch).length === 0) {
    return res.status(400).json({ error: 'Nothing to update — send displayName, description, status or attributes' });
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
app.patch('/tenants/:tenantId/service', authenticateJWT, validate({
  params: tenantParam,
  body: {
    baseUrl: v.optional(v.httpUrl()),
    ...serviceConfigBody,
    status: v.optional(v.oneOf(['active', 'inactive'])),
    // Re-read endpoints, version and owner from the service's own catalog.
    // The registry no longer does this by itself on a timer.
    syncFromCatalog: v.optional(v.boolean()),
  },
}), loadTenant, requireTenantPermission('destinations'), async (req, res) => {
  const { tenantId } = req.params;
  // Prefer the tenant's own service token; fall back to vouching for the
  // caller, whom the 'destinations' gate has already established may change
  // where this tenant's service lives. A service that self-registered never handed its token to
  // the gateway, and refusing to edit it for that reason would mean the
  // admin panel can display a service it can never change.
  const token = await readServiceToken(tenantId);

  const allowed = req.body;
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
    const { syncFromCatalog: _sync, status: _status, ...config } = allowed;
    const created = await registryFetch('/register', {
      method: 'POST',
      asPlatform: true,
      body: JSON.stringify({
        ...config, name: tenantId, owner: req.tenant.owner || req.user.username, allowAlias: true,
      }),
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
  res.json({ message: 'Service updated', service: result.body.service, warnings: result.body.warnings || [] });
});

// --- TENANT USERS -----------------------------------------------------------

app.get('/tenants/:tenantId/users', authenticateJWT, validate({ params: tenantParam }), loadTenant, requireTenantPermission('members', 'roles'), async (req, res) => {
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
app.post('/tenants/:tenantId/users', authenticateJWT, validate({
  params: tenantParam,
  body: { username: v.accountName, role: v.optional(v.roleName) },
}), loadTenant, requireTenantPermission('members'), async (req, res) => {
  const { tenantId } = req.params;
  const { username, role = null } = req.body;

  if (role && !alsoRequires(req, res, 'roles', 'Adding a member with a role')) return;

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

app.delete('/tenants/:tenantId/users/:username', authenticateJWT, validate({ params: tenantUserParams }), loadTenant, requireTenantPermission('members'), async (req, res) => {
  const { tenantId, username } = req.params;

  if (!(await tenancy.isTenantMember(tenantId, username))) {
    return res.status(404).json({ error: `'${username}' is not a member of tenant '${tenantId}'` });
  }
  if (req.tenant.owner === username) {
    return res.status(409).json({ error: `'${username}' owns this tenant — transfer ownership before removing them` });
  }
  // Removing someone takes away whatever they administer here as well, so a
  // person who only manages the member list cannot use it to unseat an
  // administrator or another delegate.
  const targetAdministers = (await tenancy.isTenantAdmin(tenantId, username))
    || (await tenancy.getDelegatedPermissions(tenantId, username)).length > 0;
  if (targetAdministers && !req.tenantStanding.isAdmin) {
    return res.status(403).json({
      error: `'${username}' holds administrative permissions in tenant '${tenantId}' — only a full administrator can remove them`,
    });
  }

  await tenancy.removeTenantMember(tenantId, username);
  await bumpTokenVersion(username);
  log.audit('tenant', `'${req.user.username}' removed '${username}' from tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });
  res.json({ message: `'${username}' removed from tenant '${tenantId}' (all their roles here were revoked)` });
});

app.post('/tenants/:tenantId/users/:username/roles', authenticateJWT, validate({
  params: tenantUserParams,
  body: { role: v.roleName },
}), loadTenant, requireTenantPermission('roles'), async (req, res) => {
  const { tenantId, username } = req.params;
  const { role } = req.body;

  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });
  // Granting a role to an outsider makes them a member.
  if (!(await tenancy.isTenantMember(tenantId, username))
      && !alsoRequires(req, res, 'members', 'Granting a role to someone who is not yet a member')) return;
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

app.delete('/tenants/:tenantId/users/:username/roles/:role', authenticateJWT, validate({ params: { ...tenantUserParams, role: v.roleName } }), loadTenant, requireTenantPermission('roles'), async (req, res) => {
  const { tenantId, username, role } = req.params;

  if (!(await tenancy.hasTenantRole(tenantId, username, role))) {
    return res.status(404).json({ error: `'${username}' does not have role '${role}' in tenant '${tenantId}'` });
  }

  await tenancy.revokeTenantRole(tenantId, username, role);
  await bumpTokenVersion(username);
  log.audit('tenant', `'${req.user.username}' revoked '${role}' from '${username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username, role,
  });
  res.json({ message: `Role '${role}' revoked from '${username}' in tenant '${tenantId}'`, user: await describeMember(tenantId, username) });
});

app.post('/tenants/:tenantId/users/:username/admin', authenticateJWT, validate({ params: tenantUserParams }), loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username } = req.params;
  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });

  await tenancy.addTenantAdmin(tenantId, username);
  log.audit('tenant', `'${req.user.username}' made '${username}' an admin of tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });
  res.json({ message: `'${username}' is now an administrator of tenant '${tenantId}'` });
});

app.delete('/tenants/:tenantId/users/:username/admin', authenticateJWT, validate({ params: tenantUserParams }), loadTenant, requireTenantAdmin, async (req, res) => {
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
  await bumpTokenVersion(username);
  log.audit('tenant', `'${req.user.username}' removed admin rights from '${username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });
  res.json({ message: `'${username}' is no longer an administrator of tenant '${tenantId}'` });
});

/**
 * PUT /tenants/:tenantId/users/:username/permissions — { permissions: [...] }
 *
 * Sets exactly which parts of administering this tenant the user may perform:
 * any of 'members', 'roles', 'policies', 'destinations', or none. Only a full
 * administrator may decide that — a delegate cannot widen their own grant or
 * pass it on.
 */
app.put('/tenants/:tenantId/users/:username/permissions', authenticateJWT, validate({
  params: tenantUserParams,
  body: { permissions: v.arrayOf(v.oneOf(TENANT_PERMISSIONS), { max: TENANT_PERMISSIONS.length }) },
}), loadTenant, requireTenantAdmin, async (req, res) => {
  const { tenantId, username } = req.params;
  const permissions = [...new Set(req.body.permissions)];

  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });

  const { granted, revoked } = await tenancy.setDelegatedPermissions(tenantId, username, permissions);
  // Losing a permission is losing access: end the sessions that had it.
  if (revoked.length > 0) await bumpTokenVersion(username);

  log.audit('tenant', `'${req.user.username}' set permissions of '${username}' in tenant '${tenantId}' to [${permissions.join(', ') || 'none'}]`, {
    actor: req.user.username, tenant: tenantId, target: username, permissions, granted, revoked,
  });
  res.json({
    message: `'${username}' may now manage: ${permissions.join(', ') || 'nothing'} in tenant '${tenantId}'`,
    user: await describeMember(tenantId, username),
  });
});

/**
 * The same in-process evaluation the platform admin gets, scoped to this
 * tenant's own service. A tenant admin learns whether a member can reach the
 * tenant's endpoints and nothing else: no token for that member exists at any
 * point, so there is nothing here that reaches into the member's other tenants.
 */
app.post('/tenants/:tenantId/users/:username/test-access', authenticateJWT, validate({ params: tenantUserParams }), loadTenant, requireTenantPermission('members', 'roles', 'policies'), async (req, res) => {
  const { tenantId, username } = req.params;
  if (!(await userExists(username))) return res.status(404).json({ error: `User '${username}' not found` });

  await syncServicesFromRegistry();
  const cfg = serviceCache.get(tenantId);
  // Only this tenant's own paths, whatever its registration advertises — a
  // tenant admin is not entitled to an answer about anyone else's.
  const services = cfg
    ? [{ name: tenantId, ...cfg, endpoints: (cfg.endpoints || []).filter((e) => ownsResource(tenantId, e)) }]
    : [];
  const evaluated = await evaluateAccessFor(username, services);

  log.audit('tenant', `'${req.user.username}' ran an access test for '${username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: username,
  });

  res.json({
    tenant: tenantId,
    username,
    roles: await tenancy.getUserTenantRoles(tenantId, username),
    testedAt: new Date().toISOString(),
    mode: 'policy-evaluation',
    note: ACCESS_EVALUATION_NOTE,
    services: evaluated,
  });
});

// --- TENANT ROLES -----------------------------------------------------------

app.get('/tenants/:tenantId/roles', authenticateJWT, validate({ params: tenantParam }), loadTenant, requireTenantMember, async (req, res) => {
  const { tenantId } = req.params;
  const names = await tenancy.listTenantRoles(tenantId);
  const policies = await tenancy.listTenantPolicies(tenantId);

  const roles = await Promise.all(names.map(async (role) => ({
    role,
    members: await usernamesHolding(tenancy.qualifyRole(tenantId, role)),
    policies: policies.filter((p) => p.role === role).map(({ resource, action }) => ({ resource, action })),
  })));

  res.json({ tenant: tenantId, count: roles.length, roles });
});

app.post('/tenants/:tenantId/roles', authenticateJWT, validate({
  params: tenantParam,
  body: { role: v.roleName },
}), loadTenant, requireTenantPermission('roles'), async (req, res) => {
  const { tenantId } = req.params;
  const { role } = req.body;

  if (await tenancy.tenantRoleExists(tenantId, role)) {
    return res.status(409).json({ error: `Role '${role}' already exists in tenant '${tenantId}'` });
  }

  await tenancy.defineTenantRole(tenantId, role);
  log.audit('tenant', `'${req.user.username}' defined role '${role}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, role,
  });
  res.status(201).json({ message: `Role '${role}' defined in tenant '${tenantId}'` });
});

app.delete('/tenants/:tenantId/roles/:role', authenticateJWT, validate({ params: { ...tenantParam, role: v.roleName } }), loadTenant, requireTenantPermission('roles'), async (req, res) => {
  const { tenantId, role } = req.params;

  if (!(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }

  // Deleting a role deletes the policies written for it.
  const hasPolicies = (await tenancy.listTenantPolicies(tenantId)).some((policy) => policy.role === role);
  if (hasPolicies && !alsoRequires(req, res, 'policies', 'Deleting a role that has policies')) return;

  // Everyone holding the role loses it with this call.
  const holders = await usernamesHolding(tenancy.qualifyRole(tenantId, role));
  await tenancy.deleteTenantRole(tenantId, role);
  await endSessions(holders);
  log.audit('tenant', `'${req.user.username}' deleted role '${role}' from tenant '${tenantId}' (policies and grants removed)`, {
    actor: req.user.username, tenant: tenantId, role,
  });
  res.json({ message: `Role '${role}' deleted from tenant '${tenantId}', along with its policies and grants` });
});

// --- TENANT POLICIES --------------------------------------------------------

app.get('/tenants/:tenantId/policies', authenticateJWT, validate({ params: tenantParam }), loadTenant, requireTenantMember, async (req, res) => {
  const policies = (await tenancy.listTenantPolicies(req.params.tenantId)).map((policy) => {
    const condition = policyStore.conditionFor([policy.subject, policy.resource, policy.action]);
    return condition ? { ...policy, condition } : policy;
  });
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
const tenantPolicyBody = { role: v.roleName, resource: v.resourcePath, action: v.action };

app.post('/tenants/:tenantId/policies', authenticateJWT, validate({
  params: tenantParam,
  body: { ...tenantPolicyBody, condition: v.optional(v.condition) },
}), loadTenant, requireTenantPermission('policies'), async (req, res) => {
  const { tenantId } = req.params;
  const { role, resource, action, condition = null } = req.body;

  if (!(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }
  if (!ownsResource(tenantId, resource)) {
    return res.status(403).json({
      error: `Tenant '${tenantId}' can only write policies for its own paths — '${resource}' must start with '/${tenantId}/'`,
    });
  }

  const added = await tenancy.addTenantPolicy(tenantId, role, resource, action, condition);
  if (!added) {
    return res.status(409).json({ error: 'That policy already exists' });
  }

  log.audit('tenant', `'${req.user.username}' added policy in tenant '${tenantId}': ${role} can ${action} ${resource}`, {
    actor: req.user.username, tenant: tenantId, role, resource, action,
  });
  res.status(201).json({ message: `Policy added: '${role}' can ${action} ${resource}` });
});

app.delete('/tenants/:tenantId/policies', authenticateJWT, validate({
  params: tenantParam,
  body: tenantPolicyBody,
}), loadTenant, requireTenantPermission('policies'), async (req, res) => {
  const { tenantId } = req.params;
  const { role, resource, action } = req.body;

  const removed = await tenancy.removeTenantPolicy(tenantId, role, resource, action);
  if (!removed) return res.status(404).json({ error: 'Policy rule not found in this tenant' });

  log.audit('tenant', `'${req.user.username}' removed policy in tenant '${tenantId}': ${role} can ${action} ${resource}`, {
    actor: req.user.username, tenant: tenantId, role, resource, action,
  });
  res.json({ message: `Policy removed: '${role}' can ${action} ${resource}` });
});

// --- TENANT ACCESS REQUESTS -------------------------------------------------

app.get('/tenants/:tenantId/requests', authenticateJWT, validate({
  params: tenantParam,
  query: { status: v.optional(v.requestStatus) },
}), loadTenant, requireTenantPermission('roles', 'members'), async (req, res) => {
  const { status } = req.query;
  const requests = await listAccessRequests({ tenant: req.params.tenantId, status });
  res.json({ tenant: req.params.tenantId, count: requests.length, requests });
});

app.post('/tenants/:tenantId/requests/:id/approve', authenticateJWT, validate({
  params: { ...tenantParam, ...requestIdParam },
  body: { role: v.optional(v.roleName) },
}), loadTenant, requireTenantPermission('roles'), async (req, res) => {
  const { tenantId, id } = req.params;
  const request = await getAccessRequest(id);

  if (!request || request.tenant !== tenantId) {
    return res.status(404).json({ error: 'Request not found in this tenant' });
  }
  if (request.status !== 'pending') {
    return res.status(409).json({ error: `Request already ${request.status}` });
  }

  const role = req.body.role || request.role;
  if (!isNonEmptyString(role)) {
    return res.status(400).json({ error: 'This request has no role attached — specify one in the body to approve with' });
  }
  if (!(await userExists(request.username))) {
    return res.status(404).json({ error: `User '${request.username}' no longer exists` });
  }
  if (!(await tenancy.tenantRoleExists(tenantId, role))) {
    return res.status(404).json({ error: `Role '${role}' does not exist in tenant '${tenantId}'` });
  }
  // Approving a request from an outsider makes them a member.
  if (!(await tenancy.isTenantMember(tenantId, request.username))
      && !alsoRequires(req, res, 'members', 'Approving a request from someone who is not yet a member')) return;

  await tenancy.grantTenantRole(tenantId, request.username, role);
  const resolved = await resolveAccessRequest(id, 'approved', req.user.username, role);

  log.audit('tenant', `'${req.user.username}' approved request ${id} — granted '${role}' to '${request.username}' in tenant '${tenantId}'`, {
    actor: req.user.username, tenant: tenantId, target: request.username, role, requestId: id,
  });
  res.json({ message: `Request approved — '${role}' granted to '${request.username}'`, request: resolved });
});

app.post('/tenants/:tenantId/requests/:id/reject', authenticateJWT, validate({ params: { ...tenantParam, ...requestIdParam } }), loadTenant, requireTenantPermission('roles', 'members'), async (req, res) => {
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
app.post('/admin/tenants', authenticateJWT, requireAdmin, validate({
  body: {
    id: v.newTenantId,
    baseUrl: v.optional(v.httpUrl()),
    ...serviceConfigBody,
    owner: v.optional(v.accountName),
  },
}), async (req, res) => {
  const { id, displayName, description, baseUrl, catalogUrl, endpoints, version, owner } = req.body;
  const warnings = [];

  if (await tenancy.tenantExists(id)) {
    return res.status(409).json({ error: `Tenant '${id}' already exists` });
  }
  if (owner && !(await userExists(owner))) {
    return res.status(404).json({ error: `User '${owner}' not found` });
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
        allowAlias: true,
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

app.post('/admin/tenants/:tenantId/owner', authenticateJWT, requireAdmin, validate({
  params: tenantParam,
  body: { username: v.accountName },
}), loadTenant, async (req, res) => {
  const { tenantId } = req.params;
  const { username } = req.body;

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
app.delete('/admin/tenants/:tenantId', authenticateJWT, requireAdmin, validate({
  params: tenantParam,
  query: { deregister: v.optional(v.oneOf(['true', 'false'])) },
}), loadTenant, async (req, res) => {
  const { tenantId } = req.params;
  const deregisterRequested = req.query.deregister === 'true';

  // Every member loses whatever they held here.
  const members = await tenancy.listTenantMembers(tenantId);
  await tenancy.deleteTenant(tenantId);
  await endSessions(members);

  let deregistered = false;
  if (deregisterRequested) {
    // The registry removes a record only for its owner. The gateway is not
    // that, so it vouches for the platform admin making this call.
    const result = await registryFetch(`/services/${encodeURIComponent(tenantId)}`, { method: 'DELETE', asPlatform: true });
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



app.use('/gateway/:serviceName', authenticateProxied, validate({ params: { serviceName: v.tenantId } }), async (req, res, next) => {
  const { serviceName } = req.params;
  const { username } = req.user;

  // Inside this mount req.url is what follows the service name, query string
  // included. It is split once, here, into the path the request is authorised
  // on and the query that is carried along untouched (proxy-request.js).
  const target = rebuildTarget(serviceName, req.url);
  if (target.problem) return res.status(400).json({ error: target.problem });

  const targetResource = target.path;
  const action = req.method.toLowerCase();

  const decision = await decideGatewayAccess(req.user, serviceName, targetResource, action, { ip: req.ip });
  gatewayDecisions.inc({ outcome: decision.allowed ? 'allowed' : decision.stoppedBy });
  if (!decision.allowed) {
    if (decision.stoppedBy === 'gateway-policy') {
      log.audit('gateway', `Denied ${username} -> ${targetResource}`, { username, resource: targetResource, action });
    } else {
      log.warn('gateway', `Blocked ${username} -> ${targetResource}: ${decision.stoppedBy}`, {
        username, serviceName, stoppedBy: decision.stoppedBy,
      });
    }
    return res.status(decision.status).json(decision.body);
  }
  const { serviceConfig } = decision;

  log.audit('gateway', `Granted ${username} -> ${targetResource} -> ${serviceConfig.baseUrl}`, {
    username, resource: targetResource, action, target: serviceConfig.baseUrl,
  });

  // Express strips the "/gateway/:serviceName" mount prefix, so req.url is
  // just "/claude?x=1" here, not "/llm/claude?x=1". Downstream services expose
  // the FULL path, so it is restored before proxying — together with the
  // query string, which setting this to the path alone used to throw away.
  req.url = target.url;

  const proxy = createProxyMiddleware({
    target: serviceConfig.baseUrl,
    changeOrigin: true,
    // The connection is made by the destination guard's agent: the name is
    // resolved once, every address it resolves to is checked against the
    // allowed networks, and the socket is opened to that address. What was
    // checked and what is connected to cannot differ.
    agent: destinations.agentFor(serviceConfig.baseUrl),
    on: {
      proxyReq: (proxyReq, req) => {
        // The caller's bearer token stops here. It is a credential for the
        // whole platform — every tenant the caller belongs to, and the admin
        // API if they are an admin — and a service needs none of that to
        // answer one request. Forwarding it handed each tenant's backend a
        // working token for everyone who called it. A service is told who is
        // calling instead; it receives the token itself only if the platform
        // operator has listed it in FORWARD_AUTHORIZATION_TO.
        // The request-target goes out exactly as it was authorised: http-proxy
        // would otherwise re-parse it and collapse "//" on the way.
        proxyReq.path = upstreamRequestTarget(serviceConfig.baseUrl, target);
        // The body is piped through unread. Unless something upstream of
        // this route has read it anyway — then its original bytes are sent.
        resendConsumedBody(proxyReq, req);

        if (!FORWARD_AUTHORIZATION_TO.has(serviceName)) proxyReq.removeHeader('authorization');
        // Always set, so a caller cannot supply their own. The name is
        // URI-encoded: usernames may contain characters a header cannot.
        proxyReq.setHeader('X-Gateway-User-Id', req.user.id);
        proxyReq.setHeader('X-Gateway-User', encodeURIComponent(req.user.username));

        log.info('proxy', `${req.method} ${serviceConfig.baseUrl}${proxyReq.path}`, {
          method: req.method, target: `${serviceConfig.baseUrl}${proxyReq.path}`,
        });
      },
      error: (err, req, res) => {
        proxyErrors.inc({ reason: err.code === DESTINATION_NOT_ALLOWED ? 'destination-not-allowed' : (err.code || 'error') });
        log.error('proxy', `Proxy error -> ${serviceConfig.baseUrl}: ${err.message}`, {
          target: serviceConfig.baseUrl, error: err.message, code: err.code,
        });
        if (!res.headersSent) {
          res.status(502).json({
            error: 'Bad Gateway — upstream service error',
            // What the name resolved to is not the caller's to learn.
            detail: err.code === DESTINATION_NOT_ALLOWED
              ? 'The service resolves to a destination this gateway is not permitted to reach'
              : err.message,
          });
        }
      },
    },
  });

  return proxy(req, res, next);
});

// --- OPENID CONNECT ---
// Standard sign-in for applications: Authorization Code flow with PKCE. The
// protocol lives in oidc.js; what it needs from the gateway is handed to it
// here, and the routes are spelled out one per line like every other route in
// this file, so the endpoint inventory can see them.

/**
 * Replaces a temporary password as part of signing in.
 * @returns {Promise<string|null>} why it could not be done, or null
 */
async function replaceTemporaryPassword(username, newPassword) {
  const userData = await getUser(username);
  if (userData?.mustChangePassword !== '1') return 'This account no longer has a temporary password — sign in again.';
  if ((await verifyPassword(newPassword, userData.password)).valid) {
    return 'The new password must be different from the temporary one.';
  }

  await redis.multi()
    .hset(`user:${username}`, 'password', await hashPassword(newPassword))
    .hdel(`user:${username}`, 'mustChangePassword')
    .exec();
  await bumpTokenVersion(username);
  if (username === BOOTSTRAP_ADMIN_USERNAME) removeInitialAdminPasswordFile();

  log.audit('auth', `User '${username}' replaced their temporary password while signing in`, { username });
  return null;
}

const oidc = createOidcProvider({
  redis,
  log,
  issuer: PUBLIC_URL,
  secret: JWT_SECRET,
  checkCredentials,
  replaceTemporaryPassword,
  passwordProblem: (password) => v.newPassword(password).error || null,
  // A session token for the account, if it may still have one.
  issueAccessToken: async (userId) => {
    const username = await redis.hget(USER_IDS_KEY, userId);
    const account = username ? await getUser(username) : null;
    if (!account || account.id !== userId
        || account.status === ACCOUNT_STATUS.suspended || account.mustChangePassword === '1') return null;
    const token = signToken({ id: userId, tokenVersion: await getTokenVersion(username) });
    const { jti, exp } = jwt.decode(token);
    return { token, jti, exp, username };
  },
  revokeAccessToken: ({ jti, exp }) => revokeJti(jti, exp - Math.floor(Date.now() / 1000)),
});

// Form posts, for the two OIDC endpoints that take them (the spec's encoding
// for the token endpoint, and what an HTML form sends).
const readForm = express.urlencoded({ extended: false, limit: '16kb' });
const parseForm = (req, res, next) => readForm(req, res, (err) => (err ? bodyParseErrors(err, req, res, next) : next()));

const publicDocument = (req, res, next) => { res.set('Access-Control-Allow-Origin', '*'); next(); };

app.get('/.well-known/openid-configuration', publicDocument, (req, res) => res.json(oidc.discoveryDocument()));
app.get('/oauth/jwks', publicDocument, (req, res) => res.json(oidc.jwks()));
app.get('/oauth/authorize', (req, res) => oidc.authorize(req, res));
app.post('/oauth/authorize', parseForm, (req, res) => oidc.authorizeSubmit(req, res));
app.options('/oauth/token', oidc.cors);
app.post('/oauth/token', oidc.cors, parseForm, (req, res) => oidc.token(req, res));
app.options('/oauth/userinfo', oidc.cors);
app.get('/oauth/userinfo', oidc.cors, authenticateJWT, (req, res) => {
  res.json({ sub: req.user.id, preferred_username: req.user.username });
});

// -- OIDC clients (platform admin) --
// An application has to be registered before anyone can be sent to it: the
// redirect URIs listed here are the only places a sign-in can end up.

const redirectUriRule = (raw) => {
  if (typeof raw !== 'string' || raw.length > 2048) return { error: 'must be a URL of at most 2048 characters' };
  const problem = redirectUriProblem(raw);
  return problem ? { error: problem } : { value: raw };
};

app.get('/admin/oidc/clients', authenticateJWT, requireAdmin, async (req, res) => {
  const clients = await oidc.listClients();
  res.json({ count: clients.length, clients });
});

app.post('/admin/oidc/clients', authenticateJWT, requireAdmin, validate({
  body: { name: v.shortText, redirectUris: v.arrayOf(redirectUriRule, { max: 10 }) },
}), async (req, res) => {
  const { name, redirectUris } = req.body;
  if (redirectUris.length === 0) return res.status(400).json({ error: 'redirectUris must list at least one URI' });

  const client = await oidc.createClient({ name, redirectUris: [...new Set(redirectUris)] });
  log.audit('admin', `Admin '${req.user.username}' registered OIDC client '${name}'`, {
    actor: req.user.username, clientId: client.clientId, redirectUris: client.redirectUris,
  });
  res.status(201).json({ message: `Client '${name}' registered`, client });
});

app.delete('/admin/oidc/clients/:clientId', authenticateJWT, requireAdmin, validate({
  params: { clientId: v.string({ max: 64, pattern: /^[A-Za-z0-9_-]+$/, patternMessage: 'is not a valid client id' }) },
}), async (req, res) => {
  const { clientId } = req.params;
  if (clientId === oidc.CONSOLE_CLIENT_ID) {
    return res.status(409).json({ error: 'The console is a built-in client and cannot be removed' });
  }
  if (!(await oidc.deleteClient(clientId))) return res.status(404).json({ error: `Client '${clientId}' not found` });

  log.audit('admin', `Admin '${req.user.username}' removed OIDC client '${clientId}'`, { actor: req.user.username, clientId });
  res.json({ message: `Client '${clientId}' removed` });
});

// --- METRICS ENDPOINT ---

/** Compares two secrets without the time taken depending on where they differ. */
function sameSecret(presented, expected) {
  const digest = (value) => crypto.createHash('sha256').update(String(value)).digest();
  return crypto.timingSafeEqual(digest(presented), digest(expected));
}

// Redis's own account of itself, read once per scrape. A Redis that does not
// answer within a second is reported as down rather than hanging the scrape.
let redisStatus = { up: 0, info: {} };
async function probeRedis() {
  const started = process.hrtime.bigint();
  try {
    const [raw, lastBackup] = await Promise.race([
      Promise.all([redis.info(), redis.get('iam:backup:last-success')]),
      new Promise((resolve, reject) => { setTimeout(() => reject(new Error('timeout')), 1000).unref(); }),
    ]);
    const info = Object.fromEntries(raw.split('\r\n').filter((line) => line.includes(':')).map((line) => {
      const at = line.indexOf(':');
      return [line.slice(0, at), line.slice(at + 1)];
    }));
    redisStatus = { up: 1, info, lastBackup, seconds: Number(process.hrtime.bigint() - started) / 1e9 };
  } catch {
    redisStatus = { up: 0, info: {} };
  }
}
const redisNumber = (field) => () => (redisStatus.up ? Number(redisStatus.info[field]) : NaN);

metrics.gauge('iam_policy_version', 'Policy version this instance is enforcing', [], () => policyStore.loadedVersion);
metrics.gauge('iam_policy_store_version', 'Policy version in Redis; ahead of iam_policy_version means this instance is behind', [],
  () => (redisStatus.up ? policyStore.currentVersion() : NaN));
metrics.gauge('iam_policy_last_sync_latency_seconds', 'How far behind this instance was the last time it caught up', [],
  () => (lastPolicySyncLatency === null ? NaN : lastPolicySyncLatency));

metrics.gauge('iam_redis_up', '1 if Redis answered this scrape within a second, else 0', [], () => redisStatus.up);
metrics.gauge('iam_redis_response_seconds', 'How long Redis took to answer this scrape', [], () => (redisStatus.up ? redisStatus.seconds : NaN));
metrics.gauge('iam_redis_connected_clients', 'Clients connected to Redis', [], redisNumber('connected_clients'));
metrics.gauge('iam_redis_used_memory_bytes', 'Memory Redis is using', [], redisNumber('used_memory'));
metrics.gauge('iam_redis_ops_per_second', 'Commands Redis is processing per second', [], redisNumber('instantaneous_ops_per_sec'));
metrics.gauge('iam_redis_changes_since_last_save', 'Writes not yet in an RDB snapshot — what a crash right now would lose without AOF', [], redisNumber('rdb_changes_since_last_save'));
metrics.gauge('iam_redis_last_save_timestamp_seconds', 'When Redis last completed an RDB snapshot (Unix time)', [], redisNumber('rdb_last_save_time'));
metrics.gauge('iam_redis_last_save_ok', '1 if the last RDB snapshot succeeded', [],
  () => (redisStatus.up ? Number(redisStatus.info.rdb_last_bgsave_status === 'ok') : NaN));
metrics.gauge('iam_redis_aof_enabled', '1 if append-only persistence is on', [], redisNumber('aof_enabled'));
// Written by src/backup/redis-backup.js once a backup is encrypted, signed and off the host.
metrics.gauge('iam_backup_last_success_timestamp_seconds', 'When the last off-host Redis backup completed (Unix time); absent if there has never been one', [],
  () => (redisStatus.up && redisStatus.lastBackup ? Number(redisStatus.lastBackup) : NaN));

metrics.gauge('iam_log_forward_queue_length', 'Security log entries waiting to be forwarded', [], () => log.forwarderStats()?.queued ?? NaN);
metrics.gauge('iam_log_forward_sent_total', 'Security log entries delivered to the collector', [], () => log.forwarderStats()?.sent ?? NaN);
metrics.gauge('iam_log_forward_failed_batches_total', 'Batches the collector did not accept (they are retried)', [], () => log.forwarderStats()?.failed ?? NaN);
metrics.gauge('iam_log_forward_dropped_total', 'Entries dropped because the queue was full (still in the local files)', [], () => log.forwarderStats()?.dropped ?? NaN);

metrics.gauge('iam_process_uptime_seconds', 'How long this gateway process has been running', [], () => process.uptime());
metrics.gauge('iam_process_resident_memory_bytes', 'Resident memory of this gateway process', [], () => process.memoryUsage().rss);

/**
 * GET /metrics — Prometheus text format, for a scraper presenting
 * `Authorization: Bearer <METRICS_TOKEN>`. Not behind a user login: a scraper
 * is not an account, and what is here is operational, not personal.
 */
app.get('/metrics', async (req, res) => {
  if (!METRICS_TOKEN) {
    return res.status(404).json({ error: 'Metrics are not enabled', hint: 'Start the gateway with METRICS_TOKEN set' });
  }
  const presented = (req.get('Authorization') || '').replace(/^Bearer /, '');
  if (!presented || !sameSecret(presented, METRICS_TOKEN)) {
    return res.status(401).json({ error: 'A valid metrics token is required' });
  }
  await probeRedis();
  res.type(METRICS_CONTENT_TYPE).send(await metrics.render());
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

// --- INITIAL ADMINISTRATOR (one-time) ---
//
// The first platform admin is created exactly once per deployment, with a
// random password that only works long enough to be replaced.
//
// It used to be re-created on every boot whenever `admin` was missing, with a
// password printed in the README, and that account was then re-granted
// platform admin on every boot by name. So deleting it brought it back with
// the published password, and anyone who had registered the name `admin` in
// the meantime was promoted at the next restart. Now the bootstrap leaves a
// marker in Redis and never runs again: after that, platform admins are made
// by other platform admins, like any other grant.
const BOOTSTRAP_ADMIN_USERNAME = 'admin';
const BOOTSTRAP_MARKER_KEY = 'iam:bootstrap:initial-admin';
const BOOTSTRAP_LOCK_KEY = 'iam:bootstrap:initial-admin:lock';
const INITIAL_ADMIN_PASSWORD_FILE = process.env.INITIAL_ADMIN_PASSWORD_FILE
  || path.join(__dirname, '..', '.run', 'initial-admin-password');
// The password older gateways seeded. Never set anywhere any more — it is only
// compared against, so that a deployment still carrying it stops accepting it.
const RETIRED_SEED_PASSWORD = 'adminpass';

/** ~190 bits, in characters that survive a copy-paste. */
function generateInitialPassword() {
  return crypto.randomBytes(24).toString('base64url');
}

/**
 * Hands the temporary password to whoever operates this host, and to nobody
 * else: a file only its owner can read, not the logs (which are shipped,
 * tailed and kept). The file is removed once the password has been changed.
 */
function deliverInitialAdminPassword(password) {
  try {
    fs.mkdirSync(path.dirname(INITIAL_ADMIN_PASSWORD_FILE), { recursive: true });
    fs.writeFileSync(INITIAL_ADMIN_PASSWORD_FILE, `${password}\n`, { mode: 0o600 });
    fs.chmodSync(INITIAL_ADMIN_PASSWORD_FILE, 0o600); // mode above is ignored if the file existed
    console.log(`[IAM] One-time password for '${BOOTSTRAP_ADMIN_USERNAME}' written to ${INITIAL_ADMIN_PASSWORD_FILE}`);
  } catch (err) {
    // Printing it is worse than the file, but an admin account nobody can log
    // in to is worse still — and the password stops working at first login.
    console.error(`[IAM] Could not write ${INITIAL_ADMIN_PASSWORD_FILE}: ${err.message}`);
    console.log(`[IAM] One-time password for '${BOOTSTRAP_ADMIN_USERNAME}': ${password}`);
  }
  console.log('[IAM] It must be changed at first login; nothing else works for that account until it is.');
}

function removeInitialAdminPasswordFile() {
  fs.rm(INITIAL_ADMIN_PASSWORD_FILE, { force: true }, () => {});
}

async function bootstrapInitialAdmin() {
  if (await redis.exists(BOOTSTRAP_MARKER_KEY)) return;
  // Several gateways can boot against one Redis; only one performs the bootstrap.
  if (!(await redis.set(BOOTSTRAP_LOCK_KEY, String(process.pid), 'EX', 60, 'NX'))) return;

  try {
    const existing = await getUser(BOOTSTRAP_ADMIN_USERNAME);
    let outcome;

    if (!existing?.password) {
      const password = generateInitialPassword();
      const id = await createUser(BOOTSTRAP_ADMIN_USERNAME, await hashPassword(password), 'admin', {
        mustChangePassword: '1',
      });
      if (!id) throw new Error(`Cannot bootstrap: 'user:${BOOTSTRAP_ADMIN_USERNAME}' exists in Redis but is not a usable account`);
      await withCasbin(() => enforcer.addRoleForUser(userSubject(id), platformRoleSubject('admin')));
      await withCasbin(() => enforcer.addRoleForUser(userSubject(id), PLATFORM_ADMIN_SUBJECT));
      deliverInitialAdminPassword(password);
      outcome = 'created';
    } else if ((await verifyPassword(RETIRED_SEED_PASSWORD, existing.password)).valid) {
      // An upgraded deployment whose admin still has the password every copy
      // of the old README gives away. Treat it as already disclosed: replace
      // it, end its sessions, and require a fresh one at next login.
      const password = generateInitialPassword();
      await redis.hset(`user:${BOOTSTRAP_ADMIN_USERNAME}`, {
        password: await hashPassword(password), mustChangePassword: '1',
      });
      await bumpTokenVersion(BOOTSTRAP_ADMIN_USERNAME);
      deliverInitialAdminPassword(password);
      outcome = 'rotated-retired-default';
    } else {
      // An admin account with a password of its own choosing: nothing to do.
      outcome = 'kept-existing';
    }

    await redis.set(BOOTSTRAP_MARKER_KEY, JSON.stringify({ outcome, at: new Date().toISOString() }));
    log.audit('iam', `Initial administrator bootstrap completed (${outcome}); it will not run again`, { outcome });
  } finally {
    await redis.del(BOOTSTRAP_LOCK_KEY);
  }
}

// --- BOOT SEQUENCE ---
async function boot() {
  console.log('\n[Gateway] Initializing IAM...');
  await initIAM();

  console.log(`[Gateway] Allowed destinations: ${destinations.describe()}`);
  if (!destinations.configured) {
    log.warn('gateway', 'UPSTREAM_ALLOWED_CIDRS is not set — no service can be reached through this gateway until it is');
  }

  console.log(`[Gateway] Per-account request budgets: API ${API_REQUEST_LIMIT.max}/min, proxied ${GATEWAY_REQUEST_LIMIT.max}/min`);

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

  await bootstrapInitialAdmin();
  await oidc.init();

  // Seed Casbin policies (addPolicy is idempotent — Casbin skips duplicates)
  await withCasbin(() => enforcer.addPolicy(platformRoleSubject('green_role'), '/llm/gemini', 'get'));
  await withCasbin(() => enforcer.addPolicy(platformRoleSubject('blue_role'), '/llm/claude', 'get'));
  await withCasbin(() => enforcer.addPolicy(platformRoleSubject('blue_role'), '/vision/service1', 'get'));
  await withCasbin(() => enforcer.addPolicy(platformRoleSubject('red_role'), '/vision/service3', 'get'));

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
    console.log(`  POST /auth/signup    {"username":"blue_user","password":"<choose one>"}`);
    console.log(`  POST /auth/login     {"username":"blue_user","password":"<the same>"}`);
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
