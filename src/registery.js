/**
 * Service Registry Server - with Redis persistence
 *
 * Redis data structures used:
 *   - Hash  `registry:service:{name}` → all fields for one service
 *   - Set   `registry:services`       → index of all service names
 *
 * Why a Set as an index?
 *   Redis Hashes store one service's fields cleanly, but you can't
 *   "list all hashes matching a pattern" without SCAN (slow, O(N)).
 *   A companion Set gives us O(1) membership checks and O(N members)
 *   full listing — exactly what GET /services needs.
 *
 * Run with: node registry.js
 * Listens on: http://localhost:3001
 * Requires:   Redis running on localhost:7000 (or set REDIS_URL env var)
 */

const crypto = require('crypto');
const express = require('express');
const Redis = require('ioredis');
const swaggerUi = require('swagger-ui-express');
const { spec } = require('./swagger');
const { createLogger } = require('./logger');
const { createDestinationGuardFromEnv } = require('./netguard');
const { v, validate, bodyParseErrors, JSON_BODY_LIMIT } = require('./validation');

const log = createLogger('registry');

// Where a registered service may live. Built first, so a malformed allowlist
// stops the process instead of leaving it running with no rule at all.
const destinations = createDestinationGuardFromEnv();

const app = express();
app.use(express.json({ limit: JSON_BODY_LIMIT }));
app.use(bodyParseErrors);
app.use(log.requestLogger());

// --- CONSTANTS ---
const REGISTRY_PORT = process.env.PORT || 3001;
const HEALTH_CHECK_INTERVAL_MS = 15000;
const HEALTH_CHECK_TIMEOUT_MS = 3000;
// A catalog is a few lines of JSON. Capping what is read stops a destination
// from answering a health check with an endless body.
const CATALOG_MAX_BYTES = 256 * 1024;

// Redis key helpers — centralised so typos don't cause silent bugs
const REDIS_KEYS = {
  // Set containing all registered service names
  serviceIndex: () => 'registry:services',
  // Hash containing all fields for a single service
  service: (name) => `registry:service:${name}`,
};

// --- REDIS CLIENT ---
const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:7000', {
  // Retry with backoff so a brief Redis blip doesn't kill the process
  retryStrategy(times) {
    const maxRetryDelay = 5000; // cap at 5 s
    const delay = Math.min(times * 200, maxRetryDelay);
    console.warn(`[Redis] Connection attempt ${times}, retrying in ${delay}ms`);
    return delay;
  },

  // Surface connection events clearly
  lazyConnect: false,
});

redis.on('connect', () => console.log('[Redis] Connected successfully'));
redis.on('ready', () => console.log('[Redis] Ready to accept commands'));
redis.on('error', (err) => console.error('[Redis] Error:', err.message));
redis.on('close', () => console.warn('[Redis] Connection closed'));
redis.on('reconnecting', () => console.warn('[Redis] Reconnecting...'));

// --- SERVICE TOKENS (name ownership) ---
//
// The first registration of a name mints a token and returns it once. From
// then on that token is the only thing that can change the record: repoint it,
// edit its catalogUrl or endpoints, renew it, or remove it. Whoever holds it
// owns the name; nobody else can touch it (the gateway aside — see below).
//
// An earlier version let a second registration through without the token as
// long as it named the same baseUrl, so that a restarting service needed no
// state. But a service's name and baseUrl are both printed by GET /services,
// so that was no test at all: anyone could re-register `llm` at its own
// address with a catalogUrl of their choosing, and the registry would fetch
// that URL and adopt the endpoints it advertised. A restart is now its own
// operation (POST /services/:name/heartbeat) that renews the record and
// cannot alter it.
//
// Only the SHA-256 of the token is stored: a Redis dump then leaks no usable
// credential.

function mintServiceToken() {
  return crypto.randomBytes(24).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function tokenMatches(token, storedHash) {
  if (!token || !storedHash) return false;
  const provided = Buffer.from(hashToken(token));
  const expected = Buffer.from(storedHash);
  if (provided.length !== expected.length) return false;
  return crypto.timingSafeEqual(provided, expected);
}

function presentedToken(req) {
  return req.get('X-Service-Token') || req.body?.serviceToken || null;
}

// --- PLATFORM OVERRIDE TOKEN (gateway <-> registry) --------------------------
//
// A service token proves "I am the process that owns this name". The gateway
// needs something different: the authority to act on a name on behalf of a
// human it has already authenticated and authorised — a platform admin editing
// any service, or a tenant admin editing their own one that self-registered
// and whose token therefore never passed through the gateway.
//
// The two processes already share exactly one trust boundary: Redis. So the
// shared secret lives there, created once with SETNX by whichever process
// boots first, and is never configured, logged or returned. That keeps the
// registry closed to anonymous callers without adding an env var to forget.
const ADMIN_TOKEN_KEY = 'registry:admin-token';
let registryAdminToken = null;

async function ensureRegistryAdminToken() {
  await redis.set(ADMIN_TOKEN_KEY, crypto.randomBytes(32).toString('hex'), 'NX');
  registryAdminToken = await redis.get(ADMIN_TOKEN_KEY);
  return registryAdminToken;
}

/** Is this the gateway acting for an already-authorised human? */
function isPlatformCall(req) {
  const presented = req.get('X-Registry-Admin-Token');
  if (!presented || !registryAdminToken) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(registryAdminToken);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// --- ENROLLMENT (who may create a record) ------------------------------------
//
// A service token answers "may this caller change THIS record". Nothing
// answered "may this caller create one": POST /register for an unused name
// was open to anyone who could reach the port. Creating a record is not
// harmless — it puts a route on the gateway, provisions a tenant for it, and
// has the registry start probing whatever URL it names — so it now needs a
// caller the registry can authenticate, in one of two ways:
//
//   the gateway      an authenticated user registering through it; it vouches
//                    with the platform override token above.
//   a service        registering itself directly, with the enrollment token
//                    the operator configured (REGISTRY_ENROLLMENT_TOKEN) and
//                    gave to the services meant to do that.
//
// There is no default enrollment token. Unset, self-registration is simply
// off and the gateway is the only way in.
const ENROLLMENT_TOKEN_MIN_LENGTH = 32;

function loadEnrollmentToken() {
  const token = process.env.REGISTRY_ENROLLMENT_TOKEN;
  if (!token) return null;
  if (token.length < ENROLLMENT_TOKEN_MIN_LENGTH) {
    console.error(`[Registry] Refusing to start: REGISTRY_ENROLLMENT_TOKEN is too short (${token.length} chars; need at least ${ENROLLMENT_TOKEN_MIN_LENGTH}).`);
    console.error('[Registry] Generate one with:  openssl rand -hex 32   (or unset it to turn self-registration off)');
    process.exit(1);
  }
  return token;
}

const enrollmentToken = loadEnrollmentToken();

function hasEnrollmentToken(req) {
  const presented = req.get('X-Enrollment-Token');
  if (!presented || !enrollmentToken) return false;
  // Compared as digests so the two buffers are always the same length.
  return crypto.timingSafeEqual(Buffer.from(hashToken(presented)), Buffer.from(hashToken(enrollmentToken)));
}

/** Either proof of name ownership, or the gateway vouching for the caller. */
function mayMutateService(req, tokenHash) {
  return tokenMatches(presentedToken(req), tokenHash) || isPlatformCall(req);
}

// --- REDIS SERIALISATION HELPERS ---

/**
 * Converts a service object into a flat Record<string, string> suitable
 * for Redis HSET. Arrays/objects must be JSON-stringified because Redis
 * Hash values are always strings.
 *
 * @param {object} serviceData
 * @returns {Record<string, string>}
 */
function serialiseService(serviceData) {
  return {
    name: serviceData.name,
    baseUrl: serviceData.baseUrl,
    catalogUrl: serviceData.catalogUrl ?? '',
    version: serviceData.version ?? 'unknown',
    owner: serviceData.owner ?? 'unknown',
    displayName: serviceData.displayName ?? serviceData.name,
    description: serviceData.description ?? '',
    // endpoints is an array → must be stringified
    endpoints: JSON.stringify(serviceData.endpoints ?? []),
    status: serviceData.status,
    // Separate from status on purpose: `status` is "should the gateway route
    // here", `health` is "did the last probe reach it". A manually registered
    // service with no catalogUrl is routable but never probed — collapsing
    // those two into one field is what used to make such a service
    // permanently unroutable.
    health: serviceData.health ?? 'unchecked',
    tokenHash: serviceData.tokenHash ?? '',
    registeredAt: serviceData.registeredAt,
    lastSeen: serviceData.lastSeen,
  };
}

/**
 * Converts the flat string Record stored in Redis back into a proper
 * service object, parsing JSON fields as needed.
 *
 * `tokenHash` is stripped — it is a credential and must never appear in an
 * API response.
 *
 * @param {Record<string, string>} hash - raw result from Redis HGETALL
 * @returns {object}
 */
function deserialiseService(hash) {
  const { tokenHash, ...publicFields } = hash;
  return {
    ...publicFields,
    displayName: hash.displayName || hash.name,
    description: hash.description || '',
    health: hash.health || 'unchecked',
    endpoints: safeParseEndpoints(hash.endpoints),
  };
}

/**
 * Splits a service's advertised endpoints into the ones that belong to it and
 * the ones that do not.
 *
 * A service's endpoints must sit under its OWN `/{name}/` prefix. This was
 * already enforced for endpoints supplied in the registration body, but NOT
 * for endpoints pulled from a remote /catalog — so registering a new name
 * against an existing service's catalog copied that service's endpoints
 * verbatim. The entry then advertised another service's paths, and everything
 * downstream that answers "who can reach this service" by matching endpoints
 * (the gateway's policiesForService, and therefore /admin/services,
 * /catalog/services and the admin access test) reported the *other* service's
 * access under this one's name. Enforcement was never affected — the proxy
 * rewrites the path to /{name}/... and Casbin has no rule for it — but an IAM
 * tool that reports access which does not exist is telling you something
 * false about your own security posture, which is its own kind of failure.
 *
 * @returns {{ kept: string[], dropped: string[] }}
 */
function partitionEndpointsByNamespace(name, endpoints) {
  const kept = [];
  const dropped = [];
  for (const endpoint of endpoints || []) {
    if (typeof endpoint !== 'string') continue;
    if (endpoint === `/${name}` || endpoint.startsWith(`/${name}/`)) kept.push(endpoint);
    else dropped.push(endpoint);
  }
  return { kept, dropped };
}

function safeParseEndpoints(raw) {
  try {
    const parsed = JSON.parse(raw || '[]');
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// --- REGISTRY DATA ACCESS LAYER ---
// All Redis interactions live here so the route handlers stay clean.

/**
 * Persist a service entry to Redis.
 * Uses a pipeline so both writes happen atomically in one round trip.
 *
 * @param {string} name      - service identifier / map key
 * @param {object} serviceData
 */
async function saveService(name, serviceData) {
  const pipeline = redis.pipeline();

  // Store all fields as a Hash
  pipeline.hset(REDIS_KEYS.service(name), serialiseService(serviceData));

  // Add the name to the master index Set
  pipeline.sadd(REDIS_KEYS.serviceIndex(), name);

  await pipeline.exec();
}

/**
 * Retrieve a single service by name, including its token hash.
 * Internal use only — route handlers return getService() instead.
 */
async function getServiceRaw(name) {
  const hash = await redis.hgetall(REDIS_KEYS.service(name));
  if (!hash || Object.keys(hash).length === 0) return null;
  return hash;
}

/**
 * Retrieve a single service by name.
 *
 * @param {string} name
 * @returns {object|null}
 */
async function getService(name) {
  const hash = await getServiceRaw(name);
  if (!hash) return null;
  return deserialiseService(hash);
}

/**
 * Retrieve all registered services.
 * Fetches the name index first, then pipelines individual lookups.
 *
 * @returns {object[]}
 */
async function getAllServices() {
  const names = await redis.smembers(REDIS_KEYS.serviceIndex());
  if (names.length === 0) return [];

  // Pipeline all HGETALL calls to avoid N round trips
  const pipeline = redis.pipeline();
  names.forEach((name) => pipeline.hgetall(REDIS_KEYS.service(name)));
  const results = await pipeline.exec();

  const services = [];

  results.forEach(([err, hash], i) => {
    if (err) {
      console.error('[Redis] Pipeline error fetching service:', err.message);
      return; // skip this entry rather than crashing
    }

    // Guard against a name in the Set with no corresponding Hash
    // (possible if a crash occurred mid-write)
    if (!hash || Object.keys(hash).length === 0) return;

    // The key a service is stored under IS its identity. An entry whose
    // `name` field disagrees with its key is corrupt data from the era when
    // registration let a service's own catalog rename it (see POST /register);
    // report it under its key so two keys can never both claim to be "llm".
    services.push({ ...deserialiseService(hash), name: names[i] });
  });

  services.sort((a, b) => a.name.localeCompare(b.name));
  return services;
}

/**
 * Remove a service from Redis completely.
 * Uses a pipeline to delete both the Hash and the Set membership.
 *
 * @param {string} name
 */
async function deleteService(name) {
  const pipeline = redis.pipeline();
  pipeline.del(REDIS_KEYS.service(name));
  pipeline.srem(REDIS_KEYS.serviceIndex(), name);
  await pipeline.exec();
}

/**
 * Check whether a service name exists in the index Set.
 * Cheaper than HGETALL when you only need existence.
 *
 * @param {string} name
 * @returns {boolean}
 */
async function serviceExists(name) {
  return (await redis.sismember(REDIS_KEYS.serviceIndex(), name)) === 1;
}

/**
 * One-time repair for records written before registration became
 * key-authoritative: entries stored under key X whose `name` field says Y
 * (because the remote catalog was allowed to rename them), plus index members
 * with no hash behind them. Both make a service appear two or three times in
 * GET /services under the same name. Idempotent, so it runs on every boot.
 */
async function repairCorruptEntries() {
  const names = await redis.smembers(REDIS_KEYS.serviceIndex());
  const repaired = [];
  const orphaned = [];

  for (const name of names) {
    const hash = await getServiceRaw(name);
    if (!hash) {
      await redis.srem(REDIS_KEYS.serviceIndex(), name);
      orphaned.push(name);
      continue;
    }
    if (hash.name !== name) {
      await redis.hset(REDIS_KEYS.service(name), 'name', name);
      repaired.push(`${name} (was claiming to be '${hash.name}')`);
    }
  }

  if (repaired.length || orphaned.length) {
    log.warn('registry', 'Repaired corrupt registry entries on boot', { repaired, orphaned });
  }
  return { repaired, orphaned };
}

// --- FETCH HELPER ---

/**
 * Fetches the /catalog endpoint from a registered service to pull its
 * live metadata (endpoints, version, etc.)
 *
 * This is the registry making a request to an address somebody typed in, so
 * it goes through the destination guard twice: the URL is checked before
 * anything is sent, and the connection is made through an agent that will
 * only open a socket to an address inside the allowed networks. Redirects are
 * refused outright — following one would let an allowed host send the
 * registry somewhere that is not.
 *
 * @param {string} catalogUrl
 * @returns {Promise<object>}
 */
async function fetchServiceCatalog(catalogUrl) {
  const refused = destinations.check(catalogUrl);
  if (refused) throw new Error(`catalogUrl ${refused}`);

  const { default: fetch } = await import('node-fetch');

  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    HEALTH_CHECK_TIMEOUT_MS,
  );

  try {
    const response = await fetch(catalogUrl, {
      signal: controller.signal,
      agent: (url) => destinations.agentFor(url),
      redirect: 'error',
      size: CATALOG_MAX_BYTES,
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timeoutId);
  }
}

/**
 * Validates the URLs in a registration or an edit against the destination
 * allowlist. Returns the reason to refuse, or null — and pushes a warning for
 * a name that does not resolve yet, since a service may be registered before
 * it exists (it will be refused at connect time if it resolves badly later).
 */
async function refuseDestinations(urls, warnings) {
  for (const [field, url] of Object.entries(urls)) {
    if (!url) continue;
    const { reason, unresolved } = await destinations.inspect(url);
    if (reason) return `${field} ${reason}`;
    if (unresolved) {
      warnings.push(`${field} host could not be resolved (${unresolved}) — it will only be reachable once it resolves to an address inside the allowed networks`);
    }
  }
  return null;
}

// --- LIFECYCLE (liveness) vs CONFIGURATION ---
//
// A record has two kinds of field, and they change for different reasons:
//
//   configuration   baseUrl, catalogUrl, endpoints, version, owner,
//                   displayName, description, status
//                   — what the service IS and where it lives. Changed only by
//                   someone who proves they own the name.
//
//   lifecycle       health, lastSeen
//                   — whether it is answering right now. Changed by the health
//                   check below and by a service's own heartbeat.
//
// Nothing on the lifecycle side may write a configuration field. The health
// check used to: every probe copied version, owner and endpoints out of
// whatever the catalog URL returned and flipped `status`, so the record was
// rewritten every fifteen seconds by a process that had authenticated nobody
// — undoing an admin's edit, re-enabling a service that had been switched
// off, and racing any PATCH that landed mid-probe. Liveness is now recorded
// by itself, in one atomic write that touches those two fields only.

// Updates health/lastSeen if — and only if — the record still exists, so a
// probe that finishes after a deregistration cannot bring half a record back.
redis.defineCommand('touchServiceLifecycle', {
  numberOfKeys: 1,
  lua: `
    if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
    redis.call('HSET', KEYS[1], 'health', ARGV[1])
    if ARGV[2] ~= '' then redis.call('HSET', KEYS[1], 'lastSeen', ARGV[2]) end
    return 1
  `,
});

/**
 * @param {string} name
 * @param {'ok'|'unreachable'} health
 * @returns {Promise<boolean>} false if there is no such service
 */
async function recordLiveness(name, health) {
  const seenAt = health === 'ok' ? new Date().toISOString() : '';
  return (await redis.touchServiceLifecycle(REDIS_KEYS.service(name), health, seenAt)) === 1;
}

/**
 * Probes every registered service's catalog URL and records whether it
 * answered. That is all it does: what the catalog SAYS is not read here.
 *
 * A service registered without a catalogUrl has nothing to probe and is left
 * as it is (health: 'unchecked').
 */
async function runHealthChecks() {
  const names = await redis.smembers(REDIS_KEYS.serviceIndex());
  if (names.length === 0) return;

  const checks = names.map(async (name) => {
    const serviceData = await getService(name);

    // Guard: entry in Set but no Hash (shouldn't happen, but be safe)
    if (!serviceData) {
      console.warn(`  ⚠️  [${name}] found in index but has no data — skipping`);
      return;
    }

    if (!serviceData.catalogUrl) return; // nothing to probe

    try {
      await fetchServiceCatalog(serviceData.catalogUrl);
      await recordLiveness(name, 'ok');
      log.info('health', `[${name}] healthy at ${serviceData.baseUrl}`, { name });
    } catch (err) {
      await recordLiveness(name, 'unreachable');
      log.warn('health', `[${name}] unreachable: ${err.message}`, { name, error: err.message });
    }
  });

  await Promise.allSettled(checks);
}

// --- REQUEST SHAPES ---

// Accepted wherever a caller may prove ownership in the body rather than the
// X-Service-Token header.
const serviceTokenField = v.optional(v.string({ max: 128 }));

const serviceConfigFields = {
  catalogUrl: v.optional(v.httpUrl({ allowEmpty: true })),
  endpoints: v.optional(v.endpoints),
  version: v.optional(v.shortText),
  owner: v.optional(v.shortText),
  displayName: v.optional(v.shortText),
  description: v.optional(v.text(500)),
};

const serviceNameParam = { name: v.tenantId };

// --- REGISTRY ROUTES ---

/**
 * POST /register
 *
 * Body: {
 *   name:        "payments",                            // required, slug
 *   baseUrl:     "http://localhost:9090",               // required
 *   catalogUrl:  "http://localhost:9090/catalog",       // OPTIONAL
 *   endpoints:   ["/payments/charge"],                  // optional manual decl
 *   version:     "v1",                                  // optional
 *   owner:       "fin_team",                            // optional
 *   displayName: "Payments API",                        // optional
 *   serviceToken: "..."                                 // required if the
 *                                                       // name already exists
 * }
 *
 * For a new name this creates the record and returns its service token, once.
 * Creating needs an authenticated caller: the gateway (acting for a signed-in
 * user), or a service presenting X-Enrollment-Token.
 *
 * For a name that already exists it is a full replacement of that record's
 * configuration, and so needs the token (or X-Service-Token) like any other
 * edit — unless the request says `createOnly`, in which case an existing name
 * is refused whoever is asking. A service that is merely starting up again
 * should not come here at all — see POST /services/:name/heartbeat.
 *
 * catalogUrl is a convenience, not a precondition. Registration used to abort
 * with 502 "Cannot reach catalogUrl" whenever the service wasn't already
 * running and serving /catalog — which meant you could never register anything
 * new, only re-register something already up. Now an unreachable (or absent)
 * catalog registers the service from the metadata in the request body and
 * reports the probe result as a warning. The periodic health check records
 * when the service starts answering; adopting what its catalog says is then
 * an explicit, authenticated step (PATCH with syncFromCatalog).
 */
app.post('/register', validate({
  body: {
    name: v.newTenantId,
    baseUrl: v.httpUrl(),
    ...serviceConfigFields,
    allowAlias: v.optional(v.boolean()),
    createOnly: v.optional(v.boolean()),
    serviceToken: serviceTokenField,
  },
}), async (req, res) => {
  const { name, baseUrl, catalogUrl, owner, version, displayName, description } = req.body;
  const endpoints = req.body.endpoints || [];
  const warnings = [];

  const badEndpoint = endpoints.find((e) => !e.startsWith(`/${name}/`) && e !== `/${name}`);
  if (badEndpoint) {
    return res.status(400).json({
      error: `Endpoint '${badEndpoint}' is outside this service's namespace — every endpoint must start with '/${name}/'`,
    });
  }

  log.audit('registry', `Registration request for service '${name}' at ${baseUrl}`, { name, baseUrl });

  // --- Name ownership check ---
  const existingRaw = await getServiceRaw(name);
  const existing = existingRaw ? deserialiseService(existingRaw) : null;
  let tokenHash = existingRaw?.tokenHash || '';
  let issuedToken = null;

  if (existing) {
    // The caller asked for "create, or nothing". The gateway sends this when
    // it is vouching for a user who may register a new service but has no
    // claim on an existing one — its override would otherwise open any record.
    if (req.body.createOnly) {
      return res.status(409).json({
        error: `Service '${name}' is already registered`,
        hint: 'Pick a different name. An existing service can only be changed by its owner.',
      });
    }
    // Any registration over an existing name rewrites its configuration, so
    // it needs proof of ownership whatever it contains — including when it
    // names the same baseUrl, which anyone can read out of GET /services.
    if (!mayMutateService(req, tokenHash)) {
      log.warn('registry', `Rejected re-registration of '${name}' without its service token`, {
        name, registeredBaseUrl: existing.baseUrl, attemptedBaseUrl: baseUrl,
      });
      return res.status(409).json({
        error: `Service '${name}' is already registered`,
        hint: `Pick a different name, or prove you own this one by passing the serviceToken issued at first registration. A service that is only restarting should call POST /services/${name}/heartbeat instead.`,
      });
    }
  } else {
    if (!isPlatformCall(req) && !hasEnrollmentToken(req)) {
      log.warn('registry', `Rejected unauthenticated registration of new service '${name}'`, { name, baseUrl });
      return res.status(401).json({
        error: 'Registering a new service requires authentication',
        hint: enrollmentToken
          ? 'Register it through the gateway (POST /tenants/register), or present the enrollment token as X-Enrollment-Token'
          : 'Register it through the gateway (POST /tenants/register). Direct self-registration is switched off: no REGISTRY_ENROLLMENT_TOKEN is configured.',
      });
    }
    const token = mintServiceToken();
    tokenHash = hashToken(token);
    issuedToken = token;
  }

  const refused = await refuseDestinations({ baseUrl, catalogUrl }, warnings);
  if (refused) {
    log.warn('registry', `Rejected registration of '${name}': ${refused}`, { name, baseUrl, catalogUrl });
    return res.status(400).json({
      error: refused,
      hint: 'Services may only be registered at destinations inside the configured allowlist (UPSTREAM_ALLOWED_CIDRS / _HOSTS / _PORTS)',
    });
  }

  // --- Optional live catalog probe ---
  let catalog = null;
  if (catalogUrl) {
    try {
      catalog = await fetchServiceCatalog(catalogUrl);
      log.info('registry', `Catalog fetched successfully for '${name}'`, { name });

      // DUPLICATE-IDENTITY GUARD.
      //
      // Two different names sharing one baseUrl is legitimate and stays
      // allowed — one process routinely hosts several logical services (this
      // project's own load-test fleet is 50 of them on a single port), and
      // blue/green and path-multiplexed deployments look the same way. What
      // is almost never intentional is pointing a NEW name at the catalog of
      // a service that is ALREADY registered: that is how 'llmm' and 'llm2'
      // came to exist as copies of 'llm'. The discriminator is identity, not
      // address — a legitimately co-hosted service reports its own name from
      // its own catalog path, whereas an accidental duplicate reports the
      // name of the service it was copied from.
      if (catalog.name && catalog.name !== name) {
        const collidesWith = await serviceExists(catalog.name);
        if (collidesWith && !existing && req.body.allowAlias !== true) {
          log.warn('registry', `Rejected '${name}': its catalog identifies as the already-registered service '${catalog.name}'`, {
            name, catalogName: catalog.name, catalogUrl,
          });
          return res.status(409).json({
            error: `The catalog at ${catalogUrl} identifies itself as '${catalog.name}', which is already registered as a separate service`,
            hint: `Registering '${name}' against it would create a duplicate of '${catalog.name}' under a second name. Re-register '${catalog.name}' itself, point '${name}' at its own catalog, or pass "allowAlias": true if a deliberate second name for the same service is what you want.`,
            duplicateOf: catalog.name,
          });
        }
        warnings.push(`Catalog identifies itself as '${catalog.name}' but is registered as '${name}'; the registered name wins`);
      }
    } catch (err) {
      warnings.push(`Catalog at ${catalogUrl} is not reachable (${err.message}) — registered from the metadata you supplied; health checks will pick it up when it comes online`);
      log.warn('registry', `Catalog unreachable for '${name}': ${err.message}`, { name, catalogUrl });
    }
  } else {
    warnings.push('No catalogUrl given — this service will not be health-checked; endpoints are taken from your registration');
  }

  let resolvedEndpoints;
  if (catalog && Array.isArray(catalog.endpoints) && catalog.endpoints.length) {
    const { kept, dropped } = partitionEndpointsByNamespace(name, catalog.endpoints);
    if (dropped.length) {
      warnings.push(`Catalog advertises ${dropped.length} endpoint(s) outside this service's namespace (${dropped.join(', ')}) — ignored; every endpoint must start with '/${name}/'`);
    }
    resolvedEndpoints = kept;
  } else if (endpoints.length) {
    resolvedEndpoints = endpoints;
  } else {
    resolvedEndpoints = existing?.endpoints || [];
  }

  if (resolvedEndpoints.length === 0) {
    warnings.push(`No endpoints declared — nothing is reachable through /gateway/${name} until endpoints are registered or the catalog reports some`);
  }

  // Sharing a baseUrl is allowed, but an accidental duplicate should be
  // visible at the moment it is created rather than discovered later in a
  // listing that shows the same host three times.
  if (!existing) {
    const sharing = (await getAllServices())
      .filter((svc) => svc.baseUrl === baseUrl && svc.name !== name)
      .map((svc) => svc.name);
    if (sharing.length) {
      warnings.push(`${baseUrl} is also registered as: ${sharing.join(', ')}. That is fine if one host serves several services; if you meant to re-register one of those, deregister '${name}' and register that name instead.`);
    }
  }

  // --- Build and persist entry ---
  // name and baseUrl come from the REGISTRATION, never from the catalog: the
  // key a record lives under and the name it reports must always agree.
  // Absent means "leave as-is" (a restarting service re-registers with only
  // name+baseUrl and must not lose its catalogUrl); an explicit "" clears it.
  const resolvedCatalogUrl = catalogUrl !== undefined ? (catalogUrl || '') : (existing?.catalogUrl || '');

  const serviceEntry = {
    name,
    baseUrl,
    catalogUrl: resolvedCatalogUrl,
    version: catalog?.version || version || existing?.version || 'unknown',
    owner: catalog?.owner || owner || existing?.owner || 'unknown',
    displayName: displayName || existing?.displayName || name,
    description: description ?? existing?.description ?? '',
    endpoints: resolvedEndpoints,
    // An explicit re-registration by the owner re-enables the service; the
    // health check never does.
    status: 'active',
    health: catalog ? 'ok' : (resolvedCatalogUrl ? 'unreachable' : 'unchecked'),
    tokenHash,
    // Keep original registration timestamp on re-register
    registeredAt: existing?.registeredAt ?? new Date().toISOString(),
    lastSeen: catalog ? new Date().toISOString() : (existing?.lastSeen ?? new Date().toISOString()),
  };

  await saveService(name, serviceEntry);

  log.audit('registry', `Service '${name}' registered`, { name, baseUrl, warnings });

  const { tokenHash: _omit, ...publicEntry } = serviceEntry;
  return res.status(201).json({
    message: `Service '${name}' registered successfully`,
    service: publicEntry,
    warnings,
    // Returned exactly once, at first registration. Store it: it is what
    // proves ownership of this name later.
    ...(issuedToken ? { serviceToken: issuedToken } : {}),
  });
});

/**
 * PATCH /services/:name
 * Changes a registered service's configuration. Requires the service token —
 * this is the tenant's service, not anyone's to edit.
 *
 * `syncFromCatalog: true` re-reads endpoints, version and owner from the
 * service's catalogUrl. That used to happen by itself on every health check;
 * it is a configuration change, so it now happens only when the owner asks.
 */
app.patch('/services/:name', validate({
  params: serviceNameParam,
  body: {
    baseUrl: v.optional(v.httpUrl()),
    ...serviceConfigFields,
    status: v.optional(v.oneOf(['active', 'inactive'])),
    syncFromCatalog: v.optional(v.boolean()),
    serviceToken: serviceTokenField,
  },
}), async (req, res) => {
  const { name } = req.params;
  const raw = await getServiceRaw(name);
  if (!raw) return res.status(404).json({ error: `Service '${name}' not found` });

  if (!mayMutateService(req, raw.tokenHash)) {
    return res.status(403).json({ error: 'A valid serviceToken is required to modify this service' });
  }

  const current = deserialiseService(raw);
  const { serviceToken: _token, syncFromCatalog, ...patch } = req.body;
  const warnings = [];

  const bad = (patch.endpoints || []).find((e) => !e.startsWith(`/${name}/`) && e !== `/${name}`);
  if (bad) {
    return res.status(400).json({ error: `Endpoint '${bad}' must start with '/${name}/'` });
  }

  const refused = await refuseDestinations({ baseUrl: patch.baseUrl, catalogUrl: patch.catalogUrl }, warnings);
  if (refused) {
    return res.status(400).json({
      error: refused,
      hint: 'Services may only be registered at destinations inside the configured allowlist (UPSTREAM_ALLOWED_CIDRS / _HOSTS / _PORTS)',
    });
  }

  if (syncFromCatalog) {
    const catalogUrl = patch.catalogUrl ?? current.catalogUrl;
    if (!catalogUrl) {
      return res.status(400).json({ error: 'This service has no catalogUrl to sync from' });
    }
    let catalog;
    try {
      catalog = await fetchServiceCatalog(catalogUrl);
    } catch (err) {
      return res.status(502).json({ error: `Could not read the catalog at ${catalogUrl}: ${err.message}` });
    }
    if (Array.isArray(catalog.endpoints)) {
      const { kept, dropped } = partitionEndpointsByNamespace(name, catalog.endpoints);
      if (dropped.length) {
        warnings.push(`Catalog advertises ${dropped.length} endpoint(s) outside this service's namespace (${dropped.join(', ')}) — ignored`);
      }
      patch.endpoints = kept;
    }
    if (typeof catalog.version === 'string') patch.version = catalog.version;
    if (typeof catalog.owner === 'string') patch.owner = catalog.owner;
  }

  if (Object.keys(patch).length === 0) {
    return res.status(400).json({ error: 'Nothing to update' });
  }

  // Only the fields being changed are written, so an edit can never carry a
  // stale health or lastSeen over a liveness update that landed meanwhile.
  await redis.hset(REDIS_KEYS.service(name), {
    ...patch,
    ...(patch.endpoints ? { endpoints: JSON.stringify(patch.endpoints) } : {}),
  });

  log.audit('registry', `Service '${name}' updated`, { name, fields: Object.keys(patch) });
  res.json({ message: `Service '${name}' updated`, service: { ...(await getService(name)), name }, warnings });
});

/**
 * POST /services/:name/heartbeat
 * Lifecycle renewal: "this service is up". Requires the service token, takes
 * no configuration, and changes none — only health and lastSeen.
 *
 * This is what a service calls when it starts again. It is deliberately a
 * different operation from registration: a restart has no reason to carry a
 * baseUrl, a catalogUrl or an endpoint list, so it is given no way to change
 * them. The current record is returned, so a service can see whether what is
 * registered still matches what it serves and send an (authenticated) PATCH
 * if it does not.
 */
app.post('/services/:name/heartbeat', validate({
  params: serviceNameParam,
  body: { serviceToken: serviceTokenField },
}), async (req, res) => {
  const { name } = req.params;
  const raw = await getServiceRaw(name);
  if (!raw) return res.status(404).json({ error: `Service '${name}' not found` });

  if (!mayMutateService(req, raw.tokenHash)) {
    return res.status(403).json({ error: 'A valid serviceToken is required to renew this service' });
  }

  await recordLiveness(name, 'ok');
  res.json({ message: `Service '${name}' renewed`, service: { ...(await getService(name)), name } });
});

/**
 * GET /services
 * Returns all registered services.
 * Optional query: ?status=active  (filter by status)
 */
app.get('/services', validate({
  query: { status: v.optional(v.oneOf(['active', 'inactive'])) },
}), async (req, res) => {
  try {
    const { status } = req.query;
    let services = await getAllServices();

    if (status) {
      services = services.filter((s) => s.status === status);
    }

    res.json({ count: services.length, services });
  } catch (err) {
    console.error('[Registry] GET /services error:', err.message);
    res.status(500).json({ error: 'Failed to retrieve services from store' });
  }
});

/**
 * GET /services/:name
 * Returns a single service by name.
 */
app.get('/services/:name', validate({ params: serviceNameParam }), async (req, res) => {
  try {
    const service = await getService(req.params.name);

    if (!service) {
      return res.status(404).json({
        error: `Service '${req.params.name}' not found in registry`,
      });
    }

    // The key is the identity — see getAllServices().
    res.json({ ...service, name: req.params.name });
  } catch (err) {
    console.error(`[Registry] GET /services/${req.params.name} error:`, err.message);
    res.status(500).json({ error: 'Failed to retrieve service from store' });
  }
});

/**
 * DELETE /services/:name
 * Deregisters a service (for graceful shutdowns). Requires the service token:
 * removing a record takes its service off the gateway for everyone, and frees
 * the name for whoever registers it next.
 */
app.delete('/services/:name', validate({
  params: serviceNameParam,
  body: { serviceToken: serviceTokenField },
}), async (req, res) => {
  const { name } = req.params;

  try {
    const raw = await getServiceRaw(name);
    const exists = raw !== null || (await serviceExists(name));

    if (!exists) {
      return res.status(404).json({ error: `Service '${name}' not found` });
    }

    if (!mayMutateService(req, raw?.tokenHash)) {
      return res.status(403).json({ error: 'A valid serviceToken is required to deregister this service' });
    }

    await deleteService(name);

    log.audit('registry', `Service '${name}' deregistered`, { name });
    res.json({ message: `Service '${name}' removed from registry` });
  } catch (err) {
    log.error('registry', `DELETE /services/${name} error: ${err.message}`, { name });
    res.status(500).json({ error: 'Failed to deregister service' });
  }
});

/**
 * GET /health
 * Registry's own health endpoint — also surfaces Redis connectivity.
 */
app.get('/health', async (req, res) => {
  // A cheap Redis ping to confirm the connection is alive
  let redisStatus = 'ok';
  try {
    await redis.ping();
  } catch {
    redisStatus = 'error';
  }

  const registeredCount = await redis
    .scard(REDIS_KEYS.serviceIndex())
    .catch(() => -1); // -1 signals Redis read failure

  res.json({
    status: redisStatus === 'ok' ? 'ok' : 'degraded',
    redis: redisStatus,
    registeredServices: registeredCount,
    uptime: process.uptime(),
  });
});

// --- GRACEFUL SHUTDOWN ---
async function shutdown(signal) {
  console.log(`\n[Registry] Received ${signal}, shutting down...`);

  try {
    await redis.quit(); // flush and close Redis connection cleanly
    console.log('[Redis] Connection closed gracefully');
  } catch (err) {
    console.error('[Redis] Error during shutdown:', err.message);
  }

  process.exit(0);
}


// for the docs
app.use('/docs', swaggerUi.serve, swaggerUi.setup(spec));
app.get('/docs.json', (req, res) => res.json(spec));

// --- CENTRALIZED ERROR HANDLER ---
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  log.error('unhandled', `Unhandled error on ${req.method} ${req.originalUrl}: ${err.message}`, {
    method: req.method, path: req.originalUrl, stack: err.stack,
  });
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error' });
});

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// --- START ---
app.listen(REGISTRY_PORT, async () => {
  console.log(`\n📋 Service Registry running on port ${REGISTRY_PORT}`);
  console.log(`  POST   /register          - Register a new service`);
  console.log(`  GET    /services          - List all services`);
  console.log(`  GET    /services/:name    - Get single service`);
  console.log(`  PATCH  /services/:name    - Change service configuration (token required)`);
  console.log(`  POST   /services/:name/heartbeat - Renew a service (token required)`);
  console.log(`  DELETE /services/:name    - Deregister a service (token required)`);
  console.log(`  GET    /health            - Registry health\n`);

  console.log(`[Registry] New services may be registered: through the gateway${enrollmentToken ? ', or directly with the enrollment token' : ' only (no REGISTRY_ENROLLMENT_TOKEN set)'}`);
  console.log(`[Registry] Allowed destinations: ${destinations.describe()}`);
  if (!destinations.configured) {
    log.warn('registry', 'UPSTREAM_ALLOWED_CIDRS is not set — no service can be registered or health-checked until it is');
  }

  await ensureRegistryAdminToken().catch((err) =>
    console.error('[Registry] Could not establish the platform override token:', err.message));

  await repairCorruptEntries().catch((err) =>
    console.error('[Registry] Boot repair failed:', err.message));

  setTimeout(() => {
    runHealthChecks();
    setInterval(runHealthChecks, HEALTH_CHECK_INTERVAL_MS);
  }, 5000);
});
