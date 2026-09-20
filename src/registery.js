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
const { validateTenantId } = require('./tenancy');

const log = createLogger('registry');

const app = express();
app.use(express.json());
app.use(log.requestLogger());

// --- CONSTANTS ---
const REGISTRY_PORT = process.env.PORT || 3001;
const HEALTH_CHECK_INTERVAL_MS = 15000;
const HEALTH_CHECK_TIMEOUT_MS = 3000;

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
// The first registration of a name mints a token and returns it once. After
// that, the name can only be repointed at a *different* baseUrl by presenting
// that token. Re-registering the same name at the same baseUrl stays free, so
// a service that self-registers on every restart (llm.reg.js, vision.reg.js)
// needs no state of its own — but nobody else can quietly redirect `/llm` at
// their own host, which in a multi-tenant system would hand them another
// tenant's traffic, headers and bearer tokens.
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
 * @param {string} catalogUrl
 * @returns {Promise<object>}
 */
async function fetchServiceCatalog(catalogUrl) {
  const { default: fetch } = await import('node-fetch');

  const controller = new AbortController();
  const timeoutId = setTimeout(
    () => controller.abort(),
    HEALTH_CHECK_TIMEOUT_MS,
  );

  try {
    const response = await fetch(catalogUrl, { signal: controller.signal });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } finally {
    clearTimeout(timeoutId);
  }
}

// --- HEALTH CHECKS ---

/**
 * Runs a health check against all registered services.
 * Fetches their /catalog endpoint — if it responds, mark active.
 * If it fails, mark inactive but keep the record.
 *
 * A service registered without a catalogUrl has nothing to probe: it is left
 * exactly as registered (health: 'unchecked') rather than being demoted to
 * inactive, which would make manually registered services permanently
 * unroutable through the gateway.
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
      const catalog = await fetchServiceCatalog(serviceData.catalogUrl);

      // Sanitised on every probe, not just at registration — otherwise a
      // catalog advertising someone else's paths simply re-injects them on
      // the next health check.
      const probed = partitionEndpointsByNamespace(name, catalog.endpoints);
      if (probed.dropped.length) {
        log.warn('health', `[${name}] catalog advertises ${probed.dropped.length} endpoint(s) outside its namespace — ignored`, {
          name, dropped: probed.dropped,
        });
      }

      const updated = {
        ...serviceData,
        // Metadata the service is authoritative about...
        version: catalog.version || serviceData.version,
        owner: catalog.owner || serviceData.owner,
        endpoints: Array.isArray(catalog.endpoints) ? probed.kept : serviceData.endpoints,
        // ...but never its name or baseUrl: those are registry identity, set
        // at registration, and letting the catalog rewrite them is exactly how
        // three separate registrations all ended up calling themselves 'llm'.
        name,
        baseUrl: serviceData.baseUrl,
        status: 'active',
        health: 'ok',
        lastSeen: new Date().toISOString(),
      };

      await saveService(name, { ...updated, tokenHash: (await getServiceRaw(name))?.tokenHash });
      log.info('health', `[${name}] healthy at ${serviceData.baseUrl}`, { name });
    } catch (err) {
      const updated = { ...serviceData, name, status: 'inactive', health: 'unreachable' };
      await saveService(name, { ...updated, tokenHash: (await getServiceRaw(name))?.tokenHash });
      log.warn('health', `[${name}] unreachable: ${err.message}`, { name, error: err.message });
    }
  });

  await Promise.allSettled(checks);
}

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
 *   serviceToken: "..."                                 // required only to
 *                                                       // repoint an existing
 *                                                       // name at a new host
 * }
 *
 * catalogUrl is a convenience, not a precondition. Registration used to abort
 * with 502 "Cannot reach catalogUrl" whenever the service wasn't already
 * running and serving /catalog — which meant you could never register anything
 * new, only re-register something already up. Now an unreachable (or absent)
 * catalog registers the service from the metadata in the request body and
 * reports the probe result as a warning; the periodic health check fills in
 * the live metadata as soon as the service answers.
 */
app.post('/register', async (req, res) => {
  const { name, baseUrl, catalogUrl, owner, version, displayName, description } = req.body || {};
  const warnings = [];

  // --- Validation ---
  if (!name || !baseUrl) {
    return res.status(400).json({
      error: 'Missing required fields: name, baseUrl (catalogUrl is optional)',
    });
  }

  const nameError = validateTenantId(name);
  if (nameError) {
    return res.status(400).json({ error: nameError });
  }

  if (!/^https?:\/\//.test(baseUrl)) {
    return res.status(400).json({ error: 'baseUrl must be a valid HTTP URL' });
  }

  if (catalogUrl && !/^https?:\/\//.test(catalogUrl)) {
    return res.status(400).json({ error: 'catalogUrl must be a valid HTTP URL' });
  }

  let endpoints = [];
  if (req.body.endpoints !== undefined) {
    if (!Array.isArray(req.body.endpoints) || req.body.endpoints.some((e) => typeof e !== 'string')) {
      return res.status(400).json({ error: 'endpoints must be an array of path strings' });
    }
    endpoints = req.body.endpoints;
  }

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
    const authorised = mayMutateService(req, tokenHash);
    if (!authorised && existing.baseUrl !== baseUrl) {
      log.warn('registry', `Rejected re-registration of '${name}' at a different baseUrl without its service token`, {
        name, registeredBaseUrl: existing.baseUrl, attemptedBaseUrl: baseUrl,
      });
      return res.status(409).json({
        error: `Service '${name}' is already registered at ${existing.baseUrl}`,
        hint: 'Pick a different name, or pass the serviceToken issued at first registration to repoint this one',
      });
    }
  } else {
    const token = mintServiceToken();
    tokenHash = hashToken(token);
    issuedToken = token;
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
        if (collidesWith && !existing && req.body.allowAlias !== true && !isPlatformCall(req)) {
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
 * Updates a registered service's own metadata (endpoints, version, display
 * name, description, status) without a full re-registration. Requires the
 * service token — this is the tenant's service, not anyone's to edit.
 */
app.patch('/services/:name', async (req, res) => {
  const { name } = req.params;
  const raw = await getServiceRaw(name);
  if (!raw) return res.status(404).json({ error: `Service '${name}' not found` });

  if (!mayMutateService(req, raw.tokenHash)) {
    return res.status(403).json({ error: 'A valid serviceToken is required to modify this service' });
  }

  const current = deserialiseService(raw);
  const patch = {};

  if (req.body.endpoints !== undefined) {
    if (!Array.isArray(req.body.endpoints) || req.body.endpoints.some((e) => typeof e !== 'string')) {
      return res.status(400).json({ error: 'endpoints must be an array of path strings' });
    }
    const bad = req.body.endpoints.find((e) => !e.startsWith(`/${name}/`) && e !== `/${name}`);
    if (bad) {
      return res.status(400).json({ error: `Endpoint '${bad}' must start with '/${name}/'` });
    }
    patch.endpoints = req.body.endpoints;
  }

  for (const field of ['version', 'owner', 'displayName', 'description']) {
    if (req.body[field] !== undefined) patch[field] = String(req.body[field]);
  }

  if (req.body.baseUrl !== undefined) {
    if (!/^https?:\/\//.test(req.body.baseUrl)) {
      return res.status(400).json({ error: 'baseUrl must be a valid HTTP URL' });
    }
    patch.baseUrl = req.body.baseUrl;
  }

  if (req.body.catalogUrl !== undefined) {
    if (req.body.catalogUrl && !/^https?:\/\//.test(req.body.catalogUrl)) {
      return res.status(400).json({ error: 'catalogUrl must be a valid HTTP URL' });
    }
    patch.catalogUrl = req.body.catalogUrl || '';
  }

  if (req.body.status !== undefined) {
    if (!['active', 'inactive'].includes(req.body.status)) {
      return res.status(400).json({ error: "status must be 'active' or 'inactive'" });
    }
    patch.status = req.body.status;
  }

  const updated = { ...current, ...patch, name, tokenHash: raw.tokenHash };
  await saveService(name, updated);

  log.audit('registry', `Service '${name}' updated`, { name, fields: Object.keys(patch) });
  const { tokenHash: _omit, ...publicEntry } = updated;
  res.json({ message: `Service '${name}' updated`, service: publicEntry });
});

/**
 * GET /services
 * Returns all registered services.
 * Optional query: ?status=active  (filter by status)
 */
app.get('/services', async (req, res) => {
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
app.get('/services/:name', async (req, res) => {
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
 * Deregisters a service (for graceful shutdowns).
 *
 * Open by default so a service can clean up after itself on SIGTERM without
 * carrying credentials. Set REGISTRY_REQUIRE_TOKEN_FOR_DELETE=1 to require the
 * service token instead.
 */
app.delete('/services/:name', async (req, res) => {
  const { name } = req.params;

  try {
    const raw = await getServiceRaw(name);
    const exists = raw !== null || (await serviceExists(name));

    if (!exists) {
      return res.status(404).json({ error: `Service '${name}' not found` });
    }

    if (process.env.REGISTRY_REQUIRE_TOKEN_FOR_DELETE === '1'
        && !mayMutateService(req, raw?.tokenHash)) {
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
  console.log(`  PATCH  /services/:name    - Update service metadata (token required)`);
  console.log(`  DELETE /services/:name    - Deregister a service`);
  console.log(`  GET    /health            - Registry health\n`);

  await ensureRegistryAdminToken().catch((err) =>
    console.error('[Registry] Could not establish the platform override token:', err.message));

  await repairCorruptEntries().catch((err) =>
    console.error('[Registry] Boot repair failed:', err.message));

  setTimeout(() => {
    runHealthChecks();
    setInterval(runHealthChecks, HEALTH_CHECK_INTERVAL_MS);
  }, 5000);
});
