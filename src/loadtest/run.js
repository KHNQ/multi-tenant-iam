/**
 * Load test + live permission-change ("chaos") driver.
 *
 * Spins up `concurrency` virtual users (mapped 1:1 onto accounts created by
 * seed.js), each looping: pick a random resource across the whole bench
 * fleet -> call it through the gateway with its own JWT -> sleep a random
 * "think time" -> repeat. While that traffic runs, two independent chaos
 * timers mutate live state through the real admin API:
 *   - role chaos:   grants/revokes a random tier for a random user
 *   - policy chaos: flips a tier's access to one resource on/off
 *
 * The harness keeps its own mirror of "what SHOULD this user be allowed to
 * do right now" and compares it against what the gateway actually returned.
 * Because this system has no authorization cache (Casbin's policy set lives
 * in-process and is mutated synchronously by addPolicy/removePolicy — see
 * README §3.5), a mismatch more than a small grace window away from the
 * mutation that caused it is a genuine correctness bug, not a race. That
 * grace window exists only to absorb requests that were already in flight
 * over the network when the mutation landed server-side.
 *
 * Run with: node src/loadtest/run.js [flags]
 *   --concurrency=1000 --ramp=15 --steady=120 --cooldown=10
 *   --thinkMin=300 --thinkMax=1200 --chaosInterval=2000 --chaosRoleToggles=5
 *   --chaosPolicyInterval=10000 --seed=1337 --state=<path> --out=<path>
 * Prerequisite: node src/loadtest/seed.js has already run.
 */

const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const Redis = require('ioredis');
const { makeRng } = require('./lib/rng');
const { timedRequest, makeAgent } = require('./lib/http');
const { summarizeLatencies, bucketize } = require('./lib/stats');

function parseArgs(argv) {
  const args = {};
  for (const a of argv) {
    const m = a.match(/^--([^=]+)=(.*)$/);
    if (m) args[m[1]] = m[2];
  }
  return args;
}
const argv = parseArgs(process.argv.slice(2));

const CONFIG = {
  gateway: argv.gateway || 'http://localhost:3000',
  concurrency: Number(argv.concurrency || 1000),
  rampSeconds: Number(argv.ramp || 15),
  steadySeconds: Number(argv.steady || 120),
  cooldownSeconds: Number(argv.cooldown || 10),
  thinkMinMs: Number(argv.thinkMin || 300),
  thinkMaxMs: Number(argv.thinkMax || 1200),
  chaosIntervalMs: Number(argv.chaosInterval || 2000),
  chaosRoleTogglesPerTick: Number(argv.chaosRoleToggles || 5),
  chaosPolicyIntervalMs: Number(argv.chaosPolicyInterval || 10000),
  requestTimeoutMs: Number(argv.timeout || 8000),
  raceGraceMs: Number(argv.grace || 500),
  seed: Number(argv.seed || 1337),
  stateFile: argv.state || path.join(__dirname, '.state', 'state.json'),
  outFile: argv.out || path.join(__dirname, '.results', `results-${Date.now()}.json`),
  redisUrl: process.env.REDIS_URL || 'redis://localhost:7000',
  runDir: argv.runDir || path.join(__dirname, '..', '..', '.run'),
};

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  green: '\x1b[32m', red: '\x1b[31m', yellow: '\x1b[33m', cyan: '\x1b[36m',
};

const rng = makeRng(CONFIG.seed);
const agent = makeAgent(CONFIG.concurrency + 32);
const adminAgent = makeAgent(16);

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
function fmtSecs(ms) {
  return `${(ms / 1000).toFixed(1)}s`;
}

// ─── STATE ────────────────────────────────────────────────────────────────

if (!fs.existsSync(CONFIG.stateFile)) {
  console.error(`\n[run] No state file at ${CONFIG.stateFile} — run seed.js first:`);
  console.error(`      node src/loadtest/seed.js`);
  process.exit(1);
}
const seedState = JSON.parse(fs.readFileSync(CONFIG.stateFile, 'utf8'));

const tierServices = seedState.tiers; // { tierName: [svcName, ...] }
const resourceTier = new Map(); // '/svc/ping' -> tierName
for (const [tier, svcs] of Object.entries(tierServices)) {
  for (const svc of svcs) {
    resourceTier.set(`/${svc}/ping`, tier);
    resourceTier.set(`/${svc}/work`, tier);
  }
}
const allResources = [...resourceTier.keys()];

const pool = seedState.users.slice(0, CONFIG.concurrency);
if (pool.length < CONFIG.concurrency) {
  console.warn(`[run] Requested concurrency ${CONFIG.concurrency} but only ${pool.length} seeded users exist — using ${pool.length}.`);
  CONFIG.concurrency = pool.length;
}

// authoritative in-memory mirror, mutated by chaos, read by the correctness check
const userState = new Map();
for (const u of pool) userState.set(u.username, { token: u.token, roles: new Set(u.roles) });

const policyOff = new Set(); // `${tier}|${resource}` currently removed by policy chaos
// Keyed by `${username}|${tier}`, NOT just username — a user touched by two
// unrelated mutations (e.g. tier03 revoked, then tier07 granted seconds
// later) must not have the first grace window smeared onto the second
// tier's requests just because they share a username.
const lastGrantMutationAt = new Map();
const lastPolicyMutationAt = new Map(); // `${tier}|${resource}` -> ms epoch

function expectedAllow(username, resource) {
  const tier = resourceTier.get(resource);
  const u = userState.get(username);
  if (!u.roles.has(tier)) return false;
  if (policyOff.has(`${tier}|${resource}`)) return false;
  return true;
}

function recentlyMutated(username, resource, atTime) {
  const tier = resourceTier.get(resource);
  const grantMutT = lastGrantMutationAt.get(`${username}|${tier}`);
  const policyMutT = lastPolicyMutationAt.get(`${tier}|${resource}`);
  if (grantMutT !== undefined && Math.abs(atTime - grantMutT) < CONFIG.raceGraceMs) return true;
  if (policyMutT !== undefined && Math.abs(atTime - policyMutT) < CONFIG.raceGraceMs) return true;
  return false;
}

// ─── METRICS ──────────────────────────────────────────────────────────────

const samples = []; // { t, username, latencyMs, status, expected, actual, mismatch, resource }
const adminSamples = []; // { t, kind: 'role'|'policy', method, latencyMs, status }
const revocationChecks = []; // { t, username, role, resource, latencyMs, correct, status }
const resourceSamples = []; // { t, service, pid, cpu, rssKb }
const redisSamples = []; // { t, opsPerSec, connectedClients, usedMemoryHuman }
const mutationLog = []; // { t, username, role, method } — every successful role grant/revoke, for post-hoc debugging

let mismatchCount = 0;
let requestCount = 0;

// ─── ADMIN AUTH ───────────────────────────────────────────────────────────

let adminToken = null;
async function adminLogin() {
  const res = await timedRequest('POST', `${CONFIG.gateway}/auth/login`, {
    body: { username: 'admin', password: 'adminpass' }, agent: adminAgent,
  });
  if (res.status !== 200) throw new Error(`Admin login failed: ${res.status}`);
  return res.body.token;
}

// ─── VIRTUAL USERS ────────────────────────────────────────────────────────

let stopFlag = false;

async function virtualUserLoop(username) {
  while (!stopFlag) {
    const resource = rng.pick(allResources);
    const [, svcName, action] = resource.split('/');
    const url = `${CONFIG.gateway}/gateway/${svcName}/${action}`;
    const expected = expectedAllow(username, resource);
    const t0 = Date.now();

    const u = userState.get(username);
    const res = await timedRequest('GET', url, { token: u.token, agent, timeoutMs: CONFIG.requestTimeoutMs });
    requestCount++;

    const actual = res.status === 200;
    const mismatch = expected !== actual && !recentlyMutated(username, resource, t0);
    if (mismatch) mismatchCount++;

    samples.push({ t: t0, username, latencyMs: res.durationMs, status: res.status, expected, actual, mismatch, resource });

    if (stopFlag) break;
    await sleep(rng.int(CONFIG.thinkMinMs, CONFIG.thinkMaxMs));
  }
}

// ─── CHAOS: ROLE GRANT/REVOKE ─────────────────────────────────────────────

const tierNames = Object.keys(tierServices);
const usernames = [...userState.keys()];

// setInterval doesn't wait for its async callback — under load a tick's
// sequential admin calls can take longer than chaosIntervalMs, and without
// this guard the next tick would start concurrently. Two overlapping ticks
// can both read the same user's role Set before either mutation lands and
// make conflicting decisions from stale data, corrupting the client-side
// mirror in a way no grace window can account for. Skip a tick outright
// rather than let it queue — queuing would just shift the same race later.
let roleChaosBusy = false;
async function roleChaosTick() {
  if (roleChaosBusy) return;
  roleChaosBusy = true;
  try {
    await roleChaosTickBody();
  } finally {
    roleChaosBusy = false;
  }
}

async function roleChaosTickBody() {
  for (let i = 0; i < CONFIG.chaosRoleTogglesPerTick; i++) {
    const username = rng.pick(usernames);
    const u = userState.get(username);
    const has = [...u.roles];
    const doRevoke = has.length > 0 && (has.length >= 3 || rng.chance(0.5));

    let role;
    let method;
    if (doRevoke) {
      role = rng.pick(has);
      method = 'DELETE';
    } else {
      const candidates = tierNames.filter((t) => !u.roles.has(t));
      if (candidates.length === 0) continue;
      role = rng.pick(candidates);
      method = 'POST';
    }

    const t0 = Date.now();
    const res = await timedRequest(method, `${CONFIG.gateway}/admin/roles`, {
      token: adminToken, body: { username, role }, agent: adminAgent, timeoutMs: CONFIG.requestTimeoutMs,
    });
    adminSamples.push({ t: t0, kind: 'role', method, latencyMs: res.durationMs, status: res.status });
    if (res.status !== 200) continue;

    if (method === 'DELETE') u.roles.delete(role); else u.roles.add(role);
    // Use t0 (when the mutation was SENT), not "now" (after its own round
    // trip) — the server applies the change close to t0, and dating the
    // grace window from the later client-observed time would systematically
    // under-forgive requests that raced the mutation on the server side.
    lastGrantMutationAt.set(`${username}|${role}`, t0);
    mutationLog.push({ t: t0, username, role, method });

    // Correctness probe: right after a revoke, immediately re-check a
    // resource that was ONLY reachable through the just-revoked role.
    if (method === 'DELETE') {
      const svcs = tierServices[role] || [];
      if (svcs.length) {
        const svc = rng.pick(svcs);
        const resource = `/${svc}/ping`;
        const stillGranted = [...u.roles].some((r) => (tierServices[r] || []).includes(svc));
        if (!stillGranted) {
          const probeT0 = Date.now();
          const probeRes = await timedRequest('GET', `${CONFIG.gateway}/gateway/${svc}/ping`, {
            token: u.token, agent: adminAgent, timeoutMs: CONFIG.requestTimeoutMs,
          });
          revocationChecks.push({
            t: probeT0, username, role, resource,
            latencyMs: probeRes.durationMs, status: probeRes.status,
            correct: probeRes.status === 403,
          });
        }
      }
    }
  }
}

// ─── CHAOS: POLICY TOGGLE (per-resource, coarser than per-user) ───────────

let policyChaosBusy = false;
async function policyChaosTick() {
  if (policyChaosBusy) return;
  policyChaosBusy = true;
  try {
    await policyChaosTickBody();
  } finally {
    policyChaosBusy = false;
  }
}

async function policyChaosTickBody() {
  const tier = rng.pick(tierNames);
  const svcs = tierServices[tier];
  if (!svcs || !svcs.length) return;
  const svc = rng.pick(svcs);
  const resource = `/${svc}/ping`;
  const key = `${tier}|${resource}`;
  const isOn = !policyOff.has(key);
  const method = isOn ? 'DELETE' : 'POST';

  const t0 = Date.now();
  const res = await timedRequest(method, `${CONFIG.gateway}/admin/policies`, {
    token: adminToken, body: { subject: tier, resource, action: 'get' }, agent: adminAgent, timeoutMs: CONFIG.requestTimeoutMs,
  });
  adminSamples.push({ t: t0, kind: 'policy', method, latencyMs: res.durationMs, status: res.status });
  if (res.status !== 200) return;

  if (isOn) policyOff.add(key); else policyOff.delete(key);
  lastPolicyMutationAt.set(key, Date.now());
}

// ─── RESOURCE SAMPLING (gateway/registry/bench-fleet process cost) ────────

function readPid(name) {
  try {
    return fs.readFileSync(path.join(CONFIG.runDir, `${name}.pid`), 'utf8').trim();
  } catch {
    return null;
  }
}

function sampleProcess(name, pid) {
  return new Promise((resolve) => {
    execFile('ps', ['-o', 'pcpu=,rss=', '-p', pid], (err, stdout) => {
      if (err || !stdout.trim()) return resolve(null);
      const [cpu, rssKb] = stdout.trim().split(/\s+/).map(Number);
      resolve({ cpu, rssKb });
    });
  });
}

let resourceSamplingAvailable = null;
async function resourceSamplerTick() {
  const targets = ['gateway', 'registry'];
  if (resourceSamplingAvailable === null) {
    resourceSamplingAvailable = targets.some((n) => readPid(n));
    if (!resourceSamplingAvailable) {
      console.warn(`  ${C.yellow}!${C.reset} no .run/*.pid files found under ${CONFIG.runDir} — skipping process resource sampling (start the stack with ./start.sh to enable it)`);
    }
  }
  if (!resourceSamplingAvailable) return;

  const t = Date.now();
  for (const name of targets) {
    const pid = readPid(name);
    if (!pid) continue;
    const sample = await sampleProcess(name, pid);
    if (sample) resourceSamples.push({ t, service: name, pid, ...sample });
  }
}

// ─── REDIS SAMPLING ─────────────────────────────────────────────────────

const redis = new Redis(CONFIG.redisUrl, { lazyConnect: true, retryStrategy: () => null });
async function redisSamplerTick() {
  try {
    const info = await redis.info('stats');
    const clients = await redis.info('clients');
    const memory = await redis.info('memory');
    const get = (blob, key) => {
      const m = blob.match(new RegExp(`${key}:(.+)`));
      return m ? m[1].trim() : null;
    };
    redisSamples.push({
      t: Date.now(),
      opsPerSec: Number(get(info, 'instantaneous_ops_per_sec')) || 0,
      connectedClients: Number(get(clients, 'connected_clients')) || 0,
      usedMemoryHuman: get(memory, 'used_memory_human'),
    });
  } catch {
    // non-fatal — redis sampling is a bonus signal, not load-bearing
  }
}

// ─── MAIN ─────────────────────────────────────────────────────────────────

async function main() {
  console.log(`\n${C.bold}=== Load test ===${C.reset}`);
  console.log(`  concurrency=${CONFIG.concurrency} ramp=${CONFIG.rampSeconds}s steady=${CONFIG.steadySeconds}s cooldown=${CONFIG.cooldownSeconds}s`);
  console.log(`  think=${CONFIG.thinkMinMs}-${CONFIG.thinkMaxMs}ms chaosInterval=${CONFIG.chaosIntervalMs}ms policyToggleEvery=${CONFIG.chaosPolicyIntervalMs}ms`);
  console.log(`  resources: ${allResources.length} across ${Object.keys(tierServices).length} tiers, ${seedState.services.length} services`);

  adminToken = await adminLogin();
  console.log(`  ${C.green}✔${C.reset} admin authenticated`);

  try {
    await redis.connect();
    console.log(`  ${C.green}✔${C.reset} redis sampling connected`);
  } catch {
    console.warn(`  ${C.yellow}!${C.reset} could not connect to redis at ${CONFIG.redisUrl} — skipping redis metrics`);
  }

  const totalMs = (CONFIG.rampSeconds + CONFIG.steadySeconds + CONFIG.cooldownSeconds) * 1000;
  const runStartT = Date.now();

  // Stagger virtual-user starts across the ramp window instead of firing
  // `concurrency` requests in the same event-loop tick.
  const rampMs = CONFIG.rampSeconds * 1000;
  const vuPromises = pool.map((u, i) => {
    const delay = Math.floor((i * rampMs) / Math.max(1, pool.length));
    return sleep(delay).then(() => virtualUserLoop(u.username));
  });

  const chaosTimer = setInterval(() => { roleChaosTick().catch(() => {}); }, CONFIG.chaosIntervalMs);
  const policyTimer = setInterval(() => { policyChaosTick().catch(() => {}); }, CONFIG.chaosPolicyIntervalMs);
  const resourceTimer = setInterval(() => { resourceSamplerTick().catch(() => {}); }, 2000);
  const redisTimer = setInterval(() => { redisSamplerTick().catch(() => {}); }, 2000);

  const mainWindowMs = (CONFIG.rampSeconds + CONFIG.steadySeconds) * 1000;
  const progressTimer = setInterval(() => {
    const elapsed = Date.now() - runStartT;
    const phase = elapsed < rampMs ? 'RAMP' : elapsed < mainWindowMs ? 'STEADY' : 'COOLDOWN';
    process.stdout.write(
      `\r  [${phase}] t=${fmtSecs(elapsed)}/${fmtSecs(totalMs)} reqs=${requestCount} mismatches=${mismatchCount} chaosEvents=${adminSamples.length}   `,
    );
  }, 1000);

  const remainingMainMs = Math.max(0, mainWindowMs - (Date.now() - runStartT));
  await sleep(remainingMainMs);
  clearInterval(chaosTimer);
  clearInterval(policyTimer);
  console.log(`\n  ${C.dim}chaos stopped, entering ${CONFIG.cooldownSeconds}s cooldown${C.reset}`);

  await sleep(CONFIG.cooldownSeconds * 1000);
  stopFlag = true;
  clearInterval(progressTimer);
  clearInterval(resourceTimer);
  clearInterval(redisTimer);

  console.log(`\n  waiting for in-flight virtual users to drain...`);
  await Promise.all(vuPromises);
  await redis.quit().catch(() => {});

  console.log(`  ${C.green}✔${C.reset} run complete: ${requestCount} requests, ${adminSamples.length} chaos mutations`);

  // ── Aggregate ──
  const latencies = samples.map((s) => s.latencyMs);
  const overall = summarizeLatencies(latencies);
  const statusBreakdown = {};
  for (const s of samples) statusBreakdown[s.status] = (statusBreakdown[s.status] || 0) + 1;

  const endT = Date.now();
  const buckets = bucketize(samples, 1000, runStartT, endT).map((b) => {
    const lat = b.samples.map((s) => s.latencyMs);
    const errors = b.samples.filter((s) => s.status === 0 || s.status >= 500).length;
    const denied = b.samples.filter((s) => s.status === 403).length;
    return {
      t: b.t,
      rps: b.samples.length,
      ...summarizeLatencies(lat),
      errors,
      denied,
    };
  });

  const chaosEvents = adminSamples
    .filter((a) => a.status === 200)
    .map((a) => ({ t: a.t, kind: a.kind, method: a.method }));

  const revocationLatencies = revocationChecks.map((r) => r.latencyMs);
  const revocationCorrectRate = revocationChecks.length
    ? revocationChecks.filter((r) => r.correct).length / revocationChecks.length
    : null;

  const adminLatenciesByKind = {};
  for (const kind of ['role', 'policy']) {
    const lat = adminSamples.filter((a) => a.kind === kind && a.status === 200).map((a) => a.latencyMs);
    adminLatenciesByKind[kind] = summarizeLatencies(lat);
  }

  const results = {
    generatedAt: new Date().toISOString(),
    config: CONFIG,
    fleet: { serviceCount: seedState.services.length, tierCount: tierNames.length, resourceCount: allResources.length },
    window: { runStartT, endT, rampMs, mainWindowMs, totalMs: endT - runStartT },
    totals: {
      requests: requestCount,
      mismatches: mismatchCount,
      mismatchRate: requestCount ? mismatchCount / requestCount : 0,
      chaosMutations: adminSamples.length,
      chaosMutationsOk: adminSamples.filter((a) => a.status === 200).length,
      revocationChecks: revocationChecks.length,
      revocationCorrectRate,
    },
    latency: overall,
    statusBreakdown,
    timeline: buckets,
    chaosEvents,
    revocationLatency: summarizeLatencies(revocationLatencies),
    revocationLatencies,
    adminLatenciesByKind,
    resourceSamples,
    redisSamples,
    mismatchSamples: samples.filter((s) => s.mismatch).slice(0, 50),
    mutationLog,
  };

  fs.mkdirSync(path.dirname(CONFIG.outFile), { recursive: true });
  fs.writeFileSync(CONFIG.outFile, JSON.stringify(results, null, 2));
  const latestFile = path.join(path.dirname(CONFIG.outFile), 'latest.json');
  fs.writeFileSync(latestFile, JSON.stringify(results, null, 2));

  printSummary(results);
  console.log(`\n  results written to ${CONFIG.outFile}`);
  console.log(`  next: node src/loadtest/report.js ${CONFIG.outFile}\n`);
}

function printSummary(r) {
  console.log(`\n${C.bold}=== Summary ===${C.reset}`);
  console.log(`  Requests:        ${r.totals.requests}  (${(r.totals.requests / (r.window.totalMs / 1000)).toFixed(1)} req/s avg)`);
  console.log(`  Latency:         p50=${r.latency.p50.toFixed(1)}ms  p90=${r.latency.p90.toFixed(1)}ms  p95=${r.latency.p95.toFixed(1)}ms  p99=${r.latency.p99.toFixed(1)}ms  max=${r.latency.max.toFixed(1)}ms`);
  console.log(`  Status codes:    ${Object.entries(r.statusBreakdown).map(([k, v]) => `${k}:${v}`).join('  ')}`);
  console.log(`  Chaos mutations: ${r.totals.chaosMutationsOk}/${r.totals.chaosMutations} ok`);
  console.log(`  Revocation checks: ${r.totals.revocationChecks}  correct=${r.totals.revocationCorrectRate === null ? 'n/a' : (r.totals.revocationCorrectRate * 100).toFixed(1) + '%'}  p50 effect latency=${r.revocationLatency.p50.toFixed(1)}ms`);
  const mismatchColor = r.totals.mismatches === 0 ? C.green : C.red;
  console.log(`  Correctness:     ${mismatchColor}${r.totals.mismatches} mismatches${C.reset} out of ${r.totals.requests} (${(r.totals.mismatchRate * 100).toFixed(3)}%)`);
}

main().catch((err) => {
  console.error(`\n[run] FATAL: ${err.stack || err.message}`);
  process.exit(1);
});
