/**
 * Load-test backend fleet — N independent mock services behind ONE process.
 *
 * Why one process instead of N?
 *   Each service is still a fully independent Service Registry record (its
 *   own name, catalogUrl, endpoint list) and a fully independent Casbin
 *   resource, addressed through the gateway exactly like llm.reg.js and
 *   vision.reg.js are. Running 50 separate Node processes to return canned
 *   JSON would spend the load test's CPU/memory budget on process overhead
 *   instead of on the thing actually being benchmarked — the gateway's
 *   auth + Casbin + proxy path. This fleet is named 'llm-bench-*' /
 *   'vision-bench-*' so it never collides with the real llm.reg.js /
 *   vision.reg.js demo services if those also happen to be running.
 *
 * Run with: node src/loadtest/mock-services.js [count]
 * Env:      BENCH_PORT (default 9000), REGISTRY_URL, BENCH_SERVICE_COUNT
 */

const express = require('express');
const { createLogger } = require('../logger');

const log = createLogger('bench-fleet');
const app = express();
app.use(express.json());

const PORT = Number(process.env.BENCH_PORT || 9000);
const REGISTRY_URL = process.env.REGISTRY_URL || 'http://localhost:3001';
const COUNT = Number(process.argv[2] || process.env.BENCH_SERVICE_COUNT || 50);
const BASE_URL = `http://localhost:${PORT}`;

// Two flavors, alternating, so the fleet isn't monolithic — different
// simulated latency profiles produce a more realistic latency distribution
// than 50 identical services would.
const CATEGORIES = [
  { prefix: 'llm-bench', owner: 'ai_team', pingMs: [2, 8], workMs: [15, 45], verb: 'generate' },
  { prefix: 'vision-bench', owner: 'cv_team', pingMs: [3, 10], workMs: [20, 60], verb: 'analyze' },
];

const services = [];
for (let i = 1; i <= COUNT; i++) {
  const cat = CATEGORIES[i % 2];
  const name = `${cat.prefix}-${String(Math.ceil(i / 2)).padStart(2, '0')}`;
  services.push({
    name,
    baseUrl: BASE_URL,
    catalogUrl: `${BASE_URL}/catalog/${name}`,
    owner: cat.owner,
    version: 'v1.0-bench',
    endpoints: [`/${name}/ping`, `/${name}/work`],
    pingMs: cat.pingMs,
    workMs: cat.workMs,
    verb: cat.verb,
  });
}
const byName = new Map(services.map((s) => [s.name, s]));

function jitter([min, max]) {
  return min + Math.random() * (max - min);
}

// Registered BEFORE the generic /:name/:action route below, or every
// request to /catalog/:x would be swallowed by that route instead
// (Express matches in registration order).
app.get('/catalog/:name', (req, res) => {
  const svc = byName.get(req.params.name);
  if (!svc) return res.status(404).json({ error: 'unknown bench service' });
  res.json({
    name: svc.name, baseUrl: svc.baseUrl, version: svc.version,
    owner: svc.owner, endpoints: svc.endpoints,
  });
});

app.get('/:name/:action', (req, res) => {
  const svc = byName.get(req.params.name);
  if (!svc || !['ping', 'work'].includes(req.params.action)) {
    return res.status(404).json({ error: 'not found' });
  }
  const delayMs = req.params.action === 'work' ? jitter(svc.workMs) : jitter(svc.pingMs);
  setTimeout(() => {
    res.json({
      service: svc.name,
      action: req.params.action,
      [svc.verb]: `mock ${svc.verb} result from ${svc.name}`,
      tookMs: Math.round(delayMs),
    });
  }, delayMs);
});

async function registerAll() {
  let ok = 0;
  let failed = 0;
  for (const svc of services) {
    try {
      const resp = await fetch(`${REGISTRY_URL}/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: svc.name, baseUrl: svc.baseUrl, catalogUrl: svc.catalogUrl, owner: svc.owner }),
      });
      if (resp.ok) ok++; else failed++;
    } catch {
      failed++;
    }
  }
  log.audit('registration', `Bench fleet registered ${ok}/${services.length} services`, { ok, failed, total: services.length });
  return { ok, failed };
}

async function deregisterAll() {
  await Promise.allSettled(
    services.map((svc) => fetch(`${REGISTRY_URL}/services/${svc.name}`, { method: 'DELETE' }).catch(() => {})),
  );
  log.audit('registration', 'Bench fleet deregistered', { count: services.length });
}

process.on('SIGINT', async () => { await deregisterAll(); process.exit(0); });
process.on('SIGTERM', async () => { await deregisterAll(); process.exit(0); });

app.listen(PORT, async () => {
  console.log(`\n🧪 Bench fleet: ${services.length} mock services on port ${PORT}`);
  console.log(`   ${services.filter((s) => s.name.startsWith('llm-bench')).length} llm-bench-*, ${services.filter((s) => s.name.startsWith('vision-bench')).length} vision-bench-*`);
  const { ok, failed } = await registerAll();
  console.log(`   Registered ${ok}/${services.length} with registry at ${REGISTRY_URL}${failed ? ` (${failed} failed — is the registry up?)` : ''}`);
});

module.exports = { services };
