/**
 * Load-test seed phase.
 *
 * Sets up everything the load test itself measures, but which shouldn't be
 * counted AS the load test: defines `tierCount` roles, partitions the bench
 * fleet's services across them, grants each tier read access to its slice,
 * creates `userCount` accounts, and assigns each 1-3 tiers at random (seeded,
 * so re-runs with the same --seed reproduce the same distribution).
 *
 * Prerequisite: registry + gateway + mock-services.js all running, with the
 * bench fleet already registered (mock-services.js registers itself).
 *
 * Run with: node src/loadtest/seed.js [--users=1000] [--tiers=10] [--seed=1337]
 * Writes:   src/loadtest/.state/state.json
 */

const fs = require('fs');
const path = require('path');
const { makeRng } = require('./lib/rng');
const { runPool } = require('./lib/pool');
const { timedRequest, makeAgent } = require('./lib/http');

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
  registry: argv.registry || 'http://localhost:3001',
  userCount: Number(argv.users || 1000),
  tierCount: Number(argv.tiers || 10),
  expectedServices: Number(argv.services || 50),
  setupConcurrency: Number(argv.concurrency || 32),
  seed: Number(argv.seed || 1337),
  stateFile: argv.state || path.join(__dirname, '.state', 'state.json'),
  fixedPassword: 'Bench!Passw0rd', // load-test-only accounts, not a security-relevant secret
};

const agent = makeAgent(CONFIG.setupConcurrency + 8);
const rng = makeRng(CONFIG.seed);

function fmtSecs(ms) {
  return `${(ms / 1000).toFixed(1)}s`;
}

async function adminLogin() {
  const res = await timedRequest('POST', `${CONFIG.gateway}/auth/login`, {
    body: { username: 'admin', password: 'adminpass' },
    agent,
  });
  if (res.status !== 200) {
    throw new Error(`Admin login failed (status ${res.status}): ${JSON.stringify(res.body)}`);
  }
  return res.body.token;
}

async function fetchBenchServices() {
  const res = await timedRequest('GET', `${CONFIG.registry}/services?status=active`, { agent });
  if (res.status !== 200) throw new Error(`Registry lookup failed: status ${res.status}`);
  return res.body.services
    .map((s) => s.name)
    .filter((n) => n.startsWith('llm-bench-') || n.startsWith('vision-bench-'))
    .sort();
}

async function waitForBenchFleet(expectedMin, tries = 30) {
  for (let i = 0; i < tries; i++) {
    const names = await fetchBenchServices();
    if (names.length >= expectedMin) return names;
    process.stdout.write(`\r  waiting for bench fleet to register (${names.length}/${expectedMin})...`);
    await new Promise((r) => setTimeout(r, 1000));
  }
  throw new Error(
    `Only found ${(await fetchBenchServices()).length} bench services registered after ${tries}s. ` +
    `Is mock-services.js running? (node src/loadtest/mock-services.js)`,
  );
}

function buildTiers(serviceNames, tierCount) {
  const tiers = {};
  const perTier = Math.ceil(serviceNames.length / tierCount);
  for (let i = 0; i < tierCount; i++) {
    const tierName = `tier${String(i + 1).padStart(2, '0')}`;
    tiers[tierName] = serviceNames.slice(i * perTier, (i + 1) * perTier);
  }
  return tiers;
}

async function defineRole(adminToken, role) {
  const res = await timedRequest('POST', `${CONFIG.gateway}/admin/roles/define`, {
    token: adminToken, body: { role }, agent,
  });
  if (res.status !== 201 && res.status !== 409) {
    throw new Error(`Failed to define role '${role}': ${res.status} ${JSON.stringify(res.body)}`);
  }
}

async function addPolicy(adminToken, subject, resource, action) {
  const res = await timedRequest('POST', `${CONFIG.gateway}/admin/policies`, {
    token: adminToken, body: { subject, resource, action }, agent,
  });
  if (res.status !== 200) {
    throw new Error(`Failed to add policy ${subject}/${resource}/${action}: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

async function removePolicy(adminToken, subject, resource, action) {
  const res = await timedRequest('DELETE', `${CONFIG.gateway}/admin/policies`, {
    token: adminToken, body: { subject, resource, action }, agent,
  });
  if (res.status !== 200 && res.status !== 404) {
    throw new Error(`Failed to remove policy ${subject}/${resource}/${action}: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

/**
 * Every currently-defined policy whose subject is one of THIS run's tier
 * names. Needed for the same reason fetchCurrentTierRoles is: a previous
 * seed.js invocation with a different --tiers/--services shape (e.g. an
 * earlier smoke test) may have defined the SAME tier names against a
 * DIFFERENT, incompatible service partition. Casbin policies are pure
 * (subject, resource, action) tuples with no notion of "which run created
 * this" — a stale tier03 -> /some-old-service policy from that run silently
 * grants real access to any user who holds tier03 under the CURRENT
 * partition, unless it's explicitly diffed out here.
 */
async function fetchCurrentTierPolicies(adminToken, tierNameSet) {
  const res = await timedRequest('GET', `${CONFIG.gateway}/admin/policies`, { token: adminToken, agent });
  if (res.status !== 200) throw new Error(`Failed to list policies: ${res.status}`);
  return res.body.policies.filter((p) => tierNameSet.has(p.subject));
}

async function signupUser(username, password) {
  const res = await timedRequest('POST', `${CONFIG.gateway}/auth/signup`, {
    body: { username, password }, agent,
  });
  // 409 = already exists from a previous seed run; treat as success (idempotent re-seed)
  if (res.status !== 201 && res.status !== 409) {
    throw new Error(`Signup failed for ${username}: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

async function assignRole(adminToken, username, role) {
  const res = await timedRequest('POST', `${CONFIG.gateway}/admin/roles`, {
    token: adminToken, body: { username, role }, agent,
  });
  if (res.status !== 200) {
    throw new Error(`Role assign failed for ${username}/${role}: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

async function revokeRole(adminToken, username, role) {
  const res = await timedRequest('DELETE', `${CONFIG.gateway}/admin/roles`, {
    token: adminToken, body: { username, role }, agent,
  });
  // 404 = didn't actually have it (fine, another lane already revoked it, or it was never there)
  if (res.status !== 200 && res.status !== 404) {
    throw new Error(`Role revoke failed for ${username}/${role}: ${res.status} ${JSON.stringify(res.body)}`);
  }
}

/**
 * Server-side current tier-role membership for every known user. Needed
 * because seed.js must be safely re-runnable even after run.js's chaos
 * driver has been granting/revoking real roles through the real admin API
 * on a previous pass — those mutations persist in Redis and are NOT
 * reverted when run.js exits, so a naive "just POST the target roles"
 * re-seed would additively pile the new plan on top of leftover chaos
 * drift instead of reproducing it.
 */
async function fetchCurrentTierRoles(adminToken, tierNameSet) {
  const res = await timedRequest('GET', `${CONFIG.gateway}/admin/users`, { token: adminToken, agent });
  if (res.status !== 200) throw new Error(`Failed to list users: ${res.status}`);
  const map = new Map();
  for (const u of res.body.users) {
    map.set(u.username, new Set((u.roles || []).filter((r) => tierNameSet.has(r))));
  }
  return map;
}

async function loginUser(username, password) {
  const res = await timedRequest('POST', `${CONFIG.gateway}/auth/login`, {
    body: { username, password }, agent,
  });
  if (res.status !== 200) {
    throw new Error(`Login failed for ${username}: ${res.status} ${JSON.stringify(res.body)}`);
  }
  return res.body.token;
}

async function main() {
  console.log(`\n=== Load test seed ===`);
  console.log(`  users=${CONFIG.userCount} tiers=${CONFIG.tierCount} seed=${CONFIG.seed} concurrency=${CONFIG.setupConcurrency}`);

  const t0 = Date.now();
  const adminToken = await adminLogin();
  console.log(`  ✔ admin authenticated`);

  const serviceNames = await waitForBenchFleet(CONFIG.expectedServices);
  console.log(`  ✔ bench fleet visible: ${serviceNames.length} services`);

  const tiers = buildTiers(serviceNames, CONFIG.tierCount);
  const tierNames = Object.keys(tiers);

  console.log(`\n-- Defining ${tierNames.length} tiers & policies (reconciled against current server state) --`);
  const tPolicy0 = Date.now();
  for (const tier of tierNames) {
    await defineRole(adminToken, tier);
  }

  const tierNameSet = new Set(tierNames);
  const targetPolicies = new Set();
  const policyGrantJobs = [];
  for (const [tier, svcs] of Object.entries(tiers)) {
    for (const svc of svcs) {
      for (const action of ['ping', 'work']) {
        const resource = `/${svc}/${action}`;
        targetPolicies.add(`${tier}|${resource}|get`);
        policyGrantJobs.push({ tier, resource });
      }
    }
  }

  const currentPolicies = await fetchCurrentTierPolicies(adminToken, tierNameSet);
  const stalePolicies = currentPolicies.filter((p) => !targetPolicies.has(`${p.subject}|${p.resource}|${p.action}`));
  const missingPolicyJobs = policyGrantJobs.filter((job) => !currentPolicies.some(
    (p) => p.subject === job.tier && p.resource === job.resource && p.action === 'get',
  ));

  await runPool(stalePolicies, (p) => removePolicy(adminToken, p.subject, p.resource, p.action), CONFIG.setupConcurrency);
  await runPool(missingPolicyJobs, (job) => addPolicy(adminToken, job.tier, job.resource, 'get'), CONFIG.setupConcurrency);

  console.log(`  ✔ ${tierNames.length} tiers defined, ${missingPolicyJobs.length} policies granted, ${stalePolicies.length} stale policies removed (${fmtSecs(Date.now() - tPolicy0)})`);
  if (stalePolicies.length) {
    console.log(`    stale policies were leftover from a previous seed.js run with a different --tiers/--services shape:`);
    for (const p of stalePolicies.slice(0, 10)) console.log(`      ${p.subject} -> ${p.resource} (${p.action})`);
    if (stalePolicies.length > 10) console.log(`      ...and ${stalePolicies.length - 10} more`);
  }
  for (const [tier, svcs] of Object.entries(tiers)) {
    console.log(`    ${tier}: ${svcs.join(', ')}`);
  }

  console.log(`\n-- Creating ${CONFIG.userCount} users --`);
  const tSignup0 = Date.now();
  const usernames = Array.from({ length: CONFIG.userCount }, (_, i) => `bench_user_${String(i + 1).padStart(4, '0')}`);
  let signedUp = 0;
  await runPool(usernames, async (username) => {
    await signupUser(username, CONFIG.fixedPassword);
    signedUp++;
    if (signedUp % 100 === 0) process.stdout.write(`\r  signed up ${signedUp}/${usernames.length}...`);
  }, CONFIG.setupConcurrency);
  console.log(`\r  ✔ ${usernames.length} users created (${fmtSecs(Date.now() - tSignup0)}, ${(usernames.length / ((Date.now() - tSignup0) / 1000)).toFixed(1)} signups/s)`);

  console.log(`\n-- Assigning tiers (1-3 per user, seeded random, reconciled against current server state) --`);
  const tRoles0 = Date.now();
  const currentRoles = await fetchCurrentTierRoles(adminToken, tierNameSet);

  const userRoles = new Map();
  const grants = [];
  const revokes = [];
  for (const username of usernames) {
    const n = rng.int(1, 3);
    const target = new Set(rng.pickN(tierNames, n));
    userRoles.set(username, [...target]);

    const current = currentRoles.get(username) || new Set();
    for (const role of target) if (!current.has(role)) grants.push({ username, role });
    for (const role of current) if (!target.has(role)) revokes.push({ username, role });
  }

  let done = 0;
  const total = grants.length + revokes.length;
  const bump = () => { done++; if (done % 200 === 0) process.stdout.write(`\r  reconciled ${done}/${total} role changes...`); };
  await runPool(revokes, async (job) => { await revokeRole(adminToken, job.username, job.role); bump(); }, CONFIG.setupConcurrency);
  await runPool(grants, async (job) => { await assignRole(adminToken, job.username, job.role); bump(); }, CONFIG.setupConcurrency);
  console.log(`\r  ✔ ${grants.length} grants + ${revokes.length} revokes applied across ${usernames.length} users (${fmtSecs(Date.now() - tRoles0)})`);
  if (revokes.length) {
    console.log(`    ${revokes.length} revokes were leftover drift from a previous run.js chaos pass on these same accounts.`);
  }

  console.log(`\n-- Logging in ${CONFIG.userCount} users --`);
  const tLogin0 = Date.now();
  let loggedIn = 0;
  const tokens = new Map();
  await runPool(usernames, async (username) => {
    const token = await loginUser(username, CONFIG.fixedPassword);
    tokens.set(username, token);
    loggedIn++;
    if (loggedIn % 100 === 0) process.stdout.write(`\r  logged in ${loggedIn}/${usernames.length}...`);
  }, CONFIG.setupConcurrency);
  console.log(`\r  ✔ ${usernames.length} users logged in (${fmtSecs(Date.now() - tLogin0)}, ${(usernames.length / ((Date.now() - tLogin0) / 1000)).toFixed(1)} logins/s)`);

  const state = {
    generatedAt: new Date().toISOString(),
    seed: CONFIG.seed,
    config: { userCount: CONFIG.userCount, tierCount: CONFIG.tierCount },
    services: serviceNames,
    tiers,
    users: usernames.map((username) => ({
      username,
      password: CONFIG.fixedPassword,
      roles: userRoles.get(username),
      token: tokens.get(username),
    })),
    setupTimingsMs: {
      policies: Date.now() - tPolicy0,
      signup: Date.now() - tSignup0,
      roleAssignment: Date.now() - tRoles0,
      login: Date.now() - tLogin0,
      total: Date.now() - t0,
    },
  };

  fs.mkdirSync(path.dirname(CONFIG.stateFile), { recursive: true });
  fs.writeFileSync(CONFIG.stateFile, JSON.stringify(state, null, 2));

  console.log(`\n=== Seed complete in ${fmtSecs(Date.now() - t0)} ===`);
  console.log(`  state written to ${CONFIG.stateFile}`);
  console.log(`  next: node src/loadtest/run.js`);
}

main().catch((err) => {
  console.error(`\n[seed] FATAL: ${err.message}`);
  process.exit(1);
});
