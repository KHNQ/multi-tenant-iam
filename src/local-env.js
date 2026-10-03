/**
 * Loads the repository's .env for the programs people start by hand — the
 * test suites, the load-test tools and the mock services.
 *
 * start.sh already reads .env and exports it to everything it launches. This
 * is for what it does not launch: `npm run e2e` needs the platform admin's
 * password and the registry's enrollment token, and a bench fleet started with
 * `node src/loadtest/mock-services.js` needs that token too. Without this,
 * each of those is a line of exports to remember.
 *
 * Anything already set in the environment wins, and a missing .env is not an
 * error. The gateway and the registry deliberately do NOT load it: where a
 * long-running service gets its secrets is the deployment's decision.
 */

const path = require('path');

// process.loadEnvFile arrived in Node 20.12 / 21.7; before that, export the variables.
if (typeof process.loadEnvFile === 'function') {
  try {
    process.loadEnvFile(path.join(__dirname, '..', '.env'));
  } catch { /* no .env — the environment is all there is */ }
}
