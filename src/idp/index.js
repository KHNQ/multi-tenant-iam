/**
 * The secondary (failover) identity provider.
 * ─────────────────────────────────────────────────────────────────────────────
 * A Keycloak-compatible OpenID Connect provider with realms, issuing the same
 * token contract as the primary IdP so applications accept it with
 * configuration only (they trust both issuers). It has no runtime dependency on
 * the primary: synchronisation reads from it when it can, and everything here
 * keeps working when it cannot.
 *
 *   store.js        realms, users, roles, clients, scopes, groups in Redis
 *   keys.js         per-realm RS256 keys, rotation, JWKS
 *   sessions.js     SSO sessions, codes, rotating refresh tokens
 *   mappers.js      the token contract (claim mappers, client scopes)
 *   tokens.js       issuing access / ID / UserInfo
 *   protocol.js     the /realms/{realm}/protocol/openid-connect endpoints
 *   sync.js         one-way synchronisation from Keycloak
 *   credentials.js  imported Argon2 hashes and passwords set here
 *   mode.js         standby / primary
 *   operations.js   health, metrics, credential import
 *   bootstrap.js    the platform realm and the console's client
 *
 * See docs/failover-idp.md.
 */

const { createStore } = require('./store');
const { createKeyring } = require('./keys');
const { createSessions } = require('./sessions');
const { createTokenService } = require('./tokens');
const { createProtocol } = require('./protocol');
const { createCredentials } = require('./credentials');
const { createMode } = require('./mode');
const { createSync, syncConfigFromEnv } = require('./sync');
const { createOperations } = require('./operations');
const { createBootstrap } = require('./bootstrap');
const { createSealer } = require('./util');
const { createRateLimiter } = require('../ratelimit');

/**
 * @param {object} deps
 * @param {import('ioredis').Redis} deps.redis
 * @param {object} deps.log
 * @param {object} deps.metrics  metrics.js registry
 * @param {string} deps.publicUrl the URL this system is reached at (issuers are `${publicUrl}/realms/{realm}`)
 * @param {string} deps.secret   JWT_SECRET, from which sealing and form keys are derived
 * @param {(password: string) => void} deps.writeSecretFile delivers the bootstrap admin's one-time password
 */
function createIdp({
  redis, log, metrics, publicUrl, secret, writeSecretFile, removeSecretFile = () => {}, env = process.env, fetchImpl,
}) {
  const base = String(env.IDP_PUBLIC_URL || publicUrl).replace(/\/+$/, '');
  const issuerFor = (realm) => `${base}/realms/${realm}`;
  const secureCookies = base.startsWith('https:');

  const store = createStore(redis);
  const keyring = createKeyring({ store, sealer: createSealer(secret, 'signing-keys'), log });
  const sessions = createSessions({ redis });
  const tokens = createTokenService({ store, keyring, issuerFor });
  const credentials = createCredentials({ store, sealer: createSealer(secret, 'credentials') });
  const sealer = createSealer(secret, 'client-secrets');
  const limiter = createRateLimiter(redis, { prefix: 'idp-rl' });
  const syncConfig = syncConfigFromEnv(env);
  const initialMode = env.IDP_MODE || (syncConfig.configured ? 'standby' : 'primary');
  const mode = createMode({ redis, log, initial: initialMode });

  const counters = {
    loginAttempts: metrics.counter('iam_idp_login_attempts_total', 'Sign-in attempts at the identity provider, by realm', ['realm']),
    logins: metrics.counter('iam_idp_logins_total', 'Successful sign-ins at the identity provider, by realm', ['realm']),
    loginFailures: metrics.counter('iam_idp_login_failures_total', 'Failed sign-ins, by realm and reason', ['realm', 'reason']),
    refreshes: metrics.counter('iam_idp_refresh_total', 'Refresh token uses, by realm and outcome', ['realm', 'outcome']),
    logouts: metrics.counter('iam_idp_logouts_total', 'Sessions ended by logout, by realm', ['realm']),
    syncErrors: metrics.counter('iam_idp_sync_errors_total', 'Failed synchronisations of a realm from the primary IdP', ['realm']),
  };

  const sync = createSync({ store, sessions, keyring, mode, log, metrics: counters, config: syncConfig, fetchImpl });
  // The first administrator's one-time password file goes once it has been replaced, as the gateway's does.
  const bootstrapAdmin = env.IDP_BOOTSTRAP_ADMIN_USERNAME || 'padmin';
  const onPasswordReplaced = (realm, user) => { if (realm === 'platform' && user.username === bootstrapAdmin) removeSecretFile(); };
  const protocol = createProtocol({
    store, keyring, sessions, tokens, credentials, mode, limiter, log, metrics: counters, secret, issuerFor, secureCookies, onPasswordReplaced,
  });
  const operations = createOperations({ store, keyring, sessions, credentials, mode, sync, log, metrics, redis, env });
  const bootstrap = createBootstrap({ store, keyring, credentials, sealer, log, publicUrl: base, writeSecretFile });

  async function init() {
    const current = await mode.init();
    for (const name of await store.listRealmNames()) await keyring.ensure(name);
    const platform = await bootstrap.ensurePlatformRealm({ syncConfigured: syncConfig.configured });
    const admin = await store.findUserByUsername('platform', bootstrapAdmin);
    if (admin && admin.source === 'local' && !(admin.requiredActions || []).includes('UPDATE_PASSWORD')) removeSecretFile();
    const consoleClient = await bootstrap.ensureConsoleClient();
    if (!consoleClient) log.warn('idp', "The console client 'iam-admin-ui' does not exist in realm 'platform' yet; the console cannot sign in until it does");
    if (syncConfig.configured) sync.start();
    log.info('idp', `Identity provider ready: mode ${current.mode}, issuers ${issuerFor('{realm}')}, sync ${syncConfig.configured ? `every ${syncConfig.intervalSeconds}s from ${syncConfig.url}` : 'not configured'}`, {
      mode: current.mode, platform,
    });
  }

  /** Re-registers the console client: after a sync created it, or after its overlay was cleared. */
  const ensureConsoleClient = () => bootstrap.ensureConsoleClient();

  return {
    init, routers: [operations.router, protocol.router],
    store, keyring, sessions, tokens, credentials, mode, sync, protocol, operations, bootstrap,
    issuerFor, publicUrl: base, secureCookies, ensureConsoleClient, sealer,
  };
}

module.exports = { createIdp };
