/**
 * Realms this system creates itself, and the console's own client.
 * ─────────────────────────────────────────────────────────────────────────────
 * In standby, realms arrive by synchronisation. Two things still have to exist
 * locally:
 *
 *  - The `platform` realm, when there is no primary system to copy it from (a
 *    fresh deployment, or after the primary was retired): created once, with
 *    the console client `iam-admin-ui`, the platform-admin / tenant-admin roles
 *    and a first administrator whose one-time password is written to a private
 *    file — never to a log.
 *  - The console's registration as a client of THIS system: its callback on
 *    this host, and a client secret generated here (secrets are never copied
 *    from the primary). Both live in the client's local overlay, which
 *    synchronisation does not touch.
 */

const crypto = require('crypto');
const { STANDARD_SCOPES, DEFAULT_DEFAULT_SCOPES, DEFAULT_OPTIONAL_SCOPES } = require('./mappers');
const { DEFAULT_POLICY } = require('./password-policy');
const { sha256b64, randomToken } = require('./util');

const CONSOLE_CLIENT_ID = 'iam-admin-ui';
const PLATFORM_REALM = 'platform';
const BFF_SECRET_KEY = 'idp:bff:client-secret';
const BOOTSTRAP_MARKER = 'idp:bootstrap:platform';

const role = (name, description, extra = {}) => ({
  id: crypto.randomUUID(), name, description, composite: false, composites: { realm: [], client: {} }, attributes: {}, source: 'local', ...extra,
});

/** A new realm with Keycloak's defaults: standard scopes, default roles, brute-force protection. */
async function createRealm(store, keyring, { name, displayName = null, roles = [], managedBy = 'iam-platform' }) {
  await store.putRealm({
    name, id: crypto.randomUUID(), displayName, enabled: true,
    accessTokenLifespan: 300, ssoSessionIdleTimeout: 1800, ssoSessionMaxLifespan: 36000,
    revokeRefreshToken: true, refreshTokenMaxReuse: 0, passwordPolicy: DEFAULT_POLICY,
    bruteForceProtected: true, failureFactor: 30, maxFailureWaitSeconds: 900, loginWithEmailAllowed: true,
    defaultRole: `default-roles-${name}`, source: 'local', managedBy, createdAt: new Date().toISOString(),
  });
  for (const scope of STANDARD_SCOPES) await store.putScope(name, { ...scope, id: crypto.randomUUID(), source: 'local' });
  await store.putRealmRole(name, role('offline_access', '${role_offline-access}'));
  await store.putRealmRole(name, role('uma_authorization', '${role_uma_authorization}'));
  await store.putRealmRole(name, role(`default-roles-${name}`, '${role_default-roles}', {
    composite: true, composites: { realm: ['offline_access', 'uma_authorization'], client: {} },
  }));
  for (const extra of roles) await store.putRealmRole(name, role(extra.name, extra.description, extra));
  await keyring.ensure(name);
  return store.getRealm(name);
}

function newClient(clientId, fields = {}) {
  return {
    id: crypto.randomUUID(), clientId, name: null, description: null, enabled: true, publicClient: false, bearerOnly: false,
    standardFlowEnabled: true, serviceAccountsEnabled: false, directAccessGrantsEnabled: false, implicitFlowEnabled: false,
    fullScopeAllowed: true, redirectUris: [], postLogoutRedirectUris: [], webOrigins: [], pkceRequired: true,
    defaultClientScopes: [...DEFAULT_DEFAULT_SCOPES], optionalClientScopes: [...DEFAULT_OPTIONAL_SCOPES],
    mappers: [], attributes: {}, source: 'local', createdAt: new Date().toISOString(), ...fields,
  };
}

/** The console client as the primary system defines it (section 5.5 A). */
const consoleClientDefinition = () => newClient(CONSOLE_CLIENT_ID, {
  name: 'IAM administration console',
  mappers: [
    { name: 'realm roles', type: 'realm-roles', claim: 'realm_access.roles', multivalued: true, tokens: ['access', 'id', 'userinfo'] },
    { name: 'tenants', type: 'user-attribute', claim: 'tenants', attribute: 'tenants', multivalued: true, tokens: ['access', 'id', 'userinfo'] },
  ],
});

function createBootstrap({ store, keyring, credentials, sealer, log, publicUrl, writeSecretFile }) {
  const { redis } = store;
  const callback = `${publicUrl}/login/oauth2/code/keycloak`;
  const logoutDone = `${publicUrl}/logout/complete`;

  async function ensurePlatformRealm({ syncConfigured }) {
    if (await store.getRealm(PLATFORM_REALM)) return 'exists';
    if (syncConfigured && process.env.IDP_BOOTSTRAP_PLATFORM !== 'true') {
      log.warn('idp', `Realm '${PLATFORM_REALM}' does not exist yet; it is expected from the first synchronisation`);
      return 'awaiting-sync';
    }
    if (!(await redis.set(BOOTSTRAP_MARKER, JSON.stringify({ at: new Date().toISOString() }), 'NX'))) return 'claimed';

    await createRealm(store, keyring, {
      name: PLATFORM_REALM, displayName: 'Platform',
      roles: [
        { name: 'platform-admin', description: 'Administers every tenant and the platform itself' },
        { name: 'tenant-admin', description: 'Administers the tenants listed in the account\'s tenants attribute' },
      ],
    });
    await store.createClient(PLATFORM_REALM, consoleClientDefinition());

    const username = process.env.IDP_BOOTSTRAP_ADMIN_USERNAME || 'padmin';
    const password = `${randomToken(18)}Aa1`;
    // Written before the account exists: if it cannot be, there is nothing to be locked out of.
    writeSecretFile(password);
    const id = crypto.randomUUID();
    await store.createUser(PLATFORM_REALM, {
      id, username, email: null, emailVerified: false, firstName: null, lastName: null, enabled: true,
      attributes: {}, requiredActions: ['UPDATE_PASSWORD'], createdTimestamp: Date.now(),
      realmRoles: [`default-roles-${PLATFORM_REALM}`, 'platform-admin'], clientRoles: {}, groups: [], source: 'local',
    });
    await credentials.setPassword(PLATFORM_REALM, id, password, { temporary: true });
    log.audit('idp', `Created realm '${PLATFORM_REALM}' with console administrator '${username}' (one-time password in a private file)`, { realm: PLATFORM_REALM, username });
    return 'created';
  }

  /**
   * Registers the console with this system and returns its client secret.
   * The callback URIs are added to the client's local overlay; the secret is
   * generated here once and kept sealed, its hash on the overlay.
   */
  async function ensureConsoleClient() {
    const client = await store.getClient(PLATFORM_REALM, CONSOLE_CLIENT_ID);
    if (!client) return null;
    // Instances booting together take turns, so the sealed secret and the
    // overlay's hash are always written by the same one.
    const lock = `${BFF_SECRET_KEY}:lock`;
    for (let attempt = 0; attempt < 100 && !(await redis.set(lock, String(process.pid), 'EX', 30, 'NX')); attempt++) {
      await new Promise((resolve) => { setTimeout(resolve, 100); });
    }
    try {
      return await registerConsole();
    } finally {
      await redis.del(lock);
    }
  }

  async function registerConsole() {
    let secret = null;
    const sealed = await redis.get(BFF_SECRET_KEY);
    if (sealed) {
      try { secret = sealer.unseal(sealed); } catch { secret = null; }
    }
    const overlay = await store.updateClientLocal(PLATFORM_REALM, CONSOLE_CLIENT_ID, (current) => {
      const add = (list, value) => [...new Set([...(list || []), value])];
      const next = {
        ...current,
        extraRedirectUris: add(current.extraRedirectUris, callback),
        extraPostLogoutRedirectUris: add(current.extraPostLogoutRedirectUris, logoutDone),
        extraWebOrigins: add(current.extraWebOrigins, new URL(publicUrl).origin),
      };
      if (!secret || current.secretHash !== sha256b64(secret)) {
        secret = randomToken(32);
        next.secretHash = sha256b64(secret);
        next.secretRotatedAt = new Date().toISOString();
      }
      return next;
    });
    if (overlay.secretHash === sha256b64(secret)) await redis.set(BFF_SECRET_KEY, sealer.seal(secret));
    return { clientId: CONSOLE_CLIENT_ID, redirectUri: callback, postLogoutRedirectUri: logoutDone };
  }

  /**
   * The console's current secret, read each time it is needed: when several
   * instances boot together, the one whose write landed last decides it.
   */
  async function consoleSecret() {
    const sealed = await redis.get(BFF_SECRET_KEY);
    if (!sealed) return null;
    try { return sealer.unseal(sealed); } catch { return null; }
  }

  return { ensurePlatformRealm, ensureConsoleClient, consoleSecret, callback, logoutDone };
}

module.exports = { createBootstrap, createRealm, newClient, consoleClientDefinition, CONSOLE_CLIENT_ID, PLATFORM_REALM };
