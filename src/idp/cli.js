#!/usr/bin/env node
/**
 * Operating the identity provider from a shell, with the gateway's own
 * REDIS_URL and JWT_SECRET (read from the environment or .env).
 *
 *   npm run idp -- mode                         show standby / primary
 *   npm run idp -- mode primary                 switch (audited; every instance follows within seconds)
 *   npm run idp -- sync-status                  last synchronisation of each realm
 *   npm run idp -- keys <realm>                 the realm's signing keys
 *   npm run idp -- rotate-key <realm>           new active key; the previous stays published as passive
 *   npm run idp -- retire-key <realm> <kid>     stop publishing a passive key
 *   npm run idp -- client-secret <realm> <id>   issue this system's secret for a confidential client (printed once)
 *   npm run idp -- create-user <realm> <username> <email>
 *                                               a local account with a one-time password (printed once)
 *   npm run idp -- grant-role <realm> <username> <role>
 *                                               a realm role, e.g. platform-admin or tenant-admin in realm platform
 *   npm run idp -- set-tenants <username> <tenant,tenant>
 *                                               the tenants a platform-realm tenant-admin administers
 *   npm run idp -- forget-realm <realm> --yes   remove a realm here (e.g. a bootstrapped one sync should replace)
 *   npm run idp -- seed-demo                    demo tenants for trying the console without a primary IdP
 *
 * Account and role commands are administrative changes: they are refused in
 * standby, as the console's are.
 */

require('../local-env');
const crypto = require('crypto');
const Redis = require('ioredis');
const { createStore } = require('./store');
const { createKeyring } = require('./keys');
const { createCredentials } = require('./credentials');
const { createMode } = require('./mode');
const { createSealer, sha256b64, randomToken } = require('./util');
const { createRealm, newClient } = require('./bootstrap');
const { createLogger } = require('../logger');
const { STATUS_KEY } = require('./sync');

const log = createLogger('idp-cli');

function fail(message) {
  console.error(message);
  process.exit(1);
}

async function seedDemo({ store, keyring, credentials, mode }) {
  if ((await mode.get()).mode !== 'primary') fail('seed-demo writes realms; switch to primary mode first (npm run idp -- mode primary).');
  const base = (process.env.DEMO_APP_BASE_URL || 'https://localhost:5173').replace(/\/+$/, '');
  const passwords = {};
  const password = (name) => { passwords[name] = `${randomToken(9)}-Aa1`; return passwords[name]; };
  const role = (name, extra = {}) => ({ id: crypto.randomUUID(), name, description: null, composite: false, composites: { realm: [], client: {} }, attributes: {}, source: 'local', ...extra });

  async function user(realm, username, fields = {}) {
    const existing = await store.findUserByUsername(realm, username);
    if (existing) return existing;
    const settings = await store.getRealm(realm);
    const doc = {
      id: crypto.randomUUID(), username, email: `${username}@${realm}.demo`, emailVerified: true, firstName: null, lastName: null, enabled: true,
      attributes: {}, requiredActions: [], createdTimestamp: Date.now(), realmRoles: [settings.defaultRole], clientRoles: {}, groups: [], source: 'local', ...fields,
      ...(fields.realmRoles ? { realmRoles: [settings.defaultRole, ...fields.realmRoles] } : {}),
    };
    await store.createUser(realm, doc);
    await credentials.setPassword(realm, doc.id, password(`${realm}/${username}`));
    return doc;
  }

  // samta: MapDashboard, its permissions and roles.
  if (!(await store.getRealm('samta'))) {
    await createRealm(store, keyring, { name: 'samta', displayName: 'Samta' });
    await store.putScope('samta', {
      id: crypto.randomUUID(), name: 'mapdashboard-roles', includeInTokenScope: false, source: 'local',
      mappers: [{ name: 'md roles', type: 'client-roles', clientId: 'samta-mapdashboard-web-poc', claim: 'md_roles', multivalued: true, tokens: ['access', 'id'] }],
    });
    await store.createClient('samta', newClient('samta-mapdashboard-web-poc', {
      name: 'MapDashboard', redirectUris: [`${base}/signin-oidc`], postLogoutRedirectUris: [`${base}/signout-callback-oidc`], webOrigins: [base],
      defaultClientScopes: ['profile', 'email', 'roles', 'web-origins', 'acr', 'basic', 'mapdashboard-roles'],
    }));
    const md = 'samta-mapdashboard-web-poc';
    const perms = [['objects.read', 'Objects', 'View objects.'], ['objects.edit', 'Objects', 'Edit objects.'], ['layers.view', 'Layers', 'View layers.'], ['layers.manage', 'Layers', 'Manage layers.']];
    for (const [key, category, description] of perms) await store.putClientRole('samta', { ...role(`perm:${key}`, { description, attributes: { category: [category] } }), clientId: md });
    const composite = (keys) => ({ realm: [], client: { [md]: keys.map((key) => `perm:${key}`) } });
    await store.putClientRole('samta', { ...role('role:admin', { composite: true, composites: composite(perms.map(([key]) => key)), attributes: { system: ['true'] }, description: 'Everything' }), clientId: md });
    await store.putClientRole('samta', { ...role('role:operator', { composite: true, composites: composite(['objects.read', 'layers.view']), description: 'Day-to-day operation' }), clientId: md });
    await store.putClientRole('samta', { ...role('role:viewer', { composite: true, composites: composite(['objects.read']), description: 'Read only' }), clientId: md });
    await user('samta', 'operator1', { firstName: 'Operator', lastName: 'One', clientRoles: { [md]: ['role:operator'] } });
    await user('samta', 'viewer1', { firstName: 'Viewer', lastName: 'One', clientRoles: { [md]: ['role:viewer'] } });
  }

  // tenant-alpha: the business-api scope, the React and native samples.
  if (!(await store.getRealm('tenant-alpha'))) {
    await createRealm(store, keyring, {
      name: 'tenant-alpha', displayName: 'Tenant Alpha',
      roles: [{ name: 'tenant-user', description: 'A member of this tenant' }, { name: 'tenant-admin', description: 'Administers this tenant', composite: true, composites: { realm: ['tenant-user'], client: {} } }],
    });
    await store.putScope('tenant-alpha', {
      id: crypto.randomUUID(), name: 'business-api', includeInTokenScope: true, source: 'local',
      mappers: [
        { name: 'business-api audience', type: 'audience', audience: 'business-api', tokens: ['access', 'introspection'] },
        { name: 'authz version', type: 'hardcoded', claim: 'authz_version', value: '0', jsonType: 'int', tokens: ['access', 'introspection'] },
        { name: 'tenant', type: 'hardcoded', claim: 'tenant', value: 'tenant-alpha', jsonType: 'String', tokens: ['access', 'id', 'introspection'] },
      ],
    });
    await store.createClient('tenant-alpha', newClient('tenant-alpha.react-reference.poc', {
      name: 'React reference', publicClient: true, redirectUris: [`${base}/auth/callback`], postLogoutRedirectUris: [`${base}/`], webOrigins: [base],
      defaultClientScopes: ['profile', 'email', 'roles', 'web-origins', 'acr', 'basic', 'business-api'],
      mappers: [
        { name: 'realm roles', type: 'realm-roles', claim: 'realm_access.roles', multivalued: true, tokens: ['access', 'id', 'userinfo'] },
        { name: 'react api audience', type: 'audience', audience: 'react-reference-api', tokens: ['access'] },
        { name: 'tenant', type: 'hardcoded', claim: 'tenant', value: 'tenant-alpha', tokens: ['access', 'id', 'userinfo'] },
      ],
    }));
    await store.createClient('tenant-alpha', newClient('tenant-alpha.python-native.poc', {
      name: 'Python native sample', publicClient: true, redirectUris: ['http://127.0.0.1/callback', 'com.samta.pydemo:/callback'],
      postLogoutRedirectUris: ['http://127.0.0.1/logged-out'],
      mappers: [
        { name: 'client roles', type: 'client-roles', clientId: 'tenant-alpha.python-native.poc', claim: 'resource_access.${client_id}.roles', multivalued: true, tokens: ['access', 'id', 'userinfo'] },
        { name: 'python api audience', type: 'audience', audience: 'python-demo-api', tokens: ['access'] },
      ],
    }));
    await user('tenant-alpha', 'alice', { firstName: 'Alice', lastName: 'Alpha', realmRoles: ['tenant-admin'] });
    await user('tenant-alpha', 'bob', { firstName: 'Bob', lastName: 'Alpha', realmRoles: ['tenant-user'] });
  }

  // platform: a tenant administrator, and permission approval for padmin.
  const approver = 'approve-permissions:samta-mapdashboard-web-poc';
  if (!(await store.getRealmRole('platform', approver))) await store.putRealmRole('platform', role(approver, { description: 'Approves MapDashboard permission imports' }));
  await user('platform', 'tadmin', { attributes: { tenants: ['tenant-alpha'] }, realmRoles: ['tenant-admin'] });
  const padmin = await store.findUserByUsername('platform', process.env.IDP_BOOTSTRAP_ADMIN_USERNAME || 'padmin');
  if (padmin) await store.updateUser('platform', padmin.id, (u) => ({ ...u, realmRoles: [...new Set([...(u.realmRoles || []), approver])] }));

  log.audit('idp', 'Demo realms seeded', { realms: ['samta', 'tenant-alpha'] });
  console.log('Demo realms ready. Passwords of the accounts created now (shown once):');
  for (const [name, value] of Object.entries(passwords)) console.log(`  ${name.padEnd(28)} ${value}`);
}

async function main() {
  const [command, ...args] = process.argv.slice(2);
  if (!command || command === 'help') {
    console.log(require('fs').readFileSync(__filename, 'utf8').split('*/')[0].split('\n').slice(2).map((l) => l.replace(/^ \* ?/, '')).join('\n'));
    return;
  }
  const secret = process.env.JWT_SECRET;
  if (!secret) fail('JWT_SECRET must be set (the same value as the gateway).');
  const redis = new Redis(process.env.REDIS_URL || 'redis://localhost:7000', { maxRetriesPerRequest: 2 });
  const store = createStore(redis);
  const keyring = createKeyring({ store, sealer: createSealer(secret, 'signing-keys'), log });
  const credentials = createCredentials({ store, sealer: createSealer(secret, 'credentials') });
  const mode = createMode({ redis, log, initial: process.env.IDP_MODE });
  const actor = `cli:${require('os').userInfo().username}`;
  const realmArg = async (name) => { if (!(await store.getRealm(name))) fail(`No realm '${name}'.`); return name; };
  const primaryOnly = async () => {
    if ((await mode.get({ fresh: true })).mode !== 'primary') fail('This is an administrative change; in standby, make it in the primary system (or switch: npm run idp -- mode primary).');
  };

  try {
    switch (command) {
      case 'mode':
        if (args[0]) console.log(JSON.stringify(await mode.set(args[0], actor)));
        else console.log(JSON.stringify(await mode.get({ fresh: true })));
        break;
      case 'sync-status': {
        const all = await redis.hgetall(STATUS_KEY);
        for (const [realm, raw] of Object.entries(all)) {
          const s = JSON.parse(raw);
          console.log(`${realm.padEnd(20)} ${s.ok ? 'ok   ' : 'FAIL '} last success ${s.lastSuccess || 'never'}${s.error ? `  (${s.error})` : ''}`);
        }
        break;
      }
      case 'keys':
        console.table(await keyring.describe(await realmArg(args[0])));
        break;
      case 'rotate-key':
        console.log(`New active key: ${await keyring.rotate(await realmArg(args[0]))}`);
        break;
      case 'retire-key':
        console.log(await keyring.retire(await realmArg(args[0]), args[1]));
        break;
      case 'client-secret': {
        const realm = await realmArg(args[0]);
        const client = await store.getClient(realm, args[1]);
        if (!client) fail(`No client '${args[1]}' in realm '${realm}'.`);
        if (client.publicClient || client.bearerOnly) fail('Only a confidential client has a secret.');
        const value = randomToken(32);
        await store.updateClientLocal(realm, client.clientId, (local) => ({ ...local, secretHash: sha256b64(value), secretRotatedAt: new Date().toISOString() }));
        log.audit('idp', `A new secret was issued for client '${client.clientId}' of realm '${realm}' from the command line`, { realm, clientId: client.clientId, actor });
        console.log(value);
        break;
      }
      case 'create-user': {
        await primaryOnly();
        const realm = await realmArg(args[0]);
        const [username, email] = [String(args[1] || '').toLowerCase(), args[2]];
        if (!/^[a-z0-9._-]{1,64}$/.test(username)) fail('The username must be lowercase letters, digits, dot, dash or underscore.');
        const settings = await store.getRealm(realm);
        const id = crypto.randomUUID();
        const outcome = await store.createUser(realm, {
          id, username, email: email || null, emailVerified: false, firstName: null, lastName: null, enabled: true, attributes: {},
          requiredActions: ['UPDATE_PASSWORD'], createdTimestamp: Date.now(), realmRoles: [settings.defaultRole], clientRoles: {}, groups: [], source: 'local',
        });
        if (outcome !== 'ok') fail(`A user with that ${outcome} already exists.`);
        const password = `${randomToken(15)}-Aa1`;
        await credentials.setPassword(realm, id, password, { temporary: true });
        log.audit('idp', `User '${username}' created in realm '${realm}' from the command line`, { realm, userId: id, actor });
        console.log(`Created ${username} (${id}). One-time password, to be replaced at first sign-in:\n${password}`);
        break;
      }
      case 'grant-role': {
        await primaryOnly();
        const realm = await realmArg(args[0]);
        const user = await store.findUserByUsername(realm, args[1] || '');
        if (!user) fail(`No user '${args[1]}' in realm '${realm}'.`);
        if (!(await store.getRealmRole(realm, args[2] || ''))) fail(`No realm role '${args[2]}' in realm '${realm}'.`);
        await store.updateUser(realm, user.id, (u) => ({ ...u, realmRoles: [...new Set([...(u.realmRoles || []), args[2]])] }));
        log.audit('idp', `Role '${args[2]}' granted to '${user.username}' in realm '${realm}' from the command line`, { realm, userId: user.id, actor });
        console.log(`Granted ${args[2]} to ${user.username}.`);
        break;
      }
      case 'set-tenants': {
        await primaryOnly();
        const user = await store.findUserByUsername('platform', args[0] || '');
        if (!user) fail(`No user '${args[0]}' in realm 'platform'.`);
        const tenants = String(args[1] || '').split(',').map((t) => t.trim()).filter(Boolean);
        await store.updateUser('platform', user.id, (u) => ({ ...u, attributes: { ...(u.attributes || {}), tenants } }));
        log.audit('idp', `Tenants of '${user.username}' set to ${tenants.join(', ') || 'none'} from the command line`, { userId: user.id, actor });
        console.log(`${user.username} administers: ${tenants.join(', ') || '(none)'}`);
        break;
      }
      case 'forget-realm': {
        const realm = await realmArg(args[0]);
        if (args[1] !== '--yes') fail(`This removes every user, client, key and session of realm '${realm}' here. Repeat with --yes.`);
        let cursor = '0';
        do {
          const [next, keys] = await redis.scan(cursor, 'MATCH', `idp:${realm}:*`, 'COUNT', 500);
          if (keys.length) await redis.del(...keys);
          cursor = next;
        } while (cursor !== '0');
        await redis.multi().del(`idp:realm:${realm}`).srem('idp:realms', realm).hdel(STATUS_KEY, realm).exec();
        if (realm === 'platform') await redis.del('idp:bootstrap:platform', 'idp:bff:client-secret');
        log.audit('idp', `Realm '${realm}' removed from this system from the command line`, { realm, actor });
        console.log(`Realm '${realm}' removed. The next synchronisation brings it back from the primary IdP, if it has one.`);
        break;
      }
      case 'seed-demo':
        await seedDemo({ store, keyring, credentials, mode });
        break;
      default:
        fail(`Unknown command '${command}'. Try: npm run idp -- help`);
    }
  } finally {
    redis.disconnect();
  }
}

main().catch((err) => fail(err.message));
