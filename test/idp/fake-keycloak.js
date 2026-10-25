#!/usr/bin/env node
/**
 * A stand-in for the primary IdP (Keycloak 26), for trying the failover
 * system by hand: `./boot.sh failover` starts it. It is the acceptance tests'
 * mock (mock-keycloak.js) run as a server, serving Keycloak's Admin REST API
 * for realms platform, samta and tenant-alpha, plus three things a real
 * deployment provides elsewhere:
 *
 *   GET /health                            for boot.sh
 *   GET /export/credentials                what the operator's database export script
 *                                          produces: Keycloak argon2 hashes, ready to POST
 *                                          to /admin/sync/credentials
 *   GET /mapdashboard/permissions/catalog  MapDashboard's declared permissions
 *
 * Every account's password is <Username>-Passw0rd-1 (e.g. Padmin-Passw0rd-1).
 * Stop the process to see the failover system carry on without it.
 *
 *   FAKE_KEYCLOAK_PORT=8180 node test/idp/fake-keycloak.js
 */

const { createMockKeycloak, keycloakCredential } = require('./mock-keycloak');

const PORT = Number.parseInt(process.env.FAKE_KEYCLOAK_PORT, 10) || 8180;

const passwordOf = (username) => `${username.charAt(0).toUpperCase()}${username.slice(1)}-Passw0rd-1`;

const CATALOG = [
  { key: 'objects.read', category: 'Objects', description: 'View objects.' },
  { key: 'layers.view', category: 'Layers', description: 'View map layers and their legends.' },
  { key: 'remoteapps.manage', category: 'RemoteApps', description: 'Manage remote applications.' },
];

let mock;
let exported = null;

async function exportCredentials() {
  if (exported) return exported;
  const entries = [];
  for (const [realm, r] of Object.entries(mock.state.realms)) {
    for (const user of r.users) {
      entries.push({ realm, userId: user.id, type: 'password', createdDate: user.createdTimestamp, ...(await keycloakCredential(passwordOf(user.username))) });
    }
  }
  exported = entries;
  return entries;
}

mock = createMockKeycloak({
  async extra(req) {
    const path = req.url.split('?')[0];
    if (path === '/health') return { status: 200, body: { status: 'UP', realms: Object.keys(mock.state.realms) } };
    if (path === '/export/credentials') return { status: 200, body: await exportCredentials() };
    if (path === '/mapdashboard/permissions/catalog') return { status: 200, body: { permissions: CATALOG } };
    return null;
  },
});

mock.listen(PORT).then((port) => {
  console.log(`Fake Keycloak (Admin REST API) on http://127.0.0.1:${port}`);
  for (const [realm, r] of Object.entries(mock.state.realms)) {
    console.log(`  ${realm.padEnd(14)} ${r.users.map((u) => `${u.username} / ${passwordOf(u.username)}`).join(', ')}`);
  }
}).catch((err) => {
  console.error(`Fake Keycloak could not listen on ${PORT}: ${err.message}`);
  process.exit(1);
});

const stop = () => mock.close().then(() => process.exit(0));
process.on('SIGTERM', stop);
process.on('SIGINT', stop);

module.exports = { passwordOf };
