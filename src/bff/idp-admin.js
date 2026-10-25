/**
 * Platform settings of the identity provider itself (platform administrators):
 *
 *   GET    /api/admin/idp                              mode, sync health, realms and their keys
 *   POST   /api/admin/idp/mode        { mode }         standby | primary (audited)
 *   POST   /api/admin/idp/sync                         synchronise now
 *   POST   /api/admin/idp/realms/{realm}/keys/rotate   new active key; the old one stays published
 *   DELETE /api/admin/idp/realms/{realm}/keys/{kid}    retire a passive key
 *
 * Key rotation and retirement concern this system's own keys, so they are
 * allowed in standby; the primary system's keys are never touched.
 */

const express = require('express');
const { handle, denied, notFound, invalid, refused } = require('./http');

function createIdpAdminApi({ idp, store, log }) {
  const router = express.Router();
  const platformOnly = (req, res, next) => (req.principal.permissions.platformAdmin ? next() : denied(res));

  router.get('/admin/idp', platformOnly, handle(async (req, res) => {
    const [health, sync, current] = await Promise.all([idp.operations.syncHealth(), idp.sync.status(), idp.mode.get()]);
    const realms = [];
    for (const realm of await store.listRealms()) {
      realms.push({ name: realm.name, source: realm.source, enabled: realm.enabled !== false, issuer: idp.issuerFor(realm.name), keys: await idp.keyring.describe(realm.name) });
    }
    res.json({ mode: current, health, sync, realms });
  }));

  router.post('/admin/idp/mode', platformOnly, handle(async (req, res) => {
    const mode = req.body?.mode;
    if (!['standby', 'primary'].includes(mode)) return invalid(res, { mode: 'must be standby or primary' });
    const record = await idp.mode.set(mode, req.principal.username);
    if (mode === 'primary') idp.sync.stop(); else idp.sync.start();
    res.json(record);
  }));

  router.post('/admin/idp/sync', platformOnly, handle(async (req, res) => {
    if (!idp.sync.configured) return refused(res, { sync: 'synchronisation is not configured' });
    log.audit('bff', `Synchronisation requested by '${req.principal.username}'`);
    const result = await idp.sync.runOnce({ actor: req.principal.username });
    if (result.realms?.some((r) => r.realm === 'platform' && r.ok)) await idp.ensureConsoleClient();
    res.json(result);
  }));

  router.post('/admin/idp/realms/:realm/keys/rotate', platformOnly, handle(async (req, res) => {
    if (!(await store.getRealm(req.params.realm))) return notFound(res);
    const kid = await idp.keyring.rotate(req.params.realm);
    res.json({ realm: req.params.realm, activeKid: kid, keys: await idp.keyring.describe(req.params.realm) });
  }));

  router.delete('/admin/idp/realms/:realm/keys/:kid', platformOnly, handle(async (req, res) => {
    if (!(await store.getRealm(req.params.realm))) return notFound(res);
    const outcome = await idp.keyring.retire(req.params.realm, req.params.kid);
    if (outcome === 'missing') return notFound(res);
    if (outcome === 'active') return refused(res, { kid: 'the active key cannot be retired; rotate first' });
    res.json({ realm: req.params.realm, keys: await idp.keyring.describe(req.params.realm) });
  }));

  return router;
}

module.exports = { createIdpAdminApi };
