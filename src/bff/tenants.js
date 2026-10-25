/**
 * The tenant catalogue (platform administrators only).
 *
 * A tenant is a realm. Realms that arrive by synchronisation, or existed
 * before the catalogue did, are listed as approved and provisioned. A new
 * tenant is requested, then approved — which provisions its realm from the
 * platform template — or rejected with a reason. "Check drift" compares the
 * realm with what the template requires and reports the difference; it
 * repairs nothing.
 */

const express = require('express');
const { createRealm } = require('../idp/bootstrap');
const { REALM_NAME } = require('../idp/store');
const {
  handle, denied, notFound, invalid, conflict, standbyReadOnly, page,
} = require('./http');

const KEY = 'bff:tenants';
const TENANT_KEY = /^[a-z0-9][a-z0-9-]{1,62}$/;
const TEMPLATE_ROLES = [
  { name: 'tenant-admin', description: 'Administers this tenant' },
  { name: 'tenant-user', description: 'A member of this tenant' },
];

function createTenantRegistry({ idp, store, redis, log, fail, hiddenTenants }) {
  const router = express.Router();

  const requirePlatformAdmin = (req, res, next) => (req.principal.permissions.platformAdmin ? next() : denied(res));

  /** What the template requires of a tenant realm, compared with what it is. */
  async function drift(realmName) {
    const realm = await store.getRealm(realmName);
    if (!realm) return { driftStatus: 'MISSING', driftDetails: 'realm_missing' };
    const problems = [];
    if (realm.enabled === false) problems.push('realm_disabled');
    if (realm.bruteForceProtected === false) problems.push('brute_force_protection_disabled');
    if (!realm.passwordPolicy) problems.push('password_policy_missing');
    if (!(await idp.keyring.ready(realmName))) problems.push('signing_key_missing');
    // Realms the platform provisioned carry its ownership marker and template roles.
    if (realm.source === 'local') {
      if (realm.managedBy !== 'iam-platform') problems.push('ownership_marker_missing');
      for (const role of TEMPLATE_ROLES) if (!(await store.getRealmRole(realmName, role.name))) problems.push(`role_missing:${role.name}`);
    }
    return problems.length ? { driftStatus: 'DRIFTED', driftDetails: problems.join(', ') } : { driftStatus: 'IN_SYNC', driftDetails: null };
  }

  async function catalogue() {
    const registered = Object.fromEntries(Object.entries(await redis.hgetall(KEY)).map(([key, raw]) => [key, JSON.parse(raw)]));
    const realms = await store.listRealms();
    for (const realm of realms) {
      if (hiddenTenants.has(realm.name) || Object.values(registered).some((t) => t.realmName === realm.name)) continue;
      registered[realm.name] = {
        tenantKey: realm.name, displayName: realm.displayName || realm.name, realmName: realm.name,
        status: 'APPROVED', provisioningStatus: 'READY', requestedBy: realm.source === 'sync' ? 'sync' : 'bootstrap',
        decisionReason: null, provisioningError: null, createdAt: realm.createdAt || null,
      };
    }
    const tenants = [];
    for (const tenant of Object.values(registered)) {
      tenants.push(tenant.status === 'APPROVED' ? { ...tenant, ...(await drift(tenant.realmName)) } : { ...tenant, driftStatus: null, driftDetails: null });
    }
    return tenants.sort((a, b) => a.tenantKey.localeCompare(b.tenantKey));
  }

  const save = (tenant) => redis.hset(KEY, tenant.tenantKey, JSON.stringify(tenant));
  async function find(key) {
    return (await catalogue()).find((tenant) => tenant.tenantKey === key) || null;
  }

  async function provision(tenant) {
    try {
      if (!(await store.getRealm(tenant.realmName))) {
        await createRealm(store, idp.keyring, { name: tenant.realmName, displayName: tenant.displayName, roles: TEMPLATE_ROLES });
      }
      return { ...tenant, provisioningStatus: 'READY', provisioningError: null };
    } catch (err) {
      log.error('bff', `Provisioning tenant '${tenant.tenantKey}' failed: ${err.message}`, { tenant: tenant.tenantKey });
      return { ...tenant, provisioningStatus: 'FAILED', provisioningError: 'provisioning_failed' };
    }
  }

  const writable = handle(async (req, res, next) => ((await idp.mode.isStandby()) ? standbyReadOnly(res) : next()));

  router.get('/admin/tenants', requirePlatformAdmin, handle(async (req, res) => {
    const search = String(req.query.search || '').toLowerCase();
    const status = String(req.query.status || '');
    const tenants = (await catalogue()).filter((t) => (!status || t.status === status)
      && (!search || `${t.tenantKey} ${t.displayName} ${t.realmName}`.toLowerCase().includes(search)));
    const { envelope, slice } = page(req, tenants, { defaultMax: 50 });
    res.json({ ...envelope, tenants: slice });
  }));

  router.post('/admin/tenants', requirePlatformAdmin, writable, handle(async (req, res) => {
    const { tenantKey, displayName, realmName } = req.body || {};
    const fields = {};
    if (typeof tenantKey !== 'string' || !TENANT_KEY.test(tenantKey)) fields.tenantKey = 'must be 2-63 lowercase letters, digits or dashes';
    if (typeof displayName !== 'string' || !displayName.trim() || displayName.length > 120) fields.displayName = 'is required (at most 120 characters)';
    const realm = typeof realmName === 'string' && realmName ? realmName : tenantKey;
    if (typeof realm !== 'string' || !REALM_NAME.test(realm) || !TENANT_KEY.test(realm) || hiddenTenants.has(realm)) fields.realmName = 'must be 2-63 lowercase letters, digits or dashes';
    if (Object.keys(fields).length) return invalid(res, fields);
    if (await find(tenantKey) || await store.getRealm(realm) || (await catalogue()).some((t) => t.realmName === realm)) return conflict(res);
    const tenant = {
      tenantKey, displayName: displayName.trim(), realmName: realm, status: 'PENDING', provisioningStatus: 'NOT_STARTED',
      requestedBy: req.principal.username, decisionReason: null, provisioningError: null, createdAt: new Date().toISOString(),
    };
    if (!(await redis.hsetnx(KEY, tenantKey, JSON.stringify(tenant)))) return conflict(res);
    log.audit('bff', `Tenant '${tenantKey}' requested by '${req.principal.username}'`, { tenant: tenantKey, realm });
    res.status(201).json(tenant);
  }));

  router.post('/admin/tenants/:key/:decision', requirePlatformAdmin, handle(async (req, res, next) => {
    const { key, decision } = req.params;
    if (!['approve', 'reject', 'retry-provisioning', 'reconcile'].includes(decision)) return notFound(res);
    const tenant = await find(key);
    if (!tenant) return notFound(res);

    if (decision === 'reconcile') {
      const result = { ...tenant, ...(await drift(tenant.realmName)), checkedAt: new Date().toISOString() };
      log.audit('bff', `Drift check of tenant '${key}': ${result.driftStatus}`, { tenant: key, drift: result.driftStatus });
      return res.json(result);
    }
    if (await idp.mode.isStandby()) return standbyReadOnly(res);

    const reason = typeof req.body?.reason === 'string' ? req.body.reason.trim().slice(0, 500) : '';
    if (decision === 'approve' || decision === 'reject') {
      if (tenant.status !== 'PENDING') return fail(res, 409, 'invalid_state');
      if (decision === 'reject') {
        if (!reason) return fail(res, 400, 'reason_required');
        const rejected = { ...tenant, status: 'REJECTED', decisionReason: reason, decidedBy: req.principal.username };
        await save(rejected);
        log.audit('bff', `Tenant '${key}' rejected by '${req.principal.username}'`, { tenant: key });
        return res.json(rejected);
      }
      const approved = await provision({ ...tenant, status: 'APPROVED', decisionReason: reason || null, decidedBy: req.principal.username });
      await save(approved);
      log.audit('bff', `Tenant '${key}' approved by '${req.principal.username}'; realm '${approved.realmName}' ${approved.provisioningStatus}`, { tenant: key });
      return res.json({ ...approved, ...(await drift(approved.realmName)) });
    }
    if (tenant.provisioningStatus !== 'FAILED') return fail(res, 409, 'invalid_state');
    const retried = await provision(tenant);
    await save(retried);
    return res.json({ ...retried, ...(await drift(retried.realmName)) });
  }));

  return router;
}

module.exports = { createTenantRegistry };
