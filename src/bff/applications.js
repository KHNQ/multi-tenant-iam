/**
 * Application access: /api/tenants/{tenant}/applications/{clientId}/…
 * ─────────────────────────────────────────────────────────────────────────────
 * An application (MapDashboard is the one the console offers) keeps its access
 * model as roles of its own client, by prefix:
 *
 *   perm:<key>   a permission, e.g. perm:objects.read (category in the role's
 *                `category` attribute, text in its description)
 *   role:<name>  an application role: a composite of permissions
 *
 * The console names them without the prefix. Every change is shown before it
 * is made and carries the fingerprint of what was shown; if the state moved in
 * between, the write is refused as stale rather than applied to something the
 * operator did not see.
 *
 * Permissions the application declares in its code but this IdP does not hold
 * yet are listed for approval (MAPDASHBOARD_PERMISSION_CATALOG_URL). Approving
 * one imports it — only in primary mode, and only for holders of
 * `approve-permissions:<clientId>` in the platform realm.
 */

const express = require('express');
const crypto = require('crypto');
const { buildCatalogue, resolve } = require('../idp/roles');
const { PLATFORM_REALM } = require('../idp/bootstrap');
const {
  handle, denied, notFound, invalid, refused, conflict, stale, standbyReadOnly,
} = require('./http');

const PERM = 'perm:';
const ROLE = 'role:';
const ROLE_NAME = /^[a-z0-9][a-z0-9._-]{0,62}$/;
const CATALOG_TIMEOUT_MS = 5000;
const HISTORY_LIMIT = 50;

const fingerprint = (value) => crypto.createHash('sha256').update(JSON.stringify(value)).digest('base64url');
const first = (value) => (Array.isArray(value) ? value[0] : value) ?? '';

function createApplicationsApi({ idp, store, redis, log, fail, fetchImpl, env = process.env }) {
  const router = express.Router();
  const A = '/tenants/:tenant/applications/:clientId';
  const catalogUrl = env.MAPDASHBOARD_PERMISSION_CATALOG_URL || null;
  const catalogToken = env.MAPDASHBOARD_PERMISSION_CATALOG_TOKEN || null;
  const keys = {
    decisions: (realm, client) => `bff:imports:${realm}:${client}`,
    history: (realm, client) => `bff:imports-history:${realm}:${client}`,
  };

  router.use(A, handle(async (req, res, next) => {
    const who = req.principal;
    const { tenant, clientId } = req.params;
    if (!who.permissions.tenantAdmin) return denied(res);
    if (!who.tenants.includes(tenant)) return who.permissions.platformAdmin ? notFound(res) : denied(res);
    const client = await store.getClient(tenant, clientId);
    if (!client) return fail(res, 404, 'APPLICATION_ACCESS_NOT_CONFIGURED');
    req.realmName = tenant;
    req.app2 = client;
    req.audit = (message, meta = {}) => log.audit('bff', message, { tenant, clientId, actor: who.username, ...meta });
    return next();
  }));

  const primaryOnly = handle(async (req, res, next) => ((await idp.mode.isStandby()) ? standbyReadOnly(res) : next()));

  async function model(realm, clientId) {
    const roles = await store.listClientRoles(realm, clientId);
    const permissions = roles.filter((r) => r.name.startsWith(PERM)).map((r) => ({
      key: r.name.slice(PERM.length), category: first(r.attributes?.category), description: r.description || '',
    })).sort((a, b) => a.key.localeCompare(b.key));
    const permissionKeys = new Set(permissions.map((p) => p.key));
    const appRoles = roles.filter((r) => r.name.startsWith(ROLE)).map((r) => {
      const perms = (r.composites?.client?.[clientId] || []).filter((n) => n.startsWith(PERM)).map((n) => n.slice(PERM.length)).sort();
      const role = { name: r.name.slice(ROLE.length), description: r.description || '', permissions: perms };
      return {
        ...role,
        system: first(r.attributes?.system) === 'true' || first(r.attributes?.['iam.system']) === 'true',
        fingerprint: fingerprint(role),
      };
    }).sort((a, b) => a.name.localeCompare(b.name));
    return { permissions, permissionKeys, roles: appRoles, raw: roles };
  }

  // ── catalogue ─────────────────────────────────────────────────────────────

  router.get(`${A}/permissions`, handle(async (req, res) => {
    res.json((await model(req.realmName, req.app2.clientId)).permissions);
  }));

  router.get(`${A}/roles`, handle(async (req, res) => {
    res.json((await model(req.realmName, req.app2.clientId)).roles);
  }));

  function validPermissions(list, known) {
    return Array.isArray(list) && list.length <= 500 && list.every((p) => typeof p === 'string' && known.has(p));
  }

  router.post(`${A}/roles/:name/preview`, handle(async (req, res) => {
    const m = await model(req.realmName, req.app2.clientId);
    const role = m.roles.find((r) => r.name === req.params.name);
    if (!role) return notFound(res);
    if (!validPermissions(req.body?.permissions, m.permissionKeys)) return invalid(res, { permissions: 'must list known permissions' });
    const wanted = new Set(req.body.permissions);
    res.json({
      added: [...wanted].filter((p) => !role.permissions.includes(p)).sort(),
      removed: role.permissions.filter((p) => !wanted.has(p)),
      fingerprint: role.fingerprint,
    });
  }));

  const composites = (clientId, permissions) => ({ realm: [], client: { [clientId]: [...new Set(permissions)].map((p) => `${PERM}${p}`) } });

  router.post(`${A}/roles`, primaryOnly, handle(async (req, res) => {
    const { clientId } = req.app2;
    const m = await model(req.realmName, clientId);
    const name = typeof req.body?.name === 'string' ? req.body.name.trim() : '';
    if (!ROLE_NAME.test(name)) return invalid(res, { name: 'must be lowercase letters, digits, dot, dash or underscore' });
    if (!validPermissions(req.body?.permissions, m.permissionKeys)) return invalid(res, { permissions: 'must list known permissions' });
    if (m.raw.some((r) => r.name === `${ROLE}${name}`)) return conflict(res);
    await store.putClientRole(req.realmName, {
      id: crypto.randomUUID(), clientId, name: `${ROLE}${name}`, description: String(req.body.description || '').slice(0, 500) || null,
      composite: true, composites: composites(clientId, req.body.permissions), attributes: {}, source: 'local',
    });
    req.audit(`Application role '${name}' created with ${req.body.permissions.length} permission(s)`);
    res.status(201).json((await model(req.realmName, clientId)).roles.find((r) => r.name === name));
  }));

  router.put(`${A}/roles/:name`, primaryOnly, handle(async (req, res) => {
    const { clientId } = req.app2;
    const m = await model(req.realmName, clientId);
    const role = m.roles.find((r) => r.name === req.params.name);
    if (!role) return notFound(res);
    if (role.system) return refused(res);
    if (req.body?.fingerprint !== role.fingerprint) return stale(res);
    if (!validPermissions(req.body?.permissions, m.permissionKeys)) return invalid(res, { permissions: 'must list known permissions' });
    const updated = await store.updateClientRole(req.realmName, clientId, `${ROLE}${role.name}`, (current) => {
      if (!current) return undefined;
      return {
        ...current, description: String(req.body.description ?? current.description ?? '').slice(0, 500) || null,
        composite: true, composites: { ...current.composites, client: { ...current.composites?.client, ...composites(clientId, req.body.permissions).client } },
      };
    });
    if (!updated) return notFound(res);
    req.audit(`Application role '${role.name}' updated`, { permissions: req.body.permissions.length });
    res.json((await model(req.realmName, clientId)).roles.find((r) => r.name === role.name));
  }));

  router.delete(`${A}/roles/:name`, primaryOnly, handle(async (req, res) => {
    const { clientId } = req.app2;
    const role = (await model(req.realmName, clientId)).roles.find((r) => r.name === req.params.name);
    if (!role) return notFound(res);
    if (role.system) return refused(res);
    if (req.body?.fingerprint !== role.fingerprint) return stale(res);
    await store.deleteClientRole(req.realmName, clientId, `${ROLE}${role.name}`);
    req.audit(`Application role '${role.name}' deleted`);
    res.json({ deleted: role.name });
  }));

  // ── a user's access to the application ────────────────────────────────────

  async function userAccess(realm, clientId, user) {
    const [realmRoles, clientRoles, groups] = await Promise.all([store.listRealmRoles(realm), store.listClientRoles(realm), store.listGroups(realm)]);
    const held = resolve(buildCatalogue({ realmRoles, clientRoles, groups }), user);
    const own = [...held.values()].filter(({ ref }) => ref.source === 'client' && ref.client === clientId);
    const directRoles = (user.clientRoles?.[clientId] || []).filter((n) => n.startsWith(ROLE)).map((n) => n.slice(ROLE.length)).sort();
    const effectiveRoles = own.filter(({ ref }) => ref.name.startsWith(ROLE)).map(({ ref }) => ref.name.slice(ROLE.length)).sort();
    const permissions = own.filter(({ ref }) => ref.name.startsWith(PERM)).map(({ ref }) => ref.name.slice(PERM.length)).sort();
    const permissionOrigins = {};
    for (const { ref, grants } of own) {
      if (!ref.name.startsWith(PERM)) continue;
      const key = ref.name.slice(PERM.length);
      permissionOrigins[key] = grants.map((g) => {
        if (g.origin === 'composite') {
          const parent = String(g.via).split('/').slice(1).join('/');
          const parentEntry = held.get(g.via);
          const how = parentEntry?.grants.some((pg) => pg.origin === 'direct') ? 'direct' : parentEntry?.grants[0]?.origin || 'composite';
          return `${how}:${parent.startsWith(ROLE) ? parent.slice(ROLE.length) : parent}`;
        }
        return g.origin === 'group' ? `group:${g.via}` : 'direct';
      });
    }
    return { userId: user.id, username: user.username, directRoles, effectiveRoles, permissions, permissionOrigins };
  }

  async function loadUser(req, res) {
    const user = await store.getUser(req.realmName, req.params.id);
    if (!user || user.serviceAccountClientId) { notFound(res); return null; }
    return user;
  }

  const stateFingerprint = (user, clientId) => fingerprint([...(user.clientRoles?.[clientId] || [])].sort());

  router.get(`${A}/users/:id/effective-access`, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (user) res.json(await userAccess(req.realmName, req.app2.clientId, user));
  }));

  function applyChange(user, clientId, role, action) {
    const names = new Set(user.clientRoles?.[clientId] || []);
    if (action === 'assign') names.add(`${ROLE}${role}`); else names.delete(`${ROLE}${role}`);
    const clientRoles = { ...(user.clientRoles || {}) };
    if (names.size) clientRoles[clientId] = [...names]; else delete clientRoles[clientId];
    return { ...user, clientRoles };
  }

  async function validateChange(req, res) {
    const { role, action } = req.body || {};
    if (!['assign', 'revoke'].includes(action)) { invalid(res, { action: 'must be assign or revoke' }); return null; }
    const m = await model(req.realmName, req.app2.clientId);
    if (!m.roles.some((r) => r.name === role)) { invalid(res, { role: 'is not a role of this application' }); return null; }
    return { role, action };
  }

  router.post(`${A}/users/:id/role-changes/preview`, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (!user) return;
    const change = await validateChange(req, res);
    if (!change) return;
    const before = await userAccess(req.realmName, req.app2.clientId, user);
    const after = await userAccess(req.realmName, req.app2.clientId, applyChange(user, req.app2.clientId, change.role, change.action));
    res.json({
      role: change.role, action: change.action,
      permissionsGained: after.permissions.filter((p) => !before.permissions.includes(p)),
      permissionsLost: before.permissions.filter((p) => !after.permissions.includes(p)),
      fingerprint: stateFingerprint(user, req.app2.clientId),
    });
  }));

  router.post(`${A}/users/:id/role-changes`, primaryOnly, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (!user) return;
    const change = await validateChange(req, res);
    if (!change) return;
    const { clientId } = req.app2;
    let wasStale = false;
    const outcome = await store.updateUser(req.realmName, user.id, (current) => {
      if (stateFingerprint(current, clientId) !== req.body.fingerprint) { wasStale = true; return undefined; }
      return applyChange(current, clientId, change.role, change.action);
    });
    if (outcome.problem) return notFound(res);
    if (wasStale) return stale(res);
    req.audit(`Application role '${change.role}' ${change.action === 'assign' ? 'assigned to' : 'revoked from'} '${user.username}'`, { userId: user.id });
    res.json(await userAccess(req.realmName, clientId, outcome.user));
  }));

  // ── permissions the application declares ─────────────────────────────────

  async function declared() {
    if (!catalogUrl) return { error: 'catalog_not_configured' };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), CATALOG_TIMEOUT_MS);
    try {
      const response = await fetchImpl(catalogUrl, {
        headers: { Accept: 'application/json', ...(catalogToken ? { Authorization: `Bearer ${catalogToken}` } : {}) },
        redirect: 'error', signal: controller.signal,
      });
      if (!response.ok) return { error: 'catalog_unavailable' };
      const body = await response.json();
      const list = Array.isArray(body) ? body : body?.permissions;
      if (!Array.isArray(list) || list.length > 5000) return { error: 'catalog_invalid' };
      const entries = [];
      for (const item of list) {
        const key = typeof item?.key === 'string' ? item.key.trim() : '';
        if (!key) return { error: 'catalog_invalid' };
        entries.push({ key, category: String(item.category ?? '').slice(0, 120), description: String(item.description ?? '').slice(0, 500) });
      }
      return { entries };
    } catch {
      return { error: 'catalog_unavailable' };
    } finally {
      clearTimeout(timer);
    }
  }

  const importable = (key) => /^[A-Za-z0-9][A-Za-z0-9._:-]{0,200}$/.test(key);

  async function queue(req) {
    const { clientId } = req.app2;
    const result = await declared();
    if (result.error) return result;
    const m = await model(req.realmName, clientId);
    const held = new Map(m.permissions.map((p) => [p.key, p]));
    const decisions = await redis.hgetall(keys.decisions(req.realmName, clientId));
    const items = [];
    for (const entry of result.entries) {
      const current = held.get(entry.key);
      if (current && current.category === entry.category && current.description === entry.description) continue;
      const fp = fingerprint(entry);
      const decision = decisions[entry.key] ? JSON.parse(decisions[entry.key]) : null;
      const valid = decision && decision.fingerprint === fp;
      items.push({
        ...entry, kind: current ? 'update' : 'create',
        ...(current ? { keycloakCategory: current.category, keycloakDescription: current.description } : {}),
        fingerprint: fp, importable: importable(entry.key),
        status: valid ? decision.status : 'pending',
        decidedBy: valid ? decision.decidedBy : null, reason: valid ? decision.reason : null, lastError: valid ? decision.lastError || null : null,
      });
    }
    const declaredKeys = new Set(result.entries.map((e) => e.key));
    const approver = req.principal.roles.includes(`approve-permissions:${clientId}`) || await holdsApprover(req.principal.id, clientId);
    return {
      source: catalogUrl,
      canApprove: approver && !(await idp.mode.isStandby()),
      items,
      notDeclaredByApplication: m.permissions.map((p) => p.key).filter((key) => !declaredKeys.has(key)),
      history: (await redis.lrange(keys.history(req.realmName, clientId), 0, HISTORY_LIMIT - 1)).map((raw) => JSON.parse(raw)),
    };
  }

  async function holdsApprover(userId, clientId) {
    const user = await store.getUser(PLATFORM_REALM, userId);
    if (!user) return false;
    const [realmRoles, clientRoles, groups] = await Promise.all([
      store.listRealmRoles(PLATFORM_REALM), store.listClientRoles(PLATFORM_REALM), store.listGroups(PLATFORM_REALM),
    ]);
    return resolve(buildCatalogue({ realmRoles, clientRoles, groups }), user).has(`realm:approve-permissions:${clientId}`);
  }

  router.get(`${A}/permissions/import-requests`, handle(async (req, res) => {
    const result = await queue(req);
    // retryable: whether the identical request could later succeed.
    if (result.error) return fail(res, result.error === 'catalog_not_configured' ? 503 : 502, result.error, { retryable: result.error === 'catalog_unavailable' });
    res.json(result);
  }));

  router.post(`${A}/permissions/import-requests`, handle(async (req, res) => {
    const { clientId } = req.app2;
    const { key, decision } = req.body || {};
    if (!['approve', 'reject'].includes(decision)) return invalid(res, { decision: 'must be approve or reject' });
    const current = await queue(req);
    if (current.error) return fail(res, 502, current.error, { retryable: current.error === 'catalog_unavailable' });
    if (!current.canApprove) return (await idp.mode.isStandby()) ? standbyReadOnly(res) : denied(res);
    const item = current.items.find((i) => i.key === key);
    if (!item || item.fingerprint !== req.body.fingerprint) return stale(res);
    const reason = typeof req.body.reason === 'string' ? req.body.reason.trim().slice(0, 500) || null : null;
    const record = (status, extra = {}) => ({
      key, kind: item.kind, status, fingerprint: item.fingerprint, decidedBy: req.principal.username, reason, at: new Date().toISOString(), ...extra,
    });

    if (decision === 'reject') {
      await redis.hset(keys.decisions(req.realmName, clientId), key, JSON.stringify(record('rejected')));
      await redis.multi().lpush(keys.history(req.realmName, clientId), JSON.stringify(record('rejected'))).ltrim(keys.history(req.realmName, clientId), 0, HISTORY_LIMIT - 1).exec();
      req.audit(`Permission '${key}' rejected for import`, { key });
      return res.json({ key, status: 'rejected' });
    }
    if (!item.importable) return fail(res, 400, 'declaration_not_importable');
    const name = `${PERM}${key}`;
    const existing = await store.getClientRole(req.realmName, clientId, name);
    await store.putClientRole(req.realmName, {
      ...(existing || { id: crypto.randomUUID(), composite: false, composites: { realm: [], client: {} }, source: 'local' }),
      clientId, name, description: item.description || null,
      attributes: { ...(existing?.attributes || {}), category: item.category ? [item.category] : [] },
    });
    await redis.hdel(keys.decisions(req.realmName, clientId), key);
    await redis.multi().lpush(keys.history(req.realmName, clientId), JSON.stringify(record('imported'))).ltrim(keys.history(req.realmName, clientId), 0, HISTORY_LIMIT - 1).exec();
    req.audit(`Permission '${key}' approved and imported (${item.kind})`, { key });
    return res.json({ key, status: 'imported' });
  }));

  return router;
}

module.exports = { createApplicationsApi };
