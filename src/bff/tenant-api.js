/**
 * The tenant-scoped administration API: /api/tenants/{tenant}/…
 * ─────────────────────────────────────────────────────────────────────────────
 * The tenant is part of every path, and every request is checked against the
 * operator's current standing: a platform administrator may address any
 * tenant, a tenant administrator only those in their `tenants` attribute. The
 * console is never sent another tenant's data to filter out, because it never
 * receives any.
 *
 * In standby mode the primary IdP owns the data, and every change is refused —
 * except what an emergency needs and what belongs to this system alone:
 * ending sessions, locking (and unlocking) an account here, and issuing a
 * client secret for this system.
 */

const express = require('express');
const crypto = require('crypto');
const { REALM_NAME } = require('../idp/store');
const { buildCatalogue, resolve, childRefs, lookup, isAdministrative, qualify, SYSTEM_CLIENTS } = require('../idp/roles');
const { redirectUriProblem, webOriginProblem, sha256b64, randomToken } = require('../idp/util');
const { passwordProblem } = require('../idp/password-policy');
const { newClient } = require('../idp/bootstrap');
const {
  handle, denied, notFound, invalid, refused, conflict, standbyReadOnly, fail, page,
} = require('./http');

const USERNAME = /^[a-z0-9._-]{1,64}$/;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const CLIENT_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$/;
const GROUP_NAME = /^[^/\u0000-\u001f]{1,64}$/;
const REQUIRED_ACTIONS = ['UPDATE_PASSWORD', 'VERIFY_EMAIL', 'CONFIGURE_TOTP', 'UPDATE_PROFILE'];
// Clients the platform itself runs on: shown, never editable from the console.
const RESERVED_CLIENTS = new Set([...SYSTEM_CLIENTS, 'iam-admin-ui', 'platform-broker', 'admin-permissions',
  'iam-application-access', 'iam-permission-importer', 'management-api', 'iam-automation', 'poc-cli']);

const text = (value, max = 255) => (typeof value === 'string' ? value.trim().slice(0, max) : '');
const optionalText = (value, max = 255) => (text(value, max) || null);

function createTenantApi({ idp, store, log }) {
  const router = express.Router();

  // ── tenant scope ──────────────────────────────────────────────────────────

  router.use('/tenants/:tenant', handle(async (req, res, next) => {
    const name = req.params.tenant;
    const who = req.principal;
    if (!who.permissions.tenantAdmin) return denied(res);
    if (!REALM_NAME.test(name) || !who.tenants.includes(name)) return who.permissions.platformAdmin ? notFound(res) : denied(res);
    const realm = await store.getRealm(name);
    if (!realm) return notFound(res);
    req.realm = realm;
    req.audit = (message, meta = {}) => log.audit('bff', message, { tenant: name, actor: who.username, ...meta });
    return next();
  }));

  const primaryOnly = handle(async (req, res, next) => ((await idp.mode.isStandby()) ? standbyReadOnly(res) : next()));
  const T = '/tenants/:tenant';

  async function catalogueOf(realm) {
    const [realmRoles, clientRoles, groups] = await Promise.all([store.listRealmRoles(realm), store.listClientRoles(realm), store.listGroups(realm)]);
    return buildCatalogue({ realmRoles, clientRoles, groups });
  }

  // ── users ─────────────────────────────────────────────────────────────────

  function presentUser(user, local = {}) {
    return {
      id: user.id, username: user.username, email: user.email || null, firstName: user.firstName || null, lastName: user.lastName || null,
      enabled: user.enabled !== false && !local.locked, emailVerified: Boolean(user.emailVerified),
      requiredActions: user.requiredActions || [], createdTimestamp: user.createdTimestamp || null,
      source: user.source || 'local', locked: Boolean(local.locked), syncedEnabled: user.enabled !== false,
    };
  }

  async function loadUser(req, res) {
    const user = await store.getUser(req.realm.name, req.params.id);
    if (!user || user.serviceAccountClientId) { notFound(res); return null; }
    return user;
  }

  router.get(`${T}/users`, handle(async (req, res) => {
    const search = text(req.query.search, 128).toLowerCase();
    const [users, locals] = await Promise.all([store.listUsers(req.realm.name), store.redis.hgetall(store.keys.userLocal(req.realm.name))]);
    const matching = users
      .filter((u) => !u.serviceAccountClientId)
      .filter((u) => !search || [u.username, u.email, u.firstName, u.lastName].some((v) => String(v || '').toLowerCase().includes(search)))
      .sort((a, b) => a.username.localeCompare(b.username));
    const { envelope, slice } = page(req, matching, { defaultMax: 20 });
    res.json({ tenant: req.realm.name, ...envelope, users: slice.map((u) => presentUser(u, locals[u.id] ? JSON.parse(locals[u.id]) : {})) });
  }));

  router.get(`${T}/users/:id`, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (!user) return;
    res.json(presentUser(user, await store.getUserLocal(req.realm.name, user.id)));
  }));

  router.post(`${T}/users`, primaryOnly, handle(async (req, res) => {
    const body = req.body || {};
    const fields = {};
    const username = text(body.username, 64).toLowerCase();
    if (!USERNAME.test(username)) fields.username = 'must be lowercase letters, digits, dot, dash or underscore';
    const email = text(body.email, 320);
    if (!EMAIL.test(email)) fields.email = 'must be a valid email address';
    if (Object.keys(fields).length) return invalid(res, fields);
    const realm = req.realm;
    const user = {
      id: crypto.randomUUID(), username, email, emailVerified: false,
      firstName: optionalText(body.firstName, 120), lastName: optionalText(body.lastName, 120),
      enabled: true, attributes: {}, requiredActions: [], createdTimestamp: Date.now(),
      realmRoles: (await store.getRealmRole(realm.name, realm.defaultRole)) ? [realm.defaultRole] : [], clientRoles: {}, groups: [], source: 'local',
    };
    const outcome = await store.createUser(realm.name, user);
    if (outcome !== 'ok') return conflict(res);
    req.audit(`User '${username}' created in tenant '${realm.name}'`, { userId: user.id });
    res.status(201).json(presentUser(user));
  }));

  router.put(`${T}/users/:id`, primaryOnly, handle(async (req, res) => {
    const body = req.body || {};
    const email = text(body.email, 320);
    if (!EMAIL.test(email)) return invalid(res, { email: 'must be a valid email address' });
    const outcome = await store.updateUser(req.realm.name, req.params.id, (user) => (user.serviceAccountClientId ? undefined : {
      ...user, email, firstName: optionalText(body.firstName, 120), lastName: optionalText(body.lastName, 120),
      emailVerified: user.email && user.email.toLowerCase() === email.toLowerCase() ? user.emailVerified : false,
    }));
    if (outcome.problem === 'missing') return notFound(res);
    if (outcome.problem === 'email') return conflict(res);
    req.audit(`User '${outcome.user.username}' updated in tenant '${req.realm.name}'`, { userId: req.params.id });
    res.json(presentUser(outcome.user, await store.getUserLocal(req.realm.name, req.params.id)));
  }));

  /**
   * Enabling and disabling. In primary mode this is the account's own state.
   * In standby it is an emergency lock held here, on top of the synchronised
   * state, which the next synchronisation does not undo.
   */
  router.put(`${T}/users/:id/enabled`, handle(async (req, res) => {
    const realm = req.realm.name;
    const user = await loadUser(req, res);
    if (!user) return;
    if (typeof req.body?.enabled !== 'boolean') return invalid(res, { enabled: 'must be true or false' });
    const enable = req.body.enabled;
    if (await idp.mode.isStandby()) {
      if (enable && user.enabled === false) return standbyReadOnly(res);
      await store.updateUserLocal(realm, user.id, (local) => (enable
        ? { ...local, locked: false, unlockedBy: req.principal.username, unlockedAt: new Date().toISOString() }
        : { ...local, locked: true, lockedBy: req.principal.username, lockedAt: new Date().toISOString() }));
    } else {
      await store.updateUser(realm, user.id, (current) => ({ ...current, enabled: enable }));
      await store.updateUserLocal(realm, user.id, (local) => ({ ...local, locked: false }));
    }
    if (!enable) {
      await store.bumpSecurityVersion(realm, user.id);
      await idp.sessions.endAllForUser(realm, user.id);
    }
    req.audit(`User '${user.username}' ${enable ? 'enabled' : 'disabled'} in tenant '${realm}'`, { userId: user.id });
    res.json(presentUser(await store.getUser(realm, user.id), await store.getUserLocal(realm, user.id)));
  }));

  router.put(`${T}/users/:id/credential`, primaryOnly, handle(async (req, res) => {
    const realm = req.realm;
    const user = await loadUser(req, res);
    if (!user) return;
    const password = req.body?.password;
    const problem = passwordProblem(realm.passwordPolicy, password, user);
    if (problem) return invalid(res, { password: `The password ${problem}` });
    await idp.credentials.setPassword(realm.name, user.id, password, { temporary: true });
    await store.updateUser(realm.name, user.id, (current) => ({
      ...current, requiredActions: [...new Set([...(current.requiredActions || []), 'UPDATE_PASSWORD'])],
    }));
    await store.bumpSecurityVersion(realm.name, user.id);
    await idp.sessions.endAllForUser(realm.name, user.id);
    req.audit(`Temporary password set for '${user.username}' in tenant '${realm.name}'`, { userId: user.id });
    // No credential material comes back, not even the account.
    res.status(204).end();
  }));

  router.put(`${T}/users/:id/required-actions`, primaryOnly, handle(async (req, res) => {
    const actions = req.body?.actions;
    if (!Array.isArray(actions) || !actions.every((a) => REQUIRED_ACTIONS.includes(a))) {
      return invalid(res, { actions: `must be a list of: ${REQUIRED_ACTIONS.join(', ')}` });
    }
    const outcome = await store.updateUser(req.realm.name, req.params.id, (user) => (user.serviceAccountClientId ? undefined : { ...user, requiredActions: [...new Set(actions)] }));
    if (outcome.problem) return notFound(res);
    req.audit(`Required actions of '${outcome.user.username}' set to ${actions.join(', ') || 'none'}`, { userId: req.params.id });
    res.json(presentUser(outcome.user, await store.getUserLocal(req.realm.name, req.params.id)));
  }));

  // ── sessions ──────────────────────────────────────────────────────────────

  function presentSession(session) {
    return {
      id: session.sid, userId: session.userId, username: session.username, ipAddress: session.ip || null,
      start: session.created, started: session.created, lastAccess: session.lastAccess,
      clients: Object.fromEntries(Object.entries(session.clients).map(([id, entry]) => [id, entry.name || id])),
    };
  }

  const reasonOf = (req) => text(req.body?.reason, 500);

  router.get(`${T}/users/:id/sessions`, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (!user) return;
    const sessions = await idp.sessions.listForUser(req.realm.name, req.realm, user.id);
    res.json({ tenant: req.realm.name, userId: user.id, sessions: sessions.map(presentSession) });
  }));

  router.delete(`${T}/users/:id/sessions/:sid`, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (!user) return;
    const reason = reasonOf(req);
    if (!reason) return invalid(res, { reason: 'is required' });
    const session = await idp.sessions.get(req.realm.name, req.realm, req.params.sid);
    if (!session || session.userId !== user.id) return notFound(res);
    await idp.sessions.end(req.realm.name, session.sid);
    req.audit(`Session of '${user.username}' terminated in tenant '${req.realm.name}': ${reason}`, { userId: user.id, sid: session.sid, reason });
    res.json({ terminated: 1 });
  }));

  router.post(`${T}/users/:id/sessions/terminate-all`, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (!user) return;
    const reason = reasonOf(req);
    if (!reason) return invalid(res, { reason: 'is required' });
    const count = await idp.sessions.endAllForUser(req.realm.name, user.id);
    req.audit(`All sessions of '${user.username}' terminated in tenant '${req.realm.name}': ${reason}`, { userId: user.id, count, reason });
    res.json({ terminated: count });
  }));

  // ── effective access and role grants ──────────────────────────────────────

  function presentRole(catalogue, ref, role) {
    const administrative = isAdministrative(catalogue, ref);
    const systemClient = ref.source === 'client' && SYSTEM_CLIENTS.has(ref.client);
    return {
      source: ref.source, client: ref.source === 'client' ? ref.client : null, name: ref.name,
      description: role?.description && !/^\$\{.*\}$/.test(role.description) ? role.description : null,
      composite: Boolean(role?.composite && childRefs(role).length), administrative,
      assignable: !administrative && !systemClient && !ref.name.startsWith('default-roles-'),
    };
  }

  async function effectiveAccess(realm, user) {
    const catalogue = await catalogueOf(realm.name);
    const held = resolve(catalogue, user);
    const access = [...held.values()]
      .map(({ ref, role, grants }) => ({ ...presentRole(catalogue, ref, role), grants, origins: [...new Set(grants.map((g) => g.origin))] }))
      .sort((a, b) => (a.source === b.source ? `${a.client || ''}/${a.name}`.localeCompare(`${b.client || ''}/${b.name}`) : a.source === 'realm' ? -1 : 1));
    const groups = (user.groups || []).map((id) => catalogue.groups.get(id)?.path).filter(Boolean).sort();
    const local = await store.getUserLocal(realm.name, user.id);
    return {
      tenant: realm.name, userId: user.id, username: user.username, enabled: user.enabled !== false && !local.locked,
      groups, count: access.length, access,
    };
  }

  router.get(`${T}/users/:id/effective-access`, handle(async (req, res) => {
    const user = await loadUser(req, res);
    if (!user) return;
    res.json(await effectiveAccess(req.realm, user));
  }));

  /**
   * The access test: would this user get into this application, and with
   * which claims? Evaluates the sign-in checks and the token contract for one
   * client and scope, from current data. Nothing is signed, issued or stored,
   * so it is allowed in standby.
   */
  router.post(`${T}/users/:id/access-test`, handle(async (req, res) => {
    const realm = req.realm;
    const user = await loadUser(req, res);
    if (!user) return;
    const client = await store.getClient(realm.name, text(req.body?.clientId, 255));
    if (!client) return invalid(res, { clientId: 'is not an application of this tenant' });
    const scope = text(req.body?.scope, 500) || 'openid profile email';
    const [local, hasPassword, standby, preview] = await Promise.all([
      store.getUserLocal(realm.name, user.id), idp.credentials.has(realm.name, user.id), idp.mode.isStandby(),
      idp.tokens.preview({ realm: realm.name, client, user, scope }),
    ]);
    const passwordChangeHeld = (user.requiredActions || []).includes('UPDATE_PASSWORD') && standby && user.source !== 'local';
    const checks = [
      { key: 'account_enabled', ok: user.enabled !== false && !local.locked },
      { key: 'password_set', ok: hasPassword },
      { key: 'password_change_possible', ok: !passwordChangeHeld },
      { key: 'client_enabled', ok: client.enabled !== false },
      { key: 'browser_sign_in', ok: client.standardFlowEnabled !== false && !client.bearerOnly },
      ...(client.publicClient ? [] : [{ key: 'client_secret_issued', ok: Boolean(client.secretHash) }]),
    ];
    // MapDashboard refuses a sign-in whose md_roles carries no role:* entry.
    if ('md_roles' in preview.accessToken || client.clientId === 'samta-mapdashboard-web-poc') {
      const mdRoles = preview.accessToken.md_roles;
      checks.push({ key: 'md_roles_role', ok: Array.isArray(mdRoles) && mdRoles.some((r) => String(r).startsWith('role:')) });
    }
    res.json({
      tenant: realm.name, userId: user.id, username: user.username, clientId: client.clientId, scope: preview.scope,
      issuer: idp.issuerFor(realm.name), allowed: checks.every((c) => c.ok), checks,
      accessToken: preview.accessToken, idToken: preview.idToken, userinfo: preview.userinfo,
    });
  }));

  router.get(`${T}/roles`, handle(async (req, res) => {
    const search = text(req.query.search, 128).toLowerCase();
    const catalogue = await catalogueOf(req.realm.name);
    const roles = [
      ...[...catalogue.realm.values()].map((role) => presentRole(catalogue, { source: 'realm', name: role.name }, role)),
      ...[...catalogue.client.values()].map((role) => presentRole(catalogue, { source: 'client', client: role.clientId, name: role.name }, role)),
    ]
      .filter((r) => !search || r.name.toLowerCase().includes(search) || String(r.client || '').toLowerCase().includes(search))
      .sort((a, b) => (a.source === b.source ? `${a.client || ''}/${a.name}`.localeCompare(`${b.client || ''}/${b.name}`) : a.source === 'realm' ? -1 : 1));
    // No total for roles, by contract: an absent total means unknown.
    const { envelope, slice } = page(req, roles, { defaultMax: 50, total: false });
    res.json({ tenant: req.realm.name, ...envelope, roles: slice });
  }));

  router.get(`${T}/roles/:name`, handle(async (req, res) => {
    const catalogue = await catalogueOf(req.realm.name);
    const ref = { source: 'realm', name: req.params.name };
    const role = lookup(catalogue, ref);
    if (!role) return notFound(res);
    res.json({
      ...presentRole(catalogue, ref, role),
      composites: childRefs(role).map((child) => ({ ...presentRole(catalogue, child, lookup(catalogue, child)) })),
    });
  }));

  router.post(`${T}/users/:id/role-mappings`, primaryOnly, handle(async (req, res) => {
    const realm = req.realm;
    const user = await loadUser(req, res);
    if (!user) return;
    const add = req.body?.add;
    if (!Array.isArray(add) || !add.length || add.length > 50) return invalid(res, { add: 'must list 1-50 roles' });
    const catalogue = await catalogueOf(realm.name);
    const refs = [];
    for (const entry of add) {
      const ref = entry?.source === 'client' ? { source: 'client', client: text(entry.client), name: text(entry.name) } : { source: 'realm', name: text(entry?.name) };
      const role = lookup(catalogue, ref);
      if (!role) return notFound(res);
      // All or nothing: one ungrantable role refuses the whole request.
      if (!presentRole(catalogue, ref, role).assignable) return fail(res, 403, 'access_denied', { reason: 'role_not_assignable' });
      refs.push(ref);
    }
    const outcome = await store.updateUser(realm.name, user.id, (current) => {
      const realmRoles = new Set(current.realmRoles || []);
      const clientRoles = Object.fromEntries(Object.entries(current.clientRoles || {}).map(([c, names]) => [c, new Set(names)]));
      for (const ref of refs) {
        if (ref.source === 'realm') realmRoles.add(ref.name);
        else (clientRoles[ref.client] ||= new Set()).add(ref.name);
      }
      return {
        ...current, realmRoles: [...realmRoles],
        clientRoles: Object.fromEntries(Object.entries(clientRoles).map(([c, names]) => [c, [...names]])),
      };
    });
    req.audit(`Granted ${refs.map(qualify).join(', ')} to '${user.username}' in tenant '${realm.name}'`, { userId: user.id });
    res.json({ ...(await effectiveAccess(realm, outcome.user)), assigned: refs.length });
  }));

  // ── clients ───────────────────────────────────────────────────────────────

  function presentClient(client) {
    return {
      clientId: client.clientId, name: client.name || null, description: client.description || null, enabled: client.enabled !== false,
      publicClient: Boolean(client.publicClient), kind: client.publicClient ? 'public' : 'confidential', bearerOnly: Boolean(client.bearerOnly),
      standardFlowEnabled: client.standardFlowEnabled !== false, serviceAccountsEnabled: Boolean(client.serviceAccountsEnabled),
      implicitFlowEnabled: false, directAccessGrantsEnabled: Boolean(client.directAccessGrantsEnabled),
      redirectUris: client.redirectUris || [], webOrigins: client.webOrigins || [], postLogoutRedirectUris: client.postLogoutRedirectUris || [],
      pkceChallengeMethod: 'S256', reserved: RESERVED_CLIENTS.has(client.clientId), source: client.source || 'local',
      hasSecret: Boolean(client.secretHash), secretRotatedAt: client.secretRotatedAt || null,
      defaultClientScopes: client.defaultClientScopes || [], optionalClientScopes: client.optionalClientScopes || [],
      audiences: (client.mappers || []).filter((m) => m.type === 'audience').map((m) => m.audience || m.audienceClient),
      mappers: (client.mappers || []).map((m) => ({ name: m.name || null, type: m.type, claim: m.claim || null, tokens: m.tokens })),
    };
  }

  function clientDraft(body, { creating }) {
    const fields = {};
    const lists = {};
    for (const [name, check] of [['redirectUris', redirectUriProblem], ['postLogoutRedirectUris', redirectUriProblem], ['webOrigins', webOriginProblem]]) {
      const value = body[name] ?? [];
      if (!Array.isArray(value) || value.length > 50 || !value.every((v) => typeof v === 'string')) { fields[name] = 'must be a list of at most 50 entries'; continue; }
      // The field and the rule, never the value that was sent.
      const index = value.findIndex((v) => check(v));
      if (index >= 0) fields[name] = `entry ${index + 1} ${check(value[index])}`;
      lists[name] = [...new Set(value)];
    }
    const draft = {
      name: optionalText(body.name, 120), description: optionalText(body.description, 500),
      standardFlowEnabled: body.standardFlow !== false, ...lists,
    };
    if (creating) {
      draft.clientId = text(body.clientId, 255);
      if (!CLIENT_ID.test(draft.clientId)) fields.clientId = 'must be letters, digits, dot, dash, underscore or colon';
      else if (RESERVED_CLIENTS.has(draft.clientId)) fields.clientId = 'is reserved by the platform';
      if (!['public', 'confidential'].includes(body.kind)) fields.kind = 'must be public or confidential';
      draft.publicClient = body.kind === 'public';
      if (draft.publicClient && !draft.standardFlowEnabled) fields.kind = 'a public client must use browser sign-in';
    }
    if (draft.standardFlowEnabled && !(draft.redirectUris || []).length) fields.redirectUris = 'at least one redirect URI is required for browser sign-in';
    return { draft, fields };
  }

  async function loadClient(req, res) {
    const client = await store.getClient(req.realm.name, req.params.clientId);
    if (!client) { notFound(res); return null; }
    return client;
  }

  router.get(`${T}/clients`, handle(async (req, res) => {
    const search = text(req.query.search, 128).toLowerCase();
    const clients = (await store.listClients(req.realm.name))
      .filter((c) => !search || `${c.clientId} ${c.name || ''} ${c.description || ''}`.toLowerCase().includes(search))
      .sort((a, b) => a.clientId.localeCompare(b.clientId));
    // No total for clients, by contract: an absent total means unknown.
    const { envelope, slice } = page(req, clients, { defaultMax: 50, total: false });
    res.json({ tenant: req.realm.name, ...envelope, clients: slice.map(presentClient) });
  }));

  router.get(`${T}/clients/:clientId`, handle(async (req, res) => {
    const client = await loadClient(req, res);
    if (client) res.json(presentClient(client));
  }));

  async function issueSecret(realm, clientId) {
    const secret = randomToken(32);
    await store.updateClientLocal(realm, clientId, (local) => ({ ...local, secretHash: sha256b64(secret), secretRotatedAt: new Date().toISOString() }));
    return secret;
  }

  router.post(`${T}/clients`, primaryOnly, handle(async (req, res) => {
    const realm = req.realm;
    const { draft, fields } = clientDraft(req.body || {}, { creating: true });
    if (Object.keys(fields).length) return refused(res, fields);
    const scopes = new Set((await store.listScopes(realm.name)).map((s) => s.name));
    const service = !draft.publicClient && !draft.standardFlowEnabled;
    const client = newClient(draft.clientId, {
      ...draft, serviceAccountsEnabled: service,
      defaultClientScopes: ['profile', 'email', 'roles', 'web-origins', 'acr', 'basic'].filter((s) => scopes.has(s)),
      optionalClientScopes: ['offline_access'].filter((s) => scopes.has(s)),
    });
    if (service) {
      const account = {
        id: crypto.randomUUID(), username: `service-account-${draft.clientId.toLowerCase()}`, email: null, emailVerified: false,
        firstName: null, lastName: null, enabled: true, attributes: {}, requiredActions: [], createdTimestamp: Date.now(),
        realmRoles: (await store.getRealmRole(realm.name, realm.defaultRole)) ? [realm.defaultRole] : [], clientRoles: {}, groups: [],
        serviceAccountClientId: draft.clientId, source: 'local',
      };
      if ((await store.createUser(realm.name, account)) !== 'ok') return conflict(res);
      client.serviceAccountUserId = account.id;
    }
    if (!(await store.createClient(realm.name, client))) return conflict(res);
    const secret = client.publicClient ? null : await issueSecret(realm.name, client.clientId);
    req.audit(`Client '${client.clientId}' registered in tenant '${realm.name}' (${client.publicClient ? 'public' : 'confidential'})`, { clientId: client.clientId });
    res.status(201).json({ ...presentClient(await store.getClient(realm.name, client.clientId)), ...(secret ? { secret, secretShownOnce: true } : {}) });
  }));

  router.put(`${T}/clients/:clientId`, primaryOnly, handle(async (req, res) => {
    const realm = req.realm;
    const client = await loadClient(req, res);
    if (!client) return;
    if (RESERVED_CLIENTS.has(client.clientId)) return refused(res);
    const { draft, fields } = clientDraft(req.body || {}, { creating: false });
    if (Object.keys(fields).length) return refused(res, fields);
    await store.updateClient(realm.name, client.clientId, (current) => ({ ...current, ...draft }));
    req.audit(`Client '${client.clientId}' updated in tenant '${realm.name}'`, { clientId: client.clientId });
    res.json(presentClient(await store.getClient(realm.name, client.clientId)));
  }));

  router.put(`${T}/clients/:clientId/enabled`, primaryOnly, handle(async (req, res) => {
    const realm = req.realm;
    const client = await loadClient(req, res);
    if (!client) return;
    if (RESERVED_CLIENTS.has(client.clientId)) return refused(res);
    if (typeof req.body?.enabled !== 'boolean') return invalid(res, { enabled: 'must be true or false' });
    await store.updateClient(realm.name, client.clientId, (current) => ({ ...current, enabled: req.body.enabled }));
    req.audit(`Client '${client.clientId}' ${req.body.enabled ? 'enabled' : 'disabled'} in tenant '${realm.name}'`, { clientId: client.clientId });
    res.json(presentClient(await store.getClient(realm.name, client.clientId)));
  }));

  /**
   * A new secret for this system. Secrets are never copied from the primary
   * IdP, so this is allowed in standby too: it is how a confidential client is
   * prepared for failover. The value is returned once and kept only as a hash.
   */
  router.post(`${T}/clients/:clientId/secret`, handle(async (req, res) => {
    const realm = req.realm;
    const client = await loadClient(req, res);
    if (!client) return;
    if (RESERVED_CLIENTS.has(client.clientId) || client.publicClient) return refused(res);
    const secret = await issueSecret(realm.name, client.clientId);
    req.audit(`A new secret was issued for client '${client.clientId}' in tenant '${realm.name}'`, { clientId: client.clientId });
    res.json({ clientId: client.clientId, secret, secretShownOnce: true });
  }));

  // ── groups ────────────────────────────────────────────────────────────────

  const presentGroup = (g) => ({ id: g.id, name: g.name, path: g.path, parentId: g.parentId || null });

  router.get(`${T}/groups`, handle(async (req, res) => {
    const search = text(req.query.search, 128).toLowerCase();
    const groups = (await store.listGroups(req.realm.name))
      .filter((g) => !search || g.path.toLowerCase().includes(search))
      .sort((a, b) => a.path.localeCompare(b.path));
    const { envelope, slice } = page(req, groups, { defaultMax: 20 });
    res.json({ tenant: req.realm.name, ...envelope, groups: slice.map(presentGroup) });
  }));

  router.get(`${T}/groups/:id`, handle(async (req, res) => {
    const all = await store.listGroups(req.realm.name);
    const group = all.find((g) => g.id === req.params.id);
    if (!group) return notFound(res);
    res.json({ ...presentGroup(group), children: all.filter((g) => g.parentId === group.id).sort((a, b) => a.name.localeCompare(b.name)).map(presentGroup) });
  }));

  router.get(`${T}/groups/:id/members`, handle(async (req, res) => {
    if (!(await store.getGroup(req.realm.name, req.params.id))) return notFound(res);
    const members = (await store.listUsers(req.realm.name)).filter((u) => (u.groups || []).includes(req.params.id))
      .sort((a, b) => a.username.localeCompare(b.username)).map((u) => ({ id: u.id, username: u.username, email: u.email || null }));
    res.json({ members });
  }));

  async function placeGroup(realm, { id, name, parentId }) {
    const all = await store.listGroups(realm);
    const parent = parentId ? all.find((g) => g.id === parentId) : null;
    if (parentId && !parent) return { problem: 'not_found' };
    if (id && parent) {
      for (let p = parent; p; p = all.find((g) => g.id === p.parentId)) if (p.id === id) return { problem: 'cycle' };
    }
    if (all.some((g) => g.id !== id && (g.parentId || null) === (parentId || null) && g.name === name)) return { problem: 'conflict' };
    return { path: `${parent ? parent.path : ''}/${name}`, all };
  }

  async function repath(realm, group, path, all) {
    const old = group.path;
    await store.updateGroup(realm, group.id, (g) => ({ ...g, path }));
    for (const g of all) {
      if (g.path.startsWith(`${old}/`)) await store.updateGroup(realm, g.id, (cur) => ({ ...cur, path: `${path}${cur.path.slice(old.length)}` }));
    }
  }

  router.post(`${T}/groups`, primaryOnly, handle(async (req, res) => {
    const name = text(req.body?.name, 64);
    if (!GROUP_NAME.test(name)) return invalid(res, { name: 'must be 1-64 characters without /' });
    const parentId = req.body?.parentId || null;
    const placed = await placeGroup(req.realm.name, { name, parentId });
    if (placed.problem === 'not_found') return notFound(res);
    if (placed.problem) return conflict(res);
    const group = { id: crypto.randomUUID(), name, path: placed.path, parentId, realmRoles: [], clientRoles: {}, attributes: {}, source: 'local' };
    await store.putGroup(req.realm.name, group);
    req.audit(`Group '${group.path}' created in tenant '${req.realm.name}'`, { groupId: group.id });
    res.status(201).json(presentGroup(group));
  }));

  router.put(`${T}/groups/:id`, primaryOnly, handle(async (req, res) => {
    const group = await store.getGroup(req.realm.name, req.params.id);
    if (!group) return notFound(res);
    const name = text(req.body?.name, 64);
    if (!GROUP_NAME.test(name)) return invalid(res, { name: 'must be 1-64 characters without /' });
    const placed = await placeGroup(req.realm.name, { id: group.id, name, parentId: group.parentId });
    if (placed.problem) return conflict(res);
    await store.updateGroup(req.realm.name, group.id, (g) => ({ ...g, name }));
    await repath(req.realm.name, group, placed.path, placed.all);
    req.audit(`Group '${group.path}' renamed to '${placed.path}'`, { groupId: group.id });
    res.json(presentGroup(await store.getGroup(req.realm.name, group.id)));
  }));

  router.put(`${T}/groups/:id/parent`, primaryOnly, handle(async (req, res) => {
    const group = await store.getGroup(req.realm.name, req.params.id);
    if (!group) return notFound(res);
    const parentId = req.body?.parentId || null;
    const placed = await placeGroup(req.realm.name, { id: group.id, name: group.name, parentId });
    if (placed.problem === 'not_found') return notFound(res);
    if (placed.problem) return refused(res, { parentId: placed.problem === 'cycle' ? 'a group cannot move under itself' : 'a sibling already has that name' });
    await store.updateGroup(req.realm.name, group.id, (g) => ({ ...g, parentId }));
    await repath(req.realm.name, group, placed.path, placed.all);
    req.audit(`Group '${group.path}' moved to '${placed.path}'`, { groupId: group.id });
    res.json(presentGroup(await store.getGroup(req.realm.name, group.id)));
  }));

  async function setMembership(req, res, member) {
    const group = await store.getGroup(req.realm.name, req.params.id);
    if (!group) return notFound(res);
    const outcome = await store.updateUser(req.realm.name, req.params.userId, (user) => {
      const groups = new Set(user.groups || []);
      if (member) groups.add(group.id); else groups.delete(group.id);
      return { ...user, groups: [...groups] };
    });
    if (outcome.problem) return notFound(res);
    req.audit(`'${outcome.user.username}' ${member ? 'added to' : 'removed from'} group '${group.path}'`, { groupId: group.id, userId: outcome.user.id });
    return res.json({ groupId: group.id, userId: outcome.user.id, member });
  }
  router.put(`${T}/groups/:id/members/:userId`, primaryOnly, handle((req, res) => setMembership(req, res, true)));
  router.delete(`${T}/groups/:id/members/:userId`, primaryOnly, handle((req, res) => setMembership(req, res, false)));

  return router;
}

module.exports = { createTenantApi, RESERVED_CLIENTS };
