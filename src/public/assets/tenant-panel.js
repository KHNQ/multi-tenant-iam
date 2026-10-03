/**
 * The tenant management component.
 * ───────────────────────────────────────────────────────────────────────────
 * Renders and drives everything one tenant contains: its service (base URL,
 * catalog, endpoints, status), its roles, its policies, its users and its
 * access-request queue.
 *
 * It is shared verbatim by the platform admin console and the tenant owner's
 * console, because they do the same job on the same object — the only
 * difference is which tenants each is allowed to open, and which parts of one
 * they may change. The API decides both: GET /tenants/:id says which of the
 * four administrative permissions (members, roles, policies, destinations)
 * the signed-in account holds here, and this component offers the controls
 * for those and no others. Writing this twice would
 * guarantee the two drift, and "the admin panel can do something the owner's
 * panel cannot" is exactly the kind of drift that turns into a support ticket.
 */

import { esc, chips, badge, ok, err, parseList, relTime, confirmDanger } from './app.js';
import { runAccessTest } from './access-test.js';

const ACTIONS = ['get', 'post', 'put', 'patch', 'delete'];
const PERMISSIONS = ['members', 'roles', 'policies', 'destinations'];

export class TenantPanel {
  /**
   * @param {object} opts
   * @param {HTMLElement} opts.mount     where to render
   * @param {Function} opts.api          the shared fetch wrapper
   * @param {boolean} [opts.isPlatform]  caller is a platform admin (unlocks owner reassignment)
   * @param {Function} [opts.onChange]   called after any mutation, so the host can refresh its own list
   */
  constructor({ mount, api, isPlatform = false, onChange = () => {} }) {
    this.mount = mount;
    this.api = api;
    this.isPlatform = isPlatform;
    this.onChange = onChange;
    this.state = { tenant: null, roles: [], policies: [], users: [], requests: [], requestFilter: 'pending' };
    this.mount.addEventListener('click', (e) => this.onClick(e));
    this.mount.addEventListener('submit', (e) => this.onSubmit(e));
    this.mount.addEventListener('change', (e) => {
      if (e.target.matches('[data-request-filter]')) {
        this.state.requestFilter = e.target.value;
        this.loadRequests().then(() => this.render());
      } else if (e.target.matches('input[data-perm]')) {
        this.savePermissions(e.target.dataset.user);
      }
    });
  }

  get id() { return this.state.tenant?.id; }

  /** May the signed-in account do this part of administering the tenant? */
  can(permission) { return (this.state.tenant?.permissions || []).includes(permission); }
  /** The member list and the request queue are for whoever manages members or roles. */
  get seesUsers() { return this.can('members') || this.can('roles'); }

  /** Sends exactly the boxes that are ticked for this user. */
  async savePermissions(username) {
    const permissions = [...this.mount.querySelectorAll('input[data-perm]:checked')]
      .filter((box) => box.dataset.user === username)
      .map((box) => box.dataset.perm);
    try {
      const res = await this.api(
        `/tenants/${encodeURIComponent(this.id)}/users/${encodeURIComponent(username)}/permissions`,
        { method: 'PUT', body: { permissions } },
      );
      ok(res.message);
    } catch { /* already surfaced by api() */ }
    await this.refresh();
  }
  get endpoints() { return this.state.tenant?.service?.endpoints || []; }

  async load(tenantId) {
    const t = encodeURIComponent(tenantId);
    this.state.tenant = await this.api(`/tenants/${t}`);
    const [roles, policies, users] = await Promise.all([
      this.api(`/tenants/${t}/roles`),
      this.api(`/tenants/${t}/policies`),
      this.seesUsers ? this.api(`/tenants/${t}/users`) : { users: [] },
    ]);
    this.state.roles = roles.roles;
    this.state.policies = policies.policies;
    this.state.users = users.users;
    if (this.seesUsers) await this.loadRequests(); else this.state.requests = [];
    this.render();
  }

  async loadRequests() {
    const f = this.state.requestFilter;
    const res = await this.api(
      `/tenants/${encodeURIComponent(this.id)}/requests${f ? `?status=${encodeURIComponent(f)}` : ''}`,
    );
    this.state.requests = res.requests;
  }

  async refresh() {
    await this.load(this.id);
    this.onChange();
  }

  clear() {
    this.state.tenant = null;
    this.mount.innerHTML = '';
  }

  // ── render ──────────────────────────────────────────────────────────────

  render() {
    if (!this.state.tenant) { this.mount.innerHTML = ''; return; }
    this.mount.innerHTML = [
      this.renderService(),
      this.renderRoles(),
      this.renderPolicies(),
      this.seesUsers ? this.renderUsers() : '',
      this.seesUsers ? this.renderRequests() : '',
    ].join('');
  }

  renderService() {
    const t = this.state.tenant;
    const s = t.service;
    return `
      <div class="sub">
        <h3>Service &amp; routes</h3>
        ${s ? `
          <dl class="kv">
            <dt>Gateway</dt><dd>/gateway/${esc(t.id)}/…</dd>
            <dt>Base URL</dt><dd>${esc(s.baseUrl)}</dd>
            <dt>Catalog</dt><dd>${s.catalogUrl ? esc(s.catalogUrl) : '<span class="muted">none — not health-checked</span>'}</dd>
            <dt>Version</dt><dd>${esc(s.version || 'unknown')}</dd>
            <dt>State</dt><dd>${badge(t.status, t.status)} ${badge(s.health, `service ${s.health}`)}</dd>
          </dl>
        ` : `
          <p class="empty">No service registered yet — give it a base URL below and it becomes routable.</p>
        `}

        ${this.can('destinations') ? `<form data-form="service" class="grid" style="margin-top:14px">
          <label class="field">Base URL
            <input name="baseUrl" placeholder="http://localhost:9090" value="${esc(s?.baseUrl || '')}">
          </label>
          <label class="field">Catalog URL <span class="tip">optional</span>
            <input name="catalogUrl" placeholder="http://localhost:9090/catalog" value="${esc(s?.catalogUrl || '')}">
          </label>
          <label class="field">Version
            <input name="version" placeholder="v1" value="${esc(s?.version === 'unknown' ? '' : s?.version || '')}">
          </label>
          <label class="field" style="grid-column:1/-1">Endpoints <span class="tip">comma separated — each must start with /${esc(t.id)}/</span>
            <input name="endpoints" placeholder="/${esc(t.id)}/alpha, /${esc(t.id)}/beta" value="${esc(this.endpoints.join(', '))}">
          </label>
          <div class="row" style="grid-column:1/-1">
            <button type="submit">Save service</button>
            ${s?.catalogUrl ? '<button type="button" class="ghost" data-act="sync-catalog" title="Re-read endpoints, version and owner from the catalog URL">Re-read from catalog</button>' : ''}
            ${t.isAdmin ? `<button type="button" class="ghost" data-act="toggle-status">
              ${t.status === 'active' ? 'Suspend tenant' : 'Reactivate tenant'}
            </button>
            <span class="muted">${t.status === 'active'
              ? 'Suspending stops all gateway traffic immediately, without touching policies.'
              : 'Suspended — the gateway is refusing every request to this service.'}</span>` : ''}
          </div>
        </form>` : ''}
      </div>`;
  }

  renderRoles() {
    const rows = this.state.roles.map((r) => `
      <tr>
        <td class="mono">${esc(r.role)}</td>
        <td>${r.members.length}</td>
        <td>${r.policies.length
          ? r.policies.map((p) => `<span class="chip navy">${esc(p.action)} ${esc(p.resource)}</span>`).join('')
          : '<span class="muted">reaches nothing</span>'}</td>
        <td class="nowrap">${this.can('roles') ? `<button class="danger tiny" data-act="del-role" data-role="${esc(r.role)}">Delete</button>` : ''}</td>
      </tr>`).join('');

    return `
      <div class="sub">
        <h3>Roles</h3>
        <div class="scroll-x">
          <table>
            <thead><tr><th>Role</th><th>Members</th><th>Can reach</th><th></th></tr></thead>
            <tbody>${rows || '<tr><td colspan="4" class="empty">No roles yet.</td></tr>'}</tbody>
          </table>
        </div>
        ${this.can('roles') ? `<form data-form="role" class="row" style="margin-top:12px">
          <input name="role" placeholder="engineer" required>
          <button type="submit">Add role</button>
          <span class="muted">Private to this tenant — another tenant may use the same name.</span>
        </form>` : ''}
      </div>`;
  }

  renderPolicies() {
    const rows = this.state.policies.map((p) => `
      <tr>
        <td class="mono">${esc(p.role)}</td>
        <td><code>${esc(p.resource)}</code></td>
        <td><span class="badge info plain">${esc(p.action)}</span></td>
        <td class="nowrap">${p.condition ? `<span class="muted" title="${esc(JSON.stringify(p.condition))}">conditional</span> ` : ''}${this.can('policies') ? `<button class="danger tiny" data-act="del-policy"
          data-role="${esc(p.role)}" data-resource="${esc(p.resource)}" data-action="${esc(p.action)}">Remove</button>` : ''}</td>
      </tr>`).join('');

    // Offer the service's real endpoints plus a catch-all, so a policy cannot
    // be written against a path this service does not actually serve.
    const paths = [...this.endpoints, `/${this.id}/*`];

    return `
      <div class="sub">
        <h3>Policies</h3>
        <div class="scroll-x">
          <table>
            <thead><tr><th>Role</th><th>Resource</th><th>Action</th><th></th></tr></thead>
            <tbody>${rows || '<tr><td colspan="4" class="empty">No policies — nobody can reach this service yet.</td></tr>'}</tbody>
          </table>
        </div>
        ${this.can('policies') ? `<form data-form="policy" class="row" style="margin-top:12px">
          <select name="role" required>${this.state.roles.map((r) => `<option value="${esc(r.role)}">${esc(r.role)}</option>`).join('')}</select>
          <select name="resource" required>${paths.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join('')}</select>
          <select name="action">${ACTIONS.map((a) => `<option value="${a}">${a}</option>`).join('')}</select>
          <button type="submit" ${this.state.roles.length ? '' : 'disabled'}>Allow</button>
          ${this.state.roles.length ? '' : '<span class="muted">Define a role first.</span>'}
        </form>` : ''}
      </div>`;
  }

  renderUsers() {
    const t = this.state.tenant;
    const roleOptions = this.state.roles.map((r) => `<option value="${esc(r.role)}">${esc(r.role)}</option>`).join('');

    const rows = this.state.users.map((u) => `
      <tr>
        <td>
          <div class="row" style="gap:6px">
            <span class="mono">${esc(u.username)}</span>
            ${t.owner === u.username ? badge('info', 'owner') : ''}
            ${u.isAdmin && t.owner !== u.username ? badge('info', 'admin') : ''}
          </div>
        </td>
        <td>${chips(u.roles, { removable: this.can('roles'), data: { act: 'revoke', user: u.username }, valueAttr: 'role', cls: 'navy' })
          || '<span class="muted">no role</span>'}</td>
        <td class="nowrap">${u.isAdmin
          ? '<span class="muted">everything</span>'
          : PERMISSIONS.map((p) => `<label style="margin-right:8px"><input type="checkbox" data-perm="${p}" data-user="${esc(u.username)}"
              ${(u.permissions || []).includes(p) ? 'checked' : ''} ${t.isAdmin ? '' : 'disabled'}> ${p}</label>`).join('')}</td>
        <td>
          <div class="row">
            <select data-grant-for="${esc(u.username)}"><option value="">grant role…</option>${roleOptions}</select>
            <button class="ghost tiny" data-act="grant" data-user="${esc(u.username)}">Grant</button>
            <button class="ghost tiny" data-act="test" data-user="${esc(u.username)}">Test</button>
            ${!t.isAdmin ? '' : u.isAdmin
              ? `<button class="ghost tiny" data-act="demote" data-user="${esc(u.username)}">Remove admin</button>`
              : `<button class="ghost tiny" data-act="promote" data-user="${esc(u.username)}">Make admin</button>`}
            <button class="danger tiny" data-act="remove-user" data-user="${esc(u.username)}">Remove</button>
          </div>
        </td>
      </tr>`).join('');

    return `
      <div class="sub">
        <h3>Users</h3>
        <div class="scroll-x">
          <table>
            <thead><tr><th>User</th><th>Roles here</th><th>May manage</th><th></th></tr></thead>
            <tbody>${rows || '<tr><td colspan="4" class="empty">Nobody yet.</td></tr>'}</tbody>
          </table>
        </div>
        <form data-form="add-user" class="row" style="margin-top:12px">
          <input name="username" placeholder="existing username" required>
          <select name="role"><option value="">no role yet</option>${roleOptions}</select>
          <button type="submit">Add to tenant</button>
          ${this.isPlatform
            ? '<button type="button" class="ghost" data-act="set-owner">Set owner…</button>'
            : ''}
          <span class="muted">Accounts are platform-wide — you grant access, you don't create the account.</span>
        </form>
      </div>`;
  }

  renderRequests() {
    const roleOptions = this.state.roles.map((r) => `<option value="${esc(r.role)}">${esc(r.role)}</option>`).join('');
    const rows = this.state.requests.map((r) => `
      <tr>
        <td><span class="mono">${esc(r.username)}</span><div class="muted">${esc(relTime(r.requestedAt))}</div></td>
        <td>${r.role ? `<span class="chip navy">${esc(r.role)}</span>` : '<span class="muted">access to the service</span>'}</td>
        <td class="muted">${esc(r.note || '')}</td>
        <td>
          ${badge(r.status, r.status)}
          ${r.grantedRole ? `<div class="muted">granted ${esc(r.grantedRole)}</div>` : ''}
          ${r.resolvedBy ? `<div class="muted">by ${esc(r.resolvedBy)}</div>` : ''}
        </td>
        <td class="nowrap">${r.status === 'pending' ? `
          <div class="row">
            <select data-approve-for="${esc(r.id)}">
              ${r.role ? `<option value="${esc(r.role)}">${esc(r.role)}</option>` : '<option value="">pick a role…</option>'}
              ${roleOptions}
            </select>
            <button class="tiny" data-act="approve" data-id="${esc(r.id)}">Approve</button>
            <button class="danger tiny" data-act="reject" data-id="${esc(r.id)}">Reject</button>
          </div>` : ''}</td>
      </tr>`).join('');

    return `
      <div class="sub">
        <h3>Access requests</h3>
        <div class="row" style="margin-bottom:10px">
          <select data-request-filter>
            ${['pending', '', 'approved', 'rejected'].map((v) => `
              <option value="${v}" ${v === this.state.requestFilter ? 'selected' : ''}>${v || 'all'}</option>`).join('')}
          </select>
          <span class="muted">People asking for a role here. Approving grants it immediately.</span>
        </div>
        <div class="scroll-x">
          <table>
            <thead><tr><th>User</th><th>Wants</th><th>Note</th><th>Status</th><th></th></tr></thead>
            <tbody>${rows || '<tr><td colspan="5" class="empty">No requests.</td></tr>'}</tbody>
          </table>
        </div>
      </div>`;
  }

  // ── behaviour ───────────────────────────────────────────────────────────

  async onSubmit(e) {
    const form = e.target.closest('form[data-form]');
    if (!form) return;
    e.preventDefault();
    const t = encodeURIComponent(this.id);
    const data = Object.fromEntries(new FormData(form).entries());

    try {
      if (form.dataset.form === 'service') {
        const payload = {};
        if (data.baseUrl?.trim()) payload.baseUrl = data.baseUrl.trim();
        if (data.catalogUrl !== undefined) payload.catalogUrl = data.catalogUrl.trim();
        if (data.version?.trim()) payload.version = data.version.trim();
        payload.endpoints = parseList(data.endpoints);
        const res = await this.api(`/tenants/${t}/service`, { method: 'PATCH', body: payload });
        ok(res.message);
      } else if (form.dataset.form === 'role') {
        await this.api(`/tenants/${t}/roles`, { method: 'POST', body: { role: data.role.trim() } });
        ok(`Role '${data.role.trim()}' defined`);
        form.reset();
      } else if (form.dataset.form === 'policy') {
        await this.api(`/tenants/${t}/policies`, {
          method: 'POST',
          body: { role: data.role, resource: data.resource, action: data.action },
        });
        ok(`${data.role} can now ${data.action} ${data.resource}`);
      } else if (form.dataset.form === 'add-user') {
        await this.api(`/tenants/${t}/users`, {
          method: 'POST',
          body: { username: data.username.trim(), ...(data.role ? { role: data.role } : {}) },
        });
        ok(`'${data.username.trim()}' added`);
        form.reset();
      }
      await this.refresh();
    } catch { /* already surfaced by api() */ }
  }

  async onClick(e) {
    const btn = e.target.closest('button[data-act], .chip button[data-act]');
    if (!btn) return;
    const t = encodeURIComponent(this.id);
    const { act } = btn.dataset;
    // Read both explicitly. A remove-chip button carries the username AND the
    // role it removes, so anything that collapses the two picks the wrong one.
    const user = btn.dataset.user;
    const role = btn.dataset.role;

    try {
      switch (act) {
        case 'toggle-status': {
          const next = this.state.tenant.status === 'active' ? 'suspended' : 'active';
          if (next === 'suspended'
            && !confirmDanger(`Suspend '${this.id}'?\n\nAll gateway traffic to it stops immediately.`)) return;
          await this.api(`/tenants/${t}`, { method: 'PATCH', body: { status: next } });
          ok(`Tenant ${next}`);
          break;
        }
        case 'sync-catalog':
          // The registry no longer copies a service's catalog on a timer;
          // adopting what it advertises is something its admin asks for.
          ok((await this.api(`/tenants/${t}/service`, { method: 'PATCH', body: { syncFromCatalog: true } })).message);
          break;
        case 'del-role':
          if (!confirmDanger(`Delete role '${btn.dataset.role}'?\n\nIts policies and every grant of it go too.`)) return;
          await this.api(`/tenants/${t}/roles/${encodeURIComponent(btn.dataset.role)}`, { method: 'DELETE' });
          ok('Role deleted');
          break;
        case 'del-policy':
          await this.api(`/tenants/${t}/policies`, {
            method: 'DELETE',
            body: { role: btn.dataset.role, resource: btn.dataset.resource, action: btn.dataset.action },
          });
          ok('Policy removed');
          break;
        case 'revoke':
          await this.api(`/tenants/${t}/users/${encodeURIComponent(user)}/roles/${encodeURIComponent(role)}`,
            { method: 'DELETE' });
          ok(`Role '${role}' revoked from '${user}'`);
          break;
        case 'grant': {
          const sel = this.mount.querySelector(`select[data-grant-for="${CSS.escape(user)}"]`);
          if (!sel?.value) { err('Pick a role to grant first'); return; }
          await this.api(`/tenants/${t}/users/${encodeURIComponent(user)}/roles`,
            { method: 'POST', body: { role: sel.value } });
          ok('Role granted');
          break;
        }
        case 'promote':
          await this.api(`/tenants/${t}/users/${encodeURIComponent(user)}/admin`, { method: 'POST' });
          ok(`'${user}' can now administer this tenant`);
          break;
        case 'demote':
          await this.api(`/tenants/${t}/users/${encodeURIComponent(user)}/admin`, { method: 'DELETE' });
          ok(`'${user}' is no longer an administrator here`);
          break;
        case 'remove-user':
          if (!confirmDanger(`Remove '${user}' from this tenant?\n\nEvery role they hold here is revoked.`)) return;
          await this.api(`/tenants/${t}/users/${encodeURIComponent(user)}`, { method: 'DELETE' });
          ok(`'${user}' removed`);
          break;
        case 'set-owner': {
          const username = window.prompt(`Make which account the owner of '${this.id}'?`, this.state.tenant.owner || '');
          if (!username) return;
          await this.api(`/admin/tenants/${t}/owner`, { method: 'POST', body: { username: username.trim() } });
          ok(`'${username.trim()}' now owns '${this.id}'`);
          break;
        }
        case 'approve': {
          const sel = this.mount.querySelector(`select[data-approve-for="${CSS.escape(btn.dataset.id)}"]`);
          if (!sel?.value) { err('Pick a role to approve with'); return; }
          await this.api(`/tenants/${t}/requests/${encodeURIComponent(btn.dataset.id)}/approve`,
            { method: 'POST', body: { role: sel.value } });
          ok('Request approved');
          break;
        }
        case 'reject':
          await this.api(`/tenants/${t}/requests/${encodeURIComponent(btn.dataset.id)}/reject`, { method: 'POST' });
          ok('Request rejected');
          break;
        case 'test':
          await this.showAccessTest(user);
          return; // opens a modal; nothing changed
        default:
          return;
      }
      await this.refresh();
    } catch { /* already surfaced by api() */ }
  }

  /**
   * The access test answers "did what I just configure actually work". The
   * gateway evaluates it with the same decision function its proxy route
   * uses, without issuing a token for the member or calling the service, so
   * testing someone never puts their credential in anyone else's hands. See
   * assets/access-test.js.
   */
  async showAccessTest(username) {
    await runAccessTest(this.api, {
      path: `/tenants/${encodeURIComponent(this.id)}/users/${encodeURIComponent(username)}/test-access`,
      title: `Access test — ${username}`,
      subtitle: (r) => `Roles in ${r.tenant}: ${r.roles.length ? r.roles.join(', ') : 'none'}`,
    });
  }
}

// Re-exported from access-test.js so a host page has one import to make.
export { accessTestModalHtml as testModalHtml, wireAccessTestModal as wireTestModal } from './access-test.js';
