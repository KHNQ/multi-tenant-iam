import { createMemoryHistory } from 'vue-router'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ApplicationsView from '@/views/ApplicationsView.vue'
import { createAppRouter } from '@/router.js'
import { setApiBase } from '@/config.js'
import { messageFor } from '@/api.js'

const session = {
  username: 'operator', tenants: ['samta'],
  permissions: { tenantAdmin: true, platformAdmin: false },
}
const base = '/api/tenants/samta/applications/samta-mapdashboard-web-poc'
const calls = []
let imports
const pendingImports = () => ({
  source: 'https://mapdashboard.internal/api/permissions/catalog', canApprove: true,
  items: [
    { key: 'remoteapps.manage', category: 'RemoteApps', description: 'Manage remotes.', kind: 'create',
      fingerprint: 'fp-remote', importable: true, status: 'pending' },
    { key: 'objects.read', category: 'Objects', description: 'View objects.', kind: 'update',
      keycloakCategory: '', keycloakDescription: 'View objects.', fingerprint: 'fp-read',
      importable: true, status: 'failed', lastError: 'upstream_denied', decidedBy: 'operator' },
  ],
  notDeclaredByApplication: ['legacy.export'],
  history: [{ key: 'objects.read', kind: 'update', status: 'failed', decidedBy: 'operator', lastError: 'upstream_denied' }],
})

beforeEach(() => {
  setApiBase('')
  calls.length = 0
  imports = pendingImports()
  vi.stubGlobal('crypto', { randomUUID: () => 'key-1' })
  document.cookie = 'XSRF-TOKEN=csrf-token'
  vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
    const method = options.method ?? 'GET'
    calls.push({ method, url, options })
    const responses = {
      [`GET ${base}/permissions`]: [
        { key: 'objects.read', category: 'Objects', description: 'View objects.' },
      ],
      [`GET ${base}/roles`]: [
        { name: 'admin', system: true, permissions: ['objects.read'], fingerprint: 'role-a' },
        { name: 'viewer', system: true, permissions: ['objects.read'], fingerprint: 'role-v' },
        { name: 'editor', system: false, permissions: ['objects.read'], fingerprint: 'role-e' },
      ],
      [`GET ${base}/permissions/import-requests`]: imports,
      [`POST ${base}/permissions/import-requests`]: { key: 'remoteapps.manage', status: 'approved' },
      'GET /api/tenants/samta/users?search=alice': {
        users: [{ id: 'u1', username: 'alice' }],
      },
      [`GET ${base}/users/u1/effective-access`]: {
        userId: 'u1', username: 'alice', directRoles: ['viewer'], effectiveRoles: ['viewer'],
        permissions: ['objects.read'], permissionOrigins: { 'objects.read': ['direct:viewer'] },
      },
      [`POST ${base}/users/u1/role-changes/preview`]: {
        fingerprint: 'state-1', permissionsLost: ['objects.read'], permissionsGained: [],
      },
      [`POST ${base}/users/u1/role-changes`]: {
        userId: 'u1', username: 'alice', directRoles: [], effectiveRoles: [],
        permissions: [], permissionOrigins: {},
      },
    }
    const body = responses[`${method} ${url}`]
    return {
      ok: body !== undefined, status: body === undefined ? 404 : 200,
      headers: { get: () => null }, json: async () => body ?? { error: 'not_found' },
    }
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
  setApiBase('')
})

async function mountView(path = '/applications/mapdashboard') {
  const router = createAppRouter(() => session, { history: createMemoryHistory() })
  router.push(path)
  await router.isReady()
  const host = document.createElement('div')
  document.body.appendChild(host)
  const shadow = host.attachShadow({ mode: 'open' })
  const target = document.createElement('div')
  shadow.appendChild(target)
  const wrapper = mount(ApplicationsView, { attachTo: target, props: { session },
    global: { plugins: [router] } })
  await flushPromises()
  return { wrapper, host }
}

describe('MapDashboard application access', () => {
  it('explains optional configuration absence without exposing a raw error code', () => {
    expect(messageFor({ code: 'APPLICATION_ACCESS_NOT_CONFIGURED' }))
      .toContain('not configured in IAM yet')
  })

  it('lists pending permissions and approves one with its fingerprint', async () => {
    const { wrapper, host } = await mountView()
    await wrapper.find('#access-tab-pending').trigger('click')
    const panel = wrapper.find('[data-test="permission-imports"]')
    expect(panel.text()).toContain('remoteapps.manage')
    expect(panel.text()).toContain('legacy.export')
    expect(panel.text()).toContain('refused by Keycloak')
    expect(wrapper.find('#access-tab-pending').text()).toContain('2')

    imports = pendingImports()
    imports.items[0].status = 'approved'
    await wrapper.find('[data-test="import-remoteapps.manage"]').findAll('button')
      .find(button => button.text().includes('Approve')).trigger('click')
    await flushPromises()

    const decision = calls.find(call => call.method === 'POST')
    expect(decision.url).toBe(`${base}/permissions/import-requests`)
    expect(JSON.parse(decision.options.body)).toEqual({
      key: 'remoteapps.manage', fingerprint: 'fp-remote', decision: 'approve', reason: null,
    })
    expect(decision.options.headers['Idempotency-Key']).toBe('key-1')
    expect(wrapper.find('[data-test="import-remoteapps.manage"]').text()).toContain('importing soon')
    wrapper.unmount()
    host.remove()
  })

  it('bulk-approves selected permissions one fingerprinted decision at a time after confirmation', async () => {
    const { wrapper, host } = await mountView()
    await wrapper.find('#access-tab-pending').trigger('click')
    const toolbar = wrapper.find('[data-test="bulk-approve"]')
    expect(toolbar.text()).toContain('Select all (2)')
    await toolbar.find('input[type="checkbox"]').setValue(true)
    expect(toolbar.text()).toContain('Approve selected (2)')

    await toolbar.find('button').trigger('click')
    const confirm = wrapper.find('[data-test="bulk-confirm"]')
    expect(confirm.text()).toContain('remoteapps.manage')
    expect(confirm.text()).toContain('objects.read')
    expect(calls.filter(call => call.method === 'POST')).toEqual([])

    await confirm.findAll('button').find(button => button.text() === 'Approve 2').trigger('click')
    await flushPromises()

    const decisions = calls.filter(call => call.method === 'POST').map(call => JSON.parse(call.options.body))
    expect(decisions).toEqual([
      { key: 'remoteapps.manage', fingerprint: 'fp-remote', decision: 'approve', reason: null },
      { key: 'objects.read', fingerprint: 'fp-read', decision: 'approve', reason: null },
    ])
    expect(wrapper.find('[data-test="bulk-result"]').text()).toContain('2 approved, 0 failed.')
    expect(wrapper.find('[data-test="bulk-confirm"]').exists()).toBe(false)
    wrapper.unmount()
    host.remove()
  })

  it('opens on the tab named in the query, ignoring unknown tabs', async () => {
    const pending = await mountView('/applications/mapdashboard?tab=pending')
    expect(pending.wrapper.find('#access-tab-pending').attributes('aria-selected')).toBe('true')
    pending.wrapper.unmount()
    pending.host.remove()
    const unknown = await mountView('/applications/mapdashboard?tab=secrets')
    expect(unknown.wrapper.find('#access-tab-roles').attributes('aria-selected')).toBe('true')
    unknown.wrapper.unmount()
    unknown.host.remove()
  })

  it('rejects with a reason', async () => {
    const { wrapper, host } = await mountView()
    const item = wrapper.find('[data-test="import-remoteapps.manage"]')
    await item.findAll('button').find(button => button.text() === 'Reject').trigger('click')
    await item.find('input[name="reject-reason"]').setValue('  not this release ')
    await item.find('form').trigger('submit')
    await flushPromises()

    const decision = calls.find(call => call.method === 'POST')
    expect(JSON.parse(decision.options.body)).toMatchObject({ decision: 'reject', reason: 'not this release' })
    wrapper.unmount()
    host.remove()
  })

  it('shows the queue read-only to administrators without the approver role', async () => {
    imports = { ...pendingImports(), canApprove: false }
    const { wrapper, host } = await mountView()
    const panel = wrapper.find('[data-test="permission-imports"]')
    expect(panel.text()).toContain('approve-permissions:samta-mapdashboard-web-poc')
    expect(panel.findAll('button').filter(button => /Approve|Reject/.test(button.text()))).toEqual([])
    wrapper.unmount()
    host.remove()
  })

  it('explains an unreachable catalogue without a raw error code', () => {
    expect(messageFor({ code: 'catalog_unavailable' })).toContain('could not be reached')
  })

  it('groups the catalogue and locks system role editing inside a shadow root', async () => {
    const { wrapper, host } = await mountView()
    expect(wrapper.text()).toContain('Objects')
    expect(wrapper.text()).toContain('objects.read')
    await wrapper.findAll('button').find(button => button.text().includes('admin')).trigger('click')
    expect(wrapper.text()).toContain('System roles are managed')
    expect(host.shadowRoot.textContent).toContain('MapDashboard access')
    wrapper.unmount()
    host.remove()
  })

  it('filters the catalogue and role list without changing selected permissions', async () => {
    const { wrapper, host } = await mountView()
    const searches = wrapper.findAll('input[type="search"]')
    await searches[0].setValue('missing')
    expect(wrapper.find('.catalogue-grid').text()).not.toContain('objects.read')
    expect(wrapper.text()).toContain('No permissions found.')
    expect(wrapper.find('.role-editor').text()).toContain('objects.read')
    await searches[0].setValue('view objects')
    expect(wrapper.find('.catalogue-grid').text()).toContain('objects.read')
    await searches[1].setValue('viewer')
    expect(wrapper.find('.role-sidebar').text()).toContain('viewer')
    expect(wrapper.find('.role-sidebar').text()).not.toContain('admin')
    expect(calls.filter(call => call.method !== 'GET')).toEqual([])
    wrapper.unmount()
    host.remove()
  })

  it('opens role details first and only edits after an explicit action', async () => {
    const { wrapper, host } = await mountView()
    expect(wrapper.find('[role="tab"][aria-selected="true"]').text()).toContain('Roles')
    expect(wrapper.find('#access-panel-roles input[type="checkbox"]').exists()).toBe(false)
    await wrapper.findAll('.role-item').find(role => role.text().includes('editor')).trigger('click')
    expect(wrapper.find('.role-editor').text()).toContain('objects.read')
    await wrapper.findAll('button').find(button => button.text() === 'Edit').trigger('click')
    const checkbox = wrapper.find('.permission-option input')
    expect(checkbox.element.checked).toBe(true)
    await wrapper.find('input[name="role-permission-search"]').setValue('missing')
    expect(wrapper.findAll('.permission-option')).toHaveLength(0)
    expect(wrapper.find('.role-editor').text()).toContain('1 permissions selected')
    await wrapper.findAll('button').find(button => button.text() === 'Cancel').trigger('click')
    expect(wrapper.find('.permission-option').exists()).toBe(false)
    expect(calls.filter(call => call.method !== 'GET')).toEqual([])
    wrapper.unmount()
    host.remove()
  })

  it('supports keyboard tab navigation and shows category-only changes accurately', async () => {
    const { wrapper, host } = await mountView()
    await wrapper.find('[role="tab"]').trigger('keydown', { key: 'ArrowRight' })
    expect(wrapper.find('[role="tab"][aria-selected="true"]').text()).toContain('Permissions')
    expect(wrapper.find('#access-panel-roles').element.style.display).toBe('none')
    const panel = wrapper.find('[data-test="import-objects.read"]')
    expect(panel.text()).toContain('In IAM: No category')
    expect(panel.text()).toContain('In MapDashboard: Objects')
    expect(panel.text()).not.toContain('In IAM: View objects.')
    wrapper.unmount()
    host.remove()
  })

  it('shows revocation impact before sending the fingerprinted mutation', async () => {
    const { wrapper, host } = await mountView()
    await wrapper.find('input[placeholder="Find a user"]').setValue('alice')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === 'alice').trigger('click')
    await flushPromises()
    const selects = wrapper.findAll('select')
    await selects[0].setValue('revoke')
    await selects[1].setValue('viewer')
    await wrapper.findAll('button').find(button => button.text() === 'Preview impact').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('Permissions lost: objects.read')
    expect(calls.filter(call => call.url.endsWith('/role-changes'))).toHaveLength(0)
    await wrapper.findAll('button').find(button => button.text() === 'Confirm change').trigger('click')
    await flushPromises()
    const mutation = calls.find(call => call.url.endsWith('/role-changes'))
    expect(JSON.parse(mutation.options.body)).toMatchObject({
      action: 'revoke', role: 'viewer', fingerprint: 'state-1',
    })
    expect(mutation.options.headers['Idempotency-Key']).toBe('key-1')
    wrapper.unmount()
    host.remove()
  })
})
