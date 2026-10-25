import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { createRouter, createWebHistory } from 'vue-router'
import AppShell from '@/components/AppShell.vue'
import AccessTest from '@/components/access/AccessTest.vue'
import DashboardView from '@/views/DashboardView.vue'
import PlatformView from '@/views/PlatformView.vue'
import SessionsView from '@/views/SessionsView.vue'
import UsersView from '@/views/UsersView.vue'
import { routes } from '@/router.js'
import { session } from '@/sessionState.js'
import { messageFor } from '@/api.js'

/**
 * System 2 (failover) additions: the console says when it is the standby
 * system, offers no edits there except the emergency ones, shows the mode and
 * the last synchronisation, manages sync and signing keys, and runs the access
 * test.
 */

const admin = (mode) => ({
  username: 'padmin', email: 'padmin@iam.poc.local', roles: ['platform-admin'],
  permissions: { platformAdmin: true, tenantAdmin: true }, crossTenant: true, tenants: ['tenant-alpha'], mode,
})

let responses
let sent

function respond(url, options = {}) {
  const method = options.method ?? 'GET'
  sent.push({ method, url, options })
  const entry = Object.entries(responses).filter(([key]) => `${method} ${url}`.startsWith(key))
    .sort(([a], [b]) => b.length - a.length)[0]
  const body = entry ? entry[1] : { error: 'not_found' }
  return { ok: !body.error, status: body.error ? 404 : 200, headers: { get: () => null }, json: async () => body }
}

beforeEach(() => {
  sent = []
  responses = {
    'GET /api/status': {
      overall: 'operational', mode: 'standby', lastSuccessfulSync: '2026-10-24T10:00:00.000Z',
      dependencies: [{ name: 'identity-provider', state: 'operational' }],
    },
    'GET /api/tenants/tenant-alpha/users': {
      tenant: 'tenant-alpha', count: 1, first: 0, limit: 20, total: 1, hasMore: false,
      users: [{ id: 'u1', username: 'alice', email: 'alice@x', enabled: true }],
    },
  }
  vi.stubGlobal('fetch', vi.fn(async (url, options) => respond(url, options)))
  vi.stubGlobal('crypto', { randomUUID: () => 'key-1', getRandomValues: (a) => a })
  document.cookie = 'XSRF-TOKEN=csrf-token'
})

afterEach(() => {
  session.value = null
  vi.unstubAllGlobals()
})

const RouterLinkStub = { template: '<a><slot /></a>' }

describe('standby', () => {
  it('shows the backup-system banner only in standby', async () => {
    const router = createRouter({ history: createWebHistory('/ui/'), routes })
    router.push('/')
    await router.isReady()
    session.value = admin('standby')
    const standbyShell = mount(AppShell, { props: { session: session.value }, global: { plugins: [router] } })
    expect(standbyShell.find('[data-testid="standby-banner"]').text()).toContain('This is the backup system')
    session.value = admin('primary')
    const primaryShell = mount(AppShell, { props: { session: session.value }, global: { plugins: [router] } })
    expect(primaryShell.find('[data-testid="standby-banner"]').exists()).toBe(false)
  })

  it('shows the operating mode and the last successful sync on the overview', async () => {
    session.value = admin('standby')
    const wrapper = mount(DashboardView, { props: { session: session.value }, global: { stubs: { RouterLink: RouterLinkStub } } })
    await flushPromises()
    const block = wrapper.find('[data-testid="idp-mode"]')
    expect(block.text()).toContain('standby')
    expect(block.text()).toContain('Last successful sync')
    expect(block.text()).not.toContain('never')
  })

  it('disables editing but keeps the emergency lock', async () => {
    session.value = admin('standby')
    const wrapper = mount(UsersView, { props: { session: session.value }, global: { stubs: { RouterLink: RouterLinkStub } } })
    await flushPromises()
    const button = (label) => wrapper.findAll('button').find((b) => b.text() === label)
    expect(button('New user').attributes('disabled')).toBeDefined()
    expect(button('Edit').attributes('disabled')).toBeDefined()
    expect(button('Credentials').attributes('disabled')).toBeDefined()
    expect(button('Disable').attributes('disabled')).toBeUndefined()
  })

  it('keeps session termination available', async () => {
    session.value = admin('standby')
    responses['GET /api/tenants/tenant-alpha/users/u1/sessions'] = {
      sessions: [{ id: 's1', ipAddress: '10.0.0.4', started: 1, lastAccess: 2, clients: { app: 'app' } }],
    }
    const wrapper = mount(SessionsView, { props: { session: session.value, embedded: true, user: { id: 'u1', username: 'alice' }, tenantKey: 'tenant-alpha' } })
    await flushPromises()
    const terminate = wrapper.findAll('button').find((b) => b.text() === 'Terminate')
    expect(terminate.attributes('disabled')).toBeUndefined()
  })

  it('explains a refused change in the operator\'s terms', () => {
    expect(messageFor({ code: 'standby_read_only' })).toContain('primary system')
  })
})

describe('platform settings: synchronisation and signing keys', () => {
  beforeEach(() => {
    responses['GET /api/admin/tenants'] = { tenants: [], count: 0, first: 0, limit: 50, total: 0, hasMore: false }
    responses['GET /api/admin/idp'] = {
      mode: { mode: 'standby', since: '2026-10-24T09:00:00.000Z', by: 'configuration' },
      health: {
        mode: 'standby', syncConfigured: true, lastSuccessfulSync: '2026-10-24T10:00:00.000Z', stale: false,
        realms: { samta: { source: 'sync', users: 12, ok: true, lastSuccess: '2026-10-24T10:00:00.000Z' } },
      },
      sync: { configured: true, intervalSeconds: 300 },
      realms: [{ name: 'samta', keys: [
        { kid: 'new-kid', status: 'active', createdAt: '2026-10-24T10:00:00.000Z', algorithm: 'RS256' },
        { kid: 'old-kid', status: 'passive', createdAt: '2026-10-01T10:00:00.000Z', algorithm: 'RS256' },
      ] }],
    }
    responses['POST /api/admin/idp/sync'] = { ok: true, realms: [] }
    responses['POST /api/admin/idp/realms/samta/keys/rotate'] = { realm: 'samta' }
  })

  it('loads the identity provider settings only when asked for', async () => {
    const wrapper = mount(PlatformView)
    await flushPromises()
    expect(sent.some((call) => call.url === '/api/admin/idp')).toBe(false)
    await wrapper.find('#platform-tab-sync').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="idp-mode-card"]').text()).toContain('standby')
    expect(wrapper.findAll('[data-testid="sync-row"]')).toHaveLength(1)
    await wrapper.find('[data-testid="sync-now"]').trigger('click')
    await flushPromises()
    const post = sent.find((call) => call.method === 'POST')
    expect(post.url).toBe('/api/admin/idp/sync')
    expect(post.options.headers['Idempotency-Key']).toBe('key-1')
    expect(post.options.headers['X-XSRF-TOKEN']).toBe('csrf-token')
  })

  it('lists active and passive keys and confirms a rotation before sending it', async () => {
    const wrapper = mount(PlatformView)
    await flushPromises()
    await wrapper.find('#platform-tab-keys').trigger('click')
    await flushPromises()
    const rows = wrapper.findAll('[data-testid="key-row"]')
    expect(rows).toHaveLength(2)
    expect(rows[1].text()).toContain('passive')
    await wrapper.findAll('button').find((b) => b.text() === 'Rotate key').trigger('click')
    expect(sent.filter((call) => call.method === 'POST')).toHaveLength(0)
    await wrapper.find('[data-testid="confirm-rotate-key"]').trigger('click')
    await flushPromises()
    expect(sent.find((call) => call.method === 'POST').url).toBe('/api/admin/idp/realms/samta/keys/rotate')
  })
})

describe('access test', () => {
  it('shows the verdict, every check and the claims', async () => {
    responses['GET /api/tenants/samta/clients'] = { clients: [{ clientId: 'samta-mapdashboard-web-poc' }, { clientId: 'api', bearerOnly: true }] }
    responses['POST /api/tenants/samta/users/u1/access-test'] = {
      clientId: 'samta-mapdashboard-web-poc', allowed: false,
      checks: [{ key: 'account_enabled', ok: true }, { key: 'md_roles_role', ok: false }],
      accessToken: { sub: 'u1', md_roles: ['perm:objects.read'] }, idToken: null, userinfo: { sub: 'u1' },
    }
    const wrapper = mount(AccessTest, { props: { tenant: 'samta', user: { id: 'u1', username: 'operator1' } } })
    await flushPromises()
    expect(wrapper.findAll('option').map((o) => o.text())).toEqual(['Choose an application', 'samta-mapdashboard-web-poc'])
    await wrapper.find('select').setValue('samta-mapdashboard-web-poc')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const post = sent.find((call) => call.method === 'POST')
    expect(JSON.parse(post.options.body)).toEqual({ clientId: 'samta-mapdashboard-web-poc', scope: 'openid profile email' })
    expect(wrapper.find('[data-testid="access-test-verdict"]').text()).toContain('cannot sign in')
    expect(wrapper.findAll('[data-testid="access-test-check"]')[1].text()).toContain('fail')
    expect(wrapper.find('[data-testid="access-test-access"]').text()).toContain('perm:objects.read')
    expect(wrapper.text()).toContain('No ID token')
  })
})
