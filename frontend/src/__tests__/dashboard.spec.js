import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import DashboardView from '@/views/DashboardView.vue'

/**
 * IAM-0208: the dashboard must be tenant-bound, and must show a degraded platform
 * without disclosing anything about why it is degraded.
 */

const RouterLinkStub = { template: '<a><slot /></a>' }

function mountDashboard(session) {
  return mount(DashboardView, {
    props: { session },
    global: { stubs: { RouterLink: RouterLinkStub } },
  })
}

const platformAdmin = {
  username: 'padmin',
  email: 'padmin@iam.poc.local',
  roles: ['platform-admin'],
  permissions: { platformAdmin: true, tenantAdmin: true },
  crossTenant: true,
  tenants: ['tenant-alpha', 'tenant-beta'],
}

const tenantAdmin = {
  username: 'tadmin',
  email: 'tadmin@iam.poc.local',
  roles: ['tenant-admin'],
  permissions: { platformAdmin: false, tenantAdmin: true },
  crossTenant: false,
  tenants: ['tenant-alpha'],
}

function respond(map) {
  return vi.fn(async (url) => {
    const entry = Object.entries(map).find(([path]) => url.startsWith(path))
    if (!entry) {
      throw new Error(`unexpected fetch: ${url}`)
    }
    const [, value] = entry
    return {
      ok: value.ok ?? true,
      status: value.status ?? 200,
      headers: { get: (name) => value.headers?.[name] ?? null },
      json: async () => value.body,
    }
  })
}

const operational = {
  overall: 'operational',
  component: 'iam-bff',
  dependencies: [
    { name: 'identity-provider', state: 'operational' },
    { name: 'authorization-service', state: 'operational' },
  ],
}

const alphaUsers = {
  tenant: 'tenant-alpha',
  count: 1,
  limit: 20,
  users: [{ id: 'u1', username: 'alice', email: 'alice@x', enabled: true }],
}

beforeEach(() => {
  vi.stubGlobal('fetch', respond({
    '/api/status': { body: operational },
    '/api/tenants/': { body: alphaUsers },
  }))
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('tenant context', () => {
  it('requests the tenant that is in scope, not a global list', async () => {
    mountDashboard(tenantAdmin)
    await flushPromises()
    const calls = fetch.mock.calls.map(([url]) => url)
    expect(calls).toContain('/api/tenants/tenant-alpha/users')
    // There is no unscoped user endpoint to call by accident.
    expect(calls.some((url) => url === '/api/users')).toBe(false)
  })

  it('offers a tenant admin only their own tenant', () => {
    const wrapper = mountDashboard(tenantAdmin)
    const options = wrapper.findAll('option').map((o) => o.text())
    expect(options).toEqual(['tenant-alpha'])
  })

  it('offers a platform admin the whole catalogue', () => {
    const wrapper = mountDashboard(platformAdmin)
    const options = wrapper.findAll('option').map((o) => o.text())
    expect(options).toEqual(['tenant-alpha', 'tenant-beta'])
  })

  it('re-requests data when the tenant changes', async () => {
    const wrapper = mountDashboard(platformAdmin)
    await flushPromises()
    await wrapper.find('select').setValue('tenant-beta')
    await flushPromises()
    expect(fetch.mock.calls.map(([url]) => url)).toContain('/api/tenants/tenant-beta/users')
  })

  it('renders the tenant the server reported, not the one requested', async () => {
    const wrapper = mountDashboard(tenantAdmin)
    await flushPromises()
    expect(wrapper.text()).toContain('tenant-alpha')
    expect(wrapper.text()).toContain('alice')
  })
})

describe('degraded dependencies', () => {
  it('shows a warning when a dependency is degraded', async () => {
    vi.stubGlobal('fetch', respond({
      '/api/status': {
        body: {
          overall: 'degraded',
          dependencies: [{ name: 'identity-provider', state: 'degraded' }],
        },
      },
      '/api/tenants/': { body: alphaUsers },
    }))
    const wrapper = mountDashboard(tenantAdmin)
    await flushPromises()
    expect(wrapper.text()).toContain('not fully available')
  })

  it('shows no warning when everything is operational', async () => {
    const wrapper = mountDashboard(tenantAdmin)
    await flushPromises()
    expect(wrapper.text()).not.toContain('not fully available')
  })

  it('discloses no host, version or upstream detail', async () => {
    vi.stubGlobal('fetch', respond({
      '/api/status': {
        body: {
          overall: 'unavailable',
          dependencies: [{ name: 'identity-provider', state: 'unavailable' }],
        },
      },
      '/api/tenants/': { body: alphaUsers },
    }))
    const wrapper = mountDashboard(tenantAdmin)
    await flushPromises()
    const text = wrapper.text()
    for (const leak of ['keycloak', 'http', '8080', 'Connection refused', 'Exception']) {
      expect(text.toLowerCase()).not.toContain(leak.toLowerCase())
    }
  })

  it('still renders when the status endpoint itself is unreachable', async () => {
    vi.stubGlobal('fetch', respond({
      '/api/status': { ok: false, status: 503, body: {} },
      '/api/tenants/': { body: alphaUsers },
    }))
    const wrapper = mountDashboard(tenantAdmin)
    await flushPromises()
    expect(wrapper.text()).toContain('could not be reached')
  })
})

describe('error recovery', () => {
  it('reports a denial without leaking why', async () => {
    vi.stubGlobal('fetch', respond({
      '/api/status': { body: operational },
      '/api/tenants/': {
        ok: false,
        status: 403,
        body: { error: 'access_denied' },
        headers: { 'X-Correlation-Id': 'corr-123' },
      },
    }))
    const wrapper = mountDashboard(tenantAdmin)
    await flushPromises()
    expect(wrapper.text()).toContain('not permitted')
    // A quotable reference, and nothing else.
    expect(wrapper.text()).toContain('corr-123')
    expect(wrapper.text()).not.toContain('403')
  })

  it('offers a retry rather than a dead end', async () => {
    vi.stubGlobal('fetch', respond({
      '/api/status': { body: operational },
      '/api/tenants/': { ok: false, status: 502, body: {} },
    }))
    const wrapper = mountDashboard(tenantAdmin)
    await flushPromises()
    expect(wrapper.text()).toContain('Try again')
  })
})

describe('quick actions', () => {
  it('offers only actions the session is entitled to', () => {
    const wrapper = mountDashboard(tenantAdmin)
    expect(wrapper.text()).toContain('Manage users')
    expect(wrapper.text()).not.toContain('Platform settings')
  })

  it('offers platform actions to a platform admin', () => {
    const wrapper = mountDashboard(platformAdmin)
    expect(wrapper.text()).toContain('Platform settings')
  })
})

describe('an account with no tenant', () => {
  it('says so rather than showing an empty list', async () => {
    const wrapper = mountDashboard({ ...tenantAdmin, tenants: [] })
    await flushPromises()
    expect(wrapper.text()).toContain('No tenant is in scope')
  })
})
