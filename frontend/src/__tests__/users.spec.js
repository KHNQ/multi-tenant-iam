import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import UsersView from '@/views/UsersView.vue'

/**
 * IAM-0209: the administrative surface. The cases that matter are the ones that
 * corrupt state or mislead an operator - a double-submitted create, a duplicate
 * reported as a generic failure, an error message quoting what was typed.
 */

const tenantAdmin = {
  username: 'tadmin',
  roles: ['tenant-admin'],
  permissions: { platformAdmin: false, tenantAdmin: true },
  crossTenant: false,
  tenants: ['tenant-alpha'],
}

const listing = {
  tenant: 'tenant-alpha',
  count: 1,
  limit: 20,
  users: [
    { id: 'u1', username: 'alice', email: 'alice@x', firstName: 'A', lastName: 'L', enabled: true },
  ],
}

let responses

function fetchStub() {
  return vi.fn(async (url, options = {}) => {
    const method = options.method ?? 'GET'
    const key = `${method} ${url.split('?')[0]}`
    const value = responses[key] ?? responses[method] ?? { body: listing }
    fetchStub.lastHeaders = options.headers
    return {
      ok: value.ok ?? true,
      status: value.status ?? 200,
      headers: { get: (name) => value.headers?.[name] ?? null },
      json: async () => value.body ?? {},
    }
  })
}

beforeEach(() => {
  responses = { GET: { body: listing } }
  vi.stubGlobal('fetch', fetchStub())
  vi.stubGlobal('crypto', {
    randomUUID: () => 'uuid-fixed',
    getRandomValues: (array) => {
      array[0] = 7
      return array
    },
  })
  document.cookie = 'XSRF-TOKEN=csrf-token'
})

afterEach(() => {
  vi.unstubAllGlobals()
})

function mountUsers(session = tenantAdmin) {
  return mount(UsersView, { props: { session }, global: { stubs: { RouterLink: { template: '<a><slot /></a>' } } } })
}

async function openCreateForm(wrapper) {
  await wrapper.findAll('button').find((b) => b.text() === 'New user').trigger('click')
  await flushPromises()
}

async function fillCreate(wrapper, values) {
  const inputs = wrapper.findAll('form').at(1).findAll('input')
  await inputs[0].setValue(values.username)
  await inputs[1].setValue(values.email)
}

describe('listing', () => {
  it('requests only the tenant in scope', async () => {
    mountUsers()
    await flushPromises()
    expect(fetch.mock.calls[0][0]).toBe('/api/tenants/tenant-alpha/users')
  })

  it('sends the search term to the server rather than filtering locally', async () => {
    const wrapper = mountUsers()
    await flushPromises()
    await wrapper.find('input[type="search"]').setValue('ali')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    expect(fetch.mock.calls.map(([url]) => url)).toContain(
      '/api/tenants/tenant-alpha/users?search=ali',
    )
  })

  it('shows enabled state for each user', async () => {
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.text()).toContain('enabled')
  })
})

describe('create', () => {
  it('sends an idempotency key and the CSRF token', async () => {
    responses['POST /api/tenants/tenant-alpha/users'] = {
      status: 201,
      body: { id: 'u2', username: 'newuser' },
    }
    const wrapper = mountUsers()
    await flushPromises()
    await openCreateForm(wrapper)
    await fillCreate(wrapper, { username: 'newuser', email: 'n@x.test' })
    await wrapper.findAll('form').at(1).trigger('submit')
    await flushPromises()

    const post = fetch.mock.calls.find(([, o]) => o?.method === 'POST')
    expect(post[1].headers['Idempotency-Key']).toBe('uuid-fixed')
    expect(post[1].headers['X-XSRF-TOKEN']).toBe('csrf-token')
  })

  it('sends only the fields the API accepts', async () => {
    responses['POST /api/tenants/tenant-alpha/users'] = { status: 201, body: { id: 'u2' } }
    const wrapper = mountUsers()
    await flushPromises()
    await openCreateForm(wrapper)
    await fillCreate(wrapper, { username: 'newuser', email: 'n@x.test' })
    await wrapper.findAll('form').at(1).trigger('submit')
    await flushPromises()

    const post = fetch.mock.calls.find(([, o]) => o?.method === 'POST')
    const sent = JSON.parse(post[1].body)
    expect(Object.keys(sent).sort()).toEqual(['email', 'firstName', 'lastName', 'username'])
    // Nothing privilege-bearing can be smuggled from the form.
    for (const forbidden of ['enabled', 'attributes', 'realmRoles', 'credentials', 'groups']) {
      expect(sent).not.toHaveProperty(forbidden)
    }
  })

  it('reuses the same key when a failed submission is retried', async () => {
    responses['POST /api/tenants/tenant-alpha/users'] = {
      ok: false,
      status: 502,
      body: { error: 'upstream_unavailable' },
    }
    const wrapper = mountUsers()
    await flushPromises()
    await openCreateForm(wrapper)
    await fillCreate(wrapper, { username: 'newuser', email: 'n@x.test' })
    await wrapper.findAll('form').at(1).trigger('submit')
    await flushPromises()
    await wrapper.findAll('form').at(1).trigger('submit')
    await flushPromises()

    const keys = fetch.mock.calls
      .filter(([, o]) => o?.method === 'POST')
      .map(([, o]) => o.headers['Idempotency-Key'])
    expect(keys).toHaveLength(2)
    // Same intent, same key: the server will not create two accounts.
    expect(keys[0]).toBe(keys[1])
  })

  it('explains a duplicate rather than reporting a generic failure', async () => {
    responses['POST /api/tenants/tenant-alpha/users'] = {
      ok: false,
      status: 409,
      body: { error: 'conflict' },
    }
    const wrapper = mountUsers()
    await flushPromises()
    await openCreateForm(wrapper)
    await fillCreate(wrapper, { username: 'alice', email: 'a@x.test' })
    await wrapper.findAll('form').at(1).trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('already in use')
  })

  it('shows which field failed validation, and never what was typed', async () => {
    responses['POST /api/tenants/tenant-alpha/users'] = {
      ok: false,
      status: 400,
      body: {
        error: 'validation_failed',
        fields: { username: 'must be lowercase letters, digits, dot, dash or underscore' },
      },
    }
    const wrapper = mountUsers()
    await flushPromises()
    await openCreateForm(wrapper)
    await fillCreate(wrapper, { username: 'Bad Name!', email: 'a@x.test' })
    await wrapper.findAll('form').at(1).trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('must be lowercase')
    expect(wrapper.text()).not.toContain('Bad Name!')
  })

  it('says the new account cannot sign in yet', async () => {
    responses['POST /api/tenants/tenant-alpha/users'] = {
      status: 201,
      body: { id: 'u2', username: 'newuser' },
    }
    const wrapper = mountUsers()
    await flushPromises()
    await openCreateForm(wrapper)
    await fillCreate(wrapper, { username: 'newuser', email: 'n@x.test' })
    await wrapper.findAll('form').at(1).trigger('submit')
    await flushPromises()
    expect(wrapper.text()).toContain('cannot be used to sign in')
  })
})

describe('disable', () => {
  it('disables through the dedicated route, not an edit', async () => {
    responses['PUT /api/tenants/tenant-alpha/users/u1/enabled'] = { body: {} }
    const wrapper = mountUsers()
    await flushPromises()
    await wrapper.findAll('button').find((b) => b.text() === 'Disable').trigger('click')
    await flushPromises()

    const put = fetch.mock.calls.find(([url]) => url.endsWith('/enabled'))
    expect(put).toBeDefined()
    expect(JSON.parse(put[1].body)).toEqual({ enabled: false })
    expect(put[1].headers['Idempotency-Key']).toBeTruthy()
  })

  it('reloads the list so the displayed state is the server truth', async () => {
    responses['PUT /api/tenants/tenant-alpha/users/u1/enabled'] = { body: {} }
    const wrapper = mountUsers()
    await flushPromises()
    const before = fetch.mock.calls.filter(([, o]) => (o?.method ?? 'GET') === 'GET').length
    await wrapper.findAll('button').find((b) => b.text() === 'Disable').trigger('click')
    await flushPromises()
    const after = fetch.mock.calls.filter(([, o]) => (o?.method ?? 'GET') === 'GET').length
    expect(after).toBeGreaterThan(before)
  })
})

describe('credentials', () => {
  it('sends a strong temporary password and never receives it from the backend', async () => {
    responses['PUT /api/tenants/tenant-alpha/users/u1/credential'] = { status: 204 }
    const wrapper = mountUsers()
    await flushPromises()
    await wrapper.findAll('button').find((button) => button.text() === 'Credentials').trigger('click')
    await wrapper.findAll('button').find((button) => button.text() === 'Reset password').trigger('click')
    await flushPromises()

    const request = fetch.mock.calls.find(([url]) => url.endsWith('/credential'))
    const body = JSON.parse(request[1].body)
    expect(body.password).toHaveLength(20)
    expect(body.password).toMatch(/[A-Z]/)
    expect(body.password).toMatch(/[a-z]/)
    expect(body.password).toMatch(/[0-9]/)
    expect(body.password).toMatch(/[^A-Za-z0-9]/)
    expect(request[1].headers['Idempotency-Key']).toBe('uuid-fixed')
    expect(wrapper.find('input[aria-label="Temporary password"]').element.value)
      .toBe(body.password)
  })

  it('clears the one-time password when the panel closes', async () => {
    responses['PUT /api/tenants/tenant-alpha/users/u1/credential'] = { status: 204 }
    const wrapper = mountUsers()
    await flushPromises()
    await wrapper.findAll('button').find((button) => button.text() === 'Credentials').trigger('click')
    await wrapper.findAll('button').find((button) => button.text() === 'Reset password').trigger('click')
    await flushPromises()
    await wrapper.findAll('button').find((button) => button.text() === 'Close').trigger('click')
    expect(wrapper.find('input[aria-label="Temporary password"]').exists()).toBe(false)
  })

  it('manages only the supported required actions', async () => {
    responses['PUT /api/tenants/tenant-alpha/users/u1/required-actions'] = { body: listing.users[0] }
    const wrapper = mountUsers()
    await flushPromises()
    await wrapper.findAll('button').find((button) => button.text() === 'Credentials').trigger('click')
    const updatePassword = wrapper.find('input[value="UPDATE_PASSWORD"]')
    const configureTotp = wrapper.find('input[value="CONFIGURE_TOTP"]')
    await updatePassword.setValue(true)
    await configureTotp.setValue(true)
    const requiredActionsForm = wrapper.findAll('form')
      .find((form) => form.text().includes('Save required actions'))
    await requiredActionsForm.trigger('submit')
    await flushPromises()

    const request = fetch.mock.calls.find(([url]) => url.endsWith('/required-actions'))
    expect(JSON.parse(request[1].body)).toEqual({
      actions: ['UPDATE_PASSWORD', 'CONFIGURE_TOTP'],
    })
  })
})

describe('errors', () => {
  it('surfaces a correlation id to quote', async () => {
    responses.GET = {
      ok: false,
      status: 502,
      body: { error: 'upstream_unavailable' },
      headers: { 'X-Correlation-Id': 'corr-abc' },
    }
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).toContain('corr-abc')
  })

  it('never shows a raw status code or error code', async () => {
    responses.GET = { ok: false, status: 502, body: { error: 'upstream_unavailable' } }
    const wrapper = mountUsers()
    await flushPromises()
    expect(wrapper.text()).not.toContain('502')
    expect(wrapper.text()).not.toContain('upstream_unavailable')
  })
})

describe('no tenant', () => {
  it('says so rather than offering actions that cannot work', async () => {
    const wrapper = mountUsers({ ...tenantAdmin, tenants: [] })
    await flushPromises()
    expect(wrapper.text()).toContain('No tenant is in scope')
  })
})


describe('user detail navigation', () => {
  it('loads an individual user and edits the profile without listing every user', async () => {
    responses['GET /api/tenants/tenant-alpha/users/u1'] = { body: listing.users[0] }
    const wrapper = mount(UsersView, { props: { session: tenantAdmin, detailUserId: 'u1', detailTenant: 'tenant-alpha' }, global: { stubs: { RouterLink: { template: '<a><slot /></a>' } } } })
    await flushPromises()
    expect(fetch.mock.calls.map(([url]) => url)).toContain('/api/tenants/tenant-alpha/users/u1')
    expect(wrapper.text()).toContain('alice')
    expect(wrapper.findAll('button').map(button => button.text())).toEqual(expect.arrayContaining(['Profile', 'Access', 'Credentials', 'Sessions']))
    await wrapper.findAll('button').find(button => button.text() === 'Edit').trigger('click')
    expect(wrapper.find('input[type="email"]').element.value).toBe('alice@x')
    await wrapper.findAll('button').find(button => button.text() === 'Cancel').trigger('click')
    expect(wrapper.find('input[type="email"]').exists()).toBe(false)
    expect(fetch.mock.calls.every(([, options]) => !options?.method || options.method === 'GET')).toBe(true)
    wrapper.unmount()
  })
})
