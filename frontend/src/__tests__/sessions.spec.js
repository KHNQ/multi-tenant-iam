import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import SessionsView from '@/views/SessionsView.vue'

const session = {
  username: 'tadmin',
  permissions: { tenantAdmin: true },
  tenants: ['tenant-alpha'],
}

let sent

beforeEach(() => {
  sent = []
  vi.stubGlobal('crypto', { randomUUID: () => 'session-key' })
  document.cookie = 'XSRF-TOKEN=csrf-token'
  vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
    const method = options.method ?? 'GET'
    if (method !== 'GET') sent.push({ url, method, options })
    let body = {}
    if (url.endsWith('/users') || url.includes('/users?')) {
      body = { users: [{ id: 'u1', username: 'alice', email: 'alice@example.com' }] }
    } else if (url.endsWith('/users/u1/sessions')) {
      body = { sessions: [{ id: 's1', ipAddress: '10.0.0.4', start: 1, lastAccess: 2, clients: { console: 'c1' } }] }
    }
    return { ok: true, status: method === 'GET' ? 200 : 204,
      headers: { get: () => null }, json: async () => body }
  }))
})

afterEach(() => vi.unstubAllGlobals())

async function selectedUser() {
  const wrapper = mount(SessionsView, { props: { session } })
  await wrapper.find('form').trigger('submit')
  await flushPromises()
  await wrapper.findAll('button').find((button) => button.text() === 'View sessions').trigger('click')
  await flushPromises()
  return wrapper
}

describe('IAM-0220 sessions console', () => {
  it('lists sessions only after an operator selects a tenant user', async () => {
    const wrapper = await selectedUser()
    expect(wrapper.findAll('[data-testid="session-row"]')).toHaveLength(1)
    expect(wrapper.text()).toContain('10.0.0.4')
  })

  it('requires a reason and sends an idempotent targeted termination', async () => {
    const wrapper = await selectedUser()
    await wrapper.findAll('button').find((button) => button.text() === 'Terminate').trigger('click')
    const confirmation = wrapper.findAll('form')[1]
    expect(confirmation.find('button[type="submit"]').attributes('disabled')).toBeDefined()
    await wrapper.find('#termination-reason').setValue('Suspected account compromise')
    await confirmation.trigger('submit')
    await flushPromises()
    expect(sent[0].method).toBe('DELETE')
    expect(sent[0].url.endsWith('/users/u1/sessions/s1')).toBe(true)
    expect(JSON.parse(sent[0].options.body).reason).toBe('Suspected account compromise')
    expect(sent[0].options.headers['Idempotency-Key']).toBe('session-key')
  })

  it('uses the explicit terminate-all route', async () => {
    const wrapper = await selectedUser()
    await wrapper.findAll('button').find((button) => button.text() === 'Terminate all').trigger('click')
    await wrapper.find('#termination-reason').setValue('User requested sign-out everywhere')
    await wrapper.findAll('form')[1].trigger('submit')
    await flushPromises()
    expect(sent[0].method).toBe('POST')
    expect(sent[0].url.endsWith('/users/u1/sessions/terminate-all')).toBe(true)
  })
})


describe('embedded user sessions', () => {
  it('opens the given user directly and displays client names instead of map keys', async () => {
    const wrapper = mount(SessionsView, { props: { session, embedded: true, user: { id: 'u1', username: 'alice' }, tenantKey: 'tenant-alpha' } })
    await flushPromises()
    expect(wrapper.find('[data-testid="session-row"]').text()).toContain('c1')
    expect(wrapper.find('[data-testid="session-row"]').text()).not.toContain('console')
    expect(wrapper.find('input[type="search"]').exists()).toBe(false)
    expect(sent).toEqual([])
    wrapper.unmount()
  })
})
