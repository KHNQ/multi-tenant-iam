import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import GroupsView from '@/views/GroupsView.vue'

const session = {
  username: 'tadmin',
  permissions: { platformAdmin: false, tenantAdmin: true },
  tenants: ['tenant-alpha'],
}

const list = {
  tenant: 'tenant-alpha', count: 1,
  groups: [{ id: 'g1', name: 'engineering', path: '/engineering' }],
}

beforeEach(() => {
  document.cookie = 'XSRF-TOKEN=csrf-token'
  vi.stubGlobal('crypto', { randomUUID: () => 'group-key' })
  vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
    const method = options.method ?? 'GET'
    let body = list
    if (url.endsWith('/groups/g1')) body = { ...list.groups[0], children: [] }
    if (url.endsWith('/groups/g1/members')) body = { members: [] }
    if (method === 'POST') body = { id: 'g2', name: 'platform', path: '/platform' }
    return { ok: true, status: method === 'POST' ? 201 : 200,
      headers: { get: () => null }, json: async () => body }
  }))
})

afterEach(() => vi.unstubAllGlobals())

describe('IAM-0212 groups surface', () => {
  it('loads groups only from the tenant in scope', async () => {
    mount(GroupsView, { props: { session } }); await flushPromises()
    expect(fetch.mock.calls[0][0]).toBe('/api/tenants/tenant-alpha/groups')
  })

  it('opens a group and reads its direct members', async () => {
    const wrapper = mount(GroupsView, { props: { session } }); await flushPromises()
    await wrapper.findAll('button').find((button) => button.text().includes('engineering')).trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.map(([url]) => url)).toContain('/api/tenants/tenant-alpha/groups/g1/members')
    expect(wrapper.text()).toContain('Manage /engineering')
  })

  it('protects group creation with CSRF and idempotency headers', async () => {
    const wrapper = mount(GroupsView, { props: { session } }); await flushPromises()
    await wrapper.findAll('button').find(button => button.text() === 'New group').trigger('click')
    await wrapper.find('input:not([type="search"])').setValue('platform')
    await wrapper.find('form').trigger('submit'); await flushPromises()
    const request = fetch.mock.calls.find(([, options]) => options?.method === 'POST')[1]
    expect(request.headers['X-XSRF-TOKEN']).toBe('csrf-token')
    expect(request.headers['Idempotency-Key']).toBe('group-key')
  })
})
