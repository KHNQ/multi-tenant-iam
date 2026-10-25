import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import PlatformView from '@/views/PlatformView.vue'
import { setLocale } from '@/i18n.js'

const approved = {
  tenantKey: 'tenant-alpha', displayName: 'Alpha', realmName: 'tenant-alpha',
  status: 'APPROVED', provisioningStatus: 'READY', driftStatus: 'IN_SYNC', requestedBy: 'bootstrap',
}
const pending = {
  tenantKey: 'tenant-gamma', displayName: 'Gamma', realmName: 'tenant-gamma',
  status: 'PENDING', provisioningStatus: 'NOT_STARTED', requestedBy: 'padmin',
}

let responses
let sent

beforeEach(() => {
  responses = { 'GET /api/admin/tenants': { tenants: [approved, pending], count: 2, total: 2 } }
  sent = []
  vi.stubGlobal('crypto', { randomUUID: () => 'iam-0215-key' })
  vi.stubGlobal('fetch', vi.fn(async (url, options = {}) => {
    const method = options.method ?? 'GET'
    sent.push({ url, method, options })
    const value = responses[`${method} ${url}`] ?? { error: 'not_found' }
    return {
      ok: !value.error,
      status: value.error ? 404 : 200,
      headers: { get: () => null },
      json: async () => value,
    }
  }))
  document.cookie = 'XSRF-TOKEN=csrf-token'
})

afterEach(() => {
  setLocale('en')
  vi.unstubAllGlobals()
})

async function mounted() {
  const wrapper = mount(PlatformView)
  await flushPromises()
  return wrapper
}

describe('IAM-0215 tenant catalogue', () => {
  it('shows mappings, status and provisioning state', async () => {
    const wrapper = await mounted()
    expect(wrapper.findAll('[data-testid="tenant-row"]')).toHaveLength(2)
    expect(wrapper.text()).toContain('tenant-alpha')
    expect(wrapper.text()).toContain('approved')
    expect(wrapper.text()).toContain('ready')
    expect(wrapper.text()).toContain('in sync')
  })

  it('offers decisions only for pending requests', async () => {
    const wrapper = await mounted()
    const rows = wrapper.findAll('[data-testid="tenant-row"]')
    expect(rows[0].text()).toContain('Check drift')
    expect(rows[1].text()).toContain('Approve')
    expect(rows[1].text()).toContain('Reject')
  })

  it('creates a pending mapping before approval starts provisioning', async () => {
    responses['POST /api/admin/tenants'] = pending
    const wrapper = await mounted()
    await wrapper.findAll('button').find((b) => b.text() === 'Request a tenant').trigger('click')
    await wrapper.find('#tenantKey').setValue('tenant-gamma')
    await wrapper.find('#tenantKey').trigger('blur')
    await wrapper.find('#tenantName').setValue('Gamma')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    const request = sent.find((item) => item.method === 'POST')
    expect(JSON.parse(request.options.body)).toEqual({
      tenantKey: 'tenant-gamma', displayName: 'Gamma', realmName: 'tenant-gamma',
    })
    expect(request.options.headers['Idempotency-Key']).toBe('iam-0215-key')
  })

  it('offers retry for a failed approved tenant', async () => {
    responses['GET /api/admin/tenants'].tenants[0] = {
      ...approved, provisioningStatus: 'FAILED', provisioningError: 'upstream_unavailable',
    }
    responses['POST /api/admin/tenants/tenant-alpha/retry-provisioning'] = approved
    const wrapper = await mounted()
    expect(wrapper.text()).toContain('Provisioning failed: upstream_unavailable')
    await wrapper.findAll('button').find((button) => button.text() === 'Retry').trigger('click')
    await flushPromises()
    expect(sent.some((item) => item.url.endsWith('/retry-provisioning'))).toBe(true)
  })

  it('requires a rejection reason before enabling the destructive decision', async () => {
    const wrapper = await mounted()
    const pendingRow = wrapper.findAll('[data-testid="tenant-row"]')[1]
    await pendingRow.findAll('button').find((b) => b.text() === 'Reject').trigger('click')
    const confirm = wrapper.find('[data-testid="confirm-decision"]')
    expect(confirm.attributes('disabled')).toBeDefined()
    await wrapper.find('#decisionReason').setValue('Not approved')
    expect(wrapper.find('[data-testid="confirm-decision"]').attributes('disabled')).toBeUndefined()
  })

  it('localizes known backend reason and drift codes while preserving their technical terms', async () => {
    responses['GET /api/admin/tenants'].tenants[0] = {
      ...approved,
      decisionReason: 'approved for pilot',
      driftStatus: 'MISSING',
      driftDetails: 'realm_missing',
    }
    setLocale('fa')
    const wrapper = await mounted()

    expect(wrapper.text()).toContain('تأییدشده برای پایلوت (approved for pilot)')
    expect(wrapper.text()).toContain('Realm یافت نشد (realm_missing)')
  })
})
