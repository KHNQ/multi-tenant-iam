import { computed } from 'vue'
import { afterEach, describe, expect, it } from 'vitest'
import { setTenantPreference, useTenantPreference } from '@/tenantPreference.js'

afterEach(() => {
  setTenantPreference(null)
  localStorage.removeItem('iam.tenant')
})

describe('shared tenant preference', () => {
  it('keeps the selected tenant when another screen uses the same allowed list', () => {
    const available = computed(() => ['tenant-accept-060324', 'tenant-alpha'])
    const dashboardTenant = useTenantPreference(available)
    dashboardTenant.value = 'tenant-alpha'

    const usersTenant = useTenantPreference(available)
    expect(usersTenant.value).toBe('tenant-alpha')
    expect(localStorage.getItem('iam.tenant')).toBe('tenant-alpha')
  })

  it('rejects a stored tenant outside the current session scope', () => {
    setTenantPreference('tenant-beta')
    const tenant = useTenantPreference(computed(() => ['tenant-alpha']))

    expect(tenant.value).toBe('tenant-alpha')
    expect(localStorage.getItem('iam.tenant')).toBe('tenant-alpha')
  })

  it('ignores attempts to select a tenant that is not allowed', () => {
    const tenant = useTenantPreference(computed(() => ['tenant-alpha']))
    tenant.value = 'tenant-beta'

    expect(tenant.value).toBe('tenant-alpha')
  })
})
