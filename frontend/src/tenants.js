import { get, send } from '@/api.js'

export function fetchTenants(search = '', status = '') {
  const query = new URLSearchParams()
  if (search) query.set('search', search)
  if (status) query.set('status', status)
  const suffix = query.size ? `?${query}` : ''
  return get(`/api/admin/tenants${suffix}`)
}

export function createTenantRequest(body, idempotencyKey) {
  return send('/api/admin/tenants', { method: 'POST', body, idempotencyKey })
}

export function decideTenant(tenantKey, decision, reason, idempotencyKey) {
  return send(`/api/admin/tenants/${encodeURIComponent(tenantKey)}/${decision}`, {
    method: 'POST',
    body: { reason },
    idempotencyKey,
  })
}

export function retryTenantProvisioning(tenantKey, idempotencyKey) {
  return send(`/api/admin/tenants/${encodeURIComponent(tenantKey)}/retry-provisioning`, {
    method: 'POST', idempotencyKey,
  })
}

export function reconcileTenant(tenantKey, idempotencyKey) {
  return send(`/api/admin/tenants/${encodeURIComponent(tenantKey)}/reconcile`, {
    method: 'POST', idempotencyKey,
  })
}
