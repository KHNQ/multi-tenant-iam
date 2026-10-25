import { get, newIdempotencyKey, send } from '@/api.js'

export const CLIENT_ID = 'samta-mapdashboard-web-poc'
const base = (tenant) =>
  `/api/tenants/${encodeURIComponent(tenant)}/applications/${CLIENT_ID}`
const rolePath = (tenant, name) => `${base(tenant)}/roles/${encodeURIComponent(name)}`
const userPath = (tenant, id) => `${base(tenant)}/users/${encodeURIComponent(id)}`

export const fetchPermissions = (tenant) => get(`${base(tenant)}/permissions`)
export const fetchPermissionImports = (tenant) => get(`${base(tenant)}/permissions/import-requests`)
export const fetchRoles = (tenant) => get(`${base(tenant)}/roles`)
export const fetchApplicationAccess = (tenant, id) => get(`${userPath(tenant, id)}/effective-access`)

export function previewRole(tenant, name, permissions) {
  return send(`${rolePath(tenant, name)}/preview`, {
    method: 'POST', body: { permissions }, idempotencyKey: newIdempotencyKey(),
  })
}

export function createRole(tenant, body, key) {
  return send(`${base(tenant)}/roles`, { method: 'POST', body, idempotencyKey: key })
}

export function updateRole(tenant, name, body, key) {
  return send(rolePath(tenant, name), { method: 'PUT', body, idempotencyKey: key })
}

export function deleteRole(tenant, name, fingerprint, key) {
  return send(rolePath(tenant, name), {
    method: 'DELETE', body: { fingerprint }, idempotencyKey: key,
  })
}

export function previewRoleChange(tenant, id, role, action) {
  return send(`${userPath(tenant, id)}/role-changes/preview`, {
    method: 'POST', body: { role, action }, idempotencyKey: newIdempotencyKey(),
  })
}

export function changeUserRole(tenant, id, role, action, fingerprint, key) {
  return send(`${userPath(tenant, id)}/role-changes`, {
    method: 'POST', body: { role, action, fingerprint }, idempotencyKey: key,
  })
}

/** Records an approval or rejection; the import worker performs the approved import. */
export function decidePermissionImport(tenant, body, key) {
  return send(`${base(tenant)}/permissions/import-requests`, { method: 'POST', body, idempotencyKey: key })
}
