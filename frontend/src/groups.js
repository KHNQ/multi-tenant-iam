import { get, newIdempotencyKey, send } from '@/api.js'

const base = (tenant) => `/api/tenants/${encodeURIComponent(tenant)}/groups`

export function fetchGroups(tenant, search = '') {
  const query = search ? `?search=${encodeURIComponent(search)}` : ''
  return get(`${base(tenant)}${query}`)
}
export function fetchGroup(tenant, id) {
  return get(`${base(tenant)}/${encodeURIComponent(id)}`)
}
export function fetchGroupMembers(tenant, id) {
  return get(`${base(tenant)}/${encodeURIComponent(id)}/members`)
}
export function createGroup(tenant, body, idempotencyKey) {
  return send(base(tenant), { method: 'POST', body, idempotencyKey })
}
export function renameGroup(tenant, id, name, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(id)}`, {
    method: 'PUT', body: { name }, idempotencyKey,
  })
}
export function moveGroup(tenant, id, parentId, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(id)}/parent`, {
    method: 'PUT', body: { parentId }, idempotencyKey,
  })
}
export function setGroupMember(tenant, groupId, userId, member, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(groupId)}/members/${encodeURIComponent(userId)}`, {
    method: member ? 'PUT' : 'DELETE', idempotencyKey,
  })
}

export { newIdempotencyKey }
