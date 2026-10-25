/**
 * IAM-0209: the user administration calls.
 *
 * Every mutation carries a fresh idempotency key (IAM-0206), generated per
 * submission rather than per attempt: if the user presses "Create" and the
 * network stalls, the retry reuses the same key and cannot create a second
 * account. That is the whole point of the header, and it only works if the key
 * is minted where the *intent* is formed, not where the request is sent.
 */

import { get, newIdempotencyKey, send } from '@/api.js'

const base = (tenant) => `/api/tenants/${encodeURIComponent(tenant)}/users`

export const fetchUser = (tenant, id) => get(`${base(tenant)}/${encodeURIComponent(id)}`)

export function searchUsers(tenant, search) {
  const query = search ? `?search=${encodeURIComponent(search)}` : ''
  return get(`${base(tenant)}${query}`)
}

export function createUser(tenant, user, idempotencyKey) {
  return send(base(tenant), { method: 'POST', body: user, idempotencyKey })
}

export function updateUser(tenant, id, user, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(id)}`, {
    method: 'PUT',
    body: user,
    idempotencyKey,
  })
}

export function setUserEnabled(tenant, id, enabled, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(id)}/enabled`, {
    method: 'PUT',
    body: { enabled },
    idempotencyKey,
  })
}

export function resetUserCredential(tenant, id, password, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(id)}/credential`, {
    method: 'PUT',
    body: { password },
    idempotencyKey,
  })
}

export function setUserRequiredActions(tenant, id, actions, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(id)}/required-actions`, {
    method: 'PUT',
    body: { actions },
    idempotencyKey,
  })
}

/**
 * Would this user get into `clientId`, and with which claims? The server
 * evaluates it from current data; nothing is issued.
 */
export function testAccess(tenant, id, body, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(id)}/access-test`, { method: 'POST', body, idempotencyKey })
}

export { newIdempotencyKey }
