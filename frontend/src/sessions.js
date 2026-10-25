import { get, messageFor, newIdempotencyKey, send } from '@/api.js'

const base = (tenant, userId) =>
  `/api/tenants/${encodeURIComponent(tenant)}/users/${encodeURIComponent(userId)}/sessions`

export function fetchSessions(tenant, userId) {
  return get(base(tenant, userId))
}

export function terminateSession(tenant, userId, sessionId, reason, idempotencyKey) {
  return send(`${base(tenant, userId)}/${encodeURIComponent(sessionId)}`, {
    method: 'DELETE',
    body: { reason },
    idempotencyKey,
  })
}

export function terminateAllSessions(tenant, userId, reason, idempotencyKey) {
  return send(`${base(tenant, userId)}/terminate-all`, {
    method: 'POST',
    body: { reason },
    idempotencyKey,
  })
}

export { messageFor, newIdempotencyKey }
