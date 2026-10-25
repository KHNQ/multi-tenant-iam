/**
 * Platform settings of the identity provider itself: operating mode,
 * synchronisation from the primary system, and signing keys. Platform
 * administrators only; the server decides.
 */

import { get, messageFor, newIdempotencyKey, send } from '@/api.js'

export const fetchIdp = () => get('/api/admin/idp')

export function setMode(mode, idempotencyKey) {
  return send('/api/admin/idp/mode', { method: 'POST', body: { mode }, idempotencyKey })
}

export function syncNow(idempotencyKey) {
  return send('/api/admin/idp/sync', { method: 'POST', idempotencyKey })
}

export function rotateKey(realm, idempotencyKey) {
  return send(`/api/admin/idp/realms/${encodeURIComponent(realm)}/keys/rotate`, { method: 'POST', idempotencyKey })
}

export function retireKey(realm, kid, idempotencyKey) {
  return send(`/api/admin/idp/realms/${encodeURIComponent(realm)}/keys/${encodeURIComponent(kid)}`, { method: 'DELETE', idempotencyKey })
}

export { messageFor, newIdempotencyKey }
