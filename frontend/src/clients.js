/**
 * IAM-0217: the OAuth/OIDC client registry, from the browser's side.
 *
 * Two things this module deliberately does NOT do.
 *
 * It does not re-implement redirect or origin validation. The server is the
 * authority (ClientPolicy), and a second copy of those rules here would drift from
 * it - at which point the UI would either refuse something the platform allows, or,
 * far worse, accept something the platform refuses and present that as approval.
 * The form surfaces the server's refusal instead. A client-side check could only
 * ever be a convenience, and a convenience that can disagree with a security
 * control is not worth having.
 *
 * It does not store a secret. There is no cache, no module-level variable and
 * nothing written to storage - the value travels from the response into component
 * state and is dropped when that component clears it. See SecretOnce.vue.
 */

import { get, messageFor, newIdempotencyKey, send } from '@/api.js'

const base = (tenant) => `/api/tenants/${encodeURIComponent(tenant)}/clients`

export function fetchClients(tenant, search) {
  const query = search ? `?search=${encodeURIComponent(search)}` : ''
  return get(`${base(tenant)}${query}`)
}

export function fetchClient(tenant, clientId) {
  return get(`${base(tenant)}/${encodeURIComponent(clientId)}`)
}

/**
 * Creates a client. For a confidential one the response carries `secret`, and that
 * is the only time it will ever be available - `secretShownOnce` says so
 * explicitly, and the caller is expected to act on it rather than assume it can
 * fetch the value again later.
 */
export function createClient(tenant, draft, idempotencyKey) {
  return send(base(tenant), {
    method: 'POST',
    body: {
      clientId: draft.clientId,
      name: draft.name || null,
      description: draft.description || null,
      kind: draft.kind,
      redirectUris: splitLines(draft.redirectUris),
      webOrigins: splitLines(draft.webOrigins),
      postLogoutRedirectUris: splitLines(draft.postLogoutRedirectUris),
      standardFlow: draft.standardFlow,
    },
    idempotencyKey,
  })
}

export function updateClient(tenant, clientId, draft, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(clientId)}`, {
    method: 'PUT',
    body: {
      name: draft.name || null,
      description: draft.description || null,
      redirectUris: splitLines(draft.redirectUris),
      webOrigins: splitLines(draft.webOrigins),
      postLogoutRedirectUris: splitLines(draft.postLogoutRedirectUris),
      standardFlow: draft.standardFlow,
    },
    idempotencyKey,
  })
}

export function setClientEnabled(tenant, clientId, enabled, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(clientId)}/enabled`, {
    method: 'PUT',
    body: { enabled },
    idempotencyKey,
  })
}

/** Rotation invalidates the current secret immediately - see the confirmation in the view. */
export function rotateSecret(tenant, clientId, idempotencyKey) {
  return send(`${base(tenant)}/${encodeURIComponent(clientId)}/secret`, {
    method: 'POST',
    idempotencyKey,
  })
}

/**
 * One URI per line is the input shape, because a comma-separated box invites
 * someone to paste a URI containing a comma and silently get two broken entries.
 * Blank lines are dropped; nothing else is normalised, since "exact" is the rule
 * and trimming a URI into validity would hide a mistake rather than report it.
 */
export function splitLines(text) {
  if (Array.isArray(text)) {
    return text
  }
  return (text ?? '')
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
}

export { messageFor, newIdempotencyKey }
