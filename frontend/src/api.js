/**
 * The shared shape of every call to the BFF.
 *
 * Extracted from users.js (IAM-0209) when IAM-0214 added a second caller. It is
 * deliberately one implementation rather than two: the error path decides what an
 * operator is told when a privileged write fails, and two copies of that rule
 * drift. Nothing here reads or stores a token - the session is the HttpOnly
 * cookie the BFF set, and the only credential this file handles is the CSRF
 * double-submit value (IAM-NFR-04).
 */

import { csrfToken } from '@/session.js'
import { i18n } from '@/i18n.js'
import { apiUrl } from '@/config.js'

export function newIdempotencyKey() {
  return crypto.randomUUID()
}

/** Turns a failed response into a shape the UI can act on, without leaking detail. */
export async function toError(res) {
  let payload = {}
  try {
    payload = await res.json()
  } catch {
    // A non-JSON error body is not something to show a user.
  }
  const error = new Error(`request failed: ${res.status}`)
  error.status = res.status
  error.code = payload.error ?? 'request_failed'
  error.fields = payload.fields ?? null
  error.correlationId = res.headers.get('X-Correlation-Id') ?? payload.correlationId ?? null
  return error
}

export async function get(path) {
  const res = await fetch(apiUrl(path), { credentials: 'same-origin' })
  if (!res.ok) {
    throw await toError(res)
  }
  return res.json()
}

export async function send(path, { method, body, idempotencyKey }) {
  const headers = { 'X-XSRF-TOKEN': csrfToken() ?? '' }
  if (body !== undefined) {
    headers['Content-Type'] = 'application/json'
  }
  if (idempotencyKey) {
    headers['Idempotency-Key'] = idempotencyKey
  }
  const res = await fetch(apiUrl(path), {
    method,
    credentials: 'same-origin',
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!res.ok) {
    throw await toError(res)
  }
  return res.status === 204 ? null : res.json()
}

/**
 * Codes are translated to something an operator can act on. The raw code is not
 * shown, and neither is the status: the useful part is what to do next, plus a
 * reference they can quote.
 */
export function messageFor(error) {
  const key = `error.${error?.code}`
  return i18n.global.te(key) ? i18n.global.t(key) : i18n.global.t('error.default')
}
