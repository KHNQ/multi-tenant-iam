import { apiUrl, getReturnTo } from '@/config.js'

/**
 * All calls go to the BFF on the same origin with the session cookie attached.
 * The SPA never sees a token, so there is nothing here that reads or stores one
 * (IAM-NFR-04); the only credential it handles is the CSRF double-submit value.
 */

export function csrfToken() {
  const match = document.cookie.match(/(?:^|;\s*)XSRF-TOKEN=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : null
}

export async function fetchSession() {
  // Not following the redirect: signed out, the BFF sends us to Keycloak, which is
  // another origin when embedded, and following it would fail as a CORS error.
  const res = await fetch(apiUrl('/api/me'), { credentials: 'same-origin', redirect: 'manual' })
  if (res.status === 401 || res.status === 302 || res.type === 'opaqueredirect' || res.redirected) {
    return null
  }
  if (!res.ok) {
    throw new Error(`session lookup failed: ${res.status}`)
  }
  return res.json()
}

/** Probes a guarded route so the shell can show the guards working end to end. */
export async function probe(path) {
  const res = await fetch(apiUrl(path), { credentials: 'same-origin' })
  return { status: res.status, allowed: res.ok }
}

/**
 * IAM-0208: platform status. A failure to reach our own API is itself a status,
 * so this resolves rather than throws - a dashboard that renders nothing when the
 * status call fails is the least useful possible response to an outage.
 */
export async function fetchStatus() {
  try {
    const res = await fetch(apiUrl('/api/status'), { credentials: 'same-origin' })
    if (!res.ok) {
      return { overall: 'unavailable', dependencies: [], unreachable: true }
    }
    return res.json()
  } catch {
    return { overall: 'unavailable', dependencies: [], unreachable: true }
  }
}

/**
 * IAM-0208: tenant-bound data for the dashboard.
 *
 * The tenant is part of the path, so the server's predicate (IAM-0204) decides
 * whether this session may see it. The UI never filters another tenant's data
 * out of a shared response, because it never receives one.
 *
 * The correlation id is surfaced on failure: it is the one piece of an error an
 * operator can usefully quote, and it discloses nothing on its own.
 */
export async function fetchTenantUsers(tenantKey) {
  const res = await fetch(apiUrl(`/api/tenants/${encodeURIComponent(tenantKey)}/users`), {
    credentials: 'same-origin',
  })
  if (!res.ok) {
    const error = new Error(`tenant users lookup failed: ${res.status}`)
    error.status = res.status
    error.correlationId = res.headers.get('X-Correlation-Id')
    throw error
  }
  return res.json()
}

export function login() {
  const returnTo = getReturnTo()
  const query = returnTo ? `?returnTo=${encodeURIComponent(returnTo)}` : ''
  window.location.href = apiUrl(`/oauth2/authorization/keycloak${query}`)
}

/** Logout must be a POST carrying the CSRF token, matching the BFF's contract. */
export function logout() {
  const form = document.createElement('form')
  form.method = 'POST'
  form.action = apiUrl('/logout')
  const field = document.createElement('input')
  field.type = 'hidden'
  field.name = '_csrf'
  field.value = csrfToken() ?? ''
  form.appendChild(field)
  const returnTo = getReturnTo()
  if (returnTo) {
    const back = document.createElement('input')
    back.type = 'hidden'
    back.name = 'returnTo'
    back.value = returnTo
    form.appendChild(back)
  }
  document.body.appendChild(form)
  form.submit()
}
