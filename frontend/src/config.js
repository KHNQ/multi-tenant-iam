/**
 * Where the BFF lives, relative to the page that loaded us.
 *
 * Standalone (served at /ui/ on the IAM origin) the BFF is the same origin, so the
 * prefix is empty. Embedded as a microfrontend the host proxies the BFF under a
 * path of its own origin (e.g. /iam), so the session cookie stays first-party.
 * mount() sets it before any request is made. See server-docs/02-microfrontend-readiness.md.
 */
let apiBase = ''

export function setApiBase(value) {
  apiBase = (value ?? '').replace(/\/+$/, '')
}

export function apiUrl(path) {
  return `${apiBase}${path}`
}

/**
 * Where login and logout should bring the operator back to. Unset standalone (the
 * BFF then lands on /ui/); embedded, it is the host page path, so the operator
 * stays inside the host. The BFF accepts only a path on its own origin.
 */
let returnTo = null

export function setReturnTo(value) {
  returnTo = value || null
}

export function getReturnTo() {
  return returnTo
}

/**
 * Embedded, the operator has already signed in to the host, so the console starts
 * its own login straight away instead of showing a second "Sign in" button. The BFF
 * routes that login through the host's realm (kc_idp_hint), which Keycloak completes
 * from its existing SSO session without a prompt.
 */
let autoSignIn = false

export function setAutoSignIn(value) {
  autoSignIn = Boolean(value)
}

export function getAutoSignIn() {
  return autoSignIn
}
