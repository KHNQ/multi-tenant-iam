/**
 * IAM-0214: the effective-access preview and the assignment that changes it.
 *
 * The screen this backs exists because a flat list of role names is not an
 * answer. AccessController/EffectiveAccess deliberately return one entry per role
 * carrying *every* reason it is held, and nothing in this module collapses that:
 * the remedy for a direct mapping, a group membership and a composite edge are
 * three different actions, so the UI must keep them three different facts.
 */

import { get, messageFor, newIdempotencyKey, send } from '@/api.js'

const base = (tenant) => `/api/tenants/${encodeURIComponent(tenant)}`

/**
 * The backend's own role identity, reproduced exactly (RoleRef.qualified).
 *
 * It has to match character for character: a COMPOSITE grant states its parent as
 * a qualified name, and the only way the UI can point at the parent row is if it
 * derives the same string. Keying on name alone would collide the moment two
 * clients both define "viewer".
 */
export function qualify(role) {
  return role.source === 'client' ? `client:${role.client}/${role.name}` : `realm:${role.name}`
}

export function fetchEffectiveAccess(tenant, userId) {
  return get(`${base(tenant)}/users/${encodeURIComponent(userId)}/effective-access`)
}

export function fetchRoleCatalogue(tenant) {
  return get(`${base(tenant)}/roles`)
}

/** One realm role with its direct composites, used to project a grant's reach. */
export function fetchRole(tenant, name) {
  return get(`${base(tenant)}/roles/${encodeURIComponent(name)}`)
}

/**
 * Grants roles to a user. The response is the recomputed preview, not an echo -
 * see AccessController - so the caller renders the consequence rather than a
 * "created" message.
 */
export function assignRolesToUser(tenant, userId, roles, idempotencyKey) {
  return send(`${base(tenant)}/users/${encodeURIComponent(userId)}/role-mappings`, {
    method: 'POST',
    body: { add: roles.map((role) => ({ source: role.source, client: role.client, name: role.name })) },
    idempotencyKey,
  })
}

/**
 * What granting `selected` is expected to drag in, stated *before* the write.
 *
 * This is a projection from the catalogue, not an authority: only the server
 * resolves the real closure, and it does so when the write happens. It is shown
 * anyway because "granting tenant-admin also grants these" is the fact an
 * administrator needs before they click, not after. Two limits are stated rather
 * than hidden:
 *
 *  - only the *direct* composites are known here, because
 *    GET /roles/{name} resolves one level;
 *  - client roles have no composite endpoint in this slice, so their reach is
 *    reported as unknown rather than as empty. Claiming "grants nothing further"
 *    when we did not look would be the more dangerous of the two errors.
 */
export async function projectReach(tenant, selected) {
  const brings = []
  let unknown = false
  for (const role of selected) {
    if (role.source !== 'realm') {
      unknown = true
      continue
    }
    try {
      const detail = await fetchRole(tenant, role.name)
      for (const child of detail.composites ?? []) {
        brings.push({ ...child, from: qualify(role) })
      }
    } catch {
      // A catalogue read that fails must not block the review; it makes the
      // reach unknown, which is what the operator is then told.
      unknown = true
    }
  }
  return { brings, unknown }
}

export { messageFor, newIdempotencyKey }
