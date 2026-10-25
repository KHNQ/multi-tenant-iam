import { beforeEach, describe, expect, it, vi } from 'vitest'
import { csrfToken, fetchSession, probe } from '../session.js'

describe('BFF session client', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT'
  })

  it('reads the CSRF token the BFF exposes to the SPA', () => {
    document.cookie = 'XSRF-TOKEN=abc-123'
    expect(csrfToken()).toBe('abc-123')
  })

  it('returns null rather than throwing when the session is gone', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 401, ok: false }))
    expect(await fetchSession()).toBeNull()
  })

  it('projects the session payload', async () => {
    const payload = {
      username: 'padmin',
      roles: ['platform-admin'],
      permissions: { platformAdmin: true, tenantAdmin: true },
    }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      status: 200, ok: true, redirected: false, json: async () => payload,
    }))
    expect(await fetchSession()).toEqual(payload)
  })

  it('sends cookies on same-origin BFF calls', async () => {
    const spy = vi.fn().mockResolvedValue({ status: 200, ok: true, redirected: false, json: async () => ({}) })
    vi.stubGlobal('fetch', spy)
    await fetchSession()
    expect(spy).toHaveBeenCalledWith('/api/me', { credentials: 'same-origin', redirect: 'manual' })
  })

  it('reports a denied guarded route without throwing', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 403, ok: false }))
    expect(await probe('/api/admin/ping')).toEqual({ status: 403, allowed: false })
  })
})
