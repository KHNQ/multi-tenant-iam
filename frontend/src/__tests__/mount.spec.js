import { afterEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { mount, update, unmount } from '@/mount.js'
import { session } from '@/sessionState.js'
import { apiUrl, setApiBase } from '@/config.js'

describe('microfrontend mount contract', () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    session.value = null
    setApiBase('')
    document.body.innerHTML = ''
  })

  it('renders into a shadow root, calls the BFF under apiBase, and cleans up', async () => {
    const fetchMock = vi.fn(async () => new Response(null, { status: 401 }))
    vi.stubGlobal('fetch', fetchMock)

    const host = document.createElement('div')
    document.body.appendChild(host)
    const shadow = host.attachShadow({ mode: 'open' })
    const point = document.createElement('div')
    shadow.appendChild(point)

    mount(point, { apiBase: '/iam/', locale: 'fa', autoSignIn: false, theme: 'dark',
      tokens: { background: '#050709', primary: '#4FC3F7', 'font-sans': 'Inter' } })
    await flushPromises()

    expect(apiUrl('/api/me')).toBe('/iam/api/me')
    expect(fetchMock.mock.calls[0][0]).toBe('/iam/api/me')
    expect(shadow.querySelector('style[data-iam-styles]')).not.toBeNull()
    expect(point.dir).toBe('rtl')
    expect(document.documentElement.dir).not.toBe('rtl')
    expect(point.textContent.length).toBeGreaterThan(0)

    expect(point.dataset.iamEmbedded).toBe('true')
    expect(point.style.getPropertyValue('--iam-surface')).toBe('#050709')
    expect(point.style.getPropertyValue('--iam-font')).toBe('Inter')
    expect(point.classList.contains('dark')).toBe(true)
    update(point, { theme: 'light', locale: 'en', tokens: { background: '#ffffff' } })
    expect(point.classList.contains('dark')).toBe(false)
    expect(point.classList.contains('light')).toBe(true)
    expect(point.dir).toBe('ltr')
    expect(point.style.getPropertyValue('--iam-brand')).toBe('')

    unmount(point)
    expect(shadow.querySelector('style[data-iam-styles]')).toBeNull()
    expect(point.hasAttribute('data-iam-root')).toBe(false)
    expect(point.innerHTML).toBe('')
    expect(point.style.getPropertyValue('--iam-surface')).toBe('')
    expect(point.hasAttribute('data-iam-embedded')).toBe(false)
  })
  it('reports deep links and applies host navigation without a second header', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      username: 'admin', roles: [], permissions: { tenantAdmin: true, platformAdmin: false },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })))
    const point = document.createElement('div')
    document.body.appendChild(point)
    const onNavigate = vi.fn()
    mount(point, { initialPath: '/forbidden', onNavigate, autoSignIn: false })
    await flushPromises()
    expect(onNavigate).toHaveBeenCalledWith('/forbidden')
    expect(point.querySelector('header')).toBeNull()
    expect(point.querySelector('nav')).not.toBeNull()
    update(point, { initialPath: '/' })
    await flushPromises()
    expect(onNavigate).toHaveBeenCalledWith('/')
    unmount(point)
  })

  it('can retain the standalone shell when explicitly requested', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({
      username: 'admin', roles: [], permissions: { tenantAdmin: true, platformAdmin: false },
    }), { status: 200, headers: { 'Content-Type': 'application/json' } })))
    const point = document.createElement('div')
    document.body.appendChild(point)
    mount(point, { embedded: false, initialPath: '/forbidden', autoSignIn: false })
    await flushPromises()
    expect(point.querySelector('header')).not.toBeNull()
    unmount(point)
  })

})
