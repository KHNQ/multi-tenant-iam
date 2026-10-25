import { mount } from '@vue/test-utils'
import { describe, expect, it } from 'vitest'
import { createRouter, createWebHistory } from 'vue-router'
import AppShell from '@/components/AppShell.vue'
import Alert from '@/components/ui/Alert.vue'
import Button from '@/components/ui/Button.vue'
import { createAppRouter, routes } from '@/router.js'

function sessionWith(platformAdmin, tenantAdmin) {
  return {
    username: 'padmin',
    email: 'padmin@iam.poc.local',
    roles: [],
    permissions: { platformAdmin, tenantAdmin },
  }
}

async function mountShell(session) {
  const router = createRouter({ history: createWebHistory('/ui/'), routes })
  router.push('/')
  await router.isReady()
  return mount(AppShell, { props: { session }, global: { plugins: [router] } })
}

describe('IAM-0207 navigation and accessibility', () => {
  it('offers a skip link as the first focusable element', async () => {
    const wrapper = await mountShell(sessionWith(true, true))
    const first = wrapper.element.querySelector('a, button, [href]')
    expect(first.getAttribute('href')).toBe('#main')
    expect(first.textContent.trim()).toBe('Skip to main content')
  })

  it('marks the main landmark as the skip-link target', async () => {
    const wrapper = await mountShell(sessionWith(true, true))
    expect(wrapper.find('main#main').exists()).toBe(true)
  })

  it('labels the primary navigation for screen readers', async () => {
    const wrapper = await mountShell(sessionWith(true, true))
    expect(wrapper.find('nav').attributes('aria-label')).toBe('Primary')
  })

  it('marks the active route with aria-current', async () => {
    const wrapper = await mountShell(sessionWith(true, true))
    const current = wrapper.findAll('a').filter((a) => a.attributes('aria-current') === 'page')
    expect(current).toHaveLength(1)
    expect(current[0].text()).toContain('Overview')
  })

  it('hides navigation the session is not entitled to', async () => {
    const wrapper = await mountShell(sessionWith(false, false))
    const labels = wrapper.findAll('nav a').map((a) => a.text())
    expect(labels).toEqual(['Overview'])
  })

  it('shows tenant navigation to a tenant admin but not platform navigation', async () => {
    const wrapper = await mountShell(sessionWith(false, true))
    const labels = wrapper.findAll('nav a').map((a) => a.text())
    expect(labels).toContain('Users')
    expect(labels).not.toContain('Platform')
  })

  it('names the menu in plain terms and keeps groups and platform out of it', async () => {
    const wrapper = await mountShell(sessionWith(true, true))
    const labels = wrapper.findAll('nav a').map((a) => a.text())
    expect(labels).toEqual(['Overview', 'Users', 'Applications', 'Roles', 'Permissions', 'Sessions'])
  })

  it('reaches platform settings from the header, for platform admins only', async () => {
    const admin = await mountShell(sessionWith(true, true))
    expect(admin.find('header a[href="/ui/platform"]').exists()).toBe(true)
    const tenantAdmin = await mountShell(sessionWith(false, true))
    expect(tenantAdmin.find('header a[href="/ui/platform"]').exists()).toBe(false)
  })

  it('hides decorative icons from assistive technology', async () => {
    const wrapper = await mountShell(sessionWith(true, true))
    const icons = wrapper.element.querySelectorAll('svg')
    expect(icons.length).toBeGreaterThan(0)
    for (const icon of icons) {
      expect(icon.getAttribute('aria-hidden')).toBe('true')
    }
  })
})

describe('IAM-0207 route guards', () => {
  it('redirects an unentitled route to the forbidden view', async () => {
    const router = createAppRouter(() => sessionWith(false, false))
    await router.push('/platform')
    expect(router.currentRoute.value.name).toBe('forbidden')
  })

  it('allows an entitled route through', async () => {
    const router = createAppRouter(() => sessionWith(true, true))
    await router.push('/platform')
    expect(router.currentRoute.value.name).toBe('platform')
  })

  it('sends unknown routes back to the dashboard rather than a dead end', async () => {
    const router = createAppRouter(() => sessionWith(true, true))
    await router.push('/does-not-exist')
    expect(router.currentRoute.value.name).toBe('dashboard')
  })
})

describe('IAM-0207 error conventions', () => {
  it('announces errors with role=alert', () => {
    const wrapper = mount(Alert, { props: { title: 'Nope' }, slots: { default: 'details' } })
    expect(wrapper.attributes('role')).toBe('alert')
  })

  it('renders a real button element so it is keyboard operable', () => {
    const wrapper = mount(Button, { slots: { default: 'Save' } })
    expect(wrapper.element.tagName).toBe('BUTTON')
  })
})
