import { createMemoryHistory } from 'vue-router'
import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import AccessView from '@/views/AccessView.vue'
import GrantReasons from '@/components/access/GrantReasons.vue'
import { createAppRouter } from '@/router.js'

/**
 * IAM-0214 on the screen. The criterion is not "roles are listed" - it is that
 * direct, group and composite effects are *displayed*, and that the consequence
 * of a grant is visible before it is confirmed. The cases below are the ones
 * that, if they broke, would leave an administrator confidently wrong:
 *
 *  - a role held two ways showing only one reason (they remove one and nothing
 *    changes);
 *  - an inherited role that does not name what it came through (unactionable);
 *  - a non-assignable role offered for assignment (the policy becomes a
 *    surprise rejection instead of a rule);
 *  - a grant applied before its reach was shown.
 */

const session = {
  username: 'tadmin',
  roles: ['tenant-admin'],
  permissions: { platformAdmin: false, tenantAdmin: true },
  crossTenant: false,
  tenants: ['tenant-alpha'],
}

const role = (over = {}) => ({
  name: 'tenant-user',
  source: 'realm',
  client: null,
  description: null,
  composite: false,
  administrative: false,
  assignable: true,
  ...over,
})

/** alice holds tenant-user BOTH directly and through /administrators. */
const preview = {
  tenant: 'tenant-alpha',
  userId: 'u1',
  username: 'alice',
  enabled: true,
  groups: ['/administrators'],
  count: 3,
  access: [
    {
      ...role({ name: 'tenant-user' }),
      grants: [
        { origin: 'direct', via: null },
        { origin: 'group', via: '/administrators' },
      ],
      origins: ['direct', 'group'],
    },
    {
      ...role({ name: 'tenant-admin', composite: true, administrative: true, assignable: false }),
      grants: [{ origin: 'group', via: '/administrators' }],
      origins: ['group'],
    },
    {
      ...role({ name: 'reports.read', source: 'client', client: 'reporting' }),
      grants: [{ origin: 'composite', via: 'realm:tenant-admin' }],
      origins: ['composite'],
    },
  ],
}

const catalogue = {
  tenant: 'tenant-alpha',
  count: 3,
  limit: 50,
  roles: [
    role({ name: 'tenant-user' }),
    role({ name: 'auditor', composite: true }),
    // Administrative: RolePolicy refuses it, so the UI must not offer it.
    role({ name: 'tenant-admin', administrative: true, assignable: false }),
  ],
}

let responses
let posted

function stub(body, over = {}) {
  return { body, ...over }
}

beforeEach(() => {
  posted = []
  responses = {
    'GET /api/tenants/tenant-alpha/users/u1/effective-access': stub(preview),
    'GET /api/tenants/tenant-alpha/roles': stub(catalogue),
    'GET /api/tenants/tenant-alpha/roles/auditor': stub({
      ...role({ name: 'auditor', composite: true }),
      // Not already held, so the review has something real to warn about.
      composites: [role({ name: 'reports.export', source: 'client', client: 'reporting' })],
    }),
    'GET /api/tenants/tenant-alpha/roles/tenant-user': stub({
      ...role({ name: 'tenant-user' }),
      composites: [],
    }),
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url, options = {}) => {
      const method = options.method ?? 'GET'
      const key = `${method} ${url}`
      if (method === 'POST') {
        posted.push({ url, options })
      }
      const value = responses[key] ?? { ok: false, status: 404, body: { error: 'not_found' } }
      return {
        ok: value.ok ?? true,
        status: value.status ?? 200,
        headers: { get: (name) => value.headers?.[name] ?? null },
        json: async () => value.body ?? {},
      }
    }),
  )
  vi.stubGlobal('crypto', { randomUUID: () => 'uuid-fixed' })
  document.cookie = 'XSRF-TOKEN=csrf-token'
})

afterEach(() => {
  vi.unstubAllGlobals()
})

async function mountAccess() {
  const router = createAppRouter(() => session, { history: createMemoryHistory() })
  router.push({ name: 'user-access', params: { id: 'u1' }, query: { tenant: 'tenant-alpha' } })
  await router.isReady()
  const wrapper = mount(AccessView, {
    props: { session },
    global: { plugins: [router] },
  })
  await flushPromises()
  return wrapper
}

function buttonNamed(wrapper, text) {
  return wrapper.findAll('button').find((b) => b.text().trim() === text)
}

describe('attribution', () => {
  it('renders every reason a role is held, not just the first', async () => {
    const wrapper = await mountAccess()
    const rows = wrapper.findAll('[data-testid="access-role"]')
    const tenantUser = rows.find((row) => row.text().includes('tenant-user'))

    const reasons = tenantUser.findAll('[data-testid="grant-reason"]')
    expect(reasons).toHaveLength(2)
    // Removing only one of these changes nothing, so both must be on screen.
    expect(reasons[0].text()).toContain('direct')
    expect(reasons[1].text()).toContain('group')
  })

  it('names the group an inherited role came through', async () => {
    const wrapper = await mountAccess()
    const vias = wrapper.findAll('[data-testid="grant-via"]').map((v) => v.text())
    expect(vias).toContain('/administrators')
  })

  it('names the parent a composite role came through', async () => {
    const wrapper = await mountAccess()
    const vias = wrapper.findAll('[data-testid="grant-via"]').map((v) => v.text())
    expect(vias).toContain('realm:tenant-admin')
  })

  it('calls out roles that are held more than one way', async () => {
    const wrapper = await mountAccess()
    expect(wrapper.text()).toContain('held for more than one reason')
    expect(wrapper.text()).toContain('tenant-user')
  })

  it('distinguishes the three origins by word, never by colour alone', () => {
    const wrapper = mount(GrantReasons, {
      props: {
        grants: [
          { origin: 'direct', via: null },
          { origin: 'group', via: '/ops' },
          { origin: 'composite', via: 'realm:tenant-admin' },
        ],
      },
    })
    for (const word of ['direct', 'group', 'composite']) {
      expect(wrapper.text()).toContain(word)
    }
  })

  it('shows the group memberships that inheritance can come from', async () => {
    const wrapper = await mountAccess()
    expect(wrapper.text()).toContain('/administrators')
  })

  it('filters on the origins the server published rather than re-deriving them', async () => {
    const wrapper = await mountAccess()
    await buttonNamed(wrapper, 'Direct').trigger('click')
    await flushPromises()
    const rows = wrapper.findAll('[data-testid="access-role"]')
    expect(rows).toHaveLength(1)
    expect(rows[0].text()).toContain('tenant-user')
  })
})

describe('offering roles to assign', () => {
  it('does not offer a role the policy refuses', async () => {
    const wrapper = await mountAccess()
    const offered = wrapper.findAll('[data-testid="offerable-role"]').map((r) => r.text())
    expect(offered.join(' ')).toContain('tenant-user')
    expect(offered.join(' ')).toContain('auditor')
    // administrative, assignable:false - must be absent, not merely disabled
    expect(offered.some((text) => text.includes('tenant-admin'))).toBe(false)
  })

  it('says how many roles were withheld rather than looking arbitrarily short', async () => {
    const wrapper = await mountAccess()
    expect(wrapper.text()).toContain('1 role(s) are not offered here')
  })
})

describe('grant', () => {
  async function selectAuditor(wrapper) {
    const row = wrapper
      .findAll('[data-testid="offerable-role"]')
      .find((r) => r.text().includes('auditor'))
    await row.find('input[type="checkbox"]').trigger('change')
    await flushPromises()
  }

  it('shows what the grant would drag in before anything is written', async () => {
    const wrapper = await mountAccess()
    await selectAuditor(wrapper)
    await buttonNamed(wrapper, 'Review 1 selected role(s)').trigger('click')
    await flushPromises()

    expect(posted).toHaveLength(0)
    const brought = wrapper.findAll('[data-testid="review-brought"]').map((r) => r.text())
    expect(brought.join(' ')).toContain('client:reporting/reports.export')
    expect(brought.join(' ')).toContain('realm:auditor')
    expect(wrapper.text()).toContain('not the authority')
  })

  it('writes only after confirmation, with a CSRF token and an idempotency key', async () => {
    responses['POST /api/tenants/tenant-alpha/users/u1/role-mappings'] = stub({
      ...preview,
      assigned: 1,
      count: 4,
      access: [
        ...preview.access,
        {
          ...role({ name: 'auditor', composite: true }),
          grants: [{ origin: 'direct', via: null }],
          origins: ['direct'],
        },
      ],
    })
    const wrapper = await mountAccess()
    await selectAuditor(wrapper)
    await buttonNamed(wrapper, 'Review 1 selected role(s)').trigger('click')
    await flushPromises()
    await buttonNamed(wrapper, 'Confirm grant').trigger('click')
    await flushPromises()

    expect(posted).toHaveLength(1)
    expect(posted[0].options.headers['Idempotency-Key']).toBe('uuid-fixed')
    expect(posted[0].options.headers['X-XSRF-TOKEN']).toBe('csrf-token')
    expect(JSON.parse(posted[0].options.body)).toEqual({
      add: [{ source: 'realm', client: null, name: 'auditor' }],
    })
  })

  it('renders the recomputed preview the server returned, marking what is new', async () => {
    responses['POST /api/tenants/tenant-alpha/users/u1/role-mappings'] = stub({
      ...preview,
      assigned: 1,
      count: 4,
      access: [
        ...preview.access,
        {
          ...role({ name: 'auditor', composite: true }),
          grants: [{ origin: 'direct', via: null }],
          origins: ['direct'],
        },
      ],
    })
    const wrapper = await mountAccess()
    await selectAuditor(wrapper)
    await buttonNamed(wrapper, 'Review 1 selected role(s)').trigger('click')
    await flushPromises()
    await buttonNamed(wrapper, 'Confirm grant').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('recomputed')
    expect(wrapper.text()).toContain('Newly held: realm:auditor')
    const rows = wrapper.findAll('[data-testid="access-role"]')
    expect(rows.find((r) => r.text().includes('auditor')).text()).toContain('new')
  })

  it('says plainly when a grant changed nothing', async () => {
    responses['POST /api/tenants/tenant-alpha/users/u1/role-mappings'] = stub({
      ...preview,
      assigned: 1,
    })
    const wrapper = await mountAccess()
    const row = wrapper
      .findAll('[data-testid="offerable-role"]')
      .find((r) => r.text().includes('tenant-user'))
    expect(row.text()).toContain('already held')
    await row.find('input[type="checkbox"]').trigger('change')
    await flushPromises()
    await buttonNamed(wrapper, 'Review 1 selected role(s)').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('this grant would change nothing')
    await buttonNamed(wrapper, 'Confirm grant').trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('already held every one of those roles')
  })

  it('reuses the key when a failed confirmation is retried', async () => {
    responses['POST /api/tenants/tenant-alpha/users/u1/role-mappings'] = {
      ok: false,
      status: 502,
      body: { error: 'upstream_unavailable' },
    }
    const wrapper = await mountAccess()
    await selectAuditor(wrapper)
    await buttonNamed(wrapper, 'Review 1 selected role(s)').trigger('click')
    await flushPromises()
    await buttonNamed(wrapper, 'Confirm grant').trigger('click')
    await flushPromises()
    await buttonNamed(wrapper, 'Confirm grant').trigger('click')
    await flushPromises()

    const keys = posted.map((p) => p.options.headers['Idempotency-Key'])
    expect(keys).toHaveLength(2)
    expect(keys[0]).toBe(keys[1])
    expect(wrapper.text()).toContain('identity provider is unavailable')
  })
})

describe('errors', () => {
  it('never shows a raw status or error code', async () => {
    responses['GET /api/tenants/tenant-alpha/users/u1/effective-access'] = {
      ok: false,
      status: 502,
      body: { error: 'upstream_unavailable' },
      headers: { 'X-Correlation-Id': 'corr-xyz' },
    }
    const wrapper = await mountAccess()
    expect(wrapper.text()).toContain('corr-xyz')
    expect(wrapper.text()).not.toContain('502')
    expect(wrapper.text()).not.toContain('upstream_unavailable')
  })
})
