import { flushPromises, mount } from '@vue/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ClientsView from '@/views/ClientsView.vue'
import SecretOnce from '@/components/clients/SecretOnce.vue'
import { splitLines } from '@/clients.js'

/**
 * IAM-0217 on the screen.
 *
 * The criterion is not "clients are listed". It is that a secret is shown once and
 * never again, and that an unsafe redirect is refused. So the cases below are the
 * ones that, if they broke, would either leak a credential or leave an
 * administrator confidently wrong:
 *
 *  - a secret rendered anywhere other than the one panel that issues it;
 *  - a secret written to storage, where it survives the page and can be recovered;
 *  - a show-once panel that does not say it is show-once;
 *  - a server refusal swallowed, so an unsafe redirect looks accepted;
 *  - a platform-managed client offered for editing.
 */

const session = {
  username: 'tadmin',
  roles: ['tenant-admin'],
  permissions: { platformAdmin: false, tenantAdmin: true },
  crossTenant: false,
  tenants: ['tenant-alpha'],
}

const SECRET = 'GENERATED-SECRET-VALUE-0217'

const client = (over = {}) => ({
  clientId: 'reporting.api.poc',
  name: 'Reporting API',
  description: null,
  enabled: true,
  publicClient: false,
  kind: 'confidential',
  standardFlowEnabled: true,
  serviceAccountsEnabled: false,
  implicitFlowEnabled: false,
  directAccessGrantsEnabled: false,
  redirectUris: ['https://app.example.com/cb'],
  webOrigins: ['https://app.example.com'],
  pkceChallengeMethod: 'S256',
  reserved: false,
  ...over,
})

const listing = {
  tenant: 'tenant-alpha',
  count: 2,
  limit: 50,
  clients: [
    client(),
    // Platform-managed: the console runs on clients like this one.
    client({ clientId: 'poc-cli', name: '${client_admin-cli}', kind: 'public', publicClient: true, reserved: true }),
  ],
}

let responses
let sent

function stub(body, over = {}) {
  return { body, ...over }
}

beforeEach(() => {
  sent = []
  responses = {
    'GET /api/tenants/tenant-alpha/clients': stub(listing),
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url, options = {}) => {
      const method = options.method ?? 'GET'
      const key = `${method} ${url}`
      if (method !== 'GET') {
        sent.push({ url, method, options })
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
  vi.restoreAllMocks()
})

async function mountClients() {
  const wrapper = mount(ClientsView, { props: { session } })
  await flushPromises()
  return wrapper
}

function buttonNamed(wrapper, text) {
  return wrapper.findAll('button').find((b) => b.text().trim() === text)
}

async function createConfidential(wrapper, response) {
  responses['POST /api/tenants/tenant-alpha/clients'] = response
  await buttonNamed(wrapper, 'Register a client').trigger('click')
  await flushPromises()
  await wrapper.find('#clientId').setValue('reporting.batch.poc')
  await wrapper.find('#redirectUris').setValue('https://app.example.com/cb')
  await wrapper.find('form').trigger('submit')
  await flushPromises()
}

describe('the registry', () => {
  it('lists clients with their kind and state', async () => {
    const wrapper = await mountClients()
    const rows = wrapper.findAll('[data-testid="client-row"]')
    expect(rows).toHaveLength(1)
    expect(rows[0].text()).toContain('reporting.api.poc')
    expect(rows[0].text()).toContain('confidential')
    expect(rows[0].text()).toContain('enabled')
  })

  it('never renders a secret in the list, whatever the server sends', async () => {
    // Defence in depth: the projection already drops it, but a UI that would
    // render one if it arrived is a UI that leaks the day the projection breaks.
    responses['GET /api/tenants/tenant-alpha/clients'] = stub({
      ...listing,
      clients: [{ ...client(), secret: SECRET }],
    })
    const wrapper = await mountClients()
    expect(wrapper.text()).not.toContain(SECRET)
  })

  it('offers no actions on a platform-managed client', async () => {
    const wrapper = await mountClients()
    await buttonNamed(wrapper, 'System clients').trigger('click')
    const managed = wrapper
      .findAll('[data-testid="client-row"]')
      .find((r) => r.text().includes('poc-cli'))
    // Disabling one of these signs out the administrator trying to undo it, so it
    // is not offered - saying why beats a rejected write.
    expect(managed.text()).toContain('Managed by the platform')
    expect(managed.findAll('button')).toHaveLength(0)
  })

  it('does not offer deletion anywhere', async () => {
    const wrapper = await mountClients()
    const labels = wrapper.findAll('button').map((b) => b.text().toLowerCase())
    expect(labels.some((l) => l.includes('delete'))).toBe(false)
    expect(wrapper.text()).toContain('cannot be deleted')
  })

  it('states the redirect and origin rules before submission, not after rejection', async () => {
    const wrapper = await mountClients()
    await buttonNamed(wrapper, 'Register a client').trigger('click')
    await flushPromises()
    expect(wrapper.find('[data-testid="redirect-help"]').text()).toContain('exact')
    expect(wrapper.find('[data-testid="redirect-help"]').text()).toContain('Wildcards are not permitted')
    expect(wrapper.find('[data-testid="origin-help"]').text()).toContain('no path')
  })
})

describe('the show-once secret', () => {
  it('shows the secret the create call returned', async () => {
    const wrapper = await mountClients()
    await createConfidential(
      wrapper,
      stub({ clientId: 'reporting.batch.poc', secret: SECRET, secretShownOnce: true }),
    )
    expect(wrapper.find('[data-testid="secret-value"]').text()).toBe(SECRET)
  })

  it('says unmistakably that it will not be shown again', async () => {
    const wrapper = await mountClients()
    await createConfidential(
      wrapper,
      stub({ clientId: 'reporting.batch.poc', secret: SECRET, secretShownOnce: true }),
    )
    const panel = wrapper.find('[data-testid="secret-once"]')
    expect(panel.text()).toContain('It will not be shown again')
    expect(panel.text()).toContain('cannot be retrieved again')
    // The remedy must be stated too, or "not shown again" reads as "lost forever".
    expect(panel.text()).toContain('issue a new one')
  })

  it('removes the secret from the DOM once acknowledged, and does not bring it back', async () => {
    const wrapper = await mountClients()
    await createConfidential(
      wrapper,
      stub({ clientId: 'reporting.batch.poc', secret: SECRET, secretShownOnce: true }),
    )
    await wrapper.find('[data-testid="secret-dismiss"]').trigger('click')
    await flushPromises()

    expect(wrapper.find('[data-testid="secret-once"]').exists()).toBe(false)
    expect(wrapper.text()).not.toContain(SECRET)
    // Nothing may reopen it - a panel that can be reopened has to keep the value.
    expect(wrapper.html()).not.toContain(SECRET)
  })

  it('never writes the secret to local or session storage', async () => {
    // Anything persisted is recoverable later by definition, which is exactly the
    // property "never returned again" denies.
    const setItem = vi.spyOn(Storage.prototype, 'setItem')
    const wrapper = await mountClients()
    await createConfidential(
      wrapper,
      stub({ clientId: 'reporting.batch.poc', secret: SECRET, secretShownOnce: true }),
    )
    const persisted = setItem.mock.calls.map((call) => String(call[1]))
    expect(persisted.some((value) => value.includes(SECRET))).toBe(false)
    expect(window.localStorage.getItem('secret')).toBeNull()
    expect(document.cookie).not.toContain(SECRET)
  })

  it('shows no secret panel for a public client, which has none', async () => {
    const wrapper = await mountClients()
    await createConfidential(
      wrapper,
      stub({ clientId: 'spa.poc', secretShownOnce: false }),
    )
    expect(wrapper.find('[data-testid="secret-once"]').exists()).toBe(false)
  })

  it('warns that rotation breaks the current integration before doing it', async () => {
    const wrapper = await mountClients()
    await buttonNamed(wrapper, 'Rotate secret').trigger('click')
    await flushPromises()
    // Nothing may be written until the warning has been shown.
    expect(sent).toHaveLength(0)
    expect(wrapper.text()).toContain('takes effect immediately')
    expect(wrapper.text()).toContain('stop working')
  })

  it('shows the rotated secret once, and says the old one is already dead', async () => {
    responses['POST /api/tenants/tenant-alpha/clients/reporting.api.poc/secret'] = stub({
      clientId: 'reporting.api.poc',
      secret: SECRET,
      secretShownOnce: true,
    })
    const wrapper = await mountClients()
    await buttonNamed(wrapper, 'Rotate secret').trigger('click')
    await flushPromises()
    await wrapper.find('[data-testid="confirm-rotate"]').trigger('click')
    await flushPromises()

    const panel = wrapper.find('[data-testid="secret-once"]')
    expect(panel.text()).toContain('New client secret')
    expect(panel.find('[data-testid="secret-value"]').text()).toBe(SECRET)
    expect(panel.text()).toContain('previous secret stopped working')
  })

  it('holds the value only in the prop it was given', () => {
    // Mounted standalone: no store, no storage, no module state. Unmounting is
    // therefore sufficient to make the value unrecoverable.
    //
    // Asserted against the real document rather than wrapper.html(), which keeps
    // returning the last render after unmount and would pass this test for the
    // wrong reason - it describes the wrapper's memory, not the page's.
    const wrapper = mount(SecretOnce, {
      attachTo: document.body,
      props: { clientId: 'a.b.c', secret: SECRET },
    })
    expect(document.body.innerHTML).toContain(SECRET)
    wrapper.unmount()
    expect(document.body.innerHTML).not.toContain(SECRET)
  })
})

describe('writes', () => {
  it('sends a CSRF token and an idempotency key, and reuses the key on retry', async () => {
    const wrapper = await mountClients()
    responses['POST /api/tenants/tenant-alpha/clients'] = {
      ok: false,
      status: 502,
      body: { error: 'upstream_unavailable' },
    }
    await buttonNamed(wrapper, 'Register a client').trigger('click')
    await flushPromises()
    await wrapper.find('#clientId').setValue('reporting.batch.poc')
    await wrapper.find('#redirectUris').setValue('https://app.example.com/cb')
    await wrapper.find('form').trigger('submit')
    await flushPromises()
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    expect(sent).toHaveLength(2)
    expect(sent[0].options.headers['X-XSRF-TOKEN']).toBe('csrf-token')
    // A stalled create clicked twice must not produce two clients.
    expect(sent[0].options.headers['Idempotency-Key']).toBe(
      sent[1].options.headers['Idempotency-Key'],
    )
  })

  it('sends redirect URIs as a list, one per line, unmodified', async () => {
    const wrapper = await mountClients()
    responses['POST /api/tenants/tenant-alpha/clients'] = stub({ clientId: 'x', secretShownOnce: false })
    await buttonNamed(wrapper, 'Register a client').trigger('click')
    await flushPromises()
    await wrapper.find('#clientId').setValue('reporting.batch.poc')
    await wrapper.find('#redirectUris').setValue(
      'https://a.example.com/cb\n\nhttps://b.example.com/cb\n',
    )
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    const body = JSON.parse(sent[0].options.body)
    expect(body.redirectUris).toEqual(['https://a.example.com/cb', 'https://b.example.com/cb'])
    expect(body.kind).toBe('confidential')
  })

  it('reports a server refusal instead of swallowing it', async () => {
    // The server refused an unsafe redirect. If this did not surface, the operator
    // would believe the configuration was accepted.
    const wrapper = await mountClients()
    responses['POST /api/tenants/tenant-alpha/clients'] = {
      ok: false,
      status: 400,
      body: { error: 'invalid_request' },
      headers: { 'X-Correlation-Id': 'corr-217' },
    }
    await buttonNamed(wrapper, 'Register a client').trigger('click')
    await flushPromises()
    await wrapper.find('#clientId').setValue('bad.client.poc')
    await wrapper.find('#redirectUris').setValue('https://*.example.com/cb')
    await wrapper.find('form').trigger('submit')
    await flushPromises()

    const error = wrapper.find('[data-testid="save-error"]')
    expect(error.exists()).toBe(true)
    expect(error.text()).toContain('refused')
    expect(error.text()).toContain('corr-217')
    // Never a raw status or error code.
    expect(error.text()).not.toContain('400')
    expect(error.text()).not.toContain('invalid_request')
  })

  it('cannot rename a client or change its kind when editing', async () => {
    const wrapper = await mountClients()
    await buttonNamed(wrapper, 'Edit').trigger('click')
    await flushPromises()
    // Renaming breaks every integration authenticating as the client; flipping
    // confidential to public strands a live secret. Neither is offered.
    expect(wrapper.find('#clientId').exists()).toBe(false)
    expect(wrapper.findAll('input[type="radio"]')).toHaveLength(0)
  })
})

describe('splitLines', () => {
  it('drops blank lines and trims, but does not otherwise normalise', () => {
    // "Exact" is the rule, so trimming a URI into validity would hide a mistake.
    expect(splitLines(' https://a.example.com/cb \n\n https://b.example.com/cb ')).toEqual([
      'https://a.example.com/cb',
      'https://b.example.com/cb',
    ])
    expect(splitLines('')).toEqual([])
    expect(splitLines(null)).toEqual([])
    expect(splitLines(['https://a.example.com/cb'])).toEqual(['https://a.example.com/cb'])
  })
})


describe('client display names', () => {
  it('resolves Keycloak built-in name placeholders without changing client identifiers', async () => {
    const wrapper = mount(ClientsView, { props: { session } })
    await flushPromises()
    await buttonNamed(wrapper, 'System clients').trigger('click')
    expect(wrapper.text()).toContain('Admin command line')
    expect(wrapper.text()).toContain('poc-cli')
    expect(wrapper.text()).not.toContain('${client_admin-cli}')
    wrapper.unmount()
  })
})


describe('application and system categories', () => {
  it('starts with applications and keeps system clients discoverable', async () => {
    const wrapper = await mountClients()
    expect(buttonNamed(wrapper, 'Application clients').attributes('aria-pressed')).toBe('true')
    expect(wrapper.text()).toContain('Reporting API')
    expect(wrapper.text()).not.toContain('poc-cli')
    await buttonNamed(wrapper, 'All clients').trigger('click')
    expect(wrapper.findAll('[data-testid="client-row"]')).toHaveLength(2)
  })

  it('protects required integrations and explains their purpose even with an older backend', async () => {
    responses['GET /api/tenants/tenant-alpha/clients'] = stub({
      ...listing, count: 4, clients: [client(), ...['admin-permissions', 'iam-application-access', 'platform-broker'].map(clientId => client({clientId, name: clientId, reserved: false}))],
    })
    const wrapper = await mountClients()
    expect(wrapper.findAll('[data-testid="client-row"]')).toHaveLength(1)
    await buttonNamed(wrapper, 'System clients').trigger('click')
    const rows = wrapper.findAll('[data-testid="client-row"]')
    expect(rows).toHaveLength(3)
    expect(rows.every(row => row.findAll('button').length === 0)).toBe(true)
    expect(wrapper.text()).toContain('fine-grained administration policies')
    expect(wrapper.text()).toContain('MapDashboard roles and user access')
    expect(wrapper.text()).toContain('IAM platform sign-in realm')
    expect(sent).toHaveLength(0)
  })
})
