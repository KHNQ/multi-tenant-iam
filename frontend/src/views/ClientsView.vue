<script setup>
/*
 * IAM-0217 (restricted): the OAuth/OIDC client registry on screen.
 *
 * Three things this screen owns: the list, the create/edit form, and the show-once
 * secret. The third is the one that matters, and it lives in SecretOnce.vue.
 *
 * Redirect and origin validation is NOT duplicated here. The server decides
 * (ClientPolicy) and this form reports what it decided. A second copy of those
 * rules in the browser would drift, and a drifted copy that *accepts* something the
 * server refuses is a UI that tells an administrator their configuration is fine
 * when the platform has already rejected it. What the form does instead is state
 * the rules in the help text, so the requirement is visible before submission
 * rather than discovered by rejection.
 *
 * Deletion is absent, matching ClientsController: removing a client silently breaks
 * every integration authenticating as it. Disable is offered in its place, is
 * reversible, and is labelled as the safe alternative.
 */
import { computed, onMounted, ref } from 'vue'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import SecretOnce from '@/components/clients/SecretOnce.vue'
import { useI18n } from '@/i18n.js'
import { useTenantPreference } from '@/tenantPreference.js'
import { standby } from '@/standby.js'
import {
  createClient,
  fetchClients,
  messageFor,
  newIdempotencyKey,
  rotateSecret,
  setClientEnabled,
  updateClient,
} from '@/clients.js'

const props = defineProps({ session: { type: Object, required: true } })
const { t } = useI18n()

const tenants = computed(() => props.session.tenants ?? [])
const tenant = useTenantPreference(tenants)

const search = ref('')
const result = ref(null)
const loading = ref(false)
const listError = ref(null)

async function load() {
  if (!tenant.value) {
    return
  }
  loading.value = true
  listError.value = null
  try {
    result.value = await fetchClients(tenant.value, search.value.trim())
  } catch (error) {
    listError.value = error
  } finally {
    loading.value = false
  }
}

function clientDisplayName(client) {
  const name = client.name?.trim()
  if (!name) return client.clientId
  if (/^\$\{[^}]+\}$/.test(name)) {
    const key = name.slice(2, -1)
    const known = ['client_account', 'client_account-console', 'client_admin-cli', 'client_broker', 'client_realm-management', 'client_security-admin-console']
    return known.includes(key) ? t(`clients.display.${key}`) : client.clientId
  }
  return name
}

const systemPurposes = {
  account: 'account',
  'account-console': 'accountConsole',
  'admin-cli': 'adminCli',
  broker: 'broker',
  'realm-management': 'realmManagement',
  'security-admin-console': 'adminConsole',
  'admin-permissions': 'adminPermissions',
  'iam-application-access': 'applicationAccess',
  'platform-broker': 'platformBroker',
  'iam-admin-ui': 'iamUi',
  'management-api': 'managementApi',
  'iam-automation': 'automation',
  'poc-cli': 'adminCli',
}
function systemPurpose(client) {
  return systemPurposes[client.clientId?.trim().toLowerCase()]
}
function isSystemClient(client) {
  return client.reserved || Boolean(systemPurpose(client))
}
const clientFilter = ref('applications')
const filteredClients = computed(() => clients.value.filter(client => clientFilter.value === 'all' || (clientFilter.value === 'platform' ? isSystemClient(client) : !isSystemClient(client))))
const clients = computed(() => result.value?.clients ?? [])

/* ---------- the show-once secret ---------- */

/*
 * The single place a secret exists in this application. It is component state, not
 * a store and not storage, so it dies with the component and cannot be read back by
 * anything else. `clearSecret` is the only way it leaves, and every path that could
 * navigate away from it calls that first.
 */
const issued = ref(null)

function clearSecret() {
  issued.value = null
}

/* ---------- create ---------- */

const blank = () => ({
  clientId: '',
  name: '',
  description: '',
  kind: 'confidential',
  redirectUris: '',
  webOrigins: '',
  postLogoutRedirectUris: '',
  standardFlow: true,
})

const draft = ref(blank())
function chooseType(type) {
  draft.value.kind = type === 'browser' ? 'public' : 'confidential'
  draft.value.standardFlow = type !== 'service'
}
const showForm = ref(false)
const editing = ref(null)
const saving = ref(false)
const saveError = ref(null)

/*
 * Minted when the form is opened, not when it is submitted. Someone who submits,
 * watches a spinner stall and clicks again must send the same key, or the second
 * click is a genuinely new operation - and for a create that means a second client.
 */
let saveKey = newIdempotencyKey()

function openCreate() {
  clearSecret()
  draft.value = blank()
  editing.value = null
  saveError.value = null
  saveKey = newIdempotencyKey()
  showForm.value = true
}

function openEdit(client) {
  clearSecret()
  draft.value = {
    clientId: client.clientId,
    name: client.name ?? '',
    description: client.description ?? '',
    kind: client.kind,
    redirectUris: (client.redirectUris ?? []).join('\n'),
    webOrigins: (client.webOrigins ?? []).join('\n'),
    postLogoutRedirectUris: (client.postLogoutRedirectUris ?? []).join('\n'),
    standardFlow: client.standardFlowEnabled !== false,
  }
  editing.value = client.clientId
  saveError.value = null
  saveKey = newIdempotencyKey()
  showForm.value = true
}

function closeForm() {
  showForm.value = false
  saveError.value = null
}

async function save() {
  saving.value = true
  saveError.value = null
  try {
    if (editing.value) {
      await updateClient(tenant.value, editing.value, draft.value, saveKey)
      showForm.value = false
    } else {
      const created = await createClient(tenant.value, draft.value, saveKey)
      showForm.value = false
      // A public client legitimately has no secret; only show the panel when the
      // server actually issued one.
      if (created.secret) {
        issued.value = { clientId: created.clientId, secret: created.secret, rotated: false }
      }
    }
    await load()
  } catch (error) {
    saveError.value = error
  } finally {
    saving.value = false
  }
}

/* ---------- enable / disable ---------- */

const rowError = ref(null)

async function toggleEnabled(client) {
  rowError.value = null
  try {
    await setClientEnabled(tenant.value, client.clientId, !client.enabled, newIdempotencyKey())
    await load()
  } catch (error) {
    rowError.value = error
  }
}

/* ---------- rotation ---------- */

/*
 * Confirmed before it happens, because rotation is destructive in a way that does
 * not look destructive: it is a button that breaks production integrations the
 * instant it is pressed, and there is no undo.
 */
const rotating = ref(null)

function askRotate(client) {
  clearSecret()
  rowError.value = null
  rotating.value = client.clientId
}

async function confirmRotate() {
  const clientId = rotating.value
  rowError.value = null
  try {
    const rotated = await rotateSecret(tenant.value, clientId, newIdempotencyKey())
    rotating.value = null
    if (rotated.secret) {
      issued.value = { clientId, secret: rotated.secret, rotated: true }
    }
    await load()
  } catch (error) {
    rotating.value = null
    rowError.value = error
  }
}

onMounted(load)
</script>

<template>
  <div class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <div>
      <h1 class="text-2xl font-semibold">{{ t('clients.title') }}</h1>
      <p class="mt-1 text-sm text-content-muted">{{ t('clients.pageHelp') }}</p>
    </div>
    <Button v-if="tenant && !showForm" :disabled="standby" @click="openCreate">{{ t('clients.register') }}</Button>
  </div>

  <p v-if="!tenant" class="text-sm text-content-muted">{{ t('common.noTenant') }}</p>

  <template v-else>
    <!-- The secret panel sits above everything: it must not be scrolled past. -->
    <SecretOnce
      v-if="issued"
      class="mb-5"
      :client-id="issued.clientId"
      :secret="issued.secret"
      :rotated="issued.rotated"
      @dismiss="clearSecret"
    />

    <Alert v-if="listError" tone="danger" class="mb-5">
      {{ messageFor(listError) }}
      <span v-if="listError.correlationId" class="block text-xs opacity-80">
        {{ t('common.reference') }}: {{ listError.correlationId }}
      </span>
      <Button variant="outline" size="sm" class="mt-2" @click="load">{{ t('action.tryAgain') }}</Button>
    </Alert>

    <Alert v-if="rowError" tone="danger" class="mb-5">{{ messageFor(rowError) }}</Alert>

    <!-- create / edit -->
    <Card v-if="showForm" class="mb-5" :title="editing ? t('users.edit', { user: editing }) : t('clients.register')">
      <form @submit.prevent="save">
        <div v-if="!editing" class="mb-5">
          <p class="mb-2 text-sm font-medium">{{ t('ux.applicationType') }}</p>
          <div class="flex flex-wrap gap-2" role="group" :aria-label="t('ux.applicationType')">
            <Button type="button" variant="outline" @click="chooseType('browser')">{{ t('ux.browserApp') }}</Button>
            <Button type="button" variant="outline" @click="chooseType('server')">{{ t('ux.serverApp') }}</Button>
            <Button type="button" variant="outline" @click="chooseType('service')">{{ t('ux.serviceApp') }}</Button>
          </div>
          <p class="mt-2 text-xs text-content-muted">{{ t('ux.clientPresetHelp') }}</p>
        </div>
        <div v-if="!editing" class="mb-4">
          <label for="clientId" class="mb-1 block text-sm font-medium">{{ t('clients.clientId') }}</label>
          <input
            id="clientId"
            v-model="draft.clientId"
            required
            class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
          />
          <p class="mt-1 text-xs text-content-muted">
            {{ t('clients.idHelp') }}
          </p>
        </div>

        <div v-if="!editing" class="mb-4">
          <span class="mb-1 block text-sm font-medium">{{ t('clients.clientType') }}</span>
          <label class="mr-4 inline-flex items-center gap-2 text-sm">
            <input v-model="draft.kind" type="radio" value="confidential" />
            {{ t('clients.confidentialHelp') }}
          </label>
          <label class="inline-flex items-center gap-2 text-sm">
            <input v-model="draft.kind" type="radio" value="public" />
            {{ t('clients.publicHelp') }}
          </label>
          <p class="mt-1 text-xs text-content-muted">
            {{ t('clients.typeHelp') }}
          </p>
        </div>

        <div class="mb-4">
          <label for="name" class="mb-1 block text-sm font-medium">{{ t('clients.displayName') }}</label>
          <input
            id="name"
            v-model="draft.name"
            class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
          />
        </div>

        <div class="mb-4">
          <label class="inline-flex items-center gap-2 text-sm">
            <input v-model="draft.standardFlow" type="checkbox" />
            {{ t('clients.standardFlow') }}
          </label>
          <p class="mt-1 text-xs text-content-muted">
            {{ t('clients.standardFlowHelp') }}
          </p>
        </div>

        <div class="mb-4">
          <label for="redirectUris" class="mb-1 block text-sm font-medium">
            {{ t('clients.redirectLines') }}
          </label>
          <textarea
            id="redirectUris"
            v-model="draft.redirectUris"
            rows="3"
            class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5
                   font-mono text-sm"
          ></textarea>
          <!--
            The rules are stated up front rather than discovered by rejection. They
            are not re-checked here: the server decides, and a second copy of the
            rules in the browser would eventually disagree with it.
          -->
          <p class="mt-1 text-xs text-content-muted" data-testid="redirect-help">
            {{ t('clients.redirectHelp') }}
          </p>
        </div>

        <div class="mb-4">
          <label for="postLogoutRedirectUris" class="mb-1 block text-sm font-medium">
            {{ t('clients.postLogoutLines') }}
          </label>
          <textarea
            id="postLogoutRedirectUris"
            v-model="draft.postLogoutRedirectUris"
            rows="3"
            class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5
                   font-mono text-sm"
          ></textarea>
          <p class="mt-1 text-xs text-content-muted" data-testid="post-logout-help">
            {{ t('clients.postLogoutHelp') }}
          </p>
        </div>

        <div class="mb-4">
          <label for="webOrigins" class="mb-1 block text-sm font-medium">
            {{ t('clients.originLines') }}
          </label>
          <textarea
            id="webOrigins"
            v-model="draft.webOrigins"
            rows="2"
            class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5
                   font-mono text-sm"
          ></textarea>
          <p class="mt-1 text-xs text-content-muted" data-testid="origin-help">
            {{ t('clients.originHelp') }}
          </p>
        </div>

        <Alert v-if="saveError" tone="danger" class="mb-4" data-testid="save-error">
          {{ messageFor(saveError) }}
          <span v-if="saveError.correlationId" class="block text-xs opacity-80">
            {{ t('common.reference') }}: {{ saveError.correlationId }}
          </span>
        </Alert>

        <div class="flex gap-3">
          <Button type="submit" :disabled="saving || standby">
            {{ saving ? t('users.saving') : editing ? t('clients.saveChanges') : t('clients.registerAction') }}
          </Button>
          <Button variant="ghost" type="button" :disabled="saving" @click="closeForm">
            {{ t('action.cancel') }}
          </Button>
        </div>
      </form>
    </Card>

    <!-- rotation confirmation -->
    <Card v-if="rotating" class="mb-5" :title="t('clients.issueSecret')">
      <Alert tone="danger" class="mb-4">
        {{ t('clients.rotateWarning', { client: rotating }) }}
      </Alert>
      <div class="flex gap-3">
        <Button data-testid="confirm-rotate" @click="confirmRotate">
          {{ t('clients.issue') }}
        </Button>
        <Button variant="ghost" @click="rotating = null">{{ t('action.cancel') }}</Button>
      </div>
    </Card>

    <Card :title="t('clients.count', { count: clientFilter === 'all' ? result?.count ?? 0 : filteredClients.length })">
      <div class="mb-4 flex flex-wrap gap-2">
        <label for="client-search" class="sr-only">{{ t('clients.search') }}</label>
        <input
          id="client-search"
          v-model="search"
          type="search"
          :placeholder="t('clients.searchPlaceholder')"
          class="min-w-0 flex-1 rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
          @keyup.enter="load"
        />
        <Button variant="outline" @click="load">{{ t('action.search') }}</Button>
      </div>

      <div class="mb-4 flex flex-wrap gap-2" role="group" :aria-label="t('ux.clientScope')">
        <Button v-for="key in ['applications', 'platform', 'all']" :key="key" size="sm" :variant="clientFilter === key ? 'default' : 'outline'" :aria-pressed="clientFilter === key" @click="clientFilter = key">{{ t(`ux.clients.${key}`) }}</Button>
      </div>
      <p class="mb-4 text-sm text-content-muted">{{ t(clientFilter === 'platform' ? 'clients.systemHelp' : clientFilter === 'applications' ? 'clients.applicationsHelp' : 'clients.allHelp') }}</p>
      <Spinner v-if="loading" />
      <p v-else-if="!filteredClients.length" class="text-sm text-content-muted">{{ t('clients.noMatch') }}</p>
      <ul v-else class="flex flex-col divide-y divide-border-subtle">
        <li
          v-for="client in filteredClients"
          :key="client.clientId"
          data-testid="client-row"
          class="flex flex-wrap items-center gap-3 py-3"
        >
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
              <span class="font-medium break-all">{{ clientDisplayName(client) }}</span><code v-if="clientDisplayName(client) !== client.clientId" class="text-xs text-content-muted break-all" dir="ltr">{{ client.clientId }}</code>
              <Badge :tone="client.enabled ? 'success' : 'neutral'">
                {{ t(`state.${client.enabled ? 'enabled' : 'disabled'}`) }}
              </Badge>
              <Badge tone="neutral">{{ t(`clients.${client.kind}`) }}</Badge>
              <Badge v-if="isSystemClient(client)" tone="brand">{{ t('clients.platformManaged') }}</Badge>
            </div>
            <p v-if="isSystemClient(client)" class="mt-2 text-sm text-content-muted">{{ t(`clients.purpose.${systemPurpose(client) || 'fallback'}`) }}</p>
            <p v-else-if="client.description" class="mt-2 text-sm text-content-muted">{{ client.description }}</p>
            <p v-if="!isSystemClient(client) && client.redirectUris?.length" class="mt-1 font-mono text-xs text-content-muted">
              {{ client.redirectUris.join(', ') }}
            </p>
            <p v-else-if="!isSystemClient(client)" class="mt-1 text-xs text-content-muted">{{ t('clients.noRedirect') }}</p>
          </div>

          <!--
            Platform-managed clients are shown but offer no actions: the console
            runs on some of these, and disabling one would sign out the person
            trying to undo it. Saying so is better than a rejected write.
          -->
          <span v-if="isSystemClient(client)" class="text-xs text-content-muted">
            {{ t('clients.managedHelp') }}
          </span>
          <div v-else class="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" :disabled="standby" @click="openEdit(client)">{{ t('action.edit') }}</Button>
            <Button
              v-if="client.kind === 'confidential'"
              variant="outline"
              size="sm"
              @click="askRotate(client)"
            >
              {{ t('clients.rotateSecret') }}
            </Button>
            <Button variant="outline" size="sm" :disabled="standby" @click="toggleEnabled(client)">
              {{ t(client.enabled ? 'action.disable' : 'action.enable') }}
            </Button>
          </div>
        </li>
      </ul>

      <p class="mt-4 text-xs text-content-muted">
        {{ t('clients.deletionHelp') }}
      </p>
    </Card>
  </template>
</template>
