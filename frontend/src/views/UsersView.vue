<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import AccessView from '@/views/AccessView.vue'
import SessionsView from '@/views/SessionsView.vue'
import AccessTest from '@/components/access/AccessTest.vue'
import { standby } from '@/standby.js'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import { messageFor } from '@/api.js'
import { useI18n } from '@/i18n.js'
import { useTenantPreference } from '@/tenantPreference.js'
import {
  createUser, fetchUser,
  newIdempotencyKey,
  resetUserCredential,
  searchUsers,
  setUserEnabled,
  setUserRequiredActions,
  updateUser,
} from '@/users.js'

const props = defineProps({ session: { type: Object, required: true }, detailUserId: { type: String, default: '' }, detailTenant: { type: String, default: '' } })
const { t } = useI18n()

const tenants = computed(() => props.session.tenants ?? [])
const preferredTenant = useTenantPreference(tenants)
const tenant = computed({ get: () => props.detailTenant || preferredTenant.value, set: value => { preferredTenant.value = value } })
const detailUser = ref(null)
const detailTab = ref('profile')
const userTabs = computed(() => [ ['profile', t('ux.profile')], ['access', t('users.access')], ['credentials', t('users.credentials')], ['sessions', t('sessions.title')], ['accessTest', t('users.accessTest')] ])
function changeDetailTab(tab) {
  editing.value = null
  closeCredentials()
  detailTab.value = tab
  if (tab === 'credentials' && detailUser.value) openCredentials(detailUser.value)
}


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
    if (props.detailUserId) detailUser.value = await fetchUser(tenant.value, props.detailUserId)
    else result.value = await searchUsers(tenant.value, search.value.trim())
  } catch (error) {
    listError.value = error
  } finally {
    loading.value = false
  }
}

/* ---------- create ---------- */

const blank = () => ({ username: '', email: '', firstName: '', lastName: '' })
const draft = ref(blank())
const creating = ref(false)
const createError = ref(null)
const created = ref(null)

/*
 * Minted when the form is opened, not when it is submitted. A user who submits,
 * sees a spinner stall and clicks again must reuse the same key - otherwise the
 * second click is a genuinely new operation and creates a second account.
 */
let createKey = newIdempotencyKey()
const showCreate = ref(false)

function openCreate() {
  draft.value = blank()
  createError.value = null
  created.value = null
  createKey = newIdempotencyKey()
  showCreate.value = true
}

async function submitCreate() {
  creating.value = true
  createError.value = null
  try {
    created.value = await createUser(tenant.value, { ...draft.value }, createKey)
    showCreate.value = false
    await load()
  } catch (error) {
    createError.value = error
  } finally {
    creating.value = false
  }
}

/* ---------- edit and disable ---------- */

const editing = ref(null)
const editDraft = ref(blank())
const editError = ref(null)
const saving = ref(false)
let editKey = null

function openEdit(user) {
  editing.value = user
  editDraft.value = {
    email: user.email ?? '',
    firstName: user.firstName ?? '',
    lastName: user.lastName ?? '',
  }
  editError.value = null
  editKey = newIdempotencyKey()
}

async function submitEdit() {
  saving.value = true
  editError.value = null
  try {
    await updateUser(tenant.value, editing.value.id, { ...editDraft.value }, editKey)
    editing.value = null
    await load()
  } catch (error) {
    editError.value = error
  } finally {
    saving.value = false
  }
}

const busyUser = ref(null)

async function toggleEnabled(user) {
  busyUser.value = user.id
  listError.value = null
  try {
    await setUserEnabled(tenant.value, user.id, !user.enabled, newIdempotencyKey())
    await load()
  } catch (error) {
    listError.value = error
  } finally {
    busyUser.value = null
  }
}

/* ---------- credentials and required actions ---------- */

const availableActions = computed(() => [
  ['UPDATE_PASSWORD', t('users.changePassword')],
  ['VERIFY_EMAIL', t('users.verifyEmail')],
  ['CONFIGURE_TOTP', t('users.configureAuthenticator')],
  ['UPDATE_PROFILE', t('users.updateProfile')],
])
const credentialsUser = ref(null)
const temporaryPassword = ref('')
const resetDone = ref(false)
const credentialError = ref(null)
const resetting = ref(false)
const actionDraft = ref([])
const savingActions = ref(false)
let resetKey = null
let actionsKey = null

function randomCharacter(characters) {
  const value = new Uint32Array(1)
  crypto.getRandomValues(value)
  return characters[value[0] % characters.length]
}

function generateTemporaryPassword() {
  const groups = ['ABCDEFGHJKLMNPQRSTUVWXYZ', 'abcdefghijkmnopqrstuvwxyz', '23456789', '!@#$%*-_=+']
  const characters = groups.join('')
  const password = groups.map(randomCharacter)
  while (password.length < 20) password.push(randomCharacter(characters))
  for (let index = password.length - 1; index > 0; index -= 1) {
    const value = new Uint32Array(1)
    crypto.getRandomValues(value)
    const swap = value[0] % (index + 1)
    ;[password[index], password[swap]] = [password[swap], password[index]]
  }
  return password.join('')
}

function openCredentials(user) {
  credentialsUser.value = user
  temporaryPassword.value = generateTemporaryPassword()
  actionDraft.value = [...(user.requiredActions ?? [])]
  resetDone.value = false
  credentialError.value = null
  resetKey = newIdempotencyKey()
  actionsKey = newIdempotencyKey()
}

function closeCredentials() {
  temporaryPassword.value = ''
  credentialsUser.value = null
  resetDone.value = false
  credentialError.value = null
}

async function submitCredentialReset() {
  resetting.value = true
  credentialError.value = null
  try {
    await resetUserCredential(
      tenant.value,
      credentialsUser.value.id,
      temporaryPassword.value,
      resetKey,
    )
    resetDone.value = true
    if (!actionDraft.value.includes('UPDATE_PASSWORD')) {
      actionDraft.value.push('UPDATE_PASSWORD')
    }
    await load()
  } catch (error) {
    credentialError.value = error
  } finally {
    resetting.value = false
  }
}

async function submitRequiredActions() {
  savingActions.value = true
  credentialError.value = null
  try {
    await setUserRequiredActions(
      tenant.value,
      credentialsUser.value.id,
      [...actionDraft.value],
      actionsKey,
    )
    actionsKey = newIdempotencyKey()
    await load()
  } catch (error) {
    credentialError.value = error
  } finally {
    savingActions.value = false
  }
}

/*
 * Error wording lives in api.js so that this screen and the effective-access
 * screen (IAM-0214) cannot drift into telling an operator two different things
 * about the same failure.
 */

watch(() => props.detailUserId, () => { detailUser.value = null; changeDetailTab('profile'); load() })
watch(tenant, () => {
  search.value = ''
  load()
})
onMounted(load)
</script>

<template>
  <div v-if="!detailUserId" class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-semibold">{{ t('users.title') }}</h1>
    <div class="flex items-center gap-2">
      <label v-if="tenants.length > 1" for="tenant" class="text-sm text-content-muted">{{ t('common.tenant') }}</label>
      <select
        v-if="tenants.length > 1"
        id="tenant"
        v-model="tenant"
        class="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
      >
        <option v-for="key in tenants" :key="key" :value="key">{{ key }}</option>
      </select>
      <Button :disabled="!tenant || standby" @click="openCreate">{{ t('users.new') }}</Button>
    </div>
  </div>

  <p v-if="!tenant" class="text-sm text-content-muted">{{ t('common.noTenant') }}</p>

  <template v-else>
    <template v-if="detailUserId">
      <RouterLink to="/users" class="mb-3 inline-block text-sm text-content-muted underline">{{ t('users.title') }}</RouterLink>
      <div class="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div><h1 class="text-2xl font-semibold">{{ detailUser?.username || t('common.loading') }}</h1><p class="mt-1 text-sm text-content-muted">{{ detailUser?.email }}</p></div>
        <Badge v-if="detailUser" :tone="detailUser.enabled ? 'success' : 'neutral'">{{ t(detailUser.enabled ? 'state.enabled' : 'state.disabled') }}</Badge>
      </div>
      <div class="mb-5 flex flex-wrap gap-2" role="group" :aria-label="t('ux.userSections')">
        <Button v-for="[key, label] in userTabs" :key="key" :variant="detailTab === key ? 'default' : 'outline'" :aria-pressed="detailTab === key" @click="changeDetailTab(key)">{{ label }}</Button>
      </div>
      <Spinner v-if="loading" />
      <Alert v-if="listError" tone="danger">{{ messageFor(listError) }}<Button variant="outline" size="sm" @click="load">{{ t('action.tryAgain') }}</Button></Alert>
      <template v-if="detailUser && !loading">
        <Card v-if="detailTab === 'profile' && !editing" :title="t('ux.profile')">
          <dl class="grid gap-4 text-sm sm:grid-cols-2">
            <div><dt class="text-content-muted">{{ t('common.username') }}</dt><dd class="mt-1 font-medium">{{ detailUser.username }}</dd></div>
            <div><dt class="text-content-muted">{{ t('common.email') }}</dt><dd class="mt-1 break-all">{{ detailUser.email || '—' }}</dd></div>
            <div><dt class="text-content-muted">{{ t('users.firstName') }}</dt><dd class="mt-1">{{ detailUser.firstName || '—' }}</dd></div>
            <div><dt class="text-content-muted">{{ t('users.lastName') }}</dt><dd class="mt-1">{{ detailUser.lastName || '—' }}</dd></div>
          </dl>
          <Button class="mt-5" variant="outline" :disabled="standby" @click="openEdit(detailUser)">{{ t('action.edit') }}</Button>
          <details class="mt-5 border-t border-border-subtle pt-4"><summary class="cursor-pointer text-sm text-content-muted">{{ t('ux.accountActions') }}</summary><p class="my-3 text-sm text-content-muted">{{ t('ux.disableHelp') }}</p><Button variant="outline" :disabled="busyUser === detailUser.id" @click="toggleEnabled(detailUser)">{{ t(detailUser.enabled ? 'action.disable' : 'action.enable') }}</Button></details>
        </Card>
        <AccessView v-if="detailTab === 'access'" :session="session" embedded />
        <SessionsView v-if="detailTab === 'sessions'" :session="session" :user="detailUser" :tenant-key="tenant" embedded />
        <AccessTest v-if="detailTab === 'accessTest'" :tenant="tenant" :user="detailUser" />
      </template>
    </template>
    <template v-if="!detailUserId">
    <Card class="mb-5">
      <form class="flex flex-wrap items-end gap-3" @submit.prevent="load">
        <div class="flex-1">
          <label for="search" class="mb-1 block text-sm text-content-muted">{{ t('action.search') }}</label>
          <input
            id="search"
            v-model="search"
            type="search"
            :placeholder="t('users.searchPlaceholder')"
            class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
          />
        </div>
        <Button type="submit" variant="outline">{{ t('action.search') }}</Button>
      </form>
    </Card>

    <Alert v-if="listError" tone="danger" class="mb-5">
      {{ messageFor(listError) }}
      <span v-if="listError.correlationId" class="block text-xs opacity-80">
        {{ t('common.reference') }}: {{ listError.correlationId }}
      </span>
      <Button variant="outline" size="sm" class="mt-2" @click="load">{{ t('action.tryAgain') }}</Button>
    </Alert>

    <Alert v-if="created" tone="neutral" class="mb-5">
      {{ t('users.created', { user: created.username }) }}
    </Alert>

    <Card :title="t('users.count', { count: result?.count ?? 0, tenant })">
      <Spinner v-if="loading" />
      <p v-else-if="result && result.users.length === 0" class="text-sm text-content-muted">
        {{ t('users.noMatch') }}
      </p>
      <ul v-else-if="result" class="flex flex-col gap-2">
        <li
          v-for="user in result.users"
          :key="user.id"
          class="flex flex-wrap items-center justify-between gap-3 rounded-md border
                 border-border-subtle px-3 py-2"
        >
          <div class="min-w-0">
            <RouterLink :to="{ name: 'user-detail', params: { id: user.id }, query: { tenant } }" class="text-sm font-semibold text-brand hover:underline">{{ user.username }}</RouterLink>
            <p class="truncate text-xs text-content-muted">{{ user.email }}</p>
          </div>
          <div class="flex items-center gap-2">
            <Badge :tone="user.enabled ? 'success' : 'neutral'">
              {{ t(`state.${user.enabled ? 'enabled' : 'disabled'}`) }}
            </Badge>
            <Button
              as="a"
              variant="outline"
              size="sm"
              :href="`/ui/users/${user.id}/access?tenant=${encodeURIComponent(tenant)}`"
              @click.prevent="$router.push({
                name: 'user-access',
                params: { id: user.id },
                query: { tenant },
              })"
            >{{ t('users.access') }}</Button>
            <details class="relative">
              <summary class="cursor-pointer rounded-md border border-border-subtle px-3 py-1.5 text-xs">{{ t('ux.moreActions') }}</summary>
              <div class="absolute end-0 z-10 mt-2 flex min-w-40 flex-col gap-2 rounded-lg border border-border-subtle bg-surface-raised p-3 shadow-lg">
                <Button variant="outline" size="sm" :disabled="standby" @click="openEdit(user)">{{ t('action.edit') }}</Button>
                <Button variant="outline" size="sm" :disabled="standby" @click="openCredentials(user)">{{ t('users.credentials') }}</Button>
                <Button variant="outline" size="sm" :disabled="busyUser === user.id" @click="toggleEnabled(user)">{{ t(user.enabled ? 'action.disable' : 'action.enable') }}</Button>
              </div>
            </details>
          </div>
        </li>
      </ul>
    </Card>

    </template>

    <!-- create -->
    <Card v-if="showCreate" :title="t('users.new')" class="mt-5">
      <form class="grid gap-3 sm:grid-cols-2" @submit.prevent="submitCreate">
        <label class="text-sm">
          {{ t('common.username') }}
          <input
            v-model="draft.username"
            required
            class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5"
            :class="createError?.fields?.username ? 'border-danger' : ''"
          />
          <span v-if="createError?.fields?.username" class="text-xs text-danger">
            {{ createError.fields.username }}
          </span>
        </label>
        <label class="text-sm">
          {{ t('common.email') }}
          <input
            v-model="draft.email"
            type="email"
            required
            class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5"
            :class="createError?.fields?.email ? 'border-danger' : ''"
          />
          <span v-if="createError?.fields?.email" class="text-xs text-danger">
            {{ createError.fields.email }}
          </span>
        </label>
        <label class="text-sm">
          {{ t('users.firstName') }}
          <input
            v-model="draft.firstName"
            class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5"
          />
        </label>
        <label class="text-sm">
          {{ t('users.lastName') }}
          <input
            v-model="draft.lastName"
            class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5"
          />
        </label>

        <Alert v-if="createError" tone="danger" class="sm:col-span-2">
          {{ messageFor(createError) }}
          <span v-if="createError.correlationId" class="block text-xs opacity-80">
            {{ t('common.reference') }}: {{ createError.correlationId }}
          </span>
        </Alert>

        <div class="flex gap-3 sm:col-span-2">
          <Button type="submit" :disabled="creating || standby">
            {{ creating ? t('users.creating') : t('users.create') }}
          </Button>
          <Button type="button" variant="ghost" @click="showCreate = false">{{ t('action.cancel') }}</Button>
        </div>
      </form>
    </Card>

    <!-- edit -->
    <Card v-if="editing" :title="t('users.edit', { user: editing.username })" class="mt-5">
      <form class="grid gap-3 sm:grid-cols-2" @submit.prevent="submitEdit">
        <label class="text-sm">
          {{ t('common.email') }}
          <input
            v-model="editDraft.email"
            type="email"
            required
            class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5"
          />
        </label>
        <label class="text-sm">
          {{ t('users.firstName') }}
          <input
            v-model="editDraft.firstName"
            class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5"
          />
        </label>
        <label class="text-sm">
          {{ t('users.lastName') }}
          <input
            v-model="editDraft.lastName"
            class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5"
          />
        </label>

        <Alert v-if="editError" tone="danger" class="sm:col-span-2">
          {{ messageFor(editError) }}
        </Alert>

        <div class="flex gap-3 sm:col-span-2">
          <Button type="submit" :disabled="saving || standby">{{ saving ? t('users.saving') : t('action.save') }}</Button>
          <Button type="button" variant="ghost" @click="editing = null">{{ t('action.cancel') }}</Button>
        </div>
      </form>
    </Card>

    <Card
      v-if="credentialsUser"
      :title="t('users.credentialsFor', { user: credentialsUser.username })"
      class="mt-5"
    >
      <Alert v-if="credentialError" tone="danger" class="mb-4">
        {{ messageFor(credentialError) }}
      </Alert>

      <section class="mb-5 border-b border-border-subtle pb-5">
        <h2 class="mb-2 text-sm font-semibold">{{ t('users.temporaryPassword') }}</h2>
        <p class="mb-3 text-sm text-content-muted">
          {{ t('users.resetHelp') }}
        </p>
        <Alert v-if="resetDone" tone="neutral" class="mb-3">
          {{ t('users.copyPassword') }}
          <input
            :value="temporaryPassword"
            readonly
            :aria-label="t('users.temporaryPassword')"
            class="mt-2 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 font-mono"
            @focus="$event.target.select()"
          />
        </Alert>
        <Button v-if="!resetDone" :disabled="resetting || standby" @click="submitCredentialReset">
          {{ resetting ? t('users.resetting') : t('users.resetPassword') }}
        </Button>
      </section>

      <form @submit.prevent="submitRequiredActions">
        <fieldset>
          <legend class="mb-2 text-sm font-semibold">{{ t('users.requiredActions') }}</legend>
          <div class="grid gap-2 sm:grid-cols-2">
            <label v-for="[value, label] in availableActions" :key="value" class="text-sm">
              <input v-model="actionDraft" type="checkbox" :value="value" class="mr-2" />
              {{ label }}
            </label>
          </div>
        </fieldset>
        <div class="mt-4 flex gap-3">
          <Button type="submit" variant="outline" :disabled="savingActions || standby">
            {{ savingActions ? t('users.saving') : t('users.saveRequiredActions') }}
          </Button>
          <Button type="button" variant="ghost" @click="closeCredentials">{{ t('action.close') }}</Button>
        </div>
      </form>
    </Card>
  </template>
</template>
