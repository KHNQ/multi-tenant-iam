<script setup>
import { computed, ref, watch, onMounted } from 'vue'
import Alert from '@/components/ui/Alert.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import { useI18n } from '@/i18n.js'
import { useTenantPreference } from '@/tenantPreference.js'
import { searchUsers } from '@/users.js'
import {
  fetchSessions,
  messageFor,
  newIdempotencyKey,
  terminateAllSessions,
  terminateSession,
} from '@/sessions.js'

const props = defineProps({ session: { type: Object, required: true }, user: { type: Object, default: null }, tenantKey: { type: String, default: '' }, embedded: Boolean })
const { t, locale } = useI18n()
const tenants = computed(() => props.session.tenants ?? [])
const preferredTenant = useTenantPreference(tenants)
const tenant = computed({ get: () => props.tenantKey || preferredTenant.value, set: value => { preferredTenant.value = value } })
const search = ref('')
const users = ref([])
const selected = ref(null)
const sessions = ref([])
const loading = ref(false)
const error = ref(null)
const pending = ref(null)
const reason = ref('')
const saving = ref(false)
const searched = ref(false)
const now = ref(Date.now())

async function findUsers() {
  if (!tenant.value) return
  searched.value = true
  loading.value = true
  error.value = null
  selected.value = null
  sessions.value = []
  try {
    users.value = (await searchUsers(tenant.value, search.value.trim())).users ?? []
  } catch (failure) {
    error.value = failure
  } finally {
    loading.value = false
  }
}

async function selectUser(user) {
  pending.value = null
  selected.value = user
  now.value = Date.now()
  loading.value = true
  error.value = null
  try {
    sessions.value = (await fetchSessions(tenant.value, user.id)).sessions ?? []
  } catch (failure) {
    error.value = failure
  } finally {
    loading.value = false
  }
}

function askTerminate(sessionId) {
  pending.value = sessionId
  reason.value = ''
  error.value = null
}

async function confirmTermination() {
  if (!reason.value.trim()) return
  saving.value = true
  error.value = null
  try {
    if (pending.value === 'all') {
      await terminateAllSessions(tenant.value, selected.value.id, reason.value.trim(), newIdempotencyKey())
    } else {
      await terminateSession(tenant.value, selected.value.id, pending.value, reason.value.trim(), newIdempotencyKey())
    }
    pending.value = null
    reason.value = ''
    await selectUser(selected.value)
  } catch (failure) {
    error.value = failure
  } finally {
    saving.value = false
  }
}

function clientNames(clients) {
  return Object.entries(clients ?? {}).map(([id, name]) => name || id).join(', ') || t('sessions.noClients')
}
function relative(epoch) {
  if (!epoch) return t('sessions.unknown')
  const seconds = Math.min(0, Math.round((epoch - now.value) / 1000))
  const format = new Intl.RelativeTimeFormat(locale.value, { numeric: 'auto' })
  return Math.abs(seconds) < 60 ? format.format(seconds, 'second') : Math.abs(seconds) < 3600 ? format.format(Math.round(seconds / 60), 'minute') : Math.abs(seconds) < 86400 ? format.format(Math.round(seconds / 3600), 'hour') : format.format(Math.round(seconds / 86400), 'day')
}
onMounted(() => { if (props.user) selectUser(props.user) })
watch(() => props.user?.id, () => { if (props.user) selectUser(props.user) })
function when(epoch) {
  return epoch ? new Date(epoch).toLocaleString() : t('sessions.unknown')
}

watch(tenant, () => {
  users.value = []
  selected.value = null
  sessions.value = []
})
</script>

<template>
  <div v-if="!embedded" class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-semibold">{{ t('sessions.title') }}</h1>
    <select v-if="tenants.length > 1" v-model="tenant" :aria-label="t('common.tenant')"
      class="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm">
      <option v-for="key in tenants" :key="key" :value="key">{{ key }}</option>
    </select>
  </div>

  <p v-if="!tenant" class="text-sm text-content-muted">{{ t('common.noTenant') }}</p>
  <template v-else>
    <Card v-if="!embedded" class="mb-5">
      <form class="flex items-end gap-3" @submit.prevent="findUsers">
        <div class="flex-1">
          <label for="session-user-search" class="mb-1 block text-sm text-content-muted">{{ t('sessions.findUser') }}</label>
          <input id="session-user-search" v-model="search" type="search" :placeholder="t('users.searchPlaceholder')"
            class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm" />
        </div>
        <Button type="submit" variant="outline">{{ t('action.search') }}</Button>
      </form>
    </Card>

    <Alert v-if="error" class="mb-5">{{ messageFor(error) }}</Alert>
    <p v-if="!embedded && !selected && !loading" class="mb-5 text-sm text-content-muted">{{ t(searched && !users.length ? 'ux.noSessionUsers' : 'ux.sessionHelp') }}</p>
    <Spinner v-if="loading">{{ t('sessions.loading') }}</Spinner>

    <Card v-else-if="!selected && users.length" :title="t('sessions.selectUser')">
      <ul class="divide-y divide-border-subtle">
        <li v-for="user in users" :key="user.id" class="flex items-center justify-between py-3">
          <span><strong>{{ user.username }}</strong><span class="ml-2 text-sm text-content-muted">{{ user.email }}</span></span>
          <Button size="sm" variant="outline" @click="selectUser(user)">{{ t('sessions.view') }}</Button>
        </li>
      </ul>
    </Card>

    <template v-else-if="selected">
      <div class="mb-4 flex items-center justify-between gap-3">
        <div><h2 class="font-semibold">{{ selected.username }}</h2><p class="text-sm text-content-muted">{{ t('sessions.active', { count: sessions.length }) }}</p></div>
        <div class="flex gap-2">
          <Button v-if="!embedded" size="sm" variant="outline" @click="selected = null; sessions = []">{{ t('sessions.chooseAnother') }}</Button>
          <Button size="sm" variant="outline" :disabled="loading" @click="selectUser(selected)">{{ t('action.refresh') }}</Button>
          <Button v-if="sessions.length" size="sm" variant="outline" @click="askTerminate('all')">{{ t('sessions.terminateAll') }}</Button>
        </div>
      </div>
      <p v-if="!sessions.length" class="text-sm text-content-muted">{{ t('sessions.none') }}</p>
      <Card v-for="item in sessions" :key="item.id" class="mb-3" data-testid="session-row">
        <div class="flex items-start justify-between gap-4">
          <dl class="grid gap-x-5 gap-y-1 text-sm sm:grid-cols-2">
            <div><dt class="text-content-muted">{{ t('sessions.ip') }}</dt><dd>{{ item.ipAddress || t('sessions.unknown') }}</dd></div>
            <div><dt class="text-content-muted">{{ t('sessions.lastAccess') }}</dt><dd><time :title="when(item.lastAccess)">{{ relative(item.lastAccess) }}</time></dd></div>
            <div><dt class="text-content-muted">{{ t('sessions.started') }}</dt><dd>{{ when(item.started) }}</dd></div>
            <div><dt class="text-content-muted">{{ t('sessions.clients') }}</dt><dd>{{ clientNames(item.clients) }}</dd></div>
          </dl>
          <Button size="sm" variant="outline" @click="askTerminate(item.id)">{{ t('sessions.terminate') }}</Button>
        </div>
      </Card>
    </template>

    <Card v-if="pending" class="mt-5" :title="t('sessions.confirmTitle')">
      <form @submit.prevent="confirmTermination">
        <p class="mb-3 text-sm">{{ t(pending === 'all' ? 'sessions.allWillEnd' : 'sessions.oneWillEnd') }} {{ t('ux.terminationScope', { user: selected.username, tenant }) }}</p>
        <label for="termination-reason" class="mb-1 block text-sm">{{ t('common.reason') }}</label>
        <textarea id="termination-reason" v-model="reason" required maxlength="500" rows="3"
          class="w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm" />
        <div class="mt-3 flex gap-2">
          <Button type="submit" variant="danger" :disabled="saving || !reason.trim()">{{ t('sessions.confirm') }}</Button>
          <Button type="button" variant="outline" @click="pending = null">{{ t('action.cancel') }}</Button>
        </div>
      </form>
    </Card>
  </template>
</template>
