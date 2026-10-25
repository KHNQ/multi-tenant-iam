<script setup>
/*
 * The access test: would this user get into an application, and with which
 * claims? The answer is the server's - it evaluates the sign-in checks and the
 * token contract from current data - and nothing is issued, so the test is
 * safe to run at any time, in standby too.
 *
 * Claims are shown exactly as the server computed them, because the question
 * this answers in practice is "why did the application refuse this person",
 * and the answer is usually one claim.
 */
import { onMounted, ref, watch } from 'vue'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import { messageFor } from '@/api.js'
import { fetchClients } from '@/clients.js'
import { newIdempotencyKey, testAccess } from '@/users.js'
import { useI18n } from '@/i18n.js'

const props = defineProps({
  tenant: { type: String, required: true },
  user: { type: Object, required: true },
})
const { t } = useI18n()

const clients = ref([])
const clientId = ref('')
const scope = ref('openid profile email')
const result = ref(null)
const running = ref(false)
const error = ref(null)

async function loadClients() {
  error.value = null
  try {
    const listing = await fetchClients(props.tenant)
    clients.value = (listing.clients ?? []).filter((client) => !client.bearerOnly)
    if (!clients.value.some((client) => client.clientId === clientId.value)) clientId.value = ''
  } catch (failure) {
    error.value = failure
  }
}

async function run() {
  running.value = true
  error.value = null
  result.value = null
  try {
    result.value = await testAccess(props.tenant, props.user.id, { clientId: clientId.value, scope: scope.value }, newIdempotencyKey())
  } catch (failure) {
    error.value = failure
  } finally {
    running.value = false
  }
}

const pretty = (value) => JSON.stringify(value, null, 2)

watch(() => [props.tenant, props.user?.id], () => { result.value = null; loadClients() })
onMounted(loadClients)
</script>

<template>
  <Card :title="t('accessTest.title')">
    <p class="mb-4 text-sm text-content-muted">{{ t('accessTest.help') }}</p>
    <form class="mb-4 grid gap-3 sm:grid-cols-[minmax(0,1fr)_minmax(0,1fr)_auto] sm:items-end" @submit.prevent="run">
      <label class="text-sm">
        {{ t('accessTest.client') }}
        <select v-model="clientId" required class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm">
          <option value="" disabled>{{ t('accessTest.chooseClient') }}</option>
          <option v-for="client in clients" :key="client.clientId" :value="client.clientId">{{ client.clientId }}</option>
        </select>
      </label>
      <label class="text-sm">
        {{ t('accessTest.scope') }}
        <input v-model="scope" dir="ltr" class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 font-mono text-sm" />
      </label>
      <Button type="submit" :disabled="running || !clientId">{{ running ? t('accessTest.running') : t('accessTest.run') }}</Button>
    </form>

    <Alert v-if="error" tone="danger" class="mb-4">
      {{ messageFor(error) }}
      <span v-if="error.correlationId" class="block text-xs opacity-80">{{ t('common.reference') }}: {{ error.correlationId }}</span>
    </Alert>
    <Spinner v-if="running" />

    <template v-if="result">
      <Alert :tone="result.allowed ? 'neutral' : 'danger'" class="mb-4" data-testid="access-test-verdict">
        {{ t(result.allowed ? 'accessTest.allowed' : 'accessTest.refused', { client: result.clientId }) }}
      </Alert>
      <h3 class="mb-2 text-sm font-semibold">{{ t('accessTest.checks') }}</h3>
      <ul class="mb-5 flex flex-col gap-2">
        <li v-for="check in result.checks" :key="check.key" class="flex items-center justify-between gap-3 rounded-md border border-border-subtle px-3 py-2 text-sm" data-testid="access-test-check">
          <span>{{ t(`accessTest.check.${check.key}`) }}</span>
          <Badge :tone="check.ok ? 'success' : 'danger'">{{ t(check.ok ? 'accessTest.pass' : 'accessTest.fail') }}</Badge>
        </li>
      </ul>
      <details open class="mb-3 rounded-lg border border-border-subtle p-4">
        <summary class="cursor-pointer text-sm font-medium">{{ t('accessTest.accessToken') }}</summary>
        <pre dir="ltr" class="mt-3 overflow-x-auto text-xs" data-testid="access-test-access">{{ pretty(result.accessToken) }}</pre>
      </details>
      <details class="mb-3 rounded-lg border border-border-subtle p-4">
        <summary class="cursor-pointer text-sm font-medium">{{ t('accessTest.idToken') }}</summary>
        <pre v-if="result.idToken" dir="ltr" class="mt-3 overflow-x-auto text-xs">{{ pretty(result.idToken) }}</pre>
        <p v-else class="mt-3 text-sm text-content-muted">{{ t('accessTest.noIdToken') }}</p>
      </details>
      <details class="rounded-lg border border-border-subtle p-4">
        <summary class="cursor-pointer text-sm font-medium">{{ t('accessTest.userinfo') }}</summary>
        <pre dir="ltr" class="mt-3 overflow-x-auto text-xs">{{ pretty(result.userinfo) }}</pre>
      </details>
    </template>
  </Card>
</template>
