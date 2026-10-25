<script setup>
/*
 * Permissions MapDashboard declares in its code that Keycloak does not hold yet.
 * The list is rebuilt from the deployed catalogue on every load, so only real
 * declarations can be approved. Approving records a decision; a separate worker,
 * the only holder of the Keycloak credential that can create permissions,
 * performs the import. While anything is queued the panel polls for the result.
 */
import { computed, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { Check, X } from 'lucide-vue-next'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import { messageFor, newIdempotencyKey } from '@/api.js'
import { useI18n } from '@/i18n.js'
import { CLIENT_ID, decidePermissionImport, fetchPermissionImports } from '@/applications.js'

const props = defineProps({ tenant: { type: String, required: true } })
const emit = defineEmits(['imported', 'count'])
const { t } = useI18n()

const POLL_MS = 5000
const POLL_LIMIT = 24
const queue = ref(null)
const loading = ref(false)
const error = ref(null)
const busyKey = ref('')
const rejecting = ref('')
const reason = ref('')
// Bulk approval sends the same per-key decision as the single button, one at a time,
// so each approval keeps its own fingerprint check and audit entry.
const selected = ref([])
const confirming = ref(false)
const bulk = ref(null)
let timer = null
let polls = 0

const waiting = computed(() => (queue.value?.items ?? [])
  .filter(item => item.status === 'approved' || item.status === 'importing'))
const actionable = computed(() => (queue.value?.items ?? [])
  .filter(item => item.status !== 'approved' && item.status !== 'importing').length)
const approverRole = `approve-permissions:${CLIENT_ID}`
const selectable = computed(() => (queue.value?.items ?? []).filter(canApprove))
const selectedItems = computed(() => selectable.value.filter(item => selected.value.includes(item.key)))
const allSelected = computed(() => selectable.value.length > 0
  && selectable.value.every(item => selected.value.includes(item.key)))
const running = computed(() => Boolean(bulk.value) && bulk.value.done < bulk.value.total)

const tones = { pending: 'brand', approved: 'neutral', importing: 'neutral', failed: 'danger', rejected: 'neutral' }

async function load({ quiet = false } = {}) {
  if (!quiet) loading.value = true
  error.value = null
  const before = new Set(waiting.value.map(item => item.key))
  try {
    queue.value = await fetchPermissionImports(props.tenant)
    const still = new Set(selectable.value.map(item => item.key))
    selected.value = selected.value.filter(key => still.has(key))
    // An approved item that left the queue was imported: Keycloak now matches it.
    const remaining = new Set((queue.value.items ?? []).map(item => item.key))
    if ([...before].some(key => !remaining.has(key))) emit('imported')
  } catch (failure) {
    error.value = failure
  } finally {
    loading.value = false
    schedule()
  }
}

function schedule() {
  clearTimeout(timer)
  timer = null
  if (!waiting.value.length) { polls = 0; return }
  if (polls++ >= POLL_LIMIT) return
  timer = setTimeout(() => load({ quiet: true }), POLL_MS)
}

async function decide(item, decision) {
  busyKey.value = item.key
  error.value = null
  try {
    await decidePermissionImport(props.tenant, {
      key: item.key, fingerprint: item.fingerprint, decision,
      reason: decision === 'reject' ? reason.value.trim() || null : null,
    }, newIdempotencyKey())
    rejecting.value = ''
    reason.value = ''
    polls = 0
    await load({ quiet: true })
  } catch (failure) {
    error.value = failure
    // A stale fingerprint means the declaration changed; show the current one.
    if (failure.code === 'stale_preview' || failure.code === 'conflict') await load({ quiet: true })
  } finally {
    busyKey.value = ''
  }
}

function toggleAll(on) {
  selected.value = on ? selectable.value.map(item => item.key) : []
}

async function approveSelected() {
  const items = [...selectedItems.value]
  if (!items.length) return
  error.value = null
  bulk.value = { done: 0, total: items.length, failed: [] }
  for (const item of items) {
    try {
      await decidePermissionImport(props.tenant, {
        key: item.key, fingerprint: item.fingerprint, decision: 'approve', reason: null,
      }, newIdempotencyKey())
    } catch (failure) {
      bulk.value.failed.push({ key: item.key, message: messageFor(failure) })
    }
    bulk.value.done++
  }
  confirming.value = false
  selected.value = []
  polls = 0
  await load({ quiet: true })
}

function canApprove(item) {
  return queue.value?.canApprove && item.importable
    && ['pending', 'failed', 'rejected'].includes(item.status)
}

function canReject(item) {
  return queue.value?.canApprove && ['pending', 'failed', 'approved'].includes(item.status)
}

watch(actionable, (count) => emit('count', count))
watch(() => props.tenant, () => load())
onMounted(() => load())
onBeforeUnmount(() => clearTimeout(timer))
defineExpose({ load })
</script>

<template>
  <Card :title="t('imports.title')">
    <p class="mb-4 text-sm text-content-muted">{{ t('imports.help') }}</p>
    <Spinner v-if="loading">{{ t('common.loading') }}</Spinner>
    <Alert v-if="error" class="mb-4" tone="danger">{{ messageFor(error) }}</Alert>
    <div v-if="queue" class="space-y-4 text-sm" data-test="permission-imports" aria-live="polite">
      <Alert v-if="!queue.canApprove && queue.items.length" tone="neutral">
        {{ t('imports.readOnly', { role: approverRole }) }}
      </Alert>
      <Alert v-if="!queue.items.length" tone="neutral">{{ t('applications.catalogueInSync') }}</Alert>

      <div v-if="queue.canApprove && selectable.length" class="flex flex-wrap items-center gap-3" data-test="bulk-approve">
        <label class="flex items-center gap-2">
          <input type="checkbox" :checked="allSelected" :disabled="running" @change="toggleAll($event.target.checked)" />
          {{ t('imports.selectAll', { count: selectable.length }) }}
        </label>
        <Button size="sm" :disabled="!selected.length || running" @click="confirming = true">
          <Check :size="15" aria-hidden="true" />{{ t('imports.approveSelected', { count: selected.length }) }}
        </Button>
      </div>

      <div v-if="confirming" class="space-y-3 rounded-lg border border-border-subtle p-4" data-test="bulk-confirm">
        <p class="font-medium">{{ t('imports.bulkConfirm', { count: selectedItems.length }) }}</p>
        <ul class="max-h-64 space-y-1 overflow-y-auto text-content-muted">
          <li v-for="item in selectedItems" :key="item.key">
            <code dir="ltr" class="font-mono text-content">{{ item.key }}</code>
            — {{ item.category }} · {{ item.description }}
          </li>
        </ul>
        <p class="text-xs text-content-muted">{{ t('imports.whatApproveDoes') }}</p>
        <div class="flex flex-wrap gap-2">
          <Button size="sm" :disabled="running || !selectedItems.length" @click="approveSelected">
            {{ t('imports.bulkConfirmAction', { count: selectedItems.length }) }}
          </Button>
          <Button size="sm" variant="outline" :disabled="running" @click="confirming = false">{{ t('action.cancel') }}</Button>
        </div>
      </div>

      <Alert v-if="bulk" :tone="bulk.failed.length ? 'danger' : 'neutral'" data-test="bulk-result">
        <template v-if="running">{{ t('imports.bulkProgress', { done: bulk.done, total: bulk.total }) }}</template>
        <template v-else>
          {{ t('imports.bulkDone', { approved: bulk.total - bulk.failed.length, failed: bulk.failed.length }) }}
          <ul v-if="bulk.failed.length" class="mt-1">
            <li v-for="row in bulk.failed" :key="row.key"><code dir="ltr" class="font-mono">{{ row.key }}</code>: {{ row.message }}</li>
          </ul>
        </template>
      </Alert>

      <ul v-if="queue.items.length" class="divide-y divide-border-subtle rounded-lg border border-border-subtle">
        <li v-for="item in queue.items" :key="item.key" class="space-y-2 p-4" :data-test="`import-${item.key}`">
          <div class="flex flex-wrap items-center gap-2">
            <input v-if="canApprove(item)" v-model="selected" type="checkbox" :value="item.key" :disabled="running"
              :aria-label="t('imports.select', { key: item.key })" />
            <code dir="ltr" class="permission-key font-mono">{{ item.key }}</code>
            <Badge>{{ t(`imports.kind.${item.kind}`) }}</Badge>
            <Badge :tone="tones[item.status]">{{ t(`imports.status.${item.status}`) }}</Badge>
          </div>
          <p class="text-content-muted">
            <span class="font-medium">{{ item.category || t('applications.uncategorized') }}</span>
            · {{ item.description || t('applications.none') }}
          </p>
          <dl v-if="item.kind === 'update'" class="grid gap-2 text-content-muted">
            <div v-if="item.keycloakCategory !== item.category" class="comparison-row">
              <dt class="font-medium">{{ t('applications.category') }}</dt>
              <dd>{{ t('applications.registeredValue') }}: {{ item.keycloakCategory || t('applications.uncategorized') }}</dd>
              <dd class="text-content">{{ t('applications.declaredValue') }}: {{ item.category || t('applications.uncategorized') }}</dd>
            </div>
            <div v-if="item.keycloakDescription !== item.description" class="comparison-row">
              <dt class="font-medium">{{ t('applications.description') }}</dt>
              <dd>{{ t('applications.registeredValue') }}: {{ item.keycloakDescription || t('applications.none') }}</dd>
              <dd class="text-content">{{ t('applications.declaredValue') }}: {{ item.description || t('applications.none') }}</dd>
            </div>
          </dl>
          <p v-if="item.decidedBy" class="text-xs text-content-muted">
            {{ t('imports.decidedBy', { name: item.decidedBy }) }}<template v-if="item.reason"> — {{ item.reason }}</template>
          </p>
          <Alert v-if="item.status === 'failed'" tone="danger">{{ t(`imports.error.${item.lastError}`, t('imports.error.default')) }}</Alert>
          <p v-if="!item.importable" class="text-content-muted">{{ t('imports.notImportable') }}</p>

          <div v-if="canApprove(item) || canReject(item)" class="flex flex-wrap items-center gap-2 pt-1">
            <Button v-if="canApprove(item)" size="sm" :disabled="busyKey === item.key || running" @click="decide(item, 'approve')">
              <Check :size="15" aria-hidden="true" />{{ t('imports.approve') }}
            </Button>
            <Button v-if="canReject(item) && rejecting !== item.key" size="sm" variant="outline"
              :disabled="busyKey === item.key" @click="rejecting = item.key; reason = ''">
              <X :size="15" aria-hidden="true" />{{ t('action.reject') }}
            </Button>
          </div>
          <form v-if="rejecting === item.key" class="flex flex-wrap items-center gap-2" @submit.prevent="decide(item, 'reject')">
            <input v-model="reason" name="reject-reason" maxlength="500" :aria-label="t('imports.reason')" :placeholder="t('imports.reason')"
              class="min-w-0 flex-1 rounded border border-border-subtle bg-surface px-3 py-1.5" />
            <Button type="submit" size="sm" variant="danger" :disabled="busyKey === item.key">{{ t('imports.confirmReject') }}</Button>
            <Button type="button" size="sm" variant="outline" @click="rejecting = ''">{{ t('action.cancel') }}</Button>
          </form>
        </li>
      </ul>
      <p v-if="queue.canApprove && queue.items.length" class="text-xs text-content-muted">{{ t('imports.whatApproveDoes') }}</p>

      <div v-if="queue.notDeclaredByApplication.length">
        <h3 class="mb-1 font-medium">{{ t('applications.catalogueUndeclared') }}</h3>
        <p dir="ltr" class="font-mono">{{ queue.notDeclaredByApplication.join(', ') }}</p>
        <p class="text-content-muted">{{ t('applications.catalogueUndeclaredHelp') }}</p>
      </div>

      <details v-if="queue.history.length" class="rounded-lg border border-border-subtle p-4">
        <summary class="cursor-pointer font-medium">{{ t('imports.history') }}</summary>
        <ul class="mt-2 space-y-1">
          <li v-for="(row, index) in queue.history" :key="index" class="flex flex-wrap gap-2 text-content-muted">
            <code dir="ltr" class="font-mono text-content">{{ row.key }}</code>
            <span>{{ t(`imports.status.${row.status}`) }}</span>
            <span>{{ t('imports.decidedBy', { name: row.decidedBy }) }}</span>
            <span v-if="row.lastError">({{ t(`imports.error.${row.lastError}`, t('imports.error.default')) }})</span>
          </li>
        </ul>
      </details>
    </div>
  </Card>
</template>
