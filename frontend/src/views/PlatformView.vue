<script setup>
import { computed, onMounted, ref } from 'vue'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import InfoHelp from '@/components/InfoHelp.vue'
import IdpSettings from '@/components/platform/IdpSettings.vue'
import { Building2, KeyRound, RefreshCw } from 'lucide-vue-next'
import { messageFor, newIdempotencyKey } from '@/api.js'
import { standby } from '@/standby.js'
import { useI18n } from '@/i18n.js'
import {
  createTenantRequest, decideTenant, fetchTenants, reconcileTenant, retryTenantProvisioning,
} from '@/tenants.js'

const result = ref(null)
const { t } = useI18n()

// Tenants, then the identity provider's own settings: synchronisation and signing keys.
const section = ref('tenants')
const sections = computed(() => [
  { id: 'tenants', label: t('platform.tab.tenants'), icon: Building2 },
  { id: 'sync', label: t('platform.tab.sync'), icon: RefreshCw },
  { id: 'keys', label: t('platform.tab.keys'), icon: KeyRound },
])
const loading = ref(false)
const error = ref(null)
const search = ref('')
const status = ref('')
const showCreate = ref(false)
const saving = ref(false)
const draft = ref({ tenantKey: '', displayName: '', realmName: '' })
const deciding = ref(null)
const reason = ref('')
let mutationKey = newIdempotencyKey()

const tenants = computed(() => result.value?.tenants ?? [])

async function load() {
  loading.value = true
  error.value = null
  try {
    result.value = await fetchTenants(search.value.trim(), status.value)
  } catch (failure) {
    error.value = failure
  } finally {
    loading.value = false
  }
}

function openCreate() {
  draft.value = { tenantKey: '', displayName: '', realmName: '' }
  mutationKey = newIdempotencyKey()
  showCreate.value = true
}

function syncRealm() {
  if (!draft.value.realmName) draft.value.realmName = draft.value.tenantKey
}

async function createRequest() {
  saving.value = true
  error.value = null
  try {
    await createTenantRequest(draft.value, mutationKey)
    showCreate.value = false
    await load()
  } catch (failure) {
    error.value = failure
  } finally {
    saving.value = false
  }
}

function askDecision(tenant, decision) {
  deciding.value = { tenant, decision }
  reason.value = ''
  mutationKey = newIdempotencyKey()
}

async function confirmDecision() {
  saving.value = true
  error.value = null
  try {
    await decideTenant(
      deciding.value.tenant.tenantKey,
      deciding.value.decision,
      reason.value.trim(),
      mutationKey,
    )
    deciding.value = null
    await load()
  } catch (failure) {
    error.value = failure
  } finally {
    saving.value = false
  }
}

async function runProvisioningAction(tenant, action) {
  saving.value = true
  error.value = null
  try {
    const key = newIdempotencyKey()
    if (action === 'retry') await retryTenantProvisioning(tenant.tenantKey, key)
    else await reconcileTenant(tenant.tenantKey, key)
    await load()
  } catch (failure) {
    error.value = failure
  } finally {
    saving.value = false
  }
}

function statusTone(value) {
  if (value === 'APPROVED') return 'success'
  if (value === 'REJECTED') return 'danger'
  return 'neutral'
}

function provisioningTone(value) {
  if (value === 'READY') return 'success'
  if (value === 'FAILED') return 'danger'
  return 'neutral'
}

function localizedDecisionReason(value) {
  return value?.trim().toLowerCase() === 'approved for pilot'
    ? t('platform.reason.approvedPilot')
    : value
}

function localizedDriftDetails(value) {
  return value?.trim().toLowerCase() === 'realm_missing'
    ? t('platform.drift.realmMissing')
    : value
}

onMounted(load)
</script>

<template>
  <!-- The same tab bar as application access (its styles are scoped to .application-access). -->
  <div class="application-access mb-5">
    <div class="access-tabs" role="tablist" :aria-label="t('platform.sections')">
      <button v-for="item in sections" :key="item.id" :id="`platform-tab-${item.id}`" type="button" role="tab"
        :aria-selected="section === item.id" @click="section = item.id">
        <component :is="item.icon" :size="17" aria-hidden="true" />{{ item.label }}
      </button>
    </div>
  </div>

  <IdpSettings v-if="section !== 'tenants'" :section="section" />

  <template v-else>
  <div class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <div>
      <h1 class="flex items-center gap-1 text-2xl font-semibold">{{ t('platform.title') }} <InfoHelp topic="tenant" /></h1>
      <p class="mt-1 text-sm text-content-muted">
        {{ t('platform.subtitle') }} <InfoHelp topic="provisioning" />
      </p>
    </div>
    <Button v-if="!showCreate" :disabled="standby" @click="openCreate">{{ t('platform.requestTenant') }}</Button>
  </div>

  <Alert v-if="error" tone="danger" class="mb-5" data-testid="tenant-error">
    {{ messageFor(error) }}
    <span v-if="error.correlationId" class="block text-xs opacity-80">
      {{ t('common.reference') }}: {{ error.correlationId }}
    </span>
  </Alert>

  <Card v-if="showCreate" class="mb-5" :title="t('platform.requestTenant')">
    <form @submit.prevent="createRequest">
      <div class="mb-4">
        <label for="tenantKey" class="mb-1 block text-sm font-medium">{{ t('platform.tenantKey') }}</label>
        <input id="tenantKey" v-model="draft.tenantKey" required maxlength="63"
          class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
          @blur="syncRealm" />
        <p class="mt-1 text-xs text-content-muted">{{ t('platform.keyHelp') }}</p>
      </div>
      <div class="mb-4">
        <label for="tenantName" class="mb-1 block text-sm font-medium">{{ t('platform.displayName') }}</label>
        <input id="tenantName" v-model="draft.displayName" required maxlength="120"
          class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm" />
      </div>
      <div class="mb-4">
        <label for="realmName" class="mb-1 block text-sm font-medium">{{ t('platform.proposedRealm') }}</label>
        <input id="realmName" v-model="draft.realmName" required maxlength="63"
          class="w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm" />
        <p class="mt-1 text-xs text-content-muted">{{ t('platform.realmHelp') }}</p>
      </div>
      <div class="flex gap-3">
        <Button type="submit" :disabled="saving || standby">{{ saving ? t('platform.saving') : t('platform.submitRequest') }}</Button>
        <Button type="button" variant="ghost" :disabled="saving" @click="showCreate = false">{{ t('action.cancel') }}</Button>
      </div>
    </form>
  </Card>

  <Card v-if="deciding" class="mb-5" :title="t('platform.decisionTitle', { action: t(deciding.decision === 'approve' ? 'action.approve' : 'action.reject'), tenant: deciding.tenant.tenantKey })">
    <Alert v-if="deciding.decision === 'approve'" class="mb-4">
      {{ t('platform.authoritativeWarning') }}
    </Alert>
    <label for="decisionReason" class="mb-1 block text-sm font-medium">
      {{ t('common.reason') }} <span v-if="deciding.decision === 'reject'">({{ t('platform.required') }})</span>
    </label>
    <textarea id="decisionReason" v-model="reason" rows="3" maxlength="500"
      class="mb-4 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"></textarea>
    <div class="flex gap-3">
      <Button :variant="deciding.decision === 'reject' ? 'danger' : 'default'"
        :disabled="saving || standby || (deciding.decision === 'reject' && !reason.trim())"
        data-testid="confirm-decision" @click="confirmDecision">
        {{ deciding.decision === 'approve' ? t('platform.approveMapping') : t('platform.rejectRequest') }}
      </Button>
      <Button variant="ghost" :disabled="saving" @click="deciding = null">{{ t('action.cancel') }}</Button>
    </div>
  </Card>

  <Card :title="t('platform.count', { count: result?.total ?? 0 })">
    <div class="mb-4 flex flex-wrap gap-2">
      <label for="tenant-search" class="sr-only">{{ t('platform.searchTenants') }}</label>
      <input id="tenant-search" v-model="search" type="search" :placeholder="t('platform.searchPlaceholder')"
        class="min-w-56 flex-1 rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
        @keyup.enter="load" />
      <label for="tenant-status" class="sr-only">{{ t('common.status') }}</label>
      <select id="tenant-status" v-model="status"
        class="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm" @change="load">
        <option value="">{{ t('platform.allStatuses') }}</option>
        <option value="PENDING">{{ t('state.pending') }}</option>
        <option value="APPROVED">{{ t('state.approved') }}</option>
        <option value="REJECTED">{{ t('state.rejected') }}</option>
      </select>
      <Button variant="outline" @click="load">{{ t('action.search') }}</Button>
    </div>

    <Spinner v-if="loading" />
    <p v-else-if="!tenants.length" class="text-sm text-content-muted">{{ t('platform.noMatch') }}</p>
    <ul v-else class="flex flex-col divide-y divide-border-subtle">
      <li v-for="tenant in tenants" :key="tenant.tenantKey" data-testid="tenant-row"
        class="flex flex-wrap items-center gap-3 py-3">
        <div class="min-w-0 flex-1">
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-medium">{{ tenant.tenantKey }}</span>
            <Badge :tone="statusTone(tenant.status)" class="h-7 py-0">{{ t(`state.${tenant.status.toLowerCase()}`) }}</Badge>
            <Badge :tone="provisioningTone(tenant.provisioningStatus)" class="h-7 gap-1 py-0">
              {{ t(`state.${tenant.provisioningStatus.toLowerCase()}`) }}
              <InfoHelp topic="provisioning" context="badge" />
            </Badge>
            <Badge v-if="tenant.status === 'APPROVED'" :tone="tenant.driftStatus === 'IN_SYNC' ? 'success' : 'neutral'" class="h-7 gap-1 py-0">
              {{ t(`state.${(tenant.driftStatus || 'UNKNOWN').toLowerCase()}`) }}
              <InfoHelp :topic="tenant.driftStatus === 'IN_SYNC' ? 'inSync' : 'drift'" context="badge" />
            </Badge>
          </div>
          <p class="mt-1 text-sm text-content-muted">{{ tenant.displayName }} · {{ t('common.realm') }} <code>{{ tenant.realmName }}</code></p>
          <p class="mt-1 text-xs text-content-muted">{{ t('platform.requestedBy', { user: tenant.requestedBy }) }}</p>
          <p v-if="tenant.decisionReason" class="mt-1 text-xs text-content-muted">{{ t('platform.decision', { reason: localizedDecisionReason(tenant.decisionReason) }) }} <InfoHelp v-if="tenant.decisionReason.toLowerCase().includes('pilot')" topic="approvedPilot" /></p>
          <p v-if="tenant.provisioningError" class="mt-1 text-xs text-danger">
            {{ t('platform.provisioningFailed', { reason: tenant.provisioningError }) }}
          </p>
          <p v-if="tenant.driftDetails" class="mt-1 text-xs text-content-muted">
            {{ t('platform.drift', { details: localizedDriftDetails(tenant.driftDetails) }) }} <InfoHelp topic="drift" />
          </p>
        </div>
        <div v-if="tenant.status === 'PENDING'" class="flex gap-2">
          <Button size="sm" variant="outline" :disabled="standby" @click="askDecision(tenant, 'approve')">{{ t('action.approve') }}</Button>
          <Button size="sm" variant="danger" :disabled="standby" @click="askDecision(tenant, 'reject')">{{ t('action.reject') }}</Button>
        </div>
        <div v-else-if="tenant.status === 'APPROVED'" class="flex gap-2">
          <Button v-if="tenant.provisioningStatus === 'FAILED'" size="sm" variant="outline"
            :disabled="saving || standby" @click="runProvisioningAction(tenant, 'retry')">{{ t('action.retry') }}</Button>
          <span class="inline-flex items-center gap-1">
            <Button size="sm" variant="outline" :disabled="saving"
              @click="runProvisioningAction(tenant, 'reconcile')">{{ t('platform.checkDrift') }}</Button>
            <InfoHelp topic="drift" />
          </span>
        </div>
      </li>
    </ul>
  </Card>
  </template>
</template>
