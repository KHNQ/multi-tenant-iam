<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { ShieldCheck, Users, Monitor } from 'lucide-vue-next'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import DescriptionList from '@/components/ui/DescriptionList.vue'
import Spinner from '@/components/ui/Spinner.vue'
import InfoHelp from '@/components/InfoHelp.vue'
import { fetchStatus, fetchTenantUsers } from '@/session.js'
import { useI18n } from '@/i18n.js'
import { useTenantPreference } from '@/tenantPreference.js'
import { embedded } from '@/embedded.js'

const props = defineProps({ session: { type: Object, required: true } })
const { t, locale } = useI18n()

/*
 * Tenant context. The list comes from /api/me, which derives it from the token -
 * a tenant admin is offered only their own tenant, a platform admin the whole
 * catalogue. Changing this selector changes which tenant's data is *requested*;
 * it grants nothing, because every request is re-checked by the server.
 */
const tenants = computed(() => props.session.tenants ?? [])
const tenant = useTenantPreference(tenants)

const users = ref(null)
const usersError = ref(null)
const loadingUsers = ref(false)

async function loadTenantData() {
  if (!tenant.value) {
    return
  }
  loadingUsers.value = true
  usersError.value = null
  users.value = null
  try {
    users.value = await fetchTenantUsers(tenant.value)
  } catch (error) {
    // Deliberately not error.message: it can carry a status and a path. The
    // operator gets a recovery action and an id they can quote to support.
    usersError.value = {
      denied: error.status === 403,
      correlationId: error.correlationId,
    }
  } finally {
    loadingUsers.value = false
  }
}

const status = ref(null)
const loadingStatus = ref(true)

async function loadStatus() {
  loadingStatus.value = true
  try {
    status.value = await fetchStatus()
  } finally {
    loadingStatus.value = false
  }
}

const degraded = computed(() => status.value && status.value.overall !== 'operational')

/** Standby or primary, and when the primary system's data last arrived. */
const lastSync = computed(() => {
  const value = status.value?.lastSuccessfulSync
  if (value) return new Date(value).toLocaleString(locale.value)
  return t(status.value?.mode === 'primary' ? 'idp.syncOff' : 'idp.never')
})

const stateTone = {
  operational: 'success',
  degraded: 'warning',
  unavailable: 'danger',
  not_configured: 'neutral',
}

/** Quick actions are filtered by entitlement, matching the navigation. */
const quickActions = computed(() =>
  [
    { to: '/users', label: t('dashboard.manageUsers'), icon: Users, requires: 'tenantAdmin' },
    { to: '/applications/mapdashboard', label: t('ux.manageApplicationAccess'), icon: ShieldCheck, requires: 'tenantAdmin' },
    { to: '/sessions', label: t('sessions.title'), icon: Monitor, requires: 'tenantAdmin' },
    { to: '/platform', label: t('dashboard.platformSettings'), icon: ShieldCheck, requires: 'platformAdmin' },
  ].filter((action) => props.session.permissions[action.requires]),
)

const identity = computed(() => [
  { label: t('common.username'), value: props.session.username },
  { label: t('common.email'), value: props.session.email },
  { label: t('common.scope'), value: props.session.crossTenant ? t('common.allTenants') : t('common.singleTenant') },
])

function stateLabel(state) { return t(`state.${state}`) }

watch(tenant, loadTenantData)
onMounted(() => {
  loadStatus()
  loadTenantData()
})
</script>

<template>
  <div class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-semibold">{{ t('dashboard.title') }}</h1>

    <!-- Keep tenant switching available when there is a choice. -->
    <div v-if="tenants.length && (!embedded.enabled || tenants.length > 1)" class="flex items-center gap-2">
      <label for="tenant" class="text-sm text-content-muted">{{ t('common.tenant') }}</label>
      <select
        id="tenant"
        v-model="tenant"
        class="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
      >
        <option v-for="key in tenants" :key="key" :value="key">{{ key }}</option>
      </select>
    </div>
  </div>

  <Alert v-if="degraded" tone="warning" class="mb-5">
    <strong>{{ t('dashboard.dependenciesWarning') }}</strong>
    {{ t('dashboard.dependenciesDetail') }}
  </Alert>

  <div class="grid gap-5 lg:grid-cols-2">
    <Card v-if="quickActions.length" :title="t('dashboard.quickActions')" class="lg:col-span-2">
      <div class="flex flex-wrap gap-3">
        <RouterLink class="inline-flex items-center gap-2 rounded-md border border-border-subtle px-4 py-3 text-sm font-medium hover:bg-surface" v-for="action in quickActions" :key="action.to" :to="action.to">

            <component :is="action.icon" class="size-4" aria-hidden="true" />
            {{ action.label }}

        </RouterLink>
      </div>
    </Card>
    <Card :title="t('dashboard.platformStatus')">
      <Spinner v-if="loadingStatus" />
      <template v-else-if="status">
        <p v-if="status.unreachable" class="text-sm text-content-muted">
          {{ t('dashboard.apiUnreachable') }}
        </p>
        <dl v-if="!status.unreachable && status.mode" class="mb-4 grid gap-3 sm:grid-cols-2" data-testid="idp-mode">
          <div class="flex flex-col gap-1">
            <dt class="text-xs font-medium tracking-wide text-content-muted uppercase">{{ t('idp.modeLabel') }}</dt>
            <dd><Badge :tone="status.mode === 'primary' ? 'success' : 'brand'">{{ t(`idp.modeName.${status.mode}`) }}</Badge></dd>
          </div>
          <div class="flex flex-col gap-1">
            <dt class="text-xs font-medium tracking-wide text-content-muted uppercase">{{ t('idp.lastSync') }}</dt>
            <dd class="text-sm text-content">{{ lastSync }}</dd>
          </div>
        </dl>
        <ul v-if="!status.unreachable" class="flex flex-col gap-2">
          <li
            v-for="dependency in status.dependencies"
            :key="dependency.name"
            class="flex items-center justify-between rounded-md border border-border-subtle px-3 py-2"
          >
            <span class="flex items-center gap-1 text-sm">
              <span dir="ltr">{{ dependency.name }}</span>
              <InfoHelp v-if="dependency.name === 'authorization-service'" topic="authorizationService" />
            </span>
            <!--
              State only. No host, version or upstream status code is rendered
              here because none is sent - see StatusController.
            -->
            <Badge :tone="stateTone[dependency.state] ?? 'neutral'">
              {{ stateLabel(dependency.state) }}
            </Badge>
          </li>
        </ul>
      </template>
    </Card>

    <Card :title="t('dashboard.signedInAs')">
      <DescriptionList :items="identity" />
      <ul v-if="session.roles.length" class="mt-3 flex flex-wrap gap-2">
        <li v-for="role in session.roles" :key="role">
          <Badge tone="brand">{{ role }}</Badge>
        </li>
      </ul>
    </Card>

    <Card :title="tenant ? t('dashboard.usersIn', { tenant }) : t('dashboard.users')" class="lg:col-span-2">
      <p v-if="!tenant" class="text-sm text-content-muted">
        {{ t('common.noTenant') }}
      </p>

      <Spinner v-else-if="loadingUsers" />

      <Alert v-else-if="usersError" tone="danger">
        <template v-if="usersError.denied">
          {{ t('dashboard.denied') }}
        </template>
        <template v-else>{{ t('dashboard.loadFailed') }}</template>
        <span v-if="usersError.correlationId" class="block text-xs opacity-80">
          {{ t('common.reference') }}: {{ usersError.correlationId }}
        </span>
        <!-- Recovery, not a dead end: the failure may well be transient. -->
        <Button variant="outline" size="sm" class="mt-2" @click="loadTenantData">
          {{ t('action.tryAgain') }}
        </Button>
      </Alert>

      <template v-else-if="users">
        <p class="mb-3 text-sm text-content-muted">
          {{ t('dashboard.shown', { count: users.count, limit: users.limit }) }}
          <strong>{{ users.tenant }}</strong>
        </p>
        <ul class="flex flex-col gap-2">
          <li
            v-for="user in users.users"
            :key="user.id"
            class="flex items-center justify-between rounded-md border border-border-subtle px-3 py-2"
          >
            <RouterLink :to="{ name: 'user-detail', params: { id: user.id }, query: { tenant } }" class="text-sm text-brand hover:underline">{{ user.username }}</RouterLink>
            <Badge :tone="user.enabled ? 'success' : 'neutral'">
              {{ t(user.enabled ? 'state.enabled' : 'state.disabled') }}
            </Badge>
          </li>
        </ul>
      </template>
    </Card>


  </div>
</template>
