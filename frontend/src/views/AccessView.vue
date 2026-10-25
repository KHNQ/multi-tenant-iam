<script setup>
/*
 * IAM-0214: "what can this user do, and why" - and the grant that changes it.
 *
 * The screen is one argument in two halves.
 *
 * The review half never shows a bare list of role names. Every role carries the
 * complete set of reasons the server gave for it, because a role held both
 * directly and through /administrators needs two removals and a UI that hid the
 * second reason would have told the reviewer a lie of exactly the shape that
 * causes an incident. The filter is driven by the flat `origins[]` the backend
 * publishes for the purpose, rather than re-deriving the classification here and
 * getting the derivation subtly wrong.
 *
 * The assignment half refuses to write anything until the consequence has been
 * shown. Two things are shown, and they are honestly labelled as different:
 *
 *  - Before confirmation, a *projection* from the role catalogue: the composites
 *    the selected roles are known to drag in, plus which of the selection the
 *    user already holds (granting those changes nothing). This is not authority -
 *    only the server resolves the true closure - and it says so.
 *  - After confirmation, the *recomputed preview* the API returns instead of an
 *    echo, with everything newly gained marked.
 *
 * Revocation is deliberately absent, matching AccessController: taking a role
 * away safely needs the impact preview of IAM-0210, and offering it here would
 * make the destructive case the easy one.
 */
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import EffectiveAccessList from '@/components/access/EffectiveAccessList.vue'
import OriginBadge from '@/components/access/OriginBadge.vue'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import { useI18n } from '@/i18n.js'
import { useTenantPreference } from '@/tenantPreference.js'
import { standby } from '@/standby.js'
import {
  assignRolesToUser,
  fetchEffectiveAccess,
  fetchRoleCatalogue,
  messageFor,
  newIdempotencyKey,
  projectReach,
  qualify,
} from '@/access.js'

const props = defineProps({ session: { type: Object, required: true }, embedded: Boolean })
const { t } = useI18n()

const route = useRoute()
const userId = computed(() => route.params.id)
const availableTenants = computed(() => props.session.tenants ?? [])
const preferredTenant = useTenantPreference(availableTenants)
const tenant = computed(() => route.query.tenant ?? preferredTenant.value)

const preview = ref(null)
const loading = ref(false)
const loadError = ref(null)

/* ---------- the review ---------- */

async function load() {
  if (!tenant.value || !userId.value) {
    return
  }
  loading.value = true
  loadError.value = null
  try {
    preview.value = await fetchEffectiveAccess(tenant.value, userId.value)
  } catch (error) {
    loadError.value = error
  } finally {
    loading.value = false
  }
}

const filter = ref('all')
const filters = computed(() => [
  { key: 'all', label: t('access.all') },
  { key: 'direct', label: t('access.direct') },
  { key: 'group', label: t('access.fromGroup') },
  { key: 'composite', label: t('access.fromComposite') },
])

const access = computed(() => preview.value?.access ?? [])

const visible = computed(() =>
  filter.value === 'all'
    ? access.value
    : access.value.filter((role) => (role.origins ?? []).includes(filter.value)),
)

/** Roles reachable more than one way. Called out because they are the trap. */
const multiOrigin = computed(() =>
  access.value.filter((role) => (role.grants ?? []).length > 1),
)

const groupedAccess = computed(() => {
  const groups = new Map()
  for (const role of visible.value) {
    const platform = role.source !== 'client' || ['account', 'realm-management', 'account-console'].includes(role.client)
    const key = platform ? 'platform' : role.client
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(role)
  }
  return [...groups].sort(([a], [b]) => a === 'platform' ? 1 : b === 'platform' ? -1 : a.localeCompare(b))
})

const held = computed(() => new Set(access.value.map(qualify)))

/* ---------- the grant ---------- */

const catalogue = ref([])
const catalogueError = ref(null)

async function loadCatalogue() {
  if (!tenant.value) {
    return
  }
  catalogueError.value = null
  try {
    const result = await fetchRoleCatalogue(tenant.value)
    catalogue.value = result.roles ?? []
  } catch (error) {
    catalogueError.value = error
  }
}

/*
 * Non-assignable roles are removed here, not merely disabled: RolePolicy already
 * refuses them and offering one only teaches an administrator the rule by having
 * their write rejected. The count of what was withheld is still shown, so the
 * catalogue does not silently look shorter than it is.
 */
const offerable = computed(() => catalogue.value.filter((role) => role.assignable === true))
const withheld = computed(() => catalogue.value.length - offerable.value.length)

const roleSearch = ref('')
const matching = computed(() => {
  const term = roleSearch.value.trim().toLowerCase()
  return offerable.value.filter((role) => !term || role.name.toLowerCase().includes(term))
})

const selected = ref([])

function isSelected(role) {
  return selected.value.some((entry) => qualify(entry) === qualify(role))
}

function toggle(role) {
  selected.value = isSelected(role)
    ? selected.value.filter((entry) => qualify(entry) !== qualify(role))
    : [...selected.value, role]
}

/* ---------- review before confirmation ---------- */

const reviewing = ref(false)
const reach = ref({ brings: [], unknown: false })
const projecting = ref(false)
/*
 * Minted when the review is opened, because that is where the *intent* is
 * formed (IAM-0206). If Confirm is pressed, stalls and is pressed again, the
 * retry carries the same key and cannot grant twice.
 */
let assignKey = null

async function openReview() {
  reviewing.value = true
  projecting.value = true
  assignKey = newIdempotencyKey()
  assignError.value = null
  try {
    reach.value = await projectReach(tenant.value, selected.value)
  } finally {
    projecting.value = false
  }
}

/** Selected roles the user already holds: the grant would change nothing. */
const alreadyHeld = computed(() => selected.value.filter((role) => held.value.has(qualify(role))))

/** Projected composites that would genuinely be new. */
const newlyBrought = computed(() =>
  reach.value.brings.filter((role) => !held.value.has(qualify(role))),
)

/* ---------- confirmation ---------- */

const assigning = ref(false)
const assignError = ref(null)
const gained = ref([])
const assigned = ref(null)

async function confirm() {
  assigning.value = true
  assignError.value = null
  const before = new Set(access.value.map(qualify))
  try {
    // The response IS the recomputed preview - rendered directly, so what is on
    // screen after the write is the server's answer, not this component's guess.
    const result = await assignRolesToUser(tenant.value, userId.value, selected.value, assignKey)
    preview.value = result
    gained.value = (result.access ?? []).map(qualify).filter((name) => !before.has(name))
    assigned.value = result.assigned ?? selected.value.length
    selected.value = []
    reviewing.value = false
    filter.value = 'all'
  } catch (error) {
    assignError.value = error
  } finally {
    assigning.value = false
  }
}

function cancelReview() {
  reviewing.value = false
  assignError.value = null
}

watch([tenant, userId], () => {
  selected.value = []
  reviewing.value = false
  gained.value = []
  assigned.value = null
  load()
  loadCatalogue()
})

onMounted(() => {
  load()
  loadCatalogue()
})
</script>

<template>
  <div v-if="!embedded" class="mb-5 flex flex-wrap items-center justify-between gap-3">
    <div class="min-w-0">
      <RouterLink to="/users" class="text-sm text-content-muted underline">{{ t('access.users') }}</RouterLink>
      <h1 class="text-2xl font-semibold">
        {{ t('access.title', { user: preview?.username ?? '' }) }}
      </h1>
    </div>
    <div class="flex items-center gap-2">
      <Badge v-if="preview" :tone="preview.enabled ? 'success' : 'neutral'">
        {{ t(`state.${preview.enabled ? 'enabled' : 'disabled'}`) }}
      </Badge>
      <Button variant="outline" size="sm" @click="load">{{ t('action.refresh') }}</Button>
    </div>
  </div>

  <p v-if="!tenant" class="text-sm text-content-muted">{{ t('common.noTenant') }}</p>

  <template v-else>
    <Alert v-if="loadError" tone="danger" class="mb-5">
      {{ messageFor(loadError) }}
      <span v-if="loadError.correlationId" class="block text-xs opacity-80">
        {{ t('common.reference') }}: {{ loadError.correlationId }}
      </span>
      <Button variant="outline" size="sm" class="mt-2" @click="load">{{ t('action.tryAgain') }}</Button>
    </Alert>

    <Alert v-if="assigned !== null" tone="neutral" class="mb-5">
      {{ t('access.granted', { count: assigned }) }}
      <span v-if="gained.length" class="mt-1 block">
        {{ t('access.newlyHeld', { roles: gained.join(', ') }) }}
      </span>
      <span v-else class="mt-1 block">
        {{ t('access.nothingGained') }}
      </span>
    </Alert>

    <Card v-if="preview" class="mb-5" :title="t('access.groupMemberships')">
      <p v-if="!preview.groups?.length" class="text-sm text-content-muted">
        {{ t('access.noGroups') }}
      </p>
      <ul v-else class="flex flex-wrap gap-2">
        <li v-for="path in preview.groups" :key="path">
          <code class="rounded bg-surface px-2 py-1 font-mono text-xs text-content">{{ path }}</code>
        </li>
      </ul>
    </Card>

    <Card class="mb-5" :title="t('access.rolesHeld', { count: preview?.count ?? 0 })">
      <Spinner v-if="loading" />
      <template v-else-if="preview">
        <p class="mb-3 text-sm text-content-muted">
          {{ t('access.reasonsHelp') }}
        </p>

        <Alert v-if="multiOrigin.length" tone="neutral" class="mb-4">
          {{ t('access.multipleReasons', { count: multiOrigin.length, roles: multiOrigin.map((role) => role.name).join(', ') }) }}
        </Alert>

        <div class="mb-4 flex flex-wrap items-center gap-2" role="group" :aria-label="t('access.filterOrigin')">
          <Button
            v-for="option in filters"
            :key="option.key"
            size="sm"
            :variant="filter === option.key ? 'default' : 'outline'"
            :aria-pressed="filter === option.key"
            @click="filter = option.key"
          >
            {{ option.label }}
          </Button>
        </div>

        <p v-if="!visible.length" class="text-sm text-content-muted">
          {{ t('access.noRoleOrigin') }}
        </p>
        <div v-else class="space-y-5">
          <template v-for="[application, items] in groupedAccess" :key="application">
            <details v-if="application === 'platform'" class="rounded-lg border border-border-subtle p-4" data-testid="platform-access">
              <summary class="cursor-pointer text-sm font-medium">{{ t('ux.platformAccess') }} <span class="text-content-muted">({{ items.length }})</span></summary>
              <div class="mt-4"><EffectiveAccessList :access="items" :highlight="gained" /></div>
            </details>
            <section v-else>
              <h3 class="mb-3 text-sm font-semibold break-all">{{ application }}</h3>
              <p class="mb-2 text-xs text-content-muted">{{ t('ux.assignedRoles') }}</p>
              <EffectiveAccessList :access="items.filter(item => !item.name.startsWith('perm:'))" :highlight="gained" />
              <details v-if="items.some(item => item.name.startsWith('perm:'))" class="mt-3 rounded-lg border border-border-subtle p-4">
                <summary class="cursor-pointer text-sm font-medium">{{ t('ux.effectivePermissions') }} ({{ items.filter(item => item.name.startsWith('perm:')).length }})</summary>
                <div class="mt-3"><EffectiveAccessList :access="items.filter(item => item.name.startsWith('perm:'))" :highlight="gained" /></div>
              </details>
            </section>
          </template>
        </div>
      </template>
    </Card>

    <!-- grant -->
    <Card :title="t('access.grantRole')">
      <Alert v-if="catalogueError" tone="danger" class="mb-4">
        {{ messageFor(catalogueError) }}
      </Alert>

      <template v-else-if="!reviewing">
        <label for="role-search" class="mb-1 block text-sm text-content-muted">
          {{ t('access.searchCatalogue') }}
        </label>
        <input
          id="role-search"
          v-model="roleSearch"
          type="search"
          :placeholder="t('access.rolePlaceholder')"
          class="mb-3 w-full rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm"
        />

        <p v-if="withheld > 0" class="mb-3 text-xs text-content-muted">
          {{ t('access.withheld', { count: withheld }) }}
        </p>

        <ul class="mb-4 flex max-h-72 flex-col gap-1 overflow-y-auto">
          <li v-for="role in matching" :key="qualify(role)" data-testid="offerable-role">
            <label class="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-surface">
              <input
                type="checkbox"
                :checked="isSelected(role)"
                :aria-label="t('access.selectRole', { role: role.name })"
                @change="toggle(role)"
              />
              <span class="font-medium">{{ role.name }}</span>
              <Badge tone="neutral">
                {{ role.source === 'client' ? `client · ${role.client}` : 'realm' }}
              </Badge>
              <Badge v-if="role.composite" tone="neutral">composite</Badge>
              <span v-if="held.has(qualify(role))" class="text-xs text-content-muted">
                {{ t('access.alreadyHeld') }}
              </span>
            </label>
          </li>
        </ul>
        <p v-if="!matching.length" class="mb-4 text-sm text-content-muted">
          {{ t('access.noAssignable') }}
        </p>

        <Button :disabled="!selected.length || standby" @click="openReview">
          {{ t('access.reviewSelected', { count: selected.length }) }}
        </Button>
      </template>

      <!-- review: nothing is written until this has been read -->
      <template v-else>
        <h3 class="mb-2 text-sm font-semibold">{{ t('access.beforeConfirm') }}</h3>
        <Spinner v-if="projecting">{{ t('access.projecting') }}</Spinner>
        <template v-else>
          <p class="mb-2 text-sm">{{ t('access.aboutToGrant') }}</p>
          <ul class="mb-4 flex flex-col gap-1">
            <li
              v-for="role in selected"
              :key="qualify(role)"
              class="flex flex-wrap items-center gap-2 text-sm"
              data-testid="review-selected"
            >
              <OriginBadge origin="direct" />
              <span class="font-medium">{{ qualify(role) }}</span>
              <span v-if="held.has(qualify(role))" class="text-xs text-content-muted">
                {{ t('access.alreadyHeldNoChange') }}
              </span>
            </li>
          </ul>

          <p class="mb-2 text-sm">{{ t('access.alsoBring') }}</p>
          <ul v-if="newlyBrought.length" class="mb-2 flex flex-col gap-1">
            <li
              v-for="role in newlyBrought"
              :key="`${role.from}->${qualify(role)}`"
              class="flex flex-wrap items-center gap-2 text-sm"
              data-testid="review-brought"
            >
              <OriginBadge origin="composite" />
              <span class="font-medium">{{ qualify(role) }}</span>
              <span class="text-xs text-content-muted">via {{ role.from }}</span>
              <Badge v-if="role.administrative" tone="danger">administrative</Badge>
            </li>
          </ul>
          <p v-else class="mb-2 text-sm text-content-muted">
            {{ t('access.nothingFurther') }}
          </p>

          <p class="mb-4 text-xs text-content-muted">
            This is a projection from the role catalogue, taken one composite level deep, and is
            not the authority.<template v-if="reach.unknown">
              Some of the selection could not be expanded, so the real reach may be wider.</template>
            The platform recomputes the true effective access when the grant is applied, and it is
            shown above afterwards.
          </p>

          <Alert v-if="assignError" tone="danger" class="mb-4">
            {{ messageFor(assignError) }}
            <span v-if="assignError.correlationId" class="block text-xs opacity-80">
              {{ t('common.reference') }}: {{ assignError.correlationId }}
            </span>
          </Alert>

          <div class="flex gap-3">
            <Button :disabled="assigning || standby" @click="confirm">
              {{ assigning ? t('access.granting') : t('access.confirmGrant') }}
            </Button>
            <Button variant="ghost" :disabled="assigning" @click="cancelReview">{{ t('access.back') }}</Button>
          </div>
        </template>
      </template>
    </Card>
  </template>
</template>
