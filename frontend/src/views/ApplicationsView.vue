<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { Search, ShieldCheck, KeyRound, RefreshCw, Plus, LockKeyhole, Users, Inbox } from 'lucide-vue-next'
import Alert from '@/components/ui/Alert.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import PermissionApprovals from '@/components/access/PermissionApprovals.vue'
import { messageFor, newIdempotencyKey } from '@/api.js'
import { useI18n } from '@/i18n.js'
import { useTenantPreference } from '@/tenantPreference.js'
import { searchUsers } from '@/users.js'
import { standby } from '@/standby.js'
import {
  changeUserRole, createRole, deleteRole, fetchApplicationAccess,
  fetchPermissions, fetchRoles, previewRole, previewRoleChange, updateRole,
} from '@/applications.js'

const props = defineProps({ session: { type: Object, required: true } })
const { t } = useI18n()
const availableTenants = computed(() => props.session.tenants ?? [])
const preferredTenant = useTenantPreference(availableTenants)
const tenant = computed(() => availableTenants.value.includes('samta') ? 'samta' : preferredTenant.value)
const permissions = ref([])
const roles = ref([])
const loading = ref(false)
const error = ref(null)
const notice = ref('')
// ?tab= lets a host, such as MapDashboard's IAM-mode notice, open a specific tab.
const TAB_IDS = ['roles', 'permissions', 'pending', 'users']
// /roles and /permissions reuse this view, so follow the route rather than
// reading it once: switching between them does not remount the component.
const route = useRoute()
const tabFor = (r) => [r.query.tab, r.meta?.tab].find((tab) => TAB_IDS.includes(tab)) ?? 'roles'
const activeTab = ref(tabFor(route))
watch(() => [route.query.tab, route.meta?.tab], () => { activeTab.value = tabFor(route) })
const pendingImports = ref(undefined)
const approvals = ref(null)
const tabs = computed(() => [
  { id: 'roles', label: t('applications.roles'), icon: ShieldCheck, count: roles.value.length },
  { id: 'permissions', label: t('applications.permissionsTab'), icon: KeyRound, count: permissions.value.length },
  { id: 'pending', label: t('imports.tab'), icon: Inbox, count: pendingImports.value },
  { id: 'users', label: t('applications.userAccessTab'), icon: Users },
])
function moveTab(event, index) {
  const direction = document.documentElement.dir === 'rtl' ? -1 : 1
  let next
  if (event.key === 'ArrowRight') next = (index + direction + tabs.value.length) % tabs.value.length
  if (event.key === 'ArrowLeft') next = (index - direction + tabs.value.length) % tabs.value.length
  if (event.key === 'Home') next = 0
  if (event.key === 'End') next = tabs.value.length - 1
  if (next === undefined) return
  event.preventDefault()
  activeTab.value = tabs.value[next].id
  event.currentTarget.parentElement.querySelectorAll('[role=tab]')[next].focus()
}
const editingRole = ref(false)
const pickerSearch = ref('')
const pickerSelectedOnly = ref(false)
const pickerGroups = computed(() => grouped.value.map(([category, items]) => [category,
  items.filter(permission => (!pickerSelectedOnly.value || chosenPermissions.value.includes(permission.key)) &&
    `${permission.key} ${permission.description ?? ''} ${category}`.toLocaleLowerCase()
      .includes(pickerSearch.value.toLocaleLowerCase().trim())),
]).filter(([, items]) => items.length))


const permissionSearch = ref('')
const roleSearch = ref('')
const visibleRoles = computed(() => roles.value.filter(role =>
  `${role.name} ${role.description ?? ''}`.toLocaleLowerCase().includes(roleSearch.value.toLocaleLowerCase().trim())))
const filteredGroups = computed(() => grouped.value.map(([category, items]) => [category,
  items.filter(permission => `${permission.key} ${permission.description ?? ''} ${category}`
    .toLocaleLowerCase().includes(permissionSearch.value.toLocaleLowerCase().trim())),
]).filter(([, items]) => items.length))

const grouped = computed(() => {
  const categories = new Map()
  for (const permission of permissions.value) {
    const category = permission.category || t('applications.other')
    if (!categories.has(category)) categories.set(category, [])
    categories.get(category).push(permission)
  }
  return [...categories].sort(([left], [right]) => left.localeCompare(right))
})

async function load() {
  if (tenant.value !== 'samta') return
  loading.value = true
  error.value = null
  try {
    ;[permissions.value, roles.value] = await Promise.all([
      fetchPermissions(tenant.value), fetchRoles(tenant.value),
    ])
    if (!editingRole.value) selectedRole.value = roles.value.find(role => role.name === selectedRole.value?.name) ?? roles.value[0] ?? null
  } catch (failure) {
    error.value = failure
  } finally {
    loading.value = false
  }
}

const selectedRole = ref(null)
const roleName = ref('')
const roleDescription = ref('')
const chosenPermissions = ref([])
const roleReview = ref(null)
const roleKey = ref(null)
const roleBusy = ref(false)
const deleteReview = ref(false)

function selectRole(role) {
  selectedRole.value = role
  editingRole.value = false
  deleteReview.value = false
  roleReview.value = null
}

function editRole(role) {
  editingRole.value = true
  pickerSearch.value = ''
  pickerSelectedOnly.value = false
  selectedRole.value = role
  roleName.value = role?.name ?? ''
  roleDescription.value = role?.description ?? ''
  chosenPermissions.value = [...(role?.permissions ?? [])]
  roleReview.value = null
  deleteReview.value = false
}

function togglePermission(key) {
  chosenPermissions.value = chosenPermissions.value.includes(key)
    ? chosenPermissions.value.filter((value) => value !== key)
    : [...chosenPermissions.value, key]
  roleReview.value = null
}

async function reviewRole() {
  error.value = null
  try {
    roleReview.value = selectedRole.value
      ? await previewRole(tenant.value, roleName.value, chosenPermissions.value)
      : { added: chosenPermissions.value, removed: [], fingerprint: null }
    roleKey.value = newIdempotencyKey()
  } catch (failure) {
    error.value = failure
  }
}

async function saveRole() {
  if (!roleReview.value) return
  roleBusy.value = true
  error.value = null
  try {
    if (selectedRole.value) {
      await updateRole(tenant.value, roleName.value, {
        description: roleDescription.value,
        permissions: chosenPermissions.value,
        fingerprint: roleReview.value.fingerprint,
      }, roleKey.value)
    } else {
      await createRole(tenant.value, {
        name: roleName.value, description: roleDescription.value,
        permissions: chosenPermissions.value,
      }, roleKey.value)
    }
    notice.value = t('applications.roleSaved')
    editingRole.value = false
    await load()
  } catch (failure) {
    error.value = failure
  } finally {
    roleBusy.value = false
  }
}

async function removeRole(role) {
  error.value = null
  if (role.system) return
  try {
    await deleteRole(tenant.value, role.name, role.fingerprint, newIdempotencyKey())
    notice.value = t('applications.roleDeleted')
    selectRole(null)
    await load()
  } catch (failure) {
    error.value = failure
  }
}

const userSearch = ref('')
const users = ref([])
const selectedUser = ref(null)
const access = ref(null)
const actionRole = ref('')
const action = ref('assign')
const changePreview = ref(null)
const changeKey = ref(null)
const changing = ref(false)
const usersBusy = ref(false)
const userSearched = ref(false)
const accessBusy = ref(false)

async function findUsers() {
  usersBusy.value = true
  userSearched.value = true
  error.value = null
  try {
    const result = await searchUsers(tenant.value, userSearch.value)
    users.value = result.users ?? []
  } catch (failure) {
    error.value = failure
  } finally {
    usersBusy.value = false
  }
}

async function chooseUser(user) {
  selectedUser.value = user
  access.value = null
  actionRole.value = ''
  accessBusy.value = true
  changePreview.value = null
  error.value = null
  try {
    access.value = await fetchApplicationAccess(tenant.value, user.id)
  } catch (failure) {
    error.value = failure
  } finally {
    accessBusy.value = false
  }
}

async function reviewChange() {
  if (!selectedUser.value || !actionRole.value) return
  error.value = null
  try {
    changePreview.value = await previewRoleChange(
      tenant.value, selectedUser.value.id, actionRole.value, action.value,
    )
    changeKey.value = newIdempotencyKey()
  } catch (failure) {
    error.value = failure
  }
}

async function confirmChange() {
  if (!changePreview.value) return
  changing.value = true
  error.value = null
  try {
    access.value = await changeUserRole(
      tenant.value, selectedUser.value.id, actionRole.value, action.value,
      changePreview.value.fingerprint, changeKey.value,
    )
    changePreview.value = null
    notice.value = t('applications.assignmentSaved')
  } catch (failure) {
    error.value = failure
  } finally {
    changing.value = false
  }
}

watch(tenant, () => {
  selectRole(null)
  selectedUser.value = null
  access.value = null
  load()
})
watch([roleName, roleDescription], () => { roleReview.value = null })
watch([actionRole, action], () => { changePreview.value = null })
onMounted(load)
</script>

<template>
  <div class="application-access space-y-6">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h1 class="text-2xl font-semibold tracking-tight">{{ t('applications.title') }}</h1>
        <p class="mt-2 max-w-2xl text-sm text-content-muted">{{ t('applications.subtitle') }}</p>
      </div>
      <Button variant="outline" size="sm" :disabled="loading" @click="load(); approvals?.load()"><RefreshCw :size="15" aria-hidden="true" />{{ t('action.refresh') }}</Button>
    </div>

    <Alert v-if="tenant !== 'samta'" tone="neutral">{{ t('applications.samtaOnly') }}</Alert>
    <template v-else>
      <Spinner v-if="loading">{{ t('common.loading') }}</Spinner>
      <Alert v-if="error" tone="danger">{{ messageFor(error) }}</Alert>
      <Alert v-if="notice" aria-live="polite" tone="neutral">{{ notice }}</Alert>

      <div class="access-tabs" role="tablist" :aria-label="t('applications.title')">
        <button v-for="(tab, index) in tabs" :key="tab.id" :id="`access-tab-${tab.id}`"
          type="button" role="tab" :aria-selected="activeTab === tab.id" :aria-controls="`access-panel-${tab.id}`"
          :tabindex="activeTab === tab.id ? 0 : -1" @click="activeTab = tab.id" @keydown="moveTab($event, index)">
          <component :is="tab.icon" :size="17" aria-hidden="true" />{{ tab.label }}
          <span v-if="tab.count !== undefined" class="count-badge">{{ tab.count }}</span>
        </button>
      </div>

      <div v-show="activeTab === 'permissions'" id="access-panel-permissions" role="tabpanel" aria-labelledby="access-tab-permissions" class="space-y-5">
      <Card :title="t('applications.catalogue')">
        <div class="search-field mb-5">
          <Search :size="17" aria-hidden="true" />
          <input v-model="permissionSearch" name="permission-search" autocomplete="off" type="search" :aria-label="t('applications.searchPermissions')"
            :placeholder="t('applications.searchPermissions')" />
        </div>
        <div class="catalogue-grid">
          <section v-for="[category, items] in filteredGroups" :key="category" class="permission-group">
            <h3 class="flex items-center justify-between gap-3 border-b border-border-subtle px-4 py-3 text-sm font-semibold">
              {{ category }} <span class="count-badge">{{ items.length }}</span>
            </h3>
            <ul class="divide-y divide-border-subtle">
              <li v-for="permission in items" :key="permission.key" class="px-4 py-3 text-sm">
                <code dir="ltr" class="permission-key font-mono">{{ permission.key }}</code>
                <p class="mt-1 leading-relaxed text-content-muted">{{ permission.description }}</p>
              </li>
            </ul>
          </section>
        </div>
        <p v-if="!loading && !filteredGroups.length" class="py-8 text-center text-sm text-content-muted">{{ t('applications.noPermissions') }}</p>
      </Card>

      </div>

      <div v-show="activeTab === 'roles'" id="access-panel-roles" role="tabpanel" aria-labelledby="access-tab-roles">
      <Card :title="t('applications.roles')">
        <div class="role-workspace">
        <aside class="role-sidebar">
          <Button class="mb-4 w-full" size="sm" :disabled="editingRole || loading || standby" @click="editRole(null)"><Plus :size="16" aria-hidden="true" />{{ t('applications.newRole') }}</Button>
          <div class="search-field mb-3">
            <Search :size="16" aria-hidden="true" />
            <input v-model="roleSearch" name="role-search" autocomplete="off" type="search" :aria-label="t('applications.searchRoles')" :placeholder="t('applications.searchRoles')" />
          </div>
          <div class="space-y-2">
            <button v-for="role in visibleRoles" :key="role.name" type="button" class="role-item"
              :class="{ 'role-item-active': selectedRole?.name === role.name }"
              :aria-pressed="selectedRole?.name === role.name" :disabled="editingRole" @click="selectRole(role)">
              <span class="flex items-center justify-between gap-2">
                <span class="break-all font-medium" dir="ltr">{{ role.name }}</span>
                <LockKeyhole v-if="role.system" :size="14" aria-hidden="true" />
              </span>
              <span class="mt-2 flex flex-wrap items-center gap-2 text-xs text-content-muted">
                {{ t('applications.permissionCount', { count: role.permissions.length }) }}
                <span v-if="role.system" class="count-badge">{{ t('applications.system') }}</span>
              </span>
            </button>
            <p v-if="!loading && !visibleRoles.length" class="py-4 text-sm text-content-muted">{{ t('applications.noRoles') }}</p>
          </div>
        </aside>
        <div class="role-editor min-w-0">
          <div class="mb-5 border-b border-border-subtle pb-4">
            <h3 class="font-semibold">{{ selectedRole?.name || t(editingRole ? 'applications.newRole' : 'applications.chooseRole') }}</h3>
            <p class="mt-1 text-sm text-content-muted">{{ editingRole ? t('applications.roleEditorHelp') : selectedRole?.description || t('applications.roleDetailsHelp') }}</p>
          </div>
        <div v-if="editingRole" class="space-y-4">
          <div class="flex items-center justify-between gap-3">
            <span class="text-sm font-medium" aria-live="polite">{{ t('applications.selectedCount', { count: chosenPermissions.length }) }}</span>
            <Button variant="outline" size="sm" :disabled="roleBusy" @click="selectRole(selectedRole)">{{ t('action.cancel') }}</Button>
          </div>
          <label class="block text-sm">
            {{ t('common.name') }}
            <input v-model.trim="roleName" :disabled="!!selectedRole" class="mt-1 w-full rounded border border-border-subtle bg-surface px-3 py-2" />
          </label>
          <label class="block text-sm">
            {{ t('applications.description') }}
            <input v-model="roleDescription" class="mt-1 w-full rounded border border-border-subtle bg-surface px-3 py-2" />
          </label>
          <div class="search-field">
            <Search :size="16" aria-hidden="true" />
            <input v-model="pickerSearch" type="search" name="role-permission-search" autocomplete="off" :aria-label="t('applications.searchPermissions')" :placeholder="t('applications.searchPermissions')" />
          </div>
          <label class="flex items-center gap-2 text-sm"><input v-model="pickerSelectedOnly" type="checkbox" class="accent-brand" />{{ t('applications.selectedOnly') }}</label>
          <div class="permission-picker space-y-3">
          <div v-for="[category, items] in pickerGroups" :key="category" class="permission-group p-4">
            <h3 class="mb-1 font-medium">{{ category }}</h3>
            <label v-for="permission in items" :key="permission.key" class="permission-option flex items-start gap-3 rounded-md px-2 py-3 text-sm">
              <input class="mt-1 accent-brand" type="checkbox" :checked="chosenPermissions.includes(permission.key)"
                     @change="togglePermission(permission.key)" />
              <span class="min-w-0"><code dir="ltr" class="permission-key font-mono">{{ permission.key }}</code><span class="mt-1 block text-content-muted">{{ permission.description }}</span></span>
            </label>
          </div>
          <p v-if="!pickerGroups.length" class="py-6 text-center text-sm text-content-muted">{{ t('applications.noPermissions') }}</p>
          </div>
          <Button :disabled="!roleName || roleBusy" @click="reviewRole">{{ t('applications.reviewRole') }}</Button>
          <Alert v-if="roleReview" tone="neutral">
            <strong>{{ t('applications.beforeConfirm') }}</strong>
            <p>{{ t('applications.added') }}: {{ [...roleReview.added].join(', ') || t('applications.none') }}</p>
            <p>{{ t('applications.removed') }}: {{ [...roleReview.removed].join(', ') || t('applications.none') }}</p>
            <Button class="mt-2" :disabled="roleBusy || standby" @click="saveRole">{{ t('action.save') }}</Button>
          </Alert>
        </div>
        <div v-else-if="selectedRole" class="space-y-4 text-sm">
          <div class="flex flex-wrap items-center justify-between gap-3">
            <span class="font-medium">{{ t('applications.permissionCount', { count: selectedRole.permissions.length }) }}</span>
            <Button v-if="!selectedRole.system" variant="outline" size="sm" :disabled="standby" @click="editRole(selectedRole)">{{ t('action.edit') }}</Button>
          </div>
          <Alert v-if="selectedRole.system" tone="neutral">{{ t('applications.systemLocked') }}</Alert>
          <div class="flex flex-wrap gap-2"><code v-for="permission in selectedRole.permissions" :key="permission" dir="ltr" class="summary-pill break-all text-xs">{{ permission }}</code></div>
        </div>
        <p v-else class="py-8 text-sm text-content-muted">{{ t('applications.chooseRoleHelp') }}</p>
        <div v-if="selectedRole && !selectedRole.system && !editingRole" class="mt-4">
          <Button v-if="!deleteReview" variant="danger" size="sm" :disabled="standby" @click="deleteReview = true">
            {{ t('applications.deleteRole') }}
          </Button>
          <Alert v-else tone="danger">
            <p>{{ t('applications.deleteWarning', { name: selectedRole.name }) }}</p>
            <p>{{ selectedRole.permissions.join(', ') || t('applications.none') }}</p>
            <Button variant="danger" size="sm" class="mt-2" @click="removeRole(selectedRole)">
              {{ t('applications.confirmDelete') }}
            </Button>
            <Button variant="outline" size="sm" class="ms-2" @click="deleteReview = false">
              {{ t('action.cancel') }}
            </Button>
          </Alert>
        </div>
        </div>
        </div>
      </Card>

      </div>

      <div v-show="activeTab === 'pending'" id="access-panel-pending" role="tabpanel" aria-labelledby="access-tab-pending">
        <PermissionApprovals ref="approvals" :tenant="tenant" @count="pendingImports = $event" @imported="load" />
      </div>

      <div v-show="activeTab === 'users'" id="access-panel-users" role="tabpanel" aria-labelledby="access-tab-users">
      <Card :title="t('applications.userAssignments')">
        <p class="mb-5 text-sm text-content-muted">{{ t('applications.userAccessHelp') }}</p>
        <form class="mb-3 flex flex-wrap gap-2" @submit.prevent="findUsers">
          <input v-model.trim="userSearch" :aria-label="t('applications.findUser')"
                 class="min-w-0 flex-1 rounded border border-border-subtle bg-surface px-3 py-2"
                 :placeholder="t('applications.findUser')" />
          <Button type="submit" :disabled="usersBusy || !userSearch">{{ usersBusy ? t('common.loading') : t('action.search') }}</Button>
        </form>
        <div class="mb-3 flex flex-wrap gap-2">
          <Button v-for="user in users" :key="user.id" size="sm" variant="outline"
                  @click="chooseUser(user)">{{ user.username }}</Button>
        </div>
        <p v-if="userSearched && !usersBusy && !users.length" class="py-4 text-sm text-content-muted">{{ t('applications.noUsers') }}</p>
        <Spinner v-if="accessBusy">{{ t('common.loading') }}</Spinner>
        <template v-if="access">
          <h3 class="mb-2 font-medium">{{ access.username }}</h3>
          <p class="mb-2 text-sm">{{ t('applications.direct') }}: {{ access.directRoles.join(', ') || t('applications.none') }}</p>
          <p class="mb-2 text-sm">{{ t('applications.effective') }}: {{ access.effectiveRoles.join(', ') || t('applications.none') }}</p>
          <ul class="mb-4 space-y-1 text-sm">
            <li v-for="permission in access.permissions" :key="permission">
              <code dir="ltr">{{ permission }}</code>
              <span class="ms-2 text-content-muted">{{ access.permissionOrigins[permission]?.join('; ') }}</span>
            </li>
          </ul>
          <div class="flex flex-wrap gap-2">
            <label class="text-sm">
              {{ t('applications.action') }}
              <select v-model="action" class="ms-1 rounded border border-border-subtle bg-surface px-2 py-1">
                <option value="assign">{{ t('applications.assign') }}</option>
                <option value="revoke">{{ t('applications.revoke') }}</option>
              </select>
            </label>
            <label class="text-sm">
              {{ t('applications.role') }}
              <select v-model="actionRole" class="ms-1 rounded border border-border-subtle bg-surface px-2 py-1">
                <option value="">{{ t('applications.chooseRole') }}</option>
                <option v-for="role in roles" :key="role.name" :value="role.name">{{ role.name }}</option>
              </select>
            </label>
            <Button :disabled="!actionRole || standby" size="sm" @click="reviewChange">{{ t('applications.previewChange') }}</Button>
          </div>
          <Alert v-if="changePreview" tone="neutral" class="mt-4">
            <strong>{{ t('applications.beforeConfirm') }}</strong>
            <p>{{ t('applications.gained') }}: {{ [...changePreview.permissionsGained].join(', ') || t('applications.none') }}</p>
            <p>{{ t('applications.lost') }}: {{ [...changePreview.permissionsLost].join(', ') || t('applications.none') }}</p>
            <p class="text-xs text-content-muted">{{ t('applications.groupNotice') }}</p>
            <Button class="mt-2" :disabled="changing || standby" @click="confirmChange">{{ t('applications.confirmChange') }}</Button>
          </Alert>
        </template>
      </Card>
      </div>
    </template>
  </div>
</template>
