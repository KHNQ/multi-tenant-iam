<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { Search } from 'lucide-vue-next'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import InfoHelp from '@/components/InfoHelp.vue'
import { useI18n } from '@/i18n.js'
import { useTenantPreference } from '@/tenantPreference.js'
import { messageFor } from '@/api.js'
import { searchUsers } from '@/users.js'
import { standby } from '@/standby.js'
import {
  createGroup, fetchGroup, fetchGroupMembers, fetchGroups, moveGroup,
  newIdempotencyKey, renameGroup, setGroupMember,
} from '@/groups.js'

const props = defineProps({ session: { type: Object, required: true } })
const { t } = useI18n()
const tenants = computed(() => props.session.tenants ?? [])
const tenant = useTenantPreference(tenants)
const search = ref('')
const result = ref(null)
const selected = ref(null)
const members = ref([])
const loading = ref(false)
const error = ref(null)
const notice = ref('')
const showCreate = ref(false)

async function load() {
  if (!tenant.value) return
  loading.value = true
  error.value = null
  try { result.value = await fetchGroups(tenant.value, search.value.trim()) }
  catch (failure) { error.value = failure }
  finally { loading.value = false }
}

async function select(id) {
  error.value = null
  try {
    selected.value = await fetchGroup(tenant.value, id)
    members.value = (await fetchGroupMembers(tenant.value, id)).members ?? []
    renameDraft.value = selected.value.name
  } catch (failure) { error.value = failure }
}

const createDraft = ref({ name: '', asChild: false })
let createKey = newIdempotencyKey()
async function submitCreate() {
  error.value = null
  try {
    const made = await createGroup(tenant.value, {
      name: createDraft.value.name,
      parentId: createDraft.value.asChild ? selected.value?.id ?? null : null,
    }, createKey)
    createDraft.value = { name: '', asChild: false }
    createKey = newIdempotencyKey()
    showCreate.value = false
    notice.value = t('groups.created', { path: made.path })
    await load(); await select(made.id)
  } catch (failure) { error.value = failure }
}

const renameDraft = ref('')
async function submitRename() {
  try {
    selected.value = await renameGroup(tenant.value, selected.value.id, renameDraft.value, newIdempotencyKey())
    notice.value = t('groups.renamed'); await load(); await select(selected.value.id)
  } catch (failure) { error.value = failure }
}

const destination = ref('')
async function submitMove() {
  try {
    selected.value = await moveGroup(tenant.value, selected.value.id, destination.value || null, newIdempotencyKey())
    notice.value = t('groups.moved'); destination.value = ''; await load(); await select(selected.value.id)
  } catch (failure) { error.value = failure }
}

const userSearch = ref('')
const candidates = ref([])
async function findUsers() {
  try { candidates.value = (await searchUsers(tenant.value, userSearch.value.trim())).users ?? [] }
  catch (failure) { error.value = failure }
}
async function membership(user, add) {
  try {
    await setGroupMember(tenant.value, selected.value.id, user.id, add, newIdempotencyKey())
    notice.value = t(add ? 'groups.added' : 'groups.removed', { user: user.username })
    await select(selected.value.id)
  } catch (failure) { error.value = failure }
}
const groups = computed(() => result.value?.groups ?? [])
const memberIds = computed(() => new Set(members.value.map((item) => item.id)))
watch(tenant, () => { selected.value = null; load() })
onMounted(load)
</script>

<template>
  <div class="mb-5 flex flex-wrap items-end justify-between gap-3">
    <div><h1 class="flex items-center gap-1 text-2xl font-semibold">{{ t('groups.title') }} <InfoHelp topic="tenant" /></h1><p class="text-sm text-content-muted">{{ t('groups.subtitle') }}</p></div>
    <label v-if="tenants.length > 1" class="text-sm">{{ t('common.tenant') }}
      <select v-model="tenant" class="ms-2 rounded-md border border-border-subtle bg-surface px-3 py-2"><option v-for="item in tenants" :key="item" :value="item">{{ item }}</option></select>
    </label>
    <Button :disabled="!tenant || standby" @click="showCreate = true">{{ t('ux.newGroup') }}</Button>
  </div>
  <Alert v-if="error" tone="danger" class="mb-4">{{ messageFor(error) }}<span v-if="error.correlationId" class="block text-xs">{{ t('common.reference') }}: {{ error.correlationId }}</span></Alert>
  <Alert v-if="notice" tone="success" class="mb-4">{{ notice }}</Alert>

  <Card v-if="showCreate" class="mb-5" :title="t('groups.create')">
    <form class="flex flex-wrap items-end gap-3" @submit.prevent="submitCreate">
      <label class="min-w-64 flex-1 text-sm">{{ t('common.name') }}<input v-model="createDraft.name" required maxlength="64" class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2" /></label>
      <label v-if="selected" class="flex items-center gap-2 pb-2 text-sm"><input v-model="createDraft.asChild" type="checkbox" /> {{ t('groups.createUnder', { path: selected.path }) }}</label>
      <Button type="submit" :disabled="standby">{{ t('groups.create') }}</Button><Button variant="outline" type="button" @click="showCreate = false">{{ t('action.cancel') }}</Button>
    </form>
  </Card>

  <div class="grid items-start gap-5 lg:grid-cols-[minmax(15rem,1fr)_minmax(0,2fr)]">
  <Card class="mb-5" :title="t('groups.count', { count: result?.count ?? 0 })">
    <form class="mb-4 flex min-w-0 items-center rounded-md border border-border-subtle bg-surface focus-within:border-brand" @submit.prevent="load">
      <input v-model="search" name="group-search" autocomplete="off" type="search" :aria-label="t('groups.searchPlaceholder')" :placeholder="t('groups.searchPlaceholder')" class="min-w-0 flex-1 bg-transparent px-3 py-2 text-sm" />
      <button type="submit" :aria-label="t('action.search')" :title="t('action.search')" :disabled="loading" class="flex size-10 shrink-0 items-center justify-center rounded-md text-content-muted hover:text-brand disabled:opacity-50"><Search :size="17" aria-hidden="true" /></button>
    </form>
    <Spinner v-if="loading">{{ t('groups.loading') }}</Spinner>
    <div v-else class="divide-y divide-border-subtle">
      <p v-if="!groups.length" class="py-6 text-sm text-content-muted">{{ t(search ? 'groups.noMatch' : 'ux.groupsEmpty') }}</p>
      <button v-for="group in groups" :key="group.id" type="button" class="flex w-full items-center justify-between rounded-md px-2 py-3 text-start hover:bg-surface" :class="selected?.id === group.id ? 'bg-surface text-brand' : ''" :aria-pressed="selected?.id === group.id" @click="select(group.id)"><span><strong>{{ group.name }}</strong><span class="block font-mono text-xs text-content-muted">{{ group.path }}</span></span><Badge tone="neutral">{{ t('action.manage') }}</Badge></button>
    </div>
  </Card>

  <Card v-if="selected" :title="t('groups.manage', { path: selected.path })">
    <p v-if="selected.children?.length" class="mb-2 text-sm font-medium">{{ t('groups.children') }}</p>
    <div class="mb-5 flex flex-wrap gap-2"><Button v-for="child in selected.children" :key="child.id" variant="outline" size="sm" @click="select(child.id)">{{ child.name }}</Button><span v-if="!selected.children?.length" class="text-sm text-content-muted">{{ t('groups.noChildren') }}</span></div>
    <details class="mb-5 rounded-lg border border-border-subtle p-4"><summary class="mb-3 cursor-pointer text-sm font-medium">{{ t('ux.groupSettings') }}</summary>
    <form class="mb-5 flex gap-2" @submit.prevent="submitRename"><label class="flex-1 text-sm">{{ t('groups.rename') }}<input v-model="renameDraft" required maxlength="64" class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2" /></label><Button class="self-end" variant="outline" type="submit" :disabled="standby">{{ t('groups.saveName') }}</Button></form>
    <form class="mb-5 flex items-end gap-2" @submit.prevent="submitMove"><label class="flex-1 text-sm">{{ t('groups.moveUnder') }}<select v-model="destination" class="mt-1 w-full rounded-md border border-border-subtle bg-surface px-3 py-2"><option value="">{{ t('groups.topLevel') }}</option><option v-for="group in groups.filter((g) => g.id !== selected.id)" :key="group.id" :value="group.id">{{ group.path }}</option></select></label><Button variant="outline" type="submit" :disabled="standby">{{ t('action.move') }}</Button></form>
    </details>
    <h2 class="mb-2 flex items-center gap-1 font-semibold">{{ t('groups.members') }} <InfoHelp topic="effectiveAccess" /></h2>
    <div class="mb-4 divide-y divide-border-subtle"><div v-for="member in members" :key="member.id" class="flex items-center justify-between py-2"><span>{{ member.username }} <span class="text-sm text-content-muted">{{ member.email }}</span></span><Button variant="danger" size="sm" :disabled="standby" @click="membership(member, false)">{{ t('action.remove') }}</Button></div><p v-if="!members.length" class="py-2 text-sm text-content-muted">{{ t('groups.noMembers') }}</p></div>
    <form class="flex gap-2" @submit.prevent="findUsers"><input v-model="userSearch" :aria-label="t('groups.findUser')" required type="search" :placeholder="t('users.searchPlaceholder')" class="flex-1 rounded-md border border-border-subtle bg-surface px-3 py-2" /><Button variant="outline" type="submit">{{ t('groups.findUser') }}</Button></form>
    <div class="mt-2 divide-y divide-border-subtle"><div v-for="user in candidates" :key="user.id" class="flex items-center justify-between py-2"><span>{{ user.username }} <span class="text-sm text-content-muted">{{ user.email }}</span></span><Badge v-if="memberIds.has(user.id)" tone="success">{{ t('groups.member') }}</Badge><Button v-else size="sm" :disabled="standby" @click="membership(user, true)">{{ t('action.add') }}</Button></div></div>
  </Card>
  <Card v-else :title="t('ux.groupDetails')"><p class="py-6 text-sm text-content-muted">{{ t('ux.chooseGroup') }}</p></Card>
  </div>
</template>
