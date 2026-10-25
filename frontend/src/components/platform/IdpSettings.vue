<script setup>
/*
 * Platform settings of the identity provider: operating mode, synchronisation
 * from the primary system, and each tenant's signing keys.
 *
 * Every action is confirmed before it is sent, because each one changes what
 * applications see: a mode switch moves the source of truth, a rotation
 * changes the signing key, a retirement invalidates tokens. Key rotation and
 * "synchronise now" are allowed in standby - they touch only this system.
 */
import { computed, onMounted, ref, watch } from 'vue'
import Alert from '@/components/ui/Alert.vue'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import { useI18n } from '@/i18n.js'
import { fetchSession } from '@/session.js'
import { session } from '@/sessionState.js'
import { fetchIdp, messageFor, newIdempotencyKey, retireKey, rotateKey, setMode, syncNow } from '@/idp.js'

const props = defineProps({ section: { type: String, required: true } })
const { t, locale } = useI18n()

const data = ref(null)
const loading = ref(false)
const busy = ref(false)
const error = ref(null)
const notice = ref('')
const switching = ref(false)
const keyRealm = ref('')
const confirmRotate = ref(false)
const retiring = ref(null)

const mode = computed(() => data.value?.mode?.mode)
const otherMode = computed(() => (mode.value === 'primary' ? 'standby' : 'primary'))
const health = computed(() => data.value?.health)
const syncRealms = computed(() => Object.entries(health.value?.realms ?? {}).sort(([a], [b]) => a.localeCompare(b)))
const realms = computed(() => data.value?.realms ?? [])
const keys = computed(() => realms.value.find((realm) => realm.name === keyRealm.value)?.keys ?? [])

const when = (value) => (value ? new Date(value).toLocaleString(locale.value) : t('idp.never'))

async function load() {
  loading.value = true
  error.value = null
  try {
    data.value = await fetchIdp()
    if (!realms.value.some((realm) => realm.name === keyRealm.value)) keyRealm.value = realms.value[0]?.name ?? ''
  } catch (failure) {
    error.value = failure
  } finally {
    loading.value = false
  }
}

async function run(action, message) {
  busy.value = true
  error.value = null
  notice.value = ''
  try {
    await action()
    notice.value = message
    await load()
  } catch (failure) {
    error.value = failure
  } finally {
    busy.value = false
  }
}

async function confirmSwitch() {
  await run(async () => {
    await setMode(otherMode.value, newIdempotencyKey())
    // The banner and the editing controls follow the session's mode.
    session.value = await fetchSession()
  }, '')
  switching.value = false
}

const synchronise = () => run(() => syncNow(newIdempotencyKey()), t('idp.syncDone'))

async function rotate() {
  await run(() => rotateKey(keyRealm.value, newIdempotencyKey()), t('idp.keysChanged'))
  confirmRotate.value = false
}

async function retire() {
  await run(() => retireKey(keyRealm.value, retiring.value, newIdempotencyKey()), t('idp.keysChanged'))
  retiring.value = null
}

watch(() => props.section, () => { notice.value = ''; switching.value = false; confirmRotate.value = false; retiring.value = null })
watch(keyRealm, () => { confirmRotate.value = false; retiring.value = null })
onMounted(load)
</script>

<template>
  <Spinner v-if="loading && !data">{{ t('common.loading') }}</Spinner>
  <Alert v-if="error" tone="danger" class="mb-5">{{ messageFor(error) }}
    <span v-if="error.correlationId" class="block text-xs opacity-80">{{ t('common.reference') }}: {{ error.correlationId }}</span>
  </Alert>
  <Alert v-if="notice" tone="neutral" class="mb-5" aria-live="polite">{{ notice }}</Alert>

  <template v-if="data && section === 'sync'">
    <Card class="mb-5" :title="t('idp.modeTitle')" data-testid="idp-mode-card">
      <div class="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Badge :tone="mode === 'primary' ? 'success' : 'brand'">{{ t(`idp.modeName.${mode}`) }}</Badge>
          <p v-if="data.mode.since" class="mt-2 text-xs text-content-muted">{{ t('idp.modeSince', { time: when(data.mode.since), actor: data.mode.by }) }}</p>
          <p class="mt-2 max-w-2xl text-sm text-content-muted">{{ t(mode === 'primary' ? 'idp.modeHelpPrimary' : 'idp.modeHelpStandby') }}</p>
        </div>
        <Button v-if="!switching" variant="outline" :disabled="busy" @click="switching = true">
          {{ t('idp.switchTo', { mode: t(`idp.modeName.${otherMode}`) }) }}
        </Button>
      </div>
      <Alert v-if="switching" tone="danger" class="mt-4">
        {{ t(otherMode === 'primary' ? 'idp.switchWarningPrimary' : 'idp.switchWarningStandby') }}
        <div class="mt-3 flex gap-2">
          <Button variant="danger" size="sm" :disabled="busy" data-testid="confirm-switch" @click="confirmSwitch">{{ t('idp.confirmSwitch') }}</Button>
          <Button variant="outline" size="sm" :disabled="busy" @click="switching = false">{{ t('action.cancel') }}</Button>
        </div>
      </Alert>
    </Card>

    <Card :title="t('idp.syncTitle')">
      <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
        <div class="text-sm text-content-muted">
          <p v-if="!data.sync.configured">{{ t('idp.syncNotConfigured') }}</p>
          <p v-else-if="mode === 'primary'">{{ t('idp.syncPrimary') }}</p>
          <p v-else>{{ t('idp.interval', { seconds: data.sync.intervalSeconds }) }}</p>
          <p class="mt-1">{{ t('idp.lastSync') }}: <span class="text-content">{{ when(health.lastSuccessfulSync) }}</span></p>
        </div>
        <Button :disabled="busy || !data.sync.configured || mode === 'primary'" data-testid="sync-now" @click="synchronise">
          {{ busy ? t('idp.syncing') : t('idp.syncNow') }}
        </Button>
      </div>
      <Alert v-if="health.stale" tone="danger" class="mb-4">{{ t('idp.stale') }}</Alert>
      <div class="overflow-x-auto">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-border-subtle text-start text-xs tracking-wide text-content-muted uppercase">
              <th class="py-2 text-start font-medium">{{ t('idp.realm') }}</th>
              <th class="py-2 text-start font-medium">{{ t('idp.source') }}</th>
              <th class="py-2 text-start font-medium">{{ t('idp.users') }}</th>
              <th class="py-2 text-start font-medium">{{ t('idp.lastSuccess') }}</th>
              <th class="py-2 text-start font-medium">{{ t('common.status') }}</th>
            </tr>
          </thead>
          <tbody class="divide-y divide-border-subtle">
            <tr v-for="[name, realm] in syncRealms" :key="name" data-testid="sync-row">
              <td class="py-2 font-medium" dir="ltr">{{ name }}</td>
              <td class="py-2 text-content-muted">{{ t(realm.source === 'sync' ? 'idp.sourceSync' : 'idp.sourceLocal') }}</td>
              <td class="py-2">{{ realm.users }}</td>
              <td class="py-2">{{ realm.source === 'sync' ? when(realm.lastSuccess) : '—' }}</td>
              <td class="py-2">
                <Badge v-if="realm.source !== 'sync'" tone="neutral">—</Badge>
                <Badge v-else :tone="realm.ok === false ? 'danger' : realm.ok ? 'success' : 'neutral'">
                  {{ t(realm.ok === false ? 'idp.statusFailed' : realm.ok ? 'idp.statusOk' : 'idp.statusNever') }}
                </Badge>
                <p v-if="realm.error" class="mt-1 text-xs text-danger" dir="ltr">{{ realm.error }}</p>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </Card>
  </template>

  <template v-if="data && section === 'keys'">
    <Card :title="t('idp.keysTitle')">
      <p class="mb-4 max-w-3xl text-sm text-content-muted">{{ t('idp.keysHelp') }}</p>
      <div class="mb-4 flex flex-wrap items-center justify-between gap-3">
        <label class="flex items-center gap-2 text-sm text-content-muted">{{ t('idp.realm') }}
          <select v-model="keyRealm" class="rounded-md border border-border-subtle bg-surface px-3 py-1.5 text-sm text-content">
            <option v-for="realm in realms" :key="realm.name" :value="realm.name">{{ realm.name }}</option>
          </select>
        </label>
        <Button v-if="!confirmRotate" variant="outline" :disabled="busy || !keyRealm" @click="confirmRotate = true">{{ t('idp.rotate') }}</Button>
      </div>
      <Alert v-if="confirmRotate" tone="neutral" class="mb-4">
        {{ t('idp.rotateWarning', { realm: keyRealm }) }}
        <div class="mt-3 flex gap-2">
          <Button size="sm" :disabled="busy" data-testid="confirm-rotate-key" @click="rotate">{{ t('idp.confirmRotate') }}</Button>
          <Button variant="outline" size="sm" :disabled="busy" @click="confirmRotate = false">{{ t('action.cancel') }}</Button>
        </div>
      </Alert>
      <ul class="flex flex-col divide-y divide-border-subtle">
        <li v-for="key in keys" :key="key.kid" class="flex flex-wrap items-center gap-3 py-3" data-testid="key-row">
          <div class="min-w-0 flex-1">
            <div class="flex flex-wrap items-center gap-2">
              <code dir="ltr" class="text-xs break-all">{{ key.kid }}</code>
              <Badge :tone="key.status === 'active' ? 'success' : 'neutral'">{{ t(key.status === 'active' ? 'idp.active' : 'idp.passive') }}</Badge>
              <Badge tone="neutral">{{ key.algorithm }}</Badge>
            </div>
            <p class="mt-1 text-xs text-content-muted">{{ t('idp.created') }}: {{ when(key.createdAt) }}</p>
          </div>
          <Button v-if="key.status === 'passive' && retiring !== key.kid" variant="outline" size="sm" :disabled="busy" @click="retiring = key.kid">{{ t('idp.retire') }}</Button>
          <Alert v-if="retiring === key.kid" tone="danger" class="w-full">
            {{ t('idp.retireWarning') }}
            <div class="mt-3 flex gap-2">
              <Button variant="danger" size="sm" :disabled="busy" @click="retire">{{ t('idp.confirmRetire') }}</Button>
              <Button variant="outline" size="sm" :disabled="busy" @click="retiring = null">{{ t('action.cancel') }}</Button>
            </div>
          </Alert>
        </li>
      </ul>
    </Card>
  </template>
</template>
