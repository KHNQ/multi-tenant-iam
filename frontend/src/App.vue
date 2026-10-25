<script setup>
import { onMounted, ref } from 'vue'
import { embedded } from '@/embedded.js'
import AppShell from '@/components/AppShell.vue'
import Alert from '@/components/ui/Alert.vue'
import Button from '@/components/ui/Button.vue'
import Card from '@/components/ui/Card.vue'
import Spinner from '@/components/ui/Spinner.vue'
import { fetchSession, login } from '@/session.js'
import { session } from '@/sessionState.js'
import { useI18n } from '@/i18n.js'
import { getAutoSignIn } from '@/config.js'

const loading = ref(true)
const error = ref(null)
const { t } = useI18n()

// One automatic attempt per tab: if we come back from Keycloak still signed out
// (e.g. the login was cancelled), show the button instead of redirecting forever.
const AUTO_SIGN_IN_KEY = 'iam.autoSignIn.attempted'

function tryAutoSignIn() {
  try {
    if (!getAutoSignIn() || sessionStorage.getItem(AUTO_SIGN_IN_KEY)) return false
    sessionStorage.setItem(AUTO_SIGN_IN_KEY, '1')
  } catch {
    return false
  }
  login()
  return true
}

onMounted(async () => {
  let redirecting = false
  try {
    session.value = await fetchSession()
    if (session.value) {
      try { sessionStorage.removeItem(AUTO_SIGN_IN_KEY) } catch { /* storage unavailable */ }
    } else {
      redirecting = tryAutoSignIn()
    }
  } catch (e) {
    error.value = e.message
  } finally {
    // Leaving for Keycloak: keep the spinner rather than flash the sign-in card.
    loading.value = redirecting
  }
})
</script>

<template>
  <div v-if="loading" :class="['grid place-items-center', embedded.enabled ? 'min-h-48' : 'min-h-screen']">
    <Spinner>{{ t('auth.loading') }}</Spinner>
  </div>

  <div v-else-if="error" class="mx-auto max-w-md p-6">
    <Alert :title="t('auth.unreachable')">
      {{ error }}
      <p class="mt-2">
        <Button variant="outline" size="sm" @click="() => window.location.reload()">{{ t('action.tryAgain') }}</Button>
      </p>
    </Alert>
  </div>

  <div v-else-if="!session" :class="['grid place-items-center p-6', embedded.enabled ? 'min-h-48' : 'min-h-screen']">
    <Card class="w-full max-w-sm text-center">
      <h1 class="mb-2 text-xl font-semibold">{{ t('app.name') }}</h1>
      <p class="mb-5 text-sm text-content-muted">{{ t('auth.signInPrompt') }}</p>
      <Button class="w-full" @click="login">{{ t('action.signIn') }}</Button>
    </Card>
  </div>

  <AppShell v-else :session="session">
    <RouterView :session="session" />
  </AppShell>
</template>
