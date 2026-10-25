<script setup>
import { computed } from 'vue'
import { useTenantPreference } from '@/tenantPreference.js'
import { AppWindow, KeyRound, LayoutDashboard, LogOut, Monitor, Settings, ShieldAlert, ShieldCheck, Users } from 'lucide-vue-next'
import { embedded } from '@/embedded.js'
import { standby } from '@/standby.js'
import Badge from '@/components/ui/Badge.vue'
import Button from '@/components/ui/Button.vue'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'
import { logout } from '@/session.js'
import { useI18n } from '@/i18n.js'

const props = defineProps({ session: { type: Object, required: true } })
const currentTenant = useTenantPreference(computed(() => props.session.tenants ?? []))

const { t } = useI18n()
const nav = [
  { to: '/', label: 'nav.dashboard', icon: LayoutDashboard, requires: null },
  { to: '/users', label: 'nav.users', icon: Users, requires: 'tenantAdmin' },
  { to: '/clients', label: 'nav.applications', icon: AppWindow, requires: 'tenantAdmin' },
  { to: '/roles', label: 'nav.roles', icon: ShieldCheck, requires: 'tenantAdmin' },
  { to: '/permissions', label: 'nav.permissions', icon: KeyRound, requires: 'tenantAdmin' },
  { to: '/sessions', label: 'nav.sessions', icon: Monitor, requires: 'tenantAdmin' },
]
</script>

<template>
  <div :class="embedded.enabled ? 'iam-embedded-shell' : 'min-h-screen'">
    <!-- Keyboard users land here first and can jump the navigation entirely. -->
    <a
      href="#main"
      class="sr-only focus:not-sr-only focus:absolute focus:top-2 focus:left-2 focus:z-50
             focus:rounded-md focus:bg-brand focus:px-4 focus:py-2 focus:text-brand-content"
    >
      {{ t('nav.skip') }}
    </a>

    <header v-if="!embedded.enabled" class="border-b border-border-subtle bg-surface-raised">
      <div class="mx-auto flex min-h-14 max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3">
        <span class="font-semibold">{{ t('app.name') }}</span>
        <div class="flex items-center gap-3">
<span v-if="currentTenant" class="text-xs text-content-muted">{{ t('common.tenant') }}: <strong dir="ltr" class="text-content">{{ $route.query.tenant || currentTenant }}</strong></span>
          <LanguageSwitcher />
          <!-- Platform settings only concern platform admins, so they sit here
               rather than in everyone's menu. -->
          <RouterLink
            v-if="session.permissions.platformAdmin"
            to="/platform"
            :title="t('nav.platform')"
            :aria-label="t('nav.platform')"
            class="rounded-md p-2 text-content-muted hover:bg-surface hover:text-content"
            active-class="text-content"
          >
            <Settings class="size-4" aria-hidden="true" />
          </RouterLink>
          <span class="hidden text-sm text-content-muted sm:inline">{{ session.username }}</span>
          <Badge v-if="session.permissions.platformAdmin" tone="brand">{{ t('role.platformAdmin') }}</Badge>
          <Badge v-else-if="session.permissions.tenantAdmin" tone="neutral">{{ t('role.tenantAdmin') }}</Badge>
          <Button variant="outline" size="sm" @click="logout">
            <LogOut class="size-4" aria-hidden="true" />
            {{ t('action.signOut') }}
          </Button>
        </div>
      </div>
    </header>

    <!-- Standby: the primary system owns the data; editing controls are disabled throughout. -->
    <div v-if="standby" role="status" data-testid="standby-banner"
      :class="embedded.enabled ? 'mb-4 rounded-md border border-warning/50 bg-warning/10' : 'border-b border-warning/50 bg-warning/10'">
      <div :class="embedded.enabled ? 'flex items-start gap-2 px-3 py-2 text-sm' : 'mx-auto flex max-w-6xl items-start gap-2 px-4 py-2.5 text-sm'">
        <ShieldAlert class="mt-0.5 size-4 shrink-0 text-warning" aria-hidden="true" />
        <p><strong>{{ t('standby.title') }}</strong> {{ t('standby.banner') }}</p>
      </div>
    </div>

    <div :class="embedded.enabled ? 'flex flex-col gap-5' : 'mx-auto flex max-w-6xl flex-col gap-6 px-4 py-6 md:flex-row'">
      <!--
        Only routes the session is actually entitled to are rendered. The BFF
        still enforces this server-side (IAM-0203); hiding them is a usability
        measure, never the control.
      -->
      <nav :aria-label="t('nav.primary')" :class="embedded.enabled ? 'border-b border-border-subtle pb-3' : 'w-full shrink-0 md:w-48'">
        <ul :class="embedded.enabled ? 'flex flex-wrap gap-1' : 'flex flex-wrap gap-1 md:flex-col'">
          <li v-for="item in nav" :key="item.to">
            <RouterLink
              v-if="!item.requires || session.permissions[item.requires]"
              :to="item.to"
              class="flex items-center gap-2 rounded-md px-3 py-2 text-sm text-content
                     hover:bg-surface-raised"
              active-class="bg-surface-raised font-medium"
              :aria-current="$route.path === item.to ? 'page' : undefined"
            >
              <component :is="item.icon" class="size-4" aria-hidden="true" />
              {{ t(item.label) }}
            </RouterLink>
          </li>
        </ul>
      </nav>

      <main id="main" class="min-w-0 flex-1">
        <slot />
      </main>
    </div>
  </div>
</template>
