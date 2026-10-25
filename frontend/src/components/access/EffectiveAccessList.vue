<script setup>
/*
 * The preview itself: one row per role, every reason attached to it.
 *
 * Presentational on purpose - filtering and loading belong to the view, so this
 * component can be dropped into the group screen (IAM-0212) unchanged.
 *
 * `highlight` carries the qualified names a just-completed grant added. They are
 * marked with a word ("new"), not only a border, so the change is reported to a
 * screen reader too.
 */
import { useI18n } from '@/i18n.js'
import { computed } from 'vue'
import GrantReasons from '@/components/access/GrantReasons.vue'
import Badge from '@/components/ui/Badge.vue'
import { qualify } from '@/access.js'

const props = defineProps({
  access: { type: Array, required: true },
  highlight: { type: Array, default: () => [] },
})

const { t } = useI18n()
const highlighted = computed(() => new Set(props.highlight))
</script>

<template>
  <ul class="flex flex-col gap-2">
    <li
      v-for="role in access"
      :key="qualify(role)"
      class="rounded-md border px-3 py-2"
      :class="highlighted.has(qualify(role)) ? 'border-brand' : 'border-border-subtle'"
      data-testid="access-role"
    >
      <div class="flex flex-wrap items-center justify-between gap-2">
        <div class="flex min-w-0 flex-wrap items-center gap-2">
          <span class="truncate text-sm font-medium">{{ role.name }}</span>
          <Badge tone="neutral">
            {{ role.source === 'client' ? `client · ${role.client}` : 'realm' }}
          </Badge>
          <Badge v-if="role.composite" tone="neutral">composite</Badge>
          <Badge v-if="role.administrative" tone="danger">administrative</Badge>
          <Badge v-if="highlighted.has(qualify(role))" tone="brand">new</Badge>
        </div>
        <span class="text-xs text-content-muted">
          {{ role.grants.length }} {{ role.grants.length === 1 ? 'reason' : 'reasons' }}
        </span>
      </div>

      <p v-if="role.description" class="mt-1 text-xs text-content-muted">{{ role.description }}</p>

      <details class="mt-2 border-t border-border-subtle pt-2">
        <summary class="cursor-pointer text-xs text-content-muted">{{ t('ux.whyAccess') }}</summary>
        <div class="mt-2"><GrantReasons :grants="role.grants" /></div>
      </details>
    </li>
  </ul>
</template>
