<script setup>
/*
 * Every reason one role is held - all of them, always.
 *
 * This is the component the whole ticket turns on, so it does the one thing the
 * backend's projection was shaped to allow: it renders `grants[]` in full rather
 * than reducing it. A role held both directly and via /administrators shows two
 * rows, because removing only one of the two changes nothing, and a UI that
 * showed a single "direct" badge would actively mislead the person about to do
 * that.
 *
 * `via` is put on the same line as the origin rather than in a tooltip or a
 * detail drawer. "Inherited" without naming the group is the same unactionable
 * answer as a flat role list.
 */
import OriginBadge from '@/components/access/OriginBadge.vue'

defineProps({
  grants: { type: Array, required: true },
})

const labels = {
  direct: 'granted to this user',
  group: 'via group',
  composite: 'via composite role',
}
</script>

<template>
  <ul class="flex flex-col gap-1.5">
    <li
      v-for="(grant, index) in grants"
      :key="`${grant.origin}:${grant.via ?? ''}:${index}`"
      class="flex flex-wrap items-center gap-2 text-xs"
      data-testid="grant-reason"
    >
      <OriginBadge :origin="grant.origin" />
      <span class="text-content-muted">{{ labels[grant.origin] ?? 'via' }}</span>
      <code
        v-if="grant.via"
        class="rounded bg-surface px-1.5 py-0.5 font-mono text-content"
        data-testid="grant-via"
      >{{ grant.via }}</code>
    </li>
  </ul>
</template>
