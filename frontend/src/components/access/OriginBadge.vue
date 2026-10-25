<script setup>
/*
 * One grant's origin, made legible at a glance.
 *
 * Three decisions worth stating:
 *
 * 1. The origin word is always spelled out. Colour is never the only carrier -
 *    that is both a WCAG requirement and, here, a safety one: "direct" and
 *    "composite" have different remedies and a colour-blind reviewer must not be
 *    the one who confuses them.
 * 2. No new colour token was introduced. The IAM-0207 palette is measured by
 *    contrast.spec.js, and the pairs that are already proven are the ones used;
 *    the three origins are separated by fill, border and icon instead.
 * 3. Comments live in the script block. A comment beside the root element makes
 *    the component a fragment and silently breaks attribute inheritance.
 */
import { GitBranch, User, Users } from 'lucide-vue-next'
import { computed } from 'vue'
import { cn } from '@/lib/utils.js'

const props = defineProps({
  origin: { type: String, required: true },
  class: { type: String, default: '' },
})

const styles = {
  // Granted to this person. Filled, because it is the only one they can revoke
  // by touching this user alone.
  direct: { icon: User, class: 'border-transparent bg-brand text-brand-content' },
  // Inherited from a group; the remedy is a membership or the group's mapping.
  group: { icon: Users, class: 'border-border-subtle text-content' },
  // Arrived through a composite edge somebody else cut.
  composite: { icon: GitBranch, class: 'border-content-muted border-dashed text-content' },
}

const style = computed(() => styles[props.origin] ?? styles.composite)

const classes = computed(() =>
  cn('inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium',
     style.value.class, props.class))
</script>

<template>
  <span :class="classes">
    <component :is="style.icon" class="size-3" aria-hidden="true" />
    {{ origin }}
  </span>
</template>
