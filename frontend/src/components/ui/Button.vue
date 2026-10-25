<script setup>
import { cva } from 'class-variance-authority'
import { computed } from 'vue'
import { cn } from '@/lib/utils.js'

const props = defineProps({
  variant: { type: String, default: 'default' },
  size: { type: String, default: 'default' },
  as: { type: String, default: 'button' },
  class: { type: String, default: '' },
})

const variants = cva(
  'inline-flex items-center justify-center gap-2 rounded-md font-medium ' +
  'transition-colors disabled:pointer-events-none disabled:opacity-50 ' +
  'focus-visible:outline-2 focus-visible:outline-offset-2',
  {
    variants: {
      variant: {
        default: 'bg-brand text-brand-content hover:opacity-90',
        outline: 'border border-border-subtle bg-surface-raised text-content hover:bg-surface',
        ghost: 'text-content hover:bg-surface',
        danger: 'bg-danger text-white hover:opacity-90',
      },
      size: {
        default: 'h-9 px-4 text-sm',
        sm: 'h-8 px-3 text-xs',
        lg: 'h-11 px-6 text-base',
      },
    },
    defaultVariants: { variant: 'default', size: 'default' },
  },
)

const classes = computed(() => cn(variants({ variant: props.variant, size: props.size }), props.class))
</script>

<template>
  <component :is="as" :class="classes">
    <slot />
  </component>
</template>
