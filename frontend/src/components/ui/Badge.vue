<script setup>
import { computed } from 'vue'
import { cn } from '@/lib/utils.js'

const props = defineProps({
  tone: { type: String, default: 'neutral' },
  class: { type: String, default: '' },
})

const tones = {
  neutral: 'border-border-subtle text-content-muted',
  success: 'border-transparent bg-success text-white',
  danger: 'border-transparent bg-danger text-white',
  brand: 'border-transparent bg-brand text-brand-content',
}

const classes = computed(() =>
  cn('inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium',
     tones[props.tone] ?? tones.neutral, props.class))
</script>

<template>
  <span :class="classes"><slot /></span>
</template>
