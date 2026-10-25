<script setup>
defineProps({ title: { type: String, default: '' } })
</script>

<template>
  <section class="rounded-lg border border-border-subtle bg-surface-raised p-5 shadow-sm">
    <h2 v-if="title" class="mb-3 text-sm font-semibold tracking-wide text-content-muted uppercase">
      {{ title }}
    </h2>
    <slot />
  </section>
</template>
