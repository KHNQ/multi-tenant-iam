<script setup>
defineProps({ items: { type: Array, required: true } })
</script>

<template>
  <dl class="grid gap-3 sm:grid-cols-2">
    <div v-for="item in items" :key="item.label" class="flex flex-col gap-1">
      <dt class="text-xs font-medium tracking-wide text-content-muted uppercase">{{ item.label }}</dt>
      <dd class="text-sm text-content">
        <slot :name="item.label" :item="item">{{ item.value }}</slot>
      </dd>
    </div>
  </dl>
</template>
