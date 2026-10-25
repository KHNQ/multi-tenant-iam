<script setup>
import Card from '@/components/ui/Card.vue'

defineProps({
  title: { type: String, required: true },
  ticket: { type: String, required: true },
})
</script>

<template>
  <h1 class="mb-5 text-2xl font-semibold">{{ title }}</h1>
  <Card>
    <p class="text-sm text-content-muted">
      This area is delivered by {{ ticket }}. The navigation, guards and shell are in place;
      the administrative surface itself arrives with the Keycloak adapter.
    </p>
  </Card>
</template>
