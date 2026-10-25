<script setup>
import Alert from '@/components/ui/Alert.vue'
import { useI18n } from '@/i18n.js'
const { t } = useI18n()
</script>

<template>
  <h1 class="mb-5 text-2xl font-semibold">{{ t('forbidden.title') }}</h1>
  <Alert :title="t('forbidden.alert')">
    {{ t('forbidden.body') }}
  </Alert>
</template>
