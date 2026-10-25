<script setup>
import { Languages } from 'lucide-vue-next'
import { useI18n } from '@/i18n.js'

const { locale, setLocale, t } = useI18n()
</script>

<template>
  <label class="flex items-center gap-2 text-sm text-content-muted">
    <Languages class="size-4" aria-hidden="true" />
    <span class="sr-only">{{ t('language.label') }}</span>
    <select
      :value="locale"
      :aria-label="t('language.label')"
      class="rounded-md border border-border-subtle bg-surface px-2 py-1 text-sm text-content"
      @change="setLocale($event.target.value)"
    >
      <option value="en">{{ t('language.en') }}</option>
      <option value="fa">{{ t('language.fa') }}</option>
    </select>
  </label>
</template>
