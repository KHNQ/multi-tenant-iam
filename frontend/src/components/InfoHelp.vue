<script setup>
import { computed, nextTick, ref } from 'vue'
import { Info, X } from 'lucide-vue-next'
import Button from '@/components/ui/Button.vue'
import { glossary } from '@/glossary.js'
import { useI18n } from '@/i18n.js'

const props = defineProps({
  topic: { type: String, required: true },
  context: { type: String, default: 'default' },
})
const { locale, t } = useI18n()
const dialog = ref(null)
const entry = computed(() => glossary[props.topic]?.[locale.value] ?? glossary[props.topic]?.en)
const triggerClass = computed(() => props.context === 'badge'
  ? 'size-5 text-white/90 hover:bg-white/15 hover:text-white focus-visible:ring-white'
  : 'size-7 text-content-muted hover:bg-surface hover:text-content focus-visible:ring-brand')
const iconClass = computed(() => props.context === 'badge' ? 'size-3.5' : 'size-4')

async function open() {
  await nextTick()
  if (typeof dialog.value?.showModal === 'function') dialog.value.showModal()
  else dialog.value?.setAttribute('open', '')
}

function close() {
  if (typeof dialog.value?.close === 'function') dialog.value.close()
  else dialog.value?.removeAttribute('open')
}
</script>

<template>
  <span v-if="entry" class="inline-flex align-middle">
    <button
      type="button"
      class="inline-flex items-center justify-center rounded-full focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-offset-1"
      :class="triggerClass"
      :aria-label="t('info.open', { term: entry.term })"
      @click="open"
    >
      <Info :class="iconClass" aria-hidden="true" />
    </button>
    <dialog
      ref="dialog"
      class="w-[min(32rem,calc(100vw-2rem))] rounded-lg border border-border-subtle bg-surface-raised p-0 text-content shadow-xl"
      :aria-labelledby="`info-${topic}-title`"
      @cancel.prevent="close"
    >
      <div class="border-b border-border-subtle px-5 py-4">
        <div class="flex items-center justify-between gap-4">
          <h2 :id="`info-${topic}-title`" class="text-lg font-semibold">{{ entry.term }}</h2>
          <button type="button" class="rounded-md p-1 text-content-muted hover:bg-surface" :aria-label="t('action.close')" @click="close">
            <X class="size-5" aria-hidden="true" />
          </button>
        </div>
      </div>
      <div class="space-y-4 px-5 py-4">
        <section>
          <h3 class="mb-1 text-xs font-semibold tracking-wide text-content-muted uppercase">{{ t('info.definition') }}</h3>
          <p class="text-sm leading-6">{{ entry.definition }}</p>
        </section>
        <section>
          <h3 class="mb-1 text-xs font-semibold tracking-wide text-content-muted uppercase">{{ t('info.example') }}</h3>
          <p class="text-sm leading-6 text-content-muted">{{ entry.example }}</p>
        </section>
      </div>
      <div class="flex justify-end border-t border-border-subtle px-5 py-4">
        <Button variant="outline" @click="close">{{ t('action.close') }}</Button>
      </div>
    </dialog>
  </span>
</template>
