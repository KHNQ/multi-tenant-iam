<script setup>
/*
 * role="alert" so assistive technology announces failures without the user
 * having to discover them - part of the IAM-0207 error conventions.
 *
 * The comment lives here rather than in the template on purpose: a comment
 * beside the root element makes the component a fragment, which breaks
 * attribute inheritance.
 */
defineProps({
  tone: { type: String, default: 'danger' },
  title: { type: String, default: '' },
})
</script>

<template>
  <div
    role="alert"
    class="rounded-md border p-4 text-sm"
    :class="tone === 'danger'
      ? 'border-danger/40 bg-danger-surface text-danger'
      : 'border-border-subtle bg-surface text-content'"
  >
    <p v-if="title" class="mb-1 font-semibold">{{ title }}</p>
    <slot />
  </div>
</template>
