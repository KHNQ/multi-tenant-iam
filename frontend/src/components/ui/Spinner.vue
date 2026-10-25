<template>
  <p class="flex items-center gap-2 text-sm text-content-muted" role="status" aria-live="polite">
    <span
      class="size-4 animate-spin rounded-full border-2 border-current border-t-transparent"
      aria-hidden="true"
    />
    <slot>Loading…</slot>
  </p>
</template>
