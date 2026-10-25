<script setup>
/*
 * IAM-0217: the one and only time a client secret is ever on screen.
 *
 * This component is the user-facing half of the "shown once and never returned
 * again" criterion, and the design rule it follows is that the interface must not
 * imply a second chance that does not exist. Someone who closes this panel assuming
 * they can find the value again later will come back to a client that cannot
 * authenticate, and the only remedy - rotation - breaks whatever is already using
 * it. So the warning is stated before the value, in plain words, and dismissal is
 * an explicit acknowledgement rather than an X in a corner.
 *
 * What this component does NOT do is as much of the point as what it does:
 *
 *  - it never writes the secret to localStorage, sessionStorage, a cookie, the URL
 *    or the document title. Anything persisted is recoverable later by definition,
 *    which is precisely the property the criterion denies;
 *  - it holds the value in one prop and emits `dismiss` rather than keeping its own
 *    copy, so there is exactly one place the parent must clear;
 *  - it is not collapsible or re-openable. A panel that can be reopened has to keep
 *    the value somewhere to reopen with.
 *
 * The value is rendered as text in a <code> block rather than an <input>: a form
 * field would be captured by a browser's form-restore and password manager
 * heuristics, and would be repopulated on a back-navigation.
 */
import { ref } from 'vue'
import Alert from '@/components/ui/Alert.vue'
import Button from '@/components/ui/Button.vue'
import { useI18n } from '@/i18n.js'

const props = defineProps({
  clientId: { type: String, required: true },
  secret: { type: String, required: true },
  /** Distinguishes a brand-new client from a rotation, which invalidated a live credential. */
  rotated: { type: Boolean, default: false },
})

const emit = defineEmits(['dismiss'])
const { t } = useI18n()

const copied = ref(false)
const copyFailed = ref(false)

async function copy() {
  copyFailed.value = false
  try {
    await navigator.clipboard.writeText(props.secret)
    copied.value = true
  } catch {
    // Clipboard access can be refused, and silently "succeeding" would be the
    // worst outcome: the operator dismisses the panel believing they have it.
    copyFailed.value = true
  }
}

/** Acknowledged. The parent drops the value; nothing here retains a copy. */
function acknowledge() {
  emit('dismiss')
}
</script>

<template>
  <section
    data-testid="secret-once"
    aria-labelledby="secret-once-heading"
    class="rounded-lg border-2 border-danger/60 bg-danger-surface p-5"
  >
    <h2 id="secret-once-heading" class="mb-2 text-base font-semibold text-danger">
      {{ t(rotated ? 'secret.newFor' : 'secret.for', { client: clientId }) }}
    </h2>

    <Alert tone="danger" class="mb-4">
      <p class="font-semibold">
        {{ t('secret.copyNow') }}
      </p>
      <p class="mt-1">
        {{ t('secret.storage') }}
        <template v-if="rotated">
          {{ t('secret.rotated') }}
        </template>
        <template v-else>
          {{ t('secret.lost') }}
        </template>
      </p>
    </Alert>

    <p class="mb-1 text-xs font-medium tracking-wide text-content-muted uppercase">
      {{ t('secret.label') }}
    </p>
    <!--
      Plain text, deliberately, not an <input>. A form field gets captured by
      browser form-restore and password-manager heuristics, which would put the
      value somewhere this console cannot reach or clear.
    -->
    <code
      data-testid="secret-value"
      class="mb-4 block overflow-x-auto rounded-md bg-surface px-3 py-2 font-mono text-sm
             break-all text-content select-all"
      >{{ secret }}</code
    >

    <div class="flex flex-wrap items-center gap-3">
      <Button variant="outline" size="sm" @click="copy">{{ t('secret.copy') }}</Button>
      <span v-if="copied" role="status" class="text-sm text-content-muted">
        {{ t('secret.copiedHelp') }}
      </span>
      <span v-if="copyFailed" role="status" class="text-sm text-danger">
        {{ t('secret.copyFailed') }}
      </span>
    </div>

    <div class="mt-4 border-t border-border-subtle pt-4">
      <!--
        An explicit acknowledgement, not a dismissal X. The wording is the last
        chance to stop someone closing this without having stored the value.
      -->
      <Button data-testid="secret-dismiss" @click="acknowledge">
        {{ t('secret.acknowledge') }}
      </Button>
    </div>
  </section>
</template>
