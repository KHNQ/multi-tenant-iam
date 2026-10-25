import { computed } from 'vue'
import { session } from '@/sessionState.js'

/**
 * True while the console runs against the standby (failover) system. The
 * primary system owns the data then, so editing controls are disabled and a
 * banner says where changes belong. The server refuses those changes anyway
 * (standby_read_only); this only avoids offering them.
 *
 * Ending sessions and locking an account in an emergency stay available, as
 * does issuing this system's own client secrets.
 */
export const standby = computed(() => session.value?.mode === 'standby')
