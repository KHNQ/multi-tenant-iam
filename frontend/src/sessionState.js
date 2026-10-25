import { ref } from 'vue'

/** Single source of truth for the signed-in session, shared with the router guard. */
export const session = ref(null)
