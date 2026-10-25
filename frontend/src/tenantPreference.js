import { computed, ref, unref, watch } from 'vue'

const STORAGE_KEY = 'iam.tenant'

function storedTenant() {
  try { return localStorage.getItem(STORAGE_KEY) }
  catch { return null }
}

const preferredTenant = ref(storedTenant())

function remember(value) {
  preferredTenant.value = value
  try {
    if (value) localStorage.setItem(STORAGE_KEY, value)
    else localStorage.removeItem(STORAGE_KEY)
  } catch { /* preference remains available for this page lifetime */ }
}

export function useTenantPreference(availableTenants) {
  watch(
    () => unref(availableTenants) ?? [],
    (available) => {
      if (!available.includes(preferredTenant.value)) remember(available[0] ?? null)
    },
    { immediate: true },
  )

  return computed({
    get: () => preferredTenant.value,
    set: (value) => {
      const available = unref(availableTenants) ?? []
      if (available.includes(value)) remember(value)
    },
  })
}

export function setTenantPreference(value) {
  remember(value)
}
