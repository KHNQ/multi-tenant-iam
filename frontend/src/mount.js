/**
 * Microfrontend entry, exposed to Module Federation hosts as `./mount`.
 *
 * The contract is framework-neutral so a React, Vue or Angular host can load it:
 *   mount(element, props)  - render into `element` (normally inside the host's shadow root)
 *   update(element, props) - accept new props from the host
 *   unmount(element)       - tear down everything mount() created
 *
 * Props (all optional):
 *   apiBase      path under which the host proxies the BFF (default '/iam'); it must be
 *                on the host's own origin, or the HttpOnly session cookie is never sent
 *   initialPath  route to open first (default '/')
 *   locale       'en' | 'fa'; otherwise the stored preference
 *   returnTo     host path to come back to after login/logout (default: current path)
 *   autoSignIn   start the console's login immediately when signed out (default true)
 *
 * Routing uses memory history: the host owns the address bar, and a second router
 * writing to it would fight the host's.
 */
import { createApp } from 'vue'
import { createMemoryHistory } from 'vue-router'
import App from '@/App.vue'
import { createAppRouter } from '@/router.js'
import { session } from '@/sessionState.js'
import { i18n, initializeLocale, setLocale, setLocaleRoot } from '@/i18n.js'
import { setApiBase, setAutoSignIn, setReturnTo } from '@/config.js'
import { embedded, applyHostAppearance, clearHostAppearance } from '@/embedded.js'
import cssText from '@/style.css?inline'

const DEFAULT_API_BASE = '/iam'
const instances = new WeakMap()

/**
 * Tailwind v4 declares its internal variables with @property, which browsers ignore
 * inside a shadow root. Registered once on the document, they apply everywhere; the
 * rules only declare variable types and initial values, so they cannot restyle the host.
 */
function registerCssProperties() {
  if (document.querySelector('style[data-iam-properties]')) return
  const rules = cssText.match(/@property[^{]+\{[^}]*\}/g)
  if (!rules) return
  const style = document.createElement('style')
  style.dataset.iamProperties = ''
  style.textContent = rules.join('\n')
  document.head.appendChild(style)
}

function injectStyles(element) {
  const root = element.getRootNode()
  const style = document.createElement('style')
  style.dataset.iamStyles = ''
  style.textContent = cssText
  // Outside a shadow root the styles would leak into the host, so they go next to us.
  if (root instanceof ShadowRoot) {
    root.prepend(style)
  } else {
    element.before(style)
  }
  return style
}

export function mount(element, props = {}) {
  if (instances.has(element)) unmount(element)

  setApiBase(props.apiBase ?? DEFAULT_API_BASE)
  setReturnTo(props.returnTo ?? `${window.location.pathname}${window.location.search}${window.location.hash}`)
  setAutoSignIn(props.autoSignIn ?? true)
  registerCssProperties()
  const style = injectStyles(element)

  embedded.enabled = props.embedded !== false
  element.setAttribute('data-iam-embedded', String(embedded.enabled))
  element.setAttribute('data-iam-root', '')
  applyHostAppearance(element, props)
  setLocaleRoot(element)
  if (props.locale) setLocale(props.locale)
  else initializeLocale()

  const router = createAppRouter(() => session.value, { history: createMemoryHistory() })
  const state = { app: null, style, router, onNavigate: props.onNavigate }
  const stopNavigation = router.afterEach((to, _from, failure) => {
    if (!failure) state.onNavigate?.(to.fullPath)
  })
  state.stopNavigation = stopNavigation
  const app = createApp(App).use(i18n).use(router)
  router.push(props.initialPath ?? '/')
  app.mount(element)
  state.app = app
  instances.set(element, state)
}

export function update(element, props = {}) {
  const instance = instances.get(element)
  if (!instance) return
  applyHostAppearance(element, props)
  if ('onNavigate' in props) instance.onNavigate = props.onNavigate
  if (props.initialPath && props.initialPath !== instance.router.currentRoute.value.fullPath) {
    instance.router.replace(props.initialPath)
  }
  if (props.locale) setLocale(props.locale)
}

export function unmount(element) {
  const instance = instances.get(element)
  if (!instance) return
  instance.stopNavigation()
  instance.app.unmount()
  embedded.enabled = false
  clearHostAppearance(element)
  element.removeAttribute('data-iam-embedded')
  instance.style.remove()
  element.removeAttribute('data-iam-root')
  setLocaleRoot(null)
  setApiBase('')
  setReturnTo(null)
  setAutoSignIn(false)
  instances.delete(element)
}

export default { mount, update, unmount }
