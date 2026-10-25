import { createApp } from 'vue'
import App from '@/App.vue'
import { createAppRouter } from '@/router.js'
import { session } from '@/sessionState.js'
import { i18n, initializeLocale } from '@/i18n.js'
import '@/style.css'

initializeLocale()
createApp(App)
  .use(i18n)
  .use(createAppRouter(() => session.value))
  .mount('#app')
