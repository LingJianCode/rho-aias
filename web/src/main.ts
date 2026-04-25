import { createApp } from 'vue'
import { createPinia } from 'pinia'

import * as ElementPlusIconsVue from '@element-plus/icons-vue'

import App from './App.vue'
import router from './router'
import './styles/variables.scss'
import './styles/dark.scss'
import './styles/global.scss'

const userAgent = navigator.userAgent
const isEdge = /Edg\//.test(userAgent)

if (isEdge) {
  const rawReplaceState = window.history.replaceState.bind(window.history)
  const rawPushState = window.history.pushState.bind(window.history)

  const shouldSkipHistoryStateUpdate = (state: unknown): boolean => {
    return document.visibilityState === 'hidden' && state != null
  }

  window.history.replaceState = function (
    state: unknown,
    unused: string,
    url?: string | URL | null
  ): void {
    if (shouldSkipHistoryStateUpdate(state)) return
    rawReplaceState(state, unused, url)
  }

  window.history.pushState = function (
    state: unknown,
    unused: string,
    url?: string | URL | null
  ): void {
    if (shouldSkipHistoryStateUpdate(state)) return
    rawPushState(state, unused, url)
  }
}

const app = createApp(App)

// Register Element Plus icons
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component)
}

app.use(createPinia())
app.use(router)

app.mount('#app')
