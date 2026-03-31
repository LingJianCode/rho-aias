import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const routes: RouteRecordRaw[] = [
  {
    path: '/login',
    name: 'Login',
    component: () => import('@/views/login/LoginView.vue'),
    meta: { requiresAuth: false },
  },
  {
    path: '/',
    component: () => import('@/layouts/DefaultLayout.vue'),
    meta: { requiresAuth: true },
    children: [
      { path: '', redirect: '/dashboard' },
      { path: 'dashboard', name: 'Dashboard', component: () => import('@/views/dashboard/DashboardView.vue') },
      { path: 'firewall/blacklist', name: 'Blacklist', component: () => import('@/views/firewall/BlacklistView.vue') },
      { path: 'firewall/whitelist', name: 'Whitelist', component: () => import('@/views/firewall/WhitelistView.vue') },
      { path: 'blocklog', name: 'BlockLog', component: () => import('@/views/blocklog/BlockLogView.vue') },
      { path: 'ban-records', name: 'BanRecords', component: () => import('@/views/ban-records/BanRecordsView.vue') },
      { path: 'sources', name: 'Sources', component: () => import('@/views/sources/SourcesView.vue') },
      { path: 'intel', name: 'Intel', component: () => import('@/views/intel/IntelView.vue') },
      { path: 'geoblocking', name: 'GeoBlocking', component: () => import('@/views/geoblocking/GeoBlockingView.vue') },
      { path: 'settings/users', name: 'Users', component: () => import('@/views/settings/UsersView.vue'), meta: { requiresAdmin: true } },
      { path: 'settings/api-keys', name: 'ApiKeys', component: () => import('@/views/settings/ApiKeysView.vue') },
      { path: 'settings/audit', name: 'Audit', component: () => import('@/views/settings/AuditView.vue') },
    ],
  },
  { path: '/403', name: 'Forbidden', component: () => import('@/views/error/403.vue') },
  { path: '/:pathMatch(.*)*', name: 'NotFound', component: () => import('@/views/error/404.vue') },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore()

  if (to.meta.requiresAuth !== false && !authStore.isLoggedIn) {
    next({ name: 'Login', query: { redirect: to.fullPath } })
    return
  }

  if (to.meta.requiresAdmin && !authStore.isAdmin) {
    next({ name: 'Forbidden' })
    return
  }

  if (to.name === 'Login' && authStore.isLoggedIn) {
    next({ name: 'Dashboard' })
    return
  }

  next()
})

export default router
