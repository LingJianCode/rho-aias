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
      
      // 安全态势（只读监控）
      { path: 'security', name: 'Security', component: () => import('@/views/security/SecurityView.vue') },

      // 防火墙
      { path: 'firewall/blacklist', name: 'Blacklist', component: () => import('@/views/firewall/BlacklistView.vue') },
      { path: 'firewall/whitelist', name: 'Whitelist', component: () => import('@/views/firewall/WhitelistView.vue') },

      // 日志
      { path: 'logs/blocklog', name: 'BlockLog', component: () => import('@/views/blocklog/BlockLogView.vue') },
      { path: 'logs/egresslog', name: 'EgressLog', component: () => import('@/views/egresslog/EgressLogView.vue') },
      { path: 'logs/ban-records', name: 'BanRecords', component: () => import('@/views/ban-records/BanRecordsView.vue') },



      // 系统设置
      { path: 'settings', redirect: '/settings/config' },
      { path: 'settings/config', name: 'Config', component: () => import('@/views/settings/ConfigPanel.vue'), meta: { title: '防护策略配置', requiresAdmin: true } },
      { path: 'settings/users', name: 'Users', component: () => import('@/views/settings/UsersView.vue'), meta: { title: '用户管理', requiresAdmin: true } },
      { path: 'settings/api-keys', name: 'ApiKeys', component: () => import('@/views/settings/ApiKeysView.vue'), meta: { title: 'API Keys', requiresAdmin: true } },
      { path: 'settings/audit', name: 'Audit', component: () => import('@/views/settings/AuditPanel.vue'), meta: { title: '审计日志', requiresAdmin: true } },
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
