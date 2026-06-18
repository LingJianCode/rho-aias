import { AppRouteRecord } from '@/types/router'

export const dashboardRoutes: AppRouteRecord = {
  name: 'Dashboard',
  path: '/dashboard',
  component: '/dashboard/index',
  meta: {
    title: 'menus.dashboard.title',
    icon: 'ri:pie-chart-line',
    keepAlive: false,
    fixedTab: true,
    roles: ['admin']
  }
}
