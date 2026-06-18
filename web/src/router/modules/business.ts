import { AppRouteRecord } from '@/types/router'

/**
 * Rho Aias 业务路由
 * 包含安全态势、防火墙、日志、系统设置等模块
 */
export const businessRoutes: AppRouteRecord[] = [
  // 安全态势
  {
    path: '/security',
    name: 'Security',
    component: '/index/index',
    meta: {
      title: '安全态势',
      icon: 'ri:shield-check-line',
      roles: ['admin']
    },
    children: [
      {
        path: '',
        name: 'SecurityIndex',
        component: '/security/index',
        meta: {
          title: '安全态势',
          keepAlive: true,
          roles: ['admin']
        }
      }
    ]
  },

  // 防火墙管理
  {
    path: '/firewall',
    name: 'Firewall',
    component: '/index/index',
    meta: {
      title: '防火墙',
      icon: 'ri:fire-line',
      roles: ['admin']
    },
    children: [
      {
        path: 'blacklist',
        name: 'Blacklist',
        component: '/firewall/blacklist',
        meta: {
          title: '黑名单',
          keepAlive: true,
          roles: ['admin']
        }
      },
      {
        path: 'whitelist',
        name: 'Whitelist',
        component: '/firewall/whitelist',
        meta: {
          title: '白名单',
          keepAlive: true,
          roles: ['admin']
        }
      }
    ]
  },

  // 日志查询
  {
    path: '/record',
    name: 'Record',
    component: '/index/index',
    meta: {
      title: '日志记录',
      icon: 'ri:file-text-line',
      roles: ['admin']
    },
    children: [
      {
        path: 'blocklog',
        name: 'BlockLog',
        component: '/record/blocklog',
        meta: {
          title: '阻断日志',
          keepAlive: true,
          roles: ['admin']
        }
      },
      {
        path: 'egresslog',
        name: 'EgressLog',
        component: '/record/egresslog',
        meta: {
          title: 'Egress 日志',
          keepAlive: true,
          roles: ['admin']
        }
      },
      {
        path: 'ban-records',
        name: 'BanRecords',
        component: '/record/ban-records',
        meta: {
          title: '封禁记录',
          keepAlive: true,
          roles: ['admin']
        }
      }
    ]
  },

  // 系统设置
  {
    path: '/settings',
    name: 'Settings',
    component: '/index/index',
    meta: {
      title: '系统设置',
      icon: 'ri:settings-3-line',
      roles: ['admin']
    },
    children: [
      {
        path: 'config',
        name: 'Config',
        component: '/settings/config',
        meta: {
          title: '防护策略配置',
          roles: ['admin']
        }
      },
      {
        path: 'users',
        name: 'Users',
        component: '/system/user',
        meta: {
          title: '用户管理',
          roles: ['admin']
        }
      },
      {
        path: 'api-keys',
        name: 'ApiKeys',
        component: '/settings/api-keys',
        meta: {
          title: 'API Keys',
          roles: ['admin']
        }
      },
      {
        path: 'audit',
        name: 'Audit',
        component: '/system/audit',
        meta: {
          title: '审计日志',
          isHide: true,
          roles: ['admin']
        }
      }
    ]
  }
]
