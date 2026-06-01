import http from '@/utils/http'

export interface SystemConfig {
  // 系统配置结构
  [key: string]: any
}

export function getConfig() {
  return http.get<SystemConfig>({ url: '/api/config' })
}

export function updateConfig(data: Partial<SystemConfig>) {
  return http.put({ url: '/api/config', data })
}
