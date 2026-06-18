import http from '@/utils/http'
import type { ConfigModuleName } from '@/types/api'

export interface SystemConfig {
  [key: string]: unknown
}

/** 获取全部配置（兼容旧接口） */
export function getConfig() {
  return http.get<SystemConfig>({ url: '/api/config' })
}

/** 更新全部配置（兼容旧接口） */
export function updateConfig(data: Partial<SystemConfig>) {
  return http.put({ url: '/api/config', data })
}

/** 获取指定模块的配置 */
export function getModuleConfig(module: ConfigModuleName) {
  return http.get<Record<string, unknown>>({ url: `/api/config/${module}` })
}

/** 更新指定模块的配置 */
export function updateModuleConfig(module: ConfigModuleName, data: Record<string, unknown>) {
  return http.put({ url: `/api/config/${module}`, data })
}
