import http from '@/utils/http'
import type { BlacklistResponse, WhitelistResponse } from '@/types/api'

// 手动黑名单接口
export function getBlacklist() {
  return http.get<BlacklistResponse>({ url: '/api/manual/blacklist/rules' })
}

export function addBlacklistRule(data: { value: string; remark?: string }) {
  return http.post<void>({ url: '/api/manual/blacklist/rules', data })
}

export function deleteBlacklistRule(value: string) {
  return http.del<void>({ url: '/api/manual/blacklist/rules', data: { value } })
}

// 白名单接口
export function getWhitelist() {
  return http.get<WhitelistResponse>({ url: '/api/manual/whitelist/rules' })
}

export function addWhitelistRule(data: { value: string; remark?: string }) {
  return http.post<void>({ url: '/api/manual/whitelist/rules', data })
}

export function deleteWhitelistRule(value: string) {
  return http.del<void>({ url: '/api/manual/whitelist/rules', data: { value } })
}
