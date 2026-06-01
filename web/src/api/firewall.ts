import http from '@/utils/http'

// 手动黑名单接口
export function getBlacklist() {
  return http.get<any>({ url: '/api/manual/blacklist' })
}

export function addBlacklistRule(data: { value: string; remark?: string }) {
  return http.post({ url: '/api/manual/blacklist', data })
}

export function deleteBlacklistRule(value: string) {
  return http.del({ url: `/api/manual/blacklist/${value}` })
}

// 白名单接口
export function getWhitelist() {
  return http.get<any>({ url: '/api/whitelist' })
}

export function addWhitelistRule(data: { value: string; remark?: string }) {
  return http.post({ url: '/api/whitelist', data })
}

export function deleteWhitelistRule(value: string) {
  return http.del({ url: `/api/whitelist/${value}` })
}
