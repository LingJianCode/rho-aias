import http from '@/utils/http'

// 手动黑名单接口
export function getBlacklist() {
  return http.get<any>({ url: '/api/manual/blacklist/rules' })
}

export function addBlacklistRule(data: { value: string; remark?: string }) {
  return http.post({ url: '/api/manual/blacklist/rules', data })
}

export function deleteBlacklistRule(value: string) {
  return http.del({ url: `/api/manual/blacklist/rules/${value}` })
}

// 白名单接口
export function getWhitelist() {
  return http.get<any>({ url: '/api/whitelist/rules' })
}

export function addWhitelistRule(data: { value: string; remark?: string }) {
  return http.post({ url: '/api/whitelist/rules', data })
}

export function deleteWhitelistRule(value: string) {
  return http.del({ url: `/api/whitelist/rules/${value}` })
}
