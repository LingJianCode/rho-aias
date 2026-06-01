import http from '@/utils/http'

export interface BlockLogFilter {
  date: string
  start_hour?: number
  end_hour?: number
  page?: number
  page_size?: number
  match_type?: string
  rule_source?: string
  src_ip?: string
  country_code?: string
}

export interface BlockLogListResponse {
  records: any[]
  total: number
}

export interface BlockLogStats {
  // 统计数据结构
  [key: string]: any
}

export function getBlockLogs(params: BlockLogFilter) {
  return http.get<any>({ url: '/api/blocklog/records', params })
}

export function getBlockLogStats() {
  return http.get<any>({ url: '/api/blocklog/stats' })
}

export function getHourlyTrend(hours?: number) {
  return http.get<any>({ url: '/api/blocklog/hourly-trend', params: { hours } })
}

export function getBlockedTopIPs(limit?: number) {
  return http.get<any>({ url: '/api/blocklog/blocked-top-ips', params: { limit } })
}

export function getBlockLogEventStatus() {
  return http.get<any>({ url: '/api/blocklog/event-status' })
}
