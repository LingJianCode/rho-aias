import http from '@/utils/http'
import type { BlockLog, BlockLogListResponse, BlockLogStats } from '@/types/api'

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

export function getBlockLogs(params: BlockLogFilter) {
  return http.get<BlockLogListResponse>({ url: '/api/blocklog/records', params })
}

export function getBlockLogStats() {
  return http.get<BlockLogStats>({ url: '/api/blocklog/stats' })
}

export function getHourlyTrend(hours?: number) {
  return http.get<{ data?: { hourly_data?: { hour: string; total: number }[] } }>({ url: '/api/blocklog/hourly-trend', params: { hours } })
}

export function getBlockedTopIPs(limit?: number) {
  return http.get<{ data?: { top_blocked_ips?: { ip: string; count: number }[] } }>({ url: '/api/blocklog/blocked-top-ips', params: { limit } })
}

export function getBlockLogEventStatus() {
  return http.get<{ enabled: boolean; sample_rate: number }>({ url: '/api/blocklog/event-status' })
}
