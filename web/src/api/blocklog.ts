import request from './request'
import type { ApiResponse, BlockLogListResponse, BlockLogStats, BlockLogEventStatus } from '@/types/api'

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

export function getBlockLogs(params: BlockLogFilter): Promise<ApiResponse<BlockLogListResponse>> {
  return request.get('/api/blocklog/records', { params }).then((res) => res.data)
}

export function getBlockLogStats(): Promise<ApiResponse<BlockLogStats>> {
  return request.get('/api/blocklog/stats').then((res) => res.data)
}

export function getHourlyTrend(hours?: number): Promise<ApiResponse<{ hours: number; hourly_data: { hour: string; total: number; breakdown: Record<string, number> }[] }>> {
  return request.get('/api/blocklog/hourly-trend', { params: { hours } }).then((res) => res.data)
}

export function getBlockedTopIPs(limit?: number): Promise<ApiResponse<{ top_blocked_ips: { ip: string; count: number }[] }>> {
  return request.get('/api/blocklog/blocked-top-ips', { params: { limit } }).then((res) => res.data)
}

export function getBlockLogEventStatus(): Promise<ApiResponse<BlockLogEventStatus>> {
  return request.get('/api/blocklog/event-status').then((res) => res.data)
}
