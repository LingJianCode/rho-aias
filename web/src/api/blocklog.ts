import request from './request'
import type { ApiResponse, BlockLogListResponse, BlockLogStats, BlockedIPsResponse } from '@/types/api'

export interface BlockLogFilter {
  page?: number
  page_size?: number
  start_time?: string
  end_time?: string
  ip?: string
  source?: string
}

export function getBlockLogs(params: BlockLogFilter): Promise<ApiResponse<BlockLogListResponse>> {
  return request.get('/api/blocklog/records', { params }).then((res) => res.data)
}

export function getBlockLogStats(): Promise<ApiResponse<BlockLogStats>> {
  return request.get('/api/blocklog/stats').then((res) => res.data)
}

export function getBlockedIPs(limit?: number): Promise<ApiResponse<BlockedIPsResponse>> {
  return request.get('/api/blocklog/blocked-ips', { params: { limit } }).then((res) => res.data)
}

export function getBlockedCountries(limit?: number): Promise<ApiResponse<{ total_blocked_countries: number; top_blocked_countries: { country: string; count: number }[] }>> {
  return request.get('/api/blocklog/blocked-countries', { params: { limit } }).then((res) => res.data)
}

export function clearBlockLogs(): Promise<ApiResponse<void>> {
  return request.delete('/api/blocklog/records').then((res) => res.data)
}
