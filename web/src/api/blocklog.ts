import request from './request'
import type { ApiResponse, PaginatedData, PaginationParams, BlockLog, BlockLogStats } from '@/types/api'

export interface GetBlockLogParams extends PaginationParams {
  start_time?: string
  end_time?: string
  source?: string
  ip?: string
}

export function getBlockLogs(params: GetBlockLogParams): Promise<ApiResponse<PaginatedData<BlockLog>>> {
  return request.get('/api/blocklog/records', { params }).then((res) => res.data)
}

export function getBlockLogStats(params?: { start_time?: string; end_time?: string }): Promise<ApiResponse<BlockLogStats>> {
  return request.get('/api/blocklog/stats', { params }).then((res) => res.data)
}

export function getBlockedIps(params?: PaginationParams): Promise<ApiResponse<PaginatedData<{ ip: string; count: number }>>> {
  return request.get('/api/blocklog/blocked-ips', { params }).then((res) => res.data)
}

export function clearBlockLogs(): Promise<ApiResponse<void>> {
  return request.delete('/api/blocklog/records').then((res) => res.data)
}
