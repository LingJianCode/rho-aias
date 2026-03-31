import request from './request'
import type { ApiResponse, BanRecordListResponse, BanRecordStats, BanRecord } from '@/types/api'

export interface BanRecordFilter {
  page?: number
  page_size?: number
  ip?: string
  source?: string
  status?: string
  start_time?: string // 开始时间 (ISO 8601 格式)
  end_time?: string   // 结束时间 (ISO 8601 格式)
}

export function getBanRecords(params: BanRecordFilter): Promise<ApiResponse<BanRecordListResponse>> {
  // 将 page/page_size 转换为 limit/offset
  const limit = params.page_size || 20
  const offset = ((params.page || 1) - 1) * limit

  const backendParams = {
    ip: params.ip,
    source: params.source,
    status: params.status,
    start_time: params.start_time,
    end_time: params.end_time,
    limit,
    offset,
  }

  return request.get('/api/ban-records', { params: backendParams }).then((res) => res.data)
}

export function getBanRecord(id: number): Promise<ApiResponse<BanRecord>> {
  return request.get(`/api/ban-records/${id}`).then((res) => res.data)
}

export function getBanRecordStats(): Promise<ApiResponse<BanRecordStats>> {
  return request.get('/api/ban-records/stats').then((res) => res.data)
}
