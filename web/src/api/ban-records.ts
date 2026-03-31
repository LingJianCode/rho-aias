import request from './request'
import type { ApiResponse, BanRecordListResponse, BanRecordStats, BanRecord } from '@/types/api'

export interface BanRecordFilter {
  page?: number
  page_size?: number
  ip?: string
  source?: string
  status?: string
}

export function getBanRecords(params: BanRecordFilter): Promise<ApiResponse<BanRecordListResponse>> {
  return request.get('/api/ban-records', { params }).then((res) => res.data)
}

export function getBanRecord(id: number): Promise<ApiResponse<BanRecord>> {
  return request.get(`/api/ban-records/${id}`).then((res) => res.data)
}

export function getBanRecordStats(): Promise<ApiResponse<BanRecordStats>> {
  return request.get('/api/ban-records/stats').then((res) => res.data)
}
