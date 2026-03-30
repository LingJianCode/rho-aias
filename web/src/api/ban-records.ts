import request from './request'
import type { ApiResponse, PaginatedData, PaginationParams, BanRecord, BanRecordStats } from '@/types/api'

export function getBanRecords(params: PaginationParams): Promise<ApiResponse<PaginatedData<BanRecord>>> {
  return request.get('/api/ban-records', { params }).then((res) => res.data)
}

export function getBanRecordStats(): Promise<ApiResponse<BanRecordStats>> {
  return request.get('/api/ban-records/stats').then((res) => res.data)
}
