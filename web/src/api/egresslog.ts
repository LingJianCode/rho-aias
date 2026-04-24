import request from './request'
import type { ApiResponse, EgressLogListResponse } from '@/types/api'

export interface EgressLogFilter {
  date: string
  start_hour?: number
  end_hour?: number
  dst_ip?: string
  page?: number
  page_size?: number
}

export function getEgressLogs(params: EgressLogFilter): Promise<ApiResponse<EgressLogListResponse>> {
  return request.get('/api/egresslog/records', { params }).then((res) => res.data)
}
