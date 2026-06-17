import http from '@/utils/http'
import type { EgressLogListResponse } from '@/types/api'

export interface EgressLogFilter {
  date: string
  start_hour?: number
  end_hour?: number
  page?: number
  page_size?: number
  src_ip?: string
  dst_ip?: string
  dst_port?: number
}

export function getEgressLogs(params: EgressLogFilter) {
  return http.get<EgressLogListResponse>({ url: '/api/egresslog/records', params })
}
