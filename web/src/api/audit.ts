import http from '@/utils/http'
import type { AuditLogsResponse } from '@/types/api'

export interface AuditLog {
  id: number
  user_id: number
  username: string
  action: string
  target_type: string
  target_id?: string
  details: string
  ip: string
  created_at: string
}

export function getAuditLogs(params: { page: number; page_size: number; action?: string; user_id?: number }) {
  return http.get<AuditLogsResponse>({ url: '/api/audit/logs', params })
}
