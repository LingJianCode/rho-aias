import request from './request'
import type { ApiResponse, AuditLogsResponse, AuditLog } from '@/types/api'

export interface GetAuditLogsParams {
  page?: number
  page_size?: number
  user_id?: number
  username?: string
  action?: string
  resource?: string
  status?: string
  start_time?: string
  end_time?: string
}

export function getAuditLogs(params: GetAuditLogsParams): Promise<ApiResponse<AuditLogsResponse>> {
  return request.get('/api/audit/logs', { params }).then((res) => res.data)
}

export function getAuditLog(id: number): Promise<ApiResponse<AuditLog>> {
  return request.get(`/api/audit/logs/${id}`).then((res) => res.data)
}

export function cleanAuditLogs(retentionDays: number): Promise<ApiResponse<void>> {
  return request.post('/api/audit/clean', { retention_days: retentionDays }).then((res) => res.data)
}
