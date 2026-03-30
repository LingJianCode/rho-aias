import request from './request'
import type { ApiResponse, PaginatedData, PaginationParams, AuditLog } from '@/types/api'

export interface GetAuditLogsParams extends PaginationParams {
  user?: string
  action?: string
  start_time?: string
  end_time?: string
}

export function getAuditLogs(params: GetAuditLogsParams): Promise<ApiResponse<PaginatedData<AuditLog>>> {
  return request.get('/api/audit/logs', { params }).then((res) => res.data)
}

export function clearAuditLogs(before?: string): Promise<ApiResponse<void>> {
  return request.delete('/api/audit/logs', { params: { before } }).then((res) => res.data)
}
