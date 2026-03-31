import request from './request'
import type { ApiResponse, SourcesStatusResponse } from '@/types/api'

export function getSourcesStatus(): Promise<ApiResponse<SourcesStatusResponse>> {
  return request.get('/api/sources/status').then((res) => res.data)
}

export function getSourceStatusByType(type: string): Promise<ApiResponse<Record<string, { id: number; source_type: string; source_id: string; source_name: string; status: string; rule_count: number; error_message: string; duration: number; updated_at: string }>>> {
  return request.get(`/api/sources/status/${type}`).then((res) => res.data)
}

export function refreshSource(type: string, id: string): Promise<ApiResponse<void>> {
  return request.post(`/api/sources/status/${type}/${id}/refresh`).then((res) => res.data)
}
