import request from './request'
import type { ApiResponse, DataSource } from '@/types/api'

export function getSourcesStatus(): Promise<ApiResponse<DataSource[]>> {
  return request.get('/api/sources/status').then((res) => res.data)
}

export function refreshSource(type: string, id: string): Promise<ApiResponse<void>> {
  return request.post(`/api/sources/${type}/${id}/refresh`).then((res) => res.data)
}
