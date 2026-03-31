import request from './request'
import type { ApiResponse, SourcesStatusResponse } from '@/types/api'

export function getSourcesStatus(): Promise<ApiResponse<SourcesStatusResponse>> {
  return request.get('/api/sources/status').then((res) => res.data)
}

// 注：后端路由为 GET /api/sources/:type/status，但前端未使用此接口
// export function getSourceStatusByType(type: string) { ... }

export function refreshSource(type: string, id: string): Promise<ApiResponse<void>> {
  // 后端路由: POST /api/sources/:type/:id/refresh
  return request.post(`/api/sources/${type}/${id}/refresh`).then((res) => res.data)
}
