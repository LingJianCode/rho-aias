import request from './request'
import type { ApiResponse, GeoBlockingStatus } from '@/types/api'

export function getGeoBlockingStatus(): Promise<ApiResponse<GeoBlockingStatus>> {
  return request.get('/api/geoblocking/status').then((res) => res.data)
}

export function triggerGeoBlockingUpdate(): Promise<ApiResponse<void>> {
  return request.post('/api/geoblocking/update').then((res) => res.data)
}
