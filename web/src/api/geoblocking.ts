import request from './request'
import type { ApiResponse, GeoBlockingStatus, GeoBlockingConfigRequest } from '@/types/api'

export function getGeoBlockingStatus(): Promise<ApiResponse<GeoBlockingStatus>> {
  return request.get('/api/geoblocking/status').then((res) => res.data)
}

export function updateGeoBlockingConfig(data: GeoBlockingConfigRequest): Promise<ApiResponse<void>> {
  return request.post('/api/geoblocking/config', data).then((res) => res.data)
}

export function triggerGeoBlockingUpdate(): Promise<ApiResponse<void>> {
  return request.post('/api/geoblocking/update').then((res) => res.data)
}
