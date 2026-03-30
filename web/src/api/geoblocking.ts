import request from './request'
import type { ApiResponse, GeoBlockingConfig } from '@/types/api'

export function getGeoBlockingStatus(): Promise<ApiResponse<GeoBlockingConfig>> {
  return request.get('/api/geoblocking/status').then((res) => res.data)
}

export function updateGeoBlockingConfig(data: GeoBlockingConfig): Promise<ApiResponse<void>> {
  return request.post('/api/geoblocking/config', data).then((res) => res.data)
}
