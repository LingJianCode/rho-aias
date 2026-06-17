import http from '@/utils/http'
import type { GeoBlockingStatus, IntelSourceDetail } from '@/types/api'

export function getGeoBlockingStatus() {
  return http.get<GeoBlockingStatus>({ url: '/api/geoblocking/status' })
}

export function triggerGeoBlockingUpdate() {
  return http.post<void>({ url: '/api/geoblocking/update' })
}
