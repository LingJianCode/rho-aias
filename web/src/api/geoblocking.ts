import http from '@/utils/http'

export interface GeoBlockingStatus {
  enabled: boolean
  mode: 'whitelist' | 'blacklist'
  allowed_countries: string[]
  last_update: string
  total_rules: number
  sources: Record<string, any>
}

export function getGeoBlockingStatus() {
  return http.get<GeoBlockingStatus>({ url: '/api/geoblocking/status' })
}

export function triggerGeoBlockingUpdate() {
  return http.post({ url: '/api/geoblocking/update' })
}
