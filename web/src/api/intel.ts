import http from '@/utils/http'

export interface IntelStatus {
  enabled: boolean
  last_update: string
  total_rules: number
  sources: Record<string, any>
}

export function getIntelStatus() {
  return http.get<IntelStatus>({ url: '/api/intel/status' })
}

export function triggerIntelUpdate() {
  return http.post({ url: '/api/intel/update' })
}
