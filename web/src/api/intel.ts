import http from '@/utils/http'
import type { IntelStatus } from '@/types/api'

export function getIntelStatus() {
  return http.get<IntelStatus>({ url: '/api/intel/status' })
}

export function triggerIntelUpdate() {
  return http.post<void>({ url: '/api/intel/update' })
}
