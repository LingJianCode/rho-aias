import http from '@/utils/http'

export interface BanRecord {
  id: number
  ip: string
  reason: string
  source: string
  status: string
  created_at: string
  expires_at: string | null
  duration: number
}

export function getBanRecords(params: { page: number; page_size: number; source?: string; status?: string }) {
  return http.get<any>({ url: '/api/ban-records', params })
}

export function unblockBanRecord(id: number) {
  return http.post({ url: `/api/ban-records/${id}/unblock` })
}
