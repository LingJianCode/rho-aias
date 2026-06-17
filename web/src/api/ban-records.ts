import http from '@/utils/http'
import type { BanRecordListResponse, BanRecordStats } from '@/types/api'

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
  return http.get<BanRecordListResponse>({ url: '/api/ban-records', params })
}

export function unblockBanRecord(id: number) {
  return http.post<void>({ url: `/api/ban-records/${id}/unblock` })
}

export function getBanRecordStats() {
  return http.get<BanRecordStats>({ url: '/api/ban-records/stats' })
}
