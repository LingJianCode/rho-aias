import request from './request'
import type { ApiResponse } from '@/types/api'

export interface XdpEvent {
  id: string
  timestamp: string
  type: string
  data: Record<string, unknown>
}

export function getEvents(params?: { limit?: number }): Promise<ApiResponse<XdpEvent[]>> {
  return request.get('/api/events', { params }).then((res) => res.data)
}
