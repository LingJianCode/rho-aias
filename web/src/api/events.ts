import request from './request'
import type { ApiResponse, EventStatus, EventConfigRequest } from '@/types/api'

export function getEventStatus(): Promise<ApiResponse<EventStatus>> {
  return request.get('/api/xdp/events/status').then((res) => res.data)
}
