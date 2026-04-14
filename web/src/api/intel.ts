import request from './request'
import type { ApiResponse, IntelStatus } from '@/types/api'

export function getIntelStatus(): Promise<ApiResponse<IntelStatus>> {
  return request.get('/api/intel/status').then((res) => res.data)
}
