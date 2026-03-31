import request from './request'
import type { ApiResponse, IntelStatus } from '@/types/api'

export function getIntelStatus(): Promise<ApiResponse<IntelStatus>> {
  return request.get('/api/intel/status').then((res) => res.data)
}

export function updateIntel(): Promise<ApiResponse<void>> {
  return request.post('/api/intel/update').then((res) => res.data)
}

export function clearIntelCache(): Promise<ApiResponse<void>> {
  return request.post('/api/intel/clear-cache').then((res) => res.data)
}
