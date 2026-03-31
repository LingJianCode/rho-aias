import request from './request'
import type { ApiResponse, IntelStatus } from '@/types/api'

export function getIntelStatus(): Promise<ApiResponse<IntelStatus>> {
  return request.get('/api/intel/status').then((res) => res.data)
}

export function updateIntel(): Promise<ApiResponse<void>> {
  return request.post('/api/intel/update').then((res) => res.data)
}

// 注：后端不存在 /api/intel/clear-cache 接口，已移除
// 如需清空缓存功能，需后端先实现该接口
