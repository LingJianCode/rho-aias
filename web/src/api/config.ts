import request from './request'
import type { ApiResponse } from '@/types/api'

export interface GetAllConfigResponse {
  [module: string]: Record<string, unknown>
}

export function getAllConfig(): Promise<ApiResponse<GetAllConfigResponse>> {
  return request.get('/api/config').then((res) => res.data)
}

export function getModuleConfig(module: string): Promise<ApiResponse<Record<string, unknown>>> {
  return request.get(`/api/config/${module}`).then((res) => res.data)
}

export interface UpdateConfigParams {
  module: string
  data: Record<string, unknown>
}

export function updateModuleConfig(module: string, data: Record<string, unknown>): Promise<ApiResponse<void>> {
  return request.put(`/api/config/${module}`, data).then((res) => res.data)
}
