import request from './request'
import type { ApiResponse, ApiKeysResponse, CreateApiKeyRequest, CreateApiKeyResponse } from '@/types/api'

export function getApiKeys(): Promise<ApiResponse<ApiKeysResponse>> {
  return request.get('/api/api-keys').then((res) => res.data)
}

export function createApiKey(data: CreateApiKeyRequest): Promise<ApiResponse<CreateApiKeyResponse>> {
  return request.post('/api/api-keys', data).then((res) => res.data)
}

export function revokeApiKey(id: number): Promise<ApiResponse<void>> {
  return request.delete(`/api/api-keys/${id}`).then((res) => res.data)
}
