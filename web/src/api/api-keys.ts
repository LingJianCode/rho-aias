import request from './request'
import type { ApiResponse, PaginatedData, PaginationParams, ApiKey, CreateApiKeyRequest, CreateApiKeyResponse } from '@/types/api'

export function getApiKeys(params: PaginationParams): Promise<ApiResponse<PaginatedData<ApiKey>>> {
  return request.get('/api/api-keys', { params }).then((res) => res.data)
}

export function createApiKey(data: CreateApiKeyRequest): Promise<ApiResponse<CreateApiKeyResponse>> {
  return request.post('/api/api-keys', data).then((res) => res.data)
}

export function revokeApiKey(id: string): Promise<ApiResponse<void>> {
  return request.delete(`/api/api-keys/${id}`).then((res) => res.data)
}
