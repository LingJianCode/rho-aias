import http from '@/utils/http'
import type { ApiKeysResponse, CreateApiKeyResponse } from '@/types/api'

export interface ApiKey {
  id: number
  name: string
  key: string
  created_at: string
  last_used?: string
  expires_at?: string | null
}

export function getApiKeys() {
  return http.get<ApiKeysResponse>({ url: '/api/api-keys' })
}

export function createApiKey(data: { name: string; expires_at?: string }) {
  return http.post<CreateApiKeyResponse>({ url: '/api/api-keys', data })
}

export function deleteApiKey(id: number) {
  return http.del<void>({ url: `/api/api-keys/${id}` })
}
