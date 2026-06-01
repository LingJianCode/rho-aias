import http from '@/utils/http'

export interface ApiKey {
  id: number
  name: string
  key: string
  created_at: string
  last_used?: string
  expires_at?: string | null
}

export function getApiKeys() {
  return http.get<any>({ url: '/api/api-keys' })
}

export function createApiKey(data: { name: string; expires_at?: string }) {
  return http.post({ url: '/api/api-keys', data })
}

export function deleteApiKey(id: number) {
  return http.del({ url: `/api/api-keys/${id}` })
}
