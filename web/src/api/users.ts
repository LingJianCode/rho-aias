import http from '@/utils/http'

export interface UserItem {
  id: number
  username: string
  role: string
  created_at: string
  last_login?: string
}

export function getUsers(params?: { page?: number; page_size?: number }) {
  return http.get<any>({ url: '/api/users', params })
}

export function createUser(data: { username: string; password: string; role?: string }) {
  return http.post({ url: '/api/users', data })
}

export function updateUser(id: number, data: { password?: string; role?: string }) {
  return http.put({ url: `/api/users/${id}`, data })
}

export function deleteUser(id: number) {
  return http.del({ url: `/api/users/${id}` })
}
