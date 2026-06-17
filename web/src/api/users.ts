import http from '@/utils/http'
import type { User } from '@/types/api'

export interface UserItem {
  id: number
  username: string
  role: string
  created_at: string
  last_login?: string
}

export interface UserListResponse {
  users: UserItem[]
  total: number
}

export function getUsers(params?: { page?: number; page_size?: number }) {
  return http.get<UserListResponse>({ url: '/api/users', params })
}

export function createUser(data: { username: string; password: string; role?: string }) {
  return http.post<User>({ url: '/api/users', data })
}

export function updateUser(id: number, data: { password?: string; role?: string }) {
  return http.put<void>({ url: `/api/users/${id}`, data })
}

export function deleteUser(id: number) {
  return http.del<void>({ url: `/api/users/${id}` })
}
