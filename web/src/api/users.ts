import request from './request'
import type { ApiResponse, User } from '@/types/api'

export interface CreateUserRequest {
  username: string
  password: string
  nickname?: string
  email?: string
  role: string
}

export interface UpdateUserRequest {
  nickname?: string
  email?: string
  role?: string
  active?: boolean
}

export interface UsersResponse {
  users: User[]
}

export function getUsers(): Promise<ApiResponse<UsersResponse>> {
  return request.get('/api/users').then((res) => res.data)
}

export function getUser(id: number): Promise<ApiResponse<User>> {
  return request.get(`/api/users/${id}`).then((res) => res.data)
}

export function createUser(data: CreateUserRequest): Promise<ApiResponse<User>> {
  return request.post('/api/users', data).then((res) => res.data)
}

export function updateUser(id: number, data: UpdateUserRequest): Promise<ApiResponse<void>> {
  return request.put(`/api/users/${id}`, data).then((res) => res.data)
}

export function deleteUser(id: number): Promise<ApiResponse<void>> {
  return request.delete(`/api/users/${id}`).then((res) => res.data)
}
