import request from './request'
import type { ApiResponse, PaginatedData, PaginationParams, User } from '@/types/api'

export interface CreateUserRequest {
  username: string
  password: string
  email: string
  role: string
  permissions?: string[]
}

export interface UpdateUserRequest {
  email?: string
  role?: string
  permissions?: string[]
  password?: string
}

export function getUsers(params: PaginationParams): Promise<ApiResponse<PaginatedData<User>>> {
  return request.get('/api/users', { params }).then((res) => res.data)
}

export function getUser(id: number): Promise<ApiResponse<User>> {
  return request.get(`/api/users/${id}`).then((res) => res.data)
}

export function createUser(data: CreateUserRequest): Promise<ApiResponse<User>> {
  return request.post('/api/users', data).then((res) => res.data)
}

export function updateUser(id: number, data: UpdateUserRequest): Promise<ApiResponse<User>> {
  return request.put(`/api/users/${id}`, data).then((res) => res.data)
}

export function deleteUser(id: number): Promise<ApiResponse<void>> {
  return request.delete(`/api/users/${id}`).then((res) => res.data)
}
