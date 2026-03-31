import request from './request'
import type { ApiResponse, LoginRequest, LoginResponse, CaptchaResponse } from '@/types/api'

export function getCaptcha(): Promise<ApiResponse<CaptchaResponse>> {
  return request.get('/api/auth/captcha', { headers: { Authorization: 'no-auth' } }).then((res) => res.data)
}

export function login(data: LoginRequest): Promise<ApiResponse<LoginResponse>> {
  return request.post('/api/auth/login', data).then((res) => res.data)
}

export function logout(): Promise<ApiResponse<void>> {
  return request.post('/api/auth/logout').then((res) => res.data)
}

export function refreshToken(token: string): Promise<ApiResponse<{ token: string }>> {
  return request.post('/api/auth/refresh', { token }).then((res) => res.data)
}

export function changePassword(data: { old_password: string; new_password: string }): Promise<ApiResponse<void>> {
  return request.put('/api/auth/password', data).then((res) => res.data)
}

export function getCurrentUser(): Promise<ApiResponse<{ id: number; username: string; nickname: string; email: string; role: string; active: boolean }>> {
  return request.get('/api/auth/me').then((res) => res.data)
}
