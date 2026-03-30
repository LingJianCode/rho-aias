import request from './request'
import type { ApiResponse, LoginRequest, LoginResponse, CaptchaResponse } from '@/types/api'

export function getCaptcha(): Promise<ApiResponse<CaptchaResponse>> {
  return request.get('/api/auth/captcha').then((res) => res.data)
}

export function login(data: LoginRequest): Promise<ApiResponse<LoginResponse>> {
  return request.post('/api/auth/login', data).then((res) => res.data)
}

export function logout(): Promise<ApiResponse<void>> {
  return request.post('/api/auth/logout').then((res) => res.data)
}

export function refreshToken(refreshToken: string): Promise<ApiResponse<{ token: string }>> {
  return request.post('/api/auth/refresh', { refresh_token: refreshToken }).then((res) => res.data)
}
