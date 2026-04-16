import request from './request'
import type { ApiResponse, WhitelistResponse, BlacklistResponse } from '@/types/api'

// ============================================
// 黑名单 API
// ============================================

export function getBlacklist(): Promise<ApiResponse<BlacklistResponse>> {
  return request.get('/api/manual/blacklist/rules').then((res) => res.data)
}

export function addBlacklistRule(value: string): Promise<ApiResponse<void>> {
  return request.post('/api/manual/blacklist/rules', { value }).then((res) => res.data)
}

export function deleteBlacklistRule(value: string): Promise<ApiResponse<void>> {
  return request.delete('/api/manual/blacklist/rules', { data: { value } }).then((res) => res.data)
}

// ============================================
// 白名单 API
// ============================================

export function getWhitelist(): Promise<ApiResponse<WhitelistResponse>> {
  return request.get('/api/manual/whitelist/rules').then((res) => res.data)
}

export function addWhitelistRule(value: string): Promise<ApiResponse<void>> {
  return request.post('/api/manual/whitelist/rules', { value }).then((res) => res.data)
}

export function deleteWhitelistRule(value: string): Promise<ApiResponse<void>> {
  return request.delete('/api/manual/whitelist/rules', { data: { value } }).then((res) => res.data)
}
