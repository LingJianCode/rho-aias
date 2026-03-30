import request from './request'
import type { ApiResponse, PaginatedData, PaginationParams, ManualRule } from '@/types/api'

export interface ManualRuleItem extends ManualRule {
  id: string
  created_at: string
}

export function getBlacklist(params: PaginationParams): Promise<ApiResponse<PaginatedData<ManualRuleItem>>> {
  return request.get('/api/manual/blacklist/rules', { params }).then((res) => res.data)
}

export function addBlacklistRule(data: ManualRule): Promise<ApiResponse<void>> {
  return request.post('/api/manual/blacklist/rules', data).then((res) => res.data)
}

export function addBlacklistRulesBatch(ips: string, reason?: string): Promise<ApiResponse<{ added: number; duplicates: number }>> {
  return request.post('/api/manual/blacklist/rules/batch', { ips, reason }).then((res) => res.data)
}

export function deleteBlacklistRule(id: string): Promise<ApiResponse<void>> {
  return request.delete(`/api/manual/blacklist/rules/${id}`).then((res) => res.data)
}

export function deleteBlacklistRules(ids: string[]): Promise<ApiResponse<void>> {
  return request.delete('/api/manual/blacklist/rules', { data: { ids } }).then((res) => res.data)
}

export function getWhitelist(params: PaginationParams): Promise<ApiResponse<PaginatedData<ManualRuleItem>>> {
  return request.get('/api/manual/whitelist/rules', { params }).then((res) => res.data)
}

export function addWhitelistRule(data: ManualRule): Promise<ApiResponse<void>> {
  return request.post('/api/manual/whitelist/rules', data).then((res) => res.data)
}

export function addWhitelistRulesBatch(ips: string, reason?: string): Promise<ApiResponse<{ added: number; duplicates: number }>> {
  return request.post('/api/manual/whitelist/rules/batch', { ips, reason }).then((res) => res.data)
}

export function deleteWhitelistRule(id: string): Promise<ApiResponse<void>> {
  return request.delete(`/api/manual/whitelist/rules/${id}`).then((res) => res.data)
}

export function deleteWhitelistRules(ids: string[]): Promise<ApiResponse<void>> {
  return request.delete('/api/manual/whitelist/rules', { data: { ids } }).then((res) => res.data)
}
