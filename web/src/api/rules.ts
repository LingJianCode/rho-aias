import request from './request'
import type { ApiResponse, PaginatedData, PaginationParams, Rule, RuleSource } from '@/types/api'

export interface GetRulesParams extends PaginationParams {
  source?: RuleSource | 'all'
}

export function getRules(params: GetRulesParams): Promise<ApiResponse<PaginatedData<Rule>>> {
  return request.get('/api/rules', { params }).then((res) => res.data)
}

export function getRuleCount(): Promise<ApiResponse<{ total: number; by_source: Record<string, number> }>> {
  return request.get('/api/rules/count').then((res) => res.data)
}
