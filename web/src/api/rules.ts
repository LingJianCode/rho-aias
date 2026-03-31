import request from './request'
import type { ApiResponse, RulesListResponse, RuleSource } from '@/types/api'

export interface GetRulesParams {
  page?: number
  page_size?: number
  source?: RuleSource | 'all'
}

export function getRules(params: GetRulesParams): Promise<ApiResponse<RulesListResponse>> {
  return request.get('/api/rules', { params }).then((res) => res.data)
}
