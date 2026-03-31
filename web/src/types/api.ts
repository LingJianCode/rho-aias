// API 通用响应类型
export interface ApiResponse<T = unknown> {
  code: number
  message: string
  data: T
}

// 分页请求参数
export interface PaginationParams {
  page?: number
  page_size?: number
  limit?: number
  offset?: number
}

// ============================================
// 用户相关
// ============================================

export interface User {
  id: number
  username: string
  nickname: string
  email: string
  role: string
  active: boolean
  created_at: string
  updated_at: string
}

export interface LoginRequest {
  username: string
  password: string
  captcha_id: string
  captcha_code: string
}

export interface LoginResponse {
  token: string
  user: User
  expires_at: string
}

export interface CaptchaResponse {
  captcha_id: string
  captcha_image: string
}

// ============================================
// 规则相关
// ============================================

export type RuleSource = 'manual' | 'ipsum' | 'spamhaus' | 'waf' | 'ddos' | 'anomaly' | 'failguard' | 'rate_limit'

export interface Rule {
  id: string
  ip: string
  cidr?: number
  source: RuleSource
  reason: string
  created_at: string
  expires_at?: string
}

export interface RulesListResponse {
  items: Rule[]
  total: number
}

// ============================================
// 手动规则（黑名单/白名单）
// ============================================

export interface ManualRuleRequest {
  value: string
}

export interface ManualRuleItem {
  value: string
  added_at?: string
}

export interface WhitelistResponse {
  rules: ManualRuleItem[]
  total: number
}

// ============================================
// 阻断日志
// ============================================

export interface BlockLog {
  timestamp: string
  src_ip: string
  dst_ip: string
  protocol: string
  match_type: string
  source: string
  country_code: string
  packet_size: number
}

export interface BlockLogListResponse {
  items: BlockLog[]
  total: number
}

export interface IPCount {
  ip: string
  count: number
}

export interface CountryCount {
  country: string
  count: number
}

export interface SourceCount {
  source: string
  count: number
}

export interface BlockLogStats {
  total_blocks: number
  unique_ips: number
  top_countries: CountryCount[]
  top_sources: SourceCount[]
  hourly_trend: { hour: string; count: number }[]
}

export interface BlockedIPsResponse {
  total_blocked_ips: number
  top_blocked_ips: IPCount[]
}

// ============================================
// 封禁记录
// ============================================

export interface BanRecord {
  id: number
  ip: string
  cidr?: number
  source: string
  reason: string
  is_active: boolean
  block_count: number
  banned_at: string
  expires_at?: string
}

export interface BanRecordListResponse {
  items: BanRecord[]
  total: number
}

export interface BanRecordStats {
  total: number
  active: number
  expired: number
  today_new: number
}

// ============================================
// 数据源状态
// ============================================

export interface SourceStatusRecord {
  id: number
  source_type: string
  source_id: string
  source_name: string
  status: 'success' | 'failed'
  rule_count: number
  error_message: string
  duration: number
  updated_at: string
}

export type SourcesStatusResponse = Record<string, Record<string, SourceStatusRecord>>

// ============================================
// 威胁情报
// ============================================

export interface IntelSourceStatus {
  name: string
  count: number
  updated: string
}

export interface IntelStatus {
  last_update: string
  total_rules: number
  sources: IntelSourceStatus[]
}

// ============================================
// 地域封禁
// ============================================

export interface GeoBlockingStatus {
  enabled: boolean
  mode: 'whitelist' | 'blacklist'
  allowed_countries: string[]
  last_update: string
  total_rules: number
  sources: Record<string, {
    enabled: boolean
    last_update: string
    success: boolean
    rule_count: number
    error: string
  }>
}

export interface GeoBlockingConfigRequest {
  mode: 'whitelist' | 'blacklist'
  allowed_countries: string[]
}

// ============================================
// API Key
// ============================================

export interface ApiKey {
  id: number
  name: string
  key_prefix: string
  permissions: string
  user_id: number
  last_used_at?: string
  expires_at?: string
  active: boolean
  created_at: string
}

export interface ApiKeysResponse {
  keys: ApiKey[]
}

export interface CreateApiKeyRequest {
  name: string
  permissions: string[]
  expires_days?: number
}

export interface CreateApiKeyResponse {
  id: number
  name: string
  key: string
  permissions: string[]
  expires_at?: string
  created_at: string
}

// ============================================
// 审计日志
// ============================================

export interface AuditLog {
  id: number
  user_id: number
  username: string
  action: string
  resource: string
  resource_id: string
  detail: string
  ip: string
  user_agent: string
  status: string
  error: string
  created_at: string
}

export interface AuditLogsResponse {
  total: number
  logs: AuditLog[]
}

// ============================================
// XDP 事件
// ============================================

export interface EventStatus {
  enabled: boolean
  sample_rate: number
}

export interface EventConfigRequest {
  enabled?: boolean
  sample_rate?: number
}

// ============================================
// 仪表盘统计（前端自定义聚合）
// ============================================

export interface DashboardStats {
  total_blocks: number
  active_rules: number
  healthy_sources: number
  today_bans: number
  block_trend: { date: string; count: number }[]
  recent_blocks: BlockLog[]
  source_status: { name: string; status: string }[]
}
