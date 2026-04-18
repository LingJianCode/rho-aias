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

// ============================================
// 手动规则（黑名单/白名单）
// ============================================

export interface ManualRuleRequest {
  value: string
  remark?: string
}

export interface ManualRuleItem {
  value: string
  remark?: string
  added_at?: string
}

export interface WhitelistRuleItem extends ManualRuleItem {
  protected?: boolean
}

export interface WhitelistResponse {
  rules: WhitelistRuleItem[]
  total: number
}

export interface BlacklistResponse {
  rules: ManualRuleItem[]
  total: number
}

// ============================================
// 阻断日志
// ============================================

export interface BlockLog {
  timestamp: number
  src_ip: string
  dst_ip: string
  match_type: string
  rule_source: string
  country_code: string
  packet_size: number
}

export interface BlockLogListResponse {
  records: BlockLog[]
  total: number
  page: number
  page_size: number
}

export interface BlockLogStats {
  total_blocked: number
  by_rule_source: Record<string, number>
}

// ============================================
// 封禁记录
// ============================================

export interface BanRecord {
  id: number
  ip: string
  source: string
  reason: string
  duration: number
  status: string
  created_at: string
  expires_at?: string
  unblocked_at?: string
}

export interface BanRecordListResponse {
  records: BanRecord[]
  total: number
}

export interface BanRecordStats {
  total: number
  active: number
  expired: number
  today_count: number
}

// ============================================
// 威胁情报
// ============================================

export interface IntelSourceStatus {
  name: string
  count: number
  updated: string
}

export interface IntelSourceDetail {
  enabled: boolean
  last_update: string
  success: boolean
  rule_count: number
  error: string
}

export interface IntelStatus {
  enabled: boolean
  last_update: string
  total_rules: number
  sources: Record<string, IntelSourceDetail>
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

export interface BlockLogEventStatus {
  enabled: boolean
  sample_rate: number
}

// ============================================
// 仪表盘统计（前端自定义聚合）
// ============================================

export interface DashboardStats {
  total_blocks: number
  active_rules: number
  today_bans: number
  block_trend: { date: string; count: number }[]
  recent_blocks: BlockLog[]
}

// ============================================
// 统一配置（运行时热更新）
// ============================================

export type ConfigModuleName = 'failguard' | 'waf' | 'rate_limit' | 'anomaly_detection' | 'geo_blocking' | 'intel' | 'blocklog_events'

export interface FailGuardConfig {
  enabled?: boolean
  max_retry?: number
  find_time?: number
  ban_duration?: number
  mode?: 'normal' | 'ddos' | 'aggressive'
}

export interface WAFConfig {
  enabled?: boolean
  ban_duration?: number
}

export interface RateLimitConfig {
  enabled?: boolean
  ban_duration?: number
}

export interface BaselineConfig {
  packets_per_sec?: number
  bytes_per_sec?: number
}

export interface AttackConfig {
  enabled?: boolean
  threshold?: number
  time_window?: number
}

export interface AnomalyDetectionConfig {
  enabled?: boolean
  min_packets?: number
  ports?: number[]
  baseline?: BaselineConfig
  attacks?: Record<string, AttackConfig>
}

export interface GeoBlockingRuntimeConfig {
  enabled?: boolean
  mode?: 'whitelist' | 'blacklist'
  allowed_countries?: string[]
}

export interface IntelSourceRuntimeConfig {
  enabled?: boolean
  schedule?: string
  url?: string
}

export interface IntelRuntimeConfig {
  enabled?: boolean
  sources?: Record<string, IntelSourceRuntimeConfig>
}
