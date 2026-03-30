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
}

// 分页响应数据
export interface PaginatedData<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

// 用户相关
export interface User {
  id: number
  username: string
  email: string
  role: string
  permissions: string[]
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
  refresh_token: string
  user: User
}

export interface CaptchaResponse {
  captcha_id: string
  captcha_image: string
}

// 规则相关
export type RuleSource = 'manual' | 'ipsum' | 'spamhaus' | 'waf' | 'ddos' | 'anomaly' | 'failguard'

export interface Rule {
  id: string
  ip: string
  cidr?: number
  source: RuleSource
  reason?: string
  created_at: string
  expires_at?: string
}

export interface ManualRule {
  ip: string
  cidr?: number
  reason?: string
  expires_at?: string
}

// 阻断日志
export interface BlockLog {
  id: string
  timestamp: string
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  match_type: string
  source: string
  country_code?: string
  packet_size: number
  action: string
}

export interface BlockLogStats {
  total_blocks: number
  unique_ips: number
  top_countries: { country: string; count: number }[]
  top_sources: { source: string; count: number }[]
  hourly_trend: { hour: string; count: number }[]
}

// 封禁记录
export interface BanRecord {
  id: string
  ip: string
  cidr?: number
  source: string
  reason?: string
  banned_at: string
  expires_at?: string
  is_active: boolean
  block_count: number
}

export interface BanRecordStats {
  total: number
  active: number
  expired: number
  today_new: number
}

// 数据源状态
export interface DataSource {
  id: string
  name: string
  type: string
  status: 'healthy' | 'unhealthy' | 'unknown'
  last_update?: string
  rule_count: number
  error?: string
}

// 威胁情报
export interface IntelStatus {
  last_update: string
  sources: { name: string; count: number; updated: string }[]
  total_rules: number
}

// 地域封禁
export interface GeoBlockingConfig {
  enabled: boolean
  mode: 'whitelist' | 'blacklist'
  countries: string[]
}

// API Key
export interface ApiKey {
  id: string
  name: string
  key_prefix: string
  permissions: string[]
  created_at: string
  expires_at?: string
  last_used_at?: string
  is_active: boolean
}

export interface CreateApiKeyRequest {
  name: string
  permissions: string[]
  expires_at?: string
}

export interface CreateApiKeyResponse {
  id: string
  name: string
  key: string
}

// 审计日志
export interface AuditLog {
  id: string
  timestamp: string
  user: string
  action: string
  resource: string
  details: string
  ip: string
}

// 仪表盘统计
export interface DashboardStats {
  total_blocks: number
  active_rules: number
  healthy_sources: number
  today_bans: number
  block_trend: { date: string; count: number }[]
  recent_blocks: BlockLog[]
  source_status: { name: string; status: string }[]
}
