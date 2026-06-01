// API 响应基础结构
declare namespace Api {
  namespace Auth {
    export interface UserInfo {
      userId?: number | string
      username?: string
      role?: string
      roles?: string[]
      avatar?: string
      [key: string]: any
    }

    export interface LoginParams {
      username: string
      password: string
      captcha_id?: string
      captcha_code?: string
    }

    export interface LoginResult {
      token: string
      user: UserInfo
    }
  }
}

// 业务实体类型
export interface BlockLog {
  id: number
  timestamp: string
  src_ip: string
  dst_ip: string
  dst_port: number
  rule_source: string
  action: string
  protocol: string
  [key: string]: any
}

export interface ManualRuleItem {
  value: string
  remark: string
  added_at: string
}

export interface BanRecord {
  id: number
  ip: string
  reason: string
  source: string
  status: string
  created_at: string
  expires_at: string | null
  duration: number
}

export interface GeoBlockingStatus {
  enabled: boolean
  mode: 'whitelist' | 'blacklist'
  allowed_countries: string[]
  last_update: string
  total_rules: number
  sources: Record<string, any>
}

export interface IntelStatus {
  enabled: boolean
  last_update: string
  total_rules: number
  sources: Record<string, any>
}

export interface BlockLogEventStatus {
  enabled: boolean
  sample_rate: number
}

// API 通用响应
export interface ApiResponse<T = any> {
  code: number
  message: string
  data: T
}
