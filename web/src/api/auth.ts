import http from '@/utils/http'

/**
 * 登录接口 - 适配 Rho Aias 后端
 * @param params 登录参数
 * @returns 登录响应
 */
export function fetchLogin(params: { username: string; password: string; captcha_id?: string; captcha_code?: string }) {
  return http.post<any>({
    url: '/api/auth/login',
    data: params
  })
}

/**
 * 获取验证码
 */
export function fetchGetCaptcha() {
  return http.get<any>({
    url: '/api/auth/captcha',
    headers: { Authorization: 'no-auth' }
  })
}


