import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { getToken, setToken, removeToken, getStoredUser, setStoredUser, removeStoredUser, clearAuth, getTokenExpires, setTokenExpires, isTokenExpired } from '@/utils/auth'
import type { User } from '@/types/api'
import { login as loginApi, logout as logoutApi, getCaptcha, refreshToken as refreshTokenApi } from '@/api/auth'

export const useAuthStore = defineStore('auth', () => {
  const token = ref<string | null>(getToken())
  const user = ref<User | null>(getStoredUser() as User | null)
  const captchaId = ref<string>('')
  const captchaImage = ref<string>('')

  const isLoggedIn = computed(() => !!token.value && !!user.value)
  const isAdmin = computed(() => user.value?.role === 'admin')

  async function fetchCaptcha() {
    const res = await getCaptcha()
    captchaId.value = res.data.captcha_id
    captchaImage.value = res.data.captcha_image
  }

  async function login(username: string, password: string, captchaCode: string) {
    const res = await loginApi({
      username,
      password,
      captcha_id: captchaId.value,
      captcha_code: captchaCode,
    })
    token.value = res.data.token
    user.value = res.data.user as User
    setToken(res.data.token)
    setTokenExpires(res.data.expires_at)
    setStoredUser(res.data.user)
    return res.data
  }

  async function refreshToken(): Promise<string> {
    const currentToken = getToken()
    if (!currentToken) {
      throw new Error('No token available')
    }
    const res = await refreshTokenApi(currentToken)
    token.value = res.data.token
    setToken(res.data.token)
    return res.data.token
  }

  async function logout() {
    try {
      await logoutApi()
    } finally {
      token.value = null
      user.value = null
      clearAuth()
    }
  }

  function hasPermission(permission: string): boolean {
    if (!user.value) return false
    if (user.value.role === 'admin') return true
    // 后端权限在 Casbin 中管理，前端暂时只做角色判断
    return false
  }

  // 检查 token 是否需要刷新
  async function checkAndRefreshToken(): Promise<boolean> {
    if (!token.value) return false
    if (isTokenExpired()) {
      try {
        await refreshToken()
        return true
      } catch {
        await logout()
        return false
      }
    }
    return true
  }

  return {
    token,
    user,
    captchaId,
    captchaImage,
    isLoggedIn,
    isAdmin,
    fetchCaptcha,
    login,
    logout,
    refreshToken,
    hasPermission,
    checkAndRefreshToken,
  }
})
