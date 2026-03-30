import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { getToken, setToken, removeToken, getStoredUser, setStoredUser, removeStoredUser, clearAuth } from '@/utils/auth'
import type { User } from '@/types/api'
import { login as loginApi, logout as logoutApi, getCaptcha } from '@/api/auth'

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
    user.value = res.data.user
    setToken(res.data.token)
    setStoredUser(res.data.user)
    return res.data
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
    return user.value.permissions?.includes(permission) ?? false
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
    hasPermission,
  }
})
