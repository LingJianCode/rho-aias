import axios, { type AxiosInstance, type AxiosResponse, type InternalAxiosRequestConfig } from 'axios'
import { ElMessage, ElNotification } from 'element-plus'
import { getToken, setToken, clearAuth } from '@/utils/auth'
import type { ApiResponse } from '@/types/api'
import router from '@/router'

const instance: AxiosInstance = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// 是否正在刷新标识，避免重复刷新
let isRefreshing = false
// 因 Token 过期导致的请求等待队列
const waitingQueue: (() => void)[] = []

// 处理会话过期
async function handleSessionExpired() {
  if (router.currentRoute.value.path === '/login') return
  ElNotification({
    title: '提示',
    message: '您的会话已过期，请重新登录',
    type: 'info',
  })
  clearAuth()
  router.push('/login')
}

// 刷新 Token 处理：将请求加入等待队列，仅由首个请求触发刷新
function handleTokenRefresh(config: InternalAxiosRequestConfig): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const retryRequest = () => {
      config.headers.Authorization = `Bearer ${getToken()}`
      resolve(instance(config as Parameters<typeof instance>[0]))
    }
    waitingQueue.push(retryRequest)

    if (!isRefreshing) {
      isRefreshing = true

      // 用原生 axios 直接调用刷新接口，绕过 instance 拦截器
      // 避免刷新请求的 401 再次触发 handleTokenRefresh 导致死循环
      const currentToken = getToken()
      axios
        .post(
          `${import.meta.env.VITE_API_BASE_URL}/api/auth/refresh`,
          { token: currentToken },
          { timeout: 10000 }
        )
        .then((res) => {
          const newToken = (res.data as ApiResponse<{ token: string }>).data?.token
          if (!newToken) throw new Error('Invalid token response')

          // 将新 token 写入 storage
          setToken(newToken)

          // 刷新成功 → 依次重试队列中所有请求
          waitingQueue.forEach((callback) => callback())
          waitingQueue.length = 0
        })
        .catch(async () => {
          // 刷新失败 → 清空队列，跳转登录页
          waitingQueue.length = 0
          await handleSessionExpired()
        })
        .finally(() => {
          isRefreshing = false
        })
    }
  }).catch((error) => Promise.reject(error))
}

instance.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const token = getToken()
    if (config.headers?.['Authorization'] === 'no-auth') {
      delete config.headers.Authorization
    } else if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => Promise.reject(error)
)

instance.interceptors.response.use(
  (response: AxiosResponse<ApiResponse>) => {
    if (response.config.responseType === 'blob') {
      return response
    }

    const { data } = response
    if (data.code === 0) {
      return response
    }

    ElMessage.error(data.message || '请求失败')
    return Promise.reject(new Error(data.message || '请求失败'))
  },
  async (error) => {
    const { config, response } = error

    if (response?.status === 401) {
      if (getToken()) {
        return handleTokenRefresh(config)
      }
      await handleSessionExpired()
    }

    const message = response?.data?.message || error.message || '网络错误'
    ElMessage.error(message)
    return Promise.reject(error)
  }
)

export default instance
