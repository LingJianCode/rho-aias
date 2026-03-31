const TOKEN_KEY = 'rho_aias_token'
const TOKEN_EXPIRES_KEY = 'rho_aias_token_expires'
const USER_KEY = 'rho_aias_user'

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY)
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token)
}

export function removeToken(): void {
  localStorage.removeItem(TOKEN_KEY)
}

export function getTokenExpires(): string | null {
  return localStorage.getItem(TOKEN_EXPIRES_KEY)
}

export function setTokenExpires(expiresAt: string): void {
  localStorage.setItem(TOKEN_EXPIRES_KEY, expiresAt)
}

export function removeTokenExpires(): void {
  localStorage.removeItem(TOKEN_EXPIRES_KEY)
}

export function getStoredUser(): unknown {
  const user = localStorage.getItem(USER_KEY)
  return user ? JSON.parse(user) : null
}

export function setStoredUser(user: unknown): void {
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}

export function removeStoredUser(): void {
  localStorage.removeItem(USER_KEY)
}

export function clearAuth(): void {
  removeToken()
  removeTokenExpires()
  removeStoredUser()
}

export function isTokenExpired(): boolean {
  const expiresAt = getTokenExpires()
  if (!expiresAt) return true
  // 提前 5 分钟认为过期，避免边界情况
  const expiresTime = new Date(expiresAt).getTime()
  const now = Date.now()
  return now >= expiresTime - 5 * 60 * 1000
}
