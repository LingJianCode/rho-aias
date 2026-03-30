<template>
  <el-container class="default-layout">
    <el-aside :width="sidebarWidth" class="sidebar">
      <div class="logo">
        <img src="@/assets/favicon.svg" alt="Rho Aias" class="logo-icon" />
        <span v-if="!collapsed" class="logo-text">rho-aias</span>
      </div>
      <el-menu
        :default-active="activeMenu"
        :collapse="collapsed"
        :collapse-transition="false"
        router
        class="sidebar-menu"
      >
        <el-menu-item index="/dashboard">
          <el-icon><Odometer /></el-icon>
          <template #title>仪表盘</template>
        </el-menu-item>
        <el-sub-menu index="firewall">
          <template #title>
            <el-icon><Aim /></el-icon>
            <span>防火墙</span>
          </template>
          <el-menu-item index="/firewall/rules">规则列表</el-menu-item>
          <el-menu-item index="/firewall/blacklist">黑名单</el-menu-item>
          <el-menu-item index="/firewall/whitelist">白名单</el-menu-item>
        </el-sub-menu>
        <el-menu-item index="/blocklog">
          <el-icon><Document /></el-icon>
          <template #title>阻断日志</template>
        </el-menu-item>
        <el-menu-item index="/ban-records">
          <el-icon><Lock /></el-icon>
          <template #title>封禁记录</template>
        </el-menu-item>
        <el-menu-item index="/sources">
          <el-icon><Connection /></el-icon>
          <template #title>数据源</template>
        </el-menu-item>
        <el-menu-item index="/intel">
          <el-icon><Warning /></el-icon>
          <template #title>威胁情报</template>
        </el-menu-item>
        <el-menu-item index="/geoblocking">
          <el-icon><Location /></el-icon>
          <template #title>地域封禁</template>
        </el-menu-item>
        <el-sub-menu index="settings">
          <template #title>
            <el-icon><Setting /></el-icon>
            <span>设置</span>
          </template>
          <el-menu-item index="/settings/users" v-if="authStore.isAdmin">用户管理</el-menu-item>
          <el-menu-item index="/settings/api-keys">API Key</el-menu-item>
          <el-menu-item index="/settings/audit">审计日志</el-menu-item>
        </el-sub-menu>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header class="header">
        <div class="header-left">
          <el-icon class="collapse-btn" @click="toggleSidebar">
            <component :is="collapsed ? 'Expand' : 'Fold'" />
          </el-icon>
          <el-breadcrumb separator="/">
            <el-breadcrumb-item v-for="item in breadcrumbs" :key="item.path" :to="item.path">
              {{ item.title }}
            </el-breadcrumb-item>
          </el-breadcrumb>
        </div>
        <div class="header-right">
          <el-icon class="theme-btn" @click="toggleDarkMode">
            <component :is="darkMode ? 'Sunny' : 'Moon'" />
          </el-icon>
          <el-dropdown @command="handleCommand">
            <span class="user-dropdown">
              <el-avatar :size="32" icon="User" />
              <span class="username">{{ authStore.user?.username }}</span>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item command="logout">退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </el-header>
      <el-main class="main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAppStore } from '@/stores/app'
import { useAuthStore } from '@/stores/auth'
import {
  Odometer, Aim, Document, Lock, Connection,
  Warning, Location, Setting, Fold, Expand, Moon, Sunny
} from '@element-plus/icons-vue'

const route = useRoute()
const router = useRouter()
const appStore = useAppStore()
const authStore = useAuthStore()

const collapsed = computed(() => appStore.sidebarCollapsed)
const darkMode = computed(() => appStore.darkMode)
const sidebarWidth = computed(() => collapsed.value ? '64px' : '220px')
const activeMenu = computed(() => route.path)

const breadcrumbs = computed(() => {
  const matched = route.matched.filter((r) => r.meta?.title)
  return matched.map((r) => ({
    path: r.path,
    title: r.meta?.title as string || r.name as string,
  }))
})

function toggleSidebar() {
  appStore.toggleSidebar()
}

function toggleDarkMode() {
  appStore.toggleDarkMode()
}

async function handleCommand(command: string) {
  if (command === 'logout') {
    await authStore.logout()
    router.push('/login')
  }
}
</script>

<style lang="scss" scoped>
.default-layout {
  height: 100vh;
}

.sidebar {
  background-color: #fff;
  border-right: 1px solid var(--el-border-color-light);
  transition: width 0.3s;
  overflow: hidden;
}

.logo {
  height: var(--header-height);
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  border-bottom: 1px solid var(--el-border-color-light);
  padding: 0 12px;
}

.logo-icon {
  width: 32px;
  height: 32px;
  flex-shrink: 0;
}

.logo-text {
  font-size: 18px;
  font-weight: bold;
  color: var(--el-color-primary);
  white-space: nowrap;
  overflow: hidden;
}

.sidebar-menu {
  border-right: none;
  height: calc(100% - var(--header-height));
}

.header {
  height: var(--header-height);
  display: flex;
  align-items: center;
  justify-content: space-between;
  background-color: #fff;
  border-bottom: 1px solid var(--el-border-color-light);
  padding: 0 16px;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}

.collapse-btn {
  font-size: 20px;
  cursor: pointer;
  color: var(--el-text-color-secondary);
  &:hover { color: var(--el-color-primary); }
}

.header-right {
  display: flex;
  align-items: center;
  gap: 16px;
}

.theme-btn {
  font-size: 20px;
  cursor: pointer;
  color: var(--el-text-color-secondary);
  &:hover { color: var(--el-color-primary); }
}

.user-dropdown {
  display: flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
}

.username {
  color: var(--el-text-color-primary);
}

.main {
  background-color: var(--el-bg-color-page);
  padding: 20px;
  overflow: auto;
}
</style>
