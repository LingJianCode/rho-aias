<template>
  <div class="settings-view">
    <div class="page-header">
      <h2>系统设置</h2>
    </div>

    <el-tabs v-model="activeTab" type="border-card">
      <el-tab-pane label="防护策略配置" name="config">
        <ConfigPanel />
      </el-tab-pane>
      <el-tab-pane label="用户管理" name="users">
        <UsersView />
      </el-tab-pane>
      <el-tab-pane label="API Keys" name="api-keys">
        <ApiKeysView />
      </el-tab-pane>
      <el-tab-pane v-if="authStore.isAdmin" label="审计日志" name="audit">
        <AuditPanel />
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import ConfigPanel from './ConfigPanel.vue'
import UsersView from './UsersView.vue'
import ApiKeysView from './ApiKeysView.vue'
import AuditPanel from './AuditPanel.vue'

const authStore = useAuthStore()
const activeTab = ref('config')
</script>

<style lang="scss" scoped>
.page-header {
  margin-bottom: 20px;

  h2 {
    margin: 0;
  }
}
</style>
