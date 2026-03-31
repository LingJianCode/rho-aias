<template>
  <div class="audit-view">
    <div class="page-header">
      <h2>审计日志</h2>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <div class="filter-row">
            <el-input
              v-model="usernameFilter"
              placeholder="用户名"
              clearable
              style="width: 150px"
              @clear="handleFilter"
              @keyup.enter="handleFilter"
            />
            <el-select v-model="actionFilter" placeholder="操作类型" clearable @change="handleFilter">
              <el-option label="全部" value="" />
              <el-option label="登录" value="login" />
              <el-option label="登出" value="logout" />
              <el-option label="创建用户" value="create_user" />
              <el-option label="更新用户" value="update_user" />
              <el-option label="删除用户" value="delete_user" />
              <el-option label="创建API Key" value="create_api_key" />
              <el-option label="吊销API Key" value="revoke_api_key" />
            </el-select>
            <el-date-picker
              v-model="dateRange"
              type="datetimerange"
              range-separator="至"
              start-placeholder="开始时间"
              end-placeholder="结束时间"
              value-format="YYYY-MM-DD HH:mm:ss"
              @change="handleFilter"
            />
          </div>
          <el-button type="danger" @click="handleClear">清理旧日志</el-button>
        </div>
      </template>

      <el-table :data="logs" v-loading="loading" stripe>
        <el-table-column prop="created_at" label="时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="username" label="用户" width="120" />
        <el-table-column prop="action" label="操作" width="120">
          <template #default="{ row }">
            <el-tag :type="getActionType(row.action)" size="small">{{ formatAction(row.action) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="resource" label="资源" min-width="120" />
        <el-table-column prop="detail" label="详情" min-width="200" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'success' ? 'success' : 'danger'" size="small">
              {{ row.status === 'success' ? '成功' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrapper">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :total="total"
          layout="total, sizes, prev, pager, next"
          @size-change="fetchLogs"
          @current-change="fetchLogs"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { formatDateTime } from '@/utils/format'
import { getAuditLogs, cleanAuditLogs } from '@/api/audit'
import type { AuditLog } from '@/types/api'

const loading = ref(false)
const logs = ref<AuditLog[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const usernameFilter = ref('')
const actionFilter = ref('')
const dateRange = ref<[string, string] | null>(null)

function getActionType(action: string) {
  const types: Record<string, string> = {
    login: 'success',
    logout: 'info',
    create_user: 'primary',
    update_user: 'warning',
    delete_user: 'danger',
    create_api_key: 'primary',
    revoke_api_key: 'warning',
  }
  return types[action] || 'info'
}

function formatAction(action: string) {
  const labels: Record<string, string> = {
    login: '登录',
    logout: '登出',
    create_user: '创建用户',
    update_user: '更新用户',
    delete_user: '删除用户',
    create_api_key: '创建API Key',
    revoke_api_key: '吊销API Key',
    change_password: '修改密码',
  }
  return labels[action] || action
}

async function fetchLogs() {
  loading.value = true
  try {
    const res = await getAuditLogs({
      page: page.value,
      page_size: pageSize.value,
      username: usernameFilter.value || undefined,
      action: actionFilter.value || undefined,
      start_time: dateRange.value?.[0],
      end_time: dateRange.value?.[1],
    })
    logs.value = res.data.logs
    total.value = res.data.total
  } catch {
    // 模拟数据（已注释保留作为格式提示）：
    // logs.value = [
    //   { id: 1, user_id: 1, username: 'admin', action: 'login', resource: 'auth', resource_id: '', detail: '登录成功', ip: '192.168.1.1', user_agent: '', status: 'success', error: '', created_at: new Date().toISOString() },
    // ]
    // total.value = 1
    logs.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function handleFilter() {
  page.value = 1
  fetchLogs()
}

async function handleClear() {
  const { value } = await ElMessageBox.prompt('请输入要保留的天数（将清理该天数之前的日志）', '清理旧日志', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    inputPattern: /^\d+$/,
    inputErrorMessage: '请输入有效数字',
  })
  
  const days = parseInt(value)
  
  try {
    await cleanAuditLogs(days)
    ElMessage.success('清理成功')
    fetchLogs()
  } catch {
    // Error handled
  }
}

onMounted(() => {
  fetchLogs()
})
</script>

<style lang="scss" scoped>
.filter-row {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}

.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
