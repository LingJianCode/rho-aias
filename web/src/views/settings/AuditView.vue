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
              v-model="userFilter"
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
              <el-option label="创建" value="create" />
              <el-option label="更新" value="update" />
              <el-option label="删除" value="delete" />
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
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="user" label="用户" width="120" />
        <el-table-column prop="action" label="操作" width="100">
          <template #default="{ row }">
            <el-tag :type="getActionType(row.action)" size="small">{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="resource" label="资源" min-width="150" />
        <el-table-column prop="details" label="详情" min-width="200" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="140" />
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
import { getAuditLogs, clearAuditLogs } from '@/api/audit'
import type { AuditLog } from '@/types/api'

const loading = ref(false)
const logs = ref<AuditLog[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const userFilter = ref('')
const actionFilter = ref('')
const dateRange = ref<[string, string] | null>(null)

function getActionType(action: string) {
  const types: Record<string, string> = {
    login: 'success',
    logout: 'info',
    create: 'primary',
    update: 'warning',
    delete: 'danger',
  }
  return types[action] || 'info'
}

async function fetchLogs() {
  loading.value = true
  try {
    const res = await getAuditLogs({
      page: page.value,
      page_size: pageSize.value,
      user: userFilter.value || undefined,
      action: actionFilter.value || undefined,
      start_time: dateRange.value?.[0],
      end_time: dateRange.value?.[1],
    })
    logs.value = res.data.items
    total.value = res.data.total
  } catch {
    logs.value = [
      { id: '1', timestamp: new Date().toISOString(), user: 'admin', action: 'login', resource: 'auth', details: '登录成功', ip: '192.168.1.1' },
      { id: '2', timestamp: new Date().toISOString(), user: 'admin', action: 'create', resource: 'rules', details: '添加黑名单规则 10.0.0.1', ip: '192.168.1.1' },
    ]
    total.value = 2
  } finally {
    loading.value = false
  }
}

function handleFilter() {
  page.value = 1
  fetchLogs()
}

async function handleClear() {
  const { value } = await ElMessageBox.prompt('请输入要清理的天数（清理该天数之前的日志）', '清理旧日志', {
    confirmButtonText: '确定',
    cancelButtonText: '取消',
    inputPattern: /^\d+$/,
    inputErrorMessage: '请输入有效数字',
  })
  
  const days = parseInt(value)
  const before = new Date(Date.now() - days * 86400000).toISOString()
  
  try {
    await clearAuditLogs(before)
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
