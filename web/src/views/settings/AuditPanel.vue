<template>
  <div class="audit-panel">
    <div class="page-header">
      <h2>审计日志</h2>
    </div>
    <!-- 筛选区 -->
    <el-card shadow="never" class="filter-card">
      <el-form :inline="true" :model="filters">
        <el-form-item label="操作类型">
          <el-select v-model="filters.action" clearable placeholder="全部" style="width: 150px">
            <el-option value="login" label="登录" />
            <el-option value="logout" label="登出" />
            <el-option value="create" label="创建" />
            <el-option value="update" label="更新" />
            <el-option value="delete" label="删除" />
            <el-option value="export" label="导出" />
          </el-select>
        </el-form-item>
        <el-form-item label="资源">
          <el-input v-model="filters.resource" placeholder="资源名称" clearable style="width: 150px" />
        </el-form-item>
        <el-form-item label="状态">
          <el-select v-model="filters.status" clearable placeholder="全部" style="width: 120px">
            <el-option value="success" label="成功" />
            <el-option value="failure" label="失败" />
          </el-select>
        </el-form-item>
        <el-form-item label="时间范围">
          <el-date-picker
            v-model="dateRange"
            type="datetimerange"
            range-separator="至"
            start-placeholder="开始时间"
            end-placeholder="结束时间"
            value-format="YYYY-MM-DD HH:mm:ss"
            style="width: 340px"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="fetchLogs">查询</el-button>
          <el-button @click="resetFilters">重置</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <!-- 操作栏 + 表格 -->
    <el-card shadow="never" style="margin-top: 16px">
      <template #header>
        <div class="table-header">
          <span>审计日志</span>
          <span class="total-info">共 {{ total }} 条记录</span>
          <el-popconfirm title="确定清理旧日志吗？" @confirm="handleClean">
            <template #reference>
              <el-button type="danger" size="small">清理日志</el-button>
            </template>
          </el-popconfirm>
        </div>
      </template>

      <el-table :data="logs" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="70" />
        <el-table-column prop="username" label="用户" width="110" />
        <el-table-column prop="action" label="操作" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="getActionType(row.action)">{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="resource" label="资源" width="130" show-overflow-tooltip />
        <el-table-column prop="detail" label="详情" min-width="200" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP 地址" width="140" />
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'success' ? 'success' : 'danger'" size="small">
              {{ row.status === 'success' ? '成功' : '失败' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="时间" width="170">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button type="primary" link size="small" @click="showDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrapper" v-if="total > 0">
        <el-pagination
          v-model:current-page="pagination.page"
          v-model:page-size="pagination.page_size"
          :total="total"
          layout="total, sizes, prev, pager, next"
          :page-sizes="[20, 50, 100]"
          @size-change="fetchLogs"
          @current-change="fetchLogs"
        />
      </div>
    </el-card>

    <!-- 详情对话框 -->
    <el-dialog v-model="detailVisible" title="审计日志详情" width="650px">
      <el-descriptions :column="2" border v-if="currentLog">
        <el-descriptions-item label="日志 ID">{{ currentLog.id }}</el-descriptions-item>
        <el-descriptions-item label="用户">{{ currentLog.username }} (ID:{{ currentLog.user_id }})</el-descriptions-item>
        <el-descriptions-item label="操作">{{ currentLog.action }}</el-descriptions-item>
        <el-descriptions-item label="资源">{{ currentLog.resource }}</el-descriptions-item>
        <el-descriptions-item label="资源 ID">{{ currentLog.resource_id || '-' }}</el-descriptions-item>
        <el-descriptions-item label="IP">{{ currentLog.ip }}</el-descriptions-item>
        <el-descriptions-item label="User Agent" :span="2">{{ currentLog.user_agent || '-' }}</el-descriptions-item>
        <el-descriptions-item label="详情" :span="2">{{ currentLog.detail || '-' }}</el-descriptions-item>
        <el-descriptions-item label="错误信息" :span="2" v-if="currentLog.error">{{ currentLog.error }}</el-descriptions-item>
        <el-descriptions-item label="状态">
          <el-tag :type="currentLog.status === 'success' ? 'success' : 'danger'">{{ currentLog.status }}</el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="时间">{{ formatDateTime(currentLog.created_at) }}</el-descriptions-item>
      </el-descriptions>
    </el-dialog>

    <!-- 清理对话框 -->
    <el-dialog v-model="cleanVisible" title="清理审计日志" width="420px">
      <el-form label-width="120px">
        <el-form-item label="保留天数">
          <el-input-number v-model="retentionDays" :min="1" :max="365" /> 天
        </el-form-item>
        <el-alert type="warning" :closable="false">
          将删除 {{ retentionDays }} 天前的所有审计日志，此操作不可撤销。
        </el-alert>
      </el-form>
      <template #footer>
        <el-button @click="cleanVisible = false">取消</el-button>
        <el-button type="danger" @click="doClean" :loading="cleaning">确认清理</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'

import { listAuditLogs, cleanAuditLogs } from '@/api/audit'
import { formatDateTime } from '@/utils/format'
import type { AuditLog } from '@/types/api'

const loading = ref(false)
const logs = ref<AuditLog[]>([])
const total = ref(0)

const filters = reactive({
  action: '',
  resource: '',
  status: '',
})

const dateRange = ref<[string, string] | null>(null)
const pagination = reactive({
  page: 1,
  page_size: 20,
})

// 详情
const detailVisible = ref(false)
const currentLog = ref<AuditLog | null>(null)

// 清理
const cleanVisible = ref(false)
const cleaning = ref(false)
const retentionDays = ref(30)

function getActionType(action: string): 'success' | 'warning' | 'danger' | 'info' | undefined {
  const map: Record<string, 'success' | 'warning' | 'danger' | 'info'> = {
    login: 'success', logout: 'info', create: 'info',
    update: 'warning', delete: 'danger', export: 'info',
  }
  return map[action]
}

async function fetchLogs() {
  loading.value = true
  try {
    const params: Parameters<typeof listAuditLogs>[0] = {
      page: pagination.page,
      page_size: pagination.page_size,
    }
    if (filters.action) params.action = filters.action
    if (filters.resource) params.resource = filters.resource
    if (filters.status) params.status = filters.status
    if (dateRange.value?.[0]) params.start_time = dateRange.value[0]
    if (dateRange.value?.[1]) params.end_time = dateRange.value[1]
    const res = await listAuditLogs(params)
    logs.value = res.data.logs
    total.value = res.data.total
  } finally {
    loading.value = false
  }
}

function resetFilters() {
  filters.action = ''
  filters.resource = ''
  filters.status = ''
  dateRange.value = null
  pagination.page = 1
  fetchLogs()
}

function showDetail(row: AuditLog) {
  currentLog.value = row
  detailVisible.value = true
}

function handleClean() {
  cleanVisible.value = true
}

async function doClean() {
  cleaning.value = true
  try {
    await cleanAuditLogs(retentionDays.value)
    ElMessage.success(`已清理 ${retentionDays.value} 天前的日志`)
    cleanVisible.value = false
    fetchLogs()
  } catch {
    // Error handled
  } finally {
    cleaning.value = false
  }
}

onMounted(() => fetchLogs())
</script>

<style lang="scss" scoped>
.page-header {
  margin-bottom: 20px;
  h2 { margin: 0; }
}

.filter-card {
  :deep(.el-card__body) {
    padding-bottom: 2px;
  }
}

.table-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;

  .total-info {
    color: var(--el-text-color-secondary);
    font-size: 13px;
    flex: 1;
  }
}

.pagination-wrapper {
  display: flex;
  justify-content: flex-end;
  margin-top: 16px;
}
</style>
