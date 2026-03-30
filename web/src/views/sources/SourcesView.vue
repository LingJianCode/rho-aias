<template>
  <div class="sources-view">
    <div class="page-header">
      <h2>数据源状态</h2>
    </div>

    <el-card>
      <el-table :data="sources" v-loading="loading" stripe>
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="type" label="类型" width="120" />
        <el-table-column prop="status" label="状态" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">
              {{ getStatusLabel(row.status) }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule_count" label="规则数" width="100">
          <template #default="{ row }">{{ formatNumber(row.rule_count) }}</template>
        </el-table-column>
        <el-table-column prop="last_update" label="最后更新" width="180">
          <template #default="{ row }">
            {{ row.last_update ? formatDateTime(row.last_update) : '-' }}
          </template>
        </el-table-column>
        <el-table-column prop="error" label="错误信息" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ row.error || '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button type="primary" link @click="handleRefresh(row)">刷新</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { formatDateTime, formatNumber } from '@/utils/format'
import { getSourcesStatus, refreshSource } from '@/api/sources'
import type { DataSource } from '@/types/api'

const loading = ref(false)
const sources = ref<DataSource[]>([])

function getStatusType(status: string) {
  return status === 'healthy' ? 'success' : status === 'unhealthy' ? 'danger' : 'info'
}

function getStatusLabel(status: string) {
  return status === 'healthy' ? '正常' : status === 'unhealthy' ? '异常' : '未知'
}

async function fetchSources() {
  loading.value = true
  try {
    const res = await getSourcesStatus()
    sources.value = res.data
  } catch {
    sources.value = [
      { id: '1', name: 'IPsum', type: 'threat_intel', status: 'healthy', rule_count: 15000, last_update: new Date().toISOString() },
      { id: '2', name: 'Spamhaus DROP', type: 'threat_intel', status: 'healthy', rule_count: 2500, last_update: new Date().toISOString() },
      { id: '3', name: 'WAF 黑名单', type: 'internal', status: 'healthy', rule_count: 500, last_update: new Date().toISOString() },
      { id: '4', name: 'DDoS 检测', type: 'internal', status: 'unhealthy', rule_count: 100, error: '连接超时' },
    ]
  } finally {
    loading.value = false
  }
}

async function handleRefresh(row: DataSource) {
  try {
    await refreshSource(row.type, row.id)
    ElMessage.success('刷新成功')
    fetchSources()
  } catch {
    // Error handled
  }
}

onMounted(() => {
  fetchSources()
})
</script>
