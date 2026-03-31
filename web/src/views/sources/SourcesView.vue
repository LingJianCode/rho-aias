<template>
  <div class="sources-view">
    <div class="page-header">
      <h2>数据源状态</h2>
    </div>

    <el-card>
      <el-table :data="sources" v-loading="loading" stripe>
        <el-table-column prop="source_name" label="名称" min-width="150" />
        <el-table-column prop="source_type" label="类型" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ formatSourceType(row.source_type) }}</el-tag>
          </template>
        </el-table-column>
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
        <el-table-column prop="updated_at" label="最后更新" width="180">
          <template #default="{ row }">
            {{ row.updated_at ? formatDateTime(row.updated_at) : '-' }}
          </template>
        </el-table-column>
        <el-table-column prop="error_message" label="错误信息" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">{{ row.error_message || '-' }}</template>
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
import type { SourceStatusRecord } from '@/types/api'

const loading = ref(false)
const sources = ref<SourceStatusRecord[]>([])

function formatSourceType(type: string) {
  const types: Record<string, string> = {
    intel: '威胁情报',
    geo_blocking: '地域封禁',
  }
  return types[type] || type
}

function getStatusType(status: string) {
  return status === 'success' ? 'success' : status === 'failed' ? 'danger' : 'info'
}

function getStatusLabel(status: string) {
  return status === 'success' ? '正常' : status === 'failed' ? '异常' : '未知'
}

async function fetchSources() {
  loading.value = true
  try {
    const res = await getSourcesStatus()
    // 后端返回嵌套结构 { "intel": { "ipsum": {...}, ... }, ... }
    // 扁平化为数组
    const records: SourceStatusRecord[] = []
    const data = res.data
    for (const sourceType of Object.keys(data)) {
      const sourcesByType = data[sourceType]
      for (const sourceId of Object.keys(sourcesByType)) {
        records.push(sourcesByType[sourceId])
      }
    }
    sources.value = records
  } catch {
    // 模拟数据（已注释保留作为格式提示）：
    // sources.value = [
    //   { id: 1, source_type: 'intel', source_id: 'ipsum', source_name: 'IPsum', status: 'success', rule_count: 15000, error_message: '', duration: 0, updated_at: new Date().toISOString() },
    //   { id: 2, source_type: 'intel', source_id: 'spamhaus', source_name: 'Spamhaus DROP', status: 'success', rule_count: 2500, error_message: '', duration: 0, updated_at: new Date().toISOString() },
    //   { id: 3, source_type: 'geo_blocking', source_id: 'maxmind', source_name: 'MaxMind GeoIP', status: 'success', rule_count: 500000, error_message: '', duration: 0, updated_at: new Date().toISOString() },
    // ]
    sources.value = []
  } finally {
    loading.value = false
  }
}

async function handleRefresh(row: SourceStatusRecord) {
  try {
    await refreshSource(row.source_type, row.source_id)
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
