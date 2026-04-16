<template>
  <el-card v-loading="loading" class="status-panel">
    <template #header>
      <div class="panel-header">
        <div class="panel-title">
          <el-icon><Connection /></el-icon>
          <span>数据源健康</span>
        </div>
        <el-button size="small" @click="fetchSources">
          <el-icon><Refresh /></el-icon> 刷新
        </el-button>
      </div>
    </template>

    <el-table :data="sources" stripe size="small" max-height="400">
      <el-table-column prop="source_name" label="名称" min-width="140" />
      <el-table-column prop="source_type" label="类型" width="110">
        <template #default="{ row }">
          <el-tag size="small">{{ formatSourceType(row.source_type) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="status" label="状态" width="85">
        <template #default="{ row }">
          <el-tag :type="getStatusType(row.status)" size="small">
            {{ getStatusLabel(row.status) }}
          </el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="rule_count" label="规则数" width="95">
        <template #default="{ row }">{{ formatNumber(row.rule_count) }}</template>
      </el-table-column>
      <el-table-column prop="updated_at" label="最后更新" width="165">
        <template #default="{ row }">
          {{ row.updated_at ? formatRelativeTime(row.updated_at) : '-' }}
        </template>
      </el-table-column>
      <el-table-column label="操作" width="80">
        <template #default="{ row }">
          <el-button type="primary" link size="small" @click="handleRefresh(row)">刷新</el-button>
        </template>
      </el-table-column>
    </el-table>
  </el-card>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh, Connection } from '@element-plus/icons-vue'
import { getSourcesStatus, refreshSource } from '@/api/sources'
import { formatNumber, formatRelativeTime } from '@/utils/format'
import type { SourceStatusRecord } from '@/types/api'

const loading = ref(false)
const sources = ref<SourceStatusRecord[]>([])

function formatSourceType(type: string): string {
  const map: Record<string, string> = { intel: '威胁情报', geo_blocking: '地域封禁' }
  return map[type] || type
}

function getStatusType(status: string): 'success' | 'danger' | 'info' {
  return status === 'success' ? 'success' : status === 'failed' ? 'danger' : 'info'
}

function getStatusLabel(status: string): string {
  return status === 'success' ? '正常' : status === 'failed' ? '异常' : '未知'
}

async function fetchSources() {
  loading.value = true
  try {
    const res = await getSourcesStatus()
    const records: SourceStatusRecord[] = []
    for (const sourceType of Object.keys(res.data)) {
      for (const sourceId of Object.keys(res.data[sourceType])) {
        records.push(res.data[sourceType][sourceId])
      }
    }
    sources.value = records
  } catch {
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

onMounted(() => fetchSources())
</script>

<style lang="scss" scoped>
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.panel-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
}
</style>
