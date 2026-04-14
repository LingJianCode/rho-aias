<template>
  <el-card v-loading="loading" class="status-panel">
    <template #header>
      <div class="panel-header">
        <div class="panel-title">
          <el-icon><Monitor /></el-icon>
          <span>威胁情报 & 事件上报</span>
        </div>
        <el-button type="primary" size="small" @click="handleRefresh" :loading="refreshing">
          刷新情报
        </el-button>
      </div>
    </template>

    <el-descriptions :column="3" border>
      <el-descriptions-item label="情报状态">
        <el-tag :type="intelStatus.enabled ? 'success' : 'info'" size="small">
          {{ intelStatus.enabled ? '已启用' : '已禁用' }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="总规则数">
        {{ formatNumber(intelStatus.total_rules) }}
      </el-descriptions-item>
      <el-descriptions-item label="最后更新">
        {{ intelStatus.last_update ? formatRelativeTime(intelStatus.last_update) : '-' }}
      </el-descriptions-item>
    </el-descriptions>

    <el-divider content-position="left">事件上报</el-divider>
    <el-descriptions :column="2" border>
      <el-descriptions-item label="上报状态">
        <el-tag :type="eventStatus.enabled ? 'success' : 'info'" size="small">
          {{ eventStatus.enabled ? '已启用' : '已禁用' }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="采样率">
        每 {{ eventStatus.sample_rate || '-' }} 个包上报 1 次
      </el-descriptions-item>
    </el-descriptions>

    <div v-if="intelSourceList.length > 0" style="margin-top: 16px">
      <h4 style="margin-bottom: 12px">情报数据源</h4>
      <el-table :data="intelSourceList" stripe size="small">
        <el-table-column prop="name" label="名称" min-width="120" />
        <el-table-column prop="enabled" label="启用" width="80">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
              {{ row.enabled ? '是' : '否' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule_count" label="规则数" width="100">
          <template #default="{ row }">{{ formatNumber(row.rule_count) }}</template>
        </el-table-column>
        <el-table-column prop="success" label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="row.success ? 'success' : 'danger'" size="small">
              {{ row.success ? '正常' : '异常' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="error" label="错误信息" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ row.error || '-' }}</template>
        </el-table-column>
        <el-table-column prop="last_update" label="最后更新" width="170">
          <template #default="{ row }">
            {{ row.last_update ? formatDateTime(row.last_update) : '-' }}
          </template>
        </el-table-column>
      </el-table>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Monitor } from '@element-plus/icons-vue'
import { getIntelStatus, triggerIntelUpdate } from '@/api/intel'
import { getEventStatus } from '@/api/events'
import { formatDateTime, formatNumber, formatRelativeTime } from '@/utils/format'
import type { IntelStatus, EventStatus } from '@/types/api'

const loading = ref(false)
const refreshing = ref(false)
const intelStatus = ref<IntelStatus>({
  enabled: false,
  last_update: '',
  total_rules: 0,
  sources: {},
})
const eventStatus = ref<EventStatus>({
  enabled: false,
  sample_rate: 0,
})

const intelSourceList = computed(() => {
  return Object.entries(intelStatus.value.sources).map(([name, info]) => ({
    name,
    ...info,
  }))
})

async function fetchData() {
  loading.value = true
  try {
    const [intelRes, eventRes] = await Promise.all([
      getIntelStatus(),
      getEventStatus(),
    ])
    intelStatus.value = intelRes.data
    eventStatus.value = eventRes.data
  } finally {
    loading.value = false
  }
}

async function handleRefresh() {
  refreshing.value = true
  try {
    ElMessage.success('情报刷新已触发')
    fetchData()
  } catch {
    // Error handled
  } finally {
    refreshing.value = false
  }
}

onMounted(() => fetchData())
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
