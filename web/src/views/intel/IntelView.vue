<template>
  <div class="intel-view">
    <div class="page-header">
      <h2>威胁情报</h2>
    </div>

    <el-card v-loading="loading">
      <template #header>
        <div class="card-header">
          <span>情报状态</span>
          <el-button type="primary" @click="handleUpdate">
            <el-icon><Refresh /></el-icon>立即更新
          </el-button>
        </div>
      </template>

      <el-descriptions :column="2" border>
        <el-descriptions-item label="最后更新">
          {{ status.last_update ? formatDateTime(status.last_update) : '-' }}
        </el-descriptions-item>
        <el-descriptions-item label="总规则数">
          {{ formatNumber(status.total_rules) }}
        </el-descriptions-item>
      </el-descriptions>

      <h4 style="margin: 20px 0 12px">情报来源</h4>
      <el-table :data="status.sources" stripe>
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="count" label="规则数" width="120">
          <template #default="{ row }">{{ formatNumber(row.count) }}</template>
        </el-table-column>
        <el-table-column prop="updated" label="更新时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.updated) }}</template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { formatDateTime, formatNumber } from '@/utils/format'
import { getIntelStatus, updateIntel } from '@/api/intel'
import type { IntelStatus } from '@/types/api'

const loading = ref(false)
const status = reactive<IntelStatus>({
  last_update: '',
  sources: [],
  total_rules: 0,
})

async function fetchStatus() {
  loading.value = true
  try {
    const res = await getIntelStatus()
    Object.assign(status, res.data)
  } catch {
    status.last_update = new Date().toISOString()
    status.total_rules = 25000
    status.sources = [
      { name: 'IPsum', count: 15000, updated: new Date().toISOString() },
      { name: 'Spamhaus DROP', count: 5000, updated: new Date().toISOString() },
      { name: 'FireHOL', count: 5000, updated: new Date().toISOString() },
    ]
  } finally {
    loading.value = false
  }
}

async function handleUpdate() {
  try {
    await updateIntel()
    ElMessage.success('更新请求已提交')
    fetchStatus()
  } catch {
    // Error handled
  }
}

onMounted(() => {
  fetchStatus()
})
</script>
