<template>
  <div class="egresslog-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>Egress 日志</span>
        </div>
      </template>

      <!-- 查询条件 -->
      <el-form :inline="true" :model="filter" class="filter-form">
        <el-form-item label="查询日期">
          <el-date-picker v-model="filter.date" type="date" placeholder="选择日期" value-format="YYYY-MM-DD" style="width: 160px" />
        </el-form-item>
        <el-form-item label="小时范围">
          <el-select v-model="filter.start_hour" placeholder="起始" style="width: 80px">
            <el-option v-for="h in 24" :key="h - 1" :label="String(h - 1).padStart(2, '0')" :value="h - 1" />
          </el-select>
          <span style="margin: 0 4px">-</span>
          <el-select v-model="filter.end_hour" placeholder="结束" style="width: 80px">
            <el-option v-for="h in 24" :key="h - 1" :label="String(h - 1).padStart(2, '0')" :value="h - 1" />
          </el-select>
        </el-form-item>
        <el-form-item label="目标 IP">
          <el-input
            v-model="filter.dst_ip"
            placeholder="输入 IP"
            clearable
            style="width: 180px"
            @clear="handleSearch"
            @keyup.enter="handleSearch"
          />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">查询</el-button>
          <el-button @click="handleReset">重置</el-button>
        </el-form-item>
      </el-form>

      <!-- 日志表格 -->
      <el-table :data="logs" v-loading="loading" stripe size="small">
        <el-table-column prop="timestamp" label="时间" min-width="180">
          <template #default="{ row }">{{ formatNanoTimestamp(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="dst_ip" label="目标 IP" min-width="140" />
        <el-table-column prop="pkt_len" label="包大小" min-width="110">
          <template #default="{ row }">{{ formatBytes(row.pkt_len) }}</template>
        </el-table-column>
        <el-table-column prop="tokens" label="令牌数" min-width="130">
          <template #default="{ row }">{{ formatNumber(row.tokens) }}</template>
        </el-table-column>
        <el-table-column prop="rate_bytes" label="限速速率" min-width="130">
          <template #default="{ row }">{{ formatRate(row.rate_bytes) }}</template>
        </el-table-column>
      </el-table>

      <!-- 分页 -->
      <div class="pagination-wrapper">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="[20, 50, 100]"
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
import { ref, reactive, onMounted } from 'vue'
import { getEgressLogs } from '@/api/egresslog'
import { formatNanoTimestamp, formatBytes, formatNumber } from '@/utils/format'

function formatRate(bytesPerSec: number): string {
  if (!bytesPerSec) return '-'
  const mbps = bytesPerSec * 8 / 1_000_000
  return mbps.toFixed(1) + ' Mbps'
}

defineOptions({ name: 'EgressLog' })

const loading = ref(false)
const logs = ref<any[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const filter = reactive({
  date: new Date().toISOString().split('T')[0],
  dst_ip: '',
  start_hour: 0,
  end_hour: 23,
})

async function fetchLogs() {
  loading.value = true
  try {
    const res = await getEgressLogs({
      ...filter,
      page: page.value,
      page_size: pageSize.value,
    })
    logs.value = res.records || []
    total.value = res.total || 0
  } catch {
    logs.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  page.value = 1
  fetchLogs()
}

function handleReset() {
  filter.date = new Date().toISOString().split('T')[0]
  filter.dst_ip = ''
  filter.start_hour = 0
  filter.end_hour = 23
  handleSearch()
}

onMounted(() => fetchLogs())
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.filter-form {
  margin-bottom: 16px;
}

.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
