<template>
  <div class="egresslog-view">
    <div class="page-header">
      <h2>Egress 丢包日志</h2>
    </div>

    <el-card class="filter-card">
      <el-form :inline="true" :model="filters" class="filter-form">
        <el-form-item label="查询日期">
          <el-date-picker
            v-model="selectedDate"
            type="date"
            placeholder="选择日期"
            format="YYYY-MM-DD"
            value-format="YYYY-MM-DD"
            style="width: 160px"
          />
        </el-form-item>
        <el-form-item label="小时范围">
          <el-select v-model="filters.start_hour" placeholder="起始" style="width: 80px">
            <el-option v-for="h in 24" :key="h - 1" :label="String(h - 1).padStart(2, '0')" :value="h - 1" />
          </el-select>
          <span style="margin: 0 4px">-</span>
          <el-select v-model="filters.end_hour" placeholder="结束" style="width: 80px">
            <el-option v-for="h in 24" :key="h - 1" :label="String(h - 1).padStart(2, '0')" :value="h - 1" />
          </el-select>
        </el-form-item>
        <el-form-item label="目标 IP">
          <el-input
            v-model="filters.dst_ip"
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
    </el-card>

    <el-card>
      <el-table :data="logs" v-loading="loading" stripe>
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatNanoTimestamp(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="dst_ip" label="目标 IP" min-width="140" />
        <el-table-column prop="pkt_len" label="包大小" width="110">
          <template #default="{ row }">{{ formatBytes(row.pkt_len) }}</template>
        </el-table-column>
        <el-table-column prop="tokens" label="令牌数" width="130">
          <template #default="{ row }">{{ formatNumber(row.tokens) }}</template>
        </el-table-column>
        <el-table-column prop="rate_bytes" label="限速速率" width="130">
          <template #default="{ row }">{{ formatRate(row.rate_bytes) }}</template>
        </el-table-column>
      </el-table>

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
import { formatBytes, formatNanoTimestamp, formatNumber } from '@/utils/format'

function formatRate(bytesPerSec: number): string {
  if (!bytesPerSec) return '-'
  const mbps = bytesPerSec * 8 / 1_000_000
  return mbps.toFixed(1) + ' Mbps'
}

import { getEgressLogs } from '@/api/egresslog'
import type { EgressLogRecord } from '@/types/api'

const loading = ref(false)
const logs = ref<EgressLogRecord[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const now = new Date()
const defaultDate = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`
const selectedDate = ref<string>(defaultDate)
const filters = reactive({
  start_hour: 0,
  end_hour: 23,
  dst_ip: '',
})

async function fetchLogs() {
  if (!selectedDate.value) {
    logs.value = []
    total.value = 0
    return
  }
  loading.value = true
  try {
    const res = await getEgressLogs({
      date: selectedDate.value,
      start_hour: filters.start_hour,
      end_hour: filters.end_hour,
      dst_ip: filters.dst_ip || undefined,
      page: page.value,
      page_size: pageSize.value,
    })
    logs.value = res.data.records
    total.value = res.data.total
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
  const now = new Date()
  selectedDate.value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`
  filters.start_hour = 0
  filters.end_hour = 23
  filters.dst_ip = ''
  page.value = 1
  fetchLogs()
}

onMounted(() => {
  fetchLogs()
})
</script>

<style lang="scss" scoped>
.filter-card {
  margin-bottom: 16px;
}

.filter-form {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
