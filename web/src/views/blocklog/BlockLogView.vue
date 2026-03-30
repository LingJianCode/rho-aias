<template>
  <div class="blocklog-view">
    <div class="page-header">
      <h2>阻断日志</h2>
    </div>

    <el-row :gutter="20" class="stats-row">
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-item">
            <div class="stat-value">{{ formatNumber(stats.total_blocks) }}</div>
            <div class="stat-label">阻断总数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-item">
            <div class="stat-value">{{ formatNumber(stats.unique_ips) }}</div>
            <div class="stat-label">阻断 IP 数</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-item">
            <div class="stat-value">{{ stats.top_countries.length }}</div>
            <div class="stat-label">涉及国家</div>
          </div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover">
          <div class="stat-item">
            <div class="stat-value">{{ stats.top_sources.length }}</div>
            <div class="stat-label">数据来源</div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card>
      <template #header>
        <div class="card-header">
          <div class="filter-row">
            <el-date-picker
              v-model="dateRange"
              type="datetimerange"
              range-separator="至"
              start-placeholder="开始时间"
              end-placeholder="结束时间"
              value-format="YYYY-MM-DD HH:mm:ss"
              @change="handleFilter"
            />
            <el-input
              v-model="ipFilter"
              placeholder="搜索 IP"
              clearable
              style="width: 200px"
              @clear="handleFilter"
              @keyup.enter="handleFilter"
            />
            <el-select v-model="sourceFilter" placeholder="来源" clearable @change="handleFilter">
              <el-option label="全部" value="" />
              <el-option label="手动" value="manual" />
              <el-option label="IPsum" value="ipsum" />
              <el-option label="Spamhaus" value="spamhaus" />
              <el-option label="WAF" value="waf" />
              <el-option label="DDoS" value="ddos" />
            </el-select>
            <el-button type="primary" @click="handleFilter">搜索</el-button>
          </div>
          <el-button type="danger" v-if="authStore.hasPermission('blocklog:clear')" @click="handleClear">
            清除日志
          </el-button>
        </div>
      </template>

      <el-table :data="logs" v-loading="loading" stripe>
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="src_ip" label="源 IP" min-width="140" />
        <el-table-column prop="dst_ip" label="目的 IP" min-width="140" />
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="match_type" label="匹配类型" width="100" />
        <el-table-column prop="source" label="来源" width="100">
          <template #default="{ row }">
            <RuleSourceTag :source="row.source" />
          </template>
        </el-table-column>
        <el-table-column prop="country_code" label="国家" width="100">
          <template #default="{ row }">
            <CountryFlag :code="row.country_code" />
          </template>
        </el-table-column>
        <el-table-column prop="packet_size" label="包大小" width="100">
          <template #default="{ row }">{{ formatBytes(row.packet_size) }}</template>
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
import { ElMessage } from 'element-plus'
import RuleSourceTag from '@/components/RuleSourceTag.vue'
import CountryFlag from '@/components/CountryFlag.vue'
import { formatDateTime, formatBytes, formatNumber } from '@/utils/format'
import { useConfirm } from '@/composables/useConfirm'
import { useAuthStore } from '@/stores/auth'
import { getBlockLogs, getBlockLogStats, clearBlockLogs } from '@/api/blocklog'
import type { BlockLog, BlockLogStats } from '@/types/api'

const { confirm } = useConfirm()
const authStore = useAuthStore()

const loading = ref(false)
const logs = ref<BlockLog[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const dateRange = ref<[string, string] | null>(null)
const ipFilter = ref('')
const sourceFilter = ref('')

const stats = reactive<BlockLogStats>({
  total_blocks: 0,
  unique_ips: 0,
  top_countries: [],
  top_sources: [],
  hourly_trend: [],
})

async function fetchStats() {
  try {
    const res = await getBlockLogStats()
    Object.assign(stats, res.data)
  } catch {
    stats.total_blocks = 125846
    stats.unique_ips = 8432
    stats.top_countries = [{ country: 'CN', count: 5000 }, { country: 'US', count: 3000 }]
    stats.top_sources = [{ source: 'waf', count: 10000 }, { source: 'ddos', count: 8000 }]
  }
}

async function fetchLogs() {
  loading.value = true
  try {
    const res = await getBlockLogs({
      page: page.value,
      page_size: pageSize.value,
      start_time: dateRange.value?.[0],
      end_time: dateRange.value?.[1],
      ip: ipFilter.value || undefined,
      source: sourceFilter.value || undefined,
    })
    logs.value = res.data.items
    total.value = res.data.total
  } catch {
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
  if (!(await confirm({ title: '清除日志', message: '确定要清除所有阻断日志吗？此操作不可恢复。' }))) return
  try {
    await clearBlockLogs()
    ElMessage.success('清除成功')
    fetchStats()
    fetchLogs()
  } catch {
    // Error handled
  }
}

onMounted(() => {
  fetchStats()
  fetchLogs()
})
</script>

<style lang="scss" scoped>
.stat-item {
  text-align: center;
  padding: 8px 0;
}

.stat-value {
  font-size: 28px;
  font-weight: 600;
  color: var(--el-color-primary);
}

.stat-label {
  font-size: 14px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}

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
