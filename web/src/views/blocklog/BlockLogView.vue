<template>
  <div class="blocklog-view">
    <div class="page-header">
      <h2>阻断日志</h2>
    </div>

    <el-row :gutter="12" class="stats-row">
      <el-col :span="5">
        <StatsCard label="阻断总数" :value="stats.total_blocks" :icon="DataLine" icon-color="#409eff" />
      </el-col>
      <el-col :span="5">
        <StatsCard label="阻断 IP 数" :value="stats.unique_ips" :icon="Monitor" icon-color="#67c23a" />
      </el-col>
      <el-col :span="5">
        <StatsCard label="涉及国家" :value="stats.top_countries.length" :icon="Location" icon-color="#e6a23c" />
      </el-col>
      <el-col :span="5">
        <StatsCard label="数据来源" :value="stats.top_sources.length" :icon="Connection" icon-color="#909399" />
      </el-col>
    </el-row>

    <el-card class="filter-card">
      <el-form :inline="true" :model="filters" class="filter-form">
        <el-form-item label="时间范围">
          <el-date-picker
            v-model="dateRange"
            type="datetimerange"
            range-separator="至"
            start-placeholder="开始时间"
            end-placeholder="结束时间"
            format="YYYY-MM-DD HH:mm:ss"
            value-format="YYYY-MM-DD HH:mm:ss"
            :shortcuts="timeShortcuts"
            style="width: 360px"
          />
        </el-form-item>
        <el-form-item label="搜索 IP">
          <el-input
            v-model="filters.ip"
            placeholder="输入 IP"
            clearable
            style="width: 180px"
            @clear="handleSearch"
            @keyup.enter="handleSearch"
          />
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="filters.source" placeholder="全部来源" clearable style="width: 140px" @change="handleSearch">
            <el-option label="手动" value="manual" />
            <!-- 注：大数据源（ipsum、spamhaus）规则量巨大，不在列表页展示 -->
            <el-option label="WAF" value="waf" />
            <el-option label="DDoS" value="ddos" />
            <el-option label="异常检测" value="anomaly" />
            <el-option label="FailGuard" value="failguard" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">查询</el-button>
          <el-button @click="handleReset">重置</el-button>
          <el-button type="danger" v-if="authStore.hasPermission('blocklog:clear')" @click="handleClear">
            清除日志
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card>

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
import { DataLine, Monitor, Location, Connection } from '@element-plus/icons-vue'
import StatsCard from '@/components/StatsCard.vue'
import RuleSourceTag from '@/components/RuleSourceTag.vue'
import CountryFlag from '@/components/CountryFlag.vue'
import { formatDateTime, formatBytes } from '@/utils/format'
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
const filters = reactive({
  ip: '',
  source: '',
})

const timeShortcuts = [
  {
    text: '今天',
    value: () => {
      const start = new Date()
      start.setHours(0, 0, 0, 0)
      return [start, new Date()]
    },
  },
  {
    text: '最近7天',
    value: () => {
      const end = new Date()
      const start = new Date()
      start.setTime(start.getTime() - 7 * 24 * 3600 * 1000)
      return [start, end]
    },
  },
  {
    text: '最近30天',
    value: () => {
      const end = new Date()
      const start = new Date()
      start.setTime(start.getTime() - 30 * 24 * 3600 * 1000)
      return [start, end]
    },
  },
]

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
    // Error handled
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
      ip: filters.ip || undefined,
      source: filters.source || undefined,
    })
    logs.value = res.data.records.map((r: any) => ({
      ...r,
      source: r.source || r.rule_source,
      timestamp: typeof r.timestamp === 'number' ? new Date(r.timestamp / 1e6).toISOString() : r.timestamp,
    }))
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
  dateRange.value = null
  filters.ip = ''
  filters.source = ''
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
