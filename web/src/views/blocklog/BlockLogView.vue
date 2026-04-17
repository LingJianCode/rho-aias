<template>
  <div class="blocklog-view">
    <div class="page-header">
      <h2>阻断日志</h2>
    </div>

    <el-row :gutter="12" class="stats-row">
      <el-col :span="5">
        <StatsCard label="阻断总数" :value="stats.total_blocked" :icon="DataLine" icon-color="#409eff" />
      </el-col>
      <el-col :span="5">
        <StatsCard label="阻断 IP 数" :value="stats.top_blocked_ips.length" :icon="Monitor" icon-color="#67c23a" />
      </el-col>
      <el-col :span="5">
        <StatsCard label="涉及国家" :value="stats.top_blocked_countries.length" :icon="Location" icon-color="#e6a23c" />
      </el-col>
      <el-col :span="5">
        <StatsCard label="数据来源" :value="Object.keys(stats.by_rule_source).length" :icon="Connection" icon-color="#909399" />
      </el-col>
    </el-row>

    <el-card class="filter-card">
      <el-form :inline="true" :model="filters" class="filter-form">
        <el-form-item label="查询时间">
          <el-date-picker
            v-model="selectedHour"
            type="datetime"
            placeholder="选择小时"
            format="YYYY-MM-DD HH:00"
            value-format="YYYY-MM-DD_HH"
            :disabled-hours="() => []"
            :disabled-minutes="() => Array.from({ length: 60 }, (_, i) => i)"
            :disabled-seconds="() => Array.from({ length: 60 }, (_, i) => i)"
            style="width: 200px"
          />
        </el-form-item>
        <el-form-item label="搜索 IP">
          <el-input
            v-model="filters.src_ip"
            placeholder="输入 IP"
            clearable
            style="width: 180px"
            @clear="handleSearch"
            @keyup.enter="handleSearch"
          />
        </el-form-item>
        <el-form-item label="匹配类型">
          <el-select v-model="filters.match_type" placeholder="全部" clearable style="width: 140px" @change="handleSearch">
            <el-option label="精确匹配" value="ip4_exact" />
            <el-option label="CIDR 匹配" value="ip4_cidr" />
            <el-option label="地域封禁" value="geo_block" />
          </el-select>
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="filters.rule_source" placeholder="全部来源" clearable style="width: 140px" @change="handleSearch">
            <el-option label="手动" value="manual" />
            <el-option label="WAF" value="waf" />
            <el-option label="DDoS" value="ddos" />
            <el-option label="异常检测" value="anomaly" />
            <el-option label="FailGuard" value="failguard" />
          </el-select>
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
        <el-table-column prop="src_ip" label="源 IP" min-width="140" />
        <el-table-column prop="dst_ip" label="目的 IP" min-width="140" />
        <el-table-column prop="match_type" label="匹配类型" width="100" />
        <el-table-column prop="rule_source" label="来源" width="100">
          <template #default="{ row }">
            <RuleSourceTag :source="row.rule_source" />
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

function formatNanoTimestamp(ts: number | string): string {
  if (typeof ts === 'number') {
    return formatDateTime(new Date(ts / 1e6).toISOString())
  }
  return formatDateTime(ts)
}
import { useConfirm } from '@/composables/useConfirm'
import { useAuthStore } from '@/stores/auth'
import { getBlockLogs, getBlockLogStats } from '@/api/blocklog'
import type { BlockLog, BlockLogStats } from '@/types/api'

const { confirm } = useConfirm()
const authStore = useAuthStore()

const loading = ref(false)
const logs = ref<BlockLog[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

// 默认当前小时
const now = new Date()
const defaultHour = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}`
const selectedHour = ref<string>(defaultHour)
const filters = reactive({
  src_ip: '',
  match_type: '',
  rule_source: '',
  country_code: '',
})

const stats = reactive<BlockLogStats>({
  total_blocked: 0,
  by_match_type: {},
  by_rule_source: {},
  by_country: {},
  top_blocked_ips: [],
  top_blocked_countries: [],
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
  if (!selectedHour.value) {
    logs.value = []
    total.value = 0
    return
  }
  loading.value = true
  try {
    const res = await getBlockLogs({
      hour: selectedHour.value,
      page: page.value,
      page_size: pageSize.value,
      src_ip: filters.src_ip || undefined,
      match_type: filters.match_type || undefined,
      rule_source: filters.rule_source || undefined,
      country_code: filters.country_code || undefined,
    })
    logs.value = res.data.records.map((r: any) => ({
      ...r,
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
  const now = new Date()
  selectedHour.value = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}_${String(now.getHours()).padStart(2, '0')}`
  filters.src_ip = ''
  filters.match_type = ''
  filters.rule_source = ''
  filters.country_code = ''
  page.value = 1
  fetchLogs()
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
