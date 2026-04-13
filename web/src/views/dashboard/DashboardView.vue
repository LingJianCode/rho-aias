<template>
  <div class="dashboard-view">
    <div class="page-header">
      <h2>仪表盘</h2>
    </div>

    <!-- 第一行：系统运行状态概览 -->
    <el-row :gutter="12" class="stats-row">
      <el-col :span="6" @click="$router.push('/security')">
        <div class="stat-card-clickable">
          <StatsCard label="XDP 事件上报" :value="systemStatus.eventEnabled ? 1 : 0" :icon="Connection" icon-color="#409eff" />
          <span class="card-sub">{{ systemStatus.eventEnabled ? '运行中' : '已停止' }}</span>
        </div>
      </el-col>
      <el-col :span="6" @click="$router.push('/security')">
        <div class="stat-card-clickable">
          <StatsCard label="威胁情报规则" :value="systemStatus.intelTotalRules" :icon="Cpu" icon-color="#67c23a" />
          <span class="card-sub">{{ systemStatus.intelEnabled ? '已启用' : '未启用' }}</span>
        </div>
      </el-col>
      <el-col :span="6" @click="$router.push('/settings/config')">
        <div class="stat-card-clickable">
          <StatsCard label="地域封禁规则" :value="systemStatus.geoTotalRules" :icon="Location" icon-color="#e6a23c" />
          <span class="card-sub">{{ systemStatus.geoMode === 'whitelist' ? '白名单' : systemStatus.geoMode === 'blacklist' ? '黑名单' : '未启用' }}</span>
        </div>
      </el-col>
      <el-col :span="6" @click="$router.push('/firewall/blacklist')">
        <div class="stat-card-clickable">
          <StatsCard label="生效封禁数" :value="systemStatus.activeBans" :icon="Lock" icon-color="#f56c6c" />
          <span class="card-sub">共 {{ systemStatus.totalBans }} 条</span>
        </div>
      </el-col>
    </el-row>

    <!-- 第二行：阻断态势图 + TOP 被封国家/来源 -->
    <el-row :gutter="20">
      <el-col :span="16">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>阻断趋势</span>
            </div>
          </template>
          <div ref="chartRef" style="height: 300px"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card>
          <template #header>
            <div class="card-header">
              <span>TOP 被封国家</span>
            </div>
          </template>
          <div v-if="topCountries.length" class="rank-list">
            <div v-for="(item, index) in topCountries" :key="item.country" class="rank-item">
              <span class="rank-index" :class="{ 'top3': index < 3 }">{{ index + 1 }}</span>
              <CountryFlag :code="item.country" />
              <span class="rank-value">{{ formatNumber(item.count) }}</span>
              <el-progress
                :percentage="getPercentage(item.count)"
                :show-text="false"
                :stroke-width="6"
                :color="index === 0 ? '#409eff' : index === 1 ? '#67c23a' : index === 2 ? '#e6a23c' : '#909399'"
                style="flex: 1; margin-left: 12px"
              />
            </div>
          </div>
          <el-empty v-else description="暂无数据" :image-size="80" />
        </el-card>
      </el-col>
    </el-row>

    <!-- 第三行：最近阻断记录（快捷入口） -->
    <el-card style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>最近阻断记录</span>
          <el-button type="primary" link @click="$router.push('/logs/blocklog')">查看全部</el-button>
        </div>
      </template>
      <el-table :data="recentBlocks" stripe>
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="src_ip" label="源 IP" min-width="140" />
        <el-table-column prop="dst_ip" label="目的 IP" min-width="140" />
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
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import { Connection, Cpu, Location, Lock } from '@element-plus/icons-vue'
import StatsCard from '@/components/StatsCard.vue'
import RuleSourceTag from '@/components/RuleSourceTag.vue'
import CountryFlag from '@/components/CountryFlag.vue'
import { formatDateTime, formatNumber } from '@/utils/format'
// 系统状态类 API
import { getEventStatus } from '@/api/events'
import { getIntelStatus } from '@/api/intel'
import { getGeoBlockingStatus } from '@/api/geoblocking'
// 统计与趋势
import { getBlockLogStats, getBlockLogs, getBlockedCountries } from '@/api/blocklog'
import { getBanRecordStats } from '@/api/ban-records'

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

const systemStatus = reactive({
  eventEnabled: false,
  eventSampleRate: 0,
  intelEnabled: false,
  intelTotalRules: 0,
  geoEnabled: false,
  geoMode: '' as string,
  geoTotalRules: 0,
  activeBans: 0,
  totalBans: 0,
})

const topCountries = ref<{ country: string; count: number }[]>([])
const recentBlocks = ref<Record<string, unknown>[]>([])
const blockTrend = ref<{ date: string; count: number }[]>([])

async function fetchDashboardData() {
  await Promise.all([
    fetchSystemStatus(),
    fetchBanStats(),
    fetchBlockStatsAndTrend(),
    fetchTopCountries(),
    fetchRecentBlocks(),
  ])
  updateChart()
}

async function fetchSystemStatus() {
  try {
    const [eventRes, intelRes, geoRes] = await Promise.all([
      getEventStatus(),
      getIntelStatus(),
      getGeoBlockingStatus(),
    ])
    // XDP 上报状态
    if (eventRes.data) {
      systemStatus.eventEnabled = eventRes.data.enabled
      systemStatus.eventSampleRate = eventRes.data.sample_rate || 0
    }
    // 威胁情报状态
    if (intelRes.data) {
      systemStatus.intelEnabled = intelRes.data.enabled
      systemStatus.intelTotalRules = intelRes.data.total_rules || 0
    }
    // 地域封禁状态
    if (geoRes.data) {
      systemStatus.geoEnabled = geoRes.data.enabled
      systemStatus.geoMode = geoRes.data.mode || ''
      systemStatus.geoTotalRules = geoRes.data.total_rules || 0
    }
  } catch {
    // Error handled
  }
}

async function fetchBanStats() {
  try {
    const res = await getBanRecordStats()
    if (res.data) {
      systemStatus.activeBans = res.data.active || 0
      systemStatus.totalBans = res.data.total || 0
    }
  } catch {
    // Error handled
  }
}

async function fetchBlockStatsAndTrend() {
  try {
    const res = await getBlockLogStats()
    if (res.data) {
      blockTrend.value = (res.data.hourly_trend || []).map((item) => ({
        date: item.hour,
        count: item.count,
      }))
    }
  } catch {
    // Error handled
  }
}

async function fetchTopCountries() {
  try {
    const res = await getBlockedCountries(10)
    if (res.data?.top_blocked_countries) {
      topCountries.value = res.data.top_blocked_countries
    }
  } catch {
    // Error handled
  }
}

async function fetchRecentBlocks() {
  try {
    const res = await getBlockLogs({ page_size: 5 })
    if (res.data?.records) {
      recentBlocks.value = res.data.records
    }
  } catch {
    // Error handled
  }
}

function getPercentage(count: number): number {
  const max = topCountries.value[0]?.count || 1
  return Math.round((count / max) * 100)
}

function updateChart() {
  if (!chart || !blockTrend.value.length) return

  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: blockTrend.value.map((d) => d.date),
    },
    yAxis: { type: 'value' },
    series: [{
      type: 'line',
      smooth: true,
      areaStyle: { opacity: 0.3 },
      data: blockTrend.value.map((d) => d.count),
    }],
  })
}

onMounted(() => {
  fetchDashboardData()
  if (chartRef.value) {
    chart = echarts.init(chartRef.value)
  }
  window.addEventListener('resize', () => chart?.resize())
})

onUnmounted(() => {
  chart?.dispose()
  window.removeEventListener('resize', () => chart?.resize())
})
</script>

<style lang="scss" scoped>
.stat-card-clickable {
  cursor: pointer;
  transition: transform 0.15s;

  &:hover {
    transform: translateY(-2px);
  }

  .card-sub {
    display: block;
    text-align: center;
    font-size: 12px;
    color: var(--el-text-color-secondary);
    margin-top: -8px;
    margin-bottom: 4px;
  }
}

.rank-list {
  max-height: 300px;
  overflow-y: auto;
}

.rank-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);

  &:last-child {
    border-bottom: none;
  }
}

.rank-index {
  width: 22px;
  height: 22px;
  border-radius: 4px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 600;
  background-color: var(--el-fill-color-light);
  color: var(--el-text-color-secondary);
  flex-shrink: 0;

  &.top3 {
    background-color: var(--el-color-primary);
    color: #fff;
  }
}

.rank-value {
  font-size: 14px;
  font-weight: 600;
  color: var(--el-text-color-primary);
  min-width: 48px;
  text-align: right;
  flex-shrink: 0;
}
</style>
