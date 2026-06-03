<template>
  <div class="dashboard-view">
    <!-- 封禁统计 -->
    <div class="metric-row">
      <span class="group-label">封禁</span>
      <MetricItem label="总数" :value="banStats.total" color="#409eff" />
      <MetricItem label="生效" :value="banStats.active" color="#67c23a" />
      <MetricItem label="过期" :value="banStats.expired" color="#909399" />
      <MetricItem label="今日" :value="banStats.today_count" color="#e6a23c" />
    </div>

    <!-- 阻断统计 -->
    <div class="metric-row">
      <span class="group-label">阻断</span>
      <MetricItem label="总计" :value="blockStats.total_blocked" color="#409eff" />
      <template v-for="(value, key) in blockStats.by_rule_source" :key="key">
        <MetricItem :label="key" :value="value" color="#67c23a" />
      </template>
    </div>

    <!-- 阻断态势图 + TOP 被封 IP -->
    <el-row :gutter="20">
      <el-col :span="16">
        <el-card shadow="never" class="art-card">
          <template #header><div class="card-header"><span>阻断趋势</span></div></template>
          <div ref="chartRef" style="height: 300px"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="never" class="art-card">
          <template #header><div class="card-header"><span>TOP 阻断 IP</span></div></template>
          <div v-if="topIPs.length" class="rank-list">
            <div v-for="(item, index) in topIPs" :key="item.ip" class="rank-item">
              <span class="rank-index" :class="{ 'top3': index < 3 }">{{ index + 1 }}</span>
              <span class="rank-ip">{{ item.ip }}</span>
              <span class="rank-value">{{ formatNumber(item.count) }}</span>
              <el-progress
                :percentage="getIPPercentage(item.count)"
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
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import MetricItem from './components/MetricItem.vue'
import { formatNumber } from '@/utils/format'
import { getBanRecordStats } from '@/api/ban-records'
import { getBlockLogStats, getHourlyTrend, getBlockedTopIPs } from '@/api/blocklog'

defineOptions({ name: 'Dashboard' })

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

const topIPs = ref<{ ip: string; count: number }[]>([])
const blockTrend = ref<{ date: string; count: number }[]>([])

const banStats = reactive({ total: 0, active: 0, expired: 0, today_count: 0 })
const blockStats = reactive({ total_blocked: 0, by_rule_source: {} as Record<string, number> })

async function fetchDashboardData() {
  await Promise.all([fetchBanStats(), fetchBlockStats(), fetchBlockTrend(), fetchTopIPs()])
  updateChart()
}

async function fetchBanStats() {
  try {
    const res = await getBanRecordStats()
    Object.assign(banStats, res)
  } catch {}
}

async function fetchBlockStats() {
  try {
    const res = await getBlockLogStats()
    Object.assign(blockStats, res)
  } catch {}
}

async function fetchBlockTrend() {
  try {
    const res = await getHourlyTrend(24)
    const data = res?.data ?? res
    if (data?.hourly_data) {
      blockTrend.value = data.hourly_data.map((item: any) => ({ date: item.hour, count: item.total }))
    }
  } catch {}
}

async function fetchTopIPs() {
  try {
    const res = await getBlockedTopIPs(10)
    const data = res?.data ?? res
    if (data?.top_blocked_ips) topIPs.value = data.top_blocked_ips
  } catch {}
}

function getIPPercentage(count: number): number {
  return Math.round((count / (topIPs.value[0]?.count || 1)) * 100)
}

function updateChart() {
  if (!chart || !blockTrend.value.length) return
  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: { type: 'category', data: blockTrend.value.map((d) => d.date), axisLabel: { rotate: 30 } },
    yAxis: { type: 'value' },
    series: [{ type: 'line', smooth: true, areaStyle: { opacity: 0.3 }, data: blockTrend.value.map((d) => d.count) }],
  })
}

onMounted(() => {
  fetchDashboardData()
  if (chartRef.value) chart = echarts.init(chartRef.value)
  window.addEventListener('resize', handleResize)
})

const handleResize = () => chart?.resize()

onUnmounted(() => {
  chart?.dispose()
  window.removeEventListener('resize', handleResize)
})
</script>

<style lang="scss" scoped>
.dashboard-view {
  padding: 16px;
}

/* 指标行 */
.metric-row {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 14px 20px;
  background-color: var(--el-bg-color);
  border-radius: var(--el-border-radius-base);
  border: 1px solid var(--el-border-color-lighter);
  flex-wrap: wrap;
  margin-bottom: 12px;
}

.group-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--el-text-color-secondary);
  padding-right: 4px;
  white-space: nowrap;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-weight: 600;
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
  &:last-child { border-bottom: none; }
}

.rank-index {
  width: 22px; height: 22px; border-radius: 4px;
  display: flex; align-items: center; justify-content: center;
  font-size: 12px; font-weight: 600;
  background-color: var(--el-fill-color-light);
  color: var(--el-text-color-secondary); flex-shrink: 0;
  &.top3 { background-color: var(--el-color-primary); color: #fff; }
}

.rank-value {
  font-size: 14px; font-weight: 600;
  color: var(--el-text-color-primary); min-width: 48px; text-align: right; flex-shrink: 0;
}

.rank-ip {
  font-size: 13px; font-family: monospace;
  color: var(--el-text-color-primary); min-width: 100px; flex-shrink: 0;
}
</style>
