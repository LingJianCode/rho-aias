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

    <!-- 阻断趋势 -->
    <div class="chart-card">
      <div class="card-title-row">
        <span class="card-icon">📈</span>
        <span class="card-title">阻断趋势</span>
        <span class="card-subtitle">近24小时</span>
      </div>
      <div ref="chartRef" class="chart-container"></div>
    </div>

    <!-- TOP 阻断 IP -->
    <div class="topip-card">
      <div class="card-title-row">
        <span class="card-icon">🎯</span>
        <span class="card-title">TOP 阻断 IP</span>
      </div>
      <div v-if="topIPs.length" class="topip-grid">
        <div v-for="(item, index) in topIPs" :key="item.ip" class="topip-item" :class="{ 'top3': index < 3 }">
          <div class="topip-header">
            <span class="topip-rank">{{ index + 1 }}</span>
            <span class="topip-ip">{{ item.ip }}</span>
            <span class="topip-count">{{ formatNumber(item.count) }}</span>
          </div>
          <div class="topip-bar-wrap">
            <div class="topip-bar" :style="{ width: getIPPercentage(item.count) + '%' }"></div>
          </div>
        </div>
      </div>
      <el-empty v-else description="暂无数据" :image-size="60" />
    </div>
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
  const primaryColor = getComputedStyle(document.documentElement).getPropertyValue('--el-color-primary').trim() || '#FF80CB'
  chart.setOption({
    tooltip: {
      trigger: 'axis',
      backgroundColor: 'rgba(255,255,255,0.95)',
      borderColor: '#eee',
      textStyle: { color: '#333', fontSize: 12 },
      axisPointer: { type: 'cross', crossStyle: { color: '#999' } },
      formatter: (params: any) => `<strong>${params[0].axisValue}</strong><br/>阻断数：<b style="color:${primaryColor}">${params[0].value}</b>`
    },
    grid: { left: '3%', right: '4%', bottom: '8%', top: '10%', containLabel: true },
    xAxis: {
      type: 'category',
      data: blockTrend.value.map((d) => d.date),
      axisLabel: { rotate: 30, color: '#999', fontSize: 11 },
      axisLine: { lineStyle: { color: '#e8e8e8' } },
      axisTick: { show: false }
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: '#f5f5f5', type: 'dashed' } },
      axisLabel: { color: '#999', fontSize: 11 }
    },
    series: [{
      type: 'line',
      smooth: true,
      symbol: 'circle',
      symbolSize: 6,
      showSymbol: false,
      lineStyle: { width: 2.5, color: primaryColor },
      itemStyle: { color: primaryColor },
      areaStyle: {
        color: {
          type: 'linear',
          x: 0, y: 0, x2: 0, y2: 1,
          colorStops: [
            { offset: 0, color: primaryColor + '40' },
            { offset: 1, color: primaryColor + '08' }
          ]
        }
      },
      data: blockTrend.value.map((d) => d.count)
    }]
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
  display: flex;
  flex-direction: column;
  gap: 16px;
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
}

.group-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--el-text-color-secondary);
  padding-right: 4px;
  white-space: nowrap;
}

/* ====== 图表卡片 ====== */
.chart-card,
.topip-card {
  background: var(--el-bg-color);
  border-radius: 12px;
  border: 1px solid var(--el-border-color-lighter);
  padding: 20px 24px;
  transition: box-shadow 0.3s;

  &:hover {
    box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
  }
}

.card-title-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 16px;
}

.card-icon {
  font-size: 18px;
}

.card-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}

.card-subtitle {
  font-size: 12px;
  color: var(--el-text-color-placeholder);
  margin-left: auto;
}

.chart-container {
  height: 280px;
  width: 100%;
}

/* ====== TOP IP 网格 ====== */
.topip-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  gap: 12px;
}

.topip-item {
  background: var(--el-fill-color-extra-light);
  border-radius: 10px;
  padding: 14px 16px;
  transition: all 0.25s ease;
  border-left: 3px solid transparent;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.06);
    background: var(--el-fill-color-light);
  }

  &.top3:nth-child(1) { border-left-color: #FF80CB; }
  &.top3:nth-child(2) { border-left-color: #B48DF3; }
  &.top3:nth-child(3) { border-left-color: #38C0FC; }
}

.topip-header {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}

.topip-rank {
  width: 22px;
  height: 22px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  font-weight: 700;
  flex-shrink: 0;
  background: var(--el-fill-color);
  color: var(--el-text-color-secondary);

  .top3:nth-child(1) &,
  .topip-item.top3:nth-child(1) & {
    background: linear-gradient(135deg, #FF80CB, #ff6eb5);
    color: #fff;
  }
  .topip-item.top3:nth-child(2) & {
    background: linear-gradient(135deg, #B48DF3, #9d73e8);
    color: #fff;
  }
  .topip-item.top3:nth-child(3) & {
    background: linear-gradient(135deg, #38C0FC, #1daaf5);
    color: #fff;
  }
}

.topip-ip {
  font-size: 13px;
  font-family: ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace;
  color: var(--el-text-color-regular);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.topip-count {
  font-size: 15px;
  font-weight: 700;
  color: var(--el-text-color-primary);
  flex-shrink: 0;
  font-variant-numeric: tabular-nums;
}

.topip-bar-wrap {
  height: 6px;
  background: var(--el-fill-color);
  border-radius: 3px;
  overflow: hidden;
}

.topip-bar {
  height: 100%;
  border-radius: 3px;
  background: linear-gradient(90deg, var(--el-color-primary), var(--el-color-primary-light-3));
  transition: width 0.6s cubic-bezier(0.22, 1, 0.36, 1);
  min-width: 4px;
}
</style>
