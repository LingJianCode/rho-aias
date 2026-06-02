<template>
  <div class="dashboard-console">
    <!-- 阻断态势图 + TOP 被封 IP -->
    <el-row :gutter="20">
      <el-col :span="16">
        <el-card shadow="never" class="art-card">
          <template #header>
            <div class="card-header">
              <span>阻断趋势</span>
            </div>
          </template>
          <div ref="chartRef" style="height: 300px"></div>
        </el-card>
      </el-col>
      <el-col :span="8">
        <el-card shadow="never" class="art-card">
          <template #header>
            <div class="card-header">
              <span>TOP 阻断 IP</span>
            </div>
          </template>
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
import { ref, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'

defineOptions({ name: 'Console' })

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

const topIPs = ref<{ ip: string; count: number }[]>([])
const blockTrend = ref<{ date: string; count: number }[]>([])

async function fetchDashboardData() {
  await Promise.all([
    fetchBlockStatsAndTrend(),
    fetchTopIPs()
  ])
  updateChart()
}

async function fetchBlockStatsAndTrend() {
  try {
    const { getHourlyTrend } = await import('@/api/blocklog')
    const res = await getHourlyTrend(24)
    if (res?.hourly_data) {
      blockTrend.value = res.hourly_data.map((item: any) => ({
        date: item.hour,
        count: item.total,
      }))
    }
  } catch (error) {
    console.error('获取阻断趋势失败:', error)
  }
}

async function fetchTopIPs() {
  try {
    const { getBlockedTopIPs } = await import('@/api/blocklog')
    const res = await getBlockedTopIPs(10)
    if (res?.top_blocked_ips) {
      topIPs.value = res.top_blocked_ips
    }
  } catch (error) {
    console.error('获取TOP IP失败:', error)
  }
}

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M'
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K'
  return num.toString()
}

function getIPPercentage(count: number): number {
  const max = topIPs.value[0]?.count || 1
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
      axisLabel: { rotate: 30 }
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
  window.addEventListener('resize', handleResize)
})

const handleResize = () => chart?.resize()

onUnmounted(() => {
  chart?.dispose()
  window.removeEventListener('resize', handleResize)
})
</script>

<style lang="scss" scoped>
.dashboard-console {
  padding: 16px;
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

.rank-ip {
  font-size: 13px;
  font-family: monospace;
  color: var(--el-text-color-primary);
  min-width: 100px;
  flex-shrink: 0;
}
</style>
