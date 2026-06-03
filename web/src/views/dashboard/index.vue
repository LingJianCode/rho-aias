<template>
  <div class="dashboard-view">
    <!-- 统计卡片 -->
    <el-row :gutter="16" class="mb-5">
      <el-col :xs="24" :sm="12" :md="6" v-for="(stat, idx) in statsCards" :key="idx">
        <StatsCard :icon="stat.icon" :value="stat.value" :label="stat.label" :color="stat.color" />
      </el-col>
    </el-row>

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

    <!-- 最近阻断记录 -->
    <el-row :gutter="20" class="mt-5">
      <el-col :span="24">
        <el-card shadow="never" class="art-card">
          <template #header>
            <div class="card-header">
              <span>最近阻断记录</span>
              <el-button type="primary" text @click="$router.push('/record/blocklog')">查看全部</el-button>
            </div>
          </template>
          <el-table :data="recentBlocks" stripe size="small" max-height="300">
            <el-table-column prop="timestamp" label="时间" width="180" />
            <el-table-column prop="src_ip" label="源 IP" width="160">
              <template #default="{ row }"><code>{{ row.src_ip }}</code></template>
            </el-table-column>
            <el-table-column prop="dst_ip" label="目标 IP" width="140" />
            <el-table-column prop="dst_port" label="端口" width="80" />
            <el-table-column label="来源" width="120">
              <template #default="{ row }">
                <el-tag size="small" :type="row.rule_source === 'failguard' ? '' : row.rule_source === 'waf' ? 'success' : 'warning'">
                  {{ row.rule_source }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="action" label="动作" width="80" />
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import StatsCard from '@/components/StatsCard.vue'
import { formatNumber } from '@/utils/format'
import { getBlockLogStats, getHourlyTrend, getBlockedTopIPs, getBlockLogs } from '@/api/blocklog'

defineOptions({ name: 'Dashboard' })

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

const topIPs = ref<{ ip: string; count: number }[]>([])
const recentBlocks = ref<any[]>([])
const blockTrend = ref<{ date: string; count: number }[]>([])

const statsCards = reactive([
  { icon: 'DataLine', value: '-', label: '总阻断数', color: '#409eff' },
  { icon: 'Warning', value: '-', label: '今日新增', color: '#e6a23c' },
  { icon: 'Shield', value: '-', label: '活跃规则', color: '#67c23a' },
  { icon: 'Monitor', value: '-', label: '受保护资产', color: '#f56c6c' },
])

async function fetchDashboardData() {
  await Promise.all([
    fetchStats(),
    fetchBlockTrend(),
    fetchTopIPs(),
    fetchRecentBlocks()
  ])
  updateChart()
}

async function fetchStats() {
  try {
    const res = await getBlockLogStats()
    const data = res?.data ?? res
    if (data) {
      statsCards[0].value = formatNumber(data.total ?? 0)
      if ('today_count' in data) {
        statsCards[1].value = formatNumber((data as any).today_count ?? 0)
      }
    }
  } catch {
    // Error handled by interceptor
  }
}

async function fetchBlockTrend() {
  try {
    const res = await getHourlyTrend(24)
    const data = res?.data ?? res
    if (data?.hourly_data) {
      blockTrend.value = data.hourly_data.map((item: any) => ({
        date: item.hour,
        count: item.total,
      }))
    }
  } catch {
    // Error handled
  }
}

async function fetchTopIPs() {
  try {
    const res = await getBlockedTopIPs(10)
    const data = res?.data ?? res
    if (data?.top_blocked_ips) {
      topIPs.value = data.top_blocked_ips
    }
  } catch {
    // Error handled
  }
}

async function fetchRecentBlocks() {
  try {
    const today = new Date().toISOString().slice(0, 10)
    const res = await getBlockLogs({ date: today, page_size: 5 })
    const data = res?.data ?? res
    if (data?.records) {
      recentBlocks.value = data.records.slice(0, 5)
    }
  } catch {
    // Error handled
  }
}

function formatNumberLocal(num: number | string): string {
  if (typeof num === 'string') return num
  return formatNumber(num)
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
      axisLabel: { rotate: 30 },
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
.dashboard-view {
  padding: 16px;
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
