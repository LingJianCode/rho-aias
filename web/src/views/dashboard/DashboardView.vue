<template>
  <div class="dashboard-view">
    <div class="page-header">
      <h2>仪表盘</h2>
    </div>

    <!-- 阻断态势图 + TOP 被封国家/来源 -->
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
import { ref, onMounted, onUnmounted } from 'vue'
import * as echarts from 'echarts'
import RuleSourceTag from '@/components/RuleSourceTag.vue'
import CountryFlag from '@/components/CountryFlag.vue'
import { formatDateTime, formatNumber } from '@/utils/format'
// 统计与趋势
import { getBlockLogStats, getBlockLogs, getBlockedCountries } from '@/api/blocklog'
import type { BlockLog } from '@/types/api'

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

const topCountries = ref<{ country: string; count: number }[]>([])
const recentBlocks = ref<BlockLog[]>([])
const blockTrend = ref<{ date: string; count: number }[]>([])

async function fetchDashboardData() {
  await Promise.all([
    fetchBlockStatsAndTrend(),
    fetchTopCountries(),
    fetchRecentBlocks(),
  ])
  updateChart()
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
    if (res.data?.items) {
      recentBlocks.value = res.data.items
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
