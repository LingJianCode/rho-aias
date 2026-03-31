<template>
  <div class="dashboard-view">
    <div class="page-header">
      <h2>仪表盘</h2>
    </div>

    <div class="stats-row">
      <StatsCard
        label="总阻断数"
        :value="stats.total_blocks"
        :icon="Document"
        icon-color="#f56c6c"
      />
      <StatsCard
        label="在线规则数"
        :value="stats.active_rules"
        :icon="List"
        icon-color="#409eff"
      />
      <StatsCard
        label="健康数据源"
        :value="stats.healthy_sources"
        :icon="Connection"
        icon-color="#67c23a"
      />
      <StatsCard
        label="今日新增封禁"
        :value="stats.today_bans"
        :icon="TrendCharts"
        icon-color="#e6a23c"
      />
    </div>

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
              <span>数据源状态</span>
            </div>
          </template>
          <div class="source-status-list">
            <div v-for="item in stats.source_status" :key="item.name" class="source-item">
              <span class="source-name">{{ item.name }}</span>
              <el-tag :type="item.status === 'healthy' ? 'success' : 'danger'" size="small">
                {{ item.status === 'healthy' ? '正常' : '异常' }}
              </el-tag>
            </div>
          </div>
        </el-card>
      </el-col>
    </el-row>

    <el-card style="margin-top: 20px">
      <template #header>
        <div class="card-header">
          <span>最近阻断记录</span>
          <el-button type="primary" link @click="$router.push('/blocklog')">查看全部</el-button>
        </div>
      </template>
      <el-table :data="stats.recent_blocks" stripe>
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="src_ip" label="源 IP" />
        <el-table-column prop="dst_ip" label="目的 IP" />
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
import { Document, List, Connection, TrendCharts } from '@element-plus/icons-vue'
import StatsCard from '@/components/StatsCard.vue'
import RuleSourceTag from '@/components/RuleSourceTag.vue'
import CountryFlag from '@/components/CountryFlag.vue'
import { formatDateTime } from '@/utils/format'
import { getBlockLogStats, getBlockLogs } from '@/api/blocklog'
import { getBanRecordStats } from '@/api/ban-records'
import { getSourcesStatus } from '@/api/sources'
import { getRules } from '@/api/rules'

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

// 注：后端不存在 /api/dashboard/stats 接口，使用以下接口组合获取数据
// 数据格式参考（模拟数据已注释保留作为格式提示）：
// {
//   total_blocks: 125846,        // 总阻断数 - 来自 getBlockLogStats().total_blocks
//   active_rules: 45678,         // 规则数 - 来自 getRules({ source: 'manual' }).total
//   healthy_sources: 8,          // 健康数据源数 - 来自 getSourcesStatus() 计算健康数量
//   today_bans: 234,             // 今日封禁数 - 来自 getBanRecordStats().today_count
//   block_trend: [               // 阻断趋势 - 来自 getBlockLogStats().hourly_trend
//     { date: '2024/1/1', count: 1234 },
//     ...
//   ],
//   recent_blocks: [             // 最近阻断记录 - 来自 getBlockLogs({ page_size: 5 })
//     { timestamp: '...', src_ip: '192.168.1.1', dst_ip: '10.0.0.1', source: 'waf', country_code: 'CN' },
//     ...
//   ],
//   source_status: [             // 数据源状态 - 来自 getSourcesStatus()
//     { name: 'IPsum', status: 'healthy' },
//     { name: 'Spamhaus', status: 'healthy' },
//     { name: 'WAF', status: 'healthy' },
//     { name: 'DDoS', status: 'unhealthy' },
//   ],
// }

const stats = ref({
  total_blocks: 0,
  active_rules: 0,
  healthy_sources: 0,
  today_bans: 0,
  block_trend: [] as { date: string; count: number }[],
  recent_blocks: [] as Record<string, unknown>[],
  source_status: [] as { name: string; status: string }[],
})

async function fetchStats() {
  // 并行获取所有数据，各接口独立 try-catch
  await Promise.all([
    fetchBlockStats(),
    fetchBanStats(),
    fetchSourceStatus(),
    fetchRecentBlocks(),
    fetchRulesCount(),
  ])
  updateChart()
}

async function fetchBlockStats() {
  try {
    const res = await getBlockLogStats()
    if (res.data) {
      stats.value.total_blocks = res.data.total_blocks || 0
      // 将 hourly_trend 转换为 block_trend 格式
      stats.value.block_trend = (res.data.hourly_trend || []).map((item) => ({
        date: item.hour,
        count: item.count,
      }))
    }
  } catch {
    // 接口失败时保持默认值
  }
}

async function fetchBanStats() {
  try {
    const res = await getBanRecordStats()
    if (res.data) {
      stats.value.today_bans = res.data.today_count || 0
    }
  } catch {
    // 接口失败时保持默认值
  }
}

async function fetchSourceStatus() {
  try {
    const res = await getSourcesStatus()
    if (res.data?.sources) {
      const sources = res.data.sources
      stats.value.healthy_sources = sources.filter((s: { status: string }) => s.status === 'healthy').length
      stats.value.source_status = sources.map((s: { source_name: string; status: string }) => ({
        name: s.source_name,
        status: s.status,
      }))
    }
  } catch {
    // 接口失败时保持默认值
  }
}

async function fetchRecentBlocks() {
  try {
    const res = await getBlockLogs({ page_size: 5 })
    if (res.data?.records) {
      stats.value.recent_blocks = res.data.records
    }
  } catch {
    // 接口失败时保持默认值
  }
}

async function fetchRulesCount() {
  try {
    const res = await getRules({ source: 'manual' })
    if (res.data) {
      stats.value.active_rules = res.data.total || 0
    }
  } catch {
    // 接口失败时保持默认值
  }
}

function updateChart() {
  if (!chart || !stats.value.block_trend.length) return

  chart.setOption({
    tooltip: { trigger: 'axis' },
    grid: { left: '3%', right: '4%', bottom: '3%', containLabel: true },
    xAxis: {
      type: 'category',
      data: stats.value.block_trend.map((d) => d.date),
    },
    yAxis: { type: 'value' },
    series: [{
      type: 'line',
      smooth: true,
      areaStyle: { opacity: 0.3 },
      data: stats.value.block_trend.map((d) => d.count),
    }],
  })
}

onMounted(() => {
  fetchStats()
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
.source-status-list {
  max-height: 260px;
  overflow-y: auto;
}

.source-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid var(--el-border-color-lighter);
  &:last-child { border-bottom: none; }
}

.source-name {
  font-size: 14px;
}
</style>
