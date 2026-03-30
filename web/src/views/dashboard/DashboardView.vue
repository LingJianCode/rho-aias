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
import request from '@/api/request'

const chartRef = ref<HTMLElement>()
let chart: echarts.ECharts | null = null

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
  try {
    const res = await request.get('/api/dashboard/stats')
    stats.value = res.data.data
    updateChart()
  } catch {
    // 使用模拟数据
    stats.value = {
      total_blocks: 125846,
      active_rules: 45678,
      healthy_sources: 8,
      today_bans: 234,
      block_trend: Array.from({ length: 7 }, (_, i) => ({
        date: new Date(Date.now() - (6 - i) * 86400000).toLocaleDateString(),
        count: Math.floor(Math.random() * 5000) + 1000,
      })),
      recent_blocks: [
        { timestamp: new Date().toISOString(), src_ip: '192.168.1.1', dst_ip: '10.0.0.1', source: 'waf', country_code: 'CN' },
        { timestamp: new Date().toISOString(), src_ip: '10.0.0.2', dst_ip: '10.0.0.1', source: 'ddos', country_code: 'US' },
      ],
      source_status: [
        { name: 'IPsum', status: 'healthy' },
        { name: 'Spamhaus', status: 'healthy' },
        { name: 'WAF', status: 'healthy' },
        { name: 'DDoS', status: 'unhealthy' },
      ],
    }
    updateChart()
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
