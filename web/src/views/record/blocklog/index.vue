<template>
  <div class="blocklog-view">
    <div class="page-header">
      <h2>阻断日志</h2>
    </div>

    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>阻断日志列表</span>
        </div>
      </template>

      <!-- 查询条件 -->
      <el-form :inline="true" :model="filter" class="filter-form">
        <el-form-item label="查询日期">
          <el-date-picker v-model="filter.date" type="date" placeholder="选择日期" value-format="YYYY-MM-DD" style="width: 160px" />
        </el-form-item>
        <el-form-item label="小时范围">
          <el-select v-model="filter.start_hour" placeholder="起始" style="width: 80px">
            <el-option v-for="h in 24" :key="h - 1" :label="String(h - 1).padStart(2, '0')" :value="h - 1" />
          </el-select>
          <span style="margin: 0 4px">-</span>
          <el-select v-model="filter.end_hour" placeholder="结束" style="width: 80px">
            <el-option v-for="h in 24" :key="h - 1" :label="String(h - 1).padStart(2, '0')" :value="h - 1" />
          </el-select>
        </el-form-item>
        <el-form-item label="搜索 IP">
          <el-input
            v-model="filter.src_ip"
            placeholder="输入 IP"
            clearable
            style="width: 180px"
            @clear="handleSearch"
            @keyup.enter="handleSearch"
          />
        </el-form-item>
        <el-form-item label="匹配类型">
          <el-select v-model="filter.match_type" placeholder="全部" clearable style="width: 140px" @change="handleSearch">
            <el-option label="精确匹配" value="ip4_exact" />
            <el-option label="CIDR 匹配" value="ip4_cidr" />
            <el-option label="地域封禁" value="geo_block" />
          </el-select>
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="filter.rule_source" placeholder="全部来源" clearable style="width: 140px" @change="handleSearch">
            <el-option label="手动" value="manual" />
            <el-option label="IPsum" value="ipsum" />
            <el-option label="Spamhaus" value="spamhaus" />
            <el-option label="WAF" value="waf" />
            <el-option label="DDoS" value="ddos" />
            <el-option label="异常检测" value="anomaly" />
            <el-option label="FailGuard" value="failguard" />
            <el-option label="Rate Limit" value="rate_limit" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">查询</el-button>
          <el-button @click="handleReset">重置</el-button>
        </el-form-item>
      </el-form>

      <!-- 日志表格 -->
      <el-table :data="logs" v-loading="loading" stripe size="small">
        <el-table-column prop="timestamp" label="时间" width="180">
          <template #default="{ row }">{{ formatNanoTimestamp(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="src_ip" label="源 IP" min-width="140" />
        <el-table-column prop="dst_port" label="目的 PORT" min-width="50" />
        <el-table-column prop="match_type" label="匹配类型" width="100" />
        <el-table-column prop="rule_source" label="来源" width="100">
          <template #default="{ row }">
            <el-tag size="small">{{ row.rule_source }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="packet_size" label="包大小" width="100">
          <template #default="{ row }">{{ formatBytes(row.packet_size) }}</template>
        </el-table-column>
        <el-table-column prop="dst_ip" label="目的 IP" min-width="50" />
        <el-table-column prop="country_code" label="国家" width="50"/>
      </el-table>

      <!-- 分页 -->
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
import { getBlockLogs } from '@/api/blocklog'
import { formatNanoTimestamp, formatBytes } from '@/utils/format'

defineOptions({ name: 'BlockLog' })

const loading = ref(false)
const logs = ref<any[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const filter = reactive({
  date: new Date().toISOString().split('T')[0],
  src_ip: '',
  match_type: '',
  rule_source: '',
  start_hour: 0,
  end_hour: 23,
})

async function fetchLogs() {
  if (!filter.date) {
    logs.value = []
    total.value = 0
    return
  }
  loading.value = true
  try {
    const res = await getBlockLogs({
      ...filter,
      page: page.value,
      page_size: pageSize.value,
    })
    logs.value = res.records || []
    total.value = res.total || 0
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
  filter.date = new Date().toISOString().split('T')[0]
  filter.src_ip = ''
  filter.match_type = ''
  filter.rule_source = ''
  filter.start_hour = 0
  filter.end_hour = 23
  handleSearch()
}

onMounted(() => {
  fetchLogs()
})
</script>

<style scoped>
.page-header {
  margin-bottom: 16px;
  h2 { margin: 0; }
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.filter-form {
  margin-bottom: 16px;
}

.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
