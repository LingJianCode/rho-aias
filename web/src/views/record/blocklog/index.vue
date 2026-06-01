<template>
  <div class="blocklog-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>阻断日志</span>
          <el-button type="primary" @click="handleExport">
            <Icon icon="ri:download-line" />导出
          </el-button>
        </div>
      </template>

      <!-- 查询条件 -->
      <el-form :model="filter" inline class="filter-form">
        <el-form-item label="日期">
          <el-date-picker v-model="filter.date" type="date" placeholder="选择日期" value-format="YYYY-MM-DD" />
        </el-form-item>
        <el-form-item label="来源 IP">
          <el-input v-model="filter.src_ip" placeholder="来源 IP" clearable style="width: 160px" />
        </el-form-item>
        <el-form-item label="规则来源">
          <el-select v-model="filter.rule_source" placeholder="全部" clearable style="width: 140px">
            <el-option label="WAF" value="waf" />
            <el-option label="FailGuard" value="failguard" />
            <el-option label="异常检测" value="anomaly" />
            <el-option label="Rate Limit" value="rate_limit" />
            <el-option label="GeoIP" value="geoblocking" />
            <el-option label="手动黑名单" value="manual" />
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
          <template #default="{ row }">{{ formatDateTime(row.timestamp) }}</template>
        </el-table-column>
        <el-table-column prop="src_ip" label="来源 IP" min-width="140" />
        <el-table-column prop="dst_ip" label="目标 IP" min-width="140" />
        <el-table-column prop="dst_port" label="目标端口" width="90" />
        <el-table-column prop="protocol" label="协议" width="80" />
        <el-table-column prop="rule_source" label="规则来源" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ row.rule_source }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="action" label="动作" width="80">
          <template #default="{ row }">
            <el-tag :type="row.action === 'drop' ? 'danger' : 'warning'" size="small">
              {{ row.action }}
            </el-tag>
          </template>
        </el-table-column>
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
import { Icon } from '@iconify/vue'
import { getBlockLogs } from '@/api/blocklog'
import { formatDateTime } from '@/utils/format'

defineOptions({ name: 'BlockLog' })

const loading = ref(false)
const logs = ref<any[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const filter = reactive({
  date: new Date().toISOString().split('T')[0],
  src_ip: '',
  rule_source: '',
})

async function fetchLogs() {
  loading.value = true
  try {
    const res = await getBlockLogs({
      ...filter,
      page: page.value,
      page_size: pageSize.value,
    })
    logs.value = res.data.records || []
    total.value = res.data.total || 0
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
  filter.rule_source = ''
  handleSearch()
}

function handleExport() {
  ElMessage.info('导出功能开发中')
}

onMounted(() => fetchLogs())
</script>

<style scoped>
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
