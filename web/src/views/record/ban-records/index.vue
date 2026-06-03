<template>
  <div class="ban-records-view">
    <div class="page-header">
      <h2>封禁记录</h2>
    </div>

    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>封禁记录列表</span>
        </div>
      </template>

      <!-- 查询条件 -->
      <el-form :model="filter" inline class="filter-form">
        <el-form-item label="状态">
          <el-select v-model="filter.status" clearable style="width: 120px">
            <el-option label="生效中" value="active" />
            <el-option label="已过期" value="expired" />
            <el-option label="已解封" value="unblocked" />
          </el-select>
        </el-form-item>
        <el-form-item label="来源">
          <el-select v-model="filter.source" clearable style="width: 140px">
            <el-option label="WAF" value="waf" />
            <el-option label="FailGuard" value="failguard" />
            <el-option label="异常检测" value="anomaly" />
            <el-option label="Rate Limit" value="rate_limit" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">查询</el-button>
          <el-button @click="handleReset">重置</el-button>
        </el-form-item>
      </el-form>

      <!-- 记录表格 -->
      <el-table :data="records" v-loading="loading" stripe>
        <el-table-column prop="ip" label="IP" min-width="140" />
        <el-table-column prop="reason" label="原因" min-width="200" show-overflow-tooltip />
        <el-table-column prop="source" label="来源" width="120">
          <template #default="{ row }">
            <el-tag size="small">{{ row.source }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="getStatusType(row.status)" size="small">{{ getStatusLabel(row.status) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="封禁时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDateTime(row.expires_at) : '永久' }}</template>
        </el-table-column>
        <el-table-column prop="duration" label="时长" width="100">
          <template #default="{ row }">{{ formatDuration(row.duration) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100" v-auth="'admin'">
          <template #default="{ row }">
            <el-button
              v-if="(row as BanRecord).status === 'active'"
              type="danger"
              link
              @click="handleUnblock(row as BanRecord)"
            >
              解封
            </el-button>
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
          @size-change="fetchRecords"
          @current-change="fetchRecords"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessageBox, ElMessage } from 'element-plus'
import { getBanRecords, unblockBanRecord } from '@/api/ban-records'
import { formatDateTime } from '@/utils/format'
import type { BanRecord } from '@/types/api'

defineOptions({ name: 'BanRecords' })

const loading = ref(false)
const records = ref<BanRecord[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const filter = reactive({
  status: '',
  source: '',
})

async function fetchRecords() {
  loading.value = true
  try {
    const res = await getBanRecords({
      ...filter,
      page: page.value,
      page_size: pageSize.value,
    })
    records.value = res.records || []
    total.value = res.total || 0
  } catch {
    records.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function getStatusType(status: string): 'danger' | 'success' | 'warning' | 'info' {
  switch (status) {
    case 'active': return 'danger'
    case 'expired': return 'info'
    case 'unblocked': return 'success'
    default: return 'info'
  }
}

function getStatusLabel(status: string): string {
  switch (status) {
    case 'active': return '生效中'
    case 'expired': return '已过期'
    case 'unblocked': return '已解封'
    default: return status
  }
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}秒`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时`
  return `${Math.floor(seconds / 86400)}天`
}

function handleSearch() {
  page.value = 1
  fetchRecords()
}

function handleReset() {
  filter.status = ''
  filter.source = ''
  handleSearch()
}

async function handleUnblock(row: BanRecord) {
  try {
    await ElMessageBox.confirm(`确认解封 IP ${row.ip}？`, '提示', { type: 'warning' })
    await unblockBanRecord(row.id)
    ElMessage.success('解封成功')
    fetchRecords()
  } catch {
    // User cancelled or error
  }
}

onMounted(() => {
  fetchRecords()
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
