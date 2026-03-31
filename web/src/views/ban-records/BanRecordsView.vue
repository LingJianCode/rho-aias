<template>
  <div class="ban-records-view">
    <div class="page-header">
      <h2>封禁记录</h2>
    </div>

    <el-row :gutter="20" class="stats-row">
      <el-col :span="6">
        <StatsCard label="总封禁数" :value="stats.total" :icon="Lock" icon-color="#409eff" />
      </el-col>
      <el-col :span="6">
        <StatsCard label="生效中" :value="stats.active" :icon="CircleCheck" icon-color="#67c23a" />
      </el-col>
      <el-col :span="6">
        <StatsCard label="已过期" :value="stats.expired" :icon="CircleClose" icon-color="#909399" />
      </el-col>
      <el-col :span="6">
        <StatsCard label="今日新增" :value="stats.today_count" :icon="TrendCharts" icon-color="#e6a23c" />
      </el-col>
    </el-row>

    <el-card>
      <el-table :data="records" v-loading="loading" stripe>
        <el-table-column prop="ip" label="IP" min-width="150">
          <template #default="{ row }">
            {{ row.ip }}{{ row.cidr ? `/${row.cidr}` : '' }}
          </template>
        </el-table-column>
        <el-table-column prop="source" label="来源" width="120">
          <template #default="{ row }">
            <RuleSourceTag :source="row.source" />
          </template>
        </el-table-column>
        <el-table-column prop="reason" label="原因" min-width="200" show-overflow-tooltip />
        <el-table-column prop="created_at" label="封禁时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDateTime(row.expires_at) : '永久' }}</template>
        </el-table-column>
        <el-table-column prop="status" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'info'" size="small">
              {{ row.status === 'active' ? '生效中' : '已过期' }}
            </el-tag>
          </template>
        </el-table-column>
      </el-table>

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
import { Lock, CircleCheck, CircleClose, TrendCharts } from '@element-plus/icons-vue'
import StatsCard from '@/components/StatsCard.vue'
import RuleSourceTag from '@/components/RuleSourceTag.vue'
import { formatDateTime } from '@/utils/format'
import { getBanRecords, getBanRecordStats } from '@/api/ban-records'
import type { BanRecord, BanRecordStats } from '@/types/api'

const loading = ref(false)
const records = ref<BanRecord[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const stats = reactive<BanRecordStats>({
  total: 0,
  active: 0,
  expired: 0,
  today_count: 0,
})

async function fetchStats() {
  try {
    const res = await getBanRecordStats()
    Object.assign(stats, res.data)
  } catch {
    // 模拟数据（已注释保留作为格式提示）：
    // stats.total = 1234
    // stats.active = 1000
    // stats.expired = 234
    // stats.today_new = 56
  }
}

async function fetchRecords() {
  loading.value = true
  try {
    const res = await getBanRecords({ page: page.value, page_size: pageSize.value })
    records.value = res.data.records
    total.value = res.data.total
  } catch {
    records.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchStats()
  fetchRecords()
})
</script>

<style lang="scss" scoped>
.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
