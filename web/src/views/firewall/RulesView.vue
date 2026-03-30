<template>
  <div class="rules-view">
    <div class="page-header">
      <h2>规则列表</h2>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <el-radio-group v-model="sourceFilter" @change="handleFilterChange">
            <el-radio-button value="all">全部</el-radio-button>
            <el-radio-button value="manual">手动</el-radio-button>
            <el-radio-button value="ipsum">IPsum</el-radio-button>
            <el-radio-button value="spamhaus">Spamhaus</el-radio-button>
            <el-radio-button value="waf">WAF</el-radio-button>
            <el-radio-button value="ddos">DDoS</el-radio-button>
            <el-radio-button value="anomaly">异常检测</el-radio-button>
            <el-radio-button value="failguard">FailGuard</el-radio-button>
          </el-radio-group>
        </div>
      </template>

      <el-table :data="rules" v-loading="loading" stripe>
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
        <el-table-column prop="created_at" label="添加时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDateTime(row.expires_at) : '永久' }}</template>
        </el-table-column>
      </el-table>

      <div class="pagination-wrapper">
        <el-pagination
          v-model:current-page="page"
          v-model:page-size="pageSize"
          :page-sizes="[20, 50, 100]"
          :total="total"
          layout="total, sizes, prev, pager, next"
          @size-change="fetchRules"
          @current-change="fetchRules"
        />
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import RuleSourceTag from '@/components/RuleSourceTag.vue'
import { formatDateTime } from '@/utils/format'
import { getRules } from '@/api/rules'
import type { Rule, RuleSource } from '@/types/api'

const loading = ref(false)
const rules = ref<Rule[]>([])
const sourceFilter = ref<RuleSource | 'all'>('all')
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

async function fetchRules() {
  loading.value = true
  try {
    const res = await getRules({
      page: page.value,
      page_size: pageSize.value,
      source: sourceFilter.value,
    })
    rules.value = res.data.items
    total.value = res.data.total
  } catch {
    // 模拟数据
    rules.value = Array.from({ length: pageSize.value }, (_, i) => ({
      id: String(i + 1),
      ip: `192.168.${Math.floor(i / 256)}.${i % 256}`,
      cidr: 32,
      source: ['manual', 'ipsum', 'spamhaus', 'waf', 'ddos', 'anomaly', 'failguard'][Math.floor(Math.random() * 7)] as RuleSource,
      reason: '恶意IP',
      created_at: new Date().toISOString(),
      expires_at: Math.random() > 0.5 ? new Date(Date.now() + 86400000).toISOString() : undefined,
    }))
    total.value = 1000
  } finally {
    loading.value = false
  }
}

function handleFilterChange() {
  page.value = 1
  fetchRules()
}

onMounted(() => {
  fetchRules()
})
</script>

<style lang="scss" scoped>
.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
