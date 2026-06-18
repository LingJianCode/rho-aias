<template>
  <div class="audit-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>审计日志</span>
          <el-button type="primary" @click="handleExport">
            <Icon icon="ri:download-line" />导出
          </el-button>
        </div>
      </template>

      <!-- 查询条件 -->
      <el-form :model="filter" inline class="filter-form">
        <el-form-item label="操作类型">
          <el-select v-model="filter.action" clearable style="width: 160px">
            <el-option label="登录" value="login" />
            <el-option label="登出" value="logout" />
            <el-option label="创建" value="create" />
            <el-option label="更新" value="update" />
            <el-option label="删除" value="delete" />
            <el-option label="配置变更" value="config_change" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="handleSearch">查询</el-button>
          <el-button @click="handleReset">重置</el-button>
        </el-form-item>
      </el-form>

      <!-- 日志表格 -->
      <el-table :data="logs" v-loading="loading" stripe size="small">
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="username" label="用户" width="120" />
        <el-table-column prop="action" label="操作" width="140">
          <template #default="{ row }">
            <el-tag size="small">{{ row.action }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="target_type" label="目标类型" width="120" />
        <el-table-column prop="target_id" label="目标 ID" width="100" />
        <el-table-column prop="details" label="详情" min-width="200" show-overflow-tooltip />
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="created_at" label="时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
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
import { getAuditLogs } from '@/api/audit'
import { formatDateTime } from '@/utils/format'

defineOptions({ name: 'Audit' })

const loading = ref(false)
const logs = ref<any[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const filter = reactive({
  action: '',
})

async function fetchLogs() {
  loading.value = true
  try {
    const res = await getAuditLogs({
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
  filter.action = ''
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
