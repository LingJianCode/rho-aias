<template>
  <div class="blacklist-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <el-radio-group v-model="sourceType" @change="handleSourceChange">
            <el-radio-button value="manual">手动黑名单</el-radio-button>
            <el-radio-button value="waf">WAF</el-radio-button>
            <el-radio-button value="failguard">FailGuard</el-radio-button>
            <el-radio-button value="anomaly">异常检测</el-radio-button>
            <el-radio-button value="rate_limit">Rate Limit</el-radio-button>
          </el-radio-group>
          <el-button v-if="sourceType === 'manual'" type="primary" @click="showAddDialog = true">
            <Icon icon="ri:add-line" />添加规则
          </el-button>
        </div>
      </template>

      <!-- 手动黑名单表格 -->
      <template v-if="sourceType === 'manual'">
        <el-alert type="info" :closable="false" style="margin-bottom: 16px">
          手动黑名单通过 eBPF XDP 程序在内核层直接阻断，性能极高
        </el-alert>
        <el-table :data="manualRules" v-loading="loading" stripe>
          <el-table-column prop="value" label="IP/CIDR" min-width="200" />
          <el-table-column prop="remark" label="备注" min-width="150">
            <template #default="{ row }">{{ row.remark || '-' }}</template>
          </el-table-column>
          <el-table-column prop="added_at" label="添加时间" width="180">
            <template #default="{ row }">{{ row.added_at ? formatDateTime(row.added_at) : '-' }}</template>
          </el-table-column>
          <el-table-column label="操作" width="100" v-auth="'admin'">
            <template #default="{ row }">
              <el-button type="danger" link @click="handleDelete(row as ManualRuleItem)">删除</el-button>
            </template>
          </el-table-column>
        </el-table>
      </template>

      <!-- 其他来源黑名单表格（从 ban_record 查询） -->
      <template v-else>
        <el-alert type="info" :closable="false" style="margin-bottom: 16px">
          {{ sourceLabel }}黑名单来自自动检测，显示当前生效中的封禁记录
        </el-alert>
        <el-table :data="banRecords" v-loading="loading" stripe>
          <el-table-column prop="ip" label="IP" min-width="150" />
          <el-table-column prop="reason" label="原因" min-width="200" show-overflow-tooltip />
          <el-table-column prop="created_at" label="封禁时间" width="180">
            <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
          </el-table-column>
          <el-table-column prop="expires_at" label="过期时间" width="180">
            <template #default="{ row }">{{ row.expires_at ? formatDateTime(row.expires_at) : '永久' }}</template>
          </el-table-column>
          <el-table-column prop="duration" label="封禁时长" width="120">
            <template #default="{ row }">{{ formatDuration(row.duration) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="100" v-auth="'admin'">
            <template #default="{ row }">
              <el-button type="danger" link @click="handleUnblock(row as BanRecord)">解封</el-button>
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
            @size-change="fetchBanRecords"
            @current-change="fetchBanRecords"
          />
        </div>
      </template>
    </el-card>

    <!-- 添加规则对话框 -->
    <el-dialog v-model="showAddDialog" title="添加黑名单规则" width="500px">
      <el-form ref="formRef" :model="form" :rules="formRules" label-width="80px">
        <el-form-item label="IP/CIDR" prop="value">
          <el-input v-model="form.value" placeholder="例如: 192.168.1.1 或 10.0.0.0/24" />
        </el-form-item>
        <el-form-item label="备注" prop="remark">
          <el-input v-model="form.remark" placeholder="可选备注" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddDialog = false">取消</el-button>
        <el-button type="primary" @click="handleAdd">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { type FormInstance, type FormRules, ElMessageBox } from 'element-plus'
import { Icon } from '@iconify/vue'
import { formatDateTime } from '@/utils/format'
import { addBlacklistRule, deleteBlacklistRule, getBlacklist } from '@/api/firewall'
import { getBanRecords, unblockBanRecord } from '@/api/ban-records'
import type { ManualRuleItem, BanRecord } from '@/types/api'

defineOptions({ name: 'Blacklist' })

const loading = ref(false)
const sourceType = ref('manual')

// 手动黑名单数据
const manualRules = ref<ManualRuleItem[]>([])

// 其他来源黑名单数据（从 ban_record 查询）
const banRecords = ref<BanRecord[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

// 添加规则表单
const showAddDialog = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({ value: '', remark: '' })
const formRules: FormRules = {
  value: [{ required: true, message: '请输入 IP 地址或 CIDR', trigger: 'blur' }],
}

// 来源标签映射
const sourceLabels: Record<string, string> = {
  manual: '手动',
  waf: 'WAF',
  failguard: 'FailGuard',
  anomaly: '异常检测',
  rate_limit: 'Rate Limit',
}

const sourceLabel = computed(() => sourceLabels[sourceType.value] || sourceType.value)

// 格式化封禁时长
function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}秒`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}分钟`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}小时`
  return `${Math.floor(seconds / 86400)}天`
}

// 切换来源
function handleSourceChange() {
  page.value = 1
  if (sourceType.value === 'manual') {
    fetchManualRules()
  } else {
    fetchBanRecords()
  }
}

// 获取手动黑名单
async function fetchManualRules() {
  loading.value = true
  try {
    const res = await getBlacklist()
    manualRules.value = res.rules || []
  } catch {
    manualRules.value = []
  } finally {
    loading.value = false
  }
}

// 获取其他来源黑名单（从 ban_record 查询未过期的）
async function fetchBanRecords() {
  loading.value = true
  try {
    const res = await getBanRecords({
      page: page.value,
      page_size: pageSize.value,
      source: sourceType.value,
      status: 'active',
    })
    banRecords.value = res.records
    total.value = res.total
  } catch {
    banRecords.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

// 添加规则
async function handleAdd() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    await addBlacklistRule({ value: form.value, remark: form.remark })
    ElMessage.success('添加成功')
    showAddDialog.value = false
    formRef.value?.resetFields()
    fetchManualRules()
  } catch {
    // Error handled by request interceptor
  }
}

// 删除规则
async function handleDelete(row: ManualRuleItem) {
  try {
    await ElMessageBox.confirm(`确认删除 ${row.value}？`, '提示', { type: 'warning' })
    await deleteBlacklistRule(row.value)
    ElMessage.success('删除成功')
    fetchManualRules()
  } catch {
    // User cancelled or error
  }
}

// 解封封禁记录
async function handleUnblock(row: BanRecord) {
  try {
    await ElMessageBox.confirm(`确认解封 IP ${row.ip}？`, '提示', { type: 'warning' })
    await unblockBanRecord(row.id)
    ElMessage.success('解封成功')
    fetchBanRecords()
  } catch {
    // User cancelled or error
  }
}

onMounted(() => {
  fetchManualRules()
})
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 12px;
}

.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
