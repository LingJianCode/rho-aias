<template>
  <div class="blacklist-view">
    <div class="page-header">
      <h2>黑名单管理</h2>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <el-button type="primary" @click="showAddDialog = true">
            <el-icon><Plus /></el-icon>添加规则
          </el-button>
          <el-button @click="showBatchDialog = true">
            <el-icon><Upload /></el-icon>批量添加
          </el-button>
          <el-button type="danger" :disabled="!selectedIds.length" @click="handleBatchDelete">
            <el-icon><Delete /></el-icon>删除选中
          </el-button>
        </div>
      </template>

      <el-table :data="rules" v-loading="loading" stripe @selection-change="handleSelectionChange">
        <el-table-column type="selection" width="50" />
        <el-table-column prop="ip" label="IP" min-width="150">
          <template #default="{ row }">
            {{ row.ip }}{{ row.cidr ? `/${row.cidr}` : '' }}
          </template>
        </el-table-column>
        <el-table-column prop="reason" label="备注" min-width="200" show-overflow-tooltip />
        <el-table-column prop="created_at" label="添加时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDateTime(row.expires_at) : '永久' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button type="danger" link @click="handleDelete(row)">删除</el-button>
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
          @size-change="fetchRules"
          @current-change="fetchRules"
        />
      </div>
    </el-card>

    <el-dialog v-model="showAddDialog" title="添加黑名单规则" width="500px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="80px">
        <el-form-item label="IP" prop="ip">
          <IpInput v-model="form.ip" :cidr="form.cidr" @update:cidr="form.cidr = $event" show-cidr />
        </el-form-item>
        <el-form-item label="备注" prop="reason">
          <el-input v-model="form.reason" type="textarea" :rows="2" />
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker v-model="form.expires_at" type="datetime" placeholder="留空表示永久" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddDialog = false">取消</el-button>
        <el-button type="primary" @click="handleAdd">确定</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showBatchDialog" title="批量添加" width="600px">
      <el-form :model="batchForm" label-width="80px">
        <el-form-item label="IP列表">
          <el-input
            v-model="batchForm.ips"
            type="textarea"
            :rows="8"
            placeholder="每行一个 IP 或 CIDR，如：&#10;192.168.1.1&#10;10.0.0.0/24"
          />
        </el-form-item>
        <el-form-item label="备注">
          <el-input v-model="batchForm.reason" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showBatchDialog = false">取消</el-button>
        <el-button type="primary" @click="handleBatchAdd">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { Plus, Upload, Delete } from '@element-plus/icons-vue'
import IpInput from '@/components/IpInput.vue'
import { formatDateTime } from '@/utils/format'
import { useConfirm } from '@/composables/useConfirm'
import { getBlacklist, addBlacklistRule, addBlacklistRulesBatch, deleteBlacklistRule, deleteBlacklistRules } from '@/api/manual'
import type { ManualRuleItem } from '@/api/manual'

const { confirmDelete } = useConfirm()

const loading = ref(false)
const rules = ref<ManualRuleItem[]>([])
const selectedIds = ref<string[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const showAddDialog = ref(false)
const showBatchDialog = ref(false)
const formRef = ref<FormInstance>()

const form = reactive({
  ip: '',
  cidr: 32,
  reason: '',
  expires_at: null as Date | null,
})

const batchForm = reactive({
  ips: '',
  reason: '',
})

const formRules: FormRules = {
  ip: [{ required: true, message: '请输入 IP 地址', trigger: 'blur' }],
}

async function fetchRules() {
  loading.value = true
  try {
    const res = await getBlacklist({ page: page.value, page_size: pageSize.value })
    rules.value = res.data.items
    total.value = res.data.total
  } catch {
    rules.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

function handleSelectionChange(selection: ManualRuleItem[]) {
  selectedIds.value = selection.map((r) => r.id)
}

async function handleAdd() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    await addBlacklistRule({
      ip: form.ip,
      cidr: form.cidr,
      reason: form.reason,
      expires_at: form.expires_at?.toISOString(),
    })
    ElMessage.success('添加成功')
    showAddDialog.value = false
    fetchRules()
  } catch {
    // Error handled by request interceptor
  }
}

async function handleBatchAdd() {
  if (!batchForm.ips.trim()) {
    ElMessage.warning('请输入 IP 列表')
    return
  }

  try {
    const res = await addBlacklistRulesBatch(batchForm.ips, batchForm.reason)
    ElMessage.success(`成功添加 ${res.data.added} 条，重复 ${res.data.duplicates} 条`)
    showBatchDialog.value = false
    fetchRules()
  } catch {
    // Error handled by request interceptor
  }
}

async function handleDelete(row: ManualRuleItem) {
  if (!(await confirmDelete(`${row.ip}${row.cidr ? `/${row.cidr}` : ''}`))) return
  try {
    await deleteBlacklistRule(row.id)
    ElMessage.success('删除成功')
    fetchRules()
  } catch {
    // Error handled by request interceptor
  }
}

async function handleBatchDelete() {
  if (!(await confirmDelete(`${selectedIds.value.length} 条规则`))) return
  try {
    await deleteBlacklistRules(selectedIds.value)
    ElMessage.success('删除成功')
    fetchRules()
  } catch {
    // Error handled by request interceptor
  }
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
