<template>
  <div class="whitelist-view">
    <div class="page-header">
      <h2>白名单管理</h2>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <el-button type="primary" @click="showAddDialog = true">
            <el-icon><Plus /></el-icon>添加规则
          </el-button>
        </div>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 16px">
        白名单中的 IP/CIDR 将绕过所有安全检查，请谨慎添加
      </el-alert>

      <el-table :data="rules" v-loading="loading" stripe>
        <el-table-column prop="value" label="IP/CIDR" min-width="200" />
        <el-table-column prop="added_at" label="添加时间" width="180">
          <template #default="{ row }">{{ row.added_at ? formatDateTime(row.added_at) : '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button type="danger" link @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>

      <div class="total-info">
        共 {{ total }} 条规则
      </div>
    </el-card>

    <el-dialog v-model="showAddDialog" title="添加白名单规则" width="500px">
      <el-form ref="formRef" :model="form" :rules="formRules" label-width="80px">
        <el-form-item label="IP/CIDR" prop="value">
          <el-input v-model="form.value" placeholder="例如: 192.168.1.1 或 10.0.0.0/24" />
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
import { ref, reactive, onMounted } from 'vue'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { formatDateTime } from '@/utils/format'
import { useConfirm } from '@/composables/useConfirm'
import { getWhitelist, addWhitelistRule, deleteWhitelistRule } from '@/api/manual'
import type { ManualRuleItem } from '@/types/api'

const { confirmDelete } = useConfirm()

const loading = ref(false)
const rules = ref<ManualRuleItem[]>([])
const total = ref(0)

const showAddDialog = ref(false)
const formRef = ref<FormInstance>()

const form = reactive({
  value: '',
})

const formRules: FormRules = {
  value: [{ required: true, message: '请输入 IP 地址或 CIDR', trigger: 'blur' }],
}

async function fetchRules() {
  loading.value = true
  try {
    const res = await getWhitelist()
    rules.value = res.data.rules
    total.value = res.data.total
  } catch {
    rules.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    await addWhitelistRule(form.value)
    ElMessage.success('添加成功')
    showAddDialog.value = false
    formRef.value?.resetFields()
    fetchRules()
  } catch {
    // Error handled
  }
}

async function handleDelete(row: ManualRuleItem) {
  if (!(await confirmDelete(row.value))) return
  try {
    await deleteWhitelistRule(row.value)
    ElMessage.success('删除成功')
    fetchRules()
  } catch {
    // Error handled
  }
}

onMounted(() => {
  fetchRules()
})
</script>

<style lang="scss" scoped>
.total-info {
  margin-top: 16px;
  color: var(--el-text-color-secondary);
}
</style>
