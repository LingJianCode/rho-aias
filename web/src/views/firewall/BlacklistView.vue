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
        </div>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 16px">
        黑名单规则通过 eBPF XDP 程序在内核层直接阻断，性能极高
      </el-alert>

      <el-table :data="rules" v-loading="loading" stripe>
        <el-table-column prop="ip" label="IP/CIDR" min-width="200">
          <template #default="{ row }">
            {{ row.value }}
          </template>
        </el-table-column>
        <el-table-column prop="added_at" label="添加时间" width="180">
          <template #default="{ row }">{{ row.added_at ? formatDateTime(row.added_at) : '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button type="danger" link @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showAddDialog" title="添加黑名单规则" width="500px">
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
import { addBlacklistRule, deleteBlacklistRule, getBlacklist } from '@/api/manual'
import type { ManualRuleItem } from '@/types/api'

const { confirmDelete } = useConfirm()

const loading = ref(false)
const rules = ref<ManualRuleItem[]>([])

const showAddDialog = ref(false)
const formRef = ref<FormInstance>()

const form = reactive({
  value: '',
})

const formRules: FormRules = {
  value: [{ required: true, message: '请输入 IP 地址或 CIDR', trigger: 'blur' }],
}

// 注：手动黑名单从磁盘缓存（manual_cache.bin）查询，避免遍历 eBPF map 影响性能
// 数据格式参考（模拟数据已注释保留作为格式提示）：
// ManualRuleItem[] = [
//   { value: '192.168.1.1', added_at: '2024-01-01T00:00:00Z' },
//   { value: '10.0.0.0/24', added_at: '2024-01-02T00:00:00Z' },
// ]

async function fetchRules() {
  loading.value = true
  try {
    const res = await getBlacklist()
    rules.value = res.data.rules || []
  } catch {
    // 接口失败时保持空列表
    rules.value = []
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    await addBlacklistRule(form.value)
    ElMessage.success('添加成功')
    showAddDialog.value = false
    formRef.value?.resetFields()
  } catch {
    // Error handled by request interceptor
  }
}

async function handleDelete(row: ManualRuleItem) {
  if (!(await confirmDelete(row.value))) return
  try {
    await deleteBlacklistRule(row.value)
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
