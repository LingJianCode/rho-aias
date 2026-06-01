<template>
  <div class="whitelist-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>白名单管理</span>
          <el-button type="primary" v-auth="'admin'" @click="showAddDialog = true">
            <Icon icon="ri:add-line" />添加规则
          </el-button>
        </div>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 16px">
        白名单中的 IP 地址将跳过所有安全检测，请谨慎添加
      </el-alert>

      <el-table :data="whitelist" v-loading="loading" stripe>
        <el-table-column prop="value" label="IP/CIDR" min-width="200" />
        <el-table-column prop="remark" label="备注" min-width="150">
          <template #default="{ row }">{{ row.remark || '-' }}</template>
        </el-table-column>
        <el-table-column prop="added_at" label="添加时间" width="180">
          <template #default="{ row }">{{ row.added_at ? formatDateTime(row.added_at) : '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100" v-auth="'admin'">
          <template #default="{ row }">
            <el-button type="danger" link @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 添加规则对话框 -->
    <el-dialog v-model="showAddDialog" title="添加白名单规则" width="500px">
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
import { ref, reactive, onMounted } from 'vue'
import { type FormInstance, type FormRules, ElMessageBox } from 'element-plus'
import { Icon } from '@iconify/vue'
import { formatDateTime } from '@/utils/format'
import { addWhitelistRule, deleteWhitelistRule, getWhitelist } from '@/api/firewall'

defineOptions({ name: 'Whitelist' })

const loading = ref(false)
const whitelist = ref<any[]>([])

const showAddDialog = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({ value: '', remark: '' })
const formRules: FormRules = {
  value: [{ required: true, message: '请输入 IP 地址或 CIDR', trigger: 'blur' }],
}

async function fetchData() {
  loading.value = true
  try {
    const res = await getWhitelist()
    whitelist.value = res.data.rules || []
  } catch {
    whitelist.value = []
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    await addWhitelistRule({ value: form.value, remark: form.remark })
    ElMessage.success('添加成功')
    showAddDialog.value = false
    formRef.value?.resetFields()
    fetchData()
  } catch {
    // Error handled
  }
}

async function handleDelete(row: any) {
  try {
    await ElMessageBox.confirm(`确认删除 ${row.value}？`, '提示', { type: 'warning' })
    await deleteWhitelistRule(row.value)
    ElMessage.success('删除成功')
    fetchData()
  } catch {
    // User cancelled or error
  }
}

onMounted(() => fetchData())
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
