<template>
  <div class="api-keys-view">
    <div class="page-header">
      <h2>API Key 管理</h2>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <el-button type="primary" @click="showAddDialog = true">
            <el-icon><Plus /></el-icon>创建 API Key
          </el-button>
        </div>
      </template>

      <el-table :data="apiKeys" v-loading="loading" stripe>
        <el-table-column prop="name" label="名称" min-width="150" />
        <el-table-column prop="key_prefix" label="Key 前缀" width="150">
          <template #default="{ row }">
            <code>{{ row.key_prefix }}****</code>
          </template>
        </el-table-column>
        <el-table-column prop="active" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.active ? 'success' : 'danger'" size="small">
              {{ row.active ? '有效' : '已吊销' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDateTime(row.expires_at) : '永久' }}</template>
        </el-table-column>
        <el-table-column prop="last_used_at" label="最后使用" width="180">
          <template #default="{ row }">{{ row.last_used_at ? formatDateTime(row.last_used_at) : '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button type="danger" link @click="handleRevoke(row)" :disabled="!row.active">吊销</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showAddDialog" title="创建 API Key" width="500px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="80px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="API Key 名称" />
        </el-form-item>
        <el-form-item label="权限" prop="permissions">
          <el-checkbox-group v-model="form.permissions">
            <el-checkbox
              v-for="perm in availablePermissions"
              :key="perm.value"
              :value="perm.value"
            >
              {{ perm.label }}
            </el-checkbox>
          </el-checkbox-group>
        </el-form-item>
        <el-form-item label="有效期">
          <el-input-number v-model="form.expires_days" :min="1" :max="365" />
          <span style="margin-left: 8px; color: var(--el-text-color-secondary)">天（留空或 0 表示永久）</span>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddDialog = false">取消</el-button>
        <el-button type="primary" @click="handleCreate">创建</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="showKeyDialog" title="API Key 已创建" width="500px">
      <el-alert type="warning" :closable="false" style="margin-bottom: 16px">
        请立即复制保存，此 Key 只会显示一次！
      </el-alert>
      <el-input v-model="newKey" readonly>
        <template #append>
          <el-button @click="copyKey">复制</el-button>
        </template>
      </el-input>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { type FormInstance, type FormRules } from 'element-plus'
import { Plus } from '@element-plus/icons-vue'
import { formatDateTime } from '@/utils/format'
import { useConfirm } from '@/composables/useConfirm'
import { getApiKeys, createApiKey, revokeApiKey, getPermissions } from '@/api/api-keys'
import type { ApiKey, PermissionInfo } from '@/types/api'

const { confirm } = useConfirm()

const loading = ref(false)
const apiKeys = ref<ApiKey[]>([])
const showAddDialog = ref(false)
const showKeyDialog = ref(false)
const newKey = ref('')
const formRef = ref<FormInstance>()
const availablePermissions = ref<PermissionInfo[]>([])

const form = reactive({
  name: '',
  permissions: [] as string[],
  expires_days: 0,
})

const rules: FormRules = {
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
  permissions: [{ type: 'array', min: 1, message: '请至少选择一个权限', trigger: 'change' }],
}

async function fetchApiKeys() {
  loading.value = true
  try {
    const res = await getApiKeys()
    apiKeys.value = res.data.keys
  } catch {
    apiKeys.value = []
  } finally {
    loading.value = false
  }
}

async function fetchPermissions() {
  try {
    const res = await getPermissions()
    availablePermissions.value = res.data.permissions
  } catch {
    availablePermissions.value = []
  }
}

async function handleCreate() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    const res = await createApiKey({
      name: form.name,
      permissions: form.permissions,
      expires_days: form.expires_days || undefined,
    })
    newKey.value = res.data.key
    showAddDialog.value = false
    showKeyDialog.value = true
    fetchApiKeys()
    formRef.value?.resetFields()
  } catch {
    // Error handled
  }
}

async function handleRevoke(key: ApiKey) {
  if (!(await confirm({ title: '吊销确认', message: `确定要吊销 API Key "${key.name}" 吗？` }))) return
  try {
    await revokeApiKey(key.id)
    ElMessage.success('已吊销')
    fetchApiKeys()
  } catch {
    // Error handled
  }
}

function copyKey() {
  navigator.clipboard.writeText(newKey.value)
  ElMessage.success('已复制到剪贴板')
}

onMounted(() => {
  fetchApiKeys()
  fetchPermissions()
})
</script>
