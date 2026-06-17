<template>
  <div class="api-keys-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>API Keys 管理</span>
          <el-button type="primary" @click="showAddDialog = true">
            <Icon icon="ri:add-line" />生成 Key
          </el-button>
        </div>
      </template>

      <el-alert type="warning" :closable="false" style="margin-bottom: 16px">
        API Key 用于程序化访问，请妥善保管。创建后仅显示一次完整 Key。
      </el-alert>

      <el-table :data="keys" v-loading="loading" stripe>
        <el-table-column prop="name" label="名称" min-width="140" />
        <el-table-column prop="key" label="Key" min-width="280">
          <template #default="{ row }">
            <code>{{ maskKey(row.key) }}</code>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="expires_at" label="过期时间" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDateTime(row.expires_at) : '永不过期' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="100">
          <template #default="{ row }">
            <el-button type="danger" link @click="handleDelete(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- 添加 Key 对话框 -->
    <el-dialog v-model="showAddDialog" title="生成 API Key" width="450px">
      <el-form ref="formRef" :model="form" :rules="formRules" label-width="80px">
        <el-form-item label="名称" prop="name">
          <el-input v-model="form.name" placeholder="例如：监控系统" />
        </el-form-item>
        <el-form-item label="过期时间">
          <el-date-picker v-model="form.expires_at" type="datetime" placeholder="永不过期" style="width: 100%" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="showAddDialog = false">取消</el-button>
        <el-button type="primary" @click="handleAdd">生成</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { type FormInstance, type FormRules, ElMessageBox } from 'element-plus'
import { Icon } from '@iconify/vue'
import { getApiKeys, createApiKey, deleteApiKey } from '@/api/api-keys'
import type { ApiKey } from '@/api/api-keys'
import type { CreateApiKeyResponse } from '@/types/api'
import { formatDateTime } from '@/utils/format'

defineOptions({ name: 'ApiKeys' })

const loading = ref(false)
const keys = ref<ApiKey[]>([])

const showAddDialog = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({ name: '', expires_at: '' })
const formRules: FormRules = {
  name: [{ required: true, message: '请输入名称', trigger: 'blur' }],
}

function maskKey(key: string): string {
  if (!key || key.length <= 12) return key || '-'
  return key.slice(0, 6) + '****' + key.slice(-6)
}

async function fetchKeys() {
  loading.value = true
  try {
    const res = await getApiKeys()
    keys.value = res.keys || []
  } catch {
    keys.value = []
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    const res = await createApiKey({
      name: form.name,
      expires_at: form.expires_at || undefined,
    })
    ElMessage.success('API Key 生成成功，请及时保存完整 Key')
    const keyValue = (res as CreateApiKeyResponse)?.key || 'Key 已生成'
    ElMessageBox.alert(`<pre style="word-break:break-all;white-space:pre-wrap;margin:0;font-family:monospace">${keyValue}</pre>`, 'API Key', {
      confirmButtonText: '我已保存',
      dangerouslyUseHTMLString: true,
    })
    showAddDialog.value = false
    formRef.value?.resetFields()
    fetchKeys()
  } catch {
    // Error handled
  }
}

async function handleDelete(row: any) {
  try {
    await ElMessageBox.confirm('确认删除此 API Key？删除后无法恢复。', '提示', { type: 'warning' })
    await deleteApiKey(row.id)
    ElMessage.success('删除成功')
    fetchKeys()
  } catch {
    // User cancelled or error
  }
}

onMounted(() => fetchKeys())
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

code {
  background: var(--el-fill-color-light);
  padding: 2px 6px;
  border-radius: 4px;
  font-size: 13px;
}
</style>
