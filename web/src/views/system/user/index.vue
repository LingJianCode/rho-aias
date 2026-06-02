<template>
  <div class="users-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>用户管理</span>
          <el-button type="primary" v-auth="'admin'" @click="showAddDialog = true">
            <Icon icon="ri:add-line" />添加用户
          </el-button>
        </div>
      </template>

      <el-table :data="users" v-loading="loading" stripe>
        <el-table-column prop="id" label="ID" width="80" />
        <el-table-column prop="username" label="用户名" min-width="140" />
        <el-table-column prop="role" label="角色" width="120">
          <template #default="{ row }">
            <el-tag>{{ row.role }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column prop="last_login" label="最后登录" width="180">
          <template #default="{ row }">{{ row.last_login ? formatDateTime(row.last_login) : '-' }}</template>
        </el-table-column>
        <el-table-column label="操作" width="200" v-auth="'admin'">
          <template #default="{ row }">
            <el-button link @click="handleEdit(row)">编辑</el-button>
            <el-button type="danger" link @click="handleDelete(row)">删除</el-button>
          </template>
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
          @size-change="fetchUsers"
          @current-change="fetchUsers"
        />
      </div>
    </el-card>

    <!-- 添加用户对话框 -->
    <el-dialog v-model="showAddDialog" title="添加用户" width="450px">
      <el-form ref="formRef" :model="form" :rules="formRules" label-width="80px">
        <el-form-item label="用户名" prop="username">
          <el-input v-model="form.username" placeholder="请输入用户名" />
        </el-form-item>
        <el-form-item label="密码" prop="password">
          <el-input v-model="form.password" type="password" placeholder="请输入密码" show-password />
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="form.role" style="width: 100%">
            <el-option label="Admin" value="admin" />
          </el-select>
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
import { getUsers, createUser, updateUser, deleteUser } from '@/api/users'
import { formatDateTime } from '@/utils/format'

defineOptions({ name: 'Users' })

const loading = ref(false)
const users = ref<any[]>([])
const page = ref(1)
const pageSize = ref(20)
const total = ref(0)

const showAddDialog = ref(false)
const formRef = ref<FormInstance>()
const form = reactive({ username: '', password: '', role: 'admin' })
const formRules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }, { min: 6, message: '密码至少6位', trigger: 'blur' }],
}

async function fetchUsers() {
  loading.value = true
  try {
    const res = await getUsers({ page: page.value, page_size: pageSize.value })
    users.value = res.records || []
    total.value = res.total || 0
  } catch {
    users.value = []
    total.value = 0
  } finally {
    loading.value = false
  }
}

async function handleAdd() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    await createUser({ ...form })
    ElMessage.success('添加成功')
    showAddDialog.value = false
    formRef.value?.resetFields()
    fetchUsers()
  } catch {
    // Error handled
  }
}

function handleEdit(row: any) {
  ElMessage.info('编辑功能开发中')
}

async function handleDelete(row: any) {
  try {
    await ElMessageBox.confirm(`确认删除用户 ${row.username}？`, '提示', { type: 'warning' })
    await deleteUser(row.id)
    ElMessage.success('删除成功')
    fetchUsers()
  } catch {
    // User cancelled or error
  }
}

onMounted(() => fetchUsers())
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
