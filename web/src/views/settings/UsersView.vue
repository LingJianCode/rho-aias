<template>
  <div class="users-view">
    <div class="page-header">
      <h2>用户管理</h2>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <el-button type="primary" @click="showAddDialog = true">
            <el-icon><Plus /></el-icon>添加用户
          </el-button>
        </div>
      </template>

      <el-table :data="users" v-loading="loading" stripe>
        <el-table-column prop="username" label="用户名" min-width="120" />
        <el-table-column prop="nickname" label="昵称" min-width="120">
          <template #default="{ row }">{{ row.nickname || '-' }}</template>
        </el-table-column>
        <el-table-column prop="email" label="邮箱" min-width="180" />
        <el-table-column prop="role" label="角色" width="100">
          <template #default="{ row }">
            <el-tag :type="row.role === 'admin' ? 'danger' : 'info'" size="small">
              {{ row.role === 'admin' ? '管理员' : '用户' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="active" label="状态" width="80">
          <template #default="{ row }">
            <el-tag :type="row.active ? 'success' : 'danger'" size="small">
              {{ row.active ? '正常' : '禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="created_at" label="创建时间" width="180">
          <template #default="{ row }">{{ formatDateTime(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" width="150">
          <template #default="{ row }">
            <el-button type="primary" link @click="handleEdit(row)">编辑</el-button>
            <el-button type="danger" link @click="handleDelete(row)" :disabled="row.role === 'admin'">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <el-dialog v-model="showAddDialog" :title="editingUser ? '编辑用户' : '添加用户'" width="500px">
      <el-form ref="formRef" :model="form" :rules="rules" label-width="80px">
        <el-form-item label="用户名" prop="username" v-if="!editingUser">
          <el-input v-model="form.username" />
        </el-form-item>
        <el-form-item label="昵称" prop="nickname">
          <el-input v-model="form.nickname" />
        </el-form-item>
        <el-form-item label="邮箱" prop="email">
          <el-input v-model="form.email" />
        </el-form-item>
        <el-form-item label="密码" prop="password" v-if="!editingUser">
          <el-input v-model="form.password" type="password" show-password />
        </el-form-item>
        <el-form-item label="角色" prop="role">
          <el-select v-model="form.role">
            <el-option label="用户" value="user" />
            <el-option label="管理员" value="admin" />
          </el-select>
        </el-form-item>
        <el-form-item label="状态" prop="active" v-if="editingUser">
          <el-switch v-model="form.active" active-text="启用" inactive-text="禁用" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="closeDialog">取消</el-button>
        <el-button type="primary" @click="handleSubmit">确定</el-button>
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
import { getUsers, createUser, updateUser, deleteUser } from '@/api/users'
import type { User } from '@/types/api'

const { confirmDelete } = useConfirm()

const loading = ref(false)
const users = ref<User[]>([])

const showAddDialog = ref(false)
const editingUser = ref<User | null>(null)
const formRef = ref<FormInstance>()

const form = reactive({
  username: '',
  nickname: '',
  email: '',
  password: '',
  role: 'user',
  active: true,
})

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  email: [{ required: true, type: 'email', message: '请输入有效邮箱', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
}

async function fetchUsers() {
  loading.value = true
  try {
    const res = await getUsers()
    users.value = res.data.users
  } catch {
    // 模拟数据（已注释保留作为格式提示）：
    // users.value = [
    //   { id: 1, username: 'admin', nickname: '管理员', email: 'admin@example.com', role: 'admin', active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    //   { id: 2, username: 'user1', nickname: '用户1', email: 'user1@example.com', role: 'user', active: true, created_at: new Date().toISOString(), updated_at: new Date().toISOString() },
    // ]
    users.value = []
  } finally {
    loading.value = false
  }
}

function handleEdit(user: User) {
  editingUser.value = user
  form.username = user.username
  form.nickname = user.nickname || ''
  form.email = user.email
  form.role = user.role
  form.active = user.active
  showAddDialog.value = true
}

function closeDialog() {
  showAddDialog.value = false
  editingUser.value = null
  formRef.value?.resetFields()
}

async function handleSubmit() {
  const valid = await formRef.value?.validate()
  if (!valid) return

  try {
    if (editingUser.value) {
      await updateUser(editingUser.value.id, {
        nickname: form.nickname,
        email: form.email,
        role: form.role,
        active: form.active,
      })
      ElMessage.success('更新成功')
    } else {
      await createUser({
        username: form.username,
        password: form.password,
        nickname: form.nickname,
        email: form.email,
        role: form.role,
      })
      ElMessage.success('添加成功')
    }
    closeDialog()
    fetchUsers()
  } catch {
    // Error handled
  }
}

async function handleDelete(user: User) {
  if (!(await confirmDelete(user.username))) return
  try {
    await deleteUser(user.id)
    ElMessage.success('删除成功')
    fetchUsers()
  } catch {
    // Error handled
  }
}

onMounted(() => {
  fetchUsers()
})
</script>

<style lang="scss" scoped>
.pagination-wrapper {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
</style>
