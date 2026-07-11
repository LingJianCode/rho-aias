<!-- 用户菜单 -->
<template>
  <ElPopover
    ref="userMenuPopover"
    placement="bottom-end"
    :width="240"
    :hide-after="0"
    :offset="10"
    trigger="hover"
    :show-arrow="false"
    popper-class="user-menu-popover"
    popper-style="padding: 5px 16px;"
  >
    <template #reference>
      <img
        class="size-8.5 mr-5 c-p rounded-full max-sm:w-6.5 max-sm:h-6.5 max-sm:mr-[16px]"
        :src="avatarImg"
        alt="avatar"
      />
    </template>
    <template #default>
      <div class="pt-3">
        <div class="flex-c pb-1 px-0">
          <span class="block text-sm font-medium text-g-800 truncate">{{ userInfo.userName }}</span>
        </div>
      </div>
      <div class="mt-3 pt-2 border-t border-[var(--default-border)]">
        <div class="flex-c cursor-pointer hover:text-theme transition-colors" @click="openChangePassword">
          <span class="ri:lock-password-line mr-1.5"></span>
          <span class="text-sm">修改密码</span>
        </div>
        <div class="flex-c cursor-pointer hover:text-danger transition-colors mt-2.5" @click="handleLogout">
          <span class="ri:logout-box-r-line mr-1.5"></span>
          <span class="text-sm">退出登录</span>
        </div>
      </div>
    </template>
  </ElPopover>

  <!-- 修改密码对话框 -->
  <ElDialog
    v-model="dialogVisible"
    title="修改密码"
    width="420"
    :close-on-click-modal="false"
    :lock-scroll="false"
    @closed="resetForm"
  >
    <ElForm
      ref="formRef"
      :model="formData"
      :rules="rules"
      label-width="90px"
      @keyup.enter="handleSubmit"
    >
      <ElFormItem label="当前密码" prop="oldPassword">
        <ElInput
          v-model.trim="formData.oldPassword"
          type="password"
          autocomplete="off"
          show-password
          placeholder="请输入当前密码"
        />
      </ElFormItem>
      <ElFormItem label="新密码" prop="newPassword">
        <ElInput
          v-model.trim="formData.newPassword"
          type="password"
          autocomplete="off"
          show-password
          placeholder="请输入新密码（至少 6 位）"
        />
      </ElFormItem>
      <ElFormItem label="确认密码" prop="confirmPassword">
        <ElInput
          v-model.trim="formData.confirmPassword"
          type="password"
          autocomplete="off"
          show-password
          placeholder="请再次输入新密码"
        />
      </ElFormItem>
    </ElForm>
    <template #footer>
      <ElButton @click="dialogVisible = false">取消</ElButton>
      <ElButton type="primary" :loading="loading" @click="handleSubmit">确认</ElButton>
    </template>
  </ElDialog>
</template>

<script setup lang="ts">
  import { useUserStore } from '@/store/modules/user'
  import avatarImg from '@/assets/images/user/avatar.webp'
  import { fetchLogout, fetchChangePassword } from '@/api/auth'
  import { ElMessageBox, type FormInstance, type FormRules } from 'element-plus'

  defineOptions({ name: 'ArtUserMenu' })

  const userStore = useUserStore()

  const { getUserInfo: userInfo } = storeToRefs(userStore)

  const userMenuPopover = ref()

  async function handleLogout() {
    try {
      await ElMessageBox.confirm('确认退出登录？', '提示', { type: 'warning' })
      await fetchLogout()
      userStore.logOut()
    } catch {
      // User cancelled
    }
  }

  // 修改密码相关
  const dialogVisible = ref(false)
  const loading = ref(false)
  const formRef = ref<FormInstance>()

  const formData = reactive({
    oldPassword: '',
    newPassword: '',
    confirmPassword: ''
  })

  const validateConfirm = (_rule: any, value: string, callback: any) => {
    if (value !== formData.newPassword) {
      callback(new Error('两次输入的密码不一致'))
    } else {
      callback()
    }
  }

  const rules: FormRules = {
    oldPassword: [{ required: true, message: '请输入当前密码', trigger: 'blur' }],
    newPassword: [
      { required: true, message: '请输入新密码', trigger: 'blur' },
      { min: 6, message: '密码长度不能少于 6 位', trigger: 'blur' }
    ],
    confirmPassword: [
      { required: true, message: '请再次输入新密码', trigger: 'blur' },
      { validator: validateConfirm, trigger: 'blur' }
    ]
  }

  function openChangePassword() {
    userMenuPopover.value?.hide()
    dialogVisible.value = true
  }

  function resetForm() {
    formRef.value?.resetFields()
  }

  async function handleSubmit() {
    if (!formRef.value) return
    try {
      const valid = await formRef.value.validate()
      if (!valid) return

      loading.value = true
      await fetchChangePassword({
        old_password: formData.oldPassword,
        new_password: formData.newPassword
      })
      dialogVisible.value = false
    } catch {
      // 错误信息已由 http 拦截器统一提示
    } finally {
      loading.value = false
    }
  }
</script>

<style scoped>
  @reference '@styles/core/tailwind.css';
</style>
