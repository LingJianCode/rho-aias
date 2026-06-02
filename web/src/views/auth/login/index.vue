<template>
  <div class="flex w-full h-screen">
    <LoginLeftView />

    <div class="relative flex-1">
      <AuthTopBar />

      <div class="auth-right-wrap">
        <div class="form">
          <h3 class="title">欢迎登录</h3>
          <p class="sub-title">{{ systemName }} 安全防护系统</p>
          <ElForm
            ref="formRef"
            :model="formData"
            :rules="rules"
            @keyup.enter="handleSubmit"
            style="margin-top: 25px"
          >
            <ElFormItem prop="username">
              <ElInput
                class="custom-height"
                placeholder="请输入用户名"
                v-model.trim="formData.username"
                :prefix-icon="User"
              />
            </ElFormItem>
            <ElFormItem prop="password">
              <ElInput
                class="custom-height"
                placeholder="请输入密码"
                v-model.trim="formData.password"
                type="password"
                autocomplete="off"
                show-password
                :prefix-icon="Lock"
              />
            </ElFormItem>

            <!-- 验证码 -->
            <ElFormItem prop="captchaCode">
              <div class="captcha-wrapper">
                <ElInput
                  class="custom-height captcha-input"
                  placeholder="验证码"
                  v-model.trim="formData.captchaCode"
                  @keyup.enter="handleSubmit"
                />
                <img
                  :src="captchaUrl"
                  class="captcha-image"
                  alt="验证码"
                  @click="refreshCaptcha"
                  title="点击刷新验证码"
                />
              </div>
            </ElFormItem>

            <!-- 推拽验证 -->
            <div class="relative pb-5 mt-6">
              <div
                class="relative z-[2] overflow-hidden select-none rounded-lg border border-transparent tad-300"
                :class="{ '!border-[#FF4E4F]': !isPassing && isClickPass }"
              >
                <ArtDragVerify
                  ref="dragVerify"
                  v-model:value="isPassing"
                  text="拖动滑块完成验证"
                  textColor="var(--art-gray-700)"
                  successText="验证通过"
                  progressBarBg="var(--main-color)"
                  :background="isDark ? '#26272F' : '#F1F1F4'"
                  handlerBg="var(--default-box-color)"
                />
              </div>
              <p
                class="absolute top-0 z-[1] px-px mt-2 text-xs text-[#f56c6c] tad-300"
                :class="{ 'translate-y-10': !isPassing && isClickPass }"
              >
                请完成滑块验证
              </p>
            </div>

            <div style="margin-top: 30px">
              <ElButton
                class="w-full custom-height"
                type="primary"
                @click="handleSubmit"
                :loading="loading"
                v-ripple
              >
                登 录
              </ElButton>
            </div>
          </ElForm>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import AppConfig from '@/config'
import { useUserStore } from '@/store/modules/user'
import { HttpError } from '@/utils/http/error'
import { fetchLogin, fetchGetCaptcha } from '@/api/auth'
import { ElNotification, type FormInstance, type FormRules } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { useSettingStore } from '@/store/modules/setting'

defineOptions({ name: 'Login' })

const settingStore = useSettingStore()
const { isDark } = storeToRefs(settingStore)

const userStore = useUserStore()
const router = useRouter()
const route = useRoute()
const dragVerify = ref()
const isPassing = ref(false)
const isClickPass = ref(false)

const systemName = AppConfig.systemInfo.name
const formRef = ref<FormInstance>()

// 验证码相关
const captchaId = ref('')
const captchaUrl = ref('')

const formData = reactive({
  username: '',
  password: '',
  captchaCode: ''
})

const rules: FormRules = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [
    { required: true, message: '请输入密码', trigger: 'blur' },
    { min: 6, message: '密码至少6位', trigger: 'blur' }
  ],
  captchaCode: [{ required: true, message: '请输入验证码', trigger: 'blur' }]
}

const loading = ref(false)

onMounted(() => {
  refreshCaptcha()
})

// 刷新验证码
async function refreshCaptcha() {
  try {
    const res = await fetchGetCaptcha()
    if (res) {
      captchaId.value = res.captcha_id || ''
      captchaUrl.value = res.captcha_image || ''
      formData.captchaCode = ''
    }
  } catch (error) {
    console.error('获取验证码失败:', error)
  }
}

// 登录
const handleSubmit = async () => {
  if (!formRef.value) return

  try {
    // 表单验证
    const valid = await formRef.value.validate()
    if (!valid) return

    // 拖拽验证
    if (!isPassing.value) {
      isClickPass.value = true
      return
    }

    loading.value = true

    // 登录请求
    const result = await fetchLogin({
      username: formData.username,
      password: formData.password,
      captcha_id: captchaId.value,
      captcha_code: formData.captchaCode
    })

    // 验证响应
    if (!result.token) {
      throw new Error('登录失败 - 未收到 Token')
    }

    // 设置角色（将单一 role 转换为 roles 数组）
    const userData = result.user || {}
    if (userData.role && !userData.roles) {
      userData.roles = [userData.role]
    }

    // 存储 token 和用户信息
    userStore.setToken(result.token)
    userStore.setUserInfo(userData)
    userStore.setLoginStatus(true)

    // 登录成功处理
    showLoginSuccessNotice()

    // 获取 redirect 参数，如果存在则跳转到指定页面，否则跳转到首页
    const redirect = route.query.redirect as string
    router.push(redirect || '/')
  } catch (error) {
    // 处理 HttpError
    if (error instanceof HttpError) {
      console.error('登录错误:', error.message)
    } else {
      console.error('[Login] Unexpected error:', error)
    }
    // 刷新验证码
    refreshCaptcha()
  } finally {
    loading.value = false
    resetDragVerify()
  }
}

// 重置拖拽验证
const resetDragVerify = () => {
  dragVerify.value?.reset?.()
}

// 登录成功提示
const showLoginSuccessNotice = () => {
  setTimeout(() => {
    ElNotification({
      title: '登录成功',
      type: 'success',
      duration: 2500,
      zIndex: 10000,
      message: `欢迎回来, ${systemName}!`
    })
  }, 500)
}
</script>

<style scoped>
@import './style.css';

.captcha-wrapper {
  display: flex;
  width: 100%;
  gap: 12px;
  align-items: center;
}

.captcha-input {
  flex: 1;
}

.captcha-image {
  height: 40px;
  cursor: pointer;
  border-radius: 4px;
  border: 1px solid var(--el-border-color);
}
</style>

<style lang="scss" scoped>
:deep(.el-select__wrapper) {
  height: 40px !important;
}
</style>
