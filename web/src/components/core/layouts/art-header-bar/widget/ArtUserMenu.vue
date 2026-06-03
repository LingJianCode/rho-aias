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
        <div class="flex-c cursor-pointer hover:text-danger transition-colors" @click="handleLogout">
          <span class="ri:logout-box-r-line mr-1.5"></span>
          <span class="text-sm">退出登录</span>
        </div>
      </div>
    </template>
  </ElPopover>
</template>

<script setup lang="ts">
  import { useUserStore } from '@/store/modules/user'
  import avatarImg from '@/assets/images/user/avatar.webp'
  import { fetchLogout } from '@/api/auth'
  import { ElMessageBox } from 'element-plus'

  defineOptions({ name: 'ArtUserMenu' })

  const userStore = useUserStore()

  const { getUserInfo: userInfo } = storeToRefs(userStore)

  async function handleLogout() {
    try {
      await ElMessageBox.confirm('确认退出登录？', '提示', { type: 'warning' })
      await fetchLogout()
      userStore.logOut()
    } catch {
      // User cancelled
    }
  }
</script>

<style scoped>
  @reference '@styles/core/tailwind.css';
</style>
