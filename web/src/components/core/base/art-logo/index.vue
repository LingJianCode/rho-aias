<!-- 系统logo -->
<template>
  <div class="flex-cc">
    <img :style="logoStyle" :src="logoImg" alt="logo" class="w-full h-full" />
  </div>
</template>

<script setup lang="ts">
  import logoImg from '@/assets/images/common/logo.svg'

  defineOptions({ name: 'ArtLogo' })

  interface Props {
    /** logo 大小 */
    size?: number | string
  }

  const props = withDefaults(defineProps<Props>(), {
    size: 36
  })

  const logoStyle = computed(() => ({ width: `${props.size}px` }))
</script>
