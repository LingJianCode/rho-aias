<template>
  <el-card shadow="hover" class="stats-card">
    <div class="stats-content">
      <div class="stats-icon" :style="{ backgroundColor: iconBgColor }">
        <el-icon :size="24"><component :is="icon" /></el-icon>
      </div>
      <div class="stats-info">
        <div class="stats-value">{{ formattedValue }}<span v-if="suffix" class="stats-suffix">{{ suffix }}</span></div>
        <div class="stats-label">{{ label }}</div>
      </div>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, type Component } from 'vue'
import { formatNumber } from '@/utils/format'

const props = withDefaults(defineProps<{
  label: string
  value: number | string
  icon: Component
  iconColor?: string
  format?: 'number' | 'bytes'
  suffix?: string
}>(), {
  format: 'number',
})

const iconBgColor = computed(() => {
  if (!props.iconColor) return 'var(--el-color-primary-light-9)'
  // 将 hex 转为带透明度的背景色
  const color = props.iconColor.replace('#', '')
  return `#${color}20`
})

const formattedValue = computed(() => {
  if (props.format === 'bytes' && typeof props.value === 'number') return formatBytes(props.value)
  return formatNumber(props.value as number)
})
</script>

<style scoped>
.stats-card { height: 100%; }

.stats-content {
  display: flex;
  align-items: center;
  gap: 16px;
}

.stats-icon {
  width: 48px;
  height: 48px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.stats-info {
  flex: 1;
  min-width: 0;
}

.stats-value {
  font-size: 24px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}

.stats-suffix {
  font-size: 14px;
  font-weight: 400;
  color: var(--el-text-color-secondary);
  margin-left: 2px;
}

.stats-label {
  font-size: 14px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}
</style>
