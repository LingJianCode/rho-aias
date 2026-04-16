<template>
  <el-card shadow="hover" class="stats-card">
    <div class="stats-content">
      <div class="stats-icon" :style="{ backgroundColor: iconBgColor }">
        <el-icon :size="24"><component :is="icon" /></el-icon>
      </div>
      <div class="stats-info">
        <div class="stats-value">{{ formattedValue }}</div>
        <div class="stats-label">{{ label }}</div>
      </div>
    </div>
    <div v-if="$slots.extra" class="stats-extra">
      <slot name="extra" />
    </div>
    <div v-if="trend !== undefined" class="stats-trend" :class="trendClass">
      <el-icon><component :is="trendIcon" /></el-icon>
      <span>{{ Math.abs(trend) }}%</span>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { computed, type Component } from 'vue'
import { TrendCharts, CaretTop, CaretBottom } from '@element-plus/icons-vue'
import { formatNumber } from '@/utils/format'

const props = defineProps<{
  label: string
  value: number
  icon: Component
  iconColor?: string
  trend?: number
  format?: 'number' | 'bytes'
}>()

const iconBgColor = computed(() => props.iconColor ? `${props.iconColor}20` : 'var(--el-color-primary-light-9)')

const formattedValue = computed(() => {
  if (props.format === 'bytes') return formatBytes(props.value)
  return formatNumber(props.value)
})

const trendClass = computed(() => ({
  'trend-up': props.trend && props.trend > 0,
  'trend-down': props.trend && props.trend < 0,
}))

const trendIcon = computed(() => props.trend && props.trend > 0 ? CaretTop : CaretBottom)

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
</script>

<style scoped>
.stats-card {
  height: 100%;
}

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
  color: var(--el-color-primary);
}

.stats-info {
  flex: 1;
}

.stats-value {
  font-size: 24px;
  font-weight: 600;
  color: var(--el-text-color-primary);
}

.stats-label {
  font-size: 14px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}

.stats-trend {
  display: flex;
  align-items: center;
  gap: 4px;
  font-size: 14px;
  margin-top: 12px;
}

.stats-extra {
  margin-top: 8px;
  text-align: center;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.stats-trend.trend-up {
  color: var(--el-color-success);
}

.stats-trend.trend-down {
  color: var(--el-color-danger);
}
</style>
