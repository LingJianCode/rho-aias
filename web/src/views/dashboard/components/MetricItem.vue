<template>
  <div class="metric-item">
    <span class="dot" :style="{ backgroundColor: color }"></span>
    <span class="label">{{ label }}</span>
    <span class="value">{{ formattedValue }}</span>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { formatNumber } from '@/utils/format'

const props = withDefaults(defineProps<{
  label: string
  value: number | string
  color?: string
}>(), {
  color: '#409eff',
})

const formattedValue = computed(() => {
  if (typeof props.value === 'string') return props.value
  return formatNumber(props.value)
})
</script>

<style scoped>
.metric-item {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  padding: 4px 10px;
  border-radius: var(--el-border-radius-small);
  transition: background-color 0.2s;
  white-space: nowrap;

  &:hover {
    background-color: var(--el-fill-color-light);
  }
}

.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.label {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.value {
  font-size: 15px;
  font-weight: 600;
  color: var(--el-text-color-primary);
  min-width: 36px;
  text-align: right;
}
</style>
