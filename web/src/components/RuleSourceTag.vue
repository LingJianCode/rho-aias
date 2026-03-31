<template>
  <el-tag :type="tagType" size="small" effect="plain">{{ label }}</el-tag>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { RuleSource } from '@/types/api'

const props = defineProps<{
  source: RuleSource
}>()

const sourceConfig: Record<RuleSource, { label: string; type: 'primary' | 'success' | 'warning' | 'info' | 'danger' }> = {
  manual: { label: '手动', type: 'primary' },
  ipsum: { label: 'IPsum', type: 'info' },
  spamhaus: { label: 'Spamhaus', type: 'warning' },
  waf: { label: 'WAF', type: 'danger' },
  ddos: { label: 'DDoS', type: 'danger' },
  anomaly: { label: '异常检测', type: 'warning' },
  failguard: { label: 'FailGuard', type: 'info' },
  rate_limit: { label: 'Rate Limit', type: 'warning' },
}

const tagType = computed(() => sourceConfig[props.source]?.type ?? 'info')
const label = computed(() => sourceConfig[props.source]?.label ?? props.source)
</script>
