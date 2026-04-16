<template>
  <span class="country-flag" :title="countryName">
    <span v-if="flagEmoji" class="flag-emoji">{{ flagEmoji }}</span>
    <span class="country-code">{{ code }}</span>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  code?: string
}>()

const countryNames: Record<string, string> = {
  CN: '中国',
  US: '美国',
  JP: '日本',
  KR: '韩国',
  RU: '俄罗斯',
  DE: '德国',
  GB: '英国',
  FR: '法国',
  BR: '巴西',
  IN: '印度',
  AU: '澳大利亚',
  CA: '加拿大',
  NL: '荷兰',
  SG: '新加坡',
  HK: '香港',
  TW: '台湾',
}

const code = computed(() => (props.code || '').toUpperCase())

const countryName = computed(() => countryNames[code.value] || code.value || '未知')

const flagEmoji = computed(() => {
  if (!code.value || code.value.length !== 2) return ''
  const codePoints = [...code.value].map((c) => 127397 + c.charCodeAt(0))
  return String.fromCodePoint(...codePoints)
})
</script>

<style scoped>
.country-flag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.flag-emoji {
  font-size: 16px;
}

.country-code {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
</style>
