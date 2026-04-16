<template>
  <el-input
    v-model="inputValue"
    :placeholder="placeholder"
    clearable
    @blur="validate"
  >
    <template #append v-if="showCidr">
      <el-input-number
        v-model="cidrValue"
        :min="0"
        :max="maxCidr"
        :controls="false"
        style="width: 60px"
      />
    </template>
  </el-input>
  <div v-if="error" class="ip-input-error">{{ error }}</div>
</template>

<script setup lang="ts">
import { ref, watch, computed } from 'vue'

const props = defineProps<{
  modelValue?: string
  cidr?: number
  placeholder?: string
  showCidr?: boolean
  ipv6?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', value: string): void
  (e: 'update:cidr', value: number): void
}>()

const inputValue = ref(props.modelValue || '')
const cidrValue = ref(props.cidr ?? 32)
const error = ref('')

const maxCidr = computed(() => props.ipv6 ? 128 : 32)

const ipv4Regex = /^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$/
const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/

function validate() {
  if (!inputValue.value) {
    error.value = ''
    return true
  }

  const isValid = props.ipv6 ? ipv6Regex.test(inputValue.value) : ipv4Regex.test(inputValue.value)
  if (!isValid) {
    error.value = props.ipv6 ? '无效的 IPv6 地址' : '无效的 IPv4 地址'
    return false
  }
  error.value = ''
  return true
}

watch(inputValue, (val) => {
  emit('update:modelValue', val)
})

watch(cidrValue, (val) => {
  emit('update:cidr', val)
})

watch(() => props.modelValue, (val) => {
  inputValue.value = val || ''
})

watch(() => props.cidr, (val) => {
  if (val !== undefined) cidrValue.value = val
})
</script>

<style scoped>
.ip-input-error {
  color: var(--el-color-danger);
  font-size: 12px;
  margin-top: 4px;
}
</style>
