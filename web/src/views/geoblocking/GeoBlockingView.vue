<template>
  <div class="geoblocking-view">
    <div class="page-header">
      <h2>地域封禁</h2>
    </div>

    <el-card v-loading="loading">
      <template #header>
        <div class="card-header">
          <span>配置</span>
          <el-switch v-model="status.enabled" active-text="启用" inactive-text="禁用" disabled />
        </div>
      </template>

      <el-alert type="info" :closable="false" style="margin-bottom: 16px">
        地域封禁功能需要加载 GeoIP 数据库后才能启用
      </el-alert>

      <el-form :model="config" label-width="100px" style="max-width: 600px">
        <el-form-item label="模式">
          <el-radio-group v-model="config.mode" @change="handleSave">
            <el-radio value="whitelist">白名单模式（仅允许列表中的国家）</el-radio>
            <el-radio value="blacklist">黑名单模式（禁止列表中的国家）</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="国家列表">
          <el-select
            v-model="config.allowed_countries"
            multiple
            filterable
            placeholder="选择国家"
            style="width: 100%"
            @change="handleSave"
          >
            <el-option
              v-for="country in countryOptions"
              :key="country.code"
              :label="country.name"
              :value="country.code"
            >
              <span>{{ country.flag }} {{ country.name }}</span>
            </el-option>
          </el-select>
        </el-form-item>
      </el-form>

      <el-divider />

      <h4>当前已选择 {{ config.allowed_countries?.length || 0 }} 个国家</h4>
      <div class="selected-countries">
        <el-tag
          v-for="code in config.allowed_countries"
          :key="code"
          closable
          @close="removeCountry(code)"
          style="margin: 4px"
        >
          {{ getCountryFlag(code) }} {{ getCountryName(code) }}
        </el-tag>
      </div>

      <el-divider />

      <h4>状态信息</h4>
      <el-descriptions :column="2" border>
        <el-descriptions-item label="最后更新">{{ status.last_update ? formatDateTime(status.last_update) : '-' }}</el-descriptions-item>
        <el-descriptions-item label="总规则数">{{ formatNumber(status.total_rules) }}</el-descriptions-item>
      </el-descriptions>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { formatDateTime, formatNumber } from '@/utils/format'
import { getGeoBlockingStatus, updateGeoBlockingConfig } from '@/api/geoblocking'
import type { GeoBlockingStatus, GeoBlockingConfigRequest } from '@/types/api'

const loading = ref(false)
const status = ref<GeoBlockingStatus>({
  enabled: false,
  mode: 'whitelist',
  allowed_countries: [],
  last_update: '',
  total_rules: 0,
  sources: {},
})

const config = reactive<GeoBlockingConfigRequest>({
  mode: 'whitelist',
  allowed_countries: [],
})

const countryOptions = [
  { code: 'CN', name: '中国', flag: '🇨🇳' },
  { code: 'US', name: '美国', flag: '🇺🇸' },
  { code: 'JP', name: '日本', flag: '🇯🇵' },
  { code: 'KR', name: '韩国', flag: '🇰🇷' },
  { code: 'RU', name: '俄罗斯', flag: '🇷🇺' },
  { code: 'DE', name: '德国', flag: '🇩🇪' },
  { code: 'GB', name: '英国', flag: '🇬🇧' },
  { code: 'FR', name: '法国', flag: '🇫🇷' },
  { code: 'BR', name: '巴西', flag: '🇧🇷' },
  { code: 'IN', name: '印度', flag: '🇮🇳' },
  { code: 'AU', name: '澳大利亚', flag: '🇦🇺' },
  { code: 'CA', name: '加拿大', flag: '🇨🇦' },
  { code: 'NL', name: '荷兰', flag: '🇳🇱' },
  { code: 'SG', name: '新加坡', flag: '🇸🇬' },
  { code: 'HK', name: '香港', flag: '🇭🇰' },
  { code: 'TW', name: '台湾', flag: '🇹🇼' },
]

function getCountryName(code: string) {
  return countryOptions.find((c) => c.code === code)?.name || code
}

function getCountryFlag(code: string) {
  return countryOptions.find((c) => c.code === code)?.flag || ''
}

async function fetchConfig() {
  loading.value = true
  try {
    const res = await getGeoBlockingStatus()
    status.value = res.data
    config.mode = res.data.mode
    config.allowed_countries = res.data.allowed_countries || []
  } catch {
    // Use defaults
  } finally {
    loading.value = false
  }
}

async function handleSave() {
  try {
    await updateGeoBlockingConfig(config)
    ElMessage.success('保存成功')
  } catch {
    // Error handled
  }
}

function removeCountry(code: string) {
  config.allowed_countries = config.allowed_countries.filter((c) => c !== code)
  handleSave()
}

onMounted(() => {
  fetchConfig()
})
</script>

<style lang="scss" scoped>
.selected-countries {
  margin-top: 12px;
}
</style>
