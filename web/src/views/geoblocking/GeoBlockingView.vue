<template>
  <div class="geoblocking-view">
    <div class="page-header">
      <h2>地域封禁</h2>
    </div>

    <el-card v-loading="loading">
      <template #header>
        <div class="card-header">
          <span>配置</span>
          <el-switch v-model="config.enabled" active-text="启用" inactive-text="禁用" @change="handleSave" />
        </div>
      </template>

      <el-form :model="config" label-width="100px" style="max-width: 600px">
        <el-form-item label="模式">
          <el-radio-group v-model="config.mode" @change="handleSave">
            <el-radio value="whitelist">白名单模式（仅允许列表中的国家）</el-radio>
            <el-radio value="blacklist">黑名单模式（禁止列表中的国家）</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="国家列表">
          <el-select
            v-model="config.countries"
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

      <h4>当前已选择 {{ config.countries.length }} 个国家</h4>
      <div class="selected-countries">
        <el-tag
          v-for="code in config.countries"
          :key="code"
          closable
          @close="removeCountry(code)"
          style="margin: 4px"
        >
          {{ getCountryFlag(code) }} {{ getCountryName(code) }}
        </el-tag>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getGeoBlockingStatus, updateGeoBlockingConfig } from '@/api/geoblocking'
import type { GeoBlockingConfig } from '@/types/api'

const loading = ref(false)
const config = reactive<GeoBlockingConfig>({
  enabled: false,
  mode: 'whitelist',
  countries: [],
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
    Object.assign(config, res.data)
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
  config.countries = config.countries.filter((c) => c !== code)
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
