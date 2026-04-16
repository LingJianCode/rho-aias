<template>
  <el-card v-loading="loading" class="status-panel">
    <template #header>
      <div class="panel-header">
        <div class="panel-title">
          <el-icon><Location /></el-icon>
          <span>地域封禁状态</span>
        </div>
        <el-button type="primary" size="small" @click="handleUpdate" :loading="updating">
          更新 GeoIP 数据库
        </el-button>
      </div>
    </template>

    <el-alert type="info" :closable="false" style="margin-bottom: 16px">
      地域封禁的配置参数（模式、国家列表等）请在「系统设置 - 防护策略配置」中修改
    </el-alert>

    <el-descriptions :column="2" border>
      <el-descriptions-item label="启用状态">
        <el-tag :type="status.enabled ? 'success' : 'info'" size="small">
          {{ status.enabled ? '已启用' : '已禁用' }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="运行模式">
        <el-tag :type="status.mode === 'whitelist' ? 'primary' : 'warning'" size="small">
          {{ status.mode === 'whitelist' ? '白名单模式' : '黑名单模式' }}
        </el-tag>
      </el-descriptions-item>
      <el-descriptions-item label="允许的国家/地区">
        <div v-if="status.allowed_countries?.length > 0">
          <el-tag
            v-for="code in status.allowed_countries"
            :key="code"
            size="small"
            style="margin: 2px"
          >
            {{ getCountryFlag(code) }} {{ getCountryName(code) }}
          </el-tag>
        </div>
        <span v-else>-</span>
      </el-descriptions-item>
      <el-descriptions-item label="总规则数">
        {{ formatNumber(status.total_rules) }}
      </el-descriptions-item>
      <el-descriptions-item label="最后更新" :span="2">
        {{ status.last_update ? formatDateTime(status.last_update) : '-' }}
      </el-descriptions-item>
    </el-descriptions>

    <div v-if="sourceList.length > 0" style="margin-top: 16px">
      <h4 style="margin-bottom: 12px">GeoIP 数据源</h4>
      <el-table :data="sourceList" stripe size="small">
        <el-table-column prop="key" label="来源" min-width="140" />
        <el-table-column prop="enabled" label="启用" width="80">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'" size="small">
              {{ row.enabled ? '是' : '否' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="rule_count" label="规则数" width="100">
          <template #default="{ row }">{{ formatNumber(row.rule_count) }}</template>
        </el-table-column>
        <el-table-column prop="success" label="状态" width="90">
          <template #default="{ row }">
            <el-tag :type="row.success ? 'success' : 'danger'" size="small">
              {{ row.success ? '正常' : '异常' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_update" label="最后更新" width="170">
          <template #default="{ row }">
            {{ row.last_update ? formatDateTime(row.last_update) : '-' }}
          </template>
        </el-table-column>
        <el-table-column prop="error" label="错误信息" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">{{ row.error || '-' }}</template>
        </el-table-column>
      </el-table>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Location } from '@element-plus/icons-vue'
import { getGeoBlockingStatus, triggerGeoBlockingUpdate } from '@/api/geoblocking'
import { formatDateTime, formatNumber } from '@/utils/format'
import type { GeoBlockingStatus } from '@/types/api'

const loading = ref(false)
const updating = ref(false)
const status = ref<GeoBlockingStatus>({
  enabled: false,
  mode: 'whitelist',
  allowed_countries: [],
  last_update: '',
  total_rules: 0,
  sources: {},
})

const countryOptions: Record<string, string> = {
  CN: '\u{1F1E8}\u{1F1F3} 中国', US: '\u{1F1FA}\u{1F1F8} 美国',
  JP: '\u{1F1EF}\u{1F1F5} 日本', KR: '\u{1F1F0}\u{1F1F7} 韩国',
  RU: '\u{1F1F7}\u{1F1FA} 俄罗斯', DE: '\u{1F1E9}\u{1F1EA} 德国',
  GB: '\u{1F1EC}\u{1F1E7} 英国', FR: '\u{1F1EB}\u{1F1F7} 法国',
  BR: '\u{1F1E7}\u{1F1F7} 巴西', IN: '\u{1F1EE}\u{1F1F3} 印度',
  AU: '\u{1F1E6}\u{1F1FA} 澳大利亚', CA: '\u{1F1E8}\u{1F1E6} 加拿大',
  NL: '\u{1F1F3}\u{1F1F1} 荷兰', SG: '\u{1F1F8}\u{1F1EC} 新加坡',
}

function getCountryName(code: string): string {
  return countryOptions[code]?.split(' ')[1] || code
}

function getCountryFlag(code: string): string {
  return countryOptions[code]?.split(' ')[0] || ''
}

const sourceList = computed(() => {
  return Object.entries(status.value.sources).map(([key, val]) => ({
    key,
    ...val,
  }))
})

async function fetchStatus() {
  loading.value = true
  try {
    const res = await getGeoBlockingStatus()
    status.value = res.data
  } finally {
    loading.value = false
  }
}

async function handleUpdate() {
  updating.value = true
  try {
    await triggerGeoBlockingUpdate()
    ElMessage.success('GeoIP 数据库更新已触发')
    fetchStatus()
  } catch {
    // Error handled
  } finally {
    updating.value = false
  }
}

onMounted(() => fetchStatus())
</script>

<style lang="scss" scoped>
.panel-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.panel-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-weight: 600;
}
</style>
