<template>
  <div class="config-panel">
    <el-alert
      :type="saveStatus === 'success' ? 'success' : saveStatus === 'error' ? 'error' : 'info'"
      :closable="false"
      style="margin-bottom: 16px"
    >
      {{ saveMessage || '修改配置后即时生效，无需重启服务。各模块参数说明请参考文档。' }}
    </el-alert>

    <div class="config-layout">
      <!-- 左侧模块导航 -->
      <div class="module-nav">
        <div
          v-for="mod in modules"
          :key="mod.key"
          class="nav-item"
          :class="{ active: activeModule === mod.key }"
          @click="switchModule(mod.key)"
        >
          <el-icon><component :is="mod.icon" /></el-icon>
          <span>{{ mod.label }}</span>
        </div>
      </div>

      <!-- 右侧表单 -->
      <div class="form-area" v-loading="loading">
        <!-- FailGuard -->
        <template v-if="activeModule === 'failguard'">
          <h3>SSH 防爆破 (FailGuard)</h3>
          <el-form :model="failguard" label-width="140px" style="max-width: 560px">
            <el-form-item label="启用状态">
              <el-switch v-model="failguard.enabled" />
            </el-form-item>
            <el-form-item label="最大重试次数">
              <el-input-number v-model="failguard.max_retry" :min="1" :max="1000" />
              <div class="form-hint">超过此次数将触发封禁</div>
            </el-form-item>
            <el-form-item label="检测时间窗口(秒)">
              <el-input-number v-model="failguard.find_time" :min="1" :max="86400" />
              <div class="form-hint">在此时间窗口内统计重试次数</div>
            </el-form-item>
            <el-form-item label="封禁时长(秒)">
              <el-input-number v-model="failguard.ban_duration" :min="1" :max="31536000" />
              <div class="form-hint">触发封禁后的持续时间</div>
            </el-form-item>
            <el-form-item label="检测模式">
              <el-select v-model="failguard.mode" style="width: 100%">
                <el-option value="normal" label="正常模式" />
                <el-option value="ddos" label="DDoS 防护模式" />
                <el-option value="aggressive" label="激进模式" />
              </el-select>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="handleSave('failguard', failguard)" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </template>

        <!-- WAF -->
        <template v-else-if="activeModule === 'waf'">
          <h3>WAF 日志监控</h3>
          <el-form :model="waf" label-width="140px" style="max-width: 480px">
            <el-form-item label="启用状态">
              <el-switch v-model="waf.enabled" />
            </el-form-item>
            <el-form-item label="封禁时长(秒)">
              <el-input-number v-model="waf.ban_duration" :min="1" :max="31536000" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="handleSave('waf', waf)" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </template>

        <!-- Rate Limit -->
        <template v-else-if="activeModule === 'rate_limit'">
          <h3>频率限制联动</h3>
          <el-form :model="rate_limit" label-width="140px" style="max-width: 480px">
            <el-form-item label="启用状态">
              <el-switch v-model="rate_limit.enabled" />
            </el-form-item>
            <el-form-item label="封禁时长(秒)">
              <el-input-number v-model="rate_limit.ban_duration" :min="1" :max="31536000" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="handleSave('rate_limit', rate_limit)" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </template>

        <!-- Anomaly Detection -->
        <template v-else-if="activeModule === 'anomaly_detection'">
          <h3>异常流量检测</h3>
          <el-form :model="anomaly" label-width="160px" style="max-width: 600px">
            <el-form-item label="启用状态">
              <el-switch v-model="anomaly.enabled" />
            </el-form-item>
            <el-form-item label="最小包阈值">
              <el-input-number v-model="anomaly.min_packets" :min="1" :max="100000" />
              <div class="form-hint">低于此数量的连接将被忽略</div>
            </el-form-item>
            <el-form-item label="监控端口列表">
              <el-select v-model="anomaly.ports" multiple filterable allow-create placeholder="输入端口号" style="width: 100%">
                <el-option v-for="p in anomaly.ports" :key="p" :label="String(p)" :value="p" />
              </el-select>
            </el-form-item>
            <el-divider content-position="left">基线参数</el-divider>
            <el-form-item label="每秒包数阈值">
              <el-input-number v-model="baseline.packets_per_sec" :min="0" />
            </el-form-item>
            <el-form-item label="每秒字节数阈值">
              <el-input-number v-model="baseline.bytes_per_sec" :min="0" />
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="handleSave('anomaly_detection', { ...anomaly, baseline })" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </template>

        <!-- Geo Blocking -->
        <template v-else-if="activeModule === 'geo_blocking'">
          <h3>地域封禁</h3>
          <el-form :model="geo" label-width="140px" style="max-width: 600px">
            <el-form-item label="启用状态">
              <el-switch v-model="geo.enabled" />
            </el-form-item>
            <el-form-item label="运行模式">
              <el-radio-group v-model="geo.mode">
                <el-radio value="whitelist">白名单模式（仅允许列表中的国家）</el-radio>
                <el-radio value="blacklist">黑名单模式（禁止列表中的国家）</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="国家/地区列表">
              <el-select
                v-model="geo.allowed_countries"
                multiple
                filterable
                placeholder="选择国家"
                style="width: 100%"
              >
                <el-option
                  v-for="c in countryOptions"
                  :key="c.code"
                  :label="`${c.flag} ${c.name}`"
                  :value="c.code"
                />
              </el-select>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" @click="handleSave('geo_blocking', geo)" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </template>

        <!-- Intel -->
        <template v-else-if="activeModule === 'intel'">
          <h3>威胁情报</h3>
          <el-form :model="intel" label-width="140px" style="max-width: 640px">
            <el-form-item label="启用状态">
              <el-switch v-model="intel.enabled" />
            </el-form-item>
            <el-divider content-position="left">数据源配置</el-divider>
            <div v-for="(src, name) in intel.sources" :key="name" style="margin-bottom: 20px; padding: 12px; border: 1px solid var(--el-border-color-lighter); border-radius: 4px;">
              <h4 style="margin: 0 0 12px">{{ name }}</h4>
              <el-form :model="src" label-width="80px">
                <el-form-item label="启用">
                  <el-switch v-model="src.enabled" />
                </el-form-item>
                <el-form-item label="调度周期">
                  <el-input v-model="src.schedule" placeholder="如 0 * * * *" />
                </el-form-item>
                <el-form-item label="URL">
                  <el-input v-model="src.url" placeholder="数据源 URL" />
                </el-form-item>
              </el-form>
            </div>
            <el-form-item>
              <el-button type="primary" @click="handleSave('intel', intel)" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </template>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { Lock, Monitor, Warning, DataAnalysis, Location, Cpu } from '@element-plus/icons-vue'
import { getModuleConfig, updateModuleConfig } from '@/api/config'
import type { ConfigModuleName } from '@/types/api'

const loading = ref(false)
const saving = ref(false)
const activeModule = ref<ConfigModuleName>('failguard')
const saveStatus = ref<'success' | 'error' | ''>('')
const saveMessage = ref('')

const modules: { key: ConfigModuleName; label: string; icon: string }[] = [
  { key: 'failguard', label: 'SSH 防爆破', icon: 'Lock' },
  { key: 'waf', label: 'WAF 监控', icon: 'Monitor' },
  { key: 'rate_limit', label: '频率限制', icon: 'Warning' },
  { key: 'anomaly_detection', label: '异常检测', icon: 'DataAnalysis' },
  { key: 'geo_blocking', label: '地域封禁', icon: 'Location' },
  { key: 'intel', label: '威胁情报', icon: 'Cpu' },
]

const failguard = reactive({ enabled: false, max_retry: 5, find_time: 600, ban_duration: 3600, mode: 'normal' as string })
const waf = reactive({ enabled: false, ban_duration: 3600 })
const rate_limit = reactive({ enabled: false, ban_duration: 3600 })
const baseline = reactive({ packets_per_sec: 0, bytes_per_sec: 0 })
const anomaly = reactive({ enabled: false, min_packets: 10, ports: [80, 443] })
const geo = reactive({ enabled: false, mode: 'whitelist' as string, allowed_countries: [] as string[] })
const intel = reactive({ enabled: false, sources: {} as Record<string, { enabled?: boolean; schedule?: string; url?: string }> })

const countryOptions = [
  { code: 'CN', name: '中国', flag: '\u{1F1E8}\u{1F1F3}' }, { code: 'US', name: '美国', flag: '\u{1F1FA}\u{1F1F8}' },
  { code: 'JP', name: '日本', flag: '\u{1F1EF}\u{1F1F5}' }, { code: 'KR', name: '韩国', flag: '\u{1F1F0}\u{1F1F7}' },
  { code: 'RU', name: '俄罗斯', flag: '\u{1F1F7}\u{1F1FA}' }, { code: 'DE', name: '德国', flag: '\u{1F1E9}\u{1F1EA}' },
  { code: 'GB', name: '英国', flag: '\u{1F1EC}\u{1F1E7}' }, { code: 'FR', name: '法国', flag: '\u{1F1EB}\u{1F1F7}' },
  { code: 'BR', name: '巴西', flag: '\u{1F1E7}\u{1F1F7}' }, { code: 'IN', name: '印度', flag: '\u{1F1EE}\u{1F1F3}' },
  { code: 'AU', name: '澳大利亚', flag: '\u{1F1E6}\u{1F1FA}' }, { code: 'CA', name: '加拿大', flag: '\u{1F1E8}\u{1F1E6}' },
]

function switchModule(key: ConfigModuleName) {
  activeModule.value = key
  loadModuleConfig(key)
}

async function loadModuleConfig(module: ConfigModuleName) {
  loading.value = true
  try {
    const res = await getModuleConfig(module)
    const data = res.data
    if (!data) return

    if (module === 'failguard') Object.assign(failguard, data)
    else if (module === 'waf') Object.assign(waf, data)
    else if (module === 'rate_limit') Object.assign(rate_limit, data)
    else if (module === 'anomaly_detection') {
      Object.assign(anomaly, { enabled: data.enabled, min_packets: data.min_packets, ports: data.ports })
      if (data.baseline) Object.assign(baseline, data.baseline)
    }
    else if (module === 'geo_blocking') Object.assign(geo, data)
    else if (module === 'intel') Object.assign(intel, { enabled: data.enabled, sources: data.sources || {} })
  } finally {
    loading.value = false
  }
}

async function handleSave(module: ConfigModuleName, data: Record<string, unknown>) {
  saving.value = true
  try {
    await updateModuleConfig(module, data)
    ElMessage.success(`${modules.find(m => m.key === module)?.label} 配置已保存`)
    saveStatus.value = 'success'
    saveMessage.value = '配置已保存，变更即时生效'
  } catch {
    saveStatus.value = 'error'
    saveMessage.value = '保存失败，请检查输入或权限'
  } finally {
    saving.value = false
  }
}

onMounted(() => loadModuleConfig(activeModule.value))
</script>

<style lang="scss" scoped>
.config-layout {
  display: flex;
  gap: 20px;
  min-height: 400px;
}

.module-nav {
  width: 180px;
  flex-shrink: 0;
}

.nav-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  cursor: pointer;
  border-radius: 6px;
  transition: all 0.2s;
  font-size: 14px;
  color: var(--el-text-color-primary);

  &:hover {
    background-color: var(--el-fill-color-light);
  }

  &.active {
    background-color: var(--el-color-primary-light-9);
    color: var(--el-color-primary);
    font-weight: 500;
  }
}

.form-area {
  flex: 1;
  padding: 16px 20px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  min-height: 300px;

  h3 {
    margin-top: 0;
    margin-bottom: 20px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--el-border-color-lighter);
  }
}

.form-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}
</style>
