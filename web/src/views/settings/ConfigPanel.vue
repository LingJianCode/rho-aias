<template>
  <div class="config-panel">
    <div class="page-header">
      <h2>防护策略配置</h2>
    </div>
    <el-alert
      :type="saveStatus === 'success' ? 'success' : saveStatus === 'error' ? 'error' : 'info'"
      :closable="false"
      style="margin-bottom: 16px"
    >
      {{ saveMessage || '修改配置后即时生效，无需重启服务。各模块参数说明请参考文档。' }}
    </el-alert>

    <el-card>
      <template #header>
        <div class="card-header">
          <el-radio-group v-model="activeModule" @change="(val) => switchModule(val as ConfigModuleName)">
            <el-radio-button v-for="mod in modules" :key="mod.key" :value="mod.key">
              {{ mod.label }}
            </el-radio-button>
          </el-radio-group>
        </div>
      </template>

      <!-- 表单区域 -->
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
              <el-button type="primary" @click="prepareSave('failguard', failguard)" :loading="saving">保存</el-button>
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
              <el-button type="primary" @click="prepareSave('waf', waf)" :loading="saving">保存</el-button>
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
              <el-button type="primary" @click="prepareSave('rate_limit', rate_limit)" :loading="saving">保存</el-button>
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
              <el-button type="primary" @click="prepareSave('anomaly_detection', { ...anomaly, baseline })" :loading="saving">保存</el-button>
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
              <el-button type="primary" @click="prepareSave('geo_blocking', geo)" :loading="saving">保存</el-button>
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
              <el-button type="primary" @click="prepareSave('intel', intel)" :loading="saving">保存</el-button>
            </el-form-item>
          </el-form>
        </template>
      </div>
    </el-card>

    <!-- 变更确认对话框 -->
    <el-dialog
      v-model="confirmDialogVisible"
      title="确认配置变更"
      width="560px"
      :close-on-click-modal="false"
    >
      <div class="confirm-content">
        <p class="confirm-intro">以下配置项将被修改，<strong>变更即时生效</strong>：</p>
        <div class="module-diff-header">{{ pendingModuleName }}</div>
        <div class="diff-list" v-if="diffItems.length">
          <div
            v-for="(item, index) in diffItems"
            :key="index"
            class="diff-item"
            :class="{ 'diff-danger': item.dangerous }"
          >
            <span class="diff-label">{{ item.label }}</span>
            <span class="diff-old">{{ item.oldFormatted }}</span>
            <span class="diff-arrow">→</span>
            <span class="diff-new">{{ item.newFormatted }}</span>
          </div>
        </div>
        <el-alert v-if="hasDangerousChange" type="warning" :closable="false" show-icon style="margin-top: 12px">
          部分关键安全参数变更可能影响现有连接或防护策略，请确认操作。
        </el-alert>
      </div>
      <template #footer>
        <el-button @click="confirmDialogVisible = false">取消</el-button>
        <el-button type="primary" @click="confirmAndSave" :loading="saving">确认保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getModuleConfig, updateModuleConfig } from '@/api/config'
import type { ConfigModuleName } from '@/types/api'

const loading = ref(false)
const saving = ref(false)
const activeModule = ref<ConfigModuleName>('failguard')
const saveStatus = ref<'success' | 'error' | ''>('')
const saveMessage = ref('')

// 确认对话框状态
const confirmDialogVisible = ref(false)
const pendingModule = ref<ConfigModuleName | null>(null)
const pendingData = ref<Record<string, unknown>>({})
const pendingModuleName = ref('')
const diffItems = ref<{ label: string; oldFormatted: string; newFormatted: string; dangerous: boolean }[]>([])
const hasDangerousChange = ref(false)

// 原始值快照（用于计算 diff）
const originalSnapshot = ref<Record<string, Record<string, unknown>>>({})

// 字段标签映射
const fieldLabels: Record<string, Record<string, string>> = {
  failguard: {
    enabled: '启用状态',
    max_retry: '最大重试次数',
    find_time: '检测时间窗口(秒)',
    ban_duration: '封禁时长(秒)',
    mode: '检测模式',
  },
  waf: {
    enabled: '启用状态',
    ban_duration: '封禁时长(秒)',
  },
  rate_limit: {
    enabled: '启用状态',
    ban_duration: '封禁时长(秒)',
  },
  anomaly_detection: {
    enabled: '启用状态',
    min_packets: '最小包阈值',
    ports: '监控端口列表',
    'baseline.packets_per_sec': '每秒包数阈值',
    'baseline.bytes_per_sec': '每秒字节数阈值',
  },
  geo_blocking: {
    enabled: '启用状态',
    mode: '运行模式',
    allowed_countries: '国家/地区列表',
  },
  intel: {
    enabled: '启用状态',
  },
}

// 危险操作判定：关闭已启用的核心模块
function isDangerous(module: string, field: string, oldValue: unknown, newValue: unknown): boolean {
  if (field === 'enabled') return oldValue === true && newValue === false
  return false
}

// 格式化值用于显示
function formatDiffValue(val: unknown): string {
  if (val === undefined || val === null) return '-'
  if (typeof val === 'boolean') return val ? '启用' : '禁用'
  if (Array.isArray(val)) {
    if (val.length === 0) return '(空)'
    return (val as unknown[]).join(', ')
  }
  return String(val)
}

// 模式映射中文
const modeLabels: Record<string, string> = {
  normal: '正常模式',
  ddos: 'DDoS 防护模式',
  aggressive: '激进模式',
  whitelist: '白名单模式',
  blacklist: '黑名单模式',
}

// 计算 diff
function computeDiff(module: ConfigModuleName, currentData: Record<string, unknown>) {
  const orig = originalSnapshot.value[module]
  if (!orig) return []

  const items: typeof diffItems.value = []
  let dangerous = false

  const labels = fieldLabels[module] || {}

  // 遍历当前数据的所有字段
  function compareFields(data: Record<string, unknown>, prefix = '') {
    for (const [key, newValue] of Object.entries(data)) {
      const fullKey = prefix ? `${prefix}.${key}` : key

      if (typeof newValue === 'object' && newValue !== null && !Array.isArray(newValue)) {
        // 嵌套对象递归比较
        const nestedOrig = prefix ? getNested(orig, prefix) : orig
        if (nestedOrig && typeof nestedOrig === 'object' && !Array.isArray(nestedOrig)) {
          compareFields(newValue as Record<string, unknown>, fullKey)
        }
        continue
      }

      const oldVal = prefix ? getNested(orig, fullKey) : orig[key]

      // 深度比较
      if (!deepEqual(oldVal, newValue)) {
        const label = labels[fullKey] || key
        let newFmt = formatDiffValue(newValue)
        let oldFmt = formatDiffValue(oldVal)

        // 特殊格式化
        if (fullKey.endsWith('.mode')) {
          oldFmt = modeLabels[String(oldVal)] || oldFmt
          newFmt = modeLabels[String(newValue)] || newFmt
        }

        const d = isDangerous(String(module), String(key), oldVal, newValue)
        if (d) dangerous = true

        items.push({
          label,
          oldFormatted: oldFmt,
          newFormatted: newFmt,
          dangerous: d,
        })
      }
    }
  }

  compareFields(currentData)
  hasDangerousChange.value = dangerous
  return items
}

function getNested(obj: Record<string, unknown>, path: string): unknown {
  return path.split('.').reduce((acc: unknown, key) => {
    if (acc && typeof acc === 'object' && !Array.isArray(acc)) {
      return (acc as Record<string, unknown>)[key]
    }
    return undefined
  }, obj)
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (!a || !b) return false
  if (typeof a !== typeof b) return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  if (Array.isArray(a)) {
    return a.length === b.length && a.every((v, i) => deepEqual(v, b[i]))
  }
  if (typeof a === 'object') {
    const ka = Object.keys(a).sort()
    const kb = Object.keys(b).sort()
    if (ka.length !== kb.length || ka.some((k, i) => k !== kb[i])) return false
    return ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]))
  }
  return false
}

// 快照当前模块的原始值
function takeSnapshot(module: ConfigModuleName) {
  switch (module) {
    case 'failguard':
      originalSnapshot.value[module] = JSON.parse(JSON.stringify(failguard))
      break
    case 'waf':
      originalSnapshot.value[module] = JSON.parse(JSON.stringify(waf))
      break
    case 'rate_limit':
      originalSnapshot.value[module] = JSON.parse(JSON.stringify(rate_limit))
      break
    case 'anomaly_detection':
      originalSnapshot.value[module] = JSON.parse(JSON.stringify({ ...anomaly, baseline }))
      break
    case 'geo_blocking':
      originalSnapshot.value[module] = JSON.parse(JSON.stringify(geo))
      break
    case 'intel':
      originalSnapshot.value[module] = JSON.parse(JSON.stringify(intel))
      break
  }
}

const modules: { key: ConfigModuleName; label: string }[] = [
  { key: 'failguard', label: 'SSH 防爆破' },
  { key: 'waf', label: 'WAF 监控' },
  { key: 'rate_limit', label: '频率限制' },
  { key: 'anomaly_detection', label: '异常检测' },
  { key: 'geo_blocking', label: '地域封禁' },
  { key: 'intel', label: '威胁情报' },
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

    // 加载完成后快照原始值
    takeSnapshot(module)
  } finally {
    loading.value = false
  }
}

/** 点击保存按钮 → 计算弹窗 */
function prepareSave(module: ConfigModuleName, data: Record<string, unknown>) {
  const diff = computeDiff(module, data)

  if (diff.length === 0) {
    ElMessage.info('没有检测到配置变更')
    return
  }

  pendingModule.value = module
  pendingData.value = data
  pendingModuleName.value = modules.find(m => m.key === module)?.label || module
  diffItems.value = diff
  confirmDialogVisible.value = true
}

/** 对话框确认 → 执行实际保存 */
async function confirmAndSave() {
  const module = pendingModule.value
  const data = pendingData.value
  if (!module) return

  saving.value = true
  try {
    await updateModuleConfig(module, data)
    ElMessage.success(`${pendingModuleName.value} 配置已保存`)
    saveStatus.value = 'success'
    saveMessage.value = '配置已保存，变更即时生效'
    confirmDialogVisible.value = false
    // 更新快照为最新值
    takeSnapshot(module)
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
.page-header {
  margin-bottom: 20px;
  h2 { margin: 0; }
}

.card-header {
  display: flex;
  align-items: center;
}

.form-area {
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

/* ---- 确认对话框样式 ---- */
.confirm-intro {
  color: var(--el-text-color-regular);
  margin: 0 0 12px;
}

.module-diff-header {
  font-weight: 600;
  font-size: 15px;
  color: var(--el-color-primary);
  padding: 8px 12px;
  background: var(--el-color-primary-light-9);
  border-radius: 4px;
  margin-bottom: 10px;
}

.diff-list {
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  overflow: hidden;
}

.diff-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  font-size: 13px;

  &:not(:last-child) {
    border-bottom: 1px solid var(--el-border-color-extra-light);
  }

  &.diff-danger {
    .diff-label, .diff-new { color: var(--el-color-danger); }
    .diff-new { font-weight: 600; }
  }
}

.diff-label {
  color: var(--el-text-color-secondary);
  white-space: nowrap;
  min-width: 110px;
  flex-shrink: 0;
}

.diff-old {
  color: var(--el-text-color-placeholder);
  text-decoration: line-through;
  min-width: 60px;
  text-align: right;
  flex-shrink: 0;
}

.diff-arrow {
  color: var(--el-text-color-placeholder);
  flex-shrink: 0;
}

.diff-new {
  color: var(--el-color-success);
  font-weight: 500;
  word-break: break-all;
}
</style>
