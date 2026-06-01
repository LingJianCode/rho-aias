<template>
  <div class="config-view">
    <el-card shadow="never" class="art-card">
      <template #header>
        <div class="card-header">
          <span>防护策略配置</span>
          <el-button type="primary" v-auth="'admin'" :loading="saving" @click="handleSave">
            保存配置
          </el-button>
        </div>
      </template>

      <el-tabs v-model="activeTab">
        <!-- WAF 配置 -->
        <el-tab-pane label="WAF 防护" name="waf">
          <el-form :model="config.waf" label-width="160px">
            <el-form-item label="启用 WAF">
              <el-switch v-model="config.waf.enabled" />
            </el-form-item>
            <el-form-item label="规则集">
              <el-checkbox-group v-model="config.waf.rule_sets">
                <el-checkbox label="sql_injection">SQL 注入</el-checkbox>
                <el-checkbox label="xss">XSS 攻击</el-checkbox>
                <el-checkbox label="path_traversal">路径遍历</el-checkbox>
                <el-checkbox label="cmd_injection">命令注入</el-checkbox>
              </el-checkbox-group>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- FailGuard 配置 -->
        <el-tab-pane label="FailGuard" name="failguard">
          <el-form :model="config.failguard" label-width="160px">
            <el-form-item label="启用 FailGuard">
              <el-switch v-model="config.failguard.enabled" />
            </el-form-item>
            <el-form-item label="失败阈值（次）">
              <el-input-number v-model="config.failguard.threshold" :min="1" :max="100" />
            </el-form-item>
            <el-form-item label="时间窗口（秒）">
              <el-input-number v-model="config.failguard.window" :min="10" :max="3600" />
            </el-form-item>
            <el-form-item label="封禁时长（秒）">
              <el-input-number v-model="config.failguard.ban_duration" :min="60" :max="86400" />
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- 异常检测配置 -->
        <el-tab-pane label="异常检测" name="anomaly">
          <el-form :model="config.anomaly" label-width="160px">
            <el-form-item label="启用异常检测">
              <el-switch v-model="config.anomaly.enabled" />
            </el-form-item>
            <el-form-item label="基线学习周期（小时）">
              <el-input-number v-model="config.anomaly.learning_period" :min="1" :max="168" />
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- Rate Limit 配置 -->
        <el-tab-pane label="Rate Limit" name="rate_limit">
          <el-form :model="config.rate_limit" label-width="160px">
            <el-form-item label="启用速率限制">
              <el-switch v-model="config.rate_limit.enabled" />
            </el-form-item>
            <el-form-item label="每 IP 请求/分钟">
              <el-input-number v-model="config.rate_limit.requests_per_minute" :min="10" :max="10000" />
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- GeoIP 配置 -->
        <el-tab-pane label="GeoIP 封禁" name="geoblocking">
          <el-form :model="config.geoblocking" label-width="160px">
            <el-form-item label="启用 GeoIP">
              <el-switch v-model="config.geoblocking.enabled" />
            </el-form-item>
            <el-form-item label="运行模式">
              <el-radio-group v-model="config.geoblocking.mode">
                <el-radio value="whitelist">白名单模式</el-radio>
                <el-radio value="blacklist">黑名单模式</el-radio>
              </el-radio-group>
            </el-form-item>
          </el-form>
        </el-tab-pane>
      </el-tabs>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { getConfig, updateConfig } from '@/api/config'

defineOptions({ name: 'Config' })

const saving = ref(false)
const activeTab = ref('waf')
const config = reactive({
  waf: {
    enabled: true,
    rule_sets: ['sql_injection', 'xss'],
  },
  failguard: {
    enabled: true,
    threshold: 5,
    window: 60,
    ban_duration: 3600,
  },
  anomaly: {
    enabled: true,
    learning_period: 24,
  },
  rate_limit: {
    enabled: true,
    requests_per_minute: 60,
  },
  geoblocking: {
    enabled: false,
    mode: 'blacklist',
  },
})

async function fetchConfig() {
  try {
    const res = await getConfig()
    Object.assign(config, res.data)
  } catch {
    // Error handled
  }
}

async function handleSave() {
  saving.value = true
  try {
    await updateConfig(config)
    ElMessage.success('配置保存成功')
  } catch {
    // Error handled
  } finally {
    saving.value = false
  }
}

onMounted(() => fetchConfig())
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
