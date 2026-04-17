<template>
  <div class="security-view">
    <div class="page-header">
      <h2>安全态势</h2>
      <span class="subtitle">实时监控各安全模块的运行状态</span>
    </div>

    <el-row :gutter="20">
      <el-col :span="24">
        <IntelEventPanel />
      </el-col>
    </el-row>
    <el-row :gutter="20" style="margin-top: 20px">
      <el-col :span="24">
        <GeoPanel />
      </el-col>
    </el-row>
  </div>
</template>

<script setup lang="ts">
import IntelEventPanel from './IntelEventPanel.vue'
import GeoPanel from './GeoPanel.vue'

</script>

<style lang="scss" scoped>
.page-header {
  display: flex;
  align-items: baseline;
  gap: 12px;
  margin-bottom: 20px;

  h2 {
    margin: 0;
  }

  .subtitle {
    color: var(--el-text-color-secondary);
    font-size: 14px;
  }
}
</style>
