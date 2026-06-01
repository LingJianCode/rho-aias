<template>
  <div class="security-view">
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

defineOptions({ name: 'SecurityIndex' })
</script>

<style lang="scss" scoped>
.security-view {
  padding: 16px;
}
</style>
