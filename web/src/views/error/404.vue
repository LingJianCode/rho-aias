<template>
  <div class="error-page">
    <div class="error-content">
      <h1>404</h1>
      <h2>页面未找到</h2>
      <p>抱歉，您访问的页面不存在</p>
      <el-button type="primary" @click="$router.push('/')">返回首页</el-button>
    </div>
  </div>
</template>

<style scoped>
.error-page {
  height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--el-bg-color-page);
}

.error-content {
  text-align: center;
}

h1 {
  font-size: 120px;
  font-weight: bold;
  color: var(--el-color-primary);
  margin: 0;
  line-height: 1;
}

h2 {
  font-size: 24px;
  color: var(--el-text-color-primary);
  margin: 20px 0 10px;
}

p {
  color: var(--el-text-color-secondary);
  margin-bottom: 24px;
}
</style>
