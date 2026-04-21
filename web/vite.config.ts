import { type ConfigEnv, type UserConfig, defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'
import IconsResolver from 'unplugin-icons/resolver'
import Icons from 'unplugin-icons/vite'
import viteCompression from 'vite-plugin-compression'

const pathSrc = resolve(__dirname, 'src')

export default defineConfig(({ mode }: ConfigEnv): UserConfig => {
  const env = loadEnv(mode, process.cwd())

  return {
    resolve: {
      alias: {
        '@': pathSrc,
      },
    },
    plugins: [
      vue(),
      AutoImport({
        imports: ['vue', 'vue-router', 'pinia'],
        resolvers: [ElementPlusResolver()],
        dts: 'src/auto-imports.d.ts',
      }),
      Components({
        resolvers: [ElementPlusResolver(), IconsResolver({ enabledCollections: ['ep'] })],
        dts: 'src/components.d.ts',
      }),
      Icons({ autoInstall: true }),
      viteCompression({
        algorithm: 'gzip',
        threshold: 10240,
      }),
    ].filter(Boolean), // 过滤掉 false 值
    server: {
      host: '0.0.0.0',
      port: 3000,
      proxy: {
        [env.VITE_API_BASE_URL]: {
          target: env.VITE_API_PROXY_TARGET || 'http://localhost:8081',
          changeOrigin: true,
          rewrite: (path: string) => path.replace(new RegExp(`^${env.VITE_API_BASE_URL}`), ''),
        },
      },
    },
    build: {
      outDir: 'dist',
      sourcemap: false, // 生产环境建议关闭，减小体积
      // 3. 核心优化：分包策略
      rollupOptions: {
        output: {
          manualChunks(id) {
            if (id.includes('node_modules')) {
              if (id.includes('echarts')) return 'echarts'
              if (id.includes('element-plus/icons-vue')) return 'ep-icons'
              if (id.includes('element-plus')) return 'element-plus'
              if (id.includes('axios')) return 'axios'
              if (id.includes('vue') || id.includes('pinia')) return 'vue-vendor'
              return 'vendor'
            }
          },
        },
      },
      // 4. 提高警告阈值 (如果确实需要大文件) 或 开启 Gzip 预压缩
      chunkSizeWarningLimit: 1000, // 默认是 500kb，适当调大避免误报
    },
  }
})