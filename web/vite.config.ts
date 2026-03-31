import { type ConfigEnv, type UserConfig, defineConfig, loadEnv } from 'vite'
import vue from '@vitejs/plugin-vue'
import { resolve } from 'path'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

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
        resolvers: [ElementPlusResolver()],
        dts: 'src/components.d.ts',
      }),
    ],
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
      sourcemap: false,
    },
  }
})
