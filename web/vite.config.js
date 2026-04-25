import { defineConfig, loadEnv } from 'vite';
import vue from '@vitejs/plugin-vue';
import { resolve } from 'path';
import AutoImport from 'unplugin-auto-import/vite';
import Components from 'unplugin-vue-components/vite';
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers';
import IconsResolver from 'unplugin-icons/resolver';
import Icons from 'unplugin-icons/vite';
var pathSrc = resolve(__dirname, 'src');
export default defineConfig(function (_a) {
    var _b;
    var mode = _a.mode;
    var env = loadEnv(mode, process.cwd());
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
        ].filter(Boolean), // 过滤掉 false 值
        server: {
            host: '0.0.0.0',
            port: 3000,
            proxy: (_b = {},
                _b[env.VITE_API_BASE_URL] = {
                    target: env.VITE_API_PROXY_TARGET || 'http://localhost:8081',
                    changeOrigin: true,
                    rewrite: function (path) { return path.replace(new RegExp("^".concat(env.VITE_API_BASE_URL)), ''); },
                },
                _b),
        },
        build: {
            outDir: 'dist',
            sourcemap: false, // 生产环境建议关闭，减小体积
            // 3. 核心优化：分包策略
            rollupOptions: {
                output: {
                    manualChunks: {
                        // 将 Vue 相关库单独打包
                        'vue-vendor': ['vue', 'vue-router', 'pinia'],
                        // 将 Element Plus 单独打包 (因为它比较大)
                        'element-plus': ['element-plus'],
                        // 其他大型工具库可以放这里
                        // 'lodash-lib': ['lodash-es'] 
                    },
                },
            },
            // 4. 提高警告阈值 (如果确实需要大文件) 或 开启 Gzip 预压缩
            chunkSizeWarningLimit: 1000, // 默认是 500kb，适当调大避免误报
        },
    };
});
