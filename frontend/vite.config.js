import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

// 开发：`npm run dev` 起 Vite（5173），/api 代理到后端 —— 默认 :8000，
//       与 `python -m core` 的默认端口一致（见 backend/core/server.py）。
//       后端若换了端口，用 RECON_API 覆盖，别再来改这里。
// 生产：`npm run build` 输出到 frontend/dist，由 `python -m core` 直接托管，
//       所以生产仍然只有一条命令、一个进程，不需要 Docker 也不需要 Nginx。
export default defineConfig({
  plugins: [vue()],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
    proxy: {
      '/api': {
        // 必须与后端默认端口一致：写错的话 dev 下所有 /api 都是 500
        // （代理转到一个没人监听的端口），而页面本身还能打开，很难一眼看出。
        target: process.env.RECON_API || 'http://127.0.0.1:8000',
        changeOrigin: true,
        // 进度用了 SSE，别让代理缓冲住
        ws: false,
      },
    },
  },
  build: {
    outDir: fileURLToPath(new URL('./dist', import.meta.url)),
    emptyOutDir: true,
    // ant-design-vue 单个 chunk 会超过默认 500KB 告警线，调高免得每次构建都刷警告
    chunkSizeWarningLimit: 1500,
    rollupOptions: {
      output: {
        // 按依赖包拆 vendor chunk（2026-10-08）：
        // 1) 浏览器可长期缓存不常变的第三方库（vue/antd/axios/dayjs...），
        //    改自己代码时 vendor 不失效；
        // 2) 避免全部第三方代码挤进单个 index chunk（曾达 1574KB，超过告警线）。
        //    拆后每个 vendor 都小于 1500KB，构建不再刷警告。
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          // 顺序敏感：vue-router 必须先于 vue 判断，否则会被归进 vendor-vue
          if (id.includes('ant-design-vue')) return 'vendor-antd'
          if (id.includes('@ant-design/icons-vue')) return 'vendor-antd-icons'
          if (id.includes('vue-router')) return 'vendor-vue-router'
          if (id.includes('vue')) return 'vendor-vue'
          if (id.includes('axios')) return 'vendor-http'
          if (id.includes('dayjs')) return 'vendor-dayjs'
          return 'vendor-other'
        },
      },
    },
  },
})
