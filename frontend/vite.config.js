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
  },
})
