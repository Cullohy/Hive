import { fileURLToPath, URL } from 'node:url'

import vue from '@vitejs/plugin-vue'
import { defineConfig } from 'vite'

// 开发：`npm run dev` 起 Vite（5173），/api 代理到后端（8080），前端热更新。
// 生产：`npm run build` 输出到 frontend/dist，由 `python -m recon web` 直接托管，
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
        target: process.env.RECON_API || 'http://127.0.0.1:8080',
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
