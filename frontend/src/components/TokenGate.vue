<template>
  <div class="gate">
    <div class="gate-card">
      <!-- 图标与 logo.svg 共用同一个文件 —— 图标是橙色的，与背景色无关，
           所以不需要"深色版"。文字由下面的 h1 承担。 -->
      <img src="/logo.svg" alt="Hive" class="gate-logo" />
      <h1>Hive蜂巢 控制台</h1>
      <p class="tk-muted">
        这个服务开启了访问令牌校验。请输入启动时 <code>--token</code> 指定的令牌。
      </p>
      <a-input-password
        v-model:value="value"
        size="large"
        placeholder="访问令牌"
        autocomplete="off"
        @press-enter="submit"
      />
      <a-button type="primary" size="large" block :loading="loading" @click="submit">
        进入
      </a-button>
      <p v-if="error" class="gate-error">{{ error }}</p>
      <p class="tk-muted gate-hint">
        令牌只保存在浏览器本地（localStorage），不会发往其他地方。
      </p>
    </div>
  </div>
</template>

<script setup>
import { ref } from 'vue'

import { getSettings } from '@/api'
import { setToken } from '@/api/http'

const emit = defineEmits(['ok'])

const value = ref('')
const loading = ref(false)
const error = ref('')

async function submit() {
  const token = value.value.trim()
  if (!token) {
    error.value = '令牌不能为空'
    return
  }
  loading.value = true
  error.value = ''
  setToken(token)
  try {
    // ⚠️ 必须打一个**受保护**的接口来验证令牌。
    // /api/health 是刻意免认证的（前端要靠它判断"要不要令牌"），拿它验永远通过。
    await getSettings()
    emit('ok')
  } catch (e) {
    setToken('') // 别在本地留一个坏令牌，否则每次请求都 401
    error.value = e.message || '令牌校验失败'
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.gate {
  position: fixed;
  inset: 0;
  z-index: 1000;
  background: var(--tk-primary);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
}
.gate-card {
  width: 380px;
  max-width: 100%;
  background: var(--tk-surface);
  border-radius: 8px;
  padding: 32px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  box-shadow: 0 12px 40px rgba(0, 0, 0, 0.35);
}
.gate-logo {
  height: 34px;
  align-self: center;
}
h1 {
  font-size: 19px;
  margin: 0;
  text-align: center;
}
p {
  margin: 0;
  font-size: 13px;
}
.gate-error {
  color: #dc2626;
  font-size: 13px;
}
.gate-hint {
  font-size: 12px;
  text-align: center;
}
code {
  background: var(--tk-surface-2);
  padding: 1px 5px;
  border-radius: 3px;
}
</style>
