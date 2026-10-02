import axios from 'axios'

const TOKEN_KEY = 'recon_token'

export const getToken = () => localStorage.getItem(TOKEN_KEY) || ''

export function setToken(value) {
  if (value) localStorage.setItem(TOKEN_KEY, value)
  else localStorage.removeItem(TOKEN_KEY)
}

const http = axios.create({
  // 开发时走 Vite 代理（同源），生产时由后端同源托管，所以 baseURL 留空即可
  baseURL: '',
  timeout: 120000,
})

http.interceptors.request.use((config) => {
  const token = getToken()
  if (token) config.headers.Authorization = `Bearer ${token}`
  return config
})

http.interceptors.response.use(
  (response) => response.data,
  (error) => {
    const status = error.response?.status

    // 401 交给上层弹一次令牌输入框（App.vue 监听这个事件）
    if (status === 401) {
      window.dispatchEvent(new CustomEvent('recon:need-token'))
    }

    const detail = error.response?.data?.detail
    let message
    if (typeof detail === 'string') message = detail
    else if (detail) message = JSON.stringify(detail)
    else if (error.code === 'ECONNABORTED') message = '请求超时'
    else if (!error.response) message = '连不上后端服务'
    else message = error.message || '请求失败'

    return Promise.reject(new Error(message))
  },
)

export default http
