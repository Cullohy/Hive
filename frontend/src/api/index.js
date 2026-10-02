import http from './http'

// ── 元信息 ───────────────────────────────────────────────────────────
export const getHealth = () => http.get('/api/health')
export const getStats = () => http.get('/api/stats')
export const getPresets = () => http.get('/api/presets')
export const getModules = (preset) =>
  http.get('/api/modules', { params: preset ? { preset } : {} })
export const getSettings = () => http.get('/api/settings')
// 「测试连接」：把表单里**还没保存**的 key / 接口地址发过去验一下。
// 服务端调源的 check_key()，尽量选不计费的接口。
export const testSource = (name, body) =>
  http.post(`/api/sources/${name}/test`, body)
export const saveSettings = (body) => http.put('/api/settings', body)
export const getAudits = (limit = 200) => http.get('/api/audits', { params: { limit } })

// ── 指纹库 ───────────────────────────────────────────────────────────
export const getFingerprints = (params = {}) => http.get('/api/fingerprints', { params })
// 新增/修改都写进 fingerprints_custom.json —— 重跑导入不会冲掉自定义规则
export const createFingerprint = (body) => http.post('/api/fingerprints', body)
export const addFingerprintMatcher = (techId, body) =>
  http.post(`/api/fingerprints/${encodeURIComponent(techId)}/matchers`, body)
export const editFingerprint = (techId, body) =>
  http.put(`/api/fingerprints/${encodeURIComponent(techId)}`, body)
export const deleteFingerprint = (techId, keyword = '') =>
  http.delete(`/api/fingerprints/${encodeURIComponent(techId)}`, {
    params: keyword ? { keyword } : {},
  })
export const reloadFingerprints = () => http.post('/api/fingerprints/reload')

// ── 扫描任务 ─────────────────────────────────────────────────────────
export const listScans = (limit = 100) => http.get('/api/scans', { params: { limit } })
export const getScan = (id) => http.get(`/api/scans/${id}`)
export const createScan = (body) => http.post('/api/scans', body)
export const stopScan = (id) => http.post(`/api/scans/${id}/stop`)
export const deleteScan = (id) => http.delete(`/api/scans/${id}`)
// 资产明细。**只返回探活确认过的资产** —— 后端 live 参数默认 true。
// 原始清单里 96% 是「发现了但没探过」的 URL，界面不展示（要完整清单用导出，
// 导出走存储层，不受这里影响）。
export const getAssets = (id, limit = 2000) =>
  http.get(`/api/scans/${id}/assets`, { params: { limit } })
export const getEvents = (id, limit = 300, type) =>
  http.get(`/api/scans/${id}/events`, { params: { limit, ...(type ? { event_type: type } : {}) } })
export const getTrace = (id, eventId) => http.get(`/api/scans/${id}/trace/${eventId}`)
export const getDiff = (id, against) =>
  http.get(`/api/scans/${id}/diff`, { params: against ? { against } : {} })

// 导出要带 Authorization 头，所以不用 <a href>，先取成 blob 再触发下载
export async function downloadExport(id, format, type = 'domains', filename) {
  const { getToken } = await import('./http')
  const params = new URLSearchParams({ format })
  if (format === 'csv') params.set('type', type)
  const token = getToken()
  const response = await fetch(`/api/scans/${id}/export?${params}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!response.ok) {
    let detail = `HTTP ${response.status}`
    try {
      const body = await response.json()
      if (typeof body.detail === 'string') detail = body.detail
    } catch {
      /* 保留状态码 */
    }
    throw new Error(detail)
  }
  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename || `hive-scan${id}.${format}`
  document.body.appendChild(link)
  link.click()
  link.remove()
  setTimeout(() => URL.revokeObjectURL(url), 3000)
}

export const screenshotUrl = (relativePath) => `/api/screenshots/${relativePath}`

// ── 全局资产搜索 ─────────────────────────────────────────────────────
// 同样只搜探活确认过的资产（后端 live 默认 true）。不过滤的话搜 qq.com
// 会命中 15542 个域名，其中只有 325 个是活的。
export const searchAssets = (q, type = 'all', limit = 50, scanId) =>
  http.get('/api/search', {
    params: { q, type, limit, ...(scanId ? { scan_id: scanId } : {}) },
  })

// ── 资产分组（对应 ARL 的「资产分组」）───────────────────────────────
// 分组 = 一组范围（主域名 / IP 网段）+ 归集到组里的资产。
// 同步是幂等的：只把「这次扫描新发现的」记进组，重复同步不会重复计。
export const listGroups = () => http.get('/api/groups')
export const getGroup = (id) => http.get(`/api/groups/${id}`)
export const createGroup = (body) => http.post('/api/groups', body)
export const updateGroup = (id, body) => http.put(`/api/groups/${id}`, body)
export const deleteGroup = (id) => http.delete(`/api/groups/${id}`)
export const addGroupScopes = (id, scopes) =>
  http.post(`/api/groups/${id}/scopes`, { scopes })
export const deleteGroupScope = (scopeId) => http.delete(`/api/scopes/${scopeId}`)
export const getGroupAssets = (id, params = {}) =>
  http.get(`/api/groups/${id}/assets`, { params })
export const syncScanToGroup = (id, scanId) =>
  http.post(`/api/groups/${id}/sync`, { scan_id: scanId })

// ── 周期监控 ─────────────────────────────────────────────────────────
export const listMonitors = () => http.get('/api/monitors')
export const createMonitor = (body) => http.post('/api/monitors', body)
export const updateMonitor = (id, body) => http.put(`/api/monitors/${id}`, body)
export const deleteMonitor = (id) => http.delete(`/api/monitors/${id}`)
export const runMonitor = (id) => http.post(`/api/monitors/${id}/run`)
export const listChanges = (params = {}) => http.get('/api/changes', { params })

// ── 告警 ─────────────────────────────────────────────────────────────
export const testNotify = (body = {}) => http.post('/api/notify/test', body)
