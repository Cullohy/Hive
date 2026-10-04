<template>
  <div class="tk-page">
    <div class="tk-stat-grid" style="margin-bottom: 16px">
      <div v-for="card in cards" :key="card.label" class="tk-stat">
        <div class="tk-stat-label">{{ card.label }}</div>
        <div class="tk-stat-value" :class="{ accent: card.accent }">{{ card.value }}</div>
      </div>
    </div>

    <div class="search-bar">
      <a-input
        v-model:value="filterText"
        size="large"
        placeholder="搜索名称 / 目标 / TaskId / 预设"
        allow-clear
      >
        <template #prefix><SearchOutlined class="tk-muted" /></template>
      </a-input>
      <a-select
        v-model:value="filterStatus"
        size="large"
        style="width: 140px"
        placeholder="筛选状态"
      >
        <a-select-option value="all">全部状态</a-select-option>
        <a-select-option value="running">运行中</a-select-option>
        <a-select-option value="finished">已完成</a-select-option>
        <a-select-option value="stopped">已停止</a-select-option>
        <a-select-option value="error">出错</a-select-option>
      </a-select>
    </div>

    <div class="tk-card">
      <div class="toolbar">
        <h3 class="tk-card-title" style="margin: 0">任务列表</h3>
        <span class="grow" />
        <a-button type="primary" @click="showCreate = true">
          <PlusOutlined /> 创建任务
        </a-button>
        <a-button size="small" style="width:28px;padding:0" @click="load(true)">
          <ReloadOutlined />
        </a-button>
      </div>

      <CreateTaskModal v-model:open="showCreate" @created="onCreated" />

      <a-table
        :columns="columns"
        :data-source="filteredScans"
        :loading="loading"
        row-key="scan_id"
        size="middle"
        :pagination="{ pageSize: 20, showSizeChanger: false }"
        :scroll="{ x: 1260 }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <!-- 名称是可选标签：没填时不留空，也不重复显示目标（目标有自己一列） -->
            <span v-if="record.name">{{ record.name }}</span>
            <span v-else class="tk-muted">未命名</span>
          </template>

          <template v-else-if="column.key === 'targets'">
            <span class="tk-mono">{{ (record.targets || []).join(', ') }}</span>
          </template>

          <template v-else-if="column.key === 'task_code'">
            <span class="tk-mono task-code">{{ record.task_code || '—' }}</span>
          </template>

          <template v-else-if="column.key === 'status'">
            <a-badge :status="statusBadge(record.status)" :text="statusText(record.status)" />
          </template>

          <template v-else-if="column.key === 'assets'">
            <span v-if="record.progress" class="tk-muted">
              域名 {{ record.progress.domains ?? '-' }} · URL {{ record.progress.urls ?? '-' }}
            </span>
            <span v-else-if="record.domains != null" class="tk-muted">
              域名 {{ record.domains }} · URL {{ record.urls ?? 0 }}
            </span>
            <a-button v-else type="link" size="small" style="padding: 0" @click="openDetail(record)">
              查看
            </a-button>
          </template>

          <template v-else-if="column.key === 'started_at'">
            <span class="tk-mono">{{ fmtCst(record.started_at) }}</span>
          </template>

          <template v-else-if="column.key === 'actions'">
            <a-space :size="4">
              <a-button type="link" size="small" @click="openDetail(record)">详情</a-button>
              <a-button
                v-if="record.status === 'running'"
                type="link"
                size="small"
                danger
                @click="onStop(record)"
              >
                停止
              </a-button>
              <a-popconfirm
                :title="`删除这次扫描？它带出的域名 / IP / 端口 / URL / 端点 / 技术栈 / 发现会一起删除，其他扫描也共用到的资产同样会没。审计日志保留。`"
                ok-text="删除"
                cancel-text="取消"
                @confirm="onDelete(record)"
              >
                <a-button type="link" size="small" danger>删除</a-button>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </div>
  </div>
</template>

<script setup>
import { PlusOutlined, ReloadOutlined, SearchOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'

import CreateTaskModal from '@/components/CreateTaskModal.vue'

import { deleteScan, getStats, listScans, stopScan } from '@/api'

const router = useRouter()

const scans = ref([])
const stats = ref({})
const loading = ref(false)
const showCreate = ref(false)
const filterText = ref('')
const filterStatus = ref('all')

const filteredScans = computed(() => {
  const q = filterText.value.trim().toLowerCase()
  const status = filterStatus.value
  return scans.value.filter((s) => {
    if (status !== 'all' && s.status !== status) return false
    if (!q) return true
    const targets = (s.targets || []).join(' ').toLowerCase()
    const name = (s.name || '').toLowerCase()
    const code = (s.task_code || '').toLowerCase()
    const preset = (s.preset || '').toLowerCase()
    return targets.includes(q) || name.includes(q) || code.includes(q) || preset.includes(q)
  })
})
let timer = null

const columns = [
  { title: '任务名称', key: 'name', width: 170, ellipsis: true },
  { title: '目标', key: 'targets', width: 240 },
  // TaskId 是 scan_id 的短码（见后端 util/ids.py）—— 对外展示不用连续整数
  { title: 'TaskId', dataIndex: 'task_code', key: 'task_code', width: 110 },
  { title: '预设', dataIndex: 'preset', key: 'preset', width: 90 },
  { title: '状态', key: 'status', width: 110 },
  { title: '资产', key: 'assets', width: 150 },

  { title: '创建时间', dataIndex: 'started_at', key: 'started_at', width: 170 },
  { title: '操作', key: 'actions', width: 170, fixed: 'right' },
]

const cards = computed(() => [
  { label: '扫描总数', value: stats.value.scans ?? 0 },
  { label: '正在运行', value: stats.value.scans_running ?? 0, accent: (stats.value.scans_running ?? 0) > 0 },
  { label: '启用中的监控', value: stats.value.monitors ?? 0 },
])

function statusBadge(status) {
  if (status === 'finished') return 'success'
  if (status === 'running') return 'processing'
  if (status === 'finalizing') return 'processing'
  if (status === 'stopped') return 'warning'
  return 'error'
}

function statusText(status) {
  return (
    {
      finished: '已完成',
      running: '运行中',
      finalizing: '整理中',
      stopped: '已停止',
      error: '出错',
    }[status] || status
  )
}

// 格式化 ISO 时间字符串为 "YYYY-MM-DD HH:mm:ss"（中国时区 CST，UTC+8）
function fmtCst(iso) {
  if (!iso) return '—'
  try {
    return new Intl.DateTimeFormat('zh-CN', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    }).format(new Date(iso))
  } catch {
    return iso
  }
}

function openDetail(record) {
  router.push({ path: '/taskList/taskDetail', query: { id: record.scan_id } })
}

async function onStop(record) {
  try {
    await stopScan(record.scan_id)
    message.success(`已请求停止 #${record.scan_id}`)
    await load()
  } catch (e) {
    message.error(e.message)
  }
}

async function onDelete(record) {
  try {
    await deleteScan(record.scan_id)
    message.success(`已删除 #${record.scan_id}`)
    await load()
  } catch (e) {
    message.error(e.message)
  }
}

async function load(toast = false) {
  loading.value = true
  try {
    const [list, overview] = await Promise.all([listScans(100), getStats()])
    scans.value = list
    stats.value = overview
    if (toast) message.success('刷新成功')
  } catch (e) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

// 只在真的有任务在跑时才持续轮询，空闲时不打扰后端
watch(
  [scans],
  () => {
    const busy = scans.value.some((s) => ['running', 'finalizing'].includes(s.status))
    if (timer) {
      clearInterval(timer)
      timer = null
    }
    if (busy) timer = setInterval(load, 3000)
  },
  { deep: false },
)

/** 新建任务后：刷新列表，并直接跳到那次任务的详情。 */
function onCreated(scanId) {
  load()
  router.push({ path: '/taskList/taskDetail', query: { id: scanId } })
}

onMounted(load)
onUnmounted(() => timer && clearInterval(timer))
</script>

<style scoped>
/* TaskId 是 8 位随机短码，等宽字体 + 一点字距更好认 */
.task-code {
  letter-spacing: 0.6px;
  font-size: 12px;
}
.search-bar {
  display: flex;
  gap: 10px;
  margin-bottom: 12px;
  flex-wrap: wrap;
  justify-content: flex-end;
}
.search-bar :deep(.ant-input-affix-wrapper) {
  flex: 1;
  min-width: 200px;
}
.toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.grow {
  flex: 1;
}
</style>
