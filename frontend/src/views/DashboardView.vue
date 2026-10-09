<template>
  <div class="tk-page">
    <!-- 运行状态 + 快捷操作 -->
    <div class="tk-card status-card">
      <div class="health-line">
        <span class="dot" :class="health.ok ? 'ok' : 'bad'" />
        <span>后端 {{ health.ok ? '在线' : '离线' }}</span>
        <span v-if="health.ok" class="tk-muted">
          · 运行中 {{ health.running }} / {{ health.max_concurrent }}
        </span>
      </div>
      <span class="grow" />
      <a-button type="primary" @click="router.push('/taskList')">
        <PlusOutlined /> 创建任务
      </a-button>
      <a-button size="small" style="width: 28px; padding: 0" @click="load(true)">
        <ReloadOutlined />
      </a-button>
    </div>

    <!-- 图表区 -->
    <a-row :gutter="[14, 14]">
      <a-col :xs="24" :lg="14">
        <div class="tk-card chart-card">
          <h3 class="tk-card-title">资产构成</h3>
          <div ref="assetEl" class="chart" />
        </div>
      </a-col>
      <a-col :xs="24" :lg="10">
        <div class="tk-card chart-card">
          <h3 class="tk-card-title">扫描状态分布</h3>
          <div ref="statusEl" class="chart" />
        </div>
      </a-col>
      <a-col :span="24">
        <div class="tk-card chart-card">
          <h3 class="tk-card-title">资产发现趋势（最近 10 次扫描）</h3>
          <div ref="trendEl" class="chart chart-tall" />
        </div>
      </a-col>
    </a-row>

    <!-- 最近扫描 -->
    <div class="tk-card">
      <div class="toolbar">
        <h3 class="tk-card-title" style="margin: 0">最近扫描</h3>
        <span class="grow" />
        <a-button type="link" size="small" @click="router.push('/taskList')">查看全部</a-button>
      </div>
      <a-table
        :columns="columns"
        :data-source="recent"
        :loading="loading"
        row-key="scan_id"
        size="middle"
        :pagination="false"
        :scroll="{ x: 900 }"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <span v-if="record.name">{{ record.name }}</span>
            <span v-else class="tk-muted">未命名</span>
          </template>

          <template v-else-if="column.key === 'targets'">
            <span class="tk-mono">{{ (record.targets || []).join(', ') }}</span>
          </template>

          <template v-else-if="column.key === 'status'">
            <a-badge :status="statusBadge(record.status)" :text="statusText(record.status)" />
          </template>

          <template v-else-if="column.key === 'mode'">
            <span :class="record.mode === 'active' ? 'mode-active' : 'tk-muted'">
              {{ record.mode === 'active' ? '主动' : '被动' }}
            </span>
          </template>

          <template v-else-if="column.key === 'assets'">
            <span class="tk-mono">{{ record.domains ?? 0 }} 域名 · {{ record.urls ?? 0 }} URL</span>
          </template>

          <template v-else-if="column.key === 'started_at'">
            <span class="tk-mono">{{ fmtCst(record.started_at) }}</span>
          </template>

          <template v-else-if="column.key === 'actions'">
            <a-button type="link" size="small" @click="openDetail(record)">详情</a-button>
          </template>
        </template>
      </a-table>
    </div>
  </div>
</template>

<script setup>
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRouter } from 'vue-router'

import * as echarts from 'echarts/core'
import { BarChart, LineChart, PieChart } from 'echarts/charts'
import {
  GridComponent,
  LegendComponent,
  TooltipComponent,
} from 'echarts/components'
import { CanvasRenderer } from 'echarts/renderers'

import { getHealth, getStats, listScans } from '@/api'

echarts.use([
  BarChart, LineChart, PieChart,
  GridComponent, LegendComponent, TooltipComponent,
  CanvasRenderer,
])

const router = useRouter()

const stats = ref({})
const health = ref({ ok: false, running: 0, max_concurrent: 0 })
const scans = ref([])
const loading = ref(false)

// ── 图表 DOM 与实例 ──
const assetEl = ref(null)
const statusEl = ref(null)
const trendEl = ref(null)
let assetChart = null
let statusChart = null
let trendChart = null

const columns = [
  { title: '任务名称', key: 'name', width: 170, ellipsis: true },
  { title: '目标', key: 'targets', width: 240 },
  { title: '状态', key: 'status', width: 100 },
  { title: '模式', key: 'mode', width: 70 },
  { title: '资产', key: 'assets', width: 140 },
  { title: '创建时间', dataIndex: 'started_at', key: 'started_at', width: 170 },
  { title: '操作', key: 'actions', width: 70, fixed: 'right' },
]

function statusBadge(status) {
  if (status === 'finished') return 'success'
  if (status === 'running' || status === 'finalizing') return 'processing'
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

// ── 图表渲染 ──
function renderCharts() {
  if (!assetChart || !statusChart || !trendChart) return
  const s = stats.value

  // 1) 资产构成柱状图
  assetChart.setOption({
    tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' } },
    grid: { left: 8, right: 16, top: 28, bottom: 20, containLabel: true },
    xAxis: {
      type: 'category',
      data: ['域名', 'IP', '端口', 'HTTP 端点', '技术栈', '发现'],
      axisLabel: { color: '#888' },
      axisLine: { lineStyle: { color: '#e5e7eb' } },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: '#f0f0f0' } },
    },
    series: [{
      name: '数量',
      type: 'bar',
      barWidth: '46%',
      data: [
        s.domains ?? 0, s.ips ?? 0, s.ports ?? 0,
        s.endpoints ?? 0, s.technologies ?? 0, s.findings ?? 0,
      ],
      itemStyle: { color: '#c2410c', borderRadius: [3, 3, 0, 0] },
    }],
  })

  // 2) 扫描状态分布环形图
  const statusCounts = { finished: 0, running: 0, stopped: 0, error: 0 }
  for (const sc of scans.value) {
    const k = statusCounts[sc.status] != null ? sc.status : 'error'
    statusCounts[k] += 1
  }
  const statusData = [
    { name: '已完成', value: statusCounts.finished, itemStyle: { color: '#22c55e' } },
    { name: '运行中', value: statusCounts.running, itemStyle: { color: '#f59e0b' } },
    { name: '已停止', value: statusCounts.stopped, itemStyle: { color: '#94a3b8' } },
    { name: '出错', value: statusCounts.error, itemStyle: { color: '#ef4444' } },
  ].filter((d) => d.value > 0)
  statusChart.setOption({
    tooltip: { trigger: 'item', formatter: '{b}: {c} 次' },
    legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8 },
    series: [{
      type: 'pie',
      radius: ['44%', '70%'],
      center: ['50%', '44%'],
      avoidLabelOverlap: true,
      itemStyle: { borderRadius: 4, borderColor: '#fff', borderWidth: 2 },
      label: { show: true, formatter: '{b} {c}' },
      data: statusData,
    }],
  })

  // 3) 资产发现趋势（最近 10 次，按时间正序）
  const recent = [...scans.value]
    .sort((a, b) => new Date(a.started_at) - new Date(b.started_at))
    .slice(-10)
  trendChart.setOption({
    tooltip: {
      trigger: 'axis',
      formatter(params) {
        const idx = params[0].dataIndex
        const sc = recent[idx]
        const head = `${sc.name || '未命名'} · ${(sc.targets || []).join(', ')}`
        const lines = params
          .map((p) => `${p.marker}${p.seriesName}：${p.value}`)
          .join('<br/>')
        return `${head}<br/>${lines}`
      },
    },
    legend: { top: 0, data: ['域名', 'URL'] },
    grid: { left: 8, right: 16, top: 34, bottom: 20, containLabel: true },
    xAxis: {
      type: 'category',
      data: recent.map((sc) => sc.task_code || sc.scan_id),
      axisLabel: { color: '#888' },
      axisLine: { lineStyle: { color: '#e5e7eb' } },
    },
    yAxis: {
      type: 'value',
      splitLine: { lineStyle: { color: '#f0f0f0' } },
    },
    series: [
      {
        name: '域名',
        type: 'bar',
        barWidth: '36%',
        data: recent.map((sc) => sc.domains ?? sc.progress?.domains ?? 0),
        itemStyle: { color: '#c2410c', borderRadius: [3, 3, 0, 0] },
      },
      {
        name: 'URL',
        type: 'line',
        smooth: true,
        symbolSize: 6,
        data: recent.map((sc) => sc.urls ?? sc.progress?.urls ?? 0),
        itemStyle: { color: '#0ea5e9' },
      },
    ],
  })
}

function onResize() {
  assetChart?.resize()
  statusChart?.resize()
  trendChart?.resize()
}

// ── 数据加载 ──
async function load(toast = false, silent = false) {
  if (!silent) loading.value = true
  try {
    const [s, h, list] = await Promise.all([getStats(), getHealth(), listScans(100)])
    stats.value = s
    health.value = h
    scans.value = list || []
    renderCharts()
    if (toast) message.success('刷新成功')
  } catch (e) {
    if (toast) message.error(e.message)
  } finally {
    if (!silent) loading.value = false
  }
}

// 最近扫描 = 列表前 5 条（/api/scans 按 id 倒序返回）
const recent = computed(() => (scans.value || []).slice(0, 5))

let timer = null
onMounted(() => {
  assetChart = echarts.init(assetEl.value)
  statusChart = echarts.init(statusEl.value)
  trendChart = echarts.init(trendEl.value)
  window.addEventListener('resize', onResize)
  load()
  timer = setInterval(() => load(false, true), 15000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
  window.removeEventListener('resize', onResize)
  assetChart?.dispose()
  statusChart?.dispose()
  trendChart?.dispose()
})
</script>

<style scoped>
.status-card {
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 12px 16px;
}
.health-line {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13.5px;
  color: var(--tk-text);
}
.dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot.ok {
  background: #22c55e;
}
.dot.bad {
  background: #ef4444;
}

.chart-card {
  height: 100%;
}
.chart-card .tk-card-title {
  margin-bottom: 4px;
}
.chart {
  height: 280px;
  width: 100%;
}
.chart-tall {
  height: 260px;
}
.mode-active {
  color: var(--tk-accent);
}
</style>