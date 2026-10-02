<template>
  <div class="tk-page">
    <div class="tk-card">
      <h3 class="tk-card-title"><SearchOutlined /> 资产搜索</h3>
      <div class="search-bar">
        <a-input
          v-model:value="keyword"
          size="large"
          placeholder="输入域名、IP、URL、标题、技术名或发现内容（至少 2 个字符）"
          allow-clear
          @press-enter="doSearch"
        >
          <template #prefix><SearchOutlined class="tk-muted" /></template>
        </a-input>
        <a-select v-model:value="type" size="large" style="width: 160px">
          <a-select-option value="all">全部类型</a-select-option>
          <a-select-option v-for="t in typeOptions" :key="t.value" :value="t.value">
            {{ t.label }}
          </a-select-option>
        </a-select>
        <a-button type="primary" size="large" :loading="loading" @click="doSearch">
          搜索
        </a-button>
      </div>
      <div class="tk-muted hint">
        跨<strong>全部扫描</strong>检索。结果里的「来自扫描」可以直接跳到那次任务的详情。
        <br />
        <InfoCircleOutlined class="tk-muted" />
        只搜<b>探活确认过</b>的资产 —— 原始清单里 96% 是「发现了但从没探过」的
        URL（目录爆破、JS 接口提取的产出），混在一起搜没有意义。
      </div>
    </div>

    <div v-if="searched" class="tk-card">
      <div class="result-head">
        <span>
          <strong>{{ keyword }}</strong> 匹配
          <b class="accent-text">{{ grandTotal.toLocaleString() }}</b> 条
          <template v-if="grandTotal > total">
            ，当前显示 <b>{{ total }}</b> 条
          </template>
        </span>
        <span class="tk-muted">
          <template v-for="(count, key) in counts" :key="key">
            <template v-if="count">
              {{ assetLabel(key) }}
              <b>{{ count }}</b><template v-if="totals[key] > count">/{{ totals[key] }}</template>
              &nbsp;&nbsp;
            </template>
          </template>
        </span>
      </div>

      <div v-if="!total" class="tk-empty">
        没有匹配的资产。换个关键词，或先跑一次扫描。
      </div>

      <a-tabs v-else v-model:activeKey="activeTab">
        <a-tab-pane
          v-for="group in nonEmptyGroups"
          :key="group.key"
          :tab="tabLabel(group)"
        >
          <a-table
            :columns="group.columns"
            :data-source="group.rows"
            row-key="id"
            size="small"
            :pagination="{ pageSize: 15, showSizeChanger: false }"
          >
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'primary'">
                <a
                  v-if="group.key === 'urls'"
                  :href="record.url"
                  target="_blank"
                  rel="noreferrer"
                  class="tk-mono"
                >{{ record.url }}</a>
                <span v-else class="tk-mono">{{ primaryOf(group.key, record) }}</span>
              </template>
              <template v-else-if="column.key === 'probe'">
                <a-tag v-if="probeState(record) !== null" :color="statusColor(record.status)">
                  {{ record.status }}
                </a-tag>
                <span v-else class="tk-muted">未探活</span>
              </template>
              <template v-else-if="column.key === 'scan'">
                <a-button type="link" size="small" style="padding: 0" @click="gotoScan(record)">
                  #{{ record.scan_id }} · {{ (record.scan_targets || []).join(', ') }}
                </a-button>
              </template>
            </template>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </div>

    <div v-else class="tk-card">
      <div class="tk-card-title">试试搜这些</div>
      <a-space wrap>
        <a-tag
          v-for="sample in samples"
          :key="sample"
          class="sample"
          @click="quickSearch(sample)"
        >
          {{ sample }}
        </a-tag>
      </a-space>
      <div class="tk-muted hint" style="margin-top: 12px">
        搜索覆盖：域名、IP（含归属）、端口、HTTP 端点（URL/标题/Server）、
        技术栈、结论性发现。
      </div>
    </div>
  </div>
</template>

<script setup>
import { InfoCircleOutlined, SearchOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, ref, watch } from 'vue'
import { useRouter } from 'vue-router'

import { searchAssets } from '@/api'

const router = useRouter()

const keyword = ref('')
const type = ref('all')
const searched = ref(false)
const loading = ref(false)
const results = ref({})
const counts = ref({})
//: 真实命中数（不受 limit 截断）。没有它的话过滤前后都显示同一个
//: 数字，看不出存活过滤起没起作用。
const totals = ref({})

const typeOptions = [
  { value: 'domains', label: '域名' },
  { value: 'ips', label: 'IP' },
  { value: 'ports', label: '端口' },
  // 「URL」包含了已经探活过的（原「HTTP 端点」），靠"探活"列区分
  { value: 'urls', label: 'URL' },
  { value: 'technologies', label: '技术栈' },
  { value: 'findings', label: '发现' },
]
const samples = ['example.com', 'nginx', 'admin', '403', 'cdn']

const scanColumn = { title: '来自扫描', key: 'scan', width: 220 }
const primaryColumn = (title) => ({ title, key: 'primary' })

const spec = {
  domains: {
    label: '域名',
    columns: [primaryColumn('域名'), { title: '来源', dataIndex: 'source', key: 'source', width: 120 }, scanColumn],
  },
  ips: {
    label: 'IP',
    columns: [
      primaryColumn('IP'),
      { title: '归属', dataIndex: 'org', key: 'org', width: 200 },
      scanColumn,
    ],
  },
  ports: {
    label: '端口',
    columns: [
      primaryColumn('端点'),
      { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 90 },
      scanColumn,
    ],
  },
  // URL 与 HTTP 端点合并成一种资产：两者本来是包含关系（探活过的 URL
  // 在 url 表里也有一行），分开会让"已知存在"和"已知活着"看着像两批东西。
  // 后端用 LEFT JOIN 把端点的状态/标题/Server 带出来。
  urls: {
    label: 'URL',
    columns: [
      primaryColumn('URL'),
      { title: '探活', key: 'probe', width: 90 },
      { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true },
      { title: 'Server', dataIndex: 'server', key: 'server', width: 140 },
      { title: '来源', dataIndex: 'source', key: 'source', width: 130 },
      { title: '类型', dataIndex: 'kind', key: 'kind', width: 100 },
      { title: '主机', dataIndex: 'host', key: 'host', width: 200 },
      scanColumn,
    ],
  },
  technologies: {
    label: '技术栈',
    columns: [
      primaryColumn('技术'),
      { title: '主机', dataIndex: 'host', key: 'host', width: 260 },
      { title: '证据', dataIndex: 'evidence', key: 'evidence' },
      scanColumn,
    ],
  },
  findings: {
    label: '发现',
    columns: [
      primaryColumn('目标'),
      { title: '类型', dataIndex: 'kind', key: 'kind', width: 130 },
      { title: '详情', dataIndex: 'detail', key: 'detail' },
      scanColumn,
    ],
  },
}

const groups = computed(() =>
  Object.entries(spec).map(([key, meta]) => ({
    key,
    label: meta.label,
    columns: meta.columns,
    rows: results.value[key] || [],
  })),
)
const nonEmptyGroups = computed(() => groups.value.filter((g) => g.rows.length))
const total = computed(() => Object.values(counts.value).reduce((a, b) => a + b, 0))
/** 过滤后的真实命中总数（不受 limit 截断），结果头部文案用。 */
const grandTotal = computed(() =>
  Object.values(totals.value).reduce((a, b) => a + b, 0),
)
/** 页签标题：`域名 100/15542` —— 被 limit 截断时一眼能看出来。 */
function tabLabel(group) {
  const shown = group.rows.length
  const all = totals.value[group.key] ?? shown
  return all > shown ? `${group.label} ${shown}/${all}` : `${group.label} (${shown})`
}

// 标签页要能真的切；当当前标签在这次搜结果里不存在时，自动退到第一个有内容的
const activeTab = ref('domains')
watch(nonEmptyGroups, (list) => {
  if (!list.some((g) => g.key === activeTab.value)) {
    activeTab.value = list[0]?.key || 'domains'
  }
})

function assetLabel(key) {
  return spec[key]?.label || key
}

function primaryOf(key, record) {
  if (key === 'domains') return record.name
  if (key === 'ips') return record.addr
  if (key === 'ports') return `${record.ip}:${record.port}`
  if (key === 'urls') return record.url
  if (key === 'technologies') return record.name
  if (key === 'findings') return record.target || record.kind
  return ''
}

/** 「探活」列：端点数据左连接进来的，没探过就没有 status。 */
function probeState(record) {
  return record.status === null || record.status === undefined ? null : record.status
}

function statusColor(status) {
  if (status === null || status === undefined) return 'default'
  if (status >= 200 && status < 300) return 'green'
  if (status >= 300 && status < 400) return 'blue'
  if (status === 403 || status === 401) return 'orange'
  if (status >= 400) return 'red'
  return 'default'
}

function gotoScan(record) {
  router.push({ path: '/taskList/taskDetail', query: { id: record.scan_id } })
}

function quickSearch(value) {
  keyword.value = value
  doSearch()
}

async function doSearch() {
  const q = keyword.value.trim()
  if (q.length < 2) {
    message.warning('搜索词至少 2 个字符')
    return
  }
  loading.value = true
  try {
    const data = await searchAssets(q, type.value, 100)
    results.value = data.results
    counts.value = data.counts
      totals.value = data.totals || {}
    searched.value = true
  } catch (e) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.search-bar {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.search-bar :deep(.ant-input-affix-wrapper) {
  flex: 1;
  min-width: 260px;
}
.hint {
  font-size: 12.5px;
  margin-top: 8px;
  line-height: 1.7;
}
.result-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.accent-text {
  color: var(--tk-accent);
  font-size: 16px;
}
.sample {
  cursor: pointer;
  user-select: none;
}
.sample:hover {
  color: var(--tk-accent);
  border-color: var(--tk-accent);
}
</style>
