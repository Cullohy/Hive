<template>
  <div class="tk-page">
    <!-- ── 筛选栏 ── -->
    <div class="tk-card">
      <div class="filter-row">
        <a-select v-model:value="type" style="width: 160px" size="middle">
          <a-select-option v-for="t in typeOptions" :key="t.value" :value="t.value">
            {{ t.label }}
          </a-select-option>
          <a-select-option value="all">全部（含路径与技术栈）</a-select-option>
        </a-select>

        <a-select
          v-model:value="groupId"
          style="width: 170px"
          size="middle"
          allow-clear
          placeholder="全部分组"
          :loading="groupsLoading"
        >
          <a-select-option v-for="g in groups" :key="g.id" :value="g.id">
            {{ g.name }}
          </a-select-option>
        </a-select>

        <a-select v-model:value="aliveFilter" style="width: 130px" size="middle">
          <a-select-option value="">全部状态</a-select-option>
          <a-select-option value="alive">仅存活</a-select-option>
          <a-select-option value="dead">仅未探活</a-select-option>
        </a-select>

        <a-select
          v-model:value="statusFilter"
          style="width: 140px"
          size="middle"
          allow-clear
          placeholder="状态码"
        >
          <a-select-option v-for="s in statusOptions" :key="s" :value="s">{{ s }}</a-select-option>
        </a-select>

        <!-- 时间段：按「首见时间」筛。留空 = 全部时间（默认，与"默认显示全部"一致） -->
        <a-range-picker
          v-model:value="dateRange"
          style="margin-left: 10px"
          size="middle"
          :allow-clear="true"
          :placeholder="['首见起', '首见止']"
          :presets="rangePresets"
          @change="onRangeChange"
        />

        <span class="grow" />
        <a-button @click="resetAll">重置</a-button>
        <a-button type="primary" :loading="loading" @click="doSearch">搜索</a-button>
      </div>

      <!-- 关键词 + 生效条件摘要 -->
      <div class="search-bar" style="margin-top: 10px">
        <a-input
          v-model:value="keyword"
          size="large"
          :placeholder="keywordPlaceholder"
          allow-clear
          @press-enter="doSearch"
        >
          <template #prefix><SearchOutlined class="tk-muted" /></template>
        </a-input>
      </div>

      <!-- 生效条件 chip -->
      <div
        v-if="aliveFilter || statusFilter || groupId || rangeLabel"
        class="chip-row"
      >
        <span class="chip-label">条件</span>
        <a-tag v-if="rangeLabel" color="cyan" closable @close="clearRange">
          首见:{{ rangeLabel }}
        </a-tag>
        <a-tag v-if="groupId" color="purple" closable @close="groupId = null">
          分组:{{ currentGroupName }}
        </a-tag>
        <a-tag v-if="aliveFilter" color="blue" closable @close="aliveFilter = ''">
          {{ aliveFilter === 'alive' ? '仅存活' : '仅未探活' }}
        </a-tag>
        <a-tag v-if="statusFilter" color="green" closable @close="statusFilter = null">
          状态码={{ statusFilter }}
        </a-tag>
      </div>
    </div>

    <!-- ── 资产表 ── -->
    <div v-if="searched" class="tk-card">
      <div class="result-head">
        <span>
          <strong>{{ displayQuery }}</strong> 匹配
          <b class="accent-text">{{ grandTotal.toLocaleString() }}</b> 条
          <template v-if="grandTotal > rows.length">
            ，当前显示 <b>{{ rows.length }}</b> 条
          </template>
        </span>
        <span class="tk-muted count-split">
          <template v-for="(n, key) in pageBreakdown" :key="key">
            {{ assetLabel(key) }} <b>{{ n }}</b>&nbsp;&nbsp;
          </template>
        </span>
      </div>

      <div v-if="!rows.length" class="tk-empty">
        没有匹配的资产。换个关键词或调整筛选条件。
      </div>

      <a-table
        v-else
        :columns="columns"
        :data-source="rows"
        row-key="rowKey"
        size="small"
        :custom-row="onRowClick"
        :pagination="false"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'asset'">
            <a
              v-if="record._type === 'urls'"
              :href="record.asset_key"
              target="_blank"
              rel="noreferrer"
              class="tk-mono"
            >{{ record.asset_key }}</a>
            <span v-else class="tk-mono">{{ primaryOf(record) }}</span>
            <!-- 副标题：光有 IP / 技术名看不出这是谁的，补一行上下文 -->
            <div v-if="subtitleOf(record)" class="type-label">{{ subtitleOf(record) }}</div>
            <div v-else class="type-label">{{ assetLabel(record._type) }}</div>
          </template>

          <template v-else-if="column.key === 'alive'">
            <!-- 只给存活标记，状态码挪到「标题 · 状态」列 ——
                 状态码放在这里等于把同一份信息显示两遍。 -->
            <span
              class="alive-dot"
              :class="record.status != null && record.status < 400 ? 'on' : 'off'"
              :title="record.status != null ? `HTTP ${record.status}` : '未探活'"
            />
          </template>

          <template v-else-if="column.key === 'ports'">
            <!-- 端口由后端折进行里（域名两跳、IP 一跳），这里只渲染。
                 全空显示「—」而不是 0：那说明这台机器没扫到端口，
                 与"扫了但一个都没开"是两回事。 -->
            <span v-if="portListOf(record).length" :title="portListOf(record).join(', ')">
              <span class="port-chip">{{ portListOf(record).length }}</span>
              <span class="port-sample">{{ portListOf(record).slice(0, 3).join(' ') }}</span>
              <span v-if="portListOf(record).length > 3" class="tk-muted">…</span>
            </span>
            <span v-else class="tk-muted">—</span>
          </template>

          <template v-else-if="column.key === 'paths'">
            <!-- 0 也要显示：它说明"这个 host 确实没发现路径"，不是"没查到"。
                 只在 null（后端没给这个类型算）时才显示横线。 -->
            <span v-if="record.path_count != null" class="path-count">{{ record.path_count }}</span>
            <span v-else class="tk-muted">—</span>
          </template>

          <template v-else-if="column.key === 'source'">
            <a-tag v-if="record.source" color="blue" class="src-tag">{{ record.source }}</a-tag>
            <span v-else class="tk-muted">—</span>
          </template>

          <template v-else-if="column.key === 'title'">
            <!-- 标题和状态码同一行（状态码在右）。标题过长时状态码优先保留，
                 所以标题用 flex-shrink 让位，而不是把状态码挤到第二行。 -->
            <div class="title-row">
              <span v-if="record.title" class="title-cell">{{ record.title }}</span>
              <span v-else class="tk-muted title-cell">—</span>
              <span
                v-if="record.status != null"
                class="code-chip"
                :class="statusClass(record.status)"
              >{{ record.status }}</span>
            </div>
          </template>

          <template v-else-if="column.key === 'risk'">
            <a-tag v-if="record.severity" :color="severityColor(record.severity)" class="risk-tag">
              {{ severityLabel(record.severity) }}
            </a-tag>
            <span v-else class="tk-muted">—</span>
          </template>

          <template v-else-if="column.key === 'first_seen'">
            <span class="tk-muted first-seen">{{ shortTime(record.first_seen) }}</span>
          </template>

          <template v-else-if="column.key === 'scan'">
            <a-button type="link" size="small" style="padding: 0" @click="gotoScan(record)">
              #{{ record.scan_id }}
            </a-button>
          </template>
        </template>
      </a-table>

      <!-- 分页：走服务端（后端 UNION 后统一排序再切页） -->
      <div v-if="grandTotal > pageSize" class="pager">
        <a-pagination
          :current="currentPage"
          :page-size="pageSize"
          :total="grandTotal"
          :page-size-options="['20', '50', '100', '200']"
          :show-size-changer="true"
          :show-total="(t) => `共 ${t.toLocaleString()} 条`"
          size="small"
          @change="onPageChange"
        />
      </div>
    </div>

    <!-- ── 空态 ── -->
    <div v-else class="tk-card">
      <div class="tk-card-title">试试搜这些</div>
      <a-space wrap>
        <a-tag v-for="s in samples" :key="s" class="sample" @click="quickSearch(s)">
          {{ s }}
        </a-tag>
      </a-space>
      <div class="tk-muted hint" style="margin-top: 12px">
        点<b>搜索</b>即列出全部资产（关键词留空即可）—— 默认是<b>域名 + IP</b>，
        端口折在每行里。想单独看 URL / 端口 / 技术栈 / 发现，
        用左上角类型下拉切。
      </div>
    </div>

    <!-- ── 详情抽屉（放在 v-if/v-else 链之外，否则会打断配对）── -->
    <a-drawer
      v-model:open="detailOpen"
      :width="560"
      placement="right"
      :closable="true"
      class="asset-detail"
    >
      <template #title>
        <span class="tk-mono detail-title">{{ detailHost }}</span>
      </template>

      <a-spin :spinning="detailLoading">
        <template v-if="detail">
          <!-- 基本信息（原本叫「信号与证据」，但那个强度条含义不明已删） -->
          <section class="d-section">
            <h4 class="d-head">基本信息</h4>
            <div class="signal-row">
              <a-tag
                v-if="primaryStatus != null"
                :color="statusClass(primaryStatus) === 'ok' ? 'green' : 'orange'"
              >HTTP {{ primaryStatus }}</a-tag>
              <span v-else class="tk-muted">未探活</span>
              <a-tag v-if="detail.domain.is_cdn" color="cyan">CDN</a-tag>
              <a-tag v-if="detail.domain.is_wildcard" color="purple">泛解析</a-tag>
              <span class="tk-muted">{{ summaryText }}</span>
            </div>
            <div v-if="detail.domain.source" class="source-line">
              <span class="tk-muted">来源</span>
              <a-tag v-for="s in allSources" :key="s" color="blue" class="src-tag">{{ s }}</a-tag>
            </div>
            <div v-if="detail.domain.ips" class="ips-line">
              <span class="tk-muted">IP</span>
              <span class="tk-mono">{{ detail.domain.ips }}</span>
            </div>
          </section>

          <!-- 技术栈 -->
          <section v-if="detail.technologies.length" class="d-section">
            <h4 class="d-head">技术栈 ({{ detail.counts.technologies }})</h4>
            <a-space wrap>
              <a-tag v-for="t in detail.technologies" :key="t.name" color="geekblue">
                {{ t.name }}<template v-if="t.version"> {{ t.version }}</template>
              </a-tag>
            </a-space>
          </section>

          <!-- 探测 -->
          <section v-if="detail.endpoints.length" class="d-section">
            <h4 class="d-head">探测 ({{ detail.counts.endpoints }})</h4>
            <a-descriptions :column="1" size="small" bordered>
              <a-descriptions-item v-if="baseUrl" label="基础 URL">
                <a :href="baseUrl" target="_blank" rel="noreferrer" class="tk-mono">
                  {{ baseUrl }}
                </a>
              </a-descriptions-item>
              <a-descriptions-item v-if="primaryEndpoint?.title" label="标题">
                {{ primaryEndpoint.title }}
              </a-descriptions-item>
              <a-descriptions-item v-if="primaryEndpoint?.server" label="Server">
                <span class="tk-mono">{{ primaryEndpoint.server }}</span>
              </a-descriptions-item>
              <a-descriptions-item v-if="primaryEndpoint?.content_length" label="长度">
                {{ primaryEndpoint.content_length }}
              </a-descriptions-item>
              <a-descriptions-item label="首见">
                {{ shortTime(detail.domain.first_seen) }}
              </a-descriptions-item>
            </a-descriptions>
          </section>

          <!-- 路径 -->
          <section v-if="allPaths.length" class="d-section">
            <h4 class="d-head">URL / 目录与路径 ({{ allPaths.length }})</h4>
            <a-table
              :columns="pathColumns"
              :data-source="allPaths"
              row-key="url"
              size="small"
              :pagination="{ pageSize: 10, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'url'">
                  <a :href="record.url" target="_blank" rel="noreferrer" class="tk-mono path-url">
                    {{ record.url }}
                  </a>
                  <div v-if="record.parent_url" class="tk-muted parent">来自 {{ record.parent_url }}</div>
                </template>
                <template v-else-if="column.key === 'status'">
                  <span v-if="record.status != null" class="status-pill" :class="statusClass(record.status)">
                    {{ record.status }}
                  </span>
                  <!-- 写「未探活」而不是「—」。
                       「—」读起来像"这个字段坏了"，而真实原因是：这条路径是
                       dir_brute / url_extract **发现**出来的，从来没人去请求过
                       它，所以根本没有状态码可显示。实测 mail.sinosoft.com.cn
                       的 244 条路径里 243 条都是这种情况。 -->
                  <span v-else class="tk-muted">未探活</span>
                </template>
                <template v-else-if="column.key === 'title'">
                  <span v-if="record.title" :title="record.title">{{ record.title }}</span>
                  <span v-else class="tk-muted">{{ record.status != null ? '—' : '未探活' }}</span>
                </template>
              </template>
            </a-table>
          </section>

          <!-- 发现 -->
          <section v-if="detail.findings.length" class="d-section">
            <h4 class="d-head">发现 ({{ detail.counts.findings }})</h4>
            <div v-for="(f, i) in detail.findings" :key="i" class="finding-item">
              <a-tag :color="severityColor(f.severity)" class="risk-tag">
                {{ severityLabel(f.severity) }}
              </a-tag>
              <div class="finding-body">
                <div class="finding-kind">{{ f.kind }}</div>
                <div v-if="f.detail" class="tk-muted finding-detail">{{ f.detail }}</div>
              </div>
            </div>
          </section>

          <!-- 溯源 -->
          <section v-if="detail.scans.length" class="d-section">
            <h4 class="d-head">来源扫描</h4>
            <a-space wrap>
              <a-tag
                v-for="s in detail.scans"
                :key="s.id"
                color="default"
                class="src-tag"
                @click="gotoScan({ scan_id: s.id })"
              >#{{ s.id }} {{ s.preset }} · {{ (s.targets || []).join(', ') }}</a-tag>
            </a-space>
          </section>
        </template>

        <div v-else-if="!detailLoading" class="tk-empty">没有这个资产的详情</div>
      </a-spin>
    </a-drawer>
  </div>
</template>

<script setup>
import { SearchOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import dayjs from 'dayjs'

import { listGroups, getHostDetail, searchAssetsFlat } from '@/api'

const router = useRouter()

const keyword = ref('')
//: 默认看**域名 + IP**。
//:
//: 原来默认只给域名，理由是「资产清单的主视角是有哪些站，URL / 端口 / 技术栈 /
//: 发现都是附属信息」（见 git 历史）。这个前提仍然成立，但当时把**端口**也
//: 一并藏起来是错的 —— 端口挂在 IP 上、域名与 IP 是 N 对 N，藏在另一个类型里
//: 就得自己拼才看得到「这台机器开着 3306 / 6379」。现在端口折进行里
//: （``_FLAT_PORTS_EXPR``），这个理由不成立了。
//: IP 保留单列：它常常不是任何域名的解析结果（裸扫出来的），藏起来会漏资产。
const type = ref('domains,ips')
const aliveFilter = ref('')
const statusFilter = ref(null)
//: 时间段（按**首见时间**筛）。``null`` = 全部时间。
//: 两个元素是 dayjs 对象；发给后端时转成 ISO 串（``since`` / ``until``）。
const dateRange = ref(null)
//: 常用档位。``dayjs`` 是 ant-design-vue 带进来的传递依赖（1.11.x）。
const rangePresets = [
  { label: '今天', value: [dayjs().startOf('day'), dayjs().endOf('day')] },
  { label: '近 7 天', value: [dayjs().subtract(6, 'day').startOf('day'), dayjs().endOf('day')] },
  { label: '近 30 天', value: [dayjs().subtract(29, 'day').startOf('day'), dayjs().endOf('day')] },
  { label: '近 90 天', value: [dayjs().subtract(89, 'day').startOf('day'), dayjs().endOf('day')] },
]

/** 条件变了就重新查，并回到第 1 页（停在第 5 页会让人以为"搜不到东西"）。 */
function onRangeChange() {
  currentPage.value = 1
  loadPage()
}

function clearRange() {
  dateRange.value = null
  onRangeChange()
}

/** 这一行的「首见」在不在当前时间段里 —— 用来在结果上方显示一行摘要。 */
const rangeLabel = computed(() => {
  const r = dateRange.value
  if (!r || !r[0] || !r[1]) return ''
  return `${r[0].format('YYYY-MM-DD')} ~ ${r[1].format('YYYY-MM-DD')}`
})

//: 2026-10-06 删掉了「仅探活」勾选框。它**从来没被发到后端** —— `liveOnly`
//: 全文件只出现在「绑定到勾选框 / ref 初始化 / resetAll 重置」三处；
//: 而 ``/api/search/flat`` 的 ``live`` 默认是 ``True``。结果是 **74% 的资产
//: （58 / 219）被永久藏起来，而那个看起来能控制它的勾选框点了没反应**。
//: 现在改成在 :func:`loadPage` 里**显式**传 ``live: false``，行为写在代码里
//: 而不是依赖后端默认值。要只看探活过的，旁边的「仅存活」下拉能筛。
const searched = ref(false)
const loading = ref(false)
//: 后端 UNION 后的扁平行（不再是 {类型: 行[]} 的字典）
const results = ref([])
//: 真实总命中数（不受分页截断）
const totalCount = ref(0)
const currentPage = ref(1)
const pageSize = ref(50)

// 分组过滤
const groups = ref([])
const groupsLoading = ref(false)
const groupId = ref(null)

// 详情抽屉
const detailOpen = ref(false)
const detailLoading = ref(false)
const detail = ref(null)
const detailHost = ref('')

const typeOptions = [
  //: 默认这一档。**端口折进行里**（后端 ``_FLAT_PORTS_EXPR``），所以
  //: 「有哪些站、每台开着什么」在一张表里就答完了，不必再切到端口类型
  //: 去看那 378 条 —— 那些里绝大多数是 CDN 节点池上的重复组合。
  //: IP 单列一行是因为它常常不是任何域名的解析结果，藏起来会漏掉裸扫出来的资产。
  { value: 'domains,ips', label: '域名 + IP' },
  { value: 'domains', label: '域名' },
  { value: 'ips', label: 'IP' },
  { value: 'ports', label: '端口' },
  { value: 'urls', label: 'URL' },
  { value: 'technologies', label: '技术栈' },
  { value: 'findings', label: '发现' },
]

const statusOptions = [200, 301, 302, 401, 403, 404, 500, 502, 503]
const samples = ['qq.com', 'nginx', 'admin', '403', 'cdn']

const currentGroupName = computed(
  () => groups.value.find((g) => g.id === groupId.value)?.name || '未知分组',
)

// 分组下拉要能选，所以进页面就把分组列表拉一次（只有名字和 id，很轻）
//
// ⚠️ 这里**不**顺手把资产表也拉出来。改成"打开就列全部"时加过一句
// ``await loadPage()``，结果是请求发出、服务端 200，但前端 Promise 不 settle、
// 按钮卡在 loading，且页面被反复重建。根因没定位到（源码结构核对过是对的），
// 所以先撤回这一句：默认类型 + 端口折进行这两处是验证过的，
// 「打开即出结果」等定位到那个不 settle 的点再加。
onMounted(async () => {
  groupsLoading.value = true
  try {
    groups.value = await listGroups()
  } catch {
    // 分组接口挂掉不该让整个页面不可用 —— 搜索本身不依赖它
    groups.value = []
  } finally {
    groupsLoading.value = false
  }
})

const columns = [
  { title: '资产', key: 'asset' },
  { title: '存活', key: 'alive', width: 60 },
  { title: '端口', key: 'ports', width: 150 },
  { title: '路径', key: 'paths', width: 70, sorter: (a, b) => (a.path_count || 0) - (b.path_count || 0) },
  { title: '标题 · 状态', key: 'title' },
  { title: '风险', key: 'risk', width: 80 },
  { title: '首见', key: 'first_seen', width: 110 },
]

/** 后端已 UNION 好并排好序，这里只做展示层的字段整形 + 存活过滤。
 *
 *  **不再合并多类型结果** —— 那是旧数据流（每类各取 N 条）的做法，页与页
 *  之间顺序不连续。现在分页在数据库里切（``search_flat``），前端拿到的
 *  就是全局第 N 页。 */
const rows = computed(() =>
  results.value
    .filter((r) => {
      if (aliveFilter.value === 'alive' && r.status == null) return false
      if (aliveFilter.value === 'dead' && r.status != null) return false
      return true
    })
    .map((r, i) => ({
      ...r,
      _type: r.asset_type,
      rowKey: `${r.asset_type}-${r.asset_key}-${i}`,
      // findings 的 extra 列装的是 severity（见后端 _FLAT_SPECS 注释）
      severity: r.asset_type === 'findings' ? r.extra : null,
    })),
)

const grandTotal = computed(() => totalCount.value)

/** 当前页各类型的条数（仅供表头一眼看分布，不是全量统计）。 */
const pageBreakdown = computed(() => {
  const out = {}
  for (const r of results.value) {
    const k = r.asset_type
    out[k] = (out[k] || 0) + 1
  }
  return out
})

const displayQuery = computed(() => {
  const parts = []
  if (groupId.value) parts.push(`分组:${currentGroupName.value}`)
  parts.push(keyword.value.trim() || '全部')
  return parts.filter(Boolean).join(' · ')
})

const keywordPlaceholder = '输入域名、IP、URL、标题、技术名（至少 2 个字符）'

function resetAll() {
  keyword.value = ''
  type.value = 'domains,ips'
  dateRange.value = null
  aliveFilter.value = ''
  statusFilter.value = null
  groupId.value = null
  searched.value = false
  results.value = []
  totalCount.value = 0
  currentPage.value = 1
}

/** 这一行的开放端口。后端给的是去重后的 ``端口/协议`` 逗号串（见
 *  ``_FLAT_PORTS_EXPR``），这里拆成数组；空 / 缺失一律当空数组。 */
function portListOf(r) {
  if (!r || !r.ports) return []
  return String(r.ports).split(',').map((s) => s.trim()).filter(Boolean)
}

/** 资产名。技术栈与发现的 asset_key 后端已拼上 host/kind 前缀保证唯一，
 *  这里拆回来只显示主体，前缀由 subtitleOf 补。 */
function primaryOf(r) {
  switch (r._type) {
    case 'domains': return r.asset_key
    case 'ips': return r.asset_key
    case 'ports': return r.asset_key
    case 'urls': return r.asset_key
    case 'technologies': return (r.asset_key || '').split(' · ').pop() || r.name
    case 'findings': return (r.asset_key || '').split(' @ ').pop() || r.target
    default: return r.asset_key || ''
  }
}

/** 资产名下面那行小字：优先显示"这是什么资产的什么身份"。 */
function subtitleOf(r) {
  switch (r._type) {
    case 'ips': return r.extra ? r.extra : 'IP'
    case 'ports': return r.host ? r.host : '端口'
    case 'technologies': return r.host || '技术栈'
    case 'findings': return r.kind || '发现'
    case 'urls': return r.source || 'URL'
    default: return ''
  }
}

const assetLabel = (key) => typeOptions.find((t) => t.value === key)?.label || key

function statusClass(status) {
  if (status == null) return ''
  if (status >= 200 && status < 300) return 'ok'
  if (status >= 300 && status < 400) return 'redir'
  if (status === 401 || status === 403) return 'auth'
  if (status >= 400) return 'err'
  return ''
}

const SEVERITY_LABELS = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
const severityLabel = (s) => SEVERITY_LABELS[s] || s || '—'
function severityColor(s) {
  return { critical: 'red', high: 'orange', medium: 'gold', low: 'blue', info: 'default' }[s] || 'default'
}

/** ISO 时间 → "09-08 19:43"（面板空间小，年份不重要） */
function shortTime(iso) {
  if (!iso) return '—'
  return String(iso).slice(5, 16).replace('T', ' ')
}

// ── 详情面板的派生数据 ──────────────────────────────────────────────
/** 主端点：优先取 2xx 的（真正"活"的那条），否则第一条。 */
const primaryEndpoint = computed(() => {
  const eps = detail.value?.endpoints || []
  return eps.find((e) => e.status >= 200 && e.status < 300) || eps[0] || null
})
const primaryStatus = computed(() => primaryEndpoint.value?.status ?? null)

/** 基础 URL = scheme://host，去掉路径。
 *
 *  这一栏原来叫「示例 URL」，取的是 primaryEndpoint.url —— 那是"响应最好的
 *  那条端点"，路径可能是一条很深的后台页（实测出现过 /admin/login 这类），
 *  放在「探测」里当入口很奇怪：这个站点**本身**的地址应该是根。
 *  截到 authority 就对了，具体路径在下面的「URL / 目录与路径」表里。 */
const baseUrl = computed(() => {
  const raw = primaryEndpoint.value?.url || detail.value?.domain?.name || ''
  if (!raw) return ''
  if (!/^https?:\/\//i.test(raw)) return `http://${raw}`
  try {
    return new URL(raw).origin
  } catch {
    return raw.split('/').slice(0, 3).join('/')
  }
})

/** 已探活的端点 + 已知存在的 URL 合成一张"路径"表。 */
const allPaths = computed(() => {
  const d = detail.value
  if (!d) return []
  const seen = new Set()
  const out = []
  for (const e of d.endpoints) {
    if (seen.has(e.url)) continue
    seen.add(e.url)
    out.push({ url: e.url, status: e.status, title: e.title, source: 'http_probe' })
  }
  for (const u of d.urls) {
    if (seen.has(u.url)) continue
    seen.add(u.url)
    // title / server 也要带：后端 host_detail 现在会从 http_endpoint 关联出
    // 标题（探活过的路径有，没探过的仍是空 —— 那是真实情况，不是 bug）。
    out.push({
      url: u.url, status: u.status, title: u.title,
      parent_url: u.parent_url, source: u.source,
    })
  }
  return out
})

/** 摘要文字：告诉用户"我掌握了这个资产的哪些信息"，而不是给个神秘分数。
 *  （原来的信号强度条已删 —— 它把 CDN、指纹这些中性事实折算成"危险度"，
 *    没有评分模型支撑，容易被读成"CDN 站点更值得打"，属于误导。） */
const summaryText = computed(() => {
  const d = detail.value
  if (!d) return ''
  const bits = []
  bits.push(`端点 ${d.counts.endpoints}`)
  bits.push(`路径 ${d.counts.urls}`)
  if (d.counts.technologies) bits.push(`技术 ${d.counts.technologies}`)
  if (d.counts.findings) bits.push(`发现 ${d.counts.findings}`)
  return bits.join(' · ')
})

const allSources = computed(() => {
  const d = detail.value
  const set = new Set()
  if (d?.domain?.source) set.add(d.domain.source)
  for (const u of d?.urls || []) if (u.source) set.add(u.source)
  return [...set]
})

const pathColumns = [
  { title: '路径', key: 'url' },
  { title: '状态', key: 'status', width: 70 },
  { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true },
]

/** 点一行开详情。只有域名有详情接口 —— IP/URL 行的 host 也能查。 */
function onRowClick(record) {
  return {
    onClick: () => openDetail(record),
    style: { cursor: 'pointer' },
  }
}

async function openDetail(record) {
  const host = detailHostOf(record)
  if (!host) return
  detailHost.value = host
  detailOpen.value = true
  detailLoading.value = true
  detail.value = null
  try {
    detail.value = await getHostDetail(host)
  } catch (e) {
    message.error(e.message)
    detailOpen.value = false
  } finally {
    detailLoading.value = false
  }
}

/** 从各种资产行推出"能查详情的域名"。后端 host 列已经是归一后的纯域名
 *  （findings 的 URL 型 target 也被 CASE 拆过了），直接用。 */
function detailHostOf(record) {
  switch (record._type) {
    case 'domains': return record.asset_key
    case 'urls': return record.host || safeHostFromUrl(record.asset_key)
    case 'technologies': return record.host
    case 'findings': return record.host
    case 'ips': return record.host
    case 'ports': return record.host
    default: return null
  }
}

function safeHostFromUrl(url) {
  try {
    return new URL(url).hostname
  } catch {
    return null
  }
}

function gotoScan(record) {
  router.push({ path: '/taskList/taskDetail', query: { id: record.scan_id } })
}

function quickSearch(value) {
  keyword.value = value
  doSearch()
}

async function doSearch() {
  // 全空**不再拦**：后端 ``/api/search/flat`` 已经放开空词（只拦 1 个字符
  // 那种没意义的搜索），所以「打开就列出全部」和「点搜索」是同一个结果。
  // 之前那句"全空搜出来的就是全库，没有意义"已经不成立 —— 全库就是这页
  // 要展示的东西。
  // 改了查询条件就回到第 1 页（继续停在第 5 页会让人以为"搜不到东西"）
  currentPage.value = 1
  await loadPage()
}

/** 拉取某一页。翻页与改条件走同一条路径 —— 参数完全一样。 */
async function loadPage() {
  loading.value = true
  try {
    // 状态码筛选走 filters 传给后端（search_flat 只认这一种结构化条件）。
    // 原来这里是 `[...filters.value]` 再 push —— 那个 filters 由「条件构建行」
    // 产生，该行已按要求删掉，现在只有状态码这一条来源。
    const cond = []
    if (statusFilter.value != null) {
      cond.push({ field: 'status', op: 'eq', value: statusFilter.value })
    }
    const r = dateRange.value
    const data = await searchAssetsFlat(keyword.value.trim(), {
      type: type.value,
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value,
      filters: cond,
      groupId: groupId.value,
      // 时间段闭区间。**必须带时区**：库里的 first_seen 是 ISO 带偏移的串，
      // 不带时区会按服务器本地时区解释，跨时区部署时边界会差几个小时。
      since: r && r[0] ? r[0].startOf('day').toISOString() : null,
      until: r && r[1] ? r[1].endOf('day').toISOString() : null,
      // 显式带上 live=false，不靠后端默认值。见上面 liveOnly 那段说明。
      live: false,
    })
    results.value = data.rows || []
    totalCount.value = data.total || 0
    searched.value = true
  } catch (e) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

function onPageChange(page, size) {
  currentPage.value = page
  if (size !== pageSize.value) pageSize.value = size
  loadPage()
}
</script>

<style scoped>
.filter-row {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
}
.search-bar :deep(.ant-input-affix-wrapper) {
  width: 100%;
}
.chip-row {
  display: flex;
  gap: 6px;
  align-items: center;
  flex-wrap: wrap;
  margin-top: 10px;
}
.chip-label {
  font-size: 12px;
  color: var(--tk-muted);
  font-weight: 500;
}
.grow { flex: 1; }
.result-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.count-split { font-size: 12px; }
.pager {
  display: flex;
  justify-content: flex-end;
  margin-top: 14px;
}
.accent-text {
  color: var(--tk-accent);
  font-size: 16px;
}
.type-label {
  font-size: 11px;
  color: var(--tk-muted);
  margin-top: 1px;
}
/* 详情抽屉路径表的状态码。与资产表的 .code-chip 同源（同样避开伪粗体），
   只是这里给到 36px 最小宽度，让窄列里的 200/301/404 也齐平。 */
.status-pill {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 36px;
  height: 19px;
  padding: 0 5px 0 6px;
  border-radius: 3px;
  font-size: 11px;
  line-height: 1;
  font-weight: 500;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
    'PingFang SC', 'Microsoft YaHei', sans-serif;
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
  border: 1px solid;
}
.status-pill.ok {
  color: #1a7f37; border-color: rgba(31, 136, 61, 0.28);
  background: rgba(31, 136, 61, 0.09);
}
.status-pill.redir {
  color: #0a58ca; border-color: rgba(9, 88, 202, 0.26);
  background: rgba(9, 88, 202, 0.08);
}
.status-pill.auth {
  color: #ad4e00; border-color: rgba(202, 106, 8, 0.3);
  background: rgba(236, 137, 24, 0.12);
}
.status-pill.err {
  color: #b42318; border-color: rgba(180, 35, 24, 0.26);
  background: rgba(180, 35, 24, 0.08);
}

/* 资产表里的状态码：细边框 + 极淡底色，不跟标题抢视觉。
   等宽字体让 200/301/404 这类数字对齐，一列下来更好扫。 */
/* 状态码紧跟标题（不加 margin-left:auto —— 那会把它推到列最右，
   标题和它的状态就分家了）。标题过长时收缩让位，状态码始终完整。 */
.title-row {
  display: flex;
  align-items: center;
  gap: 7px;
  min-width: 0;
}
.title-cell {
  flex: 0 1 auto;
  min-width: 0;
  font-size: 12.5px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
/* 状态码徽标。
   - **不用等宽字体**。``font-weight: 600`` + 等宽字形 = 浏览器伪粗体
     （描边模拟加粗），11px 下会糊出锯齿。改用系统 UI 字体，字重 500
     （UI 字体有这档，不会被合成）。
   - ``tabular-nums`` 仍然要：它让 200/301/404 的数字宽度一致，一列
     下来能对齐，而字形本身是正常的无衬线体，不会有渲染问题。
   - 左内边距略大于右，配合 3px 圆角，视觉重心居中。 */
.code-chip {
  flex: 0 0 auto;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 34px;
  height: 19px;
  padding: 0 5px 0 6px;
  border-radius: 3px;
  font-size: 11px;
  line-height: 1;
  font-weight: 500;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
    'PingFang SC', 'Microsoft YaHei', sans-serif;
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
  border: 1px solid;
  user-select: none;
}
.code-chip.ok {
  color: #1a7f37;
  border-color: rgba(31, 136, 61, 0.28);
  background: rgba(31, 136, 61, 0.09);
}
.code-chip.redir {
  color: #0a58ca;
  border-color: rgba(9, 88, 202, 0.26);
  background: rgba(9, 88, 202, 0.08);
}
.code-chip.auth {
  color: #ad4e00;
  border-color: rgba(202, 106, 8, 0.3);
  background: rgba(236, 137, 24, 0.12);
}
.code-chip.err {
  color: #b42318;
  border-color: rgba(180, 35, 24, 0.26);
  background: rgba(180, 35, 24, 0.08);
}
.src-tag { font-size: 11px; }
/* 路径数：同为等宽 + 600 会触发伪粗体锯齿，改用 UI 字体 + 500 */
.path-count {
  color: var(--tk-accent);
  font-weight: 500;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI',
    'PingFang SC', 'Microsoft YaHei', sans-serif;
  font-variant-numeric: tabular-nums;
  -webkit-font-smoothing: antialiased;
}
/* 端口：个数用强调色（一眼看出"这台开得多"），样本用等宽小字 */
.port-chip {
  display: inline-block;
  min-width: 18px;
  padding: 0 5px;
  margin-right: 6px;
  border-radius: 8px;
  color: #fff;
  background: var(--tk-accent);
  font-size: 11px;
  font-weight: 600;
  line-height: 16px;
  text-align: center;
  font-variant-numeric: tabular-nums;
}
.port-sample {
  color: var(--tk-text-sub);
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 11px;
}
.risk-tag { font-size: 11px; }
.first-seen { font-size: 11px; font-family: var(--tk-mono, monospace); }

/* ── 详情抽屉 ── */
.detail-title { font-size: 15px; font-weight: 600; }
.d-section { margin-bottom: 20px; }
.d-head {
  font-size: 12px;
  font-weight: 600;
  color: var(--tk-muted);
  margin-bottom: 8px;
  text-transform: uppercase;
  letter-spacing: 0.4px;
}
.signal-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
/* 存活列的小圆点 —— 只表达"活着/没活着"，具体状态码在「标题 · 状态」列 */
.alive-dot {
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
  vertical-align: middle;
}
.alive-dot.on { background: #52c41a; }
.alive-dot.off { background: var(--tk-border); }
.source-line, .ips-line {
  display: flex;
  gap: 6px;
  align-items: center;
  flex-wrap: wrap;
  margin-top: 6px;
  font-size: 12px;
}
.path-url {
  font-size: 12px;
  word-break: break-all;
  line-height: 1.5;
}
.parent { font-size: 11px; margin-top: 2px; }
.finding-item {
  display: flex;
  gap: 8px;
  padding: 8px 0;
  border-bottom: 1px solid var(--tk-border);
}
.finding-item:last-child { border-bottom: none; }
.finding-body { flex: 1; min-width: 0; }
.finding-kind { font-size: 12.5px; word-break: break-all; }
.finding-detail {
  font-size: 11.5px;
  margin-top: 2px;
  line-height: 1.5;
  word-break: break-all;
}
.sample { cursor: pointer; user-select: none; }
.sample:hover {
  color: var(--tk-accent);
  border-color: var(--tk-accent);
}
.hint { font-size: 12.5px; line-height: 1.7; }
</style>
