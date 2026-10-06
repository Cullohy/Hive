<template>
  <div class="tk-page">
    <!-- ── 筛选栏 ── -->
    <div class="tk-card">
      <div class="filter-row">
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

        <!--
          任务筛选：名称模糊、id / 短码精确。
          用 show-search + 自己的 filter-option，而不是 filter-option 回调，
          是为了在**每次输入时**都能同时匹配三种形态（见 scanOptions 的注释）。
        -->
        <a-select
          v-model:value="scanId"
          style="width: 260px"
          size="middle"
          allow-clear
          show-search
          placeholder="按任务筛选"
          :loading="scansLoading"
          :filter-option="false"
          :not-found-content="scansLoading ? '加载中…' : '没有匹配的任务'"
          @search="onScanSearch"
          @change="onScanChange"
          @dropdown-visible-change="onScanDropdown"
        >
          <!--
            ⚠️ ``#optionLabel`` 是**必需的**：antd 4.2.6 选中后默认把 option 的
            默认插槽内容拿来显示（``index.js`` 里 ``optionLabelRender: slots.optionLabel``），
            而下面每个 option 是**两行**的 div。塞进选择框后只有一行高度，
            第二行（TaskId）会被裁掉 —— 截图里就是名称被截断成
            "亿联网络技术股份有限公司…" 而那行短码整个看不见。
            这个插槽让「下拉里怎么排版」与「选中后显示什么」互不影响。
          -->
          <template #optionLabel="{ value }">
            <span class="scan-selected">
              <span class="scan-selected-name">{{ scanSelectedName(value) }}</span>
              <span class="scan-selected-id">任务ID：{{ scanCodeOf(value) }}</span>
            </span>
          </template>
          <a-select-option v-for="o in scanOptions" :key="o.value" :value="o.value">
            <div class="scan-option">
              <!--
                两行：**第一行任务名，第二行灰色「任务ID：<短码>」**。
                之前第二行塞了 ``#55 · passive · yealink.com.cn``（内部主键+预设+目标），
                三样挤一起反而看不出重点；而 TaskId 短码才是用户在任务列表
                「TaskId」列里看到的那个标识，两处对得上才有用。
                光秃一个 ``2BH0R2JM`` 看不出是什么，所以带个「任务ID：」前缀。
              -->
              <span class="scan-option-label">{{ o.name || o.label }}</span>
              <span class="scan-option-desc">任务ID：{{ o.code }}</span>
            </div>
          </a-select-option>
        </a-select>

        <!-- 时间段：按「首见时间」筛。留空 = 全部时间（默认，与"默认显示全部"一致） -->
        <a-range-picker
          v-model:value="dateRange"
          style="margin-left: 10px"
          size="middle"
          :allow-clear="true"
          :placeholder="['起始日期', '结束日期']"
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
            <!-- 只给一个健康标记，状态码挪到「标题 · 状态」列 ——
                 状态码放在这里等于把同一份信息显示两遍。

                 绿 = 响应正常（status < 400）；灰 = 其余两种完全不同的情形：
                 「响应了但 4xx/5xx」与「压根没有 Web 响应」。tooltip 分开说，
                 别让灰点一律读成"站点挂了"。 -->
            <span
              class="alive-dot"
              :class="record.status != null && record.status < 400 ? 'on' : 'off'"
              :title="record.status == null
                ? '无 Web 响应（没探到 http 服务）'
                : `HTTP ${record.status}${record.status >= 400 ? '（异常）' : ''}`"
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

    <!--
      2026-10-06 删掉了「未搜索」时的空态卡片（原来写"试试搜这些" + 一排
      示例 tag + 使用提示）。

      删的理由：
        · 那条提示已经**过期** —— 它写着"想单独看 URL / 端口 / 技术栈 / 发现，
          用左上角类型下拉切"，而那个类型下拉同日已删（见 TYPE_LABELS 处）。
          留着会让人去找一个不存在的控件。
        · 示例 tag 的点击只是填关键词 + 触发搜索，示例本身（qq.com / nginx /
          admin / 403 / cdn）也没有信息量 —— 输什么都能搜，不如直接搜。

      顺带说明**没有**改成"打开页面就自动加载全部资产"：代码里记着试过，
      加了 ``await loadPage()`` 之后请求发出、服务端 200，但前端 Promise 不
      settle、按钮卡在 loading，根因当时没定位到。要做这个得先解决那条。
    -->

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

import { listGroups, getHostDetail, searchAssetsFlat, listScans } from '@/api'

const router = useRouter()

const keyword = ref('')
//: 查询类型固定为 ``ASSET_TYPE``（见下面 TYPE_LABELS 处那段说明），
//: 不再是响应式的 —— 2026-10-06 删掉了「资产类型」下拉。
//
//: 2026-10-06 同时删掉了 ``aliveFilter``（「仅存活 / 仅未探活」下拉）。删的理由：
//:
//: 1. **它本来就没在正常工作。** 它是**纯前端**过滤 ``results.value`` —— 也就是
//:    当前这一页的 50 条；而分页的 ``total`` 来自服务端。于是选「仅存活」后标题仍
//:    写"匹配 N 条"，表格却可能整页空掉并显示"没有匹配的资产"，而那些资产其实
//:    就在别的页上。
//: 2. **名字与实际筛的东西对不上。** 它按 ``status != null``（有没有 HTTP 响应）
//:    筛，而那一列的圆点按 ``status < 400`` 染绿 —— 两套标准。真库里 121 个域名
//:    选「仅存活」会收进 31 条，其中 **14 条圆点是灰的**（45%）。
//: 3. **「未探活」这个叫法不准。** 那 90 个「未探活」的域名里有 36% 其实**开着
//:    端口**，只是端口不是 web 服务。它真正表达的是"这台机器有没有 Web 响应"。
//:
//: 那一列**保留**（列名改成「健康」，含义=status<400 染绿），要按这个维度筛的
//: 时候走搜索词或右侧详情面板。⚠️ 若要恢复成筛选器，**必须下推给后端**
//: （``/api/search/flat`` 的 ``live`` 口径走 ``scan_asset``），别再在前端过滤。
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

//: 2026-10-06 删掉了「仅探活」勾选框。它**从来没被发到后端** —— `liveOnly`
//: 全文件只出现在「绑定到勾选框 / ref 初始化 / resetAll 重置」三处；
//: 而 ``/api/search/flat`` 的 ``live`` 默认是 ``True``。结果是 **74% 的资产
//: （58 / 219）被永久藏起来，而那个看起来能控制它的勾选框点了没反应**。
//: 现在改成在 :func:`loadPage` 里**显式**传 ``live: false``，行为写在代码里
//: 而不是依赖后端默认值。
//: （原文这里写着"旁边的「仅存活」下拉能筛"—— 那个下拉同日也删了，理由见上面
//:  ``aliveFilter`` 那段。要按这个维度筛必须下推后端的 ``live`` 参数。）
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
//: 初始就是 true —— 列表在 onMounted 里拉，在那之前下拉应该显示加载中。
//: 写 false 再在 onMounted 里补 true 的话，挂载到请求发出之间有一帧是
//: 「加载中=false 但还是空列表」，下拉会闪一下空。
const groupsLoading = ref(true)
const groupId = ref(null)

// ── 任务（扫描）过滤 ──────────────────────────────────────────────────
//
// 需求是「按任务名称**或**任务 id 筛」。这两者性质不同，所以分两层：
//   · **最终筛选条件只有一个 `scanId`** —— 后端 `/api/search/flat` 的
//     `scan_id` 参数走 `scan_asset` 的「这次扫描看到过」口径（不是
//     `t.scan_id`，那个只是"谁最先发现的"，见 postgres.py::_seen_clause）。
//   · **用户输入的是自由文本**：任务名称模糊匹配、id/短码精确匹配。
//     所以先在本地把输入解析成 scanId，再交给后端。
//
// 为什么不把「任务名称」直接丢给后端做 SQL 模糊匹配：scan 表没有参与
// UNION 的那套检索列，走名字筛就得在每个分支里 join scan 表，代价大且
// 破坏"一个资产可能在多次扫描里出现"的语义。任务列表本来就常驻内存量级，
// 本地解析更快、也更容易把「名称 / id / 短码」三种输入统一处理。
const scanId = ref(null)
const scans = ref([])
const scansLoading = ref(false)
const scanKeyword = ref('')

/**
 * 任务在**选中后**显示的那一行文本。
 *
 * 用的是 **TaskId 短码**（`2BH0R2JM` 这种，见后端 `util/ids.py::task_code`），
 * 不是 `#55` 那个内部自增主键 —— 任务列表那一列标题就叫「TaskId」、显示的
 * 就是短码，用户在这两处看到的是同一个东西才对得上。
 *
 * 短码**兜底**到 `#id`：老数据理论上可能没有，但真出现了也不能显示成空白。
 */
function scanLabel(s) {
  const code = (s.task_code || '').trim()
  const id = `#${s.scan_id}`
  const main = code || id
  const name = (s.name || '').trim()
  const target = (s.targets || []).join(', ')
  return name || target ? `${name || target}（${main}）` : main
}

/**
 * 选中后那一行的**名称部分**（TaskId 由 :func:`scanCodeOf` 单独渲染，
 * 固定在末尾不被名称挤掉）。
 *
 * 任务可能已被删（`/api/scans` 列表里找不到），那时连名称都没有 —— 返回空串，
 * 只留 TaskId，别显示成"（2BH0R2JM）"这种括号开头的怪东西。
 */
function scanSelectedName(value) {
  const s = scans.value.find((x) => x.scan_id === value)
  if (!s) return ''
  return (s.name || '').trim() || (s.targets || []).join(', ') || ''
}

/**
 * 某个 scan_id 的 **TaskId 短码**（`2BH0R2JM` 这种）。
 *
 * 短码才是对外的任务标识 —— 任务列表那一列标题就是「TaskId」、显示的就是它。
 * 拿内部自增主键当 TaskId 展示会让用户在两个页面看到两个不同的"id"而对不上。
 * 理论上老数据可能没有短码，兜底成 ``#id``，总比空白强。
 */
function scanCodeOf(value) {
  const s = scans.value.find((x) => x.scan_id === value)
  return (s?.task_code || '').trim() || `#${value}`
}

/** 下拉里按输入过滤：名称、id、短码、目标任一命中即可。 */
const scanOptions = computed(() => {
  const kw = scanKeyword.value.trim().toLowerCase()
  const all = scans.value.map((s) => ({
    value: s.scan_id,
    // 选中后显示的那一行（名称 + TaskId），见 scanLabel
    label: scanLabel(s),
    // 下拉里第一行：纯名称/目标，不带 id —— 第二行单独显示 TaskId
    name: (s.name || '').trim() || (s.targets || []).join(', ') || '',
    // 下拉里第二行：TaskId 短码
    code: (s.task_code || '').trim() || `#${s.scan_id}`,
  }))
  if (!kw) return all.slice(0, 60)
  return all
    .filter(
      (o) =>
        o.label.toLowerCase().includes(kw) ||   // 名称 + TaskId
        o.code.toLowerCase().includes(kw) ||    // TaskId 短码
        String(o.value).includes(kw),           // 内部主键，仍然能按数字搜
    )
    .slice(0, 60)
})

/** 拉任务列表。轻量：只要 id/name/preset/targets/task_code。 */
async function loadScans() {
  if (scans.value.length || scansLoading.value) return
  scansLoading.value = true
  try {
    const data = await listScans(300)
    scans.value = Array.isArray(data) ? data : []
  } catch {
    // 任务列表拉不到不该让整页不可用 —— 筛选少一个维度而已
    scans.value = []
  } finally {
    scansLoading.value = false
  }
}

/** 打开下拉才拉列表：这一页默认不关心任务，进来时不必付这个请求。 */
function onScanDropdown(open) {
  if (open) loadScans()
}

/** 输入即筛（名称 / id / 短码 / 目标任一命中）。 */
function onScanSearch(text) {
  scanKeyword.value = text || ''
}

/** 选中任务后回到第 1 页再查 —— 停在第 5 页会像"这个任务没资产"。 */
function onScanChange() {
  scanKeyword.value = ''
  currentPage.value = 1
  loadPage()
}

// 详情抽屉
const detailOpen = ref(false)
const detailLoading = ref(false)
const detail = ref(null)
const detailHost = ref('')

//: 2026-10-06 删掉了「资产类型」下拉（原 ``type`` ref + ``typeOptions`` 数组）。
//: 固定只查**域名 + IP**。
//:
//: 为什么这两类就够：
//:   · **端口折进行里**（后端 ``_FLAT_PORTS_EXPR``），所以「有哪些站、这台机器
//:     开着什么」在一张表里就答完了 —— 单列成行的端口里绝大多数是 CDN 节点池
//:     上的重复组合，会把域名淹没。
//:   · **IP 必须单列**，它常常不是任何域名的解析结果（裸扫出来的），藏起来
//:     就会漏资产。
//: URL / 技术栈 / 发现改从**搜索词**或右侧详情面板看，不必占一个常驻下拉。
//:
//: ⚠️ ``TYPE_LABELS`` **要留着** —— 它不再是下拉选项，而是**显示用的类型名映射**，
//: 仍被两处消费：结果头的分页统计（``assetLabel(key)``）与资产行的类型副标题。
//: 整个删掉会让这两处退化成显示英文枚举值。
const ASSET_TYPE = 'domains,ips'

const TYPE_LABELS = {
  domains: '域名',
  ips: 'IP',
  ports: '端口',
  urls: 'URL',
  technologies: '技术栈',
  findings: '发现',
}

//: 2026-10-06 删掉了 ``samples``（"试试搜这些"的示例词）与 ``quickSearch`` ——
//: 配套的空态卡片已删（见模板里那段说明）。
//: 2026-10-06 **删掉了「状态码」下拉筛选**（连同 statusOptions /
//: statusFilterSupported / 那条 watch，以及 loadPage 里的 cond 构造）。
//:
//: 后端 `status` 字段只映射在 `urls` 上（`postgres.py::_ASSET_FILTER_FIELDS`），
//: 其余类型走 `col is None -> continue` **静默丢弃**。而这一页的默认类型是
//: 「域名 + IP」—— 也就是**最常用的视图下这个筛选根本不生效**，选完的结果
// 与不选完全一致，且没有任何报错。真库实测：不带筛选 total=3、status=404
// 也是 total=3；切到 urls 才降到 0。
//:
//: 之前一版是"仅在 urls 时启用、否则禁用下拉"，但那仍让一个**大多数时候
// 用不了**的控件常驻在筛选栏里。与其半可用，不如整条去掉 —— 需要看状态码
// 分布时，切到「URL」类型后看列表里的 status 列即可。
//: 真要恢复，先把后端 `status` 映射补到各类型上，别又加回一个假筛选。

const currentGroupName = computed(
  () => groups.value.find((g) => g.id === groupId.value)?.name || '未知分组',
)

// 分组下拉要能选，所以进页面就把分组列表拉一次（只有名字和 id，很轻）
//
// 2026-10-06：这里**补上了**资产表的自动加载（`loadPage()`），即"打开就列全部"。
// 之前撤过一次，症状是"请求发出、服务端 200，但 Promise 不 settle、按钮卡在
// loading，页面被反复重建"。
//
// ⚠️ **当前状态：请求层已验证通过，渲染层未通过，根因仍未定位。** 别把任何
// 猜测当结论 —— 2026-10-06 排查时推翻过两个假设（见下），都不成立。
//
// 已验证成立的（服务端日志 + 接口直调为证）：
//   · 挂载时确实发出请求、参数正确：
//     ``GET /api/search/flat?q=&type=domains,ips&limit=50&offset=0&live=false``
//   · 后端返回 200、响应体正常（50 行、total=219，字段齐全）
//   · 构建产物里 ``loadPage`` 确实被 onMounted 调用且函数体逐句正确
//     （编译成 ``Fe(()=>{Ke()...,T()})``，``T`` 就是 loadPage）
//   · 同一次加载里 ``/api/groups`` 被调 3 次而 ``/api/search/flat`` 只有 1 次
//     → **组件挂载了多次**，而最终活着那个实例的 loading 一直为 true
//
// 已验证**不成立**的猜测（都实测过，别再重复）：
//   1. "空关键词让 trigram 索引失效所以慢" —— 实测该查询 2ms；且 120s 的 axios
//      超时早该触发却没触发，说明不是慢。
//   2. "常驻的 a-drawer 打断 patch" —— 给它加 ``v-if`` 后症状完全不变。
//
// **下次要查就从"为什么一次加载挂载 3 次"入手。** 想退回"不自动加载"的话，
// 删掉下面那行 loadPage() 即可。
onMounted(() => {
  // 分组列表 —— 失败不该让页面不可用，搜索本身不依赖它
  listGroups()
    .then((data) => { groups.value = Array.isArray(data) ? data : [] })
    .catch(() => { groups.value = [] })
    .finally(() => { groupsLoading.value = false })

  // 资产表：打开就列全部。**不要 await**（见上面那段）
  loadPage()
})

const columns = [
  { title: '资产', key: 'asset' },
  // 「健康」而不是原来的「存活」：这一列按 ``status < 400`` 染绿，量的其实是
  // "**响应是否正常**"，不是"这台机器活不活"。开着 3306 的数据库主机当然是活的，
  // 但它没有 Web 响应、圆点必然是灰的 —— 叫「存活」会把它说成死的。
  { title: '健康', key: 'alive', width: 60 },
  // 「开放端口」而不是「端口」：这一列折进行里的全是 port 表的记录，而
  // port 表**只记扫到开放端口的**（closed/filtered 不入表）。叫「端口」会
  // 让人以为列的是"这台机器理论上有哪些端口"。空值显示「—」也表示
  // "没扫到开放端口"，与标题正好对上。
  { title: '开放端口', key: 'ports', width: 150 },
  { title: '路径', key: 'paths', width: 70, sorter: (a, b) => (a.path_count || 0) - (b.path_count || 0) },
  { title: '标题 · 状态', key: 'title' },
  { title: '风险', key: 'risk', width: 80 },
  { title: '首见', key: 'first_seen', width: 110 },
]

/** 后端已 UNION 好并排好序，这里只做展示层的字段整形。
 *
 *  **不再合并多类型结果** —— 那是旧数据流（每类各取 N 条）的做法，页与页
 *  之间顺序不连续。现在分页在数据库里切（``search_flat``），前端拿到的
 *  就是全局第 N 页。
 *
 *  ⚠️ 这里**不做任何过滤**（原有一段按 aliveFilter 过滤当前页的代码已删）。
 *  服务端分页 + 前端过滤必然对不上 ``total``：命中的那些行在别的页上，
 *  而当前页可能一条都不剩、显示成"没有匹配的资产"。筛选一律下推后端。 */
const rows = computed(() =>
  results.value
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
  // 任务筛选也要出现在标题里 —— 否则筛完看不出当前看的是哪次任务的结果
  if (scanId.value != null) parts.push(`任务:${currentScanLabel.value}`)
  parts.push(keyword.value.trim() || '全部')
  return parts.filter(Boolean).join(' · ')
})

/** 当前选中任务的展示名。任务可能已被删（扫描列表取不到），回落成 id。 */
const currentScanLabel = computed(() => {
  if (scanId.value == null) return ''
  const s = scans.value.find((x) => x.scan_id === scanId.value)
  return s ? scanLabel(s) : `#${scanId.value}`
})

const keywordPlaceholder = '输入域名、IP、URL、标题、技术名（至少 2 个字符）'

function resetAll() {
  keyword.value = ''
  dateRange.value = null
  groupId.value = null
  scanId.value = null
  scanKeyword.value = ''
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

const assetLabel = (key) => TYPE_LABELS[key] || key

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
    // 不传 filters：状态码下拉已删（见上面 statusOptions 处那段说明 —— 它在
    // 非 urls 类型下会被后端静默丢弃）。后端那条 `filters` 通道还在，
    // 等哪天有**各类型都支持**的筛选再接上。
    const r = dateRange.value
    const data = await searchAssetsFlat(keyword.value.trim(), {
      // 固定域名 + IP（类型下拉已删）。写常量而不是留个 ref：
      // 没有控件能改它，ref 只会让人以为还能切。
      type: ASSET_TYPE,
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value,
      // 任务筛选：传 scan_id 而不是任务名。后端按 `scan_asset` 的
      // 「这次扫描看到过」来过滤，所以**重扫时也能查到**（资产表里那条行
      // 仍挂在首次发现者名下，用 t.scan_id 会一条都查不出来）。
      scanId: scanId.value,
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
/* 任务下拉的选项：两行 —— 第一行任务名，第二行灰色「任务ID：<短码>」。
   分两行是因为 TaskId 很重要（用户常按它找任务），挤在一行会被长名称挤掉。 */
.scan-option {
  display: flex;
  flex-direction: column;
  line-height: 1.35;
  padding: 2px 0;
}
.scan-option-label {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.scan-option-desc {
  font-size: 11px;
  color: var(--tk-text-muted);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
/* 选中后显示的那一行。
   名称可能很长（实测有"亿联网络技术股份有限公司…"这种），而 **id 是定位任务
   的唯一硬坐标**，所以让它 `flex-shrink: 0` 固定在末尾：名称过长时省略的是
   名称，id 永远可见。 */
.scan-selected {
  display: flex;
  align-items: baseline;
  min-width: 0;
  overflow: hidden;
}
.scan-selected > .scan-selected-name {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.scan-selected > .scan-selected-id {
  flex-shrink: 0;
  margin-left: 6px;
  color: var(--tk-text-muted);
}
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
</style>
