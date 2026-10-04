<template>
  <div class="tk-page">
    <a-spin :spinning="loading">
      <!-- ── 头部 ── -->
      <div class="tk-card detail-head">
        <div class="head-row">
          <a-button class="back-btn" title="返回" @click="goBack">
            <ArrowLeftOutlined />
          </a-button>
          <div class="head-main">
            <h3 class="head-title" :title="`内部 ID #${scan.scan_id ?? id}`">
              <!-- 任务名称是用户填的，当主标题；「扫描 xxx」在有名时退成次要说明 -->
              <span v-if="scan.name" class="head-name">{{ scan.name }}</span>
              <span :class="{ 'tk-muted': !!scan.name }">
                扫描 {{ scan.task_code || scan.scan_id || id }}
              </span>
              <span class="tk-mono targets">{{ (scan.targets || []).join(', ') }}</span>
            </h3>
            <div class="head-meta">
              <a-badge :status="statusBadge(scan.status)" :text="statusText(scan.status)" />
              <!--
                标签跟的是**预设**（用户选了什么），不是后端 flag 推导出来的
                `mode`。后者对 `passive` 也会报 active —— DNS 解析和证书抓取
                确实会向目标发包，报得没错，但摆在这儿会让人以为选错了预设。
                flag 的真相在「源统计」和审计记录里。
              -->
              <a-tag v-if="scan.preset === 'active'" color="orange">主动</a-tag>
              <a-tag v-else-if="scan.preset === 'passive'" color="blue">被动</a-tag>
              <a-tag v-else>{{ scan.preset }}</a-tag>
              <span class="tk-muted">耗时 {{ scan.elapsed ?? 0 }}s</span>
              <span v-if="scan.error" class="err">{{ scan.error }}</span>
            </div>
          </div>
          <div class="head-actions">
            <a-button v-if="scan.status === 'running'" danger @click="onStop">停止</a-button>
            <a-dropdown>
              <a-button>导出 <DownOutlined /></a-button>
              <template #overlay>
                <a-menu @click="onExport">
                  <a-menu-item key="json">JSON（完整结构）</a-menu-item>
                  <a-menu-item key="xlsx">Excel（多工作表）</a-menu-item>
                  <a-menu-item key="csv:domains">CSV · 域名</a-menu-item>
                  <a-menu-item key="csv:urls">CSV · URL</a-menu-item>
                  <a-menu-item key="csv:endpoints">CSV · HTTP 端点</a-menu-item>
                  <a-menu-item key="csv:ports">CSV · 端口</a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
            <a-button @click="loadDiff">变更报告</a-button>
            <a-popconfirm
              title="删除这次扫描及其全部资产？"
              ok-text="删除"
              cancel-text="取消"
              @confirm="onDelete"
            >
              <a-button danger>删除</a-button>
            </a-popconfirm>
          </div>
        </div>

        <div v-if="busy" class="progress-wrap">
          <a-progress :percent="100" :show-info="false" status="active" />
          <div class="tk-muted progress-text">
            新事件 {{ progress.events_new ?? 0 }} · 去重 {{ progress.events_deduped ?? 0 }} ·
            越界丢弃 {{ progress.events_out_of_scope ?? 0 }}
          </div>
          <!-- 各模块自报的在跑进度。"新事件"不动时靠它区分"在跑"和"挂了"：
               慢模块（目录爆破）整个主机跑完前一条事件都不发，两者界面表现
               原本一模一样。有这一行就能一眼看出在打哪个主机、打到第几条。 -->
          <div v-if="busyModules.length" class="tk-muted progress-text module-busy">
            正在处理
            <span v-for="m in busyModules" :key="m.name" class="module-busy-chip">
              {{ m.name }} {{ m.hint }}
            </span>
          </div>
        </div>
      </div>

      <!-- ── 概览卡片 ── -->
      <div class="tk-stat-grid" style="margin-bottom: 16px">
        <div v-for="card in statCards" :key="card.label" class="tk-stat">
          <div class="tk-stat-label">{{ card.label }}</div>
          <div class="tk-stat-value" :class="{ accent: card.accent }">{{ card.value }}</div>
        </div>
      </div>

      <!-- ── 资产标签页 ── -->
      <div class="tk-card">
        <div class="asset-toolbar">
          <InfoCircleOutlined class="tk-muted" />
          <span class="toolbar-label">只显示探活确认过的资产</span>
          <a-tooltip>
            <template #title>
              <div style="max-width: 360px; line-height: 1.7">
                只显示被 <b>HTTP 探活确认过</b>的资产：<br />
                · 域名 —— 它本身或其子域有 HTTP 端点<br />
                · IP —— 它上面有端口给出了 HTTP 响应<br />
                · 端口 —— 这个端口给出了 HTTP 响应<br />
                · URL —— 这个 URL 被探活过<br /><br />
                原始清单里 96% 是「发现了但没探过」的 URL（目录爆破、
                JS 接口提取的产出），混在一起看没有意义，所以这里不展示。
                需要完整清单请用导出。
              </div>
            </template>
            <QuestionCircleOutlined class="tk-muted" style="margin-left: 2px" />
          </a-tooltip>
        </div>

        <a-tabs v-model:activeKey="tab">
          <!--
            影子资产单独一个页签，而且**是最前面那个** —— 它是"漏洞浓度最高的
            角落"，比域名清单更值得先看。

            为什么不并进「域名」页签：域名走 live 过滤（只看探活过的），而
            影子资产绝大多数**没被探活**（它们正是没人维护的测试环境）——
            实测 panabit.com 的 326 个影子资产在 live 视图里一个都看不到。
            卡片数得出来、列表找不到，等于白做。
          -->
          <a-tab-pane
            v-if="(assets.summary?.domains_shadow ?? 0) > 0"
            key="shadow"
            :tab="`影子资产 (${tabCount('domains_shadow', (assets.shadow_domains || []).length)})`"
          >
            <a-alert
              type="warning"
              show-icon
              style="margin-bottom: 12px"
              message="测试环境 / 废弃系统 / 临时服务 —— 漏洞浓度最高的角落"
            >
              <template #description>
                这些名字**早就被发现了**，只是没人注意到它们是什么。
                分类由 <code>shadow_asset</code> 模块按标签判定（只看整标签，
                所以 <code>device</code> 不会被误判成 <code>dev</code>）。
                它们的存活状态大多未知 —— 这里**不按探活过滤**。
              </template>
            </a-alert>
            <a-table
              :columns="domainColumns"
              :data-source="assets.shadow_domains || []"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'name'">
                  <span class="tk-mono">{{ record.name }}</span>
                </template>
                <template v-else-if="column.key === 'tags'">
                  <a-tag color="volcano">{{ record.shadow_kind }}</a-tag>
                </template>
                <template v-else-if="column.key === 'source'">
                  <span class="tk-muted">{{ record.source }}</span>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <a-tab-pane key="domains" :tab="`域名 (${tabCount('domains')})`">
            <a-table
              :columns="domainColumns"
              :data-source="assets.domains || []"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'name'">
                  <span class="tk-mono">{{ record.name }}</span>
                </template>
                <template v-else-if="column.key === 'ips'">
                  <span v-if="record.ips" class="tk-mono ip-cell" :title="record.ips">
                    {{ record.ips }}
                  </span>
                  <a-tag v-else-if="record.is_cloud" color="default">云 IP</a-tag>
                  <span v-else class="tk-muted">未解析</span>
                </template>
                <template v-else-if="column.key === 'orgs'">
                  <span v-if="record.orgs" :title="record.orgs">{{ record.orgs }}</span>
                  <span v-else class="tk-muted">—</span>
                </template>
                <template v-else-if="column.key === 'port_count'">
                  <a
                    v-if="record.port_count"
                    class="count-link"
                    @click="gotoTab('ports')"
                  >{{ record.port_count }}</a>
                  <span v-else class="tk-muted">0</span>
                </template>
                <template v-else-if="column.key === 'http_count'">
                  <a-tag v-if="record.http_count" color="green">{{ record.http_count }}</a-tag>
                  <span v-else class="tk-muted">未探活</span>
                </template>
                <template v-else-if="column.key === 'tags'">
                  <!--
                    影子资产放最前面：它是"漏洞浓度最高的角落"，比泛解析/CDN
                    更值得先看见。分类由 shadow_asset 模块打在 domain.shadow_kind 上。
                  -->
                  <a-tag v-if="record.shadow_kind" color="volcano">
                    影子 · {{ record.shadow_kind }}
                  </a-tag>
                  <a-tag v-if="record.is_wildcard" color="red">泛解析</a-tag>
                  <a-tag v-if="record.is_cdn" color="purple">CDN</a-tag>
                  <a-tag v-if="record.is_cloud" color="cyan">云</a-tag>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <a-tab-pane key="ips" :tab="`IP (${tabCount('ips')})`">
            <a-table
              :columns="ipColumns"
              :data-source="assets.ips || []"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'addr'">
                  <span class="tk-mono">{{ record.addr }}</span>
                </template>
                <template v-else-if="column.key === 'ports'">
                  <span
                    v-if="record.ports"
                    class="tk-mono ports-cell"
                    :title="record.ports"
                  >{{ record.ports }}</span>
                  <span v-else class="tk-muted">—</span>
                </template>
                <template v-else-if="column.key === 'http_count'">
                  <a-tag v-if="record.http_count" color="green">{{ record.http_count }}</a-tag>
                  <span v-else class="tk-muted">未探活</span>
                </template>
                <template v-else-if="column.key === 'domain_count'">
                  <a
                    v-if="record.domain_count"
                    class="count-link"
                    @click="gotoTab('domains')"
                  >{{ record.domain_count }}</a>
                  <span v-else class="tk-muted">0</span>
                </template>
                <template v-else-if="column.key === 'tags'">
                  <a-tag v-if="record.is_cloud" color="cyan">云</a-tag>
                  <span v-else class="tk-muted">—</span>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <a-tab-pane key="ports" :tab="`端口 (${tabCount('ports')})`">
            <a-table
              :columns="portColumns"
              :data-source="assets.ports || []"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'endpoint'">
                  <span class="tk-mono">{{ record.ip }}:{{ record.port }}</span>
                </template>
                <template v-else-if="column.key === 'cert_cn'">
                  <span class="tk-mono">{{ certCn(record) || '—' }}</span>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <a-tab-pane key="urls" :tab="`URL (${tabCount('urls')})`">
            <!-- URL 与 HTTP 端点合成一张表 —— 两者本来是包含关系
                 （每个探活过的 URL 在 url 表里都有一行），分开显示会
                 让人以为 url 表里那些都没被探过。 -->
            <div class="tk-muted hint" style="margin-bottom: 8px">
              共 {{ mergedUrls.length }} 个，其中
              <b class="ok-text">{{ probedCount }}</b> 个已探活。
              「发现于」是这条 URL 的出处（页面链接 / JS 接口 / 目录爆破 / 端口探活）。
            </div>
            <a-table
              :columns="urlColumns"
              :data-source="mergedUrls"
              row-key="url"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'url'">
                  <a :href="record.url" target="_blank" rel="noreferrer" class="tk-mono">
                    {{ record.url }}
                  </a>
                </template>
                <template v-else-if="column.key === 'probe'">
                  <a-tag v-if="record.probed" :color="statusColor(record.status)">
                    {{ record.status ?? '—' }}
                  </a-tag>
                  <span v-else class="tk-muted">未探活</span>
                </template>
                <template v-else-if="column.key === 'shot'">
                  <a-button
                    v-if="record.screenshot"
                    type="link"
                    size="small"
                    style="padding: 0"
                    @click="showShot(record.screenshot, record.url)"
                  >
                    查看
                  </a-button>
                  <span v-else class="tk-muted">—</span>
                </template>
                <template v-else-if="column.key === 'parent_url'">
                  <span class="tk-mono tk-zero">{{ record.parent_url || '—' }}</span>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <a-tab-pane key="technologies" :tab="`技术栈 (${tabCount('technologies')})`">
            <a-table
              :columns="techColumns"
              :data-source="assets.technologies || []"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'name'">
                  <a-tag color="geekblue">{{ record.name }}</a-tag>
                  <a-tag v-if="record.version" color="green" class="tk-mono">
                    {{ record.version }}
                  </a-tag>
                  <a-tag v-if="record.implied" color="default">推断</a-tag>
                </template>
                <template v-else-if="column.key === 'category'">
                  <a-tag v-if="record.category" color="blue">
                    {{ categoryLabel(record.category) }}
                  </a-tag>
                  <span v-else class="tk-muted">—</span>
                </template>
                <template v-else-if="column.key === 'cpe'">
                  <span class="tk-mono tk-zero">
                    {{ record.vendor && record.product
                      ? `cpe:2.3:a:${record.vendor}:${record.product}` : '—' }}
                  </span>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <!--
            同款系统（供应链横向）：把端点按 favicon 哈希 / 标题聚成簇。

            favicon 哈希是"同款系统"最强的信号之一 —— 同一套后台、同一个产品
            的部署，图标往往一模一样。而这个哈希**早就采下来了**，一直躺在
            http_endpoint.favicon_hash 里没有出口。
          -->
          <a-tab-pane
            v-if="(assets.clusters?.favicon?.length || 0) > 0 || (assets.clusters?.title?.length || 0) > 0"
            key="clusters"
            :tab="`同款系统 (${(assets.clusters?.favicon?.length || 0) + (assets.clusters?.title?.length || 0)})`"
          >
            <a-alert
              type="info"
              show-icon
              style="margin-bottom: 12px"
              message="同一套系统会在不同主机上留下同一个 favicon / 同一个标题"
            >
              <template #description>
                「图标」按 <code>favicon_hash</code>（mmh3，Shodan 口径）聚类，
                特异性最高；「标题」已排除 <code>404 Not Found</code> 这类错误页
                文本 —— 那是"都出错了"，不是"同款系统"。
                只在**本次扫描内**聚，不跨扫描（跨客户目标关联有外泄面）。
              </template>
            </a-alert>

            <div class="toolbar" style="margin-bottom: 12px">
              <a-radio-group v-model:value="clusterBy" size="small" button-style="solid">
                <a-radio-button value="favicon">
                  按图标 ({{ assets.clusters?.favicon?.length || 0 }})
                </a-radio-button>
                <a-radio-button value="title">
                  按标题 ({{ assets.clusters?.title?.length || 0 }})
                </a-radio-button>
              </a-radio-group>
            </div>

            <a-table
              :columns="clusterColumns"
              :data-source="clusterRows"
              row-key="key"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'key'">
                  <span class="tk-mono cluster-key">{{ record.key }}</span>
                </template>
                <template v-else-if="column.key === 'size'">
                  <a-tag color="blue">{{ record.size }} 台</a-tag>
                </template>
                <template v-else-if="column.key === 'hosts'">
                  <span class="tk-mono cluster-hosts">{{ record.hosts }}</span>
                </template>
                <template v-else-if="column.key === 'titles'">
                  <span class="tk-muted">{{ record.titles || '—' }}</span>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <a-tab-pane key="findings" :tab="`发现 (${tabCount('findings')})`">
            <a-table
              :columns="findingColumns"
              :data-source="assets.findings || []"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            />
          </a-tab-pane>

          <a-tab-pane key="events" :tab="`事件 (${tabCount('events', events.length)})`">
            <div class="tk-muted" style="margin-bottom: 8px">
              点任意一行的「溯源」可以看到这个资产是**怎么被发现的**——从种子一路推到这里。
            </div>
            <a-table
              :columns="eventColumns"
              :data-source="events"
              row-key="id"
              size="small"
              :pagination="{ pageSize: 15, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'type'">
                  <a-tag>{{ record.type }}</a-tag>
                  <a-tag v-if="record.kind" color="orange">{{ record.kind }}</a-tag>
                </template>
                <template v-else-if="column.key === 'data'">
                  <span class="tk-mono">{{ record.data }}</span>
                </template>
                <template v-else-if="column.key === 'trace'">
                  <a-button type="link" size="small" style="padding: 0" @click="showTrace(record)">
                    溯源
                  </a-button>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <a-tab-pane key="sources" :tab="`源统计 (${sourceStats.length})`">
            <div class="tk-muted" style="margin-bottom: 8px">
              每个被动源这次发了多少请求、拿回多少、错在哪。
              <b>产出 0 而错误不为 0 的源，多半是被限流或已经停服了</b>——
              以前要靠另写探针脚本才能发现，现在这一页直接看得到。
            </div>
            <a-table
              :columns="sourceColumns"
              :data-source="sourceStats"
              row-key="source"
              size="small"
              :pagination="false"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'source'">
                  <span class="tk-mono">{{ record.source }}</span>
                </template>
                <template v-else-if="column.key === 'results'">
                  <span :class="{ 'tk-zero': !record.results }">{{ record.results }}</span>
                </template>
                <template v-else-if="column.key === 'errors'">
                  <a-tag v-if="record.errors" color="red">{{ record.errors }}</a-tag>
                  <span v-else>0</span>
                </template>
                <template v-else-if="column.key === 'elapsed'">
                  {{ record.elapsed }}s
                </template>
                <template v-else-if="column.key === 'last_error'">
                  <span class="tk-muted" :title="record.last_error">
                    {{ (record.last_error || '').slice(0, 60) }}
                  </span>
                </template>
              </template>
            </a-table>
            <div v-if="!sourceStats.length" class="tk-muted" style="margin-top: 12px">
              这次扫描没有被动源参与（预设里没启用，或还没跑完）。
            </div>
          </a-tab-pane>

        </a-tabs>
      </div>
    </a-spin>

    <!-- 溯源链 -->
    <a-modal v-model:open="traceOpen" title="事件溯源链" :footer="null" width="720">
      <div v-if="trace.length" class="trace">
        <div v-for="(node, index) in trace" :key="node.id" class="trace-node">
          <div class="trace-index">{{ index + 1 }}</div>
          <div class="trace-body">
            <div class="trace-head">
              <a-tag>{{ node.type }}</a-tag>
              <a-tag v-if="node.kind" color="orange">{{ node.kind }}</a-tag>
              <span class="tk-muted trace-module">{{ node.module }}</span>
            </div>
            <div class="tk-mono">{{ node.data }}</div>
            <div class="tk-muted trace-time">{{ node.created_at }}</div>
          </div>
        </div>
      </div>
      <div v-else class="tk-empty">没有溯源信息</div>
    </a-modal>

    <!-- 变更报告 -->
    <a-modal v-model:open="diffOpen" title="变更报告" :footer="null" width="820">
      <a-spin :spinning="diffLoading">
        <div v-if="diff && diff.old_scan_id === null" class="tk-muted" style="margin-bottom: 12px">
          这是该目标的第一次扫描，没有可对比的基线，因此全部算新增。
        </div>
        <div v-else-if="diff && !diff.total" class="tk-muted">
          与上一次扫描相比没有任何变化。
        </div>
        <template v-else-if="diff">
          <div class="tk-muted" style="margin-bottom: 12px">
            对比 #{{ diff.old_scan_id }} → #{{ diff.new_scan_id }}，共 {{ diff.total }} 处变化
          </div>
          <div v-for="kind in ['added', 'removed', 'changed']" :key="kind">
            <template v-for="(items, asset) in diff[kind]" :key="kind + asset">
              <template v-if="items && items.length">
                <h4 class="diff-title">
                  {{ { added: '新增', removed: '消失', changed: '变化' }[kind] }} ·
                  {{ assetLabel(asset) }}（{{ items.length }}）
                </h4>
                <div v-for="item in items" :key="item.key" class="diff-item">
                  <span class="tk-mono">{{ item.key }}</span>
                  <span v-if="item.diff" class="tk-muted diff-delta">
                    {{ Object.entries(item.diff).map(([f, v]) => `${f}: ${v.old} → ${v.new}`).join('；') }}
                  </span>
                </div>
              </template>
            </template>
          </div>
        </template>
        <div v-else class="tk-empty">加载失败</div>
      </a-spin>
    </a-modal>

    <!-- 截图 -->
    <a-modal v-model:open="shotOpen" title="网页截图" :footer="null" width="900">
      <a-spin :spinning="shotLoading">
        <img v-if="shotSrc" :src="shotSrc" class="shot-img" alt="截图" />
        <div v-else-if="!shotLoading" class="tk-empty">截图加载失败</div>
      </a-spin>
    </a-modal>
  </div>
</template>

<script setup>
import {
  ArrowLeftOutlined,
  DownOutlined,
  InfoCircleOutlined,
  QuestionCircleOutlined,
} from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  deleteScan,
  downloadExport,
  getAssets,
  getDiff,
  getEvents,
  getScan,
  getTrace,
  stopScan,
} from '@/api'
import { getToken } from '@/api/http'
import { openProgressStream } from '@/api/stream'

const route = useRoute()
const router = useRouter()

/**
 * 返回上一页。
 *
 * 直接输 URL 打开详情时没有上一页，这时 router.back() 会把人带出站点 ——
 * 所以先看 Vue Router 记的前一页（history.state.back），没有就回任务列表。
 */
function goBack() {
  if (window.history.state?.back) router.back()
  else router.push('/taskList')
}

const id = Number(route.query.id)
const scan = ref({})
const assets = ref({})
const events = ref([])
// 每源运行统计。后端在 scan 载荷里带上（live 走 manager.to_dict，
// 历史扫描走 _historical_scan），所以不用额外请求。
const sourceStats = ref([])

const tab = ref('domains')
const loading = ref(false)
const busy = ref(false)
const progress = ref({})

const traceOpen = ref(false)
const trace = ref([])
const diffOpen = ref(false)
const diff = ref(null)
const diffLoading = ref(false)
const shotOpen = ref(false)
const shotSrc = ref('')
const shotLoading = ref(false)

let controller = null

const domainColumns = [
  { title: '域名', key: 'name', width: 230 },
  // 解析结果与归属都是从 domain_ip -> ip 聚合出来的（见 storage 的
  // _DOMAIN_ENRICH）。一个域名可能对多个 IP / 归属，所以是逗号拼接的串。
  { title: '解析 IP', key: 'ips', width: 190, ellipsis: true },
  { title: '归属', dataIndex: 'orgs', key: 'orgs', width: 190, ellipsis: true },
  { title: '国家', dataIndex: 'countries', key: 'countries', width: 80, ellipsis: true },
  { title: '端口', key: 'port_count', width: 70 },
  { title: '存活', key: 'http_count', width: 80 },
  { title: '来源', dataIndex: 'source', key: 'source', width: 130, ellipsis: true },
  { title: '标记', key: 'tags', width: 150 },
  { title: '最近发现', dataIndex: 'last_seen', key: 'last_seen', width: 170 },
]
const ipColumns = [
  { title: 'IP', key: 'addr', width: 150 },
  // 开放端口、域名数、存活数都是从关联表聚合出来的（见 storage 的 _IP_ENRICH）
  { title: '开放端口', key: 'ports', width: 200, ellipsis: true },
  { title: '端口数', dataIndex: 'port_count', key: 'port_count', width: 80 },
  { title: '存活', key: 'http_count', width: 80 },
  { title: '域名数', key: 'domain_count', width: 80 },
  { title: '归属', dataIndex: 'org', key: 'org', width: 190, ellipsis: true },
  { title: '国家', dataIndex: 'country', key: 'country', width: 80 },
  { title: '标记', key: 'tags', width: 80 },
  { title: '最近发现', dataIndex: 'last_seen', key: 'last_seen', width: 170 },
]
//: 同款系统：按 favicon 哈希还是标题聚
const clusterBy = ref('favicon')
const clusterColumns = [
  { title: '簇标识', key: 'key', width: 180 },
  { title: '规模', key: 'size', width: 90 },
  { title: '主机', key: 'hosts' },
  { title: '标题（簇内）', key: 'titles', width: 280, ellipsis: true },
]
const clusterRows = computed(() => assets.value.clusters?.[clusterBy.value] || [])

// 后端 progress.busy: {模块名: 一句话进度}。值可能不是对象（老后端没这字段，
// 或 SSE 收到半截帧），所以整体按不可信输入处理，坏了就当"没在跑"，
// 绝不能因此让整个进度块白屏。
const busyModules = computed(() => {
  const raw = progress.value?.busy
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return []
  return Object.entries(raw)
    .filter(([, hint]) => typeof hint === 'string' && hint)
    .map(([name, hint]) => ({ name, hint }))
})

const portColumns = [
  { title: '端点', key: 'endpoint', width: 200 },
  { title: '协议', dataIndex: 'protocol', key: 'protocol', width: 80 },
  { title: '证书 CN', key: 'cert_cn' },
  { title: '最近发现', dataIndex: 'last_seen', key: 'last_seen', width: 170 },
]
const urlColumns = [
  { title: 'URL', key: 'url' },
  { title: '探活', key: 'probe', width: 90 },
  { title: '标题', dataIndex: 'title', key: 'title', width: 220, ellipsis: true },
  { title: 'Server', dataIndex: 'server', key: 'server', width: 140 },
  { title: '来源', dataIndex: 'source', key: 'source', width: 120 },
  { title: '类型', dataIndex: 'kind', key: 'kind', width: 90 },
  { title: '发现于', key: 'parent_url', width: 240, ellipsis: true },
  { title: '截图', key: 'shot', width: 70 },
]
const techColumns = [
  { title: '主机', dataIndex: 'host', key: 'host', width: 240 },
  { title: '技术', key: 'name', width: 260 },
  { title: '分类', key: 'category', width: 130 },
  { title: '证据', dataIndex: 'evidence', key: 'evidence' },
  // CPE（厂商+产品）是关联 CVE 的钥匙 —— FingerprintHub 那套设计的价值所在
  { title: 'CPE', key: 'cpe', width: 240 },
]
const findingColumns = [
  { title: '类型', dataIndex: 'kind', key: 'kind', width: 130 },
  { title: '级别', dataIndex: 'severity', key: 'severity', width: 90 },
  { title: '目标', dataIndex: 'target', key: 'target' },
  { title: '详情', dataIndex: 'detail', key: 'detail' },
]
const eventColumns = [
  { title: '类型', key: 'type', width: 220 },
  { title: '数据', key: 'data' },
  { title: '来源模块', dataIndex: 'module', key: 'module', width: 150 },
  { title: '深度', dataIndex: 'scope_distance', key: 'scope_distance', width: 70 },
  { title: '溯源', key: 'trace', width: 80 },
]
const sourceColumns = [
  { title: '源', key: 'source', width: 190 },
  { title: '请求', dataIndex: 'requests', key: 'requests', width: 70 },
  { title: '原始', dataIndex: 'raw', key: 'raw', width: 80 },
  { title: '产出', key: 'results', width: 80 },
  { title: '错误', key: 'errors', width: 70 },
  { title: '耗时', key: 'elapsed', width: 80 },
  { title: '最后错误', key: 'last_error' },
]

const statCards = computed(() => {
  const s = assets.value.summary || {}
  // **必须和下面的页签用同一个口径。**
  //
  // 页签走的是 *_live（界面上只展示探活确认过的资产），卡片原来走的是原始
  // 总数 —— 结果同一个页面顶部写"域名 14333"、下面页签写"域名 (255)"。
  // 没有 *_live 的（技术栈/发现/事件）本来就只有一套数，用原值。
  const live = (key) => s[`${key}_live`] ?? s[key] ?? 0
  return [
    { label: '事件', value: s.events ?? 0 },
    { label: '域名', value: live('domains'), accent: true },
    // 影子资产（测试环境 / 废弃系统）单独拎出来：它是"漏洞浓度最高的角落"，
    // 但**早就被子域枚举发现了**，只是躺在几千个域名里没人注意。
    // 有命中才高亮。
    {
      label: '影子资产',
      value: s.domains_shadow ?? 0,
      accent: (s.domains_shadow ?? 0) > 0,
    },
    { label: 'IP', value: live('ips') },
    { label: '开放端口', value: live('ports') },
    { label: 'URL', value: live('urls') },
    { label: 'HTTP 端点', value: s.http_endpoints ?? 0 },
    { label: '技术栈', value: s.technologies ?? 0 },
    { label: '发现', value: s.findings ?? 0 },
  ]
})

function statusBadge(status) {
  return (
    {
      finished: 'success',
      running: 'processing',
      finalizing: 'processing',
      stopped: 'warning',
      error: 'error',
    }[status] || 'default'
  )
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
function statusColor(status) {
  if (!status) return 'default'
  if (status < 300) return 'green'
  if (status < 400) return 'blue'
  if (status < 500) return 'orange'
  return 'red'
}
function certCn(record) {
  try {
    return JSON.parse(record.cert_json || '{}').cert_cn || ''
  } catch {
    return ''
  }
}
function assetLabel(key) {
  return (
    {
      domains: '域名',
      ips: 'IP',
      ports: '端口',
      urls: 'URL',
      endpoints: 'HTTP 端点',
      technologies: '技术栈',
      findings: '发现',
    }[key] || key
  )
}

// 技术栈分类的中文名。slug 由后端指纹库给出（cms / framework / cdn …），
// 与「指纹库」页用的是同一套标签。
const CATEGORY_LABELS = {
  server: 'Web 服务器',
  language: '编程语言',
  framework: 'Web 框架',
  cms: '内容管理系统',
  ecommerce: '电商平台',
  js: 'JavaScript 库',
  ui: 'UI 框架',
  analytics: '统计/营销',
  cdn: 'CDN/加速',
  panel: '运维面板',
  database: '数据库',
  docs: '文档/API',
  build: '构建工具',
  captcha: '验证码',
  font: '字体/图标',
  security: '安全产品',
  paas: '平台服务',
}
function categoryLabel(slug) {
  return CATEGORY_LABELS[slug] || slug
}

async function loadAll() {
  loading.value = true
  try {
    const [detail, asset, eventList] = await Promise.all([
      getScan(id),
      getAssets(id),
      getEvents(id, 300),
    ])
    scan.value = detail
    assets.value = asset
    events.value = eventList
    sourceStats.value = detail.source_stats || []
    busy.value = ['running', 'finalizing'].includes(detail.status)
    progress.value = detail.progress || {}
  } catch (e) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

/**
 * URL + HTTP 端点合成一张表。
 *
 * 两张表是**包含关系**（每个探活过的 URL 在 url 表里都有一行），
 * 分开显示会让人以为 url 表里那些都没被探过。合并后一行一个 URL，
 * 探过的带上状态码，没探过的显示「未探活」。
 *
 * 在后端合会多传一份数据，所以在前端合；两个数组的 limit 相同，
 * 合并时取并集即可（端点在 url 里缺失时也能补上）。
 */
const mergedUrls = computed(() => {
  const byUrl = new Map()
  for (const u of assets.value.urls || []) {
    byUrl.set(u.url, { ...u, probed: false })
  }
  for (const e of assets.value.endpoints || []) {
    const cur = byUrl.get(e.url)
    if (cur) {
      Object.assign(cur, {
        probed: true,
        status: e.status,
        title: e.title,
        server: e.server,
        content_length: e.content_length,
        screenshot: e.screenshot,
      })
    } else {
      // 防御：端点不在 url 表里（结构上不该发生，但别让它消失）
      byUrl.set(e.url, { ...e, probed: true })
    }
  }
  return [...byUrl.values()]
})

/** 合并表里已探活的条数（页签上方的提示用）。 */
const probedCount = computed(() => mergedUrls.value.filter((u) => u.probed).length)

/** 切到某个资产页签（域名行里的端口数点一下跳过去）。 */
function gotoTab(key) {
  tab.value = key
}

/**
 * 页签上的数字 = **存活条数**（`summary` 里的 `*_live`）。
 *
 * **不能再用 `assets.x.length`** —— 那只是"这次取回来的行数"，
 * 被 limit 截断之后会假装成总数（页签曾经写「域名 (2000)」，其实是
 * 14333 条里只取了 2000 行）。
 *
 * 存活数远小于 limit，所以不会被截断；万一哪次真的超了，退回
 * "已加载 / 存活" 的写法，截断一眼可见。
 */
/**
 * 页签上的数字。
 *
 * 有 *_live 的用存活数（界面上只展示探活确认过的资产）；技术栈 / 发现 /
 * 事件这些没有存活口径的，退回 summary 里的原始总数 —— 原来直接取 0，
 * 于是 `发现 (2000)` 里的 2000 其实是**这次取回来的行数**（被 limit 截断），
 * 真实总数 8297 被藏起来了。
 *
 * 取回来的比总数少时写成 `已取 / 总数`，把截断如实标出来。
 */
function tabCount(key, loadedCount) {
  const s = assets.value.summary || {}
  const total = s[`${key}_live`] ?? s[key] ?? 0
  return total.toLocaleString()
}

function startStream() {
  controller = openProgressStream(id, {
    onData: (payload) => {
      scan.value = payload
      progress.value = payload.progress || {}
      busy.value = ['running', 'finalizing'].includes(payload.status)
    },
    onDone: async () => {
      busy.value = false
      await loadAll() // 跑完了补一次完整资产
    },
    onError: () => {
      busy.value = false
    },
  })
}

async function onStop() {
  try {
    await stopScan(id)
    message.success('已请求停止')
    await loadAll()
  } catch (e) {
    message.error(e.message)
  }
}

async function onDelete() {
  try {
    await deleteScan(id)
    message.success('已删除')
    router.push('/taskList')
  } catch (e) {
    message.error(e.message)
  }
}

async function onExport({ key }) {
  try {
    if (key.startsWith('csv:')) {
      const type = key.split(':')[1]
      await downloadExport(id, 'csv', type, `hive-scan${id}-${type}.csv`)
    } else {
      const ext = key === 'xlsx' ? 'xlsx' : 'json'
      await downloadExport(id, ext, 'domains', `hive-scan${id}.${ext}`)
    }
    message.success('已开始下载')
  } catch (e) {
    message.error(e.message)
  }
}

async function loadDiff() {
  diffOpen.value = true
  diffLoading.value = true
  diff.value = null
  try {
    diff.value = await getDiff(id)
  } catch (e) {
    message.error(e.message)
  } finally {
    diffLoading.value = false
  }
}

async function showTrace(record) {
  traceOpen.value = true
  trace.value = []
  try {
    const data = await getTrace(id, record.id)
    trace.value = data.chain || []
  } catch (e) {
    message.error(e.message)
  }
}

async function showShot(screenshotPath, url) {
  shotOpen.value = true
  shotSrc.value = ''
  shotLoading.value = true
  try {
    // <img src> 带不了 Authorization 头，所以先取成 blob
    const token = getToken()
    // screenshotPath 格式: scan_id/hash.png (旧路径)，从中提取 scan_id
    const scanId = screenshotPath.split('/')[0]
    const response = await fetch(`/api/screenshots/${scanId}/${encodeURIComponent(url)}`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    shotSrc.value = URL.createObjectURL(await response.blob())
  } catch (e) {
    message.error(`截图加载失败: ${e.message}`)
  } finally {
    shotLoading.value = false
  }
}

onMounted(async () => {
  if (!id || Number.isNaN(id)) {
    message.error('缺少扫描 ID')
    router.push('/taskList')
    return
  }
  await loadAll()
  if (busy.value) startStream()
})
onUnmounted(() => {
  controller?.abort()
})

</script>

<style scoped>
/* 同款系统：簇标识是哈希或长标题，主机列表可能很长 —— 都要能换行/截断 */
.cluster-key {
  font-size: 12px;
}
.cluster-hosts {
  font-size: 12px;
  word-break: break-all;
}
.asset-toolbar {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 8px 4px 0;
  margin-bottom: 4px;
  flex-wrap: wrap;
}
.toolbar-label {
  font-size: 13px;
  font-weight: 500;
}
.toolbar-hint {
  font-size: 12px;
  margin-left: 14px;
}
/* 解析 IP 可能是逗号拼接的一串，窄列里会挤成一团，单行截断靠 title 看全 */
.ip-cell,
.ports-cell {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 12px;
}
.count-link {
  font-weight: 600;
}
.detail-head {
  padding: 16px 20px;
}
.head-row {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
}
/* head-row 里现在有三个孩子（返回 / 标题 / 操作），中间那个要吃掉剩余空间 */
.head-main {
  flex: 1;
  min-width: 0;
}
/* 返回键和标题同一行，微调一下让文字基线看起来齐 */
.back-btn {
  flex: none;
  margin-top: 1px;
}
.head-title {
  margin: 0 0 8px;
  font-size: 16px;
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.targets {
  font-weight: 400;
  color: var(--tk-text-secondary);
}
/* 用户填的任务名称：作为标题主标识，「扫描 xxx」在有名时退成次要说明 */
.head-name {
  font-weight: 600;
}
.head-meta {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
  font-size: 13px;
}
.head-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
.err {
  color: #dc2626;
}
.progress-wrap {
  margin-top: 14px;
}
.progress-text {
  font-size: 12.5px;
  margin-top: 4px;
}
.module-busy-chip {
  display: inline-block;
  margin-left: 6px;
  padding: 1px 7px;
  border: 1px solid var(--tk-border);
  border-radius: 10px;
  background: var(--tk-bg-subtle, rgba(0, 0, 0, 0.03));
  font-variant-numeric: tabular-nums;
  font-weight: 500;
}
.trace-node {
  display: flex;
  gap: 12px;
  padding: 10px 0;
  border-bottom: 1px dashed var(--tk-border);
}
.trace-node:last-child {
  border-bottom: none;
}
.trace-index {
  width: 24px;
  height: 24px;
  flex-shrink: 0;
  border-radius: 50%;
  background: var(--tk-accent);
  color: #fff;
  font-size: 12px;
  display: flex;
  align-items: center;
  justify-content: center;
}
.trace-body {
  min-width: 0;
  flex: 1;
}
.trace-head {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 4px;
}
.trace-module {
  font-size: 12px;
}
.trace-time {
  font-size: 12px;
}
.diff-title {
  margin: 14px 0 6px;
  font-size: 14px;
}
.diff-item {
  padding: 4px 0;
  font-size: 13px;
}
.diff-delta {
  margin-left: 10px;
  font-size: 12.5px;
}
.shot-img {
  width: 100%;
  border: 1px solid var(--tk-border);
  border-radius: 6px;
}
</style>
