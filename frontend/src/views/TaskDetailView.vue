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
                <template v-else-if="column.key === 'last_seen'">
                  <span class="tk-muted">{{ cnDateTime(record.last_seen) }}</span>
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
                  <!--
                    有 HTTP 端点却没 IP 记录 ≠ "这个域名解析不出来"。
                    站点明明可达（dir_brute / http_probe 拿到了真实响应），
                    说它"未解析"是把**故障或未回填**说成了**事实** ——
                    实测有一个任务里 21/84 个域名（25%）落进这一档。
                    所以单独一档，并指路到真正的原因。
                  -->
                  <a-tooltip
                    v-else-if="record.http_count"
                    placement="topLeft"
                  >
                    <a-tag color="orange">站点可达 · IP 未记录</a-tag>
                    <template #title>
                      该域名有 {{ record.http_count }} 个 HTTP 端点（站点确实可达），<br />
                      但资产表里没有关联的 IP 记录。<br />
                      通常是解析查询失败（所有解析器都没应答）——<br />
                      看「源统计」里 dns_resolve 的「查询失败」计数，或重跑一次任务。
                    </template>
                  </a-tooltip>
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
                <template v-else-if="column.key === 'last_seen'">
                  <span class="tk-muted">{{ cnDateTime(record.last_seen) }}</span>
                </template>
              </template>
            </a-table>
          </a-tab-pane>

          <!--
            C 段探测。**放在「域名」和「IP」之间**是刻意的：它的输入是 IP
            （按 /24 聚合来的），但它的问题域比单个 IP 大 —— 一个 C 段就是
            一次独立授权的扫描任务。紧挨着「IP」放，用户看完 IP 就能往下扫。

            **为什么值得单独一页签而不是塞进「IP」表**：口径完全不同。IP 表是
            "这次扫到的主机"，C 段表是"这段上还有多少我们没碰过的东西"——
            `111.1.168.0/24` 本次 4 台、全库 7 台，差出来的 3 台就是还没探过的
            邻接资产。把两种行混在一张表里，两个数字会互相冒充。
          -->
          <a-tab-pane
            key="netblocks"
            :tab="`C段探测 (${(assets.netblocks || []).length})`"
          >
            <a-alert
              type="info"
              show-icon
              style="margin-bottom: 12px"
              message="按 /24 聚合本任务看到的 IP —— 归属证据是 netblock_expand 的展开闸门"
            >
              <template #description>
                <b>归属证据</b> = 这一段里挂在<b>你自己域名</b>下的机器台数。
                <code>netblock_expand</code> 默认 <code>min_owned=2</code>，
                够格才把整段展开成 IP_ADDRESS 送进端口扫描与探活。<br />
                证据不足的段<b>没有被动过</b> —— 那是刻意为之：一个 C 段里往往
                混着同段其它租户（云主机邻居占库里已知 IP 的 25%），无条件展开
                等于对第三方发扫描。<br />
                想要整段无条件扫，点「扫描」直接用该 C 段建一个 <code>active</code>
                任务（254 个地址的端口扫描，即刻生效）—— 用户显式下发一个段
                即视为明确授权该段，这也是 ARL「任务目标支持 IP 段」的做法。
              </template>
            </a-alert>
            <a-table
              :columns="netblockColumns"
              :data-source="assets.netblocks || []"
              row-key="cidr"
              size="small"
              :pagination="{ pageSize: 20, showSizeChanger: false }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'cidr'">
                  <span class="tk-mono">{{ record.cidr }}</span>
                </template>
                <template v-else-if="column.key === 'owned_hosts'">
                  <!-- 归属证据：这一段里有多少台是目标自己的域名解析出来的。
                       netblock_expand 默认 ≥2 才展开 —— 所以 0/1 的段是
                       **故意没扫**，不是"扫了没东西"。 -->
                  <a-tag v-if="record.owned_hosts >= 2" color="green">
                    {{ record.owned_hosts }} 台
                  </a-tag>
                  <a-tooltip
                    v-else
                    placement="topLeft"
                    :title="`只有 ${record.owned_hosts} 台挂在目标域名下，低于 netblock_expand.min_owned（默认 2），本轮**没有自动展开**这一段。`"
                  >
                    <a-tag color="default">{{ record.owned_hosts }} 台 · 未展开</a-tag>
                  </a-tooltip>
                </template>
                <template v-else-if="column.key === 'expanded_hosts'">
                  <a-tag v-if="record.expanded_hosts" color="purple">
                    {{ record.expanded_hosts }}
                  </a-tag>
                  <span v-else class="tk-muted">—</span>
                </template>
                <template v-else-if="column.key === 'hosts_found'">
                  <span class="tk-mono">{{ record.hosts_found }}</span>
                </template>
                <template v-else-if="column.key === 'known_hosts'">
                  <!-- 差值 = 还没碰过的邻接资产。这是这一页唯一要人动手的数 -->
                  <a-tag v-if="record.known_hosts > record.hosts_found" color="orange">
                    {{ record.known_hosts - record.hosts_found }}
                  </a-tag>
                  <span class="tk-muted">{{ record.known_hosts }}</span>
                </template>
                <template v-else-if="column.key === 'domain_count'">
                  <span class="tk-mono">{{ record.domain_count }}</span>
                </template>
                <template v-else-if="column.key === 'probed_hosts'">
                  <a-tag v-if="record.probed_hosts" color="green">
                    {{ record.probed_hosts }}
                  </a-tag>
                  <span v-else class="tk-muted">—</span>
                </template>
                <template v-else-if="column.key === 'sample_ips'">
                  <span class="tk-mono ports-cell" :title="record.sample_ips">
                    {{ record.sample_ips }}
                  </span>
                </template>
                <template v-else-if="column.key === 'action'">
                  <a-button
                    size="small"
                    type="primary"
                    ghost
                    :loading="scanningCidr === record.cidr"
                    @click.stop="scanNetblock(record)"
                  >
                    扫描
                  </a-button>
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
                  <!--
                    「C 段」这个标记回答的是"这台机器**怎么进来看的**"。

                    没有它，一个 C 段展开出来的邻居（没有任何域名）在列表里
                    就是一个裸 IP —— 和"目标某个子域解析出来的"长得一样，
                    但分量完全不同：后者是范围内的资产，前者是自动扩面
                    出去的边角。看到标记才知道该拿哪台去细看。
                  -->
                  <a-tooltip
                    v-if="record.netblock"
                    placement="topLeft"
                    :title="`C 段扫描带出来的：来自 ${record.netblock}`"
                  >
                    <a-tag color="purple">C 段</a-tag>
                  </a-tooltip>
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
                  <!--
                    有跳转时必须标出来。``url`` 是**我们请求的**地址，而同一行的
                    status / title / content_length 全是**落地页**的 —— 之前
                    界面只显示 url，于是 ``http://x:2082`` 那行写着
                    "200 / Yealink Support / 65506 字节"，可 2082 只回了个
                    跳转，那 65506 字节来自 https://x/ 。点开必然对不上。
                    （orig_status / redirects 是 2026-10-05 补的落库列，
                      之前整条链路都在丢这两个信息。）
                  -->
                  <a-tooltip
                    v-if="record.redirects || (record.final_url && record.final_url !== record.url)"
                    placement="topLeft"
                  >
                    <a-tag color="orange" style="margin-left: 6px">
                      {{ record.orig_status || '30x' }} 跳转
                    </a-tag>
                    <template #title>
                      <div>这个地址自己返回的是 <b>{{ record.orig_status || '30x' }}</b>，
                        内容来自下面这个地址：</div>
                      <div style="margin-top:4px"><b>{{ record.final_url || record.url }}</b></div>
                      <div style="margin-top:6px;opacity:.75">
                        下方「状态 / 标题 / 长度」都是**跳转之后**那个页面的。
                      </div>
                    </template>
                  </a-tooltip>
                </template>
                <template v-else-if="column.key === 'probe'">
                  <a-tag v-if="record.probed" :color="statusColor(record.status)">
                    {{ record.status ?? '—' }}
                  </a-tag>
                  <span v-else class="tk-muted">未探活</span>
                </template>
                <template v-else-if="column.key === 'shot'">
                  <!--
                    「报文」取代「截图」。按钮显不显示看 ``body_size`` ——
                    后端只在正文是文本（且有内容）时才存，二进制不存
                    （存了也读不出来）。
                  -->
                  <a-button
                    v-if="record.body_size"
                    type="link"
                    size="small"
                    style="padding: 0"
                    @click="showResponse(record)"
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

          <a-tab-pane key="events" :tab="`事件 (${eventTotal.toLocaleString()})`">
            <div class="tk-muted" style="margin-bottom: 8px">
              点任意一行的「溯源」可以看到这个资产是**怎么被发现的**——从种子一路推到这里。
            </div>

            <div class="evt-bar">
              <a-radio-group
                v-model:value="eventFilter.kind"
                size="small"
                @change="onEventFilterChange"
              >
                <a-radio-button value="conclusion">只看结论</a-radio-button>
                <a-radio-button value="all">全部事件</a-radio-button>
              </a-radio-group>

              <a-select
                v-model:value="eventFilter.type"
                placeholder="类型"
                size="small"
                style="width: 150px"
                allow-clear
                :options="eventTypeOptions"
                @change="onEventFilterChange"
              />
              <a-select
                v-model:value="eventFilter.module"
                placeholder="来源模块"
                size="small"
                style="width: 160px"
                allow-clear
                :options="eventModuleOptions"
                @change="onEventFilterChange"
              />
              <a-input
                :value="eventFilter.q"
                placeholder="搜数据（子串）"
                size="small"
                style="width: 190px"
                allow-clear
                @change="(e) => onEventSearch(e.target.value)"
              />
              <span class="tk-muted" style="margin-left: auto; font-size: 12px">
                显示 {{ events.length }} / 共 {{ eventTotal.toLocaleString() }} 条
              </span>
            </div>

            <a-table
              :columns="eventColumns"
              :data-source="events"
              row-key="id"
              size="small"
              :pagination="{
                current: eventPage,
                pageSize: eventPageSize,
                total: eventTotal,
                showSizeChanger: true,
                pageSizeOptions: ['20', '50', '100', '200'],
                showTotal: (t) => `共 ${t.toLocaleString()} 条`,
                size: 'small',
              }"
              @change="(p) => onEventPageChange(p.current, p.pageSize)"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'type'">
                  <a-tag :color="eventTypeColor(record.type)">{{ record.type }}</a-tag>
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

    <!-- 溯源链：一条**路径**（每个事件只有一个 parent），所以画成链而不是通用图 ——
         不需要引 d3/cytoscape 之类的依赖，手写 CSS 就够。
         ``trace`` 是后端沿 parent_id 回溯出来的，**顺序是从当前事件倒着回到种子**
         （postgres.py::trace 先 append 当前行再跳 parent），所以渲染时要反过来，
         让「种子」在顶部、点开的那条在底部 —— 与阅读方向一致。 -->
    <a-modal v-model:open="traceOpen" title="发现链：这个资产是怎么被挖出来的" :footer="null" width="760">
      <div v-if="trace.length" class="trace">
        <div
          v-for="(node, i) in traceTopDown"
          :key="node.id"
          class="trace-node"
          :class="{ 'trace-leaf': i === 0 }"
        >
          <div class="trace-head">
            <a-tag :color="eventTypeColor(node.type)">{{ node.type }}</a-tag>
            <a-tag v-if="node.kind" color="orange">{{ node.kind }}</a-tag>
            <span class="tk-muted trace-module">{{ node.module }}</span>
            <span v-if="i === 0" class="trace-leaf-tag">你点的那条</span>
            <span v-else-if="node.type === 'SEED'" class="trace-leaf-tag">种子</span>
          </div>
          <div class="tk-mono trace-data" :title="node.data">{{ node.data }}</div>
          <div class="tk-muted trace-time">
            深度 {{ node.scope_distance ?? '-' }} · {{ node.created_at }}
          </div>
          <!-- 转换标注：这一步「变成了什么」是最有信息量的一行，编号列表看不出来 -->
          <div v-if="i < traceTopDown.length - 1" class="trace-edge">
            <span class="trace-edge-line"></span>
            <span class="trace-edge-label">
              ↓ {{ traceTopDown[i + 1].type }} 产生
            </span>
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

    <!-- 响应报文（2026-10-06 取代截图） -->
    <a-modal
      v-model:open="shotOpen"
      title="响应内容"
      :footer="null"
      width="900"
    >
      <a-spin :spinning="shotLoading">
        <template v-if="shotText">
          <div class="resp-meta">
            <span class="tk-mono">{{ shotUrl }}</span>
            <a-tag v-if="shotStatus" color="blue">HTTP {{ shotStatus }}</a-tag>
            <a-tag v-if="shotType">{{ shotType }}</a-tag>
            <!-- 被截断时要**明说**，否则用户会拿半截报文当完整结论 -->
            <a-tag v-if="shotTruncated" color="orange">
              已截断（只显示前 {{ formatBytes(shotText.length) }}）
            </a-tag>
          </div>
          <pre class="resp-body">{{ shotText }}</pre>
        </template>
        <div v-else-if="!shotLoading" class="tk-empty">没有响应内容</div>
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
import { computed, onMounted, onUnmounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  createScan,
  deleteScan,
  downloadExport,
  getAssets,
  getDiff,
  getEvents,
  getScan,
  getTrace,
  getResponseBody,
  stopScan,
} from '@/api'
import { cnDateTime } from '@/utils/time'
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
//: 事件流是**服务端分页**的：只拿当前页，筛选条件一变就重新取。
//: 以前一次拉 300 条、不给总数、还不说截断了 —— 标题写 779、表格 300 行。
const eventTotal = ref(0)
const eventPage = ref(1)
const eventPageSize = ref(50)
const eventFilter = reactive({ kind: 'conclusion', type: '', module: '', q: '' })
let eventSearchTimer = null
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
// 响应报文弹窗（2026-10-06 取代截图）
const shotOpen = ref(false)
const shotText = ref('')
const shotUrl = ref('')
const shotStatus = ref(null)
const shotType = ref('')
const shotTruncated = ref(false)
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
// C 段探测的列（后端 storage.netblocks 按 /24 聚合，见那里「为什么要跨扫描统计」）。
//
// 「已知主机」是全库口径：本次只扫到 4 台、全库 7 台时，差出来的 3 台就是
// 还没探过的邻接资产。**别把这两个数合成一个** —— 合成之后就看不出"这段还有
// 东西没扫"，而那恰恰是这一页存在的唯一理由。
const netblockColumns = [
  { title: 'C段', key: 'cidr', width: 170 },
  // 归属证据 —— `netblock_expand` 就是按这一列决定展不展开（默认 ≥2）。
  // 它必须排在「已知主机」前面：先看到"凭什么认为是你的"，再看"还有什么没扫"。
  { title: '归属证据', key: 'owned_hosts', width: 90 },
  // 本段被 C 段扫描新捞出来的台数。与「归属证据」的差 = 扫到但没有任何归属
  // 线索的机器 —— 通常全是空地址，只要有一台开着端口，它就是这段里最值得
  // 人看的那台，所以单列出来而不是混进「已知主机」。
  { title: '本段扫出', key: 'expanded_hosts', width: 90 },
  { title: '本次发现', key: 'hosts_found', width: 90 },
  { title: '已知主机', key: 'known_hosts', width: 90 },
  { title: '域名', key: 'domain_count', width: 70 },
  { title: '已探活', key: 'probed_hosts', width: 80 },
  { title: '样例 IP', dataIndex: 'sample_ips', key: 'sample_ips', ellipsis: true },
  { title: '操作', key: 'action', width: 90 },
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
  { title: '响应', key: 'shot', width: 70 },
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

// ---------------------------------------------------------------- 事件流（服务端分页）

/** 溯源链按阅读方向翻转：后端是「当前事件 -> 父 -> … -> 种子」，
 *  渲染时要反过来，让种子在顶部、点开的那条在底部。 */
const traceTopDown = computed(() => [...trace.value].reverse())

/** 取当前页。筛选/页码变化时重新调。 */
async function loadEventPage() {
  const f = eventFilter
  return getEvents(id, {
    limit: eventPageSize.value,
    offset: (eventPage.value - 1) * eventPageSize.value,
    kind: f.kind,
    // 空串不要发：后端会当成"筛一个空类型"
    ...(f.type ? { type: f.type } : {}),
    ...(f.module ? { module: f.module } : {}),
    ...(f.q ? { q: f.q } : {}),
  })
}

function applyEventPage(page) {
  events.value = page?.items || []
  eventTotal.value = page?.total || 0
}

async function reloadEvents() {
  try {
    applyEventPage(await loadEventPage())
  } catch (e) {
    message.error(e.message)
  }
}

/** 筛选一变就回到第 1 页 —— 停在第 7 页看第 1 页的结果只会让人以为筛坏了。 */
async function onEventFilterChange() {
  eventPage.value = 1
  await reloadEvents()
}

/** 搜索框防抖：每敲一个字就发一次请求会打满后端。 */
function onEventSearch(v) {
  eventFilter.q = v
  clearTimeout(eventSearchTimer)
  eventSearchTimer = setTimeout(onEventFilterChange, 400)
}

function onEventPageChange(p, size) {
  eventPage.value = p
  if (size !== eventPageSize.value) {
    eventPageSize.value = size
    eventPage.value = 1
  }
  reloadEvents()
}

// ---------------------------------------------------------------- 事件流

//: 事件类型 -> 颜色。扫一眼就能区分"新域名"和"新证书"，
//: 不用逐行读那列等宽字体。
const EVENT_TYPE_COLOR = {
  SEED: 'default',
  DNS_NAME: 'blue',
  IP_ADDRESS: 'cyan',
  OPEN_TCP_PORT: 'geekblue',
  URL: 'default',
  HTTP_RESPONSE: 'default',
  SSL_CERTIFICATE: 'purple',
  TECHNOLOGY: 'magenta',
  FINDING: 'red',
}
function eventTypeColor(t) {
  return EVENT_TYPE_COLOR[t] || 'default'
}

const eventTypeOptions = [
  { value: 'DNS_NAME', label: 'DNS_NAME · 新域名' },
  { value: 'IP_ADDRESS', label: 'IP_ADDRESS · 新 IP' },
  { value: 'OPEN_TCP_PORT', label: 'OPEN_TCP_PORT · 新端口' },
  { value: 'SSL_CERTIFICATE', label: 'SSL_CERTIFICATE · 证书' },
  { value: 'TECHNOLOGY', label: 'TECHNOLOGY · 技术栈' },
  { value: 'FINDING', label: 'FINDING · 结论' },
  { value: 'URL', label: 'URL（过程）' },
  { value: 'HTTP_RESPONSE', label: 'HTTP_RESPONSE（过程）' },
]

//: 来源模块下拉。**取自这次扫描实际产出过事件的模块**，不是写死一张清单 ——
//: 写死的清单会漏掉新加的模块，界面上就出现"有事件但下拉里选不到"。
const eventModuleOptions = computed(() => {
  const seen = new Set()
  for (const e of events.value) if (e.module) seen.add(e.module)
  if (!seen.size) {
    for (const s of sourceStats.value) if (s.source) seen.add(s.source)
  }
  return [...seen].sort().map((m) => ({ value: m, label: m }))
})

async function loadAll() {
  loading.value = true
  try {
    const [detail, asset, eventPage] = await Promise.all([
      getScan(id),
      getAssets(id),
      loadEventPage(),
    ])
    scan.value = detail
    assets.value = asset
    applyEventPage(eventPage)
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
        // 报文长度（后端只给长度，正文要单独取，见 showResponse）
        body_size: e.body_size,
        content_type: e.content_type,
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

// ---------------------------------------------------------------- C 段探测

/** 正在开扫的 C 段。请求期间只锁这一行的按钮，不锁整页。 */
const scanningCidr = ref('')

/**
 * 用该 C 段建一个 `active` 任务开扫。
 *
 * ## 默认直接启用，不弹确认框
 *
 * 这一页的语义就是"人已经盯着这个段点下来的"，再弹一次确认等于让人确认
 * 自己刚确认过的事。防误触靠的是**这一列只出现在任务详情里**，以及新任务
 * 会立刻出现在「任务列表」上 —— 不是靠一个每次都要点掉的对话框。
 *
 * ## preset 必须是 active
 *
 * `passive` 里没有 port_scan / http_probe。对一个裸网段来说，那条链上
 * 每个模块都会被 `requires_domain` 闸门正确挡下（网段不是域名）—— 于是
 * 任务跑完状态 `finished`、资产数 0，看起来像"这段没东西"，
 * 而实际上一条端口扫描都没发出去。这是最容易踩的静默失败。
 */
async function scanNetblock(record) {
  const cidr = record.cidr
  if (!cidr || scanningCidr.value) return
  scanningCidr.value = cidr
  try {
    const res = await createScan({
      name: `C段扫描 ${cidr}`,
      targets: [cidr],
      preset: 'active',
      enable_sources: [],
      overrides: [],
    })
    message.success(
      `已开扫 ${cidr} —— 任务「${res.name}」（${res.task_code}）已进队列`,
    )
  } catch (e) {
    message.error(e.message)
  } finally {
    scanningCidr.value = ''
  }
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

async function showResponse(record) {
  shotOpen.value = true
  shotText.value = ''
  shotUrl.value = record.url || ''
  shotStatus.value = record.status ?? null
  shotType.value = record.content_type || ''
  shotTruncated.value = false
  shotLoading.value = true
  try {
    const data = await getResponseBody(id, record.url)
    shotText.value = data.body || ''
    shotStatus.value = data.status ?? shotStatus.value
    shotType.value = data.content_type || shotType.value
    // 后端已经截过一次，这里服务端再按 max_bytes 截，会把 truncated 置真
    shotTruncated.value = !!data.truncated
  } catch (e) {
    message.error(`响应加载失败: ${e.message}`)
  } finally {
    shotLoading.value = false
  }
}

/** 字节数给人看（截断提示用）。 */
function formatBytes(n) {
  if (!n) return '0 B'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
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
/* ── 发现链：一条**路径**（每个事件只有一个 parent），所以画成链而不是通用 DAG ──
   不引第三方图库：数据本身就是一条线性链，手写 CSS 足够，还不用动
   package.json。边上的「↓ XXX 产生」才是这张图真正要看的东西 —— 编号列表
   看不出"这一步变成了什么"。 */
.trace {
  padding: 4px 2px 8px;
  max-height: 66vh;
  overflow: auto;
}
.trace-node {
  position: relative;
  padding: 10px 12px;
  border: 1px solid var(--tk-border);
  border-radius: 8px;
  background: var(--tk-bg-subtle, rgba(0, 0, 0, 0.03));
}
/* 用户点开的那条：描边加重，一眼知道自己在看哪个 */
.trace-node.trace-leaf {
  border-color: var(--tk-accent);
  box-shadow: 0 0 0 1px var(--tk-accent) inset;
}
.trace-head {
  display: flex;
  align-items: center;
  gap: 6px;
  flex-wrap: wrap;
}
.trace-leaf-tag {
  margin-left: auto;
  font-size: 11px;
  color: var(--tk-accent);
  border: 1px solid var(--tk-accent);
  border-radius: 4px;
  padding: 0 4px;
}
.trace-data {
  margin-top: 4px;
  font-size: 12px;
  word-break: break-all;
}
.trace-time {
  font-size: 11px;
  margin-top: 2px;
}
/* 边：竖线 + 转换标注 */
.trace-edge {
  position: relative;
  height: 30px;
  margin-left: 14px;
  border-left: 2px solid var(--tk-border);
}
.trace-edge-line {
  position: absolute;
  left: -2px;
  bottom: 0;
  width: 10px;
  height: 10px;
  border-left: 2px solid var(--tk-border);
  border-bottom: 2px solid var(--tk-border);
  transform: rotate(-45deg);
}
.trace-edge-label {
  position: absolute;
  left: 12px;
  top: 7px;
  font-size: 11px;
  color: var(--tk-text-muted, #888);
  white-space: nowrap;
}

/* 事件流筛选栏 */
.evt-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}
/* `.trace-index` / `.trace-body` 随编号列表一起去掉了（图形版没有编号圈）。
   ⚠️ 旧版的 `.trace-head` / `.trace-time` 也一并删了：它们留在新块**之后**，
   同优先级后写的赢，会把新版的 `align-items: center` + `flex-wrap: wrap`
   盖掉 —— 叶节点标签靠 `margin-left: auto` 右对齐，没有 wrap 时模块名一长就溢出。 */
.trace-module {
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
/* 响应报文弹窗 */
.resp-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 10px;
  font-size: 12.5px;
}
.resp-body {
  margin: 0;
  padding: 12px;
  max-height: 62vh;
  overflow: auto;
  background: var(--tk-bg-soft);
  border: 1px solid var(--tk-border);
  border-radius: 6px;
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 12px;
  line-height: 1.6;
  /* 报文里常有超长的一行（JS / base64 / token），不换行会把弹窗撑爆 */
  white-space: pre-wrap;
  word-break: break-all;
}
</style>
