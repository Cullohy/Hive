# 设计文档：事件驱动信息收集引擎（BBOT 架构 × ARL 能力）

> 约束：**不使用 Docker**；架构参考 **BBOT**，能力实现参考本地 **ARL 源码**（`E:\ARL\backend`）。
> 状态：架构已定，**语言待定**（见 §9）。

---

## 1. 先说一条 License 红线 ⚠️

| 项目 | License | 对你意味着什么 |
|---|---|---|
| **BBOT** | **AGPL-3.0** | ⚠️ **最严格的一档**。AGPL 比 GPL 多一条"网络服务条款"：**即使你只把它部署成 Web 服务给用户用、不分发二进制，你也必须公开修改后的源码。** 所以——**架构思想可以学（思想不受版权保护），代码一行都不要抄**。 |
| **ARL** | **MIT** | ✅ 可以直接抄代码、可以闭源商用，只需保留版权声明 + 在项目介绍页注明原 ARL 仓库地址。 |
| ARL-NPoC（你本地有） | MIT (c) 2024 Aabyss-Team | ✅ 可复用 |

**结论**：BBOT 只当"架构教科书"读；**真正能抄的代码来自 ARL**。两者的处理方式必须严格区分。

---

## 2. 核心架构：BBOT 的事件驱动递归模型

### 2.1 为什么放弃 ARL 的串行任务链

ARL 是 **9 段固定串行流水线**（`app/tasks/domain.py` 编排），任务内无并行、无断点续跑、任一环节异常整链失败。

BBOT 的做法完全不同：**每个模块声明自己"消费什么事件、生产什么事件"，扫描引擎把事件在模块之间反复分发，形成递归网**。

BBOT 自己举的例子最能说明问题：

```
portscan  消费 DNS_NAME      → 生产 OPEN_TCP_PORT
sslcert   消费 OPEN_TCP_PORT → 生产 DNS_NAME     ← 绕回来了！
```

两个模块互相喂养 → **开一个模块就能指数级放大结果**。这就是"递归"的本质，也是 ARL 的固定流水线做不到的。

### 2.2 模块契约（要照搬的部分）

```python
class some_module(BaseModule):
    watched_events  = ["DNS_NAME"]        # 消费什么
    produced_events = ["DNS_NAME"]        # 生产什么
    flags = ["passive", "safe"]           # passive/active + safe/loud/invasive
    meta = {"description": "..."}

    class Config(BaseModuleConfig):       # 每模块独立配置（pydantic）
        api_key: str = Field("", sensitive=True, mandatory=True)

    per_domain_only = True                # 每个根域名只跑一次

    async def setup(self):                # 一次性初始化
        return True | None | False        # True=成功 / None=软失败(禁用本模块,扫描继续) / False=硬失败(中止)

    async def setup_deps(self):           # 下载字典/依赖
        ...

    async def handle_event(self, event):  # 主逻辑
        ...
        await self.emit_event(data, "DNS_NAME", parent=event)   # 生产事件
```

引擎侧：**每个模块有独立的 incoming / outgoing 队列**，`watched_events` 匹配的事件进 incoming 队列，`handle_event()` 处理后产出的事件进 outgoing 队列，由引擎重新分发给所有感兴趣的模块。批处理模块用 `handle_batch()`。

### 2.3 从 BBOT 要抄的 5 个设计决策

| # | 设计 | 价值 |
|---|---|---|
| 1 | **事件类型作为模块间唯一契约** | 模块可插拔、可单独测试，加模块不用改引擎 |
| 2 | **`flags` 区分 passive/active 与 safe/loud/invasive** | **正好实现你要的"主动/被动可选"**——按 flag 过滤模块集即可，不用在业务代码里写 if |
| 3 | **`setup()` 三态返回（True/None/False）** | 缺 API Key 的源"软失败"退出而不影响整个扫描。ARL 里靠 `enable: false` 手工开关，粗糙得多 |
| 4 | **Preset（YAML 预设）选模块集** | 用户不用记模块名；`bbot -p subdomain-enum` 这种体验，等价于 ARL 的"任务策略"，但更灵活 |
| 5 | **模块级 Config + `sensitive=True`** | API Key 自动脱敏；`mandatory=True` 时自动软失败 |

---

## 3. 事件类型设计（按你的三项需求裁剪）

BBOT 有 100+ 模块、几十种事件类型。你只需要一小撮，命名沿用 BBOT 的大写下划线风格：

| 事件类型 | 含义 | 由谁生产 | 由谁消费 |
|---|---|---|---|
| `SEED` | 输入的根域名 | 用户输入 | 所有被动源、爆破、置换 |
| `DNS_NAME` | 域名/子域名 | 被动源、爆破、置换、证书 | DNS 解析、递归爆破 |
| `IP_ADDRESS` | IP | DNS 解析、ASN 富化 | 端口扫描、反向查询 |
| `OPEN_TCP_PORT` | 开放端口 | 端口扫描 | HTTP 探活、TLS 证书 |
| `URL` | 完整 URL | HTTP 探活、爬虫 | 指纹、截图 |
| `HTTP_RESPONSE` | 状态码/标题/长度/头 | HTTP 探活 | 指纹、变更监控 |
| `TECHNOLOGY` | 技术栈指纹 | 指纹模块 | 展示 / 后续 PoC 选择 |
| `SSL_CERTIFICATE` | 证书（SAN/签发者/有效期） | TLS 模块 | **生产新的 `DNS_NAME`**（SAN 里挖子域）← 递归点 |
| `ASN` / `NETBLOCK` | ASN / IP 段 | ASN 富化 | **生产新的 `IP_ADDRESS` 段**← 递归点 |
| `FINDING` | 结论性发现（泛解析/CDN/敏感信息） | 各模块 | 展示、告警 |

**递归闭环在哪**：
```
SEED → DNS_NAME ─┬─→ IP_ADDRESS → OPEN_TCP_PORT ─┬─→ HTTP_RESPONSE → TECHNOLOGY
                 │                              └─→ SSL_CERTIFICATE → DNS_NAME ↺
                 └─→ DNS_NAME (爆破/置换) ↺
      IP_ADDRESS → ASN → NETBLOCK → IP_ADDRESS ↺
```

---

## 4. 模块清单（职责 + ARL 参考实现）

**能直接对着 ARL 的 `app/services/` 抄实现**（MIT，可抄）：

| 我们的模块 | watched → produced | flags | ARL 参考文件（`E:\ARL\backend\`） |
|---|---|---|---|
| `passive_crtsh` | SEED → DNS_NAME | passive/safe | `app/services/dns_query_plugin/crtsh.py` |
| `passive_rapiddns` | SEED → DNS_NAME | passive/safe | `.../rapiddns.py` |
| `passive_certspotter` | SEED → DNS_NAME | passive/safe | `.../certspotter.py` |
| `passive_chaos` | SEED → DNS_NAME | passive/safe | `.../chaos.py` |
| `passive_fofa` | SEED → DNS_NAME | passive/safe | `.../fofa.py` + `app/services/fofaClient.py` |
| `passive_quake` | SEED → DNS_NAME | passive/safe | `.../quake_360.py` |
| `passive_hunter` | SEED → DNS_NAME | passive/safe | `.../hunter_qax.py` |
| `passive_zoomeye` | SEED → DNS_NAME | passive/safe | `.../zoomeye.py` |
| `passive_virustotal` | SEED → DNS_NAME | passive/safe | `.../virustotal.py` |
| **`plugin_loader`** | — | — | **`app/services/dns_query.py`**：`DNSQueryBase` 抽象类 + `run_plugin()` 的 enable/skip 判定 + 线程池并发。**这套插件接口直接照搬** |
| `dns_brute` | DNS_NAME → DNS_NAME | **active**/loud | `app/services/massdns.py` + 字典 |
| `dns_permute` | DNS_NAME → DNS_NAME | **active**/loud | **`app/services/altDNS.py`**：DnsGen 5 种置换策略（插词/插数字/前置词/后置词/词替换），源码注释标明移植自 `ProjectAnte/dnsgen` |
| `dns_resolve` | DNS_NAME → IP_ADDRESS | active/safe | `app/services/resolverDomain.py`、`app/services/dns_query.py` |
| `wildcard_detect` | DNS_NAME → FINDING | active/safe | **ARL 的泛解析实现有硬伤，见 §5** |
| `cdn_check` | IP_ADDRESS → FINDING | passive/safe | `app/utils/cdn.py` + `app/dicts/cdn_info.json` |
| `asn_enrich` | IP_ADDRESS → ASN/NETBLOCK | passive/safe | `app/utils/ip.py` + GeoLite2 |
| `port_scan` | IP_ADDRESS → OPEN_TCP_PORT | **active**/loud | `app/services/portScan.py`（ARL 串行调 nmap，**我们要改**） |
| `http_probe` | OPEN_TCP_PORT → HTTP_RESPONSE/URL | **active**/loud | `app/services/probeHTTP.py`、`checkHTTP.py`、`fetchSite.py` |
| `tls_cert` | OPEN_TCP_PORT → SSL_CERTIFICATE | active/safe | `app/services/fetchCert.py` + `app/utils/cert.py` |
| `fingerprint` | HTTP_RESPONSE → TECHNOLOGY | passive/safe | `app/services/fingerprint.py`、`webAnalyze.py` + `app/dicts/webapp.json` |
| `screenshot` | URL → FINDING | active/loud | `app/services/siteScreenshot.py`（ARL 用 PhantomJS，**必须换**） |
| `engine_internal` | 去重 / 限速 / 递归深度控制 / 范围校验 | — | `app/helpers/scope.py`、`app/services/expr.py`（资产查询表达式） |

---

## 5. 从 ARL 抄什么、坚决不抄什么

### ✅ 值得抄（我已读过源码确认）

1. **被动源插件接口**（`dns_query.py`）
   ```python
   class DNSQueryBase:
       def init_key(self, **kwargs): ...     # 各源的 Key 初始化
       def sub_domains(self, target): ...    # 只需实现这一个方法
   ```
   `run_plugin()` 里统一做了：`enable` 判定 → Key 齐全性校验 → 异常吞掉只记日志 → 结果归一化。
   **`query()` 里的结果清洗逻辑特别值得抄**：剥离 `*.` 前缀、转小写、校验后缀必须属于目标、丢弃超长域名（`Config.DOMAIN_MAX_LEN`）、黑名单过滤、`domain_parsed` 校验、最后 `set()` 去重。

2. **DnsGen 的 5 种置换策略**（`altDNS.py`）：插词 / 插数字 / 前置词（含 `-`）/ 后置词（含 `-`）/ 词替换。这是"字典智能生成"的核心，比堆大字典有效得多。

3. **CDN 判定**：`utils/cdn.py` + `dicts/cdn_info.json` 数据。

4. **资产查询表达式**（`services/expr.py`）：ARL 前端能用类 MongoDB 表达式查资产，这套查询 DSL 设计值得保留。

5. **主动/被动分级**：ARL 通过任务选项开关区分，我们改成模块 `flags` 自动过滤，更干净。

### ❌ 坚决不抄（4 个硬伤）

| ARL 的做法 | 问题 | 我们的做法 |
|---|---|---|
| **泛解析过滤**：`records_count[record] >= 15` 就丢弃（`altDNS.py:233`） | **硬编码魔数**。少于 15 个子域命中同一 IP 时泛解析直接漏过；不同规模的域名用同一个阈值必然错 | 主动探测：对根域名解析 N 个随机不存在子域，构建"泛解析 IP 集合 + 响应特征"，命中则**标记 `is_wildcard` 并降权，而不是静默丢弃**；结合响应相似度/N-gram 二次判定 |
| **端口扫描串行调 nmap** | 慢、并发不可控 | 用 naabu 做发现 + nmap 只做已开放端口的服务识别（两段式） |
| **截图用 PhantomJS**（2018 停更） | 无维护、有安全风险、装不上 | Playwright（Chromium），或直接不做截图 |
| **口令 `hex_md5('arlsalt!@#' + pwd)`** | 不可接受的哈希方案 | bcrypt / argon2 |

**另外两条要改默认值**（我复核了 `E:\ARL\backend\app\config.yaml` 和 `.example`）：
- `BLACK_IPS`：本地的 `config.yaml` 保留了 `172.16.0.0/12`、`100.64.0.0/10`，但 **`10.0.0.0/8` 和 `192.168.0.0/16` 仍是注释状态**
- `FORBIDDEN_DOMAINS`：**完全为空**（`edu.cn`/`org.cn`/`gov.cn` 全被注释）
- → 内网段那条我们**收紧**了（端口扫描前默认拒绝内网与保留地址）。
  敏感域名这条**2026-10-04 改回与 ARL 一致的空列表** —— 原先设成默认拒绝，
  但它在全仓唯一的实际用法是被测试夹具逐个关掉，实际工作又以高校/职院授权测试
  为主（`edu.cn` 正是主战场），每次都得先改预设才扫得动。机制保留，需要时写
  `settings.forbidden_domains` 即可。

---

## 6. 数据模型

沿用 ARL 的资产模型（本地 `app/modules/` 可参考：`baseInfo` / `domainInfo` / `ipInfo` / `pageInfo` / `wihRecord`），但换成关系型 + 时间维度：

```
scan(id, root_domain, preset, mode, status, progress, created_at)
event(id, scan_id, type, data, parent_event_id, module, created_at)   -- 事件表，递归溯源靠 parent
domain(id, scan_id, name, source[], is_wildcard, is_cdn, first_seen, last_seen)
ip(id, addr, asn, org, country, is_cloud, first_seen, last_seen)
domain_ip(domain_id, ip_id, first_seen, last_seen)
port(id, ip_id, port, proto, service, banner, first_seen, last_seen)
http_endpoint(id, port_id, url, status, title, tech[], cert_json, first_seen, last_seen)
finding(id, scan_id, kind, severity, target, detail, created_at)
```

**`event` 表带 `parent_event_id` 是关键**——BBOT 的递归溯源靠它，能回答"这个子域是从哪个源/哪张证书挖出来的"。ARL 完全没有这个能力。

### 6.2 不用 Docker 的部署方案

| 组件 | 方案 |
|---|---|
| 数据库 | **SQLite**（单机零依赖，够用到百万级资产）或 PostgreSQL（需要并发写/大表时） |
| 队列 | **进程内 asyncio 队列**（BBOT 就是这个思路，不需要 Redis/RabbitMQ） |
| Web 后端 | FastAPI / Gin，单进程 |
| 前端 | React + Vite，构建产物由后端静态托管 |
| 启动 | 一条命令：`python -m app` / `./recon.exe serve`；可选注册为 systemd（Linux）或 Windows 服务 |
| 外部工具 | 尽量**进程内库**，避免装 nmap/massdns；确需外部二进制的（如 massdns）随包分发并锁版本 |

> **注意**：ARL 依赖 MongoDB + RabbitMQ + Nginx + systemd 五件套（官方建议 4C8G）。**不用 Docker 的话这套装起来很痛苦**——这正是我们要走进程内队列 + SQLite 路线的直接原因。

---

## 7. 与你三项需求的对应关系

| 需求 | 在本架构里的落点 |
|---|---|
| **① 主动/被动可选收集与爆破** | 被动 = `flags` 含 `passive` 的模块集；主动 = 含 `active`。**用户选 preset 即完成切换**，不需要改代码。爆破 = `dns_brute` + `dns_permute`，递归触发 |
| **② DNS 解析 IP 等信息** | `dns_resolve`（DNS_NAME→IP_ADDRESS）+ `asn_enrich` + `cdn_check`；解析器池 + 限速 + 泛解析标记 |
| **③ 探活** | `port_scan` → `http_probe` → `tls_cert` → `fingerprint`，全部通过事件链自动串起来 |

**最大的架构收益**：这三项在 ARL 里是"写死的三段"，在这里是"事件链上的模块组合"。将来加"爬虫挖新域名""favicon 关联"这类新能力，**只需加一个模块文件，引擎一行不用改**——这就是 BBOT 那个递归设计真正的价值。

---

## 8. 落地顺序建议

| 阶段 | 内容 | 可验证结果 |
|---|---|---|
| **M1** | 事件引擎骨架：Event、BaseModule、队列分发、preset 加载、SQLite 落库 | 写一个 `echo` 模块，能跑通 `SEED → 事件 → 落库` |
| **M2** | `dns_resolve` + `passive_crtsh`/`rapiddns`/`certspotter`（免 Key 三件套）+ `plugin_loader` | 输入根域名，能拿到子域 + IP |
| **M3** | `wildcard_detect`（正确实现）+ `dns_brute` + `dns_permute` | 主动模式可用，泛解析不污染结果 |
| **M4** | `port_scan` + `http_probe` + `tls_cert` + `fingerprint` | 完整探活链 |
| **M5** | FastAPI + React 管理台（任务下发、进度、资产列表、事件溯源树） | 满足"需要 Web 界面" |
| **M6** | 变更监控（first_seen/last_seen 对比）、告警推送、导出 | 产品化 |

---

## 9. 待定决策：引擎语言 ⚠️

架构是语言中立的，但**这一条定了才能开始写 M1**：

| 方案 | 优势 | 劣势 |
|---|---|---|
| **A. Python 3.11+ / asyncio** | ① 与 BBOT/ARL 同语言，**ARL 的 `services/` 代码（MIT）可以直接搬**；② 最快出活；③ 参照物最贴近 | 性能上限低；需要带 Python 运行时（可用 PyInstaller 打包缓解） |
| **B. Go 1.26** | ① **单静态二进制，最符合"不用 Docker"的交付形态**；② PD 库进程内嵌（dnsx/httpx/naabu），自带泛解析过滤与 CDN 排除；③ 并发与资源占用最优 | ARL 的 Python 代码只能"翻译"不能"搬"；与参照物语言不同 |
| **C. 混合** | 引擎用 Go 拿性能，被动源插件用 Python 子进程扩展 | 两套运行时要装，复杂度最高，**不建议** |

> **我的倾向**：如果**性能不是瓶颈、且你希望最大化复用本地 ARL 源码** → 选 **A（Python）**，"参考 BBOT 和 ARL"这句话在 Python 下才真正落地。
> 如果你想**单文件绿色版交付、且愿意把 ARL 逻辑翻译成 Go** → 选 **B**。
