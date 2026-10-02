# 信息收集项目：ARL 等开源方案对标与自研边界调研

> 调研目标：为「输入根域名 → 被动/主动可选收集与爆破 → DNS 解析 IP → 探活」这一项目，判断**直接用开源 / 改造开源 / 自研**的边界，并确认最终技术栈（要求自带 Web 管理界面）。
>
> 调研时间：本次会话；所有 GitHub 数据取自 GitHub REST API 实时返回，均为**实时值**而非记忆值。
> 凡未经核实的内容均显式标注「未确认」，不做推测性陈述。

---

## 0. 结论摘要（TL;DR）

1. **ARL（资产灯塔）已不可作为可靠底座**：官方仓库 `TophantTechnology/ARL` 已被删除（实测访问返回 **HTTP 404**），官方文档站也已 404。现存的是社区备份仓库 `Aabyss-Team/ARL`，最后实际 push 停留在 **2025-07-16**，无上游、无官方发版、无官方 issue 跟踪。技术栈停留在 **Python 3.6 / Flask 2.0.3 / Celery 5.1.2**（2020–2021 年的版本组合），Python 3.6 早已 EOL。
2. **ARL 的价值不在"拿来跑"，而在"抄设计"**：它的**功能清单和任务选项设计**（22 项任务选项、13 个被动源、DNS 字典智能生成、跳过 CDN、资产监控）几乎就是你需求的超集，可以直接照抄产品形态；但它的**代码实现不适合长期演进**——核心逻辑集中在 `app/tasks/domain.py` 这一个 **38 KB 的单文件**里，任务链**全串行、无断点续跑**，指纹与截图依赖**2018 年就停更的 PhantomJS**，最新 release 停在 **V2.6.3（2025-03-04）**。
3. **两个必须警惕的 ARL 默认值（我逐字复核了 `app/config.py`）**：`AUTH = False`（**默认关闭认证**）、`BLACK_IPS` 只含 `127.0.0.0/8` + `0.0.0.0/8`（**内网段被注释掉，默认可扫内网**）、`FORBIDDEN_DOMAINS = []`（**`gov.cn`/`edu.cn` 被注释掉，默认不拦敏感域名**）。⚠️ **ARL 默认配置即可对未授权目标发起主动扫描**——复用它的任何代码都必须把授权校验补在前面。
4. **License 分簇比功能对比更能决定选型**：带 Web UI 且最贴合你需求的几个项目——**reNgine(GPL-3.0)、reNgine-ng(GPL-3.0)、ARL-Next(GPL-3.0)、IVRE(GPL-3.0)、theHarvester(GPL-2.0)**——**一半以上落在 GPL 簇**，闭源商业化走不通。MIT 簇（ARL 原始代码、Osmedeus、SpiderFoot、w12scan + PD 全家桶）才是可商用的池子。**这是我建议自研骨架而非 fork 现成平台的核心原因：不是技术上做不到，是 License 上走不通。**
5. **强烈建议自研引擎，但不要自己造轮子**：核心的 DNS 解析、泛解析过滤、HTTP 探活、端口扫描、CDN 判定，全部用 **ProjectDiscovery 的 Go 库直接内嵌**（`dnsx` / `httpx` / `naabu` / `subfinder` + `cdncheck` / `tlsx` / `wappalyzergo` / `asnmap`）。这些库 MIT 协议、社区最活跃（subfinder 14.5k★、httpx 10.4k★）、且已经把「泛解析过滤」「CDN 排除」做成了现成能力。注意 **httpx/subfinder 已要求 Go ≥ 1.26**。
6. **最终推荐技术栈**：**Go 引擎 + PostgreSQL + Redis(asynq) + React/Vite 管理台 + Docker Compose**。（详见第 5 节）
7. **反方意见（值得考虑）**：若预算 < 2 个月、只需"子域收集 + 探活"、且**纯内部自用不分发**，ARL 开箱可用、REST API 完整（flask-restx + Swagger `/api/doc`），性价比确实高——此时 GPL 与"前端无源码"都不是问题。

---

## 1. ARL 深度对标

### 1.1 项目现状（关键事实）

| 项目 | 事实 | 核验方式 |
|---|---|---|
| 官方仓库 | `github.com/TophantTechnology/ARL` **已删除（404）** | 直接访问返回 404 |
| 官方文档站 | `tophanttechnology.github.io/ARL-doc` **已 404** | 直接访问返回 404 |
| 现存备份 | `github.com/Aabyss-Team/ARL`，README 明确说明"官方开源项目被删除了，本项目留作备份" | README 原文 |
| 备份仓库数据 | ★ 2080、fork 741、open issues 47、language Python、`pushed_at` 2025-07-16、`created_at` 2024-05-13 | GitHub API `/repos/Aabyss-Team/ARL` |
| 代码版本 | `version.txt` = **v2.6.2** | 仓库文件 |
| 最新 release | **V2.6.3，2025-03-04**（次新为 V2.6.2-Beta5，2024-07-27） | GitHub API `/releases` |
| 代码路径最后提交 | **2025-03-17**；此后 2025-07-16 仅改 README → **维护停滞（未归档）** | 子调研核查 `/commits` |
| 停更原因 | 官方发布过公开说明《**关于ARL资产灯塔开源项目生命周期的相关说明**》（Tophant 微信公众号，长亭博客有镜像）。公开口径是**开源项目"生命周期"结束**。**具体原因措辞（商业版化／合规免责／维护成本）原文未能取证 → 未确认** | 微信原文触发环境验证；镜像正文 JS 渲染返回空体 |
| 支持系统 | 不支持 Windows；Docker 或源码安装 | README |
| 资源建议 | CPU 4 线程 / 内存 8G / 带宽 10M（官方建议云服务器） | README |

> 结论：**上游已死**。任何以 ARL 为底座的方案，等于接手一个 2021 年技术选型、2023 年停更、无官方维护者的 Python 单体项目。

### 1.2 技术栈拆解（来自 `requirements.txt` 实测）

| 层 | 组件 | 版本 | 备注 |
|---|---|---|---|
| Web 框架 | Flask + flask-restx | 2.0.3 / 1.0.3 | flask-restx 说明**它是有 REST API 的**，可外部集成 |
| ASGI/WSGI | gunicorn + Werkzeug | 20.1.0 / 2.0.3 | |
| 任务队列 | **Celery** | 5.1.2 | Broker 为 **RabbitMQ**（`CELERY.BROKER_URL`） |
| 数据库 | **MongoDB**（pymongo） | 3.13.0 | 无关系型约束，资产模型靠应用层维护 |
| DNS | **dnspython** | 2.2.1 | 全部 DNS 解析走这里 |
| 指纹/哈希 | **mmh3** | 3.0.0 | favicon hash 关联 |
| 证书 | pyOpenSSL | 22.1.0 | SSL 证书获取 |
| 页面解析 | pyquery | 1.4.3 | 爬虫/站点解析 |
| GEO | geoip2 | 2.9.0 | IP 归属 |
| 导出 | openpyxl | 3.0.0 | Excel 导出 |
| 调度 | crontab + 自研 scheduler | 0.23.0 | 周期任务 |
| 其他 | psutil / tld / PyYAML / requests | — | |
| 前端 | **未确认**（仓库根目录无前端工程目录；前端应为预构建产物，随镜像/`arl_files` 经 Nginx 分发） | — | 需进一步核验 |
| 指纹库 | `misc/finger.json` = **3,087,038 字节（约 3 MB）**，另有 `misc/ADD-ARL-Finger.py` 用于追加指纹 | 仓库文件 |
| 外部工具 | massdns / nmap / nuclei / WebInfoHunter 等以预编译二进制形式由 `arl_files` 提供 | — | 未逐个核验 |
| 部署 | `misc/setup-arl.sh`（41 KB 一键脚本）+ systemd 单元（`arl-web` / `arl-worker` / `arl-worker-github` / `arl-scheduler`）+ `misc/nginx.conf`，默认 HTTPS **5003** | — | 仓库文件 |

**技术栈风险**：Python 3.6 已于 2021-12 EOL；Flask 2.0.3 / Celery 5.1.2 / pymongo 3.13 全部是 2020–2021 年的版本，存在已知 CVE 且升级链耦合（Flask 2→3、pymongo 3→4 都是破坏性变更）。**这套栈不适合承接"接下来 3 年持续演进"的项目**。

### 1.3 四大需求的实现方式对照

| 你的需求 | ARL 的实现 | 评价 |
|---|---|---|
| ① 子域收集与爆破（主动/被动可选） | `app/tasks/domain.py`（38 KB）为主；被动源为 13 个查询插件（`alienvault`、`certspotter`、`crtsh`、`fofa`、`hunter` 等）；主动侧含"域名爆破"开关、大字典（约 2 万条）/测试字典、"DNS 字典智能生成"（用已发现域名组合生成字典） | 产品形态可直接照抄；实现是单文件大杂烩 |
| ② DNS 解析 IP 等信息 | dnspython 2.2.1 统一解析；有 **CDN 判定**（"跳过CDN"选项：判定为 CDN 的 IP 不扫端口，并认为 80/443 开放） | CDN 判定这个设计值得抄；解析层无独立模块 |
| ③ 探活 | 端口扫描（ALL / TOP1000 / TOP100 / 测试）+ 服务识别 + 操作系统识别 + SSL 证书获取 + **站点指纹识别** + 站点截图 | 覆盖面比"探活"更宽，属于完整 ASM |
| （额外） | 资产分组、任务策略、计划任务、GitHub 关键字监控、资产/站点变化监控、文件泄露检测、nuclei 调用、WebInfoHunter 调用与监控 | 产品化程度高，是它最大的资产 |

任务选项共 **22 项**（README 第 6 节）：任务目标支持 IP / IP 段 / 域名，可一次下发多个目标。

### 1.4 代码结构与二次开发改造入口

```
app/
├── tasks/            # Celery 任务（业务流程真正所在）
│   ├── domain.py         # 38,124 B  ← 子域发现 + 爆破 + DNS + 站点探测，核心中的核心
│   ├── ip.py             # 11,927 B  ← IP 段资产
│   ├── asset_site.py     #  5,128 B  ← 站点探测任务
│   ├── asset_wih.py      #  3,285 B
│   ├── github.py         # 11,340 B  ← GitHub 关键字监控
│   ├── poc.py            #  7,712 B  ← nuclei 调用
│   └── scheduler.py      # 12,347 B  ← 周期任务
├── helpers/          # 领域辅助：policy(策略) / scope(范围) / task / task_schedule / scheduler / message_notify / domain / url / asset_*
├── routes/           # flask-restx 路由层（REST API）
├── modules/  services/  tools/  utils/  dicts/
├── config.py         # 13,368 B  ← 全部配置与插件 Token
└── config.yaml.example
```

**要改 ARL 做二次开发，必然要动的地方**：`app/tasks/domain.py`（38 KB 单文件，改不动就是改不动）、`app/tasks/ip.py`、`app/config.py`、`app/routes/`、`app/dicts/`（字典）。
**风险**：无官方上游 → 你的魔改无法合并、无安全补丁来源；MongoDB 无 schema 约束 → 改数据结构要靠人肉保证一致性。

### 1.5 License 与合规

- **LICENSE.md 为 MIT 的中文译本**，版权 `(c) 2023 tophant`；允许使用/复制/修改/合并/出版/发行/再授权/贩售，**允许商用与闭源**。
- 附加要求（MIT 之外的自加条款，需注意）：
  1. 「如果您在自己的项目中使用本软件，请在您的项目介绍页中注明本项目 Github 仓库的地址」；
  2. 「同意 Disclaimer.md 免责声明」。
- **免责声明的实质**：这类主动扫描工具通常限定"仅用于已获授权的目标"。你的项目若对外开放或商用，必须自己做授权校验与审计日志（这是合规红线，不是可选项）。
- **对比风险**：`reNgine` 是 **GPL-3.0**，若你闭源分发且直接复用其代码，会触发传染性义务；`OneForAll` 同样 GPL-3.0；`Kunyu` 为 GPL-2.0。**MIT/Apache 的组件才适合闭源商业产品**。

### 1.6 代码级核查发现

**A. 我逐字复核了 `app/config.py` 的默认值——这里有真正的坑：**

| 配置项 | 源码默认值 | 风险 |
|---|---|---|
| `AUTH` | **`False`** | **默认关闭认证**，服务暴露即无鉴权 |
| `API_KEY` | `""` | 后端 API Key 默认为空 |
| `BLACK_IPS` | **`["127.0.0.0/8", "0.0.0.0/8"]`** | 完整的 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16` **被注释掉了** → **默认配置可以扫内网** |
| `FORBIDDEN_DOMAINS` | **`[]`** | `gov.cn` / `edu.cn` / `org.cn` **被注释掉了** → **默认不对敏感域名做任何拦截** |
| `DOMAIN_BRUTE_CONCURRENT` | `300` | 爆破并发 |
| `ALT_DNS_CONCURRENT` | `1500` | 组合字典爆破并发（很激进） |
| `FOFA_MAX_PAGE` / `FOFA_PAGE_SIZE` | `5` / `2000` | 配置层**是有翻页参数的**，与"FofaClient 未实现翻页"的说法**存在矛盾**，未进一步核实 |
| `MASSDNS_BIN` | `app/tools/massdns` | 内置二进制 |
| `SCREENSHOT_JS` | `app/tools/screenshot.js` | 截图走 JS 引擎（即 PhantomJS 路线） |
| `FORBIDDEN_DOMAINS` 上一行 | `# FORBIDDEN_DOMAINS = ["gov.cn", "edu.cn", "org.cn"]` | 注释形式保留了原默认值，说明这是**被人为放开**的 |

> ⚠️ **合规红线**：以上两条默认值（可扫内网 + 不拦截 gov/edu）意味着 **ARL 默认配置即可对未授权目标发起主动扫描**。你若复用它的任何代码或默认值，必须自己把授权校验做在前面。

**B. 来自专项子调研的代码级结论（我未逐条复核，标注为子调研结论）：**

- 架构是 **9 段全串行任务链**（`app/tasks/domain.py::DomainTask.run`），任务内无并行、**无断点续跑**，任一环节异常即整链 ERROR
- **探活并发仅 10**（`probeHTTP.py`），截图并发 6；端口扫描串行调用 nmap
- **指纹与截图依赖 PhantomJS**（2018 年即停止维护）
- **泛解析是代码级弱点**：硬编码阈值 `records_count >= 15`、`MAX_MAP_COUNT = 35`，且"子域 > 300 且有泛解析"时**直接跳过整个 AltDNS**
- **前端只有编译产物**：`docker/frontend/{css,js,index.html}`，从 chunk 名（`npm.vue~*.js`、`npm.ant-design-vue~*.js`）可判定是 **Vue + Ant Design Vue**，但**无 `package.json`、无前端工程** → **改 UI 等于重建 UI**
- 口令存储为 `hex_md5('arlsalt!@#' + pwd)`；README 公布默认口令 `admin/arlpass`
- 高互动 issue 以**部署问题**为主（Docker Hub 拉取失败、密码重置、`arl_web.log` 被挂载成目录导致 5003 端口起不来等）；**未找到任何 ARL 的公开 CVE**（子调研明确标注未确认，不建议引用具体编号）

### 1.7 社区重构版 ARL-Next（实测核验）

子调研把它的 License 标为"未确认"，**我实测确认了**：

| 项 | 事实 |
|---|---|
| 仓库 | [`owl234/ARL-Next`](https://github.com/owl234/ARL-Next) |
| 创建 / 最后 push | 2026-04-30 / **2026-09-26（非常活跃）** |
| 数据 | ★ 444、fork 70、open issues 7 |
| 自我定位 | "现代化资产测绘与漏洞监控平台。经典 ARL 架构重构，聚焦企业资产关联、**异步解耦并发调度**与原生 **MCP 协议**集成，容器化开箱部署" |
| topics | `mcp`、`nuclei`、`fofa`、`subdomain-enumeration`、`asm`、`attack-surface-managment` |
| **License** | **GPL-3.0** ⚠️ |

**关键判断**：它的"重构卖点"（抛弃 PhantomJS、重写前端、异步解耦调度）恰好**逐条命中 ARL 的痛点**，是"原架构有硬伤"的社区侧最强证据，值得读架构。**但 GPL-3.0 意味着闭源商业化不可用**——如果你的目标是做闭源产品，这条路直接排除；内部自用则可以。

---

## 2. 同类开源方案横向对比

（下表 GitHub 数据均为本次实测的实时值）

| 项目 | 语言 | License | Web UI | 被动收集 | 主动爆破 | DNS 解析 | 端口扫描 | HTTP 指纹 | 活跃度（最后 push） | ★ | 定位 |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Aabyss-Team/ARL**（灯塔备份） | Python | MIT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 2025-07-16（上游已删除） | 2080 | 完整 ASM 平台，产品形态最贴合你 |
| **reNgine** | Python(Django) | **GPL-3.0** | ✅ | ✅ | ✅（靠 amass-active + 字典） | ✅ | ✅ | ✅ | 2026-09-21（活跃） | 8862 | 自动化侦察框架 + 持续监控，UI 成熟 |
| **reNgine-ng**（reNgine 的活跃续作） | Python(Django) | **GPL-3.0** | ✅ | ✅ | ✅（amass-active） | ✅ | ✅ | ✅ | 2026-05-12 | 183 | reNgine 原作者的社区延续版，v2.2.0 重构了扫描引擎 |
| **Osmedeus** | Go | MIT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 2026-09-12（活跃） | 6581 | **编排引擎**，把工具编排成 workflow |
| **OneForAll** | Python | **GPL-3.0** | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | 2026-05-11 | 10093 | 子域收集单一职责做到极致，无 UI |
| **Amass** | Go | Apache-2.0 | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ | 2026-07-19 | 15228 | OWASP 项目，攻击面测绘，重、慢、深 |
| **Kunyu（鲲鱼）** | Python | GPL-2.0 | ❌ | ✅ | ❌ | ❌ | ❌ | ⚠️ 企业信息 | 2025-02-06（低活跃） | 1075 | 企业信息/股权/ICP 维度，偏国内工商数据 |
| **subfinder** | Go | MIT | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ | 2026-09-25 | 14508 | **被动源聚合器（可直接内嵌为库）** |
| **dnsx** | Go | MIT | ❌ | — | ✅ | ✅ | ❌ | ❌ | 2026-09-21 | 2884 | **DNS 解析 + 泛解析过滤（可直接内嵌）** |
| **httpx** | Go | MIT | ❌ | — | — | — | ❌ | ✅ | 2026-09-23 | 10428 | **HTTP 探活/指纹（可直接内嵌）** |
| **naabu** | Go | MIT | ❌ | — | — | — | ✅ | ❌ | 2026-09-21 | 6271 | **端口扫描（可直接内嵌）** |
| ENScan_GO | Go | 未确认 | ❌ | ⚠️ 企业信息 | ❌ | ❌ | ❌ | ❌ | 原 `wgpsec/ENScan_GO` 已 404，社区 fork 可见 | — | 企业信息收集（ICP/APP/公众号） |

### 2.1 两种已被验证的架构范式（本次调研最重要的结论之一）

对比 ARL 与 reNgine-ng 的实现方式，会发现开源界存在**两条截然不同的路线**：

| | **自研派**（ARL） | **编排派**（reNgine-ng / Osmedeus） |
|---|---|---|
| 做法 | 用 dnspython / mmh3 / pyOpenSSL 自己实现 DNS 解析、指纹、证书获取 | 把 subfinder / amass / naabu / nmap / httpx / katana / ffuf / nuclei / wafw00f / EyeWitness 等 CLI 工具串起来 |
| 配置方式 | 前端 22 项任务选项写死在代码里 | **YAML 扫描引擎配置**，用户可自定义用哪些工具、哪些参数 |
| 子域爆破怎么做的 | 自己写字典爆破循环（"大字典约 2 万条"） | `amass-active` + 上传字典（默认 Deepmagic top 50000），自己不写爆破逻辑 |
| 端口扫描 | 自研 + 外部二进制 | naabu（可选挂 nmap script） |
| HTTP 层 | 自研 site 模块 | httpx + EyeWitness 截图 |
| 优点 | 可控、无外部进程依赖、部署简单 | **开发量小得多**、工具升级即能力升级、社区生态直接继承 |
| 缺点 | 什么都得自己写，永远落后于专业工具 | 依赖一堆外部二进制、进程管理复杂、结果格式需归一化、镜像体积大 |

reNgine-ng 的扫描引擎是纯 YAML 驱动的（`subdomain_discovery` / `http_crawl` / `port_scan` / `osint` / `dir_file_fuzz` / `fetch_url` / `vulnerability_scan` / `screenshot` / `waf_detection`），并预设了 "Initial Scan - Passive / recommended / Active" 等引擎模板。

> **对你的启示**：这两条路**都不必照抄**。你的三项需求里"DNS 解析"和"探活"恰恰是 ProjectDiscovery 已经把库做到极致、且**可以直接进程内调用（不用起外部进程）**的部分——也就是**第三种路线：进程内嵌 Go 库**，兼得"编排派"的复用度和"自研派"的可控性。这正是第 3 节推荐的方案。

### 关键判断

- **带 Web UI 且活跃**的只有 **reNgine（GPL，Django）** 和 **Osmedeus（MIT，Go）**。ARL 虽有最好的产品形态，但上游已死。
- **reNgine 的 License 是硬伤**（GPL-3.0）：适合自己部署用，**不适合当作闭源产品底座**。
- **Osmedeus 是最值得读架构的项目**：MIT、Go、把一堆 CLI 工具编排成 workflow，并且它本身也在往"agentic / attack surface management"演进（仓库 topics 含 `agentic-ai`、`attack-surface-management`、`workflow-engine`）。
- **真正的复用价值在 ProjectDiscovery 工具链**：它们是"零件"，MIT、超活跃、且已被设计成可当库调用。

### 2.2 其他带 Web UI 的候选（我实测复核过的项目）

| 项目 | 语言 | License | Web UI | 最后 push | ★ | 定位与参考价值 |
|---|---|---|---|---|---|---|
| **SpiderFoot** | Python | **MIT** | ✅ | 2026-04-13 | **22534** | 最成熟的开源"Web 化 OSINT 编排"。**模块化 + 任务调度**的设计参考价值最高，且是 MIT |
| **IVRE** | Python | **GPL-3.0** | ✅ | 2026-09-10 | 4153 | "自建 Shodan / Passive DNS"范式；README 明确用 Nmap / Masscan / Zeek / p0f / **ProjectDiscovery 工具**。**做大规模资产库（含被动 DNS）时必读** |
| **theHarvester** | Python | **GPL-2.0** | ❌ | 2026-09-21 | 17625 | 被动源聚合最全，可直接当采集层参考 |
| **w12scan** | Python(Django) | **MIT** | ✅ | 2022-12-08（停更） | 1331 | "Django + Elasticsearch 资产搜索引擎"架构（任务队列 + 全文检索）值得抄；代码已停更 |
| **EHole** | Go | Apache-2.0 | ❌ | 2024 | 未复核 | 无 UI，但"指纹 + 探活"引擎实现干净，适合当后端模块参考 |

> 子调研还列出了 `Safe3/CVS（森罗万象）`、`riusksk/Tide`、`SRC_scan`、`TideFinger`、`recon-ng`、`Sn1per` 等项目，**我未逐条复核其 License 与维护状态**，此处仅记录线索，不建议直接据此决策。

### 2.3 License 分簇——这条比功能对比更能决定选型

把上面所有项目按 License 归簇，结论非常清晰：

| 簇 | 项目 | 能否用于闭源商业产品 |
|---|---|---|
| **MIT** | ARL（原始）、Osmedeus、**SpiderFoot**、w12scan、subfinder、dnsx、httpx、naabu | ✅ 可以 |
| **Apache-2.0** | Amass、EHole | ✅ 可以（需保留 NOTICE） |
| **GPL-3.0** | **reNgine、reNgine-ng、ARL-Next、IVRE**、OneForAll | ❌ 传染，闭源分发有法律风险 |
| **GPL-2.0** | theHarvester、Kunyu | ❌ 同上 |

> **一句话**：带 Web UI 且功能最贴合你需求的几个国产项目（ARL、reNgine 系、ARL-Next）**恰好一半落在 GPL 簇里**；而 MIT 簇里带 Web UI 的只有 SpiderFoot（OSINT 编排，不专门做子域爆破）。**这正是我建议"自研骨架 + 内嵌 MIT 的 ProjectDiscovery 库"而非"fork 现成平台"的核心原因——不是技术上做不到，是 License 上走不通。**

---

## 3. 可复用组件清单（实测确认的 Go 依赖树）

这是本次调研**最有价值的发现**：ARL 当年用 dnspython + mmh3 + pyOpenSSL 手搓的东西，今天在 Go 生态里已经是成熟的库，而且这些库之间已经互相打通。

### 3.1 模块路径与 Go 版本要求（实测 `go.mod`）

| 组件 | module 路径 | 要求的 Go 版本 |
|---|---|---|
| dnsx | `github.com/projectdiscovery/dnsx` | go 1.25.0 |
| httpx | `github.com/projectdiscovery/httpx` | **go 1.26.0** |
| naabu | `github.com/projectdiscovery/naabu/v2` | go 1.25.0 |
| subfinder | `github.com/projectdiscovery/subfinder/v2` | go 1.26.0 |

> 实操含义：**本机/CI 需要装较新的 Go 工具链（≥1.26）**，否则 go.mod 直接报错。这是自研路线第一个要落在环境上的动作。

### 3.2 `dnsx` 的依赖暴露了它已经具备的能力

```
miekg/dns                  ← DNS 协议层
projectdiscovery/retryabledns   ← 多解析器重试
projectdiscovery/cdncheck       ← CDN 判定
projectdiscovery/asnmap         ← IP → ASN 归属
projectdiscovery/mapcidr        ← IP 段运算 / 反查
projectdiscovery/ratelimit      ← 令牌桶限速
projectdiscovery/hmap           ← 磁盘型去重
```

**你需求里的「DNS 解析 IP 等信息」几乎不需要自己写**：多解析器重试、限速、CDN 判定、ASN 归属全是现成的。dnsx 的仓库 topics 里直接写着 `wildcard-filtering`（泛解析过滤）。

### 3.3 `httpx` 的依赖暴露了它已经具备的能力

```
projectdiscovery/tlsx           ← TLS 证书解析（SAN/签发者/有效期）
projectdiscovery/wappalyzergo   ← 技术栈指纹
projectdiscovery/cdncheck       ← CDN 判定
projectdiscovery/fastdialer     ← 高速拨号（可走代理）
projectdiscovery/rawhttp        ← 畸形/原始 HTTP 请求
projectdiscovery/retryablehttp-go ← 重试 HTTP 客户端
corona10/goimagehash            ← 截图相似度
hdm/jarm-go                     ← JARM TLS 指纹
spaolacci/murmur3               ← favicon mmh3（ARL 当年用 Python 的 mmh3）
go-rod/rod                      ← 无头浏览器（站点截图）
```

**你需求里的「探活」也不需要自己写**：状态码/标题/跳转链/TLS 证书/指纹/CDN/截图/相似度比对，一个库全包。

### 3.4 直接可复用的"零件"清单

| 零件 | 用途 | 你还要写什么 |
|---|---|---|
| `subfinder` 库 | 被动源聚合（含 Chaos 等免费源） | 只需要做源开关与 Key 池化 |
| `dnsx` 库 | DNS 解析、记录类型、泛解析过滤 | 字典生成策略（DNS 字典智能生成） |
| `naabu/v2` 库 | 端口扫描（含 CDN 排除 topic） | 端口集策略 |
| `httpx` 库 | HTTP 探活、指纹、证书、截图 | 结果落库与展示 |
| `cdncheck` / `asnmap` | CDN 判定、ASN 归属 | 资产标签体系 |
| `ratelimit` / `hmap` | 限速、去重 | 全局配额调度 |
| `Osmedeus`（参考） | workflow 编排设计、Web UI 形态 | 自己的任务模型 |
| `ARL`（参考） | 22 项任务选项的产品设计、资产监控模型 | 数据模型 |

---

## 4. 自研边界建议

### 4.1 推荐做法：**自研"骨架"，复用"器官"**

| 层 | 决策 | 理由 |
|---|---|---|
| 端口扫描 / DNS 解析 / HTTP 探活 / 被动源聚合 | **100% 复用 PD 库** | 已高度成熟，自研只会更差 |
| 泛解析判定 / CDN 判定 | **复用 + 自己加一层策略** | 库给能力，业务需要可解释的结论（如"疑似泛解析，置信度 0.8"） |
| 字典生成（智能字典、变异、递归爆破） | **自研** | 这是你的产品差异化，ARL 的"DNS 字典智能生成"就是靠这个吃饭 |
| 任务模型 / 状态机 / 可恢复 / 断点续跑 | **自研** | ARL 的 Celery+MongoDB 方案耦合重、不可观测 |
| 资产数据模型 / 变更追踪（first_seen/last_seen） | **自研** | 需要关系型约束与时间维度，MongoDB 不合适 |
| 授权范围校验 / 审计日志 | **自研（必须有）** | 合规红线，开源项目基本不替你管 |
| Web 管理台 | **自研（用成熟 UI 库）** | 现成 UI 都不贴合你的三项核心流程 |

**额外可"干净剥离"复用的 ARL 资产**（子调研结论，License 已核）：

| 资产 | 内容 | License | 说明 |
|---|---|---|---|
| `dns_query_plugin/` | 13 个被动子域数据源适配器 | MIT | 现成的源清单与调用逻辑，移植成本低 |
| ARL-NPoC | PoC 引擎（ARL 核心），`xing` 模块 | MIT (c) 2024 Aabyss-Team | 可独立使用 |
| `wih_rules.yml` | WebInfoHunter 规则 | MIT | JS 里挖域名/AK-SK 的规则集 |
| `dicts/webapp.json` | 指纹库（约 657 KB） | **未确认**（疑似源自 GPL-3.0 的 wappalyzer） | ⚠️ **商用前务必核实** |
| GeoLite2 mmdb | IP 归属/ASN 数据 | **MaxMind 独立 EULA**，与 MIT 无关 | ⚠️ 再分发与商用有单独约束，需单独评估 |

### 4.2 明确不建议的三条路

- ❌ **直接 fork ARL 魔改**：38 KB 单文件核心 + 停滞两年 + Python 3.6 EOL + **前端无源码**，改造量不比自研小，且背上无上游的债务。
- ❌ **直接基于 reNgine / reNgine-ng / ARL-Next / IVRE 做闭源商业产品**：**全部是 GPL-3.0**，传染性。
- ⚠️ **只做 ARL 的外围集成（REST API + Webhook）前先想清楚**：它的 API 确实完整（flask-restx + Swagger `/api/doc` + `Token` 头），但这等于把你的产品绑在一个默认 `AUTH=False`、默认不拦 gov/edu、上游已死的系统上。

> **反方意见（也请考虑）**：如果预算 < 2 个月、且只需要"子域收集 + 探活"、且**纯内部自用不分发**，那么 ARL 开箱可用、API 完整，性价比确实高——此时 License 与前端不可改都不是问题。

---

## 5. 推荐技术栈（定稿）

| 层 | 选型 | 说明 |
|---|---|---|
| 引擎语言 | **Go ≥ 1.26** | httpx 的 go.mod 已要求 1.26 |
| 核心库 | `subfinder` / `dnsx` / `naabu/v2` / `httpx` + `cdncheck` / `asnmap` / `tlsx` / `wappalyzergo` | 全 MIT |
| 任务编排 | 单进程 goroutine worker pool + **Redis + asynq**（需 DAG/可视化再上 Temporal） | 轻、可恢复、好观测 |
| 存储 | **PostgreSQL**（资产主数据；first_seen/last_seen 变更追踪）+ 大海量事件再挂 ClickHouse | 关系型约束 + 时间维度 |
| 缓存/去重/限速 | **Redis**（bloom / 令牌桶） | |
| 后端 API | Go + Gin/Echo，SSE 推任务进度 | |
| 前端 | **React + Vite + TypeScript + shadcn/ui + TanStack Table（虚拟滚动）+ ECharts** | 资产列表动辄十万行，必须虚拟滚动 |
| 前端备选 | Vue3 + Element Plus（国内团队更顺手） | |
| 部署 | **Docker Compose**：api / worker / postgres / redis / web；Go 单二进制 + 内嵌静态资源交付 | |

---

## 6. 合规红线（必须内建）

1. **授权校验前置**：任务下发前校验目标是否在已授权白名单内，未授权直接拒绝。
   → **ARL 没有这个机制，而且默认值是反的**：`AUTH=False`、`FORBIDDEN_DOMAINS=[]`、内网段黑名单被注释。见 §1.6-A。
2. **内网与敏感域名默认拒绝**：把 `10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`127.0.0.0/8`、`169.254.0.0/16` 与 `gov.cn`/`edu.cn` 等做成**默认拒绝、需显式申请豁免**，而不是像 ARL 那样留成注释让人放开。
3. **主动/被动分级审计**：被动查询第三方源与主动对目标发包，在日志中必须可区分、可追溯。
4. **限速与熔断**：公共解析器池与被动源各自限速；对目标站点设全局 QPS 上限，避免把目标打挂。（注意 ARL 默认 `ALT_DNS_CONCURRENT=1500`，这个量级对第三方解析器很不友好，别照抄。）
5. **免责声明与使用协议**：若分发，需随附（ARL 的做法是 `Disclaimer.md` 强制同意）。
6. **凭据存储**：ARL 用 `hex_md5('arlsalt!@#'+pwd)` 存口令，这是**不可接受的**，用 bcrypt/argon2。

---

## 7. 来源链接

- ARL 备份仓库 README / LICENSE / 代码结构：[Aabyss-Team/ARL](https://github.com/Aabyss-Team/ARL)
- ARL 官方仓库（已删除，404）：`https://github.com/TophantTechnology/ARL`
- ARL Docker 维护版：[honmashironeko/ARL-docker](https://github.com/honmashironeko/ARL-docker)
- ARL 指纹库：[ADD-ARL-Finger](https://github.com/msmoshang/ADD-ARL-Finger)
- reNgine：[yogeshojha/reNgine](https://github.com/yogeshojha/reNgine)
- reNgine-ng（活跃续作）：[Security-Tools-Alliance/rengine-ng](https://github.com/Security-Tools-Alliance/rengine-ng)，扫描引擎文档：[usage scan_engine](https://github.com/Security-Tools-Alliance/rengine-ng/wiki/usage-scan_engine)
- Osmedeus：[j3ssie/osmedeus](https://github.com/j3ssie/osmedeus)
- OneForAll：[shmilylty/OneForAll](https://github.com/shmilylty/OneForAll)
- Amass：[owasp-amass/amass](https://github.com/owasp-amass/amass)
- subfinder：[projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder)
- dnsx：[projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx)
- httpx：[projectdiscovery/httpx](https://github.com/projectdiscovery/httpx)
- naabu：[projectdiscovery/naabu](https://github.com/projectdiscovery/naabu)
- Kunyu：[knownsec/Kunyu](https://github.com/knownsec/Kunyu)
- ARL-Next（GPL-3.0）：[owl234/ARL-Next](https://github.com/owl234/ARL-Next)
- SpiderFoot（MIT）：[smicallef/spiderfoot](https://github.com/smicallef/spiderfoot)
- IVRE（GPL-3.0）：[ivre/ivre](https://github.com/ivre/ivre)
- theHarvester（GPL-2.0）：[laramies/theHarvester](https://github.com/laramies/theHarvester)
- w12scan（MIT，已停更）：[w-digital-scanner/w12scan](https://github.com/w-digital-scanner/w12scan)
- EHole：[EdgeSecurityTeam/EHole](https://github.com/EdgeSecurityTeam/EHole)
- ARL 官方生命周期说明（镜像，正文未取到）：[长亭博客镜像](https://rivers.chaitin.cn/blog/cq94t0p0lnechd2447n0)、[微信原文](https://mp.weixin.qq.com/s/hM3t3lYQVqDOlrLKz3_TSQ)
- 另一 ARL 备份：[Co5mos/ARL](https://github.com/Co5mos/ARL)

**配套子调研报告**（更细的代码级核查、issue 证据、工作量估算）：[ARL-资产灯塔-二次开发底座调研.md](ARL-资产灯塔-二次开发底座调研.md)

---

## 8. 待补充项

**已闭环：**

- [x] subfinder v2 库的 Go 版本要求 → **go 1.26.0**（实测 `go.mod`）
- [x] reNgine 是否具备主动字典爆破能力 → 具备，但**不是自己实现**：走 `amass-active` + 上传字典（默认 Deepmagic top 50000）
- [x] ARL 前端框架 → **Vue + Ant Design Vue**，但**仓库内只有编译产物**（`docker/frontend/js`），无前端工程 → 改 UI 等于重建 UI
- [x] ARL 最新版本与维护状态 → **V2.6.3（2025-03-04）**，代码路径最后提交 **2025-03-17**，维护停滞（未归档）
- [x] ARL-Next 的 License → **GPL-3.0**（子调研标"未确认"，本次实测确认）
- [x] ARL 官方停更口径 → 官方确曾发布《**关于ARL资产灯塔开源项目生命周期的相关说明**》宣布开源项目生命周期结束
- [x] 其他带 Web UI 的项目 → 见 §2.2

**仍未闭环（已在正文标注"未确认"，不影响选型）：**

- [ ] 上述官方说明的**正文**（微信触发环境验证、长亭镜像正文 JS 渲染返回空体）→ 因此"商业版化 / 合规免责 / 维护成本"这类具体措辞无法取证
- [ ] `dicts/webapp.json` 指纹数据的**确切授权来源**（疑为 GPL-3.0 的 wappalyzer）→ 商用前需法务做 SBOM 级核对
- [ ] `app/tools/massdns` 内置二进制的构建来源与版本
- [ ] §1.6-B 中子调研给出的代码级细节（9 段串行链、并发数、泛解析阈值）**未逐条复核**，如需据此决策请自行看代码确认
- [ ] §2.2 表下提及的 `Safe3/CVS`、`riusksk/Tide`、`SRC_scan`、`TideFinger`、`recon-ng`、`Sn1per` 未复核 License 与维护状态
- [ ] "FofaClient 未实现翻页"与 `config.py` 中 `FOFA_MAX_PAGE=5` 的**矛盾**未澄清
