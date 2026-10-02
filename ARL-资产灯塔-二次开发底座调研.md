# ARL（资产灯塔）作为二次开发底座的可行性调研

> 调研时间基准：以各信源抓取时 GitHub API 返回的数据为准。
> 标注约定：**「未确认」**= 未找到一手证据或无法验证；本报告不编造版本号与数字。

---

## 0. 结论前置（TL;DR）

1. **原官方仓库已消失。** `https://github.com/TophantTechnology/ARL` 现返回 **HTTP 404**（GitHub API `/repos/TophantTechnology/ARL` 同样 404）。事实上的社区主仓是 [`Aabyss-Team/ARL`](https://github.com/Aabyss-Team/ARL)，其 README 首行即写明"因为灯塔ARL的官方开源项目被删除了，所以建立了本开源项目留作备份"。
2. **License 风险很低。** 原版 `LICENSE.md` 是 **MIT（版权所有 (c) 2023 tophant）**，仅附加一条署名要求；**未发现任何禁止商用或限制二次开发分发的条款**。任务描述中担心的"自定义/受限条款"在本次核查中**不成立**。但 **GeoLite2 mmdb 数据**有 MaxMind 独立 EULA，需单独评估。
3. **项目处于维护停滞状态。** 主仓 **未归档**，但代码路径最后一次提交是 **2025-03-17**（此后 2025-07-16 仅改 README）。最新 release **2.6.3（2025-03-04）**。这是"能跑但不再演进"的典型状态。
4. **架构是"Python 单体 + Celery 串行任务链"**，四项能力（子域收集 / 爆破 / DNS 解析 / 探活）**全部具备且实现明确**，但都不算强项：字典仅 2 万、泛解析靠 IP 黑名单 + 计数阈值、端口扫描串行调用 nmap、指纹与截图依赖 **已停止维护的 PhantomJS**。
5. **最大的二开结构性障碍：前端源码不在仓库里。** 仓库中只有 `docker/frontend/` 下**已编译的 Vue 产物**（`npm.vue~*.js`、`npm.ant-design-vue~*.js`），没有前端工程源码。改 UI 等于重建 UI。
6. **建议：不要以 ARL 主仓为"全栈底座"，但值得把 ARL 当作"可复用的插件与 PoC 资产库"。** 若确实要拿它当底座，要么只做外围集成（推荐），要么以社区重构版 [ARL-Next](https://github.com/owl234/arl-next) 为起点，要么只锁 commit 复用其插件层。

---

## 1. 项目基本情况

| 项 | 事实 | 来源 |
|---|---|---|
| 原官方仓库 | `TophantTechnology/ARL` → **404，已删除** | [API 404](https://api.github.com/repos/TophantTechnology/ARL) |
| 事实主仓（社区备份） | [`Aabyss-Team/ARL`](https://github.com/Aabyss-Team/ARL) | 仓库页 |
| Star 数（近似） | **≈ 2,080**（抓取时点 `stargazers_count: 2080`） | [API](https://api.github.com/repos/Aabyss-Team/ARL) |
| Fork 数 | **741** | 同上 |
| Open issues | **47** | 同上 |
| 是否归档 | `archived: false`（**未归档**） | 同上 |
| 主语言 | Python | 同上 |
| 最新 release | **V2.6.3，发布于 2025-03-04** | [releases](https://api.github.com/repos/Aabyss-Team/ARL/releases) |
| 次新 release | V2.6.2-Beta5（2024-07-27）、Beta4（2024-07-25）、Beta3（2024-05-29） | 同上 |
| 仓库内版本号 | `version.txt` = **v2.6.2**（与 `main.py` 中 API version `2.6.2` 一致） | [version.txt](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/version.txt) |
| **代码路径最后一次提交** | **2025-03-17**（`Merge pull request #70 ... 修复无权限问题，更改UA头版本`） | [commits](https://api.github.com/repos/Aabyss-Team/ARL/commits) |
| 仓库最后一次 push | **2025-07-16**（仅改 `README.md`） | 同上 |
| 维护活跃度判定 | **低 / 停滞**：近一年内的提交几乎全在 README 与 `setup-arl.sh`，无功能演进 | 同上 |

**维护现状的关键判断：**
- 原厂方已停止开源维护（官方仓库删除），备份 fork 只做"能装得上"的修补，**不做能力升级**。
- 社区侧出现了**重构版**：[ARL-Next](https://github.com/owl234/arl-next)，公开描述为"彻底重构前端，基于 Vue 3 + 现代 UI 框架"、"抛弃陈旧的 PhantomJS，全面拥抱原生 Chromium 与 Puppeteer"、"后端依托 Python 3.8+ 与 Flask 提供纯粹的 RESTful API"。这是"原架构有硬伤"的社区侧最强证据。
- 周边生态仍活跃：Docker 版由 [honmashironeko/ARL-docker](https://github.com/honmashironeko/ARL-docker) 维护，指纹扩展由 [msmoshang/ADD-ARL-Finger](https://github.com/msmoshang/ADD-ARL-Finger) 维护。
- **原版 Star 数与原版 release 时间线：未确认**（仓库已删除，无法取证）。

---

## 2. License 与商用限制（重点核查）

### 2.1 原版授权原文（决定性证据）

原版 `LICENSE.md` 在备份仓中仍保留，[原文可查](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/LICENSE.md)：

> MIT许可证
> 版权所有 (c) 2023 tophant
> 特此授予任何获得本软件及相关文档文件（以下简称"软件"）的人**免费使用本软件，包括但不限于使用、复制、修改、合并、出版、发行、再授权及贩售软件的副本**，以及允许其他人这样做，但需要遵守以下条件：
> 在软件和软件的所有副本中都必须包含上述版权声明和本许可声明。
> ……（标准 MIT 免责条款）……
> 如果您在自己的项目中使用本软件，请在您的项目介绍页中注明本项目 Github 仓库的地址。
> 同意 …/Disclaimer.md 免责声明

**逐条结论：**

| 问题 | 结论 |
|---|---|
| 具体是什么协议 | **MIT**，附加两条软性要求：① 保留版权声明；② 在项目介绍页注明原仓库地址 |
| 是否禁止商用 | **否。** 原文明确授予"贩售软件的副本"的权利 |
| 是否允许二次开发分发 | **是。** 明确授予"修改、合并、出版、发行、再授权" |
| 是否有 copyleft 传染 | 否（MIT 非传染性） |
| 免责声明性质 | `Disclaimer.md` 只做责任免除与合法使用要求，**不构成使用许可限制** |

### 2.2 需要注意的"双 License 文件"现象

`Aabyss-Team/ARL` 根目录**同时存在两个许可文件**：

| 文件 | 内容 | 大小 |
|---|---|---|
| `LICENSE` | MIT License, **Copyright (c) 2024 Aabyss-Team** | 1089 字节 |
| `LICENSE.md` | MIT许可证, **版权所有 (c) 2023 tophant**（原版，含署名条款） | 997 字节 |

GitHub 侧识别为 `license: MIT`。**未确认**维护者为何保留两份，但从条款上看两者都是 MIT，**均无商用限制**。二次开发时建议在 NOTICE 中同时保留 tophant 2023 与 Aabyss-Team 2024 的版权声明以规避争议。

### 2.3 第三方依赖的授权雷区（与 ARL 自身无关，但会传导）

| 依赖 | 授权情况 | 风险 |
|---|---|---|
| ARL-NPoC（PoC 引擎，ARL 核心） | **MIT，Copyright (c) 2024 Aabyss-Team** [原文](https://raw.githubusercontent.com/Aabyss-Team/ARL-NPoC/master/LICENSE) | 低 |
| **GeoLite2-City.mmdb / GeoLite2-ASN.mmdb** | **MaxMind GeoLite2 EULA**，与 MIT 无关，对再分发与商用有独立约束 | **需单独评估**：[Commercial License for GeoLite](https://support.maxmind.com/knowledge-base/articles/commercial-license-for-geolite)、[GeoLite2 EULA](https://www.sonicwall.com/medialibrary/legal/third-party-licenses/GeoLite2.pdf) |
| 指纹库 `dicts/webapp.json`（657 KB） | 数据来源疑似 wappalyzer 指纹集；Wappalyzer 历史上为 **GPL-3.0**（见 [chandusekhar/wappalyzer GPLv3 提交](https://github.com/chandusekhar/wappalyzer/commit/eab30f3697f52943b633c644fb2b2e28d2dbe5db)） | **未确认**该 json 的确切来源与授权，若确为 GPL 数据则分发需谨慎 |
| nuclei | MIT（社区共识） | 低，**未逐字核实** |
| PhantomJS | BSD（社区共识） | 低，但**已停止维护**（安全风险 > 授权风险） |
| massdns | 随仓库内置二进制 `app/tools/massdns` | **未确认**其内置二进制的构建来源与版本 |

> **重要提示：** 本节的"未确认"项建议在正式立项前由法务/合规做一次 SBOM 级别的核对，尤其是 **GeoLite2** 与 **webapp.json**。

---

## 3. 技术栈明细

### 3.1 后端

| 组件 | 版本 / 事实 | 来源 |
|---|---|---|
| 语言 | Python **3.6**（README badge 明示） | [README](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/README.md) |
| Web 框架 | **Flask 2.0.3** + **Werkzeug 2.0.3** | [requirements.txt](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/requirements.txt) |
| API 框架 | **flask-restx 1.0.3**（提供 Swagger） | 同上、[main.py](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/main.py) |
| WSGI | gunicorn 20.1.0 | requirements.txt |
| 任务队列 | **Celery 5.1.2** | 同上 |
| 消息中间件 | **RabbitMQ**（`amqp://arl:arlpassword@localhost:5672/arlv2host`） | [config.yaml.example](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/config.yaml.example) |
| 数据库 | **MongoDB**（驱动 pymongo **3.13.0**；默认库 `arl`） | 同上 |
| 定时/周期任务 | `crontab 0.23.0` + 自研 `arl-scheduler` 服务 | requirements.txt、`misc/arl-scheduler.service` |
| 其他关键库 | dnspython 2.2.1、tld 0.12.6、geoip2 2.9.0、mmh3 3.0.0、pyquery 1.4.3、openpyxl 3.0.0、psutil 5.7.2、PyYAML **5.4.1** | requirements.txt |

> 依赖版本普遍冻结在 2021–2022 年，直接升级会触发连锁破坏（见 §6）。

### 3.2 前端

| 项 | 事实 |
|---|---|
| 技术 | **Vue + Ant Design Vue**（从产物文件名可判定：`npm.vue~daa565d3.*.js`、`npm.ant-design-vue~*.*.js`、`runtime.*.js`、webpack chunk 风格） |
| 是否可改 | **不可以直接改源码** —— 仓库内只有 `docker/frontend/js/*.js` 等**已编译产物** |
| 构建工具 | **未确认**（无 `package.json` / 前端工程目录） |
| 典型 chunk | `taskList~*.js`、`taskDetail~*.js`、`groupAssetsManagement~*.js`、`search~*.js`、`pocList~*.js` |

### 3.3 内置 / 外部工具链

| 工具 | 用途 | 证据 |
|---|---|---|
| **massdns** | 域名爆破的 DNS 解析引擎（subprocess 调用内置二进制） | `app/tools/massdns`；[massdns.py](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/services/massdns.py) |
| **nmap** | 端口扫描 / 服务识别 / 操作系统识别（python-nmap 封装 `PortScanner`） | [portScan.py](https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/services/portScan.py) |
| **PhantomJS** | 站点截图 + 指纹识别执行环境 | `app/tools/phantomjs`、`app/tools/screenshot.js`、`app/tools/driver.js`、`app/tools/wappalyzer.js` |
| **wappalyzer.js** | Web 指纹识别引擎 | 同上 |
| **nuclei** | PoC 扫描（独立调用） | `app/services/nuclei_scan.py`、`app/routes/nuclei_result.py` |
| **ARL-NPoC / xing** | 自研 PoC + 协议识别 + 弱口令引擎（**独立仓库**，需单独安装） | `app/services/npoc.py`、`npoc_service.py` |
| **WebInfoHunter (WIH)** | 从 JS 中提取域名/AK-SK 等 | `app/services/infoHunter.py` + `dicts/wih_rules.yml` |
| **GeoIP 库** | IP 归属 / ASN | `GeoLite2-City.mmdb`、`GeoLite2-ASN.mmdb` |

### 3.4 部署方式

| 方式 | 说明 |
|---|---|
| **一键脚本（源码 + Docker 二合一）** | `misc/setup-arl.sh`（41 KB）——README 称支持 `CentOS7/8/Rocky 8.10` 与 `Ubuntu 20.04` |
| **Docker 镜像** | 社区维护：`honmashironeko/ARL-docker`，三档镜像（初始版 / 部分指纹版 / 全量指纹版） |
| **Docker Compose** | `docker/` 下含 `Dockerfile`、`mongo-init.js`、`nginx.conf`、`worker/`；容器划分 `arl_web` / `arl_worker` / `arl_scheduler` / `arl_mongodb` / `rabbitmq` |
| **systemd（源码安装）** | `misc/arl-web.service`、`arl-worker.service`、`arl-worker-github.service`、`arl-scheduler.service`，前置 `mongod` + `rabbitmq-server` + `nginx` |
| 访问入口 | `https://IP:5003/`（Nginx 前置）；后端 Flask 自身监听 5018 |
| 系统要求 | CPU 4 线程 / 内存 8 GB / 带宽 10 M；**不支持 Windows** |

---

## 4. 功能覆盖度（针对指定的四项能力）

### 4.1 输入根域名 → 被动子域名收集

**支持。** 数据源插件位于 `app/services/dns_query_plugin/`，共 **13 个**文件：`alienvault.py`、`certspotter.py`、`chaos.py`、`crtsh.py`、`fofa.py`、`hunter_qax.py`、`passivetotal.py`、`quake_360.py`、`rapiddns.py`、`securitytrails.py`、`virustotal.py`、`zoomeye.py`（+ `__init__.py`），与 README"已支持的数据源为13个"一致。

`config.yaml.example` 中的默认启用状态：

| 默认启用 | 默认关闭（需 key） |
|---|---|
| `alienvault`、`certspotter`、`crtsh`、`fofa`、`rapiddns` | `hunter_qax`、`passivetotal`、`quake_360`、`securitytrails`、`virustotal`、`zoomeye`、`chaos` |

补充被动能力：
- **ARL 历史查询**（`arl_search`）：复用本系统历史任务结果，形成自增强闭环。
- **搜索引擎调用**（`search_engines`）：从搜索结果反推子域与 URL。
- **WIH**：从 JS 中回捞域名（`web_info_hunter`）。

**弱项 / 缺失：**
- 数据源**无统一接口抽象与基类**，每个插件各自实现 HTTP 请求与参数处理，新增源需要照抄样板代码。
- 插件目录**无热加载、无版本隔离、无内置熔断/限流**——第三方源限流或失效时只能逐个 patch。
- 免费源（crtsh、rapiddns、alienvault）稳定性依赖外部，社区长期反馈"失效/限流"问题。
- **未集成 OneForAll 等主流子域工具**；（老文）有作者明确指出"域名收集这块还有很大改进空间，比如 OneForAll 就是一个很优秀的子域名收集工具，可以移植进来"——见 [ARL 灯塔资产管理系统 二](https://www.anquanke.com/post/id/253480)。

### 4.2 主动子域名爆破

**支持，实现路径清晰：**

1. `DomainBrute`（`app/tasks/domain.py`）加载字典 → `services.mass_dns()`；
2. `massdns.py`：把 `word + "." + base_domain` 写入临时文件，以 subprocess 调用 `app/tools/massdns`，参数为 `-q -r <dnsserver> -o S -w <out> -s <concurrent> --root`，超时上限写死 **5×24×60×60 秒**（5 天）；
3. 解析输出，丢弃 `record in wildcard_domain_ip` 的条目。

**字典规格：**
- 大字典 `app/dicts/domain_2w.txt`，约 **133 KB**，README 称"常用 2万字典大小"。
- 测试字典 `app/dicts/domain_dict_test.txt`，**40 字节**。
- 智能组合字典 `app/dicts/altdnsdict.txt`，**819 字节**。

**AltDNS 智能生成**（`app/services/altDNS.py`）：移植自 `ProjectAnte/dnsgen`，含 5 种变换（`insert_word_every_index` / `insert_num_every_index` / `prepend_word_every_index` / `append_word_every_index` / `replace_word_with_word`），并在 `tasks/domain.py::AltDNS` 中叠加内建词表（`test adm admin api app beta demo dev front int internal intra ops pre pro prod qa sit staff stage test uat`）与已发现子域的**频率 Top-N**（域名数 <1000 时取 50，否则 30）。

**主动爆破的明显弱项：**
- **2 万字典偏小**（现代主流工具常用 10 万～百万级）。
- **AltDNS 会主动自我禁用**：见 `tasks/domain.py`：
  - 域名数 > 300 且存在泛解析 → `logger.warning("... 域名泛解析, 当前子域名{}, 大于300, 不进行alt_dns")` 直接 return；
  - 监控任务（`monitor`）域名数 ≥ 800 → `skip alt_dns on monitor`。
- AltDNS 结果用**硬编码阈值**二次过滤：`records_count[record] >= 15` 即剔除（`altDNS.py` 末尾）。

### 4.3 DNS 解析 → IP

**支持。** 两种路径：

| 场景 | 实现 |
|---|---|
| 爆破结果 | `DomainBrute._resolver()` → `services.resolver_domain(domains)`（`app/services/resolverDomain.py`），批量解析，随后构建 `DomainInfo`（区分 A / CNAME） |
| 被动源结果 | `services.build_domain_info()`（`app/services/buildDomainInfo.py`） |

约束与细节：
- `Config.DOMAIN_MAX_LEN = 25`：子域名长度超过"根域名长度 + 25"的直接丢弃。
- 黑名单过滤：`dicts/blackdomain.txt`、`dicts/blackhexie.txt`、`dicts/black_asset_site.txt`、`FORBIDDEN_DOMAINS`。
- DNS 服务器列表独立配置：`app/dicts/dnsserver.txt`（仅 **48 字节**，即内置极少数公共 DNS）。
- 泛解析判定：`not_found_domain_ips` 属性通过查询一个随机伪造域名（`"at" + random4 + "." + base_domain`）获取其 IP 与 CNAME，作为"泛解析 IP 集合"。

**泛解析处理的实际强度（关键弱项）：**
1. 假域名法 + 精确 IP 匹配 + `records_count >= 15` 计数阈值 + **`MAX_MAP_COUNT = 35`**（同一 record 出现超过 35 次即丢弃）。均为**启发式硬编码**，对"泛解析返回大量不同 IP、或返回 CDN IP 池"的场景会漏判/误判。
2. 若泛解析 IP 集合为空（例如假域名恰好不解析），后续过滤基本失效。

### 4.4 探活（端口 + HTTP 指纹）

**支持，两条分支：**

**分支 A：开启端口扫描** → `ScanPort`（`tasks/domain.py`）→ `services.port_scan()` → `nmap.PortScanner().scan()`。

nmap 参数构造逻辑（`app/services/portScan.py`）实测：

| 条件 | 参数变化 |
|---|---|
| 基础 | `-sT -n --open` |
| `service_detect` | `+ -sV`，host_timeout +5 min |
| `os_detect` | `+ -O`，host_timeout +4 min |
| 端口数 > 60 | `+ -PE -PS<alive_port>`，max_retries=2 |
| 端口数 ≤ 60 且非全端口 | `+ -Pn` |
| **全端口 `0-65535`** | `max_host_group=2`、`min_rate≥800`、`parallelism≥128`、`+ -PE -PS...`、host_timeout +5 min |
| 恒定附加 | `--max-rtt-timeout 800ms --min-rate <n> --script-timeout 6s --max-hostgroup <n> --host-timeout <n>s --min-parallelism <n> --max-retries <n>` |
| 结果过滤 | 单 IP 端口数 > 600 时，除 80/443 外全部丢弃 |

**CDN 识别**：`dicts/cdn_info.json`（约 11.9 KB）+ CNAME 规则 + "IP ≥ 4 个即判 CDN"。开启"跳过 CDN"时不扫端口，**直接构造假的 80/443 开放记录**（`build_fake_cdn_ip_info`）。

**分支 B：未开启端口扫描** → `services.probe_http()`（`app/services/probeHTTP.py`）
- 对每个域名同时试 `https://` 与 `http://`；
- 请求参数：`timeout=(3, 2)`（连接 3s / 读 2s）、`stream=True`，**默认并发 10**；
- 状态码 `[502, 504, 501, 422, 410]` 视为跳过；
- 之后"https 优先、同 host 的 http 丢弃"。

**站点指纹识别**：`services.web_analyze()`（`app/services/webAnalyze.py`）+ PhantomJS 运行 `app/tools/wappalyzer.js`，指纹字典 `app/dicts/webapp.json`（657 KB）；另有 `utils/fingerprint.py`、`services/fingerprint_cache.py`、`routes/fingerprint.py` 与 `misc/fingerprint.json`（3 MB，备份仓/指纹增强版）。

**探活的强项与弱项：**

| 强项 | 弱项 |
|---|---|
| 有"跳过 CDN、不做无意义扫描"的工程取舍 | **PhantomJS 已停止维护**，无法渲染现代 SPA；ARL-Next 的公开宣传即以此为核心改造点 |
| nmap 参数按端口规模自适应，有速率与并行度控制 | 探活**并发仅 10**（`probe_http` 默认），对数千子域明显偏慢 |
| 有服务识别、OS 识别、SSL 证书获取的完整链路 | 指纹识别串行于站点流程中，无独立分布式指纹服务 |

---

## 5. 架构要点

### 5.1 任务流水线怎么组织的

**下发链路**（有社区文章对源码做过逐行梳理，可交叉验证，见 [ARL 灯塔资产管理系统 二](https://www.anquanke.com/post/id/253480)）：

```
POST app/routes/task.py (ARLTask.post)
  → submit_task(task_data)              # 任务记录写入 mongo 'task' 集合
  → celerytask.arl_task.delay(options)  # 投递到 RabbitMQ，返回 celery_id 回写数据库
  → app/celerytask.py 按 celery_action 分发
       ├─ CeleryAction.DOMAIN_TASK → app/tasks/domain.py::domain_task
       └─ CeleryAction.IP_TASK     → app/tasks/ip.py::ip_task
```

**域名任务 `DomainTask.run()` 是严格串行的 9 段链**（`app/tasks/domain.py`）：

| 序 | 方法 | 内容 | 状态字段 |
|---|---|---|---|
| 1 | `domain_fetch()` | 爆破 → `dns_query_plugin` → `arl_search` → `alt_dns` | `domain_brute` / `dns_query_plugin` / `arl_search` / `alt_dns` |
| 2 | `search_engines()` | 搜索引擎抓取 URL 与子域 | `search_engines` |
| 3 | `start_ip_fetch()` | `port_scan` → `ssl_cert` → `save_service_info` → `save_ip_info` | `port_scan` / `ssl_cert` |
| 4 | `start_site_fetch()` | `find_site` → `WebSiteFetch.run()`（fetch_site → site_identify → save → 截图 → 爬虫 → 文件泄露 → nuclei → WIH） | `find_site` / `fetch_site` / `site_capture` / `site_identify` / `site_spider` / `file_leak` / `nuclei_scan` / `web_info_hunter` |
| 5 | `start_find_vhost()` | Host 碰撞 | `findvhost` |
| 6 | `start_poc_run()` | `npoc_service_detection` → `poc_run` → 弱口令 | `npoc_service_detection` / `poc_run` / `weak_brute` |
| 7 | `start_wih_domain_update()` | WIH 发现域名回灌 | — |
| 8 | `common_run()` | 统计 `stat_finger` / `cip` / `task.statistic` + 资产同步 | — |
| 9 | 收尾 | `status = TaskStatus.DONE` + `end_time` | `done` |

**架构性判断（与社区一致）：** 这是"**一条链跑到底**"的设计。优点是下发一次即完成全流程；缺点是**单任务周期极长、中间环节不可干预、任一环节异常易导致整链失败**。社区原文即指出："单个任务等待周期过长。中间无法进行操作，某个环节出现不可控错误时，导致整个任务失效，损失相对较大。"

**并行模型：** 任务内**串行**；任务间并行依赖 Celery worker 数量。Celery 按 routing key 分为两类：`CeleryRoutingKey.ASSET_TASK = "arltask"` 与 `GITHUB_TASK = "arlgithub"`（对应独立的 `arl-worker-github.service`）。

### 5.2 插件 / 扩展机制

| 扩展点 | 机制 | 二开友好度 |
|---|---|---|
| 子域数据源 | `app/services/dns_query_plugin/<name>.py`，由 `app/utils/query_loader.py` 加载，`QUERY_PLUGIN` 配置 `enable` 开关 | **中**（可加，但需照抄样板、无基类、无热加载） |
| NPoC / PoC | 独立包 **ARL-NPoC**（xing 框架），插件位于 `/opt/ARL-NPoC/xing/plugins/poc`，继承 `BasePlugin` 实现 `verify()` | **中上**（模式清晰，但有部署同步成本，见 §6） |
| nuclei PoC | 直接调用外部 nuclei 及其模板 | 高（外部工具自治） |
| Web 指纹 | `app/dicts/webapp.json` + `misc/fingerprint.json` | 高（改数据即可，有 ADD-ARL-Finger 脚本辅助） |
| WIH 规则 | `app/dicts/wih_rules.yml` | 高 |
| 任务策略 | Web `policy` 集合 → 映射为 task `options` | 高（无需改码即可组合能力） |
| 任务类型 | `app/modules/__init__.py` 中的 `CeleryAction` 枚举 + `app/celerytask.py` 分发 + `app/routes/task.py` 提交 | **低**（新增任务类型必须改多处） |

### 5.3 API 是否开放

**开放，且是标准 REST + Swagger。**

- 框架：`flask_restx.Api`，`prefix="/api"`，**Swagger 文档在 `/api/doc`**。
- 认证：`ApiKeyAuth`，**Header 名 `Token`**，密钥来自配置项 **`ARL.API_KEY`**；`ARL.AUTH` 控制是否开启认证（默认 `true`）。
- **33 个 namespace**（`app/main.py` 实测）：`task`、`site`、`domain`、`ip`、`url`、`user`、`image`、`cert`、`service`、`fileleak`、`export`、`asset_scope`、`asset_domain`、`asset_ip`、`asset_site`、`scheduler`、`poc`、`vuln`、`batch_export`、`policy`、`npoc_service`、`task_fofa`、`console`、`cip`、`fingerprint`、`stat_finger`、`github_task`、`github_result`、`github_scheduler`、`github_monitor_result`、`task_schedule`、`nuclei_result`、`wih`、`asset_wih`。

**对外集成能力评估：** 具备"外部系统下发任务 + 拉取资产"的完整接口面，这是 ARL 作为底座**最被低估的优点**。

**API 层的弱点：**
- 响应不是裸资源，而是 `{message, code, data}` 自定义包装，错误码是项目内自造字典（`error_map` 从 102 到 1610），**换前端需重写适配层**。
- 无细粒度 RBAC（仅登录态 + 单一 API key）。
- 无 OpenAPI 客户端生成、无版本化 API 路径（`/api/v1` 之类）。

### 5.4 数据表 / 资产模型大致结构

MongoDB 集合（从源码 `utils.conn_db('<name>')` 与路由中归纳）：

| 集合 | 含义 | 关键字段（示例） |
|---|---|---|
| `task` | 任务 | `name`、`target`、`type`、`task_tag`、`status`、`options`、`celery_id`、`statistic`、`start_time`、`end_time`、`service[]` |
| `domain` | 子域名资产 | `domain`、`type`(A/CNAME)、`record[]`、`ips[]`、`fld`、`source`、`task_id` |
| `ip` | IP 资产 | `ip`、`domain[]`、`port_info[]`、`os_info`、`cdn_name`、`task_id` |
| `site` | 站点 | `site`、`title`、`status`、`finger[]`、`screenshot`、`task_id` |
| `url` | URL（爬虫/搜索引擎） | `site`、`fld`、`source`、`task_id` |
| `cert` | SSL 证书 | `ip`、`port`、`cert`、`task_id` |
| `service` | 服务聚合 | `service_name`、`service_info[]`、`task_id` |
| `vuln` | 漏洞（NPoC/弱口令/Host碰撞） | `plg_name`、`vuln_name`、`target`、`verify_data`、`task_id` |
| `nuclei_result` | nuclei 结果 | + `task_id`、`save_date` |
| `fileleak` | 文件泄露 | `site`、`task_id` |
| `wih` | WebInfoHunter 记录 | + `fnv_hash` 去重、`task_id` |
| `npoc_service` | 协议识别结果 | `target`、`task_id` |
| `policy` | 策略 | `policy.domain_config`、`policy.ip_config`、`policy.site_config` |
| `asset_scope` | 资产组/范围 | 类型 `AssetScopeType.DOMAIN / IP` |
| `stat_finger` / `cip` | 指纹统计 / C 段统计 | `task_id` |
| `user` | 用户 | `username`、`password`(hex_md5(salt+pass)) |
| `task_schedule`、GitHub 系列集合 | 计划任务 / GitHub 监控 | — |

模块层定义位于 `app/modules/__init__.py`，含 `TaskStatus`、`TaskTag`、`TaskType`、`TaskScheduleStatus`、`CollectSource`、`TaskSyncStatus`、`SchedulerStatus`、`AssetScopeType`、`PoCCategory`、`WebSiteFetchOption`、`WebSiteFetchStatus`、`CeleryAction`、`CeleryRoutingKey`、`error_map`。

**结构性债务：** 没有 ORM、没有 **schema 迁移机制**（无 Alembic 类工具）、没有数据模型版本号。改字段只能手写迁移脚本。

### 5.5 任务并发与限速如何控制

| 维度 | 机制 | 默认值 |
|---|---|---|
| 域名爆破并发 | `ARL.DOMAIN_BRUTE_CONCURRENT` → massdns `-s` | **300** |
| AltDNS 组合爆破并发 | `ARL.ALT_DNS_CONCURRENT` → massdns `-s` | **1500** |
| 任务间并发 | Celery worker 进程/并发数（部署时决定） + 两类 routing key 隔离 | **未确认**（取决于部署） |
| 端口扫描并行度 | `--min-parallelism`（`port_parallelism`） | **32** |
| 端口扫描速率 | `--min-rate`（`port_min_rate`） | **64**（全端口时强制 ≥800） |
| 端口扫描主机分组 | `--max-hostgroup` | 普通 **32**；全端口 **2** |
| 端口扫描主机超时 | `--host-timeout` | 基础 **300s**，+sV **+300s**，+O **+240s**，全端口 **+300s**（可被 `host_timeout` 覆盖） |
| HTTP 探活并发 | `ProbeHTTP(concurrency=)` | **10** |
| 站点截图并发 | `site_screenshot(..., concurrency=)` | **6** |
| SSRF 防护 | `ARL.BLACK_IPS` 在 `port_scan` 入口 `filter(utils.not_in_black_ips)` | `127.0.0.0/8`、`0.0.0.0/8`（**注意：默认并不含 10/172/192 内网段**） |
| 代理 | `PROXY.HTTP_URL`，README 说明"端口扫描不会走代理" | 空 |

---

## 6. 已知痛点（基于真实 issue 与社区文章）

### 6.1 Issue 分布实测（Aabyss-Team/ARL，60 个 issue）

用 GitHub Search API 按评论数排序抓取后，**高互动 issue 几乎 100% 是部署类问题**：

| # | 评论数 | 标题 | 链接 |
|---|---|---|---|
| 2 | **16** | docker 仓库也删了怎么快速搭建 | [#2](https://github.com/Aabyss-Team/ARL/issues/2) |
| 8 | 15 | 源码安装 xing 模块问题 | [#8](https://github.com/Aabyss-Team/ARL/issues/8) |
| 30 | 12 | 镜像就是拉取不到.... | [#30](https://github.com/Aabyss-Team/ARL/issues/30) |
| 28 | 9 | docker 无法拉取镜像 | [#28](https://github.com/Aabyss-Team/ARL/issues/28) |
| 23 | 9 | 连接不上 | [#23](https://github.com/Aabyss-Team/ARL/issues/23) |
| 10 | 8 | 登录提示用户名或密码错误，重置提示没有 `arl_mongodb` 容器 | [#10](https://github.com/Aabyss-Team/ARL/issues/10) |
| 12 | 7 | docker-arl-all 的账号密码无法登录 | [#12](https://github.com/Aabyss-Team/ARL/issues/12) |
| 13 | 6 | docker 安装报错，所有接口返回不到数据，重启后过段时间又不行 | [#13](https://github.com/Aabyss-Team/ARL/issues/13) |
| 9 | 6 | 任务创建报错 | [#9](https://github.com/Aabyss-Team/ARL/issues/9) |
| 37 | 6 | 重启云服务器后系统无法启动 | [#37](https://github.com/Aabyss-Team/ARL/issues/37) |
| 64 | 1 | 使用 docker 安装开始部署时报错（`registry-1.docker.io` timeout） | [#64](https://github.com/Aabyss-Team/ARL/issues/64) |
| 84 | 1 | 5003 端口十几秒后消失 | [#84](https://github.com/Aabyss-Team/ARL/issues/84) |
| 61 | 1 | 随机密码无法显示在控制台 | [#61](https://github.com/Aabyss-Team/ARL/issues/61) |
| 60 | 1 | 源码安装成功后随机密码为空 | [#60](https://github.com/Aabyss-Team/ARL/issues/60) |
| 85 | 1 | 部署完了如何修改 5003 端口 | [#85](https://github.com/Aabyss-Team/ARL/issues/85) |
| 81 | 1 | docker 安装的怎么添加 fofa api | [#81](https://github.com/Aabyss-Team/ARL/issues/81) |
| 76 | 1 | 国内 vps 不能安装 | [#76](https://github.com/Aabyss-Team/ARL/issues/76) |
| 80 | 1 | 添加任务时报错 | [#80](https://github.com/Aabyss-Team/ARL/issues/80) |
| 56 | 1 | 优化反馈：建议默认注释掉 `172.16.0.0/12` 网段 | [#56](https://github.com/Aabyss-Team/ARL/issues/56) |

**具体证据摘录：**
- #84 的日志显示 `docker compose` 起不来是因为 `arl_web.log` 被**挂载成了目录**：`Error: 'arl_web.log' isn't writable [IsADirectoryError(21, 'Is a directory')]`，`arl_web` 持续 `Restarting`，端口随之消失。
- #64 的报错是 `Get "https://registry-1.docker.io/v2/": context deadline exceeded`——国内网络拉取 Docker Hub 失败。
- #56 指出默认配置注释了 `10/192` 网段但**未注释 `172.16.0.0/12`**，导致 `172.x` 目标被 SSRF 黑名单拦截。

### 6.2 泛解析（wildcard）处理

**这是代码层面最明确的薄弱点**，且有多处硬编码：
- 假域名法（`not_found_domain_ips`）只覆盖"泛解析解析到固定 IP"的简单情形。
- `altDNS.py` 末尾：`records_count[info['record']] >= 15` 即丢弃。
- `tasks/domain.py`：`MAX_MAP_COUNT = 35`；子域 >300 且有泛解析时**直接跳过整个 AltDNS**，并打印 warning。
- 社区侧普遍把"泛解析过滤"当作独立卖点来宣传——例如有项目在介绍中明确列出"异步资产发现 · **泛解析过滤** · 自研 YAML PoC 引擎 · 负向对照校验防误报"，反向印证这是 ARL 的公认痛点（见 [hediwen831-star/attack-surface](https://github.com/hediwen831-star/attack-surface)）。
- **严谨说明：** 未检索到针对 ARL 泛解析问题的**独立 issue 编号**，上述结论主要来自**源码证据 + 社区横向对照**。

### 6.3 资源占用 / 性能瓶颈

| 痛点 | 证据强度 | 说明 |
|---|---|---|
| 单任务链路过长 | **强（源码 + 社区文章）** | `DomainTask.run()` 9 段全串行；社区原文称"单个任务等待周期过长。中间无法进行操作" |
| HTTP 探活并发仅 10 | **强（源码）** | `probe_http(domain, concurrency=10)` |
| 截图并发仅 6 | **强（源码）** | `site_screenshot(..., concurrency=6)` |
| nmap 全端口扫描极慢 | **强（源码）** | host_timeout 基础 300s + 全端口再 +300s；`max_host_group` 降到 2；单 IP 端口数 >600 时结果被丢弃 |
| 中途失败即整链失败 | **强（源码 + 社区）** | 异常统一 `except` → `TaskStatus.ERROR`，无断点续跑 |
| 任务卡在某个状态 | **中（issue）** | #13 描述"所有接口返回不到数据，重启 docker 后能访问，过段时间再次不行" |
| MongoDB 数据膨胀 | **弱 / 未确认** | 未找到直接 issue。结构上 `domain`/`site`/`url`/`wih` 每任务写入且无 TTL 索引，属**推断** |

### 6.4 被动源 / 域名查询插件失效

- `config.yaml.example` 中 **13 个源里有 7 个默认关闭**（hunter/quake/securitytrails/virustotal/zoomeye/chaos/passivetotal 均需 key），开箱可用性依赖 crtsh / rapiddns / alienvault / certspotter / fofa。
- 插件层**无熔断、无重试退避、无健康状态展示**（源码层判断）。
- **未确认**：未找到具体 issue 编号逐个指认"某源失效"。
- 另有一类"隐性限流"痛点由社区文章给出且证据确凿：**Fofa 导入降重问题**。作者定位为 `FofaClient` 调用 `/api/v1/search/all` 时 `page_size` 默认 9999，且**没有实现翻页**，导致 13,492,282 条的结果集在 ARL 里"只会跑几千条，然后反复运行结果一致"，最后确认为 Fofa API 单次最多返回 10000 条的限制。见 [ARL分析与进阶使用](https://zone.ci/secarticles/wx/570554.html)。

### 6.5 部署与升级困难

- **Docker 镜像仓库被删**：#2（16 条评论）就是"docker 仓库也删了怎么快速搭建"。
- **国内网络拉不动**：#28、#30、#64、#76（"咱那个灯塔 国内 vps 不能安装呀"）。
- **脚本兼容性**：`setup-arl.sh` 采用 yum；非 CentOS 需自行 `apt install docker.io`（#23 中用户的疑惑原文）。
- **Python 3.6 + 冻结依赖**：`requirements.txt` 锁死 2021 年版本；社区文章指出 `pip3 install -r requirements.txt` 时 **PyYAML 直接装会报错**，需要先单独 `pip install PyYAML`（见 [ARL分析与进阶使用](https://zone.ci/secarticles/wx/570554.html)）。
- **升级无平滑路径**：容器化部署下更新 PoC 需**分别同步到 `arl_web` 与 `arl_worker` 两个容器**的 `/opt/ARL-NPoC/xing/plugins/`（同上文章），无共享卷、无版本管理。
- **不支持 Windows**（README 明示）。
- **未确认**：未找到完整的历史版本升级/迁移指南。

### 6.6 UI / 体验

- **前端源码缺失**导致 UI 定制成本极高（本报告 §3.2、§7 的核心风险）。
- 随机密码不显示/为空：#61、#60。
- 端口修改无文档：#85。
- **未确认**：未找到系统性的 UI 体验 issue 汇总；ARL-Next 的"现代化前端栈、彻底重构前端"宣传可作为间接佐证。

### 6.7 安全相关问题

- **未确认存在针对 ARL 的公开 CVE。** 本次针对 "ARL 灯塔 CVE / 未授权访问 / SSRF" 的检索**未返回任何权威 CVE 记录或厂商通告**。请勿引用未经证实的编号。
- 代码层面可确认的**安全设计取舍**（非漏洞，但部署时是风险）：
  1. `Config.AUTH = False`（源码默认），但 `config.yaml.example` 与 `misc/arl.conf` 指向 `true`；README 明确警告"`ARL.AUTH` 是否开启认证，不开启有安全风险"。
  2. `ARL.BLACK_IPS` **源码默认只有 `127.0.0.0/8` 和 `0.0.0.0/8`**，不含 RFC1918 内网段；配置样例只额外屏蔽了 `172.16.0.0/12` 与 `100.64.0.0/10`，`10/8`、`192.168.0.0/16` 是**注释掉的**。这意味着**默认配置下 ARL 可以扫内网**，在云上部署是明确的 SSRF 面（#56 也印证了这个困惑）。
  3. 用户口令存储为 `hex_md5('arlsalt!@#' + password)`——**无每用户盐、无 KDF**，离线破解成本极低（见 README 重置密码段）。
  4. README 公布默认口令 `admin/arlpass`。
  5. PhantomJS 长期无维护，是供应链风险点。

---

## 7. 作为底座的改造入口、工作量与风险

### 7.1 改造入口（按"改动半径"分层）

**A 层：几乎不动架构，纯外围集成（推荐路线）**
| 目标 | 入口 |
|---|---|
| 外部系统下发任务 / 拉资产 | REST API `/api/doc`，Header `Token` = `ARL.API_KEY` |
| 监控结果外推 | `WEBHOOK.URL` + `WEBHOOK.TOKEN`（`IP/域名监控和站点监控结束后 POST JSON`，见 `app/services/webhook.py`、`helpers/message_notify.py`） |
| 消息通知 | 钉钉 / 飞书 / 企业微信 / 邮件（`config.yaml` 对应段 + `utils/push.py`） |

**B 层：改配置或数据即可**
| 目标 | 入口 |
|---|---|
| 扩大爆破字典 | `ARL.DOMAIN_DICT`（配置文件路径即可） / `app/dicts/domain_2w.txt` |
| 改端口集 | `ARL.PORT_TOP_10` / `app/config.py::Config.TOP_1000`、`TOP_100` |
| 改泛解析过滤阈值 | `app/services/altDNS.py`（`>= 15`）、`app/tasks/domain.py`（`MAX_MAP_COUNT = 35`、`>300` 跳过 AltDNS、`DOMAIN_MAX_LEN = 25`） |
| 加指纹 | `app/dicts/webapp.json`、`misc/fingerprint.json`（可用 `misc/ADD-ARL-Finger.py`） |
| 改并发/限速 | `ARL.DOMAIN_BRUTE_CONCURRENT`、`ARL.ALT_DNS_CONCURRENT`；`port_parallelism`、`port_min_rate` |
| 改 SSRF 黑名单 | `ARL.BLACK_IPS`（**强烈建议至少补 `10/8`、`172.16/12`、`192.168/16`、`100.64/10`**） |
| 改 WIH 规则 | `app/dicts/wih_rules.yml` |

**C 层：插件层扩展（改动中等、收益最高）**
| 目标 | 入口 |
|---|---|
| 新增被动子域源 | 在 `app/services/dns_query_plugin/` 加一个 `.py`，并在 `config.yaml` 的 `QUERY_PLUGIN` 注册；加载器 `app/utils/query_loader.py`，调用入口 `app/services/dns_query.py::run_query_plugin` |
| 新增 PoC / 弱口令 / 协议识别 | **ARL-NPoC** 仓库 `xing/plugins/poc`，继承 `BasePlugin` 实现 `verify(self, target)`；ARL 侧通过 `app/services/npoc.py`、`npoc_service.py` 调用 |
| 新增 nuclei 模板 | 随 nuclei 自身管理 |

**D 层：核心改造（高风险、大工作量）**
| 目标 | 需要动的文件/模块 |
|---|---|
| 替换探活/指纹引擎（去 PhantomJS） | `app/services/webAnalyze.py`、`app/services/siteScreenshot.py`、`app/tools/phantomjs`、`app/tools/wrapWappalyzer.js`、`app/tools/wappalyzer.js`、`app/helpers/fingerprint_cache.py`、`app/utils/fingerprint.py`；`Config.SCREENSHOT_JS` / `DRIVER_JS` |
| 提升探活并发 | `app/services/probeHTTP.py`（`concurrency=10`）、`app/services/baseThread.py`（线程模型基类） |
| 任务编排解耦（拆串行为 DAG / 子任务可重试） | `app/tasks/domain.py::DomainTask`、`app/tasks/ip.py::IPTask`、`app/services/commonTask.py::WebSiteFetch`、`app/services/baseUpdateTask.py` |
| 新增任务类型 | `app/modules/__init__.py`（`CeleryAction`/`TaskType`） + `app/celerytask.py`（分发） + `app/routes/task.py`（提交） + `app/routes/__init__.py` |
| 换前端 | **必须重建前端工程**：只有 `docker/frontend/`（编译产物）可参考；新前端需适配 33 个 namespace 与 `{message, code, data}` 包装 |
| 数据模型演进 | 无 ORM/无迁移工具；需自建迁移脚本 + 索引（`app/utils/conn.py`、`app/helpers/*.py`、各 `tasks/*.py` 的 `conn_db(...)` 调用点） |

### 7.2 工作量与风险估计

> 以下为基于源码证据的**工程估计**，非实测数据；人员假设为熟悉 Python + Flask 的中级工程师。

| 改造包 | 估计工作量 | 主要风险 |
|---|---|---|
| ① 部署/环境解耦（Docker 化、依赖解冻、脱离 yum、修日志挂载） | 1–2 人周 | 低 |
| ② 指纹与截图引擎替换（PhantomJS → Chromium/Puppeteer）+ 探活并发提升 | 2–4 人周 | 中（`webAnalyze` 与截图耦合在站点流程中，需回归全流程） |
| ③ 子域收集增强（换字典、加源、重写泛解析判定、熔断限流） | 2–4 人周 | 中（泛解析阈值改动会直接改变结果集规模，需大量对拍） |
| ④ 任务编排重构（串行 → 可重试子任务/DAG） | 4–8 人周 | **高**（动的是 `DomainTask`/`IPTask` 主干与状态机，前后端状态展示同步改） |
| ⑤ 前端重建 | **6–12 人周** | **高**（**源码不存在**，等价于从零写一个资产测绘控制台） |
| ⑥ 数据模型/索引/迁移 | 2–4 人周 | 中高（无迁移框架，存量数据需兼容） |
| **只做 ①+②+③（"能用且好一点"）** | **约 1.5–2.5 人月** | 中 |
| **做到 ①～④+⑥（"可维护的底座"）** | **约 4–6 人月** | 高 |
| **全量（含前端重建）** | **≈ 6 人月以上**，已接近重写 | 极高 |

### 7.3 风险清单（按严重度）

| 级别 | 风险 | 依据 |
|---|---|---|
| **致命** | **前端源码不在仓库**，UI 层无法增量改造 | 仓库树中仅有 `docker/frontend/js/*.js` 编译产物 |
| **致命** | **上游已死**：官方仓库删除，备份 fork 自 2025-03 起无功能提交 | §1 提交记录 |
| **高** | 依赖链冻结在 Python 3.6 / Flask 2.0 / PhantomJS，安全与兼容双输 | requirements.txt、`app/tools/phantomjs` |
| **高** | 任务状态机与 `options` 字段硬编码，前端 UI 与状态字符串强耦合 | `BaseUpdateTask.update_task_field("status", ...)` + `app/modules/__init__.py` 状态枚举 |
| **中高** | 数据层无 ORM/无 schema 迁移，改模型成本高 | §5.4 |
| **中** | 默认 `BLACK_IPS` 不含内网段 → 内网扫描/SSRF 面 | `app/config.py`、#56 |
| **中** | md5 加盐口令存储、默认口令 | README、`app/utils/user.py` |
| **中** | **GeoLite2 mmdb** 与 **`webapp.json` 指纹数据**的独立授权需单独确认 | §2.3（含"未确认"项） |
| **低** | ARL 自身 MIT 授权 | §2.1 |

---

## 8. 是否建议以 ARL 为底座

### 判断：**不建议把 ARL 主仓当作"全栈二开底座"；建议把它当作"插件与 PoC 资产库"，最多做外围集成。**

**支持的理由：**

1. **授权不是障碍，反而很干净。** MIT + 署名，明确允许修改、分发、贩售，商用无限制——这是 ARL 少数完全没有问题的部分。
2. **上游已经停止演进。** 官方仓库删除、备份 fork 一年多无功能提交，"底座"最核心的价值（长期跟进、修 bug、吸收社区）实际不存在。你会成为事实上的唯一维护者。
3. **前端源码缺失是硬墙。** 任何涉及 UI 的需求都会退化成"重建一个控制台"，而控制台恰恰是资产测绘平台最耗人力的部分。
4. **任务链设计是串行单体。** 想做细粒度重试、子步骤并发、部分结果增量产出，都要动主干（`DomainTask`），风险与工期都不低。
5. **技术栈已经过期两代。** Python 3.6（EOL）、Flask 2.0、PhantomJS（已停止维护）、冻结依赖，任一次安全合规审查都会成为问题。

**反方理由（这些场景下 ARL 仍然值得用）：**

1. **时间预算 < 2 个月、只需要"子域收集 + 探活"能力。** ARL 这四项能力**全部开箱可用**，且 API 完整（33 个 namespace + Swagger + Token 认证），拿来做外围集成性价比很高。
2. **你只需要它的插件层。** `dns_query_plugin/`（13 个数据源）、ARL-NPoC（MIT、插件模式清晰）、`webapp.json` 指纹库、`wih_rules.yml`——这些是**可直接复用且授权干净**的资产，剥离出来用比整体二开划算。
3. **已经有社区替你交了重构的学费。** [ARL-Next](https://github.com/owl234/arl-next) 已经用 Vue 3 + Flask + Chromium/Puppeteer + CI/CD 重做了一遍，并把 ARL 的痛点当作卖点明确列出（"抛弃陈旧的 PhantomJS"、"彻底重构前端"、"现代化前后端分离架构……极佳的二次开发扩展性"）。**若必须"以 ARL 为起点做二开"，从 ARL-Next 这类重构版出发，比从 2.6.x 主仓出发更合理。**（注：ARL-Next 的 license、维护活跃度与代码质量本次**未核实**，采用前需独立评估。）

### 推荐决策路径

| 你的目标 | 建议 |
|---|---|
| 快速获得资产测绘能力、不打算长期投入研发 | **用 ARL（锁 commit），只做 API/Webhook 外围集成**，不为它改架构 |
| 要长期自研资产测绘平台、要按自己业务改 UI 和流程 | **不要基于 ARL 主仓**。要么以 ARL-Next 为起点并评估其质量，要么用 Python 3.11+ / FastAPI 或 Go + PostgreSQL + 现成引擎（subfinder/massdns/nmap/httpx/nuclei）重写——ARL 的 9 段流程本身没有不可替代的技术壁垒 |
| 预算有限，但愿意接受"前端不换、架构不动" | 落 **①+②+③ 改造包（约 1.5–2.5 人月）**，同时锁死 commit、补齐 `BLACK_IPS`、核实 GeoLite2 与指纹数据授权、把 PhantomJS 替换列为下一阶段 |

**一句话：** ARL 在 2024 年是一款优秀的资产测绘系统，但它的"底座价值"已经被上游停止维护和前端源码缺失消耗掉了；今天它的最高价值形态是**一套授权干净、可剥离复用的插件与 PoC 资产**，而不是一个可持续演进的二开平台。

---

## 附录：主要信源

**一手代码与元数据**
- 备份主仓：https://github.com/Aabyss-Team/ARL
- 仓库元数据 API：https://api.github.com/repos/Aabyss-Team/ARL
- 原仓库（已删除，404）：https://github.com/TophantTechnology/ARL
- 原版授权原文：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/LICENSE.md
- 备份仓 LICENSE（MIT 2024）：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/LICENSE
- 免责声明：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/Disclaimer.md
- 版本号：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/version.txt
- 依赖清单：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/requirements.txt
- 配置样例：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/config.yaml.example
- 全局配置：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/config.py
- API 与 namespace：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/main.py
- 数据模型与枚举：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/modules/__init__.py
- 域名任务流水线：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/tasks/domain.py
- 站点流程：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/services/commonTask.py
- massdns 封装：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/services/massdns.py
- AltDNS / 泛解析过滤：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/services/altDNS.py
- nmap 端口扫描：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/services/portScan.py
- HTTP 探活：https://raw.githubusercontent.com/Aabyss-Team/ARL/master/app/services/probeHTTP.py
- Releases：https://api.github.com/repos/Aabyss-Team/ARL/releases
- Commits：https://api.github.com/repos/Aabyss-Team/ARL/commits
- ARL-NPoC LICENSE：https://raw.githubusercontent.com/Aabyss-Team/ARL-NPoC/master/LICENSE

**Issue 证据**
- Issue 列表（按评论排序）：https://github.com/Aabyss-Team/ARL/issues?q=is%3Aissue+sort%3Acomments-desc
- #2 https://github.com/Aabyss-Team/ARL/issues/2 ｜ #8 .../issues/8 ｜ #30 .../issues/30 ｜ #28 .../issues/28 ｜ #23 .../issues/23 ｜ #10 .../issues/10 ｜ #12 .../issues/12 ｜ #13 .../issues/13 ｜ #9 .../issues/9 ｜ #37 .../issues/37 ｜ #56 .../issues/56 ｜ #60 .../issues/60 ｜ #61 .../issues/61 ｜ #64 .../issues/64 ｜ #76 .../issues/76 ｜ #80 .../issues/80 ｜ #81 .../issues/81 ｜ #84 .../issues/84 ｜ #85 .../issues/85

**社区文章与生态**
- ARL 灯塔资产管理系统 二（源码流程梳理 + 架构批评）：https://www.anquanke.com/post/id/253480
- ARL 灯塔资产管理系统（一）：https://www.anquanke.com/post/id/252321
- ARL 灯塔资产管理系统 三：https://www.anquanke.com/post/id/253481
- ARL 分析与进阶使用（Fofa 翻页缺陷 + PyYAML 坑 + PoC 编写 + 容器同步）：https://zone.ci/secarticles/wx/570554.html
- ARL-Next 灯塔二开版（社区重构版介绍）：https://www.gm7.org/archives/122277 ｜ https://github.com/owl234/arl-next
- ARL-docker（社区镜像维护）：https://github.com/honmashironeko/ARL-docker
- ADD-ARL-Finger（指纹扩展）：https://github.com/msmoshang/ADD-ARL-Finger
- 泛解析过滤被作为卖点的对照项目：https://github.com/hediwen831-star/attack-surface

**授权合规相关**
- MaxMind GeoLite 商用许可：https://support.maxmind.com/knowledge-base/articles/commercial-license-for-geolite
- GeoLite2 EULA（第三方存档）：https://www.sonicwall.com/medialibrary/legal/third-party-licenses/GeoLite2.pdf
- Wappalyzer GPLv3 佐证：https://github.com/chandusekhar/wappalyzer/commit/eab30f3697f52943b633c644fb2b2e28d2dbe5db
