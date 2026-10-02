# recon —— 事件驱动信息收集引擎

> 架构参照 **BBOT** 的事件驱动递归模块模型，能力实现参照 **ARL**（`E:\ARL\backend`）。
> **不使用 Docker**：进程内 asyncio 队列 + PostgreSQL，一条命令即可运行。

当前进度：**M1~M6 全部完成** —— 事件引擎、被动源、泛解析/爆破/置换、探活、Web 管理台、
周期监控与变更告警。**525 个测试全绿**，并已在真实域名上验证。

> 另外已完成**资产表跨 scan 去重**（资产从"某次扫描的产物"变成"长期存在的实体"）——
> 施工图与全部实测记录见 [`设计-资产表跨scan去重迁移.md`](设计-资产表跨scan去重迁移.md)。

## 仓库布局

```
recon/
├── backend/          # 全部 Python 代码（包 + 测试 + 脚本 + 打包配置）
├── frontend/         # 独立的 Vue 3 工程（自带依赖与构建）
├── data/             # 运行时产物：库、设置、截图（生成物，可删）
└── README.md
```

前后端各占一个顶层目录，互不掺和：后端不含任何前端源码，前端也不依赖 Python 目录结构。
运行时数据单独放在 `data/`，与代码分开 —— 删掉它不影响代码，删掉代码也不影响已有数据。

---

## 0. 存储

**PostgreSQL**（2026-09 从 SQLite 换过来）。

原来走 SQLite 是「零依赖单机」的取舍，但有四条它解不了：

| 问题 | SQLite | PostgreSQL |
|---|---|---|
| 多个扫描同时投影 | `database is locked`（单写者） | MVCC，互不阻塞 |
| 多人 / 多扫描同时用 | 一个文件锁扛不住 | 连接池 |
| 跨扫描检索与模糊搜索 | `LIKE '%x%'` 全表扫描 | `pg_trgm` 的 GIN 索引 |
| 资产上到十万级 | 查询变慢 | B-tree / GIN |

> 原来 `search_assets` 里写着「用 LIKE 而不是 FTS5：这是个内部工具、量级在万条以内」——
> 那个前提在上表四条上都不成立。选 `pg_trgm` 而不是 `tsvector` 是因为它
> **不改变查询语义**（仍是子串匹配，搜 `1.2.3` 这类 IP 片段照旧），
> 而且索引由 PostgreSQL 自动维护，不需要投影时同步 —— 原设计"不想维护一套索引"
> 的顾虑也就不存在了。

默认连 `postgresql://postgres@127.0.0.1:5432/recon`，用 `--dsn` 或 `RECON_DSN` 覆盖。
**首次要先建库**：`createdb recon`。`pg_trgm` 扩展建不上时会自动降级为顺序扫描，功能不变。

### 方言差异只有一处落点

存储层 881 行、50 个方法、上百条 SQL。逐条从 SQLite 方言翻成 PostgreSQL 方言
（`?` → `$n`、`lastrowid` → `RETURNING`）是纯手工劳动，每一条都是一个可能敲错的地方，
而且错了不会在编译期暴露。

所以换了个方向：**`core/storage/pg.py` 让 PostgreSQL 提供与 aiosqlite 一致的调用形状**，
50 个方法基本原样保留。要翻译的规则收敛到一个文件，每条都能单独测：

| aiosqlite 的形状 | PostgreSQL 怎么给 |
|---|---|
| `?` 占位符 | 运行时转 `$1..$n`（**逐字符扫描**，跳过字符串/注释里的 `?`） |
| `cur.lastrowid` | INSERT 自动补 `RETURNING id`（只对真有 `id` 列的表，查 `information_schema`） |
| `cur.rowcount` | 解析 `execute()` 的状态串（`UPDATE 3`） |
| `execute()` 既能 await 又能 `async with` | 同一个对象实现两套协议 |
| `await conn.commit()` | 空操作（asyncpg 每条语句自动提交） |

真正需要改语义的只有两处，都写在 `postgres.py` 里并加了注释：
**`LIKE` → `ILIKE`**（PostgreSQL 的 LIKE 区分大小写，照搬会"搜 admin 找不到 Admin"）、
**布尔列 `MAX()` → `OR`**（PostgreSQL 没有 `MAX(boolean)`）。

### 初始化：一条命令，Windows 与 Linux 通用

```bash
python -m core.storage.bootstrap
```

幂等，重复跑不会出错、不会覆盖数据。做四件事：建应用角色、建库、装 `pg_trgm`、指 owner。

```
  管理连接: postgresql://postgres@127.0.0.1:5432/postgres
  服务端 16.15 (编码 UTF8)
  已建角色 recon（免密）
  已建库 recon（UTF8 / LC_COLLATE=C / owner=recon）
  pg_trgm 扩展就绪

  完成。应用侧连接串：
      postgresql://recon@127.0.0.1:5432/recon
```

**应用以最小权限角色运行**（非超管、无 CREATEDB）。装扩展要高权限，
所以那是 bootstrap 的活 —— Web 进程不该有超管权限。

### 两个平台完全一致的三处

| | 取值 | 为什么 |
|---|---|---|
| **排序规则** | `LC_COLLATE='C'` `LC_CTYPE='C'` | 见下，**这是最关键的一条** |
| **编码** | `UTF8`，从 `TEMPLATE template0` 建 | 自定义排序规则必须从 template0 建 |
| **角色/库名** | `recon` / `recon` | 不含平台色彩 |

#### 为什么排序规则一定要是 `C`

1. **跨平台**：Windows 装的 PostgreSQL 默认是 `Chinese (Simplified)_China.936`
   这类**平台专有**的名字。换到 Linux 根本不存在，`pg_dump` / `pg_restore`
   搬库直接失败。
2. **跨版本**：用系统 locale（`en_US.UTF-8` 之类）还有个更隐蔽的坑 ——
   **glibc 升级会改变排序规则，而已有的 B-tree 索引不会自动重建**。
   索引顺序与数据实际顺序不一致，查询开始返回错结果或漏结果，
   PostgreSQL 只在启动时给一句 warning，很容易被忽略。
3. `C` 是字节序，任何平台、任何版本、任何 locale 都一样。
   代价是 `ORDER BY` 时大写排在小写前（ASCII 序）—— 资产表里是域名、
   IP、URL，基本都是小写，可以忽略。

> 已经建好的库排序规则不对？`python -m core.storage.bootstrap --recreate`
> （**会删掉现有数据**）。

### 部署到 Linux

```bash
# 1. 装 PostgreSQL 与 contrib（pg_trgm 在 contrib 包里）
sudo apt install postgresql postgresql-contrib      # Debian / Ubuntu
sudo dnf install postgresql16-server postgresql16-contrib   # RHEL / CentOS

sudo systemctl enable --now postgresql

# 2. 初始化（用超管连一次，之后应用不再需要超管）
sudo -u postgres python -m core.storage.bootstrap --password '你的密码'

# 3. 应用侧只需要一个环境变量
export RECON_DB_PASSWORD='你的密码'
python -m core --host 0.0.0.0 --token 你的访问令牌
```

**关于密码**：asyncpg **不读** `PGPASSWORD`，也不读 `~/.pgpass`（那是 libpq 的行为）。
所以生产环境必须显式给 —— 整串 `RECON_DSN`，或只给 `RECON_DB_PASSWORD`：

```bash
export RECON_DB_PASSWORD='...'      # 最省事
# 或
export RECON_DSN='postgresql://recon:密码@db.internal:5432/recon'
```

可用的环境变量：

| 变量 | 默认 | 说明 |
|---|---|---|
| `RECON_DSN` | — | 整个连接串，设了就忽略下面所有分段变量 |
| `RECON_DB_USER` | `recon` | |
| `RECON_DB_PASSWORD` | 空 | 本机 trust 认证时可留空 |
| `RECON_DB_HOST` | `127.0.0.1` | |
| `RECON_DB_PORT` | `5432` | |
| `RECON_DB_NAME` | `recon` | |
| `RECON_ADMIN_DSN` | `postgresql://postgres@127.0.0.1:5432/postgres` | 只给 bootstrap 用 |
| `RECON_PG_MIN` / `RECON_PG_MAX` | `1` / `10` | 连接池大小 |

密码里的 `@ : /` 等字符会被自动转义，直接写明文即可。

---

## 1. 快速开始

项目**只有 Web 一个入口**。原先的多子命令 CLI（`scan` / `show` / `diff` / `export` /
`monitors` …）已删除 —— Web API 完整覆盖了它们，两套入口维护同一批能力只会互相漂移
（原 CLI 的 `--reload` 就是个例子：参数解析了却从没传给 uvicorn，静默失效）。

### 启动

```bash
# 1) 前端构建一次（之后改前端才需要重建）
cd D:\Search\recon\frontend
npm install && npm run build

# 2) 起服务（后端会自动托管 frontend/dist 并做 SPA 兜底）
cd ..\backend
python -m core
```

打开 <http://127.0.0.1:8000> 即可。常用参数：

```bash
python -m core --port 8080                    # 换端口
python -m core --host 0.0.0.0 --token 你的令牌   # 对外监听（**务必加 token**）
python -m core --dsn postgresql://user@host:5432/recon   # 换库
# 也可用环境变量: set RECON_DSN=postgresql://...
# 首次需要先建库:  createdb recon   (或 psql -c 'CREATE DATABASE recon')
python -m core -v                              # 调试日志
```

> 嫌 `cd backend` 麻烦就装一次：`pip install -e backend`，
> 之后全局 `recon` 命令等效于 `python -m core`。
> 运行时数据位置可用 `RECON_DATA_DIR` 覆盖，默认是仓库根的 `data/`。

### 四个页面

| 页面 | 干什么 |
|---|---|
| **一键收集** | 选预设、填目标、点开始。可实时看进度 |
| **任务管理** | 所有扫描的历史与状态，可停止 / 删除 / 对比 / 导出 |
| **任务详情** | 这次扫描的资产（域名 / IP / 端口 / 端点 / 技术栈 / 发现 / 事件）+ **源统计** |
| **资产搜索** | 跨扫描搜全部资产 |

原先 CLI 那些操作现在都在界面上：`show` → 任务详情页；`audit` → 任务详情的审计；
`diff` → 任务管理里的「对比」；`export` → 任务详情右上角的导出（json / csv / xlsx）；
`monitors` → 设置抽屉里的周期监控。

### 验证脚本（这些不是 CLI 的替代品，只是自检工具）

```bash
# 调试单个被动源
python scripts/probe_source.py rapiddns example.com --raw

# 看一眼运行中的服务里有什么
python scripts/status.py http://127.0.0.1:8000

# 端到端冒烟
python scripts/web_smoke.py http://127.0.0.1:8000
python scripts/m6_smoke.py  http://127.0.0.1:8000   # 监控->变更->告警->导出
python scripts/ui_check.py  http://127.0.0.1:8000   # 真实浏览器验证前端布局
```

跑测试（同样在 `backend/` 下）：

```bash
python -m unittest discover -s tests -t .
```

---

## 2. 架构：事件驱动递归

ARL 是 **9 段固定串行流水线**，任务内无并行、无断点续跑、任一环节异常整链失败。
BBOT 的做法是每个模块声明自己**消费**什么、**生产**什么，引擎把事件在模块间反复分发：

```
                     ┌─ passive_*（9 个免费被动源 + 1 个需 Key 的测绘源）──────┐
SEED ────────────────┤                                                        ├─> DNS_NAME
                     ├─ dns_brute（字典爆破，受泛解析画像过滤）                  │
                     └─ dns_permute（域名置换，受泛解析画像过滤）                │
                                                                               v
                                        dns_resolve（CNAME 链 + A/AAAA + CDN 判定）
                                                                               │
                                                                               v
   ┌──────────────────────────────────────────────────────────────── IP_ADDRESS
   │                                                                           │
   │                     ┌─────────────────────────────────────────────────────┤
   │                     v                                                     v
   │              asn_enrich（ASN/归属地）                              port_scan（端口扫描）
   │                                                                           │
   │                                                              OPEN_TCP_PORT┤
   │                                                       ┌───────────────────┴──────────────────┐
   │                                                       v                                      v
   │                                              http_probe（HTTP 探活）              tls_cert（证书）
   │                                                       │                                      │
   │                                       HTTP_RESPONSE ──┤                        SSL_CERTIFICATE + DNS_NAME
   │                                                       v                                      │
   │                                              fingerprint（指纹）                  SAN 递归回 DNS_NAME ↺
   └──────────────────────────────────────────────────────────────────────────────────────────────┘
```

**两个递归闭环**：
1. `tls_cert` 从证书 SAN 里挖出新域名 → 回到 `dns_resolve` → 又可能扫出新端口和新证书
2. `asn_enrich` 用"重发同一事件 + 更多标签"的方式补全已有资产（见 §7）

### 主动/被动可选 = 模块 flags

| 预设 | 机制 | 用途 |
|---|---|---|
| `passive` | `require_flags: [passive]` | 绝不向目标发包 |
| `default` | `deny_flags: [loud, invasive]` | 被动收集 + DNS 解析 + CDN 判定 |
| `brute` | `include: [wildcard_detect, dns_brute, dns_permute, dns_resolve]` | 只补主动面 |
| `active` | 无过滤 | 全量，含端口扫描与探活 |
| `demo` | `include: [demo_expand, dns_resolve]` | 离线链路自检 |

---

## 3. 泛解析处理（与 ARL 分歧最大的地方）

ARL 的做法（`app/tasks/domain.py` + `app/services/massdns.py:68`）：

```python
fake_domain = "at" + utils.random_choices(4) + "." + base_domain
self._not_found_domain_ips = utils.get_ip(fake_domain)   # ← 只探 1 个随机名
...
if record in self.wildcard_domain_ip:
    continue                                             # ← 静默丢弃
```

| | ARL | 本项目 |
|---|---|---|
| 探测样本 | 1 个随机名 | **5 个**（可配），取并集，覆盖 round-robin 的多 IP |
| 判定 | 命中即丢 | 候选的**全部** IP 都在通配符集合里才算噪声；有一个不在就是真资产 |
| 留痕 | 静默 `continue` | 产出 `wildcard_filtered` 结论，写清"字典 N 条 / 有解析 M 条 / 过滤 K 条" |
| 顺序 | 串行链里写死 | `dns_brute` / `dns_permute` 自己 `await scanner.state.wait_wildcard(root)` |
| 超过 300 个子域 | **直接跳过整个 AltDNS** | 按候选总量设预算，用完即止并汇报 |

**实测对照（真实网络）**：

| 目标 | 泛解析 | 字典 | 有解析 | 产出 | 被过滤 | 结论事件 |
|---|---|---|---|---|---|---|
| `github.io` | ✅ 5/5 响应（round-robin 4 个 GitHub Pages IP） | 300 | 300 | **0** | **300** | `wildcard` + `wildcard_filtered` |
| `example.com` | ❌ 无 | 300 | 0 | 0 | 0 | 无 |
| `projectdiscovery.io` | ❌ 无 | 10 | 7 | **7** | 0 | 无 |

---

## 4. 探活链（M4）

ARL 的探活极浅（`app/services/probeHTTP.py`）：对 `https://domain` 和 `http://domain`
各发一个 `GET`、`stream=True` 后立刻 `close()`，**只看状态码是否在 [502,504,501,422,410] 之外**
—— 不取标题、不取响应头、不取长度。端口扫描则是拼一长串 nmap 参数后**同步**调用
`nmap.PortScanner().scan()`，依赖外部 nmap 二进制并阻塞整个任务。

本项目的两段式：

```
port_scan（asyncio connect 扫描，进程内，无外部二进制）
    └─> OPEN_TCP_PORT ─┬─> http_probe ─> 状态码/标题/Server/长度/跳转链/favicon 哈希
                       │                 └─> fingerprint（自研 115 种技术）→ TECHNOLOGY
                       └─> tls_cert   ─> 证书 CN/SAN/签发者/有效期/指纹
                                         └─> SAN 里的域名喂回 DNS_NAME（递归扩面）
```

三个设计点：

* **连接走 IP、URL 用域名** —— 事件里带了来源域名就用域名构造 URL，这样 SNI / Host /
  vhost 都是对的（直接拿 IP 探会拿到默认站点）。
* **响应头与正文片段是"易失标签"** —— 它们要传给下游的 `fingerprint` 做匹配，
  但不落库（见 §7）。事件内存态很丰富，数据库却很干净。
* **指纹规则是自研的** —— 115 种技术，匹配来源覆盖响应头 / Cookie / 正文 /
  标题 / meta / scriptSrc / **favicon 哈希** / URL，并能**提取版本号**、
  按 ``implies`` **推断依赖**（命中 WordPress 会一并报出 PHP）、
  给出**分类**与 **CPE**（厂商+产品，用于关联 CVE）。
  刻意**不用** ARL 的 `dicts/webapp.json`，因为那批数据来源疑似 GPL-3.0 的 wappalyzer
  （详见 `backend/core/resources/ATTRIBUTION.md`）。
* **内网段闸门**（唯一会向任意 IP 发包的模块）—— 默认拒绝内网与保留地址，
  且**每种拒绝原因留痕一次**；需要扫内网时显式 `port_scan.allow_private = true`。

---

## 5. 引擎的四道闸门

| 闸门 | 作用 |
|---|---|
| **范围校验** | `DNS_NAME` 必须落在目标域名之下，越界直接丢弃（`--no-scope` 可关，默认强制） |
| **敏感域名** | 默认拒绝 `gov.cn` / `edu.cn` / `org.cn` / `mil.cn`（ARL 默认是空列表，三项全被注释） |
| **递归深度** | `scope_distance > max_scope_distance` 不再分发，防止自我喂养死循环 |
| **去重** | 同 `(type, data)` 只分发一次；**FINDING 额外带 `kind`**（否则同一目标上的多条结论会互相顶掉）；资产投影仍会执行 |

收敛判定：`_pending` 计数归零即结束。**扫描一定能终止**，有专门的测试守着。

---

## 6. 数据模型

```
scan            一次扫描
event           所有事件（parent_id 支撑递归溯源；FINDING 的 kind 参与去重键）
domain          域名资产（is_wildcard / is_cdn）
ip              IP 资产（asn / org / country / is_cloud）
domain_ip       域名<->IP 多对多
port            开放端口（含 cert_json）
http_endpoint   HTTP 端点（状态码/标题/Server/长度/favicon 哈希）
technology      技术栈（(host, name) 唯一）
finding         结论性发现（(kind, target, detail) 唯一）
audit           审计日志（谁、什么时候、对什么目标、被动还是主动、允许还是拒绝）
monitor         周期监控任务（目标 / 预设 / 间隔 / 上次扫描 / 下次运行）
change          变更记录（每次监控扫描与上一次对比的摘要与明细）
```

四个值得一提的设计点：

1. **`event.parent_id` 支撑递归溯源**（ARL 完全没有）：
   ```bash
   $ 在任务详情页点事件行的「溯源」
   事件ID │ 类型       │ 数据            │ 模块        │ 距离 │ 父事件
      6   │ IP_ADDRESS │ 172.66.147.243  │ dns_resolve │  2   │  2
      2   │ DNS_NAME   │ www.example.com │ demo_expand │  1   │  1
      1   │ SEED       │ example.com     │ engine      │  0   │
   ```
2. **重复事件仍然执行资产投影**。先去重再投影的话，"多个域名解析到同一 IP"（CDN 场景）
   后一个域名的关联就永远建不起来。
3. **富化模块靠"重发同一事件"补充信息**。`asn_enrich` 把同一个 IP 再发一次、只多带几个标签：
   引擎认为 `(type, data)` 相同 → 不再分发给模块（不会死循环）；但投影照常执行 →
   `ip` 行被 `COALESCE` 补全。**不需要任何回写接口，模块也不用碰数据库。**
4. **易失标签**：`storage.VOLATILE_TAGS` 里的键（`headers` / `body_snippet`）只在内存中
   随事件传递给下游模块，写库时被剥掉。

---

## 7. 实测数据（真实网络）

### 主动全量（`-p active`，端口集 top10）

```
目标 projectdiscovery.io
端口: 35.211.43.232:443           证书 CN=api.projectdiscovery.io (43d)
      76.76.21.21:80
      76.76.21.21:443             证书 CN=www.projectdiscovery.io (30d)
端点: https://api.projectdiscovery.io   -> 404
      https://www.projectdiscovery.io   -> 200 "Find every exposure before it's exploited"
指纹: Next.js, Vercel
```

### 被动 + 爆破（`-p active`，端口集 top100，含泛解析过滤）

```
耗时 21.06s   events_new 136   events_deduped 207   findings 43
ASN 富化（真实 ipinfo 数据）:
  104.26.6.152    AS13335  Cloudflare, Inc.      US
  167.235.220.62  AS24940  Hetzner Online GmbH   DE
  18.236.31.100   AS16509  Amazon.com, Inc.      US
CDN 判定: 多数命中 CloudflareCDN（来自 ARL 的 IP 段库）
```

---

## 8. 模块契约

约定（沿用 BBOT）：**文件名即模块名，类名与文件名一致（小写）**。

```python
from core.engine.event import EventType
from core.engine.module import BaseModule


class my_module(BaseModule):
    watched_events = (EventType.SEED,)           # 消费什么
    produced_events = (EventType.DNS_NAME,)      # 生产什么
    flags = ("passive", "safe")                  # 主动/被动 + 噪声等级
    per_domain_only = True                       # 每根域名只跑一次
    batch_size = 1                               # >1 时引擎调 handle_batch()

    async def setup(self):
        # True = 成功 / None = 软失败(禁用本模块, 扫描继续) / False = 硬失败(中止)
        return True

    async def cleanup(self):
        ...                                      # 扫描收敛后释放资源

    async def handle_event(self, event):
        await self.emit_event("sub.example.com", EventType.DNS_NAME, parent=event)
```

> ⚠️ **不要把 `self.scanner` 当成普通属性覆盖**（例如 `self.scanner = ConnectScanner(...)`）。
> 它是引擎的只读引用，覆盖会让 `emit_event()` 静默失效；基类已把它做成只读属性，
> 一旦覆盖会在启动时报错。

**新增一个被动源只要写一个 `sub_domains()`**：

```python
from core.domains.dns.dns_query import DNSQueryBase, PassiveSourceModule
from core.services.http import HTTPClient


class Query(DNSQueryBase):
    source_name = "my_source"
    requires_key = False          # True 则缺 api_key 时模块软失败

    async def sub_domains(self, target: str, http: HTTPClient) -> list[str]:
        data = await http.get_json("https://api.example.com/subs", params={"d": target})
        return [...]              # 允许带垃圾数据, 由 sanitize 统一兜底


class passive_my_source(PassiveSourceModule):
    query = Query
```

**内置模块（24 个）—— 一个能力域一个文件夹。**

```
domains/
├── subdomain/          子域收集           13 个模块 + _lib/
│   ├── passive/        被动收集（8）不碰目标
│   ├── active/         主动收集（3）会向目标发 DNS 查询
│   ├── standalone/     单独模块（2）demo_expand · seed_asset
│   └── _lib/           dns_query.py · dnsgen.py
├── resolve/            DNS 解析 + IP 富化   2 个模块 + _lib/（resolver · resolver_pool）
├── probe/              存活与证书          3 个模块 + _lib/（tls）
├── port/               端口扫描            1 个模块 + _lib/（ports）
├── fingerprint/        指纹 / CDN / WAF    2 个模块 + _lib/（rules · library · waf · importers）
├── urls/               URL / JS 采集       2 个模块 + _lib/（extract · jsendpoints）
└── fuzz/               目录 / 敏感文件      1 个模块 + _lib/（soft404）
```

| 位置 | 个数 | 内容 |
|---|---|---|
| `domains/subdomain/passive/` | 8 | 只查第三方公开数据，`flags` 全是 `passive, safe` |
| `domains/subdomain/active/` | 3 | `dns_brute` / `dns_permute` / `wildcard_detect` |
| `domains/subdomain/standalone/` | 2 | `demo_expand`（离线演示源）· `seed_asset`（把种子本身产出为资产） |
| `domains/resolve/` | 2 | `dns_resolve` + `asn_enrich` |
| `domains/probe/` | 3 | `http_probe` + `tls_cert` + `screenshot` |
| `domains/port/` | 1 | `port_scan` |
| `domains/fingerprint/` | 2 | `fingerprint` + `waf_detect` |
| `domains/urls/` | 2 | `url_extract`（抽链接，零流量）+ `js_endpoints`（挖 JS 接口，要发请求） |
| `domains/fuzz/` | 1 | `dir_brute`（目录爆破，软 404 画像 + 403 熔断） |

### 这套划分对应整条流水线

```
种子域名 → 子域收集 → 清洗 → DNS解析 → 存活 → 端口 → 指纹/WAF/CDN
         → URL/JS → 目录/敏感文件 → 入库/监控
  SEED    subdomain 引擎+wild- resolve  probe   port   fingerprint
                    card+sanitize          urls/       fuzz/
```

**按"这一步要回答什么问题"分，不按"用什么工具"分。** 所以 `probe/` 里
`http_probe` 和 `tls_cert` 放一起（都在回答"这个端口上跑的是什么服务"），
而不是按"httpx 一个域、openssl 一个域"。

**"清洗"不是一个域**，它拆在三层 —— 详见 `domains/subdomain/__init__.py`：
去重在引擎里、泛解析画像做成 `wildcard_detect` 模块（因为要被爆破/置换共用）、
格式校验是 `_lib/dns_query.py` 里的纯函数。**硬做成一个流水线阶段反而会把
去重逻辑复制到每个源里。**

### 模块和库怎么区分：按内容，不按目录

引擎把 `domains/` 下每个文件都导入一遍，然后**只挑出定义了可运行 `BaseModule`
子类的文件**当模块（`core/engine/scanner.py::_harvest`）。

于是库文件和模块文件**可以放在同一个域里**（域专属的库放该域的 `_lib/`）：

| 文件 | 有可运行的 `BaseModule` 子类吗 | 结果 |
|---|---|---|
| `domains/port/port_scan.py` | 有（`port_scan`） | 模块 |
| `domains/port/_lib/ports.py` | 没有 | 库，被忽略 |
| `domains/subdomain/_lib/dns_query.py` | 有，但标了 `abstract = True` | 基类，被忽略 |

**给别的模块继承的基类必须标 `abstract = True`**，否则它自己也会被当成模块跑起来
（`handle_event` 是空实现，不干活还白占一个 worker）。

> ⚠️ 这个标记**不继承** —— 引擎只在类自己的 `__dict__` 里查它。
> `PassiveSourceModule.abstract = True` 如果走属性继承，会顺着 MRO 传染给
> 全部 10 个被动源子类，把它们一并判成基类 —— 表现为「被动源凭空消失」
> **且不报任何错**。有测试守着这条。

> ⚠️ **每个能力域目录必须有 `__init__.py`。** `pkgutil.walk_packages` 只递归进
> **包**，漏了这个文件那个域的模块会**静默消失**（不报错、不打日志）。
> 实测一次就丢了 7 个模块（19 → 12）。有测试守着（`test_every_domain_dir_is_a_package`）。

> 曾经用过 `_lib/` 做**跨域**隔离（那时所有库都在一个共享目录里）。现在
> `_lib/` 只表示"这个域自己的库"，真正决定加载与否的是内容判断。

唯一的额外规则：`_` 开头的**文件名**仍然跳过（Python 里那是"私有的"惯用写法）。

### 三个新模块（都借鉴了成熟工具）

| 模块 | 借鉴 | 成本 |
|---|---|---|
| `urls/url_extract` | — | **零流量**（只读已抓到的正文） |
| `urls/js_endpoints` | [LinkFinder](https://github.com/GerbenJavado/LinkFinder) MIT · [URLFinder](https://github.com/pingc0y/URLFinder) MIT | `active, loud` —— **要抓 JS 文件** |
| `fuzz/dir_brute` | [ffuf](https://github.com/ffuf/ffuf) MIT · [feroxbuster](https://github.com/epi052/feroxbuster) MIT · [gobuster](https://github.com/OJ/gobuster) Apache-2.0 | `active, loud, invasive` —— **默认被预设拦住** |
| `fingerprint/waf_detect` | [wafw00f](https://github.com/EnableSecurity/wafw00f) BSD-3 | **零流量**（只读已有响应） |

**没有照抄任何一个。** 而且有几个流行项目**因为许可证不能用**：

| 项目 | 许可证 | |
|---|---|---|
| [SecretFinder](https://github.com/m4ll0k/SecretFinder) | GPL-3.0 | 传染 |
| [JSFinder](https://github.com/Threezh1/JSFinder) | **未声明** | 无许可证 = 保留所有权利 |
| [dirsearch](https://github.com/maurosoria/dirsearch) | **未声明** | 同上 |
| [WhatWaf](https://github.com/Ekultek/WhatWaf) | NOASSERTION | 自定义 |

> GitHub 上"没写许可证"**不等于**可以随便用。完整清单与理由见
> `core/resources/ATTRIBUTION.md`。

**`fuzz/dir_brute` 实测**（本地 catch-all 服务器：未知路径全部返回 200 + 同一页面）：

```
字典 10 条；真命中路径 ['/.env', '/admin', '/backup.zip', '/swagger.json']
命中 4 条：/.env  /admin  /backup.zip  /swagger.json   ← 零误报零漏报
软 404 丢弃 6 条
```

软 404 画像的关键在 `_lib/soft404.py`：探测时**刻意用 4/8/12/16 四种长度的
随机 token**，如果响应大小随 token 长度线性变化，说明页面把请求路径回显进了
正文 —— 这时按原始大小过滤会完全失效（每条都不一样），改按
`size - len(token)` 归一化比对。**这是 ffuf 的 `-ac` 不做的一步。**

> ⚠️ **目录名里的"主动/被动"和模块自己的 `flags` 是重复信息，会漂移。**
> 目前 `subdomain/active/` 的 3 个全含 `active`、`subdomain/passive/` 的 8 个全是 `passive`，没有反例；
> 但这个归类是给人看的，**引擎只认 `flags`**（`preset.allows(name, flags)`）。
> 加新模块时如果归错目录，功能不会出错，只是目录会说谎。

### 两个补上的断链（都是实测发现的）

**① `seed_asset`：根域名与裸 IP 目标原先从不被解析。**

``SEED`` 事件带的是用户输入的目标，但下游的解析/端口/探活全都只认
``DNS_NAME`` / ``IP_ADDRESS`` —— **原先没有任何模块把 SEED 转过去**：

```
SEED(example.com) → ??? → DNS_NAME(example.com) → dns_resolve → IP_ADDRESS
                     ↑ 原先没有这一步
```

实测（`demo` 预设跑 example.com）：域名表里有 `example.com`（引擎记的种子），
但 **IP 表里的两个 IP 全部来自解析 `www.example.com`** —— 根域名自己从没被解析，
于是也没被扫端口、没被探活。**主站就这样漏掉了。** 裸 IP 目标更彻底：
整条链一个事件都不产生。

> 这属于**回退**而不是新需求：ARL 的 `mass_dns` 本来是带根域名的
> （`if not is_fuzz_domain: domains.append(based_domain)`），移植时漏掉了那一句。

**② IPv6 目标被静默截断。**

种子归一化里的 `.split(":")[0]`（本意是去端口）会把 IPv6 从第一个冒号切断：
`2606:2800:220:1::1` → `2606`，于是整个 IPv6 目标失效。
改成"方括号形式取括号内，否则只在恰好一个冒号且后面全是数字时才当端口"。

各模块的作用（`flags` 决定它属于被动还是主动）：

| 模块 | flags | 作用 |
|---|---|---|
| `passive_anubis` | passive, safe | anubisdb 子域库（**无 key、极快**，按名字索引故支持递归） |
| `passive_subdomaincenter` | passive, safe | **产出最高**：subdomain.center 子域聚合，单次约 500 条 |
| `passive_rapiddns` | passive, safe | rapiddns.io 网页抓取 |
| `passive_certspotter` | passive, safe | certspotter 证书透明度 API |
| `passive_crtsh` | passive, safe | crt.sh 证书透明度日志（**很慢，几十秒到几分钟**） |
| `passive_hackertarget` | passive, safe | HackerTarget hostsearch（纯文本 CSV，**易被限流**） |
| `passive_urlscan` | passive, safe | urlscan.io 检索 |
| `passive_commoncrawl` | passive, safe, **heavy** | Common Crawl 历史索引（**默认关闭**，见下） |
| `asn_enrich` | passive, safe | ASN / 归属地富化（默认 **不在** `default`/`passive` 里） |
| `fingerprint` | passive, safe | 技术栈指纹（只用已有响应，不发请求） |
| `seed_asset` | passive, safe | **把种子本身产出为资产**（域名→DNS_NAME，IP→IP_ADDRESS）。没有它根域名和裸 IP 目标都不会被解析 |
| `url_extract` | passive, safe | 从已抓到的正文里抽 URL（**不发额外请求**） |
| `demo_expand` | passive, safe | 离线演示源，测试与自检用 |
| `dns_resolve` | active, safe | DNS 解析 + CNAME 链 + CDN 判定 |
| `wildcard_detect` | active, safe | 泛解析探测与过滤 |
| `tls_cert` | active, safe | 证书抓取 + SAN 递归 |
| `dns_brute` | active, loud | 字典爆破（默认复用 ARL 的 2 万字典） |
| `dns_permute` | active, loud | 域名置换（AltDNS 5 种策略） |
| `port_scan` | active, loud | 异步 TCP connect 扫描 |
| `http_probe` | active, loud | HTTP 探活（状态码/标题/Server/favicon） |
| `screenshot` | active, loud | 网页截图（Playwright） |

> **免 Key 的源已挖干，测绘引擎按需接入。**已实现三家：
> `passive_fofa`（支持官方 API 与**第三方中转**）、`passive_quake`（360）、
> `passive_hunter`（奇安信）—— 缺 Key 时自动软失败、扫描继续。
> 其余带 Key 的源（chaos / zoomeye / virustotal / censys）契约已就绪，
> 照 `passive_fofa.py` 写即可。
>
> 每家都能在「系统设置 → 源 API Key」里配 `api_key` 与 **接口地址**，
> 并各有一个「**测试连接**」按钮。
>
> ⚠️ **Hunter 免费账号的 API 不可用**（官方帮助中心写明「API 检索：充值可用」），
> 所以它在免费账号上会直接报错 —— 那是预期行为，不是 bug。
>
> **Key 填在「系统设置 → 源 API Key」里**（不在每次任务的配置覆盖里填）。
> 设置文件只回传"哪些源已配置"，**密钥值永不回传**；建任务时自动注入，
> 某次任务想临时换 Key 仍可在「配置覆盖」里覆盖。
> 之所以不推荐填在配置覆盖里：**监控任务**的覆盖项会被明文写进
> `monitor.overrides_json` 且接口会回显 —— 一次性任务没这个问题（不落库），
> 监控有。
> （缺 Key 时软失败、扫描继续），需要时按 `passive_hackertarget.py` 的写法加回来。

`passive_otx` **已删除**：两次实测都是 HTTP 429，基本不可用。

### 被动源实测产出

对 `example.com` 跑 `-p passive` 单次（2026-01，取自任务详情的「源统计」标签页）：

| 源 | 请求 | 原始 | 产出 | 错误 | 耗时 | 备注 |
|---|---|---|---|---|---|---|
| `passive_anubis` | 6 | 44506 | **22249** | 0 | 2.5s | 含 5 次递归查询（默认预算） |
| `passive_subdomaincenter` | 1 | 495 | **495** | 0 | 1.3s | 单次请求，性价比最高 |
| `passive_rapiddns` | 1 | 331 | 2 | 0 | 1.3s | 原始多但基本都是噪声 |
| `passive_certspotter` | 1 | 9 | 1 | 0 | 0.8s | |
| `passive_urlscan` | 1 | 300 | 1 | 0 | 1.7s | 同上 |
| `passive_crtsh` | 6 | 39 | 1 | 0 | **54.2s** | 又慢又容易 502/超时 |
| `passive_hackertarget` | 6 | 0 | 0 | **6** | 2.3s | 报 `API count exceeded`，被限流 |

> `crtsh` 和 `hackertarget` 各发 6 次 = 1 次根查询 + 5 次递归。`hackertarget`
> 被限流后连根查询都拿不到数据，递归只是把 6 次都撞在墙上 —— 这正是
> 「预算要收紧 + 要有统计可看」的理由。

> 这张表是**每源运行统计**（见 §8.5）直接打出来的 —— 以前为了发现
> "hackertarget 被限流 / crtsh 慢到 280 秒"得另写探针脚本，现在跑一次就看得到。

`passive_anubis` 的产出随域名波动极大：`qq.com` 只有 **28** 条，
`example.com` 有 **22249** 条（后者的编号子域是真实 CT 记录，不是噪声 ——
拿两个不存在的域名探测，它都返回 0 条）。

合计 **501 个事件 / 15.8 秒**。注意"子域数"是各源单独测的值；一次扫描里多个源
给出同名子域时，资产表按 **`name`** 唯一（跨 scan 去重，2026-09 迁移完成），
`source` 只记最先发现它的那个源；"哪次扫描看到过它"记在 `scan_asset` 关联表里。

### 为什么没有做搜索引擎收集

ARL 的 `app/services/searchEngines.py` 会抓百度和 Bing 的 `site:域名` 结果。
实测在这里**不可用**，所以没有移植：

| 引擎 | 实测结果 |
|---|---|
| 百度 | 返回人机验证码页面（1.5KB） |
| Bing（cn.bing.com） | 页面标题写着 `site:example.com`，但 `<cite>` 里全是 `jingyan.baidu.com` / `zhihu.com` 等**完全无关**的结果 |

搜索引擎抓取依赖页面结构，随时会被改版或反爬打断。与其加一个已知是坏的模块，
不如把 `subdomaincenter` 这类结构化 API 做好 —— 它一个源就顶 498 条。

> `screenshot` 是"软失败"的真实案例：本机没装 Chromium 时 `setup()` 返回 `None`，
> 模块被禁用并在 `modules_skipped` 里给出原因，其余扫描照常完成。

### 8.5 借鉴 subfinder 的三件事

subfinder（projectdiscovery，MIT）每个源声明四个元数据：
``IsDefault()`` / ``HasRecursiveSupport()`` / ``KeyRequirement()`` / ``Statistics()``。
其中三件已经吸收进来，一件**实测后判定不值得**。

**① 每源运行统计 `Statistics` —— 最实用的一条。**
每个被动源现在记 Requests / Errors / Raw / Results / Elapsed，
扫描结束后在任务详情的**「源统计」标签页**展示（见上面的实测产出表）。

价值在于：**不用再手写探针才知道哪个源是死的。** 实测 subfinder 那批免费源时，
我是靠一个临时脚本才发现 `threatcrowd` 已经停服、`otx` 一直 429、`sitedossier` 被 403。
现在跑一次 `-p passive`，`hackertarget` 那行直接写着 `21 请求 / 0 产出 / 21 错误 /
API count exceeded`。实现见 `SourceStats`；请求数由 `HTTPClient.stats` 自己数
（让插件自己累加容易漏）。

**② 递归被动枚举 `HasRecursiveSupport` —— 实现了，但要诚实说收益很小。**

做法是切 `-recursive` 那套：源声明 ``recursive = True`` 后，
``__init_subclass__`` 让它多订阅一个 ``DNS_NAME``，于是已发现的子域会被回喂。

**隔离测量看着很美，端到端却是另一回事：**

| | 隔离测量（手挑候选） | 端到端（走引擎，qq.com） |
|---|---|---|
| `anubis` | +103（根查询 28） | **+0** —— 根响应的 28 条全是多层名，没有第一层候选 |
| `hackertarget` | +102（根查询 50） | 被限流，拿不到根数据 |
| `crtsh` | +212（根查询 1894） | **+4**（根查询 3561）＝ 0.1% |

我在隔离测量里手工挑了 `v.qq.com`，而 anubis 对 `qq.com` 的根响应里**根本没有**
`v.qq.com`。crtsh 那 +212 则是因为那次根查询只有 1894 条（被截断）——
根查询正常返回 3561 条时，增量就塌了。

所以：**源支持递归 ≠ 引擎能拿到好候选。** 功能保留（实现正确、可关、有闸门），
但默认预算压到 **5**，别指望它翻倍。关掉用
`-c modules.passive_crtsh.recursive_max_names=0`。

三道闸门（实测逼出来的）：只回喂**第一层**子域；每个根域名有总量预算；
候选要过"像不像有下层"的筛子 —— 最后这条是因为 example.com 上 anubis 返回
22248 条按字母排前面全是 `0` / `001` / `101065` 这类 CT 噪声，20 次预算被它们
吃光且全部返回 0 条。筛掉后预算才落到 `www` / `mail` / `dns` / `api` 上，
另外常见基础设施名（`_COMMON_PARENTS`）拿 2/3 名额，普通名字只有 1/3。

**③ `heavy` flag —— 对应 `IsDefault() == false`。**
`passive_commoncrawl` 能用但**很贵**：22.9s、7.9MB，只换 35 条。
所以带 `heavy` 标签，`passive` / `default` 预设 `deny_flags` 掉它，
`-p active`（全量）才启用。subfinder 对它也是 `IsDefault() = false`。

**url_extract 的实测产出（页面里抽链接）**

| 页面 | 正文大小 | 取前 4KB | 取前 64KB |
|---|---|---|---|
| www.qq.com | 114 KB | 5 条（范围内 **1**） | 201 条（范围内 **85**） |
| www.baidu.com | 719 KB | 8 条（范围内 4） | 8 条（范围内 4，链接都在开头） |
| example.com | 559 B | 1 条（范围内 0，只有一条指向 iana.org 的外链） | 同左 |

**4KB 那一列是原来的默认值，差 85 倍。** 而 `http_probe` 的 `max_bytes`
本来就是 64KB —— 正文已经下载了，`snippet_len` 只留前 4KB 纯属白扔。
所以把 `snippet_len` 的默认值改成与 `max_bytes` 对齐（都是 64KB）；
它是易失标签、不落库，代价只是单条事件存活期间多占几十 KB 内存。

**④ 没采纳的：它的其余"免费源"。** 8 个候选实测只有 2 个能用：

| 候选 | 实测 | 结论 |
|---|---|---|
| `anubis` | ✅ 614ms，qq.com 28 条 / example.com 22249 条 | **已加** |
| `commoncrawl` | ✅ 能用但 22.9s / 7.9MB / 35 条 | **已加**（默认关） |
| `waybackarchive` | ❌ 本机连不上 `archive.org`（59.7s 超时） | 不加 |
| `threatcrowd` | ❌ 服务已死（域名都解析不了） | 不加 |
| `threatminer` | ❌ HTTP 522 | 不加 |
| `sitedossier` | ❌ 403 被拦 | 不加 |
| `robtex` | ❌ 200 但 0 条 | 不加 |
| `bufferover` | ❌ subfinder 里已是 `RequiredKey`（早不免费了） | 不加 |

> 顺带一个坑：裸 aiohttp 探 `anubis` 会报 `Can not decode content-encoding: br` ——
> 正是 §11 记的那个 brotli 问题。换自己的 `HTTPClient`（不声明 `br` + `identity`
> 兜底）就正常。**已有的那层保护是有效的。**

---

## 9. 目录结构

```
D:\Search\recon\                 ← 仓库根（项目名 recon）
├── backend/                    ← 全部 Python
│   ├── pyproject.toml
│   ├── core/                   ← **Python 包名是 core**（产品名仍是 recon）
│   │   ├── engine/             # 引擎（原 core/，为避同名改成 engine）
│   │   │   ├── event.py        #   Event / EventType（FINDING 的 kind 参与去重键）
│   │   │   ├── module.py       #   BaseModule（模块契约；scanner 为只读属性）
│   │   │   ├── scanner.py      #   队列分发、去重、四道闸门、收敛判定
│   │   │   ├── state.py        #   ScannerState + 泛解析画像与就绪闸门
│   │   │   ├── preset.py       #   预设加载、flags 过滤、-c 覆盖
│   │   │   └── log.py
│   │   ├── domains/            # ★ 一个能力域一个文件夹（详见 §8）
│   │   │   ├── subdomain/      #   子域收集（13 个模块）
│   │   │   │   ├── passive/    #     被动收集（8）anubis / subdomaincenter / rapiddns
│   │   │   │   │               #     certspotter / crtsh / hackertarget / urlscan / commoncrawl
│   │   │   │   ├── active/     #     主动收集（3）dns_brute / dns_permute / wildcard_detect
│   │   │   │   ├── standalone/ #     单独模块（1）demo_expand
│   │   │   │   └── _lib/       #     域专属库：dns_query.py · dnsgen.py
│   │   │   ├── resolve/        #   DNS 解析 + IP 富化（2）dns_resolve / asn_enrich
│   │   │   │   └── _lib/       #     resolver.py · resolver_pool.py（★ 见 §10.5）
│   │   │   ├── probe/          #   存活与证书（3）http_probe / tls_cert / screenshot
│   │   │   │   └── _lib/       #     tls.py
│   │   │   ├── port/           #   端口扫描（1）port_scan
│   │   │   │   └── _lib/       #     ports.py
│   │   │   ├── fingerprint/    #   指纹 / CDN / WAF（2）fingerprint · waf_detect
│   │   │   ├── urls/           #   URL / JS 采集（2）url_extract · js_endpoints
│   │   │   └── fuzz/           #   目录 / 敏感文件（1）dir_brute
│   │   ├── services/           # **跨域通用**的能力，仅此四类
│   │   │   ├── http.py         #   异步 HTTP —— 被动源/探活/截图都在用
│   │   │   ├── diff.py         #   两次扫描的资产差异对比
│   │   │   ├── notify.py       #   告警推送（webhook / 钉钉 / 飞书 / 企业微信 / 邮件）
│   │   │   └── export.py       #   导出 JSON / CSV / XLSX
│   │   ├── util/
│   │   │   ├── paths.py        #   ★ 所有路径推导的唯一来源（见下）
│   │   │   ├── domain.py       #   域名归一化（含 BOM/零宽字符清理）与校验
│   │   │   ├── net.py          #   内网段闸门 + 端口集解析
│   │   │   ├── cdn.py          #   CDN 判定（移植自 ARL，改用 ipaddress）
│   │   │   ├── words.py        #   字典加载（内置 or 路径）
│   │   │   ├── authz.py        #   授权白名单
│   │   │   └── mime.py         #   纠正被 Windows 注册表污染的 MIME 映射
│   │   ├── resources/          # ★ 随包分发的静态资源（不是运行时数据！）
│   │   │   ├── domain_2w.txt   #   19,706 条爆破字典（ARL）
│   │   │   ├── altdns_words.txt#   147 条置换词表（ARL）
│   │   │   ├── cdn_info.json   #   29 条 CDN 记录（ARL）
│   │   │   ├── ports.json      #   top10/top100/top1000 端口集（ARL 的 config.py）
│   │   │   ├── fingerprints.json # 115 种自研技术指纹（v2 格式）
│   │   │   ├── waf.json       #   44 条自研 WAF 指纹 / 125 条规则
│   │   │   ├── dir_common.txt #   241 条目录/敏感文件路径（自研精简版）
│   │   │   ├── resolvers.txt   #   ★ 公共解析器池（22 个，见 §10.5）
│   │   │   └── ATTRIBUTION.md  #   来源与许可（含"哪些项目因许可证不能借鉴"）
│   │   ├── storage/            # PostgreSQL 存储
│   │   │   ├── postgres.py     #   投影与查询（50 个方法）
│   │   │   ├── pg.py           #   asyncpg 适配层（方言差异只在这里）
│   │   │   ├── schema.sql      #   建表
│   │   │   └── schema_trgm.sql #   pg_trgm 检索索引（可降级）
│   │   ├── web/                # FastAPI 接口（**不含前端源码**）
│   │   │   ├── app.py          #   路由 + 令牌中间件 + SPA 托管
│   │   │   ├── manager.py      #   进程内扫描管理（不引入 Celery/Redis）
│   │   │   ├── scheduler.py    #   周期监控调度（进程内 asyncio 任务）
│   │   │   └── settings.py     #   授权白名单 / 令牌 / 告警配置
│   │   ├── presets/            # passive / default / brute / active / demo
│   │   └── server.py           # ★ 唯一入口：拉起 Web 管理台（原 cli.py 已删除）
│   ├── tests/                  # 263 个测试
│   └── scripts/                # probe_source / web_smoke / m6_smoke / status / ui_check
│
├── frontend/                   ← 独立的 Vue 3 工程
│   ├── package.json            #   自带依赖与脚本（dev / build）
│   ├── vite.config.js          #   /api 代理 + 构建输出到 dist
│   ├── dist/                   #   构建产物（生成物，后端运行时托管）
│   └── src/                    #   App.vue（布局）/ views / components / api / router / styles
│
├── data/                       ← 运行时产物（生成物，可整目录删除）
│   └── screenshots/            #   截图
│   ├── web_settings.json       #   白名单 / 令牌 / 告警配置
│   └── screenshots/            #   网页截图
└── README.md
```

### 包名是 `core`，产品名是 `recon`

两者不一致是刻意的：

| | 用什么 | 例子 |
|---|---|---|
| **代码里的模块路径** | `core` | `core.engine`、`core.domains`、`core.web` |
| **给人看的名字** | `recon` | 程序名（`usage: recon`）、日志命名空间（`recon.scanner`）、FastAPI 标题、告警来源、导出文件名 |

入口因此是 **`python -m core`**（不再是 `python -m recon`）—— 它直接启动 Web 管理台。
装了之后命令仍是 `recon`：`pip install -e backend` → `recon`。

> 日志命名空间**特意不用** `core`：`logging.getLogger("core")` 在全局注册表里
> 太泛，任何第三方库都可能撞上。`recon` 具体得多。

### 两条容易踩的路径约定

**1. 两个"data"已经拆开了。** 原先包里有个 `recon/data/`（字典、指纹、CDN 库），
仓库根又有个 `data/`（库、设置、截图）—— 同名不同命，很容易指错。现在：

| | 位置 | 内容 | 谁生成 |
|---|---|---|---|
| **静态资源** | `backend/core/resources/` | 字典、指纹规则、CDN 库、端口集 | 随代码提交 |
| **运行时数据** | `data/` | 库、设置、截图 | 程序生成，可删 |

**2. 路径推导集中在一处。** 所有路径都从 `backend/core/util/paths.py` 取，不要在自己文件里写
`Path(__file__).resolve().parents[N]`。这次改动里 `fingerprint.py` 就是栽在这种写法上
（模块下移一层后指向了不存在的 `recon/modules/data/`，而且是**静默失效**——
指纹一条都匹配不上，不报错）。`paths.py` 里同时给出：

```python
repo_root()        # 向上找同时含 backend/ 与 frontend/ 的目录
data_dir()         # 运行时数据（可用 RECON_DATA_DIR 覆盖）
db_path() / web_settings_path() / screenshots_dir()
resources_dir()    # 包内静态资源
frontend_dist()    # 前端构建产物（可用 RECON_FRONTEND_DIR 覆盖）
```

---

## 10. 与 ARL 的关系

**已实际移植（ARL 是 MIT，可抄）**：

| 来源 | 移植内容 | 落到 |
|---|---|---|
| `app/services/dns_query.py` | 插件契约 + 结果清洗逻辑 | `backend/core/domains/subdomain/_lib/dns_query.py` |
| `app/services/dns_query_plugin/` | 插件契约与结果清洗逻辑（各源的具体实现见下） | `backend/core/domains/subdomain/passive/` |
| `app/services/altDNS.py` | DnsGen 的 5 种置换策略 | `backend/core/domains/subdomain/_lib/dnsgen.py` |
| `app/utils/cdn.py` | CDN 判定顺序 + gslb/dns/cache 启发式 | `backend/core/util/cdn.py` |
| `app/utils/domain.py` | 域名校验与禁止域名语义（另修了 BOM 问题） | `backend/core/util/domain.py` |
| `app/utils/ip.py::not_in_black_ips` | 黑名单 IP 的语义 | `backend/core/util/net.py`（默认值反过来） |
| `app/services/portScan.py` | 端口集 + "开放端口异常多"的经验值（>600） | `backend/core/util/net.py` / `backend/core/domains/port/port_scan.py` |
| `app/services/probeHTTP.py` | "https 活着就别单独记 http"、弱状态码清单 | `backend/core/domains/active/http_probe.py` |
| `app/utils/cert.py` | 证书字段清单（subject/issuer/validity/fingerprint） | `backend/core/domains/probe/_lib/tls.py`（改用 cryptography） |
| `dicts/*` | domain_2w / altdnsdict / cdn_info / 端口集 | `backend/core/resources/` |
| `frontend-src/src/App.vue` | 布局骨架：固定侧栏 170/50px + 64px 顶栏 + 内容区 24/32 留白 | `frontend/src/App.vue` |
| `frontend-src/src/styles/global.css` | 主题令牌（`#1a1a1a` 侧栏 / `#c2410c` 强调色）与 antd 覆盖 | `frontend/src/styles/global.css` |
| `frontend-src/src/router/index.js` | 路由与菜单的组织方式（`meta.menu` 驱动选中态） | `frontend/src/router/index.js` |
| `frontend-src/package.json` | 技术栈选型（Vue 3 + Ant Design Vue 4 + vue-router） | `frontend/package.json` |

**结构上刻意不同**：ARL 用 `run_query_plugin()` 把所有插件塞进一个线程池；我们把**每个源做成独立模块**，
于是每个源有自己的软失败、日志、统计与清理钩子，并天然享受引擎的并发与跨源去重。

**坚决不抄（ARL 的硬伤）**：

| ARL 的做法 | 问题 | 我们的做法 |
|---|---|---|
| 泛解析只探 1 个随机名 | round-robin 会漏、超时则完全漏 | 探 5 个取并集 |
| 泛解析命中**静默丢弃** | 用户无法判断结果可信度 | 标记降权 + `wildcard_filtered` 结论留痕 |
| 子域 > 300 就跳过整个 AltDNS | 粗暴且不可见 | 按候选总量设预算，用完即止并汇报 |
| 端口扫描串行调 nmap `-sT -sV -O` | 依赖外部二进制、阻塞整任务 | asyncio connect 扫描 + 下游模块做服务识别 |
| 探活只看状态码 | 拿不到标题/响应头/长度 | 一次请求取全（还顺手算 favicon mmh3） |
| 截图用 PhantomJS（2018 停更） | 无维护、有安全风险 | 未实现（M6 可选，用 Playwright） |
| 口令 `hex_md5('arlsalt!@#'+pwd)` | 不可接受的哈希 | M5 用 bcrypt / argon2 |
| `BLACK_IPS` 注释掉内网段、`FORBIDDEN_DOMAINS` 为空 | 默认可扫内网、不拦 gov/edu | **已实现**：敏感域名默认拒绝 + 端口扫描前内网段闸门 |

**未采纳的 ARL 数据**：`dicts/webapp.json`（667 KB 指纹库）—— 来源疑似 GPL-3.0 的 wappalyzer，
与 ARL 自身的 MIT 无关。本项目改用自研规则集（115 种技术）。

想把库扩到几千条规模就**导入** —— 支持 wappalyzer 与 FingerprintHub 两种格式
（都是 MIT），本项目**不打包它们的数据**，只提供转换工具：

```bash
python -m core.domains.fingerprint._lib.importers \
    --fingerprinthub web-fingerprint/ -o core/resources/fingerprints_imported.json
```

该文件存在就会被自动叠加，不需要改配置。前端「指纹库」页有完整说明。
GeoLite2 mmdb 受 MaxMind 独立 EULA 约束，同样未包含。详见 `backend/core/resources/ATTRIBUTION.md`。

**BBOT 只学架构，不抄代码** —— BBOT 是 **AGPL-3.0**，比 GPL 多一条网络服务条款，抄代码会传染。

### 10.5 主动收集：开放解析器池

**问题**：爆破要发几万条 DNS 查询，全打到一个解析器上会立刻被限速。实测单个解析器
并发从 200 提到 600 **毫无收益**（156.8 → 158.0 qps）—— 瓶颈在解析器侧，不在客户端。
根因之一是 dnspython 的 `Resolver` 默认 `rotate=False`，每次都从 `nameservers[0]` 试起。

**做法**（借鉴 subbrute / massdns 的可移植部分，不是抄代码）：

| 环节 | 做了什么 |
|---|---|
| 池子 | `backend/core/resources/resolvers.txt`，22 个**运营方明确、不做事先过滤**的公共解析器 |
| 校验 | 启动时并发探测，解析不了任何东西的踢掉；结果进程内缓存 15 分钟（4 个模块共用一次） |
| 剔除 | 校验时顺便量延迟，**太慢的也剔除**（相对中位数，绝对阈值在不同网络下没意义） |
| 挑选 | 按 `成功率 / 延迟` **加权随机**，不是均匀轮换 |
| 熔断 | 连续失败 N 次停用一段时间；全部熔断时强行解禁最早出错的（宁可问个刚出错的，也好过整批卡死） |
| 重试 | 单条超时**换一个解析器**重试，而不是原地重试同一个坏掉的 |
| 限速 | 可选全局 QPS 上限，避免把公共解析器打成 DDoS 源 |

实测（500 个 NXDOMAIN 名字，本机）：

```
仅 223.5.5.5   并发 200        3.19s    156.8 qps
仅 223.5.5.5   并发 600        3.17s    158.0 qps   ← 并发翻三倍没用
9 个快解析器    并发 200        1.54s    325.5 qps
9 个快解析器    并发 800        1.17s    427.4 qps
```

> ⚠️ **这些数字复现不了，别当指标用。** 同一配置背靠背跑两轮：固定 5 个是
> 149.7 → 53.3 qps，9 个池是 66.8 → 157.3 qps。因为**公共解析器对源 IP 做累计
> 限速且带恢复窗口**，第 1 轮把某几个打了一遍，第 2 轮它们就开始拖延响应。
> 所以池子的价值是**推迟限速到来**，不是提高峰值。

**配置**（这些键在任意解析类模块上都可用）：

```bash
# 换一个自定义解析器列表（例如 subbrute 的 resolvers.txt，注意其 GPLv3 授权）
# 在「一键收集」页选预设后，于「高级配置」里填 modules.dns_brute.resolvers=D:/resolvers.txt

# 内联指定
# 或 settings.resolvers=1.1.1.1,8.8.8.8

# 关掉校验 / 加限速
-c modules.dns_brute.verify_resolvers=false
-c modules.dns_brute.max_qps=300
```

**没做的（也不宣称做了）**：ksubdomain 那种 **raw socket 无状态发包**。
它需要原始套接字与提权（Windows 上更不可行），而且这里的瓶颈在解析器侧、
不在内核连接状态上，照搬拿不到收益。

**一条安全提醒**：公共解析器的结果理论上可被运营方记录甚至篡改。对准确性要求
极高的场景，请换成自建递归解析器（unbound / dnsmasq）并把地址写进 `resolvers.txt`。
另外**过滤型解析器**（Quad9 / OpenDNS / AdGuard 会拦恶意域名）对子域枚举有害 ——
一个真实存在的子域被拦成 NXDOMAIN 就是一条静默的假阴性，所以默认列表里没有它们。


**部署形态上的对照**（这条比功能对比更能说明"不用 Docker"意味着什么）：

| | ARL | 本项目 |
|---|---|---|
| 依赖 | MongoDB + RabbitMQ + Nginx + `arl-web`/`arl-worker`/`arl-worker-github`/`arl-scheduler` 四个 systemd 服务 | **PostgreSQL** + 进程内 asyncio 队列（无中间件） |
| 启动 | 一键脚本装一堆系统级依赖 | `python -m core` |
| 建议配置 | 4 核 8G | 随便 |
| Windows | **不支持** | 支持（本项目就在 Windows 上开发与验证） |
| 前端技术栈 | Vue 3 + Ant Design Vue 4 + webpack | **同一套**（Vue 3 + Ant Design Vue 4），构建换成 Vite |
| 前端源码 | `frontend-src/`（本地这份副本是完整的） | `frontend/`（同样完整，布局与配色对标 ARL） |

> 更正一处我先前的错误结论：我曾写过"ARL 只有编译产物、源码不在仓库里"。
> 那是根据上游 `TophantTechnology/ARL` 已被删除推断的。**本机 `E:\ARL` 里
> `frontend-src/` 是完整源码**（含 `src/views/` 全部页面与 `package.json`），
> 本项目的前端布局规格就是从它读出来的。

**前端也是"开发分离 + 生产托管"**：

```bash
# 开发：Vite dev server（5173）热更新，/api 代理到后端
cd frontend && npm run dev

# 生产：构建产物交给后端，仍然只有一条命令
cd frontend && npm run build      # → frontend/dist
python -m core                   # 后端自动托管 frontend/dist 并做 SPA 兜底
```

没有构建产物时，后端不会崩，而是返回一张写着构建命令的说明页（HTTP 503）。

---

## 11. 已知限制

**M4 相关**

- **connect 扫描在 Cloudflare 上会大量假阳性**。实测 `example.com` 背后的 Cloudflare IP
  在 25/110/143/2082/2083/2087/2096/8443 上都接受 TCP 连接（随后在应用层拒绝）。
  这是 connect 扫描的固有特性，nmap `-sT` 也一样；要减少它需要 `-sV` 那种服务握手，
  后续可选加一个"非标端口轻量握手"环节。
- **未做服务/版本识别**（ARL 的 nmap `-sV`）。目前只区分"端口开着"和"它响应 HTTP/TLS"。
- **未做截图**。
- `port_scan` 对开放端口特别多（>600）的主机只打日志，不丢弃 —— 取舍留给用户。
- favicon 哈希每个端点只取一次；`favicon.ico` 不存在时会拿到站点首页的哈希（会落库，但不影响指纹）。

**通用**

- `dns_resolve` 只取直接 CNAME，**不展开完整 CNAME 链** —— 这是**实测后的决定**，不是没做：
  200 个真正解析出 IP 的域名，CNAME 全是**一跳且指向域外**（`mail.panabit.com → mailhz.qiye.163.com`、
  `www.qq.com → ins-r23tsuuf.ias.tencent-cloud.net`），展开链只会多花 N 次查询换 0 个新资产。
  **一次查询里的多条 CNAME 是全留的**（多 CDN 场景漏第二条会静默漏判）。
  记录类型只有 A/AAAA/CNAME。
- **JS 深度分析（SPA 渲染 / webpack chunk 递归 / sourcemap）没做，也是实测后的决定**：
  4 个实际目标全量抓 JS，`webpack=0`、`srcmap=0`、**范围内新主机=0** —— 它们是 jQuery 时代的
  服务端渲染站，没有 chunk 可递归。测量表见 `core/domains/urls/__init__.py`。
- 免 key 被动源的池子**已经挖干**：对 `panabit.com` 逐个量过候选（otx 超时 / robtex 只返回 NS 记录 /
  threatminer 522 / jldc 403 / bufferover 服务已死 / mnemonic 无子域）。剩下的已知可用源
  （fofa / quake / hunter / shodan / zoomeye / censys / virustotal / chaos）**全部要 API Key**，
  插件契约支持，填 Key 即用。详见 `core/domains/subdomain/passive/__init__.py`。
- 爆破/置换走进程内 dnspython 并发，**十万级候选**需要另挂 massdns 后端（接口预留未实现）。
  解析器池（见 §10.5）解决的是"被单个解析器限速"，不是"单机吞吐不够"。
- **解析器池的吞吐数字不可复现**：公共解析器对源 IP 做**累计限速且有恢复窗口**，
  同一配置背靠背跑两轮能差 3 倍（实测 149.7 → 53.3 qps）。所以别拿单次基准下结论，
  池子的价值在于**推迟限速到来**，不是提高峰值。
- `asn_enrich` 依赖第三方接口（默认 ipinfo），免费额度有限流，且会把目标 IP 发给第三方，
  所以 `default` / `passive` 预设都显式排除了它。
- 内置 CDN 库来自 ARL（约 2023 年），部分 IP 段可能已过时；库外的 CDN 只能靠 CNAME 启发式，
  结果是通用 `"CDN"` 而非具体厂商。
- **默认不声明 `br` 压缩**：本环境 aiohttp 3.14 + brotli 1.1.0 解不开 `br`
  （`HAS_BROTLI` 为 True 但流式解压抛错，aiohttp 还会吞掉真实异常只留一句通用消息）。
  需要时可开 `accept_brotli`，但要先确认你的环境能解。
- **Web 端没有多用户/RBAC**，只有一个共享令牌；令牌经明文 HTTP 传输，
  远程使用必须放在 HTTPS 反代或 SSH 隧道之后。默认只绑 `127.0.0.1`。
- **前端主包 1.6MB（gzip 后 500KB）**：ant-design-vue 是全量引入的。内网
  localhost 加载无感，但真要压体积，需要引入 `unplugin-vue-components` 做按需导入。
- **构建时要把 TEMP 指到工程内**（Windows 特有）：esbuild 在系统临时目录里
  删自己的临时文件会被拒（`Access is denied`），构建最后一步失败。
  已在 `frontend/.gitignore` 里留了 `.esbuild-tmp/`，命令见 §16。
- 菜单只放了 recon 真正支持的 3 个页面。ARL 有 10 个（PoC 信息、资产分组、
  指纹管理、策略配置、域名前缀统计…），这些后端还没有对应能力，
  硬摆上去只会点开一片空白。新增页面的路径是：先补 `/api/*`，再加一个
  `src/views/*.vue` 和一条路由。
- 扫描任务状态在进程内存里：**服务重启会丢掉正在跑的扫描**
  （已落库的事件与资产仍在，历史扫描可正常查看）。要跨重启续跑需把任务状态机也持久化。
- 尚无全局限速与代理池（`HTTPClient` 支持 proxy，但没有按源配额）。
- `event` 表只保留第一条 parent 关系；要记录全部来源需加 `event_edge` 表。

**M6 相关**

- **变更监控只在 Web 进程里跑**：关掉 Web 服务，周期任务就停了。不像 ARL 有独立的
  `arl-scheduler` 常驻服务。这是"不要 Docker、单进程"的直接代价 —— 想要独立常驻，
  再起一个 `recon` 指向同一个 PostgreSQL 也能工作，而且比 SQLite 更稳 ——
  MVCC 下多个进程/多个扫描同时写不会再 `database is locked`。
- **首次运行不告警**：监控刚建立时只记基线。这是刻意的，但也意味着"新建监控后立刻
  想看效果"不会收到推送。
- 告警**没有去重与抑制窗口**：同一处变化不会重复推（因为每次都是与上一次比），
  但短时间内反复触发多次扫描就会推多条。也没有重试队列 —— 推送失败只记日志。
- 邮件渠道用 `smtplib` + `asyncio.to_thread`；**未做 TLS 证书校验选项**，
  非 465 端口走明文 SMTP（STARTTLS 未自动协商）。
- 截图**每个主机只截一张**（`per_host=true`），且只截页面首屏（`full_page=false`），
  两者都可通过模块配置改。截图依赖本机装了 Chromium，否则模块软失败（会被禁用并
  在 `modules_skipped` 里给出原因），其余扫描不受影响。
- 导出的 `event_edge`、变更明细等长字段在 CSV 里会被截断（超过 200 字符的 `*_json`
  列不进 CSV），完整结构请用 JSON/XLSX。
- 变更历史**不自动清理**：`change` 表会随监控次数单调增长，长期运行需要自己加保留策略。

---

## 12. 路线图

| 阶段 | 内容 | 状态 |
|---|---|---|
| **M1** | 事件引擎骨架：Event / BaseModule / 队列分发 / preset / 存储 | ✅ 完成 |
| **M2** | 被动源：8 个免费无 Key 的源 + 插件框架 + 结果清洗 | ✅ 完成 |
| **M3** | 泛解析探测 + `dns_brute` + `dns_permute` + CDN 判定 + ASN 富化 | ✅ 完成 |
| **M4** | `port_scan` + `http_probe` + `tls_cert` + `fingerprint`（含内网段闸门） | ✅ 完成 |
| **M5** | Web 管理台（任务下发、SSE 进度、资产列表、事件溯源树）+ 授权白名单 + 分级审计 | ✅ 完成 |
| **M6** | 变更监控（diff + 周期任务）、告警推送（webhook/钉钉/飞书/企微/邮件）、导出（JSON/CSV/XLSX）、截图 | ✅ 完成 |

---

## 13. Web 管理台（M5）

```bash
python -m core --port 8791 --token 你的令牌
```

**没有 Docker、没有 Nginx、没有 Celery/Redis、没有额外 worker 进程。**
引擎本身就是 asyncio，FastAPI 也是 asyncio，扫描任务直接在同一个事件循环里跑。
一条命令就是完整系统。

> 对比 ARL：需要 MongoDB + RabbitMQ + Nginx + 四个 systemd 服务
> （`arl-web` / `arl-worker` / `arl-worker-github` / `arl-scheduler`），
> 官方建议 4C8G，且不支持 Windows。

### 前后端分离

前端是**独立的 Vue 工程**（`frontend/`），具备自己的 `package.json`、依赖与构建，
后端不包含任何前端源码 —— 只托管构建产物。

```
frontend/                        # Vue 3 + Ant Design Vue 4 + Vite
├── package.json                 # 独立依赖与脚本（dev / build）
├── vite.config.js               # /api 代理到后端；构建输出到 frontend/dist
├── public/                      # logo / favicon
└── src/
    ├── App.vue                  # 布局外壳（对标 ARL）
    ├── styles/global.css        # 主题令牌 + ant-design 覆盖
    ├── router/index.js          # 路由与菜单
    ├── api/                     # http / 接口封装 / SSE 流
    ├── components/              # SettingsDrawer / TokenGate
    └── views/                   # 一键收集 / 任务管理 / 任务详情 / 资产搜索
```

```bash
cd D:\Search\recon

# ── 开发：两个进程，前端热更新 ──
cd backend && python -m core                # 后端 :8000
cd frontend && npm run dev               # 前端 :5173，/api 自动代理到 8000

# ── 生产：一个进程，后端托管 ──
cd frontend && npm run build             # → frontend/dist
cd ../backend && python -m core             # 后端自动托管 dist，含 SPA 深链兜底
```

**Windows 上构建有个坑**：esbuild 删系统临时目录里的文件会被拒
（`Access is denied`，构建最后一步失败）。把临时目录指到工程内即可：

```powershell
cd D:\Search\recon\frontend
New-Item -ItemType Directory -Force .esbuild-tmp | Out-Null
$env:TEMP = (Resolve-Path .esbuild-tmp).Path; $env:TMP = $env:TEMP
npm run build
```

**布局对标 ARL**（逐项在真实浏览器里断言过，见 §16）：

| 元素 | 规格 |
|---|---|
| 侧边栏 | 固定定位，宽 `170px`（折叠 `50px`），背景 `#1a1a1a` |
| 侧栏菜单项 | 高 40px，文字 `#a0a0a0`；选中 = 白字 + 3px 橙红左边条 + `rgba(194,65,12,.15)` 底 |
| 顶栏 | 高 `64px`，白底，sticky，`0 1px 4px rgba(0,0,0,.08)` 阴影；左侧折叠按钮 + 页面标题 |
| 内容区 | 背景 `#fafbfc`，内边距 `24px 32px` |
| 强调色 | `#c2410c`（橙红），经 `ConfigProvider` 注入 antd 主题 |

### 接口一览

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | 健康检查 + 是否需要令牌（**免认证**） |
| GET | `/api/presets` | 内置预设列表 |
| GET | `/api/modules?preset=` | 模块清单与 flags、以及被预设过滤掉的原因 |
| GET/PUT | `/api/settings` | 授权白名单、令牌、并发上限 |
| GET | `/api/stats` | 首页概览（跨扫描去重的资产计数） |
| GET | `/api/search` | **跨扫描全局资产搜索**（`q` / `type` / `scan_id`） |
| POST | `/api/scans` | 下发扫描（**先过授权校验**） |
| GET | `/api/scans` | 扫描列表（含历史） |
| GET | `/api/scans/{id}` | 状态 + 实时进度 |
| DELETE | `/api/scans/{id}` | 删除扫描及其全部资产（审计日志保留） |
| GET | `/api/scans/{id}/progress` | **SSE** 实时进度流 |
| POST | `/api/scans/{id}/stop` | 停止 |
| GET | `/api/scans/{id}/assets` | 域名 / IP / 端口 / 端点 / 技术栈 / 发现 / 审计 |
| GET | `/api/scans/{id}/events` | 事件（可按类型过滤） |
| GET | `/api/scans/{id}/trace/{eid}` | **递归溯源链** |
| GET | `/api/scans/{id}/diff` | 与上一次扫描的**变更对比** |
| GET | `/api/scans/{id}/export` | 导出 `json` / `csv` / `xlsx` |
| GET | `/api/scans/{id}/screenshots/{name}` | 截图（严格校验文件名，防穿越） |
| GET | `/api/changes` | 变更历史 |
| GET/POST/PUT/DELETE | `/api/monitors` | 周期监控的增删改查 |
| POST | `/api/monitors/{id}/run` | 立即执行一次监控 |
| POST | `/api/notify/test` | 给所有已配置渠道发测试消息 |
| GET | `/api/audits` | 全量审计日志 |

### 授权白名单（失败关闭）

Web 是面向远程/多人的入口，所以默认强制校验；**白名单为空时一律拒绝**，
而不是放行。它只约束扫描目标，不限制操作者 —— 所有放行与拒绝都写审计。

```
example.com          # 匹配自身及所有子域
*.example.com        # 只匹配子域, 不含 example.com 本身
10.0.0.0/8           # 网段
*                    # 放行一切 —— 等于关掉这层保护, 界面会提示
```

### 分级审计

每条审计都带 `mode` 字段，一眼看出这次操作**会不会向目标发包**：

```
17:50:51 scan_denied     mode=unknown   allowed=0 evil.com
17:50:51 settings_update mode=n/a       allowed=1 example.com
17:50:51 scan_start      mode=active    allowed=1 example.com
17:50:58 scan_finish     mode=active    allowed=1 example.com
```

`mode` 由启用模块的 flags 推导：只要有一个模块带 `active` 标签就是 `active`。
`detail` 里还会写明具体是哪些主动模块、哪些高噪声模块。

### 访问令牌

ARL 的 `AUTH` 默认是 `False`（服务暴露即无鉴权），我们不想犯同样的错：

* `--token` 设置令牌后，`/api/*` 需要 `Authorization: Bearer <token>`
* **只保护数据面**：静态 HTML/JS/CSS 与 `/api/health` 保持开放 ——
  否则浏览器加载 `<script src>` 时没法带头，页面根本打不开
* 前端会把令牌存在 localStorage，遇到 401 会弹框询问并重试
* 未设令牌时启动会打 WARNING；对外监听（非 127.0.0.1）且没令牌时再警告一次

> ⚠️ **令牌是明文 HTTP 传输的**。要远程使用，请置于 HTTPS 反代之后，
> 或只通过 SSH 隧道访问。当前也没有多用户/RBAC —— 只有一个共享令牌。

### 前端能力

任务下发（含 `-c` 风格的配置覆盖）、SSE 实时进度、资产多标签页浏览、
**点击任意事件查看它的来源链**（这是 ARL 完全没有的能力），以及设置与审计面板。

---

## 14. 变更监控 · 告警 · 导出 · 截图（M6）

### 14.1 变更对比

所有资产表都带 `first_seen` / `last_seen`，那是"什么时候出现过"的记录；
真正有用的问题是**"和上次比，多了什么、少了什么、什么变了"**。

`services/diff.py` 按**自然键**索引后做集合运算：

| 资产 | 自然键 | 参与对比的属性 |
|---|---|---|
| domains | name | is_cdn / is_wildcard |
| ips | addr | asn / org / country / is_cloud |
| ports | (ip, port) | 证书 CN / 剩余天数 |
| endpoints | url | 状态码 / 标题 / Server / 长度 |
| technologies | (host, name) | — |
| findings | (kind, target, detail) | severity |

ARL 是逐个资产类型写一套监控逻辑（`asset_site_monitor.py` 等四五个文件），
这里做成通用 diff。在任务管理页点「对比」即可：

```bash
$ 在任务管理页点该扫描的「对比」
### recon 变更报告
**目标**: example.com
**扫描**: #9 → #12

新增 **1** · 消失 **1** · 变化 **0**

**新增**
- 域名: `dev.example.com`
**消失**
- 域名: `api.example.com`
```

### 14.2 周期监控（没有独立调度进程）

对应 ARL 的 `arl-scheduler` 服务 + 计划任务，但这里**就是 Web 进程里的一个
asyncio 任务**：每 N 秒扫一遍到期的 monitor，起扫描，扫完算 diff、落库、推告警。

一个刻意的取舍：**首次运行只建立基线，不告警**。否则监控刚建好就会推一条
"新增 300 条资产"，纯属噪音。

```
监控「prod」建立基线: 扫描 #1（3 条资产），本次不告警
监控「prod」变更: 扫描 #1 -> #2，共 2 处变化     → 推送告警
```

扫描状态多了个 `finalizing` 阶段：扫描本体结束后、变更对比与告警推送完成之前，
状态就是它 —— 否则调用方看到 `finished` 就去读变更记录，会读到还没写完的东西。

### 14.3 告警推送

移植 ARL 的 `app/utils/push.py`（MIT），签名算法**刻意保持一致**：

| 渠道 | 报文 | 签名 |
|---|---|---|
| 通用 webhook | `{source,title,text,level}` + `Token` 头 | — |
| 钉钉 | `{"msgtype":"markdown","markdown":{...}}` | `urlencode(base64(HMAC-SHA256(key=secret, msg=f"{ts_ms}\n{secret}")))` |
| 飞书 | `{"msg_type":"post","content":{"post":{"zh_cn":{...}}}}` | `base64(HMAC-SHA256(key=f"{ts_s}\n{secret}", msg=""))` |
| 企业微信 | `{"msgtype":"markdown","markdown":{"content":...}}` | — |
| 邮件 | MIMEMultipart HTML | SMTP_SSL(465) / SMTP(其他) |

> 注意飞书与钉钉是**反的**：钉钉把 `secret` 当 key、拼接串当消息；飞书把拼接串当 key、
> 消息留空。这两家的签名是最容易写错的地方，所以两个签名函数都有对照手工 HMAC 的单元测试。

推送是"尽力而为"：失败只记日志并返回 `(False, 原因)`，绝不影响扫描本身。

### 14.4 导出

| 格式 | 内容 |
|---|---|
| `json` | 完整结构（扫描元信息 + 全部资产），适合程序消费 |
| `csv` | 单表导出，用 `type=` 指定（默认 domains），**前置 BOM** 以免 Excel 中文乱码 |
| `xlsx` | 一个工作表一种资产 + 一张概览表，带表头样式、列宽自适应、冻结首行 |

### 14.5 截图

ARL 用 **PhantomJS**（2018 年停更），我们换成 Playwright + Chromium。

截图是二进制，塞不进事件载荷，所以：

```
URL 事件 → 截图落盘 → FINDING(kind=screenshot, data=URL, detail=相对路径)
                          ↓ 存储层回填
                   http_endpoint.screenshot
```

浏览器起不来时 `setup()` 返回 `None` **软失败**（模块被禁用、扫描继续）——
这正是模块契约里"软失败"要解决的问题。

> ⚠️ **实测踩到的环境坑**：本机 Windows 注册表把 `.png` 关联成了 `silenteye/png`，
> Python 的 `mimetypes` 读注册表后返回这个垃圾值，而 Playwright 会按扩展名推断图片
> 类型，于是报 `Unsupported screenshot mime type` —— 截图静默失败、只剩一个空字符串。
> 修法是两手：截图时显式 `type="png"`，并在 `backend/core/util/mime.py` 里于进程启动时
> 纠正被污染的映射（实测这台机器有 7 个扩展名被污染）。

---

## 15. 合规

**仅对已获得明确书面授权的目标使用。**

已内置的保护：范围校验默认强制、敏感域名默认拒绝、端口扫描前内网与保留地址默认拒绝、
被动源与主动模块用 flags 严格区分、所有过滤/跳过行为都留痕。

**授权白名单**（Web 入口失败关闭，空白名单拒绝一切下发）与**分级审计**
（每条审计带 `mode=passive/active`，事后可查清哪次操作向目标发过包）已完成，见 §13。

---

## 16. 自检与验证

```bash
cd D:\Search\recon\backend          # 以下命令都在 backend/ 下执行

# 263 个单元/集成测试（全部离线，不触网）
python -m unittest discover -s tests -t .

# 后端接口冒烟（对着已启动的服务）
python scripts/status.py   http://127.0.0.1:8000
python scripts/web_smoke.py http://127.0.0.1:8000      # 含一次真实扫描
python scripts/m6_smoke.py  http://127.0.0.1:8000      # 监控→变更→告警→导出

# 前端：真实浏览器里检查渲染、JS 报错、以及 ARL 布局规格，并截图
python scripts/ui_check.py http://127.0.0.1:8000 D:\Search\recon\.shots
```

`ui_check.py` 断言的是**计算样式**而不是"看起来对"：

```
侧边栏        宽 170px  背景 rgb(26, 26, 26)
顶栏          高 64px
选中菜单左边条 rgb(194, 65, 12)
✓ 没有 JS 报错
✓ 布局规格全部符合 ARL 目标
```

最后更新：M1–M6 完成，前端重构为独立的 Vue 3 + Ant Design Vue 工程（对标 ARL 布局）。
