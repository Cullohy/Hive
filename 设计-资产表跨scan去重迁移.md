# 迁移设计：资产表跨 scan 去重

> **决策依据**（2026-09-30 定）：资产是**长期存在的实体**，不是"某次扫描的产物"；16 张表一起梳理；
> `dedup_key` **不带 query string**；http/https 合并为一条资产另存 `schemes[]`。
>
> **本文档是施工图**，实施前请过一遍，尤其是 §9 里那处**我要修正的建议**。

---

## 1. 结论先行：实际只动 6 张，不是 16 张

把 16 张表按**性质**分完类之后，需要改的只有 6 张。

| 层 | 表 | 处置 | 为什么 |
|---|---|---|---|
| **资产层**（跨 scan 实体） | `domain` `ip` `port` `http_endpoint` `url` `technology` | **改**（6 张） | 它们回答"世界上存在什么资产"——同一个资产被扫两次不该变成两行 |
| **观测层**（某次扫描看到了什么） | `event` `finding` `audit` `change` | **不动** | 它们回答"**这次**扫描发生了什么"。事件是 append-only 的历史记录，本来就该带 scan 维度 |
| **关系层** | `domain_ip` `asset_group` `asset_group_scope` `asset_group_asset` | **结构不动** | 本来就是全局的；资产去重后它们的语义反而**变准确**了 |
| **全局配置** | `scan` `monitor` | 不动 | 已经是全局的 |
| **新增** | `scan_asset` | **建** | 把"资产"和"哪次扫描看到它"连起来 |

### 为什么 `event` / `finding` 不该跟着改

这是本次迁移**最容易做错的决定**。看起来"全部去掉 scan_id"很整齐，但会毁掉两件事：

1. **`event` 是 append-only 的证据链**（§2.1 的 `raw_hit` 同层）。去掉 scan 维度等于把"这次扫描的执行轨迹"和"这个资产的状态"混成一锅，回溯能力和断点续跑都会失去依据。
2. **`finding` 是证据，不是状态**。`domain.is_cdn` 这种**状态**列才该是资产级；finding 是"凭什么说它是 CDN"的**证据**。证据天然属于某次观测。

> **一句话判据：能回答"世界上存在什么"的改，能回答"这次跑的时候看到了什么"的不改。**

（`audit` 是审计日志、`change` 是两次扫描之间的时间序列——都不言自明。）

---

## 2. 目标模型：三层

```
观测层（per-scan，append-only）      event  finding  audit  change        ← 不动
                                      （未来 + raw_hit）
                                            │  投影
                                            ▼
资产层（global，去重）               domain  ip  port  http_endpoint  url  technology
                                            │
关联层（多对多）                     scan_asset(scan_id, asset_type, asset_key)
                                            │
                                            ▼
                                    任务详情页：WHERE scan_id = ?  →  join scan_asset
                                    资产库页面：直接查资产表（不再需要 DISTINCT）
```

**关键收益**：`summary()` 里那些 `COUNT(DISTINCT ...)`、跨 scan 的 `MIN(first_seen)`、以及
"本周新增"这类现在**算不出来**的 KPI，全部变成直读。

---

## 3. `dedup_key` 规范

### 3.1 规则总表

| 表 | 现唯一键 | 新唯一键 | 规范化 |
|---|---|---|---|
| `domain` | `(scan_id, name)` | `(name)` | 小写、去尾点（`.example.com.` → `example.com`） |
| `ip` | `(scan_id, addr)` | `(addr)` | 标准 IPv4/IPv6 文本形式 |
| `port` | `(scan_id, ip, port, protocol)` | `(ip_id, port, protocol)` | ip_id 现在全局唯一，直接可用 |
| `technology` | `(scan_id, host, name)` | `(host, name)` | host 小写；name 用指纹库的标准名 |
| `url` | `(scan_id, url)` | `(dedup_key)` | ↓ §3.2 |
| `http_endpoint` | `(scan_id, url)` | `(dedup_key)` | ↓ §3.2 + **§9.1 待确认** |

### 3.2 URL 类的 `dedup_key`

```
dedup_key = lower(host) + "|" + normalize_path(path)
```

- **`normalize_path`**：去掉结尾 `/`（根路径 `/` 除外）、**丢掉 query string**、丢掉 `fragment`
- **scheme 不进 key**（http/https 合并成一条资产），另存 `schemes TEXT[]`

用真实数据验证过（`panabit.com` / `chinazy.org` / `sinosoft.com.cn`）：

```
forum.panabit.com/search.php?mod=forum&srchtxt=流量控制&formhash=62efac51
forum.panabit.com/search.php?mod=forum&srchtxt=AP&formhash=150ae651
forum.panabit.com/search.php?searchsubmit=yes
        ↓  合并为一条
forum.panabit.com|/search.php        schemes={http,https}
```

**为什么必须丢掉 query**：`formhash` 是 CSRF token，**每次会话都变**。带进 key 的话，
定期监控每跑一轮都会"新增"一批资产 —— 去重直接失效，而这正是本次迁移要解决的问题。

**丢了什么**：只有"当时那条 URL 的完整参数"。它们是搜索词 / 帖子 ID / token，**是页面内容，
不是暴露面**。完整 URL 仍原样保留在 `url` 列里作为**资产线索**。

> ⚠ **边界**：**不要**另建 `query_keys` / `params` 之类的结构化列。那正是设计文档 §1.2 第 2 条
> 禁止的「接口语义清单：**参数**、鉴权、接口文档解析」。
> 保留完整 URL ✅（§1.2 的边界说明明确允许"JS 运行时暴露的 URL 线索当作资产线索入库"）；
> 把参数抽出来结构化成"这个端点接受这些参数" ✗。

### 3.3 实测影响（现有 1495 条真实 URL）

用 **M7-a 已经落地的 ``core/util/asset_key.py``** 跑 ``scripts/dedup_preview.py`` 得到：

```
url 表          1495 条  ->  dedup_key 1048 个   **合并 447 条（29%）**
http_endpoint       39 条  ->  dedup_key    39 个   合并   0 条（0%）
```

**447 条的归因**（``--explain``）：

| 原因 | 条数 | 占比 |
|---|---|---|
| **仅 http/https 不同** | **433** | **96%** |
| 仅 query / 尾斜杠不同 | 14 | 3% |

> ⚠ **订正一个我早先报错的数字。** 迁移文档初稿里我写的是"合并后 1438 条、只差 30 条"——
> 那个数是用**保留 scheme** 的口径估的（只丢了 query），**没有把 http/https 合并算进去**。
> 按最终确定的规则是 **1048 条 / 合并 447 条**。差距全部来自 http/https。

**`http_endpoint` 合并 0 条**这件事，实测确认了 §9.1 那个"两套规则故意不一致"的设计是对的：

* `url` 表合并了 433 组 http/https —— 它回答"这个资源存在"，合并是对的；
* `http_endpoint` **一条都没合** —— `http://x/admin` 的 301 和 `https://x/admin` 的
  200 + favicon hash + 截图**全部原样保留**。

**两个诉求都满足了，而且没有靠"二选一"妥协。**

三个规则口径对比（同一批数据）：

| 口径 | 结果 |
|---|---|
| 全 URL 去重（带 scheme / query / 尾斜杠） | 1495 |
| 丢 query，保留 scheme | 1438 |
| **丢 query + 合并 http/https（本次规则）** | **1048** |

现在 29% 这个比例偏高，是因为**同一目标还没被扫过第二遍**——这批数据里有大量
`http://` 与 `https://` 成对出现的 URL。定期监控一开，query 那一类（`formhash` 那种
每次会话都变的参数）会成为主力，而那类**只有丢 query 才治得住**。

---

## 4. `scan_asset` 关联表

```sql
CREATE TABLE IF NOT EXISTS scan_asset (
    scan_id     BIGINT      NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
    asset_type  TEXT        NOT NULL,   -- domain | ip | port | http_endpoint | url | technology
    asset_key   TEXT        NOT NULL,   -- **自然键**，不是 id：域名 / IP / dedup_key / host|name
    first_seen  TEXT        NOT NULL,   -- **这次扫描内**首次看到
    last_seen   TEXT        NOT NULL,
    PRIMARY KEY (scan_id, asset_type, asset_key)
);
CREATE INDEX IF NOT EXISTS idx_scan_asset_asset ON scan_asset(asset_type, asset_key);
```

**三个设计取舍**：

1. **用自然键，不用 `asset_id`** —— 这是查过现有数据后**改的**。第一版我打算用 `asset_id BIGINT`，
   但查 `asset_group_asset` 发现**仓库里已有的多态关联表用的就是自然键**（`asset_type, asset_key`
   = `('domain', 'anli.chinazy.org')`、`('ip', '112.16.229.53')`）。

   更重要的是：**迁移会合并重复行、删掉被合并的那些**。如果用 `asset_id`，这些关联全部变成孤儿，
   得靠重指向脚本补救；**自然键天然免疫**（被合并的行的 key 和存活行相同）。所以自然键不只是
   "和现有模式一致"，它在这个场景下**确实更对**。

2. **多态外键（没有 FK 约束）**：`asset_key` 指向哪张表由 `asset_type` 决定，数据库没法建 FK。
   代价是可能出现孤儿行，**配一个对账查询**兜底（§6.4）。
3. **`ON DELETE CASCADE` 只挂在 `scan_id` 上**：删扫描 → 删掉"这次看到了什么"的记录，
   **资产本身留着**。这是本次语义变化的核心。

---

## 5. 逐表改造（4 处 SQL 变化）

### 5.1 `domain`

```diff
- CREATE UNIQUE INDEX uq_domain ON domain(scan_id, name);
+ CREATE UNIQUE INDEX uq_domain ON domain(name);
- scan_id BIGINT NOT NULL REFERENCES scan(id) ON DELETE CASCADE,
+ -- scan_id 列保留但**不再参与唯一键**，且改可空（历史行仍需回填）
+ scan_id BIGINT REFERENCES scan(id) ON DELETE SET NULL,
```

> **`scan_id` 列留不留？** 留。全库唯一不等于要抹掉"第一次是谁发现的"这个信息 —— 它作为
> **来源标注**仍有价值（对应 `url.source` 的角色）。但**不再参与唯一键**，且不再 CASCADE 删除。

### 5.2 其余 5 张同理

| 表 | 新唯一键 |
|---|---|
| `ip` | `(addr)` |
| `port` | `(ip_id, port, protocol)` |
| `technology` | `(host, name)` |
| `url` | `(dedup_key)` — 加列 `dedup_key TEXT`、`schemes TEXT[]` |
| `http_endpoint` | `(dedup_key)` — 加列 `dedup_key TEXT`、`schemes TEXT[]` |

### 5.3 列的变化（**比初稿少 12 个列**）

初稿打算给 6 张表都加 `asset_first_seen` / `asset_last_seen` 两组时间，理由是
"任务详情页要扫描内的时间、资产库要资产级的时间"。

**实现时发现这是多余的**：那个区分**已经由分层本身表达了**——

```
资产表  url.first_seen / last_seen        → 资产级（跨扫描，最早/最晚被发现）
关联表  scan_asset.first_seen / last_seen → 扫描内（这次跑的时候首次/末次看到）
```

两张不同的表，语义天然不冲突，**不需要在同一张表里塞两组时间列**。
所以 M7-b 只加这些：

| 表 | 加列 | 说明 |
|---|---|---|
| `url` | `dedup_key TEXT`、`schemes TEXT[]` | 身份 + 协议集合 |
| `http_endpoint` | `dedup_key TEXT`、`schemes TEXT[]` | 同上（但身份规则带 scheme） |
| 其余 4 张 | **不加列** | `domain.name` / `ip.addr` / `port(ip_id,port,protocol)` / `technology(host,name)` **本来就是自然键**，不需要额外的 `dedup_key` 列 |

> 只有 `url` 和 `http_endpoint` 需要 `dedup_key` 列，因为它们的键是**推导出来的**
> （见 §3.2）；其余 4 张表的自然键就是已有列。

**M7-b 状态：✅ 已完成**（2026-09-30）。ADD COLUMN 全部 `IF NOT EXISTS`、
唯一键**未动**，所以 485 个测试全绿、存量行数一行没变。两条路径都验过：
新库（测试建独立 schema 跑完 `schema.sql`）与存量库（`ALTER` 补列）。

---

## 6. 迁移脚本策略

沿用 `scripts/backfill_shadow.py` 已经验证过的模式：**默认干跑，`--apply` 才写库**。

### 6.1 幂等

- 加一个 `schema_version` 表记录已应用的迁移号
- 所有 DDL 用 `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`
- 数据回填用 `INSERT ... ON CONFLICT DO UPDATE`，**可重复跑**
- 迁移号 + 校验和（文件哈希），防止"改了脚本又跑一遍"

### 6.2 合并重复行的策略

现有 1495 条 URL 合并后是 1438 条 → **有 57 条要被合并掉**。合并规则：

| 冲突项 | 取谁 |
|---|---|
| `first_seen` | **最早**的（资产的真实首见时间） |
| `last_seen` | **最晚**的 |
| `source` / `kind` | 合并去重（`source` 已经是多值语义） |
| `status` / `title` / `favicon_hash` | **非空优先，都有则取 `last_seen` 更晚的那条** |
| `screenshot_data` | 见 §9.1 |
| 被 FK 引用的行（如 `scan_asset`、`asset_group_asset`） | **重指向存活行**，不能直接删 |

### 6.3 可回滚

```sql
-- 动手前先整体备份（16 张表逐张）
CREATE TABLE <t>_migbak_20260930 AS SELECT * FROM <t>;
```

备份表**保留到验证通过后**再删。`--rollback` 子命令从备份表恢复。

### 6.4 对账查询（迁移后必跑）

```sql
-- 孤儿关联行（资产被合并了但关联没重指向）
SELECT sa.asset_type, COUNT(*) FROM scan_asset sa
LEFT JOIN ... -- 按 asset_type 分派
WHERE ... IS NULL GROUP BY 1;

-- 唯一键冲突（迁移没干净）
SELECT dedup_key, COUNT(*) FROM url GROUP BY 1 HAVING COUNT(*) > 1;
```

已实现在 `scripts/migrate_m7c.py --verify`，六类资产逐个查孤儿。

### 6.5 M7-c 实际结果（2026-09-30）

```
备份     url_migbak_20260930 (1495 行)  http_endpoint_migbak_20260930 (39 行)
         scan_asset_migbak_20260930 (0 行)          合计 408 KB

url              1495 行 -> 1048 个 dedup_key（404 个键对应多行，M7-d 要合并）
http_endpoint      39 行 ->   39 个 dedup_key（合并 0，预期）
scan_asset       4669 条关联 = domain 3288 + url 1048 + port 192 + technology 58
                              + ip 44 + http_endpoint 39

对账    url.dedup_key 未回填 0；重复键 404 组（M7-c 阶段预期 >0）
        六类资产孤儿关联行全部 0
```

**幂等已验证**：连跑两次，第二次 `待更新 0 行`、各类 `库中已有` 正好等于预期条数，
一条都没重复插。

**回填的两个交叉验证**（两处独立算出的数字必须相等）：

1. `scan_asset` 里 url 那类的"去重掉 **447**" == M7-a 用 `url_key` 算出的合并数 **447** ✓
2. 资产键的形态抽查全部正确，包括两个 bug 修复的效果：
   `…saas.panabit.com:8090|/`（非默认端口进键）、`http://anli.chinazy.org|/`（scheme 进键）

**实施时发现并修掉的一个 bug**（值得记，因为同类错误会让干跑失去意义）：
`_ASSET_SOURCES` 最初给 `url` / `http_endpoint` 加了 `WHERE dedup_key IS NOT NULL`，
结果干跑时那列还没填，这两类各报「源 0 行」—— **干跑严重少报**，而干跑的全部意义
就是"先看清楚"。而且那让 `scan_asset` 的回填**依赖 `dedup_key` 已被填**，两步绑死。
键在 Python 侧算，跟列填没填无关，过滤是多余的。

---

## 7. 代码影响面（精确数字）

### 7.1 存储层 `core/storage/postgres.py`

**写点 6 个方法**（都要去掉 `scan_id` 参与冲突键、改为写 `dedup_key`，并**额外写一行 `scan_asset`**）：

```
:595  _upsert_url
:661  _upsert_port
:703  _upsert_http_endpoint
:746  _upsert_technology
:795  _upsert_domain
:824  _upsert_ip
```

**读点 10 个方法**（改为 `JOIN scan_asset`，或用资产级查询）：

```
:935  events              ← 不动（观测层）
:945  domains             ← 改
:973  ips                 ← 改
:981  findings            ← 不动
:986  ports               ← 改
:994  endpoints           ← 改
:1074 urls                ← 改
:1081 technologies        ← 改
:1087 summary             ← 改（口径重算）
:1291 audits              ← 不动
:1314 search_assets       ← 变简单（本来就跨 scan）
:1362 search_counts       ← 变简单
```

### 7.2 API 层

`core/web/app.py` 里 `scan_id` 出现 **83 次**。但**只有资产类接口需要改**：

```
GET /api/scans/{id}/assets        ← 唯一入口，前端只调这一个（好消息）
GET /api/scans/{id}/events        ← 不动
GET /api/scans/{id}/diff          ← 不动
```

### 7.3 前端

**只有 1 个函数受影响**：`frontend/src/api/index.js` 的 `getAssets(id, limit)`。

页面内部不用改结构 —— 它拿到的仍然是"这次扫描的资产列表"，只是后端从 `WHERE scan_id=?`
换成了 `JOIN scan_asset`。**任务详情页的 10 个页签、统计卡片、`ui_check` 的一致性断言都不用动。**

> 这是本次迁移最省事的一点：前端把资产访问**收敛到了一个接口**。

---

## 8. 测试影响面

```
直接调用 storage.domains/ips/ports/endpoints/urls/technologies:  39 处
  test_passive.py    14
  test_m3.py         10
  test_m4.py          6
  test_engine.py      3
  test_m6.py          3
  test_storage.py     2
  test_fingerprint.py 1

测试里 scan_id 出现:  181 次
```

**预期红的测试分两类**：

| 类型 | 例子 | 处理 |
|---|---|---|
| **断言扫描隔离**的 | "扫描 A 的域名不该出现在扫描 B 里" | **改成断言共存**：扫描 A 和 B 各看到各自的行，但资产表只有一条 —— 这**正是新语义**，测试要跟着改，不是误报 |
| **断言唯一键**的 | `test_insert_returns_id` 等 | 改断言 |

**新增测试**（至少）：
1. 同一 URL 扫两次 → 资产表 **1 行**，`scan_asset` **2 行**，`last_seen` 被推后
2. `http://x/a` 与 `https://x/a` → 资产 **1 行** + `schemes={http,https}`
3. 带 query 的 12 条 `search.php` → 资产 **1 行**
4. **删扫描不删资产**（`ON DELETE CASCADE` 语义验证）
5. `dedup_key` 规范化函数的单元测试（尾斜杠 / 大小写 / query / fragment / 根路径）
6. 迁移脚本幂等性（连跑两次结果一致）

---

## 9. 已知的坑

### 9.1 ⚠ `http_endpoint` 的 scheme：**我要修正之前的建议**

我先前说"http/https 算一条，另存 `schemes[]`"。**对 `url` / `url_path` 是对的，对
`http_endpoint` 有问题**：

`http_endpoint` 存的是**响应观测** —— `status` / `title` / `content_length` / `favicon_hash` /
`screenshot_data` **都是 per-scheme 的**。同一个 path 上：

```
http://x/admin    →  301  "重定向"
https://x/admin   →  200  "运维管理平台"   favicon_hash=128...
```

合并成一行的话，`status`/`title`/`favicon_hash`/截图**必须二选一**，会丢真实观测。

**修正建议**：

| 表 | scheme 进不进 key | 理由 |
|---|---|---|
| `url` / `url_path` | **不进**（合并 + `schemes[]`） | 它们是**资产**："这个资源存在" |
| `http_endpoint` | **进**（`dedup_key = scheme + host + path`） | 它是**观测**："这个 scheme 下的响应长什么样" |

这样"路径数"这类 KPI 数 `url`（不重复），而"http 可达"这类暴露面事实由 `http_endpoint` 表达 ——
**两个诉求都满足，且都不丢。**

> 如果你觉得"两张表的 key 规则不一致"更容易出错，替代方案是 `http_endpoint` 也合并、
> 把 per-scheme 细节塞进 JSONB。**我倾向上一张表的做法**（可查询性更好），但这条请你定。

### 9.2 ⚠️ 迁移暴露的一个**架构冲突**：变更监控需要"每次扫描的快照"

**这是初稿的 §8「测试影响面」完全没预料到的。** 那一节只数了 39 处调用点，没看出
语义层面的问题。

M7-e 改完读点之后，`test_m6.TestDiff.test_added_removed_changed` 挂了，而且是
**正确地把问题暴露出来**：

```
扫描1 写入:  ('1.1.1.1', org='OldOrg')
读扫描1:     ('1.1.1.1', org='NewOrg')   ← 读到的是**当前值**，不是扫描1时的值
读扫描2:     ('1.1.1.1', org='NewOrg')

两次读数一模一样 ⇒ diff 永远看不到"归属从 OldOrg 变成 NewOrg"
```

**根因**：`diff_scans` 的做法是"读扫描 A 的资产 vs 读扫描 B 的资产，比差异"。
在 per-scan 模型下这是对的（各有一份独立行）。但资产变成**全局唯一的可变行**之后，
两次读的是**同一行**，历史状态被覆盖 —— **变更检测从根上失效了**。

这不是 bug，是**两种模型的性质冲突**：全局唯一的实体没有历史。

#### 两条修法

| | 做法 | 代价 | 契合度 |
|---|---|---|---|
| **(a)** **`scan_asset` 加 `snapshot`** | 关联行不只记"看到过"，还记"当时长什么样"（JSONB）。`diff` 改读快照 | 每 (扫描, 资产) 存一份小 JSON；改 `_link_asset` 与 `diff.py` | `scan_asset` 变成"这次扫描对这个资产的观测"——与 §2.1 的 `raw_hit → 投影` 分层一致 |
| **(b)** `diff` 改从**观测层**算 | 差异查询走 `event`（append-only，本来就带 scan 维度） | `diff.py` 要重写；`change`/`monitor` 表的读法跟着动 | 最"纯"：设计文档 §2.1 说 `raw_hit` 是"可回放"的真源，资产表只是当前投影 |

**我的倾向是 (a)**：

* 改动小、`diff.py` 的结构不变（它本来就按"每类资产一组字段"比）；
* `scan_asset` 的语义从"看到过"升级成"**这次扫描观测到的状态**"，这本来就是关联表
  该有的内容 —— 只有链接没有状态的话，它回答不了"当时是什么样"；
* 现存的 4669 条关联行可以直接回填快照（用当时的资产表值，能回填多少算多少，
  历史状态本来就已经被覆盖了，回填出来的是"当前值"，这点要在文档里写清楚）。

**为什么没有当场做掉**：这是一个**新的设计决定**（等于给关联表加一层语义），
不该由实现者顺手定。而且旧数据的快照**已经无法恢复**（覆盖掉了），
回填出来的只能算近似 —— 这件事需要你先知道，再决定怎么处理。

#### ✅ 已采用 (a)，并已实现（2026-09-30）

`scan_asset` 加了 `snapshot_json TEXT`，存该资产**被这次扫描看到时的完整行快照**
（显式列，不含截图等大字段 —— `SELECT *` 会把 `screenshot_data` 的二进制塞进去）。
`diff.py` 的 SPECS 加了 `snapshot_type`：资产层读快照，观测层（`findings`）仍直接读表。

三条测试钉住它：

* **防漂移**：SPECS 需要的字段必须在快照列里。这两个列表在两个模块里，
  **没有类型系统能保证一致**；漏一个字段的后果是那一列的变更**静默检测不到**
  （diff 照常返回，只是永远说"没变化"）。
* **保留历史**：两次扫描之间 IP 归属变了，资产表只有一行且值是当前值，
  但**各自的快照留住了当时的值**。
* **重复投影要刷快照**：同一次扫描内重复事件会重新投影，快照得跟着更新，
  否则会停在第一次投影的状态。

> 这条防漂移测试**第一次跑就抓到了它自己的误报**：`ports` 的 `value_fields`
> 是 `("cert_cn","cert_days_left")`，而那是 `transform` 的**输出**、不是行里的列。
> 有 transform 时只能检查转换的**输入**，得单独钉一条。

**坏消息照旧**：存量数据的快照只能是近似的 —— 历史值早被覆盖，回填出来的等于
"当前值"。**从现在开始才能准确追踪变更。**

### 9.2.1 ⚠️ 顺带踩到一个"越跑越少"的坑（已修 + 已恢复）

回填快照时我重跑了 `migrate_m7c.py`，结果 `url.schemes` **被削掉了**：

```
合并后每个 dedup_key 只剩一行 → 重跑时按"本行的 URL 协议"重算
→ ['http','https'] 被覆盖成 ['http']        实测 823 行的双协议变单协议
```

根因是那个脚本的 `backfill_urls` **不是单调的**：它没把"每行已有的 schemes"算进并集。
已修成单调（只会增不会减），并从 `url_migbak_merge_20260930` 逐键恢复 ——
恢复后与备份并集**逐键比对 0 行不一致**。

> **教训**：可重跑的迁移脚本，每一步都必须是**单调**的。幂等不够 ——
> 幂等允许"收敛到错误的值"。这个坑只有在"合并改变了数据形态、脚本又按新形态
> 重算"时才会暴露。

#### 当前状态

**494 / 494 测试通过。**（M7-e 时曾故意留一条失败测试把架构冲突摆出来；
选定方案 (a) 后已实现并转绿。）

### 9.2.2 跨扫描端到端验证（2026-09-30）

迁移期间所有验证都在**单次扫描**的数据上做（库里 3 个扫描目标各不相同），
"同一资产被两次扫描看到"这条路径**从没在真实数据上走过** —— 而那正是整个迁移
要解决的场景。所以专门重扫了一次同一个目标：

```
python -m core ...                            # 起服务
POST /api/scans {"targets":["sinosoft.com.cn"],"preset":"active"}   -> 扫描 #15
```

321 秒跑完（#13 当时 9 分钟），514 个新事件。验证结果：

| 验证项 | 结果 |
|---|---|
| 资产表**没有因为重扫而重复** | domain 3288 → **3289**（只加 1 个！28 个域名合并进已有行） |
| 所有唯一键仍然唯一 | domain / ip / url / http_endpoint 全部 `行数 == 键数` |
| `scan_asset` 建了关联 | #13 = 645，#15 = **410**；总计 4669 → 5079 |
| 两次都看到的资产 | **348 条**（29 个共同域名），资产表里**重复域名 0 个** |
| 读点返回"这次看到的" | `domains(13)`=29、`domains(15)`=30，**两者都与各自 `scan_asset` 的键逐键一致** |
| `first_seen` 保住 | 样本 `cas.sinosoft.com.cn`：`scan_id=13`（最先发现）、`first_seen=09-29`、`last_seen=09-30` |
| `summary` 与关联表一致 | 6 类资产逐一相等 |
| 变更监控 | 265 处变化；domains `+1/-0/~0`（没把所有东西都当新增） |

### 9.2.3 ⚠️ 端到端验证顺带炸出两个截图相关的 bug

**两个都是既有问题，只是要等"扫描真的产生了截图"才触发** —— 而我这次重扫是第一次
（`http_endpoint` 43 行里只有 2 行有截图二进制，都来自 #15）。

#### (1) `endpoints()` 的 `SELECT *` 把截图二进制带进 JSON → 整个详情页 500

```
PydanticSerializationError: Error serializing to JSON:
  invalid utf-8 sequence of 1 bytes from index 0
```

`http_endpoint` 有 `screenshot_data BYTEA`，`SELECT *` 把整张图带进响应，
FastAPI 序列化直接炸。

**而它之所以一直没被发现，是因为测试把它钉成了期望行为**：

```python
self.assertEqual(bytes(endpoints[0]["screenshot_data"]), png)   # ← 反的
```

已改成：`endpoints()` 显式列字段（不含 blob），图片走 `screenshot_blob()` 按需取。

#### (2) `GET /api/screenshots/...` **从来没工作过**

```python
row = await store.conn.fetchrow(...)      # PgConnection 上没有这个方法
# AttributeError: 'PgConnection' object has no attribute 'fetchrow'
```

`PgConnection` 只有 `fetchone` / `fetchall` / `execute` / `executescript`。
**这个路由从写下来就是坏的，且没有任何测试覆盖** —— 点开任何截图都是 500。

顺带还有第二个问题：查询写的是 `WHERE scan_id = $1`，迁移后那个字段只是"谁最先
发现的"，**重扫同一目标时新任务取自己的截图会 404**（而页面上的链接正是新任务 id）。

已改成走 `scan_asset` 确认"这次扫描确实看到过它"，并补了 3 条接口层测试
（`test_serves_the_png` / `test_missing_screenshot_is_404_not_500` /
`test_unknown_scan_id_is_404`）。

> **教训**：这两条测试以前是"用错的断言测对的行为"，而且接口层完全没覆盖。
> 端到端验证的价值就在这里 —— 单元测试全绿也盖不住它。

### 9.2.4 M7-f 完整性报告（删备份前的留档）

备份表已删，**"迁移前长什么样"不可再回溯**。这份报告替代它的可回溯作用 ——
记录迁移**结果**自洽的证据（每个唯一键都唯一、每条关联都带快照）。

```
    ﻿  ══ 前置检查 ══
      ✓ url.dedup_key 非空 1071/1071
      ✓ http_endpoint.dedup_key 非空 43/43
      ✓ 6 个全局唯一键都在
    
      ══ 段 1：删 6 条旧唯一键 ══
        uq_domain, uq_ip, uq_port, uq_url, uq_http_endpoint, uq_technology
      ══ 备份表 4 张 ══
        url_migbak_20260930                  1495 行
        http_endpoint_migbak_20260930          39 行
        scan_asset_migbak_20260930              0 行
        url_migbak_merge_20260930            1495 行
    
      ══ 迁移后完整性报告 ══
      ✓ domain             3289 行 /   3289 键
      ✓ ip                   50 行 /     50 键
      ✓ port                215 行 /    215 键
      ✓ url                1071 行 /   1071 键
      ✓ http_endpoint        43 行 /     43 键
      ✓ technology           63 行 /     63 键
      ✓ scan_asset         5079 条关联（带快照 5079）
          scan#10     3695 条关联
          scan#13      645 条关联
          scan#14      329 条关联
          scan#15      410 条关联
    
      要执行请加 --apply（段 2 另需 --drop-backups）
```

> 报告由 `scripts/migrate_m7f.py` 生成。想复核随时可以重跑那个脚本（它是只读的
> 干跑模式），但**迁移前的数据已经拿不回来了**。

### 9.2.5 ⚠️ M7-f 的 `DROP INDEX` 第一次白做了

删完那 6 条旧唯一键、打完完整性报告之后做状态复核，**6 条索引全都在**。

根因：

```
storage.open()  每次都会重跑整个 schema.sql
schema.sql      里还留着 CREATE UNIQUE INDEX IF NOT EXISTS uq_domain ...
                → 下一次启动就把刚删掉的索引原样建回来
```

**连我自己那条验证脚本的 `open()` 都算一次启动。** 所以"删掉了"这个结论在
**同一个进程内**都成立不了。

**教训**：DDL 的源头在 `schema.sql`，不在数据库里。改唯一键这类操作，
**必须同时改 schema 文件** —— 只对数据库执行 `DROP` / `ALTER` 会被下一次
`open()` 无声地撤销（`IF NOT EXISTS` 让它连个错都不报）。

修法：把那 6 条 `CREATE UNIQUE INDEX` 语句从 `schema.sql` 里删掉，并顺手改掉
两处过期注释（"与上面那条并存"、"M7-b 阶段只加列不删列"）。之后重跑
`schema.sql`，旧索引 **0 条** ✓

> 这也说明"清一次性代码"不是收尾时的洁癖 —— 那 6 条语句**本身就是 bug**，
> 不清掉的话整个 M7-f 等于没做。

### 9.3 其余

1. **删任务的语义变了** —— 现有 UI 文案、README、代码注释里"删除任务会删掉资产"的说法都要改。
   `DELETE /api/scans/{id}` 现在是干净 CASCADE，改完只删观测记录。
2. **`summary()` 的 `*_live` 口径要重算** —— 现在是"这次扫描探活了多少"，改完是"这次扫描
   **看到的**资产里有多少是活的"。前端 `ui_check` 有一条"卡片必须等于页签"的断言会盯着它。
3. **截图冲突** —— `http_endpoint.screenshot_data` 是 BYTEA；若两条记录被合并，要留哪张、还是
   都留（另建表）。见 §9.1，如果 scheme 进 key 就没这个问题。
4. **`event.parent_id` 的自引用** —— 事件层带 scan 不变，但事件**指向的资产**现在跨 scan，
   做事件回溯时要留意别把"资产被别的扫描也看到了"当成异常。
5. **`asset_group_asset.asset_key`** —— ✅ **已查证，不用迁移**：它存的本就是自然键
   （`('domain','anli.chinazy.org')`、`('ip','112.16.229.53')`），本次迁移只是把它
   "歪打正着"的全局语义扶正。详见 §11。
6. **迁移必须能在生产数据上跑** —— 现有库里 4388 个域名、1495 条 URL，规模不大，
   **不需要在线迁移**，停机跑脚本即可。但脚本要**默认干跑**。

---

## 10. 实施顺序（每步可独立验证）

| 步 | 内容 | 验证方式 | 可回滚 | 状态 |
|---|---|---|---|---|
| **M7-a** | `dedup_key` 规范化函数 + 单元测试（**纯函数，先做**） | 单测全绿；对现有 1495 条 URL 干跑 | 不涉及 DB | ✅ **完成**（46 测试；实测合并 **447** 条，非初稿估的 30 —— 见 §3.3） |
| **M7-b** | 建 `scan_asset` + `url`/`http_endpoint` 加列（**只加不删**，`dedup_key` 先可空） | 已有测试**全绿**（因为还没改唯一键）；存量库 `ALTER` 路径也要验 | 删列即可 | ✅ **完成**（485 测试全绿；新库与存量库两条路径都验过） |
| **M7-c** | 回填 `dedup_key` + `schemes` + `scan_asset`（历史数据） | 对账查询：孤儿 0、唯一键冲突 0 | 从备份表恢复 | ✅ **完成**（1495 行 url / 39 行 endpoint 已回填；`scan_asset` 4669 条；孤儿 0；**幂等已验证**） |
| **M7-d** | 切换唯一键（6 张表）+ 改 6 个写点 | 新测试全绿；39 处读点逐步改 | 从备份表恢复 | ✅ **完成**（合并 447 行；7 个写点切换〔比计划多一个 `_update_port_cert`〕） |
| **M7-e** | 改 10 个读点 + `summary()` 口径 | 全量测试；`ui_check` | 代码回滚 | ✅ **完成**（读点统一走 `_seen_clause`；`summary`/`endpoint_clusters` 一并改） |
| **M7-f** | 删旧唯一键（6 条）+ `dedup_key` 加 NOT NULL + 删备份表 | 文档更新 | — | ✅ **完成**（4 张备份已删；见 §9.2.5 —— 第一次 `DROP` 被 `schema.sql` 重跑了回去） |

**关键：M7-b 只加列不删列，所以每个中间状态都能跑、能回滚。** 真正不可逆的只有 M7-f。

### M7-a / M7-b 的实际产出

| 文件 | 内容 |
|---|---|
| `core/util/asset_key.py` | 身份函数（`url_key` / `endpoint_key` / `domain_key` / `ip_key` / `port_key` / `technology_key` / `dedup_key_for`） |
| `tests/test_asset_key.py` | 46 个测试，含真实数据回归 |
| `scripts/dedup_preview.py` | 只读的合并预览工具 |
| `core/storage/schema.sql` | `scan_asset` 表 + `url`/`http_endpoint` 的 `dedup_key`/`schemes` 列 |

**M7-a 的测试抓出两个会静默改数据的 bug**（都值得记下来，因为同类错误很难发现）：

1. **IPv6 被切成 `2001`** —— `split_url` 把主机名交给 `normalize_domain`，而后者按 `:` 切端口
   （对域名是对的）。`http://[2001:db8::1]:8080/admin` 的主机变成了 `2001`。
2. **非默认端口被丢掉** —— `http://x:8080/admin` 与 `http://x/admin` 被合成一条，
   而那是**两个不同的服务**。端口现在进键，默认端口（80/443）省略。

---

## 11. `asset_group_asset` 要不要迁移？—— **不用**（已查证）

原来列在"待确认"里，查了实际数据后可以自己回答：

```
asset_group          1 行
asset_group_scope    1 行
asset_group_asset    9 行   ← asset_key 存的是自然键
monitor              0 行
change               0 行

asset_group_asset 样本:
  ('domain', 'anli.chinazy.org')  ('domain', 'jsh5.chinazy.org')
  ('ip',     '112.16.229.53')     ('ip',     '117.50.236.146')
```

**它已经在用自然键引用资产**（域名/IP 文本），而自然键**本来就不带 scan 维度** —— 也就是说
它**早就是"全局资产"的语义了**，只是当时资产表还是 per-scan，所以语义是"歪打正着"。

本次迁移把这个语义**扶正**：`domain.name` / `ip.addr` 变成真正的唯一键之后，
这 9 行关联的含义从"某个扫描里的同名资产"变成"全局资产"，**不需要任何改动**。

> 顺带：这张表的"自然键多态关联"模式被 §4 的 `scan_asset` 采纳了。

---

## 12. 需要你确认的两点

1. **§9.1 的 scheme 修正** —— `http_endpoint` 的 key 带 scheme（我倾向，因为 status/title/favicon/
   截图都是 per-scheme 的观测），还是也合并 + JSONB？
2. **§5.1 的 `scan_id` 列留不留** —— 我倾向留（作为"首次由哪次扫描发现"的来源标注），
   但改可空、不 CASCADE。

确认后我就从 **M7-a（纯函数 + 单测）** 开始 —— 那一步不碰数据库，最安全，而且能先把你库里
那 1495 条 URL 的合并结果算出来给你看。
