"""C 段扫出来的裸 IP **点得开**。

**为什么单独一个文件**：这不是某一行 SQL 的 bug，而是三段各自看起来合理、
合起来才致命的一条链：

    ``netblock_expand`` 产出裸 IP（父事件是 IP，**没有域名**）
      → ``search_flat`` 的 ``host`` 从 ``http_endpoint`` 反查
        → 绝大多数 C 段邻居**没有 HTTP 端点** → ``host`` 是 NULL
          → 前端 ``detailHostOf`` 拿到 null 静默 return → **点整行没反应**
            → 就算点开了，``host_detail`` 查 ``domain`` 表也必然 404

单独测任何一段都是绿的（每段都有它的理由），只有把「C 段 IP 没有域名、没有
端点」这个真实形状喂进去，才会暴露整条链断掉。

实测依据（扫描 77，``yealink.com.cn``）：C 段展开 1270 个 IP，其中
**1213 个既没有域名也没有 HTTP 端点** —— 也就是界面上 95% 的 C 段行
点开都是死的。

## 后来归属过滤改了主列表的准入，这里的夹具跟着换了

「这不确定的就不要显示在这里了」落地后，``ips`` 主列表的准入条件变成：

    没有 domain_ip 关联  且  （不是 C 段展开来的  或  有带域名 Host 头的端点）

于是**纯邻居**（只有 ``netblock`` 标签、没有任何归属证据）压根不再作为独立
资产出现在主列表里 —— 它们收进任务详情的「C 段探测」页签，以 /24 聚合行的
形式呈现（``storage.netblocks``，``sample_ips`` 只是文本，不可点）。

所以本文件里凡是「一条裸 IP 行要出现在主列表」的夹具，都不能再用
:data:`NEIGHBOR` + 无端点那个形状了 —— 那个形状现在被有意排除。改用两种
**确实会进主列表**的形状：

* :data:`LOOSE` —— **不是** C 段展开来的裸 IP，无域名无端点。
  这是"host 回落成 IP""标题回落成端口摘要"这两条真正要测的形状。
* :data:`NEIGHBOR` + **带域名 Host 头的端点** —— 归属靠 vhost 推断出来的
  C 段 IP，是现在主列表里 C 段 IP 的唯一合法形态。
"""

from __future__ import annotations

import json
import unittest

from core.engine.event import Event, EventType

from .pgutil import drop_storage, make_storage

#: TEST-NET-3（RFC 5737），本仓测试夹具一律用它
NEIGHBOR = "203.0.113.148"
NEIGHBOR_SEG = "203.0.113.0/24"

#: **不是** C 段展开来的裸 IP：没有 ``netblock`` 标签、没有域名、没有端点。
#:
#: 它仍然会作为独立资产进主列表（``netblock IS NULL`` 那一支），所以
#: "host 回落成 IP 本身""标题回落成端口摘要"这两条要测的代码路径在它身上
#: 照样会执行 —— 而且这才是它们在生产里的真实触发场景。
#:
#: ⚠️ 别拿 :data:`NEIGHBOR` 无端点的形状来测那两条：那个形状已被归属过滤
#: 有意排除（见模块 docstring），测它只会得到一个"这条 IP 没进扁平表"。
LOOSE = "203.0.113.201"


def ip_event(addr: str, *, netblock: str | None = None,
             parent_domain: str | None = None) -> Event:
    """一条 IP_ADDRESS 事件。形状照 ``dns_resolve`` / ``netblock_expand`` 的
    真实产出写：``parent_data`` 有域名才有归属证据。"""
    tags = {"netblock": netblock} if netblock else {}
    return Event(type=EventType.IP_ADDRESS, data=addr, module="t",
                  parent_data=parent_domain, tags=tags)


def open_port_event(addr: str, port: int) -> Event:
    """一条 OPEN_TCP_PORT。data 的格式必须与 ``port_scan._emit_port_event``
    逐字一致（``ip:port[|domain]``），否则事件去重键对不上、投影不出端口行。"""
    return Event(type=EventType.OPEN_TCP_PORT, data=f"{addr}:{port}",
                 module="port_scan", tags={"ip": addr, "port": port,
                                           "domain": "", "proto": "tcp"})


class TestBareIpIsReachable(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _scan(self) -> int:
        """一次扫描：种下一个 C 段邻居（无域名）+ 它的两个开放端口。"""
        sid = await self.storage.create_scan(
            targets=["example.com"], preset="t"
        )
        # C 段展开的典型产出：**没有父域名**，只有 netblock 标签
        await self.storage.save_event(sid, ip_event(NEIGHBOR, netblock=NEIGHBOR_SEG))
        await self.storage.project(sid, ip_event(NEIGHBOR, netblock=NEIGHBOR_SEG))
        for p in (80, 443):
            e = open_port_event(NEIGHBOR, p)
            await self.storage.save_event(sid, e)
            await self.storage.project(sid, e)
        return sid

    async def _scan_loose(self) -> int:
        """一次扫描：一条**不在 C 段里**的裸 IP + 它的两个开放端口。

        没有 ``netblock`` 标签 → ``netblock IS NULL`` → 归属过滤放行。
        没有任何端点，所以 ``ep.host`` / ``ep.title`` 都是 NULL ——
        「回落」那两条代码路径在这里被真实走到。
        """
        sid = await self.storage.create_scan(
            targets=["example.com"], preset="t"
        )
        e = ip_event(LOOSE)
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        for p in (80, 443):
            pe = open_port_event(LOOSE, p)
            await self.storage.save_event(sid, pe)
            await self.storage.project(sid, pe)
        return sid

    # ---------------------------------------------------------------- 列表行

    async def test_pure_neighbor_is_kept_out_of_the_asset_list(self) -> None:
        """**纯邻居**（只有 netblock 标签、零归属证据）不作为独立资产出现。

        「这不确定的就不要显示在这里了」—— 收进任务详情的「C 段探测」页签，
        以 /24 聚合行的形式呈现（``storage.netblocks``），那里面有
        ``expanded_hosts`` / ``owned_hosts`` / ``probed_hosts`` 三个数，
        正好回答「这段扫到了什么、其中几台算自己的」。

        ## 这条不是防御性测试，是**意图**的记录

        没有它，下一个读到"``NEIGHBOR`` 从扁平表里消失了"的人会当成回归，
        然后把归属过滤摘掉 —— 实测那会一次性放进来 **803 个**没有任何依据的
        IP，把资产页重新变成"同段的一律算我的"。

        ⚠️ 同一台机器**有**带域名 Host 头的端点时必须留下（vhost 档），
        那条在 ``test_storage.py::TestOwnershipStrengthIsExposed`` 里。
        """
        await self._scan()
        rows = (await self.storage.search_flat(
            NEIGHBOR, types=["ips"], live=False, limit=10
        ))["rows"]
        ip_rows = [r for r in rows if r["asset_type"] == "ips"]
        self.assertEqual(
            ip_rows, [],
            "零归属证据的 C 段邻居又回到主列表了 —— 归属过滤被摘掉了？",
        )

    async def test_ip_row_without_endpoint_still_carries_a_host(self) -> None:
        """没有 HTTP 端点的 IP 行，``host`` 必须回落到 IP 本身，不能是 NULL。

        ⚠️ **这就是「点都点不开」的第一道断点。** 前端 ``detailHostOf`` 对
        ``ips`` 行返回 ``record.host``，拿到 null 就 ``return`` —— 表格那一行
        点了跟没点一样，没有任何报错。

        夹具是 :data:`LOOSE`（不在 C 段里的裸 IP）：它在主列表里合法，
        且 ``ep.host`` 必为 NULL，回落分支一定会被执行。
        """
        await self._scan_loose()
        rows = (await self.storage.search_flat(
            LOOSE, types=["ips"], live=False, limit=10
        ))["rows"]
        ip_rows = [r for r in rows if r["asset_type"] == "ips"]
        self.assertTrue(ip_rows, "这条 IP 根本没进扁平表")
        self.assertEqual(
            ip_rows[0]["host"], LOOSE,
            "无端点的 IP 行 host 是 NULL → 前端点不开",
        )

    async def test_port_row_without_endpoint_still_carries_a_host(self) -> None:
        """端口行同理 —— 它同样从 ``http_endpoint`` 反查 host。"""
        sid = await self._scan()
        rows = (await self.storage.search_flat(
            NEIGHBOR, types=["ports"], live=False, limit=10
        ))["rows"]
        port_rows = [r for r in rows if r["asset_type"] == "ports"]
        self.assertTrue(port_rows, "端口没进扁平表")
        for r in port_rows:
            self.assertEqual(
                r["host"], NEIGHBOR,
                "无端点的端口行 host 是 NULL → 点不开",
            )

    async def test_endpoint_backed_ip_prefers_the_domain_name(self) -> None:
        """**有**端点时仍然优先用域名。

        回落不能变成"永远用 IP" —— 域名才是人能读懂的名字，也是详情面板
        的查询键。有域名还用 IP 是把信息说小了。

        ## 夹具为什么要绕开 ``domain_ip``

        ``ips`` 的 ``always`` 条件是「有域名映射的 IP 不作为独立资产列出」，
        所以只要建了 ``domain_ip`` 行，这条 IP 就整条从扁平表里消失 ——
        写测试时第一版就栽在这里，现象是"``skipTest`` 掉"，看起来像
        "这个分支测不了"，其实是夹具形状不对。

        真正能让 ``ep.host`` 非空的形状是：**有 ``http_endpoint``、但没有
        ``domain_ip``** —— 也就是 ``http_probe`` 直接按 IP 探到了服务，
        而 DNS 那边没建立域名关联（vhost 枚举、证书回灌都会产生这种）。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        # IP 事件**不带 parent_domain** → 不建 domain_ip → 不被 always 排除
        e = ip_event("203.0.113.9")
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        ep = Event(type=EventType.HTTP_RESPONSE,
                   data="https://shop.example.com/", module="http_probe",
                   tags={"domain": "shop.example.com",
                         "host": "shop.example.com", "ip": "203.0.113.9",
                         "port": 443, "status": 200, "scheme": "https"})
        await self.storage.save_event(sid, ep)
        await self.storage.project(sid, ep)

        rows = (await self.storage.search_flat(
            "203.0.113.9", types=["ips"], live=False, limit=10
        ))["rows"]
        ip_rows = [r for r in rows if r["asset_type"] == "ips"]
        self.assertTrue(ip_rows, "有端点的 IP 行没进扁平表")
        self.assertEqual(
            ip_rows[0]["host"], "shop.example.com",
            "有端点时 host 必须优先用域名，不能回落成 IP",
        )

    # ---------------------------------------------------------------- 详情

    async def test_host_detail_on_a_bare_ip_returns_the_asset(self) -> None:
        """裸 IP 也要能查到详情 —— 不能 404。

        这是第二道断点。原来的实现开头就
        ``SELECT ... FROM domain WHERE d.name = ?`` 然后 ``return None``：
        C 段邻居按定义没有域名行，于是**必然**查不到。
        """
        sid = await self._scan()
        detail = await self.storage.host_detail(NEIGHBOR)
        self.assertIsNotNone(detail, "裸 IP 查不到详情")
        self.assertEqual(detail["domain"]["name"], NEIGHBOR)
        self.assertTrue(
            detail["domain"].get("is_ip"),
            "缺 is_ip 标记 → 前端分不出这是 IP 视图",
        )

    async def test_bare_ip_detail_carries_its_open_ports(self) -> None:
        """端口是这类资产的**主要内容**，详情里必须有。

        实测 ``155.102.54.148``：没有域名、没有端点，只有
        25/80/110/143/443 五个端口。原来面板对它是全空的 ——
        点开等于没东西可看，于是用户问「你入库干嘛」。
        """
        await self._scan()
        detail = await self.storage.host_detail(NEIGHBOR)
        ports = {p["port"] for p in detail["ports"]}
        self.assertEqual(ports, {80, 443}, "详情里的端口与库里对不上")
        self.assertEqual(detail["counts"]["ports"], 2,
                         "counts.ports 与列表必须一致")
        self.assertGreaterEqual(detail["counts"]["ports"], 1,
                                "counts 里漏了端口数，摘要会写成全是 0")

    async def test_bare_ip_detail_carries_the_segment_it_came_from(self) -> None:
        """归属（C 段）是「这台机器为什么会被扫」的答案，必须带出来。"""
        await self._scan()
        detail = await self.storage.host_detail(NEIGHBOR)
        self.assertEqual(detail["domain"]["netblock"], NEIGHBOR_SEG,
                         "详情里丢了 C 段归属")

    async def test_unknown_host_is_still_none(self) -> None:
        """真的什么都没有的键仍然返回 None —— 别把兜底写成万能返回。"""
        detail = await self.storage.host_detail("nothing.example.invalid")
        self.assertIsNone(detail)

    async def test_a_domain_still_takes_the_original_branch(self) -> None:
        """域名走原路径，且 ``is_ip`` 不为真。

        这是**防回归**：兜底分支插在 ``domain is None`` 之后，
        一旦有人把它挪到前面，普通域名的详情就会被换成 IP 形状。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        d = Event(type=EventType.DNS_NAME, data="www.example.com", module="dns_resolve")
        await self.storage.save_event(sid, d)
        await self.storage.project(sid, d)
        detail = await self.storage.host_detail("www.example.com")
        self.assertIsNotNone(detail)
        self.assertFalse(detail["domain"].get("is_ip", False),
                         "域名被当成 IP 渲染了")
        self.assertEqual(detail["domain"]["name"], "www.example.com")

    # ---------------------------------------------------------------- 序列化

    async def test_detail_is_json_serializable_even_with_technology_rows(
        self,
    ) -> None:
        """详情返回值必须能直接 JSON 序列化。

        ## 这条是补一个真实踩过的坑

        ``_ip_detail`` 的 ``technologies`` 最初直接返回 ``_fetchall`` 的结果
        （``pg.Row``），没转 dict。FastAPI 序列化响应时只认 dict/标量，
        碰到 Row 抛 ``PydanticSerializationError`` → **HTTP 500**。

        而**单测抓不到**：测试夹具里 ``technology`` 表是空的，那个分支
        根本不进，于是测试全绿、真库上一点就 500（实测
        ``39.173.149.54`` 就是这样挂的 —— 它上面挂着 ``*.ucdl.pp.uc.cn``
        的过期证书，技术栈有行）。

        所以这里**必须**种一行 technology 出来，强制那个分支被执行。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        e = ip_event(NEIGHBOR)
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        ep = Event(type=EventType.HTTP_RESPONSE,
                   data="https://shop.example.com/", module="http_probe",
                   tags={"domain": "shop.example.com",
                         "host": "shop.example.com", "ip": NEIGHBOR,
                         "port": 443, "status": 200, "scheme": "https"})
        await self.storage.save_event(sid, ep)
        await self.storage.project(sid, ep)
        # 这行是**关键**：没有它，technologies 分支返回空列表，测不到序列化
        await self.storage._fetchone(
            "INSERT INTO technology (scan_id, host, name, evidence, first_seen, "
            "last_seen) VALUES (?, ?, ?, ?, ?, ?)",
            (sid, "shop.example.com", "Nginx", "server: nginx", "2026-01-01",
             "2026-01-01"),
        )

        detail = await self.storage.host_detail(NEIGHBOR)
        self.assertTrue(detail["technologies"],
                        "夹具没种上技术栈，这���测试等于没测")
        # 真·序列化：FastAPI 走的就是这一步
        json.dumps(detail)
        for r in detail["technologies"]:
            self.assertIsInstance(r, dict,
                                  "Row 没转 dict → FastAPI 序列化时 500")

    async def test_related_domains_carry_their_own_probed_flag(self) -> None:
        """同机器的域名要带上**它自己**的探活状态。

        用「这台 IP 有没有端点」来判断是错的：挂在这台机器上、由别的域名
        名探活过的那些会被全部显示成"未探活" —— 而那正是 vhost 场景里最该
        被看见的一批。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        d = Event(type=EventType.DNS_NAME, data="a.example.com", module="dns_resolve")
        await self.storage.save_event(sid, d)
        await self.storage.project(sid, d)
        e = ip_event(NEIGHBOR, parent_domain="a.example.com")
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        # a.example.com **在别处**探活过（记在另一个 IP 上）——
        # 这正是「probed 该按域名判、不该按本 IP 判」的根据。
        other = Event(type=EventType.HTTP_RESPONSE,
                      data="https://a.example.com/", module="http_probe",
                      tags={"domain": "a.example.com",
                            "host": "a.example.com", "ip": "198.51.100.7",
                            "port": 443, "status": 200, "scheme": "https"})
        await self.storage.save_event(sid, other)
        await self.storage.project(sid, other)

        detail = await self.storage.host_detail(NEIGHBOR)
        names = [r["name"] for r in detail["related_domains"]]
        self.assertIn("a.example.com", names,
                      "同机器的域名没列出来 —— C 段详情就少了最重要的一块")
        row = next(r for r in detail["related_domains"]
                   if r["name"] == "a.example.com")
        # 这个 IP 自身没有端点
        self.assertFalse(detail["endpoints"], "夹具前提不对")

        # ⚠️ 断言必须**具体**，不能只断言「是个 bool」。
        #
        # 第一版这里写的是 ``assertIsInstance(row["probed"], bool)``，
        # 变异验证立刻报「抓不住」—— 把实现改成恒 False 它照样通过。
        # bool 恒等于 isinstance 检查里的一个，这断言等于没写。
        #
        # 这里要验的是**取值**：a.example.com 本身在库里被探活过
        # （下面那条 HTTP_RESPONSE 就是它的观测），所以它必须是 True；
        # 而这台 IP 自己一个端点都没有 —— 判定依据必须是**域名**，
        # 不是 IP。
        self.assertTrue(
            row["probed"],
            "a.example.com 自己被探活过，probed 必须是 True；"
            "若为 False 说明错按「本 IP 有没有端点」判了",
        )
        # 同机器的域名不该被排除泛解析之外的普通域名漏掉
        self.assertEqual(row["resolve_state"], "ok")
        self.assertTrue(row["same_ip"])

    # ---------------------------------------------------------------- 标题列

    async def test_ip_row_without_endpoint_shows_its_open_ports(self) -> None:
        """没有 HTTP 端点的 IP 行，标题列要显示**开放端口**，不能是横线。

        ## 为什么这条重要

        「标题 / 状态」列的 ``title`` / ``status`` 都从 ``http_endpoint`` 取。
        没有 Web 服务的机器**整列是横线** —— 用户看到的是"扫了一堆什么都没扫到"。

        而真实情况是：这台机器开着 5 个端口，只是那些端口不吐 HTTP。
        **「没扫到」与「扫到了但不是 Web 服务」在界面上长得一模一样**，
        信息量差着一个量级。这正是"你入库干嘛"的由来。

        ⚠️ 夹具换成 :data:`LOOSE`：C 段里的纯邻居已经被归属过滤移出主列表，
        拿 :data:`NEIGHBOR` 测这条只会得到"没进扁平表"。落在主列表里的
        无端点形状就是这种"不在 C 段里的裸 IP"。
        """
        await self._scan_loose()  # 80 / 443 两个开放端口
        rows = (await self.storage.search_flat(
            LOOSE, types=["ips"], live=False, limit=10
        ))["rows"]
        ip_rows = [r for r in rows if r["asset_type"] == "ips"]
        self.assertTrue(ip_rows, "这条 IP 没进扁平表")
        title = ip_rows[0]["title"]
        self.assertTrue(
            title, "无端点的 IP 行标题是空的 → 界面上是横线"
        )
        # 不是只要求"非空"：要能看出是哪些端口
        self.assertIn("80", title)
        self.assertIn("443", title)

    async def test_endpoint_backed_ip_keeps_the_page_title(self) -> None:
        """**有**端点时标题列仍然显示页面标题，不能被端口摘要顶掉。

        页面标题（"亿联视频会议系统…"）比"80 HTTP / 443 HTTPS"更有辨识度，
        两者不是一回事。有端点就该用页面标题。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        e = ip_event(NEIGHBOR)
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        pe = open_port_event(NEIGHBOR, 443)
        await self.storage.save_event(sid, pe)
        await self.storage.project(sid, pe)
        ep = Event(type=EventType.HTTP_RESPONSE,
                   data="https://shop.example.com/", module="http_probe",
                   tags={"domain": "shop.example.com",
                         "host": "shop.example.com", "ip": NEIGHBOR,
                         "port": 443, "status": 200, "scheme": "https",
                         "title": "某视频会议系统首页"})
        await self.storage.save_event(sid, ep)
        await self.storage.project(sid, ep)

        rows = (await self.storage.search_flat(
            NEIGHBOR, types=["ips"], live=False, limit=10
        ))["rows"]
        ip_rows = [r for r in rows if r["asset_type"] == "ips"]
        self.assertTrue(ip_rows)
        self.assertEqual(
            ip_rows[0]["title"], "某视频会议系统首页",
            "有端点时标题列被端口摘要覆盖了",
        )

    async def test_port_row_title_is_not_polluted_by_the_port_summary(self) -> None:
        """端口行的标题**不受**端口摘要影响。

        端口行的主标识已经是 ``ip:port``，再显示一遍"443 HTTPS"是废话；
        而且它是另一条 UNION 分支、**没有** ``pv`` 那个 LATERAL ——
        引用了就直接 ``UndefinedColumnError``（实测踩过）。
        """
        sid = await self._scan()
        rows = (await self.storage.search_flat(
            NEIGHBOR, types=["ports"], live=False, limit=10
        ))["rows"]
        port_rows = [r for r in rows if r["asset_type"] == "ports"]
        self.assertTrue(port_rows)
        for r in port_rows:
            self.assertNotIn(
                "HTTP", r["title"] or "",
                "端口行标题被端口摘要污染了",
            )

    # ---------------------------------------------------------------- 服务列

    async def test_service_column_names_the_service_not_the_transport(self) -> None:
        """服务列给的是**服务名**（443 → HTTPS），不是传输层协议。

        ⚠️ ``port.protocol`` 那一列本来就叫"协议"，存的是 ``tcp``/``udp``。
        实测全库 16245 条端口记录 **100% 是 tcp**（Hive 只跑 TCP connect
        扫描）—— 直接显示它会得到一整列没有信息量的 "TCP"。
        用户要的是"这个端口上跑的是什么"。
        """
        await self._scan_loose()  # 80 / 443
        rows = (await self.storage.search_flat(
            LOOSE, types=["ips"], live=False, limit=10
        ))["rows"]
        ip_rows = [r for r in rows if r["asset_type"] == "ips"]
        self.assertTrue(ip_rows)
        svc = ip_rows[0]["service"]
        self.assertTrue(svc, "服务列是空的")
        self.assertIn("HTTP", svc)
        self.assertIn("HTTPS", svc)
        # 关键断言：不能是 transport protocol
        self.assertNotIn("tcp", svc.lower(),
                         "服务列退化成了传输层协议，那一列等于没信息")

    async def test_service_column_dedupes_the_same_service_across_ports(
        self,
    ) -> None:
        """同一服务的多个端口只显示一次。

        8000 / 8080 / 8888 三个端口都是 ``HTTP-Alt``，显示三遍没有意义 ——
        这一列回答的是"提供什么服务"，不是"开了哪几个号"。

        ⚠️ 第一版写的是 ``SELECT DISTINCT`` 整行，**去重没生效**：
        DISTINCT 作用在所有输出列上，而 ``rnk`` / ``pnum`` 每个端口都不同，
        三个 ``HTTP-Alt`` 全都活了下来，实测一列出现四次 ``HTTP-Alt``。
        正解是按 ``svc`` 分组。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        e = ip_event(NEIGHBOR)
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        for p in (8000, 8080, 8888, 9000):
            pe = open_port_event(NEIGHBOR, p)
            await self.storage.save_event(sid, pe)
            await self.storage.project(sid, pe)

        rows = (await self.storage.search_flat(
            NEIGHBOR, types=["ips"], live=False, limit=10
        ))["rows"]
        ip_rows = [r for r in rows if r["asset_type"] == "ips"]
        svc = ip_rows[0]["service"]
        n_alt = svc.count("HTTP-Alt")
        self.assertEqual(
            n_alt, 1,
            f"四个 8000/8080/8888/9000 端口只该显示一次 HTTP-Alt，实际 {svc!r}",
        )

    async def test_service_column_works_for_domain_rows(self) -> None:
        """域名行要走**两跳**（domain → domain_ip → ip → port）取到服务。

        端口挂在 IP 上而域名与 IP 是 N 对 N，所以域名不能直接 join port ——
        这条没测过的话，会出现"域名行的服务列整列空白"而且不报错。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        d = Event(type=EventType.DNS_NAME, data="shop.example.com",
                  module="dns_resolve")
        await self.storage.save_event(sid, d)
        await self.storage.project(sid, d)
        e = ip_event(NEIGHBOR, parent_domain="shop.example.com")
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        for p in (443, 3306):
            pe = open_port_event(NEIGHBOR, p)
            await self.storage.save_event(sid, pe)
            await self.storage.project(sid, pe)

        rows = (await self.storage.search_flat(
            "shop.example.com", types=["domains"], live=False, limit=10
        ))["rows"]
        dom_rows = [r for r in rows if r["asset_type"] == "domains"]
        self.assertTrue(dom_rows, "域名没进扁平表")
        svc = dom_rows[0]["service"]
        self.assertIn("HTTPS", svc)
        self.assertIn("MySQL", svc)

    async def test_service_column_on_port_row_is_its_own_service(self) -> None:
        """端口行的服务就是它自己 —— "443 → HTTPS" 是那一行最值得写的话。"""
        await self._scan()
        rows = (await self.storage.search_flat(
            NEIGHBOR, types=["ports"], live=False, limit=10
        ))["rows"]
        by_port = {int(r["asset_key"].rsplit(":", 1)[1]): r["service"]
                   for r in rows if r["asset_type"] == "ports"}
        self.assertEqual(by_port.get(80), "HTTP")
        self.assertEqual(by_port.get(443), "HTTPS")

    async def test_rows_that_do_not_represent_a_machine_have_no_service(
        self,
    ) -> None:
        """URL / 技术栈 / 发现这三类行不给服务 —— 它们不代表一台机器。

        这三类由对应的 ips/domains 行显示，重复塞一份会让同一份信息在
        列表里出现两遍（端口列当初就是这么处理的）。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        d = Event(type=EventType.DNS_NAME, data="a.example.com",
                  module="dns_resolve")
        await self.storage.save_event(sid, d)
        await self.storage.project(sid, d)
        e = ip_event(NEIGHBOR, parent_domain="a.example.com")
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        pe = open_port_event(NEIGHBOR, 443)
        await self.storage.save_event(sid, pe)
        await self.storage.project(sid, pe)
        # ⚠️ finding 事件的形状照 test_storage.py 写：``data`` 是 target，
        # ``kind`` / ``severity`` 走 ``tags``。写成 ``Event(target=...)``
        # 会直接 ``TypeError``（Event 没有这个参数）。
        f = Event(type=EventType.FINDING, data="a.example.com",
                  module="admin_plane",
                  tags={"kind": "admin_plane", "severity": "info",
                        "detail": "管理面"})
        await self.storage.save_event(sid, f)
        await self.storage.project(sid, f)

        for t in ("findings", "technologies", "urls"):
            rows = (await self.storage.search_flat(
                "example.com", types=[t], live=False, limit=10
            ))["rows"]
            for r in rows:
                self.assertIsNone(
                    r["service"],
                    f"{t} 行不该带服务：它不代表一台机器",
                )