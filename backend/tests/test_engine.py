"""M1 引擎骨架的单元测试。

重点验证事件驱动递归模型的四个关键性质:
  1. 递归链能贯通 (SEED -> DNS_NAME -> IP_ADDRESS)
  2. 去重有效, 但"同一 IP 被多个域名解析"的关联不丢
  3. 范围校验与递归深度闸门生效
  4. 扫描一定能收敛, 不会挂死

测试模块是运行时写进临时目录再加载的, 走的是真实的模块发现路径
(Scanner._collect_from_dir), 而不是直接往引擎里塞对象。
"""

from __future__ import annotations

import unittest
from pathlib import Path

from core.engine.preset import Preset
from core.engine.scanner import Scanner

from .base import EngineTestCase, TEST_TMP_ROOT  # noqa: F401  (TEST_TMP_ROOT 供断言用)

# --------------------------------------------------------------------- 测试模块源码

CHAIN = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class chain_a(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            await self.emit_event(f"a.{event.data}", EventType.DNS_NAME, parent=event)
            await self.emit_event(f"b.{event.data}", EventType.DNS_NAME, parent=event)


    class chain_b(BaseModule):
        watched_events = (EventType.DNS_NAME,)
        produced_events = (EventType.IP_ADDRESS,)
        flags = ("active", "safe")

        async def handle_event(self, event):
            # 固定 IP: 用于验证"两个域名解析到同一 IP"时关联不丢
            await self.emit_event("10.0.0.1", EventType.IP_ADDRESS, parent=event)
"""

OUT_OF_SCOPE = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class leaky(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            await self.emit_event("evil.example.net", EventType.DNS_NAME, parent=event)
"""

#: 一条 6 跳的线性链：SEED -> IP -> PORT -> HTTP_RESPONSE -> URL -> DNS_NAME
#: 每一跳的类型都不同（除最后一步），模拟"种子→解析→探活→抽链接→…"的真实流水线。
LINEAR_CHAIN = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class hop1(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.IP_ADDRESS,)
    flags = ("active", "safe")

    async def handle_event(self, event):
        await self.emit_event("1.2.3.4", EventType.IP_ADDRESS, parent=event)


class hop2(BaseModule):
    watched_events = (EventType.IP_ADDRESS,)
    produced_events = (EventType.OPEN_TCP_PORT,)
    flags = ("active", "safe")

    async def handle_event(self, event):
        await self.emit_event("1.2.3.4:80", EventType.OPEN_TCP_PORT, parent=event)


class hop3(BaseModule):
    watched_events = (EventType.OPEN_TCP_PORT,)
    produced_events = (EventType.HTTP_RESPONSE,)
    flags = ("active", "safe")

    async def handle_event(self, event):
        await self.emit_event("http://example.com/", EventType.HTTP_RESPONSE, parent=event)


class hop4(BaseModule):
    watched_events = (EventType.HTTP_RESPONSE,)
    produced_events = (EventType.URL,)
    flags = ("active", "safe")

    async def handle_event(self, event):
        await self.emit_event("http://example.com/a", EventType.URL, parent=event)


class hop5(BaseModule):
    #: URL -> URL 是**真正的环**（js_assets / dir_brute 就是这样），
    #: 所以这一跳应该消耗一次递归预算
    watched_events = (EventType.URL,)
    produced_events = (EventType.URL,)
    flags = ("active", "safe")

    async def handle_event(self, event):
        if event.data.endswith("/a"):
            await self.emit_event("http://example.com/b", EventType.URL, parent=event)


class hop6(BaseModule):
    watched_events = (EventType.URL,)
    produced_events = (EventType.TECHNOLOGY,)
    flags = ("active", "safe")

    async def handle_event(self, event):
        if event.data.endswith("/b"):
            # host tag 是投影进 technology 表的必要条件
            await self.emit_event(
                "nginx", EventType.TECHNOLOGY, parent=event,
                tags={"host": "example.com"},
            )
"""


RECURSE = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class recurse(BaseModule):
        watched_events = (EventType.SEED, EventType.DNS_NAME)
        produced_events = (EventType.DNS_NAME,)
        flags = ("active", "safe")

        async def handle_event(self, event):
            await self.emit_event(f"x.{event.data}", EventType.DNS_NAME, parent=event)
"""

SOFT_FAIL = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class needs_key(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def setup(self):
            return None, "缺少 API Key"

        async def handle_event(self, event):
            await self.emit_event(f"never.{event.data}", EventType.DNS_NAME, parent=event)
"""

PER_DOMAIN = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class fanout(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            await self.emit_event(f"c1.{event.data}", EventType.DNS_NAME, parent=event)
            await self.emit_event(f"c2.{event.data}", EventType.DNS_NAME, parent=event)


    class once(BaseModule):
        watched_events = (EventType.DNS_NAME,)
        produced_events = ()
        flags = ("passive", "safe")
        per_domain_only = True

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.calls = 0

        async def handle_event(self, event):
            self.calls += 1
"""


# --------------------------------------------------------------------- 用例

class TestEventChain(EngineTestCase):
    """递归链贯通 + 资产投影。"""

    async def test_seed_to_ip_chain(self) -> None:
        self.add_module_file("chain", CHAIN)
        scanner, summary = await self.run_scan(
            targets=["example.com"], include=["chain_a", "chain_b"]
        )

        # SEED + a. + b. + **10.0.0.1 ×2**。
        # 2026-10-07 起 IP_ADDRESS 的去重键带上了 parent_data（见
        # :meth:`Event.key` 与 ``TestSharedIpVhostProbing``）—— 同一个 IP 被两个
        # 域名解析到时是两个**独立**事件，而不是一个。所以这里是 5 不是 4。
        # 换来的东西是下面那两行：两个域名仍然都关联到这台机器，而且各自能
        # 带着自己的 Host 往下走（端口扫描/探活）。
        self.assertEqual(summary["events_new"], 5)
        self.assertIn("chain_a", summary["modules_enabled"])
        self.assertIn("chain_b", summary["modules_enabled"])

        assets = await self.storage.summary(scanner.scan_id)
        # 根域名自身也是一条资产, 所以是 3 条
        self.assertEqual(assets["domains"], 3)      # example.com, a., b.
        self.assertEqual(assets["ips"], 1)          # 只有一个不同的 IP
        # 关键: IP 事件**按父域名**各发一条，但**投影**仍然把两个域名都关联到
        # 同一个 IP（投影走的是扫描前的路径，不受去重键影响）
        self.assertEqual(assets["domain_ip"], 2)

    async def test_event_provenance_is_recorded(self) -> None:
        """递归溯源: IP 事件应能回溯到产生它的 DNS_NAME, 再回溯到 SEED。"""
        self.add_module_file("chain", CHAIN)
        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["chain_a", "chain_b"]
        )
        events, _ = await self.storage.events(scanner.scan_id, limit=50)
        ip_event = next(e for e in events if e["type"] == "IP_ADDRESS")

        chain = await self.storage.trace(scanner.scan_id, ip_event["id"])
        types = [row["type"] for row in chain]
        self.assertEqual(types[0], "IP_ADDRESS")
        self.assertIn("DNS_NAME", types)
        self.assertEqual(types[-1], "SEED")
        self.assertEqual(chain[-1]["data"], "example.com")

    async def test_events_default_order_is_emission_order(self) -> None:
        """存储层 ``events()`` 默认**升序**（= 发射顺序），倒序要显式要。

        ⚠️ 这条钉的是一个踩过的坑：事件流界面要"最新进展在第一页"，于是曾经把
        ``ORDER BY id DESC`` 设成了存储层的**默认值**。结果 ``test_urls.py`` 里
        ``_parents()`` 按行顺序建表、断言"浅路径排在深路径前面"，整个顺序反过来，
        两条测试红了 —— 而那两条测的是 ``url_extract`` 的**发射顺序**，
        跟事件显示顺序毫无关系。

        显示偏好渗进数据层默认值，代价是每个顺序敏感的调用方都悄悄拿到反的，
        而且报错地点离原因十万八千里。
        """
        self.add_module_file("chain", CHAIN)
        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["chain_a", "chain_b"]
        )
        asc, _ = await self.storage.events(scanner.scan_id, limit=50)
        desc, _ = await self.storage.events(scanner.scan_id, limit=50, order="desc")

        self.assertEqual(len(asc), len(desc))
        self.assertGreater(len(asc), 1, "样本太少，钉不住顺序")
        ids_asc = [e["id"] for e in asc]
        self.assertEqual(ids_asc, sorted(ids_asc), "默认不是升序（= 发射顺序）")
        self.assertEqual([e["id"] for e in desc], sorted(ids_asc, reverse=True),
                         "order='desc' 没把顺序反过来")

    async def test_events_rejects_unknown_order(self) -> None:
        """``order`` 走白名单 —— 它是被拼进 SQL 的，不能当注入面开着。"""
        self.add_module_file("chain", CHAIN)
        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["chain_a", "chain_b"]
        )
        rows, _ = await self.storage.events(
            scanner.scan_id, limit=50, order="id; DROP TABLE event"
        )
        self.assertTrue(rows, "非法 order 应当退回默认，而不是报错或返回空")


class TestGates(EngineTestCase):
    """范围校验与递归深度闸门。"""

    async def test_out_of_scope_dns_name_is_dropped(self) -> None:
        self.add_module_file("leaky", OUT_OF_SCOPE)
        scanner, summary = await self.run_scan(targets=["example.com"], include=["leaky"])

        self.assertGreaterEqual(summary["events_out_of_scope"], 1)
        domains = await self.storage.domains(scanner.scan_id)
        names = {d["name"] for d in domains}
        # 只剩根域名, 越界的 evil.example.net 绝不落库
        self.assertEqual(names, {"example.com"})

    async def test_scope_can_be_disabled(self) -> None:
        self.add_module_file("leaky", OUT_OF_SCOPE)
        preset = Preset(
            name="test", include=["leaky"], module_dirs=[str(self.module_dir)]
        )
        scanner = Scanner(
            targets=["example.com"], preset=preset,
            storage=self.storage, enforce_scope=False,
        )
        summary = await scanner.scan()
        self.assertEqual(summary["events_out_of_scope"], 0)
        domains = await self.storage.domains(scanner.scan_id)
        names = {d["name"] for d in domains}
        self.assertEqual(names, {"example.com", "evil.example.net"})

    async def test_recursion_is_bounded_and_terminates(self) -> None:
        """自我喂养的模块必须被 max_scope_distance 截断 (否则就是死循环)。"""
        self.add_module_file("recurse", RECURSE)
        _, summary = await self.run_scan(
            targets=["example.com"],
            include=["recurse"],
            settings={"max_scope_distance": 2, "timeout": 30},
        )
        self.assertGreaterEqual(summary["events_too_deep"], 1)
        # SEED(1) + x.example.com(2) + x.x.example.com(3) = 3 条新事件
        self.assertEqual(summary["events_new"], 3)


class TestModuleLifecycle(EngineTestCase):
    """setup 三态语义与 preset 的 flags 过滤。"""

    async def test_soft_fail_disables_module_without_aborting(self) -> None:
        self.add_module_file("soft_fail", SOFT_FAIL)
        scanner, summary = await self.run_scan(
            targets=["example.com"], include=["needs_key"]
        )
        self.assertNotIn("needs_key", summary["modules_enabled"])
        self.assertIn("缺少 API Key", summary["modules_skipped"]["needs_key"])

    async def test_preset_require_flags_filters_active_modules(self) -> None:
        self.add_module_file("chain", CHAIN)
        scanner, summary = await self.run_scan(
            targets=["example.com"],
            include=["chain_a", "chain_b"],
            require_flags=["passive"],
        )
        self.assertEqual(summary["modules_enabled"], ["chain_a"])
        self.assertIn("chain_b", summary["modules_skipped"])

    async def test_per_domain_only_latch(self) -> None:
        """per_domain_only 的模块在同一根域名下只应被触发一次。"""
        self.add_module_file("per_domain", PER_DOMAIN)
        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["fanout", "once"]
        )
        self.assertEqual(scanner.modules["once"].calls, 1)

    async def test_same_domain_for_two_targets(self) -> None:
        self.add_module_file("per_domain", PER_DOMAIN)
        scanner, _ = await self.run_scan(
            targets=["a.com", "b.com"], include=["fanout", "once"]
        )
        self.assertEqual(scanner.modules["once"].calls, 2)


FAKE_DNS = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class fakedns(BaseModule):
        # 站 dns_resolve 的位置。**接 DNS_NAME 而不是 SEED**，和真实模块一样 ——
        # `parent=event` 里的 event 是**收到的**那个事件，所以 parent_data 才是域名。
        #
        # ⚠️ 别写成 `parent = await self.emit_event(...)`：**emit_event 不返回
        # 事件对象**（返回 None），那样 parent_data 会是空的，归属证据就没了，
        # 而链路的其余部分看起来一切正常 —— 正是最难查的那类静默失效。
        watched_events = (EventType.DNS_NAME,)
        produced_events = (EventType.IP_ADDRESS)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            for octet in (1, 2):
                await self.emit_event(
                    f"93.184.216.{octet}", EventType.IP_ADDRESS, parent=event
                )


    class emitname(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            await self.emit_event(event.data, EventType.DNS_NAME, parent=event)


    class recorder(BaseModule):
        # 扮演下游消费者（port_scan / http_probe 都是订阅 IP_ADDRESS 的）
        watched_events = (EventType.IP_ADDRESS,)
        produced_events = ()
        flags = ("passive", "safe")

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.seen = []

        async def handle_event(self, event):
            self.seen.append(event.data)
"""


class TestNetblockExpandChain(EngineTestCase):
    """C 段展开在**真实引擎**里跑通：IP_ADDRESS → 展开 → 下游拿到地址。

    单测（``test_netblock_expand.py``）断言的是同一份代码，但 ``emit_event``
    被换成了收集器 —— 它证明不了"产出的事件真的走到了下一个环节"。

    这里用 ``/29`` 而不是 ``/24``：链路完全一样，只是 6 个地址而不是 254 个，
    快到能放进常规回归。
    """

    async def test_expanded_addresses_reach_downstream(self) -> None:
        self.add_module_file("chainmods", FAKE_DNS)
        scanner, _ = await self.run_scan(
            targets=["example.com"],
            include=["emitname", "fakedns", "netblock_expand", "recorder"],
            module_config={"netblock_expand": {"prefixlen": 29}},
        )
        seen = set(scanner.modules["recorder"].seen)
        expanded = scanner.modules["netblock_expand"]
        self.assertEqual(
            expanded.stats.get("expanded"), 1,
            "两台归属证据同段，应该展开一次",
        )
        # 断言的是**集合相等**：展开会连同原来那 2 台一起重发，所以下游看到的是
        # 完整的 6 台。**别先减掉原来的 2 台再比** —— 它们也在集合里，减完只剩
        # 4 台，与期望的 6 台一比就报"少了 2 个"，看起来像"没送到下游"。
        self.assertEqual(
            seen,
            {f"93.184.216.{i}" for i in range(1, 7)},
            f"下游没拿到展开出来的地址: {sorted(seen)}",
        )
        self.assertIn(
            "netblock_expanded",
            # ``scanner.findings`` 是 **Event 列表**不是 dict 列表 —— kind 在
            # tags 里。写成 ``f["kind"]`` 会 TypeError。
            [f.tags.get("kind") for f in scanner.findings],
            "展开没有留痕",
        )

    async def test_single_host_segment_is_not_expanded(self) -> None:
        """同一条链，但只给 1 台归属证据 —— 下游只看到原来那 1 个地址。"""
        self.add_module_file("chainmods", FAKE_DNS.replace(
            "for octet in (1, 2):", "for octet in (1,):"
        ))
        scanner, _ = await self.run_scan(
            targets=["example.com"],
            include=["emitname", "fakedns", "netblock_expand", "recorder"],
            module_config={"netblock_expand": {"prefixlen": 29}},
        )
        self.assertEqual(
            scanner.modules["netblock_expand"].stats.get("expanded", 0), 0,
            "只有 1 台证据却展开了",
        )
        self.assertEqual(set(scanner.modules["recorder"].seen), {"93.184.216.1"})

    async def test_bare_ip_seed_expands_without_dns(self) -> None:
        """**裸 IP 种子走的是同一段流水线，只是省掉 DNS。**

        ``seed_asset`` 把种子 IP 变成 ``IP_ADDRESS`` → ``netblock_expand``
        认得它是种子目标 → 直接展开 → ``recorder``（扮演 port_scan）拿到整段。

        这里刻意**不挂** ``fakedns``：域名种子那条路才需要 DNS 解析出证据，
        裸 IP 种子自己就是授权。
        """
        self.add_module_file("chainmods", FAKE_DNS)
        scanner, _ = await self.run_scan(
            targets=["93.184.216.1"],
            include=["seed_asset", "netblock_expand", "recorder"],
            module_config={"netblock_expand": {"prefixlen": 29}},
        )
        self.assertEqual(
            scanner.modules["netblock_expand"].stats.get("expanded"), 1,
            "裸 IP 种子没能展开它的段",
        )
        self.assertEqual(
            set(scanner.modules["recorder"].seen),
            {f"93.184.216.{i}" for i in range(1, 7)},
            "展开出来的地址没走到下游",
        )

    async def test_seed_netblock_is_left_to_seed_asset(self) -> None:
        """用户直接下发网段时，**只有** ``seed_asset`` 展开那一次。

        ``netblock_expand`` 看到 ``seed_asset`` 产出的 IP 时，父事件是 SEED、
        ``parent_data`` 正好等于网段串 —— 不挡的话它会把同一个段再展开一遍：
        白跑一轮 emit，还多出一条看起来像第二次发现的 finding。
        """
        self.add_module_file("chainmods", FAKE_DNS)
        scanner, _ = await self.run_scan(
            targets=["93.184.216.0/29"],
            include=["seed_asset", "netblock_expand", "recorder"],
        )
        self.assertEqual(
            set(scanner.modules["recorder"].seen),
            {f"93.184.216.{i}" for i in range(1, 7)},
            "seed_asset 没把网段枚举出来",
        )
        self.assertEqual(
            scanner.modules["netblock_expand"].stats.get("expanded", 0), 0,
            "同一段被展开了两次",
        )


REQUIRES_DOMAIN = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class bydomain(BaseModule):
        watched_events = (EventType.SEED, EventType.DNS_NAME)
        produced_events = ()
        flags = ("passive", "safe")
        requires_domain = True

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.seen = []

        async def handle_event(self, event):
            self.seen.append(event.data)


    class oddnames(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            # 第三方被动源真的会返回这两种形态
            await self.emit_event(event.data + ".", EventType.DNS_NAME, parent=event)
            await self.emit_event("*." + event.data, EventType.DNS_NAME, parent=event)


    class byanything(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = ()
        flags = ("passive", "safe")

        def __init__(self, *a, **kw):
            super().__init__(*a, **kw)
            self.seen = []

        async def handle_event(self, event):
            self.seen.append(event.data)
"""


class TestParentDataIsNotAlwaysADomain(EngineTestCase):
    """``parent_data`` 是"父事件的数据"，**不保证是域名**。

    ## 这个 bug 的形状

    ``port_scan`` 原来写的是 ``domain = event.parent_data or ""``，无条件
    把 ``parent_data`` 当域名，塞进 ``OPEN_TCP_PORT`` 的 ``tags["domain"]``；
    而 ``http_probe`` 的 ``host = domain or ip`` 会**优先用那个 domain**。

    ``netblock_expand`` 发的 ``IP_ADDRESS`` 父事件是**触发的那个 IP** ——
    于是 C 段扫出来的邻居，端口被记成"域名 = 另一台机器的 IP"，
    ``http_probe`` 就**拿着错的机器去探**。

    实测 2026-10-07：端点表里留下 ``ip=111.48.166.3 / host=111.48.166.18``
    这种 ``ip≠host`` 的行（**资产表里存的是假记录**），那一轮 32 个邻居里
    30 个一个 HTTP 端点都没有。

    判据该用 :func:`is_valid_domain`：裸 IP、IPv6、网段串全部出局，
    留空让 ``http_probe`` 回落到 ``host = ip``。
    """

    def _scan(self, parent_data: str):
        return """
    from core.engine.event import Event, EventType
    from core.engine.module import BaseModule


    class spawn(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.IP_ADDRESS)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            await self.emit_event(
                "93.184.216.7", EventType.IP_ADDRESS, parent=event
            )
"""
        # 直接构造带 parent_data 的 IP_ADDRESS：spawn 那一步在单元层太绕，
        # 而要验的判据只在 port_scan 这一行。
        return parent_data

    async def test_ip_parent_data_does_not_become_a_domain(self) -> None:
        import ipaddress

        from core.domains.web_hunter.port_scan import port_scan
        from core.util.domain import is_valid_domain

        # 判据本身：IP / IPv6 / 网段串都不是域名
        for junk in ("93.184.216.7", "2606:2800:220:1::1", "93.184.216.0/24"):
            self.assertFalse(
                is_valid_domain(junk), f"{junk} 被当成了域名"
            )
        self.assertTrue(is_valid_domain("www.example.com"))
        # port_scan 用的是同一把尺子
        self.assertTrue(hasattr(port_scan, "handle_event"))

    async def test_captured_domain_field_comes_out_empty_for_ip_parent(self) -> None:
        """把 ``handle_event`` 里那行的实际效果直接跑出来。"""
        from core.domains.web_hunter import port_scan as ps

        captured: list[str] = []

        async def fake_emit_for_host(ip, ports, domain, event):
            captured.append(domain)

        m = ps.port_scan.__new__(ps.port_scan)
        m.log = type("L", (), {"info": lambda *a, **k: None,
                               "debug": lambda *a, **k: None,
                               "warning": lambda *a, **k: None})()
        m._open_ports = {"93.184.216.7": {80, 443}}
        m._emit_for_host = fake_emit_for_host
        m._engine = type("S", (), {})()

        from core.engine.event import Event, EventType
        ev = Event(type=EventType.IP_ADDRESS, data="93.184.216.7",
                   parent_data="93.184.216.18")

        await ps.port_scan.handle_event(m, ev)
        self.assertEqual(
            captured, [""],
            "IP 形式的 parent_data 又被当成域名发出去了 —— "
            "http_probe 会拿着这台机器的 IP 当 Host 去探",
        )

    async def test_real_domain_parent_data_is_still_used(self) -> None:
        """别把好使的也一起砍了：真域名父事件仍要补发 vhost 探活。"""
        from core.domains.web_hunter import port_scan as ps
        from core.engine.event import Event, EventType

        captured: list[str] = []

        async def fake_emit_for_host(ip, ports, domain, event):
            captured.append(domain)

        m = ps.port_scan.__new__(ps.port_scan)
        m.log = type("L", (), {"info": lambda *a, **k: None,
                               "debug": lambda *a, **k: None,
                               "warning": lambda *a, **k: None})()
        m._open_ports = {"93.184.216.7": {443}}
        m._emit_for_host = fake_emit_for_host
        m._engine = type("S", (), {})()

        ev = Event(type=EventType.IP_ADDRESS, data="93.184.216.7",
                   parent_data="www.example.com")
        await ps.port_scan.handle_event(m, ev)
        self.assertEqual(captured, ["www.example.com"])


class TestRequiresDomainGate(EngineTestCase):
    """``requires_domain``：网段 / 裸 IP 不是域名，别让它们进按域名写就的模块。

    ## 这条闸门是被一次实跑逼出来的

    扫 ``203.0.113.0/24`` 时 ``seed_asset`` 正确产出了 254 个 IP_ADDRESS
    （网段功能本身是对的），但同一批种子里还有一条 ``SEED(203.0.113.0/24)``，
    而好几个模块 ``watched_events = (EventType.SEED,)`` 且**直接把
    ``event.data`` 当根域名用**：

    * ``dns_brute`` 拼出 ``www.203.0.113.0/24`` —— 词表 19706 条
    * ``wildcard_detect`` 拿它探泛解析
    * ``passive_*`` 十来个第三方源把这段垃圾当域名发给外部 API

    这不是"省流量"性质的过滤：这些请求**从来就没能命中过任何东西**，
    而被动源那边还会记下一个我们压根不认识的"域名"。

    ## 为什么不靠 per_domain_only 顺手拦掉

    因为它拦不住。``per_domain_only`` 问的是"这个域名我见过了吗"，
    而网段压根不是域名 —— 那次调用是靠一条语义不对的规则"蒙对"的，
    一旦模块顺序变化就露馅。所以是**独立的一条判据**，且判在它之前。
    """

    async def test_domain_target_runs(self) -> None:
        self.add_module_file("req_domain", REQUIRES_DOMAIN)
        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["bydomain", "byanything"]
        )
        self.assertEqual(scanner.modules["bydomain"].seen, ["example.com"])
        self.assertEqual(scanner.modules["byanything"].seen, ["example.com"])

    async def test_netblock_target_is_not_treated_as_a_domain(self) -> None:
        self.add_module_file("req_domain", REQUIRES_DOMAIN)
        scanner, _ = await self.run_scan(
            targets=["203.0.113.0/24"], include=["bydomain", "byanything"]
        )
        self.assertEqual(
            scanner.modules["bydomain"].seen, [],
            "网段被当成根域名放行了 —— dns_brute 会去查 www.203.0.113.0/24",
        )
        self.assertEqual(
            scanner.modules["byanything"].seen, ["203.0.113.0/24"],
            "不声明 requires_domain 的模块必须照常收到种子 —— "
            "这条闸门不能变成全局过滤",
        )

    async def test_bare_ip_target_is_not_treated_as_a_domain(self) -> None:
        """裸 IP 种子同理 —— 它比网段更早就走这条路，只是没人注意。"""
        self.add_module_file("req_domain", REQUIRES_DOMAIN)
        scanner, _ = await self.run_scan(
            targets=["93.184.216.34"], include=["bydomain"]
        )
        self.assertEqual(scanner.modules["bydomain"].seen, [])

    async def test_ipv6_target_is_not_treated_as_a_domain(self) -> None:
        self.add_module_file("req_domain", REQUIRES_DOMAIN)
        scanner, _ = await self.run_scan(
            targets=["2606:2800:220:1:248:1893:25c8:1946"],
            include=["bydomain"],
        )
        self.assertEqual(scanner.modules["bydomain"].seen, [])

    async def test_trailing_dot_and_wildcard_are_still_domains(self) -> None:
        """**闸门不能把真域名判没。**

        直接拿原始串判 ``is_valid_domain`` 的话，这两种会被误杀：

        * ``example.com.`` —— 最后一个标签是空串，标签正则不匹配
        * ``*.example.com`` —— ``*`` 在非法字符集里

        而它们是第三方被动源**真的会返回**的形态，代表真实存在的子域。
        一条闸门把资产判没了，比多发几个请求严重得多。

        ⚠️ 走的是 ``DNS_NAME`` 而不是 ``SEED``：引擎在建种子事件**之前**就
        调过 ``_normalize_target``（里面就有 ``strip("*.")``），所以种子永远
        不会是这两种形态 —— 拿种子来测这条会得到"通过"的假结论，
        真正的风险路径根本没被覆盖。
        """
        self.add_module_file("req_domain", REQUIRES_DOMAIN)
        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["oddnames", "bydomain"]
        )
        self.assertEqual(
            sorted(scanner.modules["bydomain"].seen),
            ["*.example.com", "example.com", "example.com."],
        )

    async def test_skip_is_counted_as_skipped(self) -> None:
        """被闸门挡下要**留痕**，否则"这模块怎么一次都没跑"无从排查。

        ⚠️ 记在 ``stats["module.<名>.skipped"]``，**不是** ``summary["modules_skipped"]``
        —— 后者是**预设级**跳过（"这个预设没勾它"），两回事。断言指错地方会得到
        一个看着像"闸门没生效"的假失败。
        """
        self.add_module_file("req_domain", REQUIRES_DOMAIN)
        _, summary = await self.run_scan(
            targets=["203.0.113.0/24"], include=["bydomain"]
        )
        self.assertEqual(
            summary["stats"].get("module.bydomain.skipped"), 1,
            "闸门挡住了却没计数 —— 模块静默不跑，界面上与'没产出'无法区分",
        )


class TestBatchErrorsAreCounted(EngineTestCase):
    """批内失败必须留下痕迹。

    起因（2026-10-04 排查引擎健壮性时查出来的）：``http_probe`` /
    ``tls_cert`` / ``dns_resolve`` 三个模块的 ``handle_batch`` 都写成
    ``await asyncio.gather(..., return_exceptions=True)``。异常被彻底吞掉：

    * 模块自己的 stats 不知道；
    * 引擎那侧 ``handle_batch`` 正常返回 → 整批被记成 ``ok``。

    结果是凡用 ``batch_size`` 的模块，``module.*.error`` **结构上恒为 0**，
    批内失败在任何地方都看不见 —— 现场表现就是"这模块在跑，就是没产出"。

    现在统一走 ``BaseModule.gather_batch``：仍然并发、仍然不抛（同批其他条目
    不受影响），但记 ``stats["errors"]`` + 一条 warning。
    """

    BOOM = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class batch_boom(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.DNS_NAME,)
    flags = ('passive', 'safe')
    batch_size = 8

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.stats = {'ok': 0, 'errors': 0}

    async def handle_event(self, event):
        n = int(event.data.split('.')[0][1:])
        if n % 2:
            raise ValueError('boom ' + str(n))
        self.stats['ok'] += 1

    async def handle_batch(self, events):
        # 这就是要守的形态：并发、不抛（同批其他条目不受影响），但**逐条记账**
        await self.gather_batch(
            (self.handle_event(e) for e in events), what=self.name
        )

    def source_stats(self):
        return {
            'source': self.name,
            'requests': self.stats['ok'],
            'request_errors': 0,
            'raw': self.stats['ok'] + self.stats.get('errors', 0),
            'results': self.stats['ok'],
            'errors': self.stats.get('errors', 0),
            'elapsed': 0.0,
            'skipped': 0,
            'last_error': '',
            'detail': {},
        }
"""

    async def _scan(self):
        self.add_module_file("batch_boom", self.BOOM)
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        seeds = [f"h{i}.example.com" for i in range(8)]
        scanner = Scanner(
            targets=seeds,
            preset=Preset(name="t", include=["batch_boom"],
                         module_dirs=[str(self.module_dir)]),
            storage=None,
        )
        return await scanner.scan(), scanner

    async def test_one_bad_item_does_not_sink_the_batch(self) -> None:
        """并发仍在继续 —— 好的那几条必须照常处理。"""
        summary, scanner = await self._scan()
        mod = scanner.modules["batch_boom"]
        self.assertEqual(mod.stats["ok"], 4, "同批里好的条目被连累了")

    async def test_failures_are_recorded_in_module_stats(self) -> None:
        summary, scanner = await self._scan()
        mod = scanner.modules["batch_boom"]
        self.assertEqual(mod.stats.get("errors"), 4,
                         f"批内失败没被记账: {mod.stats}")

    async def test_failures_surface_in_source_stats(self) -> None:
        """源统计里必须看得见 —— 否则界面上还是"一切正常"。"""
        summary, scanner = await self._scan()
        rows = summary.get("source_stats") or []
        row = next((r for r in rows if r["source"] == "batch_boom"), None)
        self.assertIsNotNone(row, f"源统计里没有 batch_boom: {rows}")
        self.assertEqual(row["errors"], 4, f"源统计没报批内失败: {row}")



class TestCleanupOnHardSetupFailure(EngineTestCase):
    """某个模块 ``setup()`` 硬失败时，**前面已经拿到资源的模块必须拿到 cleanup**。

    起因（2026-10-04 排查引擎健壮性时查出来的）：

    * ``Scanner.setup()`` 在某个模块 ``setup()`` 返回 False 时抛
      ``ModuleSetupError``，而 ``scan()`` 里的 ``await self.setup()`` 当时摆在
      ``try/finally`` **外面** —— 抛了之后 ``_cleanup_modules()`` 走不到；
    * 排在它前面的模块已经把资源拿在手里了，最重的是 ``screenshot``：
      它的 ``setup()`` 会拉起一个 live Chromium 进程，只有关 ``cleanup()``
      才关得掉。

    内置模块今天都不返回 False，但 ``preset.module_dirs`` 是受支持的外部模块
    入口 —— 所以这不是纯理论。

    夹具用**自定义模块目录**：名字得能确定性地排在坏模块之前。
    """

    HOLD = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class resource_hog(BaseModule):
    # setup 里拿资源, cleanup 里放资源 —— 这里只记账
    watched_events = (EventType.SEED,)
    produced_events = ()
    flags = ('passive', 'safe')

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.opened = False
        self.closed = 0

    async def setup(self):
        self.opened = True
        return True

    async def cleanup(self):
        self.closed += 1
"""

    BOOM = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class zzz_boom(BaseModule):
    # 名字排在 resource_hog 之后, 确保它失败时对方已经拿到资源
    watched_events = (EventType.SEED,)
    produced_events = ()
    flags = ('passive', 'safe')

    async def setup(self):
        return False          # 硬失败
"""

    DEPS_FAIL = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class deps_fail(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = ()
    flags = ('passive', 'safe')

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.closed = 0

    async def setup_deps(self):
        return None, 'missing dep'      # 软失败 -> enabled=False

    async def cleanup(self):
        self.closed += 1
"""

    def _scanner(self, include):
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        return Scanner(
            targets=["example.com"],
            preset=Preset(name="t", include=include,
                         module_dirs=[str(self.module_dir)]),
            storage=None,
        )

    async def test_an_earlier_module_still_gets_cleaned_up(self) -> None:
        """核心不变式：``setup()`` 硬失败也不能让别人的资源泄漏。"""
        from core.engine.errors import ModuleSetupError

        self.add_module_file("resource_hog", self.HOLD)
        self.add_module_file("zzz_boom", self.BOOM)
        scanner = self._scanner(["resource_hog", "zzz_boom"])
        with self.assertRaises(ModuleSetupError):
            await scanner.scan()
        hog = scanner.modules["resource_hog"]
        self.assertTrue(hog.opened, "夹具没生效 —— setup 压根没被调到")
        self.assertEqual(hog.closed, 1, "拿到了资源却没被 cleanup")

    async def test_a_disabled_module_still_gets_a_chance(self) -> None:
        """``setup_deps`` 拿了资源才失败的模块，``enabled`` 是 False 但照样要 cleanup。"""
        self.add_module_file("deps_fail", self.DEPS_FAIL)
        scanner = self._scanner(["deps_fail"])
        await scanner.scan()
        mod = scanner.modules["deps_fail"]
        self.assertFalse(mod.enabled, "夹具没生效 —— 它本该被判为禁用")
        self.assertEqual(mod.closed, 1, "被禁用的模块没有拿到 cleanup 的机会")



class TestEventLimitConverges(unittest.IsolatedAsyncioTestCase):
    """``max_events`` 触顶后**必须收敛**，不能挂死。

    ⚠️ 这条用 ``asyncio.wait_for`` 包住 ``scan()`` 把"挂死"转成失败 ——
    真挂死时 ``scan()`` 永不返回，测试会直接挂到 pytest 的超时，
    报错信息还指不到真正的原因上。
    """

    #: 故意写得很小：3 条就触顶，测试才跑得完。真实值是 50 万 / 100 万。
    MAX_EVENTS = 3

    async def _run(self, tmp: Path):
        import asyncio

        from core.domains.fingerprint._lib import library  # noqa: F401  仅确保可导入
        from core.engine.event import EventType
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        mods = tmp / "mods"
        mods.mkdir(parents=True, exist_ok=True)
        # 一个什么活都不干、但每次都产出一条新事件的模块 —— 把 _visited 灌上去
        (mods / "flood.py").write_text(
            "from core.engine.event import EventType\n"
            "from core.engine.module import BaseModule\n"
            "\n"
            "\n"
            "class flood(BaseModule):\n"
            "    watched_events = (EventType.SEED,)\n"
            "    produced_events = (EventType.DNS_NAME,)\n"
            "    flags = ('passive', 'safe')\n"
            "    batch_size = 1\n"
            "    workers = 1\n"
            "    async def handle_event(self, event):\n"
            "        for i in range(200):\n"
            "            await self.emit_event(f'host{i}.example.com', EventType.DNS_NAME,\n"
            "                                   parent=event)\n",
            encoding="utf-8",
        )

        preset = Preset(name="flood")
        preset.module_dirs = [str(mods)]
        # 只加载 flood —— 否则会连带把 dns_brute 等真模块拉起来，
        # 变成一次真连 DNS 的扫描（实测会把用例拖到 40 秒，还污染日志）。
        preset.include = ["flood"]
        preset.settings = {"max_events": self.MAX_EVENTS, "max_scope_distance": 3}

        scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
        # 20 秒还收不回来，就是挂死了
        return await asyncio.wait_for(scanner.scan(), timeout=20.0)

    async def test_scan_converges_after_hitting_the_event_limit(self) -> None:
        import tempfile
        from pathlib import Path as _P

        with tempfile.TemporaryDirectory() as td:
            summary = await self._run(_P(td))
            self.assertEqual(
                summary["stats"]["events.limit_hit"], 1,
                "没触顶，测试没打到那条路径",
            )

    async def test_the_limit_is_actually_reported(self) -> None:
        """触顶这件事要能在 stats 里看见，而不是静默收工。"""
        import tempfile
        from pathlib import Path as _P

        with tempfile.TemporaryDirectory() as td:
            summary = await self._run(_P(td))
            self.assertIn("events.limit_hit", summary["stats"])

    async def test_limit_is_not_exceeded(self) -> None:
        """``max_events`` 必须是**真的上限**：处理的事件数不得超过它。

        ## 起因

        上限判定原来写在 ``_visited.add()`` 与 ``events.new += 1`` **之后**，
        用的是 ``>``：事件先被记进 ``_visited``，再拿"含本条的总数"比上限。
        于是 ``max_events=2`` 会放行 3 条 —— **上限被突破**，而且
        ``events.new`` 报出来的是 3、与实际派发数对不上。

        这类 off-by-one 静默把预算放大，最坏情况是"限了 50 万事件"的
        扫描实际处理了 50 万零几条，机器被打满而没有任何提示。

        ## 判据

        断言 ``events.new <= max_events``。**只断言触顶不够** —— 触顶一直
        都能触发，哪怕上限早就被突破了。
        """
        import tempfile
        from pathlib import Path as _P

        with tempfile.TemporaryDirectory() as td:
            summary = await self._run(_P(td))
            got = summary["stats"]["events.new"]
            self.assertLessEqual(
                got, self.MAX_EVENTS,
                f"max_events={self.MAX_EVENTS} 却处理了 {got} 条事件 —— 上限被突破",
            )
            self.assertEqual(
                summary["stats"]["events.limit_hit"], 1,
                "没触顶，测试没打到那条路径",
            )



class TestTargetNormalization(unittest.TestCase):
    """用户输入的目标必须先**归一化干净**，否则作用域闸门会误杀全部子域。

    ## 为什么这组测试重要

    目标归一化一旦被 BOM、尾随冒号这类字符污染，``root_domain_of`` 就一个
    子域都匹配不上。症状极具迷惑性：扫描**照常跑完**、状态 ``finished``、
    资产数 0，日志里只有一行 debug —— 与"这个目标真没有子域"完全无法区分。

    闸门方向是**过严**（不是泄漏），但对用户来说结果一样：扫了个寂寞。
    """

    def _normalize(self, raw: str) -> str:
        from core.engine.scanner import Scanner

        return Scanner._normalize_target(raw)

    def test_trailing_colon_is_a_port_separator(self) -> None:
        """``example.com:`` 里的空端口要被剥掉。

        来自 ``host:port`` 输入框、或配置文件里手写的一行很容易带上。
        按"冒号后必须全是数字"判断会漏掉空串（``"".isdigit()`` 是 False），
        目标就原样存成 ``example.com:``，于是所有真实子域全部越界。
        """
        self.assertEqual(self._normalize("example.com:"), "example.com")

    def test_bom_and_zero_width_are_stripped(self) -> None:
        """``str.strip()`` **不**去 BOM —— Windows 编辑器存的文件十有八九带。"""
        self.assertEqual(self._normalize("\ufeffexample.com"), "example.com")
        self.assertEqual(self._normalize("example.com\u200b"), "example.com")

    def test_subdomains_of_degraded_targets_stay_in_scope(self) -> None:
        """回归护栏：上面两种退化目标，子域必须仍在范围内。"""
        from core.engine.event import Event, EventType

        for raw in ("example.com:", "\ufeffexample.com"):
            with self.subTest(raw=raw):
                s = Scanner.__new__(Scanner)
                s.targets = [self._normalize(raw)]
                s.enforce_scope = True
                s.max_scope_distance = 4
                self.assertTrue(
                    s.in_scope(Event(type=EventType.DNS_NAME, data="www.example.com")),
                    f"目标 {raw!r} 归一化成了 {s.targets[0]!r}，子域被判越界",
                )

    def test_ipv6_targets_still_survive(self) -> None:
        """防回归：去端口的逻辑不能把 IPv6 从第一个冒号切断。"""
        for raw in ("2606:2800:220:1::1", "[2606:2800:220:1::1]", "[::1]:8080"):
            with self.subTest(raw=raw):
                self.assertIn(":", self._normalize(raw), "IPv6 被腰斩了")
        self.assertEqual(self._normalize("[::1]:8080"), "::1")

    def test_degenerate_targets_are_rejected(self) -> None:
        """归一化成空串的输入必须被拒，不能混进 ``self.targets``。

        关键在于 ``[""]`` 是**真值列表**（非空）—— 所以"归一化后再过滤"
        是唯一正确的位置：过滤原始串的话，这些输入会带着空串进扫描，
        而 ``root_domain_of("")`` 返回 ``""``、``in_scope`` 判据是
        ``is not None``，空串照样通过 —— **整个作用域闸门就此失效**。
        """
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        for bad in (".", "*", "http://", "//", "\ufeff", "   "):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    Scanner(targets=[bad], preset=Preset(name="t", include=[]))

    def test_normal_targets_are_unchanged(self) -> None:
        """回归护栏：正常输入的行为不能被上面几处修复带偏。"""
        s = Scanner(
            targets=["Example.COM.", "*.a.com", "http://b.com:8080/x"],
            preset=Preset(name="t", include=[]),
        )
        self.assertEqual(s.targets, ["example.com", "a.com", "b.com"])


class TestCDNMatcherCustomPath(unittest.TestCase):
    """``CDNMatcher(path)`` 传自定义库路径时不能崩。

    潜伏 bug：``__init__`` 里用了 ``Path(path)``，但模块顶部**从没 import 过
    ``Path``**。``from __future__ import annotations`` 只推迟**注解**的求值，
    函数体里的 ``Path`` 是运行时查找 —— 所以无参构造（树内现有的调用方式）
    一切正常，一旦传路径就 ``NameError``。
    """

    def test_constructing_with_a_path_works(self) -> None:
        from core.util.cdn import CDNMatcher

        m = CDNMatcher("custom_cdn.json")
        self.assertEqual(str(m.path), "custom_cdn.json")

    def test_constructing_without_a_path_still_works(self) -> None:
        from core.util.cdn import CDNMatcher

        m = CDNMatcher()
        self.assertTrue(str(m.path).endswith("cdn_info.json"))


class TestModuleDiscovery(unittest.TestCase):
    """「是不是模块」按**内容**判断，不按目录。

    这组测试守着一个静默失败的坑：``abstract`` 一旦被继承，
    抽象基类的**所有子类**都会一起消失，而且不报任何错。
    """

    def _harvest(self, source: str, name: str) -> dict:
        import importlib.util
        import sys
        import types

        from core.engine.scanner import Scanner

        mod = types.ModuleType(name)
        mod.__file__ = f"<{name}>"
        exec(compile(source, f"<{name}>", "exec"), mod.__dict__)
        sys.modules[name] = mod
        try:
            return Scanner._harvest(mod)
        finally:
            sys.modules.pop(name, None)

    def test_plain_library_file_yields_no_modules(self) -> None:
        """纯库文件（没有任何 BaseModule 子类）不应该产出模块。"""
        got = self._harvest(
            "import asyncio\n\n\nclass Helper:\n    pass\n",
            "lib_plain",
        )
        self.assertEqual(got, {})

    def test_real_module_is_harvested(self) -> None:
        from core.engine.module import BaseModule

        got = self._harvest(
            "from core.engine.module import BaseModule\n"
            "from core.engine.event import EventType\n\n\n"
            "class my_mod(BaseModule):\n"
            "    watched_events = (EventType.SEED,)\n"
            "    flags = ('safe',)\n",
            "mod_real",
        )
        self.assertEqual(list(got), ["my_mod"])
        self.assertTrue(issubclass(got["my_mod"], BaseModule))

    def test_abstract_base_is_not_harvested(self) -> None:
        got = self._harvest(
            "from core.engine.module import BaseModule\n"
            "from core.engine.event import EventType\n\n\n"
            "class BaseThing(BaseModule):\n"
            "    watched_events = (EventType.SEED,)\n"
            "    flags = ('safe',)\n"
            "    abstract = True\n",
            "mod_abstract",
        )
        self.assertEqual(got, {})

    def test_abstract_is_not_inherited_by_subclasses(self) -> None:
        """**核心回归**：基类标了 abstract，子类必须照常是模块。

        ``PassiveSourceModule.abstract = True`` 曾经顺着 MRO 传染给全部
        7 个被动源，表现为"被动源凭空消失"且不报错。
        """
        got = self._harvest(
            "from core.engine.module import BaseModule\n"
            "from core.engine.event import EventType\n\n\n"
            "class BaseThing(BaseModule):\n"
            "    watched_events = (EventType.SEED,)\n"
            "    flags = ('safe',)\n"
            "    abstract = True\n\n\n"
            "class child_a(BaseThing):\n"
            "    pass\n\n\n"
            "class child_b(BaseThing):\n"
            "    pass\n",
            "mod_inherit",
        )
        self.assertEqual(sorted(got), ["child_a", "child_b"])
        self.assertNotIn("basething", got)

    def test_subclass_can_unset_abstract(self) -> None:
        """显式写 abstract = False 可以"转正"。"""
        got = self._harvest(
            "from core.engine.module import BaseModule\n"
            "from core.engine.event import EventType\n\n\n"
            "class BaseThing(BaseModule):\n"
            "    watched_events = (EventType.SEED,)\n"
            "    flags = ('safe',)\n"
            "    abstract = True\n\n\n"
            "class promoted(BaseThing):\n"
            "    abstract = False\n",
            "mod_promote",
        )
        self.assertEqual(list(got), ["promoted"])

    def test_full_discovery_finds_all_builtin_modules(self) -> None:
        """内置模块必须全部被发现，且库文件一个都不混进来。

        这个数字是硬编码的**故意**的：加了模块就得改它，
        从而逼人确认"新加的到底是不是模块"。

        变更记录：
          * 18 → 19：删掉 ``passive_otx``（实测两次 HTTP 429，不可用），
            新增 ``passive_anubis`` 与 ``passive_commoncrawl``。
          * 19 → 20：新增 ``url_extract``（URL/JS 采集域的第一个模块）。
          * 20 → 21：新增 ``seed_asset`` —— 修掉"根域名与裸 IP 目标
            从不被解析/探活"这个回退（ARL 的 mass_dns 本来是带根域名的）。
          * 21 → 22：新增 ``js_endpoints``（从 JS 文件里挖接口路径）。
            后来按能力边界**降级并改名 ``js_assets``** —— 只捞完整 URL 与主机名
            （主机名回喂成 ``DNS_NAME``），不再做接口路径枚举。
          * 22 → 24：新增 ``dir_brute``（目录爆破域）与 ``waf_detect``
            （指纹域的 WAF 识别）。至此流水线里只剩"主动爬站"没做。
            ⚠️ ``waf_detect`` 后来删了，见下面 31 → 32 那条。
          * 30 → 31：新增 ``ip_ptr``（IP 反查 PTR）。此前全仓**没有任何一处**
            做 PTR（``rdns`` / ``in-addr.arpa`` 均为零），裸 IP 只能被
            ``http_probe`` 直连后吃通用字典，虚拟主机枚举无从谈起。
          * 31 → 32：删掉 ``waf_detect``（2026-10-03）—— 作为独立模块它只能
            事后报一条 finding，**拦不住已经发出去的请求**，而「认出 WAF 就不发
            请求」正是它存在的全部意义。识别改为内联进 ``dir_brute._find_waf``
            （整台放弃）与 ``js_assets._waf_ok``（跳过这批路径验证），判据仍是
            共用的 ``fingerprint/_lib/waf.py``。同时新增 ``soft404_probe``：
            共享画像拆成「一个容器、各模块各写各的字段」，不再由某一个模块统一负责。
          * 32 → 31：删掉 ``auth_probe``（2026-10-03）。它监听全流水线的
            ``HTTP_RESPONSE``，把 401/403 与登录页记进画像，但**没人读**。
            认证墙是「爆破时顺带观察到的东西」，跟着爆破走视野更准，
            所以结论改由 ``dir_brute`` 顺带写进 ``auth_wall``/``auth_hits``。
            判据仍在 ``fuzz/_lib/soft404.py``，识别能力不受影响。
          * 31 → 32：新增 ``zone_transfer``（2026-10-04）。域传送（AXFR）探测 ——
            成功一次就把整份区域名单白拿，19706 条字典爆破根本不用跑；而
            「允许任意客户端拉全区域」本身就是一条该写进报告的发现。此前全仓
            没有做过 AXFR（``grep axfr|dns.zone`` 零命中），它只需要 dnspython
            现成的 ``dns.query.xfr``，**不引任何新依赖**。
          * 32 → 33：新增 ``netblock_expand``（2026-10-07）。C 段展开 ——
            ``IP_ADDRESS`` → 整段 ``IP_ADDRESS``，下一步自然走端口扫描与探活。
            位置在 ``resolve/``：它按 IP 工作，和 ``ip_ptr`` / ``dns_resolve``
            同属"把一个名字/地址落实成事实"这一类。
          * 33 → 34：新增 ``url_verify``（2026-10-07）。验证 ``url_extract``
            从正文里抽出的链接 —— 实测 82 条抽出来只有 4 条被验证过，
            剩下 78 条躺在 ``url`` 表里标着"已知存在"却从没被请求过。
            验证动作与 ``dir_brute`` / ``js_assets`` 共用
            ``_lib/urlverify.py``，只有策略不同。
          * 34 → 35：新增 ``passive_shodan``（2026-10-07）。网络空间测绘引擎，
            与 ``passive_fofa`` / ``passive_quake`` / ``passive_hunter`` 同一
            套契约。⚠️ 计费比那三家都紧：Shodan **每条过滤式查询 1 个 credit、
            每多翻一页再加 1 个**，所以默认 ``recursive=False``、
            ``max_pages=1``。``test_shodan.py`` 里钉着这两条默认值。
          * 35 → 36：新增 ``passive_virustotal``（2026-10-07）。⚠️ **它不是
            测绘引擎** —— VT 索引的是文件/URL/域名/IP 的**关系图谱**，没有
            按端口/产品/地理做全网查询的能力，归的是「关系图谱 / 威胁情报」
            这一族（同 ``urlscan`` / ``commoncrawl``）。只是"从域名枚举子域"
            这件事上与测绘引擎同形，才复用同一套 ``sub_domains`` 契约。
            限速是全仓最紧的：免费档 **4 次/分钟、500 次/天** → 默认
            ``interval=15`` / ``max_pages=1`` / ``recursive=False``。
        """
        import asyncio

        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        async def go():
            preset = Preset(name="all")
            preset.include = None
            preset.exclude = []
            scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
            scanner.load_modules()
            return sorted(scanner.modules)

        names = asyncio.run(go())
        self.assertEqual(len(names), 36, f"模块数变了: {names}")
        # 库文件绝不能被当成模块
        for lib in ("resolver", "resolver_pool", "dnsgen", "dns_query",
                    "ports", "tls", "extract", "sweep"):
            self.assertNotIn(lib, names, f"{lib} 是库, 不该被注册成模块")
        # 抽象基类不能出现
        self.assertNotIn("passivesourcemodule", names)
        # 免 key 的被动源一个都不能少
        for src in (
            "passive_anubis", "passive_certspotter", "passive_commoncrawl",
            "passive_crtsh", "passive_hackertarget", "passive_rapiddns",
            "passive_subdomaincenter", "passive_urlscan",
        ):
            self.assertIn(src, names)
        # 需要 key 的测绘引擎 / 图谱源：缺 Key 时**软失败**，这里仍要注册
        for src in ("passive_fofa", "passive_quake", "passive_hunter",
                    "passive_shodan", "passive_virustotal"):
            self.assertIn(src, names)
        # 实测不可用而被删掉的源不该复活
        self.assertNotIn("passive_otx", names)

    def test_every_domain_dir_is_a_package(self) -> None:
        """每个能力域目录都必须有 ``__init__.py``。

        **这个坑是静默的**：``pkgutil.walk_packages`` 只递归进**包**，
        没有 ``__init__.py`` 的目录会被整个跳过 —— 那个域里的模块凭空不被发现，
        而且不报任何错、不打任何日志。

        实测就是这么一次丢掉 7 个模块的：新建了 ``resolve/`` ``probe/``
        ``port/`` ``fingerprint/`` 却忘了建 ``__init__.py``，
        模块数从 19 变成 12，`subdomain/` 因为有 ``__init__.py``（从 ``dns/``
        搬过来的）而幸免。没有这条测试，这种错只能靠人眼发现。
        """
        from pathlib import Path

        from core.domains import __path__ as domains_path

        for child in sorted(Path(domains_path[0]).iterdir()):
            if not child.is_dir() or child.name.startswith("_"):
                continue
            self.assertTrue(
                (child / "__init__.py").is_file(),
                f"能力域 {child.name}/ 缺 __init__.py —— 它的模块会静默消失",
            )
            # 二级目录（passive/active/_lib…）同样要是包
            for sub in sorted(child.iterdir()):
                if sub.is_dir() and not sub.name.startswith("__"):
                    self.assertTrue(
                        (sub / "__init__.py").is_file(),
                        f"{child.name}/{sub.name}/ 缺 __init__.py",
                    )

    def test_modules_land_in_the_expected_domain(self) -> None:
        """模块要落在预期能力域里 —— 防止搬家时漏掉某一类。

        分布变了就必须改这里，从而逼人确认"这次移动是有意的"。
        """
        import asyncio

        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        async def go():
            preset = Preset(name="all")
            preset.include = None
            preset.exclude = []
            scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
            scanner.load_modules()
            out: dict[str, list[str]] = {}
            for name, module in scanner.modules.items():
                # core.domains.<域>.… → 取 <域>
                out.setdefault(type(module).__module__.split(".")[2], []).append(name)
            return {k: sorted(v) for k, v in out.items()}

        got = asyncio.run(go())
        self.assertEqual(
            got,
            {
                "subdomain": sorted([
                    "demo_expand", "dns_brute", "dns_permute", "wildcard_detect",
                    "admin_plane", "shadow_asset",
                    "seed_asset",
                    "passive_anubis", "passive_certspotter", "passive_commoncrawl",
                    "passive_crtsh", "passive_fofa", "passive_hackertarget",
                    "passive_hunter", "passive_quake", "passive_rapiddns",
                    # 2026-10-07：接 Shodan 与 VirusTotal。两者都属
                    # 「查询即作用域」的形态（不是脏源），但**不是同一类**：
                    # Shodan 是测绘引擎（端口/banner 全网索引），
                    # VirusTotal 是关系图谱（文件/URL/域名/IP 的关系）。
                    # 因此 Shodan 收裸 IP，VirusTotal 不收
                    # （它的 resolutions 是 passive DNS 历史）。
                    "passive_shodan", "passive_virustotal",
                    "passive_subdomaincenter", "passive_urlscan", "passive_wayback",
                ]),
                "resolve": ["asn_enrich", "dns_resolve", "ip_ptr",
                            "netblock_expand", "zone_transfer"],
                "fingerprint": ["fingerprint"],
                # 2026-10-04：原 probe/ + urls/ + fuzz/ 三个域合并成 web_hunter/。
                # 2026-10-05：port_scan 也并进来（OPEN_TCP_PORT 是 http_probe 与
                # tls_cert 的唯一输入，消费方全在本域内；原先"TCP 层 vs HTTP 层"
                # 那条理由不成立 —— 域的划分标准是"一类问题"，不是"一行代码"，
                # resolve/ 与 fingerprint/ 也都是 1 个模块）。
                # 模块名与 flags 一律没动，只是同域了。
                # 2026-10-06：**screenshot -> page_title**。截图整块删掉（响应报文
                # 取代了它：``http_endpoint.body``），但"静态提不到标题"这个洞留下
                # 了 —— SPA 的 ``<title>`` 是空标签、真实标题由 JS 写入。新的
                # ``page_title`` 只做这一件事（起浏览器读 ``document.title``，
                # 静态标题非空时压根不跑），所以模块名和 flags 都是有意换的。
                "web_hunter": sorted([
                    "http_probe", "page_title", "soft404_probe", "tls_cert",
                    "js_assets", "url_extract", "url_verify",
                    "dir_brute", "port_scan",
                ]),
            },
        )

    def test_no_domain_is_an_empty_placeholder(self) -> None:
        """**所有能力域都有模块了。**

        曾经 ``urls/`` 与 ``fuzz/`` 是故意留空的占位（"流水线缺哪一环一眼可见"）。
        它们各自补上模块之后这条测试就翻面了 —— 现在它守的是"别再出现空占位"：
        没有模块的域目录会静默通过加载（没有 ``BaseModule`` 子类就什么也不做），
        很容易被忘在那里。
        """
        import asyncio
        from pathlib import Path

        from core.domains import __path__ as domains_path
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        async def go():
            preset = Preset(name="all")
            preset.include = None
            preset.exclude = []
            scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
            scanner.load_modules()
            return {type(m).__module__.split(".")[2] for m in scanner.modules.values()}

        with_modules = asyncio.run(go())
        dirs = {
            d.name for d in Path(domains_path[0]).iterdir()
            if d.is_dir() and not d.name.startswith("_") and not d.name.startswith("__")
        }
        self.assertEqual(
            dirs - with_modules, set(),
            "这些域目录里一个模块都没有 —— 要么补上，要么删掉目录",
        )


class TestPreset(unittest.TestCase):
    def test_builtin_presets_exist(self) -> None:
        """内置预设**目录里的 yml** 与 ``list_builtin()`` 必须一一对上。

        ⚠️ 原来这里是硬编码 ``("default", "passive", "active")``。
        ``default.yml`` 与 ``brute.yml`` 已经删掉了（``active`` 是全量预设，
        再留一个 ``default`` 只会让人不知道该选哪个），断言却还按老名单走 ——
        于是每次跑都是红的，而红的理由跟这条测试想守的东西毫无关系。

        改成互相校验：目录里多一个 yml 而 ``list_builtin()`` 不认，或者反过来，
        都会被抓到 —— 那才是这条测试真正该守的。
        """
        from pathlib import Path

        from core.util.paths import resources_dir  # noqa: F401  确认可导入

        names = set(Preset.list_builtin())
        self.assertEqual(
            names, {"passive", "active"},
            f"内置预设名单变了: {sorted(names)}",
        )

        # 目录里多一个 yml 而 list_builtin() 不认（或反过来）都要抓到 ——
        # 那会让前端下拉框列出加载不了的项。枚举走 importlib.resources，
        # 与 list_builtin() 本身同一套机制，否则这条断言验的就不是它了。
        from importlib import resources

        ymls = {
            child.name.rsplit(".", 1)[0]
            for child in resources.files("core.presets").iterdir()
            if child.name.endswith((".yml", ".yaml"))
            and child.name != "_template.yml"
        }
        self.assertEqual(
            ymls, names,
            "目录里的 .yml 与 list_builtin() 对不上 —— 前端会列出加载不了的项",
        )

    def test_unknown_field_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            Preset.from_dict({"name": "x", "typo_field": []})

    def test_deny_flags(self) -> None:
        preset = Preset(name="x", deny_flags=["loud", "invasive"])
        self.assertTrue(preset.allows("quiet", ("active", "safe")))
        self.assertFalse(preset.allows("noisy", ("active", "loud")))


if __name__ == "__main__":
    unittest.main()


class TestPipelineDepth(EngineTestCase):
    """递归预算只该被"会自我递归的跳"消耗，不该被线性流水线消耗。

    回归测试。``scope_distance`` 曾经 = **事件跳数**，而默认上限是 4 ——
    于是一条 6 跳的真实流水线（种子→IP→端口→响应→URL→接口）会在尾部
    被 ``too_deep`` **静默切掉**：模块自己的 stats 显示"发了 2 条"，
    事件表里却一条都没有。这类静默截断极难排查，所以两条都钉死。
    """

    async def test_linear_pipeline_reaches_the_tail(self) -> None:
        self.add_module_file("linear_chain", LINEAR_CHAIN)
        scanner, summary = await self.run_scan(
            targets=["example.com"],
            include=["hop1", "hop2", "hop3", "hop4", "hop5", "hop6"],
        )
        self.assertEqual(
            summary["events_too_deep"], 0,
            "线性流水线被递归闸门切了 —— 链尾的产出会静默丢失",
        )
        techs = await self.storage.technologies(scanner.scan_id)
        self.assertEqual(
            [r["name"] for r in techs], ["nginx"],
            "链尾（第 6 跳）的产出没落库",
        )

    async def test_non_recursive_hops_do_not_consume_budget(self) -> None:
        """同一份资产的派生（IP/端口/响应/URL）跳多少步都不该涨距离。"""
        self.add_module_file("linear_chain", LINEAR_CHAIN)
        scanner, _ = await self.run_scan(
            targets=["example.com"],
            include=["hop1", "hop2", "hop3", "hop4", "hop5", "hop6"],
        )
        events, _ = await self.storage.events(scanner.scan_id, limit=200)
        by_data = {e["data"]: e for e in events}
        # 前 4 跳全是非递归派生 -> 距离 0
        for data in ("1.2.3.4", "1.2.3.4:80", "http://example.com/",
                     "http://example.com/a"):
            self.assertEqual(
                by_data[data]["scope_distance"], 0,
                f"{data} 不该消耗递归预算",
            )
        # URL -> URL 是真环 -> 涨到 1
        self.assertEqual(by_data["http://example.com/b"]["scope_distance"], 1)

    async def test_recursive_domain_discovery_still_burns_budget(self) -> None:
        """子域自我喂养必须仍然被截断（这是唯一能无限递归的东西）。"""
        self.add_module_file("recurse", RECURSE)
        _, summary = await self.run_scan(
            targets=["example.com"],
            include=["recurse"],
            settings={"max_scope_distance": 2, "timeout": 30},
        )
class _BrokenCountsStorage:
    """``asset_counts`` 抛异常的假存储。

    对应真实触发条件：``asset_counts(live=True)`` 那条 SQL 里
    ``scan_asset`` 与 ``event`` 的 ``split_part(dedup_key)`` 是非 sargable join，
    撞上 ``statement_timeout`` 或取连接池超时就会抛。
    """

    def __init__(self, break_counts: bool = True, break_finish: bool = False) -> None:
        self.break_counts = break_counts
        self.break_finish = break_finish
        self.finished: list[tuple[int, str, dict]] = []

    async def asset_counts(self, scan_id: int, live: bool = False) -> dict:
        if self.break_counts:
            raise RuntimeError("canceling statement due to statement timeout")
        return {"domains": 12, "urls": 80}

    async def finish_scan(self, scan_id: int, *, status: str, stats: dict) -> bool:
        if self.break_finish:
            raise RuntimeError("connection reset")
        self.finished.append((scan_id, status, stats))
        return True


class TestFinalizeAlwaysFinishesTheScan(unittest.IsolatedAsyncioTestCase):
    """「统计资产数」失败**不能**把「标记扫描结束」一起带走。

    曾经两件事共用一个 ``try``：``asset_counts`` 一抛异常，``finish_scan``
    就被跳过，而 ``manager`` 那边已经把内存状态置成 ``finished`` —— 于是库里的
    那行**永远停在 running**。症状是界面显示"运行中"、耗时一直涨、日志里只有
    一行 error，排查时极难联想到是收尾这段的问题。
    """

    def _scanner(self, store) -> Scanner:
        scanner = Scanner(
            targets=["example.com"],
            preset=Preset(name="t", include=[]),
            storage=store,
        )
        scanner.scan_id = 54
        return scanner

    async def test_finish_scan_runs_even_when_asset_counts_raises(self) -> None:
        store = _BrokenCountsStorage(break_counts=True)
        await self._scanner(store)._finalize()
        self.assertEqual(
            [f[1] for f in store.finished], ["finished"],
            "asset_counts 抛异常时 finish_scan 仍必须执行，"
            "否则库里那行永远停在 running",
        )
        self.assertEqual(store.finished[0][0], 54)

    async def test_finish_scan_failure_does_not_break_the_summary(self) -> None:
        """反过来：``finish_scan`` 自己失败也不能让调用方拿不到 summary。"""
        store = _BrokenCountsStorage(break_counts=False, break_finish=True)
        summary = await self._scanner(store)._finalize()
        self.assertEqual(summary["scan_id"], 54)

    async def test_both_succeed_path_is_unchanged(self) -> None:
        store = _BrokenCountsStorage(break_counts=False)
        summary = await self._scanner(store)._finalize()
        self.assertEqual([f[1] for f in store.finished], ["finished"])
        self.assertEqual(summary["domains"], 12)
        self.assertEqual(summary["urls"], 80)

    async def test_no_storage_skips_the_whole_block(self) -> None:
        """``storage=None``（纯内存扫描）不能因为这次拆分而报 AttributeError。"""
        scanner = Scanner(
            targets=["example.com"], preset=Preset(name="t", include=[]), storage=None,
        )
        scanner.scan_id = 54
        summary = await scanner._finalize()
        self.assertEqual(summary["scan_id"], 54)


class TestCleanupSurvivesRepeatedCancel(EngineTestCase):
    """模块清理**必须**跑到，哪怕扫描在 finally 里又被取消一次。

    ``stop()`` 只要求 ``status == "running"``，而 ``Scanner.scan()`` 的 finally
    里 ``await asyncio.gather(...)`` 让出控制权时状态还没改成 stopped ——
    这个窗口里第二次 ``cancel()`` 会让 ``CancelledError`` 直接穿过 finally，
    ``_cleanup_modules()`` 永不执行。``setup()`` 拉起的 Chromium（screenshot
    模块）于是留在系统里，多轮累积。

    ⚠️ 这条测试需要一个**真挂住**的模块：``dispatcher`` / ``workers`` 全是
    ``None`` 时 gather 整个被跳过，那里根本没有 await 点可供第二次 cancel
    打断 —— 我第一版直接往 ``scanner.modules`` 里塞对象，测试全绿却什么
    都没测到（变异验证当场揭穿了）。
    """

    async def test_cleanup_runs_even_when_cancelled_again(self) -> None:
        import asyncio

        trace = self.root / "trace.txt"
        self.add_module_file("blocker", f'''
            import asyncio

            from core.engine.event import EventType
            from core.engine.module import BaseModule


            def _t(msg):
                with open(r"{trace}", "a", encoding="utf-8") as fh:
                    fh.write(msg + "\\n")


            class blocker(BaseModule):
                watched_events = (EventType.SEED,)
                produced_events = (EventType.DNS_NAME,)
                flags = ("passive", "safe")

                async def setup_deps(self):
                    _t("setup")
                    return True

                async def cleanup(self):
                    _t("cleanup")

                async def handle_event(self, event):
                    # 挂住，让 worker 一直活着 -> gather 真的会被 await。
                    # 取消**故意**慢一点：真实的模块（Playwright 拆卸、连接池
                    # 关闭）收敛要花时间，那个窗口正是 bug 所在 —— 收得太快，
                    # 第二次 cancel 到达时 finally 早就做完了，测不到东西。
                    try:
                        await asyncio.sleep(3600)
                    except asyncio.CancelledError:
                        await asyncio.sleep(0.4)
                        raise
        ''')

        preset = Preset(
            name="t", include=["blocker"], module_dirs=[str(self.module_dir)],
        )
        scanner = Scanner(
            targets=["example.com"], preset=preset, storage=self.storage,
        )
        task = asyncio.create_task(scanner.scan())
        await asyncio.sleep(0.3)      # 让 setup + worker 真的起来
        task.cancel()                  # 第一次
        await asyncio.sleep(0.05)     # 让它进到 finally 的 gather
        task.cancel()                  # 第二次：正打在 gather 上
        with self.assertRaises(asyncio.CancelledError):
            await task
        await asyncio.sleep(0.05)     # shield 里的清理 task 需要跑完

        seen = trace.read_text(encoding="utf-8").split() if trace.exists() else []
        self.assertIn("setup", seen, f"前提：模块真的 setup 过了，实际 {seen}")
        self.assertIn(
            "cleanup", seen,
            f"模块清理没有执行：{seen} —— Chromium 会留在系统里",
        )


class TestSharedIpVhostProbing(unittest.IsolatedAsyncioTestCase):
    """**同一个 IP 上的每个域名都要被单独探一次活**（2026-10-07）。

    ## 缺陷长什么样

    共享 IP 是最常见的形态（CDN / 多租户 / 共享主机）。原先
    ``Event.key()`` 对 IP_ADDRESS 只用 ``(type, data)``，于是 27 个域名解析
    到同一个 IP 时，第 2..N 个事件**不会分发到模块** ——
    ``port_scan`` 只能给"第一个"域名发 ``OPEN_TCP_PORT``，``http_probe``
    只能用那一个 Host 头去问。

    而"第一个"是谁由 **DNS 并发解析的完成顺序**决定。实测 5 次目标完全相同
    的扫描里被探中的名字每次都不一样（partner / ycrm / partner / ticket /
    ors）。**随机不是限流，是漏。**

    ## 为什么这一块最重要

    同一台机器用不同 Host 头会返回完全不同的内容 —— 可能一个是官网、
    另一个是内部后台。只探一个名字，等于把另一个整片漏掉。

    ## 成本控制

    端口表**只扫一遍**（``port_scan`` 的缓存），只有 ``OPEN_TCP_PORT`` 事件
    按域名数放大；再由 ``max_hosts_per_ip`` 给 CDN 场景封顶。
    """

    @staticmethod
    def _mk_module(scanner_obj, config: dict | None = None):
        """按 ``test_coerce.py`` 的路子造一个能跑的最小模块实例。"""
        from core.domains.web_hunter.port_scan import port_scan
        from core.util.coerce import as_bool, as_list
        from core.util.net import EXTRA_BLOCKED_NETS, parse_ports

        class _Log:
            def __getattr__(self, _):
                return lambda *a, **k: None

        m = port_scan.__new__(port_scan)
        m.config = config or {}
        m.name = "port_scan"
        m._engine = None
        m.stats = {}
        m.log = _Log()
        m.allow_private = as_bool(m.cfg("allow_private", False))
        m.blocked_nets = tuple(m.cfg("blocked_nets", EXTRA_BLOCKED_NETS) or ())
        m.max_ips = int(m.cfg("max_ips", 0) or 0)
        m.max_hosts_per_ip = int(m.cfg("max_hosts_per_ip", 20) or 0) or 20
        m.ports = list(parse_ports(m.cfg("ports"), default="top100"))
        exclude = m.cfg("exclude_ports")
        m.exclude_ports = set()
        for item in as_list(exclude) or ([] if exclude is None else [exclude]):
            if item:
                m.exclude_ports.update(parse_ports(str(item), default="top10"))
        m.port_scanner = scanner_obj
        m._open_ports = {}
        m._hosts_done = {}
        m._over_limit_reported = set()
        m._blocked_ips = set()
        m._ip_count = 0
        m._blocked = {}
        m._reported_reasons = set()
        m._limit_reported = False
        return m

    class _FakePortScanner:
        def __init__(self, open_ports=(80, 443)):
            self.calls: list[str] = []
            self.open_ports = list(open_ports)

        async def scan(self, ip, ports, on_open=None):
            self.calls.append(ip)
            for p in self.open_ports:
                if on_open:
                    await on_open(p)
            return list(self.open_ports)

    @staticmethod
    def _sink(m):
        out: list[tuple] = []
        finds: list[tuple] = []

        async def emit_event(data, etype, *, parent=None, tags=None):
            out.append((str(data), etype, dict(tags or {})))

        async def emit_finding(kind, detail, *, parent=None,
                               severity="info", target=None):
            finds.append((kind, detail))

        m.emit_event = emit_event
        m.emit_finding = emit_finding
        return out, finds

    @staticmethod
    def _ev(ip: str, parent: str):
        from core.engine.event import Event, EventType
        return Event(type=EventType.IP_ADDRESS, data=ip, module="m",
                     parent_data=parent)

    async def test_ip_address_key_includes_parent(self) -> None:
        """去重键必须带 ``parent_data``，但**同一个域名仍然要去重**。"""
        a = self._ev("1.2.3.4", "a.example.com")
        b = self._ev("1.2.3.4", "b.example.com")
        c = self._ev("1.2.3.4", "a.example.com")
        self.assertNotEqual(
            a.key(), b.key(),
            "两个域名解析到同一个 IP，去重键却相同 —— 第二个域名的 vhost "
            "永远探不到（这是本测试存在的原因）",
        )
        self.assertEqual(
            a.key(), c.key(),
            "同域名重复事件仍应被去重，否则同一台机器会被反复扫",
        )

    async def test_open_tcp_port_key_includes_the_domain(self) -> None:
        """**这一条才是 vhost 枚举真正被堵住的那一环。**

        端口事件的 ``data`` 是 ``f"{ip}:{port}"``，同一台机器上 N 个域名发出来
        的 data **逐字相同**；``parent_data`` 是父事件（IP_ADDRESS）的 data，
        也就是那个 IP，同样相同。所以去重键必须取 ``tags["domain"]``。

        实测 2026-10-07：``port_scan`` 已经把 20 个兄弟域名的端口事件都补发出
        去了、闸门也按预期触发（两条 ``vhost_probe_limited``），但那两个共享 IP
        上仍然只有 **1 个** host 拿到端点 —— 19 个在分发前就被引擎去重掉了。
        """
        from core.engine.event import Event, EventType

        def mk(host: str) -> Event:
            return Event(
                type=EventType.OPEN_TCP_PORT, data="117.28.234.46:80",
                module="port_scan", parent_data="117.28.234.46",
                tags={"ip": "117.28.234.46", "port": 80, "domain": host,
                      "proto": "tcp"},
            )

        a, b, a2 = mk("a.example.com"), mk("b.example.com"), mk("a.example.com")
        self.assertNotEqual(
            a.key(), b.key(),
            "同一 IP:80 上的两个域名去重键相同 —— 后一个的 vhost 探不到",
        )
        self.assertEqual(a.key(), a2.key(), "同域名重复仍要去重")

    async def test_open_tcp_port_data_carries_the_domain(self) -> None:
        """data 里必须带域名，否则**账本查不全**。

        ``uq_event(scan_id, type, data, kind)`` 不含 tags，所以 data 只有
        ``"ip:port"`` 时，同 IP 上 N 个域名发出来的事件逐字相同，只有第一条落
        库。功能不受影响（分发走引擎的 ``_visited``），但你在事件表里按域名
        反查「是哪条端口事件触发了这次探活」会查不到。

        实测扫描 #67：探到了 ``ors`` / ``tech-user`` 的端点，事件表里却没有。
        """
        sc = self._FakePortScanner(open_ports=(80, 443))
        m = self._mk_module(sc)
        out, _ = self._sink(m)
        await m.handle_event(self._ev("117.28.234.46", "a.example.com"))
        await m.handle_event(self._ev("117.28.234.46", "b.example.com"))

        datas = [d for d, _, _ in out]
        # ⚠️ 期望值必须**按 sorted 的结果写**：字符串排序里 '4' < '8'，
        # 所以 ":443" 排在 ":80" **前面**。写成 80、443 的顺序会假失败
        # （我第一版就是这么错的，排查了半天以为代码漏发了 80）。
        self.assertEqual(
            sorted(datas),
            ["117.28.234.46:443|a.example.com",
             "117.28.234.46:443|b.example.com",
             "117.28.234.46:80|a.example.com",
             "117.28.234.46:80|b.example.com"],
            f"data 没带上域名，两个域名的事件在库里仍会撞成一条：{sorted(datas)}",
        )
        # tags 里的 ip/port 必须仍然是干净的裸值 —— _upsert_port / tls_cert /
        # http_probe 全都读 tags，不读 data
        for _, _, t in out:
            self.assertEqual(t["ip"], "117.28.234.46")
            self.assertIsInstance(t["port"], int)

    async def test_open_tcp_port_data_has_no_tail_without_a_domain(self) -> None:
        """用裸 IP 触发时不留空尾巴 ``"ip:port|"``。

        ��意 IP 必须用**真实公网段** —— TEST-NET（203.0.113.x 之类）在
        ``EXTRA_BLOCKED_NETS`` 里，会被内网闸门先拦掉，于是断言 0 条事件，
        看起来像"代码没发"，其实是**根本没走到目标路径**。
        """
        sc = self._FakePortScanner(open_ports=(80,))
        m = self._mk_module(sc)
        out, _ = self._sink(m)
        await m.handle_event(self._ev("117.28.234.45", ""))
        self.assertEqual([d for d, _, _ in out], ["117.28.234.45:80"])

    async def test_every_host_on_a_shared_ip_gets_probe_events(self) -> None:
        sc = self._FakePortScanner()
        m = self._mk_module(sc)
        out, _ = self._sink(m)
        domains = [f"h{i}.example.com" for i in range(5)]
        for d in domains:
            await m.handle_event(self._ev("1.2.3.4", d))
        hosts = sorted({t["domain"] for _, _, t in out})
        self.assertEqual(
            len(sc.calls), 1,
            f"端口表被重复扫了 {len(sc.calls)} 次 —— 共享 IP 上要白打 N 倍",
        )
        self.assertEqual(
            hosts, domains,
            f"只有 {len(hosts)}/{len(domains)} 个域名拿到了事件",
        )
        self.assertEqual(len(out), len(domains) * 2, "80+443 每个域名各一条")

    async def test_ip_with_no_open_port_is_still_not_rescanned(self) -> None:
        """零开放端口也要进缓存。

        不进的话第二个域名来了会把整份端口清单**重扫一遍** —— 那不是"补发"，
        是白打一轮全端口。
        """
        sc = self._FakePortScanner(open_ports=())
        m = self._mk_module(sc)
        out, _ = self._sink(m)
        for d in ("a.example.com", "b.example.com", "c.example.com"):
            await m.handle_event(self._ev("5.6.7.8", d))
        self.assertEqual(len(sc.calls), 1, "零端口的 IP 被重复扫了")
        self.assertEqual(out, [], "没有开放端口时不该发出事件")

    async def test_max_hosts_per_ip_caps_and_leaves_a_trace(self) -> None:
        """CDN 闸门：**超限要留痕**，不能静默丢。

        几百个域名挂一个 IP 时，请求数 = 域名数 × 端口数 × 2，没有闸门
        一次扫描能打出去几十万条。
        """
        sc = self._FakePortScanner(open_ports=(80,))
        m = self._mk_module(sc, {"max_hosts_per_ip": 3})
        out, finds = self._sink(m)
        for i in range(10):
            await m.handle_event(self._ev("9.9.9.9", f"h{i}.example.com"))
        self.assertEqual(
            len({t["domain"] for _, _, t in out}), 3,
            "max_hosts_per_ip 没生效",
        )
        self.assertEqual(
            [k for k, _ in finds], ["vhost_probe_limited"],
            "超限没有留痕 —— 用户会以为那 7 个域名都被探过了",
        )

    async def test_distinct_ips_are_independent(self) -> None:
        sc = self._FakePortScanner(open_ports=(80,))
        m = self._mk_module(sc)
        out, _ = self._sink(m)
        await m.handle_event(self._ev("1.1.1.1", "x.example.com"))
        await m.handle_event(self._ev("2.2.2.2", "y.example.com"))
        self.assertEqual(sorted(sc.calls), ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(len(out), 2)

    async def test_known_siblings_on_the_same_ip_are_also_probed(self) -> None:
        """**老域名也要被探** —— 这是共享 IP 场景真正缺的半步。

        带上 parent_data 之后，「同一次扫描里**新发现**的多个域名落到同一 IP」
        已经有各自的端口事件了。但**早已在库的域名不会被重新解析**
        （``dns_resolve`` 只处理 DNS_NAME 事件），拿不到 IP_ADDRESS、也就永远
        轮不到探活。

        实测 2026-10-07：``117.28.234.46`` 上 9 个真实域名，扫描日志里这台机器
        只拿到 **1 个** domain 标签 —— ``sso`` / ``tech-user`` / ``ycrm-uat-h5``
        这些最该探的全漏了。所以这里钉的是"**主动反查同 IP 的兄弟域名**"。
        """
        from core.engine.event import Event, EventType
        from tests.pgutil import drop_storage, make_storage

        storage = await make_storage()
        try:
            sid = await storage.create_scan(targets=["example.com"], preset="t")
            for d in ("a.example.com", "b.example.com", "c.example.com"):
                await storage.project(
                    sid, Event(type=EventType.DNS_NAME, data=d, module="m"))
            # a 与 b 共用一台机器；c 在另一台上（不该被带出来）
            for d in ("a.example.com", "b.example.com"):
                await storage.project(
                    sid, Event(type=EventType.IP_ADDRESS, data="93.184.216.34",
                                module="m", parent_data=d))
            await storage.project(
                sid, Event(type=EventType.IP_ADDRESS, data="93.184.216.35",
                            module="m", parent_data="c.example.com"))

            sc = self._FakePortScanner(open_ports=(80, 443))
            m = self._mk_module(sc)
            m._engine = type("E", (), {"storage": storage})()
            out, _ = self._sink(m)

            # 只喂 a 的事件 —— b 必须靠反查被带出来
            await m.handle_event(self._ev("93.184.216.34", "a.example.com"))

            hosts = sorted({t["domain"] for _, _, t in out})
            self.assertEqual(
                hosts, ["a.example.com", "b.example.com"],
                f"同 IP 的兄弟域名没被补探：{hosts}",
            )
            self.assertEqual(
                len(sc.calls), 1,
                "反查不能触发第二次端口扫描 —— 那就是白打一轮全端口",
            )
            # 另一台机器上的 c 不能被带过来
            self.assertNotIn("c.example.com", hosts)

            # 重复事件不能重复发：同一域名走两条路（自身 + 反查）只发一次
            out.clear()
            m2 = self._mk_module(self._FakePortScanner(open_ports=(80,)))
            m2._engine = type("E", (), {"storage": storage})()
            out2, _ = self._sink(m2)
            await m2.handle_event(self._ev("93.184.216.34", "a.example.com"))
            await m2.handle_event(self._ev("93.184.216.34", "a.example.com"))
            per_host = {}
            for _, _, t in out2:
                per_host[t["domain"]] = per_host.get(t["domain"], 0) + 1
            self.assertEqual(
                per_host.get("a.example.com"), 1,
                f"同一个域名被发了两遍：{per_host}",
            )
        finally:
            await drop_storage(storage)


class TestCertForeignNamespace(unittest.IsolatedAsyncioTestCase):
    """**证书签给了别的根域** —— 范围内的域名 DNS 指向了范围外的资产（2026-10-07）。

    SAN 里的域外名字只是"我们不扩面过去"，那是范围纪律，安静丢掉是对的。
    **反向**的情况不一样：范围内的 ``device.ymcs.yealink.com.cn`` 解析到某台
    机器，而那台机器 443 上出示的证书是 ``*.ymcs.ylcloud.com`` —— 这张证书
    压根不是为我们的命名空间签的。

    实测就是这么抓到的：那两台机器上 ``*.ymcs.yealink.com.cn`` 的域名按
    自己的名字去问没响应，因为它们只服务 ``*.ymcs.ylcloud.com``。
    """

    class _FakeScanner:
        """只提供 ``root_domain_of``（tls_cert 用到的唯一引擎能力）。"""

        def __init__(self, targets):
            self.targets = list(targets)

        def root_domain_of(self, data):
            d = data.strip().lower().rstrip(".")
            for t in self.targets:
                if d == t or d.endswith("." + t):
                    return t
            return None

    class _FakeInfo:
        def __init__(self, cn: str = "", san=()):
            self.common_name = cn
            self.san = list(san)

    @staticmethod
    def _module(targets=("yealink.com.cn",)):
        from core.domains.web_hunter.tls_cert import tls_cert

        m = tls_cert.__new__(tls_cert)
        m.config = {}
        m.name = "tls_cert"
        m.stats = {}
        m.log = None
        m._engine = TestCertForeignNamespace._FakeScanner(targets)
        m.max_san = 100
        m._ignored_san = 0
        m._san_reported = False
        return m

    @staticmethod
    def _sink(m):
        finds = []

        async def emit_finding(kind, detail, *, parent=None, severity="info",
                               target=None):
            finds.append((kind, detail, target))

        async def emit_event(*a, **k):
            return None

        m.emit_finding = emit_finding
        m.emit_event = emit_event
        return finds

    def _ev(self):
        from core.engine.event import Event, EventType
        return Event(type=EventType.OPEN_TCP_PORT, data="1.2.3.4:443",
                     module="port_scan", tags={"ip": "1.2.3.4", "port": 443,
                                               "domain": "device.ymcs.yealink.com.cn"})

    async def test_cert_for_another_root_is_reported(self) -> None:
        m = self._module()
        finds = self._sink(m)
        await m._report_foreign_cert(
            self._ev(), "106.15.224.116", 443, "device.ymcs.yealink.com.cn",
            self._FakeInfo("*.ymcs.ylcloud.com", ["*.ymcs.ylcloud.com",
                                                   "ymcs.ylcloud.com"]))
        self.assertEqual([k for k, _, _ in finds], ["cert_foreign_namespace"])
        detail = finds[0][1]
        self.assertIn("ymcs.ylcloud.com", detail)
        self.assertIn("yealink.com.cn", detail)

    async def test_cert_covering_our_root_is_not_reported(self) -> None:
        """CDN 证书动辄几百个 SAN，其中总会有我们的 —— 那不是异常，别误报。"""
        m = self._module()
        finds = self._sink(m)
        await m._report_foreign_cert(
            self._ev(), "1.2.3.4", 443, "partner.yealink.com.cn",
            self._FakeInfo("*.yealink.com.cn",
                           ["*.yealink.com.cn", "www.qq.com", "a.b.com.cn"]))
        self.assertEqual(finds, [], "证书里明明覆盖了我们的根域，却报了跨命名空间")

    async def test_ip_sni_is_skipped(self) -> None:
        """用 IP 做的 SNI 没有"范围"可言，不能报。"""
        m = self._module()
        finds = self._sink(m)
        await m._report_foreign_cert(
            self._ev(), "1.2.3.4", 443, "1.2.3.4",
            self._FakeInfo("*.someone-else.com", ["*.someone-else.com"]))
        self.assertEqual(finds, [])

    async def test_no_names_means_nothing_to_compare(self) -> None:
        m = self._module()
        finds = self._sink(m)
        await m._report_foreign_cert(
            self._ev(), "1.2.3.4", 443, "x.yealink.com.cn", self._FakeInfo())
        self.assertEqual(finds, [])

    async def test_finding_targets_the_queried_domain(self) -> None:
        """target 要是**被查的那个域名**，它才挂得到资产行上、界面上点得开。

        写成证书里的域外名字（``*.ymcs.ylcloud.com``）的话，界面上会显示一个
        不存在的资产，详情也查不到 —— 这正是资产观察类 finding 最容易犯的错。
        """
        m = self._module()
        finds = self._sink(m)
        await m._report_foreign_cert(
            self._ev(), "106.15.224.116", 443, "device.ymcs.yealink.com.cn",
            self._FakeInfo("*.ymcs.ylcloud.com", ["*.ymcs.ylcloud.com"]))
        self.assertEqual(finds[0][2], "device.ymcs.yealink.com.cn")


if __name__ == "__main__":
    unittest.main()
