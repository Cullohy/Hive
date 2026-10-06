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

        self.assertEqual(summary["events_new"], 4)  # SEED + a. + b. + 10.0.0.1
        self.assertIn("chain_a", summary["modules_enabled"])
        self.assertIn("chain_b", summary["modules_enabled"])

        assets = await self.storage.summary(scanner.scan_id)
        # 根域名自身也是一条资产, 所以是 3 条
        self.assertEqual(assets["domains"], 3)      # example.com, a., b.
        self.assertEqual(assets["ips"], 1)          # 只有一个不同的 IP
        # 关键: IP 事件被去重了, 但两个域名都应关联到它
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
        self.assertEqual(len(names), 32, f"模块数变了: {names}")
        # 库文件绝不能被当成模块
        for lib in ("resolver", "resolver_pool", "dnsgen", "dns_query",
                    "ports", "tls", "extract", "sweep"):
            self.assertNotIn(lib, names, f"{lib} 是库, 不该被注册成模块")
        # 抽象基类不能出现
        self.assertNotIn("passivesourcemodule", names)
        # 7 个被动源一个都不能少
        for src in (
            "passive_anubis", "passive_certspotter", "passive_commoncrawl",
            "passive_crtsh", "passive_hackertarget", "passive_rapiddns",
            "passive_subdomaincenter", "passive_urlscan",
        ):
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
                    "passive_subdomaincenter", "passive_urlscan", "passive_wayback",
                ]),
                "resolve": ["asn_enrich", "dns_resolve", "ip_ptr", "zone_transfer"],
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
                    "js_assets", "url_extract", "dir_brute", "port_scan",
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


if __name__ == "__main__":
    unittest.main()
