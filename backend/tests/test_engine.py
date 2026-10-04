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
        events = await self.storage.events(scanner.scan_id, limit=50)
        ip_event = next(e for e in events if e["type"] == "IP_ADDRESS")

        chain = await self.storage.trace(scanner.scan_id, ip_event["id"])
        types = [row["type"] for row in chain]
        self.assertEqual(types[0], "IP_ADDRESS")
        self.assertIn("DNS_NAME", types)
        self.assertEqual(types[-1], "SEED")
        self.assertEqual(chain[-1]["data"], "example.com")


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
                "port": ["port_scan"],
                "fingerprint": ["fingerprint"],
                # 2026-10-04：原 probe/ + urls/ + fuzz/ 三个域合并成 web_search/。
                # 模块名与 flags 一个没动，只是同域了。
                "web_search": sorted([
                    "http_probe", "screenshot", "soft404_probe", "tls_cert",
                    "js_assets", "url_extract", "dir_brute",
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
        events = await self.storage.events(scanner.scan_id, limit=200)
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
        self.assertGreaterEqual(summary["events_too_deep"], 1)


if __name__ == "__main__":
    unittest.main()
