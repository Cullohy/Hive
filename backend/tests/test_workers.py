"""多 worker 的**引擎机制**回归测试。

只管引擎这一层：``worker_count()`` 的取值与兜底、多 worker 不重复处理 / 不丢
事件 / 正常收敛、以及"内置模块声明的 workers 是否合法"。

需要 ``dir_brute`` 自身状态的地方（比如 ``max_hosts`` 配额在并发下不被超发）
放在 ``tests/test_fuzz.py`` —— 那边已经有 ``TestDirBrute`` 的全部辅助设施，
在这里重复一遍只会多出一条跨测试文件的 import。

计数模块把结果写到自己所在目录的 ``counters.json``（``self.module_dir`` 的父目录
就是本测试独占的 ``self.root``），而不是模块全局变量 —— 测试模块是引擎用
``importlib`` 动态加载的，模块名带随机前缀，从 ``sys.modules`` 里捞不稳。

全部离线。
"""
from __future__ import annotations

import json
import unittest

from tests.base import EngineTestCase

#: 一次吐 12 个 URL 事件，逼出真实的 worker 交错
EMIT_MANY = """
from core.engine.event import EventType
from core.engine.module import BaseModule

COUNT = 12


class emit_many(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for i in range(COUNT):
            await self.emit_event(f"http://h{i}.example.com/", EventType.URL, parent=event)
"""

#: 记录处理过的数据、重复项、以及观察到的最大并发度。
#:
#: ⚠️ 并发度用**闸门**测而不是靠 sleep 碰运气：到达 2 个就放行。
#: 串行（1 worker）时第一个必然等超时，``maxlive`` 恒为 1；
#: 真并发时第二个一定能挤进来（第一个卡在闸门上不会退出，
#: 调度器就有机会把第二个事件派给它），``maxlive`` 必然 >= 2。
#: 纯 sleep 的写法会随时序抖动而红 —— 实测同一份代码在裸脚本里是 4、
#: 在 pytest 里就是 1，取决于调度器和 Postgres 的相对快慢。
COUNTER = """
import asyncio
import json
from pathlib import Path

from core.engine.event import EventType
from core.engine.module import BaseModule

OUT = Path(__file__).resolve().parent.parent / "counters.json"
GATE = asyncio.Event()
ARRIVED = 0
LIVE = 0
MAXLIVE = 0
SEEN = []
DUP = []


def _dump():
    OUT.write_text(json.dumps({"seen": SEEN, "dup": DUP, "maxlive": MAXLIVE}),
                   encoding="utf-8")


class counter(BaseModule):
    watched_events = (EventType.URL,)
    produced_events = ()
    flags = ("passive", "safe")
    batch_size = 1

    async def handle_event(self, event):
        global ARRIVED, LIVE, MAXLIVE
        LIVE += 1
        MAXLIVE = max(MAXLIVE, LIVE)
        ARRIVED += 1
        try:
            if ARRIVED >= 2:
                GATE.set()
            try:
                await asyncio.wait_for(GATE.wait(), timeout=0.5)
            except asyncio.TimeoutError:
                pass                       # 串行时的正常结局
            if event.data in SEEN:
                DUP.append(event.data)
            else:
                SEEN.append(event.data)
            _dump()
        finally:
            LIVE -= 1
"""


class TestWorkerCount(unittest.TestCase):
    """``BaseModule.worker_count()`` 的取值与兜底。"""

    @staticmethod
    def _mod(cls_workers: int, config=None, global_settings=None):
        import logging

        from core.engine.module import BaseModule

        # 注意别把形参也叫 settings —— 类体里的 `settings = ...` 会把它
        # 变成类局部名，右侧就找不到外层的了（NameError）。
        class _Scanner:
            log = logging.getLogger("t")
            settings = global_settings or {}

        class M(BaseModule):
            pass

        M.workers = cls_workers
        return M(_Scanner(), config or {})

    def test_default_is_class_attribute(self) -> None:
        self.assertEqual(self._mod(1).worker_count(), 1)
        self.assertEqual(self._mod(5).worker_count(), 5)

    def test_module_config_overrides_class_attribute(self) -> None:
        self.assertEqual(self._mod(1, {"workers": 4}).worker_count(), 4)
        self.assertEqual(self._mod(3, {"workers": 1}).worker_count(), 1)

    def test_global_settings_used_when_module_config_absent(self) -> None:
        self.assertEqual(self._mod(1, {}, {"workers": 6}).worker_count(), 6)

    def test_garbage_falls_back_instead_of_raising(self) -> None:
        """配置写坏了不能让整个扫描起不来，也不能静默变成 0 个 worker。"""
        self.assertEqual(self._mod(2, {"workers": "abc"}).worker_count(), 2)
        self.assertEqual(self._mod(2, {"workers": 0}).worker_count(), 1)
        self.assertEqual(self._mod(2, {"workers": -5}).worker_count(), 1)
        self.assertEqual(self._mod(2, {"workers": None}).worker_count(), 2)

    def test_every_builtin_module_declares_a_valid_value(self) -> None:
        """所有内置模块的 workers 必须是 >=1 的 int。

        写错类型/写成 0 会静默退化成"单 worker 甚至不工作"，不会有任何报错。
        另外：已经有 ``batch_size>1`` 的模块（批内 gather）**不许**再开
        ``workers>1`` —— 两套并发相乘，很容易把目标打狠。
        """
        import importlib
        import pkgutil

        from core.engine.module import BaseModule
        from core.engine.scanner import DEFAULT_MODULE_PACKAGE

        found = 0
        pkg = importlib.import_module(DEFAULT_MODULE_PACKAGE)
        for info in pkgutil.walk_packages(pkg.__path__,
                                          prefix=f"{pkg.__name__}."):
            if info.name.rsplit(".", 1)[-1].startswith("_"):
                continue
            try:
                mod = importlib.import_module(info.name)
            except Exception:  # noqa: BLE001 - 导入失败不是这里要管的事
                continue
            for _, obj in vars(mod).items():
                if not (isinstance(obj, type) and issubclass(obj, BaseModule)
                        and obj is not BaseModule
                        and obj.__module__ == mod.__name__
                        and not obj.__dict__.get("abstract", False)):
                    continue
                found += 1
                with self.subTest(module=obj.__name__):
                    self.assertIsInstance(obj.workers, int,
                                          f"{obj.__name__}.workers 必须是 int")
                    self.assertGreaterEqual(obj.workers, 1)
                    if obj.workers > 1:
                        self.assertEqual(
                            obj.batch_size, 1,
                            f"{obj.__name__} 同时 workers>1 与 batch_size>1，"
                            f"两套并发相乘")
        self.assertGreater(found, 10, f"只发现 {found} 个模块，扫描器本身有问题")


class TestMultiWorker(EngineTestCase):
    """端到端：多 worker 不错、不丢、能收敛。"""

    def _counters(self) -> dict:
        p = self.root / "counters.json"
        self.assertTrue(p.is_file(), "计数模块没写出结果，说明它压根没跑")
        return json.loads(p.read_text(encoding="utf-8"))

    async def _run(self, workers: int):
        self.add_module_file("counter", COUNTER)
        self.add_module_file("emit_many", EMIT_MANY)
        return await self.run_scan(
            targets=["example.com"],
            include=["emit_many", "counter"],
            module_config={"counter": {"workers": workers}},
            settings={"forbidden_domains": []},
        )

    async def _seen_urls(self, scan_id: int) -> set[str]:
        events = await self.storage.events(scan_id, limit=2000, event_type="URL")
        return {e["data"] for e in events if e["module"] == "emit_many"}

    async def test_single_worker_is_the_baseline(self) -> None:
        scanner, _ = await self._run(workers=1)
        c = self._counters()
        self.assertEqual(c["dup"], [], "单 worker 下不该有重复")
        self.assertEqual(len(c["seen"]), 12)
        self.assertEqual(c["maxlive"], 1, "单 worker 的并发度必须恰好是 1")
        self.assertEqual(len(await self._seen_urls(scanner.scan_id)), 12)

    async def test_multi_worker_processes_each_event_exactly_once(self) -> None:
        scanner, _ = await self._run(workers=4)
        c = self._counters()
        self.assertEqual(c["dup"], [], f"同一事件被处理了多次: {c['dup']}")
        self.assertEqual(sorted(c["seen"]),
                         sorted(f"http://h{i}.example.com/" for i in range(12)),
                         "多 worker 下丢了事件")
        self.assertGreater(c["maxlive"], 1, "4 个 worker 却没跑出并发，等于没生效")
        self.assertEqual(len(await self._seen_urls(scanner.scan_id)), 12)

    async def test_multi_worker_still_converges(self) -> None:
        """最要命的一条：worker 多一份，``_pending`` 的减法也多一处。

        ``_module_worker`` 在 ``finally`` 里按 ``len(batch)`` 减 ``_pending``。
        减多了会**提前判空闲**、扫描被静默截断；减少了则永不 idle、挂死。
        两种都不会报错，只能靠"扫完 12 条 URL 一个不少"来证伪。
        """
        for workers in (1, 3, 8):
            with self.subTest(workers=workers):
                self.setUp()
                try:
                    scanner, _ = await self._run(workers=workers)
                    self.assertEqual(len(await self._seen_urls(scanner.scan_id)), 12)
                    self.assertEqual(len(self._counters()["seen"]), 12)
                finally:
                    self.tearDown()
