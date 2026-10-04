"""源 API Key 的配置与注入。

## 为什么这批测试重要

密钥这类东西的 bug 有两种，都很糟而且都不报错：

1. **意外泄漏** —— 密钥出现在某个不该有它的响应/日志里
2. **没生效** —— 用户填了 key，扫描里那个源却因为"缺 key"被跳过，
   而界面上明明显示"已设置"

两条**纪律不同，各有测试守**：

* ``source_keys``（源 API Key）**要回显**：设置页得让用户看见自己配的是哪一个，
  也能在原值上改一个字符，而不是只能整条重填。所以 ``to_dict()`` 带明文，
  见 ``TestSettingsModel::test_to_dict_echoes_the_key_for_editing``。
* ``auth_token`` **永不回传**，只给 ``auth_token_set``
  （见 ``test_to_dict_never_contains_the_token``）。
* "没生效"那条靠端到端跑一次 ``manager.start`` 守住 —— 只测
  ``inject_source_keys`` 是不够的，那条路径上还有三个调用方可能漏。
"""

from __future__ import annotations

import asyncio

import json
import shutil
import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.engine.preset import Preset  # noqa: E402
from core.web.manager import ScanManager, inject_source_keys  # noqa: E402
from core.web.settings import WebSettings  # noqa: E402

from .base import EngineTestCase  # noqa: E402

#: 见 ``base.py`` 的说明：不用 ``tempfile.mkdtemp``（它以 0700 建目录，
#: 在受限令牌/沙箱下会拒绝继续在其中创建文件）。
TEST_TMP_ROOT = Path(__file__).resolve().parents[1] / ".testtmp"


class TestInjectSourceKeys(unittest.TestCase):
    """纯函数：把密钥写进预设的 ``module_config``。"""

    def _preset(self) -> Preset:
        return Preset.load_builtin("passive")

    def test_injects_api_key(self) -> None:
        p = self._preset()
        inject_source_keys(p, {"passive_fofa": "SECRET"})
        self.assertEqual(p.module_config["passive_fofa"]["api_key"], "SECRET")

    def test_empty_key_is_skipped(self) -> None:
        """空值不注入 —— 否则等于给源配了个空 key，它会去发无意义的请求。"""
        p = self._preset()
        inject_source_keys(p, {"passive_fofa": ""})
        self.assertIsNone(p.module_config.get("passive_fofa"))

    def test_does_not_clobber_other_module_config(self) -> None:
        """**只注入 api_key，不碰别的键。**

        ``api_url`` 指向哪个中转站、分页多少，属于任务级选择 ——
        一个全局设置不该把它们悄悄锁死。
        """
        p = self._preset()
        p.module_config.setdefault("passive_fofa", {})["api_url"] = "https://relay/x"
        inject_source_keys(p, {"passive_fofa": "SECRET"})
        self.assertEqual(p.module_config["passive_fofa"]["api_url"], "https://relay/x")
        self.assertEqual(p.module_config["passive_fofa"]["api_key"], "SECRET")

    def test_overrides_still_win(self) -> None:
        """**顺序契约**：先注入设置、再 apply_overrides，越具体越优先。

        这条钉的是 ``manager.start`` 里那两行的先后 —— 调换过来，用户就没法
        在单次任务里临时换 key 了，而且不报任何错。
        """
        p = self._preset()
        inject_source_keys(p, {"passive_fofa": "FROM-SETTINGS"})
        p.apply_overrides(["modules.passive_fofa.api_key=FROM-OVERRIDE"])
        self.assertEqual(p.module_config["passive_fofa"]["api_key"], "FROM-OVERRIDE")

    def test_none_is_a_noop(self) -> None:
        p = self._preset()
        inject_source_keys(p, {})
        inject_source_keys(p, None)  # type: ignore[arg-type]
        self.assertIsNone(p.module_config.get("passive_fofa"))

    def test_source_options_are_injected(self) -> None:
        """``api_url`` 这类**粘性**配置也要从设置里注入。

        实测教训：只注入 ``api_key`` 时，用户每个任务都得手填 ``api_url``；
        忘了填就去打官方域名，然后拿到一句「账号无效」—— 而那个提示看起来
        像 key 错。所以地址必须和 key 一样一次配好。
        """
        p = self._preset()
        inject_source_keys(
            p, {"passive_fofa": "K"}, {"passive_fofa": {"api_url": "https://fofoapi.com"}}
        )
        self.assertEqual(p.module_config["passive_fofa"]["api_url"], "https://fofoapi.com")
        self.assertEqual(p.module_config["passive_fofa"]["api_key"], "K")

    def test_options_do_not_override_existing(self) -> None:
        """同样是 ``setdefault`` 语义 —— 任务级覆盖仍然优先。"""
        p = self._preset()
        p.module_config.setdefault("passive_fofa", {})["api_url"] = "https://from-task"
        inject_source_keys(p, {}, {"passive_fofa": {"api_url": "https://from-settings"}})
        self.assertEqual(p.module_config["passive_fofa"]["api_url"], "https://from-task")

    def test_empty_option_value_is_skipped(self) -> None:
        p = self._preset()
        inject_source_keys(p, {}, {"passive_fofa": {"api_url": ""}})
        self.assertIsNone(p.module_config.get("passive_fofa"))


class TestSettingsModel(unittest.TestCase):
    def _settings(self) -> WebSettings:
        root = TEST_TMP_ROOT / f"s{uuid.uuid4().hex[:10]}"
        root.mkdir(parents=True, exist_ok=True)
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        return WebSettings(path=root / "s.json")

    def test_roundtrip(self) -> None:
        s = self._settings()
        s.source_keys = {"passive_fofa": "SECRET"}
        s.save()
        self.assertEqual(
            WebSettings.load(s.path).source_keys, {"passive_fofa": "SECRET"}
        )

    def test_to_dict_echoes_the_key_for_editing(self) -> None:
        """**这条是整件事的核心。** Key 必须能回显，否则设置页只能显示"已设置"。"""
        s = self._settings()
        s.source_keys = {"passive_fofa": "SECRET-KEY-VALUE"}
        dumped = s.to_dict()
        self.assertEqual(dumped["source_keys"], {"passive_fofa": "SECRET-KEY-VALUE"})
        # 两种表示并存：回显值用于填输入框，"已设置"列表用于兜底判断
        self.assertEqual(dumped["source_keys_set"], ["passive_fofa"])

    def test_to_dict_never_contains_the_token(self) -> None:
        """令牌与 Key 的纪律**不同**：令牌永不回传，只给 ``auth_token_set``。"""
        s = self._settings()
        s.auth_token = "TOKEN-VALUE"
        dumped = json.dumps(s.to_dict(), ensure_ascii=False)
        self.assertNotIn("TOKEN-VALUE", dumped)
        self.assertTrue(s.to_dict()["auth_token_set"])

    def test_empty_values_are_not_reported_as_set(self) -> None:
        s = self._settings()
        s.source_keys = {"passive_fofa": "k", "passive_other": ""}
        self.assertEqual(s.to_dict()["source_keys_set"], ["passive_fofa"])

    def test_load_drops_empty_values(self) -> None:
        """手改文件写了个空串，也不该被当成"已设置"。"""
        s = self._settings()
        s.save()
        s.path.write_text(
            json.dumps({"source_keys": {"passive_fofa": "", "passive_x": "v"}}),
            encoding="utf-8",
        )
        self.assertEqual(WebSettings.load(s.path).source_keys, {"passive_x": "v"})


class TestManagerInjectsStoredKeys(EngineTestCase):
    """**端到端**：设置里存了 key，``manager.start`` 造出来的扫描要带上它。

    只测 ``inject_source_keys`` 是不够的 —— ``start()`` 有三个调用方
    （建任务接口、调度器到期、监控"立即执行"），漏掉任何一个都表现为
    "某个入口的源密钥莫名不生效"，而单测全绿。
    """

    async def _start_with(self, source_keys: dict[str, str]):
        manager = ScanManager(
            self.storage,
            settings=SimpleNamespace(source_keys=source_keys),
        )
        record = await manager.start(
            name="密钥注入测试", targets=["example.com"], preset_name="passive",
        )
        return manager, record

    async def test_stored_key_reaches_the_scanner(self) -> None:
        manager, record = await self._start_with({"passive_fofa": "SECRET"})
        preset = record.scanner.preset
        self.assertEqual(
            preset.module_config.get("passive_fofa", {}).get("api_key"), "SECRET",
            "设置里的 key 没进到这次扫描的 preset",
        )
        # 收尾：跑完的扫描别留着占并发
        await manager.stop(record.scan_id)

    async def test_scan_without_stored_key_still_works(self) -> None:
        """没有存 key 时不能因此崩掉 —— 源照旧软失败、扫描继续。"""
        manager, record = await self._start_with({})
        preset = record.scanner.preset
        self.assertIsNone(preset.module_config.get("passive_fofa"))
        await manager.stop(record.scan_id)

    async def test_no_settings_object_does_not_crash(self) -> None:
        """``settings=None``（旧代码/测试直接构造 manager）时不能炸。"""
        manager = ScanManager(self.storage)
        record = await manager.start(
            name="无设置对象测试", targets=["example.com"], preset_name="passive"
        )
        self.assertIsNone(record.scanner.preset.module_config.get("passive_fofa"))
        await manager.stop(record.scan_id)


class TestStopDoesNotLie(unittest.IsolatedAsyncioTestCase):
    import asyncio  # noqa: PLC0415 - 放在类里, 只给本类用
    """``stop()`` 发出取消之后等不到，**不许**把状态改成 stopped。

    起因（2026-10-04 排查引擎健壮性时查出来的）：原来的兜底是
    「等 ``stop_grace`` 秒后若状态仍是 running，就强行置 stopped 并写库」。

    那是在撒谎 —— 任务还活着，还在发包、还在写库；而更糟的是
    ``running_count`` 只数 ``status == "running"``，一旦被改成 ``stopped``，
    这条**僵尸任务就不再占并发额度**，于是可以超额下发新扫描，而实际同时
    跑着 ``max_concurrent + 1`` 个。

    能踩到的场景不是理论：收尾要做变更对比 + 告警推送，``on_finished``
    回调慢一点就超过宽限期了。
    """

    class _SlowStorage:
        """最小 storage 替身：只记调用，不碰数据库。"""

        def __init__(self) -> None:
            self.finished: list[tuple[int, str]] = []
            self.audits: list[str] = []

        async def finish_scan(self, scan_id, status=None, stats=None, **kw):
            self.finished.append((scan_id, status))

        async def record_audit(self, action, **kw):
            self.audits.append(action)

    def _record(self, status: str = "running"):
        from types import SimpleNamespace

        return SimpleNamespace(
            scan_id=7, status=status, task=None, actor="t",
            targets=["example.com"], mode="active", elapsed=1.0,
        )

    def _manager(self, storage):
        from core.web.manager import ScanManager

        return ScanManager(storage, stop_grace=0.01)      # 0.01s 就"等不到"

    async def test_status_stays_running_when_the_task_ignores_cancel(self) -> None:
        """任务没在宽限期内结束 → 状态**必须**还是 running。"""
        storage = self._SlowStorage()
        manager = self._manager(storage)
        record = self._record()
        never = asyncio.ensure_future(asyncio.sleep(3600))
        record.task = never
        manager._scans[7] = record
        try:
            ok = await manager.stop(7)
        finally:
            never.cancel()

        self.assertTrue(ok, "停止请求已发出，应该返回 True")
        self.assertEqual(record.status, "running",
                         "任务还在跑却写成 stopped —— 僵尸不再占并发额度")
        self.assertEqual(storage.finished, [], "不该往库里写终态")
        self.assertEqual(manager.running_count, 1, "僵尸必须继续占着并发额度")

    async def test_the_scan_stays_in_the_concurrency_count(self) -> None:
        """核心危害：超额下发。"""
        storage = self._SlowStorage()
        manager = self._manager(storage)
        manager.max_concurrent = 1
        for sid in (7,):
            rec = self._record()
            rec.scan_id = sid
            rec.task = asyncio.ensure_future(asyncio.sleep(3600))
            manager._scans[sid] = rec
        try:
            await manager.stop(7)
            self.assertEqual(manager.running_count, 1)
            # 这时再下发第二个必须被拒 —— 否则就是 max_concurrent + 1
            with self.assertRaises(RuntimeError):
                await manager.start(
                    name="第二个", targets=["example.com"], preset_name="passive"
                )
        finally:
            for r in list(manager._scans.values()):
                if r.task:
                    r.task.cancel()

    async def test_stop_never_writes_the_terminal_status_itself(self) -> None:
        """**状态迁移是 ``_run`` 的职责，不是 ``stop()`` 的。**

        ``_run`` 的 ``except asyncio.CancelledError`` 才会把记录置成
        ``stopped`` 并写库。``stop()`` 只负责"发取消 + 等一会儿"——
        它一旦自己写终态，就是在替一个还活着的任务撒谎（见类文档）。
        """
        storage = self._SlowStorage()
        manager = ScanManager(storage, stop_grace=0.01)
        rec = self._record()
        rec.task = asyncio.ensure_future(asyncio.sleep(3600))
        manager._scans[7] = rec
        try:
            await manager.stop(7)
        finally:
            rec.task.cancel()
        self.assertEqual(
            storage.finished, [],
            "stop() 越权写了终态 —— 库里的状态可能与实际不符",
        )
        self.assertEqual(rec.status, "running")

if __name__ == "__main__":
    unittest.main()
