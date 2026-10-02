"""源 API Key 的配置与注入。

## 为什么这批测试重要

密钥这类东西的 bug 有两种，都很糟而且都不报错：

1. **回显** —— 密钥出现在某个 API 响应里，而那个响应会被浏览器/日志/录屏留下
2. **没生效** —— 用户填了 key，扫描里那个源却因为"缺 key"被跳过，
   而界面上明明显示"已设置"

第 1 条靠"**只回传是否已设置，不回传值**"守住（``auth_token`` 早就是这么做的）；
第 2 条靠端到端跑一次 ``manager.start`` 守住 —— 只测 ``inject_source_keys``
是不够的，那条路径上还有三个调用方可能漏。
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.engine.preset import Preset  # noqa: E402
from core.web.manager import ScanManager, inject_source_keys  # noqa: E402
from core.web.settings import WebSettings  # noqa: E402

from .base import EngineTestCase  # noqa: E402


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
        d = Path(tempfile.mkdtemp())
        return WebSettings(path=d / "s.json")

    def test_roundtrip(self) -> None:
        s = self._settings()
        s.source_keys = {"passive_fofa": "SECRET"}
        s.save()
        self.assertEqual(
            WebSettings.load(s.path).source_keys, {"passive_fofa": "SECRET"}
        )

    def test_to_dict_never_contains_the_key(self) -> None:
        """**这条是整件事的核心。**"""
        s = self._settings()
        s.source_keys = {"passive_fofa": "SECRET-KEY-VALUE"}
        dumped = json.dumps(s.to_dict(), ensure_ascii=False)
        self.assertNotIn("SECRET-KEY-VALUE", dumped)
        self.assertEqual(s.to_dict()["source_keys_set"], ["passive_fofa"])

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
            targets=["example.com"], preset_name="passive",
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
        record = await manager.start(targets=["example.com"], preset_name="passive")
        self.assertIsNone(record.scanner.preset.module_config.get("passive_fofa"))
        await manager.stop(record.scan_id)


if __name__ == "__main__":
    unittest.main()
