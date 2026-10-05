"""出站代理设置：重点钉住「三态不被压平成两态」。

这个功能最容易出的错不是"代理填错"，而是**"强制直连"静悄悄退化成
"跟随环境"** —— 那样出站会被甩给一个已经关掉的代理，任务卡住、界面像死了、
日志一条错都没有（2026-10-05 实测挂了 24 分钟）。
所以每条测试都盯住"空串有没有被当成 None"。
"""

import json
import tempfile
import unittest
from pathlib import Path

from .base import EngineTestCase


class TestProxyTriState(unittest.TestCase):
    """三态在设置文件里的存/取。"""

    def setUp(self) -> None:
        from core.web.settings import WebSettings

        self.tmp = tempfile.mkdtemp()
        self.path = Path(self.tmp) / "web_settings.json"
        self.WebSettings = WebSettings

    def _roundtrip(self, value):
        s = self.WebSettings(path=self.path)
        s.proxy = value
        s.save()
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        back = self.WebSettings.load(self.path)
        return back, raw

    def test_absent_means_follow_env(self) -> None:
        """没这一项 = 跟随环境。"""
        s = self.WebSettings(path=self.path)
        s.save()
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        self.assertIsNone(raw["proxy"])
        self.assertIsNone(self.WebSettings.load(self.path).proxy)

    def test_empty_string_survives_the_roundtrip(self) -> None:
        """⚠️ 核心：``""`` = 强制直连，**不能**在存/取里变成 ``None``。

        变成 None 就等于"跟随环境" —— 正是这个设置要避免的情况。
        """
        back, raw = self._roundtrip("")
        self.assertEqual(raw["proxy"], "")
        self.assertIsNotNone(back.proxy, "空串被当成 None 了：强制直连失效")
        self.assertEqual(back.proxy, "")

    def test_custom_url_survives_the_roundtrip(self) -> None:
        back, raw = self._roundtrip("http://127.0.0.1:7897")
        self.assertEqual(raw["proxy"], "http://127.0.0.1:7897")
        self.assertEqual(back.proxy, "http://127.0.0.1:7897")

    def test_explicit_null_means_follow_env(self) -> None:
        """写了 ``proxy: null`` 也是"跟随环境"，和"没写"同义。"""
        self.path.write_text(json.dumps({"proxy": None}), encoding="utf-8")
        self.assertIsNone(self.WebSettings.load(self.path).proxy)

    def test_to_dict_keeps_the_three_states_apart(self) -> None:
        """回传也不能塌：env 必须是 null，direct 必须是空串。"""
        self.assertIsNone(self.WebSettings().to_dict()["proxy"])
        self.assertEqual(self.WebSettings(proxy="").to_dict()["proxy"], "")
        self.assertEqual(
            self.WebSettings(proxy="http://127.0.0.1:7897").to_dict()["proxy"],
            "http://127.0.0.1:7897",
        )


class TestResolveProxySemantics(unittest.TestCase):
    """``resolve_proxy`` 是三态落地的地方。"""

    def test_empty_string_forces_direct_connection(self) -> None:
        from core.services.http import resolve_proxy

        self.assertIsNone(resolve_proxy(""))

    def test_explicit_url_wins(self) -> None:
        from core.services.http import resolve_proxy

        self.assertEqual(
            resolve_proxy("http://10.0.0.1:8888"), "http://10.0.0.1:8888")

    def test_none_follows_env(self) -> None:
        import os

        from core.services.http import PROXY_ENV, resolve_proxy

        old = os.environ.get(PROXY_ENV)
        os.environ[PROXY_ENV] = "http://127.0.0.1:9999"
        try:
            # _env_proxy 是 lru_cache 的，先清掉才能测到刚设的值
            from core.services.http import _env_proxy

            _env_proxy.cache_clear()
            self.assertEqual(resolve_proxy(None), "http://127.0.0.1:9999")
            # ⚠️ 这一条才是要害：环境里有代理时，空串必须**盖住**它
            self.assertIsNone(resolve_proxy(""))
        finally:
            if old is None:
                os.environ.pop(PROXY_ENV, None)
            else:
                os.environ[PROXY_ENV] = old
            from core.services.http import _env_proxy

            _env_proxy.cache_clear()


class TestInjectProxy(unittest.TestCase):
    """注入预设：只有"设置里确实有这一项"才写，且不覆盖预设自己的。"""

    def _preset(self):
        from core.engine.preset import Preset

        return Preset(name="t", include=["http_probe"])

    def test_not_configured_does_not_touch_the_preset(self) -> None:
        from core.web.manager import inject_proxy

        p = self._preset()
        inject_proxy(p, None)
        self.assertNotIn("proxy", p.settings)

    def test_direct_injects_empty_string(self) -> None:
        from core.web.manager import inject_proxy

        p = self._preset()
        inject_proxy(p, "")
        self.assertIn("proxy", p.settings)
        self.assertEqual(p.settings["proxy"], "")

    def test_custom_injects_the_url(self) -> None:
        from core.web.manager import inject_proxy

        p = self._preset()
        inject_proxy(p, "http://127.0.0.1:7897")
        self.assertEqual(p.settings["proxy"], "http://127.0.0.1:7897")

    def test_preset_own_value_is_not_overwritten(self) -> None:
        """预设里写了 proxy 的（"越具体越优先"），设置不能盖掉它。"""
        from core.web.manager import inject_proxy

        p = self._preset()
        p.settings["proxy"] = "http://preset.example:1"
        inject_proxy(p, "http://settings.example:2")
        self.assertEqual(p.settings["proxy"], "http://preset.example:1")

    def test_modules_see_the_injected_value_via_cfg(self) -> None:
        """端到端一环：模块 ``cfg("proxy")`` 要真能拿到强制直连的空串。"""
        from core.web.manager import inject_proxy

        p = self._preset()
        inject_proxy(p, "")

        class _FakeScanner:
            settings = p.settings

        class _FakeModule:
            config: dict = {}
            scanner = _FakeScanner()

            def cfg(self, key, default=None):
                if key in self.config:
                    return self.config[key]
                if self.scanner is not None and key in self.scanner.settings:
                    return self.scanner.settings[key]
                return default

        got = _FakeModule().cfg("proxy")
        self.assertEqual(got, "")
        self.assertIsNotNone(got, "模块拿到的是 None：强制直传到不了模块")


class TestRealCallSitesPreserveTheEmptyString(EngineTestCase):
    """**真实模块**的代理传参点必须原样透传。

    ## 为什么单独一类

    上面那些测试验的是 ``resolve_proxy`` / ``inject_proxy`` / ``cfg``，
    而真正的坑在**四个模块各自的调用点**上：它们曾经写成

        proxy=(self.cfg("proxy") or None),

    ``or None`` 会把**空串变成 None** —— 于是"强制直连"静悄悄退化成
    "跟随环境"，出站被甩给一个关掉的代理，任务卡住而日志一条错都没有。

    这类错**用 mock 测不出来**：把 ``cfg`` 换成假的，上面全部照绿。
    所以这里跑真扫描、patch ``HTTPClient`` 记下它真正收到的 ``proxy`` ——
    mock 打在被调用方**之下**，那层接缝才算被跑到。
    """

    #: 会发 HTTP 的模块（它们各自建自己的 client）
    MODULES = ("dir_brute", "js_assets", "soft404_probe")

    async def _proxy_seen_by_clients(self, settings: dict) -> list:
        from unittest import mock

        from core.services.http import HTTPClient

        seen: list = []
        real_init = HTTPClient.__init__

        def spy(self, **kwargs):
            seen.append(kwargs.get("proxy"))
            return real_init(self, **kwargs)

        with mock.patch.object(HTTPClient, "__init__", spy):
            await self.run_scan(
                targets=["example.com"],
                include=list(self.MODULES),
                settings=dict(settings),
            )
        return seen

    async def test_force_direct_reaches_clients_as_empty_string(self) -> None:
        seen = await self._proxy_seen_by_clients({"proxy": ""})
        self.assertTrue(seen, "没有任何 client 被建起来，这条测试等于没测")
        # ❗ 修复点：把 `or None` 加回去，这里就会红
        for got in seen:
            self.assertEqual(
                got, "",
                f"client 收到的是 {got!r} 而不是空串 —— "
                f"『强制直连』被 `or None` 吃成了『跟随环境』",
            )

    async def test_custom_url_reaches_clients(self) -> None:
        seen = await self._proxy_seen_by_clients(
            {"proxy": "http://127.0.0.1:7897"})
        self.assertTrue(seen)
        for got in seen:
            self.assertEqual(got, "http://127.0.0.1:7897")

    async def test_unset_passes_none_through(self) -> None:
        """没配时是 ``None``（跟随环境），这是三态里的第一态，不是被吃掉。"""
        seen = await self._proxy_seen_by_clients({})
        self.assertTrue(seen)
        for got in seen:
            self.assertIsNone(got)


if __name__ == "__main__":
    unittest.main()
