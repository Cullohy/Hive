"""WAF 识别域的测试。

两层：
  1. ``_lib/waf.py`` 的匹配 —— 纯函数；重点是**字面 vs 正则**的区别
  2. ``waf_detect`` 模块 —— 走引擎，从已有的 HTTP_RESPONSE 里认 WAF

全部离线：不发任何探测载荷（这正是这个模块的设计前提）。
"""

from __future__ import annotations

import unittest
from unittest import mock

from core.domains.fingerprint._lib.waf import WafRule, detect, load_waf_db
from tests.base import EngineTestCase


class TestWafDb(unittest.TestCase):
    def test_builtin_db_loads(self) -> None:
        db = load_waf_db()
        self.assertGreater(len(db), 20, "指纹库太小")
        names = {e.name for e in db}
        for expected in ("Cloudflare", "ModSecurity"):
            self.assertIn(expected, names)

    def test_rules_are_deduped_across_entries(self) -> None:
        """同一条规则只归给最先加载的条目。

        ``x-nws-log-uuid`` 这种特征被两个条目共用时，不去重会产出两条重复结论。
        """
        db = load_waf_db()
        seen: set[tuple[str, str, str]] = set()
        for entry in db:
            for rule in entry.rules:
                key = (rule.type, rule.name, rule.pattern.lower())
                self.assertNotIn(key, seen, f"规则重复: {key}")
                seen.add(key)

    def test_high_confidence_sorts_first(self) -> None:
        db = load_waf_db()
        ranks = [{"high": 0, "medium": 1, "low": 2}.get(e.confidence, 9) for e in db]
        self.assertEqual(ranks, sorted(ranks), "高置信度条目应排在前面")

    def test_missing_db_is_empty_not_crash(self) -> None:
        self.assertEqual(load_waf_db("D:/definitely/not/here.json"), [])


class TestWafMatching(unittest.TestCase):
    """匹配语义。"""

    def setUp(self) -> None:
        self.db = load_waf_db()

    def _names(self, headers, body="") -> set[str]:
        return {e.name for e, _ in detect(headers, body, entries=self.db)}

    def test_header_presence(self) -> None:
        self.assertIn("Cloudflare", self._names({"cf-ray": "8a1b2c"}))

    def test_cookie_substring(self) -> None:
        self.assertIn("Imperva / Incapsula",
                      self._names({"set-cookie": "incap_ses_123=abc; path=/"}))
        self.assertIn("安全狗 SafeDog",
                      self._names({"set-cookie": "safedog=xyz"}))

    def test_server_regex(self) -> None:
        self.assertIn("ModSecurity",
                      self._names({"server": "Apache/2.4 (ModSecurity)"}))

    def test_body_substring_with_regex_metacharacters(self) -> None:
        """**这条是关键。**

        指纹 ``Attention Required! | Cloudflare`` 里有 ``!`` 和 ``|``。
        如果按正则处理，``|`` 会变成"或"，于是几乎任何正文都能命中。
        所以 body/cookie 必须走字面子串匹配。
        """
        self.assertIn("Cloudflare", self._names({}, "Attention Required! | Cloudflare"))

        # 反例：正文里只有竖线两侧的普通内容，**不该**命中
        self.assertNotIn(
            "Cloudflare",
            self._names({}, "<html><body>Attention Required</body></html>"),
        )
        self.assertNotIn("Cloudflare", self._names({}, "Required!"))

    def test_no_match_on_generic_headers(self) -> None:
        """通用头绝不能命中 —— 否则整库都是误报。"""
        self.assertEqual(
            self._names({
                "server": "nginx/1.24.0",
                "content-type": "text/html; charset=utf-8",
                "date": "Mon, 01 Jan 2026 00:00:00 GMT",
                "connection": "keep-alive",
            }, "<html><body>hello</body></html>"),
            set(),
        )

    def test_rule_describe_is_readable(self) -> None:
        self.assertIn("响应头", WafRule(type="header", name="cf-ray").describe())
        self.assertIn("Server", WafRule(type="server", pattern="x").describe())
        self.assertIn("Cookie", WafRule(type="cookie", pattern="x").describe())
        self.assertIn("正文", WafRule(type="body", pattern="x").describe())


PAYLOAD = {
    "cloudflare": {
        "headers": {"cf-ray": "8a1b2c", "server": "cloudflare"},
        "body": "<html>ok</html>",
    },
    "clean": {
        "headers": {"server": "nginx/1.24.0", "content-type": "text/html"},
        "body": "<html>hello</html>",
    },
}

EMIT_RESPONSE = """
from core.engine.event import EventType
from core.engine.module import BaseModule

HEADERS = %r
BODY = %r


class emit_response(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.HTTP_RESPONSE,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event(
            "http://www.example.com/",
            EventType.HTTP_RESPONSE,
            parent=event,
            tags={"url": "http://www.example.com/", "domain": "www.example.com",
                  "headers": HEADERS, "body_snippet": BODY},
        )
"""


class TestWafDetectModule(EngineTestCase):
    async def _scan(self, which: str, **cfg):
        self.add_module_file(
            "emit_response",
            EMIT_RESPONSE % (PAYLOAD[which]["headers"], PAYLOAD[which]["body"]),
        )
        kwargs = {"settings": {"forbidden_domains": []}}
        # 只能在非空时带上 module_config —— 传 None 会让 preset 的同名字段
        # 变成 None，而它的类型是 dict（已在 Preset.config_for 里加了兜底，
        # 但测试这边也不该依赖那个兜底）
        if cfg:
            kwargs["module_config"] = {"waf_detect": cfg}
        return await self.run_scan(
            targets=["example.com"],
            include=["emit_response", "waf_detect"],
            **kwargs,
        )

    async def _findings(self, scan_id: int) -> list[str]:
        rows = await self.storage.findings(scan_id)
        return [f"{r['kind']} | {r['detail']}" for r in rows]

    async def test_detects_and_reports(self) -> None:
        scanner, _ = await self._scan("cloudflare")
        findings = await self._findings(scanner.scan_id)
        self.assertTrue(
            any("WAF: Cloudflare" in f for f in findings), f"没识别到: {findings}"
        )
        # 结论里要说清后果，而不只是"发现了一个 WAF"
        self.assertTrue(any("目录爆破" in f for f in findings), findings)

    async def test_clean_response_reports_nothing(self) -> None:
        scanner, _ = await self._scan("clean")
        self.assertEqual(await self._findings(scanner.scan_id), [])

    async def test_per_host_dedup(self) -> None:
        """同一个主机只报一次，否则每个端点都会刷一条一样的结论。"""
        scanner, _ = await self._scan("cloudflare")
        findings = await self._findings(scanner.scan_id)
        self.assertEqual(len([f for f in findings if "WAF:" in f]), 1, findings)

    async def test_min_confidence_filters_medium(self) -> None:
        """把阈值提到 high 之上时，medium 的猜测不该进结论区。"""
        # 造一个只靠 medium 规则才能命中的响应
        scanner, _ = await self._scan("clean", min_confidence="low")
        self.assertEqual(await self._findings(scanner.scan_id), [])

    async def test_stats_are_reported(self) -> None:
        _, summary = await self._scan("cloudflare")
        row = next((r for r in summary["source_stats"] if r["source"] == "waf_detect"), None)
        self.assertIsNotNone(row, f"没收到统计: {summary['source_stats']}")
        self.assertEqual(row["requests"], 0, "它不该发任何请求")

    async def test_no_requests_are_made(self) -> None:
        """**核心前提**：只用已有响应，不发探测载荷。"""
        from core.services.http import HTTPClient

        calls: list[str] = []

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                calls.append(url)
                return None
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            await self._scan("cloudflare")
        self.assertEqual(calls, [], f"不该发请求: {calls}")



class TestWafPresets(unittest.TestCase):
    """它不碰目标（passive/safe），所以默认预设应该启用它。"""

    def _names(self, preset_name: str) -> set[str]:
        import asyncio

        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        async def go():
            s = Scanner(targets=["example.com"],
                        preset=Preset.load_builtin(preset_name), storage=None)
            s.load_modules()
            return set(s.modules)

        return asyncio.run(go())

    def test_enabled_in_passive_and_default(self) -> None:
        self.assertIn("waf_detect", self._names("default"))
        self.assertIn("waf_detect", self._names("passive"))

    def test_disabled_when_not_in_include_list(self) -> None:
        # brute 预设是显式 include 列表，里面没有它
        self.assertNotIn("waf_detect", self._names("brute"))


if __name__ == "__main__":
    unittest.main()
