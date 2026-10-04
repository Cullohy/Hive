"""WAF 识别域的测试。

三层：
  1. ``_lib/waf.py`` 的匹配 —— 纯函数；重点是**字面 vs 正则**、
     **同组 AND / 组间 OR**、以及 **attackOnly**（只认被拦截响应的规则）
  2. 导入库与上游的一致性 —— ``scripts/import_wafw00f.py --check``
  3. ``dir_brute`` 里的 WAF 闸门 —— 走引擎（原先的独立模块 ``waf_detect``
     已删：它拦不住已经发出去的请求，理由见 ``TestWafInsideDirBrute``）

第 1 层全部离线（不发任何探测载荷）；发载荷那部分在 ``test_fuzz.py`` 里，
且只在 ``active`` 预设下可达（见 ``TestWafProbeInDirBrute``）。
"""

from __future__ import annotations

import os
import unittest
from pathlib import Path
from unittest import mock

from core.domains.fingerprint._lib.waf import WafRule, detect, load_waf_db
from tests.base import EngineTestCase

#: 上游 clone 的位置。本机 HTTPS 全挂，只有 ``git clone`` 通，所以拿不到
#: 就跳过一致性校验，而不是让测试假装通过。
_WAFW00F_CHECKOUT = os.path.join(os.environ.get("TEMP", r"C:\Windows\Temp"),
                                "wafw00f")


class TestWafDb(unittest.TestCase):
    def test_builtin_db_loads(self) -> None:
        db = load_waf_db()
        self.assertGreater(len(db), 20, "指纹库太小")
        names = {e.name for e in db}
        for expected in ("Cloudflare", "ModSecurity"):
            self.assertIn(expected, names)

    def test_wafw00f_fingerprints_are_imported(self) -> None:
        """库里有相当一部分来自 wafw00f，且覆盖到国产量厂。"""
        db = load_waf_db()
        imported = {e.name for e in db if e.source == "wafw00f"}
        self.assertGreater(len(imported), 100, "wafw00f 的指纹没导进来")
        for expected in ("WebKnight", "DenyALL", "AliYunDun", "Qcloud", "ModSecurity"):
            with self.subTest(waf=expected):
                self.assertIn(expected, imported)

    def test_library_matches_upstream(self) -> None:
        """``waf.json`` 必须与「自研文件 + 上游」重新算出来的一致。

        用 AST 解析的导入器有个隐蔽的坑：辅助函数一旦用 ``set`` 去重，
        迭代顺序会随 ``PYTHONHASHSEED`` 变，于是规则顺序每跑一次都不同、
        ``--check`` 永远说"不一致"。这条测试就是钉住那个顺序的。
        """
        import json
        import pathlib
        import sys

        src = pathlib.Path(__file__).resolve().parents[1] / "scripts"
        sys.path.insert(0, str(src))
        try:
            import import_wafw00f as imp
        finally:
            sys.path.pop(0)

        up = pathlib.Path(_WAFW00F_CHECKOUT)
        if not up.is_dir():
            self.skipTest("本机没有 wafw00f 的 clone，跳过一致性校验")
        imported, _ = imp.collect(up, only_signature=False)
        builtin_path = pathlib.Path(imp.BUILTIN_DB)
        builtin = json.loads(builtin_path.read_text(encoding="utf-8"))["wafs"]
        wafs, _, _ = imp.merge(builtin, imported)
        expected = {
            "version": 1,
            "sources": [
                {"id": "builtin", "file": builtin_path.name, "entries": len(builtin)},
                {"id": "wafw00f", "entries": len(imported)},
            ],
            "wafs": wafs,
        }
        cur = json.loads(imp.DEFAULT_DB.read_text(encoding="utf-8"))
        self.assertEqual(cur, expected, "waf.json 与上游不一致，重跑 scripts/import_wafw00f.py")

    def test_rules_are_deduped_across_entries(self) -> None:
        """同一条规则只归给最先加载的条目。

        ``x-nws-log-uuid`` 这种特征被两个条目共用时，不去重会产出两条重复结论。
        """
        db = load_waf_db()
        seen: set[tuple] = set()
        for entry in db:
            for rule in entry.rules:
                # 键形状必须与 ``load_waf_db`` 里的完全一致 —— 那里加了
                # mode / attackOnly / group 三项，测试这边对不上就等于没测
                key = (rule.type, rule.name, rule.pattern.lower(),
                       rule.mode, rule.attack_only, rule.group)
                self.assertNotIn(key, seen, f"规则重复: {key}")
                seen.add(key)

    def test_high_confidence_sorts_first(self) -> None:
        db = load_waf_db()
        ranks = [{"high": 0, "medium": 1, "low": 2}.get(e.confidence, 9) for e in db]
        self.assertEqual(ranks, sorted(ranks), "高置信度条目应排在前面")

    def test_missing_db_is_empty_not_crash(self) -> None:
        self.assertEqual(load_waf_db("D:/definitely/not/here.json"), [])


class TestImportedRuleSemantics(unittest.TestCase):
    """导入 wafw00f 之后**必须成立**的四条语义。

    这四条每一条都是实测踩出来的：弄错任何一条，库看起来变大了（44 → 199），
    实际要么漏报要么满屏误报，而单看代码都"像是对的"。
    """

    def setUp(self) -> None:
        self.db = load_waf_db()

    def _names(self, headers, body="", *, status=None, reason="", attack=False):
        return [
            e.name for e, _ in detect(
                headers, body, entries=self.db,
                status=status, reason=reason, attack=attack,
            )
        ]

    def test_signature_mode_does_not_false_positive(self) -> None:
        """普通站点在签名模式下**一个都不能中**。

        这条是被 ``DenyALL`` 教会的：它有条 ``status == 200`` 规则，在
        wafw00f 里只查被拦截的响应；拿来查正常响应的话，**每个站点都成
        DenyALL**。所以 ``attackOnly`` 的规则必须在签名模式下被跳过。
        """
        for headers, body, status, reason in (
            ({"server": "nginx/1.24.0"}, "<html>hello</html>", 200, "OK"),
            ({"server": "Apache/2.4.41"}, "<html>hi</html>", 404, "Not Found"),
            ({"server": "nginx"}, "<html>forbidden</html>", 403, "Forbidden"),
            ({}, "", 200, "OK"),
        ):
            with self.subTest(server=headers.get("server"), status=status):
                self.assertEqual(
                    self._names(headers, body, status=status, reason=reason), [],
                    "普通站点被误报成 WAF",
                )

    def test_status_rules_only_fire_on_attack_responses(self) -> None:
        """``status == 200`` 这类规则只在探测模式下参与。"""
        self.assertIn("DenyALL", self._names(
            {}, "blocked", status=200, reason="Condition Intercepted", attack=True,
        ))
        self.assertNotIn("DenyALL", self._names(
            {}, "blocked", status=200, reason="Condition Intercepted",
        ))

    def test_rules_in_one_group_are_anded(self) -> None:
        """同组 AND、组间 OR。

        ``WebKnight`` 的一条规则是「状态码 404 **且** reason 是
        ``Hack Not Found``」。展平成独立规则（OR）之后，**任何正常 404 站点
        都会被判成 WebKnight** —— 实测踩到过。
        """
        both = self._names({}, "x", status=404, reason="Hack Not Found", attack=True)
        self.assertIn("WebKnight", both, "两个条件都满足却没认出来")

        only_status = self._names({}, "x", status=404, reason="Not Found", attack=True)
        self.assertNotIn(
            "WebKnight", only_status,
            "只满足状态码就判成 WebKnight —— AND 被展平成 OR 了",
        )

    def test_single_rule_groups_behave_as_or(self) -> None:
        """云解析类厂商是"任一条命中即可"，不能被当成 AND。"""
        names = self._names(
            {"server": "cloudflare", "cf-ray": "8f0a-LAX"},
            "<html>ok</html>", status=200, reason="OK",
        )
        self.assertIn("Cloudflare", names)

    def test_imported_body_rules_are_regex_not_literal(self) -> None:
        """导入的 ``body`` 规则是**正则**语义。

        wafw00f 的 292 条 ``matchContent`` 全是正则：
        ``Attention Required! | Cloudflare`` 在它是「或」，当字面永远不匹配。
        反过来自研那几条含元字符的（``.fgd_icon``）当正则会误报，所以是
        **逐条**声明 ``mode``，不是全局切换。
        """
        names = self._names(
            {"server": "CloudFlare", "cf-mitigated": "challenge"},
            "<title>Attention Required! | Cloudflare</title>",
            status=403, reason="Forbidden", attack=True,
        )
        self.assertIn("Cloudflare", names, "body 的正则交替没生效（被当字面了）")

    def test_header_matching_ignores_case(self) -> None:
        """``server: CloudFlare`` 必须能匹配上 ``cloudflare`` 的规则。

        wafw00f 一律 ``re.I``；原先本项目是区分大小写的，那是漏判不是设计。
        """
        self.assertIn("Cloudflare", self._names({"server": "CLOUDFLARE"}))
        self.assertIn("Cloudflare", self._names({"server": "CloudFlare"}))

    def test_status_403_alone_is_not_modsecurity(self) -> None:
        """对载荷回 403 **不等于** ModSecurity。

        这条钉的是「合并时不能把 AND 结构拆掉」：ModSecurity 在 wafw00f 里
        是 ``reason == "ModSecurity Action"`` **且** ``status == 403``。
        而它同时也有自研条目（同名，导入时要合并）—— 合并时若给每条规则重编
        一个组号，AND 就变成 OR，于是**任何对探测载荷回 403 的站点**（多到
        离谱）都会被判成 ModSecurity 并放弃爆破。
        """
        self.assertNotIn(
            "ModSecurity",
            self._names({}, "whatever", status=403, reason="Forbidden", attack=True),
            "只回 403 就被判成 ModSecurity —— 合并时把 AND 拆成 OR 了",
        )
        self.assertIn("ModSecurity", self._names(
            {}, "whatever", status=403,
            reason="ModSecurity Action", attack=True,
        ))


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


#: 三种应答。``medium`` 只靠 medium 置信度的规则命中（``x-hwwaf`` 是华为云
#: WAF 的裸响应头规则），用来测 ``waf_min_confidence`` 的门槛。
PAYLOAD = {
    "cloudflare": {
        "headers": {"cf-ray": "8a1b2c", "server": "cloudflare"},
        "body": "<html>ok</html>",
    },
    "medium": {
        "headers": {"x-hwwaf": "1"},
        "body": "<html>ok</html>",
    },
    "clean": {
        "headers": {"server": "nginx/1.24.0", "content-type": "text/html"},
        "body": "<html>hello</html>",
    },
}

#: 直接发一个 URL 事件，把 ``dir_brute`` 指向本地假主机（HTTPClient 打了桩）。
EMIT_URL = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_url(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event("http://www.example.com/", EventType.URL, parent=event)
"""


class TestWafInsideDirBrute(EngineTestCase):
    """WAF 识别的端到端行为，现在住在 ``dir_brute`` 里。

    2026-10-03：原先的独立模块 ``waf_detect`` **已删**。理由是它作为独立模块
    只能事后报一条 finding，**拦不住已经发出去的请求** —— 而「认出 WAF 就不发
    请求」正是这个能力存在的全部意义。识别因此内联进 ``dir_brute._find_waf``，
    判据仍是共用的 ``fingerprint/_lib/waf.py``。

    ⚠️ 这几条以前是对着 ``waf_detect`` 跑的。模块删掉之后它们**会空转通过** ——
    ``include`` 里那个名字不存在就等于没加载，finding 自然是空的，于是
    「没报」那几条照样绿。所以必须整体改写，光把名字换掉等于什么都没测。
    """

    HOST = "http://www.example.com"

    async def _scan(self, which: str, **cfg):
        from core.services.http import FetchResult, HTTPClient

        self.add_module_file("emit_url", EMIT_URL)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "waf_gate.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\np000\n", encoding="utf-8")

        seen: list[str] = []
        spec = PAYLOAD[which]

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            seen.append(url)

            async def go():
                return FetchResult(url=url, status=404, text=spec["body"],
                                   headers=dict(spec["headers"]))
            return go()

        module_cfg = {
            "wordlist": str(wl), "probes": 2, "concurrency": 1, "delay": 0,
            # 默认关掉主动载荷探测：这里测的是**识别**，不是探测
            "waf_probe": False,
        }
        module_cfg.update(cfg)

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["emit_url", "dir_brute"],
                module_config={"dir_brute": module_cfg},
                settings={"forbidden_domains": []},
            )
        return scanner, summary, seen

    async def _waf_findings(self, scan_id: int) -> list[str]:
        rows = await self.storage.findings(scan_id)
        return [f"{r['kind']} | {r['detail']}"
                for r in rows if "WAF" in str(r.get("kind") or "")]

    async def test_detects_and_reports(self) -> None:
        scanner, _, _ = await self._scan("cloudflare")
        findings = await self._waf_findings(scanner.scan_id)
        self.assertTrue(findings, f"没识别到 WAF: {findings}")
        self.assertIn("Cloudflare", findings[0])
        # 结论里要说清后果，而不只是"发现了一个 WAF"
        self.assertIn("未发送任何字典请求", findings[0])

    async def test_clean_response_reports_nothing(self) -> None:
        scanner, _, _ = await self._scan("clean")
        self.assertEqual(await self._waf_findings(scanner.scan_id), [])

    async def test_per_host_dedup(self) -> None:
        """同一个主机只报一次，否则每条端点都会刷一条一样的结论。"""
        scanner, _, _ = await self._scan("cloudflare")
        self.assertEqual(len(await self._waf_findings(scanner.scan_id)), 1)

    async def test_min_confidence_filters_medium(self) -> None:
        """把阈值提到 high 之上时，medium 的猜测不该进结论区。"""
        scanner, _, _ = await self._scan("medium", waf_min_confidence="high")
        self.assertEqual(await self._waf_findings(scanner.scan_id), [])

    async def test_medium_still_counts_at_the_default_threshold(self) -> None:
        """对照组：默认阈值（medium）下同一条响应**应该**报出来。

        跟上面那条合起来才说明门槛真的在起作用，而不是"medium 压根认不出来"。
        """
        scanner, _, _ = await self._scan("medium")
        self.assertTrue(await self._waf_findings(scanner.scan_id))

    async def test_stats_are_reported(self) -> None:
        _, summary, _ = await self._scan("cloudflare")
        names = {r["source"] for r in summary["source_stats"]}
        self.assertIn("dir_brute", names, f"没收到统计: {names}")

    async def test_no_attack_payload_when_the_probe_is_off(self) -> None:
        """``waf_probe=False`` 时一条攻击载荷都不该发。

        ⚠️ 这条**不再是**「整个模块零请求」—— 识别住进了 ``dir_brute``，而它
        本来就得发字典请求（收到主机就放弃，发的是那之前）。现在能保证的是：
        **识别本身只读已有响应**，主动载荷探测必须显式开。
        """
        _, _, seen = await self._scan("cloudflare", waf_probe=False)
        self.assertEqual([u for u in seen if "?" in u], [],
                         f"识别不该发带查询串的载荷: {seen}")


class TestWafPresets(unittest.TestCase):
    """WAF 闸门住在 ``dir_brute`` 里 —— 它是爆破域的模块，只在主动模式可用。

    ⚠️ 原先这里断言的是「``waf_detect`` 在两个预设里都有」（它当时是
    passive/safe 的）。模块删掉之后前提就不成立了，不能照抄。
    """

    """WAF 闸门住在 ``dir_brute`` 里，所以看的是 ``dir_brute`` 有没有被启用。"""

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

    def test_bruteforce_carries_the_gate_in_the_active_preset(self) -> None:
        self.assertIn("dir_brute", self._names("active"))


    def test_the_deleted_module_is_not_back(self) -> None:
        """``waf_detect`` 已删。两个预设都不该再出现它。"""
        for name in ("passive", "active"):
            with self.subTest(preset=name):
                self.assertNotIn("waf_detect", self._names(name))


if __name__ == "__main__":
    unittest.main()
