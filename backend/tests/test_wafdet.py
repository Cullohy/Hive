"""``WafDetector`` —— 判定收拢 + 多形态载荷。

要钉的四件事：

1. **第 1 段零流量。** 静态匹配只读已有响应，一个包都不发。
2. **第 2 段只在有迹象时发。** 没迹象就朝目标发畸形 URL，那本身就是攻击器行为。
3. **多种形态。** 303 条 attack_only 规则里 271 条是 body 型（匹配 WAF 的
   拦截页），只发 query 形状的话，路径穿越/头注入那批规则永远点不着。
4. **两条线分开。** ``name`` = 够格写结论（宁缺勿滥）；``suspected`` =
   任何迹象都算（宁滥勿打，因为它决定**要不要继续发包**）。
"""
from __future__ import annotations

import unittest

from core.domains.fingerprint._lib import waf as waflib
from core.domains.web_hunter._lib.wafdet import (
    ATTACK_PROBES,
    AttackProbe,
    WafDetector,
)


def _entry(name: str, confidence: str, rules) -> waflib.WafEntry:
    return waflib.WafEntry(name=name, vendor=name, confidence=confidence,
                           rules=list(rules))


def _rule(type_: str, pattern: str = "", *, attack_only: bool = False,
          name: str = "") -> waflib.WafRule:
    """造一条规则 —— **必须走 ``_compile``**。

    ``load_waf_db`` 内部会对每条规则调 :func:`_compile` 预编译正则；
    手工构造 ``WafEntry`` 的人不会想到这一步，于是 ``_re`` 是 ``None``，
    而 ``_search`` 里是 ``bool(self._re and self._re.search(...))``
    —— **静默返回 False**，不报错、不警告。

    实测踩到：``server`` / ``body`` 这些类型的默认模式就是 regex，
    所以「规则明明写对了却一条都匹配不上」。这是建夹具时最容易漏的一步。
    """
    return waflib._compile(waflib.WafRule(
        type=type_, name=name, pattern=pattern, attack_only=attack_only,
    ))


class _Resp:
    """最小 FetchResult 替身。"""

    def __init__(self, headers=None, text="", status=200, reason="OK"):
        self.headers = headers or {}
        self.text = text
        self.status = status
        self.reason = reason


class TestWafDetectorStaticStage(unittest.TestCase):
    """第 1 段：零流量。"""

    def test_matches_on_existing_response_without_sending_anything(self) -> None:
        # header 规则的 pattern 是「在**头值里搜**的字符串」，name 才是头名。
        # 只想看存在性就留空 pattern。
        entries = [_entry("Cloudflare", "high",
                          [_rule("header", "", name="cf-ray")])]
        d = WafDetector(entries=entries, enable_probe=True)
        verdict = d.scan_static([({"cf-ray": "abc", "server": "cloudflare"}, "")])
        self.assertEqual(verdict.name, "Cloudflare")
        self.assertEqual(verdict.stage, "static")
        self.assertEqual(verdict.probed, 0, "静态段发了载荷")

    def test_low_confidence_is_suspected_but_not_a_conclusion(self) -> None:
        """**报不报**和**要不要继续打**是两个问题。"""
        entries = [_entry("SomethingLow", "low",
                          [_rule("server", "someserver")])]
        d = WafDetector(entries=entries, min_confidence="medium")
        verdict = d.scan_static([({"server": "someserver"}, "")])
        self.assertEqual(verdict.name, "", "低置信度不该写进结论")
        self.assertEqual(verdict.suspected, "SomethingLow")
        self.assertTrue(verdict.blocked, "有迹象就要挡住后续发包")

    def test_no_signal_at_all(self) -> None:
        d = WafDetector(entries=[])
        verdict = d.scan_static([({"server": "nginx"}, "hello")])
        self.assertEqual(verdict.name, "")
        self.assertEqual(verdict.suspected, "")
        self.assertFalse(verdict.blocked)


class TestWafDetectorAttackStage(unittest.IsolatedAsyncioTestCase):
    """第 2 段：多种形态，且只在有迹象时发。"""

    async def test_no_signal_means_no_payload_is_sent(self) -> None:
        sent: list[str] = []

        async def fetch(url, headers=None):
            sent.append(url)
            return _Resp()

        d = WafDetector(entries=[], enable_probe=True)
        v = await d.detect("https://x", [({"server": "nginx"}, "hi")], fetch)
        self.assertEqual(sent, [], "没迹象也发攻击载荷 = 无差别打站点")
        self.assertEqual(v.stage, "static")

    async def test_static_hit_short_circuits_the_payload_stage(self) -> None:
        entries = [_entry("Cloudflare", "high",
                          [_rule("header", "", name="cf-ray")])]
        sent: list[str] = []

        async def fetch(url, headers=None):
            sent.append(url)
            return _Resp()

        d = WafDetector(entries=entries, enable_probe=True)
        v = await d.detect("https://x", [({"cf-ray": "1"}, "")], fetch)
        self.assertEqual(v.name, "Cloudflare")
        self.assertEqual(sent, [], "静态已经认出来了还发载荷")

    async def test_attack_only_rule_is_reachable_via_body(self) -> None:
        """**这一条是本次改动的核心。**

        FortiWeb 的规则是 body 型 + ``attack_only``：只有当请求**像攻击**、
        响应里带着 WAF 自己的拦截页时才会匹配。把它当普通规则跑，永远点不着。
        """
        entries = [_entry("FortiWeb", "high",
                          [_rule("body", "attack.id", attack_only=True)])]
        sent: list[str] = []

        async def fetch(url, headers=None):
            sent.append(url)
            return _Resp(headers={"server": "FortiWeb"},
                         text='{"attack.id": "12345"}', status=403)

        # 先给一点"有迹象"的静态信号，触发第 2 段
        entries_static = entries + [
            _entry("VagueThing", "low", [_rule("server", "forti")])]
        d = WafDetector(entries=entries_static, min_confidence="medium",
                        enable_probe=True, max_probes=3)
        v = await d.detect("https://x", [({"server": "forti"}, "")], fetch)
        self.assertEqual(v.name, "FortiWeb", "attack_only 规则没被触发")
        self.assertEqual(v.stage, "attack")
        self.assertGreater(len(sent), 0, "一条载荷都没发")

    async def test_payload_shapes_cover_query_path_and_header(self) -> None:
        """只发 query 形状，路径穿越/头注入那批规则永远点不着。"""
        shapes = {p.shape for p in ATTACK_PROBES}
        self.assertIn("query", shapes)
        self.assertIn("path", shapes)
        self.assertTrue(shapes & {"path_param", "header"},
                        "Tomcat 路径参数与头注入也要覆盖")

    async def test_probe_url_keeps_the_path_shape(self) -> None:
        """**路径形态必须保持原样的分隔符** —— 编码了就等于打不出路径穿越。"""
        p = AttackProbe("path", "../../etc/passwd")
        self.assertEqual(p.url("https://x", "q0"),
                         "https://x/../../etc/passwd")
        # Tomcat/Spring 的路径参数，末尾那个 `;x=1` 就是载荷所在
        self.assertEqual(AttackProbe("path_param", "admin").url("https://x", "q1"),
                         "https://x/q1;x=1")
        # query 形态的路径是空的，全部信息在查询串里
        self.assertTrue(
            AttackProbe("query", "abc").url("https://x", "q0")
            .startswith("https://x/?q0=")
        )

    async def test_max_probes_caps_the_traffic(self) -> None:
        sent: list[str] = []

        async def fetch(url, headers=None):
            sent.append(url)
            return _Resp()

        d = WafDetector(entries=[], enable_probe=True, max_probes=2,
                        probes=ATTACK_PROBES)
        entries = [_entry("Vague", "low", [_rule("server", "x")])]
        d2 = WafDetector(entries=entries, enable_probe=True, max_probes=2,
                         probes=ATTACK_PROBES)
        await d2.scan_attack("https://x", fetch)
        self.assertEqual(len(sent), 2, f"发了 {len(sent)} 条，上限是 2")

    async def test_probe_can_be_disabled_entirely(self) -> None:
        sent: list[str] = []

        async def fetch(url, headers=None):
            sent.append(url)
            return _Resp()

        entries = [_entry("Vague", "low", [_rule("server", "x")])]
        d = WafDetector(entries=entries, enable_probe=False)
        v = await d.detect("https://x", [({"server": "x"}, "")], fetch)
        self.assertEqual(sent, [])
        self.assertEqual(v.probed, 0)

    async def test_suspect_signal_survives_a_failed_attack_stage(self) -> None:
        """**认不出具体是谁，也得记住"有东西挡着"。**"""

        async def fetch(url, headers=None):
            return _Resp(headers={"server": "unknown-waf-ish"},
                         text="blocked", status=403)

        entries = [_entry("Vague", "low", [_rule("server", "unknown-waf-ish")])]
        d = WafDetector(entries=entries, min_confidence="high",
                        enable_probe=True, max_probes=1)
        v = await d.detect("https://x", [({"server": "unknown-waf-ish"}, "")], fetch)
        self.assertEqual(v.name, "")
        self.assertTrue(v.suspected, "迹象丢了 → 后续会继续往有 WAF 的站点打")
        self.assertGreater(v.probed, 0)


if __name__ == "__main__":
    unittest.main()
