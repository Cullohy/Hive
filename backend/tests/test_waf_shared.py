"""三个模块共用一份 WAF 结论（``WebProfile.waf``）——2026-10-07 切换。

``dir_brute`` 先切到 ``_lib/wafdet.py``，``js_assets`` / ``url_verify`` 跟着切。
切这件事本身不难，难的是**切了之后结论还能不能对齐**。要钉的四件事：

1. **先读共享结论。** ``web.waf`` 里已经有了就别重判 —— 重判既慢，又可能
   得出另一个名字，让同一个站在不同模块的 finding 里显示成两个厂商。
2. **认出来就写回。** 认出来的那一家是**唯一**写 ``web.waf`` 的入口，
   后两家直接吃到结论（跨模块这条最容易断：只读不写就永远各判各的）。
3. **绝不抹空。** 「这一轮没认出来」**不等于**「没有 WAF」。写成
   ``web.waf = name or suspected`` 会在没认出来时抹成空串，于是
   「宁滥勿打」这条规矩**静默失效** —— 没有任何报错。
4. **这两个模块零流量。** 它们走 ``scan_static`` 而不是 ``detect``：
   为了确认多打的 XSS/SQLi 请求正是最容易触发封 IP 的动作。第 2 段载荷
   只留给 ``dir_brute``。

判据本身的测试在 ``test_wafdet.py``，这里只测**接线**。
"""
from __future__ import annotations

import unittest

from core.domains.fingerprint._lib import waf as waflib
from core.domains.web_hunter._lib.webprofile import WebProfile
from core.domains.web_hunter.js_assets import js_assets
from core.domains.web_hunter.url_verify import url_verify
from core.engine.event import Event, EventType


# ------------------------------------------------------------------ 夹具

def _entry(name: str, confidence: str, rules) -> waflib.WafEntry:
    return waflib.WafEntry(name=name, vendor=name, confidence=confidence,
                           rules=list(rules))


def _rule(type_: str, pattern: str = "", *, attack_only: bool = False,
          name: str = "") -> waflib.WafRule:
    """造规则**必须走 ``_compile``** —— 否则 ``_re`` 是 ``None``，
    ``_search`` 里静默返回 False，规则一条都匹配不上还不报错。"""
    return waflib._compile(waflib.WafRule(
        type=type_, name=name, pattern=pattern, attack_only=attack_only,
    ))


#: 高置信度、静态可认 —— 切过去之后**必须**还能认出来
CF_ENTRIES = [_entry("Cloudflare", "high",
                     [_rule("header", "", name="cf-ray")])]

#: 只有被攻击后才匹配（body 型拦截页）。零流量的模块**认不出**它。
FORTI_ENTRIES = [_entry("FortiWeb", "high",
                        [_rule("body", "attack.id", attack_only=True)])]

ORIGIN = "https://www.example.com"


class _State:
    def __init__(self, web: WebProfile | None) -> None:
        self._web = {web.origin: web} if web is not None else {}

    def web_profile(self, origin: str):
        return self._web.get(origin)


class _Engine:
    def __init__(self, state: _State) -> None:
        self.state = state
        self.targets = ["example.com"]

    def root_domain_of(self, d: str) -> str | None:
        return "example.com"


def _profile(*, waf: str = "", headers=None, html: str = "") -> WebProfile:
    return WebProfile(origin=ORIGIN, waf=waf,
                      headers=dict(headers or {}), html=html)


def _findings(recorder: list) -> object:
    """记录 ``emit_finding(kind, detail, *, target=...)``。

    ⚠️ 两个模块的**第一个位置参数含义不同**：``url_verify`` 传的是
    ``detail``（kind 固定），``js_assets`` 传的是 ``kind``（正文走
    ``detail=`` 关键字）。所以这里把两段都收下，断言时拼起来找厂商名 ——
    否则「finding 里写的是别的厂商」这条永远测不到。
    """
    async def emit_finding(*a, **k):
        parts = [str(x) for x in a]
        parts.append(str(k.get("detail") or ""))
        recorder.append((" ".join(parts), k.get("target")))
    return emit_finding


def _build_uv(web: WebProfile | None, entries, findings: list):
    m = url_verify.__new__(url_verify)
    m.name = "url_verify"
    # ``scanner`` 是只读属性，测试夹具必须设底层 ``_engine``
    m._engine = _Engine(_State(web))
    m.waf_entries = list(entries)
    m.waf_min_confidence = "medium"
    m.stats = {"waf_skipped": 0}
    m.log = type("L", (), {"info": lambda *a, **k: None})()
    m.emit_finding = _findings(findings)
    return m


def _build_js(web: WebProfile | None, entries, findings: list):
    m = js_assets.__new__(js_assets)
    m.name = "js_assets"
    m._engine = _Engine(_State(web))
    m.waf_entries = list(entries)
    m.waf_min_confidence = "medium"
    m.stats = {"waf_skipped": 0, "paths_raw": 12}
    m.log = type("L", (), {"info": lambda *a, **k: None})()
    m.emit_finding = _findings(findings)
    return m


def _event() -> Event:
    return Event(type=EventType.URL, data=f"{ORIGIN}/a/b", module="t")


# ------------------------------------------------------------------ 用例

class TestSharedWafConclusionIsReadFirst(unittest.IsolatedAsyncioTestCase):
    """``web.waf`` 已有结论时直接用，不重判。"""

    async def test_existing_conclusion_blocks_even_when_nothing_matches(
        self,
    ) -> None:
        """关键差异：响应里**一条规则都不匹配**，模块仍然收手。

        老写法（每次都自己判）在这里会返回 True —— 于是"前面明明已经有
        WAF 结论"这件事被无视，请求照发。整个「宁滥勿打」的口径在这一步
        就漏了，而且不报错。
        """
        web = _profile(waf="FortiWeb", headers={"server": "nginx"},
                       html="<html>ok</html>")
        f: list = []
        m = _build_uv(web, CF_ENTRIES, f)

        self.assertFalse(await m._waf_ok(ORIGIN, _event()),
                         "已有 WAF 结论却放行了验证请求")
        self.assertEqual(m.stats["waf_skipped"], 1)
        self.assertIn("FortiWeb", f[0][0],
                      "finding 写的是别的厂商 → 同一个站在两个模块里"
                      "显示成两个名字")

    async def test_a_second_module_reuses_the_first_ones_conclusion(
        self,
    ) -> None:
        """``url_verify`` 认出来 → ``js_assets`` 直接吃，不重判。

        ⚠️ 关键是第二家拿到的规则库**故意不匹配**这个响应
        （``CF_ENTRIES`` 认的是 ``cf-ray``，这里给的是 nginx）。
        于是「重判」与「读共享结论」必然给出不同答案：重判会放行，
        读结论会收手。规则库一样的写法分不出这两条路。

        顺带钉住一条边界：``waf_entries`` 为空 = 本模块的闸门关着
        （``abort_on_waf=False`` 或规则库没读进来），那就连共享结论
        也不看 —— 与 ``dir_brute`` 的语义一致，不给全局开暗门。
        """
        web = _profile(headers={"cf-ray": "abc"}, html="<html>x</html>")
        f: list = []
        uv = _build_uv(web, CF_ENTRIES, f)
        self.assertFalse(await uv._waf_ok(ORIGIN, _event()))
        self.assertEqual(web.waf, "Cloudflare",
                         "认出来了却没写回共享画像 → 后两家永远各判各的")

        f2: list = []
        # 换成**认不出**的规则库：这台机器的响应没有 cf-ray 了
        other = [_entry("FortiWeb", "high", [_rule("body", "attack.id")])]
        js = _build_js(web, other, f2)
        self.assertFalse(await js._waf_ok(ORIGIN, "https://x/a.js", _event()),
                         "前一家认出来了，后一家却重判成放行")
        self.assertIn("Cloudflare", f2[0][0],
                      "后一家报的厂商与共享结论对不上")

        # 闸门关着 = 连共享结论也不看
        f3: list = []
        off = _build_js(web, [], f3)
        self.assertTrue(await off._waf_ok(ORIGIN, "https://x/a.js", _event()))
        self.assertEqual(f3, [])

    async def test_low_confidence_signal_still_blocks(self) -> None:
        """宁缺勿滥（写结论）≠ 宁滥勿打（挡住发包）。

        ``name`` 要够置信度才写进结论，``suspected`` 是「有任何迹象」——
        决定**要不要继续发包**的是后者。只看 ``name`` 的话，一大批低置信度
        站点会被当成"没 WAF"继续打过去。
        """
        entries = [_entry("Vague", "low", [_rule("server", "weird-proxy")])]
        web = _profile(headers={"server": "weird-proxy"}, html="x")
        for build, args in ((_build_uv, (ORIGIN, _event())),
                            (_build_js, (ORIGIN, "https://x/a.js", _event()))):
            with self.subTest(module=build.__name__):
                f: list = []
                m = build(web, entries, f)
                self.assertFalse(await m._waf_ok(*args))
                # 写回的是厂商名（宁滥勿打那一档），不是空串
                self.assertEqual(web.waf, "Vague")
                web.waf = ""


class TestWafConclusionIsWrittenNotBlanked(unittest.IsolatedAsyncioTestCase):
    """写回规则：只在认出来时写。"""

    async def test_recognition_writes_the_name_back(self) -> None:
        web = _profile(headers={"cf-ray": "abc"}, html="x")
        f: list = []
        m = _build_js(web, CF_ENTRIES, f)
        self.assertFalse(await m._waf_ok(ORIGIN, "https://x/a.js", _event()))
        self.assertEqual(web.waf, "Cloudflare")

    async def test_no_signal_leaves_the_field_alone(self) -> None:
        """没认出来**不许写任何东西** —— 尤其不许把已有的抹成空串。"""
        web = _profile(headers={"server": "nginx"}, html="x")
        f: list = []
        m = _build_uv(web, CF_ENTRIES, f)
        self.assertTrue(await m._waf_ok(ORIGIN, _event()),
                        "没有 WAF 却收手了")
        self.assertEqual(web.waf, "", "没认出来却写了东西")
        self.assertEqual(f, [], "没认出来却报了 finding")

    async def test_unconditional_write_would_have_blanked_it(self) -> None:
        """把「无条件覆盖」这个写法钉成一条会失败的对照。

        真实踩过的形状是 ``web.waf = name or suspected``：识别不出时
        ``name`` 和 ``suspected`` 都是空串，于是已有的结论被抹掉。
        这里的夹具就是那个场景的前半段 —— 已有结论、这一轮没信号。
        """
        web = _profile(waf="FortiWeb", headers={"server": "nginx"}, html="x")
        f: list = []
        m = _build_uv(web, CF_ENTRIES, f)
        await m._waf_ok(ORIGIN, _event())
        self.assertEqual(
            web.waf, "FortiWeb",
            "已有结论被这一轮的「没认出来」抹掉了 —— "
            "「宁滥勿打」静默失效，没有任何报错",
        )


class TestTheseTwoModulesNeverSendPayloads(unittest.IsolatedAsyncioTestCase):
    """零流量。``attack_only`` 规则认不出来，正是「没发载荷」的证据。"""

    async def _both(self, web, entries):
        f1: list = []
        f2: list = []
        uv = _build_uv(web, entries, f1)
        js = _build_js(web, entries, f2)
        return (await uv._waf_ok(ORIGIN, _event()),
                await js._waf_ok(ORIGIN, "https://x/a.js", _event()),
                f1, f2)

    async def test_attack_only_rule_does_not_fire_without_probing(self) -> None:
        """FortiWeb 的规则是 ``attack_only``：只有发了攻击请求才会匹配。

        这里响应正文里就带着拦截页内容。如果两个模块偷发了一条载荷，
        这条规则会命中、收手 —— 于是**「它们没发载荷」这件事本身就是
        可观测的**，不用去数包。
        """
        web = _profile(headers={"server": "FortiWeb"},
                       html='{"attack.id": "12345"}')
        ok_uv, ok_js, f1, f2 = await self._both(web, FORTI_ENTRIES)
        self.assertTrue(ok_uv,
                        "url_verify 发攻击载荷了 —— 它承诺只做零流量判定")
        self.assertTrue(ok_js, "js_assets 发攻击载荷了")
        self.assertEqual((f1, f2), ([], []))

    async def test_static_rule_still_fires_in_both_modules(self) -> None:
        """对照组：静态可认的该认还是要认，否则上一条就成 trivially 通过。"""
        web = _profile(headers={"cf-ray": "abc"}, html="x")
        ok_uv, ok_js, f1, f2 = await self._both(web, CF_ENTRIES)
        self.assertFalse(ok_uv)
        self.assertFalse(ok_js)
        self.assertEqual(len(f1), 1)
        self.assertEqual(len(f2), 1)


if __name__ == "__main__":
    unittest.main()
