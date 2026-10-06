"""前五环审计修复的回归测试。

每个用例对应一个**实跑复现过**的 bug，判据来自真实行为而非源码文本。
"""
from __future__ import annotations

import unittest
from unittest import mock

from core.util.coerce import as_bool, as_list
from core.util.net import parse_networks, scan_allowed


class TestConfigListCoercion(unittest.TestCase):
    """``as_list`` —— 列表型配置到模块手里可能是**逗号串**。"""

    def test_comma_string_is_split(self) -> None:
        self.assertEqual(as_list("A,AAAA"), ["A", "AAAA"])

    def test_space_is_also_a_separator(self) -> None:
        self.assertEqual(as_list("a, b c"), ["a", "b", "c"])

    def test_list_passes_through(self) -> None:
        self.assertEqual(as_list(["a", "b"]), ["a", "b"])

    def test_none_is_empty(self) -> None:
        self.assertEqual(as_list(None), [])

    def test_empty_string_is_empty(self) -> None:
        self.assertEqual(as_list(""), [])

    def test_nested_comma_string_in_list(self) -> None:
        """Web 可能传 ``["a,b"]`` —— 元素本身又是逗号串。"""
        self.assertEqual(as_list(["a,b", "c"]), ["a", "b", "c"])


class TestBlockedNetsNotCharSplit(unittest.TestCase):
    """``blocked_nets`` 传字符串时被 ``tuple()`` 拆成字符 -> 黑名单失效。

    这是审计里唯一的 **critical**：用户明确拉黑的网段一条都没生效，
    端口扫描照常发包（可能扫出授权范围），且全程零日志。
    """

    NET = "10.0.0.0/8"

    def test_scalar_string_is_parsed(self) -> None:
        self.assertEqual(len(parse_networks(self.NET)), 1)
        self.assertEqual(str(parse_networks(self.NET)[0]), self.NET)

    def test_comma_string_is_parsed(self) -> None:
        nets = parse_networks("10.0.0.0/8, 192.168.0.0/16")
        self.assertEqual(len(nets), 2)

    def test_list_is_parsed(self) -> None:
        self.assertEqual(len(parse_networks(["172.16.0.0/12"])), 1)

    def test_blacklist_actually_blocks(self) -> None:
        """决定性判据：同一条黑名单，字符串与正确元组**行为一致**。"""
        ip = "10.5.5.5"
        as_str = scan_allowed(ip, blocked_nets=self.NET)
        as_tuple = scan_allowed(ip, blocked_nets=(self.NET,))
        self.assertFalse(as_str[0], f"字符串写法没挡住：{as_str}")
        self.assertEqual(as_str[0], as_tuple[0])

    def test_blacklist_beats_allow_private(self) -> None:
        """显式放行内网时，用户自己拉黑的网段**仍然要拒**。"""
        ip = "10.5.5.5"
        for spec in (self.NET, (self.NET,)):
            allowed, reason = scan_allowed(
                ip, allow_private=True, blocked_nets=spec
            )
            self.assertFalse(allowed, f"blocked_nets={spec!r} 被 allow_private 盖过了")

    def test_illegal_entry_is_logged_not_silent(self) -> None:
        """非法网段要留 warning —— 静默丢弃与"没配"不可区分。"""
        with self.assertLogs("recon.net", level="WARNING"):
            parse_networks("这不是网段")
        # 混一个合法的，非法那个被丢掉但合法那个还在
        with self.assertLogs("recon.net", level="WARNING"):
            nets = parse_networks("10.0.0.0/8, 垃圾")
        self.assertEqual(len(nets), 1)


class TestAsBoolOnStringConfig(unittest.TestCase):
    def test_false_string_is_false(self) -> None:
        self.assertFalse(as_bool("false"))
        self.assertFalse(as_bool("0"))
        self.assertFalse(as_bool("off"))

    def test_true_string_is_true(self) -> None:
        self.assertTrue(as_bool("true"))
        self.assertTrue(as_bool("1"))


class TestSafetyGateUnchanged(unittest.TestCase):
    """安全闸门不许因为这轮改动而变松（它是这次修的东西的邻居）。"""

    def test_permanent_blocks_ignore_allow_private(self) -> None:
        for ip in ("127.0.0.1", "169.254.169.254", "::1", "fe80::1"):
            with self.subTest(ip=ip):
                allowed, _ = scan_allowed(ip, allow_private=True)
                self.assertFalse(allowed, f"{ip} 被放行了")

    def test_private_needs_explicit_opt_in(self) -> None:
        self.assertFalse(scan_allowed("10.0.0.1")[0])
        self.assertTrue(scan_allowed("10.0.0.1", allow_private=True)[0])

    def test_public_allowed(self) -> None:
        self.assertTrue(scan_allowed("1.1.1.1")[0])


class TestRecordTypesNotCharSplit(unittest.TestCase):
    """``record_types=A,AAAA`` 传进来时不能被拆成字符。

    拆了之后里面没有 ``"AAAA"``，于是**用户明确要的 IPv6 一条都没查**，
    而且全程零报错 —— 最难发现的那类。
    """

    def _module(self, cfg_value):
        """构造一个 ``dns_resolve`` 实例并跑完 ``setup()``（它是协程）。

        只关心 ``record_types`` 这一行的解析结果，不发任何 DNS 查询。
        """
        import asyncio

        from core.domains.resolve.dns_resolve import dns_resolve as m

        scanner = mock.MagicMock()
        scanner.log = mock.MagicMock()
        scanner.settings = {}
        mod = m(scanner, {})
        mod.log = mock.MagicMock()
        mod.cfg = lambda key, default=None: (
            cfg_value if key == "record_types" else default
        )
        asyncio.run(mod.setup())
        return mod

    def test_comma_string_yields_both_types(self) -> None:
        mod = self._module("A,AAAA")
        self.assertIn("AAAA", mod.record_types,
                      "AAAA 没了 —— IPv6 会被静默跳过")
        self.assertIn("A", mod.record_types)

    def test_no_garbage_elements(self) -> None:
        mod = self._module("A,AAAA")
        self.assertNotIn(",", mod.record_types)
        self.assertNotIn("A", [e for e in mod.record_types if len(e) > 2 and "," in e])

    def test_list_form_unchanged(self) -> None:
        mod = self._module(["A", "AAAA"])
        self.assertEqual(sorted(mod.record_types), ["A", "AAAA"])


class TestBodyTruncatedFlag(unittest.TestCase):
    """``body_truncated`` 必须为真 —— 否则半截正文被当成完整结论。

    ``result.text`` 在 ``HTTPClient.fetch()`` 里**已经被截到 <= max_bytes**，
    而 ``body_max`` 默认就等于 ``max_bytes``，所以只看
    ``len(result.text) > body_max`` 恒为 False。

    这里**跑真实的 ``http_probe._emit``**（不抄它的表达式）—— 抄一份的话
    变异验证会全绿：被测的是我复制的那行，不是产品代码。
    """

    def _run_emit(self, result) -> dict:
        from core.domains.web_hunter.http_probe import http_probe
        from core.engine.event import Event

        mod = http_probe.__new__(http_probe)
        mod.log = mock.MagicMock()
        mod.body_max = 65536
        mod.snippet_len = 65536
        mod.max_bytes = 65536
        mod._tech_rules = []
        mod.stats = {"probed": 0, "emitted": 0, "upstream_rejected": 0}

        captured: dict = {}

        async def grab(*args, **kwargs):
            captured.update(kwargs.get("tags") or {})

        mod.emit_event = grab
        mod._record_profile = lambda *a, **k: None
        mod._favicon_hash = lambda base: _async_none()

        event = Event(type=None, data=result.url, module="test")
        import asyncio
        asyncio.get_event_loop_policy().new_event_loop().run_until_complete(
            mod._emit(
                event, "http", "1.2.3.4", 80, "x.com", "x.com", result, ""
            )
        )
        return captured

    def test_truncated_when_fetch_says_so(self) -> None:
        from core.services.http import FetchResult

        # text 恰好 == body_max（fetch 已截过），但 fetch 层知道被截了
        r = FetchResult(url="http://x.com/", status=200,
                        text="X" * 65536, truncated=True)
        tags = self._run_emit(r)
        self.assertTrue(
            tags.get("body_truncated"),
            "正文明明被截了却标成完整 —— 导出/软404/指纹都会当完整内容用",
        )

    def test_not_truncated_when_actually_short(self) -> None:
        from core.services.http import FetchResult

        r = FetchResult(url="http://x.com/", status=200, text="short", truncated=False)
        tags = self._run_emit(r)
        self.assertFalse(tags.get("body_truncated"))


class TestHttpProbeConfigCoercion(unittest.TestCase):
    """``http_probe`` 的两个列表/布尔型配置。

    和 ``record_types`` 同一类病，**后果更大**：

    * ``schemes`` 被拆成 ``['h','t','t','p','s']`` -> ``build_url('h', ...)``
      造出 ``h://host`` -> httpx 抛错 -> **整台主机零产出**，而日志只有一行
      debug，看起来就像"目标不响应"。
    * ``reject_upstream_errors`` 用 ``bool()`` -> ``bool("false")`` 是 True。
      Web 设置的 ``source_options`` 一律存**字符串**，所以界面上关不掉这道
      闸门，而且没有任何提示（``-c`` 路径走 ``_coerce`` 会转成真 bool，
      用命令行测根本测不出来）。

    两处都跑真实的 ``setup()``，不抄表达式。
    """

    def _module(self, **cfg_map):
        import asyncio

        from core.domains.web_hunter.http_probe import http_probe as m

        scanner = mock.MagicMock()
        scanner.log = mock.MagicMock()
        scanner.settings = {}
        mod = m(scanner, {})
        mod.log = mock.MagicMock()
        mod.cfg = lambda key, default=None: cfg_map.get(key, default)
        asyncio.run(mod.setup())
        return mod

    # ------------------------------------------------------------------ schemes
    def test_scalar_scheme_is_not_split_into_chars(self) -> None:
        mod = self._module(schemes="https")
        self.assertEqual(
            mod.schemes, ["https"],
            "标量 schemes 被逐字符拆开了 -> 造出 h://host -> 整台主机零产出",
        )

    def test_comma_schemes_are_split(self) -> None:
        mod = self._module(schemes="https,http")
        self.assertEqual(mod.schemes, ["https", "http"])

    def test_scheme_list_is_lowercased(self) -> None:
        mod = self._module(schemes=["HTTPS", "Http"])
        self.assertEqual(mod.schemes, ["https", "http"])

    def test_default_schemes_when_unset(self) -> None:
        mod = self._module()
        self.assertEqual(mod.schemes, ["https", "http"])

    # ------------------------------------------------------------------ reject_upstream_errors
    def test_string_false_is_false(self) -> None:
        mod = self._module(reject_upstream_errors="false")
        self.assertFalse(
            mod.reject_upstream_errors,
            'bool("false") 是 True -> Web 界面上这道闸门关不掉',
        )

    def test_string_true_is_true(self) -> None:
        mod = self._module(reject_upstream_errors="true")
        self.assertTrue(mod.reject_upstream_errors)

    def test_defaults_to_true(self) -> None:
        mod = self._module()
        self.assertTrue(mod.reject_upstream_errors)


class TestPtrProviderDoesNotSwallowRealDomain(unittest.TestCase):
    """``classify_ptr``：**只有完全没有真域名时**才算纯 provider。

    原来只要 ``provider`` 非空就返回 ``provider``，于是
    ``PTR = ["ns1.customer.com", "ec2-...amazonaws.com"]`` 这种
    "一个真域名 + 一个云默认名"的情况，会把 ``ns1.customer.com`` **直接丢掉**
    —— 它永远不会被产出成 DNS_NAME，也就永远不会被解析/探测/爆破。
    而 finding 里还写着"这是共享主机"，**主动误导**操作的人。

    ``classify_ptr`` 是纯函数，所以直接测它，不需要 mock 解析器。
    """

    def _f(self):
        from core.domains.resolve.ip_ptr import classify_ptr
        return classify_ptr

    def test_real_domain_survives_alongside_provider_name(self) -> None:
        candidate, kind, _ = self._f()(
            ["ns1.customer.com", "ec2-1-2-3-4.compute-1.amazonaws.com"]
        )
        self.assertEqual(
            candidate, "ns1.customer.com",
            "真域名被云厂商默认名吞掉了 —— 这个资产永远不会被探测",
        )
        self.assertEqual(kind, "candidate")

    def test_provider_only_is_still_provider(self) -> None:
        candidate, kind, _ = self._f()(["ec2-1-2-3-4.compute-1.amazonaws.com"])
        self.assertIsNone(candidate)
        self.assertEqual(kind, "provider")

    def test_gcp_internal_is_provider_not_candidate(self) -> None:
        """``.gcp.`` 是个**永远不可能命中**的后缀（归一化后不以点结尾）。"""
        candidate, kind, _ = self._f()(["host.c.my-project.gcp.internal"])
        self.assertIsNone(candidate)
        self.assertEqual(kind, "provider", "GCP 内部名没被认成共享主机")

    def test_invalid_names_do_not_hide_a_real_one(self) -> None:
        candidate, kind, _ = self._f()(["localhost.", "mail.example.com"])
        self.assertEqual(candidate, "mail.example.com")
        self.assertEqual(kind, "candidate")

    def test_empty(self) -> None:
        candidate, kind, _ = self._f()([])
        self.assertIsNone(candidate)
        self.assertEqual(kind, "empty")


async def _async_none():
    return ""


if __name__ == "__main__":
    unittest.main(verbosity=2)
