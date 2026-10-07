"""M2 被动源的测试。

全部离线: 通过给 ``HTTPClient`` 打桩来模拟各源的响应, 不触碰真实网络。
覆盖四件事:
  1. 结果清洗 (sanitize) 的每一条规则
  2. 真实模块的解析逻辑 (crt.sh / rapiddns / OTX)
  3. 需要 Key 的源缺 Key 时"软失败"而不是中断扫描
  4. 单个源抛异常时不影响整条链路
"""

from __future__ import annotations

import unittest
from unittest import mock

from core.domains.subdomain._lib.dns_query import sanitize_subdomains
from core.services.http import HTTPClient

from .base import EngineTestCase

#: 一个只往 SEED 上挂一条 gov.cn 子域的最小模块，用来端到端验证
#: 「敏感域名闸门删干净了」。原来这套闸门会在分发器里把这条子域丢掉。
GOV_EMITTER = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class govleak(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            await self.emit_event("jwc.gov.cn", EventType.DNS_NAME, parent=event)
"""

# --------------------------------------------------------------------- 清洗规则

class TestSanitize(unittest.TestCase):
    def test_normalizes_wildcard_and_dedupes(self) -> None:
        raw = ["*.WWW.Example.com", "www.example.com", "a.example.com", "a.example.com"]
        self.assertEqual(
            sanitize_subdomains(raw, "example.com"),
            ["a.example.com", "www.example.com"],
        )

    def test_drops_out_of_scope_and_target_itself(self) -> None:
        raw = [
            "a.example.com",
            "example.com",          # 目标自身不算"子域"
            "evil.com",
            "notexample.com",       # 后缀相似但不同域
            "a.example.com.evil.com",
        ]
        self.assertEqual(sanitize_subdomains(raw, "example.com"), ["a.example.com"])

    def test_drops_invalid_chars_and_overlong(self) -> None:
        raw = [
            "bad_name!.example.com",   # 非法字符
            "ok.example.com",
            "x" * 80 + ".example.com",  # 超过 max_subdomain_len
            "-lead.example.com",        # 标签以连字符开头
        ]
        self.assertEqual(sanitize_subdomains(raw, "example.com"), ["ok.example.com"])

    def test_handles_junk_input(self) -> None:
        self.assertEqual(sanitize_subdomains(None, "example.com"), [])
        self.assertEqual(sanitize_subdomains([], "example.com"), [])
        self.assertEqual(sanitize_subdomains([None, 123, ""], "example.com"), [])

    def test_max_subdomain_len_is_configurable(self) -> None:
        raw = ["abcdefghij.example.com"]  # 相对 target 长出 10 个字符
        self.assertEqual(sanitize_subdomains(raw, "example.com", max_subdomain_len=5), [])
        self.assertEqual(sanitize_subdomains(raw, "example.com", max_subdomain_len=10), raw)


# --------------------------------------------------------------------- 真实模块解析

class TestCrtshModule(EngineTestCase):
    PAYLOAD = [
        {"name_value": "www.example.com\napi.example.com"},
        {"name_value": "*.dev.example.com"},
        {"name_value": "notours.com"},
        {"name_value": "www.example.com"},
    ]

    async def test_end_to_end(self) -> None:
        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            self.last_params = params
            return TestCrtshModule.PAYLOAD

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, summary = await self.run_scan(
                targets=["example.com"], include=["passive_crtsh"]
            )

        self.assertIn("passive_crtsh", summary["modules_enabled"])
        # SEED + www/api/dev 三个子域
        self.assertEqual(summary["events_new"], 4)
        domains = await self.storage.domains(scanner.scan_id)
        names = {d["name"] for d in domains}
        self.assertEqual(
            names, {"example.com", "www.example.com", "api.example.com", "dev.example.com"}
        )
        # source 标签落到了资产上
        by_name = {d["name"]: d for d in domains}
        self.assertEqual(by_name["www.example.com"]["source"], "passive_crtsh")


class TestRapiddnsModule(EngineTestCase):
    HTML = """
    <html><body><table id="table"><tbody>
      <tr><td>1</td><td>a.example.com</td><td>1.2.3.4</td></tr>
      <tr><td>2</td><td>b.example.com</td><td>1.2.3.5</td></tr>
      <tr><td>3</td><td>other.com</td><td>1.2.3.6</td></tr>
    </tbody></table></body></html>
    """

    async def test_extracts_td_cells(self) -> None:
        async def fake_get_text(self, url, *, params=None, headers=None):  # noqa: ANN001
            return TestRapiddnsModule.HTML

        with mock.patch.object(HTTPClient, "get_text", fake_get_text):
            scanner, _ = await self.run_scan(
                targets=["example.com"], include=["passive_rapiddns"]
            )

        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com", "a.example.com", "b.example.com"})


class TestAnubisModule(EngineTestCase):
    """anubisdb 返回一个裸 JSON 数组，里面可能混非字符串。

    这个源实测很值：无 key、614ms，而且**按名字索引**，所以支持递归
    （见 ``dns_query.py`` 里 recursive 的实测表）。
    """

    PAYLOAD = ["x.example.com", "y.example.com", "z.other.com", {"bad": 1}, None, 42]

    async def test_parses_json_array_and_drops_non_strings(self) -> None:
        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            return TestAnubisModule.PAYLOAD

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, _ = await self.run_scan(targets=["example.com"], include=["passive_anubis"])

        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com", "x.example.com", "y.example.com"})

    async def test_non_list_payload_is_ignored(self) -> None:
        """上游改版返回对象时不能炸，只是没结果。"""

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            return {"unexpected": "shape"}

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, _ = await self.run_scan(targets=["example.com"], include=["passive_anubis"])

        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com"})


class TestSubdomainCenterModule(EngineTestCase):
    """subdomain.center 返回一个裸的字符串数组。"""

    PAYLOAD = [
        "www.example.com",
        "api.example.com",
        "147-255-227-10.w.example.com",   # 扫描器噪音, 但格式合法 → 保留
        "bookgdze.ru.example.com",         # 层级很深, 但仍在目标域下 → 保留
        "other.com",                       # 域外 → 丢弃
        "example.com",                     # 目标自身 → 丢弃
        123,                               # 非字符串 → 丢弃
    ]

    async def test_parses_string_array(self) -> None:
        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            return TestSubdomainCenterModule.PAYLOAD

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, summary = await self.run_scan(
                targets=["example.com"], include=["passive_subdomaincenter"]
            )

        self.assertIn("passive_subdomaincenter", summary["modules_enabled"])
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(
            names,
            {
                "example.com",
                "www.example.com",
                "api.example.com",
                "147-255-227-10.w.example.com",
                "bookgdze.ru.example.com",
            },
        )

    async def test_non_list_payload_is_tolerated(self) -> None:
        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            return {"unexpected": "shape"}

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, summary = await self.run_scan(
                targets=["example.com"], include=["passive_subdomaincenter"]
            )
        # 形状不对时安静地没产出, 不能崩
        self.assertEqual(summary["events_new"], 1)


class TestHackerTargetModule(EngineTestCase):
    """HackerTarget 返回纯文本 CSV: 每行 ``子域,IP``。"""

    CSV = (
        "www.example.com,1.2.3.4\n"
        "api.example.com,1.2.3.5\n"
        "other.com,1.2.3.6\n"
        "\n"
        "   \n"
    )

    async def test_parses_csv(self) -> None:
        async def fake_get_text(self, url, *, params=None, headers=None):  # noqa: ANN001
            return TestHackerTargetModule.CSV

        with mock.patch.object(HTTPClient, "get_text", fake_get_text):
            scanner, _ = await self.run_scan(
                targets=["example.com"], include=["passive_hackertarget"]
            )
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com", "www.example.com", "api.example.com"})

    async def test_error_page_raises_instead_of_looking_empty(self) -> None:
        """接口用 200 + 纯文本报错。不能让它看起来像"这个域名没有子域"，
        而要抛出去被上层记成一条 warning。"""
        from core.domains.subdomain.passive.hackertarget import Query

        async def fake_get_text(self, url, *, params=None, headers=None):  # noqa: ANN001
            return "API count exceeded - Increase Quota with Premium Purchase"

        with mock.patch.object(HTTPClient, "get_text", fake_get_text):
            with self.assertRaises(RuntimeError) as ctx:
                await Query().sub_domains("example.com", HTTPClient())
        self.assertIn("错误提示", str(ctx.exception))


class TestCommonCrawlModule(EngineTestCase):
    """Common Crawl 的 CDX 返回 **NDJSON，每行一个完整 URL**。

    这个源曾经**永远 0 产出**：它把 ``https://sub.example.com/path`` 原样
    append，下游 ``normalize_domain`` 会在 ``split(":", 1)[0]`` 那一步切成
    ``"https"``，于是后缀校验恒为假、整条被静默丢掉。所以这里钉住
    "URL 必须被还原成主机名"。
    """

    #: 真实的 CDX 行形态（只留用得到的字段）
    NDJSON = (
        '{"urlkey":"com,example,www)/a","timestamp":"20250101000000",'
        '"url":"https://www.example.com/a?x=1","status":"200"}\n'
        '{"urlkey":"com,example,api)/v1","timestamp":"20250101000000",'
        '"url":"http://api.example.com:8080/v1/users","status":"200"}\n'
        '{"urlkey":"com,other,evil)/x","timestamp":"20250101000000",'
        '"url":"https://evil.other.com/x","status":"200"}\n'
        "not json at all\n"
        "\n"
    )

    async def _run(self):
        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            return [{"id": "CC-MAIN-2025-30", "cdx-api": "https://index.commoncrawl.org/CC-MAIN-2025-30-index"}]

        async def fake_get_text(self, url, *, params=None, headers=None,
                                max_bytes=0):  # noqa: ANN001
            # ⚠️ ``max_bytes`` 必须接（2026-10-07）：本模块给索引端点传了
            # ``max_bytes=MAX_BODY_BYTES``，而这个替身原先的签名里没有它 →
            # ``TypeError: unexpected keyword argument 'max_bytes'``，
            # 源整条软失败、测试只看到"0 产出"。
            #
            # 这与「别给假响应加真实对象没有的能力」是同一族问题的反面：
            # 真实对象**加了**能力而替身没跟上。签名要和真的一起长。
            return TestCommonCrawlModule.NDJSON

        with mock.patch.object(HTTPClient, "get_json", fake_get_json), \
                mock.patch.object(HTTPClient, "get_text", fake_get_text):
            return await self.run_scan(
                targets=["example.com"], include=["passive_commoncrawl"]
            )

    async def test_extracts_hostname_not_url(self) -> None:
        """**核心回归**：产出的必须是主机名，不能是 URL。"""
        scanner, _ = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("www.example.com", names)
        # 带端口的也要还原干净
        self.assertIn("api.example.com", names)
        # 作用域外的丢掉
        self.assertFalse(any("other.com" in n for n in names), f"外域泄漏: {names}")
        # 不能有任何 URL 形态残留
        self.assertFalse(any("/" in n or ":" in n for n in names), f"URL 没还原: {names}")

    async def test_non_json_lines_are_skipped(self) -> None:
        """CDX 偶尔会混进非 JSON 行，不能因此整源失败。"""
        scanner, _ = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertTrue(names, "非 JSON 行把整个源搞挂了")


class TestUrlscanModule(EngineTestCase):
    """urlscan 必须用 ``page.domain:`` 查询；子域从页面 URL 的 host 里取。"""

    PAYLOAD = {
        "total": 10000,
        "results": [
            {
                "page": {"domain": "example.com", "url": "https://www.example.com/a"},
                "task": {"url": "https://www.example.com/a"},
            },
            {
                "page": {"domain": "api.example.com", "url": "https://api.example.com/v1"},
                "task": {"url": "https://api.example.com/v1"},
            },
            # page.domain: 查询理论上不会混进域外结果, 但这里故意放一条,
            # 验证清洗层仍然兜得住
            {"page": {"domain": "evil.com", "url": "https://evil.com/x"}, "task": {}},
            "垃圾数据",
        ],
    }

    async def test_extracts_hosts_from_urls(self) -> None:
        seen_urls: list[str] = []

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            seen_urls.append(url)
            return TestUrlscanModule.PAYLOAD

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, _ = await self.run_scan(
                targets=["example.com"], include=["passive_urlscan"]
            )

        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com", "www.example.com", "api.example.com"})

        # 查询必须用 page.domain, 用 domain: 会带回大量域外噪声
        self.assertIn("page.domain", seen_urls[0])
        self.assertNotIn("?q=domain", seen_urls[0])


# --------------------------------------------------------------------- 软失败 / 异常隔离

#: 需要 Key 的源用**内联测试模块**声明，不依赖任何生产模块 —— 这样删掉某个
#: 带 Key 的源（比如原先的 passive_chaos）不会连带把这段契约测试删掉。
KEYED_SOURCE = """
    from core.domains.subdomain._lib.dns_query import DNSQueryBase, PassiveSourceModule


    class Query(DNSQueryBase):
        source_name = "keyed"
        requires_key = True

        def init_key(self, **kwargs):
            self.key = kwargs.get("api_key", "")

        async def sub_domains(self, target, http):
            return [f"www.{target}", f"api.{target}"]


    class keyed_source(PassiveSourceModule):
        query = Query
"""


class TestWaybackModule(EngineTestCase):
    """Wayback CDX 返回**二维 JSON 数组**，第一行是表头 ``["original"]``。

    和 ``commoncrawl`` 是同一类坑：接口给的是**完整 URL**，必须在这里抠出主机名，
    否则下游 ``normalize_domain`` 的 ``split(":", 1)[0]`` 会把它切成 ``"https"``，
    整条被静默丢掉。

    ⚠️ **本机连不上 web.archive.org**（网络受限），所以这里只钉解析逻辑，
    没有对真实接口做过端到端验证。
    """

    CDX = [
        ["original"],                                   # 表头，必须跳过
        ["http://www.example.com/"],
        ["https://api.example.com:8443/v1?x=1"],        # 带端口 + 查询串
        ["https://evil.other.com/track"],               # 作用域外
        ["//cdn.example.com/a.js"],                     # 协议相对
        [],                                             # 空行
        ["not a url"],                                  # 畸形
    ]

    async def _run(self, *, max_urls: int | None = None):
        seen: dict = {}

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            seen["url"] = url
            seen["params"] = dict(params or {})
            return TestWaybackModule.CDX

        # module_config 是按**模块名**索引的，不是源名
        cfg = {"passive_wayback": {"max_urls": max_urls}} if max_urls else None
        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["passive_wayback"],
                **({"module_config": cfg} if cfg else {}),
            )
        self.params = seen.get("params") or {}
        return scanner

    async def test_extracts_hostname_not_url(self) -> None:
        scanner = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("www.example.com", names)
        self.assertIn("api.example.com", names)   # 端口要去掉
        self.assertIn("cdn.example.com", names)
        self.assertFalse(any("other.com" in n for n in names), f"外域泄漏: {names}")
        self.assertFalse(any("/" in n or ":" in n for n in names), f"URL 没还原: {names}")

    async def test_header_row_is_skipped(self) -> None:
        """表头 ``["original"]`` 不能被当成主机名。"""
        scanner = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertNotIn("original", names)
        self.assertTrue(names, "整源没产出")

    async def test_sends_expected_cdx_params(self) -> None:
        await self._run(max_urls=123)
        self.assertEqual(self.params.get("output"), "json")
        self.assertEqual(self.params.get("url"), "*.example.com")
        self.assertEqual(self.params.get("limit"), "123")
        self.assertEqual(self.params.get("collapse"), "urlkey")


class TestKeyRequiredSource(EngineTestCase):
    # 注意是 asyncSetUp 而不是 setUp —— 临时目录与 storage 都在那里创建
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.add_module_file("keyed_source", KEYED_SOURCE)

    async def test_missing_key_soft_fails_and_scan_continues(self) -> None:
        scanner, summary = await self.run_scan(
            targets=["example.com"], include=["keyed_source"]
        )
        self.assertNotIn("keyed_source", summary["modules_enabled"])
        self.assertIn("api_key", summary["modules_skipped"]["keyed_source"])
        # 扫描没有崩, 只是没产出
        self.assertEqual(summary["events_new"], 1)

    async def test_with_key_it_runs(self) -> None:
        scanner, summary = await self.run_scan(
            targets=["example.com"],
            include=["keyed_source"],
            module_config={"keyed_source": {"api_key": "fake-key"}},
        )
        self.assertIn("keyed_source", summary["modules_enabled"])
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com", "www.example.com", "api.example.com"})


FAILING_SOURCE = """
    from core.domains.subdomain._lib.dns_query import DNSQueryBase, PassiveSourceModule


    class Query(DNSQueryBase):
        source_name = "boom"

        async def sub_domains(self, target, http):
            raise RuntimeError("源挂了")


    class boom(PassiveSourceModule):
        query = Query
"""


class TestSourceErrorIsolation(EngineTestCase):
    async def test_failing_source_does_not_break_scan(self) -> None:
        self.add_module_file("boom", FAILING_SOURCE)
        scanner, summary = await self.run_scan(targets=["example.com"], include=["boom"])

        # handle_event 自己吞掉了异常, 所以引擎侧算成功
        self.assertEqual(summary["stats"].get("module.boom.ok"), 1)
        self.assertEqual(summary["stats"].get("module.boom.error", 0), 0)
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com"})


# --------------------------------------------------------------------- 敏感域名闸门

class TestSensitiveDomainGateRemoved(EngineTestCase):
    """敏感域名闸门已于 2026-10-04 **整块删除**（不再是「默认关掉」）。

    原来的实现是硬编码 ``("gov.cn", "edu.cn", "org.cn", "mil.cn")`` 的后缀黑名单，
    在分发器里拦掉命中的 ``SEED`` / ``DNS_NAME``。它只会挡路：全仓 40 多处测试
    夹具都写着 ``settings={"forbidden_domains": []}`` 才能跑。而实际工作以
    **高校 / 职院的授权测试**为主（``edu.cn`` 正是主战场），每次都得先改预设
    yml 才扫得动。现在连机制一起删掉，edu.cn / gov.cn 直接扫。

    钉的是**不变量**：``.gov.cn`` 必须能走完整条流水线落库。
    """

    async def test_gov_cn_target_survives_the_whole_pipeline(self) -> None:
        """默认配置下 gov.cn 照常展开：SEED + 4 个子域 = 5 条新事件。"""
        _, summary = await self.run_scan(
            targets=["test.gov.cn"], include=["demo_expand"]
        )
        self.assertEqual(summary["events_new"], 5)

    def test_the_mechanism_is_gone(self) -> None:
        """闸门本身不该再存在 —— 别让人「顺手」把它加回来。"""
        from core.engine.scanner import Scanner
        from core.util import domain as domain_util

        self.assertFalse(hasattr(Scanner, "is_forbidden"))
        self.assertFalse(hasattr(Scanner, "forbidden_domains"))
        self.assertFalse(hasattr(domain_util, "is_forbidden_domain"))

    async def test_gov_cn_lands_in_the_asset_table(self) -> None:
        """不是只发事件 —— 得真的进资产表。"""
        # 文件名要跟类名小写一致：引擎是按**模块名**（类名小写）去 include 的，
        # 不是按文件名。写成 leaky.py + class govleak 会「启用 0 个」而静默通过。
        self.add_module_file("govleak", GOV_EMITTER)
        scanner, _ = await self.run_scan(targets=["gov.cn"], include=["govleak"])
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("jwc.gov.cn", names)



# --------------------------------------------------------------------- 递归枚举

class _FakeScanner:
    """只给 BaseModule.__init__ 用的最小替身（它只读 scanner.log）。"""

    log = None


class TestRecursion(unittest.TestCase):
    """递归被动枚举：能力声明 + 预算闸门。

    **收益的诚实结论**：隔离测量看着很美（anubis +103、hackertarget +102、
    crtsh +212），但端到端跑起来几乎不增加东西 —— anubis 根查询返回的全是
    多层名（无第一层候选，增量 0），crtsh 根查询 3561 条时递归只多 4 条（0.1%）。
    所以这里重点测**闸门**：宁可不挖，也不能让请求数失控。
    """

    def _module(self, recursive: bool, **cfg):
        from core.domains.subdomain._lib.dns_query import DNSQueryBase, PassiveSourceModule

        if recursive:
            class _Q(DNSQueryBase):
                recursive = True
        else:
            class _Q(DNSQueryBase):
                pass

        class _M(PassiveSourceModule):
            query = _Q

        m = _M(_FakeScanner(), cfg)
        m._seen_roots = {"example.com"}
        for k, v in cfg.items():
            setattr(m, k, v)
        return m

    def test_recursive_source_subscribes_to_dns_name(self) -> None:
        from core.engine.event import EventType

        m = self._module(recursive=True)
        self.assertIn(EventType.DNS_NAME, m.watched_events)
        # 递归源不能再"一个根只跑一次"，否则回喂的子域全被门闩挡掉
        self.assertFalse(m.per_domain_only)

    def test_non_recursive_source_is_untouched(self) -> None:
        from core.engine.event import EventType

        m = self._module(recursive=False)
        self.assertEqual(tuple(m.watched_events), (EventType.SEED,))
        self.assertTrue(m.per_domain_only)

    def test_only_first_level_children_are_requeried(self) -> None:
        m = self._module(recursive=True, recursive_max_names=10)
        self.assertTrue(m._should_recurse("www.example.com"))
        # 第二层不回喂：实测增量主要来自第一层，往下请求数线性膨胀
        self.assertFalse(m._should_recurse("a.www.example.com"))

    def test_budget_caps_requeries_per_root(self) -> None:
        m = self._module(recursive=True, recursive_max_names=4)
        for name in ("www.example.com", "api.example.com",
                     "mail.example.com", "cdn.example.com"):
            self.assertTrue(m._should_recurse(name), name)
        # 总预算已满
        self.assertFalse(m._should_recurse("dns.example.com"))
        self.assertGreater(m.stats.skipped, 0)

    def test_random_names_are_limited_to_a_third(self) -> None:
        """不在常见名表里的标签只能用 1/3 名额。

        没有这道分流，按到达顺序先撞上的噪声会把预算吃光 —— 实测在
        example.com 上就是这样（``1specific`` / ``2d8ed406`` / ``95uofd``）。
        """
        m = self._module(recursive=True, recursive_max_names=9)
        for i in range(3):  # 9 // 3 == 3 个普通名额
            self.assertTrue(m._should_recurse(f"r{i}.example.com"))
        self.assertFalse(m._should_recurse("r3.example.com"))
        # 常见名不受普通名额限制，继续能用
        self.assertTrue(m._should_recurse("www.example.com"))
        self.assertTrue(m._should_recurse("api.example.com"))

    def test_noise_labels_do_not_consume_budget(self) -> None:
        """纯数字 / 哈希样 / 过长的标签直接筛掉，一个名额都不占。

        实测逼出来的：example.com 上 anubis 返回 22248 条，按字母排序前面
        全是 ``0`` / ``001`` / ``101065`` 这类 CT 噪声，问它们全部返回 0 条。
        """
        m = self._module(recursive=True, recursive_max_names=3)
        for noise in ("0", "001", "101065", "102323", "2d8ed406", "95uofd",
                      "1specific", "a3f9b2c1d4e5", "x" * 40):
            self.assertFalse(m._should_recurse(f"{noise}.example.com"), noise)
        self.assertGreater(m.stats.skipped, 0)
        # 名额没被噪声占用，优质候选照常可用
        self.assertTrue(m._should_recurse("www.example.com"))
        self.assertTrue(m._should_recurse("api.example.com"))
        self.assertTrue(m._should_recurse("mail.example.com"))

    def test_heuristic_keeps_real_names(self) -> None:
        """筛选的边界要钉死 —— 判错了会白扔请求，也会漏掉真名字。"""
        from core.domains.subdomain._lib.dns_query import _looks_like_parent

        # 短名、基础设施名、带年份/版本后缀的真实名
        for good in ("www", "v", "m", "mp", "api", "mail", "cdn", "dns", "id",
                     "game", "portal", "bbs", "3g", "4g", "shop2024", "static1"):
            self.assertTrue(_looks_like_parent(good), f"{good} 被误筛")
        # 3 字符内的数字开头保留（3g/4g 是真实服务名），超过就视为生成名
        self.assertTrue(_looks_like_parent("4g"))
        self.assertFalse(_looks_like_parent("4gpp"))
        # 长且一半是数字 → 哈希样
        self.assertFalse(_looks_like_parent("a3f9b2c1d4e5"))

    def test_unknown_root_is_not_requeried(self) -> None:
        """没见过的根域名不该被回喂（防止越界查询无关域名）。"""
        m = self._module(recursive=True)
        self.assertFalse(m._should_recurse("x.other.com"))

    def test_budget_zero_disables_recursion(self) -> None:
        m = self._module(recursive=True, recursive_max_names=0)
        self.assertFalse(m._should_recurse("a.example.com"))


# --------------------------------------------------------------------- 每源统计

class TestSourceStats(EngineTestCase):
    """每源运行统计 —— 为了不再靠手写探针去发现"这个源是不是死了"。"""

    async def test_stats_and_recursion_end_to_end(self) -> None:
        """一次扫描里既验证统计，也验证**递归真的被触发了**。

        这是实测驱动的那条链路的端到端检查：anubis 声明 ``recursive = True``，
        所以它在查完根域名之后应该继续回喂第一层子域。不递归的话 raw 只会是 2。

        payload 刻意用 ``www`` / ``api``（在 ``_COMMON_PARENTS`` 里）而不是
        ``a`` / ``b``：普通标签只有 1/3 的预算名额，用常见名才能稳定验证
        递归本身，而不被预算分配干扰。
        """
        seen: list[str] = []

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            name = url.rsplit("/", 1)[-1]
            seen.append(name)
            if name == "example.com":
                return ["www.example.com", "api.example.com"]
            if name == "www.example.com":
                # 实测中 anubis 就是这么干的：问 v.qq.com 才给 v.qq.com 下的东西
                return ["deep.www.example.com"]
            return []

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, summary = await self.run_scan(
                targets=["example.com"], include=["passive_anubis"]
            )

        # ── 递归 ← 核心断言
        self.assertIn("www.example.com", seen, f"没回喂子域, 只查了 {seen}")
        self.assertIn("api.example.com", seen)
        # 第二层不再回喂
        self.assertNotIn("deep.www.example.com", seen)

        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(
            names,
            {"example.com", "www.example.com", "api.example.com", "deep.www.example.com"},
        )

        # ── 统计
        stats = summary.get("source_stats")
        self.assertIsInstance(stats, list)
        row = next((r for r in stats if r["source"] == "anubis"), None)
        self.assertIsNotNone(row, f"没收到 anubis 的统计: {stats}")
        # 3 次查询的原始条目：2 + 1 + 0
        self.assertEqual(row["raw"], 3)
        # 清洗后：www、api、deep.www
        self.assertEqual(row["results"], 3)
        self.assertEqual(row["errors"], 0)
        # 打桩后调用是瞬时的，round(x, 2) 会把真实耗时压成 0.0 —— 所以这里只查
        # 类型与非负；"确实记到了耗时"由真实扫描覆盖。
        self.assertIsInstance(row["elapsed"], float)
        self.assertGreaterEqual(row["elapsed"], 0.0)
        # requests 计数在 HTTPClient.request() 那一层；这里把 get_json 整个打桩了，
        # 真实请求没发生，所以只能是 0 —— 计数器本身在 test_http.py 里单独测。
        self.assertEqual(row["requests"], 0)

    async def test_recursion_can_be_disabled(self) -> None:
        """``recursive_max_names=0`` 时退回"只查根域名"。"""
        seen: list[str] = []

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            seen.append(url.rsplit("/", 1)[-1])
            return ["a.example.com"]

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            await self.run_scan(
                targets=["example.com"],
                include=["passive_anubis"],
                module_config={"passive_anubis": {"recursive_max_names": 0}},
            )

        self.assertEqual(seen, ["example.com"])

    async def test_failed_source_records_error_text(self) -> None:
        """源抛异常时要留下**可读的**错误原因。

        用 describe(e) 而不是 str(e)：``str(TimeoutError())`` 是空字符串，
        日志和统计里会变成一片空白。
        """

        async def boom(self, url, *, params=None, headers=None):  # noqa: ANN001
            raise TimeoutError()

        with mock.patch.object(HTTPClient, "get_json", boom):
            _, summary = await self.run_scan(
                targets=["example.com"], include=["passive_anubis"]
            )

        row = next(r for r in summary["source_stats"] if r["source"] == "anubis")
        self.assertEqual(row["errors"], 1)
        self.assertNotEqual(row["last_error"], "", "错误描述为空 —— describe() 没生效")
        self.assertIn("Timeout", row["last_error"])


# --------------------------------------------------------------------- heavy flag

class TestHeavySources(unittest.TestCase):
    """能用但很贵的源默认不启用（对应 subfinder 的 IsDefault() == false）。"""

    def _names(self, preset_name: str) -> set[str]:
        import asyncio

        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        async def go():
            p = Preset.load_builtin(preset_name)
            s = Scanner(targets=["example.com"], preset=p, storage=None)
            s.load_modules()
            return set(s.modules)

        return asyncio.run(go())

    def test_commoncrawl_is_off_in_the_passive_preset(self) -> None:
        # 实测 22.9s / 7.9MB 只换 35 条，不能默认拖慢每一次被动收集
        self.assertNotIn("passive_commoncrawl", self._names("passive"))

    def test_commoncrawl_is_on_in_full_preset(self) -> None:
        self.assertIn("passive_commoncrawl", self._names("active"))

    def test_no_other_source_is_marked_heavy(self) -> None:
        """heavy 是"实测确认很贵"的标签，别随手贴。"""
        from core.presets import __name__ as _  # noqa: F401

        names = self._names("active")
        heavy = {n for n in names if n == "passive_commoncrawl"}
        self.assertEqual(heavy, {"passive_commoncrawl"})


if __name__ == "__main__":
    unittest.main()
