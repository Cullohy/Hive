"""URL 采集域的测试。

两层：
  1. ``_lib/extract.py`` 的纯函数 —— 边界条件一条条钉死，不碰网络也不碰引擎
  2. ``url_extract`` 模块 —— 作用域闸门与预算，走引擎的事件链

全部离线。
"""

from __future__ import annotations

import unittest
from unittest import mock

from core.domains.urls._lib.extract import extract_links, host_of, normalize
from core.util.domain import host_of as util_host_of
from tests.base import EngineTestCase

BASE = "https://www.example.com/portal/index.html"


def urls_of(html: str, base: str = BASE, **kw) -> list[str]:
    return [u for u, _ in extract_links(html, base, **kw)]


class TestExtractLinks(unittest.TestCase):
    """从 HTML 片段里抽 URL。"""

    def test_relative_urls_resolve_against_base(self) -> None:
        got = urls_of('<a href="/about">x</a><a href="detail">y</a>')
        self.assertIn("https://www.example.com/about", got)
        self.assertIn("https://www.example.com/portal/detail", got)

    def test_fragment_is_stripped(self) -> None:
        """fragment 不改变服务端返回的东西，留着只会制造重复事件。"""
        self.assertEqual(
            urls_of('<a href="/docs?x=1#section">x</a>'),
            ["https://www.example.com/docs?x=1"],
        )

    def test_absolute_urls_are_kept(self) -> None:
        got = urls_of('<a href="https://mail.example.com/login">x</a>')
        self.assertEqual(got, ["https://mail.example.com/login"])

    def test_pseudo_schemes_are_skipped(self) -> None:
        html = (
            '<a href="javascript:void(0)">1</a>'
            '<a href="#top">2</a>'
            '<a href="mailto:a@b.com">3</a>'
            '<a href="tel:+1234">4</a>'
            '<img src="data:image/png;base64,AAAA">'
        )
        self.assertEqual(urls_of(html), [])

    def test_static_assets_are_skipped(self) -> None:
        """图片/样式/字体对资产梳理没价值，对截图更是纯浪费。"""
        html = (
            '<img src="/logo.png">'
            '<link rel="stylesheet" href="/app.css">'
            '<img srcset="/a-1x.webp 1x, /a-2x.webp 2x">'
            '<div data-src="/lazy/photo.jpg"></div>'
        )
        self.assertEqual(urls_of(html), [])

    def test_javascript_and_json_are_kept(self) -> None:
        """``.js`` / ``.json`` **不能**当静态资源丢掉。

        它们是后续"从 JS 里挖接口"的输入 —— 那是流水线里 URL/JS 那一步的
        真正价值所在。
        """
        html = '<script src="/static/app.js"></script><a href="/data.json">d</a>'
        got = urls_of(html)
        self.assertIn("https://www.example.com/static/app.js", got)
        self.assertIn("https://www.example.com/data.json", got)

    def test_skip_static_can_be_disabled(self) -> None:
        got = urls_of('<img src="/logo.png">', skip_static=False)
        self.assertEqual(got, ["https://www.example.com/logo.png"])

    def test_extension_like_path_segment_is_not_static(self) -> None:
        """``/v1.2/users`` 的 ``.2`` 不是扩展名，别误杀。"""
        got = urls_of('<a href="/v1.2/users">x</a>')
        self.assertEqual(got, ["https://www.example.com/v1.2/users"])

    def test_srcset_and_meta_refresh(self) -> None:
        html = (
            '<img srcset="/big.jpg 1x, /also.png 2x">'
            '<meta http-equiv="refresh" content="0;url=/landing">'
        )
        got = urls_of(html)
        # srcset 两条都是图片 → 丢掉；只剩 meta-refresh
        self.assertEqual(got, ["https://www.example.com/landing"])

    def test_srcset_without_extension_is_kept(self) -> None:
        """``srcset`` 里没扩展名的那条是保留的 —— 无法判断是图片还是页面。

        宁可多留一条（截图有 ``per_host`` 兜底），也不要靠猜误杀。
        """
        got = urls_of('<img srcset="/big.jpg 1x, /page-thumb 2x">')
        self.assertEqual(got, ["https://www.example.com/page-thumb"])

    def test_absolute_url_in_inline_script(self) -> None:
        html = '<script>var api = "https://api.example.com/v1/users";</script>'
        self.assertEqual(urls_of(html), ["https://api.example.com/v1/users"])

    def test_relative_path_in_inline_script_is_not_taken(self) -> None:
        """内联 JS 里的相对路径误报太多，本步刻意不做。

        ``"/api/v1/x"`` 可能是拼接出来的片段，收进来会灌一堆假 URL。
        这留给后续专门的"JS 接口挖掘"（需要 AST 或更严的上下文）。
        """
        html = '<script>var p = "/api/v1/users";</script>'
        self.assertEqual(urls_of(html), [])

    def test_dedup_keeps_first_kind(self) -> None:
        """同一个 URL 出现多次只留一条，种类按首次出现算。"""
        html = '<a href="/x">a</a><script>var u="https://www.example.com/x";</script>'
        self.assertEqual(extract_links(html, BASE), [("https://www.example.com/x", "link")])

    def test_empty_and_garbage_input(self) -> None:
        self.assertEqual(extract_links("", BASE), [])
        self.assertEqual(extract_links("<html>没有链接</html>", BASE), [])

    def test_base_url_is_respected(self) -> None:
        """基准必须是**跳转之后**的 URL，否则相对链接会解析到错误的主机。"""
        got = urls_of('<a href="/x">a</a>', "https://other.example.com/deep/page")
        self.assertEqual(got, ["https://other.example.com/x"])

    def test_normalize_adds_root_path(self) -> None:
        self.assertEqual(normalize("https://a.com"), "https://a.com/")

    def test_host_of_matches_the_shared_helper(self) -> None:
        """``host_of`` 的真正实现在 util/domain.py —— 引擎也要用同一个。

        两处各写一份必然漂移，所以这里钉住它们是同一个行为。
        """
        for sample in (
            "https://a.b.com:8443/x?y=1#z",
            "http://127.0.0.1:8080/",
            "https://user:pw@host.example.com/p",
            "not a url",
            "",
        ):
            self.assertEqual(host_of(sample), util_host_of(sample), sample)


PAGE = """<html><body>
<a href="/about">关于</a>
<a href="/contact">联系</a>
<a href="https://evil.other.com/track">外链</a>
<img src="/logo.png">
<script src="/app.js"></script>
</body></html>"""

#: 直接发一个公网 IP，避开真实 DNS。链路：
#: emit_ips → IP_ADDRESS → port_scan → OPEN_TCP_PORT → http_probe → HTTP_RESPONSE
#: → url_extract → URL
EMIT_IPS = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_ips(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.IP_ADDRESS,)
    flags = ("active", "safe")

    async def handle_event(self, event):
        await self.emit_event("93.184.216.34", EventType.IP_ADDRESS, parent=event)
"""

REAL_IP = "93.184.216.34"


def make_fake_scan(open_map):
    """替身端口扫描。**必须返回列表而不是 yield** ——
    ``port_scan`` 用的是 ``await scanner.scan(...)``，异步生成器会报
    ``TypeError: object async_generator``。"""

    async def fake_scan(self, host, ports, *, on_open=None):
        found = open_map.get(host, [])
        for port in found:
            if on_open is not None:
                maybe = on_open(port)
                if hasattr(maybe, "__await__"):
                    await maybe
        return found

    return fake_scan


def make_fake_fetch(responder):
    async def fake_fetch(self, url, **kwargs):  # noqa: ANN001
        return responder(url)

    return fake_fetch


class TestUrlExtractModule(EngineTestCase):
    """走引擎：作用域过滤 + 预算。"""

    def _responder(self, url: str):
        from core.services.http import FetchResult

        if url.endswith("/favicon.ico"):
            return FetchResult(url=url, status=200, text="")
        return FetchResult(
            url=url,
            status=200,
            headers={"content-type": "text/html; charset=utf-8"},
            text=PAGE,
            history=[],
            elapsed=0.01,
        )

    async def _scan(self, **cfg):
        from core.domains.port._lib.ports import ConnectScanner
        from core.services.http import HTTPClient

        self.add_module_file("emit_ips", EMIT_IPS)

        async def fake_fetch_bytes(client, url, **kwargs):  # noqa: ANN001
            return None

        with mock.patch.object(ConnectScanner, "scan", make_fake_scan({REAL_IP: [80]})), \
                mock.patch.object(HTTPClient, "fetch", make_fake_fetch(self._responder)), \
                mock.patch.object(HTTPClient, "fetch_bytes", fake_fetch_bytes):
            return await self.run_scan(
                targets=["example.com"],
                include=["emit_ips", "port_scan", "http_probe", "url_extract"],
                module_config={
                    "port_scan": {"ports": "top10"},
                    "http_probe": {"schemes": ["http"], "prefer_https": False},
                    "url_extract": cfg,
                },
            )

    async def _emitted_urls(self, scan_id: int, module: str | None = "url_extract") -> set[str]:
        """取扫描里的 URL 事件。

        **默认只取 ``url_extract`` 发的** —— ``http_probe`` 自己也会为探测到的
        地址发一条 URL，混在一起会让"预算是否生效"这类断言失真。
        """
        events = await self.storage.events(scan_id, limit=500, event_type="URL")
        return {
            e["data"] for e in events if module is None or e["module"] == module
        }

    async def test_extracts_in_scope_urls_only(self) -> None:
        """**外链必须被挡掉。**

        引擎原先拦不住 URL（``in_scope`` 只管 ``DNS_NAME``），所以
        ``https://evil.other.com/track`` 会直接进资产库。
        """
        scanner, _ = await self._scan()
        emitted = await self._emitted_urls(scanner.scan_id)

        self.assertTrue(emitted, "没抽出任何 URL")
        for url in emitted:
            self.assertNotIn("other.com", url, f"外链没被挡住: {url}")
        self.assertTrue(
            any(u.endswith("/about") for u in emitted), f"页内链接丢了: {emitted}"
        )

    async def test_static_assets_are_not_emitted(self) -> None:
        scanner, _ = await self._scan()
        emitted = await self._emitted_urls(scanner.scan_id)
        self.assertFalse(any(u.endswith(".png") for u in emitted), emitted)

    async def test_js_is_kept(self) -> None:
        """``.js`` 是后续"挖接口"的输入，不能当静态资源丢掉。"""
        scanner, _ = await self._scan()
        emitted = await self._emitted_urls(scanner.scan_id)
        self.assertTrue(any(u.endswith("/app.js") for u in emitted), emitted)

    async def test_max_per_page_budget(self) -> None:
        scanner, _ = await self._scan(max_per_page=1)
        emitted = await self._emitted_urls(scanner.scan_id)
        # 页面里有 3 条在范围内的链接，预算 1 → 只发 1 条
        self.assertEqual(len(emitted), 1, emitted)

    async def test_stats_are_reported(self) -> None:
        _, summary = await self._scan()
        row = next(
            (r for r in summary["source_stats"] if r["source"] == "url_extract"), None
        )
        self.assertIsNotNone(row, f"没收到 url_extract 的统计: {summary['source_stats']}")
        self.assertGreater(row["raw"], 0, "抽到的原始链接数应大于 0")
        self.assertEqual(row["requests"], 0, "它不该发任何请求")


class TestEngineScopeGateForUrls(unittest.TestCase):
    """引擎**刻意不**对 URL 做作用域检查 —— 这条边界要钉住。

    试过加进来（按主机名匹配目标域名），结果误杀了合法资产：
    ``http_probe`` 构造 URL 时用 ``host = domain or ip``，没有 domain 的场景
    （例如从裸 IP 起扫）会产出 ``http://1.2.3.4:80/`` —— 那个 IP 确实属于目标，
    只是文本上不匹配目标域名，一刀切会**打断截图链路**。

    所以爬来的链接必须在 ``url_extract`` 里自己过滤（见上面那组测试）。
    """

    def _scanner(self):
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        return Scanner(targets=["example.com"], preset=Preset(name="t"), storage=None)

    def test_dns_name_is_checked(self) -> None:
        from core.engine.event import Event, EventType

        scanner = self._scanner()
        ok = Event(type=EventType.DNS_NAME, data="www.example.com", module="t")
        bad = Event(type=EventType.DNS_NAME, data="www.other.com", module="t")
        self.assertTrue(scanner.in_scope(ok))
        self.assertFalse(scanner.in_scope(bad))

    def test_url_is_deliberately_not_checked(self) -> None:
        """IP 形式的 URL 必须放行，否则截图链路会断。"""
        from core.engine.event import Event, EventType

        scanner = self._scanner()
        for url in (
            "https://www.example.com/a",
            "http://93.184.216.34:80/",          # host = domain or ip 里的 ip 分支
            "http://127.0.0.1:8080/",            # 本机测试服务器
        ):
            self.assertTrue(
                scanner.in_scope(Event(type=EventType.URL, data=url, module="t")),
                f"URL {url} 不该被引擎拦掉 —— 过滤是产出模块自己的责任",
            )


class TestSeedAsset(unittest.TestCase):
    """``seed_asset`` 把种子本身转成下游能消费的事件类型。

    修的是一个**回退**：原先没有任何模块把 SEED 转成 DNS_NAME / IP_ADDRESS，
    于是根域名永远不被解析（主站漏掉），裸 IP 目标更是整条链一个事件都不产生。
    ARL 的 ``mass_dns`` 本来是带根域名的，移植时丢了这一句。
    """

    def _run(self, seed: str) -> list[tuple[str, str]]:
        import asyncio

        from core.engine.preset import Preset
        from core.engine.scanner import Scanner
        from pathlib import Path

        from .pgutil import drop_storage, make_storage

        async def go():
            # 刻意不用 tempfile.mkdtemp：沙箱下 0700 目录会失败，沿用测试目录
            root = Path(__file__).resolve().parents[1] / ".testtmp" / "seed_asset"
            root.mkdir(parents=True, exist_ok=True)
            storage = await make_storage()
            try:
                preset = Preset(
                    name="seed",
                    include=["seed_asset"],
                    settings={"forbidden_domains": []},
                )
                scanner = Scanner(targets=[seed], preset=preset, storage=storage)
                await scanner.scan()
                events = await storage.events(scanner.scan_id, limit=50)
                return [(e["type"], e["data"]) for e in events]
            finally:
                await drop_storage(storage)

        return asyncio.run(go())

    def test_domain_seed_becomes_dns_name(self) -> None:
        events = self._run("example.com")
        self.assertIn(("DNS_NAME", "example.com"), events)

    def test_ip_seed_becomes_ip_address(self) -> None:
        """IP 种子不能塞进 DNS_NAME —— 下游的域名逻辑会拿到非法输入。"""
        events = self._run("93.184.216.34")
        self.assertIn(("IP_ADDRESS", "93.184.216.34"), events)
        self.assertNotIn(("DNS_NAME", "93.184.216.34"), events)

    def test_ipv6_seed_is_handled(self) -> None:
        events = self._run("2606:2800:220:1:248:1893:25c8:1946")
        self.assertIn(
            ("IP_ADDRESS", "2606:2800:220:1:248:1893:25c8:1946"),
            events,
            f"IPv6 没被完整识别: {events}",
        )


class TestTargetNormalization(unittest.TestCase):
    """种子目标的归一化。

    **去端口不能简单地 ``split(":")[0]``** —— 那会把 IPv6 从第一个冒号切断
    （``2606:2800:...`` → ``2606``），整个 IPv6 目标静默失效。
    """

    def _norm(self, raw: str) -> str:
        from core.engine.scanner import Scanner

        return Scanner._normalize_target(raw)

    def test_常见形式(self) -> None:
        self.assertEqual(self._norm("example.com"), "example.com")
        self.assertEqual(self._norm("EXAMPLE.com."), "example.com")
        self.assertEqual(self._norm("https://example.com/path?x=1"), "example.com")
        self.assertEqual(self._norm("*.example.com"), "example.com")

    def test_port_is_stripped(self) -> None:
        self.assertEqual(self._norm("example.com:8443"), "example.com")
        self.assertEqual(self._norm("93.184.216.34:80"), "93.184.216.34")

    def test_ipv6_is_not_truncated(self) -> None:
        addr = "2606:2800:220:1:248:1893:25c8:1946"
        self.assertEqual(self._norm(addr), addr)
        self.assertEqual(self._norm(f"[{addr}]:8443"), addr)
        self.assertEqual(self._norm("[::1]"), "::1")


class TestJsAssets(unittest.TestCase):
    """从 JS 里捞资产线索：**写全了的 URL** 与**主机名**。

    这个类的另一半职责是**钉住边界** —— 裸路径、相对路径、密钥、邮箱
    一个都不许进来。详见 ``core/domains/urls/_lib/jsassets.py``。
    """

    def _urls(self, js: str) -> list[str]:
        from core.domains.urls._lib.jsassets import extract_urls

        return extract_urls(js)

    def _hosts(self, js: str) -> list[str]:
        from core.domains.urls._lib.jsassets import extract_hosts

        return extract_hosts(js)

    # ---------------------------------------------------------------- 该捞的
    def test_absolute_urls(self) -> None:
        js = 'a="https://api.example.com/v2/orders";b="wss://ws.example.com/socket";'
        got = self._urls(js)
        self.assertIn("https://api.example.com/v2/orders", got)
        self.assertIn("wss://ws.example.com/socket", got)

    def test_protocol_relative_becomes_https(self) -> None:
        self.assertEqual(
            self._urls('a="//static.example.com/lib.js";'),
            ["https://static.example.com/lib.js"],
        )

    def test_must_be_inside_quotes(self) -> None:
        """**这一条是降噪的主力** —— 不加引号的地址多半是代码/注释，不是字面量。"""
        self.assertEqual(self._urls("fetch(https://api.example.com/x)"), [])

    def test_hosts_from_bare_strings(self) -> None:
        js = 'a="api.example.com";b="dev.internal.example.org";'
        self.assertEqual(self._hosts(js), ["api.example.com", "dev.internal.example.org"])

    def test_hosts_include_those_inside_urls(self) -> None:
        """URL 里的主机也要捞 —— 这是"JS 里发现的域名"最集中的来源。"""
        got = self._hosts('a="https://api.example.com/v1";')
        self.assertIn("api.example.com", got)

    def test_hosts_are_lowercased_and_deduped(self) -> None:
        got = self._hosts('a="API.Example.COM";b="api.example.com";')
        self.assertEqual(got, ["api.example.com"])

    def test_wildcard_host_is_stripped(self) -> None:
        """证书里的 ``*.dev.example.com`` 形态要能认出来。"""
        self.assertIn("dev.example.com", self._hosts('a="*.dev.example.com";'))

    def test_fragment_is_stripped(self) -> None:
        self.assertEqual(
            self._urls('a="https://www.example.com/x#section";'),
            ["https://www.example.com/x"],
        )

    def test_dedup(self) -> None:
        js = 'a="https://www.example.com/x";b="https://www.example.com/x";'
        self.assertEqual(self._urls(js), ["https://www.example.com/x"])

    def test_empty_and_junk(self) -> None:
        self.assertEqual(self._urls(""), [])
        self.assertEqual(self._urls("var a = 1; function f() { return 2; }"), [])
        self.assertEqual(self._hosts(""), [])

    def test_long_input_does_not_blow_up(self) -> None:
        """量词全部有上限，长行不能触发回溯爆炸。"""
        import time

        js = ('var s = "' + "a" * 200000 + '";') * 5
        t0 = time.monotonic()
        self._urls(js)
        self._hosts(js)
        self.assertLess(time.monotonic() - t0, 5.0, "抽取耗时异常 —— 可能有回溯")

    # ---------------------------------------------------------------- 边界
    def test_bare_paths_are_not_collected(self) -> None:
        """**这是与旧版 ``js_endpoints`` 最大的区别。**

        裸路径（``"/api/v1/users"``）是"主动收集网站接口"，平台的边界是
        只铺暴露面、接口语义交给 AI。所以一条都不该被抽出来。
        """
        for js in (
            'a="/api/v1/users";',
            'a="/graphql";',
            'a="/admin";',
            'a="/actuator/env";',
            'a="/swagger.json";',
        ):
            with self.subTest(js=js):
                self.assertEqual(self._urls(js), [], f"裸路径漏进来了: {js}")

    def test_relative_paths_are_not_collected(self) -> None:
        """相对路径要先拼基准才能成 URL —— 那是**凭空造资产**，不是发现资产。"""
        for js in ('a="./x";', 'a="../assets/cfg.json";', 'a="users/list";'):
            with self.subTest(js=js):
                self.assertEqual(self._urls(js), [])
                self.assertEqual(self._hosts(js), [])

    def test_no_secret_patterns(self) -> None:
        """密钥 / 凭证 / 邮箱 / 手机号一律不碰（SecretFinder 是 GPL-3.0，且那是 AI 的活）。"""
        js = (
            'ak="AKIAIOSFODNN7EXAMPLE";'
            'sk="sk_live_abcdefghijklmn";'
            'pw="hunter2";'
            'mail="admin@example.com";'
            'phone="13800138000";'
            'gh="ghp_0123456789abcdefghij";'
        )
        blob = "\n".join(self._urls(js) + self._hosts(js))
        for token in ("AKIAIOSFODNN7EXAMPLE", "sk_live_abcdefghijklmn",
                      "hunter2", "admin@example.com", "13800138000",
                      "ghp_0123456789abcdefghij"):
            self.assertNotIn(token, blob, f"敏感内容漏进来了: {token}")

    def test_looks_like_host_rejects_files_and_ips(self) -> None:
        from core.domains.urls._lib.jsassets import looks_like_host

        for value in ("jquery.min.js", "app.css", "logo.png", "app.js.map",
                      "1.2.3.4", "localhost", "example.com:8080", "-bad.com",
                      "a.b.", "*.", ""):
            with self.subTest(value=value):
                self.assertFalse(looks_like_host(value), f"误收: {value}")

    def test_looks_like_host_accepts_real_domains(self) -> None:
        from core.domains.urls._lib.jsassets import looks_like_host

        for value in ("example.com", "api.example.com", "a.b.c.d.example.com",
                      "xn--fiqs8s.example", "my-service.example.co.uk"):
            with self.subTest(value=value):
                self.assertTrue(looks_like_host(value), f"漏收: {value}")


JS_TARGET = "https://www.example.com/static/app.js"

JS_BODY = """
var cfg = {
  api:   "https://api.example.com/v1",
  order: "https://order.example.com/v2",
  ext:   "https://evil.other.com/track",
  img:   "https://cdn.example.com/logo.png",
  path:  "/api/v1/admin/users",
  rel:   "./chunk-abc.js",
};
var bare = "dev.example.com";
"""


class TestJsAssetsModule(EngineTestCase):
    """走引擎：抓取 → 抽取 → 作用域 → 预算。"""

    EMIT_JS_URL = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_js_url(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event(%r, EventType.URL, parent=event)
""" % JS_TARGET

    def _responder(self, url: str, body: str = JS_BODY, status: int = 200):
        from core.services.http import FetchResult

        return FetchResult(
            url=url,
            status=status,
            headers={"content-type": "application/javascript"},
            text=body,
        )

    async def _scan(self, body: str = JS_BODY, status: int = 200, **cfg):
        from core.services.http import HTTPClient

        self.add_module_file("emit_js", self.EMIT_JS_URL)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return self._responder(url, body, status)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            return await self.run_scan(
                targets=["example.com"],
                include=["emit_js_url", "js_assets"],
                module_config={"js_assets": cfg},
            )

    async def _emitted(self, scan_id: int, event_type: str = "URL") -> set[str]:
        events = await self.storage.events(scan_id, limit=1000, event_type=event_type)
        return {e["data"] for e in events if e["module"] == "js_assets"}

    async def test_emits_urls_and_filters_scope(self) -> None:
        scanner, _ = await self._scan()
        got = await self._emitted(scanner.scan_id)
        self.assertTrue(got, "没抽出任何 URL")
        self.assertIn("https://api.example.com/v1", got)
        self.assertIn("https://order.example.com/v2", got)
        self.assertIn("https://cdn.example.com/logo.png", got)
        # 外链不能进库
        self.assertFalse(any("other.com" in u for u in got), f"外链泄漏: {got}")
        # 裸路径 / 相对路径不能进库（边界）
        self.assertFalse(any("/admin/users" in u for u in got), f"裸路径泄漏: {got}")
        self.assertFalse(any("chunk-abc" in u for u in got), f"相对路径泄漏: {got}")

    async def test_emits_dns_names_for_js_hosts(self) -> None:
        """**JS 里发现的主机名要回喂成 DNS_NAME。**

        少了这一步，``api.example.com`` 只会在 ``url`` 表里躺着，
        永远不被解析、不被探活 —— 等于白发现。
        """
        scanner, _ = await self._scan()
        names = await self._emitted(scanner.scan_id, "DNS_NAME")
        self.assertIn("api.example.com", names)
        self.assertIn("order.example.com", names)
        self.assertIn("dev.example.com", names, "裸主机名字符串也要捞")
        self.assertIn("cdn.example.com", names)
        # 作用域外的名字不能回喂
        self.assertFalse(any("other.com" in n for n in names), f"外域泄漏: {names}")

    async def test_html_fallback_is_skipped(self) -> None:
        """请求 ``.js`` 返回 HTML 是 SPA 常态，那种正文捞出来的是页面链接。"""
        html = "<!DOCTYPE html><html><body><a href=\"/page/x\">x</a></body></html>"
        scanner, _ = await self._scan(body=html)
        self.assertEqual(await self._emitted(scanner.scan_id), set())

    async def test_only_js_urls_are_fetched(self) -> None:
        """非 JS 的 URL 事件不该触发抓取。"""
        from core.services.http import HTTPClient

        self.add_module_file("emit_js", """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_js_url(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event("https://www.example.com/index.html", EventType.URL, parent=event)
""")
        calls: list[str] = []

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                calls.append(url)
                return self._responder(url)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            await self.run_scan(targets=["example.com"], include=["emit_js_url", "js_assets"])

        self.assertEqual(calls, [], f"不该去抓非 JS: {calls}")

    async def test_budget_caps_urls_per_file(self) -> None:
        scanner, _ = await self._scan(max_urls_per_file=1)
        self.assertEqual(len(await self._emitted(scanner.scan_id)), 1)

    async def test_budget_caps_hosts_total(self) -> None:
        scanner, _ = await self._scan(max_hosts_total=2)
        self.assertEqual(len(await self._emitted(scanner.scan_id, "DNS_NAME")), 2)

    async def test_stats_are_reported(self) -> None:
        _, summary = await self._scan()
        row = next(
            (r for r in summary["source_stats"] if r["source"] == "js_assets"), None
        )
        self.assertIsNotNone(row, f"没收到统计: {summary['source_stats']}")
        self.assertGreater(row["raw"], 0)
        self.assertGreater(row["results"], 0)
        self.assertEqual(row["requests"], 1, "抓了 1 个 JS 文件")

    async def test_non_200_is_ignored(self) -> None:
        scanner, _ = await self._scan(status=404)
        self.assertEqual(await self._emitted(scanner.scan_id), set())


if __name__ == "__main__":
    unittest.main()
