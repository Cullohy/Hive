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


class TestJsLiteralDecoding(unittest.TestCase):
    r"""字面量解码 —— 三类在真实前端产物里成片出现、却被"引号+形态"正则漏掉的写法。

    这组用例是**回归钉子**：早期实现是一条大正则扫全文（LinkFinder / JSFinder
    的做法），于是下面三种一个都认不出来。改成"先切字面量再判形态"之后才补上。
    """

    def _urls(self, js: str) -> list[str]:
        from core.domains.urls._lib.jsassets import extract_urls

        return extract_urls(js)

    def _hosts(self, js: str) -> list[str]:
        from core.domains.urls._lib.jsassets import extract_hosts

        return extract_hosts(js)

    def _paths(self, js: str) -> list[str]:
        from core.domains.urls._lib.jsassets import extract_paths

        return extract_paths(js)

    # ------------------------------------------------------------------ 三类盲点
    def test_escaped_slash_is_decoded(self) -> None:
        r"""``https:\/\/api.example.com`` —— 压缩器 / 转义产物的标准写法。

        老正则在字符类里排掉了反斜杠，于是 ``\/\/`` 直接把 ``//`` 打断，
        整条地址一个字符都取不到。
        """
        self.assertEqual(
            self._urls(r'var a="https:\/\/api.example.com\/v1\/user";'),
            ["https://api.example.com/v1/user"],
        )
        self.assertEqual(
            self._hosts(r'var a="https:\/\/api.example.com\/v1";'),
            ["api.example.com"],
        )

    def test_backtick_template_is_scanned(self) -> None:
        """反引号模板字符串 —— 现代前端产物里密度很高，老正则只认两种引号。"""
        self.assertEqual(
            self._urls("var b=`https://api.example.com/x`;"),
            ["https://api.example.com/x"],
        )
        self.assertEqual(
            self._hosts("var b=`api.example.com`;"),
            ["api.example.com"],
        )

    def test_hex_and_unicode_escapes_are_decoded(self) -> None:
        r"""``\xNN`` 与 ``\uNNNN`` —— 混淆过的前端产物会这么写。"""
        self.assertEqual(
            self._paths(r'var c="\x2f\x61\x70\x69\x2f\x75\x73\x65\x72";'),
            ["/api/user"],
        )
        self.assertEqual(
            self._paths(r'var d="/api/v1";'), ["/api/v1"],
        )
        self.assertEqual(
            self._paths(r'var e="\u002f\u0061\u0070\u0069";'), ["/api"],
        )

    def test_decoded_escapes_can_form_a_full_url(self) -> None:
        r"""转义 + 拼接叠在一起时仍要还原 —— 两种形态不是各管一段的。"""
        self.assertEqual(
            self._urls(r'var a="\x68\x74\x74\x70\x73://api.example.com/x";'),
            ["https://api.example.com/x"],
        )

    # ------------------------------------------------------------------ 拼接折叠
    def test_literal_concatenation_is_folded(self) -> None:
        """``"https://" + "api.example.com/v1"`` 要还原成一条完整地址。"""
        self.assertEqual(
            self._urls('var e="https://" + "api.example.com/v1";'),
            ["https://api.example.com/v1"],
        )

    def test_folding_stops_at_a_variable(self) -> None:
        """碰到变量就停手 —— ``"https://" + host`` 里的 host 是什么我们不知道。

        硬拼出来的 ``https://undefined`` 是**发明资产**，比漏掉坏得多。
        """
        got = self._urls('var e="https://" + host + "/v1";')
        self.assertNotIn("https://undefined/v1", got)
        self.assertEqual(got, [])

    def test_protocol_relative_split_across_literals(self) -> None:
        """``"https:" + "//cdn.example.com/lib.js"`` —— 真实写法，不是 ``https://`` + ``//``。"""
        self.assertEqual(
            self._urls('var q="https:" + "//cdn.example.com/lib.js";'),
            ["https://cdn.example.com/lib.js"],
        )

    # ------------------------------------------------------------------ 模板插值
    def test_leading_interpolation_is_stripped(self) -> None:
        r"""``${base}/api/v1`` 里 ``/api/v1`` 是完全确定的，不该连坐丢掉。"""
        self.assertEqual(self._paths("var j=`${base}/api/v1`;"), ["/api/v1"])

    def test_nested_interpolation_does_not_swallow_the_path(self) -> None:
        r"""``${a ? {b:1} : 2}/api/v2`` —— 花括号要配对地跳。

        数到第一个 ``}`` 就停的话，插值**后面**的路径会被一起吃掉。
        """
        self.assertEqual(
            self._paths("var k=`${a ? {b:1} : 2}/api/v2`;"), ["/api/v2"],
        )

    def test_middle_interpolation_is_rejected(self) -> None:
        """``/api/${id}/x`` 判断不了 —— 整条当不是，而不是发一条瞎猜的请求。"""
        self.assertEqual(self._paths("var r=`/api/${id}/x`;"), [])

    def test_interpolation_marker_never_leaks(self) -> None:
        """占位符绝不能进产出 —— 那是内部控制字符，泄漏出去就是脏数据。"""
        for js in ("var j=`${base}/api/v1`;", "var k=`${a}/${b}/v2`;"):
            with self.subTest(js=js):
                for got in self._paths(js):
                    self.assertNotIn("\x00", got)

    # ------------------------------------------------------------------ 路径形态
    def test_only_root_relative_paths_are_taken(self) -> None:
        """点相对与裸相对**没有可用基准**，认了就是发明资产。

        ``./x`` / ``a/b.php`` 的基准是**文档 URL**，而抽取时只看得到 JS 文件
        自己的 URL —— 拿它当基准拼出来的地址是凭空造的。相比之下根相对
        不需要基准，接上站点 origin 就是确定的。
        """
        self.assertEqual(self._paths('var f="/api/v1/users";'), ["/api/v1/users"])
        self.assertEqual(self._paths('var g="/admin/list.php";'),
                         ["/admin/list.php"])
        for js in ('var h="../up/load.action";', 'var i="user/list.json";',
                   'var j="./chunk.js";'):
            with self.subTest(js=js):
                self.assertEqual(self._paths(js), [],
                                 f"没有基准的相对形态被收了: {js}")

    def test_query_string_is_kept_but_fragment_is_not(self) -> None:
        """query 能看出"这是个带租户的接口"，值得留；fragment 不改变服务端行为。"""
        self.assertEqual(
            self._paths('var m="/api/v1/list?tenant=1#top";'),
            ["/api/v1/list?tenant=1"],
        )

    def test_noise_is_filtered(self) -> None:
        """静态资源与打包器内部结构**不值得花请求去验证**。

        抽路径是为了替代字典爆破，而字典爆破找的是目录/接口/后台。
        """
        for js in (
            'var l="/static/img/logo.png";',
            'var l="/static/css/app.css";',
            'var l="/static/js/chunk.js";',
            'require("webpack:///./src/x.js");',
            'var s="main.js";',                  # 单段文件名：噪声太大
            'var s="/";',                        # 光秃秃一个斜杠
            'var s="not a path";',               # 含空格
            # ↓ 这两条**没有**静态扩展名，静态资源那一关拦不住它们，
            #   只有打包器噪声名单能拦。少了那一步它们就会漏进来。
            'var m="/node_modules/lodash/index";',
            'var m="/webpack/build/helper";',
        ):
            with self.subTest(js=js):
                self.assertEqual(self._paths(js), [], f"噪声没收干净: {js}")

    def test_full_urls_are_not_reported_as_paths(self) -> None:
        """地址归 ``extract_urls``，路径归 ``extract_paths`` —— 两边不重叠。"""
        for js in ('a="https://api.example.com/x";', 'a="//cdn.example.com/y.js";'):
            with self.subTest(js=js):
                self.assertEqual(self._paths(js), [])

    def test_urls_still_refuse_bare_paths(self) -> None:
        """**契约没变** —— ``extract_urls`` 仍然只给写全了的地址。

        相对路径是候选（走 ``extract_paths``），要验证过才算资产。
        老的 ``TestJsAssets`` 边界用例依赖这条，不能因为加了路径抽取就松掉。
        """
        for js in ('a="/api/v1/users";', 'a="./x";', 'a="../a/b.json";'):
            with self.subTest(js=js):
                self.assertEqual(self._urls(js), [])

    # ------------------------------------------------------------------ 排序
    def test_api_like_paths_are_ranked_first(self) -> None:
        """预算截断时先保接口 —— 被砍掉的应该是资源而不是 ``/api/v1``。"""
        from core.domains.urls._lib.jsassets import rank_paths

        got = rank_paths(["/about", "/api/v1/users", "/public/js/app.js",
                          "/admin/login", "/static/logo.svg"])
        self.assertEqual(got[:2], ["/api/v1/users", "/admin/login"])
        self.assertIn("/about", got)

    def test_rank_is_stable_and_total(self) -> None:
        from core.domains.urls._lib.jsassets import rank_paths

        paths = ["/a", "/b", "/c", "/d"]
        self.assertEqual(sorted(rank_paths(paths)), sorted(paths))
        self.assertEqual(rank_paths(paths), rank_paths(paths))

    # ------------------------------------------------------------------ 性能
    def test_pathological_quote_density_does_not_blow_up(self) -> None:
        """引号密集的输入不能让回溯爆炸 —— 找收尾引号那一步必须无回溯。"""
        import time

        for src in ("'" * 50000, '"' * 50000, "`" * 50000):
            with self.subTest(n=len(src)):
                t0 = time.monotonic()
                self._paths(src)
                self.assertLess(
                    time.monotonic() - t0, 5.0,
                    "引号密集的输入耗时异常 —— 量词失去上界了",
                )


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
        # 点相对（`./chunk-abc.js`）没有可用基准，**永远**不该进库
        self.assertFalse(any("chunk-abc" in u for u in got), f"相对路径泄漏: {got}")
        # 根相对路径**可以**进库，但必须先验证过。这个 fixture 里每条请求都
        # 返回同一份 JS 正文，软 404 画像会把候选全判成噪声，所以一条都进不来
        # —— 这正是「没验证的路径不许算数」。真验证通过的那条见
        # TestJsPathVerification。
        self.assertFalse(any("/admin/users" in u for u in got),
                         f"未经验证的路径泄漏: {got}")

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
        _, summary = await self._scan(verify_paths=False)
        row = next(
            (r for r in summary["source_stats"] if r["source"] == "js_assets"), None
        )
        self.assertIsNotNone(row, f"没收到统计: {summary['source_stats']}")
        self.assertGreater(row["raw"], 0)
        self.assertGreater(row["results"], 0)
        self.assertEqual(row["requests"], 1, "抓了 1 个 JS 文件")
        self.assertEqual(row["detail"]["路径验证请求"], 0,
                         "verify_paths=False 时不该有任何验证请求")

    async def test_non_200_is_ignored(self) -> None:
        scanner, _ = await self._scan(status=404)
        self.assertEqual(await self._emitted(scanner.scan_id), set())


#: JS 里写的路径，以及其中**确实存在**的那些。存在的返回真内容，
#: 不存在的返回固定 404 页 —— 这是最常见的真实形态。
PATH_JS_BODY = """
var cfg = {
  real:  "/api/v1/admin/users",
  fake:  "/api/v1/does/not/exist",
  also:  "/api/v1/orders",
  img:   "/static/img/logo.png",
};
"""

_EXISTING = {"/api/v1/admin/users", "/api/v1/orders"}
_NOT_FOUND = (
    "<!DOCTYPE html><html><head><title>404</title></head>"
    "<body><h1>404 Not Found</h1><p>The requested page does not exist.</p>"
    "</body></html>"
)


class TestJsPathVerification(EngineTestCase):
    r"""根相对路径**验证之后**才进库 —— 这是拿 JS 替代字典爆破的落点。

    这组用例守的是整个改动里最要紧的那条线：

    * 没验证的路径**一条都不许进库**（否则就是在发明资产）
    * 验证过、确认存在的**必须**进库（否则白抽）
    * 验证请求要**如实记账**（用户换这条路的原因就是流量）
    """

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

    async def _scan(self, *, body: str = PATH_JS_BODY, **cfg):
        """跑一次完整链路，返回 ``(scanner, 实际发出去的 URL, 汇总)``。"""
        from core.services.http import FetchResult, HTTPClient

        self.add_module_file("emit_js", self.EMIT_JS_URL)
        sent: list[str] = []

        def responder(url: str):
            from urllib.parse import urlsplit

            sent.append(url)
            if url == JS_TARGET:
                return FetchResult(
                    url=url, status=200, headers={}, text=body,
                )
            path = urlsplit(url).path
            if path in _EXISTING:
                return FetchResult(
                    url=url, status=200,
                    headers={"content-type": "application/json"},
                    text='{"code":0,"data":[{"id":1,"name":"admin"}]}',
                )
            return FetchResult(url=url, status=404, headers={}, text=_NOT_FOUND)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["emit_js_url", "js_assets"],
                module_config={"js_assets": cfg},
            )
        return scanner, sent, summary

    async def _emitted(self, scan_id: int) -> set[str]:
        events = await self.storage.events(scan_id, limit=1000, event_type="URL")
        return {e["data"] for e in events if e["module"] == "js_assets"}

    @staticmethod
    def _row(summary: dict) -> dict:
        return next(
            (r for r in summary["source_stats"] if r["source"] == "js_assets"), {}
        )

    @staticmethod
    def _probes(sent: list[str]) -> list[str]:
        """除抓 JS 那一条以外，模块自己发出去的所有请求。"""
        return [u for u in sent if not u.endswith("app.js")]

    # ------------------------------------------------------------------ 该进的
    async def test_verified_path_is_emitted(self) -> None:
        scanner, _sent, _summary = await self._scan()
        got = await self._emitted(scanner.scan_id)
        self.assertIn("https://www.example.com/api/v1/admin/users", got,
                      "验证通过却没入库 —— 那就白抽了")

    async def test_noise_path_is_not_emitted(self) -> None:
        """**这条是整个改动的命门**：软 404 判成噪声的路径一条都不许进库。

        ``/api/v1/does/not/exist`` 在 JS 里写得和真接口一模一样，不验证就
        发出去的话，资产表里会多出一条根本不存在的接口。
        """
        scanner, _sent, _summary = await self._scan()
        got = await self._emitted(scanner.scan_id)
        self.assertNotIn("https://www.example.com/api/v1/does/not/exist", got,
                         "软 404 被当成了真实接口")

    async def test_static_asset_is_not_probed_at_all(self) -> None:
        """静态资源不该占验证请求 —— 这条本来就该在抽取阶段就被滤掉。"""
        _scanner, sent, _summary = await self._scan()
        self.assertFalse(any("logo.png" in u for u in sent),
                         f"静态资源被拿去验证了: {sent}")

    # ------------------------------------------------------------------ 流量
    async def test_traffic_is_far_below_a_dictionary(self) -> None:
        """**这是换这条路的全部意义**，所以必须钉死。

        一个站点抽出来的候选只有个位数到几十条；目录字典动辄几百条。
        请求量差一个数量级，才值得把爆破换掉。
        """
        _scanner, sent, _summary = await self._scan()
        probes = self._probes(sent)
        # 2 条校准 + 3 条候选（两条真 + 一条假）
        self.assertEqual(len(probes), 5, f"验证请求数失控: {probes}")
        self.assertLess(len(probes), 10,
                        "验证请求比字典还多，这条路就没有意义了")

    async def test_requests_are_reported_honestly(self) -> None:
        """统计里的请求数**必须包含验证请求**。

        藏起来的话，用户在界面上看到的还是「只抓了 1 个 JS」，
        换来的省流量就成了看不见的代价。
        """
        _scanner, sent, summary = await self._scan()
        row = self._row(summary)
        self.assertEqual(row["detail"]["路径验证请求"], 3)
        self.assertEqual(row["detail"]["确认存在的路径"], 2)
        self.assertEqual(row["detail"]["判为软 404"], 1)
        self.assertEqual(row["requests"], len(sent),
                         "requests 必须等于实际发出的请求数")

    async def test_verification_can_be_turned_off(self) -> None:
        """``verify_paths: false`` → 退回旧行为，**一个额外请求都不发**。"""
        _scanner, sent, summary = await self._scan(verify_paths=False)
        self.assertEqual(self._probes(sent), [], "关掉后仍在发验证请求")
        self.assertEqual(self._row(summary)["detail"]["路径验证请求"], 0)

    async def test_per_host_budget_caps_probes(self) -> None:
        """``max_paths_per_host`` 是硬上限 —— 它是这个模块最贵的一项。"""
        _scanner, sent, _summary = await self._scan(max_paths_per_host=1)
        probes = self._probes(sent)
        # 2 条校准 + 1 条候选
        self.assertEqual(len(probes), 3, f"上限没生效: {probes}")

    # ------------------------------------------------------------------ 画像
    async def test_profile_is_built_once_per_origin(self) -> None:
        """一个站点几十个 JS 文件都在同一个 origin 上，重复校准就是白烧流量。

        3 条候选共用一条画像 —— 校准只发 2 条，不是每条候选都重新校准一次。
        """
        _scanner, sent, summary = await self._scan()
        self.assertEqual(self._row(summary)["detail"]["JS 校准次数"], 1)
        self.assertEqual(len(self._probes(sent)), 5)

    async def test_same_path_in_many_chunks_is_verified_once(self) -> None:
        """**这是本模块最该省的地方。**

        真实前端产物里，同一个接口路径常常在十几个 chunk 里各写一遍
        （路由表、公共模块、懒加载页各一份）。不跨文件去重的话，
        请求量直接翻十几倍 —— 去重比什么都值钱。
        """
        from core.services.http import FetchResult, HTTPClient

        chunks = [f"https://www.example.com/static/c{i}.js" for i in range(4)]
        self.add_module_file("emit_chunks", """
from core.engine.event import EventType
from core.engine.module import BaseModule

URLS = %r


class emit_chunks(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for url in URLS:
            await self.emit_event(url, EventType.URL, parent=event)
""" % (chunks,))

        sent: list[str] = []

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            from urllib.parse import urlsplit

            async def go():
                sent.append(url)
                if url in chunks:
                    # 四个 chunk 里**写的是同一批路径**
                    return FetchResult(url=url, status=200, headers={},
                                       text=PATH_JS_BODY)
                if urlsplit(url).path in _EXISTING:
                    return FetchResult(url=url, status=200, headers={},
                                       text='{"code":0}')
                return FetchResult(url=url, status=404, headers={},
                                   text=_NOT_FOUND)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["emit_chunks", "js_assets"],
                module_config={"js_assets": {}},
            )

        # 4 个 JS + 2 条校准 + **3 条候选（不是 4×3）**
        self.assertEqual(len(sent), 9, f"跨文件去重没生效: {sent}")
        # 画像按 origin 建，**四个 chunk 共用一条** —— 每个文件都重新校准一遍
        # 的话就是 8 条校准请求，比候选本身还多
        self.assertEqual(self._row(summary)["detail"]["JS 校准次数"], 1,
                         "每个 JS 文件都重新校准了一遍 —— 白烧流量")
        got = await self._emitted(scanner.scan_id)
        self.assertIn("https://www.example.com/api/v1/admin/users", got)

    async def test_second_chunk_with_new_paths_reuses_the_profile(self) -> None:
        """第二个 chunk 带来**新路径**时，也要用同一个 origin 已建好的画像。

        这是画像缓存唯一真正吃劲的场景 —— 上一个用例里四个 chunk 写的路径
        全一样，第二个文件在候选去重后就没有候选了，压根走不到建画像那步。
        这里让第二个 chunk 带一条只有它有的路径，才真的踩到缓存。
        """
        from core.services.http import FetchResult, HTTPClient

        c0, c1 = ("https://www.example.com/static/c0.js",
                  "https://www.example.com/static/c1.js")
        bodies = {
            c0: 'var a = "/api/v1/one"; var b = "/api/v1/two";',
            c1: 'var c = "/api/v1/three";',
        }
        self.add_module_file("emit_two", """
from core.engine.event import EventType
from core.engine.module import BaseModule

URLS = %r


class emit_two(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for url in URLS:
            await self.emit_event(url, EventType.URL, parent=event)
""" % ([c0, c1],))

        sent: list[str] = []

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            from urllib.parse import urlsplit

            async def go():
                sent.append(url)
                if url in bodies:
                    return FetchResult(url=url, status=200, headers={},
                                       text=bodies[url])
                if urlsplit(url).path.startswith("/api/"):
                    return FetchResult(url=url, status=200, headers={},
                                       text='{"code":0}')
                return FetchResult(url=url, status=404, headers={},
                                   text=_NOT_FOUND)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["emit_two", "js_assets"],
                module_config={"js_assets": {}},
            )

        # 2 个 JS + 2 条校准（**不是 4 条**）+ 3 条候选
        self.assertEqual(len(sent), 7, f"画像被重建了: {sent}")
        self.assertEqual(self._row(summary)["detail"]["JS 校准次数"], 1)
        got = await self._emitted(scanner.scan_id)
        self.assertIn("https://www.example.com/api/v1/three", got,
                      "第二个 chunk 的新路径没验上")

    async def test_unusable_profile_skips_every_candidate(self) -> None:
        """画像立不起来时**一条候选都不许发**。

        判不了就等于没判，把候选全打出去只会得到一堆判不了的响应 ——
        既没结论，又把流量花光了。
        """
        from core.services.http import FetchResult, HTTPClient

        self.add_module_file("emit_js", self.EMIT_JS_URL)
        sent: list[str] = []

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                sent.append(url)
                if url == JS_TARGET:
                    return FetchResult(url=url, status=200, headers={},
                                       text=PATH_JS_BODY)
                # 每条都返回完全不一样的东西 → 基线立不起来。
                # 幅度要大到**超出容差**（8 字节）：差几字节属于正常抖动，
                # 那种情况软 404 画像照样立得起来，测试就变成在测别的东西了。
                pad = "x" * (200 * len(sent))
                return FetchResult(url=url, status=200, headers={},
                                   text=f"<html>{pad}</html>")
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_js_url", "js_assets"],
                module_config={"js_assets": {}},
            )

        got = await self._emitted(scanner.scan_id)
        self.assertFalse(any("/api/v1/" in u for u in got),
                         f"画像不可用却还是发了候选: {got}")
        self.assertEqual([u for u in sent if "/api/v1/" in u], [],
                         "画像不可用却仍在验证候选")


_PARENT_EMIT_MODULE = """
from core.engine.event import EventType
from core.engine.module import BaseModule

HTML = %s
URL = "https://www.example.com/"


class emit_html(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.HTTP_RESPONSE,)
    flags = ("active", "loud")

    async def handle_event(self, event):
        await self.emit_event(URL, EventType.HTTP_RESPONSE, parent=event,
                              tags={"url": URL, "final_url": URL,
                                    "body_snippet": HTML, "status": 200})
"""


_PARENT_EMIT_MODULE = """
from core.engine.event import EventType
from core.engine.module import BaseModule

HTML = %s
URL = "https://www.example.com/"


class emit_html(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.HTTP_RESPONSE,)
    flags = ("active", "loud")

    async def handle_event(self, event):
        await self.emit_event(URL, EventType.HTTP_RESPONSE, parent=event,
                              tags={"url": URL, "final_url": URL,
                                    "body_snippet": HTML, "status": 200})
"""


class TestParentDirDerivation(EngineTestCase):
    """父目录推导 —— 2026-10-03 从 ``dir_brute`` 搬到 ``url_extract``。

    搬家的理由：**``dir_brute`` 该只干「猜字典」**，而从页面里「读」出目录
    是采集的活。而且原来两边都在抽同一份首页正文（``dir_brute`` 自己抓一遍
    首页，``url_extract`` 也抽一遍），那是实打实的重复。

    ⚠️ 搬过来之后语义变了：这些是**已发现、未验证**的地址。验证要发请求，
    那是 active 的事；``url_extract`` 是 ``passive, safe``，加了验证就破坏
    性质了。所以事件上带 ``verified=False`` 标记。
    """

    HOST = "https://www.example.com"

    #: 首页里写着的链接
    INDEX_HTML = (
        '<html><head><link href="/static/app.css" rel="stylesheet"></head>'
        '<body><a href="/docs/guide/intro.html">指南</a>'
        '<a href="/docs/api/reference.html">接口</a>'
        '<a href="https://other.example.org/external-only-path">外站</a>'
        '<script src="/static/app.js"></script></body></html>'
    )

    async def _scan(self, html: str = None, **cfg):
        """跑一条链：``SEED → HTTP_RESPONSE(带正文) → url_extract``。

        ⚠️ **刻意不 mock HTTPClient** —— 这条链上任何模块发了请求都会真的
        出去，那就不是「纯读」了。``test_derivation_sends_no_requests`` 专门
        盯这条（那里才去 mock）。
        """
        self.add_module_file(
            "emit_html", _PARENT_EMIT_MODULE % repr(self.INDEX_HTML if html is None else html)
        )
        scanner, _summary = await self.run_scan(
            targets=["example.com"],
            include=["emit_html", "url_extract"],
            module_config={"url_extract": cfg},
        )
        return scanner

    async def _parents(self, scan_id: int) -> list[str]:
        # ⚠️ 两个坑叠在一起，踩过一次：
        # 1. ``kind`` **列**只对 FINDING 事件填（见 postgres.save_event），
        #    URL 事件的 kind 留在 tags 里；
        # 2. 而 ``tags_json`` 这一列读回来是**字符串**，不是 dict。
        # 所以要自己 json.loads 一下。
        import json as _json

        rows = await self.storage.events(scan_id, limit=2000, event_type="URL")
        out = []
        for row in rows:
            try:
                tags = _json.loads(row.get("tags_json") or "{}")
            except (TypeError, ValueError):
                tags = {}
            if tags.get("kind") == "parent_dir":
                out.append(row["data"])
        return out

    # ------------------------------------------------------------------ 该发的
    async def test_parent_directories_are_emitted(self) -> None:
        """``/docs/guide/intro.html`` 要推出 ``/docs`` 与 ``/docs/guide``。"""
        scanner = await self._scan()
        parents = await self._parents(scanner.scan_id)
        for path in ("/docs", "/docs/guide"):
            self.assertIn(f"{self.HOST}{path}", parents, f"父目录没发出来: {path}")

    async def test_parents_are_marked_unverified(self) -> None:
        """**必须标成「未验证」** —— 目录存在 ≠ 请求它有有用响应。

        很多站点目录列表是关的，``/docs/`` 本身回 403 或空页。把它当成
        「已确认存在」入库，后面的人就白跑一趟。
        """
        scanner = await self._scan()
        parents = await self._parents(scanner.scan_id)
        self.assertTrue(parents, "一条父目录都没发")
        # ``verified`` 存在 tags_json 里（读回来是字符串），这里只验它确实
        # 以 False 落库，而不是压根没写这个标记
        for url in parents:
            row = await self.storage.events(
                scanner.scan_id, limit=50, event_type="URL"
            )
            hit = [r for r in row if r["data"] == url]
            self.assertTrue(hit, f"父目录事件不见了: {url}")
            self.assertIn('"verified":false',
                          str(hit[0].get("tags_json") or "").lower().replace(
                              '"verified": false', '"verified":false'),
                          f"没标未验证: {url}")

    # ------------------------------------------------------------------ 不该发的
    async def test_external_links_are_not_derived(self) -> None:
        """**只推本站** —— 外站路径拿到本站验证纯属浪费。

        ⚠️ 断言必须落在**路径**上，不能查 URL 里有没有外站域名：
        就算把本站过滤关掉，发出去的也是 ``https://本站/外站路径``，
        URL 里根本不会出现那个域名，按域名查是查不出问题的。
        """
        scanner = await self._scan()
        parents = await self._parents(scanner.scan_id)
        self.assertFalse([p for p in parents if "external-only-path" in p],
                         f"外站的路径被拿来推导了: {parents}")

    async def test_static_assets_are_not_seeds(self) -> None:
        """静态资源在推之前丢掉 —— ``/static/app.js`` 会拖出 ``/static``。"""
        scanner = await self._scan()
        parents = await self._parents(scanner.scan_id)
        self.assertFalse([p for p in parents if p.endswith("/static")],
                         f"构建目录被推导出来了: {parents}")
        self.assertFalse([p for p in parents if p.endswith(".js")],
                         f"静态资源本身被推导出来了: {parents}")

    async def test_shallow_is_ranked_first(self) -> None:
        """**越浅的越先** —— ``/a/`` 是正经入口，深的是构建产物。

        这个顺序就是预算不够时丢谁的决定，所以要钉住。
        """
        # 深的那条**写在前面**，才能证明排序确实生效而不是碰巧顺着文档顺序。
        # ⚠️ 两段都得**至少两层**：单段的 ``/z`` 没有祖先（``include_self=False``），
        # 拿它当"浅"的样本会得到空列表。
        html = ('<html><body><a href="/a/b/c/d">deep</a>'
                '<a href="/z/w">shallow</a></body></html>')
        scanner = await self._scan(html)
        parents = await self._parents(scanner.scan_id)
        self.assertIn(f"{self.HOST}/z", parents)
        self.assertIn(f"{self.HOST}/a/b", parents)
        self.assertLess(parents.index(f"{self.HOST}/z"),
                        parents.index(f"{self.HOST}/a/b"),
                        f"深路径排在浅路径前面了: {parents}")

    async def test_same_depth_keeps_document_order(self) -> None:
        """同深度**保持文档顺序** —— 稳定排序不是可有可无的。

        深度相同时谁先谁后，就是「同一层里先试哪条」的决定。
        """
        html = ('<html><body><a href="/a/x">x</a>'
                '<a href="/c/y">y</a></body></html>')
        scanner = await self._scan(html)
        parents = await self._parents(scanner.scan_id)
        # 两段的祖先都是深度 1，顺序就该跟文档里一样
        self.assertEqual(parents, [f"{self.HOST}/a", f"{self.HOST}/c"],
                         f"同深度顺序被改动了: {parents}")

    async def test_the_link_itself_is_not_re_emitted(self) -> None:
        """**只推祖先，不推叶子。**

        叶子链接上面已经正常抽过一次了，再发一遍会被引擎按
        ``(type, data, kind)`` 去重掉（URL 事件的 kind 列恒为空，必然撞）——
        推它是白费一次事件预算。真正有价值的是链接里没有的祖先目录。
        """
        html = '<html><body><a href="/a/b/c">x</a></body></html>'
        scanner = await self._scan(html)
        parents = await self._parents(scanner.scan_id)
        self.assertIn(f"{self.HOST}/a/b", parents)
        self.assertIn(f"{self.HOST}/a", parents)
        self.assertNotIn(f"{self.HOST}/a/b/c", parents,
                         "叶子被当成父目录又发了一遍")

    # ------------------------------------------------------------------ 预算
    async def test_budget_caps_parents(self) -> None:
        html = "".join(f'<a href="/d{i}/x/y">x</a>' for i in range(10))
        scanner = await self._scan(html, max_parents_per_page=3)
        self.assertEqual(len(await self._parents(scanner.scan_id)), 3)

    async def test_total_budget_stops_early(self) -> None:
        html = "".join(f'<a href="/d{i}/x/y">x</a>' for i in range(10))
        scanner = await self._scan(html, max_parents_per_page=8,
                                  max_parents_total=4)
        self.assertEqual(len(await self._parents(scanner.scan_id)), 4)

    async def test_can_be_turned_off(self) -> None:
        """``derive_parents: false`` → 一条都不发。"""
        scanner = await self._scan(derive_parents=False)
        self.assertEqual(await self._parents(scanner.scan_id), [])

    # ------------------------------------------------------------------ 契约
    async def test_derivation_sends_no_requests(self) -> None:
        """**纯读，一个请求都不许多发。**

        这是它能待在 ``passive, safe`` 里的唯一理由 —— 加了验证就破坏性质。
        """
        from core.services.http import HTTPClient

        called: list[str] = []

        async def boom(*a, **k):  # pragma: no cover
            called.append(str(a[:1]))
            raise AssertionError("父目录推导发了请求")

        self.add_module_file(
            "emit_html", _PARENT_EMIT_MODULE % repr(self.INDEX_HTML)
        )
        with mock.patch.object(HTTPClient, "fetch", boom):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_html", "url_extract"],
                module_config={"url_extract": {}},
            )
        self.assertEqual(called, [], "父目录推导发了请求")


if __name__ == "__main__":
    unittest.main()
