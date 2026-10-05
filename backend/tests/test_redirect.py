"""重定向：请求地址与落地地址必须能被分开读出来。

## 为什么这条要测在"落库"这一层

`redirects` 这个标签**曾经一直在发**（`http_probe` 早就有），但 `http_endpoint`
表里**没有对应列** —— 标签在半路上被存储层丢掉了。测"事件 tags 里有没有
redirects"对它完全无效，**必须断言那一行真的读得到**。

## 真实故障长什么样

2026-10-05 用户报"有些 url 访问根本不是显示的那个地址"。查 scan 50：

    url       = http://support.yealink.com.cn:2082
    final_url = https://support.yealink.com.cn/
    status 200  title='Yealink Support'  len=65506

这一行在说"**2082 端口返回了 200、65506 字节、标题 Yealink Support**"——
全是假的。2082 只回了个跳转，那 65506 字节和标题来自主站首页。
而界面上**只显示 `url`**，于是点开必然对不上。
"""

from __future__ import annotations

import json
import unittest

from .base import EngineTestCase

EMIT_PORT = """
from core.engine.event import EventType
from core.engine.module import BaseModule

URLS = ["http://fuzz.example.com/"]


class emit_port(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for url in URLS:
            await self.emit_event(url, EventType.URL, parent=event)
"""


class TestRedirectIsNotSilentlyFlattened(EngineTestCase):
    """一个「整站 301 到别处」的 origin，测三件事。"""

    def _redirecting(self, seen: list[str]):
        """造一个应答器：**所有**路径都 301 到另一个 origin。

        刻意让落地地址与请求地址**不同源**（换端口），因为同源跳转最容易被
        误当成"就是这个页面"。实测那个 65506 字节的假数据就是跨 origin 的。

        ``/admin`` 的落地页带可辨识的标题与长度（否则每一路响应长得一样，
        会被软 404 基线整批判成噪声，dir_brute 记 0 命中 —— 那样就测不到
        落库那一行了）；其余路径返回统一的短内容当噪声。
        """
        from core.services.http import FetchResult

        async def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            seen.append(url)
            if url.startswith("https://fuzz.example.com:8443"):
                # 直连落地 origin：自己就是 200
                return FetchResult(url=url, status=200,
                                   text="<title>Landing</title>",
                                   headers={"server": "nginx"}, orig_status=200)
            is_admin = url.rstrip("/").endswith("/admin")
            if is_admin:
                return FetchResult(
                    url="https://fuzz.example.com:8443/admin-panel",
                    status=200,                       # 落地页的状态
                    text="<title>Admin Panel</title>" + "A" * 4000,
                    headers={"server": "nginx"},
                    history=[url],                    # 跳转链
                    orig_status=301,                   # **这个 URL 自己的状态**
                )
            # 其余路径：整站跳转到同一个落地页（噪声）
            return FetchResult(
                url="https://fuzz.example.com:8443/landing",
                status=200, text="not found", headers={"server": "nginx"},
                history=[url], orig_status=301,
            )

        return fake_fetch

    async def _scan(self, seen: list[str]):
        from unittest import mock

        from core.services.http import HTTPClient

        self.add_module_file("emit_port", EMIT_PORT)
        wl = self.root / "wl.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\n.env\nconfig.yml\n", encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", self._redirecting(seen)):
            return await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "max_paths": 5, "probes": 2,
                        "concurrency": 2, "delay": 0, "forbidden_min": 5,
                    },
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    async def test_the_row_separates_requested_url_from_where_content_came_from(self) -> None:
        """**落库那一行**必须能读出首跳状态码与跳转链。"""
        scanner, _ = await self._scan([])
        rows = {
            r["url"]: r for r in await self.storage.endpoints(scanner.scan_id, limit=500)
        }
        row = rows.get("http://fuzz.example.com/admin")
        self.assertIsNotNone(
            row, f"命中的路径没落成 http_endpoint 行: {sorted(rows)}")

        # ❗ 这三条就是修复点。把 orig_status / redirects 去掉，它就红。
        self.assertEqual(
            row["orig_status"], 301,
            "首跳状态码没落库 —— 那一行只剩落地页的信息，"
            "会声称『这个 URL 自己返回了 200 + 落地页的标题与长度』")
        self.assertTrue(
            row["redirects"],
            "跳转链没落库 —— 无法区分『这个 URL 是 200』与『它跳走了才 200』")
        self.assertEqual(
            json.loads(row["redirects"])[0], "http://fuzz.example.com/admin")
        # 而 status 仍然是**落地页**的 —— 这是既有语义，别顺手改掉
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["final_url"],
                         "https://fuzz.example.com:8443/admin-panel")

    async def test_a_rescan_without_a_redirect_clears_the_stale_chain(self) -> None:
        """**重扫**（走 ``ON CONFLICT`` 那条路）之后两列必须自洽。

        监控每轮都撞同一个 ``dedup_key``，所以这不是边角路径。

        曾经用 ``COALESCE`` 合并，于是第二轮**没有**跳转时：
        ``orig_status`` 被刷成 200（= 没跳），``redirects`` 却留着上一轮的
        跳转链 —— 同一行里两个字段自相矛盾（"没有跳转" + 列出跳转链）。

        判据是那条不变式：``orig_status != status`` 当且仅当 ``redirects`` 非空。
        """
        from unittest import mock

        from core.services.http import HTTPClient, FetchResult

        self.add_module_file("emit_port", EMIT_PORT)
        wl = self.root / "wl3.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\n", encoding="utf-8")

        def _landing(url):
            return FetchResult(url=url, status=200, text="<title>Landing</title>",
                               headers={"server": "nginx"}, orig_status=200)

        async def redirecting(client, url, **kwargs):  # noqa: ANN001
            if url.startswith("https://fuzz.example.com:8443"):
                return _landing(url)
            if url.rstrip("/").endswith("/admin"):
                return FetchResult(
                    url="https://fuzz.example.com:8443/admin-panel", status=200,
                    text="<title>Admin Panel</title>" + "A" * 4000,
                    headers={"server": "nginx"},
                    history=[url], orig_status=301)
            return FetchResult(
                url="https://fuzz.example.com:8443/landing", status=200,
                text="not found", headers={"server": "nginx"},
                history=[url], orig_status=301)

        # 第二轮同一个 URL、**没有**跳转
        async def plain(client, url, **kwargs):  # noqa: ANN001
            if url.startswith("https://fuzz.example.com:8443"):
                return _landing(url)
            if url.rstrip("/").endswith("/admin"):
                return FetchResult(
                    url=url, status=200,
                    text="<title>Admin Panel</title>" + "A" * 4000,
                    headers={"server": "nginx"})
            return FetchResult(url=url, status=200, text="not found",
                               headers={"server": "nginx"})

        cfg = {
            "dir_brute": {"wordlist": str(wl), "max_paths": 3, "probes": 2,
                          "concurrency": 2, "delay": 0, "forbidden_min": 5},
            "http_probe": {"prefer_https": False, "schemes": ["http"]},
        }
        with mock.patch.object(HTTPClient, "fetch", redirecting):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config=cfg)
        key = "http://fuzz.example.com/admin"
        first = {r["url"]: r for r in
                 await self.storage.endpoints(scanner.scan_id, limit=500)}[key]
        self.assertEqual(first["orig_status"], 301, "第一轮就该记成 301")
        self.assertTrue(first["redirects"], "第一轮就该有跳转链")

        with mock.patch.object(HTTPClient, "fetch", plain):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config=cfg)

        row = {r["url"]: r for r in
               await self.storage.endpoints(scanner.scan_id, limit=500)}[key]
        # ❗ 修复点：第二轮没有跳转，陈旧的跳转链必须被**清掉**
        self.assertEqual(
            row["orig_status"], 200,
            "重扫后首跳状态码没更新 —— 两个字段会和跳转链对不上")
        self.assertIn(
            row["redirects"], (None, ""),
            f"重扫后仍留着上一轮的跳转链，两列自相矛盾: {row['redirects']!r}")
        # 不变式：没有跳转 -> orig_status == status 且 redirects 为空
        self.assertEqual(row["status"], 200)

    async def test_a_non_redirecting_url_records_no_redirects(self) -> None:
        """没发生跳转时，``redirects`` 要留空而不是写成 ``"[]"``。

        写入端用 ``COALESCE(excluded.redirects, ...)`` 合并，存成 ``"[]"``
        会把"这次没跳"和"这次没记"混成一回事。
        """
        from core.services.http import FetchResult
        from unittest import mock
        from core.services.http import HTTPClient

        self.add_module_file("emit_port", EMIT_PORT)
        wl = self.root / "wl2.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\n", encoding="utf-8")

        async def plain(client, url, **kwargs):  # noqa: ANN001
            # /admin 要有可辨识的标题与长度，否则会跟软 404 校准响应撞成一片，
            # dir_brute 记 0 命中，就落不出 http_endpoint 行了
            is_admin = url.rstrip("/").endswith("/admin")
            return FetchResult(
                url=url, status=200,
                text=("<title>Admin</title>" + "A" * 4000) if is_admin
                     else "not found",
                headers={"server": "nginx"},
            )

        with mock.patch.object(HTTPClient, "fetch", plain):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "max_paths": 3, "probes": 2,
                        "concurrency": 2, "delay": 0, "forbidden_min": 5,
                    },
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )
        rows = {
            r["url"]: r for r in await self.storage.endpoints(scanner.scan_id, limit=500)
        }
        row = rows.get("http://fuzz.example.com/admin")
        self.assertIsNotNone(row, f"没落成端点行: {sorted(rows)}")
        self.assertEqual(row["orig_status"], 200)
        self.assertIn(row["redirects"], (None, ""),
                      f"没跳转却记了 redirects={row['redirects']!r}")


class TestOrigStatusIsTheFirstHop(unittest.TestCase):
    """``FetchResult.orig_status`` 的定义：首跳状态码，不是最终状态码。"""

    def test_defaults_to_status_when_nothing_redirected(self) -> None:
        from core.services.http import FetchResult

        r = FetchResult(url="http://a/", status=200)
        self.assertEqual(r.orig_status, 0, "默认应为 0（未填）而不是偷偷等于 status")

    def test_constructor_carries_both(self) -> None:
        from core.services.http import FetchResult

        r = FetchResult(url="https://b/", status=200, orig_status=301,
                        history=["http://a/"])
        self.assertEqual(r.status, 200)
        self.assertEqual(r.orig_status, 301)
        self.assertEqual(r.history, ["http://a/"])


class TestRealClientComputesOrigStatus(unittest.IsolatedAsyncioTestCase):
    """**真服务器 + 真 fetch()** —— 上面那些手搓夹具绕过了这段逻辑。

    ## 为什么必须再补这一类

    变异验证实测：把 ``services/http.py`` 里的

        orig_status = (response.history[0].status_code if response.history
                       else response.status_code)

    改回 ``orig_status = response.status_code``（= 修复前的行为，跳转就
    看不出来），**上面 4 条测试全绿**。因为它们的假响应是自己 new 出来的
    ``FetchResult``，``fetch()`` 压根没被跑到。

    判据只能落在真代码路径上，所以这里起一个 stdlib 的本地 302 服务器
    （不引任何新依赖），走真正的 :meth:`HTTPClient.fetch`。
    """

    async def asyncSetUp(self) -> None:
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        landing = b"<title>Landing</title>" + b"L" * 4096

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *a):  # 静音
                pass

            def do_GET(self):  # noqa: N802
                if self.path == "/landing":
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(landing)))
                    self.end_headers()
                    self.wfile.write(landing)
                else:
                    self.send_response(302)
                    self.send_header("Location", "/landing")
                    self.send_header("Content-Length", "0")
                    self.end_headers()

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
        self._thread.start()
        self.base = f"http://127.0.0.1:{self._srv.server_address[1]}"

    async def asyncTearDown(self) -> None:
        self._srv.shutdown()
        self._srv.server_close()

    async def test_a_redirecting_url_reports_the_first_hop_status(self) -> None:
        from core.services.http import HTTPClient

        client = HTTPClient(timeout=10, retries=0)
        try:
            r = await client.fetch(f"{self.base}/admin")
        finally:
            await client.close()

        self.assertIsNotNone(r, "本地服务器没响应")
        # 落地页是 200、4096 字节以上
        self.assertEqual(r.status, 200)
        self.assertTrue(len(r.text) > 100)
        # ❗ 修复点：orig_status 必须是**首跳**的 302。
        # 改回 `= response.status_code` 时这里就红。
        self.assertEqual(
            r.orig_status, 302,
            "orig_status 不是首跳状态码 —— 跳转这件事在数据里就消失了")
        self.assertEqual(len(r.history), 1)
        self.assertTrue(r.url.endswith("/landing"))

    async def test_a_plain_url_reports_its_own_status(self) -> None:
        from core.services.http import HTTPClient

        client = HTTPClient(timeout=10, retries=0)
        try:
            r = await client.fetch(f"{self.base}/landing")
        finally:
            await client.close()

        self.assertEqual(r.status, 200)
        self.assertEqual(r.orig_status, 200, "没跳转时 orig_status 应等于 status")
        self.assertEqual(r.history, [])

