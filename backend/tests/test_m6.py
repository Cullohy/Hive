"""M6 测试: 变更对比 / 导出 / 告警推送 / 周期监控 / 截图。

重点验证五件事:
  1. diff 能正确区分"新增 / 消失 / 变化"
  2. 导出（含 xlsx）内容正确
  3. 钉钉与飞书的签名算法与 ARL 一致（这两家签名最容易写错）
  4. 监控首次运行只建基线、不告警；第二次才推变更
  5. 截图模块在浏览器不可用时**软失败**，而不是把扫描搞挂
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import threading
import time
import unittest
import uuid
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from core.engine.event import Event, EventType
from core.services.diff import ChangeSet, diff_scans
from core.services.export import SHEET_KEYS, collect_assets, to_csv, to_json, to_xlsx
from core.services.notify import (
    DingTalkNotifier,
    EmailNotifier,
    FeishuNotifier,
    NotifyConfig,
    NotifyHub,
    _judge,
    dingtalk_sign,
    feishu_sign,
)
from .pgutil import drop_storage, make_storage
from core.web.manager import ManagedScan, ScanManager
from core.web.scheduler import MonitorScheduler

TEST_TMP_ROOT = Path(__file__).resolve().parents[1] / ".testtmp"

OFFLINE_PRESET = """
name: offline
description: 离线
include:
  - demo_expand
settings:
  max_events: 500
"""


def ev(etype: str, data: str, **tags) -> Event:
    return Event(type=etype, data=data, module="test", tags=tags)


# --------------------------------------------------------------------- 变更对比

class DiffTestCase(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.root = TEST_TMP_ROOT / f"d{uuid.uuid4().hex[:10]}"
        self.root.mkdir(parents=True, exist_ok=True)
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)
        shutil.rmtree(self.root, ignore_errors=True)

    def preset_file(self) -> Path:
        path = self.root / "offline.yml"
        path.write_text(OFFLINE_PRESET, encoding="utf-8")
        return path

    async def seed_old(self) -> int:
        """旧扫描: 含 a/b 两个子域、一个 IP、一个端点、一个技术栈。"""
        scan_id = await self.storage.create_scan(targets=["example.com"], preset="t")
        for event in (
            ev(EventType.SEED, "example.com"),
            ev(EventType.DNS_NAME, "a.example.com", source="brute"),
            ev(EventType.DNS_NAME, "b.example.com", source="brute"),
            ev(EventType.IP_ADDRESS, "1.1.1.1", asn="AS1", org="OldOrg"),
            ev(EventType.OPEN_TCP_PORT, "1.1.1.1:443", ip="1.1.1.1", port=443),
            ev(EventType.HTTP_RESPONSE, "https://a.example.com",
               url="https://a.example.com", domain="a.example.com", ip="1.1.1.1",
               port=443, scheme="https", status=200, title="Hello", server="nginx"),
            ev(EventType.TECHNOLOGY, "Nginx", host="a.example.com", evidence="header:server"),
        ):
            await self.storage.save_event(scan_id, event)
            await self.storage.project(scan_id, event)
        return scan_id

    async def seed_new(self) -> int:
        """新扫描: a 消失、c 新增、IP 归属变了、端点状态码变了、多了一个技术栈。"""
        scan_id = await self.storage.create_scan(targets=["example.com"], preset="t")
        for event in (
            ev(EventType.SEED, "example.com"),
            ev(EventType.DNS_NAME, "b.example.com", source="brute"),
            ev(EventType.DNS_NAME, "c.example.com", source="passive"),
            ev(EventType.IP_ADDRESS, "1.1.1.1", asn="AS1", org="NewOrg"),
            ev(EventType.HTTP_RESPONSE, "https://a.example.com",
               url="https://a.example.com", domain="a.example.com", ip="1.1.1.1",
               port=443, scheme="https", status=403, title="Hello", server="cloudflare"),
            ev(EventType.TECHNOLOGY, "Nginx", host="a.example.com", evidence="header:server"),
            ev(EventType.TECHNOLOGY, "PHP", host="a.example.com", evidence="cookie:PHPSESSID"),
        ):
            await self.storage.save_event(scan_id, event)
            await self.storage.project(scan_id, event)
        return scan_id


class TestDiff(DiffTestCase):
    async def test_added_removed_changed(self) -> None:
        old = await self.seed_old()
        new = await self.seed_new()
        changes = await diff_scans(self.storage, new, old)

        added_domains = {i["key"] for i in changes.added.get("domains", [])}
        removed_domains = {i["key"] for i in changes.removed.get("domains", [])}
        self.assertEqual(added_domains, {"c.example.com"})
        self.assertEqual(removed_domains, {"a.example.com"})

        # IP 归属变化被识别为"变化"而不是"新增+消失"
        ip_change = changes.changed.get("ips", [])
        self.assertEqual(len(ip_change), 1)
        self.assertEqual(ip_change[0]["diff"]["org"]["old"], "OldOrg")
        self.assertEqual(ip_change[0]["diff"]["org"]["new"], "NewOrg")

        # 端点的状态码与 Server 变化
        endpoint_change = changes.changed.get("endpoints", [])
        self.assertEqual(len(endpoint_change), 1)
        self.assertEqual(endpoint_change[0]["diff"]["status"], {"old": 200, "new": 403})

        # 技术栈只新增了 PHP
        self.assertEqual(
            {i["key"] for i in changes.added.get("technologies", [])},
            {"a.example.com|PHP"},
        )

    async def test_first_scan_marks_everything_added(self) -> None:
        new = await self.seed_new()
        changes = await diff_scans(self.storage, new, None)
        self.assertTrue(changes.added)
        self.assertFalse(changes.removed)
        self.assertFalse(changes.changed)
        self.assertIn("首次", changes.to_markdown())

    async def test_markdown_and_roundtrip(self) -> None:
        old = await self.seed_old()
        new = await self.seed_new()
        changes = await diff_scans(self.storage, new, old)

        text = changes.to_markdown()
        self.assertIn("example.com", text)
        self.assertIn("c.example.com", text)

        # to_dict 产出可以再装回 ChangeSet（Web 的 POST /api/monitors/{id}/run 就是这么干的）
        payload = changes.to_dict()
        rebuilt = ChangeSet(
            new_scan_id=payload["new_scan_id"], old_scan_id=payload["old_scan_id"],
            target=payload["target"], added=payload["added"],
            removed=payload["removed"], changed=payload["changed"],
        )
        self.assertEqual(rebuilt.total, changes.total)

    async def test_unknown_scan_raises(self) -> None:
        with self.assertRaises(ValueError):
            await diff_scans(self.storage, 99999, None)


# --------------------------------------------------------------------- 导出

class TestExport(DiffTestCase):
    async def test_export_shapes(self) -> None:
        scan_id = await self.seed_old()
        assets = await collect_assets(self.storage, scan_id)
        row = await self.storage.get_scan(scan_id)
        scan = dict(row)
        scan["scan_id"] = scan_id
        scan["targets"] = json.loads(scan["targets_json"])

        # JSON
        payload = json.loads(to_json(scan, assets))
        self.assertEqual(payload["scan"]["scan_id"], scan_id)
        self.assertEqual(len(payload["assets"]["domains"]), 3)

        # CSV
        text = to_csv(assets, "domains")
        lines = text.strip().splitlines()
        self.assertIn("域名", lines[0])
        self.assertEqual(len(lines), 4)  # 表头 + 3 个域名

        with self.assertRaises(ValueError):
            to_csv(assets, "nope")

        # XLSX
        data = to_xlsx(scan, assets)
        self.assertTrue(data.startswith(b"PK"))  # zip 魔数
        import io

        from openpyxl import load_workbook

        workbook = load_workbook(io.BytesIO(data))
        self.assertIn("概览", workbook.sheetnames)
        self.assertIn("域名", workbook.sheetnames)
        self.assertEqual(workbook["域名"].max_row, 4)

    async def test_all_sheet_keys_exportable(self) -> None:
        scan_id = await self.seed_old()
        assets = await collect_assets(self.storage, scan_id)
        for key in SHEET_KEYS:
            self.assertIsInstance(to_csv(assets, key), str)


# --------------------------------------------------------------------- 告警

class TestSignatures(unittest.TestCase):
    def test_dingtalk_sign_matches_manual_hmac(self) -> None:
        import base64
        import hashlib
        import hmac
        import urllib.parse

        secret = "SEC000abc"
        ts = "1700000000000"
        expected_raw = hmac.new(
            secret.encode(), f"{ts}\n{secret}".encode(), hashlib.sha256
        ).digest()
        expected = urllib.parse.quote_plus(base64.b64encode(expected_raw))
        self.assertEqual(dingtalk_sign(secret, ts), expected)

    def test_feishu_sign_uses_string_as_key_and_empty_message(self) -> None:
        import base64
        import hashlib
        import hmac

        secret = "FS000abc"
        ts = "1700000000"
        expected = base64.b64encode(
            hmac.new(f"{ts}\n{secret}".encode(), b"", hashlib.sha256).digest()
        ).decode()
        self.assertEqual(feishu_sign(secret, ts), expected)

    def test_dingtalk_url_contains_sign_only_with_secret(self) -> None:
        notifier = DingTalkNotifier(None, "tok")  # type: ignore[arg-type]
        self.assertEqual(
            notifier.build_url("1700000000000"),
            "https://oapi.dingtalk.com/robot/send?access_token=tok",
        )
        notifier = DingTalkNotifier(None, "tok", "sec")  # type: ignore[arg-type]
        url = notifier.build_url("1700000000000")
        self.assertIn("timestamp=1700000000000", url)
        self.assertIn("&sign=", url)

    def test_feishu_body_shape(self) -> None:
        notifier = FeishuNotifier(None, "http://x", "sec")  # type: ignore[arg-type]
        body = notifier.build_body("T", "hello", "1700000000")
        self.assertEqual(body["msg_type"], "post")
        self.assertEqual(body["timestamp"], "1700000000")
        self.assertIn("sign", body)
        content = body["content"]["post"]["zh_cn"]
        self.assertEqual(content["title"], "T")
        self.assertEqual(content["content"][0][0]["text"], "hello")


class TestNotifyHub(unittest.IsolatedAsyncioTestCase):
    def test_config_masks_secrets(self) -> None:
        cfg = NotifyConfig(
            enabled=True, webhook_url="http://x", webhook_token="t0ken",
            dingtalk_secret="s3cret", email_password="pw",
        )
        out = cfg.to_dict()
        self.assertNotIn("webhook_token", out)
        self.assertTrue(out["webhook_token_set"])
        self.assertTrue(out["dingtalk_secret_set"])
        self.assertTrue(out["email_password_set"])
        self.assertEqual(out["webhook_url"], "http://x")

    def test_apply_does_not_wipe_secrets_when_absent(self) -> None:
        cfg = NotifyConfig(webhook_url="http://x", webhook_token="keepme")
        cfg.apply({"enabled": True, "min_changes": 3})
        self.assertEqual(cfg.webhook_token, "keepme")
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.min_changes, 3)

    def test_channels(self) -> None:
        self.assertEqual(NotifyConfig().channels(), [])
        cfg = NotifyConfig(
            webhook_url="http://a", dingtalk_access_token="t",
            feishu_webhook="http://b", wxwork_webhook="http://c",
            email_host="smtp", email_to="a@b.c",
        )
        self.assertEqual(cfg.channels(), ["webhook", "dingtalk", "feishu", "wxwork", "email"])

    async def test_broadcast_is_a_noop_when_disabled(self) -> None:
        hub = NotifyHub(NotifyConfig(enabled=False, webhook_url="http://x"))
        self.assertEqual(await hub.broadcast("t", "x"), [])
        await hub.aclose()

    async def test_broadcast_reports_each_channel(self) -> None:
        cfg = NotifyConfig(enabled=True, webhook_url="http://a", wxwork_webhook="http://b")
        hub = NotifyHub(cfg)
        sent: list[str] = []

        class FakeResponse:
            """httpx 形状：``status_code``、同步 ``json()``、``await aclose()``。"""

            status_code = 200

            def json(self):
                return {"errcode": 0}

            async def aclose(self):
                return None

        async def fake_request(self, method, url, **kwargs):
            sent.append(url)
            return FakeResponse()

        with mock.patch("core.services.http.HTTPClient.request", fake_request):
            results = await hub.broadcast("标题", "正文")
        await hub.aclose()

        self.assertEqual(len(results), 2)
        self.assertTrue(all(r["ok"] for r in results))
        self.assertEqual(sorted(sent), ["http://a", "http://b"])


# --------------------------------------------------------------------- 周期监控

class TestMonitorScheduler(DiffTestCase):
    async def _scheduler(self, notify: NotifyHub) -> MonitorScheduler:
        manager = ScanManager(self.storage)
        scheduler = MonitorScheduler(manager, self.storage, notify, tick_seconds=5)
        manager.on_finished = scheduler.on_scan_finished
        return scheduler

    async def _wait(self, manager: ScanManager, scan_id: int, timeout: float = 60.0) -> None:
        deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < deadline:
            record = manager.get(scan_id)
            # finalizing 表示后处理（变更对比/告警）还没做完, 必须继续等
            if record is None or record.is_terminal:
                return
            await asyncio.sleep(0.1)
        raise AssertionError("扫描未在超时内结束")

    async def test_due_monitor_runs_and_builds_baseline_without_alert(self) -> None:
        preset = self.preset_file()
        monitor_id = await self.storage.create_monitor(
            name="m1", targets=["example.com"], preset=str(preset), interval_minutes=1
        )

        notified: list[str] = []

        class SpyHub(NotifyHub):
            async def broadcast(self, title, text, level="info"):
                notified.append(title)
                return []

        hub = SpyHub(NotifyConfig(enabled=True, webhook_url="http://x", min_changes=1))
        scheduler = await self._scheduler(hub)
        manager = scheduler.manager

        started = await scheduler.run_due()
        self.assertEqual(len(started), 1)
        await self._wait(manager, started[0])

        # 基线建立: 有 change 记录, 但**不告警**
        change = await self.storage.change_for_scan(started[0])
        self.assertIsNotNone(change)
        self.assertEqual(notified, [])

        row = await self.storage.get_monitor(monitor_id)
        self.assertEqual(row["last_scan_id"], started[0])
        self.assertIsNotNone(row["next_run_at"])

        # 下一次不再立刻到期
        self.assertEqual(await self.storage.due_monitors(), [])
        await hub.aclose()

    async def test_second_run_alerts_on_changes(self) -> None:
        preset = self.preset_file()
        await self.storage.create_monitor(
            name="m2", targets=["example.com"], preset=str(preset), interval_minutes=1
        )

        notified: list[tuple[str, str]] = []

        class SpyHub(NotifyHub):
            async def broadcast(self, title, text, level="info"):
                notified.append((title, text))
                return [{"channel": "spy", "ok": True, "detail": ""}]

        hub = SpyHub(NotifyConfig(enabled=True, webhook_url="http://x", min_changes=1))
        scheduler = await self._scheduler(hub)
        manager = scheduler.manager

        # 第一次: 建基线
        scan1 = (await scheduler.run_due())[0]
        await self._wait(manager, scan1)
        self.assertEqual(notified, [])

        # 人为往第一次扫描里塞一条资产, 制造"第二次会消失"的差异
        await self.storage.save_event(scan1, ev(EventType.DNS_NAME, "ghost.example.com"))
        await self.storage.project(scan1, ev(EventType.DNS_NAME, "ghost.example.com"))

        # 让监控立刻到期, 跑第二次
        await self.storage.update_monitor(1, next_run_at=None)
        scans = await scheduler.run_due()
        self.assertEqual(len(scans), 1)
        await self._wait(manager, scans[0])

        self.assertEqual(len(notified), 1)
        title, text = notified[0]
        self.assertIn("example.com", title)
        self.assertIn("消失", text)
        self.assertIn("ghost.example.com", text)
        await hub.aclose()

    async def test_run_monitor_now(self) -> None:
        preset = self.preset_file()
        monitor_id = await self.storage.create_monitor(
            name="m3", targets=["example.com"], preset=str(preset)
        )
        hub = NotifyHub(NotifyConfig())
        scheduler = await self._scheduler(hub)
        scan_id = await scheduler.run_monitor_now(monitor_id)
        await self._wait(scheduler.manager, scan_id)
        row = await self.storage.get_monitor(monitor_id)
        self.assertEqual(row["last_run_at"] is not None, True)
        await hub.aclose()

    async def test_trigger_failure_backs_off(self) -> None:
        """并发打满时不该每个 tick 都撞一次。"""
        await self.storage.create_monitor(name="m4", targets=["example.com"], preset="passive")
        hub = NotifyHub(NotifyConfig())
        scheduler = await self._scheduler(hub)
        scheduler.manager.max_concurrent = 0  # 强制触发 RuntimeError

        started = await scheduler.run_due()
        self.assertEqual(started, [])
        row = await self.storage.get_monitor(1)
        self.assertIsNotNone(row["next_run_at"])
        await hub.aclose()


# --------------------------------------------------------------------- 截图

class TestPageTitleSoftFail(unittest.IsolatedAsyncioTestCase):
    """浏览器起不来必须软失败（禁用模块），不能抛错中断整个扫描。

    2026-10-06 截图模块被删、换成只取标题的 ``page_title`` —— 但"起浏览器"
    这件事本身还在，所以这条软失败的性质**完全没变**，跟着换了个对象。
    """

    async def test_setup_soft_fails_without_browser(self) -> None:
        from core.domains.web_hunter.page_title import page_title

        scanner = mock.Mock()
        scanner.log = None
        scanner.settings = {}
        module = page_title(scanner, {})
        module.log = mock.Mock()

        async def boom(self, async_playwright):
            return False, "启动 Chromium 失败: 假装没有浏览器"

        with mock.patch.object(page_title, "_launch", boom):
            result = await module.setup()
        self.assertEqual(result, (None, "启动 Chromium 失败: 假装没有浏览器"))


class TestPageTitleReal(unittest.IsolatedAsyncioTestCase):
    """真跑一次 Playwright 取标题（对着本地 http.server，不依赖外网）。

    重点验证**新增的判据**：静态 ``<title>`` 为空时才会起浏览器。
    2026-10-06 起这个模块是截图模块的替代品 —— SPA 的 ``<title>`` 是空标签、
    真实标题由 JS 写入，不起浏览器就拿不到。
    """

    PORT = 8798

    #: 空 ``<title>`` + 脚本运行时写入 —— 复刻 SPA 站点的真实形态。
    #:
    #: ⚠️ **必须带 ``<meta charset="utf-8">``**。缺了它浏览器会按 latin-1
    #: 解析页面，``document.title`` 取回来就是「ç»Ÿä¸€ç”¨æˆ·ä¸­å¿ƒ」
    #: 这种乱码 —— 那不是代码的锅，是**页面自己**没声明编码。真实站点都带。
    SPA_HTML = (
        "<html><head><meta charset='utf-8'><title></title></head>"
        "<body><div id=app></div>"
        "<script>document.title='统一用户中心';</script></body></html>"
    )
    #: 传统服务端渲染页面的形态：标题本来就在 HTML 里。
    SSR_HTML = "<html><head><title>Shot Page</title></head><body>hi</body></html>"

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.async_api import async_playwright  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("未安装 playwright")
        cls.serve_dir = TEST_TMP_ROOT / "title_site"
        cls.serve_dir.mkdir(parents=True, exist_ok=True)
        (cls.serve_dir / "spa.html").write_text(cls.SPA_HTML, encoding="utf-8")
        (cls.serve_dir / "ssr.html").write_text(cls.SSR_HTML, encoding="utf-8")
        (cls.serve_dir / "index.html").write_text(cls.SSR_HTML, encoding="utf-8")

        class Handler(SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=str(cls.serve_dir), **kwargs)

            def log_message(self, *args):  # 静音
                pass

        cls.httpd = ThreadingHTTPServer(("127.0.0.1", cls.PORT), Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def _module(self):
        """造一个未 ``setup()`` 的模块实例（供只测 handle_event 分支用）。"""
        from core.domains.web_hunter.page_title import page_title

        scanner = mock.Mock()
        scanner.log = None
        scanner.settings = {"settle_ms": 300}
        m = page_title(scanner, {})
        m.log = mock.Mock()
        return m

    async def test_fills_title_for_spa_page(self) -> None:
        """静态标题为空 → 起浏览器 → 把 JS 写的标题补进存储层。"""
        from core.domains.web_hunter.page_title import page_title

        storage = mock.AsyncMock()
        scanner = mock.Mock()
        scanner.storage = storage
        # settle_ms 调小一点让测试快；其余走 setup() 的默认值
        scanner.settings = {"settle_ms": 300}
        m = page_title(scanner, {})
        m.log = mock.Mock()
        # ⚠️ 必须走 setup()：它除了起浏览器还初始化 timeout_ms / body_max 这些
        # _fill() 要用的字段。直接调 _launch 的话那些属性根本没建。
        ok = await m.setup()
        if ok is not True:
            self.skipTest(f"Chromium 不可用: {ok}")
        try:
            url = f"http://127.0.0.1:{self.PORT}/spa.html"
            await m._fill(url)
        finally:
            await m.cleanup()

        storage.fill_endpoint_title.assert_awaited_once()
        args = storage.fill_endpoint_title.await_args[0]
        self.assertEqual(args[0], url)
        self.assertEqual(args[1], "统一用户中心", "没拿到 JS 运行时写入的标题")
        self.assertEqual(m.stats["filled"], 1)

    async def test_skips_when_static_title_already_present(self) -> None:
        """静态标题非空 → **压根不排队**（省掉一次浏览器启动）。"""
        m = self._module()
        event = mock.Mock()
        event.type = "http_response"
        event.data = f"http://127.0.0.1:{self.PORT}/ssr.html"
        event.tags = {"url": event.data, "title": "Shot Page", "host": "x"}
        await m.handle_event(event)
        self.assertEqual(
            m.stats["queued"], 0,
            "静态就有标题还去起浏览器 —— 整个模块省开销的关键就是这条",
        )


class TestResponseProjection(DiffTestCase):
    """响应报文落库（2026-10-06 取代 ``TestScreenshotProjection``）。

    守的性质一样，只是对象从"截图 BLOB + 相对路径"换成"响应报文 + 截断标记"：
      · 报文要真的写进去；
      · ``endpoints()`` **绝不能**把正文带出来（几千个端点 = 几百 MB）；
      · 按"这次扫描看到过"取，不是按"谁最先发现的"；
      · URL 对不上任何端点时静默跳过，不打断链路。
    """

    BODY = "<html><head><title>T</title></head><body>" + "x" * 200 + "</body></html>"
    URL = "http://www.example.com"

    async def _seed(self, *, body: str = None, ctype: str = "text/html") -> int:
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        for event in (
            ev(EventType.DNS_NAME, "www.example.com", source="brute"),
            ev(EventType.IP_ADDRESS, "1.1.1.1"),
            ev(EventType.OPEN_TCP_PORT, "1.1.1.1:80", ip="1.1.1.1", port=80),
            ev(EventType.HTTP_RESPONSE, self.URL, url=self.URL,
               domain="www.example.com", ip="1.1.1.1", port=80, scheme="http",
               status=200, title="T", content_type=ctype,
               body_snippet=self.BODY if body is None else body),
        ):
            await self.storage.save_event(sid, event)
            await self.storage.project(sid, event)
        return sid

    async def test_body_is_written_and_readable(self) -> None:
        """报文写进 ``http_endpoint.body``，且能按 url 取回。"""
        scan_id = await self._seed()

        endpoints = await self.storage.endpoints(scan_id)
        self.assertEqual(len(endpoints), 1)
        self.assertGreater(endpoints[0]["body_size"], 0)
        self.assertFalse(endpoints[0]["body_truncated"])

        got = await self.storage.response_body(scan_id, self.URL)
        self.assertIn("<html>", got["body"])

    async def test_endpoints_never_pull_the_body(self) -> None:
        """``endpoints()`` 的 SQL 里**不能**带 ``body``（只准带长度）。

        上面那条断言测的是"结果里没有"，这条测的是"**压根没去取**"——
        否则一次几千个端点的扫描就是几百 MB 正文涌进 JSON，列表页直接卡死。

        ⚠️ 这条以前因为实现里留着 ``screenshot`` 两个字而失败过；现在换成
        同一原则的**新对象**（body / body_size），别再让它退回去。
        """
        import inspect
        import re as _re

        from core.storage.postgres import PostgresStorage

        src = inspect.getsource(PostgresStorage.endpoints)
        # ⚠️ 先把注释去掉：这个方法为了讲清"为什么不能用 SELECT *"**在注释里
        # 提到了 body**，直接搜源码会把注释也算命中（第一版就这么错的）。
        code = "\n".join(
            ln for ln in src.splitlines() if not ln.strip().startswith("#")
        )
        code = _re.sub(r"#.*$", "", code, flags=_re.M)
        self.assertNotIn("SELECT *", code, "endpoints() 用了 SELECT *")
        # 正文字段名不能出现（只允许 length(body) 这种取长度的写法）
        self.assertNotRegex(code, r"body_truncated\s*=\s*excluded|,\s*body\s*,")
        # 但长度与截断标记必须留着 —— 前端靠它们决定显不显示「查看」按钮
        self.assertIn("body_size", code)
        self.assertIn("body_truncated", code)

    async def test_body_is_scoped_to_the_scan_that_saw_it(self) -> None:
        """报文按"**这次扫描看到过**"取，不是按"谁最先发现的"。

        跨 scan 去重之后 ``http_endpoint.scan_id`` 只是"谁最先发现的"，
        重扫同一目标时资产行留在旧扫描名下。按那个字段查，**新任务取自己的
        报文会 404**（而页面上的链接正是新任务 id）。
        """
        first = await self._seed()
        second = await self._seed()          # 重扫同一个目标

        self.assertIn("<html>", (await self.storage.response_body(first, self.URL))["body"])
        self.assertIn(
            "<html>", (await self.storage.response_body(second, self.URL))["body"],
            "重扫之后新任务取不到自己看到的响应",
        )
        # 没看到过它的扫描取不到（既没 500 也不会串）
        third = await self.storage.create_scan(targets=["other.com"], preset="t")
        self.assertEqual(
            (await self.storage.response_body(third, self.URL))["body"], "",
            "跨扫描串读了",
        )

    async def test_write_for_unknown_url_is_a_noop(self) -> None:
        """URL 对不上任何端点时不能报错、也不能误伤别的行。

        报文是**扫描末尾**并行落盘的，目标端点可能因为超时/被删而不在表里 ——
        那种情况下静默跳过是对的，抛出去会把整条链打断。

        ⚠️ 返回"是否真写进去了"而不是永远 True：UPDATE 命中 0 行也报成功的话，
        调用方无从察觉数据丢了 —— 而那正是它最需要知道的。这里是"什么都没写"，
        所以必须返回 False。
        """
        ok = await self.storage.fill_endpoint_title(
            "http://不存在.example.com/", "标题"
        )
        self.assertFalse(ok, "URL 对不上任何端点时却报成功")

class TestNoiseFindings(DiffTestCase):
    """截图流水账不该出现在"发现"里。

    ## 为什么要单独一组

    截图模块改过设计：现在直接写 ``http_endpoint.screenshot_data``，**不发
    FINDING**。但老版本发过，一条 ``kind='screenshot'``、``detail`` 是
    ``14/9ef6512….png``。这些行留在库里会淹没真正的结论 —— 实测一次
    qq.com 扫描 1,951 条 finding 里 **1,398 条（72%）**是它。

    读侧已经到处排除（见 ``core/storage/postgres.py`` 的 ``_NOISE_KINDS``），
    这里钉的是**五个出口一个都不许漏** —— 加新的读取点时忘了排除，
    用户就会在某个页面又看到一堆 ``screenshot``。
    """

    async def _seed_noise(self) -> int:
        """造一次扫描，同时塞进一条真结论和一条历史遗留的截图 finding。"""
        scan_id = await self.storage.create_scan(targets=["example.com"], preset="t")
        for event in (
            ev(EventType.DNS_NAME, "www.example.com", source="brute"),
            ev(EventType.FINDING, "www.example.com", kind="cdn",
               detail="命中 CDN: 又拍云", severity="info"),
        ):
            await self.storage.save_event(scan_id, event)
            await self.storage.project(scan_id, event)
        # 绕过 ``project()`` 直接塞 —— 现在的代码路径**已经产不出**这种行，
        # 要复现历史数据只能手写（也正因为产不出，这里用底层 SQL）。
        await self.storage.conn.execute(
            "INSERT INTO finding (scan_id, kind, severity, target, detail,"
            " created_at) VALUES (?, 'screenshot', 'info', 'http://www.example.com',"
            " '14/9ef6512da2e2e714.png', ?)",
            (scan_id, "2026-01-01T00:00:00+00:00"),
        )
        return scan_id

    async def test_findings_reader_hides_screenshot(self) -> None:
        scan_id = await self._seed_noise()
        rows = await self.storage.findings(scan_id, limit=1000)
        self.assertEqual(
            [r["kind"] for r in rows], ["cdn"],
            f"findings() 还在返回截图流水账: {rows}",
        )

    async def test_summary_card_matches_the_tab(self) -> None:
        """任务详情页的「发现」卡片读 ``summary()``，页签读 ``findings()``。

        两者口径必须一致 —— 否则卡片写 430、页签列 3 条，
        用户会以为还有 427 条没加载出来。
        """
        scan_id = await self._seed_noise()
        self.assertEqual(
            (await self.storage.summary(scan_id))["findings"],
            len(await self.storage.findings(scan_id, limit=1000)),
        )

    async def test_flat_search_hides_screenshot(self) -> None:
        """资产库那张合并表走 ``search_flat``，是另一个 WHERE 拼装点。"""
        scan_id = await self._seed_noise()
        res = await self.storage.search_flat(
            "example.com", types=["findings"], scan_id=scan_id, live=False,
        )
        self.assertNotIn(
            "screenshot", {r["kind"] for r in res["rows"]},
            f"合并表里还有截图 finding: {res['rows']}",
        )
        self.assertEqual(res["total"], 1, f"total 也没排除: {res['total']}")

    async def test_typed_search_hides_screenshot(self) -> None:
        """``search_assets`` 是第四个拼装点（分类型搜索接口用它）。"""
        scan_id = await self._seed_noise()
        hits = await self.storage.search_assets(
            "example.com", types=["findings"], scan_id=scan_id, live=False,
        )
        self.assertNotIn(
            "screenshot", {r["kind"] for r in hits["findings"]},
            f"分类型搜索里还有截图 finding: {hits}",
        )

    async def test_host_detail_hides_screenshot(self) -> None:
        """抽屉里的「发现」区块走 ``host_detail``，第五个拼装点。"""
        await self._seed_noise()
        detail = await self.storage.host_detail("www.example.com")
        self.assertNotIn(
            "screenshot", {f["kind"] for f in detail["findings"]},
            f"主机详情里还有截图 finding: {detail['findings']}",
        )

    async def test_global_stats_matches_the_table(self) -> None:
        """概览的「发现」数与库里真结论数必须一致。"""
        await self._seed_noise()
        self.assertEqual((await self.storage.global_stats())["findings"], 1)

    async def test_purge_drops_legacy_rows_on_open(self) -> None:
        """``open()`` 自带清理 —— 备份恢复 / 换机器时这些行会回来。"""
        scan_id = await self._seed_noise()
        self.assertEqual(
            await self.storage._purge_noise_findings(), 1,
            "清理没有删掉历史遗留的截图 finding",
        )
        # 再跑一次必须是 0（幂等），否则每次启动都在做无用功
        self.assertEqual(await self.storage._purge_noise_findings(), 0)
        # 真结论一条都不能少
        self.assertEqual(
            [r["kind"] for r in await self.storage.findings(scan_id, limit=10)], ["cdn"],
        )


class TestScanDeleteCascade(DiffTestCase):
    """删任务 = 删掉这次扫描牵出的**全部**数据，不留悬挂引用。

    ## 语义

    「任务是主」：删掉扫描，``domain / ip / port / url / http_endpoint /
    technology`` 里 ``scan_id`` 是它的行、以及 ``event / finding / scan_asset``，
    全部消失。审计日志保留（留痕）。

    ## 真正难的是"没外键的那几张表"

    资产是跨扫描去重的：一个域名被两次扫描都看到，只存**一行**、``scan_id``
    记的是首个发现者。于是删掉首个发现者那次的扫描时，**另一次**扫描在
    ``scan_asset`` 里的关联行会指向已经不存在的资产 —— 而 ``scan_asset``
    自己没被删（它属于那次幸存的扫描）。

    这类引用没有外键，CASCADE 管不到。实测旧实现在真实库上删 #13 会残留
    **348** 条、删 #10 残留 **67** 条悬空的关联记录 —— 症状是资产列表里
    莫名其妙多出几条点开是空的行。
    """

    async def _scan_with_asset(self, name: str = "shared.example.com") -> int:
        """一次扫描：DNS + IP + 端口 + 端点 + URL + 技术栈 + 发现，全套。"""
        scan_id = await self.storage.create_scan(targets=[name], preset="t")
        for event in (
            ev(EventType.DNS_NAME, name, source="brute"),
            ev(EventType.IP_ADDRESS, "1.1.1.1"),
            ev(EventType.OPEN_TCP_PORT, "1.1.1.1:80", ip="1.1.1.1", port=80),
            ev(EventType.HTTP_RESPONSE, f"http://{name}",
               url=f"http://{name}", domain=name, ip="1.1.1.1", port=80,
               scheme="http", status=200, title="T"),
            ev(EventType.URL, f"http://{name}/x", domain=name),
            ev(EventType.TECHNOLOGY, name, name="Nginx"),
            ev(EventType.FINDING, name, kind="cdn", severity="info"),
        ):
            await self.storage.save_event(scan_id, event)
            await self.storage.project(scan_id, event)
        return scan_id

    async def _c(self, sql: str, params=()) -> int:
        cur = self.storage.conn.execute(sql, params)
        return int((await cur.fetchone())[0])

    async def test_assets_owned_by_the_scan_all_disappear(self) -> None:
        scan_id = await self._scan_with_asset()
        self.assertTrue(await self.storage.delete_scan(scan_id))

        for table in ("event", "finding", "domain", "ip", "port", "url",
                      "http_endpoint", "technology", "scan_asset"):
            with self.subTest(table=table):
                self.assertEqual(
                    await self._c(f"SELECT COUNT(*) FROM {table}"), 0,
                    f"{table} 里还有这次扫描的数据",
                )

    async def test_no_orphan_scan_asset_left_behind(self) -> None:
        """**别的扫描**对共享资产的关联行必须一起清掉。

        两次扫描都看到 shared.example.com，它只存一行、``scan_id`` 记第一次。
        删掉第一次之后，第二次的那条关联行不能变成指向空气的孤儿。
        """
        first = await self._scan_with_asset()
        second = await self.storage.create_scan(targets=["other"], preset="t")
        again = ev(EventType.DNS_NAME, "shared.example.com", source="brute")
        await self.storage.save_event(second, again)
        await self.storage.project(second, again)

        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM scan_asset WHERE scan_id = ?",
                          (second,)), 1,
            "前提：第二次扫描确实也关联到了这个域名",
        )

        await self.storage.delete_scan(first)

        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM scan_asset"), 0,
            "共享资产的关联行没跟着清 —— 留下了指向已删资产的孤儿记录",
        )
        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM domain"), 0,
            "共享域名应该随首个发现者那次扫描一起删（任务是主）",
        )

    async def test_asset_group_entries_are_cleaned(self) -> None:
        """删掉被组引用的任务时，组内条目必须跟着收敛，分组本身留下。

        ``asset_group_asset`` 存的是资产字面量、不引各资产表的 id，所以外键
        管不到它；而组成员资格现在由 ``asset_group_scan`` 决定，那上面有
        ``scan_id`` 的 CASCADE —— 关联行会自己消失，但**组内那批资产行不会**。

        以前这里是按 ``domain`` / ``ip`` 两种类型逐个 DELETE（跟着资产行的
        ``scan_id`` 反查）。范围改成"按任务"之后有两个问题：一是组内类型已经
        有七种，枚举永远漏；二是"这条资产属于哪个组"由**被关联的任务**决定，
        而不是资产自己那行的 ``scan_id``。现在改成删完扫描直接重算受影响的组。
        """
        scan_id = await self._scan_with_asset()
        gid = await self.storage.create_group(name="g1", description="")
        await self.storage.set_group_scans(gid, [scan_id])
        before = await self._c("SELECT COUNT(*) FROM asset_group_asset")
        self.assertGreater(
            before, 0, "前提：同步确实把资产收进了组",
        )

        await self.storage.delete_scan(scan_id)

        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM asset_group_asset"), 0,
            f"分组里留下了 {before} 条指向已删任务的条目 —— 没有任何东西会再去同步这个组",
        )
        # 分组本身与其余任务是长期配置，不该因为删任务而消失
        self.assertEqual(await self._c("SELECT COUNT(*) FROM asset_group"), 1)
        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM asset_group_scan"), 0,
            "任务关联行没被清掉 —— FK 的 CASCADE 没生效",
        )

    async def test_monitor_baseline_and_change_history_are_cleaned(self) -> None:
        """``change`` / ``monitor.last_scan_id`` 是裸 BIGINT，没有外键。"""
        scan_id = await self._scan_with_asset()
        mid = await self.storage.create_monitor(
            name="m1", targets=["example.com"], preset="t",
        )
        await self.storage.conn.execute(
            "UPDATE monitor SET last_scan_id = ? WHERE id = ?", (scan_id, mid)
        )
        await self.storage.conn.execute(
            "INSERT INTO change (monitor_id, old_scan_id, new_scan_id, target,"
            " total, created_at) VALUES (?, NULL, ?, 'example.com', 3, '2026-01-01')",
            (mid, scan_id),
        )

        await self.storage.delete_scan(scan_id)

        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM monitor WHERE last_scan_id = ?",
                          (scan_id,)),
            0, "monitor 还指着已删的扫描当基线",
        )
        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM monitor"), 1, "监控本身不该被删")
        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM change"), 0,
            "拿已删扫描当基线的变更记录没清掉",
        )

    async def test_audit_log_is_kept(self) -> None:
        """审计是留痕，不该因为删任务而消失（schema 里是 ON DELETE SET NULL）。"""
        scan_id = await self._scan_with_asset()
        await self.storage.record_audit(
            action="scan_start", actor="web", target="example.com",
            scan_id=scan_id,
        )
        await self.storage.delete_scan(scan_id)
        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM audit"), 1,
            "删任务把审计日志也删了 —— 留痕就没了",
        )
        # scan_id 置空而不是留下悬空引用
        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM audit WHERE scan_id IS NOT NULL"), 0)


class TestEnvironmentGuards(unittest.TestCase):
    """两个被真实环境咬过的坑, 各留一个回归测试。"""

    def test_logging_level_is_updatable(self) -> None:
        """任何模块 import 时取 logger, 都不能把调用方设的 DEBUG 冲回 INFO。

        早先 `setup_logging` 是"首次调用即定稿", 而 `core/state.py` 在 import
        时就取了 logger —— 结果 `-v/--verbose` 完全失效, 连排查用的 debug 日志
        也一起被吞掉。
        """
        import logging

        from core.engine.log import get_logger, setup_logging

        get_logger("early")              # 模拟 import 期提前取 logger
        setup_logging("DEBUG")
        root = logging.getLogger("recon")
        self.assertEqual(root.level, logging.DEBUG)
        self.assertEqual(root.handlers[0].level, logging.DEBUG)
        self.assertTrue(get_logger("t").isEnabledFor(logging.DEBUG))

        # 再调一次应当降到 INFO, 而不是被忽略
        setup_logging("INFO")
        self.assertEqual(root.handlers[0].level, logging.INFO)
        self.assertFalse(get_logger("t").isEnabledFor(logging.DEBUG))

        setup_logging("INFO")  # 复原, 免得影响后面的测试输出

    def test_mimetypes_get_corrected(self) -> None:
        """Windows 注册表可能把 .png 映射成 silenteye/png, Playwright 会因此拒拍。"""
        import mimetypes

        import core
        from core.util.mime import CANONICAL, fix_common_mimetypes

        fix_common_mimetypes()  # 幂等
        for ext, expected in CANONICAL.items():
            got, _ = mimetypes.guess_type("x" + ext)
            self.assertEqual(got, expected, f"{ext} 的 MIME 没有被纠正")
        self.assertIsInstance(core._MIME_FIXES, list)


class TestNotifyFlagCoercion(unittest.TestCase):
    """告警开关**认得 "false" 这一类写法**。

    ## 这是一条会外发数据的闸门

    ``SettingsRequest.notify`` 声明成 ``dict[str, Any]``，Pydantic 不做任何
    转换，**字符串原样送到** ``NotifyConfig.apply``。而：

        bool("false")  ->  True        # 非空字符串一律真

    于是用户关掉告警，实际照发 —— 内网域名 / URL 被推到外部钉钉 / 飞书 / 企微。
    这与 ``util/coerce.py`` 模块文档里记的那个"安全闸门反转"是同一个形状，
    当时全仓 32 处都改成了 ``as_bool``，唯独这里漏了。
    """

    def _cfg(self) -> NotifyConfig:
        return NotifyConfig(enabled=True, webhook_url="http://x")

    def test_apply_string_false_turns_it_off(self) -> None:
        cfg = self._cfg()
        cfg.apply({"enabled": "false"})
        self.assertFalse(cfg.enabled, '"false" 被当成了真 —— 告警关不掉')

    def test_apply_string_true_turns_it_on(self) -> None:
        cfg = NotifyConfig(enabled=False, webhook_url="http://x")
        cfg.apply({"enabled": "true"})
        self.assertTrue(cfg.enabled)

    def test_apply_recognises_the_usual_spellings(self) -> None:
        for value, expected in [
            ("false", False), ("False", False), ("FALSE", False),
            ("0", False), ("off", False), ("no", False), ("否", False), ("关", False),
            ("", False),
            ("true", True), ("1", True), ("on", True), ("yes", True),
            ("是", True), ("开", True),
        ]:
            with self.subTest(value=value):
                cfg = self._cfg()
                cfg.apply({"enabled": value})
                self.assertIs(cfg.enabled, expected, f"{value!r} 判成了 {cfg.enabled}")

    def test_apply_real_bool_is_untouched(self) -> None:
        for value in (True, False):
            with self.subTest(value=value):
                cfg = self._cfg()
                cfg.apply({"enabled": value})
                self.assertIs(cfg.enabled, value)

    def test_unrecognised_keeps_old_value_and_warns(self) -> None:
        """认不出来时保持原值**并记一条告警**。

        纯静默地保持旧值，症状就是"界面上把开关关掉，它纹丝不动"且毫无线索。
        """
        cfg = self._cfg()
        with self.assertLogs("recon.notify", level="WARNING") as caught:
            cfg.apply({"enabled": "flase"})
        self.assertTrue(cfg.enabled)
        self.assertTrue(
            any("enabled" in line for line in caught.output),
            f"没有告警日志，用户无从知道为什么开关没反应：{caught.output}",
        )

    def test_from_dict_reads_string_false(self) -> None:
        """手改 ``settings.json`` 写成 ``"false"``（带引号）同样要认得。"""
        cfg = NotifyConfig.from_dict({"enabled": "false", "webhook_url": "http://x"})
        self.assertFalse(cfg.enabled)

    def test_disabled_config_really_blocks_broadcast(self) -> None:
        """端到端：关掉之后 broadcast 必须是空操作，不能只是"看起来关了"。"""
        async def go() -> list:
            hub = NotifyHub(self._cfg())
            hub.config.apply({"enabled": "false"})
            try:
                return await hub.broadcast("t", "x")
            finally:
                await hub.aclose()

        self.assertEqual(asyncio.run(go()), [])


class _FakeRecord:
    """``running_count`` / ``stop`` / ``shutdown`` 只碰这几个属性。"""

    def __init__(self, status: str, task: "asyncio.Task | None" = None) -> None:
        self.status = status
        self.task = task
        self.actor = "test"
        self.targets = ["example.com"]
        self.mode = "passive"
        self.elapsed = 0.0
        self.scan_id = 1


class TestFinalizingHoldsConcurrencySlot(unittest.IsolatedAsyncioTestCase):
    """``finalizing`` 阶段的扫描**仍然占着并发额度**。

    ``finalizing`` 是"扫描本体已结束、正在做变更对比与告警推送"这段。
    曾经 ``running_count`` 只数 ``running``，于是这段时间里额度被提前释放 ——
    而 ``manager.py`` 自己的注释写过"一旦被改成非 running，这条僵尸任务就不再
    占并发额度"，``finalizing`` 正是为了避免调用方读到半成品才加的状态，
    却把同一个洞重新引了回来。后果是 ``max_concurrent=2`` 实际能跑 3 条，
    对目标的并发发包翻倍。
    """

    def _manager(self) -> ScanManager:
        mgr = ScanManager(mock.MagicMock(), max_concurrent=2, stop_grace=0.05)
        mgr._scans = {
            1: _FakeRecord("running"),
            2: _FakeRecord("finalizing"),
            3: _FakeRecord("finished"),
        }
        return mgr

    def test_finalizing_is_counted(self) -> None:
        self.assertEqual(self._manager().running_count, 2,
                         "running + finalizing 都该占额度，终态不占")

    def test_terminal_states_are_not_counted(self) -> None:
        mgr = ScanManager(mock.MagicMock(), max_concurrent=2)
        for status in ("finished", "error", "stopped"):
            with self.subTest(status=status):
                mgr._scans = {1: _FakeRecord(status)}
                self.assertEqual(mgr.running_count, 0)

    def test_occupying_is_exactly_the_non_terminal_set(self) -> None:
        """别让 OCCUPYING 悄悄和 TERMINAL 对不上：占额度的必须是**非终态**。"""
        self.assertEqual(set(ManagedScan.OCCUPYING), {"running", "finalizing"})
        self.assertFalse(
            set(ManagedScan.OCCUPYING) & set(ManagedScan.TERMINAL),
            "终态不该占并发额度",
        )

    async def test_concurrency_gate_rejects_while_finalizing(self) -> None:
        """额度被占满时，即使在收尾也要挡住新任务。"""
        mgr = ScanManager(mock.MagicMock(), max_concurrent=2, stop_grace=0.05)
        mgr._scans = {1: _FakeRecord("running"), 2: _FakeRecord("finalizing")}
        with self.assertRaises(RuntimeError):
            await mgr.start(targets=["example.com"], name="第三个")

    async def test_stop_works_on_a_finalizing_scan(self) -> None:
        """收尾中的扫描也要能停 —— 它在推告警，正是用户想停的东西。

        曾经用 ``status != "running"`` 把这个状态挡在外面，于是点"停止"返回
        False、界面毫无反应，而任务还在往外发。
        """
        mgr = ScanManager(mock.MagicMock(), max_concurrent=2, stop_grace=0.05)
        mgr.storage.record_audit = mock.AsyncMock()
        task = asyncio.create_task(asyncio.sleep(30))
        await asyncio.sleep(0)  # 让它真正起来
        mgr._scans = {7: _FakeRecord("finalizing", task)}

        self.assertTrue(await mgr.stop(7), "finalizing 的扫描必须能停")
        self.assertTrue(task.cancelled() or task.done())

    async def test_shutdown_cancels_finalizing_tasks(self) -> None:
        """关服时收尾中的扫描也要被 cancel + await，不能带着在途推送退出。"""
        mgr = ScanManager(mock.MagicMock(), max_concurrent=2, stop_grace=0.5)
        tasks = [asyncio.create_task(asyncio.sleep(30)) for _ in range(3)]
        await asyncio.sleep(0)
        mgr._scans = {
            1: _FakeRecord("running", tasks[0]),
            2: _FakeRecord("finalizing", tasks[1]),   # 以前会被漏掉
            3: _FakeRecord("finished", tasks[2]),    # 终态不该动
        }
        await mgr.shutdown()
        self.assertTrue(tasks[0].done(), "running 应被 cancel")
        self.assertTrue(tasks[1].done(), "finalizing 也必须被 cancel")
        self.assertFalse(tasks[2].done(), "终态的 task 不该被动")


class TestDeliveryConfirmation(unittest.IsolatedAsyncioTestCase):
    """**"送到了"必须有依据**，判不出来就说判不出来。

    审计发现：投递结果有三条宽松出口，出口网关 / 公司代理 / 验证码拦截返回的
    「200 + HTML 登录页」会被判成**已送达**。而 ``broadcast`` 只在失败时记
    日志 —— 报成"送到了"就一个字都不留，这条变更告警静默丢失。
    """

    def test_judge_rejects_non_dict_payload(self) -> None:
        for payload in ("<html>登录</html>", ["a"], None, 200, ""):
            with self.subTest(payload=payload):
                ok, detail = _judge(payload)
                self.assertFalse(ok, f"{payload!r} 被判成送达了")
                self.assertTrue(detail, "判不出来必须给出原因")

    def test_judge_rejects_payload_without_a_verdict_field(self) -> None:
        ok, detail = _judge({"html": "<html>请登录</html>", "title": "拦截"})
        self.assertFalse(ok, "没有任何判据字段却判成送达")
        self.assertIn("判据字段", detail)

    def test_judge_still_accepts_a_real_verdict(self) -> None:
        for payload, ok in [
            ({"errcode": 0}, True), ({"errcode": 40001}, False),
            ({"code": 0}, True), ({"code": 1}, False),
            ({"StatusCode": 0}, True), ({"status": "success"}, True),
            ({"status": "error"}, False),
        ]:
            with self.subTest(payload=payload):
                self.assertIs(_judge(payload)[0], ok)

    async def _webhook(self) -> tuple[bool, str]:
        """只配一个通用 webhook 渠道，跑一次 broadcast。"""
        hub = NotifyHub(NotifyConfig(enabled=True, webhook_url="http://x"))
        try:
            results = await hub.broadcast("t", "x")
        finally:
            await hub.aclose()
        return bool(results[0]["ok"]), results[0]["detail"]

    def _patch_response(self, status: int, content_type: str, body_raises: bool = True):
        """把 HTTPClient.request 换掉 —— **测试绝不能出网**。

        （曾经这条用例没打桩，带着假 token 真发到钉钉，拿到
        ``errcode=300005 token is not exist`` 才发现。）
        """
        class Resp:
            def __init__(self) -> None:
                self.status_code = status
                self.headers = {"content-type": content_type}

            def json(self):
                if body_raises:
                    raise ValueError("not json")
                return {"errcode": 0}

            async def aclose(self):
                return None

        async def fake_request(self, method, url, **kwargs):
            return Resp()

        return mock.patch("core.services.http.HTTPClient.request", fake_request)

    def _patch_webhook_response(self, status: int, content_type: str) -> None:
        self._patcher = self._patch_response(status, content_type).start()
        self.addCleanup(mock.patch.stopall)

    async def test_generic_webhook_html_response_is_not_delivered(self) -> None:
        """200 + HTML —— 那是代理/网关的登录页，请求压根没到接收方。"""
        self._patch_webhook_response(200, "text/html; charset=utf-8")
        ok, detail = await self._webhook()
        self.assertFalse(ok, "HTML 响应被判成已送达")
        self.assertIn("HTML", detail)

    async def test_generic_webhook_json_response_is_delivered(self) -> None:
        self._patch_webhook_response(200, "application/json")
        ok, _ = await self._webhook()
        self.assertTrue(ok, "2xx + 非 HTML 仍应判为送达")

    async def test_generic_webhook_error_status_is_not_delivered(self) -> None:
        self._patch_webhook_response(502, "application/json")
        ok, detail = await self._webhook()
        self.assertFalse(ok)
        self.assertIn("502", detail)

    async def test_unparseable_body_is_not_delivered_even_on_200(self) -> None:
        """``resp.json()`` 抛异常时，**不能**退回"看状态码"。

        走到那里说明正文没读到或不是 JSON：可能是响应体中途断了（对方根本没
        收到完整请求），也可能是拦截页。
        """
        hub = NotifyHub(NotifyConfig(
            enabled=True, dingtalk_access_token="t", dingtalk_secret="s",
        ))
        with self._patch_response(200, "text/html"):
            try:
                results = await hub.broadcast("t", "x")
            finally:
                await hub.aclose()
        ding = next(r for r in results if r["channel"] == "dingtalk")
        self.assertFalse(
            ding["ok"],
            f"返回体解析失败却按状态码报了送达：{ding}",
        )
        self.assertIn("无法解析", ding["detail"])

    async def test_email_has_a_total_timeout(self) -> None:
        """``smtplib`` 的 ``timeout=15`` 是**每个 socket 操作**的上限。

        connect + login + send 三段最坏 ~45 秒，而 ``SMTP()`` 构造时的 DNS
        解析不受它约束。足够多的监控同时告警就能把默认 executor 抽干。
        """
        notifier = EmailNotifier("h", 25, "u", "p", "a@b.c")
        self.assertGreater(EmailNotifier.SEND_TIMEOUT, 15,
                           "总超时必须大于单次 socket 超时，否则没有意义")

        original = notifier._send_sync

        def slow(title, text):
            time.sleep(5)
            return original(title, text)

        notifier._send_sync = slow
        old_timeout = EmailNotifier.SEND_TIMEOUT
        EmailNotifier.SEND_TIMEOUT = 0.2
        try:
            ok, detail = await notifier.send("t", "x")
        finally:
            EmailNotifier.SEND_TIMEOUT = old_timeout

        self.assertFalse(ok, "超过总超时却报成功")
        self.assertIn("未完成", detail)


class TestAdmissionAndCleanup(DiffTestCase):
    """两处「时序」问题：并发闸门的 TOCTOU 与重复 cancel 跳过清理。"""

    async def _manager(self, max_concurrent: int) -> ScanManager:
        return ScanManager(self.storage, max_concurrent=max_concurrent,
                           stop_grace=0.05)

    async def test_concurrent_starts_cannot_exceed_max(self) -> None:
        """并发下发时，**实际跑起来的条数**不能超过 ``max_concurrent``。

        曾经「并发检查」与「写进 ``self._scans``」之间隔着 ``create_scan``
        （DB 往返）与 ``load_modules``（读盘）两个 await —— 典型的 TOCTOU。
        三个请求一起进来时，它们都在对方登记之前通过了检查，
        ``max_concurrent=1`` 于是真跑出 3 条。
        """
        mgr = await self._manager(1)
        preset = str(self.preset_file())

        async def one(i: int):
            try:
                return await mgr.start(
                    targets=["example.com"], name=f"n{i}", preset_name=preset,
                )
            except RuntimeError:
                return None

        results = await asyncio.gather(*(one(i) for i in range(3)))
        started = [r for r in results if r is not None]

        self.assertEqual(
            len(started), 1,
            f"max_concurrent=1 却启动了 {len(started)} 条 —— 检查与登记之间有缝",
        )
        self.assertEqual(mgr.running_count, 1)

        for rec in started:
            rec.task.cancel()
        await asyncio.gather(
            *(r.task for r in started if r.task), return_exceptions=True
        )


if __name__ == "__main__":
    unittest.main()
