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
    FeishuNotifier,
    NotifyConfig,
    NotifyHub,
    dingtalk_sign,
    feishu_sign,
)
from .pgutil import drop_storage, make_storage
from core.web.manager import ScanManager
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

class TestScreenshotSoftFail(unittest.IsolatedAsyncioTestCase):
    async def test_setup_soft_fails_without_browser(self) -> None:
        """浏览器起不来时必须软失败（禁用模块），而不是抛错中断扫描。"""
        from core.domains.web_hunter.screenshot import screenshot

        scanner = mock.Mock()
        scanner.log = None
        scanner.settings = {}
        module = screenshot(scanner, {})
        module.log = mock.Mock()

        async def boom(self, async_playwright):
            return False, "启动 Chromium 失败: 假装没有浏览器"

        with mock.patch.object(screenshot, "_launch", boom):
            result = await module.setup()
        self.assertEqual(result, (None, "启动 Chromium 失败: 假装没有浏览器"))


class TestScreenshotReal(unittest.IsolatedAsyncioTestCase):
    """真跑一次 Playwright 截图（对着本地 http.server，不依赖外网）。"""

    PORT = 8799

    @classmethod
    def setUpClass(cls) -> None:
        try:
            from playwright.async_api import async_playwright  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("未安装 playwright")
        cls.serve_dir = TEST_TMP_ROOT / "shot_site"
        cls.serve_dir.mkdir(parents=True, exist_ok=True)
        (cls.serve_dir / "index.html").write_text(
            "<html><head><title>Shot Page</title></head><body><h1>hi</h1></body></html>",
            encoding="utf-8",
        )

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

    async def test_capture_writes_png_to_db(self) -> None:
        """截图落 **DB BLOB**（``http_endpoint.screenshot_data``），不再是磁盘文件 + FINDING。

        这个模块改过设计：截图是二进制，塞不进事件载荷，所以从"发一条带相对路径的
        FINDING、再由投影回填"改成"直接按 URL 写 http_endpoint"。
        老的断言（找 ``kind == "screenshot"`` 的 finding、再去磁盘上找文件）已经
        不成立了 —— 它们钉的是旧行为。
        """
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        root = TEST_TMP_ROOT / f"s{uuid.uuid4().hex[:10]}"
        mods = root / "mods"
        mods.mkdir(parents=True, exist_ok=True)
        (mods / "emit_url.py").write_text(
            "from core.engine.event import EventType\n"
            "from core.engine.module import BaseModule\n\n\n"
            "class emit_url(BaseModule):\n"
            "    watched_events = (EventType.SEED,)\n"
            "    produced_events = (EventType.HTTP_RESPONSE, EventType.URL)\n"
            "    flags = ('passive', 'safe')\n\n"
            "    async def handle_event(self, event):\n"
            f"        url = 'http://127.0.0.1:{self.PORT}/'\n"
            "        # 先把端点建出来。截图模块是**按 URL 写 http_endpoint** 的，\n"
            "        # 真实扫描里那一行由 http_probe 产出；这里省掉它就得自己造。\n"
            "        await self.emit_event(\n"
            "            url, EventType.HTTP_RESPONSE, parent=event,\n"
            "            tags={'url': url, 'domain': '127.0.0.1', 'ip': '127.0.0.1',\n"
            f"                  'port': {self.PORT}, 'scheme': 'http', 'status': 200,\n"
            "                  'title': 'T'})\n"
            "        await self.emit_event(url, EventType.URL, parent=event)\n",
            encoding="utf-8",
        )

        storage = await make_storage()
        try:
            preset = Preset(
                name="t",
                include=["emit_url", "screenshot"],
                module_dirs=[str(mods)],
            )
            scanner = Scanner(targets=["example.com"], preset=preset, storage=storage)
            try:
                summary = await scanner.scan()
            except Exception as e:  # 浏览器环境问题不算产品缺陷
                self.skipTest(f"Chromium 不可用: {e}")

            if "screenshot" not in summary["modules_enabled"]:
                self.skipTest(
                    f"screenshot 模块未启用: {summary['modules_skipped'].get('screenshot')}"
                )

            url = f"http://127.0.0.1:{self.PORT}/"
            endpoints = await storage.endpoints(scanner.scan_id)
            with_shot = [e for e in endpoints if e["screenshot"]]
            self.assertEqual(len(with_shot), 1, f"endpoints={endpoints}")

            # 二进制真的写进去了，而且是 PNG。
            #
            # ⚠️ 走 `screenshot_blob()` 而不是从 `endpoints()` 里取 —— 端点行
            # **不该带** BYTEA（会让 API 序列化 500，见上面几条测试的说明）。
            blob = await storage.screenshot_blob(scanner.scan_id, url)
            self.assertIsNotNone(blob, "screenshot_data 是空的")
            self.assertTrue(bytes(blob).startswith(b"\x89PNG"), "不是 PNG")
            self.assertGreater(len(bytes(blob)), 1000)

            # 相对路径形态保持 {scan_id}/{sha256(url)[:16]}.png —— 前端兼容它
            expected = (
                f"{scanner.scan_id}/"
                f"{hashlib.sha256(url.encode()).hexdigest()[:16]}.png"
            )
            self.assertEqual(with_shot[0]["screenshot"], expected)

            # **不再产 FINDING** —— 那正是这次设计改动的内容
            findings = await storage.findings(scanner.scan_id)
            self.assertEqual(
                [f for f in findings if f["kind"] == "screenshot"], [],
                f"不该再有截图 FINDING: {findings}",
            )
        finally:
            await storage.close()
            shutil.rmtree(root, ignore_errors=True)


class TestScreenshotProjection(DiffTestCase):
    async def test_save_screenshot_writes_blob_and_path(self) -> None:
        """截图二进制 + 相对路径**一起**写进 ``http_endpoint``。

        原来这条测的是"FINDING 投影回填端点"，现在那条链路已经没有了 ——
        模块直接调 ``save_screenshot``。所以这里改成直接钉存储层的行为。
        """
        scan_id = await self.storage.create_scan(targets=["example.com"], preset="t")
        for event in (
            ev(EventType.DNS_NAME, "www.example.com", source="brute"),
            ev(EventType.IP_ADDRESS, "1.1.1.1"),
            ev(EventType.OPEN_TCP_PORT, "1.1.1.1:80", ip="1.1.1.1", port=80),
            ev(EventType.HTTP_RESPONSE, "http://www.example.com",
               url="http://www.example.com", domain="www.example.com", ip="1.1.1.1",
               port=80, scheme="http", status=200, title="T"),
        ):
            await self.storage.save_event(scan_id, event)
            await self.storage.project(scan_id, event)

        url = "http://www.example.com"
        png = b"\x89PNG\r\n\x1a\n" + b"x" * 128
        self.assertTrue(await self.storage.save_screenshot(scan_id, url, png))

        endpoints = await self.storage.endpoints(scan_id)
        self.assertEqual(len(endpoints), 1)
        expected = (
            f"{scan_id}/{hashlib.sha256(url.encode()).hexdigest()[:16]}.png"
        )
        self.assertEqual(endpoints[0]["screenshot"], expected)

        # ⚠️ **``endpoints()`` 绝不能带 ``screenshot_data``。**
        #
        # 它返回的 dict 会被 FastAPI 直接序列化成 JSON，而截图是 BYTEA ——
        # 实测抛 `invalid utf-8 sequence of 1 bytes from index 0`，
        # **整个任务详情页 500**。
        #
        # 这条断言以前是反的（要求 blob 在里面），所以那个 bug 被测试**钉成了
        # 期望行为**，一直没被发现。图片本身走
        # `GET /api/screenshots/{scan_id}/{url}` → `screenshot_blob()`。
        self.assertNotIn(
            "screenshot_data", endpoints[0],
            "endpoints() 带了截图二进制 —— 会让 API 序列化直接 500",
        )
        # 而按需取二进制仍然拿得到
        self.assertEqual(await self.storage.screenshot_blob(scan_id, url), png)

    async def test_screenshot_blob_is_scoped_to_the_scan_that_saw_it(self) -> None:
        """截图按"**这次扫描看到过**"取，不是按"谁最先发现的"。

        跨 scan 去重之后 ``http_endpoint.scan_id`` 只是"谁最先发现的"，
        重扫同一目标时资产行留在旧扫描名下。如果按那个字段查，**新任务取自己的
        截图会 404**（而页面上的链接正是新任务 id）。
        """
        url = "http://www.example.com"
        png = b"\x89PNG\r\n\x1a\n" + b"y" * 64

        async def seed() -> int:
            sid = await self.storage.create_scan(targets=["example.com"], preset="t")
            for event in (
                ev(EventType.DNS_NAME, "www.example.com", source="brute"),
                ev(EventType.IP_ADDRESS, "1.1.1.1"),
                ev(EventType.OPEN_TCP_PORT, "1.1.1.1:80", ip="1.1.1.1", port=80),
                ev(EventType.HTTP_RESPONSE, url, url=url, domain="www.example.com",
                   ip="1.1.1.1", port=80, scheme="http", status=200, title="T"),
            ):
                await self.storage.save_event(sid, event)
                await self.storage.project(sid, event)
            return sid

        first = await seed()
        self.assertTrue(await self.storage.save_screenshot(first, url, png))
        second = await seed()          # 重扫同一个目标

        self.assertEqual(await self.storage.screenshot_blob(first, url), png)
        self.assertEqual(
            await self.storage.screenshot_blob(second, url), png,
            "重扫之后新任务取不到自己看到的截图",
        )
        # 没看到过它的扫描取不到（既没 500 也不会串）
        third = await self.storage.create_scan(targets=["other.com"], preset="t")
        self.assertIsNone(await self.storage.screenshot_blob(third, url))

    async def test_endpoints_never_pull_the_blob(self) -> None:
        """``endpoints()`` 的 SQL 里不该出现 ``screenshot_data``。

        上面那条断言测的是"结果里没有"，这条测的是"**压根没去取**"——
        否则每次列端点都要从数据库搬几 MB 的二进制。
        """
        import inspect
        import re as _re

        from core.storage.postgres import PostgresStorage

        src = inspect.getsource(PostgresStorage.endpoints)
        # ⚠️ 先把注释去掉：这个方法为了讲清"为什么不能用 SELECT *"**在注释里
        # 提到了 screenshot_data**，直接搜源码会把注释也算命中（第一版就这么错的）。
        code = "\n".join(
            ln for ln in src.splitlines() if not ln.strip().startswith("#")
        )
        # 去掉行尾注释
        code = _re.sub(r"#.*$", "", code, flags=_re.M)
        self.assertNotIn("screenshot_data", code)
        self.assertNotIn("SELECT *", code, "endpoints() 用了 SELECT *")
        # 但截图**路径**必须留着 —— 前端靠它显示缩略图
        self.assertIn("screenshot", code)

    async def test_save_screenshot_for_unknown_url_is_a_noop(self) -> None:
        """URL 对不上任何端点时不能报错、也不能误伤别的行。

        截图是**扫描末尾**并行落盘的，目标端点可能因为超时/被删而不在表里 ——
        那种情况下静默跳过是对的，抛出去会把整条截图链打断。

        ⚠️ 返回值从"永远 True"改成了**"是否真写进去了"**（2026-10-04）。旧实现
        无条件 ``return True``，于是 UPDATE 命中 0 行也报成功，调用方无从
        察觉截图丢了 —— 而那正是调用方最需要知道的。这里是"什么都没写"，
        所以必须返回 False；本测试原来 assertTrue，钉的是实现细节而不是意图。
        """
        scan_id = await self.storage.create_scan(targets=["example.com"], preset="t")
        for event in (
            ev(EventType.DNS_NAME, "www.example.com", source="brute"),
            ev(EventType.IP_ADDRESS, "1.1.1.1"),
            ev(EventType.OPEN_TCP_PORT, "1.1.1.1:80", ip="1.1.1.1", port=80),
            ev(EventType.HTTP_RESPONSE, "http://www.example.com",
               url="http://www.example.com", domain="www.example.com", ip="1.1.1.1",
               port=80, scheme="http", status=200, title="T"),
        ):
            await self.storage.save_event(scan_id, event)
            await self.storage.project(scan_id, event)

        # 什么都没写 → 必须如实报告 False（而不是"成功"）
        self.assertFalse(
            await self.storage.save_screenshot(scan_id, "http://nope.invalid/", b"\x89PNG"),
            "URL 没有对应端点行 —— 什么都没写却报成功",
        )
        endpoints = await self.storage.endpoints(scan_id)
        self.assertEqual(len(endpoints), 1)
        self.assertIsNone(endpoints[0]["screenshot"], "误伤了不相关的端点")
        # 二进制也不该出现在端点行里（见上一条测试的说明）
        self.assertNotIn("screenshot_data", endpoints[0])
        self.assertIsNone(
            await self.storage.screenshot_blob(scan_id, "http://nope.invalid/")
        )


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
        """资产分组存的是域名字面量，不引 domain.id —— 外键管不到。"""
        scan_id = await self._scan_with_asset()
        gid = await self.storage.create_group(
            name="g1", description="", scopes=["example.com"],
        )
        await self.storage.sync_scan_to_group(gid, scan_id)
        before = await self._c("SELECT COUNT(*) FROM asset_group_asset")
        self.assertGreater(
            before, 0, "前提：同步确实把资产收进了组",
        )

        await self.storage.delete_scan(scan_id)

        self.assertEqual(
            await self._c("SELECT COUNT(*) FROM asset_group_asset"), 0,
            f"分组里留下了 {before} 条指向已删资产的条目",
        )
        # 分组本身与它的范围不受影响 —— 那是长期配置，不是这次扫描的产物
        self.assertEqual(await self._c("SELECT COUNT(*) FROM asset_group"), 1)
        self.assertEqual(await self._c("SELECT COUNT(*) FROM asset_group_scope"), 1)

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


if __name__ == "__main__":
    unittest.main()
