"""M5 测试: Web 管理台 + 授权白名单 + 分级审计。

用 FastAPI 的 TestClient 直接跑 ASGI 应用（它会启动真实的 lifespan，
因而 SQLite、ScanManager、后台扫描任务都是真的），不建 HTTP 服务、不占端口。

重点验证四件事:
  1. **失败关闭**: 没配白名单时 Web 下发的扫描一律拒绝, 并写审计
  2. 授权通过后扫描能真的跑完, 资产能查出来
  3. **分级审计**: 审计里能看出这次扫描是 passive 还是 active
  4. 递归溯源接口能把一条事件回溯到 SEED
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from .pgutil import DSN, _drop_schema, ensure_database, new_schema
from core.web.app import create_app

TEST_TMP_ROOT = Path(__file__).resolve().parents[1] / ".testtmp"

OFFLINE_PRESET = """
name: offline
description: 只跑离线演示源, 不联网
include:
  - demo_expand
settings:
  max_events: 1000
"""


# --------------------------------------------------------------------- 纯单元

# --------------------------------------------------------------------- API

class WebTestCase(unittest.TestCase):
    #: 子类可以指定访问令牌，测试认证分支
    AUTH_TOKEN: str | None = None

    def setUp(self) -> None:
        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.root = TEST_TMP_ROOT / f"w{uuid.uuid4().hex[:10]}"
        self.root.mkdir(parents=True, exist_ok=True)
        # 存储换成 PostgreSQL 之后没有"库文件"了：这个 schema 名就是隔离单位，
        # 每个测试一个，tearDown 里删掉。
        self.schema = new_schema()
        self.settings_path = self.root / "web_settings.json"
        self.preset_path = self.root / "offline.yml"
        self.preset_path.write_text(OFFLINE_PRESET, encoding="utf-8")

        asyncio.run(ensure_database())
        app = create_app(
            dsn=DSN,
            schema=self.schema,
            settings_path=self.settings_path,
            auth_token=self.AUTH_TOKEN,
        )
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        asyncio.run(_drop_schema(self.schema))
        shutil.rmtree(self.root, ignore_errors=True)

    # ------------------------------------------------------------------ 辅助
    def h(self) -> dict[str, str]:
        """请求头。子类设了令牌时自动带上。"""
        if self.AUTH_TOKEN:
            return {"Authorization": f"Bearer {self.AUTH_TOKEN}"}
        return {}

    def start(
        self,
        targets: list[str],
        preset: str | None = None,
        name: str | None = "测试任务",
    ) -> dict:
        """下发一次扫描。

        ``name`` 默认给一个 —— 名称是**必填**的（见 ``TestScanName``），
        但绝大多数用例不关心它，不该每处都手写一遍。
        """
        body: dict = {
            "targets": targets,
            "preset": preset or str(self.preset_path),
            "overrides": [],
        }
        # ``name=None`` 是**故意不发这个字段**，用来测"缺名称应当被拒"
        if name is not None:
            body["name"] = name
        resp = self.client.post("/api/scans", json=body, headers=self.h())
        self.assertEqual(resp.status_code, 201, resp.text)
        return resp.json()

    def wait_done(self, scan_id: int, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.client.get(f"/api/scans/{scan_id}", headers=self.h()).json()
            if data.get("status") not in ("running", "finalizing"):
                return data
            time.sleep(0.2)
        raise AssertionError(f"扫描 #{scan_id} 未在 {timeout}s 内结束")


class TestScanName(WebTestCase):
    """任务名称：**必填**，且三条读路径都要带出来。

    为什么必填：它在「任务管理」和「任务分组」里都是主要标识 —— 分组同步要靠
    名字挑"把哪次扫描同步进来"（见 AssetGroupView 的同步下拉）。留空如果只是
    存个空串，界面上就多出一批分不清的任务。

    两条读路径必须分别测：进程内的那份走 ``ManagedScan.to_dict()``，
    服务重启后从库里拼的那份走 ``_historical_scan()`` —— 是两段代码。
    """

    def test_name_round_trips_through_all_three_paths(self) -> None:
        record = self.start(["example.com"], name="每月巡检 · 主站")
        self.assertEqual(record["name"], "每月巡检 · 主站", "创建响应里没名字")

        scan_id = record["scan_id"]
        detail = self.wait_done(scan_id)
        self.assertEqual(detail["name"], "每月巡检 · 主站", "详情里没名字")

        listed = {
            s["scan_id"]: s
            for s in self.client.get("/api/scans", headers=self.h()).json()
        }
        self.assertEqual(listed[scan_id]["name"], "每月巡检 · 主站", "列表里没名字")

    def test_missing_name_is_rejected(self) -> None:
        """**不发 name 字段 = 422**，而不是默默建一个没名字的任务。"""
        resp = self.client.post(
            "/api/scans",
            json={"targets": ["example.com"], "preset": str(self.preset_path)},
            headers=self.h(),
        )
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_blank_name_is_rejected(self) -> None:
        """纯空白也不算填了 —— ``min_length=1`` 拦不住 ``"   "``，由 validator 拦。"""
        for blank in ("", "   ", "\t\n"):
            with self.subTest(blank=repr(blank)):
                resp = self.client.post(
                    "/api/scans",
                    json={
                        "name": blank,
                        "targets": ["example.com"],
                        "preset": str(self.preset_path),
                    },
                    headers=self.h(),
                )
                self.assertEqual(resp.status_code, 422, resp.text)

    def test_overlong_name_is_rejected(self) -> None:
        """名称是给人看的标签，不是塞大文本的地方（上限 120）。"""
        resp = self.client.post(
            "/api/scans",
            json={
                "name": "长" * 121,
                "targets": ["example.com"],
                "preset": str(self.preset_path),
            },
            headers=self.h(),
        )
        self.assertEqual(resp.status_code, 422, resp.text)

    def test_manager_also_refuses_blank_name(self) -> None:
        """第二道闸门：绕过 HTTP 直接调 ``manager.start()`` 也拒。

        API 层与 manager 层都拦，任何新入口都不会悄悄漏掉名称。
        """
        import asyncio

        manager = self.client.app.state.manager

        async def go() -> None:
            with self.assertRaises(ValueError):
                await manager.start(name="   ", targets=["example.com"])

        asyncio.run(go())

    def test_name_shows_up_in_historical_view(self) -> None:
        """服务重启后从库里拼的那一份（``_historical_scan``）也要带名字。"""
        record = self.start(["example.com"], name="hist")
        self.wait_done(record["scan_id"])
        # 丢掉内存记录 → 强制走"历史扫描"分支。
        # ``forget`` 是同步的，所以不会踩 pgutil 里那个"跨事件循环用连接"的坑。
        self.client.app.state.manager.forget(record["scan_id"])
        detail = self.client.get(
            f"/api/scans/{record['scan_id']}", headers=self.h()
        ).json()
        self.assertTrue(detail.get("historical"), "没走到历史扫描分支")
        self.assertEqual(detail["name"], "hist")

    def test_name_is_stripped(self) -> None:
        """首尾空白去掉再存 —— 否则列表里会出现"看不见的空格差异"。"""
        record = self.start(["example.com"], name="  月度巡检  ")
        self.assertEqual(record["name"], "月度巡检")


class TestMetaEndpoints(WebTestCase):
    def test_health(self) -> None:
        data = self.client.get("/api/health").json()
        self.assertTrue(data["ok"])
        self.assertEqual(data["running"], 0)

    def test_presets_include_builtins(self) -> None:
        names = {p["name"] for p in self.client.get("/api/presets").json()}
        # 只剩两个模式：被动 / 主动
        self.assertEqual(names, {"passive", "active"})

    def test_modules_for_preset(self) -> None:
        data = self.client.get("/api/modules", params={"preset": "passive"}).json()
        names = {m["name"] for m in data["modules"]}
        self.assertIn("passive_crtsh", names)
        # 判据是"有没有探测流量"，不是"模块自称 passive" ——
        # dns_resolve 的 flags 是 ("active","safe")，但它不发探测流量，
        # 所以必须在。写成 require_flags:[passive] 会把它连带 ip_ptr /
        # tls_cert / admin_plane 一起砍掉。
        self.assertIn("dns_resolve", names)
        self.assertIn("ip_ptr", names)
        # 而真正会发探测流量的一个都不该在
        for module in ("port_scan", "http_probe", "dir_brute", "dns_brute"):
            self.assertIn(module, data["skipped"], f"{module} 不该在 passive 里跑")
        # 兜底：列表里不该出现任何带 loud/invasive/heavy 的模块
        for m in data["modules"]:
            self.assertFalse(
                {"loud", "invasive", "heavy", "metered"} & set(m["flags"]),
                f"{m['name']} 带探测流量标签，却在 passive 预设里",
            )

    def test_static_frontend_is_served(self) -> None:
        """前端是独立的 Vue 工程，后端只托管它的构建产物。

        这些断言在没构建前端时会被跳过 —— 否则跑单元测试会依赖 node_modules。
        """
        resp = self.client.get("/")
        if resp.status_code != 200:
            self.skipTest("前端未构建（cd frontend && npm run build）")
        self.assertIn('id="app"', resp.text)

        # SPA 深链必须回 index.html，否则刷新就 404
        deep = self.client.get("/taskList")
        self.assertEqual(deep.status_code, 200)
        self.assertIn('id="app"', deep.text)

        # 带扩展名却找不到的资源必须是 404 —— 不能伪装成 200 HTML，
        # 否则浏览器会把 HTML 当 JS 解析，报一个和真实原因无关的语法错误
        for missing in ("/app.js", "/style.css", "/nope.png"):
            self.assertEqual(self.client.get(missing).status_code, 404, missing)

        # 未知接口也不能被兜底吞掉
        self.assertEqual(self.client.get("/api/nope").status_code, 404)


class TestNoAuthGate(WebTestCase):
    """**授权白名单已删除** —— 什么设置都不配也能直接下发扫描。

    这里原本是"失败关闭"：白名单为空则拒绝所有 Web 下发的扫描，并写一条
    ``scan_denied`` 审计。那层保护与访问令牌职责重叠（都只是"能不能用这个
    界面"），而且每次加目标都要先去设置里登记，实际使用中只是摩擦。

    现在唯一的门槛是访问令牌，见 :class:`TestTokenAuth`。
    """

    def test_scan_works_without_any_settings(self) -> None:
        """没配白名单、没开任何开关，扫描照样能下发跑完。"""
        record = self.start(["example.com"])
        self.assertEqual(record["status"], "running")
        final = self.wait_done(record["scan_id"])
        self.assertEqual(final["status"], "finished")

    def test_settings_file_has_no_allowlist_fields(self) -> None:
        """设置落盘时不该再出现白名单字段。

        留着的话会变成"界面改不了、文件里有"的幽灵配置 ——
        下次读到的人还得去查它到底管不管用。
        """
        resp = self.client.put(
            "/api/settings", json={"max_concurrent_scans": 3}, headers=self.h()
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        saved = json.loads(self.settings_path.read_text(encoding="utf-8"))
        self.assertNotIn("authorized_targets", saved)
        self.assertNotIn("require_authorization", saved)
        self.assertEqual(saved["max_concurrent_scans"], 3)

    def test_old_settings_file_with_allowlist_still_loads(self) -> None:
        """旧设置文件里还留着白名单字段时不能让服务起不来。

        升级路径上一定会遇到 —— 直接崩掉的话用户只能手工删文件。
        """
        self.settings_path.write_text(
            json.dumps(
                {
                    "authorized_targets": ["legacy.com"],
                    "require_authorization": True,
                    "max_concurrent_scans": 2,
                }
            ),
            encoding="utf-8",
        )
        resp = self.client.get("/api/settings", headers=self.h())
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertNotIn("authorized_targets", resp.json())


class TestScreenshotRoute(WebTestCase):
    """``GET /api/screenshots/{scan_id}/{url}``。

    ## 为什么单独补这一组

    **这个路由以前完全没有测试覆盖，而它从写下来就是坏的** ——
    它直接调 ``store.conn.fetchrow()``，而 ``PgConnection`` 上**根本没有这个方法**
    （只有 ``fetchone`` / ``fetchall`` / ``execute`` / ``executescript``）。
    于是任何点开截图的操作都是 500，而且没人发现。

    连带暴露的还有第二个问题：查询写的是 ``WHERE scan_id = $1``，跨 scan 去重之后
    那个字段只是"谁最先发现的"，**重扫同一目标时新任务取自己的截图会 404**
    （而页面上的链接正是新任务的 id）。
    """

    URL = "http://www.example.com"

    async def _seed(self) -> tuple[int, bytes]:
        """用**独立连接**往同一个 schema 里种数据。

        ⚠️ 不能用 ``self.client.app.state.storage`` —— 那条连接活在 TestClient
        自己的事件循环里，`asyncio.run()` 会在**新**循环里用它，直接报
        ``got Future attached to a different loop``。

        独立连接写的是同一个 PostgreSQL schema，app 下次请求就读得到 ✓
        也顺带避开了"app 那边正跑着扫描"的并发竞争。
        """
        from core.engine.event import Event, EventType
        from core.storage.postgres import PostgresStorage

        from .pgutil import DSN

        store = PostgresStorage(DSN, schema=self.schema, create_search_index=False)
        await store.open()
        try:
            scan_id = await store.create_scan(targets=["example.com"], preset="t")
            for event in (
                Event(EventType.DNS_NAME, "www.example.com", module="t",
                      tags={"source": "brute"}),
                Event(EventType.IP_ADDRESS, "1.1.1.1", module="t", tags={}),
                Event(EventType.OPEN_TCP_PORT, "1.1.1.1:80", module="t",
                      tags={"ip": "1.1.1.1", "port": 80}),
                Event(EventType.HTTP_RESPONSE, self.URL, module="t",
                      tags={"url": self.URL, "domain": "www.example.com",
                            "ip": "1.1.1.1", "port": 80, "scheme": "http",
                            "status": 200, "title": "T"}),
            ):
                await store.save_event(scan_id, event)
                await store.project(scan_id, event)
            png = b"\x89PNG\r\n\x1a\n" + b"z" * 64
            await store.save_screenshot(scan_id, self.URL, png)
            return scan_id, png
        finally:
            await store.close()

    def test_serves_the_png(self) -> None:
        from urllib.parse import quote

        scan_id, png = asyncio.run(self._seed())
        resp = self.client.get(
            f"/api/screenshots/{scan_id}/{quote(self.URL, safe='')}", headers=self.h()
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(resp.content, png)
        self.assertEqual(resp.headers["content-type"], "image/png")

    def test_missing_screenshot_is_404_not_500(self) -> None:
        """**回归**：不存在的截图必须 404。

        修复前这里是 500（``AttributeError: 'PgConnection' object has no
        attribute 'fetchrow'``）—— 前端只会看到一个"服务器错误"。
        """
        from urllib.parse import quote

        scan_id, _ = asyncio.run(self._seed())
        resp = self.client.get(
            f"/api/screenshots/{scan_id}/{quote('http://nope.invalid/', safe='')}",
            headers=self.h(),
        )
        self.assertEqual(resp.status_code, 404, resp.text)

    def test_unknown_scan_id_is_404(self) -> None:
        from urllib.parse import quote

        resp = self.client.get(
            f"/api/screenshots/999999/{quote(self.URL, safe='')}", headers=self.h()
        )
        self.assertEqual(resp.status_code, 404, resp.text)


class TestSourceKeySettings(WebTestCase):
    """``/api/settings`` 里的源 API Key。

    两条性质：**存得进去**（否则源用不了）、**永不回显**（否则密钥泄漏到
    浏览器/日志/录屏里）。第二条比第一条重要 —— 前者看得见，后者看不见。
    """

    def test_modules_api_exposes_requires_key(self) -> None:
        """前端靠这个字段列出"哪些源要填 Key"。

        ⚠️ 它读的是模块的**类属性** ``query``，不是 ``setup()`` 之后才有的
        ``_query`` —— 这个接口不跑 setup，读错地方的话字段永远是 ``False``，
        表现为「设置里一个要 Key 的源都不显示」。

        ⚠️ **两个清单都要看。** 要 Key 的源现在都带 ``metered`` 标记，
        因而默认被预设挡下、不在 ``modules``（已启用）里，而是出现在
        ``metered``（可勾选）里。只查 ``modules`` 会误判成"一个都没有"。
        """
        data = self.client.get("/api/modules", params={"preset": "passive"},
                               headers=self.h()).json()
        everything = list(data["modules"]) + list(data.get("metered") or [])
        needing = [m["name"] for m in everything if m.get("requires_key")]
        self.assertIn("passive_fofa", needing, "要 Key 的源没被标出来")
        # 免 key 的源不能被标成需要 key
        self.assertNotIn("passive_crtsh", needing)

    def test_key_is_echoed_back_for_editing(self) -> None:
        """源 API Key **明文回显**，好让设置页能显示、复制、在原值上改。

        与 ``auth_token`` 的纪律不同（那个永不回传，只给 ``auth_token_set``）：
        Key 只回传"已设置"的话，用户看不出自己配的是哪个账号的 Key，
        也没法在原值上改一个字符 —— 只能整条重填。
        """
        resp = self.client.put(
            "/api/settings",
            json={"max_concurrent_scans": 2,
                  "source_keys": {"passive_fofa": "SECRET-XYZ"}},
            headers=self.h(),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertEqual(
            resp.json()["source_keys"], {"passive_fofa": "SECRET-XYZ"},
            "PUT 的响应里没带回明文 Key，前端就没法回显",
        )
        # "已设置"列表继续保留：前端用它判断哪些源配过（回显值缺失时的兜底）
        self.assertEqual(resp.json()["source_keys_set"], ["passive_fofa"])

        got = self.client.get("/api/settings", headers=self.h())
        self.assertEqual(got.json()["source_keys"], {"passive_fofa": "SECRET-XYZ"})
        self.assertEqual(got.json()["source_keys_set"], ["passive_fofa"])

    def test_key_is_persisted_for_the_next_scan(self) -> None:
        """存下来才有意义 —— 存不进文件的话重启就没了。"""
        self.client.put(
            "/api/settings",
            json={"max_concurrent_scans": 2,
                  "source_keys": {"passive_fofa": "SECRET-XYZ"}},
            headers=self.h(),
        )
        self.assertIn(
            "SECRET-XYZ", self.settings_path.read_text(encoding="utf-8"),
            "密钥没落到设置文件里",
        )

    def test_merge_does_not_wipe_other_sources(self) -> None:
        """**按模块合并**，不是整体覆盖。

        前端按模块逐个提交，覆盖语义会把这次没提到的源全抹掉 ——
        用户只想改一个源，结果别的源悄悄失效了。
        """
        self.client.put("/api/settings", json={
            "max_concurrent_scans": 2,
            "source_keys": {"passive_fofa": "A", "passive_other": "B"},
        }, headers=self.h())
        self.client.put("/api/settings", json={
            "max_concurrent_scans": 2,
            "source_keys": {"passive_fofa": "A2"},
        }, headers=self.h())
        names = self.client.get("/api/settings", headers=self.h()).json()["source_keys_set"]
        self.assertEqual(names, ["passive_fofa", "passive_other"])

    def test_empty_string_clears_a_key(self) -> None:
        """空串 = 显式清掉，而不是存个空值。

        存空值的话 ``source_keys_set`` 会一直显示"已设置"，用户没法取消。
        """
        self.client.put("/api/settings", json={
            "max_concurrent_scans": 2,
            "source_keys": {"passive_fofa": "A"},
        }, headers=self.h())
        resp = self.client.put("/api/settings", json={
            "max_concurrent_scans": 2,
            "source_keys": {"passive_fofa": ""},
        }, headers=self.h())
        self.assertEqual(resp.json()["source_keys_set"], [])

    def test_omitting_source_keys_keeps_them(self) -> None:
        """``source_keys=None``（前端没动这一块）= 保持原样。"""
        self.client.put("/api/settings", json={
            "max_concurrent_scans": 2,
            "source_keys": {"passive_fofa": "A"},
        }, headers=self.h())
        resp = self.client.put("/api/settings", json={"max_concurrent_scans": 3},
                               headers=self.h())
        self.assertEqual(resp.json()["source_keys_set"], ["passive_fofa"])


class TestSourceConnectionTest(WebTestCase):
    """``POST /api/sources/{模块}/test`` —— 「测试连接」按钮。

    ## 两条容易写错的地方

    1. **必须测表单里还没保存的值。** 用户填完 key 想先确认再保存；
       测已保存的旧值等于没测。
    2. **源没实现检测时要如实说"没测"**，不能返回"成功" —— 那是假阳性，
       用户会以为配好了。
    """

    def test_source_without_check_reports_unsupported(self) -> None:
        """免 key 的源没实现 ``check_key`` → ``ok=null``、``supported=False``。"""
        resp = self.client.post("/api/sources/passive_crtsh/test", json={},
                                headers=self.h())
        self.assertEqual(resp.status_code, 200, resp.text)
        data = resp.json()
        self.assertIsNone(data["ok"], "没实现检测却报了成功/失败")
        self.assertFalse(data["supported"])
        self.assertIn("未提供连接检测", data["detail"])

    def test_missing_key_is_reported_before_any_request(self) -> None:
        """没填 key 就直接说，不浪费一次请求。"""
        resp = self.client.post("/api/sources/passive_fofa/test", json={},
                                headers=self.h())
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertFalse(resp.json()["ok"])
        self.assertIn("API Key", resp.json()["detail"])

    def test_unknown_module_is_404(self) -> None:
        resp = self.client.post("/api/sources/definitely_not_a_module/test",
                                json={}, headers=self.h())
        self.assertEqual(resp.status_code, 404)

    def test_non_source_module_is_rejected(self) -> None:
        """非被动源（没有 query 插件）不能拿去测。"""
        resp = self.client.post("/api/sources/dns_resolve/test", json={},
                                headers=self.h())
        self.assertEqual(resp.status_code, 400, resp.text)

    def test_form_values_are_used_not_saved_ones(self) -> None:
        """**核心行为**：测的是表单里的值。

        用一个明显错的地址去测 —— 读"已保存的值"（这里是空的）就会走官方域名
        并返回「账号无效」；读表单值则会打到那个不存在的主机上、报连接错误。
        两种结果不同，据此判定它读的是哪一份。
        """
        resp = self.client.post(
            "/api/sources/passive_fofa/test",
            json={"api_key": "k", "options": {"api_url": "http://127.0.0.1:9/nope"}},
            headers=self.h(),
        )
        self.assertEqual(resp.status_code, 200, resp.text)
        detail = resp.json()["detail"]
        self.assertFalse(resp.json()["ok"])
        self.assertNotIn("账号无效", detail, "读的是已保存的值，不是表单里的")


class TestScanLifecycle(WebTestCase):
    def test_full_offline_scan_and_assets(self) -> None:
        record = self.start(["example.com"])
        scan_id = record["scan_id"]
        final = self.wait_done(scan_id)

        self.assertEqual(final["status"], "finished")
        self.assertIn("progress", final)

        # 默认是 live=true（只看被 HTTP 探活确认过的）—— 这次离线扫描
        # 没跑 http_probe，所以默认视图里一个域名都不该有。
        default_view = self.client.get(f"/api/scans/{scan_id}/assets").json()
        self.assertTrue(default_view["live"])
        self.assertEqual(default_view["domains"], [],
                         "离线扫描没有 HTTP 端点，默认视图不该有域名")
        self.assertEqual(default_view["summary"]["domains_live"], 0)
        # 总数仍是 5 —— 页签要能显示"存活 / 总数"，不能把 0 当成没有资产
        self.assertEqual(default_view["summary"]["domains"], 5)

        # live=false 拿到的才是原始资产投影
        assets = self.client.get(f"/api/scans/{scan_id}/assets?live=false").json()
        names = {d["name"] for d in assets["domains"]}
        # demo_expand 会产出这 4 个子域 + 根域名
        self.assertEqual(
            names,
            {"example.com", "www.example.com", "api.example.com",
             "mail.example.com", "dev.example.com"},
        )
        self.assertEqual(assets["summary"]["domains"], 5)

    def test_events_and_trace(self) -> None:
        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)

        events = self.client.get(f"/api/scans/{scan_id}/events").json()
        self.assertGreater(len(events), 0)
        seed = next(e for e in events if e["type"] == "SEED")
        child = next(e for e in events if e["type"] == "DNS_NAME")

        trace = self.client.get(f"/api/scans/{scan_id}/trace/{child['id']}").json()
        types = [n["type"] for n in trace["chain"]]
        self.assertEqual(types[0], "DNS_NAME")
        self.assertEqual(types[-1], "SEED")
        self.assertEqual(trace["chain"][-1]["id"], seed["id"])

    def test_event_type_filter(self) -> None:
        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)
        events = self.client.get(
            f"/api/scans/{scan_id}/events", params={"type": "DNS_NAME"}
        ).json()
        self.assertTrue(events)
        self.assertTrue(all(e["type"] == "DNS_NAME" for e in events))

    def test_scan_list_contains_scan(self) -> None:
        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)
        listed = {s["scan_id"] for s in self.client.get("/api/scans").json()}
        self.assertIn(scan_id, listed)

    def test_stop_non_running_scan_conflicts(self) -> None:
        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)
        resp = self.client.post(f"/api/scans/{scan_id}/stop")
        self.assertEqual(resp.status_code, 409)

    def test_unknown_scan_is_404(self) -> None:
        self.assertEqual(self.client.get("/api/scans/999999").status_code, 404)


class TestAuditLevels(WebTestCase):
    def test_audit_records_passive_mode(self) -> None:
        """离线预设只有 demo_expand（passive），审计里 mode 应是 passive。"""
        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)

        audits = self.client.get("/api/scans", params={}).json()
        self.assertTrue(audits)

        rows = self.client.get("/api/audits").json()
        start = next(a for a in rows if a["action"] == "scan_start")
        self.assertEqual(start["mode"], "passive")
        self.assertEqual(start["actor"], "web")
        self.assertEqual(start["allowed"], 1)

        finish = next((a for a in rows if a["action"] == "scan_finish"), None)
        self.assertIsNotNone(finish)
        self.assertEqual(finish["mode"], "passive")

    def test_active_preset_is_audited_as_active(self) -> None:
        """active 预设含主动模块，审计必须标成 active（这是分级审计的意义）。"""
        resp = self.client.post(
            "/api/scans",
            json={"name": "分级审计 · active", "targets": ["example.com"], "preset": "active",
                  "overrides": ["modules.dns_brute.max_words=1",
                                "modules.port_scan.ports=top10",
                                "modules.asn_enrich.qps=0"]},
        )
        self.assertEqual(resp.status_code, 201, resp.text)
        record = resp.json()
        self.assertEqual(record["mode"], "active")

        # 立刻停掉, 不真的跑主动扫描
        self.client.post(f"/api/scans/{record['scan_id']}/stop")

        rows = self.client.get("/api/audits").json()
        start = next(a for a in rows if a["action"] == "scan_start")
        self.assertEqual(start["mode"], "active")
        self.assertIn("主动模块=", start["detail"])

    def test_settings_update_is_audited(self) -> None:
        """改设置要写审计，而且明细里能看出改成了什么。

        （原来这条依赖 ``authorize()`` 顺带发的那次 PUT；授权白名单删掉之后
        那个辅助方法没了，就自己发一次 —— 顺便把明细也断言上，
        之前只断言"有这么条记录"，改坏了内容也发现不了。）
        """
        resp = self.client.put(
            "/api/settings", json={"max_concurrent_scans": 3}, headers=self.h()
        )
        self.assertEqual(resp.status_code, 200, resp.text)

        rows = self.client.get("/api/audits", headers=self.h()).json()
        upd = next((a for a in rows if a["action"] == "settings_update"), None)
        self.assertIsNotNone(upd, "改设置没写审计")
        self.assertEqual(upd["actor"], "local")
        self.assertIn("max_concurrent=3", upd["detail"])


class TestTokenAuth(WebTestCase):
    """访问令牌。ARL 的 AUTH 默认是 False，我们不想犯同样的错。"""

    AUTH_TOKEN = "sekret-token"

    def test_api_requires_token(self) -> None:
        self.assertEqual(self.client.get("/api/scans").status_code, 401)
        self.assertEqual(
            self.client.get(
                "/api/scans", headers={"Authorization": "Bearer wrong"}
            ).status_code,
            401,
        )
        self.assertEqual(self.client.get("/api/scans", headers=self.h()).status_code, 200)

    def test_health_and_static_stay_open(self) -> None:
        """健康检查与静态前端不能锁 —— 否则浏览器连页面都加载不出来。

        浏览器加载 ``<script src>`` / ``<link href>`` 时带不了 Authorization 头，
        把 HTML/JS/CSS 一起锁上，页面根本打不开。
        """
        health = self.client.get("/api/health")
        self.assertEqual(health.status_code, 200)
        self.assertTrue(health.json()["auth_required"])

        root = self.client.get("/")
        if root.status_code != 200:
            self.skipTest("前端未构建（cd frontend && npm run build）")
        self.assertIn('id="app"', root.text)

        # 构建产物也必须免认证可取，否则页面加载不出来
        import re

        assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', root.text)
        self.assertTrue(assets, "index.html 里没有 /assets/* 引用")
        for path in assets:
            self.assertEqual(self.client.get(path).status_code, 200, path)

    def test_query_param_token_also_accepted(self) -> None:
        self.assertEqual(
            self.client.get("/api/scans?token=sekret-token").status_code, 200
        )

    def test_settings_never_echoes_the_token(self) -> None:
        data = self.client.get("/api/settings", headers=self.h()).json()
        self.assertTrue(data["auth_token_set"])
        self.assertNotIn("auth_token", data)

    def test_full_flow_with_token(self) -> None:
        scan_id = self.start(["example.com"])["scan_id"]
        final = self.wait_done(scan_id)
        self.assertEqual(final["status"], "finished")


if __name__ == "__main__":
    unittest.main()

class TestDeleteForgetsInMemoryScan(WebTestCase):
    """删除扫描必须同时丢掉内存记录。

    踩过的坑：只删库的话，``GET /api/scans`` 末尾那句
    ``out.extend(in_memory.values())``（用来补"刚启动、列表查询还没覆盖到"
    的那些）会把已删除的扫描补回列表；``GET /api/scans/{id}`` 也会先命中
    内存那份，照样能打开详情。表现就是"删了还在"。
    """

    def test_deleted_scan_disappears_from_list_and_detail(self) -> None:
        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)
        self.assertIn(scan_id, [s["scan_id"] for s in self.client.get("/api/scans").json()])

        resp = self.client.delete(f"/api/scans/{scan_id}", headers=self.h())
        self.assertEqual(resp.status_code, 200, resp.text)

        ids = [s["scan_id"] for s in self.client.get("/api/scans").json()]
        self.assertNotIn(scan_id, ids, "删掉的扫描又出现在列表里（内存记录没清）")
        self.assertEqual(
            self.client.get(f"/api/scans/{scan_id}", headers=self.h()).status_code,
            404,
            "删掉的扫描还能打开详情（内存记录没清）",
        )
