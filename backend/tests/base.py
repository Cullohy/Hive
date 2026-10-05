"""测试公共基类。

**存储已从 SQLite 换成 PostgreSQL**（理由见 ``core/storage/postgres.py``）。
每个测试拿到一个独立 schema，见 ``tests/pgutil.py``。

注意: 这里刻意不用 ``tempfile.mkdtemp`` —— 它在 Windows 上以 0700 建目录,
在受限沙箱下会拒绝继续向下创建子目录。统一用普通 mkdir。
"""

from __future__ import annotations

import asyncio
import shutil
import textwrap
import time
import unittest
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from core.engine.preset import Preset
from core.engine.scanner import Scanner
from core.web.app import create_app

from .pgutil import DSN, _drop_schema, drop_storage, ensure_database, make_storage, new_schema

TEST_TMP_ROOT = Path(__file__).resolve().parents[1] / ".testtmp"

#: 只跑离线演示源、不联网的预设。给 API 测试用：起一个真 app 但**不**真发请求。
OFFLINE_PRESET = """
name: offline
description: 只跑离线演示源, 不联网
include:
  - demo_expand
settings:
  max_events: 1000
"""


class WebTestCase(unittest.TestCase):
    """起一个**真的** FastAPI app（隔离 schema + 临时设置文件）。

    与 :class:`EngineTestCase` 的分工：那个直接驱动 ``Scanner``，这个走
    HTTP 层，所以接口的序列化 / 参数名 / 默认值都得靠它验。

    以前它住在 ``test_m5.py`` 里，于是第二个 API 测试文件要么重复抄一遍、
    要么跨测试模块 import。挪到这里和 ``EngineTestCase`` 放一起。
    """

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
        )
        self.client = TestClient(app)
        self.client.__enter__()

    def tearDown(self) -> None:
        self.client.__exit__(None, None, None)
        asyncio.run(_drop_schema(self.schema))
        shutil.rmtree(self.root, ignore_errors=True)

    def start(
        self,
        targets: list[str],
        preset: str | None = None,
        name: str | None = "测试扫描",
    ) -> dict:
        """起一个扫描任务。

        ``name`` 默认给一个值 —— **必填**，缺了或只有空白直接 422，
        所以"故意不传"要写 ``name=None``。
        """
        body: dict = {
            "targets": targets,
            "preset": preset or str(self.preset_path),
            "overrides": [],
        }
        if name is not None:
            body["name"] = name
        resp = self.client.post("/api/scans", json=body)
        self.assertEqual(resp.status_code, 201, resp.text)
        return resp.json()

    def wait_done(self, scan_id: int, timeout: float = 30.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            data = self.client.get(f"/api/scans/{scan_id}").json()
            if data.get("status") not in ("running", "finalizing"):
                return data
            time.sleep(0.2)
        raise AssertionError(f"扫描 #{scan_id} 未在 {timeout}s 内结束")


class EngineTestCase(unittest.IsolatedAsyncioTestCase):
    """提供一个临时模块目录 + 隔离的 PostgreSQL schema 的运行环境。"""

    async def asyncSetUp(self) -> None:
        TEST_TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.root = TEST_TMP_ROOT / f"t{uuid.uuid4().hex[:10]}"
        self.module_dir = self.root / "mods"
        self.module_dir.mkdir(parents=True, exist_ok=True)
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)
        shutil.rmtree(self.root, ignore_errors=True)

    def add_module_file(self, name: str, source: str) -> None:
        (self.module_dir / f"{name}.py").write_text(
            textwrap.dedent(source), encoding="utf-8"
        )

    async def run_scan(
        self, *, targets, include, enforce_scope: bool = True, **preset_kw
    ):
        preset = Preset(
            name="test",
            include=list(include),
            module_dirs=[str(self.module_dir)],
            **preset_kw,
        )
        scanner = Scanner(
            targets=targets, preset=preset, storage=self.storage,
            enforce_scope=enforce_scope,
        )
        summary = await scanner.scan()
        return scanner, summary

