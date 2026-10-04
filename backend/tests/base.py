"""测试公共基类。

**存储已从 SQLite 换成 PostgreSQL**（理由见 ``core/storage/postgres.py``）。
每个测试拿到一个独立 schema，见 ``tests/pgutil.py``。

注意: 这里刻意不用 ``tempfile.mkdtemp`` —— 它在 Windows 上以 0700 建目录,
在受限沙箱下会拒绝继续向下创建子目录。统一用普通 mkdir。
"""

from __future__ import annotations

import shutil
import textwrap
import unittest
import uuid
from pathlib import Path

from core.engine.preset import Preset
from core.engine.scanner import Scanner

from .pgutil import drop_storage, make_storage

TEST_TMP_ROOT = Path(__file__).resolve().parents[1] / ".testtmp"


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
