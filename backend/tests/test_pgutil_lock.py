"""测试基建自测：``RECON_TEST_DB`` 这条逃生命令第一次就得能用。

## 起因

两个 pytest 进程同时用一个测试库时会互删 schema（本文件所在套件里那条
session 级 advisory lock 就是为此）。报错提示里给的处理办法是换一个库::

    $env:RECON_TEST_DB = 'recon_test2'

**但这条命令第一次用必然失败。** ``ensure_database()`` 原来是先
``_acquire_run_lock()`` 再建库，而 advisory lock 是按库隔离的 —— 要拿锁
就 得先能连上目标库，而那个库还不存在。于是报的是
``connection was closed in the middle of operation``，跟"被另一个进程占着"
这个真实原因毫无关系。

结果是：提示给出的唯一解法，在最需要它的场景（临时换个库并行跑）里不管用。
本文件把这个行为钉住。

## 为什么用子进程

``pgutil.DB_NAME`` 是**模块级**常量（导入时读环境变量），同一个进程里改不了。
只能另起一个进程、给它一个全新的库名，看它能不能自己建起来。
"""
from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

BACKEND = Path(__file__).resolve().parent.parent
ADMIN_DSN = "postgresql://postgres@127.0.0.1:5432/postgres"


def _db_exists(name: str) -> bool:
    async def _q() -> bool:
        import asyncpg

        conn = await asyncpg.connect(ADMIN_DSN)
        try:
            got = await conn.fetchval(
                "SELECT 1 FROM pg_database WHERE datname = $1", name
            )
            return bool(got)
        finally:
            await conn.close()

    return asyncio.run(_q())


def _drop(name: str) -> None:
    async def _d() -> None:
        import asyncpg

        conn = await asyncpg.connect(ADMIN_DSN)
        try:
            # 标识符不能参数化；名字是本文件自己 uuid 生成的，不是外部输入。
            await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
        finally:
            await conn.close()

    asyncio.run(_d())


class TestRunLockEscapeHatch(unittest.TestCase):
    def test_fresh_database_name_is_created_and_lockable(self) -> None:
        name = f"recon_locktest_{uuid.uuid4().hex[:10]}"
        self.assertFalse(_db_exists(name), "测试库名必须是全新的，否则测不到建库")

        # 子进程里只做一件事：跑 ensure_database()。它内部要先连上新库拿锁。
        code = (
            "import asyncio, sys\n"
            "sys.path.insert(0, '.')\n"
            "import tests.pgutil as p\n"
            "asyncio.run(p.ensure_database())\n"
            "print('OK', p.DB_NAME)\n"
        )
        env = {**os.environ, "RECON_TEST_DB": name, "PYTHONIOENCODING": "utf-8"}
        try:
            r = subprocess.run(
                [sys.executable, "-c", code],
                cwd=BACKEND, env=env, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=120,
            )
            self.assertEqual(
                r.returncode, 0,
                f"换新库名应当自动建库并拿到锁。\n"
                f"stdout: {r.stdout}\nstderr: {r.stderr}",
            )
            self.assertIn("OK", r.stdout)
            self.assertTrue(_db_exists(name), "ensure_database 跑完了但库不存在")
        finally:
            _drop(name)


if __name__ == "__main__":
    unittest.main()
