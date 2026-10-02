"""测试用的 PostgreSQL 连接与 schema 隔离。

**测试不再用 SQLite。** 每个测试拿到一个独立的 schema（``t<uuid>``），
所以彼此不干扰，也能安全并行跑。用 schema 而不是「一个测试一个数据库」，
是因为建数据库要拷模板文件（百毫秒级），而建 schema 只是一条 DDL。

```
每次测试:
  CREATE SCHEMA "t3f9c1..."        -- 毫秒级
  search_path = 该 schema          -- 通过连接参数下发, 池里每条连接都带上
  跑测试
  DROP SCHEMA ... CASCADE          -- 收尾
```

## 为什么关掉检索索引

``pg_trgm`` 的 GIN 索引有 18 个，每个测试建一遍会让整个套件慢一个数量级，
而**搜索的正确性与索引无关**（没索引只是走顺序扫描，结果一样）。
索引本身由 ``test_storage.py::TestSearchIndex`` 单独覆盖。

## 没有 PostgreSQL 怎么办

直接抛错并给出可执行的修复提示，**不静默跳过** —— 静默跳过会让
"测试全绿"变成假象，而这个项目正是靠测试兜住方言差异的。
"""

from __future__ import annotations

import os
import re
import uuid

import asyncpg

from core.storage.postgres import PostgresStorage

#: schema 名的形状，用来识别"这是本套件留下的"（清理遗留时用）
_SCHEMA_RE = re.compile(r"^t[0-9a-f]{12}$")

#: 测试库。与生产的 recon 库分开，避免污染真实数据。
DB_NAME = os.environ.get("RECON_TEST_DB") or "recon_test"
HOST = os.environ.get("RECON_TEST_HOST") or "127.0.0.1"
PORT = int(os.environ.get("RECON_TEST_PORT") or 5432)
USER = os.environ.get("RECON_TEST_USER") or "postgres"

DSN = f"postgresql://{USER}@{HOST}:{PORT}/{DB_NAME}"
_ADMIN_DSN = f"postgresql://{USER}@{HOST}:{PORT}/postgres"

_db_ready = False

_HINT = (
    "连不上 PostgreSQL。测试需要它（存储层已从 SQLite 换成 PostgreSQL）。\n"
    "  检查服务: sc query postgresql-x64-16\n"
    "  或改连接: 设环境变量 RECON_TEST_HOST / RECON_TEST_PORT / RECON_TEST_USER / RECON_TEST_DB"
)


async def ensure_database() -> None:
    """保证测试库存在，并清掉上一次跑剩下的 schema。进程内只做一次。"""
    global _db_ready
    if _db_ready:
        return
    try:
        admin = await asyncpg.connect(_ADMIN_DSN)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"{_HINT}\n  原始错误: {e}") from e
    try:
        exists = await admin.fetchval(
            "SELECT 1 FROM pg_database WHERE datname = $1", DB_NAME
        )
        if not exists:
            # 标识符不能参数化，DB_NAME 来自常量/环境变量，不是用户输入。
            #
            # **排序规则必须与生产一致（C / UTF8 / template0）** ——
            # 测试库用平台默认 locale 的话，ORDER BY 与索引行为和生产不同，
            # 测出来的东西不能代表生产。详见 storage/bootstrap.py 的模块文档。
            await admin.execute(
                f'CREATE DATABASE "{DB_NAME}" '
                f"ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0"
            )
    finally:
        await admin.close()

    # 上一次跑挂掉会留下 schema。不清的话它们会一直堆着，
    # 而且残留的 pg_trgm 索引还会挡住"把扩展挪到 public"这类修复。
    conn = await asyncpg.connect(DSN)
    try:
        left = [
            r["nspname"]
            for r in await conn.fetch(
                "SELECT nspname FROM pg_namespace WHERE nspname LIKE 't%'"
            )
            if _SCHEMA_RE.match(r["nspname"])
        ]
        for name in left:
            await conn.execute(f'DROP SCHEMA IF EXISTS "{name}" CASCADE')
    finally:
        await conn.close()

    _db_ready = True


def new_schema() -> str:
    return f"t{uuid.uuid4().hex[:12]}"


async def make_storage() -> PostgresStorage:
    """给一个测试建一套隔离的存储。"""
    await ensure_database()
    storage = PostgresStorage(DSN, schema=new_schema(), create_search_index=False)
    await storage.open()
    return storage


async def drop_storage(storage: PostgresStorage) -> None:
    await storage.close()
    await storage.drop_schema()


async def _drop_schema(schema: str) -> None:
    """按名字删 schema（给不走 PostgresStorage 的测试用）。"""
    admin = await asyncpg.connect(DSN)
    try:
        await admin.execute(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
    finally:
        await admin.close()
