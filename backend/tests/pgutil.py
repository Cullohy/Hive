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

#: 整套件共用的 advisory lock 键。**session 级**，所以进程退出、连接断开时
#: 由 PostgreSQL 自动释放，不需要显式解锁。
_RUN_LOCK_KEY = 0x0ACE5EED

#: 持锁的那条连接。必须**一直开着** —— advisory lock 是绑在会话上的，
#: 连接一断锁就没了，那就等于没锁。
_lock_conn: "asyncpg.Connection | None" = None


_HINT = (
    "连不上 PostgreSQL。测试需要它（存储层已从 SQLite 换成 PostgreSQL）。\n"
    "  检查服务: sc query postgresql-x64-16\n"
    "  或改连接: 设环境变量 RECON_TEST_HOST / RECON_TEST_PORT / RECON_TEST_USER / RECON_TEST_DB"
)


async def _acquire_run_lock() -> None:
    """占一把进程生命周期的锁，保证**同一时间只有一个 pytest 进程**在用测试库。

    ## 为什么必须

    :func:`ensure_database` 会把上一次跑剩下的 schema 全部 ``DROP ... CASCADE``。
    同一进程内的测试互不干扰（各有各的 schema），但**跨进程就不然**了：
    第二个进程启动时会掀掉第一个进程**正在用**的活 schema，于是第一个进程的
    每一条 INSERT 都撞外键，错误签名是::

        ForeignKeyViolationError: 键值对 "(scan_id)=(1)" 不存在于表 "scan"

    这条错误**完全看不出跟 schema 被删有关**，排障方向会被直接带偏
    （实测误判成"代码的并发问题"、"跨 scan 去重的回归"）。

    所以这里不检测、不跳过，而是**直接拒绝启动**并说明原因 —— 宁可吵闹，
    也不要静默地互相破坏。
    """
    global _lock_conn
    if _lock_conn is not None:
        return
    try:
        conn = await asyncpg.connect(DSN)
    except Exception as e:  # noqa: BLE001
        raise RuntimeError(f"{_HINT}\n  原始错误: {e}") from e
    got = await conn.fetchval("SELECT pg_try_advisory_lock($1)", _RUN_LOCK_KEY)
    if not got:
        await conn.close()
        raise RuntimeError(
            "**已经有另一个 pytest 进程在用这个测试库。**\n"
            "两个进程会互删对方的 schema，把对方打成一片外键违规，\n"
            "而且报错完全看不出真实原因。\n"
            "  处理: 等那个进程跑完；或给它换一个库:\n"
            "    $env:RECON_TEST_DB = 'recon_test2'   # 不存在会自动建"
        )
    _lock_conn = conn


async def ensure_database() -> None:
    """保证测试库存在，并清掉上一次跑剩下的 schema。进程内只做一次。"""
    global _db_ready
    if _db_ready:
        return

    # ⚠️ **建库必须在拿锁之前**。
    # advisory lock 是按库隔离的，所以要拿锁就得先能连上目标库 —— 而
    # 第一次用某个新库名时那个库还不存在，连不上，报的是
    # "connection was closed in the middle of operation"，看不出真实原因。
    #
    # 后果很实在：错误提示里推荐的那条逃生命令
    # ``$env:RECON_TEST_DB = 'recon_test2'`` **第一次必然失败**，
    # 只有那个库已经存在才生效 —— 也就是说"被另一个进程占着"这条
    # 提示给出的唯一解法，第一次用是不管用的。
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
            try:
                await admin.execute(
                    f'CREATE DATABASE "{DB_NAME}" '
                    f"ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0"
                )
            except asyncpg.DuplicateDatabaseError:
                # 两个进程同时建同一个库。有一个成了就够了，不是错误。
                pass
    finally:
        await admin.close()

    # 库在了，现在才拿得到锁。锁住了才有资格去删 schema。
    await _acquire_run_lock()

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
