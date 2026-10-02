"""M7-f：收尾 —— 删旧唯一键、``dedup_key`` 加 NOT NULL、删备份表。

配套设计见 ``设计-资产表跨scan去重迁移.md`` §10。

## 两段，危险程度不同

    python scripts/migrate_m7f.py                    # 干跑，只报告
    python scripts/migrate_m7f.py --apply            # 段 1：删旧索引 + NOT NULL
    python scripts/migrate_m7f.py --apply --drop-backups   # 段 2：删备份（**不可逆**）

**段 1** 本质可恢复（旧索引随时能重建，而且重建也建不出东西 —— 全局唯一键
已经保证不会有跨扫描重复）。

**段 2 不可逆。** 删掉备份之后，"迁移前长什么样"就再也查不到了。所以：

* 默认**只做段 1**，段 2 要显式加 ``--drop-backups``；
* 段 2 执行前会打一份**完整性报告**（行数、键数、重复数、关联数），
  证明迁移结果自洽 —— 这份报告留档在迁移文档里，替代备份的"可回溯"作用。

## 为什么 ``dedup_key`` 要加 NOT NULL

PostgreSQL 的**唯一索引允许多个 NULL**。所以 ``dedup_key`` 可空时，将来某个
bug 忘了写这个字段，插入**不会报错** —— 只是那几行永远去不了重，而且查不出来。

``NOT NULL`` 把这个静默失败变成一次明确的报错。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.storage.postgres import PostgresStorage, default_dsn  # noqa: E402

#: 迁移前的 per-scan 唯一键。全局唯一键生效后它们完全冗余。
OLD_INDEXES = (
    "uq_domain", "uq_ip", "uq_port", "uq_url", "uq_http_endpoint", "uq_technology",
)

#: ``dedup_key`` 要收紧成 NOT NULL 的表（只有这两张的键是算出来的）。
NOT_NULL = (("url", "dedup_key"), ("http_endpoint", "dedup_key"))

BACKUP_SUFFIX = "_migbak"


async def preflight(st) -> bool:
    """段 1 的前置检查。过不了就不该动。"""
    print("  ══ 前置检查 ══")
    ok = True
    for table, col in NOT_NULL:
        r = await st._fetchone(
            f"SELECT COUNT(*) AS n, COUNT({col}) AS has FROM {table}"
        )
        good = r["n"] == r["has"]
        ok = ok and good
        print(f"  {'✓' if good else '✗'} {table}.{col} 非空 {r['has']}/{r['n']}")

    # 全局唯一键必须在：它们才是旧索引的替代品
    for name in ("uq_domain_global", "uq_ip_global", "uq_port_global",
                 "uq_url_dedup", "uq_http_dedup", "uq_technology_global"):
        r = await st._fetchone(
            "SELECT COUNT(*) AS c FROM pg_indexes WHERE schemaname = current_schema() "
            "AND indexname = ?", (name,),
        )
        if not r["c"]:
            ok = False
            print(f"  ✗ 缺全局唯一键 {name} —— 不能删旧索引")
    if ok:
        print("  ✓ 6 个全局唯一键都在")
    return ok


async def report(st) -> None:
    """完整性报告。**段 2 删备份前必须打这一份。**"""
    print("\n  ══ 迁移后完整性报告 ══")
    for table, col in (
        ("domain", "name"), ("ip", "addr"), ("port", "ip || '|' || port || '|' || protocol"),
        ("url", "dedup_key"), ("http_endpoint", "dedup_key"),
        ("technology", "host || '|' || name"),
    ):
        r = await st._fetchone(
            f"SELECT COUNT(*) AS n, COUNT(DISTINCT {col}) AS k FROM {table} "
            f"WHERE {col} IS NOT NULL"
        )
        flag = "✓" if r["n"] == r["k"] else "✗ 有重复"
        print(f"  {flag} {table:16} {r['n']:6} 行 / {r['k']:6} 键")
    r = await st._fetchone(
        "SELECT COUNT(*) AS n, "
        "COUNT(*) FILTER (WHERE snapshot_json <> '{}') AS snap FROM scan_asset"
    )
    print(f"  ✓ scan_asset       {r['n']:6} 条关联（带快照 {r['snap']}）")
    for sid in await st._fetchall("SELECT id FROM scan ORDER BY id"):
        n = (await st._fetchone(
            "SELECT COUNT(*) AS c FROM scan_asset WHERE scan_id = ?", (sid["id"],)))["c"]
        print(f"      scan#{sid['id']:<4} {n:6} 条关联")


async def main() -> None:
    ap = argparse.ArgumentParser(description="M7-f 收尾")
    ap.add_argument("--apply", action="store_true", help="执行段 1（删旧索引 + NOT NULL）")
    ap.add_argument("--drop-backups", action="store_true",
                    help="执行段 2：删备份表（**不可逆**，需同时给 --apply）")
    args = ap.parse_args()

    st = PostgresStorage(default_dsn(), create_search_index=False)
    await st.open()
    try:
        if not await preflight(st):
            print("\n  前置检查没过，什么都不做")
            return

        existing = {
            r["indexname"] for r in await st._fetchall(
                "SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()")
        }
        to_drop = [n for n in OLD_INDEXES if n in existing]
        print(f"\n  ══ 段 1：删 {len(to_drop)} 条旧唯一键 ══")
        print(f"    {', '.join(to_drop) or '（都不存在，已删过）'}")

        backups = [
            r["relname"] for r in await st._fetchall(
                "SELECT relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                "WHERE n.nspname = current_schema() AND relkind = 'r' "
                "AND relname LIKE ?", (f"%{BACKUP_SUFFIX}%",))
        ]
        print(f"  ══ 备份表 {len(backups)} 张 ══")
        for b in backups:
            n = (await st._fetchone(f"SELECT COUNT(*) AS c FROM {b}"))["c"]
            print(f"    {b:34} {n:6} 行")

        if not args.apply:
            await report(st)
            print("\n  要执行请加 --apply（段 2 另需 --drop-backups）")
            return

        for name in to_drop:
            await st.conn.execute(f"DROP INDEX IF EXISTS {name}")
        for table, col in NOT_NULL:
            await st.conn.execute(f"ALTER TABLE {table} ALTER COLUMN {col} SET NOT NULL")
        await st.conn.commit()
        print(f"\n  ✓ 段 1 完成：删了 {len(to_drop)} 条索引，{len(NOT_NULL)} 列设为 NOT NULL")

        await report(st)

        if not args.drop_backups:
            print(f"\n  备份还留着（{len(backups)} 张）。删它们**不可逆**，"
                  f"确认无误后再跑 --drop-backups")
            return

        print(f"\n  ══ 段 2：删 {len(backups)} 张备份（不可逆）══")
        for b in backups:
            await st.conn.execute(f"DROP TABLE IF EXISTS {b}")
            print(f"    ✓ 已删 {b}")
        await st.conn.commit()
        print("\n  ✅ M7-f 全部完成。迁移前状态已不可回溯 —— "
              "完整性报告见 设计-资产表跨scan去重迁移.md §9.2.4")
    finally:
        await st.close()


asyncio.run(main())
