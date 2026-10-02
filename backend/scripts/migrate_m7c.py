"""M7-c：回填 ``dedup_key`` / ``schemes`` / ``scan_asset`` —— **第一次真正改存量数据**。

配套设计见 ``设计-资产表跨scan去重迁移.md`` §6。

## 怎么跑

    python scripts/migrate_m7c.py            # 干跑，只报告
    python scripts/migrate_m7c.py --apply    # 建备份 + 真的写库
    python scripts/migrate_m7c.py --verify   # 只跑对账

## 为什么默认干跑

这是 UPDATE/INSERT，**写错了没有变更日志可回滚**。所以：

* 默认只报告"会改多少行、改成什么"
* ``--apply`` 会**先建备份表**（``<表>_migbak_<日期>``）再动手
* 全部语句**幂等**，可以重复跑

## 它用的是同一套身份函数

回填的键一律来自 :mod:`core.util.asset_key`，**不在 SQL 里另写一份**。
两套实现迟早分叉，而分叉的表现是"迁移后的键和代码算出来的不一致" ——
那会让 M7-d 切唯一键时静默丢数据。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.storage.postgres import PostgresStorage, default_dsn  # noqa: E402
from core.util.asset_key import (  # noqa: E402
    domain_key,
    endpoint_key,
    ip_key,
    port_key,
    split_url,
    technology_key,
    url_key,
)

BACKUP_DATE = datetime.now(timezone.utc).strftime("%Y%m%d")


def _scheme_of(url: str) -> str:
    return split_url(url)[0]


async def backfill_urls(st, *, apply: bool) -> None:
    """回填 ``url.dedup_key`` / ``url.schemes``。

    ``schemes`` 填的是**同一 dedup_key 下所有行的协议并集**，而不是本行的协议 ——
    这样 M7-d 合并时无论哪一行存活，拿到的都是完整的协议集合，合并本身就成了空操作。
    """
    rows = await st._fetchall(
        "SELECT id, scan_id, url, dedup_key, schemes FROM url ORDER BY id"
    )
    groups: dict[str, list] = defaultdict(list)
    for r in rows:
        groups[url_key(r["url"])].append(r)

    changes: list[tuple[str, list[str], int]] = []
    for key, members in groups.items():
        # ⚠️ **必须把每行已有的 schemes 也算进并集，不能只看本行的 URL 协议。**
        #
        # 合并之后每个键只剩一行，而那一行的 schemes 是 M7-c 早期算好的**并集**
        # （如 ['http','https']）。只按本行 URL 算的话会算出单个协议，把它**覆盖
        # 掉** —— 协议信息丢失。本脚本可重跑，所以这种"越跑越少"的行为是致命的。
        #
        # 实测踩到：合并后重跑一次，823 行的双协议被削成单协议。
        # 并集本身是**单调**的（只会增不会减），重跑多少次都稳定。
        schemes = sorted(
            {s for m in members for s in (m["schemes"] or [])}
            | {_scheme_of(m["url"]) for m in members if _scheme_of(m["url"])}
        )
        for m in members:
            if m["dedup_key"] != key or list(m["schemes"] or []) != schemes:
                changes.append((key, schemes, m["id"]))

    multi = sum(1 for v in groups.values() if len(v) > 1)
    print(f"  ── url ──")
    print(f"    {len(rows)} 行 -> {len(groups)} 个 dedup_key"
          f"（{multi} 个键对应多行，即将来要合并的）")
    print(f"    待更新 {len(changes)} 行")

    if apply and changes:
        for key, schemes, row_id in changes:
            await st.conn.execute(
                "UPDATE url SET dedup_key = ?, schemes = ? WHERE id = ?",
                (key, schemes, row_id),
            )
        await st.conn.commit()
        print(f"    ✓ 已写库")


async def backfill_endpoints(st, *, apply: bool) -> None:
    """回填 ``http_endpoint.dedup_key`` / ``schemes``。

    这张表的键**带 scheme**，所以每个键下**恒为一行** —— 预期合并 0 条。
    实测确认过：``url`` 合并 433 组 http/https，而这里一条都不合，
    从而 status/title/favicon/截图**一条观测都不丢**。
    """
    rows = await st._fetchall(
        "SELECT id, url, dedup_key, schemes FROM http_endpoint ORDER BY id"
    )
    changes: list[tuple[str, list[str], int]] = []
    keys: set[str] = set()
    for r in rows:
        key = endpoint_key(r["url"])
        keys.add(key)
        schemes = sorted({s for s in [_scheme_of(r["url"])] if s})
        if r["dedup_key"] != key or list(r["schemes"] or []) != schemes:
            changes.append((key, schemes, r["id"]))

    print(f"\n  ── http_endpoint ──")
    print(f"    {len(rows)} 行 -> {len(keys)} 个 dedup_key"
          f"（合并 {len(rows) - len(keys)} 条，预期为 0）")
    print(f"    待更新 {len(changes)} 行")

    if apply and changes:
        for key, schemes, row_id in changes:
            await st.conn.execute(
                "UPDATE http_endpoint SET dedup_key = ?, schemes = ? WHERE id = ?",
                (key, schemes, row_id),
            )
        await st.conn.commit()
        print(f"    ✓ 已写库")


#: 每类资产：怎么从各自的表里取出 `(scan_id, asset_key, first_seen, last_seen)`。
#:
#: 写成 SQL 是因为**取数**该在数据库里做；但 ``asset_key`` 一律在 Python 侧用
#: :mod:`core.util.asset_key` 算 —— 两边分工清楚，避免身份规则被复制。
#:
#: ⚠ **不要在这里加 ``WHERE dedup_key IS NOT NULL`` 之类的过滤。**
#: 第一版就这么写了，结果是干跑时 ``dedup_key`` 还没填，url/http_endpoint
#: 两类各报 "源 0 行" —— **干跑严重少报**，而干跑的全部意义就是"先看清楚"。
#: 而且那让 scan_asset 的回填依赖 dedup_key 已被填，两步就绑死了。
#: 键在 Python 侧算，跟列填没填无关。
_ASSET_SOURCES = {
    "domain": "SELECT scan_id, name AS raw, first_seen, last_seen FROM domain",
    "ip": "SELECT scan_id, addr AS raw, first_seen, last_seen FROM ip",
    "port": "SELECT scan_id, ip AS addr, port, protocol, first_seen, last_seen FROM port",
    "url": "SELECT scan_id, url AS raw, first_seen, last_seen FROM url",
    "http_endpoint": "SELECT scan_id, url AS raw, first_seen, last_seen FROM http_endpoint",
    "technology": "SELECT scan_id, host, name, first_seen, last_seen FROM technology",
}


def _key_for(asset_type: str, row) -> str:
    if asset_type == "domain":
        return domain_key(row["raw"])
    if asset_type == "ip":
        return ip_key(row["raw"])
    if asset_type == "port":
        return port_key(row["addr"], row["port"], row["protocol"])
    if asset_type == "url":
        return url_key(row["raw"])
    if asset_type == "http_endpoint":
        return endpoint_key(row["raw"])
    if asset_type == "technology":
        return technology_key(row["host"], row["name"])
    raise ValueError(asset_type)


async def backfill_scan_asset(st, *, apply: bool) -> None:
    """把"每张资产表带 scan_id"的关系转成 ``scan_asset`` 关联行。

    ⚠️ **冲突时不能简单 DO NOTHING。** 现在 ``url`` 里 1495 行有大量重复的
    ``(scan_id, dedup_key)``（就是将来要合并的那 433 组 http/https）——
    ``DO NOTHING`` 会丢掉其中一行的 ``first_seen``，那是一次**真实的观测**。
    所以取 ``MIN(first_seen)`` / ``MAX(last_seen)``。

    ISO-8601 字符串的字典序与时间序一致（见 ``schema.sql`` 头部的类型说明），
    所以 ``LEAST`` / ``GREATEST`` 在 TEXT 上是正确的。
    """
    print(f"\n  ── scan_asset ──")
    total = 0
    for asset_type, sql in _ASSET_SOURCES.items():
        rows = await st._fetchall(sql)
        triples = [
            (r["scan_id"], _key_for(asset_type, r), r["first_seen"], r["last_seen"])
            for r in rows
            if _key_for(asset_type, r)
        ]
        # 关联表的主键是 (scan_id, asset_type, asset_key)，
        # 所以同一扫描里多行算出同一个键时只落一条 —— 报"去重后"的条数才对得上。
        unique = {(s, k) for s, k, _f, _l in triples}
        before = await st._fetchone(
            "SELECT COUNT(*) AS c FROM scan_asset WHERE asset_type = ?", (asset_type,)
        )
        # 键在 SQL 里只算一次（上面列表推导会算两遍，量的表无所谓但看着别扭）
        print(f"    {asset_type:15} 源 {len(rows):6} 行"
              f" -> 关联 {len(unique):6} 条（去重掉 {len(triples) - len(unique)}）"
              f"   库中已有 {before['c']}")
        total += len(unique)

        if apply and triples:
            for scan_id, key, fs, ls in triples:
                # 快照 = 资产**当前**的行值（不含大字段，见 postgres._SNAPSHOT_SQL）。
                #
                # ⚠️ **存量数据的快照只能是近似的。** 历史值早就被后续投影覆盖
                # 掉了，这里回填出来的等于"当前值"。也就是说：
                # **从现在开始才能准确追踪变更，之前已经发生的变更找不回来了。**
                # 设计文档 §9.2 记了这件事。
                snapshot = await st._snapshot_of(asset_type, key)
                await st.conn.execute(
                    """
                    INSERT INTO scan_asset
                        (scan_id, asset_type, asset_key, first_seen, last_seen,
                         snapshot_json)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (scan_id, asset_type, asset_key) DO UPDATE SET
                        first_seen    = LEAST(scan_asset.first_seen, excluded.first_seen),
                        last_seen     = GREATEST(scan_asset.last_seen, excluded.last_seen),
                        snapshot_json = excluded.snapshot_json
                    """,
                    (
                        scan_id, asset_type, key, fs, ls,
                        json.dumps(snapshot, ensure_ascii=False, default=str),
                    ),
                )
            await st.conn.commit()

    print(f"    合计 {len(_ASSET_SOURCES)} 类 / {total} 条关联"
          + ("（已写库）" if apply else ""))


async def reconcile(st) -> None:
    """对账。迁移后必跑（设计文档 §6.4）。"""
    print(f"\n  ══ 对账 ══")

    for table, col in (("url", "dedup_key"), ("http_endpoint", "dedup_key")):
        nulls = await st._fetchone(
            f"SELECT COUNT(*) AS c FROM {table} WHERE {col} IS NULL"
        )
        dup = await st._fetchone(
            f"""SELECT COUNT(*) AS c FROM (
                    SELECT {col} FROM {table} WHERE {col} IS NOT NULL
                    GROUP BY {col} HAVING COUNT(*) > 1) t"""
        )
        print(f"  {table}.{col}: 未回填 {nulls['c']} 行；"
              f"重复键 {dup['c']} 组"
              + ("（M7-c 阶段预期 >0，M7-d 切唯一键后才归零）" if dup["c"] else " ✓"))

    # 孤儿关联行：asset_key 在对应资产表里找不到
    orphans = 0
    checks = [
        ("domain", "SELECT COUNT(*) AS c FROM scan_asset sa WHERE sa.asset_type='domain' "
                   "AND NOT EXISTS (SELECT 1 FROM domain d WHERE d.name = sa.asset_key)"),
        ("ip", "SELECT COUNT(*) AS c FROM scan_asset sa WHERE sa.asset_type='ip' "
               "AND NOT EXISTS (SELECT 1 FROM ip i WHERE i.addr = sa.asset_key)"),
        ("url", "SELECT COUNT(*) AS c FROM scan_asset sa WHERE sa.asset_type='url' "
                "AND NOT EXISTS (SELECT 1 FROM url u WHERE u.dedup_key = sa.asset_key)"),
        ("http_endpoint",
         "SELECT COUNT(*) AS c FROM scan_asset sa WHERE sa.asset_type='http_endpoint' "
         "AND NOT EXISTS (SELECT 1 FROM http_endpoint e WHERE e.dedup_key = sa.asset_key)"),
        ("technology",
         "SELECT COUNT(*) AS c FROM scan_asset sa WHERE sa.asset_type='technology' "
         "AND NOT EXISTS (SELECT 1 FROM technology t "
         "                WHERE t.host || '|' || t.name = sa.asset_key)"),
        ("port", "SELECT COUNT(*) AS c FROM scan_asset sa WHERE sa.asset_type='port' "
                 "AND NOT EXISTS (SELECT 1 FROM port p "
                 "                WHERE p.ip || '|' || p.port || '|' || p.protocol "
                 "                      = sa.asset_key)"),
    ]
    for label, sql in checks:
        row = await st._fetchone(sql)
        orphans += row["c"]
        mark = "✓" if row["c"] == 0 else "⚠"
        print(f"  {mark} {label:15} 孤儿关联行 {row['c']}")
    if orphans:
        print(f"\n  ⚠ 共 {orphans} 条孤儿 —— 说明键算法与回填不一致，先别看 M7-d")


async def make_backups(st) -> None:
    """动手前整体备份。**只在 --apply 时做。**

    备份表**保留到验证通过之后**再手工删 —— 迁移没有变更日志，
    这是唯一的回退手段。
    """
    print(f"  ══ 备份 ══")
    for table in ("url", "http_endpoint", "scan_asset"):
        name = f"{table}_migbak_{BACKUP_DATE}"
        exists = await st._fetchone(
            "SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_name = ?",
            (name,),
        )
        if exists["c"]:
            print(f"    {name} 已存在，跳过（幂等）")
            continue
        await st.conn.execute(f"CREATE TABLE {name} AS SELECT * FROM {table}")
        await st.conn.commit()
        n = await st._fetchone(f"SELECT COUNT(*) AS c FROM {name}")
        print(f"    ✓ {name}  ({n['c']} 行)")


async def main() -> None:
    ap = argparse.ArgumentParser(description="M7-c 回填 dedup_key / schemes / scan_asset")
    ap.add_argument("--apply", action="store_true", help="建备份 + 真的写库（默认只报告）")
    ap.add_argument("--verify", action="store_true", help="只跑对账")
    ap.add_argument("--no-backup", action="store_true", help="跳过备份（**危险**）")
    args = ap.parse_args()

    st = PostgresStorage(default_dsn(), create_search_index=False)
    await st.open()
    try:
        if args.verify:
            await reconcile(st)
            return

        mode = "**写库**" if args.apply else "**干跑**（不会改任何数据）"
        print(f"  M7-c 回填 —— {mode}\n")

        if args.apply and not args.no_backup:
            await make_backups(st)
            print()

        await backfill_urls(st, apply=args.apply)
        await backfill_endpoints(st, apply=args.apply)
        await backfill_scan_asset(st, apply=args.apply)
        await reconcile(st)

        if not args.apply:
            print("\n  要真的写库请加 --apply")
    finally:
        await st.close()


asyncio.run(main())
