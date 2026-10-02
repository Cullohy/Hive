"""M7-d 第 1 步：把重复的资产行**合并成一条**（``url`` 表 1495 -> 1048）。

配套设计见 ``设计-资产表跨scan去重迁移.md`` §6.2。

## 这一步是整次迁移里**唯一不可逆**的操作

前面 M7-b/M7-c 都是"只加不删"，删掉列或清空 `scan_asset` 就回去了。
这一步**真的删行** —— 所以：

* 默认**干跑**，把"谁存活、谁被删、first_seen/last_seen 变成什么"全列出来
* ``--apply`` 会**先建备份表**再动手
* 删之前会检查外键引用并**重指向**（见下）

## 外键重指向

``url`` / ``http_endpoint`` **没有任何外键指向它们的 id**，所以删行无副作用。
但 ``domain`` 与 ``ip`` 有：

    domain_ip.domain_id -> domain.id
    domain_ip.ip_id     -> ip.id
    port.ip_id          -> ip.id

现在这两张表的"可合并数"是 0（还没有目标被扫过两遍），**但脚本必须能处理** ——
否则等到真有跨扫描重复时，删行会直接违反外键约束（或者更糟：报错前已经删了一半）。

## 怎么选存活行

按设计文档 §6.2：

===============  ==========================================
字段             取谁
===============  ==========================================
``first_seen``  **最早**的（资产的真实首见时间）
``last_seen``   **最晚**的
``schemes``     并集（M7-c 已经预先算成并集了，这里只做兜底）
存活行本身       ``first_seen`` 最早的那条；平手取 ``id`` 最小
===============  ==========================================
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.storage.postgres import PostgresStorage, default_dsn  # noqa: E402

BACKUP_DATE = datetime.now(timezone.utc).strftime("%Y%m%d")

#: 每个资产表：键列、以及**指向它 id 的外键**（删行前要重指向）。
#:
#: ``url`` / ``http_endpoint`` 的键是**算出来的一列**；``domain`` / ``ip`` 是自然列。
#: 两种都统一成"按某一列分组"，这样脚本只有一份逻辑。
SPECS: dict[str, dict] = {
    "url": {"key_col": "dedup_key", "refs": []},
    "http_endpoint": {"key_col": "dedup_key", "refs": []},
    # 下面两张现在没有重复，但重扫描之后会有 —— 外键必须先重指向再删行
    "domain": {
        "key_col": "name",
        "refs": [("domain_ip", "domain_id")],
    },
    "ip": {
        "key_col": "addr",
        "refs": [("domain_ip", "ip_id"), ("port", "ip_id")],
    },
}


async def merge_table(st, table: str, spec: dict, *, apply: bool) -> tuple[int, int]:
    """合并一张表。返回 ``(合并前行数, 删掉的行数)``。"""
    key_col = spec["key_col"]
    rows = await st._fetchall(
        f"SELECT id, {key_col} AS k, first_seen, last_seen FROM {table} "
        f"WHERE {key_col} IS NOT NULL ORDER BY {key_col}, first_seen, id"
    )
    groups: dict[str, list] = defaultdict(list)
    for r in rows:
        groups[r["k"]].append(r)

    dupes = {k: v for k, v in groups.items() if len(v) > 1}
    print(f"\n  ── {table} ──")
    print(f"    {len(rows)} 行 / {len(groups)} 个键 / **{len(dupes)} 个键需要合并**")

    if not dupes:
        print("    没有重复，跳过")
        return len(rows), 0

    plan: list[tuple] = []          # (keep_id, new_fs, new_ls, drop_ids)
    drop_total = 0
    for key, members in dupes.items():
        keep = members[0]           # 已按 first_seen, id 排序
        new_fs = min(m["first_seen"] for m in members)
        new_ls = max(m["last_seen"] for m in members)
        drops = [m["id"] for m in members[1:]]
        plan.append((keep["id"], new_fs, new_ls, drops))
        drop_total += len(drops)

    print(f"    将删除 {drop_total} 行，存活 {len(plan)} 行")
    # ⚠️ 这里**不能**写 `if v[0]['first_seen'] != min(...)` —— 存活行本来就是按
    # first_seen 升序选的第一条，那个判断**恒为 0**，是一句废代码。
    # （第一版就是这么写的，报"first_seen 需要修正的: 0"，看着像好消息，
    #   实际什么都没测。）真正要看的是这两件事：
    span = sum(1 for v in dupes.values()
               if min(m["first_seen"] for m in v) != max(m["last_seen"] for m in v))
    stale = sum(1 for v in dupes.values()
                if v[0]["last_seen"] != max(m["last_seen"] for m in v))
    print(f"    组内观测跨时间的: {span} 组（说明这些行的 first/last_seen 本来不同）")
    print(f"    **last_seen 需要修正的: {stale} 组**（存活行自己的 last_seen 不是最晚的）")
    print(f"    前 3 组:")
    for key, members in list(dupes.items())[:3]:
        print(f"      {key[:50]}")
        print(f"        存活 id={members[0]['id']}  "
              f"first_seen {members[0]['first_seen']} -> {min(m['first_seen'] for m in members)}")
        print(f"        删除 {[m['id'] for m in members[1:]][:6]}"
              f"{' …' if len(members) > 7 else ''}")

    # 外键重指向：**必须在删行之前**，否则删到一半会违反约束
    refs = spec.get("refs") or []
    ref_moves = 0
    for ref_table, ref_col in refs:
        for keep_id, _fs, _ls, drops in plan:
            if not drops:
                continue
            n = await st._fetchone(
                f"SELECT COUNT(*) AS c FROM {ref_table} WHERE {ref_col} = ANY(?)",
                (drops,),
            )
            ref_moves += n["c"]
            if apply and n["c"]:
                await st.conn.execute(
                    f"UPDATE {ref_table} SET {ref_col} = ? WHERE {ref_col} = ANY(?)",
                    (keep_id, drops),
                )
    if refs:
        print(f"    外键重指向: {ref_moves} 行（{', '.join(t for t, _ in refs)}）")

    if apply:
        for keep_id, new_fs, new_ls, drops in plan:
            await st.conn.execute(
                f"UPDATE {table} SET first_seen = ?, last_seen = ? WHERE id = ?",
                (new_fs, new_ls, keep_id),
            )
            await st.conn.execute(
                f"DELETE FROM {table} WHERE id = ANY(?)", (drops,)
            )
        await st.conn.commit()
        left = await st._fetchone(f"SELECT COUNT(*) AS c FROM {table}")
        print(f"    ✓ 已写库，现在 {left['c']} 行")

    return len(rows), drop_total


async def make_backup(st, table: str) -> None:
    name = f"{table}_migbak_merge_{BACKUP_DATE}"
    exists = await st._fetchone(
        "SELECT COUNT(*) AS c FROM information_schema.tables WHERE table_name = ?",
        (name,),
    )
    if exists["c"]:
        print(f"    {name} 已存在，跳过")
        return
    await st.conn.execute(f"CREATE TABLE {name} AS SELECT * FROM {table}")
    await st.conn.commit()
    n = await st._fetchone(f"SELECT COUNT(*) AS c FROM {name}")
    print(f"    ✓ {name} ({n['c']} 行)")


async def verify(st) -> None:
    print(f"\n  ══ 验证 ══")
    for table, spec in SPECS.items():
        key_col = spec["key_col"]
        r = await st._fetchone(
            f"SELECT COUNT(*) AS n, COUNT(DISTINCT {key_col}) AS k FROM {table} "
            f"WHERE {key_col} IS NOT NULL"
        )
        ok = r["n"] == r["k"]
        print(f"  {'✓' if ok else '✗'} {table:16} {r['n']} 行 / {r['k']} 个键"
              + ("" if ok else "  ← **还有重复**"))


async def main() -> None:
    ap = argparse.ArgumentParser(description="M7-d 第 1 步：合并重复资产行")
    ap.add_argument("--apply", action="store_true", help="建备份 + 真的删行")
    ap.add_argument("--table", default="url", choices=sorted(SPECS),
                    help="只处理某张表（默认 url，它是唯一真有重复的）")
    ap.add_argument("--all", action="store_true", help="所有资产表都过一遍")
    ap.add_argument("--verify", action="store_true", help="只验证")
    args = ap.parse_args()

    st = PostgresStorage(default_dsn(), create_search_index=False)
    await st.open()
    try:
        if args.verify:
            await verify(st)
            return

        targets = sorted(SPECS) if args.all else [args.table]
        print(f"  M7-d 合并 —— {'**写库**' if args.apply else '**干跑**'}"
              f"    表: {', '.join(targets)}\n")

        if args.apply:
            print("  ══ 备份 ══")
            for t in targets:
                await make_backup(st, t)
            print()

        total_before = total_dropped = 0
        for t in targets:
            before, dropped = await merge_table(st, t, SPECS[t], apply=args.apply)
            total_before += before
            total_dropped += dropped

        print(f"\n  合计: {total_before} 行 -> 删除 {total_dropped} 行"
              f" = {total_before - total_dropped} 行")

        if args.apply:
            await verify(st)
        else:
            print("\n  要真的写库请加 --apply")
    finally:
        await st.close()


asyncio.run(main())
