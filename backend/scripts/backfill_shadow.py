"""回填 ``domain.shadow_kind`` —— 给**已经扫完的历史数据**补上影子资产标记。

## 为什么需要它

``shadow_kind`` 是后加的列。加之前跑的所有扫描，那一列全是 NULL ——
表现为"影子资产卡片显示 0"，而实际上库里躺着几百个测试环境。

实测（回填前）：

    panabit.com      域名 3205   其中影子资产 326
    chinazy.org      域名   54   其中影子资产   3

## 怎么用

    python scripts/backfill_shadow.py            # 干跑，只报告不改
    python scripts/backfill_shadow.py --apply    # 真的写库

默认**干跑**。这一步是 UPDATE，写错了没法回滚（没有变更日志），
所以先看清楚再 ``--apply``。

## 它用的是同一套匹配逻辑

直接 import ``shadow_asset`` 的匹配方法，不另写一份 SQL 版 —— 两套实现
迟早会分叉，而分叉的表现是"新扫的和老数据的判定不一致"，极难查。
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.domains.subdomain.standalone.shadow_asset import shadow_asset  # noqa: E402
from core.engine.preset import Preset  # noqa: E402
from core.engine.scanner import Scanner  # noqa: E402
from core.storage.postgres import PostgresStorage, default_dsn  # noqa: E402


def _targets(raw) -> list[str]:
    try:
        got = json.loads(raw or "[]")
    except (TypeError, ValueError):
        return []
    return [str(t) for t in got if t]


async def main() -> None:
    ap = argparse.ArgumentParser(description="回填 domain.shadow_kind")
    ap.add_argument("--apply", action="store_true", help="真的写库（默认只报告）")
    ap.add_argument("--scan-id", type=int, default=None, help="只处理某一次扫描")
    args = ap.parse_args()

    storage = PostgresStorage(default_dsn(), create_search_index=False)
    await storage.open()
    try:
        if args.scan_id:
            scans = await storage._fetchall(
                "SELECT id, targets_json FROM scan WHERE id = ? ORDER BY id",
                (args.scan_id,),
            )
        else:
            scans = await storage._fetchall(
                "SELECT id, targets_json FROM scan ORDER BY id"
            )
        if not scans:
            print("  库里没有扫描")
            return

        total_hits = total_domains = 0
        for row in scans:
            scan_id = int(row["id"])
            targets = _targets(row["targets_json"])
            preset = Preset(name="backfill")
            preset.include = None
            preset.exclude = []
            scanner = Scanner(
                targets=targets or ["invalid.invalid"], preset=preset, storage=None
            )
            matcher = shadow_asset(scanner)
            if await matcher.setup() is not True:
                print(f"  扫描 #{scan_id}: 匹配器起不来，跳过")
                continue

            domains = await storage._fetchall(
                "SELECT name, shadow_kind FROM domain WHERE scan_id = ? ORDER BY name",
                (scan_id,),
            )
            total_domains += len(domains)
            updates: list[tuple[str, str]] = []
            for d in domains:
                kind = matcher.match(d["name"])
                if kind and kind != d["shadow_kind"]:
                    updates.append((d["name"], kind))

            by_kind: dict[str, int] = {}
            for _, kind in updates:
                by_kind[kind] = by_kind.get(kind, 0) + 1
            total_hits += len(updates)
            summary = "、".join(f"{k} {v}" for k, v in sorted(by_kind.items())) or "无"
            print(
                f"  扫描 #{scan_id:3}  域名 {len(domains):5}  "
                f"待标记 {len(updates):4}  ({summary})"
            )

            if args.apply:
                for name, kind in updates:
                    await storage.conn.execute(
                        "UPDATE domain SET shadow_kind = ? WHERE scan_id = ? AND name = ?",
                        (kind, scan_id, name),
                    )
                if updates:
                    await storage.conn.commit()

        print(f"\n  合计: 域名 {total_domains}  影子资产 {total_hits}")
        print("  已写库" if args.apply else "  **干跑** —— 要真的写库请加 --apply")
    finally:
        await storage.close()


asyncio.run(main())
