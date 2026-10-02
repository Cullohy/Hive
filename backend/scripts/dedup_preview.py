"""``dedup_key`` 规则在**真实采集数据**上的预览。迁移前的必做验证。

## 为什么要有这个脚本

``dedup_key`` 写歪了不会报错，只会让数字慢慢不可信。跑这个脚本能把
"合并之后长什么样"在**动手改库之前**看清楚，尤其是两类危险：

* **合过头**（两条不同的资产被合成一条）—— 永久丢信息，没人会发现
* **没合掉**（该合的还是两条）—— 去重形同虚设

脚本默认**只读**，不动任何数据。

    python scripts/dedup_preview.py              # 看 url 表
    python scripts/dedup_preview.py --table http_endpoint
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncpg  # noqa: E402

from core.storage.postgres import default_dsn  # noqa: E402
from core.util.asset_key import endpoint_key, url_key  # noqa: E402


async def main() -> None:
    ap = argparse.ArgumentParser(description="dedup_key 合并预览（只读）")
    ap.add_argument("--table", default="url", choices=["url", "http_endpoint"])
    ap.add_argument("--show", type=int, default=15, help="展示多少个合并组")
    args = ap.parse_args()

    keyfn = url_key if args.table == "url" else endpoint_key

    conn = await asyncpg.connect(default_dsn())
    try:
        rows = await conn.fetch(f"SELECT DISTINCT url FROM {args.table} ORDER BY url")
    finally:
        await conn.close()

    urls = [r["url"] for r in rows]
    print(f"  table={args.table}   唯一 URL {len(urls)} 条")

    groups: dict[str, list[str]] = defaultdict(list)
    for u in urls:
        groups[keyfn(u)].append(u)

    merged = {k: v for k, v in groups.items() if len(v) > 1}
    collapsed = len(urls) - len(groups)

    print(f"  dedup_key 唯一值 {len(groups)} 个")
    print(f"  **合并掉 {collapsed} 条（{collapsed*100//max(len(urls),1)}%）**\n")

    if not merged:
        print("  没有需要合并的 —— 现有数据本身就没有重复")
        return

    for k, v in sorted(merged.items(), key=lambda x: -len(x[1]))[: args.show]:
        print(f"  x{len(v):<3} {k}")
        for one in v[:4]:
            print(f"         {one[:104]}")
        if len(v) > 4:
            print(f"         … 还有 {len(v)-4} 条")

    # ── 风险自查 1：只差大小写的组 —— 如果规则里把路径小写化，这些会被错合 ──
    case_only = [
        (k, v) for k, v in merged.items() if len({x.lower() for x in v}) == 1
    ]
    print(f"\n  ── 风险自查 ──")
    print(f"  只差大小写的合并组: {len(case_only)} 个")
    if case_only:
        print("    这些组里两条 URL **仅仅**大小写不同 —— 保留大小写的规则让它们")
        print("    正确地保持为两条（Linux 上 `/Admin` 与 `/admin` 可以是两个资源）:")
        for k, v in case_only[:5]:
            print(f"      {k}")
            for one in v[:3]:
                print(f"        {one[:100]}")

    # ── 风险自查 2：参数不同才合起来的组（预期中的主力）──
    with_q = [(k, v) for k, v in merged.items() if any("?" in x for x in v)]
    print(f"  含 query string 的合并组: {len(with_q)} 个（预期中的主力）")

    # ── 风险自查 3：分布 —— 有多少组是因为 host/端口 不同而挂在一起 ──
    hosts = Counter(k.split("|", 1)[0] for k in groups)
    print(f"  涉及的不同 authority: {len(hosts)} 个")


asyncio.run(main())
