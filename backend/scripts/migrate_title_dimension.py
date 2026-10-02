"""一次性迁移：把 ``match.html`` 里"其实是按 ``<title>`` 匹配"的模式搬进 ``title``。

    python scripts/migrate_title_dimension.py            # 干跑，只报告（默认）
    python scripts/migrate_title_dimension.py --apply    # 原地改写库文件

## 为什么要做

``MatchSet`` 支持 11 个匹配维度，其中 ``title`` **一条规则都没有**
（8843 条技术里 title=0、url=0）。真因不是来源库没有标题匹配，而是导入器
把 617 条拿 ``<title>`` 当锚点写的模式按"匹配器没写 part，缺省就是 body"
归进了 ``match.html``（见 ``importers._apply_matcher``）。

## 改判判据

**只写在一处**：``core/domains/fingerprint/_lib/title_migration.py``。
本脚本与导入器调的是同一个 :func:`migrate_match_dict` —— 这个仓库里
"两处判据分头演化"已经出过 bug（``importers._MMH3_RE`` 那段注释：
favicon 哈希按"8 位十六进制"认，191 个十进制哈希被误判成格式不认识）。

两种形态的转换规则**不同**：

* ``(?mi)<title[^>]*>X.*?</title>`` → ``title`` 加 ``X``，**不加锚**
  （原来 ``X`` 后面是 ``.*?``，``X - 站点名`` 这类尾部要能命中）
* ``<title>X</title>`` → ``title`` 加 ``^\\s*X\\s*$``，**必须加锚**
  （原语义是"整个标题就是 X"；``Login`` 不加锚会匹配上 ``Please Login Here``）

``X`` 含任何正则元字符（含 ``\\``）就**保持原样留在 html**。

## 幂等

改判过的模式不会再出现在 ``html`` 里，所以对同一份文件再跑一次
``moved`` 必为空、文件字节不变。``--apply`` 里显式断言了这一点。

## 为什么要备份

库文件 2.4 MB、8843 条技术。``--apply`` 前会写一份
``fingerprints.json.bak``（只在本脚本里用，**验证完请删掉**）。
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.domains.fingerprint._lib.title_migration import (  # noqa: E402
    KIND_OTHER,
    KIND_PLAIN,
    KIND_STRICT,
    migrate_match_dict,
)

LIBRARY = ROOT / "core" / "resources" / "fingerprints.json"

#: 库文件的规范序列化形式（``--apply`` 后必须逐字节可复现）
_JSON_KWARGS: dict[str, object] = {"ensure_ascii": False, "indent": 1}

_KIND_LABEL = {
    KIND_STRICT: "严格形态 (?mi)<title[^>]*>X.*?</title>",
    KIND_PLAIN: "纯字面形态 <title>X</title>",
    KIND_OTHER: "其它形态",
}

#: 追加到顶层 ``note`` 的那条说明。**幂等**：按前缀去重，重复 --apply 不会重复追加。
NOTE_PREFIX = "指纹改判:"
NOTE_TEXT = (
    f"{NOTE_PREFIX} {date.today().isoformat()} 把 match.html 里 617 条按 <title> "
    "形态写的模式改判到 match.title：严格形态 (?mi)<title[^>]*>X.*?</title>（X 为"
    "纯字面量）改为 title 加 X（不加锚，保留原有的尾部容忍）；纯字面形态 "
    "<title>X</title> 改为 title 加 ^\\s*X\\s*$（加锚，原语义是整个标题就是 X）。"
    "X 含正则元字符的保持原样留在 html。判据与将来重新导入共用 "
    "core/domains/fingerprint/_lib/title_migration.py，一致、幂等。"
)


def dedupe_note(note: object) -> list[str]:
    """追加说明，但**不重复追加**（``--apply`` 跑多次结果一样）。"""
    items = [str(n) for n in note] if isinstance(note, list) else []
    if any(n.startswith(NOTE_PREFIX) for n in items):
        return items
    return [*items, NOTE_TEXT]


def migrate_library(raw: dict) -> tuple[dict, dict]:
    """在内存里改判整库，返回 ``(新数据, 统计)``。**不碰磁盘。**"""
    stats: dict = {
        "technologies": 0,
        "html_patterns_before": 0,
        "html_patterns_after": 0,
        "title_patterns_before": 0,
        "title_patterns_after": 0,
        "html_key_before": 0,
        "html_key_after": 0,
        "title_key_before": 0,
        "title_key_after": 0,
        "moved": 0,
        "added": 0,
        "title_shaped_total": 0,
        "kinds": Counter(),
        "skipped": Counter(),
        "per_tech": [],
    }

    for tech in raw.get("technologies") or []:
        stats["technologies"] += 1
        match = tech.get("match")
        if not isinstance(match, dict):
            continue

        before_html = list(match.get("html") or [])
        before_title = list(match.get("title") or [])
        stats["html_patterns_before"] += len(before_html)
        stats["title_patterns_before"] += len(before_title)
        # 含 ``<title`` 的模式总数 —— 改判数 + 保守留在 html 的数必须等于它
        stats["title_shaped_total"] += sum(
            1 for p in before_html if "<title" in str(p)
        )
        if before_html:
            stats["html_key_before"] += 1
        if before_title:
            stats["title_key_before"] += 1

        tid = str(tech.get("id") or tech.get("name") or "?")
        result = migrate_match_dict(match, tech_id=tid)

        stats["html_patterns_after"] += len(match.get("html") or [])
        stats["title_patterns_after"] += len(match.get("title") or [])
        if match.get("html"):
            stats["html_key_after"] += 1
        if match.get("title"):
            stats["title_key_after"] += 1

        if result.moved:
            for _tid, old, new, kind in result.moved:
                stats["kinds"][kind] += 1
            stats["moved"] += len(result.moved)
            stats["added"] += result.added
            stats["per_tech"].append((tid, len(result.moved)))
        for reason, n in result.skipped.items():
            stats["skipped"][reason] += n

    out = dict(raw)
    out["note"] = dedupe_note(raw.get("note"))
    return out, stats


def _render(stats: dict, *, header: str) -> None:
    print(f"\n  ══ {header} ══")
    print(f"  技术总数            {stats['technologies']}")
    print(f"  title 模式          {stats['title_patterns_before']:5} -> "
          f"{stats['title_patterns_after']}")
    print(f"  html  模式          {stats['html_patterns_before']:5} -> "
          f"{stats['html_patterns_after']}")
    print(f"  带 title 维度的技术 {stats['title_key_before']:5} -> "
          f"{stats['title_key_after']}")
    print(f"  带 html  维度的技术 {stats['html_key_before']:5} -> "
          f"{stats['html_key_after']}")

    print(f"\n  改判 {stats['moved']} 条，涉及 {len(stats['per_tech'])} 条技术。逐形态：")
    for kind in (KIND_STRICT, KIND_PLAIN, KIND_OTHER):
        n = stats["kinds"].get(kind, 0)
        if n:
            print(f"      {n:5}  {_KIND_LABEL[kind]}")
    if not stats["kinds"]:
        print("      （无 —— 已经是改判后的状态）")
    if stats["added"] != stats["moved"]:
        print(f"\n  其中 {stats['moved'] - stats['added']} 条被同一技术里**更宽的形态吸收**"
              f"（两种形态同字面量；加锚的'整个标题就是 X'是'标题以 X 开头'的子集）")
        print(f"  实际加进 title 维度：{stats['added']} 条")

    if stats["skipped"]:
        print("\n  保守留在 html：")
        for reason, n in stats["skipped"].most_common():
            print(f"      {n:5}  {reason}")

    if stats["per_tech"]:
        print("\n  逐条技术明细（技术 id，改判条数）：")
        for tid, n in stats["per_tech"][:25]:
            print(f"      {tid:44} {n}")
        if len(stats["per_tech"]) > 25:
            print(f"      …… 另有 {len(stats['per_tech']) - 25} 条技术")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="把 match.html 里的 <title> 形态改判到 match.title（默认干跑）"
    )
    ap.add_argument("--apply", action="store_true", help="原地改写库文件（默认只报告）")
    ap.add_argument("--path", type=Path, default=LIBRARY, help=f"库文件（默认 {LIBRARY}）")
    ap.add_argument("--no-backup", action="store_true",
                    help="--apply 时不写 .bak（不建议）")
    args = ap.parse_args(argv)

    text = args.path.read_text(encoding="utf-8")
    raw = json.loads(text)

    migrated, stats = migrate_library(raw)
    _render(stats, header="改判报告（干跑）" if not args.apply else "改判报告")

    # ── 不变量：这是搬运，不是过滤 ──
    # 改判数 + 保守留下的数 == 源文件里含 ``<title`` 的模式总数。
    # 这个不变量对**幂等**也成立：第二次跑 moved=0、留下 0，两边都是 0。
    if len(migrated["technologies"]) != len(raw["technologies"]):
        print("\n  ✗ 技术总数变了 —— 这是搬运不是过滤，拒绝写入")
        return 2
    accounted = stats["moved"] + sum(stats["skipped"].values())
    if accounted != stats["title_shaped_total"]:
        print(f"\n  ✗ 改判 {stats['moved']} + 留在 html "
              f"{sum(stats['skipped'].values())} ≠ 含 <title> 的模式总数 "
              f"{stats['title_shaped_total']}，拒绝写入")
        return 2
    print(f"\n  ✓ 不变量：{stats['moved']} 改判 + "
          f"{sum(stats['skipped'].values())} 留 html = "
          f"{stats['title_shaped_total']} 条含 <title> 的模式，一条不少")

    new_text = json.dumps(migrated, **_JSON_KWARGS)  # type: ignore[arg-type]

    if not args.apply:
        # 干跑也要能证明"写进去会不会动到别的地方"
        if new_text == text:
            print("\n  文件已是最新（这一次没有任何改动）—— 幂等 ✓")
        else:
            print(f"\n  --apply 会改写 {args.path}"
                  f"（{len(text)} -> {len(new_text)} 字符）")
        print("  要执行请加 --apply")
        return 0

    if not stats["moved"] and new_text == text:
        print("\n  文件已是最新（这一次没有任何改动）—— 幂等 ✓，不写盘")
        return 0

    backup = args.path.with_name(args.path.name + ".bak")
    if not args.no_backup:
        shutil.copy2(args.path, backup)
        print(f"\n  已备份 -> {backup}")

    args.path.write_text(new_text, encoding="utf-8")
    print(f"  ✓ 已写入 {args.path}")

    # ── 幂等自检：再跑一遍必须没有改动 ──
    written = args.path.read_text(encoding="utf-8")
    again, again_stats = migrate_library(json.loads(written))
    if again_stats["moved"] or json.dumps(again, **_JSON_KWARGS) != written:  # type: ignore[arg-type]
        print("  ✗ 幂等自检失败 —— 再跑一次还会改动，请检查判据")
        return 3
    print("  ✓ 幂等自检通过（再跑一次没有任何改动）")
    print(f"\n  备份还在 {backup} —— **验证完请删掉**，别留在仓库里")
    return 0


if __name__ == "__main__":
    sys.exit(main())
