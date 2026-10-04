"""从 wafw00f 导入 WAF 指纹 —— 一条命令刷新导入的那部分。

    python scripts/import_wafw00f.py --src D:/tmp/wafw00f          # 导入
    python scripts/import_wafw00f.py --src D:/tmp/wafw00f --dry-run  # 只报告差异
    python scripts/import_wafw00f.py --src D:/tmp/wafw00f --check   # 校验库与上游一致

**为什么要有这个脚本**：wafw00f（BSD-3）那 170 多个插件是别人在维护的
资产，会持续更新。打包一份静态副本等于把它冻结在某个时间点，之后既不会
更新、也说不清改过什么 —— 和 ``import_fingerprints.py`` 同一个理由。

**怎么抽的**：插件是 Python 代码（``def is_waf(self)`` 里一串原语调用），
所以用 :mod:`ast` 解析而不是正则 —— 正则改不动 ``re.search`` 那种写法，
而且很容易把注释和字符串里的同形文本也算进去。

**为什么不 exec 那个模块**：直接 import 上游代码等于在���进程里执行第三方
代码。AST 解析只读语法树，不执行任何东西。

⚠️ **本机 HTTPS 是全挂的**（PowerShell / curl / urllib 都连不上，
只有 ``git clone`` 通，因为 Git for Windows 用自带的 OpenSSL 而不是
Windows schannel）。所以 ``--src`` 要指向一个已经 clone 下来的目录。

许可证：wafw00f 是 **BSD-3-Clause**。导入的条目在 ``waf.json`` 里带
``source: "wafw00f"``，来源与许可记在 ``core/resources/ATTRIBUTION.md``。
"""

from __future__ import annotations

import argparse
import ast
import json
import pathlib
import re
import sys
from collections import Counter

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from core.domains.fingerprint._lib.waf import DEFAULT_DB   # noqa: E402

#: 自研那部分指纹单独存一份 —— 导入时按名字与上游**合并**（实测 13 个厂商两边
#: 都有，自研有 35 条是上游没有的）。库文件 ``waf.json`` 每次都从
#: 「自研文件 + 本次导入」重算，所以重跑不会累积。
BUILTIN_DB = DEFAULT_DB.with_name("waf_builtin.json")

SOURCE = "wafw00f"

#: wafw00f 的原语 → 本项目的规则类型。
#:
#: ⚠️ **各原语的 ``attack`` 默认值不一样**，这一项决定了导入的规则在
#: ``passive``（只读已有响应）模式下到底能不能用：
#:
#:   matchHeader  attack=False  → 正常响应就能匹配（签名可识别）
#:   matchCookie  attack=False  → 同上（内部转 matchHeader）
#:   matchContent attack=True   → 只在被攻击后的响应里匹配
#:   matchStatus  attack=True   → 同上
#:   matchReason  attack=True   → 同上
#:
#: 实测 172 个插件里 49 个只认正常响应、60 个两种都认、63 个只认攻击响应。
#: 也就是说签名模式下能用 109/172，剩下的要靠 ``dir_brute`` 在 ``active``
#: 模式发载荷才点得着。``--only-signature`` 可以只导前 109 个。
PRIMITIVE_DEFAULTS = {
    "matchHeader": False,
    "matchCookie": False,
    "matchContent": True,
    "matchStatus": True,
    "matchReason": True,
    "matchLib": True,
    "matchRegEx": True,
}
PRIMITIVE_TYPE = {
    "matchHeader": "header",
    "matchCookie": "cookie",
    "matchContent": "body",
    "matchStatus": "status",
    "matchReason": "reason",
}

#: wafw00f 用 ``re.search``，我们默认也用正则 + ``re.I``。
REGEX_TYPES = {"header", "server", "cookie", "body"}


class Report:
    def __init__(self) -> None:
        self.dropped: list[str] = []
        self.notes: list[str] = []

    def drop(self, msg: str) -> None:
        self.dropped.append(msg)


def _literal(node: ast.AST) -> str | int | None:
    """把常量节点求值成字符串或整数；不是字面量就返回 None。"""
    try:
        val = ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        return None
    # matchStatus 传的是 int（403 / 400），matchContent 传的是 str
    return val if isinstance(val, (str, int)) else None


def _is_match_call(node: ast.AST) -> ast.Call | None:
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in PRIMITIVE_TYPE):
        return node
    return None


def _rule_from_call(node: ast.Call) -> dict | None:
    fn = node.func.attr
    kwargs = {k.arg: getattr(k.value, "value", None) for k in node.keywords}
    is_attack = bool(kwargs["attack"]) if "attack" in kwargs else PRIMITIVE_DEFAULTS[fn]
    rtype = PRIMITIVE_TYPE[fn]

    if rtype == "header":
        try:
            pair = ast.literal_eval(node.args[0])
            hname, pattern = str(pair[0]), str(pair[1])
        except (IndexError, ValueError, SyntaxError, TypeError):
            return None
        rule = {"type": "header", "name": hname.lower(), "pattern": pattern}
    else:
        if not node.args:
            return None
        text = _literal(node.args[0])
        if text is None:
            return None
        rule = {"type": rtype, "pattern": str(text)}

    if rtype in REGEX_TYPES:
        rule["mode"] = "regex"
        rule["ignoreCase"] = True
    # ⚠️ **逐条**标 attackOnly，不是按插件。混用插件里 header 规则签名可用、
    # content 规则不可用；按插件一刀切会砍掉可用的，不标则更糟 ——
    # DenyALL 的 `status == 200` 会被拿去查正常响应，于是**每个站点都成 DenyALL**。
    rule["attackOnly"] = is_attack
    return rule


def _function_groups(fn: ast.FunctionDef, report: Report,
                     tag: str) -> list[list[dict]]:
    """把一个函数抽成「若干组，每组若干条（同组 AND）」。

    认两种写法：

    * ``if self.matchX(...): return True``  → OR，每条自己一组
    * ``if not self.matchX(...): return False`` → AND，**全部合成一组**
      （末尾的 ``return True`` / ``return False`` 是隐含的，不另抽）
    """
    and_rules: list[dict] = []
    or_rules: list[dict] = []

    for stmt in fn.body:
        if not isinstance(stmt, ast.If):
            continue
        test = stmt.test
        negated = isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
        call = _is_match_call(test.operand if negated else test)
        if call is None:
            continue
        rule = _rule_from_call(call)
        if rule is None:
            report.drop(f"{tag}: {fn.name} 里有取不出字面量的调用")
            continue
        (and_rules if negated else or_rules).append(rule)

    groups: list[list[dict]] = []
    if and_rules:
        groups.append(and_rules)            # 全部同时成立
    groups.extend([[r] for r in or_rules])  # 任一成立即可
    return groups


def parse_plugin(path: pathlib.Path, report: Report) -> dict | None:
    """把一个插件文件解析成一条待导入的库条目（保留 AND/OR 结构）。"""
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
    except SyntaxError as e:
        report.drop(f"{path.name}: 语法错误 {e}")
        return None

    name = path.stem
    for node in tree.body:
        if (isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", "") == "NAME"):
            try:
                name = str(ast.literal_eval(node.value))
            except (ValueError, SyntaxError):
                pass

    fns = {
        f.name: f for f in tree.body
        if isinstance(f, ast.FunctionDef) and f.args.args
        and f.args.args[0].arg == "self"
    }
    is_waf = fns.get("is_waf")
    if is_waf is None:
        return None

    # is_waf 自己带 match 调用 → 纯 OR，直接抽它的。
    # 否则它只是在委派给 check_schema_* —— 那些函数的组才是真正的规则组。
    #
    # ⚠️ 辅助函数必须**按 AST 里出现的顺序**取，不能去重成 set：
    # set 的迭代顺序取决于 PYTHONHASHSEED，跨进程会变，于是规则顺序每跑一次
    # 都不一样，``--check`` 永远说"库与上游不一致"。
    if any(_is_match_call(s.test) or (
            isinstance(s.test, ast.UnaryOp) and _is_match_call(s.test.operand))
            for s in is_waf.body if isinstance(s, ast.If)):
        sources = [is_waf]
    else:
        called: list[str] = []
        for n in ast.walk(is_waf):
            if (isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                    and n.func.id in fns and n.func.id not in called):
                called.append(n.func.id)
        sources = [fns[n] for n in called] or list(fns.values())

    groups: list[list[dict]] = []
    for fn in sources:
        groups.extend(_function_groups(fn, report, path.stem))
    if not groups:
        return None

    rules: list[dict] = []
    for gid, members in enumerate(groups):
        for rule in members:
            rule["group"] = gid
            rules.append(rule)

    # NAME 形如 "Cloudflare (Cloudflare Inc.)" → name=厂商, vendor=括号里的
    m = re.match(r"^(.*?)\s*\((.*)\)\s*$", name)
    vendor = m.group(2) if m else ""
    return {
        "name": m.group(1).strip() if m else name,
        "vendor": vendor,
        # wafw00f 没给置信度。header/cookie 规则是厂商主动留痕的（较硬），
        # body/status/reason 可能是巧合撞上，所以整条按 medium 起步 ——
        # 真正要严格的时候（dir_brute 的放弃闸门）由 waf_min_confidence 控。
        "confidence": "medium",
        "source": SOURCE,
        "rules": rules,
        # 供 --only-signature / 报告用，不写进 waf.json
        "_signature_only": not any(r["attackOnly"] for r in rules),
    }


def collect(src: pathlib.Path, *, only_signature: bool) -> tuple[list[dict], Report]:
    plugins = src / "wafw00f" / "plugins"
    if not plugins.is_dir():
        plugins = src / "plugins"
    if not plugins.is_dir():
        raise SystemExit(f"找不到插件目录: {plugins}")

    report = Report()
    out: list[dict] = []
    for path in sorted(plugins.glob("*.py")):
        if path.name == "__init__.py":
            continue
        entry = parse_plugin(path, report)
        if entry is None:
            continue
        signature_only = entry.pop("_signature_only")
        if only_signature and not signature_only:
            report.drop(f"{path.name}: 只认被拦截响应，--only-signature 下跳过")
            continue
        out.append(entry)
    return out, report


def merge(builtin: list[dict], imported: list[dict]) -> tuple[list[dict], int, int]:
    """按名字**合并**自研与导入条目，产出完整的库。

    为什么要合而不是二选一：实测 13 个厂商两边都有，而自研那 44 条里有
    **35 条是导入版没有的**（多半是"只看响应头在不在"这种宽松检查）。
    跳过会白丢 168 个厂商的覆盖，替换会丢这 35 条，所以合。

    合并时把自研规则的组号**逐条重排** —— 它们原本是 OR 语义（组号都是 0），
    直接塞进分组结构会变成"全部同时成立"。

    幂等：``waf.json`` 每次都是「自研文件 + 本次导入」重新算出来的，
    不依赖上一轮的结果，所以重复跑不会累积。
    """
    by_name: dict[str, dict] = {}
    clashes = 0
    for entry in builtin:
        rules = []
        for i, r in enumerate(entry.get("rules") or []):
            r = dict(r)
            r["group"] = i          # 原本都是 0（OR），逐条拆成独立组
            r.setdefault("origin", "builtin")
            rules.append(r)
        by_name[entry["name"]] = {
            "name": entry["name"],
            "vendor": entry.get("vendor", ""),
            "confidence": entry.get("confidence", "medium"),
            "source": None,
            "rules": rules,
        }

    for entry in imported:
        name = entry["name"]
        base = by_name.get(name)
        if base is None:
            by_name[name] = entry
            continue
        clashes += 1
        # ⚠️ **整体偏移组号，不能逐条重编。**
        # 导入条目内部的组号带着 AND 结构（`check_schema_02` 是
        # 「reason==… **且** status==403」一组），逐条重编会把它拆成两组，
        # 于是裸的 `status == 403` 就成立 —— 实测后果是**任何对探测载荷回 403
        # 的站点都被判成 ModSecurity**。偏移之后两组才各自保持完整。
        offset = max((r.get("group", 0) for r in base["rules"]), default=-1) + 1
        merged_rules = list(base["rules"])
        for r in entry["rules"]:
            r = dict(r)
            r["group"] = offset + r.get("group", 0)
            r.setdefault("origin", SOURCE)
            merged_rules.append(r)
        base["rules"] = merged_rules
        base["vendor"] = base["vendor"] or entry.get("vendor", "")
        base["source"] = SOURCE          # 整条按导入算，重跑时能被替换

    return list(by_name.values()), len(builtin), clashes


def main() -> int:
    ap = argparse.ArgumentParser(description="从 wafw00f 导入 WAF 指纹")
    ap.add_argument("--src", required=True, help="已 clone 的 wafw00f 目录")
    ap.add_argument("--out", default=str(DEFAULT_DB), help="目标库文件")
    ap.add_argument("--builtin", default=str(BUILTIN_DB), help="自研指纹文件")
    ap.add_argument("--only-signature", action="store_true",
                    help="只导签名模式能用的（跳过只认被拦截响应的插件）")
    ap.add_argument("--dry-run", action="store_true", help="只报告，不写文件")
    ap.add_argument("--check", action="store_true",
                    help="校验库与上游一致（CI 用；有差异就退出码 1）")
    args = ap.parse_args()

    src = pathlib.Path(args.src)
    out = pathlib.Path(args.out)
    builtin_path = pathlib.Path(args.builtin)
    imported, report = collect(src, only_signature=args.only_signature)

    if builtin_path.is_file():
        builtin = json.loads(builtin_path.read_text(encoding="utf-8")).get("wafs", [])
    else:
        builtin = []

    wafs, n_builtin, clashes = merge(builtin, imported)
    merged = {
        "version": 1,
        "sources": [
            {"id": "builtin", "file": builtin_path.name, "entries": n_builtin},
            {"id": SOURCE, "entries": len(imported)},
        ],
        "wafs": wafs,
    }
    total = len(wafs)
    rules = sum(len(w.get("rules", [])) for w in wafs)

    print(f"插件目录      {src}")
    print(f"自研          {n_builtin} 条")
    print(f"导入          {len(imported)} 条（与自研重名并合并 {clashes} 个）")
    print(f"库内合计      {total} 个 WAF / {rules} 条规则")
    if report.dropped:
        print(f"\n丢弃 {len(report.dropped)} 项：")
        for msg in report.dropped:
            print(f"  - {msg}")

    if args.check:
        cur = json.loads(out.read_text(encoding="utf-8")) if out.is_file() else {}
        if cur != merged:
            print("\n[FAIL] 库与上游不一致，请重跑导入")
            return 1
        print("\n[OK] 库与上游一致")
        return 0

    if args.dry_run:
        print("\n--dry-run：未写文件")
        return 0

    out.write_text(
        json.dumps(merged, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(f"\n已写入 {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
