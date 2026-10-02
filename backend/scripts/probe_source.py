"""单个被动源的调试工具。

用法::

    python scripts/probe_source.py rapiddns example.com
    python scripts/probe_source.py crtsh github.com --raw

它绕开引擎直接调用插件的 ``sub_domains()``, 同时打印「原始返回」与
「清洗后结果」, 方便判断某个源是挂在了网络、还是挂在了清洗逻辑上。
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.engine.log import setup_logging  # noqa: E402
from core.domains.subdomain._lib.dns_query import PassiveSourceModule, sanitize_subdomains  # noqa: E402
from core.services.http import HTTPClient  # noqa: E402


def _all_sources() -> dict[str, type]:
    """返回 {可用的源名: 插件类}。

    同时用模块名 (``passive_crtsh``) 和插件自报的 ``source_name``
    (``crtsh``) 作为键, 两种写法都能用。
    """
    from core.engine.scanner import Scanner
    from core.engine.preset import Preset

    scanner = Scanner(targets=["placeholder.test"], preset=Preset(name="probe"))
    scanner.load_modules()
    out: dict[str, type] = {}
    for name, module in scanner.modules.items():
        query = getattr(module, "query", None)
        if query is None:
            continue
        out[name] = query
        source_name = getattr(query, "source_name", "")
        if source_name:
            out.setdefault(source_name, query)
    return out


async def main() -> int:
    sources = _all_sources()
    parser = argparse.ArgumentParser(description="调试单个被动源")
    parser.add_argument("source", choices=sorted(sources), help="源模块名")
    parser.add_argument("target", help="根域名")
    parser.add_argument("--raw", action="store_true", help="同时打印原始返回的前 20 条")
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    setup_logging("WARNING")
    query_cls = sources[args.source]
    query = query_cls()
    if query.requires_key:
        print(f"[!] {args.source} 需要 API Key; 这里没有配置, 直接跳过")
        return 2

    async with HTTPClient(timeout=args.timeout) as http:
        try:
            raw = await query.sub_domains(args.target, http)
        except Exception as e:
            print(f"[x] {args.source} 请求失败: {type(e).__name__}: {e}")
            return 1

    raw_list = list(raw or [])
    clean = sanitize_subdomains(raw_list, args.target)
    print(f"[+] {args.source} @ {args.target}")
    print(f"    原始返回 : {len(raw_list)} 条")
    print(f"    清洗之后 : {len(clean)} 条")
    if args.raw:
        print("    --- 原始前 20 条 ---")
        for item in raw_list[:20]:
            print(f"      {item!r}")
    print("    --- 清洗结果前 20 条 ---")
    for item in clean[:20]:
        print(f"      {item}")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
