"""下载外部指纹库并导入 —— 一条命令刷新整个指纹库。

    python scripts/import_fingerprints.py                 # 两个来源都导
    python scripts/import_fingerprints.py --source fh     # 只要 FingerprintHub
    python scripts/import_fingerprints.py --dry-run       # 只下载不导入

**为什么要有这个脚本**：指纹库是别人在维护的资产，会持续更新。打包一份
静态副本等于把它冻结在某个时间点，之后既不会更新、也说不清改过什么。
所以这里只提供"拉取 + 转换"，数据不进代码仓库的历史。

下载要**断点续传**：这几个文件 1.4~3.8 MB，实测一次连接常常下不完
（服务器提前关连接），而 `read()` 遇到 EOF 会正常返回 —— 只看"循环有没有
报错"会把截断的文件当成下载成功。所以要按 Content-Length 核对。
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "core" / "resources"
OUTPUT = RESOURCES / "fingerprints.json"

UA = {"User-Agent": "recon-fingerprint-import/1.0"}
_RANGE_TOTAL = re.compile(r"/(\d+)\s*$")

#: 来源。都是 MIT（详见 core/resources/ATTRIBUTION.md）
#:
#: **为什么走 jsDelivr 而不是 raw.githubusercontent.com**：实测这台机器上
#: raw.githubusercontent.com **不可达**（TLS 连接被重置），而 ``download()``
#: 的失败路径是会吞掉异常再重试的（``except Exception: pass``），所以表现是
#: **安静地重试 25 次然后失败** —— 看不出是"域名不通"还是"网络抖动"。
#: ``cdn.jsdelivr.net/gh/<owner>/<repo>@<branch>/<path>`` 内容一致、实测可达，
#: 所以三个地址都换成它。分支要写进路径（``@main``），不留默认分支。
#:
#: ⚠️ **2026-10 复测：jsDelivr 自己在这台机器上也连不上了**
#: （``urllib`` 报 ``SSL: UNEXPECTED_EOF_WHILE_READING``，``curl.exe`` 报
#: ``schannel: failed to receive handshake``），而 ``git clone`` 仍然通。
#: 本脚本**没有** git 回退，所以在这台机器上只会静默重试到失败。
#: 同期的 ``import_dirmap_dicts.py`` 加了 git 回退，可作改造参考。
SOURCES = {
    "fh": {
        "name": "FingerprintHub (0x727)",
        "url": "https://cdn.jsdelivr.net/gh/0x727/FingerprintHub@main/"
               "web_fingerprint_v4.json",
        "file": "fh_web_v4.json",
        "kind": "fingerprinthub-json",
    },
    "wapp": {
        "name": "wappalyzergo (projectdiscovery)",
        "url": "https://cdn.jsdelivr.net/gh/projectdiscovery/wappalyzergo@main/"
               "fingerprints_data.json",
        "file": "wapp_fingerprints.json",
        "kind": "wappalyzer",
    },
    "wapp_cats": {
        "name": "wappalyzergo 分类表",
        "url": "https://cdn.jsdelivr.net/gh/projectdiscovery/wappalyzergo@main/"
               "categories_data.json",
        "file": "wapp_categories.json",
        "kind": "categories",
    },
}


def _expected(headers, have: int) -> int | None:
    cr = headers.get("Content-Range")
    if cr:
        m = _RANGE_TOTAL.search(cr)
        if m:
            return int(m.group(1))
    cl = headers.get("Content-Length")
    return int(cl) if cl and have == 0 else None


def download(url: str, dest: Path, *, tries: int = 25) -> int:
    """反复续传直到下满。返回字节数（0 = 失败）。

    **判断"下完了没有"要看 Content-Length。** 服务器提前关连接时 ``read()``
    照样返回空、循环正常退出 —— 那会把截断的文件当成成功。
    """
    total: int | None = None
    for _ in range(tries):
        have = dest.stat().st_size if dest.exists() else 0
        if total is not None and have >= total:
            return have
        headers = dict(UA)
        if have:
            headers["Range"] = f"bytes={have}-"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=90) as r:
                if have and r.status != 206:
                    have = 0
                    dest.unlink(missing_ok=True)
                if total is None:
                    total = _expected(r.headers, have)
                with dest.open("ab" if have else "wb") as fh:
                    while True:
                        chunk = r.read(131072)
                        if not chunk:
                            break
                        fh.write(chunk)
        except Exception:
            pass

        size = dest.stat().st_size if dest.exists() else 0
        if total is not None and size >= total:
            return size
        time.sleep(1.2)
    return dest.stat().st_size if dest.exists() else 0


def main() -> int:
    ap = argparse.ArgumentParser(description="下载并导入外部指纹库")
    ap.add_argument("--source", action="append", choices=["fh", "wapp"],
                    help="只导某个来源；默认两个都导。"
                         "⚠️ 只导一个来源会**覆盖掉另一个来源的数据** —— "
                         "想保留就要两个一起导")
    ap.add_argument("--cache", type=Path, default=None,
                    help="下载文件放哪（默认临时目录，用完即删）")
    ap.add_argument("--dry-run", action="store_true", help="只下载不导入")
    args = ap.parse_args()

    wanted = args.source or ["fh", "wapp"]
    if args.source and len(args.source) == 1:
        print("  ⚠️  只导了一个来源 —— 库文件会被整体覆盖，"
              "另一个来源的规则会丢失。")
        print("      想保留就两个一起导（去掉 --source）。\n")

    keys = []
    for s in wanted:
        keys.append(s)
        if s == "wapp":
            keys.append("wapp_cats")

    cache = args.cache or Path(tempfile.mkdtemp(prefix="recon-fp-"))
    cache.mkdir(parents=True, exist_ok=True)

    print("  ── 下载 ──")
    for key in keys:
        spec = SOURCES[key]
        dest = cache / spec["file"]
        t0 = time.time()
        size = download(spec["url"], dest)
        ok = ""
        if spec["kind"] != "categories":
            try:
                json.loads(dest.read_text(encoding="utf-8", errors="replace"))
                ok = "  JSON 完整"
            except Exception:
                ok = "  ⚠ JSON 不完整"
        if not size:
            print(f"  ✗ {spec['name']}: 下载失败")
            return 1
        print(f"  ✓ {spec['name']:34} {size:10,} 字节  {time.time()-t0:5.1f}s{ok}")

    if args.dry_run:
        print(f"\n  --dry-run：文件在 {cache}")
        return 0

    cmd = [sys.executable, "-m", "core.domains.fingerprint._lib.importers"]
    if "fh" in wanted:
        cmd += ["--fingerprinthub-json", str(cache / SOURCES["fh"]["file"])]
    if "wapp" in wanted:
        cmd += [
            "--wappalyzer", str(cache / SOURCES["wapp"]["file"]),
            "--categories", str(cache / SOURCES["wapp_cats"]["file"]),
        ]
    cmd += ["-o", str(OUTPUT)]

    print("\n  ── 导入 ──")
    result = subprocess.run(cmd, cwd=str(ROOT))
    if result.returncode != 0:
        print("  导入失败")
        return result.returncode
    size = OUTPUT.stat().st_size
    print(f"\n  完成：{OUTPUT}")
    print(f"          {size / 1024 / 1024:.1f} MB")
    print("  重启服务（或点界面上的「重载」）即可生效。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
