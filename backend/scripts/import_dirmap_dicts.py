"""拉取 dirmap 的路径字典并生成 Hive 的内置四档 —— 一条命令刷新。

    python scripts/import_dirmap_dicts.py               # 四档全导
    python scripts/import_dirmap_dicts.py --tier dirmap # 只导一档
    python scripts/import_dirmap_dicts.py --dry-run     # 只报告差异，不写文件

**为什么要有这个脚本**：和 ``import_fingerprints.py`` 同一个理由 —— 字典是
别人在维护的资产，会持续更新。打包一份静态副本等于把它冻结在某个时间点，
之后既不会更新、也说不清改过什么。

## 下载通道：HTTPS 与 git 的实测差异

这台机器上（走本地代理 ``127.0.0.1:7897``）实测：

* ``urllib`` → jsDelivr：**失败**（``SSL: UNEXPECTED_EOF_WHILE_READING``）
* ``urllib`` → raw.githubusercontent.com：**失败**（同上）
* ``curl.exe`` → 两者：``schannel: failed to receive handshake``
* ``git clone --depth 1``：✅ **通**

注意 ``import_fingerprints.py`` 写的是"改走 jsDelivr"来解决
``raw.githubusercontent.com`` 不通的问题 —— 那是当时的实测结论，现在
jsDelivr 自己也不通了。所以这里不假设任何 HTTPS 通道可用：
**先试 HTTPS，全失败就退回 git**。git 走的是自带 OpenSSL 而不是
Windows schannel，这是两条路径能通的原因。

## 清洗规则（改了什么，逐条可查）

* 剔注释行、空行、控制字符、含空白或反斜杠的条目
* **剔注入探针**（含 ``<`` ``>`` ``|`` ``{}`` 反引号）—— 上游 ``BAK.txt``
  混进了整段 XSS payload，越过了本项目「只铺暴露面、不做注入」的边界
* ``#`` 编码成 ``%23`` —— 它是 URL 片段分隔符，原样请求永远发不出去
* 已编码的 ``%XX``（``%23data%23/`` 等）**原样保留**
* 去重**大小写敏感**（``.ds_store`` 与 ``.DS_Store`` 是不同路径）
"""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESOURCES = ROOT / "core" / "resources"

REPO = "H4ckForJob/dirmap"
#: dirmap 的默认分支是 ``master`` **不是** ``main``（``git ls-remote --heads``
#: 实测：只有 ``master`` 与 ``dev``）。写错分支名的表现是
#: ``fatal: Remote branch main not found in upstream origin``。
BRANCH = "master"

CONTROL = re.compile(r"[\x00-\x1f\x7f]")
#: 注入类探针的标记字符，见模块 docstring
INJECTION = re.compile(r"[<>|{}`]")

HEADER = """\
# ─────────────────────────────────────────────────────────────────────────
# {title}
#
# 来源：dirmap — https://github.com/{repo}
#       data/{src}
# 条目：{n} 条（去重后）
# 许可：GPL-3.0（dirmap）
#
{note}
#
# 格式：一行一条相对路径（不带前导 `/`），`#` 之后是注释。
#   · 结尾带 `/` 表示目录，会原样请求
#   · 已做 URL 百分号编码的条目（如 %23data%23/）按原样发出，不会二次编码
# 生成：python scripts/import_dirmap_dicts.py
# 加载：-c modules.dir_brute.wordlist={alias}
#       多份字典用逗号串联，按顺序合并去重：
#       -c modules.dir_brute.wordlist={example}
# ─────────────────────────────────────────────────────────────────────────
"""

TIERS = {
    "leaks": {
        "alias": "dir_leaks",
        "file": "dir_leaks.txt",
        "src": "dictmult/LEAKS.txt",
        "title": "高信噪比泄露面（极小字典）",
        "note": (
            "全是 `.env` / `.git/config` / `.bash_history` / `.vscode/settings.json`\n"
            "# 这类**一条命中就是一次真实信息泄露**的路径。\n"
            "# 几乎不产生 404 噪声，适合放多档字典的**第一档**先跑。\n"
            "# 注：去重是**大小写敏感**的，所以 `.ds_store` / `.DS_Store` 都在 ——\n"
            "# Windows/IIS 上它们等价，Linux/Apache 上是不同路径，都留着。"
        ),
        "example": "dir_leaks,dir_dirmap",
    },
    "dirmap": {
        "alias": "dir_dirmap",
        "file": "dir_dirmap.txt",
        "src": "dict_mode_dict.txt",
        "title": "dirmap 通用目录/文件字典（推荐档）",
        "note": (
            "dirmap 默认 `dict_mode` 使用的字典：目录 + 敏感文件混排。\n"
            "# 比自研的 `dir_common.txt`（200 条）宽一个数量级，是想扩面时的默认档。\n"
            "# 单主机全量约 5.7k 请求 —— 主机多时务必配 `max_hosts` / `max_paths`。"
        ),
        "example": "dir_leaks,dir_dirmap",
    },
    "bak": {
        "alias": "dir_bak",
        "file": "dir_bak.txt",
        "src": "dictmult/BAK.txt",
        "title": "备份压缩包路径（大字典，命中即高危）",
        "note": (
            "dirmap `dictmult/BAK.txt`：`site.zip` / `/data/back.rar` 形式的\n"
            "# **备份压缩包**路径，多为中文 CMS / 老站群的真实遗留。\n"
            "# 404 率极高（绝大多数站一个都没有），但命中一条通常直接等于源码泄露。\n"
            "# 只建议在**已知是老系统**的目标上开；配合 `extensions` 收益更大。"
        ),
        "example": "dir_leaks,dir_dirmap,dir_bak",
    },
    "big": {
        "alias": "dir_big",
        "file": "dir_big.txt",
        "src": "fuzz_mode_dir.txt",
        "title": "dirmap fuzz 大字典（最大档）",
        "note": (
            "dirmap `fuzz_mode` 字典。\n"
            "# 单主机就是 8 万次请求，**默认别开**；要开请同时压低 `max_hosts`\n"
            "# 并调大 `delay`，否则基本会触发 WAF 403 熔断或被目标封 IP。"
        ),
        "example": "dir_leaks,dir_dirmap,dir_big",
    },
}


class FetchError(RuntimeError):
    """所有通道都拿不到数据。"""


# --------------------------------------------------------------------- 下载

def _https(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "hive-dict-import/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def fetch_via_https(rel: str, branch: str) -> bytes:
    """先 jsDelivr 再 raw.githubusercontent。任一成功即返回。"""
    errors = []
    for base in (f"https://cdn.jsdelivr.net/gh/{REPO}@{branch}/data/",
                 f"https://raw.githubusercontent.com/{REPO}/{branch}/data/"):
        try:
            return _https(base + rel)
        except Exception as e:                      # noqa: BLE001 - 逐个通道报告
            errors.append(f"{base.split('/')[2]}: {type(e).__name__}")
    raise FetchError("; ".join(errors))


def fetch_via_git(rel: str, branch: str, workdir: Path) -> bytes:
    """退回 git：HTTPS 两条通道都不通时唯一实测可用的一条。

    走 ``--depth 1`` 浅克隆。**不用** ``--filter=blob:none`` —— 那会让
    按路径取文件多走一次 lazy fetch，而我们只需要 data/ 下几个文本文件。
    """
    repo = workdir / "dirmap"
    if not (repo / ".git").is_dir():
        r = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch,
             f"https://github.com/{REPO}.git", str(repo)],
            capture_output=True, text=True, timeout=600,
        )
        if r.returncode != 0:
            raise FetchError(f"git clone 失败 rc={r.returncode}: {r.stderr.strip()[:200]}")
    path = repo / "data" / rel
    if not path.is_file():
        raise FetchError(f"仓库里没有 data/{rel}")
    return path.read_bytes()


def fetch(rel: str, branch: str, workdir: Path, *, prefer_git: bool) -> bytes:
    if prefer_git:
        return fetch_via_git(rel, branch, workdir)
    try:
        return fetch_via_https(rel, branch)
    except FetchError as e:
        print(f"  [回退] HTTPS 不通（{e}），改用 git")
        return fetch_via_git(rel, branch, workdir)


# --------------------------------------------------------------------- 清洗

def clean(raw: bytes) -> tuple[list[str], int, int]:
    """返回 ``(条目, 剔掉的注入探针数, 编码过的 # 数)``。"""
    text = raw.decode("utf-8", errors="replace")
    out: list[str] = []
    seen: set[str] = set()
    dropped = encoded = 0
    for line in text.splitlines():
        w = CONTROL.sub("", line).strip().lstrip("\ufeff")
        if not w or w.startswith("#"):
            continue
        if any(c.isspace() for c in w) or "\\" in w:
            continue
        if INJECTION.search(w):
            dropped += 1
            continue
        if "#" in w:
            w = w.replace("#", "%23")
            encoded += 1
        w = unicodedata.normalize("NFC", w)
        if w in seen:
            continue
        seen.add(w)
        out.append(w)
    return out, dropped, encoded


def render(words: list[str], spec: dict) -> str:
    # note 的每一行统一成注释。**不能让作者自己记得加前缀** —— 漏一个，
    # 那行说明就会变成一条会被 dir_brute 真实请求的垃圾路径（踩过）。
    # 先剥掉已有的 '#' 再补，所以写不写前缀都不会出错，也不会出现 '# # ...'。
    note = "\n".join(
        f"# {line.lstrip('#').strip()}" if line.strip() else "#"
        for line in spec["note"].splitlines()
    )
    return HEADER.format(
        title=spec["title"], repo=REPO, src=spec["src"], n=len(words),
        note=note, alias=spec["alias"], example=spec["example"],
    ).replace("\n", "\r\n") + "\r\n".join(words) + "\r\n"


def existing_count(path: Path) -> int:
    if not path.is_file():
        return -1
    return sum(1 for line in path.read_text(encoding="utf-8").splitlines()
               if line.strip() and not line.startswith("#"))


# --------------------------------------------------------------------- 主流程

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="导入 dirmap 路径字典")
    ap.add_argument("--tier", action="append", choices=sorted(TIERS),
                    help="只导指定档，可重复；默认全导")
    ap.add_argument("--dry-run", action="store_true", help="只报告差异，不写文件")
    ap.add_argument("--prefer-git", action="store_true",
                    help="跳过 HTTPS，直接用 git clone")
    ap.add_argument("--branch", default=BRANCH,
                    help=f"上游分支，默认 {BRANCH}")
    args = ap.parse_args(argv)

    names = args.tier or sorted(TIERS)
    workdir = Path(tempfile.mkdtemp(prefix="hive-dirmap-"))
    failures = 0
    try:
        for name in names:
            spec = TIERS[name]
            out = RESOURCES / spec["file"]
            have = existing_count(out)
            print(f"\n=== {name} → {spec['file']} ===")
            try:
                raw = fetch(spec["src"], args.branch, workdir,
                            prefer_git=args.prefer_git)
            except FetchError as e:
                print(f"  [失败] {spec['src']}: {e}")
                failures += 1
                continue

            words, dropped, encoded = clean(raw)
            if not words:
                print(f"  [失败] 清洗后为空，源文件可能变了：{spec['src']}")
                failures += 1
                continue

            print(f"  源 {len(raw):>9,} bytes → {len(words):>6} 条"
                  f"  (剔注释/空行/控制字符, 剔注入探针 {dropped}, #→%23 {encoded})")
            print(f"  现有 {have if have >= 0 else '(无)':>9} 条"
                  f"  →  {'不变' if have == len(words) else f'变化 {have} → {len(words)}'}")
            if args.dry_run:
                continue
            # CRLF + 无 BOM，与同目录的 dir_common.txt 保持一致
            out.write_bytes(render(words, spec).encode("utf-8"))
            print(f"  已写入 {out}  ({out.stat().st_size:,} bytes)")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
