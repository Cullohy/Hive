"""看一眼正在运行的服务：健康状况 + 库里的东西。

用法::

    python scripts/status.py                       # 默认 http://127.0.0.1:8000
    python scripts/status.py http://127.0.0.1:8791
    $env:RECON_TOKEN="xxx"; python scripts/status.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
TOKEN = os.environ.get("RECON_TOKEN", "")


def get(path: str):
    headers = {}
    if TOKEN:
        headers["Authorization"] = f"Bearer {TOKEN}"
    req = urllib.request.Request(BASE + path, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            raw = resp.read()
            ctype = resp.headers.get("Content-Type") or ""
            return resp.status, ctype, raw
    except urllib.error.HTTPError as e:
        return e.code, e.headers.get("Content-Type") or "", e.read()
    except OSError as e:
        return 0, "", str(e).encode()


def js(path: str):
    status, _ctype, raw = get(path)
    try:
        return status, json.loads(raw)
    except Exception:
        return status, None


def main() -> int:
    status, ctype, raw = get("/api/health")
    if status != 200:
        print(f"  连不上 {BASE}（HTTP {status}）")
        if raw:
            print("  " + raw.decode("utf-8", "replace")[:300])
        return 1

    health = json.loads(raw)
    auth = "需令牌" if health.get("auth_required") else "无认证"
    print(f"  {BASE}  OK  运行中 {health['running']}/{health['max_concurrent']}  {auth}")

    print("\n  -- 静态资源 --")
    status, _ctype, raw = get("/")
    print(f"  {'前端页面':8} {'/':12} -> {status}  {len(raw)} 字节")
    # 前端是 Vue 构建产物，入口资源名带内容哈希，从 index.html 里现取；
    # 写死 /app.js 那种旧名字会在重构后变成"探测成功但其实是 HTML"的假象。
    import re

    assets = re.findall(r'(?:src|href)="(/assets/[^"]+)"', raw.decode("utf-8", "replace"))
    for path in assets:
        st, ct, body = get(path)
        print(f"  {'构建资源':8} {path[:28]:28} -> {st}  {ct[:24]}  {len(body)} 字节")
    if not assets:
        print("  ⚠ index.html 里没找到 /assets/* —— 前端可能没构建，或产物不完整")

    print("\n  -- 服务端数据 --")
    st, scans = js("/api/scans")
    if scans is None:
        print(f"  /api/scans -> HTTP {st}（可能需要令牌）")
    else:
        print(f"  扫描记录 {len(scans)} 条:")
        for s in scans[:8]:
            print(f"    #{s['scan_id']:<3} {s['status']:<10} {s['preset']:<10} "
                  f"{' '.join(s.get('targets') or [])}")

    st, mons = js("/api/monitors")
    if mons is not None:
        print(f"  周期监控 {len(mons)} 个:")
        for m in mons:
            flag = "启用" if m["enabled"] else "停用"
            print(f"    #{m['id']:<3} {m['name']:<16} {flag}  每 {m['interval_minutes']} 分钟  "
                  f"{' '.join(m.get('targets') or [])}  上次扫描={m.get('last_scan_id') or '-'}")

    st, changes = js("/api/changes?limit=5")
    if changes is not None and changes:
        print(f"  变更记录 {len(changes)} 条（最近 5 条）:")
        for c in changes[:5]:
            print(f"    #{c['new_scan_id']:<3} vs #{c.get('old_scan_id') or '-':<3} "
                  f"{c['target']:<20} 变化 {c['total']} 处")

    st, settings = js("/api/settings")
    if settings is not None:
        print(f"  绑定: {settings.get('host')}:{settings.get('port')}   "
              f"并发上限: {settings.get('max_concurrent_scans')}   "
              f"告警渠道: {', '.join(k[:-4] for k, v in (settings['notify'] or {}).items() if k.endswith('_set') and v) or '无'}")

    if scans:
        scan_id = scans[0]["scan_id"]
        st, assets = js(f"/api/scans/{scan_id}/assets")
        if assets is not None:
            print(f"  最新扫描 #{scan_id} 资产: {assets['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
