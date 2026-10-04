"""对已启动的 Web 服务做一次端到端验证。

用法::

    python scripts/web_smoke.py http://127.0.0.1:8791
    $env:RECON_TOKEN="xxx"; python scripts/web_smoke.py http://127.0.0.1:8791
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8791"
TOKEN = os.environ.get("RECON_TOKEN", "")


def call(path: str, method: str = "GET", body=None, token: str | None = None):
    headers = {"Content-Type": "application/json"}
    use = TOKEN if token is None else token
    if use:
        headers["Authorization"] = f"Bearer {use}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return resp.status, (json.loads(raw) if raw.strip()[:1] in "{[" else raw)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")


def main() -> int:
    status, health = call("/api/health")
    print(f"  /api/health          -> {status} {health}")

    print("\n  -- 接口与静态资源 --")
    print(f"  / (静态前端)          -> {call('/')[0]}")
    print(f"  /app.js              -> {call('/app.js')[0]}")
    print(f"  /style.css           -> {call('/style.css')[0]}")

    if TOKEN:
        print("\n  -- 访问令牌 --")
        print(f"  无令牌  /api/scans    -> {call('/api/scans', token='')[0]} (应 401)")
        print(f"  错令牌  /api/scans    -> {call('/api/scans', token='wrong')[0]} (应 401)")
        print(f"  正确令牌 /api/scans   -> {call('/api/scans')[0]} (应 200)")
        print(f"  健康检查无令牌         -> {call('/api/health', token='')[0]} (应 200)")

    status, presets = call("/api/presets")
    print(f"\n  /api/presets         -> {[p['name'] for p in presets]}")

    print("\n  -- 授权白名单 --")
    print(f"  未配黑名单前下发        -> {call('/api/scans', 'POST', {'name': '冒烟 · 未配白名单', 'targets': ['example.com'], 'preset': 'default'})[0]}")
    call("/api/settings", "PUT", {
        "authorized_targets": ["example.com"],
        "require_authorization": True,
        "max_concurrent_scans": 2,
    })
    print(f"  未授权目标 evil.com     -> {call('/api/scans', 'POST', {'name': '冒烟 · 未授权目标', 'targets': ['evil.com'], 'preset': 'default'})[0]} (应 403)")

    print("\n  -- 真的跑一次扫描（default 预设，会联网）--")
    status, record = call(
        "/api/scans", "POST",
        {"name": "冒烟 · example.com", "targets": ["example.com"], "preset": "default"},
    )
    if status != 201:
        print(f"  下发失败: {status} {record}")
        return 1
    scan_id = record["scan_id"]
    print(f"  scan_id={scan_id} status={record['status']} mode={record['mode']}")

    current = {}
    for _ in range(300):
        _, current = call(f"/api/scans/{scan_id}")
        if current.get("status") != "running":
            break
        time.sleep(1)
    progress = current.get("progress", {})
    print(f"  最终: {current.get('status')} | 新事件 {progress.get('events_new')} | 耗时 {current.get('elapsed')}s")

    _, assets = call(f"/api/scans/{scan_id}/assets")
    summary = assets["summary"]
    print(f"  资产: 域名 {summary['domains']} | IP {summary['ips']} | 域名↔IP {summary['domain_ip']} "
          f"| 端点 {summary['http_endpoints']} | 发现 {summary['findings']}")
    print(f"  域名样本: {sorted(d['name'] for d in assets['domains'])[:6]}")
    if assets["endpoints"]:
        ep = assets["endpoints"][0]
        print(f"  端点样本: {ep['url']} -> {ep['status']} {ep['title']!r} [{ep['server']}]")

    _, events = call(f"/api/scans/{scan_id}/events?limit=50")
    child = next((e for e in events if e["type"] == "IP_ADDRESS"), None) or events[-1]
    _, trace = call(f"/api/scans/{scan_id}/trace/{child['id']}")
    print(f"  溯源链: {' <- '.join(n['type'] for n in trace['chain'])}")

    print("\n  -- 审计日志 --")
    _, audits = call("/api/audits?limit=8")
    for row in audits:
        print(f"  {row['ts'][11:19]} {row['action']:15} mode={row['mode']:9} allowed={row['allowed']} {row['target'][:34]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
