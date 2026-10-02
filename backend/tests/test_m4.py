"""M4 测试: 端口扫描 / HTTP 探活 / 证书 SAN 递归 / 指纹识别。

全部离线 —— 网络层（端口连接、HTTP、TLS、DNS）都打桩。
重点验证四件事:
  1. **安全闸门**: 内网与保留地址默认被拒绝, 而且拒绝要留痕
  2. 端口 -> HTTP -> 指纹 这条链能把资产落到正确的表
  3. **证书 SAN 的递归闭环**: SAN -> DNS_NAME -> IP_ADDRESS 真能跑通
  4. 易失标签（响应头/正文片段）传给下游模块但不落库
"""

from __future__ import annotations

import json
import sys
import unittest
from unittest import mock

from core.engine.preset import Preset
from core.services.http import FetchResult, HTTPClient
from core.domains.port._lib.ports import ConnectScanner
from core.domains.resolve._lib.resolver import AsyncResolverPool
from core.domains.probe._lib.tls import CertInfo
from core.util.net import parse_ports, scan_allowed

from .base import EngineTestCase

REAL_IP = "93.184.216.34"
PRIVATE_IP = "10.1.2.3"


# --------------------------------------------------------------------- 纯单元

class TestPortParsing(unittest.TestCase):
    def test_builtin_sets_load(self) -> None:
        self.assertEqual(len(parse_ports("top10")), 16)          # ARL 的 TOP_10 是 16 个
        self.assertGreater(len(parse_ports("top100")), 200)
        self.assertGreater(len(parse_ports("top1000")), 700)

    def test_explicit_and_ranges(self) -> None:
        self.assertEqual(parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])
        self.assertEqual(parse_ports("443,80,443"), [80, 443])   # 去重 + 排序

    def test_full_range_and_bad_input(self) -> None:
        self.assertEqual(len(parse_ports("full")), 65535)
        with self.assertRaises(ValueError):
            parse_ports("top9999")
        with self.assertRaises(ValueError):
            parse_ports("not-a-port")


class TestSecurityGate(unittest.TestCase):
    def test_private_and_reserved_are_blocked_by_default(self) -> None:
        for ip in ("10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1",
                   "169.254.1.1", "0.0.0.0", "::1"):
            allowed, reason = scan_allowed(ip)
            self.assertFalse(allowed, f"{ip} 应被拒绝")
            self.assertTrue(reason)

    def test_public_address_allowed(self) -> None:
        allowed, _ = scan_allowed("8.8.8.8")
        self.assertTrue(allowed)

    def test_allow_private_only_relaxes_the_global_check(self) -> None:
        # 显式放行后, 10.x 可以扫
        self.assertTrue(scan_allowed("10.0.0.1", allow_private=True)[0])
        # 但 DNS 保留段仍在黑名单里 —— allow_private 不该把它也放开
        self.assertFalse(scan_allowed("192.0.2.5", allow_private=True)[0])

    def test_garbage_input(self) -> None:
        self.assertFalse(scan_allowed("not-an-ip")[0])


# --------------------------------------------------------------------- 测试模块

EMIT_IPS = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class emit_ips(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.IP_ADDRESS,)
        flags = ("active", "safe")

        async def handle_event(self, event):
            await self.emit_event("93.184.216.34", EventType.IP_ADDRESS, parent=event)
            await self.emit_event("10.1.2.3", EventType.IP_ADDRESS, parent=event)
"""


def make_fake_scan(open_map: dict[str, list[int]]):
    async def fake_scan(self, host, ports, *, on_open=None):
        found = open_map.get(host, [])
        for port in found:
            if on_open is not None:
                maybe = on_open(port)
                if hasattr(maybe, "__await__"):
                    await maybe
        return found

    return fake_scan


def make_fake_fetch(responder):
    async def fake_fetch(self, url, **kwargs):
        return responder(url)

    return fake_fetch


async def fake_fetch_bytes(self, url, **kwargs):
    return b"\x00\x01\x02fakefavicon"


# --------------------------------------------------------------------- 端口扫描

class TestPortScan(EngineTestCase):
    async def test_open_ports_are_recorded_and_private_blocked(self) -> None:
        self.add_module_file("emit_ips", EMIT_IPS)

        with mock.patch.object(
            ConnectScanner, "scan", make_fake_scan({REAL_IP: [80, 443]})
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_ips", "port_scan"],
                module_config={"port_scan": {"ports": "top10"}},
            )

        ports = await self.storage.ports(scanner.scan_id)
        self.assertEqual({(p["ip"], p["port"]) for p in ports}, {(REAL_IP, 80), (REAL_IP, 443)})

        # 内网地址被闸门拦下, 而且必须留痕
        findings = await self.storage.findings(scanner.scan_id)
        blocked = [f for f in findings if f["kind"] == "port_scan_blocked"]
        self.assertEqual(len(blocked), 1)
        self.assertIn(PRIVATE_IP, blocked[0]["detail"])

    async def test_events_produced(self) -> None:
        self.add_module_file("emit_ips", EMIT_IPS)
        with mock.patch.object(ConnectScanner, "scan", make_fake_scan({REAL_IP: [8080]})):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["emit_ips", "port_scan"],
                module_config={"port_scan": {"ports": "top10"}},
            )
        events = await self.storage.events(scanner.scan_id, limit=200)
        opens = [e for e in events if e["type"] == "OPEN_TCP_PORT"]
        self.assertEqual([e["data"] for e in opens], [f"{REAL_IP}:8080"])
        self.assertGreaterEqual(summary["events_new"], 4)


# --------------------------------------------------------------------- HTTP 探活 + 指纹

class TestHttpProbeAndFingerprint(EngineTestCase):
    PAGE = (
        "<html><head><title>Example Domain</title>"
        # 用真实站点的写法：WordPress 的识别规则要求 <link> 上带
        # rel="stylesheet" 且路径含 /wp-content/。之前这里只写了个裸的
        # <link href='/wp-content/style.css'>，导入的库（wappalyzer 规则）
        # 天然认不出 —— 那是测试数据不真实，不是规则有问题。
        "<link rel='stylesheet' href='/wp-content/themes/twentytwenty/style.css'>"
        "</head><body>hello</body></html>"
    )

    def _responder(self, url: str):
        if url.endswith("/favicon.ico"):
            return FetchResult(url=url, status=200, text="")
        return FetchResult(
            url=url,
            status=200,
            headers={
                "server": "nginx/1.24.0",
                "content-type": "text/html; charset=utf-8",
                "set-cookie": "PHPSESSID=abc; path=/, cf_clearance=xyz; path=/",
            },
            text=self.PAGE,
            history=[],
            elapsed=0.02,
        )

    async def test_chain_lands_in_endpoint_and_technology_tables(self) -> None:
        self.add_module_file("emit_ips", EMIT_IPS)

        with mock.patch.object(ConnectScanner, "scan", make_fake_scan({REAL_IP: [80]})), \
             mock.patch.object(HTTPClient, "fetch", make_fake_fetch(self._responder)), \
             mock.patch.object(HTTPClient, "fetch_bytes", fake_fetch_bytes):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_ips", "port_scan", "http_probe", "fingerprint"],
                module_config={
                    "port_scan": {"ports": "top10"},
                    "http_probe": {"schemes": ["http"], "prefer_https": False},
                },
            )

        endpoints = await self.storage.endpoints(scanner.scan_id)
        self.assertEqual(len(endpoints), 1)
        ep = endpoints[0]
        self.assertEqual(ep["url"], "http://example.com")
        self.assertEqual(ep["status"], 200)
        self.assertEqual(ep["title"], "Example Domain")
        self.assertEqual(ep["server"], "nginx/1.24.0")
        self.assertTrue(ep["favicon_hash"])

        techs = await self.storage.technologies(scanner.scan_id)
        names = {t["name"] for t in techs}
        # Nginx 来自响应头, WordPress 来自正文, PHP 来自 Cookie
        self.assertIn("Nginx", names)
        self.assertIn("WordPress", names)
        self.assertIn("PHP", names)

    async def test_volatile_tags_are_not_persisted(self) -> None:
        """响应头与正文片段要传给 fingerprint, 但不能落库。"""
        self.add_module_file("emit_ips", EMIT_IPS)

        with mock.patch.object(ConnectScanner, "scan", make_fake_scan({REAL_IP: [80]})), \
             mock.patch.object(HTTPClient, "fetch", make_fake_fetch(self._responder)), \
             mock.patch.object(HTTPClient, "fetch_bytes", fake_fetch_bytes):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_ips", "port_scan", "http_probe", "fingerprint"],
                module_config={
                    "port_scan": {"ports": "top10"},
                    "http_probe": {"schemes": ["http"], "prefer_https": False},
                },
            )

        events = await self.storage.events(scanner.scan_id, limit=200)
        http_event = next(e for e in events if e["type"] == "HTTP_RESPONSE")
        stored = json.loads(http_event["tags_json"])
        self.assertNotIn("body_snippet", stored)
        self.assertNotIn("headers", stored)
        # 但派生出来的技术栈事件是落库了的
        self.assertIn("title", stored)


class TestFingerprintRules(unittest.TestCase):
    """指纹匹配的**旧格式回归**。

    规则格式在 v2 换成了多来源结构（见 ``tests/test_fingerprint.py``），
    但 v1 的扁平格式 ``{name, where, key, pattern}`` **仍然被支持** ——
    否则规则文件没法增量升级。这条测试守的就是那层兼容。
    """

    def test_legacy_rule_matching(self) -> None:
        from core.domains.fingerprint._lib.rules import (
            Observation,
            detect,
            load_technologies,
        )

        techs = load_technologies({"rules": [
            {"name": "Nginx", "where": "header", "key": "server", "pattern": "nginx"},
            {"name": "Cloudflare", "where": "header", "key": "cf-ray", "pattern": ""},
            {"name": "PHP", "where": "cookie", "key": "PHPSESSID", "pattern": ""},
            {"name": "WordPress", "where": "body", "pattern": "wp-content"},
            {"name": "Grafana", "where": "title", "pattern": "grafana"},
        ]})
        self.assertEqual(len(techs), 5, "v1 旧格式没被正确转换")

        base = Observation.from_tags({
            "headers": {"server": "nginx/1.24.0", "cf-ray": "abc123",
                        "set-cookie": "PHPSESSID=abc; path=/, other=1"},
            "body_snippet": "xx wp-content yy",
            "title": "plain title",
        })
        names = {d.tech.name for d in detect(base, techs)}
        self.assertEqual(names, {"Nginx", "Cloudflare", "PHP", "WordPress"})

        # 头不存在就不该匹配；标题对不上不该匹配
        bare = Observation.from_tags({"headers": {}, "body_snippet": "", "title": ""})
        self.assertEqual(detect(bare, techs), [])


# --------------------------------------------------------------------- 证书 SAN 递归

class TestTlsAndSanRecursion(EngineTestCase):
    async def test_san_feeds_back_into_the_event_chain(self) -> None:
        """证书 SAN -> DNS_NAME -> IP_ADDRESS 的递归闭环。"""
        self.add_module_file("emit_ips", EMIT_IPS)

        cert = CertInfo(
            common_name="example.com",
            subject="CN=example.com",
            issuer="CN=Test CA",
            san=["api.example.com", "unrelated.example.net"],
            not_after="2030-01-01T00:00:00+00:00",
            days_left=1000,
            fingerprint_sha256="deadbeef",
        )

        async def fake_fetch_cert(host, port, *, timeout=6.0, server_hostname=None):
            return cert

        async def fake_query(self, name, rdtype):
            if name == "api.example.com" and rdtype == "A":
                return ["1.2.3.4"]
            return []

        with mock.patch.object(ConnectScanner, "scan", make_fake_scan({REAL_IP: [443]})), \
             mock.patch("core.domains.probe.tls_cert.fetch_certificate", fake_fetch_cert), \
             mock.patch.object(AsyncResolverPool, "_query", fake_query):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_ips", "port_scan", "tls_cert", "dns_resolve"],
                module_config={"port_scan": {"ports": "top10"}},
            )

        # 1) SAN 里的同域名字被喂回事件链, 并解析出 IP
        domains = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("api.example.com", domains)
        self.assertIn("1.2.3.4", {i["addr"] for i in await self.storage.ips(scanner.scan_id)})

        # 2) 域外的 SAN 名字被忽略（但留痕）
        self.assertNotIn("unrelated.example.net", domains)
        findings = await self.storage.findings(scanner.scan_id)
        self.assertIn("tls_san_filtered", {f["kind"] for f in findings})

        # 3) 证书信息回填到了端口行
        ports = await self.storage.ports(scanner.scan_id)
        port = next(p for p in ports if p["port"] == 443)
        self.assertIsNotNone(port["cert_json"])
        self.assertEqual(json.loads(port["cert_json"])["cert_cn"], "example.com")

    async def test_expired_certificate_is_reported(self) -> None:
        self.add_module_file("emit_ips", EMIT_IPS)
        cert = CertInfo(common_name="example.com", not_after="2000-01-01T00:00:00+00:00",
                        expired=True, days_left=-9000)

        async def fake_fetch_cert(host, port, *, timeout=6.0, server_hostname=None):
            return cert

        with mock.patch.object(ConnectScanner, "scan", make_fake_scan({REAL_IP: [443]})), \
             mock.patch("core.domains.probe.tls_cert.fetch_certificate", fake_fetch_cert):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_ips", "port_scan", "tls_cert"],
                module_config={"port_scan": {"ports": "top10"}},
            )

        findings = await self.storage.findings(scanner.scan_id)
        expired = [f for f in findings if f["kind"] == "cert_expired"]
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0]["severity"], "medium")


# --------------------------------------------------------------------- 解析器池回归
#
# 这一组是**离线**测试：注入一个替身解析器池，绝不真的去查 DNS。
# 替身只需实现 ResolverPool 的四个方法（pick / resolver_for / report /
# acquire_slot），接口很小，所以这里重复定义一次也不值得抽公共模块。


class FakeResolverPool:
    """替身解析器池。记录"问了谁、结果如何"，方便断言轮换与熔断上报。"""

    def __init__(self, resolvers: list) -> None:
        self._resolvers = list(resolvers)
        self.addresses = [f"fake-{i}" for i in range(len(resolvers))]
        self.reports: list[tuple[str, str]] = []
        self.asked: list[str] = []
        self._cursor = 0

    def pick(self):
        if not self._resolvers:
            return None
        addr = self.addresses[self._cursor % len(self.addresses)]
        self._cursor += 1
        self.asked.append(addr)
        return addr

    def resolver_for(self, addr):
        return self._resolvers[self.addresses.index(addr)]

    def report(self, addr: str, outcome: str, latency: float = 0.0) -> None:
        self.reports.append((addr, outcome))

    async def acquire_slot(self) -> None:
        return None


class TestResolverPoolRegression(unittest.IsolatedAsyncioTestCase):
    async def test_nxdomain_returns_empty_and_is_cached(self) -> None:
        import asyncio as _asyncio

        import dns.resolver

        from core.domains.resolve._lib.resolver import AsyncResolverPool

        calls: list[str] = []

        class _FakeAnswer:
            rrset = None

        class _FakeResolver:
            async def resolve(self, name, rdtype, raise_on_no_answer=False):  # noqa: ANN001
                calls.append(name)
                if name == "nope.example.com":
                    raise dns.resolver.NXDOMAIN()
                return _FakeAnswer()

        fake_pool = FakeResolverPool([_FakeResolver()])
        pool = AsyncResolverPool(pool=fake_pool)
        self.assertEqual(await pool.a_records("nope.example.com"), [])
        # 第二次命中缓存, 不再查一次
        self.assertEqual(await pool.a_records("nope.example.com"), [])
        self.assertEqual(calls.count("nope.example.com"), 1)
        self.assertEqual(pool.stats["errors"], 0)
        # NXDOMAIN 是**有效回答**, 不能当成故障去熔断解析器
        self.assertEqual(fake_pool.reports, [("fake-0", "answered")])

    async def test_noanswer_also_returns_empty(self) -> None:
        from core.domains.resolve._lib.resolver import AsyncResolverPool

        class _FakeAnswer:
            rrset = None

        class _FakeResolver:
            async def resolve(self, name, rdtype, raise_on_no_answer=False):  # noqa: ANN001
                return _FakeAnswer()

        pool = AsyncResolverPool(pool=FakeResolverPool([_FakeResolver()]))
        self.assertEqual(await pool.a_records("whatever.example.com"), [])

    async def test_timeout_fails_over_to_another_resolver(self) -> None:
        """单条超时要**换一个解析器重试**，而不是原地重试同一个坏掉的。"""
        import dns.resolver

        from core.domains.resolve._lib.resolver import AsyncResolverPool

        class _FakeAnswer:
            def __init__(self) -> None:
                self.rrset = [_FakeRdata()]

        class _FakeRdata:
            address = "1.2.3.4"

        class _DeadResolver:
            async def resolve(self, name, rdtype, raise_on_no_answer=False):  # noqa: ANN001
                raise dns.resolver.Timeout()

        class _GoodResolver:
            async def resolve(self, name, rdtype, raise_on_no_answer=False):  # noqa: ANN001
                return _FakeAnswer()

        fake_pool = FakeResolverPool([_DeadResolver(), _GoodResolver()])
        pool = AsyncResolverPool(pool=fake_pool)
        self.assertEqual(await pool.a_records("a.example.com"), ["1.2.3.4"])
        # 轮换意味着第二个名字会先问到那个好的解析器
        self.assertEqual(len(set(fake_pool.asked)), 2)
        self.assertIn(("fake-0", "timeout"), fake_pool.reports)
        self.assertEqual(pool.stats["retries"], 1)


class TestResolverPoolUnit(unittest.IsolatedAsyncioTestCase):
    """ResolverPool 本身的行为，用假 resolver 对象，不碰网络。"""

    def _pool(self, addrs, **kw):
        from core.domains.resolve._lib.resolver_pool import ResolverPool

        pool = ResolverPool(addrs, verify=False, **kw)
        # 直接塞假 resolver，跳过 dns.asyncresolver 的构造；
        # 同时补上 setup() 在校验关闭时会做的"标记为已验证"——
        # 漏了这步 healthy() 会一直返回空，测试就跑偏了
        pool._resolvers = {a: object() for a in addrs}
        pool._order = list(addrs)
        for stat in pool.stats.values():
            stat.verified = True
        pool._ready = True
        return pool

    async def test_fast_resolvers_get_more_traffic(self) -> None:
        """按健康度加权，而不是均匀轮换。

        这是实测驱动的改动：均匀轮换会把等量查询喂给被限速的慢解析器，
        9 个快池轮换能到 325 qps，混进一个 791ms 的就掉到 30 qps。
        """
        pool = self._pool(["fast", "slow"])
        # fast: 100% 成功、20ms；slow: 100% 成功、800ms
        for _ in range(20):
            pool.report("fast", "answered", 0.02)
            pool.report("slow", "answered", 0.80)

        picks = [pool.pick() for _ in range(2000)]
        fast = picks.count("fast")
        slow = picks.count("slow")
        self.assertEqual(fast + slow, 2000)
        # 两者都还会被用到（慢的没被饿死），但快的明显多
        self.assertGreater(slow, 0, "慢解析器被完全饿死了")
        self.assertGreater(fast / slow, 3, f"加权不明显: fast={fast} slow={slow}")

    async def test_unmeasured_pool_falls_back_to_uniform(self) -> None:
        """还没测出任何延迟时不能把流量压到一个上。"""
        pool = self._pool(["a", "b", "c"])
        picks = {pool.pick() for _ in range(200)}
        self.assertEqual(picks, {"a", "b", "c"})

    async def test_banned_resolver_is_never_picked(self) -> None:
        pool = self._pool(["fast", "bad"], ban_after=1, ban_seconds=999)
        pool.report("fast", "answered", 0.02)
        pool.report("bad", "timeout")
        self.assertTrue(all(pool.pick() == "fast" for _ in range(50)))

    async def test_streak_failures_ban_then_recover(self) -> None:
        pool = self._pool(["a", "b"], ban_after=2, ban_seconds=10)
        pool.report("b", "answered", 0.02)
        for _ in range(2):
            pool.report("a", "timeout")
        self.assertNotIn("a", pool.healthy())
        self.assertIn("b", pool.healthy())
        # 熔断期间不会被选中
        self.assertTrue(all(pool.pick() == "b" for _ in range(4)))

    async def test_all_banned_force_unbans_one(self) -> None:
        """全部熔断时必须强行解禁，否则整批查询直接卡死。"""
        pool = self._pool(["a", "b"], ban_after=1, ban_seconds=999)
        pool.report("a", "timeout")
        pool.report("b", "timeout")
        self.assertEqual(pool.healthy(), [])
        picked = pool.pick()
        self.assertIn(picked, ("a", "b"))
        self.assertEqual(len(pool.healthy()), 1)

    async def test_success_resets_streak(self) -> None:
        pool = self._pool(["a"], ban_after=2)
        pool.report("a", "timeout")
        pool.report("a", "answered", 0.05)
        pool.report("a", "timeout")
        # 中间成功过，不该被熔断
        self.assertIn("a", pool.healthy())

    async def test_outcomes_are_counted_separately(self) -> None:
        pool = self._pool(["a"])
        pool.report("a", "answered", 0.10)
        pool.report("a", "answered", 0.30)
        pool.report("a", "timeout")
        pool.report("a", "error")
        stat = pool.stats["a"]
        self.assertEqual((stat.answered, stat.timeouts, stat.errors), (2, 1, 1))
        # 平均延迟只按**成功的**算 —— 超时不该把延迟拉高
        self.assertAlmostEqual(stat.avg_latency, 0.20, places=6)

    def test_load_resolvers_parses_files_and_inline(self) -> None:
        from core.domains.resolve._lib.resolver_pool import load_resolvers

        # 内置列表存在且不含明显垃圾
        builtin = load_resolvers()
        self.assertGreater(len(builtin), 10)
        self.assertNotIn("#", " ".join(builtin))
        self.assertIn("223.5.5.5", builtin)

        # 内联串
        self.assertEqual(load_resolvers("1.1.1.1,8.8.8.8"), ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(load_resolvers("1.1.1.1 8.8.8.8"), ["1.1.1.1", "8.8.8.8"])

        # 带注释与重复
        from core.domains.resolve._lib.resolver_pool import _parse_lines

        self.assertEqual(
            _parse_lines("# 注释\n1.1.1.1  # 行尾注释\n1.1.1.1\n\n 8.8.8.8 "),
            ["1.1.1.1", "8.8.8.8"],
        )

    async def test_qps_limiter_paces(self) -> None:
        """限速生效时，N 个令牌至少要花 N/rate 秒。"""
        import time

        pool = self._pool(["a"], max_qps=50.0)
        # 重置桶，避免容量上限预支令牌
        pool._bucket.tokens = 0.0
        pool._bucket.capacity = 1.0
        pool._bucket.updated = time.monotonic()

        started = time.monotonic()
        for _ in range(5):
            await pool.acquire_slot()
        elapsed = time.monotonic() - started
        # 5 个令牌 @50qps ≈ 0.08s（扣掉桶里已有的 1 个）
        self.assertGreater(elapsed, 0.03)

    async def test_qps_zero_means_unlimited(self) -> None:
        import time

        pool = self._pool(["a"], max_qps=0)
        started = time.monotonic()
        for _ in range(200):
            await pool.acquire_slot()
        self.assertLess(time.monotonic() - started, 0.05)

class TestInvisibleCharacters(unittest.TestCase):
    """字典文件带 UTF-8 BOM 是家常便饭, 而 str.strip() 不去 BOM。"""

    def test_normalize_strips_bom_and_zero_width(self) -> None:
        from core.util.domain import normalize_domain

        self.assertEqual(normalize_domain("\ufeffwww.example.com"), "www.example.com")
        self.assertEqual(normalize_domain("www\u200b.example.com"), "www.example.com")
        self.assertEqual(normalize_domain("  *.Dev.Example.com.  "), "dev.example.com")
        # 确认前提: str.strip() 确实去不掉 BOM
        self.assertEqual("\ufeffwww".strip(), "\ufeffwww")

    def test_wordlist_loading_strips_bom(self) -> None:
        import tempfile
        from pathlib import Path

        from core.util.words import load_words

        base = Path(__file__).resolve().parents[1] / ".testtmp" / "bomtest"
        base.mkdir(parents=True, exist_ok=True)
        path = base / "words.txt"
        # 模拟 PowerShell Out-File -Encoding utf8 写出来的带 BOM 文件
        path.write_bytes("\ufeffwww\nAPI\n\ndev\n".encode("utf-8"))

        words = load_words(str(path))
        self.assertEqual(words, ["www", "api", "dev"])
        self.assertNotIn("\ufeffwww", words)


# --------------------------------------------------------------------- 预设卫生

class TestPresetHygiene(EngineTestCase):
    def test_active_preset_configures_m4_modules(self) -> None:
        preset = Preset.load_builtin("active")
        for name in ("port_scan", "http_probe", "tls_cert"):
            self.assertIn(name, preset.module_config)
        self.assertFalse(preset.module_config["port_scan"].get("allow_private", False))
        self.assertEqual(preset.config_for("port_scan")["ports"], "top100")

    def test_default_preset_does_not_run_port_scan(self) -> None:
        preset = Preset.load_builtin("default")
        # port_scan / http_probe 是 loud, 应被 deny_flags 挡掉
        self.assertFalse(preset.allows("port_scan", ("active", "loud")))
        self.assertFalse(preset.allows("http_probe", ("active", "loud")))
        # 内网闸门相关的模块配置不该在 default 里被打开
        self.assertNotIn("allow_private", preset.settings)


class TestFaviconHash(unittest.TestCase):
    """favicon 哈希的**口径**。

    这个函数有个静默退化分支：没装 ``mmh3`` 时返回 ``sha256[:16]``。那是**另一
    个口径** —— 指纹库里的 favicon 规则全是 mmh3 整数形式，sha256 形式一条都
    匹配不上，而且不会有任何报错。所以这里把两个口径都钉住，并确认降级会告警。
    """

    def setUp(self) -> None:
        from core.domains.probe._lib import tls

        # 告警只打一次，测试之间要复位
        tls._WARNED_NO_MMH3 = False
        self.tls = tls

    def test_mmh3_result_matches_fingerprint_library_format(self) -> None:
        """装了 mmh3 时必须是整数形式 —— 指纹导入器只认 ``^-?\\d{1,11}$``。"""
        got = self.tls.favicon_hash(b"\x89PNG\r\n\x1a\n fake icon")
        self.assertRegex(got, r"^-?\d{1,11}$", f"不是 mmh3 口径: {got!r}")

    def test_same_bytes_give_same_hash(self) -> None:
        data = b"identical"
        self.assertEqual(self.tls.favicon_hash(data), self.tls.favicon_hash(data))

    def test_empty_returns_empty(self) -> None:
        self.assertEqual(self.tls.favicon_hash(b""), "")

    def test_missing_mmh3_falls_back_and_warns(self) -> None:
        """**降级不能是静默的。**

        原来这条分支写着 ``# pragma: no cover``，等于没人测过；真跑到它的时候
        指纹失效了也查不出来。现在要求：返回 sha256 形式，并且打一条 WARNING。
        """
        data = b"fake icon"
        with mock.patch.dict(sys.modules, {"mmh3": None}):
            with self.assertLogs("recon.tls", level="WARNING") as captured:
                got = self.tls.favicon_hash(data)
        self.assertRegex(got, r"^[0-9a-f]{16}$", f"不是 sha256 口径: {got!r}")
        self.assertTrue(
            any("mmh3" in line for line in captured.output),
            f"降级没告警: {captured.output}",
        )

    def test_the_two_dialects_differ(self) -> None:
        """两个口径必须**真的不一样** —— 否则"退化"就无所谓了。"""
        data = b"fake icon"
        real = self.tls.favicon_hash(data)
        with mock.patch.dict(sys.modules, {"mmh3": None}):
            with self.assertLogs("recon.tls", level="WARNING"):
                degraded = self.tls.favicon_hash(data)
        self.assertNotEqual(real, degraded)

    def test_warning_is_emitted_only_once(self) -> None:
        """别每个 favicon 刷一行 —— 一个扫描可能有几百个。"""
        with mock.patch.dict(sys.modules, {"mmh3": None}):
            with self.assertLogs("recon.tls", level="WARNING") as captured:
                self.tls.favicon_hash(b"a")
                self.tls.favicon_hash(b"b")
                self.tls.favicon_hash(b"c")
        self.assertEqual(len(captured.output), 1, f"告警刷屏: {captured.output}")


if __name__ == "__main__":
    unittest.main()
