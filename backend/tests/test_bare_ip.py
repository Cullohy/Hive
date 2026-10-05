"""测绘源返回的裸 IP 能不能插进「IP 变成站点」那一步。

## 为什么要测这一段

裸 IP 以前被 ``sanitize_subdomains`` 的 ``is_subdomain_of`` 静悄悄丢掉 ——
界面上只看得到"产出少"，**没有任何地方能看出丢了什么**。

判据落在三处（缺一不可）：

1. **纯函数**：``partition_ips`` 拆得对不对（含 IPv6 —— ``host_of`` 以前会把
   ``2001:db8::1`` 腰斩成 ``2001``，而 fofa 的裸 IP 资产恰恰是这种形态）
2. **按源闸门**：只给"查询即作用域"的源开；关着的源不许发，但**必须计数**
3. **端到端**：真跑一遍扫描，裸 IP 落成 ``ip`` 表行、**没有** ``domain_ip``
   关联 —— 这正是"无 DNS 映射"在数据里的天然形态
"""
from __future__ import annotations

import unittest

from .base import EngineTestCase


class TestPartitionIPs(unittest.TestCase):
    def test_splits_ips_from_domains(self) -> None:
        from core.domains.subdomain._lib.dns_query import partition_ips

        ips, rest, _rows = partition_ips([
            "a.yealink.com.cn",
            "1.2.3.4:8443",            # 裸 IP + 端口
            "https://5.6.7.8:443/x",   # 完整 URL 形态的裸 IP
            "b.yealink.com.cn",
        ])
        self.assertEqual(sorted(ips), ["1.2.3.4", "5.6.7.8"])
        self.assertEqual(sorted(rest), ["a.yealink.com.cn", "b.yealink.com.cn"])

    def test_ipv6_is_not_mangled(self) -> None:
        """❗ ``host_of`` 以前把 ``2001:db8::1`` 切成 ``2001`` —— IPv6 腰斩。

        而 fofa 的裸 IP 资产恰恰是这个形态，所以这不是理论问题。
        """
        from core.domains.subdomain._lib.dns_query import partition_ips

        for text in ("2001:db8::1", "[2001:db8::1]:8443"):
            ips, rest, _rows = partition_ips([text])
            self.assertEqual(ips, ["2001:db8::1"], f"{text} 被切坏了: {rest}")
            self.assertEqual(rest, [], f"{text} 落到了域名那边")


class TestHostOfIPv6(unittest.TestCase):
    """``host_of`` 的 IPv6 处理要与 ``Scanner._normalize_target`` 一致。

    两处各修一半正是这类 bug 反复出现的原因（扫描器的目标归一化早就修对了，
    ``domain.host_of`` 里一直漏着），所以这里钉住"两者对同一批输入给同一个结果"。

    ⚠️ 只比**两种实现都认**的形态。``user:pw@h.com:8080`` 不参与 ——
    ``host_of`` 要剥用户信息、目标归一化不剥，两者**本来就应当不同**。
    """

    SHARED = [
        "2001:db8::1", "[2001:db8::1]:8443", "1.2.3.4:8443",
        "a.b.com", "a.b.com:443",
    ]

    def test_no_colon_truncation(self) -> None:
        from core.util.domain import host_of

        self.assertEqual(host_of("2001:db8::1"), "2001:db8::1")
        self.assertEqual(host_of("[2001:db8::1]:8443"), "2001:db8::1")
        self.assertEqual(host_of("1.2.3.4:8443"), "1.2.3.4")
        self.assertEqual(host_of("a.b.com:443"), "a.b.com")
        self.assertEqual(host_of("user:pw@h.com:8080"), "h.com")

    def test_agrees_with_the_scanner_target_normalizer(self) -> None:
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner
        from core.util.domain import host_of

        sc = Scanner(targets=["x"], preset=Preset(name="t"), storage=None)
        for t in self.SHARED:
            self.assertEqual(
                host_of(t), sc._normalize_target(t),
                f"host_of 与 目标归一化 对 {t!r} 的结果不一致")


async def _drive_source(cls, rows, *, accept_ips: bool, needs_key: bool = True):
    """直接驱动一个被动源模块，返回 (发出的事件, stats)。

    不走引擎 —— 这里要验的只是"裸 IP 有没有被收成资产、丢了有没有留痕"，
    走引擎会掺进一堆无关的失败。
    """
    from unittest import mock

    from core.domains.subdomain._lib.dns_query import SourceStats
    from core.domains.subdomain._lib import dns_query as base
    from core.engine.event import Event, EventType
    from core.services.http import HTTPClient

    mod = cls.__new__(cls)
    mod.name = cls.__name__
    # ``scanner`` 是只读属性，读它会取 ``self._engine``；这里不走引擎，
    # 补一个 None 让属性可读（``emit_event`` 已被替换，不会真用到）
    mod._engine = None
    mod.config = {"api_key": "dummy"} if needs_key else {}
    mod.stats = SourceStats(source=mod.name)
    mod._seen_roots = set()
    mod._recursed = {}
    mod.recursive_max_names = 5
    mod.max_subdomain_len = 63
    mod.accepts_ip_assets = accept_ips
    mod._query = cls.query()
    mod._http = HTTPClient()

    emitted: list[tuple[str, str]] = []
    tags_seen: list[dict] = []

    async def fake_emit(data, etype, parent=None, tags=None):  # noqa: ANN001
        emitted.append((getattr(etype, "value", etype), str(data)))
        tags_seen.append(dict(tags or {}))

    mod.emit_event = fake_emit
    mod.log = mock.MagicMock()

    async def fake_sub(_self, target, http):  # noqa: ANN001
        return list(rows)

    with mock.patch.object(type(mod._query), "sub_domains", fake_sub):
        r = await mod.setup()
        if r is False or (isinstance(r, tuple) and r[0] is False):
            raise AssertionError(f"{mod.name} setup 失败: {r}")
        await mod.handle_event(Event(type=EventType.SEED, data="example.com"))
    return emitted, mod.stats, tags_seen


class TestIPAcceptanceGate(unittest.IsolatedAsyncioTestCase):
    """按源开关。只给"查询即作用域"的测绘源开 —— 见下面的分组理由。"""

    def test_only_query_scoped_sources_accept_ips(self) -> None:
        from core.domains.subdomain.passive.fofa import passive_fofa
        from core.domains.subdomain.passive.hunter import passive_hunter
        from core.domains.subdomain.passive.quake import passive_quake

        # 查询语句由 target 拼出 -> 返回的天然是关于目标的
        for m in (passive_fofa, passive_quake, passive_hunter):
            self.assertTrue(m.accepts_ip_assets, f"{m.__name__} 该收裸 IP")

        # 源本身不干净（CT 日志 / 存档索引里混着第三方）-> 那道闸门是承重墙
        for name in ("crtsh", "certspotter", "commoncrawl", "wayback",
                     "rapiddns", "hackertarget", "anubis", "urlscan",
                     "subdomaincenter"):
            mod = __import__(
                f"core.domains.subdomain.passive.{name}", fromlist=["x"])
            cls = getattr(mod, f"passive_{name}")
            self.assertFalse(
                cls.accepts_ip_assets,
                f"{name} 的返回里混着第三方资产，收裸 IP 会越界")

    async def test_off_source_counts_but_does_not_emit(self) -> None:
        """关着的源：裸 IP 一个都不发，但**必须计过数**。

        静悄悄丢掉正是这次要消灭的 —— 丢了却没有任何痕迹，就等于没丢过。
        """
        from core.domains.subdomain.passive.crtsh import passive_crtsh

        emitted, stats, _ = await _drive_source(
            passive_crtsh, ["a.example.com", "1.2.3.4", "5.6.7.8:9000"],
            accept_ips=False)

        self.assertIn(("DNS_NAME", "a.example.com"), emitted)
        self.assertNotIn(("IP_ADDRESS", "1.2.3.4"), emitted)
        self.assertNotIn(("IP_ADDRESS", "5.6.7.8"), emitted)
        # ❗ 修复点：丢了必须留痕
        self.assertEqual(stats.ip_results, 2,
                         "裸 IP 没有计数 —— 界面上看不出丢了东西")
        self.assertEqual(stats.ip_accepted, 0)

    async def test_on_source_emits_ip_address_with_provenance(self) -> None:
        """开着的源：裸 IP 发成 ``IP_ADDRESS``，并带"哪来的"标记。"""
        from core.domains.subdomain.passive.fofa import passive_fofa

        emitted, stats, tags = await _drive_source(
            passive_fofa, ["a.example.com", "1.2.3.4", "1.2.3.4:9000"],
            accept_ips=True)

        self.assertIn(("DNS_NAME", "a.example.com"), emitted)
        self.assertIn(("IP_ADDRESS", "1.2.3.4"), emitted)
        # 同一 IP 的两个端口要合并成**一条**（源给的是"资产行"，一行一个
        # host:port；不去重就会为同一个 IP 连发事件，统计也跟着虚高）
        self.assertEqual([e for e in emitted if e[1] == "1.2.3.4"], 1 * [("IP_ADDRESS", "1.2.3.4")],
                         "同 IP 的多端口应当合并成一条 IP_ADDRESS")
        # 收到 2 行、接收 1 个 —— 两个数不同才是对的
        self.assertEqual(stats.ip_results, 2)
        self.assertEqual(stats.ip_accepted, 1,
                         "去重后只该接收 1 个 IP（两个端口是同一个）")

        ip_tags = [t for (etype, _), t in zip(emitted, tags)
                   if etype == "IP_ADDRESS"]
        self.assertTrue(ip_tags)
        self.assertEqual(ip_tags[0].get("ip_source"), "passive_fofa")
        self.assertIs(ip_tags[0].get("no_domain_mapping"), True)


class TestBareIPLandsInAssetTable(EngineTestCase):
    """端到端：裸 IP 落成 ``ip`` 行，且**没有** ``domain_ip`` 关联。

    这正是"无 DNS 映射的裸 IP 资产"在数据里的形态 —— 不需要额外标记字段，
    天然就分得开。
    """

    async def test_orphan_ip_is_reachable_via_the_asset_tables(self) -> None:
        """真跑一遍扫描，断言裸 IP 落成了 ``ip`` 资产。"""
        from unittest import mock

        from core.domains.subdomain.passive.fofa import Query as FofaQuery

        async def fake_sub(_self, target, http):  # noqa: ANN001
            return ["a.example.com", "1.2.3.4:8443", "1.2.3.4:9000",
                    "5.6.7.8:443"]

        # 走真引擎：被动源出事件 -> 存储投影。预设里没有 dns_resolve/port_scan，
        # 所以这一步验的正是"裸 IP 自己进了链路"，后面的端口扫描不在范围内。
        with mock.patch.object(FofaQuery, "sub_domains", fake_sub):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["passive_fofa"],
                module_config={"passive_fofa": {"api_key": "dummy"}},
            )

        ips = [i["addr"] for i in await self.storage.ips(scanner.scan_id)]
        self.assertIn("1.2.3.4", ips, "裸 IP 没有落成 ip 资产")
        self.assertIn("5.6.7.8", ips)
        # 同一 IP 的两个端口只算一个 IP 资产
        self.assertEqual(ips.count("1.2.3.4"), 1, "同 IP 的多端口应当合并")
        # 域名那条走正常路径，也该在
        domains = [d["name"] for d in
                   await self.storage.domains(scanner.scan_id)]
        self.assertIn("a.example.com", domains)
