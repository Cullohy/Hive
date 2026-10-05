"""`query_extra` 的越界边界 —— 不烧额度，纯测试钉死。

## 要证明的三件事

1. **配了 `query_extra` 就默认不收裸 IP**（`cert=` / `title=` 很可能不是按目标
   限定的，那些资产行的裸 IP 属于别人）
2. **显式写了就能收**，且"写什么"都认 —— 包括**字符串** ``"false"``
3. **域名的承重墙没被动过**：即便 ``cert=`` 捞回别家的域名，
   ``sanitize_subdomains`` 照样拦下来

## 为什么第 2 条要单独强调

``WebSettings.source_options`` 的值**一律是字符串**。这意味着

    旧：bool(self.cfg("accept_ip_assets", True))  ->  bool("false")  ->  **True**
    新：as_bool(self.cfg(...))                      ->  "false"        ->  **False**

也就是说**"我明确不要收" 在旧代码里会变成"要收"** —— 与
``port_scan.allow_private`` 那个内网闸门是同一类反转，只是这次反转的是
"要不要把别人的 IP 写进资产表"。

本文件里的 :func:`_old_style_bool` 把旧行为原样算出来放在旁边对照，
这样"修之前是什么样"就不只是 commit message 里的一句话。
"""
from __future__ import annotations

import json
import unittest
from unittest import mock

from .base import EngineTestCase


def _old_style_bool(value) -> bool:
    """修复前的行为，原样复刻 —— 用来对照，不是用来推荐。"""
    return bool(value)


class TestQueryExtraGate(unittest.TestCase):
    """同一份配置，新旧两条路给出不同答案。"""

    def test_query_extra_flips_ip_acceptance_off(self) -> None:
        from core.domains.subdomain.passive.fofa import Query

        q = Query()
        q.init_key(api_key="k", query_extra='cert="example"')

        # 新：认得 extra -> 默认不收
        self.assertFalse(q.accept_ip_assets)
        # 旧：class 属性恒为 True，config 里没这个键就没人改它
        self.assertTrue(_old_style_bool(True),
                        "对照失效：旧行为也该是 True，否则这条测试没意义")

    def test_explicit_true_still_works(self) -> None:
        from core.domains.subdomain.passive.fofa import Query

        for raw in (True, "true", "1", "yes", "on"):
            q = Query()
            q.init_key(api_key="k", query_extra='ip="1.2.3.4"',
                       accept_ip_assets=raw)
            self.assertTrue(q.accept_ip_assets, f"{raw!r} 没被认成真")

    def test_explicit_false_is_respected(self) -> None:
        """❗ 字符串 ``"false"`` 必须被认成假 —— 这就是本文件的核心。"""
        from core.domains.subdomain.passive.fofa import Query

        for raw in (False, "false", "0", "no", "off", ""):
            q = Query()
            q.init_key(api_key="k", query_extra='ip="1.2.3.4"',
                       accept_ip_assets=raw)
            self.assertFalse(
                q.accept_ip_assets,
                f"{raw!r} 被当成了真 —— 『明确不要收』变成了『要收』")

    def test_the_old_code_would_have_inverted_it(self) -> None:
        """把对照写死：修之前 ``"false"`` 的确是 True。"""
        self.assertTrue(_old_style_bool("false"),
                        "对照失效：旧代码对 'false' 并不是真，"
                        "那这条修复就没有实际后果")

    def test_without_extra_the_base_query_is_trusted(self) -> None:
        """没配 extra 时（``domain="目标"``，查询即作用域）默认收。"""
        from core.domains.subdomain.passive.fofa import Query

        q = Query()
        q.init_key(api_key="k")
        self.assertTrue(q.accept_ip_assets)


class TestQueryExtraEndToEnd(EngineTestCase):
    """真跑一遍源（不联网），看它到底发不发 IP_ADDRESS。"""

    async def _drive(self, cfg: dict, rows: list[str]):
        from core.domains.subdomain._lib.dns_query import SourceStats
        from core.domains.subdomain.passive.fofa import Query as FofaQuery
        from core.domains.subdomain.passive.fofa import passive_fofa
        from core.engine.event import Event, EventType
        from core.services.http import HTTPClient

        mod = passive_fofa.__new__(passive_fofa)
        mod.name = "passive_fofa"
        mod._engine = None
        mod.config = cfg
        mod.stats = SourceStats(source="passive_fofa")
        mod._seen_roots = set()
        mod._recursed = {}
        mod.recursive_max_names = 5
        mod.max_subdomain_len = 63

        q = FofaQuery()

        async def sub_domains(_self, target, http):  # noqa: ANN001
            # ⚠️ `_self` 不能省：补丁打在**类**上，所以取出来时 `self` 已绑定，
            #    不收这个参数就是 "takes 2 positional arguments but 3 were given"。
            return list(rows)

        q.init_key(**{"api_key": "k", **cfg})

        emitted: list[tuple[str, str]] = []

        async def fake_emit(data, etype, parent=None, tags=None):  # noqa: ANN001
            emitted.append((getattr(etype, "value", etype), str(data)))

        mod.emit_event = fake_emit
        mod.log = mock.MagicMock()
        # ⚠️ 补丁必须**同时**覆盖 setup 和 handle_event。写成只包 setup 的话，
        #    handle_event 会去调真的 sub_domains（真发 HTTP），于是全空 ——
        #    症状是"什么都没产出"，看不出是夹具的问题。
        with mock.patch.object(type(q), "sub_domains", sub_domains):
            mod._query = q
            mod._http = HTTPClient()
            await mod.setup()
            await mod.handle_event(Event(type=EventType.SEED, data="example.com"))
        return emitted, mod.stats

    async def test_with_cert_extra_foreign_ips_are_not_emitted(self) -> None:
        """``cert=`` 捞回来的**别人的裸 IP** 不能进资产表。"""
        emitted, stats = await self._drive(
            {"api_key": "k", "query_extra": 'cert="example"'},
            # cert 检索的典型返回：本家的域名 + 别人（裸 IP 形态）的资产
            ["a.example.com", "203.0.113.5:8443", "198.51.100.9"],
        )
        ips = [d for t, d in emitted if t == "IP_ADDRESS"]
        self.assertEqual(ips, [], f"别人的裸 IP 被收进来了: {ips}")
        # 域名照发（而且只有本家的那个）
        names = [d for t, d in emitted if t == "DNS_NAME"]
        self.assertEqual(names, ["a.example.com"])
        # ⚠️ 但必须**计过数** —— 丢了却没痕迹，就等于没丢过
        self.assertEqual(stats.ip_results, 2)
        self.assertEqual(stats.ip_accepted, 0)

    async def test_with_ip_extra_and_opt_in_they_are_emitted(self) -> None:
        """自己写了 ``ip=`` 又显式开了开关 -> 收。"""
        emitted, stats = await self._drive(
            {"api_key": "k", "query_extra": 'ip="203.0.113.5"',
             "accept_ip_assets": "true"},
            ["a.example.com", "203.0.113.5:8443", "203.0.113.5:9000"],
        )
        ips = sorted(d for t, d in emitted if t == "IP_ADDRESS")
        self.assertEqual(ips, ["203.0.113.5"])
        self.assertEqual(stats.ip_results, 2, "两行是同一个 IP 的两个端口")
        self.assertEqual(stats.ip_accepted, 1, "去重后只收 1 个")

    async def test_the_domain_wall_holds_even_with_cert_extra(self) -> None:
        """❗ 域名的承重墙**没被动过**：别家的域名照样被拦。

        前面几条测的是 IP，这条测域名 —— ``cert=`` 天然会捞回别人的域名，
        拦住它们的是 :func:`sanitize_subdomains` 的 ``is_subdomain_of``，
        与 ``query_extra`` 无关。
        """
        emitted, _ = await self._drive(
            {"api_key": "k", "query_extra": 'cert="example"'},
            ["a.example.com", "b.other-corp.com", "c.example.com"],
        )
        names = sorted(d for t, d in emitted if t == "DNS_NAME")
        self.assertEqual(names, ["a.example.com", "c.example.com"],
                         "别家的域名被放进来了 —— 承重墙被动了")


class TestNoQueryExtraLeaksForeignDomain(unittest.TestCase):
    """把承重墙单独钉一道：不配任何东西时它也得在。"""

    def test_sanitize_drops_other_domains(self) -> None:
        from core.domains.subdomain._lib.dns_query import sanitize_subdomains

        got = sanitize_subdomains(
            ["a.example.com", "evil.other.com", "example.com.evil.com",
             "b.example.com"],
            "example.com")
        self.assertEqual(got, ["a.example.com", "b.example.com"])
