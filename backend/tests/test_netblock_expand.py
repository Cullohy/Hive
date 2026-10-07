"""``netblock_expand`` —— C 段展开的单元测试。

## 为什么要按归属证据重写判据

第一版是"看到一个 IP 就展开整段"，实测口径下有两个问题：

* 一个 /24 里绝大多数机器是**同段其它租户**（库里 25% 的已知 IP 标着
  ``is_cloud``），无条件展开等于对第三方发端口扫描；
* 展开出来的邻居如果也算证据，递归会自我放大。

现在改成**段里至少 ``min_owned`` 台挂在目标域名下**才展开。归属证据直接取自
事件里的 ``parent_data``，不查库、不发外部请求。

## 为什么全部走单元层

展开一个 /24 会发 254 个 ``IP_ADDRESS``，每个都要落库、投影、走 ``key()``
去重 —— 单跑一个用例就把这一类拖到几百秒，变异验证本身都会超时。这里直接调
``handle_event``、``emit_event`` 换成收集器，断言的是**同一份代码**。
"""
from __future__ import annotations

import asyncio
import unittest

from core.domains.resolve.netblock_expand import netblock_expand
from core.engine.event import Event, EventType


class _Log:
    def info(self, msg, *a, **k) -> None:  # noqa: ANN001
        pass


class _Scanner:
    """只提供本模块用到的那一点扫描器接口：``targets`` 与 ``root_domain_of``。"""

    def __init__(self, targets=("example.com",)) -> None:
        self.targets = list(targets)

    def root_domain_of(self, d: str) -> str | None:
        d = (d or "").strip().lower().rstrip(".")
        for t in self.targets:
            t = str(t).strip().lower()
            if d == t or d.endswith("." + t):
                return t
        return None


def build(targets=("example.com",), scanner=None, **cfg) -> tuple[netblock_expand, dict]:
    m = netblock_expand.__new__(netblock_expand)
    m.config = dict(cfg)
    m.name = "netblock_expand"
    m.log = _Log()
    m.stats = {}
    # ⚠️ ``scanner`` 是**只读属性**（基类刻意做成只读，子类一覆盖就启动即报错），
    # 所以这里必须设底层那个 ``_engine``。直接 ``m.scanner = ...`` 会抛
    # AttributeError —— 而那是基类设计，不是本模块的问题。
    m._engine = scanner if scanner is not None else _Scanner(targets)
    m._expanded = set()
    m._owned = {}
    m._unexpanded = set()
    m.prefixlen = cfg.get("prefixlen", 24)
    m.min_owned = cfg.get("min_owned", 2)
    m.max_hosts = cfg.get("max_hosts", 254)
    m.max_netblocks = cfg.get("max_netblocks", 64)
    out = {"ip": [], "finding": [], "tags": []}

    async def emit_event(data, etype, *, parent=None, tags=None):
        if etype == EventType.IP_ADDRESS:
            out["ip"].append(str(data))
            out["tags"].append(dict(tags or {}))

    async def emit_finding(kind, detail, *, parent=None, severity="info",
                           target=None):
        out["finding"].append(kind)

    m.emit_event = emit_event
    m.emit_finding = emit_finding
    return m, out


def resolved(ip: str, parent_domain: str) -> Event:
    """一条"目标解析出了这个 IP"的事件 —— 有归属证据。"""
    return Event(type=EventType.IP_ADDRESS, data=ip, module="dns_resolve",
                 parent_data=parent_domain)


def neighbour(ip: str, parent_ip: str = "93.184.216.1") -> Event:
    """一条"从别的 IP 带出来的"事件 —— **没有**归属证据。"""
    return Event(type=EventType.IP_ADDRESS, data=ip, module="netblock_expand",
                 parent_data=parent_ip)


def from_seed(addr: str) -> Event:
    """一条裸 IP 种子的产物 —— ``seed_asset`` 发的 IP_ADDRESS，父事件是 SEED。

    注意**不要**写成 ``seed()`` 再让模块自己去认父事件：本模块只认
    「父事件是目标域名下的 DNS_NAME」和「这个地址就是种子目标本身」，
    后者比的是 ``scanner.targets``，跟父事件是什么没关系。
    """
    return Event(type=EventType.IP_ADDRESS, data=addr, module="seed_asset")


class TestNetblockExpandGate(unittest.IsolatedAsyncioTestCase):
    """归属证据不足就不展开 —— 这是本模块存在的全部理由。"""

    async def test_two_owned_hosts_expand_the_segment(self) -> None:
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "www.example.com"))
        self.assertEqual(out["ip"], [], "只有 1 台证据就展开 = 对第三方发扫描")
        await m.handle_event(resolved("93.184.216.2", "api.example.com"))
        # ⚠️ **必须比集合，不能比 ``sorted()`` 之后的列表。**
        # 字符串排序里 ``'93.184.216.10' < '93.184.216.2'``（比的是字符不是数），
        # 照数字顺序写期望值会得到一个"少了一个地址"的假失败 —— 实测踩过。
        self.assertEqual(
            set(out["ip"]),
            {f"93.184.216.{i}" for i in range(1, 255)},
            f"应展开 254 个地址: {len(out['ip'])} 个",
        )
        self.assertEqual(len(out["ip"]), 254)
        self.assertIn("netblock_expanded", out["finding"])

    async def test_one_owned_host_is_not_enough(self) -> None:
        """1 台不构成"这段是你的" —— 哪怕之后涌进 38 个邻居。

        邻居**连候选都算不上**：它们没有归属证据，直接在第一道门就被挡掉，
        不会把 ``no_evidence`` 计数推上去（那个计数只记"有证据但不够"）。
        """
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        for i in range(2, 40):
            await m.handle_event(neighbour(f"93.184.216.{i}"))
        self.assertEqual(out["ip"], [])
        self.assertEqual(m._peek("no_evidence"), 1, "计数的是段，不是事件")
        self.assertEqual(m._unexpanded, {"93.184.216.0/24"})
        self.assertEqual(m._expanded, set())

    async def test_neighbours_do_not_count_as_evidence(self) -> None:
        """**展开出来的邻居一条都不能算归属证据。**

        它们的父事件是 IP 而不是域名。要是算进去，一个段一展开就会把自己
        的产出当成"这台机器属于目标"的证据 —— 递归自我放大，而且闸门形同虚设。
        """
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        for i in range(2, 60):
            await m.handle_event(neighbour(f"93.184.216.{i}"))
        self.assertEqual(out["ip"], [], "邻居被当成了归属证据")

    async def test_evidence_must_be_in_target_scope(self) -> None:
        """父域名**不在目标范围**内不算证据 —— 那是别人的域名。"""
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "a.other.com"))
        await m.handle_event(resolved("93.184.216.2", "b.other.com"))
        self.assertEqual(out["ip"], [], "范围外的域名被当成了归属证据")

    async def test_bare_ip_seed_expands_its_segment_directly(self) -> None:
        """**裸 IP 种子和域名种子是同一类输入**，只是省掉 DNS 解析那一步。

        域名种子靠子域解析拿到若干 IP 累积成证据；裸 IP 种子本身只有一台，
        卡在 ``min_owned``（默认 2）上等于让这条路径**永远空转** ——
        「段扫描的 IP 来源是种子直接给的 IP 或者 DNS 产出的」这句话里，
        前半截就白写了。

        用户亲手把这个 IP 填进任务目标，本身就是对这一台的明确授权，
        所以它所在的段直接展开，不等第二台。
        """
        m, out = build(targets=("93.184.216.4",))
        await m.handle_event(Event(type=EventType.IP_ADDRESS, data="93.184.216.4"))
        self.assertEqual(len(out["ip"]), 254, "裸 IP 种子没能展开它的段")
        self.assertEqual(m._peek("seed_evidence"), 1)
        self.assertIn("netblock_expanded", out["finding"])

    async def test_bare_ip_seed_does_not_need_the_min_owned_gate(self) -> None:
        """把 ``min_owned`` 调高也不该拦住种子 —— 那条闸门是给 DNS 路径用的。"""
        m, out = build(targets=("93.184.216.4",), min_owned=99)
        await m.handle_event(Event(type=EventType.IP_ADDRESS, data="93.184.216.4"))
        self.assertEqual(len(out["ip"]), 254)

    async def test_ip_from_dns_is_still_gated(self) -> None:
        """**别把闸门一起拆了。** DNS 路径单台依然不够。"""
        m, out = build(min_owned=99)
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        self.assertEqual(out["ip"], [], "DNS 单台证据就展开了")

    async def test_min_owned_is_configurable(self) -> None:
        m, out = build(min_owned=1)
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        self.assertEqual(len(out["ip"]), 254)

    async def test_different_segments_are_independent(self) -> None:
        """A 段证据够就展开 A 段，不牵动 B 段。"""
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        await m.handle_event(resolved("93.184.216.2", "b.example.com"))
        first = len(out["ip"])
        await m.handle_event(resolved("93.185.1.1", "c.example.com"))
        self.assertEqual(len(out["ip"]), first, "只有 1 台证据的 B 段也被展开了")
        self.assertEqual(m.stats["expanded"], 1)


    async def test_seed_netblock_is_not_expanded_twice(self) -> None:
        """**用户直接下发网段时，轮到 ``seed_asset``，不是本模块。**

        种子是 ``93.184.216.0/24`` 时 ``seed_asset`` 已经枚举出 254 个地址。
        而这些 IP 的父事件是 SEED，``parent_data`` 正好等于网段串 ——
        ``root_domain_of`` 会判它"在范围内"。不拦住的话，本模块会把同一个段
        再数出 2 台证据、再展开一遍：白跑一轮，还多出一条看起来像第二次发现的
        finding。
        """
        m, out = build(targets=("93.184.216.0/24",))
        await m.handle_event(resolved("93.184.216.1", "93.184.216.0/24"))
        await m.handle_event(resolved("93.184.216.2", "93.184.216.0/24"))
        self.assertEqual(out["ip"], [], "种子网段被重复展开了")
        self.assertEqual(m._peek("seed_netblock"), 2)
        self.assertEqual(m._expanded, set())

    async def test_seed_netblock_shorter_than_prefixlen_is_still_caught(self) -> None:
        """**守卫必须拿地址去比网段，不能拿段串比段串。**

        第一版写成 ``key in netblock_targets()``，而 ``key`` 是按
        ``prefixlen``（默认 24）算的段 —— 种子写 ``/29`` 时 ``key`` 是 ``/24``，
        **永远不相等**，守卫形同虚设。

        这条是端到端测试 ``test_seed_netblock_is_left_to_seed_asset`` 抓出来的：
        ``seed_asset`` 出了 6 个地址，``netblock_expand`` 又把整个 /24 展开成
        254 个（单跑那一类用例从 8 秒涨到 32 秒）。
        """
        m, out = build(targets=("93.184.216.0/29",), prefixlen=24)
        await m.handle_event(resolved("93.184.216.1", "93.184.216.0/29"))
        self.assertEqual(out["ip"], [], "/29 的种子被当成 /24 重复展开了")
        self.assertEqual(m._peek("seed_netblock"), 1)

    async def test_address_outside_seed_netblock_is_not_suppressed(self) -> None:
        """守卫不能过头：段**外面**的 IP 不受种子网段影响。

        目标同时给一个域名（提供归属证据）和一个无关网段 —— 后者不能把
        域名那条路算出来的段也一起压掉。
        """
        m, out = build(targets=("example.com", "10.0.0.0/8"))
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        await m.handle_event(resolved("93.184.216.2", "b.example.com"))
        self.assertEqual(len(out["ip"]), 254, "无关的段被种子网段误伤了")
        self.assertEqual(m._peek("seed_netblock"), 0)


class TestNetblockExpandBoundaries(unittest.IsolatedAsyncioTestCase):
    """去重、封顶、留痕、IPv6。"""

    async def test_same_segment_expands_only_once(self) -> None:
        """引擎去重救不了这里：IP_ADDRESS 的键带 parent_data。

        同一个邻居地址从 20 个父 IP 进来会算成 20 个键 —— 端口扫描被打 20 遍。
        """
        m, out = build()
        for host in ("a", "b", "c"):
            await m.handle_event(resolved(f"93.184.216.1", f"{host}.example.com"))
            await m.handle_event(resolved(f"93.184.216.2", f"{host}.example.com"))
        self.assertEqual(len(out["ip"]), 254)
        self.assertEqual(m.stats["expanded"], 1)

    async def test_network_and_broadcast_are_not_emitted(self) -> None:
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        await m.handle_event(resolved("93.184.216.2", "b.example.com"))
        self.assertNotIn("93.184.216.0", out["ip"])
        self.assertNotIn("93.184.216.255", out["ip"])

    async def test_ipv6_is_not_expanded(self) -> None:
        """「C 段」是 IPv4 的说法；/64 是 2^64 个地址。"""
        m, out = build()
        await asyncio.wait_for(
            m.handle_event(neighbour("2606:2800:220:1:248:1893:25c8:1946")),
            timeout=10,
        )
        self.assertEqual(out["ip"], [])
        self.assertEqual(m.stats["skipped_v6"], 1)

    async def test_garbage_input_does_not_raise(self) -> None:
        m, out = build()
        await m.handle_event(Event(type=EventType.IP_ADDRESS, data="不是IP"))
        await m.handle_event(Event(type=EventType.IP_ADDRESS, data=""))
        self.assertEqual(out["ip"], [])
        self.assertEqual(m.stats.get("bad_input"), 1)

    async def test_max_hosts_truncates(self) -> None:
        m, out = build(max_hosts=16)
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        await m.handle_event(resolved("93.184.216.2", "b.example.com"))
        self.assertEqual(len(out["ip"]), 16)

    async def test_netblock_budget_is_capped_and_reported_once(self) -> None:
        """段数封顶，**且超限 finding 只发一次**。"""
        m, out = build(max_netblocks=2)
        for i in range(6):
            await m.handle_event(resolved(f"93.184.{i}.1", f"a{i}.example.com"))
            await m.handle_event(resolved(f"93.184.{i}.2", f"b{i}.example.com"))
        self.assertEqual(m.stats["expanded"], 2)
        self.assertEqual(out["finding"].count("netblock_expand_capped"), 1)

    async def test_emitted_events_carry_their_segment(self) -> None:
        """每个地址带 ``netblock`` 标签。

        这个标签不只是日志：存储层 ``_upsert_ip`` 会把它写进 ``ip.netblock``，
        于是界面上能分清「这是目标子域解析出来的」和「这是 C 段扫出来的邻居」——
        后者没有任何域名，光看地址完全看不出区别。
        """
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        await m.handle_event(resolved("93.184.216.2", "b.example.com"))
        self.assertEqual(out["tags"][0]["netblock"], "93.184.216.0/24")
        self.assertEqual(out["tags"][0]["source"], "netblock_expand")

    async def test_prefixlen_is_configurable(self) -> None:
        m, out = build(prefixlen=16, max_hosts=5)
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        await m.handle_event(resolved("93.184.216.2", "b.example.com"))
        self.assertEqual(out["tags"][0]["netblock"], "93.184.0.0/16")
        self.assertEqual(len(out["ip"]), 5)


class TestNetblockExpandLeavesATrace(unittest.IsolatedAsyncioTestCase):
    """少扫必须留痕 —— 否则界面上「没东西」与「没展开」无法区分。"""

    async def test_skipped_segments_are_reported_at_cleanup(self) -> None:
        """每个「只有 1 台证据」的段各记一条，收尾时汇总上报。"""
        m, out = build()
        for seg, host in (("93.184.216.1", "a"), ("93.185.1.1", "b")):
            await m.handle_event(resolved(seg, f"{host}.example.com"))
        self.assertEqual(out["finding"], [], "证据不足时不该当场吵")
        self.assertEqual(
            m._unexpanded, {"93.184.216.0/24", "93.185.1.0/24"},
        )
        await m.cleanup()
        self.assertEqual(out["finding"].count("netblock_expand_skipped"), 1)

    async def test_expanded_segments_are_not_reported_as_skipped(self) -> None:
        """已展开的段不该又出现在"没扫"清单里 —— 那会让人以为漏了。"""
        m, out = build()
        await m.handle_event(resolved("93.184.216.1", "a.example.com"))
        await m.handle_event(resolved("93.184.216.2", "b.example.com"))
        await m.cleanup()
        self.assertNotIn("netblock_expand_skipped", out["finding"])

    async def test_no_finding_when_nothing_was_considered(self) -> None:
        m, out = build()
        await m.cleanup()
        self.assertEqual(out["finding"], [], "什么都没遇到却报了一条")


if __name__ == "__main__":
    unittest.main()
