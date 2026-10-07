"""seed_asset 的网段枚举 —— **单元层**，不走完整扫描。

## 为什么单独拆出来

``TestSeedAsset`` 里那条 ``10.0.0.0/8`` 原本是走完整 ``Scanner.scan()`` 的：
1024 个 IP_ADDRESS 事件进总线，每个都要落库、投影、走 ``key()`` 去重 ——
单这一条就把整类测试拖到 **900 秒以上**，最后把变异验证本身都跑到超时。

所以「大网段截断」「IPv6 网段拒绝」这两条改在这里：直接调 ``handle_event``，
``emit_event`` 换成收集器。断言的是**同一份代码**，只是不付那 1000 个事件的代价。
"""
from __future__ import annotations

import asyncio
import unittest

from core.domains.subdomain.standalone.seed_asset import seed_asset
from core.engine.event import Event, EventType


class _Log:
    def __getattr__(self, _):
        return lambda *a, **k: None


class _Scanner:
    targets = ["example.com"]
    settings: dict = {}

    def root_domain_of(self, d):
        return None


def build(max_hosts: int = 1024):
    m = seed_asset.__new__(seed_asset)
    m.config = {"max_hosts": max_hosts}
    m.name = "seed_asset"
    m._engine = _Scanner()
    m.log = _Log()
    m.stats = {}
    m.max_hosts = max_hosts
    out = {"ip": [], "finding": []}

    async def emit_event(data, etype, *, parent=None, tags=None):
        if etype == EventType.IP_ADDRESS:
            out["ip"].append(str(data))

    async def emit_finding(kind, detail, *, parent=None, severity="info",
                           target=None):
        out["finding"].append(kind)

    m.emit_event = emit_event
    m.emit_finding = emit_finding
    return m, out


def seed_event(seed: str) -> Event:
    return Event(type=EventType.SEED, data=seed, module="engine")


class TestSeedNetblockUnit(unittest.IsolatedAsyncioTestCase):
    """网段枚举的边界：截断上限、IPv6 拒绝、网络号/广播。"""

    async def test_netblock_emits_one_ip_per_host(self) -> None:
        m, out = build()
        await m.handle_event(seed_event("93.184.216.0/29"))
        self.assertEqual(
            sorted(out["ip"]),
            [f"93.184.216.{i}" for i in range(1, 7)],
            f"/29 应产出 .1~.6: {sorted(out['ip'])}",
        )

    async def test_network_and_broadcast_are_not_emitted(self) -> None:
        """``.0`` / ``.255`` 不是主机。

        2026-10-07 之前 CIDR 被当成裸 IP 时，扫的正是 ``.0``，还在 domain 表里
        造出一条 IP 冒充域名的垃圾行。

        真正跳过它们的是 ``ipaddress`` 的 ``hosts()``（``/30`` 及更短会跳过网络号
        与广播），不是我们自己那行 ``total -= 2`` —— 后者只影响日志里的计数。
        """
        m, out = build()
        await m.handle_event(seed_event("93.184.216.0/24"))
        self.assertNotIn("93.184.216.0", out["ip"], "网络地址被扫了")
        self.assertNotIn("93.184.216.255", out["ip"], "广播地址被扫了")
        self.assertIn("93.184.216.1", out["ip"])
        self.assertEqual(len(out["ip"]), 254)

    async def test_oversized_netblock_is_truncated_with_a_finding(self) -> None:
        """**超限必须留痕。**

        不封顶的话 ``10.0.0.0/8`` 会产出 1677 万个 IP_ADDRESS，每一个都会去跑
        端口扫描 —— 那是实打实的对外流量。静默少扫又违反本项目「宁可多探，不要
        漏掉」的原则，所以截断与留痕必须同时有。

        ⚠️ ``wait_for`` 不是可有可无的装饰，是**变异验证的保险丝**：
        去掉那个 ``break`` 的变异会让本用例去迭代 1677 万个地址、往列表里塞
        1GB 以上的字符串，直接把整轮测试拖到超时 —— 于是「测试抓不住」和
        「环境太慢」又长得一模一样。套上 ``wait_for``，那次变异会在 30 秒
        处干净地失败，而不是把进程拖垮。
        """
        m, out = build(max_hosts=1024)
        await asyncio.wait_for(
            m.handle_event(seed_event("10.0.0.0/8")), timeout=30
        )
        self.assertEqual(len(out["ip"]), 1024, f"没按上限截断：{len(out['ip'])} 个")
        self.assertIn(
            "netblock_truncated", out["finding"],
            "截断了却没有发 finding —— 用户会以为整段都扫过了",
        )

    async def test_small_netblock_does_not_warn(self) -> None:
        m, out = build()
        await m.handle_event(seed_event("93.184.216.0/28"))
        self.assertNotIn(
            "netblock_truncated", out["finding"],
            "没截断却报了截断 —— 告警噪声",
        )

    async def test_ipv6_netblock_is_rejected(self) -> None:
        """IPv6 网段直接拒掉，**不能卡死**。

        ``2001:db8::/32`` 的地址数是 2^96：``list(net.hosts())`` 会去物化整个
        网段，实测**直接把进程卡死**。就算改成切片，扫 1024 个 IPv6 地址也没有
        产出（地址空间稀疏、几乎必然全不响应），只是白花流量。
        """
        m, out = build()
        await asyncio.wait_for(
            m.handle_event(seed_event("2001:db8::/32")), timeout=10
        )
        self.assertEqual(out["ip"], [], "IPv6 网段被当主机枚举了")
        self.assertIn(
            "netblock_unsupported", out["finding"],
            "IPv6 网段被拒却没有留痕 —— 调用方以为整段扫过了",
        )

    async def test_slash32_is_treated_as_a_netblock(self) -> None:
        """``1.2.3.4/32`` 是网段形态（等价于一个主机），走网段分支产出它自己。"""
        m, out = build()
        await m.handle_event(seed_event("1.2.3.4/32"))
        self.assertEqual(out["ip"], ["1.2.3.4"])


if __name__ == "__main__":
    unittest.main()
