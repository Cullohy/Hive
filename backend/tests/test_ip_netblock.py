"""``ip.netblock`` 落库判据。

**为什么单独一个文件**：模块层那套（标签有没有带上）只能证明事件对不对，
证明不了"这一列真的写进 ip 行、而且没被后来的更新抹掉" —— 而后者正是
界面上区分「C 段扫出来的邻居」和「目标解析出来的 IP」的全部依据。
"""
from __future__ import annotations

import unittest

from core.engine.event import Event, EventType

from .pgutil import drop_storage, make_storage


def ip_event(addr: str, *, netblock: str | None = None,
             parent_domain: str | None = None) -> Event:
    """一条 IP_ADDRESS。

    ⚠️ **归属必须用 ``parent_data``，不能用 ``domain`` 标签。**
    存储层建 ``domain_ip`` 关联行读的是 ``event.parent_data``，而且要求那个
    域名行**已经存在**（由前面的 DNS_NAME 建出来）—— 这正是 ``dns_resolve``
    真实的产出形状。写成 ``tags={"domain": ...}`` 的话关联一行都不会建，
    测出来的是"归属证据 0"，看起来像功能坏了。
    """
    tags = {"netblock": netblock} if netblock else {}
    return Event(type=EventType.IP_ADDRESS, data=addr, module="t",
                  parent_data=parent_domain, tags=tags)


def dns_event(name: str) -> Event:
    return Event(type=EventType.DNS_NAME, data=name, module="dns_resolve")


class TestIpNetblockColumn(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _put(self, e: Event) -> int:
        sid = await self.storage.create_scan(targets=["a.com"], preset="t")
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        return sid

    async def _ip_row(self, addr: str):
        return await self.storage._fetchone(
            "SELECT * FROM ip WHERE addr = ?", (addr,)
        )

    # ---------------------------------------------------------------- 落库

    async def test_netblock_tag_lands_on_the_ip_row(self) -> None:
        """C 段扫出来的邻居在资产表里要**认得出来**。"""
        await self._put(ip_event("93.184.216.7", netblock="93.184.216.0/24"))
        self.assertEqual(
            (await self._ip_row("93.184.216.7"))["netblock"], "93.184.216.0/24"
        )

    async def test_address_without_the_tag_has_no_segment(self) -> None:
        """目标子域解析出来的 IP **不该**被标成 C 段来源。

        反了的话，界面上会把范围内的资产说成自动扩面出去的边角 ——
        那是把证据说反了，比没有这一列更糟。
        """
        await self._put(ip_event("93.184.216.9", parent_domain="www.a.com"))
        self.assertIsNone((await self._ip_row("93.184.216.9"))["netblock"])

    async def test_later_tagless_update_does_not_erase_it(self) -> None:
        """⚠️ **COALESCE 不是可选项。**

        同一个地址可能先被 C 段展开带出来（带标签），之后又被目标的某个
        子域解析到（**不带**标签）。直接赋值的话那第二次更新会把辛苦记下的
        段抹成 NULL —— 而且是**静默**的：界面上退回成"查不出这段是哪儿来的"，
        没有任何报错。
        """
        sid = await self._put(
            ip_event("93.184.216.7", netblock="93.184.216.0/24")
        )
        later = ip_event("93.184.216.7", parent_domain="www.a.com")  # 无 netblock
        await self.storage.save_event(sid, later)
        await self.storage.project(sid, later)

        self.assertEqual(
            (await self._ip_row("93.184.216.7"))["netblock"],
            "93.184.216.0/24",
            "后来的无标签更新把 C 段来源抹掉了 —— 界面上再也说不清它从哪来",
        )

    # ---------------------------------------------------------------- 聚合

    async def test_expanded_hosts_counts_only_expanded_addresses(self) -> None:
        """``expanded_hosts`` 只数**本段被 C 段扫出来**的那些。

        它和 ``owned_hosts`` 是两回事：前者是"我们自己扩面捞到的"，
        后者是"目标自己的域名指过来的"。混在一起就看不出这一段到底
        新发现了什么。
        """
        sid = await self.storage.create_scan(targets=["a.com"], preset="t")

        async def put(e: Event) -> None:
            await self.storage.save_event(sid, e)
            await self.storage.project(sid, e)

        # 目标自己的两个域名（先有 DNS_NAME 建出行，再有指向它的 IP）
        for dom, addr in (("www.a.com", "93.184.216.1"),
                          ("api.a.com", "93.184.216.2")):
            await put(dns_event(dom))
            await put(ip_event(addr, parent_domain=dom))
        # 同一段里被 C 段扫出来的两个邻居（没有任何域名）
        await put(ip_event("93.184.216.7", netblock="93.184.216.0/24"))
        await put(ip_event("93.184.216.8", netblock="93.184.216.0/24"))
        # 另一个段
        await put(ip_event("93.185.1.9", netblock="93.185.1.0/24"))

        segs = {r["cidr"]: r for r in await self.storage.netblocks(sid)}
        self.assertEqual(segs["93.184.216.0/24"]["owned_hosts"], 2)
        self.assertEqual(segs["93.184.216.0/24"]["expanded_hosts"], 2)
        self.assertEqual(segs["93.185.1.0/24"]["expanded_hosts"], 1)

    # ---------------------------------------------------------------- 可见性

    async def test_open_port_alone_makes_an_ip_live(self) -> None:
        """**有开放端口就算活**，哪怕一个 HTTP 响应都没有。

        C 段扫出来的邻居大半只开 25/110/143 这类端口（有的 443 开了但 TLS
        没握手成功），原口径要求"必须有 HTTP 响应" —— 实测扫描 #74 有 30 台
        这样的机器、19 台开着 80/443，IP 页签只显示 2 台。C 段扫描捞上来的
        东西在界面上等于不存在。
        """
        sid = await self.storage.create_scan(targets=["a.com"], preset="t")
        ip_ev = ip_event("111.47.224.11", netblock="111.47.224.0/24")
        await self.storage.save_event(sid, ip_ev)
        await self.storage.project(sid, ip_ev)
        # 一个开放端口，**不带**任何 HTTP 端点
        port = Event(
            type=EventType.OPEN_TCP_PORT, data="111.47.224.11:443",
            module="port_scan", tags={"ip": "111.47.224.11", "port": 443},
        )
        await self.storage.save_event(sid, port)
        await self.storage.project(sid, port)

        live = {str(r["addr"]) for r in await self.storage.ips(sid, live=True)}
        self.assertIn(
            "111.47.224.11", live,
            "只开了端口的 IP 被当成死的 —— C 段扫出来的机器全都不显示",
        )

    async def test_closed_host_stays_hidden(self) -> None:
        """**别把闸门拆了。** 没有任何观测的 IP 仍然不算活。"""
        sid = await self.storage.create_scan(targets=["a.com"], preset="t")
        e = ip_event("93.184.216.200", netblock="93.184.216.0/24")
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)

        live = {str(r["addr"]) for r in await self.storage.ips(sid, live=True)}
        self.assertNotIn("93.184.216.200", live)


if __name__ == "__main__":
    unittest.main()
