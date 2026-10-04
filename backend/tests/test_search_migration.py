"""跨 scan 去重迁移留下的三处读点：URL 端点归并、扫描已删的资产、资产组同步。

迁移把资产表变成了**全局实体**（一条资产一行，``scan_id`` 只剩下"谁最先发现的"
这层意思），"哪次扫描看到了什么"搬进了 ``scan_asset``。读点如果还按旧模型写，
**全都不报错，只是数不对**，所以这个文件把三处的行为逐条钉住：

1. ``_SEARCH_SPECS["urls"]`` 的展示连接 —— 状态列挂不上的**静默丢失**
   （实测 scan #19：886 条 live URL 只有 877 条有 status）
2. ``search_assets()`` 里的 ``JOIN scan`` —— 首个发现者那次扫描没了就整批隐藏，
   而且与不连 ``scan`` 的 ``search_counts`` 对不上（"命中 3 条、结果 0 条"）
3. ``sync_scan_to_group()`` —— 入组与清理都还在拿 ``scan_id`` 当扫描维度
   （重扫归集到 0 条；同步一次没探活的扫描会把整组域名删光）

每条测试的文档都写了"旧写法会怎么错"。其中 ① ② ③ 的回归用例都**真的会红**：
把实现换回旧写法即可复现（验证记录见提交说明）。
"""

from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.engine.event import Event, EventType  # noqa: E402
from core.storage.postgres import PostgresStorage  # noqa: E402

from .pgutil import (  # noqa: E402
    DSN,
    drop_storage,
    ensure_database,
    make_storage,
)
from .test_m5 import WebTestCase  # noqa: E402

#: 资产表上都挂着这个外键（``scan_id REFERENCES scan(id) ON DELETE CASCADE``）。
#:
#: 这是**产品语义本身**，不是遗留：任务是主，删扫描 = 删掉它带出的全部资产
#: （见 schema.sql 的「ON DELETE 语义」段）。下面那条测试要先把它摘掉，是为了
#: 人工造出"资产行在、scan 行不在"这个正常路径到不了的状态，单独验证查询层
#: 不会因此把资产藏起来。
_DOMAIN_SCAN_FK = "domain_scan_id_fkey"

HOST = "a.example.com"
URL = "http://a.example.com/"


def _domain_event(name: str = HOST) -> Event:
    return Event(EventType.DNS_NAME, name, module="test", tags={"source": "test"})


def _endpoint_event(url: str = URL, *, status: int = 200, **extra) -> Event:
    from core.util.asset_key import split_url

    scheme, host, _path = split_url(url)
    tags = {
        "url": url, "domain": host, "ip": "1.1.1.1", "port": 80,
        "scheme": scheme, "status": status,
    }
    tags.update(extra)
    return Event(EventType.HTTP_RESPONSE, url, module="http_probe", tags=tags)


class _RealDatabase(unittest.IsolatedAsyncioTestCase):
    """一个测试一个隔离 schema（与 ``test_storage.TestRealDatabase`` 同款）。"""

    async def asyncSetUp(self) -> None:
        await ensure_database()
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _scan(self, targets: list[str] | None = None) -> int:
        return await self.storage.create_scan(
            targets=targets or ["example.com"], preset="t"
        )

    async def _project(self, scan_id: int, *events: Event) -> None:
        for event in events:
            await self.storage.project(scan_id, event)


# ─────────────────────────────────────────── ① URL 与端点的展示连接


class TestSearchUrlEndpointJoin(_RealDatabase):
    """URL 搜索里 status / title / server 的挂载规则。

    旧写法 ``ON e.scan_id = t.scan_id AND e.url = t.url`` 同时要求两件不该要求
    的事：① 端点与 URL 的**首个发现者**是同一次扫描（迁移后这两个数不相干）；
    ② 两边的 URL 字符串一模一样（http 与 https 是两行端点，url 表只有一行）。
    结果是**静默**漏挂：字段为 NULL，页面上就是"未探活"。
    """

    async def test_status_attaches_when_another_scan_first_found_the_url(self) -> None:
        """URL 先被 A 发现、后被 B 探活 —— 状态仍然要挂上。

        这是线上那 9 条的成因：``url`` 行挂在 A 名下（谁先发现），``http_endpoint``
        行挂在 B 名下，旧写法比 ``e.scan_id = t.scan_id`` 比不过 → status 为 NULL。
        """
        scan_a = await self._scan()
        scan_b = await self._scan()
        await self._project(scan_a, Event(
            EventType.URL, "http://a.example.com/admin", module="url_extract",
            tags={"domain": HOST},
        ))
        await self._project(scan_b, _endpoint_event(
            "http://a.example.com/admin", status=200, title="后台", server="nginx",
        ))

        rows = (await self.storage.search_assets(
            "a.example.com", types=["urls"], live=False
        ))["urls"]
        self.assertEqual(len(rows), 1, "URL 只有一行（url 表按身份去重）")
        self.assertEqual(rows[0]["status"], 200, "端点是被另一次扫描探测的，状态没挂上")
        self.assertEqual(rows[0]["title"], "后台")
        self.assertEqual(rows[0]["server"], "nginx")

        # 计数语句**不连 scan**，两边必须一致（旧写法在这里会给出 1 条命中、
        # 但 title 搜索时结果为空 —— "命中 N、显示 0"就是这么来的）
        totals = await self.storage.search_counts(
            "a.example.com", types=["urls"], live=False
        )
        self.assertEqual(totals["urls"], len(rows))

    async def test_one_row_per_url_and_the_newest_observation_wins(self) -> None:
        """同一 ``authority|path`` 的 http/https 是两行端点 —— 只能挑一行出来。

        ★ 不能退化成等值连接：那样 886 行会变成 1312 行（结果集重复）。
        ★ 挑哪一行有明确规则：**最近一次观测优先**（资产行是"当前值"），
          同秒再让 https 优先、最后用 dedup_key 兜底（顺序稳定）。
        """
        from core.util.asset_key import endpoint_key

        scan_id = await self._scan()
        # url 表一行（不带 scheme 的身份）；端点两行（带 scheme）
        await self._project(scan_id, Event(
            EventType.URL, "https://a.example.com/x", module="url_extract",
            tags={"domain": HOST},
        ))
        await self._project(scan_id, _endpoint_event("http://a.example.com/x", status=500))
        await self._project(scan_id, _endpoint_event("https://a.example.com/x", status=200))
        # 把 https 那行的观测时间改早 —— 于是"最近观测"应该是那条 http
        # （注意 dedup_key 的形状是 ``scheme://authority|path``，不是 URL 字符串）
        await self.storage.conn.execute(
            "UPDATE http_endpoint SET last_seen = ? WHERE dedup_key = ?",
            ("2000-01-01T00:00:00+00:00", endpoint_key("https://a.example.com/x")),
        )

        rows = (await self.storage.search_assets(
            "a.example.com", types=["urls"], live=False
        ))["urls"]
        self.assertEqual(len(rows), 1, "一对多的连接会把同一行 URL 返回多次")
        self.assertEqual(rows[0]["status"], 500, "没有按'最近观测'挑端点")

    async def test_tie_breaks_towards_https(self) -> None:
        """同一秒内探到的 http / https：取 https（url 表留下的就是它那个形态）。

        ``last_seen`` 精确到秒，一次扫描里 http 与 https 同秒是常态，所以这条
        平局规则不是理论问题。
        """
        scan_id = await self._scan()
        await self._project(scan_id, Event(
            EventType.URL, "https://a.example.com/y", module="url_extract",
            tags={"domain": HOST},
        ))
        await self._project(scan_id, _endpoint_event("http://a.example.com/y", status=500))
        await self._project(scan_id, _endpoint_event("https://a.example.com/y", status=200))

        rows = (await self.storage.search_assets(
            "a.example.com", types=["urls"], live=False
        ))["urls"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], 200, "平局时没有优先 https")


# ─────────────────────────────────────────── ② 首个发现者那次扫描没了


class TestSearchSurvivesDeletedFirstDiscoverer(_RealDatabase):
    """资产行还在、但 ``scan`` 行没了时，搜索**不能**把它藏起来。

    ## 这条测试现在测的是什么

    产品语义是**任务为王**：删扫描 = 删掉它带出的全部资产
    （见 ``schema.sql`` 的「ON DELETE 语义」段与
    ``PostgresStorage.delete_scan``）。所以"删掉首个发现者那次扫描、资产
    还在"这个状态**正常路径下到不了** —— ``delete_scan`` 会把两者一起删。

    留这条是为了钉住**查询层**的性质：万一将来出现"资产行在、scan 行不在"
    的数据（手工改库、从旧备份导入、``ON DELETE SET NULL`` 化），
    ``search_assets`` 也不能因为 LEFT JOIN 拿不到 scan 行就把资产藏起来 ——
    那是静默丢数据。

    ## ⚠️ 这条测试为什么先摘外键

    资产表上的 ``scan_id`` 外键是 ``ON DELETE CASCADE``，正常删扫描时资产会
    跟着没，压根到不了这里要测的状态。所以先 ``DROP CONSTRAINT`` 人工造出
    那个状态，再断言搜索行为。**这也是它当年被写出来的原因** —— 那时文档
    写的是"资产本身留着"，与外键矛盾（见 git 历史）；现在文档已改成"任务为
    王"，矛盾消除，但查询层这条性质仍然值得钉住。
    """

    async def test_asset_is_still_searchable_after_its_scan_is_deleted(self) -> None:
        scan_id = await self._scan(["gone.example.com"])
        await self._project(scan_id, _domain_event("gone.example.com"))
        self.assertEqual(
            len((await self.storage.search_assets(
                "gone", types=["domains"], live=False
            ))["domains"]),
            1,
            "前提：扫描还在时这条资产本来搜得到",
        )

        await self.storage.conn.execute(
            f"ALTER TABLE domain DROP CONSTRAINT IF EXISTS {_DOMAIN_SCAN_FK}"
        )
        self.assertTrue(await self.storage.delete_scan(scan_id))

        rows = (await self.storage.search_assets(
            "gone", types=["domains"], live=False
        ))["domains"]
        self.assertEqual(
            len(rows), 1,
            "首个发现者那次扫描没了，资产就从搜索里消失了（左侧是内连接）",
        )
        # 三个取自 scan 的展示字段：扫描行没了就给空值（接口层把 targets 转成 []）
        self.assertIsNone(rows[0]["scan_targets"])
        self.assertIsNone(rows[0]["scan_preset"])
        self.assertIsNone(rows[0]["scan_started_at"])
        # 但 t.scan_id 本身仍然是"最初是哪次扫到的"（它不依赖 scan 行在不在）
        self.assertEqual(int(rows[0]["scan_id"]), scan_id)

        # 计数与结果必须一致：计数语句根本不连 scan
        totals = await self.storage.search_counts(
            "gone", types=["domains"], live=False
        )
        self.assertEqual(totals["domains"], len(rows))


class TestSearchApiKeepsAssetsOfDeletedScans(WebTestCase):
    """接口层的同一条：扫描行没了，``scan_targets`` 要降级成 ``[]`` 而不是 500。

    前端对这三个字段是直接消费的（``#{{ record.scan_id }} · {{ (record.scan_targets
    || []).join(', ') }}``），所以"缺了什么显示什么"必须在接口层定死。
    """

    async def _seed(self) -> int:
        """独立连接往同一个 schema 里种"一次扫描 + 一个域名"。

        （不能走 ``self.client.app.state.storage``：那条连接活在 TestClient 自己的
        事件循环里，``asyncio.run()`` 在新循环里用它会被 asyncpg 拒掉。）
        """
        store = PostgresStorage(DSN, schema=self.schema, create_search_index=False)
        await store.open()
        try:
            scan_id = await store.create_scan(targets=["gone.example.com"], preset="t")
            await store.project(scan_id, _domain_event("gone.example.com"))
            # 见 TestSearchSurvivesDeletedFirstDiscoverer：先摘掉那个与迁移文档
            # 矛盾的外键，才能到达"资产行留着、扫描行没了"的状态。
            await store.conn.execute(
                f"ALTER TABLE domain DROP CONSTRAINT IF EXISTS {_DOMAIN_SCAN_FK}"
            )
            return scan_id
        finally:
            await store.close()

    def test_deleted_scan_assets_are_still_returned(self) -> None:
        scan_id = asyncio.run(self._seed())
        resp = self.client.delete(f"/api/scans/{scan_id}", headers=self.h())
        self.assertEqual(resp.status_code, 200, resp.text)

        data = self.client.get(
            "/api/search",
            params={"q": "gone", "type": "domains", "live": "false"},
            headers=self.h(),
        ).json()
        rows = data["results"]["domains"]
        self.assertEqual(len(rows), 1, data)
        self.assertEqual(rows[0]["scan_targets"], [], "scan_targets 该是空列表")
        self.assertEqual(int(rows[0]["scan_id"]), scan_id)
        self.assertEqual(data["totals"]["domains"], len(rows))


# ─────────────────────────────────────────── ③ 资产组同步


class TestGroupSyncAfterMigration(_RealDatabase):
    """``sync_scan_to_group``：入组按"这次扫描看到的"，清理按资产级失效。

    分组是**跨扫描累积**的（``schema.sql``：「ARL 的资产分组核心价值恰恰是"看这次
    监控多发现了什么"」；界面：「只把这次扫描『新发现』的资产记进来，已在组里的
    不会重复计」）。旧写法两头都错：

    * 入组用 ``d.scan_id = ?`` ⇒ 重扫同一目标时**一条都匹配不到**（资产行还挂在
      第一次名下），界面提示"已同步：新增域名 0 · IP 0"；
    * 清理用"这次扫描的存活集合之外全删" ⇒ 子查询为空时 ``NOT IN (空)`` 恒真，
      **把整组域名删光**（同步一次没跑 http_probe 的扫描就会发生）。
    """

    async def _scan_with(self, *, probe: bool, name: str = HOST) -> int:
        """一次"发现 name（可选：探活它）"的扫描。"""
        scan_id = await self._scan(["example.com"])
        events = [_domain_event(name)]
        if probe:
            events.append(_endpoint_event())
        await self._project(scan_id, *events)
        return scan_id

    async def _keys(self, group_id: int, asset_type: str = "domain") -> set[str]:
        data = await self.storage.list_group_assets(
            group_id, asset_type=asset_type, limit=500
        )
        return {row["asset_key"] for row in data["rows"]}

    async def test_rescan_adds_what_it_saw(self) -> None:
        """重扫（这次也探活了）必须能把它看到的资产归集进组。

        旧写法下：域名行与端点行的 ``scan_id`` 都还是**第一次**那次扫描，
        ``d.scan_id = 第二次`` 匹配 0 行 —— 于是"同步这次扫描"什么都没同步。
        """
        first = await self._scan_with(probe=True)
        second = await self._scan_with(probe=True)
        row = await self.storage._fetchone(
            "SELECT scan_id FROM domain WHERE name = ?", (HOST,)
        )
        self.assertEqual(int(row["scan_id"]), first, "前提：资产行挂在第一次名下")

        group = await self.storage.create_group(name="重扫", scopes=["example.com"])
        added = await self.storage.sync_scan_to_group(group, second)
        self.assertEqual(added["domain"], 1, "重扫看到的域名没被归集进组")
        self.assertIn(HOST, await self._keys(group))

        # 幂等：同一扫描再同步一次不重复计
        again = await self.storage.sync_scan_to_group(group, second)
        self.assertEqual(again["domain"], 0)

    async def test_ip_scope_branch_uses_this_scan(self) -> None:
        """网段范围那条分支同样按"**这次扫描看到的 IP**"入组。

        它以前写的是 ``i.scan_id = ?``，重扫时同样匹配 0 行；现在走
        ``scan_asset(ip)`` + ``se.scan_id = sa.scan_id``（只吃一个参数）。
        """
        async def ip_scan() -> int:
            sid = await self._scan(["203.0.113.0/24"])
            await self._project(sid, Event(
                EventType.IP_ADDRESS, "203.0.113.9", module="test", tags={},
            ))
            await self._project(sid, Event(
                EventType.OPEN_TCP_PORT, "203.0.113.9:80", module="test",
                tags={"ip": "203.0.113.9", "port": 80},
            ))
            return sid

        first = await ip_scan()
        rescan = await ip_scan()
        row = await self.storage._fetchone(
            "SELECT scan_id FROM ip WHERE addr = ?", ("203.0.113.9",)
        )
        self.assertEqual(int(row["scan_id"]), first, "前提：IP 行挂在第一次名下")

        group = await self.storage.create_group(name="网段", scopes=["203.0.113.0/24"])
        added = await self.storage.sync_scan_to_group(group, rescan)
        self.assertEqual(added["ip"], 1, "重扫看到的 IP 没被归集进组")
        self.assertEqual(await self._keys(group, asset_type="ip"), {"203.0.113.9"})

    async def test_sync_without_http_probe_does_not_wipe_the_group(self) -> None:
        """同步一次**没跑 http_probe** 的扫描，不能把组里已有的域名删光。

        这正是线上 scan #20 那种扫描（``default`` 预设）：它自己的
        ``scan_asset`` 里一个 http_endpoint 都没有，于是旧写法的清理子查询为空、
        ``NOT IN (空)`` 恒真 —— 一次同步就把组清空。
        """
        probed = await self._scan_with(probe=True)
        bare = await self._scan_with(probe=False)

        group = await self.storage.create_group(name="裸扫", scopes=["example.com"])
        await self.storage.sync_scan_to_group(group, probed)
        self.assertIn(HOST, await self._keys(group))

        await self.storage.sync_scan_to_group(group, bare)
        self.assertIn(
            HOST, await self._keys(group),
            "同步一次没探活的扫描，把组里已有的域名删光了",
        )

    async def test_dead_assets_are_still_pruned(self) -> None:
        """改口径之后清理**不能失效**：库里没有端点记录的组内域名要被删掉。

        （这条在旧写法下也通过 —— 它是防止"改过头"的护栏，不是回归复现。
        新旧口径的差别只在"**什么时候**删"：资产级失效 vs 这次扫描没看到。）
        """
        group = await self.storage.create_group(name="清理", scopes=["example.com"])
        await self.storage.conn.execute(
            "INSERT INTO asset_group_asset "
            "(group_id, asset_type, asset_key, first_seen, last_seen) "
            "VALUES (?, 'domain', ?, ?, ?)",
            (group, "dead.example.com", "2020-01-01T00:00:00+00:00",
             "2020-01-01T00:00:00+00:00"),
        )
        probed = await self._scan_with(probe=True)
        self.assertIn("dead.example.com", await self._keys(group))

        await self.storage.sync_scan_to_group(group, probed)
        self.assertNotIn(
            "dead.example.com", await self._keys(group),
            "库里已经没有端点记录的域名没被清理",
        )


if __name__ == "__main__":
    unittest.main()
