"""关联行快照：变更监控的地基（``scan_asset.snapshot_json``）。

## 为什么需要这层

资产是**全局唯一的可变行**，重新扫描会覆盖它的字段。于是"扫描 A 时 org 是
OldOrg、扫描 B 时是 NewOrg"这件事**在资产表里查不到** —— 两次读的是同一行。

全局唯一的实体没有历史，历史只能存在**关联行**上。这个文件钉的就是它。

（这个坑是迁移过程中 `test_m6.TestDiff` 挂掉时暴露的：差异恒为空。
设计文档 §9.2 有完整记录。）
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.services.diff import SPECS, diff_scans  # noqa: E402
from core.storage.postgres import _SNAPSHOT_SQL  # noqa: E402

from .base import EngineTestCase  # noqa: E402
from .pgutil import drop_storage, make_storage  # noqa: E402
# ``WebTestCase``（TestClient + 独立 schema + 离线预设）本来在 tests/test_m5.py 里；
# 资产接口的这条回归测试要有 HTTP 面，所以从这里借基类。
from .test_m5 import WebTestCase  # noqa: E402


def _select_columns(sql: str) -> set[str]:
    """把 ``SELECT a, b, c FROM ...`` 的列名抠出来。"""
    body = re.split(r"\bFROM\b", sql, maxsplit=1, flags=re.I)[0]
    body = re.sub(r"^\s*SELECT\s+", "", body, flags=re.I)
    return {c.strip() for c in body.split(",") if c.strip()}


class TestSnapshotCoversSpecs(unittest.TestCase):
    """⚠️ **防漂移**：``diff.py`` 的 SPECS 需要的字段，``_SNAPSHOT_SQL`` 必须都取到。

    这两个列表在两个模块里（一个读、一个写），**没有任何类型系统能保证它们
    一致**。漏一个字段的后果是：那一列的变更**静默地检测不到** —— diff 照常
    返回结果，只是永远说"没变化"。所以必须机械地钉住。
    """

    def test_every_spec_field_is_in_the_snapshot(self) -> None:
        problems: list[str] = []
        for spec in SPECS:
            if spec.snapshot_type is None:
                continue  # 观测层的表不读快照
            sql = _SNAPSHOT_SQL.get(spec.snapshot_type)
            if sql is None:
                problems.append(f"{spec.key}: _SNAPSHOT_SQL 里没有 {spec.snapshot_type!r}")
                continue
            have = _select_columns(sql)
            # ⚠️ 有 ``transform`` 时 ``value_fields`` 是**转换后的输出名**，不是
            # 行里的列（见 ``_port_transform``：它把 cert_json 拆成 cert_cn /
            # cert_days_left）。所以要检查的是转换的**输入**，而那个只能单独钉
            # ——见下面那条 ``test_port_transform_input_is_in_the_snapshot``。
            #
            # （第一版没区分这一点，于是这条测试对着 ports 报了"缺 cert_cn"，
            #   而那是它自己的误报。）
            need = set(spec.key_fields)
            if spec.transform is None:
                need |= set(spec.value_fields)
            missing = need - have
            if missing:
                problems.append(f"{spec.key}: 快照缺 {sorted(missing)}")
        self.assertEqual(problems, [], "SPECS 与快照列漂移了:\n  " + "\n  ".join(problems))

    def test_port_transform_input_is_in_the_snapshot(self) -> None:
        """端口的 ``cert_cn`` / ``cert_days_left`` 是从 ``cert_json`` 里抽的。

        它不在 SPECS 的 ``value_fields`` 里（那两项是 transform 的**输出**），
        所以上面那条通用检查覆盖不到它 —— 单独钉一条。
        """
        self.assertIn("cert_json", _select_columns(_SNAPSHOT_SQL["port"]))

    def test_snapshot_never_pulls_blobs(self) -> None:
        """**`SELECT *` 会把截图二进制塞进快照。**

        ``http_endpoint`` 有 ``screenshot_data BYTEA`` —— 每行关联都带一份整张
        截图的 JSON，关联表会迅速膨胀。所以列必须是显式列出的。
        """
        for asset_type, sql in _SNAPSHOT_SQL.items():
            with self.subTest(asset_type=asset_type):
                self.assertNotIn("*", sql, f"{asset_type} 的快照用了 SELECT *")
                self.assertNotIn("screenshot", sql, f"{asset_type} 的快照带了截图")

    def test_every_asset_type_has_a_snapshot_query(self) -> None:
        for spec in SPECS:
            if spec.snapshot_type is not None:
                self.assertIn(spec.snapshot_type, _SNAPSHOT_SQL)


class TestAssetCountsAfterMigration(EngineTestCase):
    """``asset_counts()`` 必须和 ``summary()`` 用**同一套**跨 scan 语义。

    ## 这条是补一个漏网之鱼

    跨 scan 去重迁移时改了 ``summary()``（改成数 ``scan_asset``），
    却**漏了** ``asset_counts()`` —— 它还在用 ``domain.scan_id = ?``。

    后果链很深，而且全程不报错：

    1. 引擎在扫描结束时调 ``asset_counts(live=True)`` 写回 ``stats_json``
    2. 重扫同一目标时那个查询数出 **0**（``scan_id`` 现在只是"谁最先发现的"）
    3. 错的值被**冻结进库**，任务列表和详情页从此都显示 0
    4. 而资产接口按 ``scan_asset`` 数是对的 —— 于是"页面上有 127 个、
       卡片上写 0"

    所以这条测试**比较两个函数的输出**，而不是各自断言一个写死的数 ——
    它们分头演化正是这个 bug 的成因。
    """

    async def test_counts_match_summary_for_a_second_scan(self) -> None:
        """重扫同一目标：第二次扫描的计数不能是 0。"""
        first, _ = await self.run_scan(targets=["example.com"], include=["leaky"])
        # 再来一次：资产行已存在，`domain.scan_id` 会指向**第一次**
        second, _ = await self.run_scan(targets=["example.com"], include=["leaky"])

        for scan_id in (first.scan_id, second.scan_id):
            counts = await self.storage.asset_counts(scan_id)
            summary = await self.storage.summary(scan_id)
            with self.subTest(scan_id=scan_id):
                self.assertEqual(
                    counts["domains"], summary["domains"],
                    f"#{scan_id}: asset_counts 与 summary 不一致",
                )
                self.assertEqual(counts["urls"], summary["urls"])

        # 最关键的一条：重扫的计数**不能**因为"scan_id 不是本次"而归零
        second_counts = await self.storage.asset_counts(second.scan_id)
        first_counts = await self.storage.asset_counts(first.scan_id)
        self.assertEqual(
            second_counts["domains"], first_counts["domains"],
            "重扫同一目标时资产数归零了 —— asset_counts 又在数 domain.scan_id",
        )

    async def test_live_is_a_subset_of_all(self) -> None:
        """``live=True`` 是 ``live=False`` 的子集 —— 探活过滤不该列出更多。"""
        record, _ = await self.run_scan(targets=["example.com"], include=["leaky"])
        all_counts = await self.storage.asset_counts(record.scan_id, live=False)
        live_counts = await self.storage.asset_counts(record.scan_id, live=True)
        self.assertLessEqual(live_counts["domains"], all_counts["domains"])
        self.assertLessEqual(live_counts["urls"], all_counts["urls"])

    async def test_by_scan_matches_per_scan(self) -> None:
        """列表用的批量查询要和逐个查询给出一样的数。"""
        record, _ = await self.run_scan(targets=["example.com"], include=["leaky"])
        batched = await self.storage.asset_counts_by_scan()
        single = await self.storage.asset_counts(record.scan_id)
        self.assertEqual(batched.get(record.scan_id, {}).get("domains"), single["domains"])
        self.assertEqual(batched.get(record.scan_id, {}).get("urls"), single["urls"])


class TestAssetsEndpointLiveFilter(WebTestCase):
    """``GET /api/scans/{id}/assets?live=true`` 的存活过滤。

    ## 为什么补的是**接口**这一侧

    上面那组钉的是 ``asset_counts()``。但那不是页面读的东西 —— 页面读的是
    ``/assets``，而它走的是 ``domains()/ips()/ports()/urls()`` 那条路。
    两处口径**分头演化过一次**（迁移时 ``asset_counts()`` 改了、"存活过滤"
    没改），所以只测其中一处正好漏掉报警的那一处。

    ## 语义

    "这次扫描里探活过" = 这次扫描的 ``scan_asset`` 里出现过对应的
    ``http_endpoint``。**不是**"这个资产在别的扫描里被探活过"—— 后者会让一个
    没跑 http_probe 的扫描列出别的扫描探到的域名（实测 scan #20 因此从
    scan #10 借来 12 个域名，正确答案是 0）。

    离线预设只跑 ``demo_expand``（不发 HTTP_RESPONSE），所以：
    ``live=true`` 必须是空，``live=false`` 仍要列出全部域名 ——
    "没有端点"不等于"没有资产"。
    """

    def test_live_is_empty_without_http_endpoints(self) -> None:
        """这条扫描自己没有任何端点观测 ⇒ 存活视图为空。"""
        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)

        live = self.client.get(
            f"/api/scans/{scan_id}/assets?live=true"
        ).json()
        self.assertTrue(live["live"])
        self.assertEqual(live["domains"], [], "没跑 http_probe，存活视图不该有域名")
        self.assertEqual(live["ips"], [])
        self.assertEqual(live["ports"], [])
        self.assertEqual(live["urls"], [])
        self.assertEqual(live["summary"]["domains_live"], 0)

        # live=false 拿到的才是原始资产投影（5 个域名），live 必须是它的子集
        every = self.client.get(
            f"/api/scans/{scan_id}/assets?live=false"
        ).json()
        self.assertEqual(len(every["domains"]), 5)
        self.assertEqual(every["summary"]["domains"], 5)
        self.assertLessEqual(len(live["domains"]), len(every["domains"]))

    def test_live_does_not_borrow_endpoints_from_another_scan(self) -> None:
        """**回归**：重扫同一目标时，存活视图不能拿上一次扫描的端点充数。

        场景与线上那条 bug 一模一样：库里已经有一次**探过活**的扫描
        （端点行属于它），接着用**不带 http_probe** 的预设重扫同一目标。
        第二次扫描自己的 ``scan_asset`` 里一个 http_endpoint 都没有，所以
        ``live=true`` 必须是空。

        修复前这里是 1：存活条件写成了"这个域名在**某处**有端点"
        （或"端点与域名的首个发现者是同一次扫描"），于是第二次扫描白捡了
        第一次的端点。这两种写法都不报错，只是把数字变大 —— 正是这类 bug
        能活下来的原因。
        """
        asyncio.run(self._seed_a_probed_scan())

        scan_id = self.start(["example.com"])["scan_id"]
        self.wait_done(scan_id)

        live = self.client.get(
            f"/api/scans/{scan_id}/assets?live=true"
        ).json()
        every = self.client.get(
            f"/api/scans/{scan_id}/assets?live=false"
        ).json()

        # 域名行是全局唯一的：第二次扫描看到的是**同一批**域名行
        self.assertEqual(len(every["domains"]), 5, every["domains"])
        self.assertEqual(
            live["domains"], [],
            f"重扫时借用了别的扫描的端点：{[d['name'] for d in live['domains']]}",
        )
        self.assertEqual(live["summary"]["domains_live"], 0)
        self.assertLessEqual(live["summary"]["domains_live"], every["summary"]["domains"])

    async def _seed_a_probed_scan(self) -> int:
        """用**独立连接**往同一个 schema 里种一次"探过活"的扫描。

        复用 ``tests/test_m5.py::TestScreenshotRoute._seed`` 的做法：不能走
        ``self.client.app.state.storage``（那条连接活在 TestClient 自己的事件
        循环里，``asyncio.run()`` 在新循环里用它会被 asyncpg 拒掉）。
        独立连接写的是同一个 schema，app 下次请求就读得到。
        """
        from core.engine.event import Event, EventType
        from core.storage.postgres import PostgresStorage

        from .pgutil import DSN

        store = PostgresStorage(DSN, schema=self.schema, create_search_index=False)
        await store.open()
        try:
            scan_id = await store.create_scan(targets=["example.com"], preset="t")
            for event in (
                Event(EventType.DNS_NAME, "www.example.com", module="t",
                      tags={"source": "brute"}),
                Event(EventType.HTTP_RESPONSE, "http://www.example.com/", module="t",
                      tags={"url": "http://www.example.com/",
                            "domain": "www.example.com", "ip": "1.1.1.1",
                            "port": 80, "scheme": "http", "status": 200,
                            "title": "T"}),
            ):
                await store.save_event(scan_id, event)
                await store.project(scan_id, event)
            return scan_id
        finally:
            await store.close()


class TestSnapshotProjection(EngineTestCase):
    """跑真扫描，验证快照确实写进去了、而且**保留了历史**。"""

    async def _scan_with_ip_org(self, org: str) -> int:
        """跑一次"发现一个 IP"的扫描。"""
        from core.engine.event import Event, EventType

        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["demo_expand"]
        )
        await self.storage.project(scanner.scan_id, Event(
            type=EventType.IP_ADDRESS, data="1.1.1.1", module="test",
            tags={"asn": "AS1", "org": org},
        ))
        return scanner.scan_id

    async def test_snapshot_is_written(self) -> None:
        sid = await self._scan_with_ip_org("OldOrg")
        snaps = await self.storage.asset_snapshots(sid, "ip")
        self.assertEqual(len(snaps), 1, f"没写快照: {snaps}")
        self.assertEqual(snaps[0]["addr"], "1.1.1.1")
        self.assertEqual(snaps[0]["org"], "OldOrg")

    async def test_snapshot_preserves_history_across_scans(self) -> None:
        """**这条是整个快照机制存在的理由。**

        两次扫描之间 IP 归属变了。资产表里只有一行、值已经被覆盖成 NewOrg；
        但**每次扫描的快照各自留住了当时的值**，所以变更监控能看出差异。
        """
        old = await self._scan_with_ip_org("OldOrg")
        new = await self._scan_with_ip_org("NewOrg")

        old_snaps = await self.storage.asset_snapshots(old, "ip")
        new_snaps = await self.storage.asset_snapshots(new, "ip")
        self.assertEqual(old_snaps[0]["org"], "OldOrg", "旧扫描的快照被新扫描覆盖了")
        self.assertEqual(new_snaps[0]["org"], "NewOrg")

        # 而资产表只有一行，值是当前值 —— 这正是"读资产表看不出变化"的原因
        ips = await self.storage.ips(old)
        self.assertEqual(len(ips), 1, "IP 应该全局只有一行")
        self.assertEqual(ips[0]["org"], "NewOrg", "资产表里就该是当前值")

    async def test_diff_sees_the_change(self) -> None:
        """端到端：`diff_scans` 能报出归属变化。"""
        old = await self._scan_with_ip_org("OldOrg")
        new = await self._scan_with_ip_org("NewOrg")
        changes = await diff_scans(self.storage, new, old)

        ip_change = changes.changed.get("ips", [])
        self.assertEqual(len(ip_change), 1, f"没检测到 IP 变化: {changes.to_dict()}")
        self.assertEqual(ip_change[0]["diff"]["org"]["old"], "OldOrg")
        self.assertEqual(ip_change[0]["diff"]["org"]["new"], "NewOrg")

    async def test_snapshot_is_valid_json(self) -> None:
        sid = await self._scan_with_ip_org("X")
        row = await self.storage._fetchone(
            "SELECT snapshot_json FROM scan_asset WHERE scan_id = ? AND asset_type = 'ip'",
            (sid,),
        )
        parsed = json.loads(row["snapshot_json"])
        self.assertIsInstance(parsed, dict)
        self.assertEqual(parsed["addr"], "1.1.1.1")

    async def test_snapshot_refreshes_on_duplicate_projection(self) -> None:
        """同一次扫描内重复投影时，快照要**跟着刷新**。

        事件引擎允许重复事件重新投影（见 ``scanner.py``：投影在去重闸门之前）。
        如果 ``ON CONFLICT`` 只更新 ``last_seen`` 而不刷快照，快照会停在第一次
        投影的状态，而那不是"这次扫描结束时的样子"。
        """
        from core.engine.event import Event, EventType

        scanner, _ = await self.run_scan(targets=["example.com"], include=["demo_expand"])
        sid = scanner.scan_id
        for org in ("First", "Second"):
            await self.storage.project(sid, Event(
                type=EventType.IP_ADDRESS, data="1.1.1.1", module="test",
                tags={"asn": "AS1", "org": org},
            ))
        snaps = await self.storage.asset_snapshots(sid, "ip")
        self.assertEqual(snaps[0]["org"], "Second", "重复投影没有刷新快照")


class TestRescanWritesThroughGlobalAssets(EngineTestCase):
    """**重扫时那些写入路径不能被 ``scan_id`` 挡掉。**

    资产表（``domain`` / ``http_endpoint`` …）在 M7-f 之后是**全局唯一**的，
    ``scan_id`` 只表示"谁最先发现的"。于是任何 ``WHERE scan_id = ?`` 的**写入**
    都只在"本次扫描新插入那行"时命中 —— 对上一次已发现的资产，它们**静默不生效、
    还不报错**。

    这三条以前全是这样，而测试套件**一次都没覆盖过重扫**（``TestSnapshotProjection``
    测的是快照可读性，不是这些写入路径），所以它们活了下来。
    """

    async def _scan(self):
        """一次跑出 example.com + 4 个子域的扫描，返回 scan_id。"""
        scanner, _ = await self.run_scan(
            targets=["example.com"], include=["demo_expand"]
        )
        return scanner.scan_id

    async def test_domain_ip_link_is_written_on_a_rescan(self) -> None:
        """第二次扫描只发 ``IP_ADDRESS``（没重发 ``DNS_NAME``）也要建关联。

        真实场景：子域在上一轮已入库，这轮只解析出它的 IP。
        """
        from core.engine.event import Event, EventType

        first = await self._scan()
        second = await self._scan()
        self.assertNotEqual(first, second)

        # 第二轮只发 IP_ADDRESS，parent_data 指向上轮已入库的域名
        await self.storage.project(second, Event(
            type=EventType.IP_ADDRESS, data="9.9.9.9", module="test",
            parent_data="www.example.com",
        ))

        row = await self.storage._fetchone(
            "SELECT count(*) AS n FROM domain_ip di "
            "JOIN domain d ON d.id = di.domain_id "
            "JOIN ip i ON i.id = di.ip_id "
            "WHERE d.name = ? AND i.addr = ?",
            ("www.example.com", "9.9.9.9"),
        )
        self.assertEqual(
            int(row["n"]), 1,
            "重扫时域名<->IP 关联没写进去 —— 查询还带着 scan_id？",
        )

    async def test_cdn_finding_marks_the_domain_on_a_rescan(self) -> None:
        """第二轮才判定出 CDN，``is_cdn`` 也必须点亮。

        ``services/diff.py`` 正是拿 ``is_cdn`` / ``is_wildcard`` 做变更对比的 ——
        这条不生效，"新增 CDN"这类变更监控**永远报不出来**，且不留任何痕迹。
        """
        from core.engine.event import Event, EventType

        await self._scan()
        second = await self._scan()

        before = await self.storage._fetchone(
            "SELECT is_cdn FROM domain WHERE name = ?", ("api.example.com",)
        )
        self.assertFalse(before["is_cdn"], "前置条件不成立：它一开始就是 CDN")

        await self.storage.project(second, Event(
            # FINDING 事件的 ``data`` 就是 target（见 ``_insert_finding``），
            # ``kind`` 走 tags —— 两者别搞反，否则 UPDATE 拿域名去匹配 0 行。
            type=EventType.FINDING, data="api.example.com", module="dns_resolve",
            tags={"kind": "cdn", "detail": "命中 CDN 网段"},
        ))

        after = await self.storage._fetchone(
            "SELECT is_cdn FROM domain WHERE name = ?", ("api.example.com",)
        )
        self.assertTrue(after["is_cdn"], "重扫的 finding 没点亮 is_cdn")

    async def test_screenshot_write_survives_a_rescan(self) -> None:
        """截图写进的是"上一轮已存在"的端点行，且**真写进去时才算成功**。

        ⚠️ 端点行必须由**第一次**扫描建立 —— 那样 ``http_endpoint.scan_id``
        才是"第一轮那个 id"，第二轮的 UPDATE 才真的面临"scan_id 对不上"。
        （第一版测试把 HTTP_RESPONSE 也投影在第二轮，于是行本来就是第二轮的，
        删掉修复照样绿 —— 写测试时得先确认"资产行的 scan_id 到底是谁的"。）
        """
        from core.engine.event import Event, EventType

        url = "http://www.example.com/"

        def http_response(sid: int) -> None:
            return self.storage.project(sid, Event(
                type=EventType.HTTP_RESPONSE, data=url, module="http_probe",
                tags={"status": 200, "host": "www.example.com", "ip": "9.9.9.9",
                      "port": 80, "scheme": "http"},
            ))

        first = await self._scan()
        await http_response(first)              # ← 端点行归第一轮所有
        second = await self._scan()
        await http_response(second)             # 重扫：ON CONFLICT，scan_id 仍是 first

        row = await self.storage._fetchone(
            "SELECT scan_id FROM http_endpoint WHERE url = ?", (url,)
        )
        self.assertEqual(int(row["scan_id"]), first, "前置条件不成立")

        blob = b"\x89PNG-fake-1"
        self.assertTrue(
            await self.storage.save_screenshot(second, url, blob),
            "重扫时截图写不进去 —— UPDATE 还带着 scan_id？",
        )
        self.assertEqual(await self.storage.screenshot_blob(second, url), blob)


if __name__ == "__main__":
    unittest.main()
