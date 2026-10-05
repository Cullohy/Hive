"""血缘图接口：树结构 / 断头 / 深度 / 截断 / 筛选。

## 为什么要单独测这个图

事件列表那笔改动之后，界面上要画一张"这个资产是怎么被发现的"图。
数据不用额外准备 —— 每条事件本来就带 ``parent_id``，那张图直接就是
``(id, parent_id)`` 组成的树。

## 夹具为什么是三级的

只有 SEED -> DNS_NAME 的话，"父被筛掉"这件事测不出来：DNS_NAME 的父
是 SEED，而 SEED 也在结论型之外，于是所有节点都是断头，**看起来对**。

真实情况是混着的：IP_ADDRESS 的父是 DNS_NAME（两条都在结论型里，
是图内部的边），DNS_NAME 的父是 SEED（被筛掉，是断头）。所以夹具做成
SEED -> DNS_NAME -> IP_ADDRESS 三级，3 条断言才各自测到一件事。
"""
from __future__ import annotations

import unittest

from .base import WebTestCase

API = "TestLineageApi"


class TestLineageApi(WebTestCase):
    MODULE = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_chain(BaseModule):
    # SEED -> 4 个 DNS_NAME -> 每个再产出 1 个 IP_ADDRESS。
    # 另外从 SEED 直接发 6 个 URL，它们只出现在 kind=all 里 ——
    # 用来验证「结论型默认」确实把过程型滤掉了。
    # （这里用 # 而不是 docstring：外层是三引号字符串，内层再用三引号
    #   会把外层提前闭合，pytest 报的是个看不出所以然的 SyntaxError。）

    watched_events = (EventType.SEED, EventType.DNS_NAME)
    produced_events = (EventType.DNS_NAME, EventType.IP_ADDRESS, EventType.URL)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        if event.type == EventType.SEED:
            for i in range(4):
                await self.emit_event(f"h{i}.example.com", EventType.DNS_NAME,
                                      parent=event)
            for i in range(6):
                await self.emit_event(f"https://example.com/p{i}", EventType.URL,
                                      parent=event)
        else:
            # DNS_NAME -> IP_ADDRESS（父在结论型内部，是一条内部边）
            await self.emit_event(f"10.0.0.{event.data[1]}", EventType.IP_ADDRESS,
                                  parent=event)
"""

    def setUp(self) -> None:
        super().setUp()
        self.mods = self.root / "mods"
        self.mods.mkdir(parents=True, exist_ok=True)
        (self.mods / "emit_chain.py").write_text(self.MODULE, encoding="utf-8")
        self.preset = self.root / "chain.yml"
        self.preset.write_text(
            "name: chain\n"
            "include:\n"
            "  - emit_chain\n"
            f"module_dirs:\n  - {self.mods}\n"
            "settings:\n  max_events: 1000\n",
            encoding="utf-8",
        )
        rec = self.start(["example.com"], preset=str(self.preset))
        self.wait_done(rec["scan_id"])
        self.scan_id = rec["scan_id"]

    def _get(self, **params):
        r = self.client.get(f"/api/scans/{self.scan_id}/lineage", params=params)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    # ── 形状 ─────────────────────────────────────────────────────
    def test_kind_all_is_one_connected_tree(self) -> None:
        """kind=all：779 张图那种完整树，边 = 节点数 - 根数。"""
        d = self._get(kind="all", limit=1000)
        # 1 SEED + 4 DNS_NAME + 4 IP_ADDRESS + 6 URL = 15
        self.assertEqual(d["total"], 15, f"节点总数不对: {d['total']}")
        self.assertEqual(len(d["edges"]), 14, "边数应等于节点数减一（单根树）")
        self.assertEqual(d["orphans"], [], "全量图不该有断头")

    def test_default_is_conclusion_only(self) -> None:
        d = self._get(limit=1000)
        types = {n["type"] for n in d["nodes"]}
        self.assertEqual(types, {"DNS_NAME", "IP_ADDRESS"},
                         f"默认混进了过程型: {types}")
        self.assertNotIn("URL", types)

    def test_orphans_are_reported_not_silently_dropped(self) -> None:
        """⚠️ 结论型里 DNS_NAME 的父是 SEED，SEED 被筛掉了 —— 那是**断头**。

        边必须一起少掉（不能画一条指向不存在节点的边），但要**报出来**：
        静默丢边会让用户看到的因果是假的。
        """
        d = self._get(limit=1000)
        self.assertEqual(d["total"], 8, "4 DNS_NAME + 4 IP_ADDRESS")
        self.assertEqual(len(d["edges"]), 4, "只有 DNS->IP 是内部边")
        self.assertEqual(len(d["orphans"]), 4, "4 个 DNS_NAME 是断头")
        # 断头的 id 必须真的是图里没有的节点
        ids = {n["id"] for n in d["nodes"]}
        for oid in d["orphans"]:
            self.assertIn(oid, ids, "断头节点本身必须在图里")

    def test_depth_is_computed_not_borrowed_from_scope_distance(self) -> None:
        """深度按图论算，不采信 scope_distance。

        中间有事件被筛掉时两者会分叉：kind=all 下 IP_ADDRESS 是第 2 层，
        而它的 scope_distance 未必是 2。
        """
        d = self._get(kind="all", limit=1000)
        by_type = {}
        for n in d["nodes"]:
            by_type.setdefault(n["type"], []).append(n["depth"])
        self.assertEqual(set(by_type["SEED"]), {0})
        self.assertEqual(set(by_type["DNS_NAME"]), {1})
        self.assertEqual(set(by_type["IP_ADDRESS"]), {2}, "IP 应在第 2 层")

    def test_max_depth_filters_and_total_follows(self) -> None:
        """⚠️ total 必须在 max_depth **之后**统计。

        深度筛选也是一种筛选；把被它滤掉的算进"共 M"，标题又开始说谎
        （事件列表栽过这个跟头）。
        """
        d = self._get(kind="all", max_depth=1, limit=1000)
        self.assertEqual({n["depth"] for n in d["nodes"]}, {0, 1})
        # 深度 1 里有 4 个 DNS_NAME **和 6 个 URL** —— URL 也是直接从 SEED
        # 发的（夹具里就是从 SEED emit 的），所以 1 + 4 + 6 = 11。
        self.assertEqual(d["total"], 11)
        self.assertEqual(d["shown"], 11)

    # ── 截断要说清楚 ─────────────────────────────────────────────
    def test_truncation_is_reported(self) -> None:
        d = self._get(kind="all", limit=5)
        self.assertEqual(d["shown"], 5)
        self.assertEqual(d["total"], 15, "total 不受 limit 影响")
        self.assertTrue(d["truncated"], "截断了却没说 —— 前端就会显示成'只有 5 个'")
        self.assertEqual(len(d["edges"]), len(d["nodes"]) - 1,
                         "截断后剩下的应当仍是一棵树")

    def test_not_truncated_when_all_fits(self) -> None:
        d = self._get(kind="all", limit=1000)
        self.assertFalse(d["truncated"])
        self.assertEqual(d["shown"], d["total"])

    # ── 筛选 ─────────────────────────────────────────────────────
    def test_types_filter_accepts_comma_list(self) -> None:
        d = self._get(types="DNS_NAME,IP_ADDRESS", limit=1000)
        self.assertEqual({n["type"] for n in d["nodes"]}, {"DNS_NAME", "IP_ADDRESS"})

    def test_module_and_query_filters(self) -> None:
        # 必须显式 kind="all"：默认是结论型，那样 module 过滤的基数更小。
        # ⚠️ 14 而不是 15：SEED 那条是 **scanner** 发的（module="engine"，
        # 见 scanner.py 的 submit(Event(type=SEED, module="engine"))），
        # 不属于 emit_chain，所以按模块过滤时本该被排除。
        # 引擎日志说"记录 15 条"，这 15 条里有一条不属于任何模块 ——
        # 不知道这一点就会把这张图当成"少了一条"的 bug 去查。
        self.assertEqual(self._get(kind="all", module="emit_chain",
                                    limit=1000)["total"], 14)
        self.assertEqual(self._get(kind="all", module="engine",
                                    limit=1000)["total"], 1)
        self.assertEqual(self._get(kind="all", module="nope", limit=1000)["total"], 0)
        d = self._get(q="h1.", kind="all", limit=1000)
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["nodes"][0]["data"], "h1.example.com")

    def test_empty_result_is_not_an_error(self) -> None:
        d = self._get(q="definitely-not-there", limit=1000)
        self.assertEqual(d["nodes"], [])
        self.assertEqual(d["edges"], [])
        self.assertEqual(d["total"], 0)
        self.assertFalse(d["truncated"])


class TestLineageRouteDoesNotCollide(unittest.TestCase):
    """⚠️ ``/graph`` 已经被「资产关系图」占用了。

    两张图回答的不是同一个问题：``/graph`` 是域名→IP→端口那种**资产关系**
    （谁和谁共享基础设施），``/lineage`` 是事件的**血缘**（怎么被发现的）。
    用同一个路径的话，FastAPI 只认先注册的那个，后注册的**静默失效** ——
    我第一版就踩了，症状是接口返回 422（老接口的 ``ge=100`` 拦住了请求）。
    """

    def test_both_graph_routes_exist_and_are_different(self) -> None:
        from core.web.app import create_app

        paths = {r.path for r in create_app().routes if hasattr(r, "path")}
        self.assertIn("/api/scans/{scan_id}/graph", paths)
        self.assertIn("/api/scans/{scan_id}/lineage", paths)
        self.assertNotEqual("/api/scans/{scan_id}/graph",
                            "/api/scans/{scan_id}/lineage")
