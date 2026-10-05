"""事件流接口：结论型默认 / 倒序 / 分页 / 筛选 / 计数。

## 起因：界面"看不全"，而且标题在说谎

一次 yealink 扫描产出 779 条事件。界面上：

* 前端硬编码 ``getEvents(id, 300)`` —— 只取 **300** 条
* 后端 ``ORDER BY id`` —— 取的是**最早**那 300 条，**最新的永远看不到**
* tab 标题用 ``summary.events`` 显示 **779**，表格里只有 300 行
* **没有任何"被截断"的提示**

而那 428 条看不到的里面，恰好包含 ``dir_brute`` 的全部 HTTP_RESPONSE 与
``tls_cert`` 的全部证书 —— 溯源要用到的正是它们。

另外还发现一处**从来没通过过**的筛选：后端声明
``event_type: ... = Query(None, alias="type")``（FastAPI 只认 ``?type=``），
而前端发的是 ``?event_type=``。
"""
from __future__ import annotations

import unittest
from collections import Counter

from .base import WebTestCase


class TestEventsEndpoint(WebTestCase):
    """用真扫描 + 真 HTTP 灌出混合类型的事件，再验接口行为。

    不用 ``EngineTestCase``：那条路没有 ``self.client``，而这里要验的正是
    **接口层**（参数名、默认值、分页、计数），跑引擎是绕远。
    """

    #: 结论型 4 条、过程型 6 条，**另有 scanner 自己发的 1 条 SEED**。
    #: 走 API 起扫描（``WebTestCase.start`` 支持自带 preset），
    #: 所以事件是引擎真产出的，不是手塞的。
    MODULE = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_mixed(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.DNS_NAME, EventType.URL)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for i in range(4):
            await self.emit_event(f"h{i}.example.com", EventType.DNS_NAME,
                                  parent=event)
        for i in range(6):
            await self.emit_event(f"https://example.com/p{i}", EventType.URL,
                                  parent=event)
"""

    def setUp(self) -> None:
        super().setUp()
        self.mods = self.root / "mods"
        self.mods.mkdir(parents=True, exist_ok=True)
        (self.mods / "emit_mixed.py").write_text(self.MODULE, encoding="utf-8")
        self.preset = self.root / "mixed.yml"
        self.preset.write_text(
            "name: mixed\n"
            "include:\n"
            "  - emit_mixed\n"
            f"module_dirs:\n  - {self.mods}\n"
            "settings:\n  max_events: 1000\n",
            encoding="utf-8")
        rec = self.start(["example.com"], preset=str(self.preset))
        self.wait_done(rec["scan_id"])
        self.scan_id = rec["scan_id"]

    def _get(self, **params):
        r = self.client.get(f"/api/scans/{self.scan_id}/events", params=params)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    # ── 默认只看结论型 ────────────────────────────────────────────
    def test_default_returns_conclusions_only(self) -> None:
        d = self._get(limit=50)
        self.assertEqual(d["kind"], "conclusion")
        types = {i["type"] for i in d["items"]}
        self.assertEqual(types, {"DNS_NAME"},
                         "默认混进了过程型事件（URL / HTTP_RESPONSE）")
        self.assertEqual(d["total"], 4, "结论型应当是 4 条")

    def test_kind_all_returns_everything(self) -> None:
        d = self._get(limit=50, kind="all")
        # 11 = 4 DNS_NAME + 6 URL + **1 条 SEED**。最后这条不是 emit_mixed
        # 发的，是 scanner 给每个 target 发的起点事件（scanner.py:649）——
        # 夹具只声明了 10 条，少算它就会得到一个"看起来对"的假数字。
        self.assertEqual(d["total"], 11, "kind=all 应当是 1 SEED + 4 + 6 = 11 条")
        self.assertEqual(
            Counter(i["type"] for i in d["items"]),
            {"SEED": 1, "DNS_NAME": 4, "URL": 6},
            "事件类型分布不对")
        seed = [i for i in d["items"] if i["type"] == "SEED"][0]
        self.assertEqual(seed["module"], "engine", "SEED 应当是 scanner 自己发的")

    # ── 倒序 ─────────────────────────────────────────────────────
    def test_newest_first(self) -> None:
        """⚠️ 以前是 ``ORDER BY id`` 升序 —— 任务在跑时新发生的事一条都看不到。"""
        d = self._get(limit=50, kind="all")
        ids = [i["id"] for i in d["items"]]
        self.assertEqual(ids, sorted(ids, reverse=True),
                         "不是倒序 —— 最新进展不在第一页")

    # ── 分页 ─────────────────────────────────────────────────────
    def test_pagination_does_not_overlap(self) -> None:
        p1 = [i["id"] for i in self._get(limit=3, offset=0, kind="all")["items"]]
        p2 = [i["id"] for i in self._get(limit=3, offset=3, kind="all")["items"]]
        self.assertEqual(len(p1), 3)
        self.assertEqual(len(p2), 3)
        self.assertFalse(set(p1) & set(p2), "两页重叠了")
        self.assertEqual(max(p2), min(p1) - 1, "两页之间断了")

    def test_total_is_independent_of_page_size(self) -> None:
        """total 必须是**命中总数**，不是本页行数 —— 否则标题又在说谎。"""
        big = self._get(limit=50)["total"]
        small = self._get(limit=2)["total"]
        self.assertEqual(big, small)
        self.assertEqual(small, 4)

    # ── 筛选 ─────────────────────────────────────────────────────
    def test_type_filter(self) -> None:
        d = self._get(limit=50, type="URL", kind="all")
        self.assertEqual(d["total"], 6)
        self.assertEqual({i["type"] for i in d["items"]}, {"URL"})

    def test_legacy_event_type_param_still_works(self) -> None:
        """⚠️ 以前这个筛选**从来没通过过** —— 前端发 ``event_type``、
        后端 alias 成 ``type``，两边对不上。"""
        d = self._get(limit=50, event_type="URL", kind="all")
        self.assertEqual(d["total"], 6, "旧参数名 event_type 没被接受")

    def test_module_filter(self) -> None:
        d = self._get(limit=50, module="emit_mixed")
        self.assertEqual(d["total"], 4)
        other = self._get(limit=50, module="nope")
        self.assertEqual(other["total"], 0)

    def test_query_searches_the_data_field(self) -> None:
        d = self._get(limit=50, q="h1.", kind="all")
        self.assertEqual(d["total"], 1)
        self.assertEqual(d["items"][0]["data"], "h1.example.com")

    def test_filters_combine(self) -> None:
        # SEED 的 data 也是 "example.com"，所以全文搜会连它一起命中（11 条）
        d = self._get(limit=50, q="example", kind="all")
        self.assertEqual(d["total"], 11)
        d = self._get(limit=50, q="example", type="DNS_NAME", kind="all")
        self.assertEqual(d["total"], 4)

    def test_response_shape_has_items_and_total(self) -> None:
        d = self._get(limit=50)
        self.assertIn("items", d)
        self.assertIn("total", d)
        self.assertIn("kinds_all", d)
        self.assertIsInstance(d["items"], list)


class TestConclusionTypeSet(unittest.TestCase):
    """「结论型」这个集合本身要对 —— 它是默认视图的全部内容。"""

    def test_process_types_are_excluded(self) -> None:
        from core.web.app import _CONCLUSION_EVENT_TYPES

        for t in ("URL", "HTTP_RESPONSE"):
            self.assertNotIn(t, _CONCLUSION_EVENT_TYPES,
                             f"{t} 是过程型，不该出现在默认视图")
        # 产出新资产/新结论的这些都该在
        for t in ("DNS_NAME", "IP_ADDRESS", "OPEN_TCP_PORT",
                  "SSL_CERTIFICATE", "TECHNOLOGY", "FINDING"):
            self.assertIn(t, _CONCLUSION_EVENT_TYPES, f"{t} 漏出了默认视图")

    def test_seed_is_not_a_conclusion(self) -> None:
        """SEED 是链的**起点**，不是产出 —— 列进结论型会稀释视图。"""
        from core.web.app import _CONCLUSION_EVENT_TYPES

        self.assertNotIn("SEED", _CONCLUSION_EVENT_TYPES)
