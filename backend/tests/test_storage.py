"""存储层专测：方言适配与检索索引。

这里覆盖的是**从 SQLite 换到 PostgreSQL 时新引入的那部分**，
也就是 ``core/storage/pg.py`` 的三条模拟规则与 ``pg_trgm`` 索引。

其余存储行为由各个域自己的测试覆盖（它们现在也跑在 PostgreSQL 上）。
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path
from unittest import IsolatedAsyncioTestCase

import asyncpg

from core.engine.event import Event, EventType
from core.storage.pg import (
    Row,
    _count_from_status,
    _first_word,
    _insert_table,
    convert_placeholders,
)
from core.storage.postgres import (
    _ASSET_FILTER_FIELDS,
    _LIVE_COUNT_SQL,
    _LIVE_SQL,
    _NUMERIC_FILTER_FIELDS,
    _SEARCH_SPECS,
    SEARCH_KEYS,
    PostgresStorage,
    _build_filter_where,
    _live_clause,
    _search_where,
)

from .pgutil import DSN, drop_storage, ensure_database, make_storage, new_schema


#: 「scan_id 用测试自己的默认值」的哨兵 —— 显式传 ``None`` 表示"真的没有 scan_id"
_USE_SENTINEL = object()


class TestSearchWhereParamOrder(unittest.TestCase):
    """**参数顺序必须等于占位符在 SQL 文本里出现的顺序。**

    曾经把「多维筛选」的 ``params.extend`` 写在「分组过滤」的
    ``params.append(group_id)`` 前面，而 return 里的串是
    ``{group_clause}{filter_clause}`` —— 文本里 group 在前、参数里 filter 在前。

    **条数是对的**，所以那些"钉住条数"的测试（``test_search_spec_live_needs_a
    _scan_id`` 之类）全绿；错的是值落在哪个占位符上。后果分两种：

    * 字符串列 → asyncpg 抛类型错，接口 500（**能看见**，算幸运）
    * 数字列（``status`` / ``port``）两边都是 int → **不报错**，
      静默返回错组错值的结果与 total，界面上只是"数字有点怪"

    所以这里不看条数，改看**每个 ``?`` 前面那段文本说的是谁、拿到的是谁**。
    """

    #: 用来定位的哨兵值：一眼能认出是它，就说明没落到该去的占位符上
    PATTERN = "%needle%"
    SCAN_ID = 7
    GROUP_ID = 4242

    @staticmethod
    def _fragments(sql: str) -> list[str]:
        """按 ``?`` 切成 n+1 段。第 i 段是**第 i 个** ``?`` 之前的那段文本，
        也就是那个 ``?`` 对应 ``params[i]``。"""
        return sql.split("?")

    def _where(
        self,
        filters: list[dict] | None = None,
        group_id: int | None = None,
        asset_type: str = "domains",
        live: bool = True,
    ) -> tuple[str, list, list[str]]:
        """返回 (原始 SQL, 参数序列, 按 ? 切开的片段)。

        **原始 SQL 必须原样带回** —— 把片段 join 起来会连 ``?`` 一起拼没，
        条数校验就成了 0 != N 的假失败。
        """
        sql, params = _search_where(
            _SEARCH_SPECS[asset_type],
            self.PATTERN, self.SCAN_ID, live, asset_type, filters, group_id,
        )
        return sql, params, self._fragments(sql)

    def _index_of(self, frags: list[str], needle: str) -> int:
        """找出**唯一**带 ``needle`` 的那个 ``?`` 的下标。

        只接受"恰好命中一次"——像 ``t.name ILIKE`` 那种在搜索主句与筛选条件里
        都会出现的写法，匹配到第一个只会验到搜索主句，等于什么都没验。
        """
        hits = [i for i, frag in enumerate(frags) if needle in frag]
        if len(hits) != 1:
            self.fail(
                f"期望 {needle!r} 在 SQL 里恰好出现一次，实际 {len(hits)} 次"
                f"（下标 {hits}）——换个唯一的锚点，或这个片段已经变了"
            )
        return hits[0]

    def _expected_params(
        self, spec, filter_params: list, group_id: int | None,
        live: bool, scan_id: int | None,
    ) -> list:
        """按 return 那个串的顺序，把六段拼成应有的参数序列。

        筛选那一段是**调用方写死的期望值**，不是调 ``_build_filter_where``
        算出来的 —— 那样就成了拿被测对象证明自己。
        """
        expected = [self.PATTERN] * len(spec.columns)        # ① 每个可搜列
        if scan_id is not None:
            expected.append(scan_id)                         # ② scope
            if live and spec.live:
                expected.extend([scan_id] * spec.live_params)  # ③ live
        if group_id is not None and spec.seen is not None:    # ④ 分组
            expected.append(group_id)
        expected.extend(filter_params)                       # ⑤ 多维筛选
        expected.extend(spec.exclude_kinds)                  # ⑥ 噪声 kind
        return expected

    def _assert_params(
        self, sql: str, params: list, spec, filter_params: list,
        group_id: int | None, live: bool = True,
        scan_id: int | None = _USE_SENTINEL,
    ) -> None:
        if scan_id is _USE_SENTINEL:
            scan_id = self.SCAN_ID
        self.assertEqual(
            params,
            self._expected_params(spec, filter_params, group_id, live, scan_id),
            "参数序列与占位符顺序不一致（条数对但值错位时，这里会直接列出顺序）",
        )
        self.assertEqual(sql.count("?"), len(params), "占位符条数与参数条数不一致")

    # ---------------------------------------------------------------- 钉住值

    def test_group_id_lands_in_the_group_placeholder(self) -> None:
        """``ga.group_id = ?`` 拿到的必须是 group_id 本身。"""
        _sql, params, frags = self._where(
            filters=[{"field": "name", "op": "contains", "value": "admin"}],
            group_id=self.GROUP_ID,
        )
        idx = self._index_of(frags, "ga.group_id")
        self.assertEqual(
            params[idx], self.GROUP_ID,
            f"ga.group_id 拿到的是 {params[idx]!r}；参数顺序与占位符顺序错位了",
        )

    def test_string_filter_and_group_never_swap(self) -> None:
        sql, params, frags = self._where(
            filters=[{"field": "name", "op": "contains", "value": "admin"}],
            group_id=self.GROUP_ID,
        )
        self.assertEqual(params[self._index_of(frags, "ga.group_id")], self.GROUP_ID)
        self._assert_params(
            sql, params, _SEARCH_SPECS["domains"], ["%admin%"], self.GROUP_ID,
        )

    def test_numeric_filter_is_not_silently_swapped(self) -> None:
        """数字列这条是**静默**的那个：两边都是 int，asyncpg 不会拦。

        所以除了查 ``ga.group_id``，还要把整条参数序列钉死。
        """
        sql, params = _search_where(
            _SEARCH_SPECS["urls"], self.PATTERN, self.SCAN_ID, True, "urls",
            [{"field": "status", "op": "eq", "value": "200"}], self.GROUP_ID,
        )
        frags = self._fragments(sql)
        self.assertEqual(params[self._index_of(frags, "ga.group_id")], self.GROUP_ID)
        self._assert_params(sql, params, _SEARCH_SPECS["urls"], [200], self.GROUP_ID)

    def test_two_filters_and_group_keep_their_slots(self) -> None:
        sql, params, frags = self._where(
            filters=[
                {"field": "name", "op": "contains", "value": "alpha"},
                {"field": "source", "op": "eq", "value": "shodan"},
            ],
            group_id=self.GROUP_ID,
        )
        self.assertEqual(params[self._index_of(frags, "ga.group_id")], self.GROUP_ID)
        self._assert_params(
            sql, params, _SEARCH_SPECS["domains"], ["%alpha%", "shodan"], self.GROUP_ID,
        )

    def test_group_only_still_works(self) -> None:
        """只给 group_id（前端常见：进分组页只看这一组）。"""
        sql, params = _search_where(
            _SEARCH_SPECS["domains"], self.PATTERN, self.SCAN_ID, True, "domains",
            None, self.GROUP_ID,
        )
        frags = self._fragments(sql)
        self.assertEqual(params[self._index_of(frags, "ga.group_id")], self.GROUP_ID)
        self._assert_params(sql, params, _SEARCH_SPECS["domains"], [], self.GROUP_ID)

    def test_no_group_no_filters_is_unchanged(self) -> None:
        """两个都不给时退化成最简形式（组不追加、筛选不追加）。"""
        sql, params = _search_where(
            _SEARCH_SPECS["domains"], self.PATTERN, self.SCAN_ID, True, "domains",
            None, None,
        )
        self.assertNotIn("asset_group_asset", sql)
        self._assert_params(sql, params, _SEARCH_SPECS["domains"], [], None)

    def test_global_search_without_scan_id(self) -> None:
        """``scan_id=None`` 的跨扫描检索：scope 与 live 都不追加参数。"""
        sql, params = _search_where(
            _SEARCH_SPECS["domains"], self.PATTERN, None, True, "domains",
            [{"field": "name", "op": "contains", "value": "admin"}], self.GROUP_ID,
        )
        frags = self._fragments(sql)
        self.assertEqual(params[self._index_of(frags, "ga.group_id")], self.GROUP_ID)
        self._assert_params(
            sql, params, _SEARCH_SPECS["domains"], ["%admin%"], self.GROUP_ID,
            scan_id=None,
        )
        self.assertNotIn(self.SCAN_ID, params, "没有 scan_id 时不该出现它")


class TestPlaceholderConversion(unittest.TestCase):
    """``?`` → ``$n``。

    **必须逐字符扫描而不是 str.replace** —— SQL 里会出现字面 ``?``。
    每条规则一个用例，因为漏一条就是静默把参数插错位置。
    """

    def test_simple(self) -> None:
        self.assertEqual(
            convert_placeholders("SELECT * FROM t WHERE a = ? AND b = ?"),
            "SELECT * FROM t WHERE a = $1 AND b = $2",
        )

    def test_question_mark_inside_string_is_not_a_placeholder(self) -> None:
        """``LIKE '%?%'`` 里的问号是数据，不是占位符。"""
        self.assertEqual(
            convert_placeholders("SELECT * FROM t WHERE a LIKE '%?%' AND b = ?"),
            "SELECT * FROM t WHERE a LIKE '%?%' AND b = $1",
        )

    def test_escaped_single_quote(self) -> None:
        """SQL 里 ``''`` 是转义的单引号，不能提前结束字符串。"""
        self.assertEqual(
            convert_placeholders("SELECT 'it''s ?' , ?"),
            "SELECT 'it''s ?' , $1",
        )

    def test_line_comment(self) -> None:
        self.assertEqual(
            convert_placeholders("SELECT ? -- 这里有个?\n, ?"),
            "SELECT $1 -- 这里有个?\n, $2",
        )

    def test_block_comment(self) -> None:
        self.assertEqual(
            convert_placeholders("/* ? */ SELECT ?"), "/* ? */ SELECT $1"
        )

    def test_quoted_identifier(self) -> None:
        self.assertEqual(
            convert_placeholders('SELECT "weird?col" FROM t WHERE a = ?'),
            'SELECT "weird?col" FROM t WHERE a = $1',
        )

    def test_escape_clause_survives(self) -> None:
        self.assertEqual(
            convert_placeholders("WHERE a ILIKE ? ESCAPE '\\'"),
            "WHERE a ILIKE $1 ESCAPE '\\'",
        )

    def test_no_placeholders(self) -> None:
        sql = "SELECT 1"
        self.assertEqual(convert_placeholders(sql), sql)


class TestStatementClassification(unittest.TestCase):
    def test_first_word_skips_comments(self) -> None:
        self.assertEqual(_first_word("-- 注释\nSELECT 1"), "SELECT")
        self.assertEqual(_first_word("/* 块 */ INSERT INTO t"), "INSERT")
        self.assertEqual(_first_word("   update t set a=1"), "UPDATE")

    def test_insert_table_extraction(self) -> None:
        self.assertEqual(_insert_table("INSERT INTO domain (a) VALUES (?)"), "domain")
        self.assertEqual(
            _insert_table("  insert into public.url (a) values (?)"), "url"
        )
        self.assertIsNone(_insert_table("SELECT 1"))

    def test_status_count(self) -> None:
        """asyncpg 的 ``execute()`` 返回状态串，rowcount 要从里面解析。"""
        for status, want in [
            ("INSERT 0 1", 1),
            ("INSERT 0 0", 0),
            ("UPDATE 3", 3),
            ("DELETE 2", 2),
            ("SELECT 5", 5),
            ("", 0),
        ]:
            self.assertEqual(_count_from_status(status), want, status)


class TestRow(unittest.TestCase):
    """行对象要**同时支持列名与位置索引** —— 现有代码两种都在用。"""

    def test_string_index(self) -> None:
        self.assertEqual(Row({"name": "a", "id": 1})["name"], "a")

    def test_positional_index(self) -> None:
        """``SELECT COUNT(*)`` 那条路径用的是 ``row[0]``。"""
        self.assertEqual(Row({"c": 42})[0], 42)

    def test_dict_roundtrip(self) -> None:
        self.assertEqual(dict(Row({"a": 1, "b": 2})), {"a": 1, "b": 2})

    def test_iteration_yields_keys(self) -> None:
        self.assertEqual(list(Row({"a": 1, "b": 2})), ["a", "b"])

    def test_len(self) -> None:
        self.assertEqual(len(Row({"a": 1, "b": 2})), 2)


class TestSearchKeys(unittest.TestCase):
    def test_urls_is_searchable(self) -> None:
        """``url`` 表必须能被搜到。

        它是 url_extract / js_assets / dir_brute 三个模块的产出落点；
        漏了检索规格等于那三个模块白跑 —— 这个漏过一次，所以钉住。
        """
        self.assertIn("urls", SEARCH_KEYS)

    def test_expected_keys(self) -> None:
        for key in ("domains", "ips", "ports", "urls",
                    "technologies", "findings"):
            self.assertIn(key, SEARCH_KEYS)

    def test_endpoints_merged_into_urls(self) -> None:
        """``endpoints`` 不再是独立的检索类型 —— 它并进了 ``urls``。

        HTTP 端点与 URL 本来是**包含关系**（探活过的 URL 在 url 表里也有
        一行），界面上分两个页签/两个类型会让人以为"已知存在"和"已知活着"
        是两批东西。合并后靠 ``LEFT JOIN`` 把状态/标题/Server 带出来。
        """
        self.assertNotIn("endpoints", SEARCH_KEYS)
        spec = _SEARCH_SPECS["urls"]
        # 必须留下没探过的 URL —— 用 LEFT JOIN，不是内连接
        self.assertTrue(spec.join.lstrip().startswith("LEFT JOIN"))
        # 端点的列要能搜到
        self.assertTrue(any("title" in c for c in spec.columns))
        self.assertTrue(any("server" in c for c in spec.columns))
        # 端点的列也要被 SELECT 出来（前端要显示状态）
        self.assertIn("status", spec.select)


class TestLiveFilterShape(unittest.TestCase):
    """「只显示探活确认过的资产」的过滤条件。

    这里钉的是**语义一致性**和两个性能陷阱 —— 后者都是"改错了不报错、
    结果也对，只是页面加载不出来"的那种。
    """

    def test_domain_liveness_means_the_domain_itself(self) -> None:
        """域名存活 = **它自己有** HTTP 端点，不是"它的某个子域有"。

        早先用的是后缀匹配（`e.host = d.name OR e.host LIKE '%.' || d.name`），
        于是 `accounts.qq.com` 会因为 `ptlogin2.accounts.qq.com` 响应而入选 ——
        但它自己一个端点都没有，"存活"那一列就显示"未探活"，与
        "只显示探活确认过的资产"自相矛盾（实测 70 行是这样）。

        必须是等值匹配 ``e.host = d.name``。
        """
        sql, _ = _LIVE_SQL["domains"]
        self.assertIn("e.host = d.name", sql)
        self.assertNotIn("LIKE", sql, "后缀 LIKE 会让子域存活算到父域名头上")
        self.assertNotIn("generate_subscripts", sql, "不需要再展开后缀了")

    def test_live_filter_asks_scan_asset_which_scan(self) -> None:
        """存活过滤必须**带上"哪次扫描"** —— 而那个只能从 ``scan_asset`` 问。

        ## 这条钉的是跨 scan 去重迁移的漏网之鱼

        迁移前资产行按扫描分家，所以 ``e.scan_id = d.scan_id``（端点与域名是
        同一次扫描里的两行）是成立的。迁移后两边都只有一行，``scan_id`` 变成
        "**谁最先发现的**"——那句比的是两个不相干的数。正确口径与
        ``asset_counts()`` 一致：这次扫描的 ``scan_asset`` 里有对应端点。

        （历史：这里曾经钉的是"不需要额外参数"，因为当时把它写成了不带扫描
        维度的 ``EXISTS (... WHERE e.host = d.name)`` —— 那是**另一个错**：
        把别的扫描探到的端点算到这次头上。实测 scan #20 用不含 http_probe 的
        ``default`` 预设重扫 panabit.com，正确答案 0，那种写法给出 12。）
        """
        sql, extra = _LIVE_SQL["domains"]
        self.assertIn("scan_asset", sql, "没走 scan_asset = 不知道问的是哪次扫描")
        self.assertEqual(extra, 1, "片段要吃掉一个 scan_id 参数")
        self.assertEqual(sql.count("?"), 1)
        # 用正则而不是 assertNotIn：片段里的 ``se.scan_id``（scan_asset 自己的
        # 列）含子串 "e.scan_id"，直接搜会误报。
        self.assertIsNone(re.search(r"\be\.scan_id\b", sql),
                          "端点的 scan_id 只是'谁最先发现的'")

    def test_live_filters_never_compare_first_discoverers(self) -> None:
        """四类资产的存活片段都**不能**拿两行的 ``scan_id`` 相比。

        这是整类 bug 的机械防线：``d.scan_id`` / ``i.scan_id`` / ``u.scan_id``
        和 ``e.scan_id`` 现在都只是"首个发现者"，任何比较都不成立。

        ⚠️ **``ports`` 是恒真片段，不查任何表**（2026-10-07 改）——
        ``port`` 表里一行就代表"这个端口开着"（``port_scan`` 只在 ``on_open``
        里写），拿它去要求 HTTP 观测等于要求邮件端口也得吐 HTTP，实测把
        16245 行里的 15055 行误杀。所以它**不参与**下面这条查表断言。

        但"恒真"不等于"可以随便写"：仍然要防它被改回 ``e.scan_id`` 那种
        写法，所以 scan_id 比较那条对所有 key 都查。
        """
        for key, (sql, extra) in _LIVE_SQL.items():
            with self.subTest(key=key):
                if key == "ports":
                    # 恒真：不查表、不吃占位符，但也不许出现 scan_id 比较
                    self.assertEqual(sql.strip().upper(), "TRUE",
                                     "ports 的 live 片段应当恒真")
                    self.assertEqual(extra, 0, "恒真片段不吃 scan_id 参数")
                else:
                    self.assertIn("scan_asset", sql)
                    self.assertEqual(sql.count("?"), extra)
                for alias in ("e", "d", "i", "p", "u"):
                    self.assertIsNone(
                        re.search(rf"\b{alias}\.scan_id\b", sql),
                        f"{key}: 又在拿 {alias}.scan_id 当语义了",
                    )

    def test_search_spec_live_needs_a_scan_id(self) -> None:
        """检索规格的 ``live`` 也要带 scan_id，且条数必须与声明一致。

        参数条数对不上时占位符会整体错位，报的是"参数类型不匹配"之类的怪错
        —— 完全看不出是这里少了一个数。所以逐条钉住 ``live.count("?")``。

        另外：有 ``live`` 就必须有 ``live_any`` —— 跨扫描检索（``scan_id=None``）
        时没有"这次扫描"可谈，缺了兜底条件会**静默地不过滤**（返回一堆
        从没探过的资产，而界面上什么都不会说）。

        ⚠️ **``ports`` 走恒真片段，不查表**（2026-10-07）—— 端口行本身的
        存在就代表端口开着。其余类型仍必须走 ``scan_asset``（它带
        "哪次扫描"的语义，是这条断言真正要防的东西）。
        """
        for key, spec in _SEARCH_SPECS.items():
            with self.subTest(key=key):
                self.assertEqual(spec.live.count("?"), spec.live_params)
                self.assertNotIn("t.scan_id", spec.live)
                if spec.live:
                    self.assertTrue(spec.live_any, f"{key}: 缺 live_any 兜底")
                    self.assertEqual(spec.live_any.count("?"), 0)
                    if key == "ports":
                        # 恒真：不查表，但也不许退回按 HTTP 观测判
                        self.assertEqual(spec.live.strip().upper(), "TRUE")
                        self.assertEqual(spec.live_params, 0)
                    else:
                        self.assertIn("scan_asset", spec.live)
                else:
                    self.assertEqual(spec.live_params, 0)

    def test_search_scan_filter_uses_scan_asset_for_assets(self) -> None:
        """资产表的 ``scan_id`` 过滤也要走 ``scan_asset``，不能用 ``t.scan_id``。

        跨 scan 去重之后 ``t.scan_id`` 是"谁最先发现的"：拿它过滤，重扫同一
        目标时（资产行还挂在第一次的扫描名下）会一条都查不出来。观测层的表
        （``finding``）不受影响，它自己的 ``scan_id`` 仍然是扫描维度。
        """
        for key, spec in _SEARCH_SPECS.items():
            with self.subTest(key=key):
                if spec.seen is None:
                    continue  # 观测层：t.scan_id 仍是扫描维度
                asset_type, key_expr = spec.seen
                self.assertTrue(asset_type)
                self.assertIn("t.", key_expr)
                self.assertNotIn("scan_id", key_expr)
        # finding 是唯一没走 scan_asset 的那张表
        self.assertIsNone(_SEARCH_SPECS["findings"].seen)

    def test_domain_filter_is_index_backed_not_like(self) -> None:
        """相关 ``EXISTS`` 本身没问题 —— 只要它走索引。

        真正致命的是 ``LIKE '%.' || d.name``：14,333 个域名 × 979 个端点
        逐个跑，实测 1,431 ms。等值匹配走索引后 22 ms。
        """
        sql, _ = _LIVE_SQL["domains"]
        self.assertTrue(sql.startswith("EXISTS ("))
        self.assertIn("http_endpoint", sql)

    def test_live_clause_returns_matching_param_count(self) -> None:
        """片段的参数个数必须和它实际用了几个 ``?`` 对得上。

        对不上时占位符编号会错位，报的是"参数类型不匹配"之类的怪错，
        而不是一眼能看出的问题。
        """
        for key, (sql, extra) in _LIVE_SQL.items():
            with self.subTest(key=key):
                self.assertEqual(sql.count("?"), extra,
                                 f"{key}: 片段里有 {sql.count('?')} 个占位符，"
                                 f"但声明要 {extra} 个 scan_id")
                clause, got = _live_clause(key, True)
                self.assertTrue(clause.startswith(" AND "))
                self.assertEqual(got, extra)
                self.assertEqual(_live_clause(key, False), ("", 0))

    def test_count_sql_param_count(self) -> None:
        """计数语句的参数个数 = 主 scan_id + 片段自己要的。"""
        for key, (sql, n) in _LIVE_COUNT_SQL.items():
            with self.subTest(key=key):
                self.assertEqual(sql.count("?"), n)


class TestDroppedDeadColumns(unittest.TestCase):
    """三列死重量已清 —— 它们从建库起就没被真正用过。

    钉住它们不会悄悄回来：要么真正实现，要么就不留。
    """
    """三列死重量已清 —— 它们从建库起就没被真正用过。

    钉住它们不会悄悄回来：要么真正实现，要么就不留。
    """

    SCHEMA = Path(__file__).resolve().parents[1] / "core" / "storage" / "schema.sql"
    TRGM = Path(__file__).resolve().parents[1] / "core" / "storage" / "schema_trgm.sql"

    def test_port_has_no_service_or_banner(self) -> None:
        """``service`` / ``banner`` 从没有代码写过。

        前端倒是有一列「服务」，永远是空白 —— 比没有更糟。
        要恢复的话得先有一份端口到服务名的映射表（nmap services 那种）。
        """
        schema = self.SCHEMA.read_text(encoding="utf-8")
        body = re.search(r"CREATE TABLE IF NOT EXISTS port \((.*?)\n\);", schema, re.S)
        self.assertIsNotNone(body)
        cols = re.findall(r"^\s{4}(\w+)\s", body.group(1), re.M)
        self.assertNotIn("service", cols)
        self.assertNotIn("banner", cols)
        # 明确写了删列，老库升级时才会真的掉
        self.assertIn("ALTER TABLE port", schema)
        self.assertIn("DROP COLUMN IF EXISTS service", schema)

    def test_technology_has_no_confidence(self) -> None:
        """``confidence`` 写过但没有任何消费方，前端从不显示。"""
        schema = self.SCHEMA.read_text(encoding="utf-8")
        self.assertNotIn("ADD COLUMN IF NOT EXISTS confidence", schema)
        self.assertIn("DROP COLUMN IF EXISTS confidence", schema)

    def test_no_trgm_index_on_dropped_column(self) -> None:
        """**索引必须跟着列一起删。**

        留着 ``CREATE INDEX ... ON port(service)`` 的话，整个 schema_trgm
        脚本会在那一句中断 —— 后面所有检索索引都建不起来，而且没有任何
        报错提示（实测就是这个症状："检索索引没建起来"）。
        """
        trgm = self.TRGM.read_text(encoding="utf-8")
        live = [ln for ln in trgm.splitlines() if ln.strip().startswith("CREATE INDEX")]
        for line in live:
            self.assertNotIn("service", line)
            self.assertNotIn("banner", line)
            self.assertNotIn("confidence", line)
        self.assertIn("DROP INDEX IF EXISTS trgm_port_service", trgm)


class TestDefaultConfig(unittest.TestCase):
    """**默认配置必须能跑** —— 这是所有部署路径里最容易漏测的一条。

    回归两次，都是同一个盲点：调用方显式传了参数，于是
    ``参数 or 默认值`` 右边的默认值**永远不求值**，默认路径里的错误
    就一直是隐形的。

    * ``app.py`` 用了 ``default_dsn()`` 却没导入它 —— 所有测试与手动启动
      都传了 ``--dsn``，所以只在"用默认值启动"时才 ``NameError``。
    * 同类问题还可能出现在任何 ``x or default()`` 上。
    """

    def test_default_dsn_is_assembled(self) -> None:
        from core.storage.postgres import default_dsn

        dsn = default_dsn()
        self.assertTrue(dsn.startswith("postgresql://"), dsn)
        self.assertIn("recon", dsn)

    def test_default_dsn_without_platform_assumptions(self) -> None:
        """两个平台拼出来的连接串必须一样（只受环境变量影响）。"""
        import os
        from unittest import mock

        from core.storage.postgres import default_dsn

        with mock.patch.dict(os.environ, {}, clear=False):
            for key in ("RECON_DSN", "RECON_DB_USER", "RECON_DB_PASSWORD",
                        "RECON_DB_HOST", "RECON_DB_PORT", "RECON_DB_NAME"):
                os.environ.pop(key, None)
            self.assertEqual(
                default_dsn(), "postgresql://recon@127.0.0.1:5432/recon"
            )

    def test_password_is_url_escaped(self) -> None:
        """密码里的 ``@ : /`` 不转义会把连接串解析坏。"""
        import os
        from unittest import mock

        from core.storage.postgres import default_dsn

        with mock.patch.dict(os.environ, {"RECON_DB_PASSWORD": "p@ss:w/ord"}):
            dsn = default_dsn()
        self.assertNotIn("p@ss:w/ord", dsn, "密码没转义")
        self.assertIn("p%40ss%3Aw%2Ford", dsn)

    def test_explicit_dsn_wins(self) -> None:
        import os
        from unittest import mock

        from core.storage.postgres import default_dsn

        with mock.patch.dict(
            os.environ,
            {"RECON_DSN": "postgresql://u@h:1/d", "RECON_DB_USER": "ignored"},
        ):
            self.assertEqual(default_dsn(), "postgresql://u@h:1/d")

    def test_create_app_works_without_arguments(self) -> None:
        """``create_app()`` 不带任何参数必须能建起来（默认路径不炸）。"""
        from core.web.app import create_app

        app = create_app()          # 不启动 lifespan，只验证构造
        self.assertIsNotNone(app)


class TestFilterOpAppliesToColumnType(unittest.TestCase):
    """筛选操作符**能不能用在这类列上**要判，不能只判"认不认识这个 op"。

    ``contains`` 展开成 ``{col} ILIKE ?``。用在 int 列上时 asyncpg 会直接抛
    ``DataError``（"can't adapt type 'int' for ILIKE"）→ 接口 500。数字列本来
    也没有"子串"语义（``status=2`` 不是"含 2"），所以只能丢弃。
    """

    def test_contains_on_a_numeric_column_is_dropped(self) -> None:
        for op in ("contains", "not_contains"):
            with self.subTest(op=op):
                sql, params = _build_filter_where(
                    "urls", [{"field": "status", "op": op, "value": "2"}]
                )
                self.assertEqual((sql, params), ("", []),
                                 f"status 的 {op} 应当被丢弃，不能生成 ILIKE")

    def test_numeric_comparison_still_works(self) -> None:
        for op in ("eq", "ne", "gt", "gte", "lt", "lte"):
            with self.subTest(op=op):
                sql, params = _build_filter_where(
                    "urls", [{"field": "status", "op": op, "value": "200"}]
                )
                self.assertTrue(sql, f"status 的 {op} 是合法的，不该被丢")
                self.assertEqual(params, [200])
                self.assertNotIn("ILIKE", sql)

    def test_string_column_keeps_contains(self) -> None:
        sql, params = _build_filter_where(
            "urls", [{"field": "url", "op": "contains", "value": "admin"}]
        )
        self.assertIn("ILIKE", sql)
        self.assertEqual(params, ["%admin%"])

    def test_every_op_is_safe_on_every_numeric_field(self) -> None:
        """逐个操作符 × 逐个数字列扫一遍 —— 不留"忘了哪一个"的缝。"""
        from core.storage.postgres import _FILTER_OPS, _NUMERIC_FILTER_FIELDS

        asset_for = {"status": "urls", "port": "ports"}
        for field in _NUMERIC_FILTER_FIELDS:
            for op in _FILTER_OPS:
                with self.subTest(field=field, op=op):
                    sql, params = _build_filter_where(
                        asset_for[field], [{"field": field, "op": op, "value": "2"}]
                    )
                    if sql and params and isinstance(params[0], int):
                        self.assertNotIn(
                            "ILIKE", sql,
                            f"{field} 的 {op} 展开成 ILIKE 却传了 int → 会 500",
                        )


class TestRealDatabase(unittest.IsolatedAsyncioTestCase):
    """真库往返：只测方言适配里最容易错的那几条。"""

    async def asyncSetUp(self) -> None:
        await ensure_database()
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_insert_returns_id(self) -> None:
        """``cur.lastrowid`` 靠自动补 ``RETURNING id`` 实现。"""
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        self.assertGreater(sid, 0)
        sid2 = await self.storage.create_scan(targets=["example.org"], preset="t")
        self.assertEqual(sid2, sid + 1)

    async def test_rowcount_on_conflict_do_nothing(self) -> None:
        """幂等插入：第二次的 rowcount 必须是 0，否则 ``_resolve_ip_id``
        会拿到一个错的 id。"""
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        ev = Event(type=EventType.IP_ADDRESS, data="1.2.3.4", module="m", tags={})
        await self.storage.project(sid, ev)
        await self.storage.project(sid, ev)
        ips = await self.storage.ips(sid)
        self.assertEqual(len(ips), 1, "同一个 IP 不该插出两行")

    async def test_ilike_is_case_insensitive(self) -> None:
        """**PostgreSQL 的 LIKE 区分大小写**（SQLite 的不区分）。

        照搬 LIKE 会让"搜 admin 找不到 Admin"，是个静默漏结果。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self.storage.project(sid, Event(
            type=EventType.URL, data="http://example.com/Admin/Panel",
            module="url_extract", tags={"domain": "example.com"},
        ))
        for query in ("admin", "ADMIN", "Admin", "Panel", "panel"):
            # live=False：这条 URL 没探活过，默认的存活过滤会把它筛掉 ——
            # 这里测的是 ILIKE 的大小写语义，不是存活过滤。
            found = await self.storage.search_assets(
                query, types=["urls"], live=False
            )
            self.assertEqual(
                len(found["urls"]), 1,
                f"搜 {query!r} 没命中 —— ILIKE 没生效",
            )

    async def test_search_live_filter_excludes_unprobed(self) -> None:
        """默认只看探活确认过的资产。

        搜 qq.com 命中 15542 个域名但只有 325 个存活、27565 个 URL 只有 979 个
        —— 不过滤的话搜出来几乎全是目录爆破的产物（实测占 96%）。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        # 一条只被发现、没探过的 URL
        await self.storage.project(sid, Event(
            type=EventType.URL, data="http://example.com/admin",
            module="url_extract", tags={"domain": "example.com"},
        ))
        # 一条探活过的 URL。**http_probe 是两个事件都发的**：
        # HTTP_RESPONSE 写 http_endpoint，URL 写 url 表 —— 只发前者的话
        # url 表里不会有这一行（第一版测试就漏了这个，被断言挡下了）。
        await self.storage.project(sid, Event(
            type=EventType.HTTP_RESPONSE, data="http://example.com/admin/ok",
            module="http_probe",
            tags={"domain": "example.com", "status": 200, "host": "example.com"},
        ))
        await self.storage.project(sid, Event(
            type=EventType.URL, data="http://example.com/admin/ok",
            module="http_probe", tags={"domain": "example.com", "ip": "1.2.3.4"},
        ))

        all_urls = await self.storage.search_assets(
            "example.com", types=["urls"], live=False
        )
        live_urls = await self.storage.search_assets(
            "example.com", types=["urls"], live=True
        )
        self.assertEqual(len(all_urls["urls"]), 2, "不过滤应两条都在")
        self.assertEqual(len(live_urls["urls"]), 1, "过滤后只剩探活过的那条")

        # 计数接口也要跟着过滤
        t_all = await self.storage.search_counts("example.com", types=["urls"], live=False)
        t_live = await self.storage.search_counts("example.com", types=["urls"], live=True)
        self.assertEqual(t_all["urls"], 2)
        self.assertEqual(t_live["urls"], 1)

    async def test_concurrent_writes_do_not_lock(self) -> None:
        """换 PostgreSQL 的核心动机之一：SQLite 在这里会 ``database is locked``。"""
        import asyncio

        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")

        async def one(i: int) -> None:
            await self.storage.project(sid, Event(
                type=EventType.DNS_NAME, data=f"c{i}.example.com",
                module="bench", tags={},
            ))

        await asyncio.gather(*(one(i) for i in range(60)))
        self.assertEqual((await self.storage.summary(sid))["domains"], 60)

    async def test_boolean_columns_roundtrip(self) -> None:
        """布尔列是 BOOLEAN 而不是 0/1 —— 前端用 ``v-if`` 消费, 两种都兼容,
        但 ``MAX(bool)`` 这类合并必须走 ``OR``。"""
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self.storage.project(sid, Event(
            type=EventType.DNS_NAME, data="a.example.com", module="m",
            tags={"is_wildcard": False},
        ))
        await self.storage.project(sid, Event(
            type=EventType.DNS_NAME, data="a.example.com", module="m2",
            tags={"is_wildcard": True},
        ))
        row = (await self.storage.domains(sid))[0]
        self.assertIs(row["is_wildcard"], True, "OR 合并没生效")

    async def test_positional_access_on_real_row(self) -> None:
        """``SELECT COUNT(*)`` 那条路径。"""
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        row = await self.storage._fetchone(
            "SELECT COUNT(*) FROM domain WHERE scan_id = ?", (sid,)
        )
        self.assertEqual(row[0], 0)




    # ------------------------------------------------------------ 查询里的字面量
    async def test_events_query_escapes_like_wildcards(self) -> None:
        """事件流搜索框里输入 ``%`` **不能变成"匹配全部"**。

        ``_like()`` 转义 ``%`` 与 ``_`` 并要求 SQL 带上 ``ESCAPE '\\'``；
        ``search_assets`` / ``search_flat`` 都走它，只有 ``events()`` 以前直接
        ``f"%{query}%"`` 拼进去 —— 搜一个 ``%`` 会把所有事件都捞出来。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self.storage.save_event(
            sid, Event(type=EventType.DNS_NAME, data="cpu 100%", module="m")
        )
        await self.storage.save_event(
            sid, Event(type=EventType.DNS_NAME, data="cpu 100X", module="m")
        )
        await self.storage.save_event(
            sid, Event(type=EventType.DNS_NAME, data="host a_b", module="m")
        )
        await self.storage.save_event(
            sid, Event(type=EventType.DNS_NAME, data="host aXb", module="m")
        )

        pct, total = await self.storage.events(sid, limit=50, query="100%")
        self.assertEqual([r["data"] for r in pct], ["cpu 100%"],
                         "'%' 被当成了通配符")
        self.assertEqual(total, 1, "total 也必须跟着过滤，不能报全量")

        under, _ = await self.storage.events(sid, limit=50, query="a_b")
        self.assertEqual([r["data"] for r in under], ["host a_b"],
                         "'_' 被当成了单字符通配符")

    async def test_host_detail_findings_count_is_not_the_list_length(self) -> None:
        """详情面板的"发现"数必须是**真实总数**，不是折叠/截断后的列表长度。

        ``target LIKE '%name%'`` 会把子域的证书 / WAF 结论一起捞进来，几十条
        很常见。曾经 ``counts["findings"] = len(findings)`` 而列表固定
        ``LIMIT 50`` —— 于是面板写 50、概览写 312，用户以为还有 262 条没加载。
        这正是 ``global_stats`` 注释里写的"计数与列表必须一致"。

        ⚠️ 60 条的 detail 必须**各不相同**（2026-10-07 改）。折叠是按
        「抹掉数字后的 detail」判同的，而 ``d0``~``d59`` 抹完全一样
        → 60 条折成 1 条，这条测试就变成在测折叠、没在测截断了。
        真实场景里 60 条发现是不同的证书 / 不同的主机，每条 detail 各异。
        """
        from core.engine.event import Event, EventType

        HOST = "cnt.example.com"
        total = 60
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self.storage.project(
            sid, Event(type=EventType.DNS_NAME, data=HOST, module="m", tags={})
        )
        # ⚠️ detail 里必须有**非数字**的差异。折叠按「抹掉数字后」判同，
        # 而 ``'d' || i || '-unique-' || (1000+i)`` 抹完是 ``d#-unique-#``，
        # 60 条仍然全部相同 → 折成 1 条，这条测试就变成在测折叠了。
        # 用 ``md5`` 给出十六进制串（含 a-f 字母），数字抹不掉。
        # ⚠️ ``{i}`` 由 ``_insert_finding`` 在 **Python 端**替换（.format），
        # 不是 SQL 的 generate_series —— 写成裸 ``i`` 会报「字段 i 不存在」。
        # 而这一段整体是 f-string，所以要写成 ``{{i}}`` 才轮到 .format 那一层
        # 去替换（实测栽过：写成 ``'{i}'`` 被 f-string 先吃掉，直接 NameError）。
        await self._insert_finding(
            f"INSERT INTO finding (scan_id, kind, target, detail, severity, created_at)"
            f" VALUES ({sid}, 'cdn', '{HOST}',"
            f" 'd{{i}}-cdn-' || md5('{{i}}'), 'info', '2026-01-01')",
            total,
        )

        data = await self.storage.host_detail(HOST)
        self.assertEqual(len(data["findings"]), 50, "列表应当仍然截断到 50")
        self.assertEqual(data["counts"]["findings_shown"], 50)
        self.assertEqual(
            data["counts"]["findings"], total,
            f"计数用的是截断后的列表长度：面板说 50、实际 {total}",
        )

    async def _insert_finding(self, sql_tmpl: str, times: int) -> None:
        """把一条**无参** INSERT 模板跑 N 遍（``{i}`` 逐行替换）。

        ``finding`` 上有 ``uq_finding(scan_id, kind, target, detail)``，所以
        每行的 detail 必须不同，否则第二条就撞唯一约束。
        """
        for i in range(times):
            await self.storage.conn.execute(sql_tmpl.format(i=i))
        await self.storage.conn.commit()

    async def test_update_returns_false_when_nothing_matched(self) -> None:
        """传一个已被删掉的 id 时，接口**不能**回"保存成功"。

        ``delete_monitor`` / ``delete_group`` 早就用 ``bool(rowcount)`` 判成败，
        两个 ``update_*`` 却无条件 ``return True`` —— 改动静默丢弃。
        """
        mid = await self.storage.create_monitor(
            name="m1", targets=["example.com"], preset="passive",
        )
        self.assertTrue(await self.storage.update_monitor(mid, name="改名了"))
        self.assertEqual(
            (await self.storage.get_monitor(mid))["name"], "改名了",
            "前提：正常路径要真的写进去",
        )
        self.assertFalse(
            await self.storage.update_monitor(mid + 9999, name="改了不存在的"),
            "更新 0 行却返回 True —— 改动被静默丢弃",
        )

        gid = await self.storage.create_group(name="g1")
        self.assertTrue(await self.storage.update_group(gid, description="d"))
        self.assertFalse(
            await self.storage.update_group(gid + 9999, description="x"),
            "更新 0 行却返回 True",
        )

    async def test_title_fill_failure_is_logged(self) -> None:
        """标题回填写失败**要留线索**（截图模块删掉后，这条原则留给新方法）。

        以前测的是 ``save_screenshot``：``rowcount == 0`` 那条分支有 warning，
        而连接断了 / 权限不足 / 语句超时全被压成同一个 ``False``，调用方
        当成"还没有端点行"于是不再重试，事后查日志一条线索都没有。

        同样的坑对 ``fill_endpoint_title`` 一样成立 —— 它也是"写不进去就
        返回 False"的形状，所以这里钉住的是**行为**而不是某个方法名。
        """
        from unittest import mock

        real = self.storage._conn
        self.storage._conn = mock.AsyncMock()
        self.storage._conn.execute.side_effect = RuntimeError("connection reset")
        try:
            with self.assertLogs("recon.storage", level="WARNING") as caught:
                ok = await self.storage.fill_endpoint_title(
                    "http://x/", "统一用户中心"
                )
        finally:
            self.storage._conn = real

        self.assertFalse(ok)
        self.assertTrue(
            any("connection reset" in line for line in caught.output),
            f"异常被吞掉且没有日志：{caught.output}",
        )

class TestResponseBody(unittest.IsolatedAsyncioTestCase):
    """响应报文存取（2026-10-06 取代截图）。

    报文是"目标回了什么"—— 测绘里反复要看的东西，取代只能看"长什么样"
    的截图。判据覆盖四件容易做错的事：往返、截断要标、扫描隔离、
    **防退化成空**（新观测没抓到正文时不能把上一轮的抹掉）。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.HTTP_RESPONSE, data="http://x.example.com/a", module="m",
                tags={"url": "http://x.example.com/a", "scheme": "http", "status": 200,
                      "title": "标题", "content_type": "text/html; charset=utf-8",
                      "body_snippet": "<html>hello</html>", "body_truncated": False},
            ),
        )

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_body_roundtrip(self) -> None:
        got = await self.storage.response_body(self.sid, "http://x.example.com/a")
        self.assertIn("hello", got["body"])
        self.assertFalse(got["truncated"])
        self.assertIn("text/html", got["content_type"])

    async def test_max_bytes_truncates_and_marks(self) -> None:
        """限长返回时**必须**标 truncated —— 否则用户会拿半截当完整结论。"""
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.HTTP_RESPONSE, data="http://x.example.com/big", module="m",
                tags={"url": "http://x.example.com/big", "scheme": "http", "status": 200,
                      "content_type": "text/html", "body_snippet": "X" * 500,
                      "body_truncated": True},
            ),
        )
        got = await self.storage.response_body(
            self.sid, "http://x.example.com/big", max_bytes=50
        )
        self.assertEqual(len(got["body"]), 50)
        self.assertTrue(got["truncated"], "截断了却没标 —— 前端会当完整报文显示")

    async def test_other_scan_cannot_read_it(self) -> None:
        """别的扫描不该读到这份报文（按扫描隔离的语义要保住）。"""
        other = await self.storage.create_scan(targets=["other.com"], preset="t")
        got = await self.storage.response_body(other, "http://x.example.com/a")
        self.assertEqual(got["body"], "", "跨扫描串读了")

    async def test_empty_body_does_not_wipe_previous(self) -> None:
        """新观测没抓到正文时，**不能**把上一轮的报文清掉。

        站点改了 content-type、或这轮被 WAF 挡了，都会让 body 为空；
        若用 ``body = excluded.body`` 直接覆盖，这里的 NULL 就把
        "这个端点有报文"变成了"没有" —— 而它明明有。
        """
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.HTTP_RESPONSE, data="http://x.example.com/a", module="m",
                tags={"url": "http://x.example.com/a", "scheme": "http", "status": 502,
                      "content_type": "application/octet-stream", "body_snippet": ""},
            ),
        )
        got = await self.storage.response_body(self.sid, "http://x.example.com/a")
        self.assertIn("hello", got["body"], "这一轮没抓到正文就把旧报文抹掉了")

    async def test_non_textual_body_is_not_stored(self) -> None:
        """图片/二进制**一律不存** —— 存了在 JSON 响应里就是乱码。

        ⚠️ 这条判据**必须放在存储层**，不能只靠 ``http_probe`` 过滤：
        实测那样会漏，任何直接调 ``project()`` 的路径（测试替身、手搓事件）
        都能把二进制塞进来。放这里才是**唯一**一份判据。
        """
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.HTTP_RESPONSE, data="http://x.example.com/a.png",
                module="m",
                tags={"url": "http://x.example.com/a.png", "scheme": "http",
                      "status": 200, "content_type": "image/png",
                      "body_snippet": "\\x89PNGfake", "body_truncated": False},
            ),
        )
        got = await self.storage.response_body(self.sid, "http://x.example.com/a.png")
        self.assertEqual(got["body"], "", "二进制被存下来了")

    async def test_missing_content_type_still_stores(self) -> None:
        """没有 content-type 时**宁可存**：漏存比存乱码更可惜（乱码用户一眼看得出）。"""
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.HTTP_RESPONSE, data="http://x.example.com/nc",
                module="m",
                tags={"url": "http://x.example.com/nc", "scheme": "http",
                      "status": 200, "content_type": "",
                      "body_snippet": "<html>无 MIME</html>"},
            ),
        )
        got = await self.storage.response_body(self.sid, "http://x.example.com/nc")
        self.assertIn("无 MIME", got["body"], "没有 content-type 就把正文丢了")

    async def test_title_fill_only_when_empty(self) -> None:
        """SPA 标题回填：**只在原来为空时写**，先到的留下。"""
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.HTTP_RESPONSE, data="http://x.example.com/spa", module="m",
                tags={"url": "http://x.example.com/spa", "scheme": "http", "status": 200,
                      "title": "", "content_type": "text/html", "body_snippet": "x"},
            ),
        )
        first = await self.storage.fill_endpoint_title(
            "http://x.example.com/spa", "统一用户中心"
        )
        second = await self.storage.fill_endpoint_title(
            "http://x.example.com/spa", "另一个标题"
        )
        row = await self.storage._fetchone(
            "SELECT title FROM http_endpoint WHERE url = ?",
            ("http://x.example.com/spa",),
        )
        self.assertTrue(first, "第一次该写进去")
        self.assertFalse(second, "已经有标题了，第二次不该覆盖")
        self.assertEqual(row["title"], "统一用户中心")


class TestEndpointClusters(unittest.IsolatedAsyncioTestCase):
    """同款系统聚类（favicon 哈希 / 标题）—— 供应链横向最省力的杠杆。

    这个哈希**早就被 http_probe 采下来了**，一直躺在
    ``http_endpoint.favicon_hash`` 里没有出口。实测 panabit.com 一次扫描里
    ``1286151072`` 这个哈希对应 **8 个**子域（download/forum/miniapp/raas…）
    —— 那就是"同款系统"。
    """

    async def asyncSetUp(self) -> None:
        await ensure_database()
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _endpoint(self, scan_id, host, *, favicon=None, title=None, status=200):
        from core.engine.event import Event, EventType

        url = f"http://{host}/"
        await self.storage.project(scan_id, Event(
            type=EventType.HTTP_RESPONSE, data=url, module="http_probe",
            tags={"url": url, "domain": host, "ip": "1.1.1.1", "port": 80,
                  "scheme": "http", "status": status, "title": title,
                  "favicon_hash": favicon},
        ))

    async def test_favicon_clusters_by_hash(self) -> None:
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        for host in ("a.example.com", "b.example.com", "c.example.com"):
            await self._endpoint(sid, host, favicon="1286151072")
        await self._endpoint(sid, "solo.example.com", favicon="999")

        rows = await self.storage.endpoint_clusters(sid, by="favicon")
        self.assertEqual(len(rows), 1, f"单例不该成簇: {rows}")
        cluster = rows[0]
        self.assertEqual(cluster["key"], "1286151072")
        self.assertEqual(cluster["size"], 3)
        for host in ("a.example.com", "b.example.com", "c.example.com"):
            self.assertIn(host, cluster["hosts"])
        self.assertNotIn("solo.example.com", cluster["hosts"])

    async def test_orders_by_size_desc(self) -> None:
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        for host in ("a.example.com", "b.example.com", "c.example.com"):
            await self._endpoint(sid, host, favicon="big")
        for host in ("d.example.com", "e.example.com"):
            await self._endpoint(sid, host, favicon="small")

        rows = await self.storage.endpoint_clusters(sid, by="favicon")
        self.assertEqual([r["key"] for r in rows], ["big", "small"])

    async def test_min_size_is_respected(self) -> None:
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        for host in ("a.example.com", "b.example.com", "c.example.com"):
            await self._endpoint(sid, host, favicon="x")
        for host in ("d.example.com", "e.example.com"):
            await self._endpoint(sid, host, favicon="y")

        rows = await self.storage.endpoint_clusters(sid, by="favicon", min_size=3)
        self.assertEqual([r["key"] for r in rows], ["x"], "min_size 没生效")

    async def test_title_clustering_excludes_http_status_text(self) -> None:
        """**最常见的"同标题"是错误页。**

        实测 ``404 Not Found`` 出现 6 次、``400 The plain HTTP request was sent
        to HTTPS port`` 出现 2 次。那是"都返回了错误"，不是"同款系统" ——
        不过滤的话聚类表一半是噪声，真正有价值的 ``认证服务`` 反而被淹掉。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        for host in ("a.example.com", "b.example.com", "c.example.com"):
            await self._endpoint(sid, host, title="404 Not Found", status=404)
        await self._endpoint(sid, "d.example.com", title="400 The plain HTTP request")
        await self._endpoint(sid, "e.example.com", title="400 The plain HTTP request")
        for host in ("f.example.com", "g.example.com"):
            await self._endpoint(sid, host, title="认证服务")

        rows = await self.storage.endpoint_clusters(sid, by="title")
        keys = [r["key"] for r in rows]
        self.assertEqual(keys, ["认证服务"], f"错误页文本没被排除: {keys}")

    async def test_favicon_view_is_unaffected_by_title_filter(self) -> None:
        """按 favicon 聚时不该套标题那套过滤（两者是独立的信号）。"""
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        for host in ("a.example.com", "b.example.com"):
            await self._endpoint(sid, host, favicon="1", title="404 Not Found")
        rows = await self.storage.endpoint_clusters(sid, by="favicon")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["size"], 2)

    async def test_scope_is_per_scan_by_default(self) -> None:
        """默认**按扫描内聚** —— 跨客户目标关联有数据外泄面。"""
        sid1 = await self.storage.create_scan(targets=["a.com"], preset="t")
        sid2 = await self.storage.create_scan(targets=["b.com"], preset="t")
        await self._endpoint(sid1, "x.a.com", favicon="shared")
        await self._endpoint(sid2, "y.b.com", favicon="shared")

        per_scan = await self.storage.endpoint_clusters(sid1, by="favicon")
        self.assertEqual(per_scan, [], "不同扫描的端点不该聚在一起")

        # 显式传 None 才是全局
        global_rows = await self.storage.endpoint_clusters(None, by="favicon")
        self.assertEqual(len(global_rows), 1)
        self.assertEqual(global_rows[0]["size"], 2)
        self.assertIn("x.a.com", global_rows[0]["hosts"])
        self.assertIn("y.b.com", global_rows[0]["hosts"])

    async def test_rows_without_the_field_are_skipped(self) -> None:
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self._endpoint(sid, "a.example.com")           # 没 favicon 也没标题
        await self._endpoint(sid, "b.example.com")
        self.assertEqual(await self.storage.endpoint_clusters(sid, by="favicon"), [])
        self.assertEqual(await self.storage.endpoint_clusters(sid, by="title"), [])

    async def test_unknown_by_raises(self) -> None:
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        with self.assertRaises(ValueError):
            await self.storage.endpoint_clusters(sid, by="server")


class TestSearchIndex(unittest.IsolatedAsyncioTestCase):
    """``pg_trgm`` 的 GIN 索引。

    其余测试都关掉了索引（18 个 GIN 索引 × 266 个测试太慢），所以**索引本身
    必须有专门的一条**, 否则"索引能建起来"这件事没人验证。
    """

    async def asyncSetUp(self) -> None:
        await ensure_database()
        self.schema = new_schema()
        self.storage = PostgresStorage(
            DSN, schema=self.schema, create_search_index=True
        )
        await self.storage.open()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_extension_and_indexes_exist(self) -> None:
        self.assertTrue(self.storage.search_indexed, "检索索引没建起来")
        conn = await asyncpg.connect(DSN)
        try:
            ext = await conn.fetchval(
                "SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm'"
            )
            self.assertEqual(ext, 1, "pg_trgm 扩展没装上")
            n = await conn.fetchval(
                """
                SELECT COUNT(*) FROM pg_indexes
                WHERE schemaname = $1 AND indexname LIKE 'trgm!_%' ESCAPE '!'
                """,
                self.schema,
            )
            self.assertGreaterEqual(n, 15, f"trigram 索引只有 {n} 个")
        finally:
            await conn.close()

    async def test_ilike_uses_the_index(self) -> None:
        """确认 GIN 索引真的会被 ``ILIKE '%x%'`` 用上。

        这是换 pg_trgm 而不是 tsvector 的**全部理由** —— 查询语义不变、
        但能从全表扫描变成索引扫描。不验证这一条, 索引就只是摆设。

        两点是为**确定性**特意选的, 都不是作弊:

        * **查 ``source`` 而不是 ``url``。** ``url`` 列上还有 ``uq_url_dedup``
          这个 btree，对它做前导通配的 ILIKE 虽然没用、但"全扫索引"比
          GIN 便宜，规划器会选它 —— 实测 5000 行时选那条、20000 行
          才选 trgm。靠调行数来断言是脆的；``source`` 上只有 trgm 索引，
          没有竞争者，断言就是确定的。
        * **``enable_seqscan = off``。** GIN 启动成本高，小表上顺序扫描
          确实更便宜（规划器算得没错）。关掉它才是问"这个索引对这条查询
          **可不可用**"，而那正是要断言的事。
        """
        conn = await asyncpg.connect(DSN)
        try:
            await conn.execute(f'SET search_path TO "{self.schema}", public')
            sid = await conn.fetchval(
                "INSERT INTO scan (targets_json, preset, status, started_at) "
                "VALUES ('[]', 't', 'running', 'now') RETURNING id"
            )
            rows = [
                (sid, f"http://h{i}.example.com/p/{i}", f"h{i}.example.com",
                 "url_extract", "link", "now", "now")
                for i in range(200)
            ]
            rows.append((sid, "http://example.com/a", "example.com",
                         "js_assets", "js_url", "now", "now"))
            await conn.copy_records_to_table(
                "url",
                records=rows,
                columns=("scan_id", "url", "host", "source", "kind",
                         "first_seen", "last_seen"),
            )
            await conn.execute("ANALYZE url")

            await conn.execute("SET enable_seqscan = off")
            plan = await conn.fetch(
                "EXPLAIN SELECT url FROM url WHERE source ILIKE $1", "%js_assets%"
            )
            text = " ".join(r[0] for r in plan)
            self.assertIn(
                "trgm_url_source", text,
                f"索引对 ILIKE 不可用，实际计划:\n{text}",
            )
        finally:
            await conn.close()


class TestUrlUpsertSchemesNotNull(IsolatedAsyncioTestCase):
    """``url`` 的 UPSERT **不能把 ``schemes`` 写成 NULL**。

    ## 起因

    ``schemes`` 列是 ``TEXT[] NOT NULL``，而合并写法是::

        schemes = (SELECT array_agg(DISTINCT s ORDER BY s)
                   FROM unnest(url.schemes || excluded.schemes) AS s)

    ``array_agg`` 遇到**零行**返回 NULL（不是空数组）。而"零行"的真实触发
    条件很容易凑齐：写点给的是 ``[scheme] if scheme else []``，所以只要这条
    URL 解析不出 scheme 就是空数组 —— protocol-relative 的 ``//host/path``
    与裸路径都算（``split_url`` 对它们返回 ``''``），而 ``url_extract`` 正是
    从网页正文里抽链接，抽到 protocol-relative 是家常便饭。

    两边都空 → ``unnest('{}' || '{}')`` 零行 → ``array_agg`` → NULL → 撞
    NOT NULL 约束（SQLSTATE 23502），**整条 UPSERT 回滚**：``last_seen`` 没
    推进、该 URL 这轮直接丢。异常被 ``scanner.py`` 的 ``except Exception``
    吞成一行 error 日志，不看日志完全察觉不到。

    ## 为什么"投影两次"是必要的条件

    第一次是 INSERT，不走 ``DO UPDATE`` 子句，所以正常写进空数组。必须**第二
    次**才进冲突分支。重复投影不是假设：``_link_asset`` 的文档明确说同一次
    扫描内重复事件会重新投影，第二轮扫描更是必然。

    判据是**真库真抛异常** + 行还在不在，不从被测 SQL 文本自证。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.scan_id = await self.storage.create_scan(
            targets=["example.com"], preset="t"
        )

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _project(self, data: str) -> None:
        await self.storage.project(
            self.scan_id,
            Event(
                type=EventType.URL, data=data, module="url_extract",
                tags={"source": "url_extract", "kind": "link"},
            ),
        )

    async def test_scheme_less_url_survives_reprojection(self) -> None:
        """无 scheme 的 URL 被重复投影时不能抛 NOT NULL 违例。"""
        for data in ("/admin", "//x.example.com/a", "http://x.example.com/b"):
            with self.subTest(data=data):
                await self._project(data)          # 第一次: INSERT
                try:
                    await self._project(data)      # 第二次: 冲突分支
                except Exception as e:  # noqa: BLE001
                    self.fail(
                        f"第二次投影 {data!r} 抛异常 {type(e).__name__}: {e}\n"
                        f"这会让整条 UPSERT 回滚，资产丢失且只有一行 error 日志"
                    )

    async def test_scheme_less_url_keeps_advancing_last_seen(self) -> None:
        """修完之后重复投影还必须真的推进 ``last_seen``。

        只断言"没抛异常"不够 —— 那也可能是**静默回滚**。所以补一条正向断言：
        冲突分支跑完之后，行的 ``last_seen`` 应当是更新过的（这里用
        ``first_seen`` 与 ``last_seen`` 拉开时间来判定）。
        """
        await self._project("//y.example.com/a")
        await self.storage.conn.execute(
            "UPDATE url SET first_seen = '2000-01-01T00:00:00+00:00' "
            "WHERE dedup_key = 'y.example.com|/a'"
        )
        await self._project("//y.example.com/a")

        row = await self.storage._fetchone(
            "SELECT first_seen, last_seen, schemes FROM url "
            "WHERE dedup_key = 'y.example.com|/a'"
        )
        self.assertIsNotNone(row, "冲突分支把行回滚掉了")
        self.assertNotEqual(
            row["first_seen"], row["last_seen"],
            "last_seen 没有被冲突分支更新 —— 说明 UPDATE 实际没生效",
        )
        self.assertEqual(list(row["schemes"]), [], "无 scheme 不该凭空长出协议")

    async def test_scheme_merge_still_unions(self) -> None:
        """对照组：带 scheme 的**并集语义不能被上面那处修复破坏**。

        防止有人用"清空 schemes"来躲开 NOT NULL —— 那会把 ``schemes`` 这个
        暴露面事实（同一个路径 http 与 https 都通）整个丢掉。
        """
        await self._project("http://z.example.com/p")
        await self._project("https://z.example.com/p")   # 同一 dedup_key

        row = await self.storage._fetchone(
            "SELECT schemes FROM url WHERE dedup_key = 'z.example.com|/p'"
        )
        self.assertIsNotNone(row, "两次不同 scheme 应该合成一行")
        self.assertEqual(sorted(row["schemes"]), ["http", "https"])

    async def test_parent_url_is_not_lost_on_reprojection(self) -> None:
        """``parent_url`` 会在冲突时被**静默丢弃** —— 它是唯一会真丢的列。

        ``parent_url`` 可空，写点是 ``str(tags.get("from") or "") or None``：
        事件没带 ``from`` 标签时就是 NULL。同一 dedup_key 第二次投影若带了
        ``from``（先被 url_extract 抽到、后被 js_assets 验证并指明出处），
        而 ON CONFLICT 子句没列这一项 —— 更完整的那次观察就没了，
        这一行永久停在 NULL，"这条路径是从哪发现的"永久查不到。
        """
        await self.storage.project(
            self.scan_id,
            Event(type=EventType.URL, data="http://p.example.com/a", module="m1",
                  tags={"source": "m1", "kind": "link"}),
        )
        row = await self.storage._fetchone(
            "SELECT parent_url FROM url WHERE dedup_key = 'p.example.com|/a'"
        )
        self.assertIsNone(row["parent_url"], "前置条件：第一次应当是 NULL")

        # 第二次带 from（更完整的信息）
        await self.storage.project(
            self.scan_id,
            Event(type=EventType.URL, data="http://p.example.com/a", module="m2",
                  tags={"source": "m2", "kind": "js_path",
                        "from": "http://p.example.com/app.js"}),
        )
        row = await self.storage._fetchone(
            "SELECT parent_url FROM url WHERE dedup_key = 'p.example.com|/a'"
        )
        self.assertEqual(
            row["parent_url"], "http://p.example.com/app.js",
            "后一次更完整的出处被静默丢弃了",
        )

    async def test_parent_url_is_not_erased_by_a_bare_reprojection(self) -> None:
        """反向护栏：补齐之后，新的空观测**不能**把已有出处抹掉。"""
        await self.storage.project(
            self.scan_id,
            Event(type=EventType.URL, data="http://q.example.com/a", module="m1",
                  tags={"source": "m1", "from": "http://q.example.com/i.js"}),
        )
        await self.storage.project(
            self.scan_id,
            Event(type=EventType.URL, data="http://q.example.com/a", module="m2",
                  tags={"source": "m2"}),
        )
        row = await self.storage._fetchone(
            "SELECT parent_url FROM url WHERE dedup_key = 'q.example.com|/a'"
        )
        self.assertEqual(row["parent_url"], "http://q.example.com/i.js")


class TestTechnologyEvidenceUpsert(IsolatedAsyncioTestCase):
    """``technology.evidence`` 为 NULL 时，后续真实证据**必须写得进去**。

    ## 起因（三值逻辑）

    列是可空的，写点传的是 ``tags.get("evidence")``（没有 ``or ""`` 归一，
    而同一段的 category/version/vendor/product 都做了归一 —— 就这一列漏了）。
    合并条件写的是::

        CASE WHEN technology.evidence = '' OR technology.implied THEN ...

    第一次落库 evidence 为 NULL、implied 为 false 时：
    ``NULL = ''`` → NULL，``NULL OR false`` → NULL，CASE 走 ELSE 保留 NULL。
    于是**之后无论多少次带真实证据的直接命中都写不进去** —— 该技术在资产
    检索和 host_detail 里永远没有证据可显示。

    对照：把条件改成 ``evidence IS NULL OR evidence = '' OR implied`` 就好
    （已在真库上验过条件求值从 NULL 变成 true）。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.scan_id = await self.storage.create_scan(
            targets=["example.com"], preset="t"
        )

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _project(self, evidence: str | None, *, implied: bool) -> None:
        tags: dict[str, object] = {
            "host": "t.example.com", "implied": implied,
            "category": "web", "version": "", "vendor": "", "product": "",
        }
        if evidence is not None:
            tags["evidence"] = evidence
        await self.storage.project(
            self.scan_id,
            Event(type=EventType.TECHNOLOGY, data="SomeTech", module="fp", tags=tags),
        )

    async def test_null_evidence_gets_filled_by_later_hit(self) -> None:
        # 第一次没有证据（tags 里根本没有 evidence 键）
        await self._project(None, implied=False)
        row = await self.storage._fetchone(
            "SELECT evidence FROM technology WHERE host = 't.example.com'"
        )
        self.assertIsNotNone(row)
        self.assertIsNone(row["evidence"], "前置条件：第一次应当是 NULL")

        # 第二次带真实证据的直接命中
        await self._project("header: X-Powered-By", implied=False)
        row = await self.storage._fetchone(
            "SELECT evidence FROM technology WHERE host = 't.example.com'"
        )
        self.assertEqual(
            row["evidence"], "header: X-Powered-By",
            "NULL evidence 让 CASE 的 WHEN 求值为 NULL，真实证据永远写不进去",
        )

    async def test_null_evidence_gets_filled_by_direct_hit_over_implied(self) -> None:
        """先来一条**推断命中**（无证据），再来一条直接命中，也必须能顶掉。"""
        await self._project(None, implied=True)
        await self._project("body: nginx", implied=False)
        row = await self.storage._fetchone(
            "SELECT evidence, implied FROM technology WHERE host = 't.example.com'"
        )
        self.assertEqual(row["evidence"], "body: nginx")
        self.assertFalse(row["implied"], "直接命中应当把推断标记也清掉")

    async def test_first_real_evidence_is_not_overwritten(self) -> None:
        """反向护栏：已经有证据的行，**不该**被后来的空证据冲掉。"""
        await self._project("header: A", implied=False)
        await self._project(None, implied=False)
        row = await self.storage._fetchone(
            "SELECT evidence FROM technology WHERE host = 't.example.com'"
        )
        self.assertEqual(row["evidence"], "header: A")


class TestGraphRescanKeepsEdges(IsolatedAsyncioTestCase):
    """关系图的**边**必须与节点同口径：都按"这次扫描看到过"来算。

    ## 起因

    资产跨 scan 去重之后，``domain.scan_id`` 只表示"**谁最先发现的**"。
    节点走 ``self.domains(scan_id)``（经 ``scan_asset``，能查到重扫看到的
    老域名），而 ``resolves_to`` 边原先按 ``d.scan_id = ?`` 过滤 ——
    第二次扫描时域名行仍挂在首次发现者名下，那条查询**零行**。

    症状很有迷惑性：域名节点、IP 节点都画出来了，**只有边全没了**，
    看着像前端渲染问题，而根因在 SQL。

    ## 判据

    两次扫描同一组资产，断言**两次都有 resolves_to 边**。只断言"边不为空"
    是不够的 —— 第一次扫描本来就有边，恒绿。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.s1 = await self.storage.create_scan(targets=["example.com"], preset="t")
        self.s2: int | None = None

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _seed(self, scan_id: int) -> None:
        await self.storage.project(
            scan_id,
            Event(type=EventType.DNS_NAME, data="www.example.com", module="m"),
        )
        await self.storage.project(
            scan_id,
            Event(
                type=EventType.IP_ADDRESS, data="1.2.3.4", module="m",
                parent_data="www.example.com",
            ),
        )

    async def test_edges_present_on_both_first_and_rescan(self) -> None:
        await self._seed(self.s1)
        g1 = await self.storage.graph(self.s1)
        edges1 = [e for e in g1["edges"] if e["relation"] == "resolves_to"]
        self.assertTrue(edges1, f"第一次扫描就应当有边，实际: {g1['edges']}")

        # 第二次扫描看同一批资产（资产表全局唯一，scan_id 仍记在第一次名下）
        self.s2 = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self._seed(self.s2)

        g2 = await self.storage.graph(self.s2)
        edges2 = [e for e in g2["edges"] if e["relation"] == "resolves_to"]
        self.assertTrue(
            edges2,
            f"重扫时 resolves_to 边全丢（节点 {len(g2['nodes'])} 个）—— "
            f"边还在按 d.scan_id 过滤，而节点走的是 scan_asset",
        )


class TestGroupAssetSearchEscaping(IsolatedAsyncioTestCase):
    """组内资产搜索框必须转义 LIKE 通配符。

    ``_`` 在 LIKE 里是"匹配任意单字符"、``%`` 是"匹配一切"。不转义的话
    搜 ``a_b`` 会把 ``axb`` 一起带出来，搜 ``%`` 直接列出全组资产 ——
    而 **total 与列表用了同一个错误模式**，数字看着还自洽，特别难发现。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        now = "2026-01-01T00:00:00+00:00"
        cur = await self.storage.conn.execute(
            "INSERT INTO asset_group (name, created_at) VALUES ('g', ?)", (now,)
        )
        self.gid = int(cur.lastrowid)
        for key in ("a_b", "axb", "zzz"):
            await self.storage.conn.execute(
                "INSERT INTO asset_group_asset "
                "(group_id, asset_type, asset_key, first_seen, last_seen) "
                "VALUES (?, 'ip', ?, ?, ?)",
                (self.gid, key, now, now),
            )

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_underscore_is_literal(self) -> None:
        """搜 ``a_b`` 只该命中字面量那一条，不能把 ``axb`` 带出来。"""
        got = await self.storage.list_group_assets(self.gid, q="a_b")
        keys = [r["asset_key"] for r in got["rows"]]
        self.assertEqual(keys, ["a_b"], f"下划线没被转义: {keys}")
        self.assertEqual(got["total"], 1, "total 也用了同一个错误模式")

    async def test_percent_does_not_match_everything(self) -> None:
        got = await self.storage.list_group_assets(self.gid, q="%")
        self.assertEqual(got["total"], 0, f"搜 %% 竟列出了 {got['total']} 条")


class TestGroupSyncCountsAndGlobalStats(IsolatedAsyncioTestCase):
    """两处**计数**口径：同步新增数不能互相覆盖，概览要与列表一致。"""

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.sid = await self.storage.create_scan(targets=["example.com"], preset="t")

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_domain_and_cidr_scopes_accumulate_ip_count(self) -> None:
        """域名范围 + 网段范围**同时**配了时，IP 数要累加而不是被覆盖。

        两段各自 ``ON CONFLICT DO NOTHING`` 去重、各自报"我新插了几条"，
        但原先第二段是**直接赋值** —— 域名范围带进来的 IP 数被整段吃掉。
        数据照样入库了，丢的只是回给 UI 的那个数字，而它正是用户判断
        "这次同步带进来多少东西"的依据。

        ## 判据为什么这么写（这里有个陷阱，值得记下来）

        原先想造"两段各收一个不同 IP"让覆盖(得 1)与累加(得 2)拉开差异，
        **两次都造不出来**，两次都是恒绿：

        1. 只造「域名 + 端口」而没有 ``http_endpoint`` → 域名范围那段的
           ``rowcount`` 恒为 0，两种写法结果相同。
        2. 把域名段的 IP 放到网段**外**、只靠端点进来 → 域名段那段是按端点的
           ``e.host`` 匹配的，而 ``http_probe`` 产出的事件**根本不传 host 标签**
           （见 http_probe.py::_emit 的 tags），host 由 ``domain or ip`` 推出，
           生产数据里既可能是域名也可能是 IP。硬塞 ``host='b.example.com'``
           造出来的数据在真实链路里不会出现；且一旦该 IP 也在网段内，
           网段那段会一起收掉，两段 rowcount 互补 → 仍然恒绿。

        所以退一步断言**真正可验证**的性质：返回值与实际入库条数一致。
        覆盖写法在"两段都有贡献"时会返回更小的数、与入库条数对不上；
        累加写法两者恒等。这条判据不依赖"两段是否重叠"，也不依赖
        只有测试才造得出的数据形态。
        """
        # IP A：在网段内、有端口 -> 必然被「网段范围」那段收走
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.IP_ADDRESS, data="10.1.2.3", module="m",
                parent_data="a.example.com",
            ),
        )
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.OPEN_TCP_PORT, data="10.1.2.3:80", module="m",
                tags={"ip": "10.1.2.3", "port": 80, "protocol": "tcp"},
            ),
        )
        # IP B：也在网段内，但有端点 -> 「域名范围」那段**可能**也收它
        #（按端点 host 匹配；生产数据里 host 可能是域名也可能是 IP）
        await self.storage.project(
            self.sid,
            Event(type=EventType.DNS_NAME, data="b.example.com", module="m"),
        )
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.IP_ADDRESS, data="10.9.9.9", module="m",
                parent_data="b.example.com",
            ),
        )
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.HTTP_RESPONSE, data="http://b.example.com/",
                module="m",
                tags={"url": "http://b.example.com/", "scheme": "http",
                      "domain": "b.example.com", "ip": "10.9.9.9", "port": 80,
                      "status": 200},
            ),
        )
        # 组 = 这一次扫描扫出来的资产（范围改成"按任务"后不再有手填的范围）
        now = "2026-01-01T00:00:00+00:00"
        cur = await self.storage.conn.execute(
            "INSERT INTO asset_group (name, created_at) VALUES ('g', ?)", (now,)
        )
        gid = int(cur.lastrowid)
        result = (await self.storage.set_group_scans(gid, [self.sid]))["counts"]
        in_group = await self.storage._fetchone(
            "SELECT COUNT(*) AS c FROM asset_group_asset "
            "WHERE group_id = ? AND asset_type = 'ip'",
            (gid,),
        )
        stored = int(in_group["c"])
        self.assertGreater(stored, 0, "夹具没生效：一个 IP 都没进组")
        self.assertEqual(
            result.get("ip", 0), stored,
            f"返回的 IP 数 {result.get('ip')} 与实际入库 {stored} 对不上：{result}",
        )

    async def test_group_sync_is_idempotent(self) -> None:
        """重复同步必须**幂等**：第二次新增数应为 0，不得重复计。"""
        await self.storage.project(
            self.sid,
            Event(type=EventType.IP_ADDRESS, data="10.1.2.3", module="m",
                  parent_data="a.example.com"),
        )
        await self.storage.project(
            self.sid,
            Event(type=EventType.OPEN_TCP_PORT, data="10.1.2.3:80", module="m",
                  tags={"ip": "10.1.2.3", "port": 80, "protocol": "tcp"}),
        )
        now = "2026-01-01T00:00:00+00:00"
        cur = await self.storage.conn.execute(
            "INSERT INTO asset_group (name, created_at) VALUES ('g', ?)", (now,)
        )
        gid = int(cur.lastrowid)
        await self.storage.set_group_scans(gid, [self.sid])

        # ⚠️ 判据是"再同步一次，计数一模一样"。``sync_group`` 返回的是**当前
        # 成员数**而不是"这次新增几条"（范围改成按任务后接口契约变了），
        # 拿"第二次新增应为 0"去判，恒真 —— 第二次返回的仍是总数。
        first = dict(await self.storage.sync_group(gid))
        second = dict(await self.storage.sync_group(gid))
        self.assertGreater(first.get("ip", 0), 0, "第一次同步就该有 IP")
        self.assertEqual(
            second, first,
            f"重复同步后计数从 {first} 变成 {second} —— 同一条资产被重复计了",
        )

    async def _reverse_domain_summary(self, ip_id: int) -> str:
        """直接跑 ``ips`` 规格里那段 ``dn.name`` 表达式，取出截断后的串。

        ## 为什么绕开 search_flat

        「有域名映射的 IP 不再单列」这条规则（同文件
        :class:`TestMappedIpsAreFoldedIntoDomain`）会把挂了域名的 IP 从列表里
        滤掉 —— 而反查域名**只可能出现在有域名映射的 IP 上**。所以拿列表测它
        必然搜不到，测试就变成"断言夹具失效"。

        而截断本身是那段 SQL 的性质，与它出现在哪张表里无关。所以这里直接用
        同一段表达式（从 :data:`core.storage.postgres._SEARCH_SPECS` 取，
        不复制一份）查一次 —— 测的是 SQL 逻辑本身。
        """
        from core.storage.postgres import _SEARCH_SPECS

        join = _SEARCH_SPECS["ips"].join
        # 截取"反查域名"那一个 LATERAL（含 "LEFT JOIN LATERAL ... dn ON TRUE"
        # 整块）—— 它自带闭合括号，整体搬过来才不会出现括号不配对。
        # 从 string_agg 往前找**最近的**那个 LATERAL（前面还有一个取端点的 ep，
        # 别抓错）。用 rfind 而不是写死偏移 —— 改动这段 SQL 时偏移会失效。
        anchor = join.index("string_agg")
        block_start = join.rindex("LEFT JOIN LATERAL (", 0, anchor)
        block_end = join.index(") dn ON TRUE", block_start) + len(") dn ON TRUE")
        block = join[block_start:block_end]
        sql = f"SELECT dn.name FROM ip t {block} WHERE t.id = ?"
        row = await self.storage._fetchone(sql, (ip_id,))
        return (row["name"] or "") if row else ""

    async def test_ip_reverse_domains_are_truncated(self) -> None:
        """IP 行的反查域名**必须有上限** —— 不能把全部域名拼成一串。

        CDN / 共享主机上一个 IP 解析到几十个域名是常事（实测 yealink 的
        183.251.103.227 有 23 个），全量 ``string_agg`` 出来 644 字，界面
        一行放不下也读不出重点。

        规则：按字典序取前 2 个，超出时补「等 N 个域名」。取字典序是为了
        **确定性** —— 同一批数据每次都拼出同样的字符串，不随扫描顺序抖动。
        """
        now = "2026-01-01T00:00:00+00:00"
        cur = await self.storage.conn.execute(
            "INSERT INTO ip (scan_id, addr, first_seen, last_seen) "
            "VALUES (?, '9.9.9.9', 'now', 'now')",
            (self.sid,),
        )
        ip_id = int(cur.lastrowid)
        for name in (f"h{i}.cdn.example.com" for i in range(12)):
            await self.storage.project(
                self.sid, Event(type=EventType.DNS_NAME, data=name, module="m")
            )
            row = await self.storage._fetchone(
                "SELECT id FROM domain WHERE name = ?", (name,)
            )
            await self.storage.conn.execute(
                "INSERT INTO domain_ip (domain_id, ip_id, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?)",
                (int(row["id"]), ip_id, now, now),
            )
        await self.storage.conn.commit()

        extra = await self._reverse_domain_summary(ip_id)
        self.assertTrue(extra, "反查域名整列为空了")
        self.assertIn(
            "等 12 个域名", extra,
            f"12 个域名没被截断成摘要：{extra!r}",
        )
        # 只留 2 个 + 摘要，整体长度应当很短
        self.assertLess(
            len(extra), 120,
            f"截断后仍然太长，界面放不下：{len(extra)} 字 {extra!r}",
        )

    async def test_few_ip_reverse_domains_are_listed_in_full(self) -> None:
        """反向护栏：不超过 2 个时**原样全列**，别硬加「等 N 个」。

        截断是为了解决"太长"，不是为了统一格式。只剩一两个域名还写成
        "… 等 1 个域名"是把简单事说复杂。
        """
        now = "2026-01-01T00:00:00+00:00"
        cur = await self.storage.conn.execute(
            "INSERT INTO ip (scan_id, addr, first_seen, last_seen) "
            "VALUES (?, '8.8.8.8', 'now', 'now')",
            (self.sid,),
        )
        ip_id = int(cur.lastrowid)
        for name in ("only.example.com", "two.example.com"):
            await self.storage.project(
                self.sid, Event(type=EventType.DNS_NAME, data=name, module="m")
            )
            row = await self.storage._fetchone(
                "SELECT id FROM domain WHERE name = ?", (name,)
            )
            await self.storage.conn.execute(
                "INSERT INTO domain_ip (domain_id, ip_id, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?)",
                (int(row["id"]), ip_id, now, now),
            )
        await self.storage.conn.commit()

        extra = await self._reverse_domain_summary(ip_id)
        self.assertNotIn("等", extra, f"只有 2 个域名却加了摘要：{extra!r}")
        self.assertIn("only.example.com", extra)
        self.assertIn("two.example.com", extra)

    async def test_global_port_count_includes_protocol(self) -> None:
        """概览的端口数必须与 ``port`` 表的行数一致 —— 身份含 protocol。

        ``port_key`` 把 protocol 算进身份（``ip|port|protocol``），
        概览原先只按 ``ip:port`` 去重，同一 IP 同一端口号上 tcp+udp 会被
        合成一条，于是概览数字比资产管理页的列表少。
        """
        await self.storage.conn.execute(
            "INSERT INTO ip (scan_id, addr, first_seen, last_seen) "
            "VALUES (?, '1.2.3.4', 'now', 'now')",
            (self.sid,),
        )
        ip_row = await self.storage._fetchone(
            "SELECT id FROM ip WHERE addr = '1.2.3.4'"
        )
        for proto in ("tcp", "udp"):
            await self.storage.conn.execute(
                "INSERT INTO port (scan_id, ip_id, ip, port, protocol, "
                "first_seen, last_seen) "
                "VALUES (?, ?, '1.2.3.4', 53, ?, 'now', 'now')",
                (self.sid, int(ip_row["id"]), proto),
            )
        rows = await self.storage._fetchone("SELECT COUNT(*) AS c FROM port")
        stats = await self.storage.global_stats()
        self.assertEqual(
            int(rows["c"]), 2, "夹具没生效：应当有 2 条（tcp + udp）"
        )
        self.assertEqual(
            stats["ports"], 2,
            "概览把 tcp/udp 合成一条了，与端口列表对不上",
        )


class TestStatusFilterIsNotSilentlyDropped(IsolatedAsyncioTestCase):
    """``status`` 筛选字段**六种类型都要有**（2026-10-07）。

    ## 为什么这条是机械断言

    ``_build_filter_where`` 对**未知字段**是静默 ``continue`` —— 这是给
    "前端加了新字段时后端不要 500" 留的兼容性设计。代价是：**字段没配就
    等于没筛**，不报错、计数不变、界面上就是"下拉点了没反应"。

    实测踩过两次：

    * 只有 ``urls`` 配了 ``status`` 时，资产管理页的域名/IP 筛选完全无效
      （40 → 40，一条没少）
    * 补到四种后，``all`` 模式筛 2xx 仍混进 ``status=403`` 的行 ——
      ``technologies`` / ``findings`` 也没配，放行了 31 条

    所以这里**逐类型断言字段存在**，而不是只测"某个类型能筛"。
    """

    #: 与 ``_FLAT_SPECS`` 那列保持一致（都取 ``ep.status``）——
    #: 筛选用的列和显示用的列必须是同一个，否则"筛出来的"和"看到的"对不上。
    EXPECTED = {
        "domains": "ep.status",
        "ips": "ep.status",
        "ports": "ep.status",
        "urls": "e.status",
        "technologies": "ep.status",
        "findings": "ep.status",
    }

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    def test_every_type_can_filter_by_status(self) -> None:
        from core.storage.postgres import _ASSET_FILTER_FIELDS

        for atype, col in self.EXPECTED.items():
            with self.subTest(atype=atype):
                fields = _ASSET_FILTER_FIELDS.get(atype, {})
                self.assertIn(
                    "status", fields,
                    f"{atype} 没配 status 筛选字段 → 筛选被静默丢弃，"
                    f"界面上表现为「点了没反应」",
                )
                self.assertEqual(
                    fields["status"], col,
                    f"{atype} 的 status 列引用与 _FLAT_SPECS 不一致 —— "
                    f"筛出来的行和显示的状态码会对不上",
                )

    def test_status_is_treated_as_a_numeric_column(self) -> None:
        """``status`` 必须在数字列名单里。

        不在的话 ``contains`` 之类会展开成 ``ILIKE``，拿 int 当模式喂给
        asyncpg 直接报错；更重要的是范围比较（gte/lt）根本没法用 ——
        而 2xx/3xx/4xx/5xx 正是靠两条范围条件实现的。
        """
        from core.storage.postgres import _NUMERIC_FILTER_FIELDS

        self.assertIn("status", _NUMERIC_FILTER_FIELDS)

    async def test_status_range_filter_never_leaks_other_buckets(self) -> None:
        """按范围筛 2xx，返回的行**不能**混进 3xx/4xx/5xx。

        这条是端到端版本：只断言"字段存在"不够 —— 列引用写错了（比如
        指到另一张表的 status）字段照样存在，筛出来却是乱的。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        d = Event(type=EventType.DNS_NAME, data="a.example.com", module="m")
        await self.storage.save_event(sid, d)
        await self.storage.project(sid, d)
        # 三个不同档位各一个
        for name, code in (("ok", 200), ("moved", 301), ("boom", 500)):
            host = f"{name}.example.com"
            e = Event(type=EventType.DNS_NAME, data=host, module="m")
            await self.storage.save_event(sid, e)
            await self.storage.project(sid, e)
            ep = Event(
                type=EventType.HTTP_RESPONSE, data=f"https://{host}/",
                module="http_probe",
                tags={"domain": host, "host": host, "ip": "203.0.113.7",
                      "port": 443, "status": code, "scheme": "https"},
            )
            await self.storage.save_event(sid, ep)
            await self.storage.project(sid, ep)

        filt = [{"field": "status", "op": "gte", "value": 200},
                {"field": "status", "op": "lt", "value": 300}]
        got = await self.storage.search_flat(
            "example.com", types=["domains"], live=True, limit=50,
            filters=filt,
        )
        codes = sorted(r["status"] for r in got["rows"]
                       if r["status"] is not None)
        self.assertEqual(
            codes, [200],
            f"筛 2xx 却混进了别的档位：{codes}",
        )


class TestOwnershipStrengthIsExposed(IsolatedAsyncioTestCase):
    """IP 行要能区分「真归属」与「同段邻居」（2026-10-07）。

    ## 为什么这条要紧

    C 段扫描会整段展开一个 /24，而段里**绝大多数机器属于别人**。实测
    ``111.0.248.0/24``：254 个 IP 里只有 4 个真的解析到
    ``www.yealink.com.cn``，另外 250 个是同一台 SLB 后面的其他租户 ——
    它们返回一样的 ``Server: Tengine`` 和一样的 403，但那**不是**归属证据。

    这两类平铺在同一张表里、标签一模一样时，用户只能靠"一大片 403 看着
    像别人的"自己判断 —— 而同一台负载均衡后面的机器响应特征完全一致，
    恰恰是最容易误判的地方。所以后端必须把这个区别**算出来**，
    让界面能标出来。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_neighbor_ips_are_kept_out_of_the_asset_list(self) -> None:
        """归属只能推断的 IP **不进**资产列表（2026-10-07）。

        C 段扫描展开出的 IP 里绝大多数属于别人（全库 803 个归属只是
        "同段推断"）。它们留在主列表里，用户只能靠"一大片 403 看着像
        别人的"自己判断 —— 而同一台负载均衡后面的机器响应特征完全一致，
        这恰恰是最容易误判的地方。

        **它们没有被丢弃**：任务详情的「C 段探测」页签按 /24 聚合展示
        （归属证据 / 本段扫出 / 已知主机），那才是这个口径该待的地方。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        # ⚠️ 必须先建域名行 —— ``domain_ip`` 关联要求 parent 那个域名**已存在**
        # （``project`` 里是 ``SELECT id FROM domain WHERE name = ?`` 查到了才建）。
        # 不建的话那两个 IP 压根没有域名映射，会掉进 ``none`` 档而不被本过滤命中。
        d = Event(type=EventType.DNS_NAME, data="www.example.com", module="m")
        await self.storage.save_event(sid, d)
        await self.storage.project(sid, d)
        # 两个 DNS 解析出来的 IP（真归属）
        for ip in ("93.184.216.7", "93.184.216.8"):
            e = Event(type=EventType.IP_ADDRESS, data=ip, module="m",
                      parent_data="www.example.com")
            await self.storage.save_event(sid, e)
            await self.storage.project(sid, e)
        # 三个只有 netblock 标记、没有域名映射的 —— 同段邻居
        for n in (1, 2, 3):
            e = Event(type=EventType.IP_ADDRESS, data=f"93.184.216.{n}",
                      module="netblock_expand",
                      tags={"netblock": "93.184.216.0/24"})
            await self.storage.save_event(sid, e)
            await self.storage.project(sid, e)

        rows = (await self.storage.search_flat(
            "93.184.216", types=["ips"], live=False, limit=50
        ))["rows"]
        own = {r["asset_key"]: r["ownership"] for r in rows
               if r["asset_type"] == "ips"}

        # 有域名映射的那两个**本来就不作为独立 ip 行列出**（信息挂在域名行上）
        # 同段推断的那三个现在也不列出了 → 一条都不该剩
        self.assertEqual(
            own, {},
            f"归属只靠推断的 IP 仍在资产列表里：{own}",
        )

    async def test_vhost_hit_survives_the_filter(self) -> None:
        """带**域名** Host 头拿到响应的 IP 要留在列表里（归属的较强证据）。

        ⚠️ 判据是「host 长得像域名」，**不是**「host 不是这个 IP」。
        写成后者会把 C 段邻居之间的互相 vhost 探测算成命中 ——
        ``port_scan._sibling_domains`` 会把裸 IP 也送去做 vhost 探测，
        端点 host 记成同段另一个 IP，两边都不是域名（实测踩过）。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        # 先建域名行（否则没有 domain_ip 关联，那些 IP 会掉进 ``none`` 档）
        for h in ("www.example.com", "shop.example.com"):
            d0 = Event(type=EventType.DNS_NAME, data=h, module="m")
            await self.storage.save_event(sid, d0)
            await self.storage.project(sid, d0)
        # C 段邻居，但带**域名** Host 头应答过 → vhost 档
        # ⚠️ 两条事件的 ``data`` 必须**不同**（比如带不同路径）。
        # ``uq_event`` 按 ``(scan_id, type, data, kind)`` 去重，而两个 IP
        # 探的是同一个 URL 的话，第二条会被静默吃掉 ——
        # ``http_endpoint`` 表里就只剩一个 IP，测的就不是过滤而��去重了。
        for n, path in ((9, "/a"), (10, "/b")):
            e = Event(type=EventType.IP_ADDRESS, data=f"93.184.216.{n}",
                      module="netblock_expand",
                      tags={"netblock": "93.184.216.0/24"})
            await self.storage.save_event(sid, e)
            await self.storage.project(sid, e)
            ep = Event(type=EventType.HTTP_RESPONSE,
                       data=f"https://shop.example.com{path}",
                       module="http_probe",
                       tags={"domain": "shop.example.com",
                             "host": "shop.example.com",
                             "ip": f"93.184.216.{n}", "port": 443,
                             "status": 200, "scheme": "https"})
            await self.storage.save_event(sid, ep)
            await self.storage.project(sid, ep)
        # 对照：同段邻居之间互相探测（host 是**另一个 IP**）—— 不算命中
        e = Event(type=EventType.IP_ADDRESS, data="93.184.216.20",
                  module="netblock_expand",
                  tags={"netblock": "93.184.216.0/24"})
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        ep = Event(type=EventType.HTTP_RESPONSE, data="http://93.184.216.21",
                   module="http_probe",
                   tags={"domain": "", "host": "93.184.216.21",
                         "ip": "93.184.216.20", "port": 80,
                         "status": 403, "scheme": "http"})
        await self.storage.save_event(sid, ep)
        await self.storage.project(sid, ep)

        rows = (await self.storage.search_flat(
            "93.184.216", types=["ips"], live=False, limit=50
        ))["rows"]
        own = {r["asset_key"]: r["ownership"] for r in rows
               if r["asset_type"] == "ips"}
        self.assertEqual(
            set(own), {"93.184.216.9", "93.184.216.10"},
            f"只有带域名 Host 头的该留下：{own}",
        )
        for a, o in own.items():
            self.assertEqual(o, "vhost", f"{a} 归属档算错了")
        self.assertNotIn(
            "93.184.216.20", own,
            "同段 IP 之间的互相探测被算成了 vhost 命中（host 也是 IP）",
        )

    def test_ownership_is_constant_for_the_five_non_ip_types(self) -> None:
        """域名/URL/技术栈/发现/端口行的归属是**确定的**，不许出现 neighbor。

        它们各自有名字或有 IP 依附，归属不需要推断。留成常量是为了前端
        只需要处理两种取值。
        """
        from core.storage.postgres import PostgresStorage

        exprs = PostgresStorage._FLAT_OWNER_EXPR
        for atype in ("domains", "ports", "urls", "technologies", "findings"):
            with self.subTest(atype=atype):
                self.assertEqual(
                    exprs[atype].strip().strip("'\""), "dns",
                    f"{atype} 的归属恒为 dns，不该出现推断值",
                )


class TestLiveCountAgreesWithTheTabItLabels(IsolatedAsyncioTestCase):
    """页签上的「存活 N / 总数 M」必须与那个页签列出来的行**同一口径**。

    ## 这条是补一个自己造出来的不一致

    归属过滤（零证据的 C 段邻居不进资产主列表）写进
    ``_SearchSpec.always`` 之后，``_LIVE_COUNT_SQL`` 里那句
    ``AND {always}`` 顺手把它也套到了**任务详情页签的存活计数**上 ——
    而页签列表走 :meth:`PostgresStorage.ips`，那条路径只有
    ``_seen_clause`` + ``_live_clause``，**没有** ``always``。

    于是扫描 76 的页签写着「存活 **0** / 770」，同一次扫描明明有 4026 个
    开放端口。这比数据缺失更坏：它把"扫到了"说成"什么都没扫到"，用户会
    回头怀疑 C 段扫描白跑了。

    ## 规则

    **计数 ⊆ 列表**，且计数只表达"列出来的这些里有多少是活的"。
    归属过滤要生效的地方是资产管理页，那边列表和计数走同一套
    ``_SEARCH_SPECS``，天然一致。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _seed_csegment_scan(self) -> int:
        """一次典型的 C 段扫描：1 台有域名归属 + 3 台纯邻居，各开两个端口。

        纯邻居是**零归属证据**的形状 —— 正是归属过滤要排除的那种。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        d = Event(type=EventType.DNS_NAME, data="www.example.com", module="m")
        await self.storage.save_event(sid, d)
        await self.storage.project(sid, d)
        own = Event(type=EventType.IP_ADDRESS, data="93.184.216.7", module="m",
                    parent_data="www.example.com")
        await self.storage.save_event(sid, own)
        await self.storage.project(sid, own)
        for n in (1, 2, 3):
            e = Event(type=EventType.IP_ADDRESS, data=f"93.184.216.{n}",
                      module="netblock_expand",
                      tags={"netblock": "93.184.216.0/24"})
            await self.storage.save_event(sid, e)
            await self.storage.project(sid, e)
        for host in ("93.184.216.1", "93.184.216.2", "93.184.216.3",
                     "93.184.216.7"):
            for port in (80, 443):
                pe = Event(type=EventType.OPEN_TCP_PORT,
                           data=f"{host}:{port}", module="port_scan",
                           tags={"ip": host, "port": port, "domain": "",
                                 "proto": "tcp"})
                await self.storage.save_event(sid, pe)
                await self.storage.project(sid, pe)
        return sid

    async def test_neighbor_ips_still_count_as_live_in_the_scan_tab(self) -> None:
        """纯邻居在**这次扫描**的 IP 页签里必须是"存活"的。

        它们确实探到端口了 —— ``port`` 表里那些行就是证据。把它们算成
        未探活，等于对"探活做完了"这件事撒谎。
        """
        sid = await self._seed_csegment_scan()
        s = await self.storage.summary(sid)
        self.assertEqual(s["ips"], 4, "夹具前提不对：这次扫描应看到 4 台 IP")
        self.assertEqual(
            s["ips_live"], 4,
            f"页签写着「存活 {s['ips_live']} / {s['ips']}」—— "
            f"4 台都有开放端口，全被判成未探活",
        )

    async def test_live_count_never_exceeds_the_rows_the_tab_lists(self) -> None:
        """通用不变式：四种资产的存活计数都不得超过该页签列出的行数。

        这条比"某个具体数字对不对"更耐改 —— 以后再有人给 ``_LIVE_COUNT_SQL``
        加条件，它会立刻在这里现形。
        """
        sid = await self._seed_csegment_scan()
        s = await self.storage.summary(sid)
        for label, rows in (
            ("ips_live", await self.storage.ips(sid)),
            ("domains_live", await self.storage.domains(sid)),
            ("ports_live", await self.storage.ports(sid)),
        ):
            with self.subTest(label=label):
                self.assertLessEqual(
                    s[label], len(rows),
                    f"{label}={s[label]} 但该页签只列 {len(rows)} 行 —— "
                    f"计数不在列表范围内，页签上的比例是编出来的",
                )

    async def test_asset_list_and_scan_tab_keep_their_own_admission_rules(
        self,
    ) -> None:
        """两个地方**故意**用不同口径，别再有人把它们"统一"到一起。

        * 资产管理页（跨扫描）：纯邻居**不出现** —— 它们是"可能属于别人"。
        * 任务详情 IP 页签（单次扫描）：纯邻居**出现** —— 它们是"这次明确
          扫过、且有观测结果"的机器，不因为归属存疑就假装没扫到。
        """
        sid = await self._seed_csegment_scan()

        tab = await self.storage.ips(sid)
        self.assertEqual(
            {r["addr"] for r in tab},
            {"93.184.216.1", "93.184.216.2", "93.184.216.3", "93.184.216.7"},
            "任务详情的 IP 页签必须仍然列出全部 4 台",
        )

        flat = (await self.storage.search_flat(
            "93.184.216", types=["ips"], live=False, limit=50))["rows"]
        self.assertEqual(
            [r for r in flat if r["asset_type"] == "ips"], [],
            "资产主列表不该出现零归属证据的 IP",
        )


class TestRepeatedFindingsAreCollapsed(IsolatedAsyncioTestCase):
    """同一结论被重复上报时，详情面板只列一条 + 标次数（2026-10-07）。

    ## 根因

    ``uq_finding`` 的唯一键是 ``(scan_id, kind, target, detail)`` ——
    **detail 参与去重**。只要模块把会变的计数写进 detail
    （"（18 条待验）"、"checked 312 条里有 12 条"），每来一条新观测就
    产生一条**内容不同**的 finding，唯一键压不住。

    实测 ``www.yealink.com.cn`` 39 条发现里，20 条是同一句
    "疑似有 WAF 跳过 URL 验证"，只有括号里的数字在变。

    折叠时按**抹掉数字后的** detail 比签名 —— 否则「18 条待验」与
    「23 条待验」仍是两条不同的，那正是要消灭的情况。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _put(self, sid: int, kind: str, target: str, detail: str,
                   severity: str = "info", created: str = "") -> None:
        ev = Event(type=EventType.FINDING, data=target, module="m",
                   tags={"kind": kind, "severity": severity, "detail": detail})
        await self.storage.save_event(sid, ev)
        await self.storage.project(sid, ev)
        if created:
            await self.storage._fetchall(
                "UPDATE finding SET created_at = ? WHERE scan_id = ? "
                "AND kind = ? AND target = ? AND detail = ?",
                (created, sid, kind, target, detail),
            )

    async def _domain(self, sid: int, name: str) -> None:
        """建一行 domain —— **不做这一步 ``host_detail`` 直接返回 None**。

        域名视图的 ``host_detail`` 开头就是 ``SELECT ... FROM domain
        WHERE name = ?``，查不到就 ``return None``（那时才会走裸 IP 分支）。
        """
        ev = Event(type=EventType.DNS_NAME, data=name, module="m", tags={})
        await self.storage.save_event(sid, ev)
        await self.storage.project(sid, ev)

    async def test_same_conclusion_with_differing_counts_becomes_one(
        self,
    ) -> None:
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self._domain(sid, "a.example.com")
        for n in (18, 19, 20, 21, 22, 23):
            await self._put(
                sid, "疑似有 WAF", "https://a.example.com",
                f"前面有 WAF，本轮没有逐条请求（{n} 条待验）。",
                created=f"2026-01-01T00:00:{n:02d}",
            )
        # 另一条**真的不同**的结论，不该被合掉
        await self._put(sid, "cdn", "a.example.com", "命中 CDN：阿里云",
                        created="2026-01-01T00:01:00")

        d = await self.storage.host_detail("a.example.com")
        kinds = [f["kind"] for f in d["findings"]]
        self.assertEqual(
            kinds.count("疑似有 WAF"), 1,
            f"同一句话说了 6 遍，列表里应只剩 1 条：{d['findings']}",
        )
        waf = next(f for f in d["findings"] if f["kind"] == "疑似有 WAF")
        self.assertEqual(waf["repeat"], 6, "次数没标对")
        self.assertEqual(kinds.count("cdn"), 1, "不同结论被误合了")
        # 真实总数仍然是 7 —— 折叠只是展示层的事，账不能少记
        self.assertEqual(d["counts"]["findings"], 7,
                         "折叠后 counts 必须是真实总数，否则账目对不上")

    async def test_genuinely_different_details_are_kept_apart(self) -> None:
        """detail 里的**非数字**差异是真信息，不能合。

        ⚠️ 5 张证书的 ``target`` 必须是**同一个**（证书过期是按
        ``*.ucdl.pp.uc.cn`` 记的，实测 26 条全挂在同一个 target 上），
        差异在 detail 的 CN 里。若把 target 写成 host0..host4，
        ``target LIKE '%host0.example.com%'`` 只会匹配到 1 条 ——
        那测的就不是折叠而是检索了。
        """
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self._domain(sid, "cdn.example.com")
        # 5 张不同的过期证书，挂在同一个 target 上，CN 各不相同
        for i in range(5):
            await self._put(
                sid, "cert_expired", "*.cdn.example.com",
                f"证书已过期 (2020-01-0{i + 1}, CN=*.svc{i}.example.com)",
                severity="medium",
                created=f"2026-01-01T00:00:{i:02d}",
            )
        d = await self.storage.host_detail("cdn.example.com")
        self.assertEqual(
            d["counts"]["findings"], 5,
            "5 张不同证书被折成一条了 —— 那是真信息，折叠等于丢信息",
        )

    async def test_http_and_https_targets_stay_separate(self) -> None:
        """``http://x`` 与 ``https://x`` 是**两次不同的检测**，不该合。"""
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self._domain(sid, "a.example.com")
        for t in ("http://a.example.com", "https://a.example.com"):
            await self._put(
                sid, "识别到 WAF，跳过目录爆破", t,
                "站点响应里有 WAF 特征（3 条），已放弃。",
                created="2026-01-01T00:00:00",
            )
        d = await self.storage.host_detail("a.example.com")
        self.assertEqual(
            d["counts"]["findings"], 2,
            "http 与 https 两次检测被合成一条了",
        )


class TestOpenPortsAreLiveByThemselves(IsolatedAsyncioTestCase):
    """**端口开着就是活着** —— ``ports`` 的 live 片段恒真（2026-10-07）。

    ## 为什么这条要单独占一个类

    它需要 ``storage``（真跑一次查询），所以必须落在
    ``IsolatedAsyncioTestCase`` 里。**写进同步的 ``TestLiveFilterShape``
    会得到一条骗人的假绿**：pytest 只发一条 ``coroutine ... was never
    awaited`` 的 RuntimeWarning，然后照常算它通过。（实测踩过，
    114 passed 里混着一条根本没跑的用例。）
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_open_ports_survive_the_live_filter(self) -> None:
        """开着但**不吐 HTTP** 的端口行必须留在存活列表里。

        原口径是"这一行要有 http_endpoint 观测"，于是 25/110/143 这种
        本来就不吐 HTTP 的端口整批被判成"未探活" —— 实测 16245 行里
        只有 1190 行（7.3%）通过，2177 个 SMTP 与 2177 个 IMAP 全消失。

        端口扫描**做了**、端口**确实开着**，那就是探活过且存活。
        """
        from core.engine.event import Event, EventType

        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        e = Event(type=EventType.IP_ADDRESS, data="203.0.113.30", module="t")
        await self.storage.save_event(sid, e)
        await self.storage.project(sid, e)
        # 只有 25(SMTP) —— 邮件端口永远不会有 HTTP 观测
        pe = Event(type=EventType.OPEN_TCP_PORT, data="203.0.113.30:25",
                   module="port_scan",
                   tags={"ip": "203.0.113.30", "port": 25, "domain": "",
                         "proto": "tcp"})
        await self.storage.save_event(sid, pe)
        await self.storage.project(sid, pe)

        # ⚠️ ``search_counts`` 是协程 —— 少一个 await 会得到
        # ``TypeError: 'coroutine' object is not subscriptable``，
        # 而它只在真的 await 之后才报错，所以写错了很难一眼看出是漏 await。
        counts = await self.storage.search_counts(
            "203.0.113", types=["ports"], live=True
        )
        self.assertEqual(
            counts["ports"], 1,
            "开着 SMTP 的端口行被判成未探活 —— 它确实开着，就是不发 HTTP",
        )
        # ``search_flat`` 走的是另一条 live（``_SEARCH_SPECS``），两处都要对
        got = await self.storage.search_flat(
            "203.0.113", types=["ports"], live=True, limit=10
        )
        self.assertEqual(got["total"], 1, "资产管理页那条路径漏改了")

    def test_ports_live_is_consistent_in_both_places(self) -> None:
        """``ports`` 的 live 判据在**两处**都必须恒真。

        同一个概念有两个定义：``_LIVE_SQL``（任务详情页那几个列表）与
        ``_SEARCH_SPECS['ports'].live``（资产管理页的 ``/api/search/flat``）。
        改一处不改另一处**不会报错、不警告**，就是数据少了 ——
        实测只改 ``_LIVE_SQL`` 时接口照旧返回 0 条，很难定位。

        这条把两边钉在一起：任何一边单独改掉，另一边不动就会红。
        """
        from core.storage.postgres import _SEARCH_SPECS

        self.assertEqual(
            _LIVE_SQL["ports"][0].strip().upper(), "TRUE",
            "_LIVE_SQL 里的 ports live 应恒真",
        )
        self.assertEqual(
            _SEARCH_SPECS["ports"].live.strip().upper(), "TRUE",
            "_SEARCH_SPECS 里的 ports live 应恒真（它管资产管理页）",
        )
        self.assertEqual(
            _SEARCH_SPECS["ports"].live_params, 0,
            "恒真片段不吃 scan_id 参数，多一个会整体错位",
        )
        self.assertEqual(
            _SEARCH_SPECS["ports"].live_any.strip().upper(), "TRUE",
            "跨扫描检索（scan_id=None）的兜底条件也要恒真",
        )


class TestMappedIpsAreFoldedIntoDomain(IsolatedAsyncioTestCase):
    """**有域名映射的 IP 不作为独立资产列出**（原始设计）。

    一个 IP 解析得到域名时，它的信息（端口/状态/标题）已经全部挂在域名行上
    （``domains`` 的 LATERAL 按 ``e.host = t.name`` 取）。IP 再单占一行就是
    同一份信息在列表里出现两遍。只有**没有域名映射的裸 IP**才独立成条。

    ## 配套要求（这条是本测试的真正难点）

    滤掉 IP 行之后，域名原本**只搜 name**，于是搜 "10.0.0.1" 这种 IP 关键词
    会一条都搜不到 —— 那个 IP 的信息全在域名行上，却没法用 IP 找出来。
    所以 ``domains`` 的检索列必须补上"它解析到的 IP"。两条一起验。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.s1 = await self.storage.create_scan(targets=["example.com"], preset="t")
        self.s2 = await self.storage.create_scan(targets=["other.com"], preset="t")
        # 有域名映射的 IP
        for d in ("a.example.com", "b.example.com"):
            await self.storage.project(
                self.s1, Event(type=EventType.DNS_NAME, data=d, module="m")
            )
            await self.storage.project(
                self.s1,
                Event(type=EventType.IP_ADDRESS, data="10.0.0.1", module="m",
                      parent_data=d),
            )
        # 没有域名映射的裸 IP
        await self.storage.project(
            self.s2, Event(type=EventType.IP_ADDRESS, data="10.0.0.9", module="m")
        )
        await self.storage.project(
            self.s2,
            Event(type=EventType.OPEN_TCP_PORT, data="10.0.0.9:80", module="m",
                  tags={"ip": "10.0.0.9", "port": 80, "protocol": "tcp"}),
        )

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def test_mapped_ip_is_not_listed_but_bare_ip_is(self) -> None:
        flat = await self.storage.search_flat(
            "", types=["domains", "ips"], limit=50, live=False
        )
        keys = {r["asset_key"] for r in flat["rows"]}
        self.assertNotIn(
            "10.0.0.1", keys,
            "有域名映射的 IP 仍单列 —— 它的信息已经在域名行上了，重复",
        )
        self.assertIn("10.0.0.9", keys, "裸 IP 必须独立成条，否则会丢资产")
        self.assertIn("a.example.com", keys)
        self.assertIn("b.example.com", keys)

    async def test_searching_by_ip_still_finds_the_domain(self) -> None:
        """按 IP 搜仍要能搜到域名行 —— 否则那些信息就找不回来了。"""
        flat = await self.storage.search_flat(
            "10.0.0.1", types=["domains", "ips"], limit=50, live=False
        )
        keys = {r["asset_key"] for r in flat["rows"]}
        self.assertTrue(
            keys & {"a.example.com", "b.example.com"},
            f"搜 IP 关键词搜不到任何域名行，IP 的信息等于丢了：{keys}",
        )

    async def test_total_matches_rows(self) -> None:
        """total 必须与实际行数一致（滤掉 IP 行后两边要同步少）。"""
        flat = await self.storage.search_flat(
            "", types=["domains", "ips"], limit=50, live=False
        )
        self.assertEqual(
            flat["total"], len(flat["rows"]),
            "total 与行数对不上 —— 计数查询与取行查询的过滤条件没同步",
        )


class TestDomainRowsCarryWorstSeverity(IsolatedAsyncioTestCase):
    """**域名行的 severity 列**（2026-10-06 新增）。

    ## 背景：这一列之前压根不存在，「风险」列是死的

    资产管理页写死 ``severity = asset_type === 'findings' ? extra : null``，
    而页面只查 ``domains,ips`` —— 于是那一列每格都是横线，库里 145 条
    finding 一条都没露出来（真机实测：``extra`` 非空 0 行）。

    ## 为什么要单开一列而不是复用 extra

    ``extra`` 是"每类型特有的那一个值"：``ips`` 装**反查域名**、
    ``technologies`` 装识别证据。前端图省事读 ``extra`` 当 severity，IP 行
    就会把域名串显示到「风险」列里。独立一列读错的机会就没了。

    ## 夹具为什么必须是"混合 severity"

    真机数据里每个域名的 finding **severity 全都一样**（要么 10 条 info、
    要么 6 条 medium），所以"取最坏"那段 ORDER BY 在真实数据上**恒等于取任意
    一条** —— 不构造混合夹具，测了也证明不了排序是对的。下面的
    ``test_worst_severity_wins_over_info`` 专门补这个洞。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.sid = await self.storage.create_scan(
            targets=["example.com"], preset="t"
        )
        for d in ("plain.example.com", "mixed.example.com", "crit.example.com"):
            await self.storage.project(
                self.sid, Event(type=EventType.DNS_NAME, data=d, module="m")
            )

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _finding(self, target: str, severity: str, kind: str = "probe") -> None:
        await self.storage.project(
            self.sid,
            Event(
                type=EventType.FINDING,
                data=target,
                module="m",
                tags={"kind": kind, "severity": severity, "detail": ""},
            ),
        )

    async def _severity_of(self, domain: str) -> object:
        flat = await self.storage.search_flat(
            domain, types=["domains"], limit=20, live=False
        )
        for r in flat["rows"]:
            if r["asset_key"] == domain:
                return r["severity"]
        return "<域名行没搜到>"

    async def test_domain_without_finding_has_null_severity(self) -> None:
        """没有 finding 的域名必须是 ``None``，不是空串也不是 'info'。

        空串会让前端 ``v-if="record.severity"`` 判成真、渲染出一个空标签；
        写成 'info' 则是**凭空捏造**一条结论。
        """
        self.assertIsNone(
            await self._severity_of("plain.example.com"),
            "没有 finding 的域名不该有 severity",
        )

    async def test_severity_reaches_the_domain_row(self) -> None:
        await self._finding("mixed.example.com", "medium")
        self.assertEqual(
            await self._severity_of("mixed.example.com"), "medium",
            "域名行没拿到 severity —— 「风险」列仍然是死的",
        )

    async def test_target_with_port_and_path_is_normalised(self) -> None:
        """``https://host:8443/a/b`` 必须归一到 ``host``。

        真机实测 target 有 108 条 URL / 32 条裸域名 / 5 条 host:port，
        其中大量带端口。不剥端口的话去重后 81 个 host 只有 18 个对得上
        domain.name（22%），剥完 38 个 host 里对得上 26 个（68%）。
        """
        await self._finding("https://porty.example.com:8443/a/b", "high")
        # 先把域名建出来
        await self.storage.project(
            self.sid, Event(type=EventType.DNS_NAME, data="porty.example.com", module="m")
        )
        self.assertEqual(
            await self._severity_of("porty.example.com"), "high",
            "带端口/路径的 target 没归一到裸域名 —— 命中率为 22% 的那个坑",
        )

    async def test_worst_severity_wins_over_info(self) -> None:
        """同一域名上 info 与 high 混着时，**必须**取 high。

        这条是整个改动里最容易写错的地方：按 created_at 或不排序地取
        ``LIMIT 1``，在真机数据上（每域名 severity 都相同）照样全绿。
        """
        await self._finding("mixed.example.com", "info", kind="k_info")
        await self._finding("https://mixed.example.com:443/x", "high", kind="k_high")
        self.assertEqual(
            await self._severity_of("mixed.example.com"), "high",
            "info 与 high 混着时没取最坏的那条",
        )

    async def test_critical_outranks_high(self) -> None:
        """critical > high > medium > low > info，顺序不能错。"""
        for sev in ("info", "low", "medium", "high"):
            await self._finding(f"crit.example.com", sev, kind=f"k_{sev}")
        await self._finding("crit.example.com", "critical", kind="k_critical")
        self.assertEqual(
            await self._severity_of("crit.example.com"), "critical",
            "critical 没有压过 high —— 排序表写错了",
        )

    async def test_ip_rows_keep_severity_null(self) -> None:
        """**IP 行的 severity 必须是 None**，哪怕它确实挂着 finding。

        IP 行的 ``extra`` 装的是**反查域名**。如果哪天有人图省事把 severity
        也从 extra 取，这一列就会开始显示域名串 —— 这条就是那个回归的哨兵。
        """
        await self.storage.project(
            self.sid,
            Event(type=EventType.IP_ADDRESS, data="10.0.0.7", module="m"),
        )
        await self._finding("10.0.0.7:443", "high", kind="k_ip")
        flat = await self.storage.search_flat(
            "", types=["ips"], limit=20, live=False
        )
        for r in flat["rows"]:
            self.assertIsNone(
                r["severity"],
                f"IP 行 {r['asset_key']} 的 severity 不该有值"
                f"（extra={r['extra']!r}，那是反查域名）",
            )

    async def test_all_six_branches_emit_the_column(self) -> None:
        """六条分支的列数必须一致 —— 少一条 UNION ALL 直接报错。

        ``type=all`` 会把六条分支全拼上，是唯一能一次性验到列数对齐的入口。
        """
        flat = await self.storage.search_flat(
            "", types=None, limit=200, live=False
        )
        self.assertTrue(flat["rows"], "夹具失效：一条行都没搜出来")
        for r in flat["rows"]:
            self.assertIn(
                "severity", r,
                f"{r['asset_type']} 分支漏了 severity 列 —— "
                f"UNION ALL 的列数不一致",
            )

    def test_index_expression_matches_the_query(self) -> None:
        """**索引表达式与查询表达式必须一致** —— 最阴的一种回归。

        ``idx_finding_norm_host`` 是表达式索引，PG 对文本敏感：查询里那段
        ``regexp_replace(...)`` 与索引定义差一个空格或换行，索引就**静默用不上**，
        计划悄悄退回对 finding 全表扫。功能测试**照样全绿**，只有量性能或
        EXPLAIN 才看得出来 —— 实测没有索引时 20,145 条 finding 要 2,622 ms，
        建了索引是 95 ms。

        所以这条不测行为、只测**两边文本对得上**：把 ``_FLAT_SEVERITY_EXPR``
        里 domains 那段抠出来，与 schema.sql 的索引定义逐字比对（忽略空白）。
        """
        from core.storage.postgres import PostgresStorage as PS

        expr = PS._FLAT_SEVERITY_EXPR["domains"]
        m = re.search(r"regexp_replace\(.*?= t\.name", expr, re.S)
        self.assertIsNotNone(m, f"没在 domains 表达式里找到 regexp_replace：{expr}")
        query_norm = re.sub(r"\s+", "", m.group(0)).replace("=t.name", "")
        # 查询里是 ``f.target``（子查询给 finding 起了别名 f），索引定义里是
        # ``target``。PG 会把表达式索引的表别名归一掉，所以这是**同一个**
        # 表达式 —— 比文本时必须先把别名剥了，否则这条测试会永远红。
        # （别名归一这件事是 EXPLAIN 实测确认的：建索引前 Seq Scan on finding，
        #  建索引后 SubPlan 走索引、0.013 ms/loop。）
        query_norm = query_norm.replace("f.target", "target")

        schema = (
            Path(__file__).resolve().parents[1]
            / "core" / "storage" / "schema.sql"
        ).read_text(encoding="utf-8")
        idx = re.search(
            r"CREATE INDEX IF NOT EXISTS idx_finding_norm_host.*?;", schema, re.S
        )
        self.assertIsNotNone(idx, "schema.sql 里没有 idx_finding_norm_host")
        idx_norm = re.sub(r"\s+", "", idx.group(0))

        self.assertIn(
            query_norm, idx_norm,
            "索引表达式与查询表达式对不上 —— 索引会静默失效，"
            "资产页在 finding 变多后从 95 ms 退化到秒级。"
            f"\n查询: {query_norm}\n索引: {idx_norm}",
        )


class TestResolveStateTellsFailureFromNonexistence(IsolatedAsyncioTestCase):
    """``domain.resolve_state`` —— **解析失败 ≠ 域名不存在**。

    ## 为什么要这一列

    以前这两种情况都表现为"没有 ``domain_ip`` 行"，界面上完全分不开。
    实测 2026-10-07 现场重解析：当时判成"不存在"的 58 个域名里有 **1 个**
    又能解析了（``ors.label-yai.yealink.com.cn`` -> 183.251.103.227）——
    那一条其实是**查询失败被固化成了事实**。

    ``dns_resolve`` 一直分得清（``no_records`` / ``unresolved_due_to_failure``），
    但那组计数器**从来没进过 stats_json**，所以"分得清"只存在于内存里。

    ## 三个结论必须保持可区分

    ``ok``       解析成功      —— 进资产列表
    ``nxdomain`` 确认没有 A 记录 —— **也进**列表（那是事实，不是故障）
    ``failed``   解析器无应答   —— **不进**列表（那是未知，可重试）
    ``NULL``     没查过        —— 进列表
    """

    RESOLVE_FAIL = "resolvefail.example.com"
    NX = "nx.example.com"
    OK1 = "ok.example.com"
    SHARED = "shared.example.com"
    FRESH = "fresh.example.com"
    ALL = [RESOLVE_FAIL, NX, OK1, SHARED, FRESH]

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.sid = await self.storage.create_scan(
            targets=["example.com"], preset="t"
        )
        for d in self.ALL:
            await self.storage.project(
                self.sid, Event(type=EventType.DNS_NAME, data=d, module="m")
            )
        # 两个域名解析成功，共用同一个 IP（vhost 场景）
        for d in (self.OK1, self.SHARED):
            await self.storage.project(
                self.sid,
                Event(type=EventType.IP_ADDRESS, data="10.9.9.9", module="m",
                      parent_data=d),
            )

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _finding(self, target: str, kind: str) -> None:
        await self.storage.project(
            self.sid,
            Event(type=EventType.FINDING, data=target, module="m",
                  tags={"kind": kind, "severity": "info", "detail": "x"}),
        )

    async def _state(self, name: str):
        row = await self.storage._fetchone(
            "SELECT resolve_state FROM domain WHERE name = ?", (name,)
        )
        return row["resolve_state"] if row else "<没有这一行>"

    async def test_states_are_written_and_distinguishable(self) -> None:
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        await self._finding(self.NX, "dns_nxdomain")
        self.assertEqual(await self._state(self.RESOLVE_FAIL), "failed")
        self.assertEqual(await self._state(self.NX), "nxdomain")
        self.assertEqual(await self._state(self.OK1), "ok")
        self.assertEqual(await self._state(self.SHARED), "ok")
        self.assertIsNone(await self._state(self.FRESH))

    async def test_only_failed_is_hidden_from_the_asset_list(self) -> None:
        """**只有 failed 被排除。** nxdomain 是事实，照样是资产。"""
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        await self._finding(self.NX, "dns_nxdomain")
        flat = await self.storage.search_flat(
            "", types=["domains"], limit=50, live=False
        )
        keys = {r["asset_key"] for r in flat["rows"]}
        self.assertNotIn(
            self.RESOLVE_FAIL, keys,
            "解析失败的域名是**未知**不是不存在，不该占资产列表的名额",
        )
        for keep in (self.NX, self.OK1, self.SHARED, self.FRESH):
            self.assertIn(keep, keys, f"{keep} 不该被排除")
        self.assertEqual(
            flat["total"], len(flat["rows"]),
            "排除条件必须同时作用在计数上，否则翻页出现空洞",
        )

    async def test_ok_is_never_downgraded_to_failed(self) -> None:
        """``ok`` 的优先级最高：解析成功过就永远是成功过。

        某个域名上一轮因为解析器全挂被标成 failed，这一轮解析成功了，
        绝不能被**同一轮里晚到的 finding** 覆盖回去。
        """
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        self.assertEqual(await self._state(self.RESOLVE_FAIL), "failed")
        await self.storage.project(
            self.sid,
            Event(type=EventType.IP_ADDRESS, data="10.9.9.9", module="m",
                  parent_data=self.RESOLVE_FAIL),
        )
        self.assertEqual(
            await self._state(self.RESOLVE_FAIL), "ok",
            "解析成功后 resolve_state 没有升到 ok",
        )
        # 升级之后晚到的 failed finding 也盖不回去
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        self.assertEqual(
            await self._state(self.RESOLVE_FAIL), "ok",
            "已经解析成功的域名被 finding 降级回 failed 了",
        )
        flat = await self.storage.search_flat(
            "", types=["domains"], limit=50, live=False
        )
        self.assertIn(
            self.RESOLVE_FAIL, {r["asset_key"] for r in flat["rows"]},
            "升级成 ok 之后仍然不在资产列表里 —— 它已经解析成功了",
        )

    async def test_excluded_domain_is_still_findable_in_detail(self) -> None:
        """**排除了不能等于查不到。**

        用户的要求：解析失败的域名不进资产列表，但要能在详情里看到并标记。
        这条钉住"还能按名字查得到" —— 否则那批域名就是真丢了。
        """
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        det = await self.storage.host_detail(self.RESOLVE_FAIL)
        self.assertIsNotNone(det, "解析失败的域名按名字查不到 —— 数据丢了")
        self.assertEqual(
            det["domain"]["resolve_state"], "failed",
            "详情里没有带上解析状态，前端没法标「解析失败」",
        )

    async def test_related_domains_uses_root_not_shared_ip(self) -> None:
        """**必须按根域关联，不能按共享 IP。**

        ``failed`` 的域名压根没有 ``domain_ip`` 行（它没解析出 IP），按 IP
        关联时它们一条都进不来 —— 而这个区块存在的意义就是收留它们。
        """
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        await self._finding(self.NX, "dns_nxdomain")
        det = await self.storage.host_detail(self.OK1)
        rel = {r["name"]: r for r in det["related_domains"]}
        self.assertEqual(
            sorted(rel), sorted(set(self.ALL) - {self.OK1}),
            f"同根域的域名没列全：{sorted(rel)}",
        )
        self.assertIn(
            self.RESOLVE_FAIL, rel,
            "解析失败的域名没进 related_domains —— 它没有 IP，按 IP 关联不到",
        )
        self.assertTrue(
            rel[self.SHARED]["same_ip"],
            "共用同一台机器的兄弟域名没被标出来（vhost 场景的入口）",
        )
        self.assertFalse(rel[self.FRESH]["same_ip"])
        self.assertEqual(
            det["counts"]["related_domains_unresolved"], 1,
            "未解析计数不对 —— 界面上会少报一个需要人工看的域名",
        )

    async def test_unresolved_domains_sort_first(self) -> None:
        """failed 排最前（唯一需要人工判断的一类）。

        ⚠️ 这条钉的是 ``ORDER BY`` 的 **NULL 行为**：写成
        ``(resolve_state = 'failed') DESC`` 时，"没查过"（NULL）的行会因为
        ``ORDER BY ... DESC`` 默认 NULL 排最前而抢到第一行。
        """
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        det = await self.storage.host_detail(self.OK1)
        names = [r["name"] for r in det["related_domains"]]
        self.assertEqual(
            names[0], self.RESOLVE_FAIL,
            f"解析失败的域名没排最前，实际第一行是 {names[0]}",
        )

    async def test_ops_findings_do_not_pollute_the_risk_column(self) -> None:
        """``dns_nxdomain`` / ``dns_resolve_failed`` 是**运维事实不是风险**。

        喂进 severity 会让整个域名列表挂满灰色「信息」标签，把真正的
        medium/high 淹掉。
        """
        await self._finding(self.NX, "dns_nxdomain")
        await self._finding(self.RESOLVE_FAIL, "dns_resolve_failed")
        flat = await self.storage.search_flat(
            "", types=["domains"], limit=50, live=False
        )
        sev = {r["asset_key"]: r["severity"] for r in flat["rows"]}
        self.assertIsNone(
            sev.get(self.NX), "nxdomain 让「风险」列冒出了信息标签"
        )
        # 真有风险时仍然要显示出来
        await self.storage.project(
            self.sid,
            Event(type=EventType.FINDING, data=self.NX, module="m",
                  tags={"kind": "admin_plane", "severity": "high", "detail": "x"}),
        )
        flat2 = await self.storage.search_flat(
            self.NX, types=["domains"], limit=50, live=False
        )
        self.assertEqual(
            flat2["rows"][0]["severity"], "high",
            "真风险被运维类 finding 挤掉了",
        )


class TestWildcardDerivedNamesAreNotAssets(IsolatedAsyncioTestCase):
    """**泛解析造出来的幻影域名不进资产列表，也不占 vhost 探活额度。**

    ## 问题长什么样

    泛解析 ``*.label-yai.yealink.com.cn`` 会把**任意**名字都解析到同一台机器。
    实测那台 ``117.28.234.46`` 上因此挂着 **21 个** ``*.label-yai.*`` ——
    它们不是 21 个不同的子域，而是同一个泛解析区造出来的幻影。"能解析"这件事
    毫无信息量，却有两个实际代价：

    * 资产列表里全是它们（实测占 domain 表 121 行中的 23 行）
    * ``port_scan.max_hosts_per_ip``（默认 20）的额度被**按字母序吃光**：
      ``adm`` / ``admin`` / ``ai`` / ``alpha`` 排在真实域名 ``tech-user`` /
      ``waf`` / ``ycrm-uat-h5`` 前面，真正值得探的反而被挡在门外（长期 7 个域名
      探不到）。

    ## 判据

    父域被标记了泛解析（``is_wildcard``，由 ``wildcard_detect`` 检出后经 finding
    回写）。真机实测：排除 23 个、全是幻影，真实域名**零误伤**。
    """

    async def asyncSetUp(self) -> None:
        self.storage = await make_storage()
        self.sid = await self.storage.create_scan(
            targets=["example.com"], preset="t")
        # 泛解析区根域 + 三个幻影（DNS 上确实能解析，但不代表是真实子域）
        for d in ("label", "adm.label", "admin.label", "zzz.label"):
            await self.storage.project(
                self.sid, Event(type=EventType.DNS_NAME, data=d + ".example.com",
                                module="m"))
        # 真实域名：与幻影共用同一台机器
        for d in ("real.example.com", "other.example.com"):
            await self.storage.project(
                self.sid, Event(type=EventType.DNS_NAME, data=d, module="m"))
            await self.storage.project(
                self.sid, Event(type=EventType.IP_ADDRESS, data="93.184.216.34",
                                module="m", parent_data=d))
        # 标记泛解析（wildcard_detect 的回写路径）
        await self.storage.project(
            self.sid,
            Event(type=EventType.FINDING, data="label.example.com", module="m",
                  tags={"kind": "wildcard", "severity": "low", "detail": "泛解析"}))

    async def asyncTearDown(self) -> None:
        await drop_storage(self.storage)

    async def _keys(self) -> set[str]:
        flat = await self.storage.search_flat(
            "", types=["domains"], limit=50, live=False)
        return {r["asset_key"] for r in flat["rows"]}

    async def test_phantom_names_are_excluded_from_the_asset_list(self) -> None:
        keys = await self._keys()
        for phantom in ("adm.label.example.com", "admin.label.example.com",
                        "zzz.label.example.com"):
            self.assertNotIn(
                phantom, keys,
                f"{phantom} 是泛解析幻影，不该出现在资产列表里",
            )
        self.assertIn("real.example.com", keys, "真实域名被误伤了")
        self.assertIn("other.example.com", keys, "真实域名被误伤了")

    async def test_the_wildcard_root_itself_is_kept(self) -> None:
        """泛解析的**根域自己必须保留**。

        它是个真实存在的 DNS 名字，而且**正是它那条记录标记了整个泛解析区** ——
        把它排除掉的话，这个区会连带把自己的定义删掉，下次泛解析检测就再也标不出
        新的一批了（实测踩过：根域被一起滤掉后，幻影还在、根域没了）。
        """
        self.assertIn(
            "label.example.com", await self._keys(),
            "泛解析根域被自己的规则滤掉了 —— 下次泛解析就再也标不出新的一批",
        )

    async def test_sibling_lookup_skips_phantoms(self) -> None:
        """vhost 反查要跳过幻影 —— 否则额度被它们吃光。

        这条钉的是第二处的 SQL：``_NOT_WILDCARD_DERIVED`` 必须与资产列表共用
        同一份。抄成两份的话症状是「列表里没有了但还是占着探活额度」。
        """
        await self.storage.project(
            self.sid,
            Event(type=EventType.IP_ADDRESS, data="93.184.216.34", module="m",
                  parent_data="adm.label.example.com"))
        sibs = await self.storage.sibling_domains_on("93.184.216.34")
        self.assertNotIn("adm.label.example.com", sibs,
                         "幻影进了 vhost 反查结果 —— 它会吃掉 max_hosts_per_ip 的额度")
        self.assertEqual(
            sorted(sibs), ["other.example.com", "real.example.com"],
            f"兄弟域名列表不对：{sibs}",
        )

    async def test_sibling_lookup_excludes_the_requested_host(self) -> None:
        sibs = await self.storage.sibling_domains_on(
            "93.184.216.34", exclude="real.example.com")
        self.assertNotIn("real.example.com", sibs)
        self.assertIn("other.example.com", sibs)

    async def test_total_still_matches_rows(self) -> None:
        """过滤条件必须同时作用在计数上，否则翻页出空洞。"""
        flat = await self.storage.search_flat(
            "", types=["domains"], limit=50, live=False)
        self.assertEqual(flat["total"], len(flat["rows"]))


if __name__ == "__main__":
    unittest.main()
