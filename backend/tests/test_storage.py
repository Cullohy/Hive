"""存储层专测：方言适配与检索索引。

这里覆盖的是**从 SQLite 换到 PostgreSQL 时新引入的那部分**，
也就是 ``core/storage/pg.py`` 的三条模拟规则与 ``pg_trgm`` 索引。

其余存储行为由各个域自己的测试覆盖（它们现在也跑在 PostgreSQL 上）。
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import asyncpg

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
        """
        for key, (sql, extra) in _LIVE_SQL.items():
            with self.subTest(key=key):
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
        """
        for key, spec in _SEARCH_SPECS.items():
            with self.subTest(key=key):
                self.assertEqual(spec.live.count("?"), spec.live_params)
                self.assertNotIn("t.scan_id", spec.live)
                if spec.live:
                    self.assertTrue(spec.live_any, f"{key}: 缺 live_any 兜底")
                    self.assertEqual(spec.live_any.count("?"), 0)
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
        """详情面板的"发现"数必须是**真实总数**，不是截断后的列表长度。

        ``target LIKE '%name%'`` 会把子域的证书 / WAF 结论一起捞进来，几十条
        很常见。曾经 ``counts["findings"] = len(findings)`` 而列表固定
        ``LIMIT 50`` —— 于是面板写 50、概览写 312，用户以为还有 262 条没加载。
        这正是 ``global_stats`` 注释里写的"计数与列表必须一致"。
        """
        from core.engine.event import Event, EventType

        HOST = "cnt.example.com"
        total = 60
        sid = await self.storage.create_scan(targets=["example.com"], preset="t")
        await self.storage.project(
            sid, Event(type=EventType.DNS_NAME, data=HOST, module="m", tags={})
        )
        await self._insert_finding(
            f"INSERT INTO finding (scan_id, kind, target, detail, severity, created_at)"
            f" VALUES ({sid}, 'cdn', '{HOST}', 'd{{i}}', 'info', '2026-01-01')",
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

        gid = await self.storage.create_group(name="g1", scopes=["example.com"])
        self.assertTrue(await self.storage.update_group(gid, description="d"))
        self.assertFalse(
            await self.storage.update_group(gid + 9999, description="x"),
            "更新 0 行却返回 True",
        )

    async def test_screenshot_failure_is_logged(self) -> None:
        """截图写失败**要留线索**。

        ``rowcount == 0`` 那条分支有 warning，而连接断了 / 权限不足 / 语句
        超时全被压成同一个 ``False``，调用方当成"还没有端点行"于是不再重试，
        事后查日志一条线索都没有。
        """
        from unittest import mock

        real = self.storage._conn
        self.storage._conn = mock.AsyncMock()
        self.storage._conn.execute.side_effect = RuntimeError("connection reset")
        try:
            with self.assertLogs("recon.storage", level="WARNING") as caught:
                ok = await self.storage.save_screenshot(1, "http://x/", b"png")
        finally:
            self.storage._conn = real

        self.assertFalse(ok)
        self.assertTrue(
            any("connection reset" in line for line in caught.output),
            f"异常被吞掉且没有日志：{caught.output}",
        )

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


if __name__ == "__main__":
    unittest.main()
