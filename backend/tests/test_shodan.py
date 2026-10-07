"""Shodan 源（``core/domains/subdomain/passive/shodan.py``）。

## 为什么这批测试要盯这么细

**我拿不到 Shodan 的 key，真实接口一次都没调过。** 而 Shodan 有**两个
fofa/quake 没有的坑**，两个都只会静默出错：

1. **页码从 1 开始，不是 0。** 写成 ``range(max_pages)`` 会去请求
   ``page=0`` —— 那是 Shodan 的**默认页**，看着"有数据"，于是
   ``max_pages=2`` 悄悄变成只查了第 0 页，**翻页这个功能从来没生效过**，
   而且不报错。
2. **鉴权失败时响应体不是 JSON。** Shodan 可能回一个 nginx 的 HTML 错误页。
   先 ``json.loads`` 会抛 ``JSONDecodeError``，而那个异常与"key 填错了"
   毫无关系 —— 用户会以为接口挂了。（``passive_quake`` 撞的是同一类：
   那边 401 回的是纯文本 ``/quake/login``。）

## 真实接口验证清单（拿到 key 后按这个过一遍）

1. 官方 ``api_url`` + key → ``hostname:example.com`` 能返回 ``matches``
2. 看一眼**真实响应**的 ``matches[0]``，确认 ``hostnames`` / ``domain`` /
   ``http.host`` 三个字段哪些真的有值 —— ``_hosts_of`` 按可靠性排了序
3. 把 ``minify=true`` 打开跑一次，确认它**没有把 ``hostnames`` 裁掉**
   （本模块默认关着，就是因为没验证过这一点）
4. 故意把 key 填错，确认拿到的是**中文提示**而不是 ``JSONDecodeError``
5. ``shodan info`` 对一下 ``/account/profile`` 返回的剩余额度是否准
6. 确认免费账号实际能翻几页（决定 ``max_pages`` 默认值要不要调）
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.domains.subdomain.passive.shodan import (  # noqa: E402
    DEFAULT_API,
    PROFILE_API,
    SHODAN_PAGE_SIZE,
    Query,
)
from core.services.http import HTTPClient  # noqa: E402

from .base import EngineTestCase  # noqa: E402


class _Resp:
    """最小响应替身 —— ``_get`` 只碰这三样。"""

    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text
        self.closed = False

    async def aclose(self) -> None:
        self.closed = True


class TestHostExtraction(unittest.TestCase):
    """``_hosts_of`` —— 三个字段都要看，且必须过 ``host_of``。"""

    def test_reads_all_three_sources(self) -> None:
        out = Query._hosts_of([{
            "ip_str": "93.184.216.7",
            "hostnames": ["a.example.com", "b.example.com"],
            "domain": "c.example.com",
            "http": {"host": "d.example.com"},
        }])
        self.assertEqual(
            out, ["a.example.com", "b.example.com", "c.example.com",
                  "d.example.com"],
        )

    def test_strips_port_from_http_host(self) -> None:
        """``http.host`` 偶尔带端口。不抠会在下游被当非法域名丢掉。

        这与 ``passive_fofa`` 的 ``host`` 字段是**同一个坑**（那边是完整
        URL），只是表现不同。
        """
        out = Query._hosts_of([{"http": {"host": "www.example.com:8443"}}])
        self.assertEqual(out, ["www.example.com"])

    def test_strips_scheme(self) -> None:
        self.assertEqual(
            Query._hosts_of([{"hostnames": ["https://x.example.com/a"]}]),
            ["x.example.com"],
        )

    def test_hostnames_may_be_a_bare_string(self) -> None:
        """别假定它一定是数组 —— 形状不对时静默丢掉整个源最亏。"""
        self.assertEqual(
            Query._hosts_of([{"hostnames": "a.example.com"}]),
            ["a.example.com"],
        )

    def test_non_dict_rows_are_skipped(self) -> None:
        self.assertEqual(Query._hosts_of([None, "x", 42]), [])

    def test_missing_fields_yield_nothing(self) -> None:
        """一行什么都没有不是错，别往结果里塞空串。"""
        self.assertEqual(Query._hosts_of([{"ip_str": "1.2.3.4"}]), [])


class TestQueryParams(unittest.TestCase):
    def _q(self, *, key: str = "k", **kw) -> Query:
        q = Query()
        q.init_key(api_key=key, **kw)
        return q

    def test_default_url_is_official(self) -> None:
        self.assertEqual(self._q().api_url, DEFAULT_API)
        self.assertEqual(Query.api_url, DEFAULT_API)

    def test_query_uses_hostname_filter(self) -> None:
        self.assertEqual(
            self._q()._query_text("example.com"), "hostname:example.com"
        )

    def test_query_extra_is_joined_with_a_space(self) -> None:
        """Shodan 的空格是**隐式 AND**，所以合并成一条而不是多次查询 ——
        而 Shodan 每条过滤式查询都扣 1 credit，省下的不只是往返。"""
        q = self._q(query_extra="port:443 country:CN")
        self.assertEqual(q._query_text("example.com"),
                         "hostname:example.com port:443 country:CN")

    def test_key_is_sent(self) -> None:
        self.assertEqual(self._q().api_key, "k")

    def test_key_is_stripped(self) -> None:
        """Web 设置里粘进来常带首尾空格，Shodan 会当无效 key。"""
        self.assertEqual(self._q(key="  k \n").api_key, "k")


class TestCreditDiscipline(unittest.TestCase):
    """Shodan **每条查询 1 credit、每多翻一页再扣 1** —— 比 FOFA 紧得多。"""

    def _q(self, **kw) -> Query:
        q = Query()
        q.init_key(api_key="k", **kw)
        return q

    def test_defaults_to_one_page(self) -> None:
        self.assertEqual(self._q().max_pages, 1,
                         "默认翻页 = 默认多烧额度")

    def test_recursion_is_off(self) -> None:
        """递归 = 每个子域再发一条**新的**过滤式查询 = 成倍烧额度。"""
        self.assertFalse(Query.recursive)
        self.assertFalse(Query().recursive)

    def test_zero_and_negative_mean_default(self) -> None:
        """0 与没填都表示"用默认值"；负数夹到 1。"""
        self.assertEqual(self._q(max_pages=0).max_pages, 1)
        self.assertEqual(self._q(max_pages=-5).max_pages, 1)

    def test_page_size_is_a_protocol_constant(self) -> None:
        """不是"分页大小"，Shodan 固定 100 —— 不该被配置改掉。"""
        self.assertEqual(SHODAN_PAGE_SIZE, 100)


class TestIpAcceptance(unittest.TestCase):
    """「你额外查了什么，我就不替你担保它属于你」。"""

    def _q(self, **kw) -> Query:
        q = Query()
        q.init_key(api_key="k", **kw)
        return q

    def test_default_accepts_ips(self) -> None:
        self.assertTrue(self._q().accept_ip_assets)

    def test_query_extra_turns_it_off_by_default(self) -> None:
        self.assertFalse(
            self._q(query_extra='org:"Someone Else"').accept_ip_assets,
            "附加条件不限定目标时，裸 IP 很可能是别人的",
        )

    def test_explicit_false_string_must_mean_false(self) -> None:
        """⚠️ Web 设置里这是**字符串** ``"false"``，而 ``bool("false")`` 是 True
        —— 用户明明关掉了，模块还在收别人的 IP。与 ``port_scan`` 的内网
        闸门是同一类反转。"""
        self.assertFalse(self._q(accept_ip_assets="false").accept_ip_assets)


class TestQueryInjectionGuard(unittest.IsolatedAsyncioTestCase):
    """目标直接拼进查询语句，必须先验合法性。

    ⚠️ 这里**必须**是 ``IsolatedAsyncioTestCase`` —— 同步 TestCase 里放
    ``async def`` 用例，pytest 只发一条 RuntimeWarning 然后**照常算它通过**，
    于是「这条用例一次都没跑过」混在全绿报告里。本仓已在 ``pyproject.toml``
    里把它提为 error（见 ``filterwarnings``），第一版就是被它当场抓住的。
    """

    async def test_invalid_target_is_refused(self) -> None:
        """不拒绝的话，一个带引号的目标能拼出**畸形的 Shodan 查询** ——
        轻则查不到，重则把别人的资产查回来。"""
        q = Query()
        q.init_key(api_key="k")
        with self.assertRaises(ValueError) as cm:
            await q.sub_domains('evil" org:"x', HTTPClient())
        self.assertIn("不是合法域名", str(cm.exception))


class TestErrorSemantics(unittest.IsolatedAsyncioTestCase):
    """错误提示要翻译成人话，且**不能**让异常与真实原因无关。"""

    def _q(self) -> Query:
        q = Query()
        q.init_key(api_key="k", interval=0)
        return q

    async def _call(self, resp: _Resp, url: str | None = None):
        q = self._q()
        captured: dict = {}

        async def fake_request(self, method, u, **kwargs):  # noqa: ANN001
            captured.update(kwargs)
            captured["url"] = u
            return resp

        with mock.patch.object(HTTPClient, "request", fake_request):
            await q.sub_domains("example.com", HTTPClient())
        return captured

    async def test_401_html_must_not_become_a_json_decode_error(self) -> None:
        """⚠️ **这是本模块最贵的那个坑。**

        Shodan 在鉴权失败时可能回 nginx 的 HTML 错误页。先 ``json.loads``
        的话，用户看到的是 ``Expecting value: line 1 column 1`` —— 与
        "key 填错了"毫无关系，于是会去反复检查网络、接口地址。
        """
        resp = _Resp(401, "<html><head><title>401 Authorization Required</title>")
        with self.assertRaises(RuntimeError) as cm:
            await self._call(resp)
        msg = str(cm.exception)
        self.assertIn("鉴权失败", msg)
        self.assertIn("api_key", msg, "没指出该查 key")

    async def test_429_is_translated(self) -> None:
        resp = _Resp(429, "{}")
        with self.assertRaises(RuntimeError) as cm:
            await self._call(resp)
        self.assertIn("429", str(cm.exception))

    async def test_non_json_200_mentions_the_status(self) -> None:
        resp = _Resp(200, "<html>maintenance</html>")
        with self.assertRaises(RuntimeError) as cm:
            await self._call(resp)
        self.assertIn("不是 JSON", str(cm.exception))
        self.assertIn("200", str(cm.exception))

    async def test_credit_exhaustion_points_at_the_billing_page(self) -> None:
        resp = _Resp(200, '{"error": "No more query credits available"}')
        with self.assertRaises(RuntimeError) as cm:
            await self._call(resp)
        msg = str(cm.exception)
        self.assertIn("额度", msg)
        self.assertIn("max_pages", msg, "没告诉用户可以少翻页")

    async def test_invalid_query_points_at_query_extra(self) -> None:
        resp = _Resp(200, '{"error": "Invalid query string"}')
        with self.assertRaises(RuntimeError) as cm:
            await self._call(resp)
        self.assertIn("query_extra", str(cm.exception))

    async def test_empty_matches_is_not_an_error(self) -> None:
        """没有结果**不是错误** —— 目标就是没有资产。"""
        resp = _Resp(200, '{"total": 0, "matches": []}')
        self.assertEqual(await self._call(resp) is not None, True)


class TestPagination(unittest.IsolatedAsyncioTestCase):
    """⚠️ **页码从 1 开始** —— Shodan 的 ``page=0`` 是默认页。"""

    def _q(self, **kw) -> Query:
        q = Query()
        q.init_key(api_key="k", interval=0, **kw)
        return q

    async def _pages(self, pages: list[int]) -> tuple[list[int], Query]:
        seen: list[int] = []

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            params = kwargs.get("params") or {}
            seen.append(int(params["page"]))
            body = pages.pop(0)
            return _Resp(200, body)

        q = self._q(max_pages=len(pages))
        with mock.patch.object(HTTPClient, "request", fake_request):
            await q.sub_domains("example.com", HTTPClient())
        return seen, q

    async def test_first_page_is_one_not_zero(self) -> None:
        seen, _ = await self._pages(['{"total": 3, "matches": [{"domain": "a.example.com"}]}'])
        self.assertEqual(seen, [1], "page 从 0 开始 → Shodan 会当默认值，"
                                  "于是 max_pages>1 永远查不到第 2 页")

    async def test_full_page_advances_to_the_next_one(self) -> None:
        """返回满 100 条才继续翻 —— 不足就是最后一页。"""
        full = '{"total": 200, "matches": [' + \
            ",".join('{"domain": "h%d.example.com"}' % i
                     for i in range(SHODAN_PAGE_SIZE)) + "]}"
        last = '{"total": 200, "matches": [{"domain": "z.example.com"}]}'
        seen, q = await self._pages([full, last])
        self.assertEqual(seen, [1, 2])
        self.assertEqual(q.credits_spent, 2, "两页就是两个 credit，"
                                              "记下来才知道额度花在哪")

    async def test_short_page_stops(self) -> None:
        seen, q = await self._pages(
            ['{"total": 5, "matches": [{"domain": "a.example.com"}]}']
        )
        self.assertEqual(seen, [1])
        self.assertEqual(q.credits_spent, 1)

    async def test_last_query_records_the_spend(self) -> None:
        _, q = await self._pages(
            ['{"total": 1, "matches": [{"domain": "a.example.com"}]}']
        )
        self.assertIn("hostname:example.com", q.last_query)
        self.assertIn("credit", q.last_query)


class TestCheckKey(unittest.IsolatedAsyncioTestCase):
    """「测试连接」必须走**不计费**的账号接口 —— 用户一天可能点很多次。"""

    def _q(self) -> Query:
        q = Query()
        q.init_key(api_key="k", interval=0)
        return q

    async def _run(self, resp: _Resp) -> tuple[bool, str, str]:
        seen: dict = {}

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            seen["url"] = url
            return resp

        q = self._q()
        with mock.patch.object(HTTPClient, "request", fake_request):
            ok, msg = await q.check_key(HTTPClient())
        return ok, msg, seen["url"]

    async def test_uses_the_free_profile_endpoint(self) -> None:
        """``/account/profile`` 不消耗查询额度 —— 与 FOFA 的
        ``/api/v1/info/my`` 同一思路。"""
        _, _, url = await self._run(
            _Resp(200, '{"plan": "member", "query_credits": 42}')
        )
        self.assertEqual(url, PROFILE_API)
        self.assertNotIn("search", url, "用搜索接口测连接 = 白烧一个 credit")

    async def test_reports_remaining_credits(self) -> None:
        """额度按月重置，很容易一夜烧光 —— 用户此刻最想看的就是它。"""
        ok, msg, _ = await self._run(
            _Resp(200, '{"plan": "member", "query_credits": 42,'
                       ' "scan_credits": 7}')
        )
        self.assertTrue(ok)
        self.assertIn("42", msg)
        self.assertIn("member", msg)

    async def test_error_payload_fails_cleanly(self) -> None:
        ok, msg, _ = await self._run(_Resp(200, '{"error": "Invalid API key"}'))
        self.assertFalse(ok)
        self.assertIn("Invalid API key", msg)

    async def test_exception_becomes_a_readable_failure(self) -> None:
        async def boom(self, method, url, **kwargs):  # noqa: ANN001
            return _Resp(401, "<html>nope</html>")

        q = self._q()
        with mock.patch.object(HTTPClient, "request", boom):
            ok, msg = await q.check_key(HTTPClient())
        self.assertFalse(ok)
        self.assertIn("鉴权失败", msg)


class TestShodanModule(EngineTestCase):
    """端到端：跑一次扫描，确认产出与作用域闸门。"""

    #: 官方形状。刻意混入**作用域外**的名字（``evil.other.com``）与
    #: 借道主机（``example.com.evil.net``）—— ``hostname:`` 是"包含"语义，
    #: 这两类是它必然带回来的噪声。
    PAYLOAD = {
        "total": 4,
        "matches": [
            {"ip_str": "93.184.216.7",
             "hostnames": ["www.example.com", "example.com.evil.net"],
             "domain": "www.example.com"},
            {"ip_str": "93.184.216.8",
             "hostnames": ["api.example.com"],
             "http": {"host": "api.example.com:8443"}},
            {"ip_str": "198.51.100.9", "domain": "cdn.other.com"},
        ],
    }

    async def _run(self, payload=None, *, config=None):
        payload = self.PAYLOAD if payload is None else payload
        seen: dict = {}

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            seen["url"] = url
            seen["params"] = dict(kwargs.get("params") or {})
            return _Resp(200, __import__("json").dumps(payload))

        cfg = {"api_key": "test-key"}
        if config:
            cfg.update(config)
        with mock.patch.object(HTTPClient, "request", fake_request):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["passive_shodan"],
                module_config={"passive_shodan": cfg},
            )
        self.seen = seen
        self.summary = summary
        return scanner, summary

    async def _names(self, scanner) -> set[str]:
        """落库的域名集合 —— 端到端断言只能打在这儿。

        别去读 ``scanner.state.events``：那是引擎的内部缓存，不是"最终
        进了资产表的东西"。作用域闸门正是在投影那一步生效的，只看事件
        会漏掉「闸门有没有真的挡住」。
        """
        return {d["name"] for d in await self.storage.domains(scanner.scan_id)}

    async def test_missing_key_soft_fails_and_scan_continues(self) -> None:
        """没配 ``api_key`` 就**软失败**：扫描继续，只是这个源不跑。

        （第一批测试就是忘了给 key，三条因此"抽不到资产"而挂。）
        """
        scanner, summary = await self.run_scan(
            targets=["example.com"], include=["passive_shodan"]
        )
        self.assertNotIn("passive_shodan", summary["modules_enabled"])
        self.assertIn("api_key", summary["modules_skipped"]["passive_shodan"])
        # 种子本身还在（DNS_NAME 由 seed_asset 产生），扫描没崩
        self.assertEqual(
            {d["name"] for d in await self.storage.domains(scanner.scan_id)},
            {"example.com"},
        )

    async def test_query_sent_to_the_official_endpoint(self) -> None:
        await self._run()
        self.assertEqual(self.seen["url"], DEFAULT_API)
        self.assertEqual(self.seen["params"]["query"], "hostname:example.com")
        self.assertEqual(self.seen["params"]["page"], "1")
        self.assertEqual(self.seen["params"]["key"], "test-key")

    async def test_source_is_recorded_on_the_asset(self) -> None:
        """产出必须标来源，否则资产表里分不清是哪个源找到的。

        ⚠️ 记在 ``domain.source`` 上的是**模块名**（``passive_shodan``），
        而 ``source_stats`` 里的键是**插件名**（``shodan``）——
        两套命名空间，别混：统计是按插件记的，资产是按模块记的。
        """
        scanner, _ = await self._run()
        rows = await self.storage.domains(scanner.scan_id)
        found = [r for r in rows if r["name"] == "www.example.com"]
        self.assertTrue(found, "一条子域都没产出")
        self.assertEqual(found[0].get("source"), "passive_shodan")
        stats = next(s for s in self.summary["source_stats"]
                     if s["source"] == "shodan")
        self.assertEqual(stats["results"], 2,
                         "统计里应该有 2 个子域（作用域外的已挡掉）")

    async def test_out_of_scope_names_are_dropped(self) -> None:
        """⚠️ **这条是 ``hostname:`` 包含语义的那道承重墙。**

        Shodan 会带回来 ``example.com.evil.net``（子串命中，不是子域）与
        ``cdn.other.com``（顺带同 IP 上的第三方）。``sanitize_subdomains``
        里的 ``is_subdomain_of`` 必须把它们全挡掉 —— 这道闸门要是失效，
        陌生人的域名会直接进资产表。
        """
        scanner, _ = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("www.example.com", names)
        self.assertIn("api.example.com", names)
        self.assertNotIn("example.com.evil.net", names,
                         "借道主机被当成了子域 —— 作用域闸门失效")
        self.assertNotIn("cdn.other.com", names,
                         "别人的域名进了资产表 —— 作用域闸门失效")
        self.assertFalse(any("other.com" in n for n in names), f"外域泄漏: {names}")

    async def test_http_host_with_port_is_normalized(self) -> None:
        """``http.host`` 带端口那条（``api.example.com:8443``）要能正常收下，
        且**不能**带端口入库。"""
        scanner, _ = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("api.example.com", names)
        self.assertFalse(any(":" in n or "/" in n for n in names),
                         f"没还原成主机名: {names}")

    async def test_empty_matches_does_not_break_the_scan(self) -> None:
        """``matches: []`` 是**正常**的空结果，不是错误。

        与"响应里压根没有 ``matches`` 键"要分开 —— 那个才是形状变了，
        见下一条。
        """
        scanner, summary = await self._run(
            payload={"total": 0, "matches": []}
        )
        self.assertIn("passive_shodan", summary["modules_enabled"])
        stats = next(s for s in summary["source_stats"]
                     if s["source"] == "shodan")
        self.assertEqual(stats["results"], 0)
        self.assertEqual(stats["errors"], 0, "空结果不该被记成错误")
        self.assertEqual(
            {d["name"] for d in await self.storage.domains(scanner.scan_id)},
            {"example.com"},
        )

    async def test_unparseable_shape_does_not_kill_the_scan(self) -> None:
        """形状认不出来时源报错，但**扫描继续**（异常由适配器兜住）。"""
        scanner, _ = await self._run(payload={"unexpected": "shape"})
        stats = next(s for s in self.summary["source_stats"]
                     if s["source"] == "shodan")
        self.assertEqual(stats["results"], 0)
        self.assertGreaterEqual(stats["errors"], 1, "异常没被记进源统计")
        self.assertEqual(
            {d["name"] for d in await self.storage.domains(scanner.scan_id)},
            {"example.com"}, "源炸了不该把种子也弄丢",
        )


if __name__ == "__main__":
    unittest.main()