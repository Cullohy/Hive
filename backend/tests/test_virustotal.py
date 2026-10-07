"""VirusTotal 源（``core/domains/subdomain/passive/virustotal.py``）。

## 为什么这批测试要盯这些点

**拿不到 VT 的 key，真实接口一次都没调过。** 而 VT 有**三个只改一行、
不报错**的坑：

1. **key 放请求头还是查询参数。** 官方明确要求 ``x-apikey`` **头**。
   写成 ``?apikey=`` 不会报"参数错"，只会 401，而且 key 进了 access log。
2. **游标要从 ``links.next`` 里切干净。** 那是个**完整 URL**：
   ``?cursor=zzz&limit=40``。用 ``rsplit("cursor=", 1)[0]`` 会把
   ``zzz&limit=40`` 整个当游标传回去，下一页必然 400。
   （这是冒烟时真踩到的，不是想象。）
3. **404 与「见过但没有子域」是两件事。** 前者是 key/域名有问题，
   后者是 200 + 空 ``data``。混起来就变成了"这个域名查不到东西"。

另外这个源的**限速是全仓最紧的**（4 次/分钟 vs Shodan 的 1 次/秒），
所以 ``interval=15`` / ``max_pages=1`` / ``recursive=False`` 三条默认值
都得钉住 —— 改宽了会直接撞 429，而 429 只表现为"这个源没产出"。

## ✅ 真实接口已验证（2026-10-07）

用免费 Public API key 打 ``example.com``，**走的是本模块**（不是探针）：

```
check_key   → OK，信誉 28，1 次请求
sub_domains → 80 条 / 2 页 / 30.4 秒（每页 40，第 2 页确实取到了）
清洗闸门    → 原始 80 → 真子域 80，零误伤
```

这一轮把下面几条「没查证到的」变成了已确认：

* **免费档能用 ``/domains/{id}/subdomains``**（最大的未知）
* ``x-apikey`` 头认证、``data[].id`` + ``type == "domain"`` 的抽法
* **游标翻页工作正常**（80 > 每页 40）
* 15 秒限速按设计生效

仍待确认：官方 ``limit`` 硬上限、超额是 429 还是静默降级、
其余关系类型在免费档的可用性。

## 剩余的验证清单（下次拿到额度再过）

1. ~~免费 Public API 能不能用 ``/domains/{id}/subdomains``~~ → **已确认能用**
2. ~~游标给在 ``meta`` 还是 ``links``~~ → **已确认两者都能取到（代码两条路都走）**
3. 故意把 key 填错 → 确认拿到的是**中文提示**而不是 `JSONDecodeError`
   （已用一把无效 key 实测过：接口回的是**规范的 JSON** 错误体
   `{"error":{"code":"WrongCredentialsError",...}}`，与 ``_explain`` 的读法一致；
   但**错误 key 的那条中文路径还没在真接口上走过**）
4. `curl -H "x-apikey: KEY" https://www.virustotal.com/api/v3/users/<你的id>/overall_quotas`
   对一下剩余额度（本模块不查，因为要先知道 user id）
5. 确认免费档超额是 429 还是静默降级（文档没说）
6. 确认 ``limit`` 能不能超过 40（代码夹到 100，社区观察是 40）

## ⚠️ 顺带记一条**别误读数据**的事

免费档拿 ``example.com`` 会返回 ``c2-financial-proxy`` / ``exfil`` /
``banklogin`` / ``instagrarn-verify`` 这一批 —— 那是 **VirusTotal 自己塞在
IANA 文档域名下的测试数据**，不是真实资产。拿它当"产出很高"的成功案例
会看走眼。
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.domains.subdomain.passive.virustotal import (  # noqa: E402
    DEFAULT_API,
    DEFAULT_INTERVAL,
    DEFAULT_PAGE_SIZE,
    Query,
    passive_virustotal,
)
from core.services.http import HTTPClient  # noqa: E402

from .base import EngineTestCase  # noqa: E402


class _Resp:
    def __init__(self, status_code: int = 200, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    async def aclose(self) -> None:
        pass


def _page(ids, *, cursor="", total=0):
    """造一页官方形状的响应。"""
    return {
        "data": [{"id": i, "type": "domain",
                  "links": {"self": f"https://x/api/v3/domains/{i}"}}
                 for i in ids],
        "meta": {"count": total, **({"cursor": cursor} if cursor else {})},
    }


class TestHostExtraction(unittest.TestCase):
    """JSON:API 的 ``data[]`` —— 只取 ``type == "domain"``。"""

    def test_takes_domain_entries(self) -> None:
        self.assertEqual(
            Query._hosts_of(_page(["a.example.com", "b.example.com"])),
            ["a.example.com", "b.example.com"],
        )

    def test_skips_non_domain_types(self) -> None:
        """关系接口理论上只回 domain，但**不能假设**。

        混进别的 type 时那一条会变成资产表里的垃圾，而且不报错。
        """
        data = {"data": [
            {"id": "ok.example.com", "type": "domain"},
            {"id": "1.2.3.4", "type": "ip_address"},
            {"id": "https://x/y", "type": "url"},
        ]}
        self.assertEqual(Query._hosts_of(data), ["ok.example.com"])

    def test_skips_empty_ids(self) -> None:
        self.assertEqual(
            Query._hosts_of({"data": [{"id": "", "type": "domain"}]}), [])

    def test_missing_type_is_not_taken(self) -> None:
        """没有 ``type`` 的条目同样不能收 —— 那说明形状变了。"""
        self.assertEqual(
            Query._hosts_of({"data": [{"id": "a.example.com"}]}), [])

    def test_non_dict_entries_skipped(self) -> None:
        self.assertEqual(Query._hosts_of({"data": ["x", None, 42]}), [])

    def test_missing_data_key(self) -> None:
        self.assertEqual(Query._hosts_of({"unexpected": "shape"}), [])

    def test_not_a_dict(self) -> None:
        self.assertEqual(Query._hosts_of("a string"), [])


class TestCursorParsing(unittest.TestCase):
    """⚠️ 游标要从**完整 URL** 里切干净。"""

    def test_meta_cursor(self) -> None:
        self.assertEqual(Query._next_cursor({"meta": {"cursor": "abc"}}), "abc")

    def test_links_next_is_read(self) -> None:
        """``meta.cursor`` 缺失时还有 ``links.next`` —— 只看一个会漏页。"""
        self.assertEqual(
            Query._next_cursor(
                {"meta": {}, "links": {"next": "https://x/y?cursor=zzz"}}),
            "zzz",
        )

    def test_cursor_is_trimmed_at_the_next_separator(self) -> None:
        """⚠️ **这条是冒烟时真踩到的坑。**

        ``links.next`` 后面还跟着别的参数。按 ``cursor=`` 一刀切会拿到
        ``zzz&limit=40``，当成游标传回去下一页必然 400。
        """
        self.assertEqual(
            Query._next_cursor(
                {"links": {"next": "https://x/y?cursor=zzz&limit=40"}}),
            "zzz",
        )
        self.assertEqual(
            Query._next_cursor(
                {"links": {"next": "https://x/y?limit=40&cursor=qqq"}}),
            "qqq",
        )

    def test_meta_wins_over_links(self) -> None:
        self.assertEqual(
            Query._next_cursor({"meta": {"cursor": "m"},
                                "links": {"next": "https://x?cursor=l"}}),
            "m",
        )

    def test_no_cursor_means_the_end(self) -> None:
        for data in ({"data": []}, {"meta": {}}, {"links": {}},
                     {"links": {"next": ""}}, "not a dict"):
            with self.subTest(data=data):
                self.assertEqual(Query._next_cursor(data), "")


class TestRateLimitDiscipline(unittest.TestCase):
    """VT 免费档 **4 次/分钟、500 次/天** —— 全仓最紧。"""

    def _q(self, **kw) -> Query:
        q = Query()
        q.init_key(api_key="k", **kw)
        return q

    def test_interval_defaults_to_fifteen_seconds(self) -> None:
        """4 req/min = 15 秒。这是**唯一**能在免费档活下来的节奏。"""
        self.assertEqual(DEFAULT_INTERVAL, 15.0)
        self.assertEqual(self._q().interval, 15.0)
        self.assertNotEqual(self._q().interval, 1.0,
                            "1 秒是 Shodan 的节奏，抄过来必撞 429")

    def test_defaults_to_one_page(self) -> None:
        """一天 500 次，翻页是奢侈品。"""
        self.assertEqual(self._q().max_pages, 1)

    def test_recursion_is_off(self) -> None:
        """递归 = 每个子域再一条请求。15 秒一个起步。"""
        self.assertFalse(Query.recursive)
        self.assertFalse(Query().recursive)

    def test_zero_and_negative_mean_default(self) -> None:
        self.assertEqual(self._q(max_pages=0).max_pages, 1)
        self.assertEqual(self._q(max_pages=-5).max_pages, 1)

    def test_page_size_default(self) -> None:
        self.assertEqual(DEFAULT_PAGE_SIZE, 40)
        self.assertEqual(self._q().page_size, 40)


class TestAuthIsInTheHeader(unittest.IsolatedAsyncioTestCase):
    """⚠️ **key 只能放 ``x-apikey`` 请求头。**

    官方文档明确要求。写成查询参数只会 401，而且 key 会被记进 access log。

    ⚠️ 这里**必须**是 ``IsolatedAsyncioTestCase``。第一版写成同步
    ``unittest.TestCase``，5 条 ``async def`` 用例**一次都没跑过**而报告全绿。
    而且 ``filterwarnings = ["error::RuntimeWarning"]`` **没抓住** ——
    pytest 把那条 ``RuntimeWarning: coroutine ... never awaited`` 包进了
    ``PytestUnraisableExceptionWarning``，于是只降级成 warning 照常算通过。
    这就是那个机制的一个洞，见 ``pyproject.toml`` 的补强。
    """

    async def _request(self, **kw) -> dict:
        q = Query()
        q.init_key(api_key="SECRET-KEY", interval=0, **kw)
        captured: dict = {}

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            captured["method"] = method
            captured["url"] = url
            captured["headers"] = dict(kwargs.get("headers") or {})
            captured["params"] = dict(kwargs.get("params") or {})
            return _Resp(200, json.dumps(_page(["a.example.com"])))

        with mock.patch.object(HTTPClient, "request", fake_request):
            await q.sub_domains("example.com", HTTPClient())
        return captured

    async def test_key_is_in_the_x_apikey_header(self) -> None:
        got = await self._request()
        self.assertEqual(got["headers"].get("x-apikey"), "SECRET-KEY")

    async def test_key_is_never_in_the_query(self) -> None:
        got = await self._request()
        self.assertNotIn("SECRET-KEY", json.dumps(got["params"]),
                         "key 进了查询参数 → 会进 access log")
        for key in ("apikey", "key", "api_key"):
            self.assertNotIn(key, got["params"])

    async def test_url_is_the_relationship_path(self) -> None:
        got = await self._request()
        self.assertEqual(got["method"], "GET")
        self.assertEqual(got["url"],
                         f"{DEFAULT_API}/domains/example.com/subdomains")

    async def test_base_url_trailing_slash_does_not_double(self) -> None:
        """配 ``https://host/api/v3/`` 不该拼出 ``//domains``。"""
        got = await self._request(api_url="https://host/api/v3/")
        self.assertEqual(got["url"], "https://host/api/v3/domains/example.com/subdomains")

    async def test_limit_is_sent(self) -> None:
        got = await self._request()
        self.assertEqual(got["params"].get("limit"), "40")

    async def test_cursor_absent_on_first_page(self) -> None:
        got = await self._request()
        self.assertNotIn("cursor", got["params"])


class TestPagination(unittest.IsolatedAsyncioTestCase):
    async def _pages(self, bodies, **kw) -> tuple[list[dict], Query]:
        seen: list[dict] = []

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            params = dict(kwargs.get("params") or {})
            seen.append(params)
            return _Resp(200, json.dumps(bodies.pop(0)))

        q = Query()
        q.init_key(api_key="k", interval=0, max_pages=len(bodies), **kw)
        with mock.patch.object(HTTPClient, "request", fake_request):
            out = await q.sub_domains("example.com", HTTPClient())
        self.out = out
        return seen, q

    async def test_cursor_is_carried_to_the_next_page(self) -> None:
        seen, _ = await self._pages([
            _page(["a.example.com"], cursor="C1"),
            _page(["b.example.com"]),
        ])
        self.assertEqual([p.get("cursor") for p in seen], [None, "C1"])

    async def test_stops_when_there_is_no_cursor(self) -> None:
        seen, _ = await self._pages([
            _page(["a.example.com"], cursor="C1"),
            _page(["b.example.com"]),
        ])
        self.assertEqual(len(seen), 2)
        self.assertEqual(self.out, ["a.example.com", "b.example.com"])

    async def test_max_pages_caps_the_walk(self) -> None:
        """即便还有游标，到 ``max_pages`` 就停 —— 15 秒一个请求。"""
        q = Query()
        q.init_key(api_key="k", interval=0, max_pages=1)
        calls = []

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            calls.append(1)
            return _Resp(200, json.dumps(_page(["a.example.com"], cursor="C1")))

        with mock.patch.object(HTTPClient, "request", fake_request):
            await q.sub_domains("example.com", HTTPClient())
        self.assertEqual(len(calls), 1)
        self.assertEqual(q.requests_spent, 1)


class TestErrorSemantics(unittest.IsolatedAsyncioTestCase):
    def _q(self) -> Query:
        q = Query()
        q.init_key(api_key="k", interval=0)
        return q

    async def _raise(self, resp: _Resp):
        q = self._q()

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            return resp

        with mock.patch.object(HTTPClient, "request", fake_request):
            await q.sub_domains("example.com", HTTPClient())

    async def test_401_points_at_the_key(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await self._raise(_Resp(401, '{"error":{"code":"AuthenticationRequiredError"}}'))
        msg = str(cm.exception)
        self.assertIn("鉴权失败", msg)
        self.assertIn("api_key", msg)

    async def test_429_explains_the_free_tier_limit(self) -> None:
        """429 在界面上只是"这个源没产出" —— 提示必须说清是额度。"""
        with self.assertRaises(RuntimeError) as cm:
            await self._raise(_Resp(429, "{}"))
        msg = str(cm.exception)
        self.assertIn("4 次/分钟", msg)
        self.assertIn("500 次/天", msg)
        self.assertIn("interval", msg, "没告诉用户可以调大间隔")

    async def test_403_mentions_enterprise_only(self) -> None:
        """部分关系类型是 Enterprise 专属 —— 免费账号可能直接用不了。"""
        with self.assertRaises(RuntimeError) as cm:
            await self._raise(_Resp(403, "{}"))
        self.assertIn("Enterprise", str(cm.exception))

    async def test_non_json_mentions_status(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            await self._raise(_Resp(200, "<html>maintenance</html>"))
        self.assertIn("不是 JSON", str(cm.exception))
        self.assertIn("200", str(cm.exception))

    async def test_not_found_is_distinguished_from_empty(self) -> None:
        """⚠️ 「完全没见过这个域名」≠「见过但没有子域」。

        混起来就变成"这个域名查不到东西" —— 而前者其实说明 key 或域名有问题。
        """
        body = {"error": {"code": "NotFoundError", "message": "Resource not found"}}
        with self.assertRaises(RuntimeError) as cm:
            await self._raise(_Resp(200, json.dumps(body)))
        self.assertIn("完全没见过", str(cm.exception))

    async def test_empty_data_is_not_an_error(self) -> None:
        """200 + 空 ``data`` 是正常结果 —— 见过的域名但没有子域。"""
        q = self._q()

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            return _Resp(200, json.dumps({"data": [], "meta": {"count": 0}}))

        with mock.patch.object(HTTPClient, "request", fake_request):
            self.assertEqual(await q.sub_domains("example.com", HTTPClient()), [])


class TestIpAcceptance(unittest.TestCase):
    def test_does_not_accept_ip_assets(self) -> None:
        """**故意的** —— ``/domains/{d}/resolutions`` 是 passive DNS 历史。

        写进 ``ip`` 表等于声称"这台机器被本次扫描探到过"，而实际上那可能
        是几个月前的解析记录。归属分档与存活口径会一起说谎，且不报错。
        """
        self.assertFalse(passive_virustotal.accepts_ip_assets)
        self.assertEqual(passive_virustotal.produced_events, ("DNS_NAME",))

    def test_it_is_metered(self) -> None:
        """会烧额度 → 内置预设默认不启用。"""
        self.assertIn("metered", passive_virustotal.flags)


class TestQueryInjectionGuard(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_target_is_refused(self) -> None:
        """目标要进 **URL 路径** —— 带 ``/`` 会拼出越界的路径。"""
        q = Query()
        q.init_key(api_key="k", interval=0)
        with self.assertRaises(ValueError) as cm:
            await q.sub_domains("evil/../../admin", HTTPClient())
        self.assertIn("不是合法域名", str(cm.exception))


class TestCheckKey(unittest.IsolatedAsyncioTestCase):
    async def _run(self, resp: _Resp):
        seen: dict = {}

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            seen["url"] = url
            return resp

        q = Query()
        q.init_key(api_key="k", interval=0)
        with mock.patch.object(HTTPClient, "request", fake_request):
            ok, msg = await q.check_key(HTTPClient())
        return ok, msg, seen["url"]

    async def test_says_it_costs_one_request(self) -> None:
        """VT **没有** key-free 的账号接口 —— 提示必须写明这一点。"""
        ok, msg, _ = await self._run(
            _Resp(200, json.dumps({"data": {"attributes": {}}}))
        )
        self.assertTrue(ok)
        self.assertIn("500", msg, "没写明这条探测会消耗额度")

    async def test_uses_the_domain_endpoint_not_the_relationship(self) -> None:
        """测连接不该去查一个真实目标的子域。"""
        _, _, url = await self._run(
            _Resp(200, json.dumps({"data": {"attributes": {}}}))
        )
        self.assertEqual(url, f"{DEFAULT_API}/domains/example.com")
        self.assertNotIn("subdomains", url)

    async def test_error_payload_fails_cleanly(self) -> None:
        ok, msg, _ = await self._run(
            _Resp(200, json.dumps({"error": {"code": "AuthenticationRequiredError",
                                            "message": "bad key"}}))
        )
        self.assertFalse(ok)
        self.assertIn("AuthenticationRequiredError", msg)


class TestVirusTotalModule(EngineTestCase):
    #: 官方形状。刻意混入**作用域外**的名字与别的 type ——
    #: JSON:API 关系接口不能假设只回 domain，而 ``is_subdomain_of``
    #: 是作用域的承重墙。
    PAYLOAD = _page(["www.example.com", "api.example.com",
                     "example.com.evil.net", "cdn.other.com"],
                    total=4)

    async def _run(self, payload=None, *, config=None):
        payload = self.PAYLOAD if payload is None else payload
        seen: dict = {}

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            seen["url"] = url
            seen["headers"] = dict(kwargs.get("headers") or {})
            seen["params"] = dict(kwargs.get("params") or {})
            return _Resp(200, json.dumps(payload))

        cfg = {"api_key": "test-key"}
        if config:
            cfg.update(config)
        with mock.patch.object(HTTPClient, "request", fake_request):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["passive_virustotal"],
                module_config={"passive_virustotal": cfg},
            )
        self.seen = seen
        self.summary = summary
        return scanner, summary

    async def test_missing_key_soft_fails_and_scan_continues(self) -> None:
        scanner, summary = await self.run_scan(
            targets=["example.com"], include=["passive_virustotal"]
        )
        self.assertNotIn("passive_virustotal", summary["modules_enabled"])
        self.assertIn("api_key", summary["modules_skipped"]["passive_virustotal"])
        self.assertEqual(
            {d["name"] for d in await self.storage.domains(scanner.scan_id)},
            {"example.com"},
        )

    async def test_key_goes_in_the_header_end_to_end(self) -> None:
        await self._run()
        self.assertEqual(self.seen["headers"].get("x-apikey"), "test-key")
        self.assertNotIn("test-key", json.dumps(self.seen["params"]))

    async def test_out_of_scope_names_are_dropped(self) -> None:
        scanner, _ = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("www.example.com", names)
        self.assertIn("api.example.com", names)
        self.assertNotIn("example.com.evil.net", names, "借道主机被当成了子域")
        self.assertNotIn("cdn.other.com", names, "别人的域名进了资产表")

    async def test_source_is_recorded_on_the_asset(self) -> None:
        scanner, _ = await self._run()
        rows = await self.storage.domains(scanner.scan_id)
        found = [r for r in rows if r["name"] == "www.example.com"]
        self.assertTrue(found)
        self.assertEqual(found[0].get("source"), "passive_virustotal")
        stats = next(s for s in self.summary["source_stats"]
                     if s["source"] == "virustotal")
        self.assertEqual(stats["results"], 2, "作用域外的应已被挡掉")

    async def test_empty_data_does_not_break_the_scan(self) -> None:
        scanner, summary = await self._run(
            payload={"data": [], "meta": {"count": 0}}
        )
        self.assertIn("passive_virustotal", summary["modules_enabled"])
        stats = next(s for s in summary["source_stats"]
                     if s["source"] == "virustotal")
        self.assertEqual(stats["results"], 0)
        self.assertEqual(stats["errors"], 0, "空结果不该被记成错误")

    async def test_unparseable_shape_does_not_kill_the_scan(self) -> None:
        scanner, _ = await self._run(payload={"unexpected": "shape"})
        stats = next(s for s in self.summary["source_stats"]
                     if s["source"] == "virustotal")
        self.assertEqual(stats["results"], 0)
        self.assertEqual(
            {d["name"] for d in await self.storage.domains(scanner.scan_id)},
            {"example.com"}, "源炸了不该把种子也弄丢",
        )


if __name__ == "__main__":
    unittest.main()