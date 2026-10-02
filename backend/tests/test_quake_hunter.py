"""360 Quake 与奇安信 Hunter 两个测绘源。

## 为什么这两个源的测试要写得这么细

**它们的失败方式是"静默"的**，而且两家的错误语义都不是 HTTP 状态码：

* Quake：成功/失败 **HTTP 都是 200**，靠 body 的 ``code == 0`` 区分；
  而鉴权失败却是 **HTTP 401 + 纯文本 ``/quake/login``**（不是 JSON！）
* Hunter：**连鉴权失败都是 HTTP 200**，靠 ``code == 200`` 区分

所以"看状态码判断成败"这种直觉写法在两个源上**都会静默出错**。
下面把这几条钉死。

⚠️ 我没有这两家的 key，**真实接口一次都没调过**。接口形态来自官方文档、
``uncover`` / ``subfinder`` 源码、以及多个第三方实现（详见各自模块文档），
但**拿到 key 后仍应按模块文档里的"没查证到的"一节复核**。
"""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.domains.subdomain.passive.hunter import (  # noqa: E402
    DOMAIN_QUERIES,
    Query as HunterQuery,
    _pick_page_size,
)
from core.domains.subdomain.passive.quake import Query as QuakeQuery  # noqa: E402
from core.services.http import HTTPClient  # noqa: E402

from .base import EngineTestCase  # noqa: E402


class _FakeResponse:
    """够用的 aiohttp 响应替身（Quake 走 ``request()``，拿的是原始响应）。"""

    def __init__(self, status: int, text: str) -> None:
        self.status = status
        self._text = text
        self.released = False

    async def text(self) -> str:
        return self._text

    def release(self) -> None:
        self.released = True


# ══════════════════════════════════════════════════════════════════════ Quake


class TestQuakeAuthFailure(unittest.TestCase):
    """**Quake 的 401 响应体是纯文本，不是 JSON。**

    实测：``POST https://quake.360.net/api/v3/search/quake_service``（无/假 token）
    → ``HTTP 401`` + ``Content-Type: text/html`` + body **``/quake/login``**。

    先 ``json.loads`` 再看状态码的写法，会抛一个与真实原因毫无关系的
    ``JSONDecodeError`` —— 用户看到的是"接口返回格式不对"，而真相是 key 没填对。
    """

    def _query(self) -> QuakeQuery:
        q = QuakeQuery()
        q.init_key(api_key="k")
        return q

    async def _run(self, status: int, text: str):
        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            return _FakeResponse(status, text)

        with mock.patch.object(HTTPClient, "request", fake_request):
            async with HTTPClient(timeout=5.0, retries=0) as http:
                return await self._query().sub_domains("example.com", http)

    def test_plain_text_401_is_not_a_json_error(self) -> None:
        import asyncio

        with self.assertRaises(RuntimeError) as cm:
            asyncio.run(self._run(401, "/quake/login"))
        msg = str(cm.exception)
        self.assertIn("鉴权失败", msg)
        self.assertIn("/quake/login", msg)
        self.assertNotIn("JSONDecodeError", msg)
        self.assertIn("api_key", msg, "没告诉用户该去检查什么")

    def test_releases_the_response(self) -> None:
        """``request()`` 拿到的是原始响应，不 release 会漏连接。"""
        import asyncio

        captured: list[_FakeResponse] = []

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            r = _FakeResponse(401, "/quake/login")
            captured.append(r)
            return r

        async def go():
            with mock.patch.object(HTTPClient, "request", fake_request):
                async with HTTPClient(timeout=5.0, retries=0) as http:
                    try:
                        await self._query().sub_domains("example.com", http)
                    except RuntimeError:
                        pass

        asyncio.run(go())
        self.assertTrue(captured and captured[0].released, "响应没被 release")

    def test_non_json_body_is_reported_clearly(self) -> None:
        import asyncio

        with self.assertRaises(RuntimeError) as cm:
            asyncio.run(self._run(200, "<html>waf</html>"))
        self.assertIn("不是 JSON", str(cm.exception))


class TestQuakeErrorCodes(unittest.TestCase):
    """官方错误码要翻译成带处置建议的中文。

    Quake 的成功码是 **0**（Hunter 是 200，两者不同），失败时 HTTP 仍是 200。
    """

    def test_insufficient_credits(self) -> None:
        msg = QuakeQuery._explain("q2001", "用户当前积分不足以完成本次查询操作。")
        self.assertIn("积分不足", msg)

    def test_rate_limited_suggests_the_interval(self) -> None:
        msg = QuakeQuery._explain("q3005", "调用API过于频繁")
        self.assertIn("15", msg, "没给出官方的间隔建议")

    def test_bad_query(self) -> None:
        self.assertIn("查询语句出错", QuakeQuery._explain("t6003", "查询请求出错"))

    def test_unknown_code_keeps_the_raw_message(self) -> None:
        """**不认识的码不要瞎解释** —— 原文透出去才有排查依据。"""
        msg = QuakeQuery._explain("x9999", "某些没见过的情况")
        self.assertIn("x9999", msg)
        self.assertIn("某些没见过的情况", msg)


class TestQuakeResultParsing(unittest.TestCase):
    """子域名要看 ``service.http.host`` —— 那才是社区实际用的字段。"""

    def test_uses_service_http_host(self) -> None:
        items = [{"hostname": "", "service": {"http": {"host": "a.example.com"}}}]
        self.assertEqual(QuakeQuery._hosts_of(items), ["a.example.com"])

    def test_falls_back_to_hostname(self) -> None:
        items = [{"hostname": "b.example.com", "service": {}}]
        self.assertEqual(QuakeQuery._hosts_of(items), ["b.example.com"])

    def test_filters_non_ascii_placeholder(self) -> None:
        """**无权限时 ``service.http.host`` 会返回含中文的伪值。**

        subfinder 专门过滤它。不过滤的话资产表里会混进"暂无权限"这类垃圾。
        """
        items = [{"hostname": "ok.example.com",
                  "service": {"http": {"host": "暂无权限"}}}]
        self.assertEqual(QuakeQuery._hosts_of(items), ["ok.example.com"])

    def test_skips_empty(self) -> None:
        self.assertEqual(QuakeQuery._hosts_of([{}, {"hostname": None}]), [])

    def test_tolerates_net_location_difference(self) -> None:
        """官方参数表写 ``data.net``、JSON 示例里 ``net`` 在 ``service`` 内部。

        两个位置都兜 —— 这里只确保不因为缺字段而炸。
        """
        items = [{"net": {}, "service": {"net": {}, "http": {"host": "c.example.com"}}}]
        self.assertEqual(QuakeQuery._hosts_of(items), ["c.example.com"])


class TestQuakeRequestShape(unittest.TestCase):
    def _query(self, **kw) -> QuakeQuery:
        q = QuakeQuery()
        q.init_key(api_key="K", **kw)
        return q

    async def _capture(self, query: QuakeQuery):
        seen: dict = {}

        async def fake_request(self, method, url, **kwargs):  # noqa: ANN001
            seen["method"] = method
            seen["url"] = url
            seen.update(kwargs)
            return _FakeResponse(200, '{"code":0,"data":[],"meta":{}}')

        with mock.patch.object(HTTPClient, "request", fake_request):
            async with HTTPClient(timeout=5.0, retries=0) as http:
                await query.sub_domains("example.com", http)
        return seen

    def test_post_with_token_header(self) -> None:
        import asyncio

        seen = asyncio.run(self._capture(self._query()))
        self.assertEqual(seen["method"], "POST")
        self.assertEqual(seen["headers"]["X-QuakeToken"], "K")
        self.assertEqual(seen["headers"]["Content-Type"], "application/json")

    def test_body_shape(self) -> None:
        import asyncio

        seen = asyncio.run(self._capture(self._query()))
        body = seen["json"]
        self.assertEqual(body["query"], 'domain: "example.com"')
        self.assertEqual(body["start"], 0)
        self.assertIn("service.http.host", body["include"])

    def test_include_is_configurable(self) -> None:
        """``include`` 里出现白名单外的字段会让**整个请求失败** —— 所以要能改。"""
        import asyncio

        q = self._query(include="ip,port,hostname")
        seen = asyncio.run(self._capture(q))
        self.assertEqual(seen["json"]["include"], ["ip", "port", "hostname"])

    def test_page_size_is_clamped(self) -> None:
        # 0 与"没填"一视同仁（都表示用默认值），负数才是"要最小的"
        self.assertEqual(self._query(page_size=0).page_size, 100)
        self.assertEqual(self._query(page_size=None).page_size, 100)
        self.assertEqual(self._query(page_size=-5).page_size, 1)
        self.assertEqual(self._query(page_size=99999).page_size, 500)
        self.assertEqual(self._query(page_size=50).page_size, 50)


# ═════════════════════════════════════════════════════════════════════ Hunter


class TestHunterErrorSemantics(unittest.TestCase):
    """**Hunter 连鉴权失败都是 HTTP 200。**

    实测：无 key / 假 key → ``HTTP 200`` + ``{"code":401,"data":null,
    "message":"令牌缺失"}`` / ``"令牌过期"``。

    所以"看 HTTP 状态码判断成败"在这里会以为成功了，然后拿到空结果 ——
    这正是最常见的静默失败。
    """

    def test_missing_token_explains_where_to_put_it(self) -> None:
        msg = HunterQuery._explain(401, "令牌缺失")
        self.assertIn("未收到 API Key", msg)
        self.assertIn("系统设置", msg)

    def test_expired_token_says_where_to_get_a_new_one(self) -> None:
        msg = HunterQuery._explain(401, "令牌过期")
        self.assertIn("无效或已过期", msg)
        self.assertIn("用户中心", msg)

    def test_unknown_code_keeps_the_raw_message(self) -> None:
        """网上流传的"402 积分不足"找不到可验证来源，所以**不按码瞎解释**。"""
        msg = HunterQuery._explain(402, "某些没验证过的说法")
        self.assertIn("402", msg)
        self.assertIn("某些没验证过的说法", msg)

    def test_success_code_is_200_not_zero(self) -> None:
        """Hunter 的成功码是 **200**，Quake 是 **0** —— 两者不同，别抄错。"""
        self.assertNotEqual(HunterQuery._explain(200, "ok"), "ok")  # 200 不该走错误分支
        # 反过来：Hunter 收到 0 要当失败
        self.assertIn("code=0", HunterQuery._explain(0, ""))

    def test_http_200_with_code_401_is_a_failure(self) -> None:
        """**端到端**：HTTP 200 但 body 里 code=401 → 必须抛，不能当成功。"""
        import asyncio

        q = HunterQuery()
        q.init_key(api_key="k")

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            return {"code": 401, "data": None, "message": "令牌过期"}

        async def go():
            with mock.patch.object(HTTPClient, "get_json", fake_get_json):
                async with HTTPClient(timeout=5.0, retries=0) as http:
                    await q.sub_domains("example.com", http)

        with self.assertRaises(RuntimeError) as cm:
            asyncio.run(go())
        self.assertIn("无效或已过期", str(cm.exception))


class TestHunterPageSize(unittest.TestCase):
    """``page_size`` 只能取 1/10/50/100。传别的会被拒。"""

    def test_snaps_up_to_valid_values(self) -> None:
        # 用户的意图是"尽量多取"，所以向上取最近的合法值
        self.assertEqual(_pick_page_size(37), 50)
        self.assertEqual(_pick_page_size(11), 50)
        self.assertEqual(_pick_page_size(3), 10)

    def test_exact_values_kept(self) -> None:
        for n in (1, 10, 50, 100):
            self.assertEqual(_pick_page_size(n), n)

    def test_oversize_clamped(self) -> None:
        self.assertEqual(_pick_page_size(9999), 100)

    def test_garbage_becomes_one(self) -> None:
        self.assertEqual(_pick_page_size("abc"), 1)
        self.assertEqual(_pick_page_size(None), 1)


class TestHunterRequestShape(unittest.TestCase):
    def _query(self, **kw) -> HunterQuery:
        q = HunterQuery()
        q.init_key(api_key="K", **kw)
        return q

    async def _capture(self, query: HunterQuery, payload: dict):
        seen: dict = {}

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            seen["url"] = url
            seen["params"] = dict(params or {})
            return payload

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            async with HTTPClient(timeout=5.0, retries=0) as http:
                names = await query.sub_domains("example.com", http)
        return seen, names

    def test_key_goes_in_the_query_string(self) -> None:
        import asyncio

        payload = {"code": 200, "data": {"arr": [], "total": 0}}
        seen, _ = asyncio.run(self._capture(self._query(), payload))
        self.assertEqual(seen["params"]["api-key"], "K")

    def test_search_is_base64url(self) -> None:
        import asyncio

        payload = {"code": 200, "data": {"arr": [], "total": 0}}
        seen, _ = asyncio.run(self._capture(self._query(), payload))
        decoded = base64.urlsafe_b64decode(seen["params"]["search"]).decode()
        self.assertEqual(decoded, DOMAIN_QUERIES[0].format(target="example.com"))

    def test_page_size_defaults_to_100(self) -> None:
        import asyncio

        payload = {"code": 200, "data": {"arr": [], "total": 0}}
        seen, _ = asyncio.run(self._capture(self._query(), payload))
        self.assertEqual(seen["params"]["page_size"], "100")

    def test_extracts_domain_field(self) -> None:
        import asyncio

        payload = {"code": 200, "data": {"arr": [
            {"domain": "a.example.com", "url": "https://a.example.com/"},
            {"domain": "b.example.com"},
        ], "total": 2}}
        _, names = asyncio.run(self._capture(self._query(), payload))
        self.assertEqual(names, ["a.example.com", "b.example.com"])

    def test_falls_back_to_url_when_domain_empty(self) -> None:
        import asyncio

        payload = {"code": 200, "data": {"arr": [
            {"domain": "", "url": "https://c.example.com/x"},
        ], "total": 1}}
        _, names = asyncio.run(self._capture(self._query(), payload))
        self.assertEqual(names, ["https://c.example.com/x"],
                         "domain 为空时要用 url 兜底（下游会抠主机名）")

    def test_domain_suffix_fallback(self) -> None:
        """``domain.suffix=`` 与 ``domain_suffix=`` 哪个生效**没有官方文档背书**。

        所以两种都试：第一种返回错误码时自动退到第二种 —— 否则在只认旧写法的
        账号上这个源会一条都拿不到。
        """
        import asyncio

        calls: list[str] = []

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            decoded = base64.urlsafe_b64decode((params or {})["search"]).decode()
            calls.append(decoded)
            if decoded.startswith("domain.suffix="):
                return {"code": 400, "data": None, "message": "语法错误"}
            return {"code": 200, "data": {"arr": [{"domain": "x.example.com"}],
                                          "total": 1}}

        async def go():
            q = self._query()
            with mock.patch.object(HTTPClient, "get_json", fake_get_json):
                async with HTTPClient(timeout=5.0, retries=0) as http:
                    return await q.sub_domains("example.com", http)

        names = asyncio.run(go())
        self.assertEqual(names, ["x.example.com"])
        self.assertEqual(len(calls), 2, f"没有退到第二种写法: {calls}")
        self.assertTrue(calls[1].startswith("domain_suffix="))

    def test_auth_error_does_not_retry_the_other_syntax(self) -> None:
        """鉴权问题跟查询语法无关，换写法只会白发一次请求。"""
        import asyncio

        calls: list[str] = []

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            calls.append("x")
            return {"code": 401, "data": None, "message": "令牌缺失"}

        async def go():
            q = self._query()
            with mock.patch.object(HTTPClient, "get_json", fake_get_json):
                async with HTTPClient(timeout=5.0, retries=0) as http:
                    await q.sub_domains("example.com", http)

        with self.assertRaises(RuntimeError):
            asyncio.run(go())
        self.assertEqual(len(calls), 1, "鉴权失败后不该再试另一种语法")


class TestSourcesAreWired(EngineTestCase):
    """两个源要能被引擎发现、且缺 key 时软失败（扫描继续）。"""

    async def test_missing_key_soft_fails(self) -> None:
        for module in ("passive_quake", "passive_hunter"):
            with self.subTest(module=module):
                scanner, summary = await self.run_scan(
                    targets=["example.com"], include=[module]
                )
                self.assertNotIn(module, summary["modules_enabled"])
                self.assertIn("api_key", summary["modules_skipped"][module])


if __name__ == "__main__":
    unittest.main()
