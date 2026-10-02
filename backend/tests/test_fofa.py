"""FOFA 源（``core/domains/subdomain/passive/fofa.py``）。

## 为什么这批测试写得比别的源细

**我拿不到 FOFA 的 key，所以真实接口一次都没调过。** 而且这个源要同时兼容
**官方 API** 和**第三方中转** —— 后者的响应形状我完全不知道。

没有真实响应可对照时，唯一能做的就是：

1. 把**已知的官方形状**钉死（二维数组 + ``fields``）
2. 把**常见的中转站变体**各钉一条（对象数组、换个键名）
3. **认不出来的形状必须抛**，不能静默返回空 —— 空结果和"接口形状变了"长得
   一模一样，而后者需要人去改配置
4. 把那个最容易写错的坑（``host`` 是**完整 URL**）单独钉死

## 真实接口验证清单（拿到 key 后按这个过一遍）

1. 官方 ``api_url`` + 邮箱 + key → 能返回结果
2. 中转站的 ``api_url`` + key（不带邮箱）→ 能返回结果
3. 如果第 2 步报「找不到结果数组」，把**实际响应**贴出来，改
   ``_rows_of`` 的键名或 ``api_field``
"""

from __future__ import annotations

import base64
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.domains.subdomain.passive.fofa import (  # noqa: E402
    OFFICIAL_API,
    Query,
    _hosts_of,
    _rows_of,
)
from core.services.http import HTTPClient  # noqa: E402

from .base import EngineTestCase  # noqa: E402


class TestRowParsing(unittest.TestCase):
    """``_rows_of`` 的形状兼容 —— 纯函数，不碰引擎。"""

    def test_official_shape(self) -> None:
        data = {"error": False, "size": 2, "page": 1,
                "results": [["https://a.com"], ["https://b.com"]]}
        self.assertEqual(len(_rows_of(data)), 2)

    def test_object_array_shape(self) -> None:
        """部分中转站返回对象数组而不是二维数组。"""
        data = {"results": [{"host": "https://a.com"}, {"host": "https://b.com"}]}
        self.assertEqual(len(_rows_of(data)), 2)

    def test_alternate_key_names(self) -> None:
        for key in ("data", "list", "items"):
            with self.subTest(key=key):
                self.assertEqual(len(_rows_of({key: [{"host": "a.com"}]})), 1)

    def test_bare_array(self) -> None:
        self.assertEqual(len(_rows_of([["a.com"]])), 1)

    def test_error_true_raises(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            _rows_of({"error": True, "errmsg": "key 无效"})
        self.assertIn("key 无效", str(cm.exception))

    def test_nonzero_code_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            _rows_of({"code": 401, "msg": "unauthorized"})

    def test_zero_code_is_ok(self) -> None:
        self.assertEqual(len(_rows_of({"code": 0, "data": [{"host": "a.com"}]})), 1)

    def test_unknown_shape_raises_not_empty(self) -> None:
        """**认不出来必须抛。**

        静默返回空的话，"接口改了"和"这个域名真没资产"就分不开 ——
        而前者需要人去改配置。抛出去至少 ``SourceStats`` 里留着错误文本。
        """
        with self.assertRaises(ValueError) as cm:
            _rows_of({"unexpected": "shape"})
        self.assertIn("找不到结果数组", str(cm.exception))

    def test_wrong_type_raises(self) -> None:
        with self.assertRaises(ValueError):
            _rows_of("a string")


class TestQueryParams(unittest.TestCase):
    def _q(self, **kw) -> Query:
        q = Query()
        q.init_key(api_key="k", **kw)
        return q

    def test_qbase64_encodes_the_fofa_syntax(self) -> None:
        params = self._q()._params("example.com", 1)
        decoded = base64.b64decode(params["qbase64"]).decode()
        self.assertEqual(decoded, 'domain="example.com"')

    def test_key_is_sent(self) -> None:
        self.assertEqual(self._q()._params("a.com", 1)["key"], "k")

    def test_email_omitted_when_not_configured(self) -> None:
        """多数中转站不要邮箱 —— 不带这个参数，免得它们认成别的认证方式。"""
        self.assertNotIn("email", self._q()._params("a.com", 1))

    def test_email_included_when_configured(self) -> None:
        q = self._q(api_email="me@x.com")
        self.assertEqual(q._params("a.com", 1)["email"], "me@x.com")

    def test_official_url_is_default(self) -> None:
        q = self._q()
        self.assertEqual(q.api_url, OFFICIAL_API)
        self.assertFalse(q.is_relay, "没配中转地址却被标成了中转")

    def test_relay_url_overrides_and_is_flagged(self) -> None:
        q = self._q(api_url="https://relay.example.net/fofa")
        # 会自动补上接口路径，见 TestApiUrlNormalization
        self.assertEqual(
            q.api_url, "https://relay.example.net/fofa/api/v1/search/all"
        )
        self.assertTrue(q.is_relay, "配了中转却没标出来")

    def test_relay_is_never_a_default(self) -> None:
        """**中转站地址必须显式配。** 写死成默认值等于让人不知不觉走了第三方。"""
        self.assertNotIn("relay", OFFICIAL_API.lower())
        self.assertEqual(Query.api_url, OFFICIAL_API)

    def test_pagination_is_frugal_by_default(self) -> None:
        """免费额度紧，默认只查一页。"""
        q = self._q()
        self.assertEqual(q.max_pages, 1)
        self.assertEqual(q.page_size, 100)


class TestApiUrlNormalization(unittest.TestCase):
    """``api_url`` 要**同时接受 base 地址和完整接口地址**。

    ## 为什么这条必须有

    中转站的文档是这么教配置的：

    > 只需要将官网的 api 地址换成本站的 api 地址（``https://fofoapi.com``）即可

    所以**用户会自然地只填 base URL**。而 ``https://fofoapi.com`` 本身既是网页
    又是接口根 —— 直接请求它会拿到首页 HTML，然后 ``json.loads`` 抛一个
    莫名其妙的 ``Expecting value: line 1 column 1``。

    实测踩到过：配了 base URL，报"不是 JSON"，看起来像接口挂了。
    """

    def _url(self, raw: str) -> str:
        q = Query()
        q.init_key(api_key="k", api_url=raw)
        return q.api_url

    def test_base_url_gets_the_path(self) -> None:
        self.assertEqual(
            self._url("https://fofoapi.com"),
            "https://fofoapi.com/api/v1/search/all",
        )

    def test_trailing_slash_is_fine(self) -> None:
        self.assertEqual(
            self._url("https://fofoapi.com/"),
            "https://fofoapi.com/api/v1/search/all",
        )

    def test_full_endpoint_is_left_alone(self) -> None:
        full = "https://fofoapi.com/api/v1/search/all"
        self.assertEqual(self._url(full), full)

    def test_sub_path_base(self) -> None:
        """中转站挂在子路径下时，补在路径**后面**而不是替换掉它。"""
        self.assertEqual(
            self._url("https://x.com/fofa"),
            "https://x.com/fofa/api/v1/search/all",
        )

    def test_default_is_official(self) -> None:
        self.assertEqual(self._url(""), OFFICIAL_API)

    def test_relay_flag(self) -> None:
        q = Query()
        q.init_key(api_key="k", api_url="https://fofoapi.com")
        self.assertTrue(q.is_relay, "配了中转却没标出来")
        q2 = Query()
        q2.init_key(api_key="k")
        self.assertFalse(q2.is_relay, "官方地址被误标成中转")


class TestRelayErrorSemantics(unittest.TestCase):
    """中转站的错误提示要**翻译成人话**。

    它的公告为此连喊了三遍 —— 因为「账号无效」看起来像 key 错，
    实际是**接口地址没换**。不翻译的话用户会去反复检查 key。
    """

    def test_account_invalid_points_at_the_url(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            _rows_of({"error": True, "errmsg": "[-700] 账号无效"})
        msg = str(cm.exception)
        self.assertIn("api_url", msg, "没指出问题在接口地址上")
        self.assertIn("fofoapi.com", msg, "没给出可用的中转地址")

    def test_key_not_found_points_at_the_key(self) -> None:
        with self.assertRaises(RuntimeError) as cm:
            _rows_of({"error": True, "errmsg": "key 不存在"})
        self.assertIn("key 填错", str(cm.exception))

    def test_key_not_found_is_case_insensitive(self) -> None:
        """**实测返回的是大写的 ``Key``。**

        中转站给的是 ``[-101] Key 不存在``。只匹配小写的话会落到通用错误分支 ——
        提示还在，但丢了"接口是对的、问题在 key"这层指引，而用户此刻最需要的
        恰恰是别再怀疑接口地址。
        """
        with self.assertRaises(RuntimeError) as cm:
            _rows_of({"error": True, "errmsg": "[-101] Key 不存在"})
        self.assertIn("key 填错", str(cm.exception))
        self.assertIn("接口地址是对的", str(cm.exception))

    def test_quota_exhausted_demands_a_stop(self) -> None:
        """**配额耗尽必须当硬错误。**

        中转站明确要求脚本发现"已用完"就停，否则可能被封。
        当成"空结果"继续跑是最糟的处理方式。
        """
        with self.assertRaises(RuntimeError) as cm:
            _rows_of({"error": True, "errmsg": "今日配额已用完"})
        self.assertIn("必须停止", str(cm.exception))

    def test_quota_in_a_benign_field_still_trips(self) -> None:
        """「已用完」出现在任何字段里都要拦 —— 中转站没说它放哪个字段。"""
        with self.assertRaises(RuntimeError) as cm:
            _rows_of({"error": False, "tip": "你的配额已用完", "results": []})
        self.assertIn("必须停止", str(cm.exception))


class TestFlatStringArray(unittest.TestCase):
    """⚠️ **fofoapi 的 ``results`` 是「字符串扁平数组」**，不是官方的二维数组。

    实测响应：

        {"error": false, "results": ["https://example.com", "www.example.com",
                                     "example.com:8443"], ...}

    如果只按官方二维数组写（``row[0]``），字符串会被切成**首字母** ——
    而且不报错，只是资产全变成 ``h`` / ``w``。

    （官方 ``fields=host`` 给的是 ``[["https://x"], ...]``，两种都要吃。）
    """

    def test_flat_strings(self) -> None:
        hosts = _hosts_of(
            ["https://example.com", "www.example.com", "example.com:8443"], "host"
        )
        self.assertEqual(hosts, ["example.com", "www.example.com", "example.com"])

    def test_two_dimensional_rows(self) -> None:
        hosts = _hosts_of([["https://example.com"], ["b.example.com:8443"]], "host")
        self.assertEqual(hosts, ["example.com", "b.example.com"])

    def test_object_rows(self) -> None:
        hosts = _hosts_of([{"host": "https://a.example.com"}], "host")
        self.assertEqual(hosts, ["a.example.com"])

    def test_empty_rows_are_skipped(self) -> None:
        self.assertEqual(_hosts_of([[], "", None], "host"), [])


class TestFofaModule(EngineTestCase):
    #: 官方形状：``host`` 是**完整 URL**（带 scheme 和端口）
    OFFICIAL = {
        "error": False, "size": 5, "page": 1,
        "results": [
            ["https://www.example.com"],
            ["https://api.example.com:8443"],
            ["http://cdn.example.com/assets"],
            ["https://evil.other.com/x"],        # 作用域外
            ["not a url"],                       # 畸形
        ],
    }

    async def _run(self, payload=None, *, config=None):
        """跑一次扫描。

        ``config`` 默认给一个**有 key** 的配置 —— 不给的话源会软失败，
        什么都抽不到（第一版就是那么写的，三条测试因此挂了）。
        """
        seen: dict = {}

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            seen["url"] = url
            seen["params"] = dict(params or {})
            return payload if payload is not None else TestFofaModule.OFFICIAL

        cfg = {"api_key": "test-key"}
        if config:
            cfg.update(config)
        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["passive_fofa"],
                module_config={"passive_fofa": cfg},
            )
        self.seen = seen
        self.summary = summary
        return scanner

    async def test_missing_key_soft_fails_and_scan_continues(self) -> None:
        """没配 ``api_key`` 就**软失败**：扫描继续，只是这个源不跑。"""
        scanner, summary = await self.run_scan(
            targets=["example.com"], include=["passive_fofa"]
        )
        self.assertNotIn("passive_fofa", summary["modules_enabled"])
        self.assertIn("api_key", summary["modules_skipped"]["passive_fofa"])
        # 种子本身还在（DNS_NAME 由 seed_asset 产生），扫描没崩
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(names, {"example.com"})

    async def test_extracts_hostname_not_url(self) -> None:
        """**最容易写错的地方。**

        ``host`` 返回的是 ``https://api.example.com:8443``。直接丢给下游的话，
        ``normalize_domain`` 里的 ``split(":", 1)[0]`` 会把它切成 ``"https"``，
        整批结果**静默消失**。这和 ``commoncrawl`` / ``wayback`` 是同一个坑。
        """
        scanner = await self._run()
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        for expected in ("example.com", "www.example.com", "api.example.com",
                         "cdn.example.com"):
            self.assertIn(expected, names)
        self.assertFalse(any("other.com" in n for n in names), f"外域泄漏: {names}")
        self.assertFalse(
            any("/" in n or ":" in n or n in ("https", "http") for n in names),
            f"URL 没还原成主机名: {names}",
        )

    async def test_object_array_variant(self) -> None:
        """中转站返回对象数组时也要能解析。"""
        payload = {"code": 0, "data": [
            {"host": "https://a.example.com"},
            {"host": "https://b.example.com:9443"},
        ]}
        scanner = await self._run(payload)
        names = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("a.example.com", names)
        self.assertIn("b.example.com", names)

    async def test_relay_url_is_actually_used(self) -> None:
        """配了中转地址，请求就得打到那儿去。"""
        await self._run(config={"api_key": "k",
                                "api_url": "https://relay.example.net/fofa"})
        self.assertEqual(
            self.seen["url"], "https://relay.example.net/fofa/api/v1/search/all"
        )

    async def test_official_url_used_by_default(self) -> None:
        await self._run(config={"api_key": "k"})
        self.assertEqual(self.seen["url"], OFFICIAL_API)

    async def test_fields_is_sent(self) -> None:
        await self._run(config={"api_key": "k"})
        self.assertEqual(self.seen["params"]["fields"], "host")

    async def test_unknown_shape_does_not_kill_the_scan(self) -> None:
        """形状认不出来时，源报错但**扫描继续**（异常由适配器兜住）。"""
        scanner = await self._run({"unexpected": "shape"},
                                  config={"api_key": "k"})
        stats = self.summary.get("source_stats") or []
        fofa = next((s for s in stats if s["source"] == "fofa"), None)
        self.assertIsNotNone(fofa, f"没有 fofa 的源统计: {stats}")
        self.assertEqual(fofa["results"], 0)
        self.assertGreaterEqual(fofa["errors"], 1, "认不出的形状没被记成错误")

    async def test_invalid_target_is_refused(self) -> None:
        """目标要拼进查询语法，非法目标必须拒绝。

        不拒绝的话，一个带引号的目标能拼出**畸形的 FOFA 查询** ——
        轻则查不到，重则把别人的资产查回来。
        """
        q = Query()
        q.init_key(api_key="k")
        with self.assertRaises(ValueError) as cm:
            await q.sub_domains('x" OR domain="y.com', HTTPClient())
        self.assertIn("不是合法域名", str(cm.exception))

    async def test_not_recursive(self) -> None:
        """测绘引擎一次就拿到全量，再查一遍只会白烧额度。"""
        self.assertFalse(Query.recursive)
