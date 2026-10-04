"""HTTP 客户端自身的测试。

M2 的被动源测试把 ``get_json`` / ``get_text`` **整个打桩**了，
M4 的探活测试打桩的是 ``HTTPClient.fetch`` —— 这条测的是这两个都没覆盖到的
中间路径：解码逻辑、异常处理、stats 计数。

打桩点在 ``_get_client()``（httpx.AsyncClient 级别），把上面的解码/重试/异常处理全部跑到。
"""

from __future__ import annotations

import asyncio
import os
import unittest
from unittest import mock

import httpx

from core.services.http import HTTPClient, _decode_body


class FakeResponse:
    """够用的假响应：``status_code`` / ``headers`` / ``read`` / ``text`` / ``url`` / ``request``。

    ⚠️ **刻意只提供 httpx.Response 真正有的东西。** 早先这里还给过
    ``async with`` 与 ``release()``（aiohttp 的形状），于是
    ``services/http.py`` 写成 ``async with response`` 也能测过 —— 而真实
    httpx.Response 根本没有上下文管理器协议。结果是测试全绿、被动源全挂
    （fofa/hunter/crtsh… 全部 ``TypeError``）。**别给假响应加真实对象没有的能力。**
    """

    def __init__(
        self,
        data: bytes,
        *,
        status: int = 200,
        headers=None,
        content_type: str = "text/plain; charset=utf-8",
        url: str = "http://fake/",
    ) -> None:
        self._data = data
        self.status_code = status
        self.headers = httpx.Headers({"Content-Type": content_type, **(headers or {})})
        self.history: list[httpx.Response] = []
        self.closed = False
        self._text: str | None = None
        self._url = url

    def read(self) -> bytes:
        return self._data

    async def read_async(self) -> bytes:
        return self._data

    @property
    def text(self) -> str:
        if self._text is None:
            self._text = self._data.decode("utf-8", errors="replace")
        return self._text

    @property
    def url(self) -> httpx.URL:
        return httpx.URL(self._url)

    async def aclose(self) -> None:
        """AsyncClient 拿到的响应要用 ``await aclose()`` 收尾（没有 ``release()``）。"""
        self.closed = True

    # httpx.HTTPStatusError 需要 response.request
    @property
    def request(self) -> httpx.Request:
        return httpx.Request("GET", self._url)


class BrokenEncodingResponse(FakeResponse):
    """模拟解压失败的响应（read() 抛 DecodingError）。"""

    def read(self) -> bytes:
        raise httpx.DecodingError("Can not decode content-encoding: br")

    @property
    def text(self) -> str:
        # get_text 访问 .text 时直接抛 DecodingError
        raise httpx.DecodingError("Can not decode content-encoding: br")


class FakeHttpxClient:
    """Fake httpx.AsyncClient，用于测试 fetch()。"""

    is_closed = False

    def __init__(self, response: FakeResponse | Exception) -> None:
        self._response = response

    async def request(self, method, url, **kwargs):
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def aclose(self) -> None:
        self.is_closed = True


def fake_httpx_client(response: FakeResponse | Exception) -> FakeHttpxClient:
    """返回预设响应的 FakeHttpxClient 构造器。"""
    return FakeHttpxClient(response)


class TestDecodeBody(unittest.TestCase):
    def test_charset_from_header(self) -> None:
        raw = "中文".encode("gbk")
        self.assertEqual(_decode_body(raw, "text/html; charset=gbk"), "中文")

    def test_falls_back_to_utf8_then_gbk(self) -> None:
        self.assertEqual(_decode_body("你好".encode("utf-8"), "text/html"), "你好")
        # 声明里没 charset 且不是合法 UTF-8 → 回退 GBK
        self.assertEqual(_decode_body("你好".encode("gbk"), "text/html"), "你好")

    def test_never_raises(self) -> None:
        self.assertIsInstance(_decode_body(b"\xff\xfe\x00bad", ""), str)
        self.assertEqual(_decode_body(b"", ""), "")


class TestFetchPath(unittest.IsolatedAsyncioTestCase):
    """测试 get_text / get_json / fetch 的真实路径。

    get_text/get_json 通过打桩 HTTPClient.request 覆盖（它们调用它）。
    fetch 直接调 httpx.AsyncClient.request，需要打桩 _get_client()。
    """

    # ------------------------------------------------------------------ get_text / get_json / error_status
    async def _with_fake_request(self, factory, coro):
        """打桩 HTTPClient.request 并运行 coRoutine。"""
        async def _request(self, method, url, **kwargs):
            result = factory(url, kwargs)
            if isinstance(result, Exception):
                raise result
            return result

        with mock.patch.object(HTTPClient, "request", _request):
            async with HTTPClient() as client:
                return await coro(client)

    async def test_get_text(self) -> None:
        await self._with_fake_request(
            lambda url, kw: FakeResponse("你好，世界".encode()),
            lambda client: client.get_text("http://x/"),
        )
        self.assertEqual(
            await self._with_fake_request(
                lambda url, kw: FakeResponse("你好，世界".encode()),
                lambda client: client.get_text("http://x/"),
            ),
            "你好，世界",
        )

    async def test_get_json(self) -> None:
        body = b'{"subdomains": ["www", "api"]}'
        result = await self._with_fake_request(
            lambda url, kw: FakeResponse(body, content_type="application/json"),
            lambda client: client.get_json("http://x/"),
        )
        self.assertEqual(result, {"subdomains": ["www", "api"]})

    async def test_error_status_raises(self) -> None:
        with self.assertRaises(httpx.HTTPStatusError):
            await self._with_fake_request(
                lambda url, kw: FakeResponse(b"nope", status=404),
                lambda client: client.get_text("http://x/"),
            )

    async def test_encoding_failure_retries_with_identity(self) -> None:
        """读取正文失败时应改用 identity 再试一次。"""
        seen: list[dict] = []

        def factory(url, kwargs):
            seen.append(dict(kwargs.get("headers") or {}))
            if len(seen) == 1:
                return BrokenEncodingResponse(b"")
            return FakeResponse("ok".encode())

        await self._with_fake_request(factory, lambda client: client.get_text("http://x/"))

        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[1].get("Accept-Encoding"), "identity")

    # ------------------------------------------------------------------ fetch（打桩 _get_client）
    async def test_fetch_result_fields(self) -> None:
        fake = fake_httpx_client(
            FakeResponse(
                b"<html><title>Hi</title></html>",
                headers={"Server": "nginx", "Set-Cookie": "a=1"},
            )
        )
        async with HTTPClient() as client:
            client._client = fake
            result = await client.fetch("http://x/", max_bytes=64)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.status, 200)
        self.assertEqual(result.server, "nginx")
        self.assertIn("<title>Hi</title>", result.text)

    async def test_accept_encoding_default_excludes_br(self) -> None:
        """brotli 需要显式开启才声明，默认不声明。"""
        from core.services.http import _accept_encoding

        self.assertNotIn("br", _accept_encoding(False))
        self.assertIn("gzip", _accept_encoding(False))

    async def test_fetch_returns_none_on_network_error(self) -> None:
        fake = fake_httpx_client(httpx.ConnectError("boom"))
        async with HTTPClient(retries=0) as client:
            client._client = fake
            self.assertIsNone(await client.fetch("http://x/"))


class TestRequestStats(unittest.IsolatedAsyncioTestCase):
    """``HTTPClient.stats`` —— 被动源的"发了几次请求"就是从这里取的。"""

    class FakeSession:
        closed = False
        is_closed = False  # _get_client() 需要

        def __init__(self, responses) -> None:
            self._responses = list(responses)
            self.calls = 0

        async def request(self, method, url, **kwargs):
            self.calls += 1
            if not self._responses:
                return FakeResponse(b"ok")
            item = self._responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item

        async def aclose(self) -> None:
            self.closed = True

    async def test_counts_every_attempt_including_retries(self) -> None:
        session = self.FakeSession(
            [FakeResponse(b"", status=500), FakeResponse(b"ok")]
        )
        async with HTTPClient(retries=2, backoff=0.01) as client:
            client._client = session
            resp = await client.request("GET", "http://x/")
            self.assertEqual(resp.status_code, 200)
        self.assertEqual(session.calls, 2)
        self.assertEqual(client.stats["requests"], 2)
        self.assertEqual(client.stats["retries"], 1)
        self.assertEqual(client.stats["errors"], 0)

    async def test_counts_network_errors(self) -> None:
        session = self.FakeSession([httpx.ConnectError("boom")])
        async with HTTPClient(retries=0) as client:
            client._client = session
            with self.assertRaises(httpx.ConnectError):
                await client.request("GET", "http://x/")
        self.assertEqual(client.stats["requests"], 1)
        self.assertEqual(client.stats["errors"], 1)

    async def test_clean_success_counts_once(self) -> None:
        session = self.FakeSession([FakeResponse(b"ok")])
        async with HTTPClient(retries=2) as client:
            client._client = session
            await client.request("GET", "http://x/")
        self.assertEqual(client.stats, {"requests": 1, "retries": 0, "errors": 0})


class TestProxyResolution(unittest.TestCase):
    """代理怎么定 —— 这里定错一次，整场扫描的出站就是错的。

    起因：httpx 默认 ``trust_env=True``，会现读 shell 的 ``HTTP_PROXY``。
    于是**同一个后端换个 shell 启动就是两种行为**，而代理没开时的表现是
    "每个源都超时"，看着像源全挂了。现在改成显式解析，优先级写死在
    :func:`resolve_proxy` 里。
    """

    #: 这些名字会**破坏**本机配置，全部摘掉再测
    _NOISE = ("RECON_PROXY", "HTTPS_PROXY", "https_proxy",
              "HTTP_PROXY", "http_proxy")

    def setUp(self) -> None:
        from core.services import http as http_mod

        self.mod = http_mod
        self._saved = {k: os.environ.pop(k, None) for k in self._NOISE}
        # _env_proxy 带 lru_cache，不清的话上一条用例的结论会渗进下一条
        http_mod._env_proxy.cache_clear()
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        for k, v in self._saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v
        self.mod._env_proxy.cache_clear()

    def _set_env(self, **kwargs: str) -> None:
        for k, v in kwargs.items():
            os.environ[k] = v
        self.mod._env_proxy.cache_clear()

    # ------------------------------------------------------------------
    def test_explicit_argument_wins(self) -> None:
        self._set_env(RECON_PROXY="http://127.0.0.1:1111")
        self.assertEqual(
            self.mod.resolve_proxy("http://127.0.0.1:2222"),
            "http://127.0.0.1:2222",
        )

    def test_recon_proxy_env_wins_over_the_standard_names(self) -> None:
        """项目自己的变量必须压得住通用的 ``HTTPS_PROXY``。"""
        self._set_env(
            RECON_PROXY="http://127.0.0.1:1111",
            HTTPS_PROXY="http://127.0.0.1:2222",
        )
        self.assertEqual(self.mod.resolve_proxy(None), "http://127.0.0.1:1111")

    def test_standard_env_is_the_last_resort(self) -> None:
        self._set_env(HTTPS_PROXY="http://127.0.0.1:2222")
        self.assertEqual(self.mod.resolve_proxy(None), "http://127.0.0.1:2222")

    def test_no_configure_means_direct(self) -> None:
        self.assertIsNone(self.mod.resolve_proxy(None))

    def test_explicit_empty_string_forces_direct(self) -> None:
        """预设里写 ``proxy: ""`` = 这一轮强制直连，**必须盖掉**环境变量。

        这是整套设计里最要紧的一条语义：用户在"shell 里还留着陈旧
        HTTP_PROXY"的机器上需要能把出站钉死。要是空串被当成"没配"
        继续往下找环境，这个明确的关闭意图就等于没写。
        """
        self._set_env(
            RECON_PROXY="http://127.0.0.1:1111",
            HTTPS_PROXY="http://127.0.0.1:2222",
        )
        self.assertIsNone(self.mod.resolve_proxy(""))
        self.assertIsNone(self.mod.resolve_proxy("   "))

    def test_env_empty_string_also_forces_direct(self) -> None:
        """``RECON_PROXY=``（显式设成空）同样是"关闭"，不是"没配"。"""
        self._set_env(RECON_PROXY="", HTTP_PROXY="http://127.0.0.1:2222")
        self.assertIsNone(self.mod.resolve_proxy(None))

    def test_falsy_spellings_all_mean_off(self) -> None:
        """``RECON_PROXY=0`` / ``off`` / ``false`` 都不能被当成代理地址。"""
        for value in ("0", "off", "false", "none", "OFF", "None"):
            with self.subTest(value=value):
                self._set_env(RECON_PROXY=value)
                self.assertIsNone(self.mod.resolve_proxy(None))

    def test_env_is_read_once_then_frozen(self) -> None:
        """环境改了也不该让长生命周期的客户端行为漂移。

        一个 ``HTTPClient`` 跑整场扫描，代理要在建的时候定下来。
        """
        self._set_env(RECON_PROXY="http://127.0.0.1:1111")
        self.assertEqual(self.mod.resolve_proxy(None), "http://127.0.0.1:1111")
        os.environ["RECON_PROXY"] = "http://127.0.0.1:9999"
        self.assertEqual(
            self.mod.resolve_proxy(None), "http://127.0.0.1:1111",
            "环境在进程生命周期里被改了也不该影响已解析的代理",
        )

    # ------------------------------------------------------------------
    def test_client_resolves_at_construction(self) -> None:
        self._set_env(RECON_PROXY="http://127.0.0.1:1111")
        self.assertEqual(HTTPClient().proxy, "http://127.0.0.1:1111")
        self.assertIsNone(HTTPClient(proxy="").proxy)

    def test_trust_env_defaults_to_off(self) -> None:
        """**默认必须是关的。**

        开着的话 httpx 会在每次连接时现读环境，代理就成了"进程跑到哪一步
        算哪一步"，排查起来没法复现。
        """
        self.assertFalse(HTTPClient().trust_env)
        self.assertTrue(HTTPClient(trust_env=True).trust_env)


class TestSlowSourceTimeouts(unittest.TestCase):
    """慢源的默认超时。

    这类值很容易被当成"魔法数字"随手改，所以钉住两件事：
    **别退回紧到会稳定超时的值**，以及 **它真的能被配置覆盖**。
    """

    def test_commoncrawl_default_is_wide_enough(self) -> None:
        from core.domains.subdomain.passive.commoncrawl import Query

        #: 7.9MB 的通配查询，不挂代理直连时比实测值慢好几倍
        self.assertGreaterEqual(Query.default_http_timeout, 800.0)

    def test_slow_sources_declare_their_own(self) -> None:
        """慢源必须声明自己的超时，否则会用统一的 60 秒被误判成"挂了"。"""
        from core.domains.subdomain.passive.commoncrawl import Query as CC
        from core.domains.subdomain.passive.crtsh import Query as CRT
        from core.domains.subdomain.passive.wayback import Query as WB

        for name, q in (("commoncrawl", CC), ("crtsh", CRT), ("wayback", WB)):
            with self.subTest(source=name):
                self.assertGreater(q.default_http_timeout, 60.0)

    def test_module_config_overrides_the_default(self) -> None:
        """``active`` 预设里必须**真的**写着这个值。

        这里直接读预设文件，而不是复刻一遍取值逻辑 —— 复刻出来的断言
        只能证明"我自己写的那个函数返回了它自己刚传进去的值"。
        """
        from pathlib import Path

        from core.engine.preset import Preset

        from core.domains.subdomain.passive.commoncrawl import Query

        preset = Preset.load(
            Path(__file__).resolve().parents[1] / "core" / "presets" / "active.yml"
        )
        self.assertEqual(
            float(preset.module_config["passive_commoncrawl"]["http_timeout"]),
            800.0,
            "active 预设里没写死这个超时，改它只能去翻 Python 源码",
        )
        # 预设的值必须**大于等于**类属性默认值，否则预设反而在收紧超时
        self.assertGreaterEqual(
            float(preset.module_config["passive_commoncrawl"]["http_timeout"]),
            Query.default_http_timeout,
        )


if __name__ == "__main__":
    unittest.main()
