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
from pathlib import Path
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
        reason_phrase: str = "",
    ) -> None:
        self._data = data
        self.status_code = status
        self.headers = httpx.Headers({"Content-Type": content_type, **(headers or {})})
        self.history: list[httpx.Response] = []
        self.closed = False
        self._text: str | None = None
        self._url = url
        #: 真实 httpx.Response 有这个属性（wafw00f 的 ``matchReason`` 认它）
        self.reason_phrase = reason_phrase

    def read(self) -> bytes:
        return self._data

    async def read_async(self) -> bytes:
        return self._data

    async def aread(self) -> bytes:
        """httpx ``stream()`` 上下文里的全量读取。"""
        return self._data

    async def _iter_once(self):
        yield self._data

    def aiter_bytes(self):
        """真实 httpx.Response 的 ``aiter_bytes()`` 是**异步生成器函数**。"""
        return self._iter_once()

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


class ChunkedResponse(FakeResponse):
    """真·分块流，并**记录被消费了几块**。

    ``consumed`` 是这里唯一有意义的判据：光断言"拿到的字节 <= 上限"，
    回退成 ``await response.aread()`` 再切片也一样成立 —— 那正是这次改动
    要治的毛病（整包进内存，切片一分钱内存都省不下）。只有"没把整个流
    读完"才是真的省下了内存。
    """

    def __init__(self, total: int, chunk: int = 65536, **kw) -> None:
        super().__init__(b"", **kw)
        self.total = total
        self.chunk = chunk
        self.consumed = 0
        self.aread_called = False

    @property
    def total_chunks(self) -> int:
        return (self.total + self.chunk - 1) // self.chunk

    async def aread(self) -> bytes:
        # 模拟"整个 body 一次性进内存"
        self.aread_called = True
        self.consumed = self.total_chunks
        return b"A" * self.total

    async def _gen(self):
        left = self.total
        while left > 0:
            n = min(self.chunk, left)
            self.consumed += 1
            yield b"A" * n
            left -= n

    def aiter_bytes(self):
        return self._gen()


class FakeStreamCtx:
    """httpx ``AsyncClient.stream()`` 的形状。

    ⚠️ 真实 httpx 里 ``stream()`` 是被 ``@asynccontextmanager`` 装饰的方法：
    **调用它本身不发请求**，只是返回一个上下文管理器；真正的请求发生在
    ``__aenter__``。所以异常也必须由 ``__aenter__`` 抛。

    这里曾经写成"``stream()`` 直接抛异常"的形状，测试照样绿 —— 但那意味着
    桩和真实时序不一致：真实 httpx 是在进入上下文时才建连/读响应头，
    提前抛会漏掉"已经建连但读响应头失败"那一段。
    """

    def __init__(self, response: FakeResponse | Exception) -> None:
        self._response = response

    async def __aenter__(self) -> FakeResponse:
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    async def __aexit__(self, *exc: object) -> bool:
        if isinstance(self._response, FakeResponse):
            await self._response.aclose()
        return False


class FakeHttpxClient:
    """Fake httpx.AsyncClient，用于测试 fetch()。"""

    is_closed = False

    def __init__(self, response: FakeResponse | Exception) -> None:
        self._response = response
        #: ``get()`` 的调用记录，用于断言 fetch_bytes 的重定向参数
        self.get_calls: list[dict] = []

    async def request(self, method, url, **kwargs):
        if isinstance(self._response, Exception):
            raise self._response
        return self._response

    def stream(self, **kwargs) -> FakeStreamCtx:
        return FakeStreamCtx(self._response)

    async def get(self, url, **kwargs):
        self.get_calls.append({"url": url, **kwargs})
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


class TestStreamBoundedRead(unittest.IsolatedAsyncioTestCase):
    """``fetch()`` 的流式限量读取。

    改之前的形态是 ``await client.request()`` + ``raw[:max_bytes]`` 事后切片：
    切片看着在截断，其实整个 body 已经进内存了 —— 一个返回 500MB 的下载型
    端点，``http_probe`` 的 batch_size=10 并发下就足以把后端打爆。
    现在改成 ``client.stream()`` + 超限立刻 break。

    判据是 ``consumed``（流被消费了几块），不是"返回字节数没超" —— 后者
    在旧实现下同样成立，恒绿。
    """

    async def _fetch(self, resp: FakeResponse, max_bytes: int):
        fake = fake_httpx_client(resp)
        async with HTTPClient() as client:
            client._client = fake
            return await client.fetch("http://x/big", max_bytes=max_bytes)

    async def test_does_not_read_whole_body_when_over_limit(self) -> None:
        resp = ChunkedResponse(total=1024 * 1024, chunk=65536)
        result = await self._fetch(resp, max_bytes=65536)

        self.assertEqual(resp.total_chunks, 16)
        self.assertFalse(resp.aread_called, "不该走 aread()（那会把整包读进内存）")
        self.assertLess(resp.consumed, resp.total_chunks,
                        "流没读完 = 上限真的在生效")
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.text.encode("utf-8")), 65536)

    async def test_never_exceeds_limit_even_by_a_whole_chunk(self) -> None:
        """块比上限大时也必须切到上限 —— 少一个 chunk 不行，超一个也不行。"""
        resp = ChunkedResponse(total=200_000, chunk=100_000)
        result = await self._fetch(resp, max_bytes=1000)
        self.assertTrue(result.truncated)
        self.assertEqual(len(result.text.encode("utf-8")), 1000)
        # 第一块就超了，但那块本身是 100000 字节 -> 一定会被判截断
        self.assertEqual(resp.consumed, 1)

    async def test_body_under_limit_is_not_marked_truncated(self) -> None:
        resp = ChunkedResponse(total=100, chunk=65536)
        result = await self._fetch(resp, max_bytes=65536)
        self.assertFalse(result.truncated)
        self.assertEqual(result.text, "A" * 100)

    async def test_zero_max_bytes_means_unbounded(self) -> None:
        """``max_bytes<=0`` = 不设上限，那就老老实实全读。"""
        resp = ChunkedResponse(total=300_000, chunk=65536)
        result = await self._fetch(resp, max_bytes=0)
        self.assertFalse(result.truncated)
        self.assertEqual(len(result.text.encode("utf-8")), 300_000)
        self.assertEqual(resp.consumed, resp.total_chunks)

    async def test_stream_response_is_closed(self) -> None:
        """``async with`` 退出必须把连接还回池子，否则批量探测会耗尽连接。"""
        resp = ChunkedResponse(total=100, chunk=65536)
        await self._fetch(resp, max_bytes=65536)
        self.assertTrue(resp.closed)


class TestFetchBytesRedirects(unittest.IsolatedAsyncioTestCase):
    """``fetch_bytes()`` 的重定向与状态码（favicon 哈希就靠它）。

    httpx 0.28.x 的 ``AsyncClient`` 默认**不跟随**重定向，而 ``fetch()``
    是显式传了的 —— 两条路径不一致时，站点把 ``/favicon.ico`` 301 到别处
    （极常见）就会拿那个几十字节的重定向响应体算哈希。
    """

    async def _call(self, resp: FakeResponse):
        fake = fake_httpx_client(resp)
        async with HTTPClient() as client:
            client._client = fake
            data = await client.fetch_bytes("http://x/favicon.ico")
        return data, fake

    async def test_follows_redirects(self) -> None:
        resp = FakeResponse(b"\x00icon-bytes", status=200)
        _, fake = await self._call(resp)
        self.assertTrue(fake.get_calls, "根本没发请求")
        self.assertTrue(fake.get_calls[0].get("follow_redirects"),
                        "没显式跟随重定向 -> favicon 哈希算在跳转响应体上")

    async def test_non_200_final_status_yields_nothing(self) -> None:
        """跳完之后必须回 200；302 落地的登录页 HTML 拿来算哈希同样没意义。"""
        data, _ = await self._call(FakeResponse(b"<html>login</html>", status=302))
        self.assertEqual(data, b"")

    async def test_error_status_yields_nothing(self) -> None:
        data, _ = await self._call(FakeResponse(b"nope", status=404))
        self.assertEqual(data, b"")

    async def test_success_returns_bytes(self) -> None:
        data, _ = await self._call(FakeResponse(b"\x00icon-bytes", status=200))
        self.assertEqual(data, b"\x00icon-bytes")


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


class TestContentLength(unittest.TestCase):
    """``content_length`` 必须是**字节数**。

    起因是真跑 yealink 时对出来的：``http_probe`` 与 ``dir_brute`` 两处都写
    ``len(result.text)``，那是解码后的**字符数**。实测同一批页面：

    ==================================  =========  ==========
    页面                字符数(旧)     字节数(真)
    ==================================  =========  ==========
    support.yealink.com.cn              65506      65536
    ticket.yealink.com.cn                2150       2170
    ams.yealink.com.cn                   1732       1740
    ==================================  =========  ==========

    中文站一页 UTF-8 HTML 里两者差几百字节，所以这一列在**所有中文页面上
    都是错的**。界面把它当"长度"显示，而拿它判断"正文有没有被截断"
    （``content_length > body_max``）会得出**相反**的结论。
    """

    def _result(self, text, *, header=None, body_bytes=None):
        from core.services.http import FetchResult

        headers = {"Content-Type": "text/html; charset=utf-8"}
        if header is not None:
            headers["Content-Length"] = header
        raw = text.encode("utf-8")
        return FetchResult(
            url="http://x/", status=200, headers=headers, text=text,
            body_bytes=len(raw) if body_bytes is None else body_bytes,
        )

    def test_prefers_the_header_when_present(self) -> None:
        """头在就用头 —— 那是资源的**真实大小**，即使本地只读到一部分。"""
        from core.services.http import content_length

        r = self._result("短", header="999999")
        self.assertEqual(content_length(r), 999999,
                         "头就是权威值：本地截断了也不该改小")

    def test_falls_back_to_bytes_when_chunked(self) -> None:
        """实测 yealink 全家都是 chunked（没有这个头），这时只能用读到的字节数。"""
        from core.services.http import content_length

        r = self._result("中文页面" * 10)          # 40 字符 / 120 字节
        self.assertEqual(len(r.text), 40)
        self.assertEqual(content_length(r), 120, "chunked 下也得是字节数")

    def test_never_returns_the_character_count(self) -> None:
        """核心判据：含中文时结果必须 ≠ 字符数。"""
        from core.services.http import content_length

        text = "中" * 50                            # 50 字符 / 150 字节
        r = self._result(text)
        self.assertNotEqual(
            content_length(r), len(text),
            "又退回 len(text) 了 —— 中文页面上这一列是错的",
        )

    def test_last_resort_encodes_when_body_bytes_missing(self) -> None:
        """``body_bytes`` 没填（老构造路径）也不能退回字符数。"""
        from core.services.http import FetchResult, content_length

        r = FetchResult(url="http://x/", status=200, headers={}, text="中文")
        r.body_bytes = 0
        self.assertEqual(content_length(r), 6)      # 2 字 × 3 字节

    def test_truncated_still_reports_what_was_read(self) -> None:
        """被截断且没有头时，这一列只能等于"读到的字节数" —— 上限由标志表达。"""
        from core.services.http import content_length

        r = self._result("x" * 65536, body_bytes=65536)
        r.truncated = True
        self.assertEqual(content_length(r), 65536)


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


class TestPassiveSourceBodyCap(unittest.IsolatedAsyncioTestCase):
    """``get_text`` / ``get_json`` 的**响应体上限**（2026-10-07）。

    ## 为什么要有

    12 个被动源全都走 ``request``，而它内部是
    ``client.request()`` = ``send(stream=False)`` —— **body 在返回时就已经
    全进内存**。所以"取回来再切片"一分内存都省不下，那正是
    ``_read_bounded`` 存在的理由（``fetch`` 早就是流式的）。

    于是这条给 ``get_json`` / ``get_text`` 开了 ``max_bytes``，走
    :meth:`HTTPClient._read_text` 的流式路径。

    ## 默认值是 0（不限），**不是**一个"安全默认"

    因为**截断对不同响应形状的后果完全不同**：

    * **NDJSON**（commoncrawl 的 CDX 端点，一行一个 JSON）：安全降级，
      末尾半行被解析循环的 ValueError 分支吃掉。
    * **整体 JSON**（crt.sh）：**硬失败**。截断后 ``json.loads`` 直接抛。

    盲目给个默认上限，只会让"截断"变成"这个源坏了"。所以默认不限、
    由确认过形状的调用方显式传。

    ## 判据是"流被读完了吗"，不是"拿到的字节 <= 上限"

    只断言后者的话，回退成 ``await response.aread()`` 再切片也一样成立 ——
    而那正是这次要治的毛病。``ChunkedResponse.consumed`` 才是真判据。
    """

    async def test_default_is_unbounded_and_goes_through_request(self) -> None:
        """不传 ``max_bytes`` 时行为与以前**逐字一致**（走 request）。"""
        fake = fake_httpx_client(FakeResponse(b"hello"))
        async with HTTPClient() as client:
            client._client = fake
            self.assertEqual(await client.get_text("http://x/"), "hello")
            self.assertEqual(client.stats.get("truncated"), None,
                             "没传上限却记了截断")

    async def test_bounded_read_does_not_drain_the_whole_stream(self) -> None:
        resp = ChunkedResponse(total=300_000, chunk=1000)
        fake = fake_httpx_client(resp)
        async with HTTPClient() as client:
            client._client = fake
            text = await client.get_text("http://x/", max_bytes=5000)
        self.assertEqual(len(text), 5000)
        # 真判据：**没把流读完**。
        #
        # ⚠️ 别断言"恰好读了 5 块"—— ``_read_bounded`` 是 ``got > max_bytes``
        # 才 break，所以**必须读过线才知道超了**，末块会多读一块。这是
        # ``max_bytes + 一个数据块`` 的由来，不是 bug。
        self.assertLess(
            resp.consumed, resp.total_chunks,
            f"读了 {resp.consumed}/{resp.total_chunks} 块 —— 流被读完了，内存没省下",
        )
        self.assertFalse(resp.aread_called,
                         "走了 aread() = 整包进内存 = 白改")

    async def test_truncation_is_counted_and_logged(self) -> None:
        """截断必须**可观测**。

        静默返回一个不完整的响应，会让"这个域名资产少"看起来像源本身的性质 ——
        排查时先怀疑源，怀疑不到真凶。
        """
        resp = ChunkedResponse(total=300_000, chunk=1000)
        async with HTTPClient() as client:
            client._client = fake_httpx_client(resp)
            await client.get_text("http://x/", max_bytes=5000)
            self.assertEqual(client.stats["truncated"], 1)

    async def test_4xx_still_raises_in_the_streaming_path(self) -> None:
        """被动源靠**异常**判断"这一条源挂了"，所以 4xx 必须抛。

        ⚠️ 这条是 :meth:`HTTPClient._read_text` 存在的理由：``fetch`` 那条
        流式路径 4xx **不抛**（探活要看到状态码），直接拿来用会让所有被动源
        把错误当空结果。

        ⚠️ ``get_text`` 与 ``get_json`` 各有一份，**两条都得测** —— 只测一个
        时另一个被改成"不抛"照样全绿（变异验证实测过一次）。
        """
        async with HTTPClient() as client:
            client._client = fake_httpx_client(FakeResponse(b"nope", status=500))
            with self.assertRaises(httpx.HTTPStatusError):
                await client.get_text("http://x/", max_bytes=1000)

        async with HTTPClient() as client:
            client._client = fake_httpx_client(FakeResponse(b"{}", status=503))
            with self.assertRaises(httpx.HTTPStatusError):
                await client.get_json("http://x/", max_bytes=1000)

    async def test_network_error_propagates(self) -> None:
        async with HTTPClient(retries=0) as client:
            client._client = fake_httpx_client(httpx.ConnectError("boom"))
            with self.assertRaises(httpx.ConnectError):
                await client.get_text("http://x/", max_bytes=1000)

    async def test_get_json_bounded_parses_normally_when_under_limit(
        self,
    ) -> None:
        payload = b'[{"id": "CC-MAIN-2025-30"}]'
        async with HTTPClient() as client:
            client._client = fake_httpx_client(FakeResponse(payload))
            data = await client.get_json("http://x/", max_bytes=10_000)
        self.assertEqual(data, [{"id": "CC-MAIN-2025-30"}])
        self.assertEqual(client.stats.get("truncated"), None)

    def test_commoncrawl_passes_a_cap_because_its_shape_is_ndjson(self) -> None:
        """只有 NDJSON 形状才敢传 ``max_bytes``。

        这是本条改动最容易被人"顺手统一"的地方 —— 一旦有人给 crt.sh
        （整体 JSON）也加上限，截断会让 ``json.loads`` 抛，源从"慢"变成"坏"。
        所以把判据钉在这里。
        """
        from core.domains.subdomain.passive.commoncrawl import MAX_BODY_BYTES

        src = Path(
            "core/domains/subdomain/passive/commoncrawl.py"
        ).read_text(encoding="utf-8")
        self.assertIn("max_bytes=MAX_BODY_BYTES", src,
                      "commoncrawl 的索引端点没传上限 —— 单次流量最大的源")
        self.assertGreater(MAX_BODY_BYTES, 8 * 1024 * 1024,
                           "上限比实测的 qq.com 7.9MB 还小 → 会损失正常产出")
        # 解析循环必须能吃掉被截断的半行
        self.assertIn("except ValueError", src,
                      "NDJSON 解析循环没有跳过坏行的分支 → 截断会硬失败")


if __name__ == "__main__":
    unittest.main()
