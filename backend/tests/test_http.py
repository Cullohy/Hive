"""HTTP 客户端自身的测试。

存在的理由：M2 的被动源测试把 ``get_json`` / ``get_text`` **整个打桩**了，
M4 的探活测试打桩的是 ``HTTPClient.fetch`` —— 于是 ``_fetch`` 这条真实路径
从来没有被测到过，而它恰恰在一次重构里被写坏了（引用了一个不存在的变量），
直到真实网络跑起来才暴露。

所以这里只打桩**最底层**的 ``request``，把上面的解码/重试/异常处理全部跑到。
"""

from __future__ import annotations

import asyncio
import unittest
from unittest import mock

import aiohttp

from core.services.http import HTTPClient, _decode_body


class FakeContent:
    def __init__(self, data: bytes) -> None:
        self._data = data

    async def read(self, n: int = -1) -> bytes:
        return self._data if n < 0 else self._data[:n]


class FakeResponse:
    """够用的假响应：支持 async with / status / headers / content / read。"""

    def __init__(self, data: bytes, *, status: int = 200, headers=None,
                 content_type: str = "text/plain; charset=utf-8") -> None:
        self._data = data
        self.status = status
        self.headers = {"Content-Type": content_type, **(headers or {})}
        self.content = FakeContent(data)
        self.history: list = []
        self.request_info = None
        self.released = False

    async def read(self) -> bytes:
        return self._data

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, *exc) -> bool:
        return False

    def release(self) -> None:
        self.released = True


def fake_request(factory):
    """把 HTTPClient.request 换成返回预设响应的协程。"""

    async def _request(self, method, url, **kwargs):
        result = factory(url, kwargs)
        if isinstance(result, Exception):
            raise result
        return result

    return _request


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
    """只打桩 request，把 _fetch / get_text / get_json 的真实路径跑一遍。"""

    async def test_get_text(self) -> None:
        with mock.patch.object(
            HTTPClient, "request", fake_request(lambda url, kw: FakeResponse("你好，世界".encode()))
        ):
            async with HTTPClient() as client:
                self.assertEqual(await client.get_text("http://x/"), "你好，世界")

    async def test_get_json(self) -> None:
        body = b'{"subdomains": ["www", "api"]}'
        with mock.patch.object(
            HTTPClient, "request",
            fake_request(lambda url, kw: FakeResponse(body, content_type="application/json")),
        ):
            async with HTTPClient() as client:
                data = await client.get_json("http://x/")
        self.assertEqual(data, {"subdomains": ["www", "api"]})

    async def test_error_status_raises(self) -> None:
        with mock.patch.object(
            HTTPClient, "request", fake_request(lambda url, kw: FakeResponse(b"nope", status=404))
        ):
            async with HTTPClient(retries=0) as client:
                with self.assertRaises(aiohttp.ClientResponseError):
                    await client.get_text("http://x/")

    async def test_encoding_failure_retries_with_identity(self) -> None:
        """读取正文失败时应改用 identity 再试一次。

        注意假响应的行为要贴近真实 aiohttp：解压失败是在**读正文**时抛出的,
        不是发起请求时。第一版测试把异常抛在 request() 上, 结果测了个假路径。
        """
        seen: list[dict] = []

        class BrokenEncoding(FakeResponse):
            async def read(self) -> bytes:
                raise aiohttp.ClientPayloadError("Can not decode content-encoding: br")

        def factory(url, kwargs):
            seen.append(dict(kwargs.get("headers") or {}))
            if len(seen) == 1:
                return BrokenEncoding(b"")
            return FakeResponse("ok".encode())

        with mock.patch.object(HTTPClient, "request", fake_request(factory)):
            async with HTTPClient(retries=0) as client:
                self.assertEqual(await client.get_text("http://x/"), "ok")

        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[1].get("Accept-Encoding"), "identity")

    async def test_fetch_result_fields(self) -> None:
        with mock.patch.object(
            HTTPClient, "request",
            fake_request(lambda url, kw: FakeResponse(
                b"<html><title>Hi</title></html>",
                headers={"Server": "nginx", "Set-Cookie": "a=1"},
            )),
        ):
            async with HTTPClient() as client:
                result = await client.fetch("http://x/", max_bytes=64)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result.status, 200)
        self.assertEqual(result.server, "nginx")
        self.assertIn("<title>Hi</title>", result.text)

    async def test_accept_encoding_default_excludes_br(self) -> None:
        """本环境 aiohttp 解不开 br，所以默认不该声明它。"""
        from core.services.http import _accept_encoding

        self.assertNotIn("br", _accept_encoding(False))
        self.assertIn("gzip", _accept_encoding(False))

    async def test_fetch_returns_none_on_network_error(self) -> None:
        with mock.patch.object(
            HTTPClient, "request",
            fake_request(lambda url, kw: aiohttp.ClientConnectorError(None, OSError("boom"))),
        ):
            async with HTTPClient(retries=0) as client:
                self.assertIsNone(await client.fetch("http://x/"))


class TestRequestStats(unittest.IsolatedAsyncioTestCase):
    """``HTTPClient.stats`` —— 被动源的"发了几次请求"就是从这里取的。

    计数刻意放在 ``request()`` 而不是 ``_fetch()``：只有这一层才**包含重试**。
    放在 ``_fetch`` 的话，一次被限流重试 3 次的请求会被数成 1 次，而
    "这个源是不是被限流了"恰恰要看真实请求量。
    """

    class FakeSession:
        closed = False

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

        async def close(self) -> None:
            self.closed = True

    async def test_counts_every_attempt_including_retries(self) -> None:
        session = self.FakeSession([FakeResponse(b"", status=500), FakeResponse(b"ok")])
        async with HTTPClient(retries=2, backoff=0.01) as client:
            client._session = session
            resp = await client.request("GET", "http://x/")
            self.assertEqual(resp.status, 200)
        self.assertEqual(session.calls, 2)
        self.assertEqual(client.stats["requests"], 2)
        self.assertEqual(client.stats["retries"], 1)
        self.assertEqual(client.stats["errors"], 0)

    async def test_counts_network_errors(self) -> None:
        session = self.FakeSession([aiohttp.ClientError("boom")])
        async with HTTPClient(retries=0) as client:
            client._session = session
            with self.assertRaises(aiohttp.ClientError):
                await client.request("GET", "http://x/")
        self.assertEqual(client.stats["requests"], 1)
        self.assertEqual(client.stats["errors"], 1)

    async def test_clean_success_counts_once(self) -> None:
        session = self.FakeSession([FakeResponse(b"ok")])
        async with HTTPClient(retries=2) as client:
            client._session = session
            await client.request("GET", "http://x/")
        self.assertEqual(client.stats, {"requests": 1, "retries": 0, "errors": 0})


if __name__ == "__main__":
    unittest.main()
