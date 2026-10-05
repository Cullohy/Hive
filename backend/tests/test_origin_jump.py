"""整站跳转就该收手 —— 但"某些路径跳转"的站点绝不能被误伤。

## 起因

scan 50（yealink）实测：``http://partner.yealink.com.cn`` 的每一条路径都被
301 到 ``https://partner.yealink.com.cn``。于是

* 流量白花一倍（每个请求多走一跳），80 端口上 17 条端点全是 301；
* 两边各报一条 finding，数字还对不上（404 比例 69/200 vs 75/200 ——
  两轮独立的软 404 画像，基线各自算）。

## 判据有多窄

只在**三条同时成立**时才收手：连续 N 条观测**全部**是跨 origin 跳转、都跳到
**同一个**目标、且目标 origin 确实换了。任何一条没跳就立刻解除判定。

⚠️ **软 404 校准的探针也算进观测**。那几条用的是随机 token 路径，如果它们也
跳到同一个地方，那本身就是"整站跳"的**更强**证据（连不存在的路径都跳）。
所以计入是有意的，但请求数因此会比"字典条数"多出校准那几条。

## 夹具的坑（写测试时踩的）

词表用 ``p0..p19`` 时，按子串匹配 ``"p1" in url`` 会把 ``p10``~``p19``
全算成跳转 —— 于是"只跳一部分"其实变成了"跳了 12/20"，判成跳板是**对的**，
错的是夹具。这里一律用互不为子串的名字。
"""
from __future__ import annotations

import unittest

from .base import EngineTestCase

EMIT_PORT = """
from core.engine.event import EventType
from core.engine.module import BaseModule

URLS = ["http://fuzz.example.com/"]


class emit_port(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for url in URLS:
            await self.emit_event(url, EventType.URL, parent=event)
"""

#: 互不为子串的路径名（别再用 p0..p19 + 子串匹配）
PATHS = [f"{c}{i}.html" for c in "abcdefgh" for i in (1, 2)]
WORDLIST = "\n".join(PATHS) + "\n"


def _redir(final: str, *, status: int = 301, size: int = 400):
    from core.services.http import FetchResult

    def make(url: str):
        return FetchResult(url=final, status=200, text="L" * size,
                           headers={"server": "nginx"},
                           history=[url], orig_status=status)
    return make


def _responder_for(kind: str):
    """四种形态的应答器。"""
    from core.services.http import FetchResult

    if kind == "jumper":
        # 每条都跳到**同一个**目标
        async def r(client, url, **kw):  # noqa: ANN001
            return FetchResult(url="https://fuzz.example.com/landing",
                               status=200, text="L" * 400,
                               headers={"server": "nginx"},
                               history=[url], orig_status=301)
        return r

    if kind == "some_paths":
        # 只有 a1/a2/b1/b2 跳，其余直返 404 —— 明确的少数派
        jumpers = {"a1.html", "a2.html", "b1.html", "b2.html"}

        async def r(client, url, **kw):  # noqa: ANN001
            if any(url.endswith(p) for p in jumpers):
                return FetchResult(url="https://fuzz.example.com/landing",
                                   status=200, text="L" * 400,
                                   headers={"server": "nginx"},
                                   history=[url], orig_status=301)
            return FetchResult(url=url, status=404, text="not found",
                               headers={"server": "nginx"})
        return r

    if kind == "many_places":
        # 每次跳到不同目标 —— 不是整站跳转
        seen: list[str] = []

        async def r(client, url, **kw):  # noqa: ANN001
            seen.append(url)
            n = len(seen)
            return FetchResult(url=f"https://other{n}.example.com/",
                               status=200, text="L" * 400,
                               headers={"server": "nginx"},
                               history=[url], orig_status=301)
        return r

    if kind == "same_origin":
        # 同源跳转：/x1.html -> /dash-x1.html
        async def r(client, url, **kw):  # noqa: ANN001
            p = url.rsplit("/", 1)[-1]
            return FetchResult(url=f"http://fuzz.example.com/dash-{p}",
                               status=200, text="L" * 400,
                               headers={"server": "nginx"},
                               history=[url], orig_status=302)
        return r

    if kind == "direct":
        async def r(client, url, **kw):  # noqa: ANN001
            return FetchResult(url=url, status=404, text="not found",
                               headers={"server": "nginx"})
        return r

    raise ValueError(kind)


class TestOriginRedirectGate(EngineTestCase):
    async def _scan(self, kind: str, **cfg):
        from unittest import mock

        from core.services.http import HTTPClient

        self.add_module_file("emit_port", EMIT_PORT)
        wl = self.root / "wl.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text(WORDLIST, encoding="utf-8")

        module_cfg = {
            "wordlist": str(wl), "max_paths": 16, "probes": 1,
            "concurrency": 1, "delay": 0, "forbidden_min": 999,
            "zero_hit_abort": 0,      # 关掉零命中收手，单独验这条闸门
            "soft404_simhash": False,
        }
        module_cfg.update(cfg)

        with mock.patch.object(HTTPClient, "fetch", _responder_for(kind)):
            return await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    async def test_a_pure_jumper_stops_early(self) -> None:
        """整站跳转 → 剩下的路径不扫，stat 记一笔。"""
        scanner, _ = await self._scan("jumper")
        stats = scanner.modules["dir_brute"].stats
        self.assertEqual(stats.get("origin_jumper"), 1,
                         f"跳板没有被识别: {dict(stats)}")
        # 判据在第 6 条观测成立（probes=1 所以校准只贡献 1 条）
        self.assertLessEqual(stats.get("requests", 0), 8,
                             f"跳板主机仍打了 {stats.get('requests')} 个请求")

    async def test_sites_with_only_some_paths_redirecting_are_not_harmed(self) -> None:
        """❗ 只跳一部分路径的站点**必须照扫**。

        这是这条闸门最危险的误伤面：``/login`` 跳 ``/dashboard`` 是站点内部
        行为，字典爆破在它上面完全有意义。
        """
        scanner, _ = await self._scan("some_paths")
        stats = scanner.modules["dir_brute"].stats
        self.assertEqual(stats.get("origin_jumper", 0), 0,
                         "只跳一部分路径的站点被误判成跳板了")
        self.assertGreaterEqual(stats.get("requests", 0), 12,
                                f"被误伤收手了，只打了 {stats.get('requests')} 个请求")

    async def test_redirecting_to_many_places_is_not_a_jumper(self) -> None:
        """跳去好几个不同 origin → 不是整站跳转。"""
        scanner, _ = await self._scan("many_places")
        stats = scanner.modules["dir_brute"].stats
        self.assertEqual(stats.get("origin_jumper", 0), 0,
                         "跳往多个 origin 的站点被误判成跳板了")
        self.assertGreaterEqual(stats.get("requests", 0), 10)

    async def test_same_origin_redirect_is_not_a_jumper(self) -> None:
        """同源跳转（``/x1.html`` -> ``/dash-x1.html``）不是跳板。"""
        scanner, _ = await self._scan("same_origin")
        stats = scanner.modules["dir_brute"].stats
        self.assertEqual(stats.get("origin_jumper", 0), 0,
                         "同源跳转被误判成整站跳板了")
        self.assertGreaterEqual(stats.get("requests", 0), 10)

    async def test_a_normal_site_is_untouched(self) -> None:
        """对照组：正常站点（不跳）不该被这条闸门碰到。"""
        scanner, _ = await self._scan("direct")
        stats = scanner.modules["dir_brute"].stats
        self.assertEqual(stats.get("origin_jumper", 0), 0)
        self.assertGreaterEqual(stats.get("requests", 0), 10)

    async def test_the_gate_can_be_turned_off(self) -> None:
        """``origin_redirect_probes: 0`` 关闭后，跳板主机也照扫。"""
        scanner, _ = await self._scan("jumper", origin_redirect_probes=0)
        stats = scanner.modules["dir_brute"].stats
        self.assertEqual(stats.get("origin_jumper", 0), 0)
        self.assertGreaterEqual(stats.get("requests", 0), 12,
                                "闸门关掉后仍没照扫")


class TestQueryExtra(unittest.TestCase):
    """``query_extra`` 合并成一条查询 + 越界边界。"""

    def test_extra_is_or_merged_into_one_query(self) -> None:
        """❗ 断言**真正上线路的那条** —— ``_params()["qbase64"]`` 解回来。

        只测 ``_query_text()`` 是不够的：它只是给人看的字符串，而
        ``_params()`` 才真的把它 base64 后发给 fofa。曾经这样写过一条测试，
        把"合并"那段代码删掉它照样绿 —— 因为展示用的字符串是另一条路径。
        """
        import base64

        from core.domains.subdomain.passive.fofa import Query

        def sent(cfg, target="a.com") -> str:
            q = Query()
            q.init_key(**cfg)
            params = q._params(target, 1)
            return base64.b64decode(params["qbase64"]).decode("utf-8")

        self.assertEqual(sent({"api_key": "k"}), 'domain="a.com"')
        self.assertEqual(
            sent({"api_key": "k", "query_extra": 'ip="1.2.3.4"'}),
            'domain="a.com" || ip="1.2.3.4"')
        # 合并成**一条**（不是两次查询）—— 计费按返回条数，省下的只是往返
        q = Query()
        q.init_key(api_key="k", query_extra='cert="a" || title="b"')
        self.assertEqual(q.max_pages, 1)

    def test_query_text_mirrors_what_is_sent(self) -> None:
        """展示用的字符串要和真正发出去的一致，否则日志会骗人。"""
        from core.domains.subdomain.passive.fofa import Query

        q = Query()
        q.init_key(api_key="k", query_extra='cert="a"')
        self.assertEqual(q._query_text("x.com"),
                         'domain="x.com" || cert="a"')

    def test_extra_turns_ip_acceptance_off_by_default(self) -> None:
        """⚠️ 越界边界：配了 extra 就**默认不收裸 IP**。

        附加表达式很可能不是按目标限定的（``cert="x"`` 会捞到带该证书的
        **第三方的站**），那些资产行的裸 IP 属于别人。
        """
        from core.domains.subdomain.passive.fofa import Query

        q = Query()
        q.init_key(api_key="k")
        self.assertTrue(q.accept_ip_assets, "基础查询是查询即作用域，默认应收")

        for extra in ('ip="1.2.3.4"', 'cert="a"', 'title="X" || body="x"'):
            q = Query()
            q.init_key(api_key="k", query_extra=extra)
            self.assertFalse(
                q.accept_ip_assets,
                f"配了 extra={extra!r} 还默认收裸 IP —— 会把别人的 IP 收进来")

    def test_explicit_opt_in_wins(self) -> None:
        from core.domains.subdomain.passive.fofa import Query

        q = Query()
        q.init_key(api_key="k", query_extra='ip="1.2.3.4"',
                   accept_ip_assets=True)
        self.assertTrue(q.accept_ip_assets)
