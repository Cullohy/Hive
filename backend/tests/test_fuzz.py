"""目录爆破域的测试。

两层：
  1. ``_lib/soft404.py`` 的画像构建与判定 —— 纯函数，三种基线形态一条条钉死
  2. ``dir_brute`` 模块 —— 走引擎，验证画像生效、403 熔断、预算

全部离线。
"""

from __future__ import annotations

import asyncio
import unittest
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

from core.domains.web_search._lib.soft404 import (
    PROBE_LENGTHS,
    SIMHASH_MAX_DISTANCE,
    SIMHASH_MIN_TOKENS,
    Probe,
    SoftProfile,
    extract_text,
    hamming_distance,
    looks_like_auth_wall,
    looks_like_soft_404,
    mask_token,
    random_token,
    simhash64,
)
from tests.base import EngineTestCase


def probes_for(sizes_by_len: dict[int, int], *, status: int = 404) -> list[Probe]:
    """按 token 长度造一组探测结果。"""
    return [
        Probe(token="a" * n, status=status, size=size, words=1)
        for n, size in sizes_by_len.items()
    ]


class TestSoftProfile(unittest.TestCase):
    """软 404 画像。"""

    def test_uniform_baseline_is_usable(self) -> None:
        p = SoftProfile.build(probes_for({4: 500, 8: 500, 12: 500, 16: 500}))
        self.assertTrue(p.usable)
        self.assertFalse(p.echo_token)
        self.assertIn(404, p.statuses)

    def test_uniform_baseline_filters_matching_sizes(self) -> None:
        p = SoftProfile.build(probes_for({4: 500, 8: 500, 12: 500, 16: 500}))
        # 同样的状态码 + 同样的大小 → 噪声
        self.assertTrue(p.is_noise(status=404, size=500, words=1, token_len=7))
        # 大小不同 → 真命中
        self.assertFalse(p.is_noise(status=404, size=1234, words=1, token_len=7))
        # **状态码不同 → 一定不是噪声**（200 的路径值得看）
        self.assertFalse(p.is_noise(status=200, size=500, words=1, token_len=7))

    def test_catch_all_200_is_detected(self) -> None:
        """catch-all 站点：每个不存在的路径都返回 200 + 同一个页面。

        这时"看状态码"完全失效 —— 画像必须能靠大小把它挡住。
        """
        p = SoftProfile.build(probes_for({4: 8123, 8: 8123, 12: 8123, 16: 8123}, status=200))
        self.assertTrue(p.usable)
        self.assertTrue(p.is_noise(status=200, size=8123, words=1, token_len=9))
        self.assertFalse(p.is_noise(status=200, size=999, words=1, token_len=9))

    def test_echo_type_is_detected_and_normalized(self) -> None:
        """**回显型软 404**：页面把请求路径写进正文，大小随 token 长度变化。

        这是 ffuf 的 ``-ac`` 处理不了的一类：原始大小每条都不一样，
        按大小过滤会失效；但 ``size - len(token)`` 是恒定的。
        """
        base = 500
        p = SoftProfile.build(
            probes_for({n: base + n for n in (4, 8, 12, 16)}, status=404)
        )
        self.assertTrue(p.usable, p.reason)
        self.assertTrue(p.echo_token, "没识别出回显型软 404")

        # 不同长度的 token，归一化后都是 500 → 都是噪声
        for tl in (3, 10, 25):
            self.assertTrue(
                p.is_noise(status=404, size=base + tl, words=1, token_len=tl),
                f"token_len={tl} 没被识别为噪声",
            )
        # 归一化后明显不同 → 真命中
        self.assertFalse(p.is_noise(status=404, size=base + 500, words=1, token_len=10))

    def test_non_uniform_baseline_is_not_usable(self) -> None:
        """基线本身乱七八糟时**必须明确说不可用** —— 硬过滤会误杀真命中。"""
        p = SoftProfile.build(probes_for({4: 100, 8: 9000, 12: 250, 16: 7777}))
        self.assertFalse(p.usable)
        self.assertIn("不恒定", p.reason)
        # 不可用时一条都不该被过滤
        self.assertFalse(p.is_noise(status=404, size=100, words=1, token_len=7))

    def test_too_many_statuses_is_not_usable(self) -> None:
        probes = [
            Probe(token="aaaa", status=200, size=100, words=1),
            Probe(token="aaaaaaaa", status=404, size=100, words=1),
            Probe(token="a" * 12, status=500, size=100, words=1),
            Probe(token="a" * 16, status=301, size=100, words=1),
        ]
        p = SoftProfile.build(probes)
        self.assertFalse(p.usable)
        self.assertIn("状态码不集中", p.reason)

    def test_empty_probes(self) -> None:
        p = SoftProfile.build([])
        self.assertFalse(p.usable)
        self.assertFalse(p.is_noise(status=200, size=1, words=1, token_len=1))

    def test_all_unanswered_only_when_no_sample_at_all(self) -> None:
        """``all_unanswered`` 只在**一个样本都没有**时为真。

        与 ``all_upstream_errors`` 是两回事：后者是"有响应但全是 502"，
        说明机器还活着、只是当前网络到不了它；前者是彻底不应答。
        把两者搞混会导致"换个网络就能扫的站点"被当成死站跳过。
        """
        empty = SoftProfile.build([])
        self.assertTrue(empty.all_unanswered)
        self.assertFalse(empty.all_upstream_errors, "没有样本就不该同时判成上游错误")

        # 502 基线：状态码有值、上游错误为真，但**它应答了**，所以不是 all_unanswered
        upstream = SoftProfile.build(
            [
                Probe(token="a" * n, status=502, size=0, words=1)
                for n in (8, 12, 16)
            ],
        )
        self.assertTrue(upstream.all_upstream_errors)
        self.assertFalse(upstream.all_unanswered, "502 也算有响应，不该判成完全无响应")

        # 正常 404 基线：两个标志都为假
        normal = SoftProfile.build(probes_for({8: 100, 12: 100, 16: 100}))
        self.assertFalse(normal.all_unanswered)
        self.assertFalse(normal.all_upstream_errors)

    def test_tolerance_allows_small_drift(self) -> None:
        """时间戳、nonce 之类的几字节浮动不该让画像失效。"""
        p = SoftProfile.build(probes_for({4: 500, 8: 503, 12: 501, 16: 504}))
        self.assertTrue(p.usable, p.reason)
        self.assertTrue(p.is_noise(status=404, size=502, words=1, token_len=7))

    def test_probe_lengths_are_varied(self) -> None:
        """**长短必须不一** —— 这是识别回显型软 404 的唯一手段。"""
        self.assertGreater(len(set(PROBE_LENGTHS)), 1)
        self.assertEqual(len(PROBE_LENGTHS), len(set(PROBE_LENGTHS)))

    def test_random_token_length(self) -> None:
        for n in (4, 8, 16):
            self.assertEqual(len(random_token(n)), n)
        self.assertNotEqual(random_token(16), random_token(16))


PAGE_404 = "x" * 512

#: 走真实路径的入口：发 ``OPEN_TCP_PORT``，由 ``http_probe`` 探活并写画像。
#: 2026-10-03 起 ``techs`` / ``root_shape`` 是探活的副产品，测试必须真的跑探活。
EMIT_PORT = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_port(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.OPEN_TCP_PORT,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event(
            "fuzz.example.com:80", EventType.OPEN_TCP_PORT, parent=event,
            tags={"ip": "93.184.216.34", "port": 80, "domain": "fuzz.example.com"},
        )
"""


#: 直接发一个 URL 事件，把爆破指向本地假主机（不会真发请求 —— HTTPClient 被打了桩）
EMIT_URL = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_url(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event("http://fuzz.example.com/", EventType.URL, parent=event)
"""

#: 发**两台不同主机**的 URL。用来验"按主机记账"的东西（熔断、失败预算）。
#:
#: ⚠️ 顺序有意义：``a`` 在前。测跨主机污染时必须保证污染源先跑完 —— 引擎
#: 默认单 worker，队列是 FIFO，所以事件到达顺序 = 处理顺序。
EMIT_TWO_URLS = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_two_urls(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event("http://a.example.com/", EventType.URL, parent=event)
        await self.emit_event("http://b.example.com/", EventType.URL, parent=event)
"""


#: 先发几个**非 HTTP 端口**，最后才发真正的 HTTP 主机。
#: 复刻 http_probe 的真实行为：它把 25/110/143/3306 也当成 URL 发出来。
EMIT_URLS_MANY = """
from core.engine.event import EventType
from core.engine.module import BaseModule

URLS = [
    "http://fuzz.example.com:25/",
    "http://fuzz.example.com:110/",
    "http://fuzz.example.com:143/",
    "http://fuzz.example.com:3306/",
    "http://fuzz.example.com/",
]


class emit_urls_many(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for url in URLS:
            await self.emit_event(url, EventType.URL, parent=event)
"""

#: 两台主机，用来验「按主机记」的信号不会互相污染。
#: 第一台挂 WAF、第二台干净 —— 干净那台的绕过**必须照常发生**。
EMIT_URL_TWO_HOSTS = """
from core.engine.event import EventType
from core.engine.module import BaseModule

URLS = [
    "http://wafhost.example.com/",
    "http://clean.example.com/",
]


class emit_urls_two(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for url in URLS:
            await self.emit_event(url, EventType.URL, parent=event)
"""

#: ``busy_hint()`` 抛异常的模块。引擎每 1 秒问一次所有启用中的模块，
#: 一个实现写错的模块绝不能把整个进度接口带崩（更不能带崩扫描）。
EMIT_URL_RAISY_BUSY = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_url_raisy_busy(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    def busy_hint(self):
        raise RuntimeError("观测实现写错了")

    async def handle_event(self, event):
        await self.emit_event("http://fuzz.example.com/", EventType.URL, parent=event)
"""

#: 先发一个**死**主机，再发一个**活**主机 —— 用来验配额是否归还。
#: 顺序有意义：``dir_brute`` 串行消费事件，死的那个会先占掉 ``max_hosts`` 名额。
EMIT_DEAD_THEN_ALIVE = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_dead_then_alive(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event(
            "http://dead.example.com/", EventType.URL, parent=event
        )
        await self.emit_event(
            "http://alive.example.com/", EventType.URL, parent=event
        )
"""

#: 一个带非标准端口、一个不带 —— 用来验证 502 的两种成因被分开表述
EMIT_MIXED_502 = """
from core.engine.event import EventType
from core.engine.module import BaseModule

URLS = [
    "http://mix.example.com:25/",
    "http://mix.example.com/",
]


class emit_mixed_502(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        for url in URLS:
            await self.emit_event(url, EventType.URL, parent=event)
"""


class TestDirBrute(EngineTestCase):
    """走引擎：画像 → 爆破 → 熔断。"""

    def _fake_fetch(self, responder):
        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        return fake_fetch

    @staticmethod
    def _resp(url: str, status: int, size: int, *, text: str = "", headers=None):
        """构造一个假响应。

        ``size`` 只在没有显式给 ``text`` 时用（凑长度，用来让软 404 画像
        按"响应大小"区分命中与噪声）。要验证标题/响应头时用 ``text`` /
        ``headers``，因为那才是 ``http_endpoint`` 落库时读的字段。
        """
        from core.services.http import FetchResult

        body = text if text else "x" * size
        return FetchResult(
            url=url, status=status, text=body,
            headers=headers if headers is not None else {},
        )

    async def _scan(self, responder, max_paths: int = 20, *,
                    emitter: str = "emit_port", emitter_src: str = EMIT_PORT, **cfg):
        from core.services.http import HTTPClient

        self.add_module_file(emitter, emitter_src)
        # 用自己的小字典：内置默认档 dir_common 有 200 条，配合 max_paths 会把
        # 想验证的路径（robots.txt 之类）截在窗口之外，断言就失去意义了
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_test.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text(
            "admin\nlogin\nrobots.txt\n.env\napi/v1\nconfig.json\n"
            "backup.zip\nswagger.json\n.git/config\nhealth\n",
            encoding="utf-8",
        )
        module_cfg = {"wordlist": str(wl), "max_paths": max_paths, "probes": 4,
                      "concurrency": 4, "delay": 0, "forbidden_min": 5}
        module_cfg.update(cfg)

        with mock.patch.object(HTTPClient, "fetch", self._fake_fetch(responder)):
            return await self.run_scan(
                # 目标只给根域：``fuzz.example.com`` 必须**不是**种子，否则
                # ``skip_seed`` 会把它当种子跳过（它才是被爆破的那台）。
                targets=["example.com"],
                include=[emitter, "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    async def _urls(self, scan_id: int) -> set[str]:
        events = await self.storage.events(scan_id, limit=2000, event_type="URL")
        return {e["data"] for e in events if e["module"] == "dir_brute"}

    async def _findings(self, scan_id: int) -> list[str]:
        """返回 ``kind | detail``。

        断言时只看 ``detail`` 会漏 —— 例如"被拦截"写在 ``kind`` 里
        （``目录爆破被拦截: <host>``），而 ``detail`` 里是解释。
        """
        rows = await self.storage.findings(scan_id)
        return [f"{r['kind']} | {r['detail']}" for r in rows]

    async def test_soft404_responses_are_filtered(self) -> None:
        """经典 catch-all：所有路径都 200 + 同样大小。**只有真命中的那个不同。**"""

        def responder(url: str):
            if url.endswith("/admin"):
                return self._resp(url, 200, 4242)      # 真命中
            if url.endswith("/robots.txt"):
                return self._resp(url, 200, 64)
            return self._resp(url, 200, 7777)          # 软 404

        scanner, _ = await self._scan(responder)
        got = await self._urls(scanner.scan_id)
        self.assertIn("http://fuzz.example.com/admin", got)
        self.assertIn("http://fuzz.example.com/robots.txt", got)
        # 软 404 那些不该出现
        self.assertNotIn("http://fuzz.example.com/login", got)
        self.assertLess(len(got), 8, f"过滤没生效，命中过多: {sorted(got)}")

    async def test_hits_are_recorded_as_probed_endpoints(self) -> None:
        """**爆破命中的路径必须落成 ``http_endpoint`` 行，带上状态码与标题。**

        ## 这条在钉什么

        ``dir_brute`` 报的每一条路径都是它**自己请求过**才判断"存在"的 ——
        观测是真实发生的。但它过去只发 ``URL`` 事件，而 ``URL`` 事件的投影
        只读 ``source`` / ``kind`` / ``from`` 三个标签，``status`` 被静默
        丢弃，``http_endpoint`` 表里也就没有这行。

        症状：爆破出来的几百条路径在资产库里全是"未探活"，状态码、标题、
        Server、长度一律空白 —— **明明已经探活了**。这不是"少一个字段"，
        是整条链路对不上（真实库里 mail.sinosoft.com.cn 200 条路径只有 1 条
        有状态码，而那 1 条还是 http_probe 探的根 URL）。

        所以命中时要额外发一条 ``HTTP_RESPONSE``，把已经拿到的响应记进
        ``http_endpoint``。
        """

        def responder(url: str):
            if url.endswith("/admin"):
                # 故意带上 <title> 与 Server —— 验证标题不是空的
                return self._resp(
                    url, 200, 4242,
                    text="<html><head><title>后台管理</title></head></html>",
                    headers={"server": "nginx", "content-type": "text/html"},
                )
            if url.endswith("/robots.txt"):
                return self._resp(url, 200, 64)
            return self._resp(url, 200, 7777)          # 软 404

        scanner, _ = await self._scan(responder)
        scan_id = scanner.scan_id

        endpoints = {
            r["url"]: r for r in await self.storage.endpoints(scan_id, limit=500)
        }
        self.assertIn(
            "http://fuzz.example.com/admin", endpoints,
            f"命中的路径没落成 http_endpoint 行: {sorted(endpoints)}",
        )
        row = endpoints["http://fuzz.example.com/admin"]
        self.assertEqual(row["status"], 200, f"状态码没记上: {dict(row)}")
        self.assertEqual(row["title"], "后台管理", f"标题没记上: {dict(row)}")
        self.assertEqual(row["server"], "nginx")

        # 软 404 那些**不该**变成端点 —— 它们是噪声，不是观测
        self.assertNotIn(
            "http://fuzz.example.com/login", endpoints,
            "软 404 的噪声被当成观测记进去了",
        )

        # URL 表里仍然要留着（"路径存在"这条事实不受影响）
        self.assertIn("http://fuzz.example.com/admin", await self._urls(scan_id))

    async def test_hit_http_response_carries_no_volatile_tags(self) -> None:
        """**不能**把 headers / body_snippet 放进这条事件。

        那两个是易失标签，是 url_extract / fingerprint 的输入。
        带上它们等于让这几百条路径各再跑一遍抽链接 + 指纹匹配，
        事件量翻几倍；而这两个模块在没有它们时本来就会直接 return
        （见各自 ``handle_event`` 的空值闸门），所以不发既安全又不丢东西。
        """
        from core.storage.postgres import VOLATILE_TAGS

        import json

        def responder(url: str):
            if url.endswith("/admin"):
                return self._resp(url, 200, 4242, text="<title>x</title>")
            return self._resp(url, 200, 7777)

        scanner, _ = await self._scan(responder)
        events = await self.storage.events(
            scanner.scan_id, limit=2000, event_type="HTTP_RESPONSE"
        )
        mine = [e for e in events if e["module"] == "dir_brute"]
        self.assertTrue(mine, "没有发 HTTP_RESPONSE 事件")
        for e in mine:
            # events() 走 SELECT *，拿到的是原始 tags_json 字符串
            tags = json.loads(e["tags_json"] or "{}")
            leaked = VOLATILE_TAGS & set(tags)
            self.assertEqual(leaked, set(), f"易失标签泄漏进事件: {leaked}")
            # 落库字段要齐
            self.assertIn("status", tags)
            self.assertIn("title", tags)

    async def test_forbidden_flood_trips_the_breaker(self) -> None:
        """ffuf 的 ``-sf``：大面积 403 说明被拦了，继续打没意义。"""

        def responder(url: str):
            return self._resp(url, 403, 100)

        scanner, _ = await self._scan(responder, max_paths=50)
        findings = await self._findings(scanner.scan_id)
        self.assertTrue(
            any("被拦截" in d for d in findings), f"没触发熔断: {findings}"
        )
        self.assertEqual(await self._urls(scanner.scan_id), set())

    async def test_forbidden_finding_is_emitted_only_once(self) -> None:
        """熔断结论只能发一条。

        并发之下多个协程都会返回 403。如果只在循环开头查一次 ``_tripped``，
        每个都已越过那次检查的协程都会触发一次 —— 实测同一条结论被发了 4 遍。
        所以"是否已熔断"必须写进触发条件本身（判断到 add 之间没有 await，
        在 asyncio 里因而是原子的）。
        """

        def responder(url: str):
            return self._resp(url, 403, 100)

        scanner, _ = await self._scan(responder, max_paths=50, concurrency=8)
        findings = [f for f in await self._findings(scanner.scan_id) if "被拦截" in f]
        self.assertEqual(
            len(findings), 1, f"熔断结论发了 {len(findings)} 条: {findings}"
        )

    async def test_unusable_profile_emits_a_warning_finding(self) -> None:
        """画像不可用时要**明确告诉用户结果需要人工看**，不能默默给一堆假命中。"""
        import itertools

        sizes = itertools.cycle([100, 5000, 250, 9000])

        def responder(url: str):
            return self._resp(url, 200, next(sizes))

        scanner, _ = await self._scan(responder, max_paths=8)
        findings = await self._findings(scanner.scan_id)
        self.assertTrue(
            any("画像不可用" in d for d in findings), f"没给出警告: {findings}"
        )

    async def test_one_pass_per_host(self) -> None:
        """同一个主机只爆破一次（否则每个 URL 事件都会重跑全字典）。"""
        calls: list[str] = []

        def responder(url: str):
            calls.append(url)
            return self._resp(url, 404, 500)

        await self._scan(responder, max_paths=5)
        # 5 个路径 + 4 次探测 = 9 次；如果每事件跑一遍会远超这个数
        self.assertLessEqual(len(calls), 15, f"请求数异常: {len(calls)}")

    async def test_stats_are_reported(self) -> None:
        def responder(url: str):
            return self._resp(url, 404, 500)

        _, summary = await self._scan(responder, max_paths=10)
        row = next((r for r in summary["source_stats"] if r["source"] == "dir_brute"), None)
        self.assertIsNotNone(row, f"没收到统计: {summary['source_stats']}")
        self.assertGreater(row["requests"], 0)
        self.assertGreater(row["skipped"], 0, "软 404 丢弃数应大于 0")

    async def test_in_site_link_does_not_kill_the_whole_host(self) -> None:
        """首页里有站内链接时，字典必须照常跑完。

        ``_discovered_paths`` 无条件写 ``stats["discovered_raw"]`` /
        ``["discovered_used"]``，而这两个 key 以前**没在** ``setup()`` 里声明
        —— 于是凡首页含 ≥1 条同源非静态链接的站点（也就是几乎所有真站点）
        都在发出第一条字典请求**之前** KeyError 退出，``max_hosts`` 名额还
        占着不归还。

        ⚠️ 这条测试的价值全在"真的喂一个带链接的首页"。原来的夹具正文里
        ``links=0``，``_discovered_paths`` 开头就 return 了，**永远够不到**那
        两行 —— 所以这个 bug 能在全绿的测试套件里活这么久。

        判据用 ``module.dir_brute.error``：软 404 校准的请求在崩之前已经发过了，
        所以"请求数 > 0"区分不出修没修，只有"模块有没有抛异常"能。
        """
        homepage = (
            '<html><body>'
            '<a href="/about/team">团队</a>'
            '<a href="/docs/guide">文档</a>'
            '<a href="/static/app.js">静态</a>'                 # 应被丢掉
            '<a href="https://other.example.org/x">外站</a>'   # 越界，应被丢掉
            '</body></html>'
        )

        def responder(url: str):
            if url.rstrip("/") == "http://fuzz.example.com":
                return self._resp(url, 200, 0, text=homepage)
            return self._resp(url, 404, 500)

        _, summary = await self._scan(responder, max_paths=20)
        self.assertEqual(
            summary["stats"].get("module.dir_brute.error", 0), 0,
            "dir_brute 抛异常了 —— 头号嫌疑是 discovered_raw/discovered_used "
            f"没在 setup() 里声明。全量: {summary['stats']}",
        )

    async def test_breaker_does_not_inherit_another_host_401s(self) -> None:
        """熔断判据必须只看**本机**的 401/403。

        以前 403 用函数局部计数、401 用 ``self.stats["unauthorized"]``
        （模块级累计，跨主机跨 worker），而分母 ``checked`` 是本机的 ——
        分子被历史污染，比值虚高。于是先扫完一台"到处 401"的主机后，
        后面那台只有 1 条 403 的正常主机也会被误判成"被 WAF 拦"而静默截断，
        还附带发出一条**归因错误**的 finding。同一站点、同一份字典，仅因前面
        扫过几台机器就得出相反结论。
        """
        def responder(url: str):
            if "a.example.com" in url:
                return self._resp(url, 401, 100)      # 认证墙，攒一堆 401
            if url.endswith("/admin"):
                return self._resp(url, 403, 100)      # b 只有这 1 条 403
            return self._resp(url, 404, 500)

        scanner, _ = await self._scan(
            responder, max_paths=50, workers=1, max_hosts=0,
            emitter="emit_two_urls", emitter_src=EMIT_TWO_URLS,
        )
        tripped = [f for f in await self._findings(scanner.scan_id) if "被拦截" in f]
        self.assertTrue(
            any("a.example.com" in f for f in tripped),
            f"认证墙那台本来就该熔断，没熔断: {tripped}",
        )
        self.assertFalse(
            [f for f in tripped if "b.example.com" in f],
            f"b 只有 1 条 403，却被 a 的历史 401 连坐熔断了: {tripped}",
        )



class TestDirBrutePresets(unittest.TestCase):
    """默认预设必须拦住它 —— 这类动作最容易把目标打挂。"""

    def _names(self, preset_name: str) -> set[str]:
        import asyncio

        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        async def go():
            s = Scanner(targets=["example.com"],
                        preset=Preset.load_builtin(preset_name), storage=None)
            s.load_modules()
            return set(s.modules)

        return asyncio.run(go())

    def test_invasive_is_denied_by_the_passive_preset(self) -> None:
        # dir_brute 带 invasive，passive 预设的 deny_flags 里有它
        self.assertNotIn("dir_brute", self._names("passive"))

    def test_full_preset_includes_it(self) -> None:
        self.assertIn("dir_brute", self._names("active"))


class TestPathWordlist(unittest.TestCase):
    """路径字典的加载 —— 前导点必须保住。"""

    def test_leading_dot_is_preserved(self) -> None:
        """``normalize_domain`` 会 ``lstrip(".")``：``.env`` → ``env``。

        敏感文件字典里最有价值的就是这些点开头的条目，所以路径字典必须走
        独立的清洗逻辑。这里把差异钉住。
        """
        from core.util.domain import normalize_domain
        from core.util.words import load_path_words

        # 先确认前提：域名归一化确实会破坏它们
        self.assertEqual(normalize_domain(".env"), "env")
        self.assertEqual(normalize_domain(".git/config"), "git/config")

        words = load_path_words()
        self.assertIn(".env", words)
        self.assertIn(".git/config", words)
        # 注意：这里**不能**再断言 swagger.json 存在 —— 它已按能力边界删除，
        # 见 TestDictionaryBoundary。

    def test_comments_and_blanks_are_dropped(self) -> None:
        from core.util.words import _clean_paths

        self.assertEqual(
            _clean_paths(["# 注释\n", "admin\n", "\n", "  \n", "admin\n", ".env\n"]),
            ["admin", ".env"],
        )

    def test_missing_file_raises(self) -> None:
        from core.util.words import load_path_words

        with self.assertRaises(FileNotFoundError):
            load_path_words("D:/definitely/not/here.txt")

    def test_unknown_alias_says_so(self) -> None:
        """打错别名时错误信息要**指名道姓**，而不是说"文件不存在"。

        别名和磁盘路径都解析不了才是未知别名；只报"文件不存在"会让人
        以为是路径写错了，去检查一个根本不存在的目录。
        """
        from core.util.words import PATH_WORDLISTS, load_path_words

        with self.assertRaises(FileNotFoundError) as cm:
            load_path_words("dir_dirmp")          # 少个 a
        msg = str(cm.exception)
        self.assertIn("dir_dirmp", msg)
        self.assertIn("别名", msg)
        # 已知别名应当被列出来，省得再去翻源码
        for alias in PATH_WORDLISTS:
            self.assertIn(alias, msg)


class TestDirmapWordlists(unittest.TestCase):
    """dirmap 的四档字典 + 逗号多档串联。

    这批字典来自 dirmap（GPL-3.0，仅取数据文件
    引入它们是为了补上自研 200 条覆盖不到的面，所以这里钉住的是
    **"接进来之后仍然成立的性质"**，而不是具体条目 —— 具体条目随上游更新。
    """

    def test_all_aliases_load(self) -> None:
        from core.util.words import PATH_WORDLISTS, load_path_words

        for alias in PATH_WORDLISTS:
            with self.subTest(alias=alias):
                words = load_path_words(alias)
                self.assertGreater(len(words), 0, f"{alias} 是空字典")
                self.assertEqual(len(words), len(set(words)), f"{alias} 内部有重复")

    def test_tiers_are_ordered_by_size(self) -> None:
        """档位是按规模分的，顺序不能乱 —— 文档和 active 预设都依赖这个。"""
        from core.util.words import load_path_words

        sizes = {a: len(load_path_words(a))
                 for a in ("dir_leaks", "dir_dirmap", "dir_bak", "dir_big")}
        self.assertLess(sizes["dir_leaks"], sizes["dir_dirmap"])
        self.assertLess(sizes["dir_dirmap"], sizes["dir_bak"])
        self.assertLess(sizes["dir_bak"], sizes["dir_big"])

    def test_dirmap_tier_beats_the_self_made_default(self) -> None:
        """扩面档必须真的比自研默认档宽，否则引入没有意义。"""
        from core.util.words import load_path_words

        self.assertGreater(len(load_path_words("dir_dirmap")),
                           len(load_path_words("dir_common")) * 10)

    def test_leading_dot_survives_every_tier(self) -> None:
        """点开头的条目是敏感文件字典里最值钱的部分，各档都得保住。

        ``_clean_paths`` 刻意不走 ``normalize_domain``（后者 ``lstrip(".")``），
        这里防的是将来有人"顺手统一"成 ``load_words``。
        """
        from core.util.words import load_path_words

        for alias in ("dir_leaks", "dir_dirmap"):
            with self.subTest(alias=alias):
                words = set(load_path_words(alias))
                self.assertIn(".env", words)
                self.assertIn(".git/config", words)

    def test_multi_tier_merges_in_order_and_dedups(self) -> None:
        from core.util.words import load_path_words

        leaks = load_path_words("dir_leaks")
        dirmap = load_path_words("dir_dirmap")
        merged = load_path_words("dir_leaks,dir_dirmap")

        overlap = set(leaks) & set(dirmap)
        self.assertTrue(overlap, "两档若无交集，这条用例测不出跨档去重")
        self.assertEqual(len(merged), len(leaks) + len(dirmap) - len(overlap))
        self.assertEqual(len(merged), len(set(merged)), "合并后仍有重复")
        # 顺序：第一档整体排在第二档之前
        self.assertEqual(merged[: len(leaks)], leaks)

    def test_reversing_tiers_reverses_the_merge(self) -> None:
        """顺序由用户给，不是由字典名排 —— 钉住这个，控制住实现自由度。"""
        from core.util.words import load_path_words

        a = load_path_words("dir_leaks,dir_dirmap")
        b = load_path_words("dir_dirmap,dir_leaks")
        self.assertEqual(set(a), set(b))
        self.assertNotEqual(a, b)
        self.assertEqual(a[:1], load_path_words("dir_leaks")[:1])
        self.assertEqual(b[:1], load_path_words("dir_dirmap")[:1])

    def test_head_truncation_keeps_the_first_tier(self) -> None:
        """``max_paths`` 从头截断，所以小字典写前面才谈得上"优先保高价值"。

        这是 ``wordlist: dir_leaks,dir_dirmap`` 这类写法的全部意义，
        一旦实现改成从尾截断或打散，这条就会红。
        """
        from core.util.words import load_path_words

        merged = load_path_words("dir_leaks,dir_dirmap")
        truncated = merged[: len(load_path_words("dir_leaks"))]
        self.assertEqual(truncated, load_path_words("dir_leaks"))
        self.assertIn(".env", truncated)

    def test_whitespace_around_commas_is_tolerated(self) -> None:
        from core.util.words import load_path_words

        self.assertEqual(load_path_words(" dir_leaks , dir_dirmap "),
                         load_path_words("dir_leaks,dir_dirmap"))

    def test_filename_containing_comma_wins_over_splitting(self) -> None:
        """带逗号的**真实文件名**不能被拆。

        整串先按单档试就是为这个：``D:/dicts/my,big.txt`` 若先按逗号拆，
        会变成两个都不存在的路径而报错。
        """
        import tempfile

        from core.util.words import load_path_words

        path = Path(tempfile.gettempdir()) / "hive_dict,with_comma.txt"
        path.write_text("# 注释\nfoo\nbar\nfoo\n", encoding="utf-8")
        try:
            self.assertEqual(load_path_words(str(path)), ["foo", "bar"])
        finally:
            path.unlink(missing_ok=True)

    def test_bad_tier_names_the_offending_tier(self) -> None:
        """多档里有一档写错时，错误信息必须指向**那一档**，不是整串。"""
        from core.util.words import load_path_words

        with self.assertRaises(FileNotFoundError) as cm:
            load_path_words("dir_leaks,dir_nope")
        self.assertIn("dir_nope", str(cm.exception))
        self.assertNotIn("dir_leaks,dir_nope", str(cm.exception))

    def test_active_preset_keeps_the_offline_flag_ceiling(self) -> None:
        """active 预设的字典请求量**必须有上限**。

        ⚠️ 2026-10-03 改过一次。原来这条钉的是「必须用多档、且第一档是
        ``dir_leaks``」—— 那时 ``dir_leaks,dir_dirmap``（5767 条）是唯一的
        补充面，多档是硬要求。

        现在不成立了：``js_assets``（从 JS 抽路径并验证）与 ``url_extract``
        （父目录推导）拿到的地址是**站点自己写的**，精度高一个数量级；
        而那 5767 条是 2010 年代的老系统字典（phpMyAdmin 2.6、FCKeditor、
        snoop…），3663 条在根目录。所以 active 换成单档 ``dir_common``
        （243 条，自研、含 .env / .git/config / .DS_Store / .svn/entries）。

        **多档不再是硬要求，请求量上限才是。** 所以这条现在钉的是后者 ——
        换字典档时最容易漏掉的就是「忘了同时设 max_paths」，那会让请求量
        悄悄回到每主机几千条。
        """
        from core.engine.preset import Preset
        from core.util.words import load_path_words

        cfg = Preset.load_builtin("active").config_for("dir_brute")
        spec = cfg.get("wordlist", "")
        self.assertTrue(spec, "active 预设没配字典")
        # 预设里写的字典必须真的能加载，否则 active 跑起来才发现就晚了
        self.assertGreater(len(load_path_words(spec)), 0)
        # 每主机请求量必须有上限。代码默认 0 = 不限，那意味着没有闸。
        self.assertGreater(
            int(cfg.get("max_paths", 0)), 0,
            f"max_paths 没设上限（0=不限），字典一变请求量就失控: {spec!r}",
        )
        # 全量档是"全量"：主机数也必须有上限
        self.assertGreater(int(cfg.get("max_hosts", 0)), 0)
        # 自研那档必须留在字典里 —— 它是高信噪比面（.env/.git/config），
        # 换成纯 dirmap 就等于把这层覆盖丢了
        self.assertIn("dir_common", spec, f"自研档被移出了: {spec!r}")

    def test_preset_wordlist_keeps_the_leak_files(self) -> None:
        """**泄露文件必须留在字典里** —— 换字典档时最容易丢的就是这批。

        ⚠️ 2026-10-03 踩过：把 ``wordlist`` 从 ``dir_leaks,dir_dirmap``
        换成 ``dir_common`` 时，``WEB-INF/web.xml`` / ``.bash_history`` /
        ``WEB-INF/database.properties`` 跟着没了 —— 它们**只在 dir_leaks 里**。
        而这三样是 Java 应用最经典的暴露面，JS 和页面链接里都不会有它们。

        这条测试就是那次事故的守门人。
        """
        from core.engine.preset import Preset
        from core.util.words import load_path_words

        cfg = Preset.load_builtin("active").config_for("dir_brute")
        have = set(load_path_words(cfg["wordlist"]))
        for path in ("WEB-INF/web.xml", "WEB-INF/database.properties",
                     ".bash_history", ".git/config", ".env", "phpinfo.php",
                     "dump.sql", "config.php"):
            with self.subTest(path=path):
                self.assertIn(path, have, f"字典里没有 {path}")

    def test_preset_wordlist_is_smaller_than_it_used_to_be(self) -> None:
        """字典规模是被**刻意**压下来的，别不知不觉又涨回去。

        5767 条 → 243 条，省掉的是"对现在的站点基本打不中"的那部分。
        真正有用的补充面已经由 js_assets 与父目录推导接手了。
        """
        from core.engine.preset import Preset
        from core.util.words import load_path_words

        cfg = Preset.load_builtin("active").config_for("dir_brute")
        n = len(load_path_words(cfg["wordlist"]))
        self.assertLess(
            n, 1000,
            f"字典又涨到 {n} 条了 —— 确认一下是真需要，还是忘了为什么砍的",
        )


class TestDirmapDictHygiene(unittest.TestCase):
    """导入 dirmap 字典时做的清洗，必须被钉住。

    这些不是"锦上添花"，每一条都对应一个**具体的失败模式**：

    * 注入探针 —— ``BAK.txt`` 上游混进了 21 条 ``action=<script>alert(...)</0.rar``。
      往查询串里塞脚本已经越过了本项目写明的边界（``fuzz/__init__.py``：
      这一层只铺暴露面，不做注入测试），所以整段剔掉而不是原样引入。
    * 裸 ``#`` —— 它是 URL 的**片段分隔符**，客户端只把 ``#`` 之后的部分留在
      本地、永远不会发给服务器。留着等于每次跑都白请求一条。
    * 裸 ``%`` —— 不是合法 ``%XX``，``httpx`` 会拒绝或误解义。`` 的「导入时做了什么改动」。
    """

    _INJECTION = ("<", ">", "|", "{", "}", "`")
    _PCT = __import__("re").compile(r"%[0-9A-Fa-f]{2}")

    def _tiers(self) -> list[str]:
        from core.util.words import PATH_WORDLISTS

        # dir_common 是自研的，走的是另一套标准，不在这里一起查
        return [a for a in PATH_WORDLISTS if a != "dir_common"]

    def test_no_injection_probe(self) -> None:
        from core.util.words import load_path_words

        for alias in self._tiers():
            with self.subTest(alias=alias):
                bad = [w for w in load_path_words(alias)
                       if any(c in w for c in self._INJECTION)]
                self.assertEqual(
                    bad[:5], [],
                    f"{alias} 里混进了注入探针（共 {len(bad)} 条），"
                    f"超出本项目「只铺暴露面、不做注入」的边界")

    def test_no_bare_hash(self) -> None:
        """``#`` 必须已被编码成 ``%23``，否则那一段永远发不出去。"""
        from core.util.words import load_path_words

        for alias in self._tiers():
            with self.subTest(alias=alias):
                bad = [w for w in load_path_words(alias) if "#" in w]
                self.assertEqual(bad[:5], [], f"{alias} 里有裸 #（片段分隔符）")

    def test_percent_escapes_are_all_well_formed(self) -> None:
        """已编码的 ``%XX`` 要保留（那些是真路径），但不能有裸 ``%``。"""
        from core.util.words import load_path_words

        for alias in self._tiers():
            with self.subTest(alias=alias):
                words = load_path_words(alias)
                bare = [w for w in words if "%" in w
                        and self._PCT.sub("", w).count("%")]
                self.assertEqual(bare[:5], [], f"{alias} 里有裸 %")

    def test_pre_encoded_paths_are_preserved(self) -> None:
        """``dir_bak`` 里那批 ``%23data%23/*.rar`` 必须原样留着。

        它们在 dirmap 上游就是编码好的，``httpx`` 不会二次编码，所以能真正
        发出去。全被清掉就等于把 dirmap 字典最特有的那部分价值删了 ——
        所以这条与上面那条"不能有裸 %"是成对的。

        只对 ``dir_bak`` 断言：``dir_leaks`` / ``dir_big`` 上游本来一条
        编码路径都没有，对它们断言"必须存在编码条目"是凭空要求。
        """
        from core.util.words import load_path_words

        words = load_path_words("dir_bak")
        encoded = [w for w in words if "%" in w]
        # 目录名 `#data#` 在 URL 里只能写成 `%23data%23`，上游就是这么给的
        self.assertGreater(len(encoded), 100, "dir_bak 的预编码路径几乎被清空了")
        self.assertIn("%23data%23/0.rar", words)

    def test_no_control_char_or_backslash(self) -> None:
        from core.util.words import load_path_words

        for alias in self._tiers():
            with self.subTest(alias=alias):
                bad = [w for w in load_path_words(alias)
                       if "\\" in w or any(ord(c) < 0x20 or ord(c) == 0x7F for c in w)]
                self.assertEqual(bad[:5], [], f"{alias} 里有控制字符或反斜杠")

    def test_no_entry_looks_like_a_comment_line(self) -> None:
        """字典头部漏进条目 —— 一行说明会变成一条**会被真实请求**的路径。

        导入脚本的 HEADER 有一处 ``# {note}`` 占位：note 的续行若忘了带
        ``#`` 前缀，那行中文说明就会混进条目列表（实测踩过，四档各多 1 条）。
        这里从结果侧兜住：导入时含空白/反斜杠的条目一律被剔，所以**任何**
        带空白的条目都只可能是头部漏进来的。
        """
        from core.util.words import load_path_words

        for alias in self._tiers():
            with self.subTest(alias=alias):
                bad = [w for w in load_path_words(alias) if any(c.isspace() for c in w)]
                self.assertEqual(
                    bad[:3], [],
                    f"{alias} 里有含空白的条目，多半是字典头部漏进来了")

    def test_shipped_files_match_the_import_script(self) -> None:
        """磁盘上的字典必须**正好是**导入脚本会写出的样子。

        把文件里的条目读出来、用 ``render()`` 重新渲染，逐字节比对：

        * 头部被手改过 → 对不上
        * 头部漏了一行进条目 → 条目数与 ``条目：N 条`` 不符 → 对不上
        * 有人手加了词没走脚本 → 对不上

        这条让"字典是脚本产物、不是手工维护"这件事变成可执行的约定。
        全程离线，不联网。
        """
        import importlib.util

        spec_path = (Path(__file__).resolve().parents[1] / "scripts"
                     / "import_dirmap_dicts.py")
        spec = importlib.util.spec_from_file_location("_hive_import_dirmap", spec_path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        resources = Path(mod.RESOURCES)
        for tier, tspec in mod.TIERS.items():
            with self.subTest(tier=tier):
                path = resources / tspec["file"]
                raw = path.read_bytes()
                text = raw.decode("utf-8")
                # 末行分隔线从脚本自己的 HEADER 取，不硬编码长度；
                # 首行和末行是同一行，所以要 rpartition 取**最后**一处
                fence = "\r\n" + mod.HEADER.rstrip().splitlines()[-1] + "\r\n"
                header, sep, body = text.rpartition(fence)
                self.assertTrue(sep, f"{path.name} 里找不到 HEADER 末行分隔线")
                words = [l for l in body.split("\r\n") if l.strip()]
                self.assertEqual(
                    mod.render(words, tspec).encode("utf-8"), raw,
                    f"{path.name} 与 scripts/import_dirmap_dicts.py 的产出不一致；"
                    f"改动字典请走脚本，别手改文件")
                # 头部自称的条数也要与实际一致
                self.assertIn(f"条目：{len(words)} 条", header)


class TestDirmapWordlistEndToEnd(EngineTestCase):
    """内置 ``dir_leaks`` 档**真跑一遍**引擎。

    前面那些都是纯函数层的验证。这条走完整链路：``dir_brute`` 的
    ``setup()`` 读 ``wordlist`` 别名 → 建软 404 画像 → 逐条请求 →
    命中落 ``http_endpoint``。

    用的是**真字典**（30 条，不是临时文件），所以它同时钉住了一件事：
    新增的别名在模块的 ``setup()`` 路径上真的能解析 —— 别名只在
    ``load_path_words`` 里注册是不够的，还要能穿过 ``self.cfg("wordlist")``。
    """

    async def test_leaks_tier_finds_env_and_records_it(self) -> None:
        from core.services.http import HTTPClient

        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            if url.endswith("/.env"):
                return TestDirBrute._resp(
                    url, 200, 0,
                    text="DB_PASSWORD=hunter2\nSECRET_KEY=abc\n",
                    headers={"server": "nginx", "content-type": "text/plain"},
                )
            return TestDirBrute._resp(url, 404, 64)     # 真 404，不是软 404

        self.add_module_file("emit_port", EMIT_PORT)
        with mock.patch.object(HTTPClient, "fetch", TestDirBrute._fake_fetch(self, responder)):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": "dir_leaks",        # ← 真别名，不给路径
                        "probes": 3, "concurrency": 4, "delay": 0,
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        self.assertIn("http://fuzz.example.com/.env", seen,
                      "内置 dir_leaks 档里的 .env 没被请求")

        endpoints = {
            r["url"]: r for r in await self.storage.endpoints(scanner.scan_id, limit=500)
        }
        self.assertIn("http://fuzz.example.com/.env", endpoints,
                      f"命中没落成 http_endpoint: {sorted(endpoints)}")
        row = endpoints["http://fuzz.example.com/.env"]
        self.assertEqual(row["status"], 200)
        self.assertEqual(row["server"], "nginx")
        # .env 是纯文本，没有 <title>，标题为空是对的
        self.assertFalse(row["title"])


class TestDirBruteQuotaUnderConcurrency(EngineTestCase):
    """``dir_brute`` 开了 3 个 worker，配额**不能**被超发。

    这是多 worker 在本模块唯一会真正出错的地方：``max_hosts`` 的"检查"与
    "占位"之间原本隔着 ``await self._calibrate(...)``，两个 worker 会同时
    通过检查，于是实际开跑的主机数超过配额。修法是 ``_claimed`` 原子占位
    （检查与 ``+= 1`` 相邻，中间无 await）。

    配套的引擎层测试在 ``tests/test_workers.py``。
    """

    async def test_max_hosts_is_never_exceeded(self) -> None:
        from core.services.http import HTTPClient

        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            return TestDirBrute._resp(url, 404, 77)      # 正常 404，画像可用

        self.add_module_file("emit_urls_many", EMIT_URLS_MANY)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_quota2.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\n.env\n", encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", TestDirBrute._fake_fetch(self, responder)):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_urls_many", "dir_brute"],
                module_config={"dir_brute": {
                    "wordlist": str(wl), "probes": 2, "concurrency": 4,
                    "delay": 0, "max_hosts": 3, "host_budget": 60,
                }},
            )

        # 只有拿到字典请求的才是"真正开跑"的主机
        hosts = {u.split("/", 3)[2] for u in seen
                 if u.rsplit("/", 1)[-1] in {"admin", ".env"}}
        self.assertLessEqual(
            len(hosts), 3,
            f"max_hosts=3 却有 {len(hosts)} 个主机被开跑: {sorted(hosts)}")
        self.assertEqual(len(hosts), 3, f"配额没用满: {sorted(hosts)}")


class TestUpstreamErrorHostIsSkipped(EngineTestCase):
    """非 HTTP 端口（25/110/143…）必须**在发字典请求之前**就被放弃。

    2026-10-03 实测踩到：``http_probe`` 把 ``http://host:25`` 也当成 URL 发出来，
    本地代理对非 HTTP 端口一律回 502、正文为空。于是软 404 画像"建立成功"
    （状态码恒定、大小恒定 0），旧实现照样开跑 5.7k 条字典路径 ——
    每条都判成噪声丢弃，零命中，而且因为每模块只有一个串行 worker，
    整个扫描就此僵住 30 分钟（进程 CPU 为 0、无出站连接）。

    这条测试钉住的是"**一条字典请求都不许发**"，不是"结果少一点"。
    """

    async def test_all_502_baseline_stops_before_any_dict_request(self) -> None:
        from core.services.http import HTTPClient

        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            # 全部 502 且正文为空 —— 本地代理拒绝非 HTTP 端口时的典型响应
            return TestDirBrute._resp(url, 502, 0, text="")

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_502.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\n.env\n.git/config\nbackup.zip\n", encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", TestDirBrute._fake_fetch(self, responder)):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "probes": 4, "concurrency": 2,
                        "delay": 0, "host_budget": 60,
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        # 只应该有软 404 校准的探测，不该有任何一条字典路径
        dict_paths = [u for u in seen
                      if u.rsplit("/", 1)[-1] in {"admin", ".env", "backup.zip"}
                      or u.endswith("/.git/config")]
        self.assertEqual(dict_paths, [], f"非 HTTP 主机上仍发了字典请求: {dict_paths}")
        # 探活 1 次（http_probe 的根请求）+ 校准 probes=4 次，一条字典都不能有
        self.assertLessEqual(len(seen), 5, f"探测次数异常: {seen}")

        # 并且要说清楚为什么跳过
        # 注意 finding 表里**没有 title 列**：emit_finding() 的第一个位置参数
        # 是 kind，这条摘要就存在 kind 里（与本文件既有 finding 一致）。
        findings = [
            f for f in await self.storage.findings(scanner.scan_id)
            if "跳过" in str(f.get("kind") or "")
        ]
        self.assertTrue(findings, "跳过了却没留下任何说明")
        self.assertEqual(findings[0]["severity"], "info")
        # http_probe 对默认端口拼出的是**无端口**的 http:// URL，所以成因是
        # "上游不可达"而不是"端口不对"
        # （两种成因的区分见 test_skip_reason_distinguishes_port_from_upstream）
        self.assertIn("上游不可达", str(findings[0]["detail"]))

    async def test_skip_reason_distinguishes_port_from_upstream(self) -> None:
        """全 502 有两种成因，**处置完全不同**，文案不能混成一句。

        带非标准端口（25/110/3306）→ 那个端口本来就不提供 HTTP，换个端口才
        有意义；无端口或 80/443 → 是**上游不可达**，再换路径也没用。

        2026-10-03 实测踩到：文案一律写"该端口不是 HTTP 服务"，结果
        ``http://www.sinosoft.com.cn``（根本没有端口）也被说成端口问题 ——
        把"站点挂了"误导成"换个端口再试"。
        """
        from core.services.http import HTTPClient

        def responder(url: str):
            return TestDirBrute._resp(url, 502, 0, text="")

        # 先发一个非标准端口，再发一个无端口的
        self.add_module_file("emit_mixed_502", EMIT_MIXED_502)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_502b.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\n.env\n", encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", TestDirBrute._fake_fetch(self, responder)):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_mixed_502", "dir_brute"],
                module_config={"dir_brute": {
                    "wordlist": str(wl), "probes": 2, "concurrency": 2, "delay": 0,
                }},
            )

        by_target = {
            f["target"]: str(f.get("detail") or "")
            for f in await self.storage.findings(scanner.scan_id)
            if "跳过" in str(f.get("kind") or "")
        }
        smtp = by_target.get("http://mix.example.com:25")
        web = by_target.get("http://mix.example.com")
        self.assertIsNotNone(smtp, f"没为 :25 留下说明: {sorted(by_target)}")
        self.assertIsNotNone(web, f"没为无端口主机留下说明: {sorted(by_target)}")

        self.assertIn("不提供 HTTP 服务", smtp)
        self.assertNotIn("上游不可达", smtp)
        self.assertIn("上游不可达", web)
        self.assertNotIn("不提供 HTTP 服务", web)

    async def test_max_hosts_is_not_consumed_by_skipped_hosts(self) -> None:
        """跳过的 host **不占** max_hosts 配额。

        真实场景：一个目标上 25/110/143/3306 这些端口都被 ``http_probe``
        当成了 URL。旧实现把"来过的 host"直接当配额，于是 ``max_hosts=1``
        会被第一个 SMTP 端口吃掉，真正该扫的 80/443 反而一个都没排上。
        """
        from core.services.http import HTTPClient

        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            if urlsplit(url).port in (25, 110, 143, 3306):   # 非 HTTP 端口
                return TestDirBrute._resp(url, 502, 0, text="")
            return TestDirBrute._resp(url, 404, 77)           # 真 HTTP 主机

        # 先发三个非 HTTP 端口，最后才发真正的 HTTP 主机
        self.add_module_file("emit_urls_many", EMIT_URLS_MANY)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_quota_skipped.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\n.env\n", encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", TestDirBrute._fake_fetch(self, responder)):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_urls_many", "dir_brute"],
                module_config={"dir_brute": {
                    "wordlist": str(wl), "probes": 2, "concurrency": 4,
                    "delay": 0, "max_hosts": 1, "host_budget": 60,
                }},
            )

        dict_paths = [u for u in seen
                      if u.rsplit("/", 1)[-1] in {"admin", ".env"}]
        # 必须打在**真主机**上
        self.assertTrue(
            any(u.startswith("http://fuzz.example.com/") for u in dict_paths),
            f"max_hosts=1 却被非 HTTP 端口吃掉了配额，真主机没排上: {seen}",
        )
        # 而且一个非 HTTP 端口都不许收到字典请求（旧实现在这里就去撞 :25）
        bad = [u for u in dict_paths if urlsplit(u).port]
        self.assertEqual(
            bad, [],
            f"非 HTTP 端口上发了字典请求: {bad}",
        )


class TestHostBudget(EngineTestCase):
    """每主机墙钟预算：超了就收尾，**并且说清楚结果不完整**。

    引擎每模块只有一个串行 worker，所以"一个主机跑太久"等于"整个扫描卡住"。
    这道闸门保证最坏情况是"覆盖不全"，而不是"拖死全局"。
    """

    async def test_budget_cuts_off_and_reports_partial_coverage(self) -> None:
        from core.services.http import HTTPClient

        seen: list[str] = []

        async def slow_fetch(client, url, **kwargs):  # noqa: ANN001
            seen.append(url)
            await asyncio.sleep(0.05)                # 模拟慢响应
            return TestDirBrute._resp(url, 404, 77)

        self.add_module_file("emit_port", EMIT_PORT)
        # 200 条路径 × 0.05s / 并发 2 = 5 秒；预算给 0.4 秒，必然截断
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_budget.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("\n".join(f"p{i:03d}" for i in range(200)), encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", slow_fetch):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "probes": 2, "concurrency": 2,
                        "delay": 0, "soft404": False, "host_budget": 0.4,
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        probed = [u for u in seen if u.rsplit("/", 1)[-1].startswith("p")]
        self.assertTrue(probed, "一条都没跑就说超预算，那是 bug")
        self.assertLess(len(probed), 200, f"预算没生效，跑了全部 {len(probed)} 条")

        findings = [
            f for f in await self.storage.findings(scanner.scan_id)
            if "时间预算" in str(f.get("kind") or "")
        ]
        self.assertTrue(findings, "截断了却没告诉用户结果不完整")
        detail = str(findings[0]["detail"])
        self.assertIn("不完整", detail)
        self.assertIn("host_budget", detail, "得告诉用户调哪个参数才能跑全")

    async def test_a_host_is_always_probed_at_least_once(self) -> None:
        """预算已经到期时，也必须**至少探一条**。

        ``checked == 0`` 就停手，等于这个主机白占了一个 ``max_hosts`` 名额
        和一次软 404 校准，换来 0 条信息 —— 比不跑还差。而且这不需要"预算配错"
        才会发生：机器一忙，进 ``_run_against`` 到第一次拿到 ``_sem`` 之间
        就可能已经超预算（实测整轮跑测试时偶发）。

        并发设 1，所以漏过去的请求数有界：精确地 1 条。
        """
        from core.services.http import HTTPClient

        seen: list[str] = []

        async def slow_fetch(client, url, **kwargs):  # noqa: ANN001
            seen.append(url)
            await asyncio.sleep(0.01)
            return TestDirBrute._resp(url, 404, 77)

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_tiny_budget.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("\n".join(f"p{i:03d}" for i in range(50)), encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", slow_fetch):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "probes": 0, "concurrency": 1,
                        "delay": 0, "soft404": False,
                        # 进场即到期：唯一还能救回来的是 checked == 0 那条豁免
                        "host_budget": 0.000001,
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        # ⚠️ 按字典内容精确匹配，不要用"末段以 p 开头"：
        # WAF 探测的载荷里含 `../../etc/passwd`，末段就是 `passwd`；
        # 校准 token 也是随机字母。两种都会污染这个判据。
        dict_paths = {f"p{i:03d}" for i in range(50)}
        probed = [u for u in seen if u.rsplit("/", 1)[-1] in dict_paths]
        self.assertEqual(len(probed), 1, f"应精确探 1 条，实际 {len(probed)}")


class TestUnreachableHostIsSkipped(EngineTestCase):
    """校准阶段**一个响应都没拿到**的主机要被跳过。

    与 :class:`TestUpstreamErrorHostIsSkipped` 是两回事，处置必须分开：

    * 全是 502 —— 机器**还活着**，只是当前网络到不了它（换个环境值得再试）
    * 一条响应都没有 —— 彻底不应答。拿它跑 5731 条字典，每条都耗在 8 秒
      超时上；而且没有画像可过滤，产出全是无法判真的条目。
    """

    async def _scan(self, *, skip: bool = True, **cfg):
        from core.services.http import HTTPClient

        seen: list[str] = []

        async def dead_fetch(client, url, **kwargs):  # noqa: ANN001
            seen.append(url)
            # ⚠️ **只有带路径的请求才是死的。** 根路径那一下必须成功 ——
            # 那是 ``http_probe`` 的探活；它失败就根本不会放行这台机器，
            # ``dir_brute`` 压根进不来，这条用例就变成在测探活了。
            if not urlsplit(url).path.strip("/"):
                return TestDirBrute._resp(url, 404, 77)
            return None        # 网络层失败 —— 校准拿不到任何响应

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_unreachable.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("\n".join(f"p{i:03d}" for i in range(20)), encoding="utf-8")

        module_cfg = {
            "wordlist": str(wl), "probes": 2, "concurrency": 2,
            "delay": 0, "skip_unreachable": skip,
        }
        module_cfg.update(cfg)
        with mock.patch.object(HTTPClient, "fetch", dead_fetch):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )
        return scanner, seen

    async def test_not_a_single_dict_request_is_sent(self) -> None:
        scanner, seen = await self._scan()

        # 校准的 probes 次 + 零次字典请求
        # （只数带路径的：探活那一下根请求是 http_probe 发的，不算校准）
        calib = [u for u in seen if urlsplit(u).path.strip("/")]
        self.assertEqual(len(calib), 2, f"应只有 2 次校准探测，实际 {seen}")
        # ⚠️ **必须按字典内容匹配，不能用"末段以 p 开头"。**
        # 校准 token 是随机字母，偶尔会生成 `ptIk` 这种以 p 开头的，
        # 于是被当成字典请求 —— 约 3% 的轮次会假红（实测踩到过）。
        # 字典是 p000..p019，精确集合匹配没有这个歧义。
        dict_paths = {f"p{i:03d}" for i in range(20)}
        self.assertFalse(
            [u for u in seen if u.rsplit("/", 1)[-1] in dict_paths],
            "完全不应答的主机不该收到任何字典请求",
        )

        findings = [
            f for f in await self.storage.findings(scanner.scan_id)
            if "无响应" in str(f.get("kind") or "")
        ]
        self.assertTrue(findings, "跳过了却没告诉用户为什么")
        detail = str(findings[0]["detail"])
        self.assertIn("一个响应都没拿到", detail)
        # 必须说清"不是 404" —— 否则用户会以为这台机器没东西可扫
        self.assertIn("不是 404", detail)

    async def test_max_hosts_quota_is_returned(self) -> None:
        """跳过的主机要**归还** ``max_hosts`` 名额。

        不还的话，一批全是死 IP 的域名能吃掉全部名额，排在后面的真站点
        一个都跑不了（这正是 ``all_upstream_errors`` 那道闸的同款问题）。

        构造：``max_hosts=1``，先来一个**死**主机再來一个**活**主机。
        只有配额归还了，第二个才拿得到名额、才真的发字典请求。
        """
        from core.services.http import HTTPClient

        self.add_module_file("emit_dead_then_alive", EMIT_DEAD_THEN_ALIVE)
        # 文件名必须唯一：`.testtmp` 是整个测试目录共享的，别处也写
        # `dir_quota.txt` 的话，这里读到的就是别人的内容（实测踩到过：
        # 跑出来的是 /admin 和 /.env 而不是 p000/p001）。
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_quota_unreachable.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("p000\np001\n", encoding="utf-8")

        seen: list[str] = []

        async def mixed_fetch(client, url, **kwargs):  # noqa: ANN001
            seen.append(url)
            if "dead." in url:
                return None                        # 完全不应答
            return TestDirBrute._resp(url, 404, 77)  # 活主机，正常 404

        with mock.patch.object(HTTPClient, "fetch", mixed_fetch):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_dead_then_alive", "dir_brute"],
                module_config={"dir_brute": {
                    "wordlist": str(wl), "probes": 1, "concurrency": 1,
                    "delay": 0, "soft404": True, "max_hosts": 1,
                    # ⚠️ **必须钉死单 worker。** 配额是"先占位、再干活、
                    # 干不了就归还"的（见 handle_event 的注释）：多 worker 下
                    # dead 主机占着名额去 await 校准时，alive 主机可能**在
                    # 归还之前**就到了，看到 _claimed=1 直接退出 ——
                    # 于是这条断言变成在测竞态调度，随 worker 数而变。
                    #
                    # 那个竞态本身不是 bug（配额终会归还，最坏是短暂少用一个
                    # 名额），所以这里不去改实现，而是把测试固定成确定性的。
                    "workers": 1,
                }},
            )

        alive_probed = [
            u for u in seen
            if "alive." in u and u.rsplit("/", 1)[-1].startswith("p")
        ]
        self.assertTrue(
            alive_probed,
            f"死主机没归还 max_hosts 名额，活的排在后面就一个都跑不了；"
            f"实际 seen={seen}",
        )

    async def test_switch_can_be_turned_off(self) -> None:
        """关掉 ``skip_unreachable`` 就回到旧行为 —— 开关必须真的有效。

        留着它是为了**可对比**：万一出现"校准超时但字典请求其实能通"
        （很可能是瞬时抖动），能一条配置切回去验证，而不是改代码。
        """
        _, seen = await self._scan(skip=False)
        probed = [u for u in seen if u.rsplit("/", 1)[-1].startswith("p")]
        self.assertTrue(
            probed,
            "skip_unreachable=False 时不该跳过（否则这条配置形同虚设）",
        )


class TestBusyHint(EngineTestCase):
    """模块自报进度 —— 界面上区分"在跑"和"挂了"的唯一信号。

    2026-10-03 实测踩到：``dir_brute`` 把命中攒在列表里、**整个主机跑完前
    一条事件都不发**，所以界面上「新事件」计数不动。于是一次真卡死
    （CPU 0 增长、无出站连接）和一次正常在跑（38 请求/秒）**表现完全一样**。
    ``progress.busy`` 就是补这个洞的。
    """

    def _scanner(self, **dir_cfg):
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_busy.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("\n".join(f"p{i}" for i in range(5)), encoding="utf-8")
        cfg = {
            "wordlist": str(wl), "soft404": False, "concurrency": 1,
            "delay": 0, "forbidden_min": 5, "max_hosts": 0,
        }
        cfg.update(dir_cfg)
        preset = Preset(
            name="test",
            include=["emit_port", "http_probe", "dir_brute"],
            module_dirs=[str(self.module_dir)],
            module_config={
                "dir_brute": cfg,
                # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                # https://host:80 —— URL 形状对不上，画像也就对不上
                "http_probe": {"prefer_https": False, "schemes": ["http"]},
            },
        )
        return Scanner(
            targets=["example.com"], preset=preset, storage=self.storage,
        )

    async def test_hint_names_the_host_and_moves_while_bruting(self) -> None:
        from core.services.http import HTTPClient

        # 闸门而不是 sleep：第一条**字典**请求进来就卡住，扫描**必然**停在爆破
        # 中途，此时读到的 busy 才是确定的。sleep 方案在本机上进出两遍结果
        # 都不一样（实测 4:1），不是能进 CI 的写法。
        #
        # ⚠️ 卡点必须是**字典路径**而不是任意请求。``dir_brute`` 在开跑前还会
        # 先取一次首页做指纹识别（``soft404`` 关掉时它就是第一个请求），
        # 那个阶段还没登记 ``_inflight``，``busy_hint()`` 自然是 None ——
        # 那是"还没开始爆破"，不是"爆破中却不报进度"。
        gate = asyncio.Event()
        entered = asyncio.Event()
        dict_paths = {f"p{i}" for i in range(5)}

        async def blocking_fetch(client, url, **kwargs):  # noqa: ANN001
            if url.rsplit("/", 1)[-1] in dict_paths:
                entered.set()
                await gate.wait()
            return TestDirBrute._resp(url, 404, 77)

        scanner = self._scanner()
        with mock.patch.object(HTTPClient, "fetch", blocking_fetch):
            task = asyncio.create_task(scanner.scan())
            try:
                await asyncio.wait_for(entered.wait(), timeout=10)
                busy = scanner.progress()["busy"]
                self.assertIn("dir_brute", busy, f"爆破中却没自报进度：{busy}")
                hint = busy["dir_brute"]
                self.assertIn("fuzz.example.com", hint)
                # 分母是展开后的字典条数
                self.assertRegex(hint, r"0/5\b")
            finally:
                gate.set()
                await asyncio.wait_for(task, timeout=30)

        # 跑完之后必须**摘干净**：留着会让界面一直挂着一个早就不跑的主机，
        # 比不显示更误导。
        self.assertEqual(scanner.progress()["busy"], {}, "跑完了还在自报进度")

    async def test_hint_is_cleared_when_the_scan_is_cancelled(self) -> None:
        """取消路径：``finally`` 摘除，不是"跑到函数末尾摘"。

        扫描被 stop 掉时是 ``CancelledError`` 从 ``asyncio.gather`` 冒出来，
        直接 return 的路径一个都覆盖不到 —— 漏摘就等于界面谎报。
        """
        from core.services.http import HTTPClient

        entered = asyncio.Event()
        dict_paths = {f"p{i}" for i in range(5)}

        async def blocking_fetch(client, url, **kwargs):  # noqa: ANN001
            if url.rsplit("/", 1)[-1] in dict_paths:
                entered.set()
                await asyncio.Event().wait()   # 永远不返回，只能被取消
            return TestDirBrute._resp(url, 404, 77)  # pragma: no cover

        scanner = self._scanner()
        with mock.patch.object(HTTPClient, "fetch", blocking_fetch):
            task = asyncio.create_task(scanner.scan())
            await asyncio.wait_for(entered.wait(), timeout=10)
            module = scanner.modules["dir_brute"]
            self.assertIsNotNone(module.busy_hint(), "爆破中却没自报进度")
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=30)

        self.assertIsNone(module.busy_hint(), "取消后没摘掉，界面会一直谎报在跑")

    async def test_a_raising_busy_hint_never_breaks_progress(self) -> None:
        """观测代码抛异常不能带崩进度接口，更不能带崩扫描。"""
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        self.add_module_file("emit_url_raisy_busy", EMIT_URL_RAISY_BUSY)
        preset = Preset(
            name="test",
            include=["emit_url_raisy_busy"],
            module_dirs=[str(self.module_dir)],
        )
        scanner = Scanner(
            targets=["example.com"], preset=preset, storage=self.storage,
        )
        await asyncio.wait_for(scanner.scan(), timeout=30)
        self.assertEqual(scanner.progress()["busy"], {})
        urls = await self.storage.events(
            scanner.scan_id, limit=100, event_type="URL",
        )
        self.assertTrue(urls, "模块自己的活没干完就完了，那是另一个 bug")


class TestDirBruteLeadingSlashEntry(EngineTestCase):
    """字典里带前导 ``/`` 的条目不能拼出双斜杠。

    ``dir_leaks.txt`` 里有一条真实条目就是 ``/secure/ManageFilters.jspa?filterView=popular``
    （WebLogic 管理台）。``dir_brute`` 拼 URL 时是 ``f"{host}/{path.lstrip('/')}"``，
    这条 ``lstrip`` 就是为它准备的 —— 但它是隐式的，值得钉一道。
    """

    async def test_leading_slash_entry_requests_single_slash(self) -> None:
        from core.services.http import HTTPClient

        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            return TestDirBrute._resp(url, 404, 500)

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_slash.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("/secure/ManageFilters.jspa?filterView=popular\n", encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", TestDirBrute._fake_fetch(self, responder)):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "probes": 2, "concurrency": 2,
                        "delay": 0, "soft404": False,
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        hits = [u for u in seen if "ManageFilters" in u]
        self.assertTrue(hits, f"这条字典条目根本没被请求: {seen}")
        for u in hits:
            self.assertIn("://fuzz.example.com/secure/ManageFilters.jspa", u)
            self.assertNotIn("//secure", u.split("://", 1)[1])

    async def test_query_entries_are_not_given_an_extension(self) -> None:
        """配了 ``extensions`` 时，带 query 的条目**不能**被展开。

        ``dir_joomla.txt`` 里有 ``index.php?option=com_users&view=reset``，
        加上 ``.html`` 变成 ``...&view=reset.html`` —— query 被塞进参数里，
        请求的根本不是同一个东西。而且它只在**配了 extensions 时**才暴露，
        不钉住的话大概率是等到某次换了配置才发现。
        """
        from core.services.http import HTTPClient

        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            return TestDirBrute._resp(url, 404, 500)

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_query_ext.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text(
            "index.php?option=com_users&view=reset\nplain\n", encoding="utf-8"
        )

        with mock.patch.object(HTTPClient, "fetch", TestDirBrute._fake_fetch(self, responder)):
            await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "probes": 2, "concurrency": 2,
                        "delay": 0, "soft404": False, "extensions": ["html", "jsp"],
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        with_query = [u for u in seen if "com_users" in u]
        self.assertTrue(with_query, f"带 query 的条目根本没被请求: {seen}")
        for u in with_query:
            self.assertFalse(
                u.endswith((".html", ".jsp")),
                f"带 query 的条目被加了扩展名，请求的根本不是同一个东西: {u}",
            )
        # 反面对照：普通条目**要**照常展开
        self.assertTrue([u for u in seen if u.endswith("/plain.html")],
                        "普通条目没被展开，_expand 整个坏了")


class TestDictionaryBoundary(unittest.TestCase):
    """字典必须守住能力边界。

    平台的边界是"只把暴露面铺到最大，接口语义与参数结构交给 AI"。目录爆破本身
    是允许的（AtlasX 的"目录暴露面"就是这么做的），但**字典里不能混进接口清单
    类的路径** —— 命中 ``swagger.json`` / ``actuator/mappings`` 的唯一价值就是
    枚举接口，那是"主动收集网站接口"。

    这份字典曾经混进了整整一段 ``# ── API / 文档 ──``（32 条），命中后会把
    ``/api/v1``、``/graphql``、``/swagger.json`` 当接口资产写库。所以在这里钉住。
    """

    #: 接口文档 / 接口清单端点 —— 命中它只说明"这个接口清单能拿到"
    _INTERFACE_INVENTORY = (
        "swagger.json", "swagger.yaml", "swagger-ui.html", "openapi.json",
        "openapi.yaml", "api-docs", "api/docs", "graphiql", "redoc",
        "actuator", "actuator/env", "actuator/mappings", "actuator/beans",
    )

    #: 接口动作名 —— 是"接口"，不是"目录"
    _INTERFACE_VERBS = (
        "search", "query", "list", "view", "detail",
        "edit", "delete", "create", "update",
    )

    def _words(self) -> list[str]:
        from core.util.words import load_path_words

        return load_path_words()

    def test_no_interface_inventory_paths(self) -> None:
        words = set(self._words())
        leaked = sorted(w for w in self._INTERFACE_INVENTORY if w in words)
        self.assertEqual(leaked, [], f"接口清单类路径漏进字典了: {leaked}")

    def test_no_interface_verbs(self) -> None:
        words = set(self._words())
        leaked = sorted(w for w in self._INTERFACE_VERBS if w in words)
        self.assertEqual(leaked, [], f"接口动作名漏进字典了: {leaked}")

    def test_real_exposure_surface_is_kept(self) -> None:
        """剔接口不等于把字典掏空 —— 目录 / 文件暴露面必须还在。

        这几条是"命中即有价值"的代表：配置文件、备份、管理台、状态页。
        注意 ``dir_brute`` 只比状态码/字节数/词数，**从不解析正文**，
        所以命中 ``.env`` 拿到的是"这个文件能访问"，不是里面的密钥。
        """
        words = set(self._words())
        for expected in (
            ".env", ".git/config", "config.php.bak", "backup.zip",
            "admin", "wp-admin", "phpinfo.php", "server-status", "jenkins",
            "robots.txt", "index.php",
        ):
            with self.subTest(word=expected):
                self.assertIn(expected, words, f"暴露面条目被误删: {expected}")

    def test_dictionary_is_not_empty(self) -> None:
        self.assertGreater(len(self._words()), 100)

    def test_tech_dictionaries_respect_the_same_boundary(self) -> None:
        """自研的**产品专属**字典也得守住这条边界。

        这条测试原先只查 ``dir_common`` —— 那时它是唯一的自研档。``techdicts``
        又带进来 17 档同样是手写的专属字典，边界测试不同步扩大的话就成了空壳：
        往 ``dir_spring.txt`` 里塞一条 ``actuator/env`` 不会有任何测试变红。

        dirmap 那四档**不在这里查**：那是整包引入的第三方数据，里面本来就混着
        ``swagger-ui.html`` / ``api-docs``（实测确认过），清理它是另一件事，
        不该由这条测试顺手夹带。
        """
        from core.util.words import TECH_PATH_WORDLISTS, load_path_words

        self.assertTrue(TECH_PATH_WORDLISTS, "产品专属字典表是空的")
        for alias in sorted(TECH_PATH_WORDLISTS):
            with self.subTest(alias=alias):
                words = set(load_path_words(alias))
                leaked = sorted(w for w in self._INTERFACE_INVENTORY if w in words)
                self.assertEqual(leaked, [], f"{alias} 混进了接口清单端点: {leaked}")


# --------------------------------------------------------------------- 指纹选字典


def _tech_rules():
    """映射表用到的那几十条规则（整库匹配 80ms，裁完 2ms）。"""
    from core.domains.fingerprint._lib.library import load_library
    from core.domains.web_search._lib.techdicts import relevant_technologies

    return relevant_technologies(load_library()[0])


def _obs(*, headers=None, html="", title="", cookies=None):
    from core.domains.fingerprint._lib.rules import Observation

    return Observation(
        headers=headers or {}, html=html, title=title, cookies=cookies or {},
    )


class TestTechDictMapping(unittest.TestCase):
    """「技术 → 字典」映射表本身：键必须真的存在，档必须真的能加载。"""

    def test_every_tech_id_exists_in_the_fingerprint_library(self) -> None:
        from core.domains.fingerprint._lib.library import load_library
        from core.domains.web_search._lib.techdicts import TECH_DICTS

        technologies, _labels, _loaded, errors = load_library()
        self.assertEqual(errors, [], "指纹库本身加载就有错，先修库")
        by_id = {t.id for t in technologies}
        missing = sorted(tid for tid in TECH_DICTS if tid not in by_id)
        self.assertEqual(
            missing, [],
            "映射表里的技术 id 在指纹库里不存在 —— 写错一个 id 不会报错，"
            "只会让那一档永远不被选中，属于静默失效",
        )

    def test_every_alias_loads_a_non_empty_unique_wordlist(self) -> None:
        from core.domains.web_search._lib.techdicts import TECH_DICTS
        from core.util.words import PATH_WORDLISTS, load_path_words

        for alias in sorted(set(TECH_DICTS.values())):
            with self.subTest(alias=alias):
                self.assertIn(alias, PATH_WORDLISTS, "别名没登记，用户无法显式使用")
                words = load_path_words(alias)
                # 下限压到 4：专属档剔掉接口清单端点之后本来就很薄
                # （dir_grafana 只剩 5 条），这条卡的是"字典不能是空壳"。
                self.assertGreaterEqual(len(words), 4, f"{alias} 是空壳")
                self.assertEqual(len(words), len(set(words)), f"{alias} 内部有重复")

    def test_all_aliases_are_declared_in_the_tech_table(self) -> None:
        """登记了别名却没被任何技术映射到 = 写了没人用的字典。"""
        from core.domains.web_search._lib.techdicts import TECH_DICTS
        from core.util.words import TECH_PATH_WORDLISTS

        self.assertEqual(sorted(TECH_PATH_WORDLISTS), sorted(set(TECH_DICTS.values())))

    def test_no_mapped_tech_matches_on_bare_english_words(self) -> None:
        """映射表里不许有"正文里搜几个普通英文词"就能命中的规则。

        真实站点上踩到过：指纹库给 ``spring-cloud-config`` 的规则是
        ``html: label|profiles|propertysources`` —— 三个词的裸交替，
        没有任何路径、标签名或资源名这种有区分度的写法。结果是
        **任何一个正常页面都命中**：实测 13 个公开站点里 7 个被判成
        Spring Cloud Config，包括 ``zyxwv.com``、``laravel.com``、``grafana.com``。

        这条规则要是留在映射表里，``dir_brute`` 就会对着一台跟 Spring 毫无
        关系的机器白发 46 条 Spring 路径。合成响应头的单元测试永远发现不了
        这个（那里压根没有正文），所以只能用**静态判据**钉住：
        没有预筛字面量的模式，至少得含一个非单词字符
        （``/`` ``.`` ``<`` ``"`` ``_`` ``-`` ``\\`` 之类）。
        """
        import re

        from core.domains.fingerprint._lib.library import load_library
        from core.domains.web_search._lib.techdicts import TECH_DICTS

        by_id = {t.id: t for t in load_library()[0]}
        specific = re.compile(r"""[./<>"'_\\\[\]()= :{}^$?+*#@~;,]""")

        offenders: dict[str, list[str]] = {}
        for tid in TECH_DICTS:
            patterns = getattr(by_id[tid].match, "html", None) or ()
            bare = [
                p.pattern for p in patterns
                if p.required is None and not specific.search(p.pattern)
            ]
            if bare:
                offenders[tid] = bare

        self.assertEqual(
            offenders, {},
            "这些技术会被任意正常页面命中，不能用来自动发字典请求",
        )

    def test_order_is_the_table_order_not_the_detection_order(self) -> None:
        """返回顺序由映射表钉死，不受 ``detect()`` 按 id 排序的影响。

        ``dir_brute`` 的 ``max_paths`` 是从头截断的，顺序 = 预算耗尽时谁先被砍。
        """
        from core.domains.web_search._lib.techdicts import TECH_DICTS, relevant_technologies

        rel = relevant_technologies(
            [_FakeTech(tid) for tid in ("apache-tomcat", "jboss")]
        )
        self.assertEqual([t.id for t in rel], ["apache-tomcat", "jboss"])
        self.assertLess(
            list(TECH_DICTS).index("apache-tomcat"),
            list(TECH_DICTS).index("jboss"),
        )


class TestTechDictSelection(unittest.TestCase):
    """认出技术 → 选出对应的字典档。"""

    #: 一台跑 Tomcat 的机器，只看响应头就够认出来
    TOMCAT = _obs(headers={
        "server": "Apache-Coyote/1.1", "x-powered-by": "Apache Tomcat/9.0.60",
    })
    #: 典型反代：一个技术特征都没有
    PLAIN = _obs(headers={"server": "nginx/1.24.0"})

    def _select(self, obs, **kw):
        from core.domains.web_search._lib.techdicts import select

        return [alias for _t, alias in select(obs, _tech_rules(), **kw)]

    def test_server_header_picks_the_tomcat_dict(self) -> None:
        self.assertEqual(self._select(self.TOMCAT), ["dir_tomcat"])

    def test_plain_reverse_proxy_picks_nothing(self) -> None:
        """识别不出来是常态（裸 IP 前面挂着 WAF/反代），不是错误。"""
        self.assertEqual(self._select(self.PLAIN), [])

    def test_aliases_matching_the_same_dict_collapse_to_one_pick(self) -> None:
        """六个 jboss-* id 指向同一档 —— 不能把同一批路径插 6 遍。"""
        obs = _obs(headers={"x-powered-by": "JBoss/4.2.7.GA"})
        self.assertEqual(self._select(obs), ["dir_jboss"])

    def test_limit_caps_the_number_of_dicts(self) -> None:
        """catch-all 页面很容易同时认出好几样东西，必须有上限。"""
        obs = _obs(headers={"x-powered-by": "Apache Tomcat/9.0"}, cookies={
            "django_language": "zh-hans", "phpmyadmin": "x",
        })
        self.assertLessEqual(len(self._select(obs, limit=2)), 2)
        self.assertEqual(self._select(obs, limit=0), [])

    def test_detection_is_cheap_enough_to_run_inline(self) -> None:
        """整库一次约 80ms（2026-10-03 实测）；裁到映射表那几十条之后必须到毫秒级。

        这条钉的是"能不能直接同步调 detect()、不必扔线程池"——
        有人日后把 ``relevant_technologies`` 改成返回整库，
        事件循环就会被每个主机卡 80 毫秒。
        """
        import time

        rules = _tech_rules()
        self.assertLess(len(rules), 100, "规则没裁干净")
        start = time.perf_counter()
        for _ in range(20):
            self._select(self.TOMCAT)
        self.assertLess((time.perf_counter() - start) / 20, 0.05)


class TestTechDictMerge(unittest.TestCase):
    """把专属档并进基础字典。"""

    BASE = ["p000", "p001", "admin"]

    def _picks(self):
        from core.domains.web_search._lib.techdicts import select

        return select(
            _obs(headers={"server": "Apache-Coyote/1.1"}), _tech_rules()
        )

    def test_prepend_keeps_every_base_word_and_puts_tech_first(self) -> None:
        from core.domains.web_search._lib.techdicts import merge_paths

        merged, added = merge_paths(self.BASE, self._picks())
        tomcat = [w for w in merged if w in load_alias("dir_tomcat")]

        self.assertEqual(merged[: len(tomcat)], tomcat, "专属档必须排在最前面")
        for word in self.BASE:
            self.assertIn(word, merged, "基础字典是用户显式配的，一条都不能少")
        self.assertEqual(added, len(tomcat))
        self.assertEqual(len(merged), len(set(merged)), "合并后有重复")

    def test_only_mode_drops_the_base_wordlist(self) -> None:
        from core.domains.web_search._lib.techdicts import merge_paths

        merged, _added = merge_paths(self.BASE, self._picks(), mode="only")
        self.assertIn("manager/html", merged)
        for word in self.BASE:
            self.assertNotIn(word, merged, "only 模式下基础字典不该出现")

    def test_only_mode_falls_back_when_base_already_covers_everything(self) -> None:
        """专属档整档都被基础字典覆盖时，**不能**回落到空列表。

        "只跑专属档"的字面语义会让这个主机一条请求都不发，
        那比跑通用字典差得多（白排一次队、白花一次软 404 校准）。
        """
        from core.domains.web_search._lib.techdicts import merge_paths

        covered = load_alias("dir_tomcat")
        merged, added = merge_paths(covered + ["p000"], self._picks(), mode="only")
        self.assertEqual(added, 0)
        self.assertEqual(merged, covered + ["p000"], "应该回落到基础字典")

    def test_no_picks_means_the_base_wordlist_is_returned_untouched(self) -> None:
        from core.domains.web_search._lib.techdicts import merge_paths

        merged, added = merge_paths(self.BASE, [], mode="only")
        self.assertEqual(merged, self.BASE)
        self.assertEqual(added, 0)


def load_alias(alias: str) -> list[str]:
    from core.util.words import load_path_words

    return load_path_words(alias)


class _FakeTech:
    """只带 ``id`` 的技术替身，供纯排序测试用。"""

    def __init__(self, tid: str) -> None:
        self.id = tid


#: 引擎里跑的目录是 ``.testtmp``（整个测试目录共享），文件名必须唯一
TECH_WL = "dir_tech_select.txt"


class TestTechDictSelectionEndToEnd(EngineTestCase):
    """走引擎：认出技术栈 → 产品专属路径真的被发出去。

    前面几组测的是纯函数；这里测的是接线 —— 多出来的那 1 个首页请求、
    闸门跑完之后才做指纹（被跳过的主机不该多收一个请求）、
    以及 ``max_paths`` 截断时先砍掉的必须是通用字典的尾部。
    """

    HOST = "http://fuzz.example.com"

    @staticmethod
    def _resp(url, status, size, *, text="", headers=None):
        from core.services.http import FetchResult

        return FetchResult(
            url=url, status=status, text=text or "x" * size,
            headers=headers if headers is not None else {},
        )

    def _responder(self, seen: list[str], *, stack: str = "tomcat"):
        """造一个"记下每次请求"的应答器。

        ``stack`` 决定首页带什么指纹 —— 这是整套机制唯一的输入。
        """
        heads = {
            "tomcat": {"server": "Apache-Coyote/1.1",
                       "x-powered-by": "Apache Tomcat/9.0.60"},
            "none": {"server": "nginx/1.24.0"},
        }
        root_body = {"tomcat": "<html><body>tomcat</body></html>",
                     "none": "<html><body>hi</body></html>"}

        def responder(url: str):
            seen.append(url)
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, 200, text=root_body[stack],
                                  headers=heads[stack])
            if url.endswith("/manager/html"):
                return self._resp(url, 200, 512)      # 真命中
            return self._resp(url, 404, 111)           # 软 404 基线

        return responder

    async def _scan(self, seen: list[str], *, stack: str = "tomcat", **cfg):
        from core.services.http import HTTPClient

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / TECH_WL
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("p000\np001\nadmin\n", encoding="utf-8")

        module_cfg = {
            "wordlist": str(wl), "probes": 4, "concurrency": 4,
            "delay": 0, "max_paths": 0,       # 0 = 不截断，方便逐条断言
        }
        module_cfg.update(cfg)
        responder = self._responder(seen, stack=stack)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            return await self.run_scan(
                # 目标只给根域：见 TestDirBrute._scan 的同名注释
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    def _dict_urls(self, seen: list[str]) -> list[str]:
        """只取**字典**请求。

        判据不能是"末段非空"：软 404 校准的随机 token 同样有末段，会混进来；
        也不能用 ``rsplit("/")`` 取末段 —— 字典里 ``manager/html`` 这种
        **带斜杠的路径**取出来只剩 ``html``。所以按完整路径前缀切。
        """
        known = set(load_alias("dir_tomcat")) | {"p000", "p001", "admin"}
        prefix = self.HOST + "/"
        return [u for u in seen
                if u.startswith(prefix) and u[len(prefix):] in known]

    async def test_tomcat_host_gets_the_tomcat_paths(self) -> None:
        seen: list[str] = []
        await self._scan(seen)

        self.assertIn(f"{self.HOST}/manager/html", seen,
                      "认出了 Tomcat 却没有去探 /manager/html —— 整个机制没生效")

    async def test_base_wordlist_is_still_fully_covered(self) -> None:
        """专属档是**追加**，不是替换 —— 用户配的字典一条都不能少。"""
        seen: list[str] = []
        await self._scan(seen)

        for word in ("p000", "p001", "admin"):
            self.assertIn(f"{self.HOST}/{word}", seen, f"基础字典 {word} 被吞了")

    async def test_unknown_stack_still_brutes_the_base_wordlist(self) -> None:
        """识别不出来是常态，绝不能因此跳过整个主机。"""
        seen: list[str] = []
        scanner, _ = await self._scan(seen, stack="none")

        self.assertIn(f"{self.HOST}/p000", seen)
        self.assertNotIn(f"{self.HOST}/manager/html", seen)

    async def test_it_can_be_turned_off(self) -> None:
        seen: list[str] = []
        await self._scan(seen, tech_dicts=False)

        self.assertNotIn(f"{self.HOST}/manager/html", seen)
        self.assertIn(f"{self.HOST}/p000", seen, "关掉选字典不该影响基础爆破")

    async def test_only_mode_runs_the_tech_paths_alone(self) -> None:
        seen: list[str] = []
        await self._scan(seen, tech_dict_mode="only")

        self.assertIn(f"{self.HOST}/manager/html", seen)
        self.assertNotIn(f"{self.HOST}/p000", seen, "only 模式不该跑基础字典")

    async def test_only_mode_falls_back_when_nothing_is_detected(self) -> None:
        """认不出技术时回落 —— 否则这个主机一条请求都不会发。"""
        seen: list[str] = []
        await self._scan(seen, stack="none", tech_dict_mode="only")

        self.assertIn(f"{self.HOST}/p000", seen, "认不出技术时必须回落到基础字典")

    async def test_max_paths_keeps_the_tech_paths_first(self) -> None:
        """截断从**头**砍，所以专属档必须排在前面才活得下来。"""
        seen: list[str] = []
        await self._scan(seen, max_paths=5)

        probed = self._dict_urls(seen)
        self.assertEqual(len(probed), 5, f"max_paths=5 却探了 {len(probed)} 条")
        self.assertIn(f"{self.HOST}/manager/html", probed)
        self.assertNotIn(f"{self.HOST}/admin", probed, "被砍掉的应该是通用路径")

    async def test_detected_stack_is_reported_to_the_user(self) -> None:
        """识别结果必须落到 finding 里 —— 否则用户不知道为什么多了一批请求。"""
        seen: list[str] = []
        scanner, _ = await self._scan(seen)

        rows = [
            r for r in await self.storage.findings(scanner.scan_id)
            if "技术栈" in str(r.get("kind") or "")
        ]
        self.assertTrue(rows, "选中了字典却没告诉用户")
        detail = str(rows[0]["detail"])
        self.assertIn("Tomcat", detail)
        self.assertIn("不解析响应正文", detail,
                      "必须说清命中只代表路径能访问，不代表看到了内容")

    async def test_no_finding_when_nothing_is_detected(self) -> None:
        seen: list[str] = []
        scanner, _ = await self._scan(seen, stack="none")

        rows = [
            r for r in await self.storage.findings(scanner.scan_id)
            if "技术栈" in str(r.get("kind") or "")
        ]
        self.assertEqual(rows, [], "没识别出技术就不该发这条 finding")

    async def test_skipped_host_is_never_fingerprinted(self) -> None:
        """闸门放行的顺序不能错：不可达的主机**不该**多收一个首页请求。"""
        from core.services.http import HTTPClient

        seen: list[str] = []

        async def dead_fetch(client, url, **kwargs):  # noqa: ANN001
            seen.append(url)
            # 同上：根路径放活，否则探活阶段就把这台机器筛掉了，
            # 压根走不到「校准全灭」这道闸门。
            if not urlsplit(url).path.strip("/"):
                return self._resp(url, 404, 77)
            return None

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_tech_dead.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("p000\np001\n", encoding="utf-8")

        with mock.patch.object(HTTPClient, "fetch", dead_fetch):
            await self.run_scan(
                # 目标只给根域：``fuzz.example.com`` 必须不是种子，否则
                # ``skip_seed`` 会直接跳过它（连校准都不会发生）
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "probes": 2, "concurrency": 2, "delay": 0,
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        self.assertNotIn(f"{self.HOST}/", seen,
                         "校准就全灭的主机不该再收一个首页请求")
        calib = [u for u in seen if urlsplit(u).path.strip("/")]
        self.assertEqual(len(calib), 2, f"应只有 2 次校准探测，实际 {seen}")


    async def test_a_broken_fingerprint_library_is_a_soft_failure(self) -> None:
        """指纹库加载不了也不能让整个模块起不来 —— 退回原字典继续跑。"""
        from core.domains.fingerprint._lib import library as fp_library
        from core.services.http import HTTPClient

        seen: list[str] = []
        responder = self._responder(seen)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        def boom(*a, **kw):
            raise OSError("指纹库文件损坏")

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_tech_badlib.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("p000\np001\n", encoding="utf-8")

        with mock.patch.object(fp_library, "load_library", boom), \
                mock.patch.object(HTTPClient, "fetch", fake_fetch):
            scanner, _ = await self.run_scan(
                # 目标只给根域：见上面那条的同名注释
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": {
                        "wordlist": str(wl), "probes": 4, "concurrency": 2, "delay": 0,
                    },
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

        self.assertIn(f"{self.HOST}/p000", seen, "库坏了也不该影响基础爆破")
        self.assertNotIn(f"{self.HOST}/manager/html", seen)
        rows = [
            r for r in await self.storage.findings(scanner.scan_id)
            if "技术栈" in str(r.get("kind") or "")
        ]
        self.assertEqual(rows, [])


class TestSeedAndWafGates(EngineTestCase):
    """① 种子域名默认不处理 ② 识别到 WAF 就放弃爆破。

    起因是一次真实扫描：目标是 ``panabit.com``，apex 门户被跑了 5731 条目录，
    把它自己打崩之后整台机器开始回 512，**连带子域一起遭殃**。
    """

    @staticmethod
    def _resp(url, status, size, *, text="", headers=None):
        from core.services.http import FetchResult

        return FetchResult(
            url=url, status=status, text=text or "x" * size,
            headers=headers if headers is not None else {},
        )

    async def _scan(self, responder, *, targets, **cfg):
        from core.services.http import HTTPClient

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_seed_waf.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("p000\np001\n", encoding="utf-8")
        module_cfg = {
            "wordlist": str(wl), "probes": 2, "concurrency": 2, "delay": 0,
        }
        module_cfg.update(cfg)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            return await self.run_scan(
                targets=targets,
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    # ------------------------------------------------------------------ ①
    async def test_seed_domain_is_not_bruted(self) -> None:
        """种子就是 ``targets`` 里那一条 —— 默认一条字典请求都不发。"""
        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, targets=["fuzz.example.com"])

        dict_hits = [u for u in seen if u.endswith(("p000", "p001"))]
        self.assertEqual(dict_hits, [], f"种子域名仍被爆破了: {dict_hits}")
        detail = [
            f for f in await self.storage.findings(scanner.scan_id)
            if f.get("detail") and "seed" in str(f["detail"])
        ]
        self.assertEqual(detail, [], "跳过种子是配置行为，不必发 finding")

    async def test_subdomain_is_still_bruted(self) -> None:
        """不能连子域一起跳掉 —— 那是这次改动的全部意义。"""
        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            return self._resp(url, 404, 111)

        await self._scan(responder, targets=["example.com"])
        self.assertIn("http://fuzz.example.com/p000", seen)

    async def test_seed_gate_can_be_turned_off(self) -> None:
        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            return self._resp(url, 404, 111)

        await self._scan(responder, targets=["fuzz.example.com"], skip_seed=False)
        self.assertTrue(
            [u for u in seen if u.endswith(("p000", "p001"))],
            "关掉 skip_seed 后种子仍该被扫",
        )
    # ------------------------------------------------------------------ ②
    async def test_waf_aborts_the_bruteforce(self) -> None:
        """响应里有 WAF 特征 → 一条字典请求都不发，并且要说清为什么。"""
        seen: list[str] = []
        waf_headers = {
            "server": "cloudflare",
            "cf-ray": "8f0a1b2c3d4e5f60-LAX",
            "cf-cache-status": "DYNAMIC",
        }

        def responder(url: str):
            seen.append(url)
            return self._resp(url, 403, 120, headers=waf_headers)

        scanner, _ = await self._scan(responder, targets=["example.com"])

        dict_hits = [u for u in seen if u.endswith(("p000", "p001"))]
        self.assertEqual(dict_hits, [], f"识别到 WAF 还在打字典: {dict_hits}")
        rows = [
            f for f in await self.storage.findings(scanner.scan_id)
            if "WAF" in str(f.get("kind") or "")
        ]
        self.assertTrue(rows, "放弃爆破却没告诉用户为什么")
        self.assertIn("未发送任何字典请求", str(rows[0]["detail"]))

    async def test_waf_gate_can_be_turned_off(self) -> None:
        seen: list[str] = []
        waf_headers = {"server": "cloudflare", "cf-ray": "8f0a1b2c3d4e5f60-LAX"}

        def responder(url: str):
            seen.append(url)
            return self._resp(url, 403, 120, headers=waf_headers)

        await self._scan(responder, targets=["example.com"], abort_on_waf=False)
        self.assertTrue(
            [u for u in seen if u.endswith(("p000", "p001"))],
            "关掉 WAF 闸门后字典照跑",
        )


class TestRootFallbackAndServerErrors(EngineTestCase):
    """③ 回到根目录不算命中 ＋ 5xx 不算命中 ＋ 画像漂移停手。

    三条都来自同一次真实扫描（``panabit.com``）：3311 行端点里
    941 个 200 是假的、70 个 502 是垃圾。
    """

    HOST = "http://fuzz.example.com"
    #: 假首页：状态 200、正文 4096 字节
    HOME = "H" * 4096

    @staticmethod
    def _resp(url, status, size, *, text="", headers=None):
        from core.services.http import FetchResult

        return FetchResult(
            url=url, status=status, text=text or "x" * size,
            headers=headers if headers is not None else {},
        )

    async def _scan(self, responder, **cfg):
        from core.services.http import HTTPClient

        self.add_module_file("emit_port", EMIT_PORT)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_rootfb.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("p000\np001\nadmin\n.env\n", encoding="utf-8")
        module_cfg = {
            "wordlist": str(wl), "probes": 2, "concurrency": 2, "delay": 0,
        }
        module_cfg.update(cfg)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            return await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    async def _urls(self, scan_id: int) -> set[str]:
        events = await self.storage.events(scan_id, limit=500, event_type="URL")
        return {e["data"] for e in events if e["module"] == "dir_brute"}

    # ------------------------------------------------------------------ ③
    async def test_spa_fallback_is_not_a_hit(self) -> None:
        """随机路径 404，但字典路径回同一份首页 → 一条命中都不该有。

        ⚠️ 校准与字典路径的响应**必须形态不同**，否则软 404 画像会先把它们
        全判成噪声，这条用例根本走不到"回到根目录"判据上（等于什么都没测）。
        真实场景正是这样：只有像文件名的路径才会被 rewrite 回首页。
        """
        dict_paths = {"p000", "p001", "admin", ".env"}

        def responder(url: str):
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, len(self.HOME), text=self.HOME)
            if url.rsplit("/", 1)[-1] in dict_paths:
                return self._resp(url, 200, len(self.HOME), text=self.HOME)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder)
        self.assertEqual(
            await self._urls(scanner.scan_id), set(),
            "SPA history fallback 把首页重复记成了命中",
        )

    async def test_a_real_page_still_counts(self) -> None:
        """长度不同 → 真的是新页面，必须算命中。"""

        def responder(url: str):
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, len(self.HOME), text=self.HOME)
            if url.endswith("/admin"):
                return self._resp(url, 200, 123, text="A" * 123)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder)
        urls = await self._urls(scanner.scan_id)
        self.assertIn(f"{self.HOST}/admin", urls)
        self.assertNotIn(f"{self.HOST}/p000", urls, "404 噪声不该被记进来")

    async def test_root_that_is_itself_404_keeps_the_noise_filter(self) -> None:
        """⚠️ 根目录自己是 404 时，"回到根目录"判据**不能**吃掉正常的 404 噪声。

        判据一旦排在软 404 过滤之前，根目录 404 的站点上字典里每条 404 都会
        "与根目录同形"而被误杀，整轮零命中（改这一版时踩到过）。
        """

        def responder(url: str):
            if url.endswith("/admin"):
                return self._resp(url, 200, 123, text="A" * 123)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder)
        self.assertIn(
            f"{self.HOST}/admin", await self._urls(scanner.scan_id),
            "根目录为 404 时把真命中也误杀了",
        )

    async def test_redirect_to_root_is_not_a_hit(self) -> None:
        """跟随重定向后最终 URL 就是 ``/`` → 也是回到首页。"""

        def responder(url: str):
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, len(self.HOME), text=self.HOME)
            if url.endswith("/p000"):
                # 内容长度故意不同（不像首页），但最终 URL 回到了根
                r = self._resp(url, 200, 999, text="Z" * 999)
                r.url = f"{self.HOST}/"
                return r
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder)
        self.assertNotIn(
            f"{self.HOST}/p000", await self._urls(scanner.scan_id),
            "重定向回首页的路径不该算命中",
        )

    # ------------------------------------------------------------------ 缺陷 A
    async def test_5xx_is_never_a_hit(self) -> None:
        """502/512 不是"这个路径存在"的证据。

        实测扫 ``panabit.com`` 落库了 70 行 ``502``（title 是
        ``502-服务器内部错误``）—— 服务器在报错，不是在说路径存在。

        ⚠️ 同样要保证校准形态与字典路径**不同**（404 vs 5xx），否则软 404
        画像会把 5xx 判成噪声，这条用例就测不到 5xx 闸门本身了。
        """
        dict_paths = {"p000", "p001", "admin", ".env"}
        for status in (500, 502, 503, 504, 512):
            with self.subTest(status=status):

                def responder(url: str, _s=status):
                    if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                        return self._resp(url, 200, len(self.HOME), text=self.HOME)
                    if url.rsplit("/", 1)[-1] in dict_paths:
                        return self._resp(url, _s, 798)
                    return self._resp(url, 404, 111)

                scanner, _ = await self._scan(responder)
                self.assertEqual(
                    await self._urls(scanner.scan_id), set(),
                    f"{status} 被当成了命中",
                )

    # ------------------------------------------------------------------ 缺陷 B
    async def test_profile_drift_stops_the_run(self) -> None:
        """校准之后站点换了行为 → 停手，并说清结果不可信。"""
        calls = {"n": 0}

        def responder(url: str):
            calls["n"] += 1
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, len(self.HOME), text=self.HOME)
            # 校准那几次回 404，之后一律 200 —— 模拟"上了 WAF / 换成 catch-all"
            return self._resp(url, 404 if calls["n"] <= 3 else 200, 12345)

        # 字典必须够长：``drift_min_samples`` 下限 20，采不够样永远不会触发
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_drift.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("\n".join(f"d{i:03d}" for i in range(40)), encoding="utf-8")

        scanner, _ = await self._scan(
            responder, probes=2, drift_ratio=0.25, drift_min_samples=20,
            wordlist=str(wl),
        )
        rows = [
            f for f in await self.storage.findings(scanner.scan_id)
            if "中途变化" in str(f.get("kind") or "")
        ]
        self.assertTrue(rows, "画像漂移了却没说")
        self.assertIn("不可信", str(rows[0]["detail"]))


class TestZeroHitAbort(EngineTestCase):
    """零命中提前收手 —— 这是 ``dir_brute`` 省流量最有效的一条。

    目录爆破本质是猜 URL。有价值的通用路径（``.env`` / ``.git/config`` / ``admin``）
    在任何靠谱字典里都排在**前面**，所以真站点会在前几百条命中；死站点一条都
    命中不了，却要老老实实把 5745 条跑完。实测扫描 #40：22528 条请求里
    **21900 条是 404 噪声**（97%），只换 18 条命中。
    """

    HOST = "http://fuzz.example.com"

    @staticmethod
    def _resp(url, status, size, *, text="", headers=None):
        from core.services.http import FetchResult

        return FetchResult(
            url=url, status=status, text=text or "x" * size,
            headers=headers if headers is not None else {},
        )

    async def _scan(self, responder, *, npaths=2000, wl_name="zh.txt", **cfg):
        from core.services.http import HTTPClient

        self.add_module_file("emit_port", EMIT_PORT)
        # ⚠️ **文件名必须逐用例唯一。** ``load_path_words`` 带 ``lru_cache``，
        # 同一个路径的字典整个进程只读一次 —— 换个用例改内容也不会重读，
        # 于是所有用例都会拿到第一条写入的那份（实测踩到：四条用例里三条
        # 拿到的都是 500 条的旧字典）。``.testtmp`` 是整个测试目录共享的。
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / wl_name
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("\n".join(f"p{i:04d}" for i in range(npaths)),
                      encoding="utf-8")
        module_cfg = {
            "wordlist": str(wl), "probes": 2, "concurrency": 4, "delay": 0,
            "max_paths": 0,
        }
        module_cfg.update(cfg)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            return await self.run_scan(
                targets=["example.com"],
                include=["emit_port", "http_probe", "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    def _dict_probes(self, seen: list[str], npaths: int = 2000) -> list[str]:
        """只取**字典**请求。

        不能用 ``startswith("/p")``：软 404 校准的 token 是随机字母，偶尔会
        生成 ``pXkq`` 这种以 p 开头的，于是被算进来（实测踩到，2000 变 2001）。
        """
        prefix = f"{self.HOST}/"
        known = {f"p{i:04d}" for i in range(npaths)}
        return [u for u in seen
                if u.startswith(prefix) and u[len(prefix):] in known]

    async def test_dead_site_stops_at_the_threshold(self) -> None:
        """什么都没有的站点：试满 N 条就收手，不跑完 2000 条。"""
        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, 300, headers={"server": "nginx"})
            return self._resp(url, 404, 111)

        await self._scan(responder, zero_hit_abort=300, wl_name="zh_dead.txt")
        probed = self._dict_probes(seen)
        self.assertLessEqual(
            len(probed), 305,
            f"零命中站点仍被探了 {len(probed)} 条 —— 提前收手没生效",
        )
        self.assertGreater(len(probed), 290, "收手太早，样本量不足")

    async def test_live_site_keeps_going(self) -> None:
        """有命中的站点**绝不能**被提前收手掐掉。"""
        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, 300, headers={"server": "nginx"})
            if url.endswith("/p0005"):          # 靠前的命中
                return self._resp(url, 200, 777)
            return self._resp(url, 404, 111)

        await self._scan(responder, zero_hit_abort=300, wl_name="zh_live.txt")
        probed = self._dict_probes(seen)
        self.assertEqual(len(probed), 2000, "已经命中过的站点被误收手了")

    async def test_a_hit_after_the_threshold_is_missed_by_design(self) -> None:
        """阈值**之后**的命中会漏 —— 这是刻意的代价，写在这里免得将来被当 bug 改掉。

        收手的判据是"**累计**零命中"，所以第 800 条的命中在第 300 条收手时
        根本还没发生。要覆盖靠后的冷门路径，得把 ``zero_hit_abort`` 设成 0，
        代价就是回到"每个站点 5745 条全跑完"。
        """
        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, 300, headers={"server": "nginx"})
            if url.endswith("/p0800"):
                return self._resp(url, 200, 777)
            return self._resp(url, 404, 111)

        await self._scan(responder, zero_hit_abort=300, npaths=1000,
                         wl_name="zh_late.txt")
        self.assertEqual(
            len(self._dict_probes(seen, 1000)), 300,
            "阈值之后的命中居然没漏 —— 那说明收手判据不是「累计零命中」",
        )
        # 同一个场景，把阈值关掉就应该拿到那条命中
        seen2: list[str] = []

        def responder2(url: str):
            seen2.append(url)
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, 300, headers={"server": "nginx"})
            if url.endswith("/p0800"):
                return self._resp(url, 200, 777)
            return self._resp(url, 404, 111)

        await self._scan(responder2, zero_hit_abort=0, npaths=1000,
                         wl_name="zh_late_full.txt")
        self.assertEqual(len(self._dict_probes(seen2, 1000)), 1000)
        self.assertTrue([u for u in seen2 if u.endswith("/p0800")],
                        "关掉收手后连靠后的命中都丢了，那是另一个 bug")

    async def test_can_be_turned_off(self) -> None:
        seen: list[str] = []

        def responder(url: str):
            seen.append(url)
            if url in (self.HOST, f"{self.HOST}/"):   # 无尾斜杠也算首页
                return self._resp(url, 200, 300, headers={"server": "nginx"})
            return self._resp(url, 404, 111)

        await self._scan(responder, zero_hit_abort=0, npaths=500,
                         wl_name="zh_off.txt")
        self.assertEqual(len(self._dict_probes(seen, 500)), 500,
                         "zero_hit_abort=0 时应当跑满")


class TestSoft404ThreeLayer(unittest.TestCase):
    """软 404 的三层判据（关键词 → 大小 → SimHash）+ auth-wall + 同目录基线。

    层次来源：ffuf 的 ``-ac``（基线）、pathprobe 的 FNV-1a simhash 与
    ``invalidSibling``。**两处不能照抄**：pathprobe 的 ``[a-z0-9]{3,}`` 分词
    提不出中文 token（中文站点的 404 页会算出常数指纹，于是所有中文正文
    都被判成软 404），SnailPath 的 ``hash()`` 不跨进程稳定。
    """

    NOTFOUND_ZH = (
        "<html><head><title>404</title></head><body>"
        "<h1>页面不存在</h1><p>您访问的页面不存在或已被删除。</p>"
        "</body></html>"
    )

    def _profile(self, probes, **kw):
        return SoftProfile.build(probes, **kw)

    def _p(self, token, status, size, text=""):
        return Probe.of(token, status, size, len((text or "").split()), text)

    # ------------------------------------------------------------------ 中文
    def test_chinese_404_body_is_recognised(self) -> None:
        """中文错误页必须能判出来 —— 只认英文的话国内站点一个都拦不住。"""
        self.assertIsNotNone(looks_like_soft_404(self.NOTFOUND_ZH))

    def test_chinese_simhash_is_not_a_constant(self) -> None:
        """中文正文必须能算出**有区分度**的指纹。

        pathprobe 的 ``[a-z0-9]{3,}`` 在中文正文上提不出 token，simhash 恒为
        0 → 相似度恒等 → 任何中文页面都被判成软 404。
        """
        a = simhash64(extract_text(self.NOTFOUND_ZH))
        b = simhash64(extract_text(
            "<html><body><h1>系统维护中</h1><p>我们正在升级，稍后再试。</p></body></html>"
        ))
        self.assertNotEqual(a, 0, "中文正文算出常数指纹 —— 分词没覆盖中文")
        self.assertNotEqual(a, b, "两段完全不同的中文正文指纹相同")
        self.assertGreater(hamming_distance(a, b), SIMHASH_MAX_DISTANCE,
                           "中文指纹过于相似，区分度不够")

    def test_hash_is_stable_across_calls(self) -> None:
        """FNV-1a 必须稳定 —— 指纹要能跨扫描比对、能落库。"""
        text = extract_text(self.NOTFOUND_ZH)
        self.assertEqual(simhash64(text), simhash64(text))
        # 换个进程（哈希随机盐）也必须一样
        import subprocess
        import sys
        out = subprocess.run(
            [sys.executable, "-c",
             "import sys;sys.path.insert(0,'.');"
             "from core.domains.web_search._lib.soft404 import simhash64,extract_text;"
             f"print(simhash64(extract_text({self.NOTFOUND_ZH!r})))"],
            capture_output=True, text=True, cwd=str(Path(__file__).resolve().parents[1]),
        )
        self.assertEqual(out.stdout.strip().splitlines()[-1],
                         str(simhash64(extract_text(self.NOTFOUND_ZH))),
                         "跨进程指纹不一致 —— 哈希不稳定")

    # ------------------------------------------------------------------ 放行
    def test_json_response_is_not_soft_404(self) -> None:
        """API 站点的 404 往往是 JSON，不能当软 404 丢掉。"""
        self.assertIsNone(looks_like_soft_404('{"error":"not found","code":404}'))
        self.assertIsNone(looks_like_soft_404('<?xml version="1.0"?><e/>'))

    def test_long_body_with_one_marker_is_not_soft_404(self) -> None:
        """只命中 1 个词且正文很长 → 多半是真内容。"""
        long_zh = "页面不存在" + "正文内容。" * 800
        self.assertIsNone(looks_like_soft_404(long_zh, size=len(long_zh)))

    # ------------------------------------------------------------------ auth-wall
    def test_auth_wall_is_not_noise(self) -> None:
        """敏感路径回登录页是**暴露面**，不是噪声 —— 不能丢。

        ⚠️ 登录页的**长度必须和 404 基线一样**：否则大小层本来就判它不是噪声，
        这条用例压根走不到 auth-wall 判断，测了个寂寞。
        """
        filler = "<p>占位</p>" * 200
        login = f"<html><body><h2>用户登录</h2>{filler}<form>请输入密码</form></body></html>"
        login = login + "x" * max(0, 4096 - len(login))       # 对齐基线长度
        prof = self._profile([self._p("abcd", 404, 4096, self.NOTFOUND_ZH)])
        self.assertEqual(len(login), 4096, "登录页长度没对齐，测不到 auth-wall 分支")
        self.assertTrue(prof.is_noise(status=404, size=0, words=1,
                                      token_len=4, text="") is False,
                        "空正文当然不是噪声（对照）")
        self.assertFalse(
            prof.is_noise(status=404, size=len(login),
                          words=len(login.split()), token_len=4, text=login),
            "登录页被判成软 404 丢掉了 —— 那是一条真实的暴露面",
        )
        self.assertTrue(prof.is_auth_wall(login))

    def test_english_auth_wall_too(self) -> None:
        login = "<html><body>Please sign in to continue</body></html>"
        self.assertTrue(looks_like_auth_wall(login))

    def test_normal_admin_page_is_not_an_auth_wall(self) -> None:
        real = "<html><body><h1>控制台</h1><p>共 12 个项目</p></body></html>"
        self.assertFalse(looks_like_auth_wall(real))

    # ------------------------------------------------------------------ 三层
    def test_simhash_rescues_when_size_jitters(self) -> None:
        """**核心用例**：软 404 页带 nonce/时间戳，每次大小差上百字节。

        这时**连基线都立不起来**（两次校准探测的大小就超了容差），旧实现
        会直接判"画像不可用"然后放行全部 —— 几百条假命中就是这么来的。
        现在改成：大小立不起来时，用**基线之间的指纹是否一致**来决定。
        """
        filler = "这是用来把错误页撑到真实体量的正文内容。" * 200

        def with_nonce(n: int) -> str:
            # nonce 长度必须差**超过容差（8 字节）**
            return (self.NOTFOUND_ZH.replace("</body>",
                                             f'{filler}<!-- {"t" * (n * 120)} --></body>'))

        prof = self._profile([
            self._p("a1b2", 404, len(with_nonce(1)), with_nonce(1)),
            self._p("c3d4e5f6", 404, len(with_nonce(2)), with_nonce(2)),
        ])
        self.assertTrue(prof.usable, "指纹一致的模板页被判成画像不可用")
        self.assertEqual(prof.mode, "simhash")
        cand = with_nonce(3)
        self.assertTrue(
            prof.is_noise(status=404, size=len(cand), words=len(cand.split()),
                          token_len=4, text=cand),
            "大小抖动上百字节的软 404 没被拦住",
        )

    def test_jittering_body_with_differing_skeleton_is_unusable(self) -> None:
        """大小在抖**且骨架也不一样** → 真的没法判，必须明说不可用。"""
        prof = self._profile([
            self._p("a1b2", 404, 3000, "完全不同的第一页内容" * 50),
            self._p("c3d4", 404, 3900, "另外一整套完全不同的内容" * 50),
        ])
        self.assertFalse(prof.usable)
        self.assertIn("每次都不同", prof.reason)

    def test_templates_differing_by_a_bit_still_count_as_one(self) -> None:
        """两条基线指纹差 1~2 位，**仍然是同一个模板页**。

        SimHash 是相似度度量。正文里塞个随机词 / 时间戳，指纹就会差几位 ——
        实测 djangoproject.com 的 404 页用随机词生成正文，抹掉回显的 token
        后指纹距离是 0~1 位。写成"指纹必须逐位相等"会直接判成画像不可用，
        几百条假命中照旧漏网。

        ⚠️ 正文必须够长（几百 token）—— 短文本的 SimHash 本来就不稳，
        20 个 token 改 2 个就能翻 12 位（见
        ``test_short_body_refuses_to_use_fingerprint``）。
        """
        filler = "这是一段用来撑长度的正文内容，用来模拟真实错误页那种体量。" * 200

        def page(tok: str, noise: str) -> str:
            return ("<html><body><h1>页面不存在</h1><p>路径 " + tok
                    + " 没有对应的内容</p><div>" + filler
                    + noise + "</div></body></html>")

        a, b = "QWER", "ASDFGH"
        fa = simhash64(extract_text(mask_token(page(a, "taymon a. beal"), a)))
        fb = simhash64(extract_text(mask_token(page(b, "filehorse"), b)))
        self.assertLessEqual(hamming_distance(fa, fb), SIMHASH_MAX_DISTANCE,
                             "这两条应当被认成同一个模板")

        prof = self._profile([
            self._p(a, 404, len(page(a, "taymon a. beal")),
                    page(a, "taymon a. beal")),
            self._p(b, 404, len(page(b, "xx")), page(b, "xx")),
        ])
        self.assertTrue(prof.usable, "差 1 位的模板被误判成不可用")
        self.assertEqual(prof.mode, "simhash")

    def test_short_body_refuses_to_use_fingerprint(self) -> None:
        """**太短的正文不许拿指纹建基线。**

        20 个 token 的正文，改 2 个词就能翻 12 位 —— 拿这种不稳的指纹判噪声
        会把软 404 放过去，制造**漏判**。宁可判不可用（明说）也不能猜。

        ⚠️ 两个页面的**大小也必须拉开**：大小恒定时第 ② 层就判了，压根不会
        走到指纹那道门槛，这条用例就测不到它。
        也不能用中文凑长度 —— 中文按二元组分词，同样几个字能出上百个
        token，那就不是"短正文"了。
        """
        def page(tok: str) -> str:
            return ("<html><body>missing " + tok + " "
                    + "x" * (len(tok) * 40) + "</body></html>")

        a = self._p("QWER", 404, len(page("QWER")), page("QWER"))
        b = self._p("ASDFGH", 404, len(page("ASDFGH")), page("ASDFGH"))
        self.assertLess(a.tokens, SIMHASH_MIN_TOKENS,
                        "这条用例的正文本来就该短到不够用指纹建基线")
        self.assertGreater(abs(a.size - b.size), 8, "大小没拉开，测不到指纹门槛")
        prof = self._profile([a, b])
        self.assertFalse(prof.usable, "短正文被拿去建指纹基线了")

    def test_echoed_path_is_masked_before_fingerprinting(self) -> None:
        """回显型：抹掉 token 之后指纹才对得上。

        djangoproject.com 的 404 页把请求路径原样打回正文，不抹的话
        每条探测的指纹都不同，基线永远建不起来。
        """
        def page(tok: str) -> str:
            return f"<html><body>您访问的路径 {tok} 不存在</body></html>"

        a, b = "QWER", "ASDFGH"
        raw_a = simhash64(extract_text(page(a)))
        raw_b = simhash64(extract_text(page(b)))
        masked_a = simhash64(extract_text(mask_token(page(a), a)))
        masked_b = simhash64(extract_text(mask_token(page(b), b)))
        self.assertEqual(masked_a, masked_b, "掩码后两个不同 token 的指纹仍不同")
        self.assertNotEqual(raw_a, raw_b,
                            "不掩码时指纹本就该不同（这正是要治的病）")

    def test_simhash_does_not_swallow_a_real_hit(self) -> None:
        """真命中与基线骨架不同 → 即便大小凑巧接近也不算噪声。"""
        prof = self._profile([self._p("a1b2", 404, 4096, self.NOTFOUND_ZH)])
        real = "<html><body>" + "<p>配置文件内容</p>" * 300 + "</body></html>"
        self.assertFalse(
            prof.is_noise(status=404, size=len(real), words=len(real.split()),
                          token_len=4, text=real),
            "真命中被 SimHash 误杀了",
        )

    def test_5xx_is_never_noise(self) -> None:
        prof = self._profile([self._p("a1b2", 404, 4096, self.NOTFOUND_ZH)])
        self.assertFalse(prof.is_noise(status=502, size=798, words=80, token_len=4))

    # ------------------------------------------------------------------ 同目录基线
    def test_dir_baseline_overrides_the_root_one(self) -> None:
        """目录专属基线优先于根目录基线。

        有些站点 ``/static/xxx`` 的 404 和 ``/xxx`` 的 404 长得不一样，
        拿根目录的基线去比会失准（pathprobe 的 ``invalidSibling``）。
        """
        # ⚠️ 静态页的正文**不能**含 "资源不存在" 这类关键词 ——
        # 关键词层比大小层先跑，那样就变成"关键词层把它判掉了"，
        # 压根测不到同目录基线。要测的就是**大小层**的分目录差异。
        static_404 = "<html><body>该目录下没有你要的东西</body></html>"
        prof = self._profile([self._p("a1b2", 404, 4096, self.NOTFOUND_ZH)])
        prof.add_baseline("static/", self._p("q1w2e3r4", 404, len(static_404),
                                             static_404))
        # 根目录基线的形态：不是噪声
        self.assertFalse(prof.is_noise(
            status=404, size=len(static_404), words=len(static_404.split()),
            token_len=4, text=static_404, directory="",
        ))
        # 同目录基线的形态：是噪声
        self.assertTrue(prof.is_noise(
            status=404, size=len(static_404), words=len(static_404.split()),
            token_len=4, text=static_404, directory="static/",
        ))


class TestAuthStatusAndBypass(EngineTestCase):
    """401/403 的记账、命中，以及绕过尝试。

    三件事分开测，因为它们是三个独立缺陷：
    ① 401/403 以前**不算命中**（`return` 掉了）—— 路径存在却一条不报
    ② 401 以前**完全不计数**、不参与熔断
    ③ 绕过：只对确实被挡的路径打，且要有「真的绕过了」的判据
    """

    HOST = "http://fuzz.example.com"

    @staticmethod
    def _resp(url, status, size, *, text="", headers=None):
        from core.services.http import FetchResult

        return FetchResult(
            url=url, status=status, text=text or "x" * size,
            headers=headers if headers is not None else {},
        )

    async def _scan(self, responder, *, emit=("emit_url", EMIT_URL), **cfg):
        from core.services.http import HTTPClient

        self.add_module_file(*emit)
        wl = Path(__file__).resolve().parents[1] / ".testtmp" / "dir_auth.txt"
        wl.parent.mkdir(parents=True, exist_ok=True)
        wl.write_text("admin\np000\np001\nprivate\np002\np003\n", encoding="utf-8")
        module_cfg = {
            "wordlist": str(wl), "probes": 2, "concurrency": 1, "delay": 0,
            "max_paths": 0, "zero_hit_abort": 0,
        }
        module_cfg.update(cfg)

        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url, kwargs.get("headers") or {})
            return go()

        with mock.patch.object(HTTPClient, "fetch", fake_fetch):
            return await self.run_scan(
                targets=["example.com"],
                include=[emit[0], "dir_brute"],
                module_config={
                    "dir_brute": module_cfg,
                    # 夹具是 http:// 的，探活默认 prefer_https 会拼成
                    # https://host:80 —— URL 形状对不上，画像也就对不上
                    "http_probe": {"prefer_https": False, "schemes": ["http"]},
                },
            )

    async def _urls(self, scan_id: int) -> set[str]:
        events = await self.storage.events(scan_id, limit=500, event_type="URL")
        return {e["data"] for e in events if e["module"] == "dir_brute"}

    # ------------------------------------------------------------------ ①
    async def test_403_is_recorded_as_a_hit(self) -> None:
        """`/admin` 回 403 = **路径存在、只是要认证**。必须落进资产库。"""

        def responder(url, _h):
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder)
        self.assertIn(f"{self.HOST}/admin", await self._urls(scanner.scan_id),
                      "403 路径没被记成命中 —— 最有价值的结论被扔了")

    async def test_401_is_recorded_as_a_hit(self) -> None:
        def responder(url, _h):
            if url.endswith("/private"):
                return self._resp(url, 401, 120)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder)
        self.assertIn(f"{self.HOST}/private", await self._urls(scanner.scan_id))


    async def test_auth_wall_observations_land_in_the_shared_profile(self) -> None:
        """认证墙的两侧观察都要写进共享画像的 ``auth_hits`` / ``auth_wall``。

        ⚠️ 2026-10-03：这两格原先由一个独立的 ``auth_probe`` 模块填。它监听全
        流水线的 ``HTTP_RESPONSE``，但**写完没人读** —— 认证墙是「爆破时顺带
        观察到的东西」，跟着爆破走视野反而更准（只记真正发出过的请求）。所以
        模块删了，结论改由 ``dir_brute`` 顺带写。

        **状态码侧**（401/403）与**正文侧**（200 + 登录页）分开记：前者说明
        「这台会挡你」，后者说明「这台有登录面」，两者能同时成立，也能各自成立。
        """
        login = ("<html><body><h2>用户登录</h2>"
                 + "<p>占位</p>" * 200
                 + "<form>请输入密码</form></body></html>")

        def responder(url, _h):
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            if url.endswith("/private"):
                return self._resp(url, 200, len(login), text=login)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, forbidden_min=999)

        web = scanner.state.web_profile_for(self.HOST)
        self.assertEqual(web.auth_hits, 1, "401/403 没有记进画像")
        self.assertTrue(web.auth_wall, "登录页正文没有记进画像")

    async def test_a_clean_host_leaves_the_auth_fields_alone(self) -> None:
        """对照组：没有认证墙时两个字段必须保持空 —— 不能无脑置位。"""

        def responder(url, _h):
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder)
        web = scanner.state.web_profile_for(self.HOST)
        self.assertEqual(web.auth_hits, 0)
        self.assertFalse(web.auth_wall)

    # ------------------------------------------------------------------ ②
    async def test_401_is_counted_for_the_breaker(self) -> None:
        """大面积 401 和大面积 403 一样说明被挡了，都该熔断。"""

        def responder(url, _h):
            return self._resp(url, 401, 120)

        scanner, _ = await self._scan(responder, forbidden_min=3,
                                      forbidden_ratio=0.9)
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "被拦截" in str(f.get("kind") or "")]
        self.assertTrue(rows, "大面积 401 没有触发熔断")

    async def test_exclude_status_can_drop_403_from_hits(self) -> None:
        """``exclude_status: "403"`` → 403 不再算命中（但仍参与熔断统计）。"""

        def responder(url, _h):
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, exclude_status="403",
                                      bypass_401_403=False)
        self.assertNotIn(f"{self.HOST}/admin", await self._urls(scanner.scan_id),
                         "exclude_status 里写了 403 却仍被记成命中")

    async def test_include_status_allows_ranges(self) -> None:
        """``include_status: "200,301-303"`` 这种区间写法要认。"""

        def responder(url, _h):
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            if url.endswith("/private"):
                return self._resp(url, 302, 30)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, include_status="200,301-303",
                                      bypass_401_403=False)
        urls = await self._urls(scanner.scan_id)
        self.assertIn(f"{self.HOST}/private", urls, "302 在 301-303 区间里，该算命中")
        self.assertNotIn(f"{self.HOST}/admin", urls, "403 不在白名单里")

    async def test_uniformly_blocked_host_gives_up_early(self) -> None:
        """敏感路径成片回 403 → 试够 ``bypass_giveup`` 条就熔断。

        这是流量控制的关键：403 一片时逐条试下去最坏要 5 路径 × 16 = 80 个
        请求，而那只是给对面送流量。

        ⚠️ 场景必须是「基线 404、敏感路径 403」：如果**整站**都回 403，
        那基线也是 403，所有路径都会先被软 404 判成噪声，压根到不了
        绕过那步 —— 那不是绕过的问题，是「这台机器什么都没暴露」。
        """
        seen: list[tuple[str, tuple]] = []
        blocked = {"admin", "private", "p000", "p001", "p002", "p003"}

        def responder(url, headers):
            seen.append((url, tuple(sorted(headers.items()))))
            leaf = url[len(self.HOST) + 1:] if url.startswith(self.HOST + "/") else ""
            if leaf.split(";")[0].split("/")[0] in blocked and "?" not in leaf:
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(
            responder, bypass_401_403=True, bypass_giveup=2,
            bypass_patience=2, bypass_max_per_path=8, forbidden_min=999,
        )
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "整站被访问控制挡住" in str(f.get("kind") or "")]
        self.assertTrue(rows, "敏感路径成片 403 却没有熔断")
        # 每条路径：耐心 2 个路径变体 + 8 个 header = 10；2 条路径就熔断 = 20
        bypass_reqs = sum(1 for _, h in seen if h) + sum(
            1 for u, h in seen
            if not h and any(v in u for v in
                             ("//admin", "/./admin", "admin;", "admin..;/"))
        )
        self.assertLessEqual(
            bypass_reqs, 26,
            f"熔断前烧了 {bypass_reqs} 个绕过请求（预期 ≤26）",
        )

    async def test_a_single_real_bypass_does_not_trip_the_breaker(self) -> None:
        """真绕过了 → 不该熔断，后面还有路径要试。"""
        seen: list[tuple[str, tuple]] = []

        def responder(url, headers):
            seen.append((url, tuple(sorted(headers.items()))))
            leaf = url[len(self.HOST) + 1:] if url.startswith(self.HOST + "/") else ""
            if leaf.rstrip("/") == "private;" and not leaf.endswith("/"):
                return self._resp(url, 200, 4321, text="SECRET")
            if leaf.split(";")[0].rstrip("/") in {"admin", "private"}:
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, bypass_401_403=True,
                                      bypass_giveup=2, forbidden_min=999)
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "整站被访问控制挡住" in str(f.get("kind") or "")]
        self.assertEqual(rows, [], "真绕过了一处却熔断，把后面的路径都丢了")

    async def test_breaker_and_hit_are_decoupled(self) -> None:
        """熔断停了之后，已经确认存在的路径**仍然要报出来**。"""

        def responder(url, _h):
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 403, 300)

        scanner, _ = await self._scan(responder, forbidden_min=3,
                                      forbidden_ratio=0.9, bypass_401_403=False)
        self.assertIn(f"{self.HOST}/admin", await self._urls(scanner.scan_id),
                      "熔断把已确认的暴露面一起吞了")

    # ------------------------------------------------------------------ ③
    async def test_no_bypass_attempt_on_404(self) -> None:
        """404 路径不该收到任何变体请求 —— 那纯属浪费。

        必须按 ``(URL, 请求头)`` 记：header 注入变体用的 URL 与原路径**相同**，
        只看 URL 会把 8 个不同的 header 注入看成同一条。
        """
        seen: list[tuple[str, tuple]] = []
        dict_paths = {f"{self.HOST}/{p}" for p in
                      ("admin", "p000", "p001", "private", "p002", "p003")}

        def responder(url, headers):
            seen.append((url, tuple(sorted(headers.items()))))
            return self._resp(url, 404, 111)

        await self._scan(responder, bypass_401_403=True)
        # 前 2 条是软 404 校准（probes=2，顺序确定），随机 token 没法预先枚举
        calib = {u for u, _ in seen[:2]}
        skip = dict_paths | {f"{self.HOST}/"} | calib
        root_q = f"{self.HOST}/?"
        variants = [u for u, h in seen
                    if not u.startswith(root_q) and (u not in skip or h)]
        self.assertEqual(
            variants, [],
            f"404 路径也发了绕过变体: {variants}",
        )

    async def test_path_variant_bypass_is_reported(self) -> None:
        """`/admin` 回 403，但 `/admin;` 放行 → 报「访问控制疑似可绕过」。

        ``;`` 是 Tomcat / Spring 的路径参数，最经典的 403 绕过手法之一。
        """
        seen: list[str] = []

        def responder(url, _h):
            seen.append(url)
            if url.endswith("/admin;") and url != f"{self.HOST}/admin":
                return self._resp(url, 200, 4321, text="SECRET")
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, bypass_401_403=True)
        self.assertIn(f"{self.HOST}/admin;", seen, "没试 Tomcat 的 ; 路径参数变体")
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "可绕过" in str(f.get("kind") or "")]
        self.assertTrue(rows, "绕过了却没报出来")
        self.assertIn("路径改成", str(rows[0]["detail"]))

    async def test_header_bypass_is_reported(self) -> None:
        """`X-Original-URL` 注入放行 → 同样报出来。"""

        def responder(url, headers):
            if url.endswith("/admin") and headers.get("X-Original-URL"):
                return self._resp(url, 200, 4321, text="SECRET")
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, bypass_401_403=True)
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "可绕过" in str(f.get("kind") or "")]
        self.assertTrue(rows, "header 注入绕过了却没报")
        self.assertIn("X-Original-URL", str(rows[0]["detail"]))

    async def test_identical_response_is_not_a_bypass(self) -> None:
        """变体回的还是同一个拦截页 → **不算绕过**，别报噪声。"""

        def responder(url, _h):
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, bypass_401_403=True)
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "可绕过" in str(f.get("kind") or "")]
        self.assertEqual(rows, [], "一模一样的响应被当成了绕过")

    async def test_bypass_can_be_turned_off(self) -> None:
        seen: list[str] = []

        def responder(url, _h):
            seen.append(url)
            if url.endswith("/admin;/"):
                return self._resp(url, 200, 4321, text="SECRET")
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        scanner, _ = await self._scan(responder, bypass_401_403=False)
        self.assertFalse(any("/admin;/" in u for u in seen), "关掉后仍在试变体")
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "可绕过" in str(f.get("kind") or "")]
        self.assertEqual(rows, [])

    async def test_bypass_paths_per_host_is_capped(self) -> None:
        """站点 403 一片时，不能每条路径都试绕过 —— 流量会翻好几倍。

        字典里 6 条路径全回 403，但 ``bypass_max_paths=1`` 意味着只有第一条
        能试变体，所以变体请求数应当 ≤ 1 条路径 × 3 档。
        """
        seen: list[tuple[str, tuple]] = []
        dict_paths = {f"{self.HOST}/{p}" for p in
                      ("admin", "p000", "p001", "private", "p002", "p003")}

        def responder(url, headers):
            seen.append((url, tuple(sorted(headers.items()))))
            return self._resp(url, 403, 552)

        await self._scan(responder, bypass_401_403=True, bypass_max_paths=1,
                         bypass_max_per_path=3, forbidden_ratio=1.0,
                         forbidden_min=999)
        # 前 2 条是软 404 校准（probes=2，顺序确定）；全站 403 还会触发
        # WAF 主动探测（根路径上的 `?载荷`）—— 那些也不是"绕过变体"。
        calib = {u for u, _ in seen[:2]}
        skip = dict_paths | {f"{self.HOST}/"} | calib
        root_q = f"{self.HOST}/?"
        variants = [u for u, h in seen
                    if not u.startswith(root_q) and (u not in skip or h)]
        self.assertLessEqual(
            len(variants), 3,
            f"上限 1 条路径 × 3 档 = 最多 3 个变体，实际 {len(variants)}: {variants}",
        )

    # ------------------------------------------------------------------ ④
    # 遇到 WAF 就放弃绕过。判据在 ``dir_brute._find_waf``（2026-10-03 搬回来），
    # 这里验的是**信号真的从共享画像传到 ``_try_bypass``**。
    async def test_bypass_is_skipped_when_the_host_shows_a_waf_signal(self) -> None:
        """画像里有 WAF 信号 → 403 路径**一个变体都不试**。

        判据在 ``dir_brute._find_waf``（2026-10-03 又搬回来了：WAF 判断必须
        内联在发请求的那一步，独立模块只能事后报 finding、拦不住已发出的
        请求）。这里验的是**信号真的从共享画像传到 ``_try_bypass``**。

        停手的是**绕过**，不是暴露面本身 —— 403 路径照样要报出来。
        """
        seen: list[tuple[str, tuple]] = []

        def responder(url, headers):
            seen.append((url, tuple(sorted(headers.items()))))
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        with self._shared_waf("FakeWAF"):
            scanner, _ = await self._scan(responder, bypass_401_403=True,
                                          forbidden_min=999)

        dict_paths = {f"{self.HOST}/{p}" for p in
                      ("admin", "p000", "p001", "private", "p002", "p003")}
        calib = {u for u, _ in seen[:2]}
        variants = [u for u, h in seen
                    if (u not in dict_paths | calib | {f"{self.HOST}/"}) or h]
        self.assertEqual(variants, [],
                         f"有 WAF 信号却还在发绕过请求: {variants}")
        self.assertIn(f"{self.HOST}/admin", await self._urls(scanner.scan_id),
                      "因为有 WAF 就把已确认存在的路径也丢了")

    async def test_a_low_confidence_waf_signal_also_stops_the_bypass(self) -> None:
        """置信度不够高**只影响报不报**，不影响还要不要打。

        两条线必须分开（理由见 ``_try_bypass`` 的文档）：``waf_min_confidence``
        调到 ``high`` 时，medium 命中**不该**写进结论、**不该**放弃整台爆破 ——
        但只要有一丁点迹象，绕过变体就一个都不该试。

        ⚠️ 这条钉的是 ``_find_waf`` 把结论写进了**共享画像的 ``web.waf``**。
        它曾经写进一个模块私有的字典，而那个字典**没人读** —— 于是这条规矩
        在生产里是断的，medium 信号照发绕过请求。上面那条用例的桩
        （``_shared_waf`` 直接设 ``web.waf``）恰好把这个洞盖住了，所以
        **光靠它发现不了**。这条不桩画像，走真实识别路径。
        """
        seen: list[tuple[str, tuple]] = []
        waf_headers = {"x-hwwaf": "1"}          # 华为云 WAF，medium 置信度

        def responder(url, headers):
            seen.append((url, tuple(sorted(headers.items()))))
            if url.endswith("/admin"):
                return self._resp(url, 403, 552, headers=waf_headers)
            return self._resp(url, 404, 111, headers=waf_headers)

        scanner, _ = await self._scan(responder, bypass_401_403=True,
                                      forbidden_min=999,
                                      waf_min_confidence="high",
                                      waf_probe=False)

        dict_paths = {f"{self.HOST}/{p}" for p in
                      ("admin", "p000", "p001", "private", "p002", "p003")}
        calib = {u for u, _ in seen[:2]}
        variants = [u for u, h in seen
                    if (u not in dict_paths | calib | {f"{self.HOST}/"}) or h]
        self.assertEqual(variants, [],
                         f"低置信度 WAF 信号压不住绕过: {variants}")
        # 「报不报」是另一条线：medium 不够格写进结论，就不该报出去
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "WAF" in str(f.get("kind") or "")]
        self.assertEqual(rows, [], "medium 信号被当成了结论报出去")
        self.assertIn(f"{self.HOST}/admin", await self._urls(scanner.scan_id),
                      "因为信号不够硬就把已确认存在的路径也丢了")

    async def test_waf_signal_on_one_host_does_not_silence_another(self) -> None:
        """WAF 信号必须**按 origin**记 —— 不能一台有信号就全都不绕。

        这条钉的是数据结构：画像存在 ``ScannerState.web_profile[origin]``，
        按 origin 取而不是"看有没有任何一台有"。
        """
        seen: list[str] = []

        def responder(url, _headers):
            seen.append(url)
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            if "clean.example.com" in url and url.endswith("/admin;"):
                return self._resp(url, 200, 4321, text="SECRET")
            return self._resp(url, 404, 111)

        with self._shared_waf("FakeWAF", only_for="http://wafhost.example.com"):
            # 必须真的有两台主机，所以用双主机夹具：
            # 假的 WAF 只记在 wafhost 上，不能把干净的 clean 一起压掉
            await self._scan(responder, emit=("emit_urls_two", EMIT_URL_TWO_HOSTS),
                             bypass_401_403=True,
                             forbidden_min=999, tech_dicts=False)

        clean = [u for u in seen if "clean.example.com" in u]
        self.assertTrue(clean, "干净那台一个请求都没发")

    async def test_bypass_still_runs_when_no_waf_signal(self) -> None:
        """对照组：**没有 WAF 信号**时压制不能误伤。

        上面两条合起来才说明压制是"有信号才生效"，而不是"绕过功能坏了"。
        """
        seen: list[str] = []

        def responder(url, _h):
            seen.append(url)
            if url.endswith("/admin;") and url != f"{self.HOST}/admin":
                return self._resp(url, 200, 4321, text="SECRET")
            if url.endswith("/admin"):
                return self._resp(url, 403, 552)
            return self._resp(url, 404, 111)

        with self._shared_waf(""):        # 空 = 没认出 WAF
            scanner, _ = await self._scan(responder, bypass_401_403=True,
                                          forbidden_min=999)

        self.assertIn(f"{self.HOST}/admin;", seen, "没有 WAF 信号却也没试绕过")
        rows = [f for f in await self.storage.findings(scanner.scan_id)
                if "可绕过" in str(f.get("kind") or "")]
        self.assertTrue(rows, "没 WAF 信号时绕过了却没报")

    @staticmethod
    def _shared_waf(name: str, only_for: str = ""):
        """在 ``ScannerState`` 的共享画像里预置 WAF 结论。

        桩的是**共享容器**而不是 ``detect_waf`` —— WAF 识别已经内联进
        ``dir_brute`` / ``js_assets``（独立模块拦不住已发出的请求），
        这里要验的是**信号有没有从画像传到绕过那一步**。

        ``only_for`` 模拟"只有某台主机有 WAF"；留空则对所有 origin 生效。
        """
        from core.domains.web_search._lib.soft404 import Probe, SoftProfile
        from core.domains.web_search.soft404_probe import origin_of
        from core.engine.state import ScannerState

        real = ScannerState.web_profile_for

        def patched(self, origin):
            web = real(self, origin)
            if not only_for or origin == only_for:
                web.waf = name
            # ⚠️ 画像必须**可用**：``samples == 0`` 会被闸门一之二判成
            # 「完全无响应」，主机在到达绕过那步之前就被整体跳过了。
            if web.soft404 is None:
                web.soft404 = SoftProfile.build([
                    Probe.of(t, 404, 111, 10, "x" * 111)
                    for t in ("a1", "b2", "c3")
                ])
            return web

        return mock.patch.object(ScannerState, "web_profile_for", patched)


class TestBypassHelpers(unittest.TestCase):
    """``_lib/bypass.py`` 的纯函数。"""

    def test_path_variants_are_unique_and_bounded(self) -> None:
        from core.domains.web_search._lib.bypass import path_variants

        vs = path_variants("admin", 5)
        self.assertEqual(len(vs), 5)
        self.assertEqual(len(set(vs)), 5, "变体里有重复")
        self.assertNotIn("admin", vs, "原路径不该出现在变体里")

    def test_path_variants_keep_the_original_path(self) -> None:
        """变体必须都还是**同一个资源**的不同写法。"""
        from core.domains.web_search._lib.bypass import path_variants

        for v in path_variants("admin/config.php", 20):
            self.assertIn("config.php", v, v)

    def test_is_bypass_on_status_change(self) -> None:
        from core.domains.web_search._lib.bypass import is_bypass

        self.assertTrue(is_bypass((403, 552), (200, 552)),
                        "403 → 200 就算拿到了内容，长度一样也算数")

    def test_403_to_404_is_not_a_bypass(self) -> None:
        """**403 → 404 绝不是绕过。**

        状态码确实变了，但 404 恰恰是「没找到」—— 基线 403 的路径，
        换个写法变成「不存在」，什么都没拿到。判据只按「状态码变了」算的话，
        每个变体都会报一条假绕过。
        """
        from core.domains.web_search._lib.bypass import is_bypass

        self.assertFalse(is_bypass((403, 552), (404, 111)))
        self.assertFalse(is_bypass((403, 552), (500, 0)), "5xx 更不是放行")
        self.assertTrue(is_bypass((403, 552), (301, 0)), "3xx 跳转也是拿到东西了")

    def test_is_bypass_needs_a_real_delta(self) -> None:
        from core.domains.web_search._lib.bypass import is_bypass

        self.assertFalse(is_bypass((403, 552), (403, 560)),
                         "长度差 1.5% 不算信号")
        self.assertTrue(is_bypass((403, 552), (403, 900)),
                        "长度差 63% 算信号")


if __name__ == "__main__":
    unittest.main()
