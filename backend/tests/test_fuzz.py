"""目录爆破域的测试。

两层：
  1. ``_lib/soft404.py`` 的画像构建与判定 —— 纯函数，三种基线形态一条条钉死
  2. ``dir_brute`` 模块 —— 走引擎，验证画像生效、403 熔断、预算

全部离线。
"""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from core.domains.fuzz._lib.soft404 import (
    PROBE_LENGTHS,
    Probe,
    SoftProfile,
    random_token,
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


class TestDirBrute(EngineTestCase):
    """走引擎：画像 → 爆破 → 熔断。"""

    def _fake_fetch(self, responder):
        def fake_fetch(client, url, **kwargs):  # noqa: ANN001
            async def go():
                return responder(url)
            return go()

        return fake_fetch

    @staticmethod
    def _resp(url: str, status: int, size: int):
        from core.services.http import FetchResult

        return FetchResult(url=url, status=status, text="x" * size, headers={})

    async def _scan(self, responder, max_paths: int = 20, **cfg):
        from core.services.http import HTTPClient

        self.add_module_file("emit_url", EMIT_URL)
        # 用自己的小字典：内置那份有 241 条，配合 max_paths 会把
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
                targets=["example.com", "fuzz.example.com"],
                include=["emit_url", "dir_brute"],
                module_config={"dir_brute": module_cfg},
                settings={"forbidden_domains": []},
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

    def test_invasive_is_denied_by_default(self) -> None:
        # dir_brute 带 invasive，default 预设 deny_flags 里有它
        self.assertNotIn("dir_brute", self._names("default"))

    def test_passive_does_not_include_it(self) -> None:
        # passive 预设 require_flags=[passive]，它是 active，自然进不来
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


if __name__ == "__main__":
    unittest.main()
