"""M3 测试: 泛解析探测 / 字典爆破 / 域名置换 / CDN 与富化。

全部离线 —— DNS 查询与 HTTP 都通过打桩模拟, 不触碰真实网络。
重点验证四件事:
  1. DnsGen 的 5 种置换策略与上限
  2. 泛解析画像的构建, 以及**被过滤的数量必须留痕**（这是与 ARL 最大的分歧点）
  3. 爆破/置换会正确等待泛解析闸门, 且置换结果不会被反复置换
  4. 富化事件不会死循环, 但能把 IP 资产补全
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import unittest
from pathlib import Path
from unittest import mock

from core.domains.subdomain._lib.dnsgen import DnsGen
from core.services.http import HTTPClient
from core.domains.resolve._lib.resolver import AsyncResolverPool
from core.util.cdn import get_matcher

from .base import EngineTestCase

WILDCARD_IP = "10.0.0.9"
REAL_IP = "1.2.3.4"
MIXED_IP = "1.2.3.5"

# 用 paths.resources_dir()，而不是自己数 parents —— 目录一调整就会指错
# （模块按功能域分组那次，就是这种写法静默失效的）
from core.util.paths import resources_dir  # noqa: E402

CDN_DATA_PATH = resources_dir() / "cdn_info.json"


def load_cdn_entries() -> list[dict]:
    return json.loads(CDN_DATA_PATH.read_text(encoding="utf-8"))


# --------------------------------------------------------------------- DnsGen

class TestDnsGen(unittest.TestCase):
    def test_parts_of_splits_labels_and_keeps_base(self) -> None:
        gen = DnsGen([], ["dev"], "example.com")
        self.assertEqual(gen.parts_of("a.b.example.com"), ["a", "b", "example.com"])
        self.assertEqual(gen.parts_of("example.com"), ["example.com"])
        # 不属于 base 的域名直接返回空, 不瞎切
        self.assertEqual(gen.parts_of("a.other.com"), [])

    def test_multi_level_suffix_is_not_split_wrongly(self) -> None:
        """根域名由外部传入, 所以 co.uk 这种多级后缀不会被切错（ARL 要靠 tld 库猜）。"""
        gen = DnsGen([], ["dev"], "example.co.uk")
        self.assertEqual(gen.parts_of("api.example.co.uk"), ["api", "example.co.uk"])

    def test_five_strategies_all_produce(self) -> None:
        gen = DnsGen([], ["dev", "staging"], "example.com", max_per_domain=0)
        out = set(gen.permutations_of("www.example.com"))

        self.assertIn("dev.www.example.com", out)        # insert word
        self.assertIn("www1.example.com", out)           # insert num
        self.assertIn("devwww.example.com", out)         # prepend
        self.assertIn("dev-www.example.com", out)        # prepend with dash
        self.assertIn("wwwdev.example.com", out)         # append
        self.assertIn("www-dev.example.com", out)        # append with dash
        # replace_word_with_word 只处理长度 > 3 的词, "dev"/"staging" -> staging 会替换 dev
        self.assertIn("staging.www.example.com", out)
        # 自身与非本域不应出现
        self.assertNotIn("www.example.com", out)

    def test_max_per_domain_caps_output(self) -> None:
        gen = DnsGen([], ["dev", "test", "beta"], "example.com", max_per_domain=5)
        self.assertEqual(len(gen.permutations_of("www.example.com")), 5)

    def test_root_domain_has_no_permutation(self) -> None:
        gen = DnsGen([], ["dev"], "example.com")
        self.assertEqual(gen.permutations_of("example.com"), [])


# --------------------------------------------------------------------- 泛解析画像

class TestWildcardProfile(unittest.TestCase):
    def test_describe_and_match(self) -> None:
        from core.engine.state import WildcardProfile

        profile = WildcardProfile(root="example.com", wildcard=True, probes=5, resolved=5)
        profile.ips.add(WILDCARD_IP)
        profile.cnames.add("wild.example.net")

        self.assertTrue(profile.matches_ip(WILDCARD_IP))
        self.assertFalse(profile.matches_ip(REAL_IP))
        self.assertTrue(profile.matches_cname("a.wild.example.net"))
        self.assertFalse(profile.matches_cname("example.com"))
        self.assertIn("5/5", profile.describe())


class TestCDNMatcher(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.entries = load_cdn_entries()

    def test_by_ip_hits_bundled_cidr(self) -> None:
        import ipaddress

        entry = next(e for e in self.entries if e.get("ip_cidr"))
        network = ipaddress.ip_network(entry["ip_cidr"][0], strict=False)
        probe = str(network.network_address + 1)

        matcher = get_matcher()
        self.assertEqual(matcher.by_ip(probe), entry["name"])

    def test_by_cname_hits_bundled_suffix(self) -> None:
        entry = next(e for e in self.entries if e.get("cname_domain"))
        suffix = entry["cname_domain"][0]

        matcher = get_matcher()
        self.assertEqual(matcher.by_cname(f"xyz.{suffix}"), entry["name"])

    def test_cname_heuristic_and_miss(self) -> None:
        matcher = get_matcher()
        # ARL 的 gslb/dns/cache 子串启发式
        self.assertEqual(matcher.by_cname("foo.gslb.bar.net"), "CDN")
        self.assertEqual(matcher.by_cname("nothing.matches.here"), "")
        self.assertEqual(matcher.by_ip("9.9.9.9"), "")


# --------------------------------------------------------------------- 打桩

def make_fake_query(
    answers: dict[tuple[str, str], list[str]],
    fallback_ip: str | None,
    calls: list[tuple[str, str]] | None = None,
):
    """构造 AsyncResolverPool._query 的替身。

    ``answers`` 里没有的 (name, rdtype) 命中 fallback_ip（用来模拟泛解析）。
    ``calls`` 会记录每一次调用 —— 注意不能拿 ``pool.stats["queries"]`` 判断，
    因为被替换掉的 ``_query`` 正是计数的位置。
    """

    async def fake_query(self, name: str, rdtype: str) -> list[str]:
        if calls is not None:
            calls.append((name, rdtype))
        key = (name, rdtype)
        if key in answers:
            return list(answers[key])
        if rdtype == "A" and fallback_ip and name.endswith(".example.com"):
            return [fallback_ip]
        return []

    return fake_query


# --------------------------------------------------------------------- 泛解析 + 爆破

BRUTE_WORDS = "www\napi\nmail\ndev\n"


class TestWildcardAndBrute(EngineTestCase):
    async def test_wildcard_profile_then_brute_filters_and_reports(self) -> None:
        """核心用例: 泛解析命中要被过滤, 而且必须留痕。"""
        wordlist = self.root / "words.txt"
        wordlist.write_text(BRUTE_WORDS, encoding="utf-8")

        answers = {
            ("api.example.com", "A"): [REAL_IP],                  # 真实资产
            ("www.example.com", "A"): [WILDCARD_IP],              # 纯噪声
            ("mail.example.com", "A"): [WILDCARD_IP, MIXED_IP],   # 混合: 有自己的 IP
        }

        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query(answers, WILDCARD_IP)
        ):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["wildcard_detect", "dns_brute"],
                module_config={
                    "dns_brute": {"wordlist": str(wordlist), "concurrency": 8}
                },
            )

        # 两个模块都跑起来了
        self.assertIn("wildcard_detect", summary["modules_enabled"])
        self.assertIn("dns_brute", summary["modules_enabled"])

        # 泛解析画像被正确建立
        profile = scanner.state.wildcard_profile("example.com")
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertTrue(profile.wildcard)
        self.assertEqual(profile.ips, {WILDCARD_IP})
        self.assertEqual(profile.resolved, profile.probes)

        # 爆破产出: api + mail 是真资产; www 与 dev 被泛解析挡掉
        domains = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("api.example.com", domains)
        self.assertIn("mail.example.com", domains)
        self.assertNotIn("www.example.com", domains)
        self.assertNotIn("dev.example.com", domains)

        # 结论: 被过滤的数量必须留痕（ARL 是静默 continue）
        findings = await self.storage.findings(scanner.scan_id)
        kinds = {f["kind"] for f in findings}
        self.assertIn("wildcard", kinds)
        self.assertIn("wildcard_filtered", kinds)

        filtered = next(f for f in findings if f["kind"] == "wildcard_filtered")
        self.assertIn("2 条命中泛解析", filtered["detail"])

        # 根域名被点亮 is_wildcard
        root_row = next(
            d for d in await self.storage.domains(scanner.scan_id) if d["name"] == "example.com"
        )
        self.assertEqual(root_row["is_wildcard"], 1)

    async def test_no_wildcard_means_everything_with_an_answer_is_emitted(self) -> None:
        wordlist = self.root / "words.txt"
        wordlist.write_text(BRUTE_WORDS, encoding="utf-8")

        answers = {("api.example.com", "A"): [REAL_IP]}

        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query(answers, None)
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["wildcard_detect", "dns_brute"],
                module_config={
                    "dns_brute": {"wordlist": str(wordlist), "concurrency": 8}
                },
            )

        profile = scanner.state.wildcard_profile("example.com")
        self.assertIsNotNone(profile)
        assert profile is not None
        self.assertFalse(profile.wildcard)

        domains = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("api.example.com", domains)

        # 没有泛解析就不该有 wildcard_filtered 汇报
        findings = await self.storage.findings(scanner.scan_id)
        self.assertNotIn("wildcard_filtered", {f["kind"] for f in findings})


# --------------------------------------------------------------------- 置换

PERMUTED_SEED = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class permuted_seed(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.DNS_NAME,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            # 打上 permuted 标签, 模拟"置换出来的"域名
            await self.emit_event(
                f"www.{event.data}", EventType.DNS_NAME, parent=event,
                tags={"permuted": True},
            )
"""


# --------------------------------------------------------------------- 管理面枚举

ADMIN_WORDS = """\
# 这是管理面定向字典

# ── 管理后台 ──
admin
manage

# ── 测试环境 ──
test
dev
"""


class TestAdminPlaneDictionary(unittest.TestCase):
    """带分类字典的解析。

    分类来自 ``# ── 分类 ──`` 段标题。它有用是因为命中 ``jenkins`` 和命中
    ``test`` 是两件不同的事：前者是运维入口、后者是影子资产。
    """

    def test_sections_become_categories(self) -> None:
        from core.util.words import _clean_categorized

        got = _clean_categorized(ADMIN_WORDS.splitlines())
        self.assertEqual(
            got,
            [("admin", "管理后台"), ("manage", "管理后台"),
             ("test", "测试环境"), ("dev", "测试环境")],
        )

    def test_plain_comments_are_not_categories(self) -> None:
        """普通注释不能被当成段标题。"""
        from core.util.words import _clean_categorized

        got = _clean_categorized(["# 这是一句普通说明", "admin", ""])
        self.assertEqual(got, [("admin", "")])

    def test_dedupe_keeps_first_category(self) -> None:
        from core.util.words import _clean_categorized

        got = _clean_categorized(["# ── A ──", "x", "# ── B ──", "x"])
        self.assertEqual(got, [("x", "A")])

    def test_bundled_dictionary_is_loaded_and_categorized(self) -> None:
        """随包分发的 admin_prefixes 要能加载，而且**确实带分类**。"""
        from core.util.words import load_categorized_words

        pairs = load_categorized_words()
        self.assertGreater(len(pairs), 100, "管理面字典太小了")
        categories = {c for _, c in pairs}
        self.assertNotIn("", categories, f"有词条没归到分类: {categories}")
        self.assertGreaterEqual(len(categories), 5, f"分类太少: {categories}")
        # 几个必须有分类的
        by_word = dict(pairs)
        self.assertEqual(by_word.get("admin"), "管理后台")
        self.assertEqual(by_word.get("jenkins"), "研发 / CI")
        self.assertIn("test", by_word)
        # 分类名里带斜杠不能把解析搞崩
        self.assertIn("/", by_word["jenkins"])


class TestAdminPlane(EngineTestCase):
    """管理面定向枚举：C 端反推 B 端。

    这个模块补的是**覆盖漏洞**而不是词表缺口：``domain_2w`` 已经覆盖了管理面
    常见前缀，但 ``dns_brute`` 是 ``loud``、被 ``default`` 挡掉，所以默认扫描
    一个管理面都找不到。``admin_plane`` 只有 200 来个候选、是 ``safe``，
    ``default`` 会跑它。
    """

    async def _run(self, answers, *, fallback=None, words: str = ADMIN_WORDS, **cfg):
        wordlist = self.root / "admin_words.txt"
        wordlist.write_text(words, encoding="utf-8")
        calls: list[tuple[str, str]] = []
        with mock.patch.object(
            AsyncResolverPool, "_query",
            make_fake_query(answers, fallback, calls),
        ):
            scanner, summary = await self.run_scan(
                targets=["example.com"],
                include=["wildcard_detect", "admin_plane"],
                module_config={
                    "admin_plane": {"wordlist": str(wordlist), "concurrency": 4, **cfg}
                },
            )
        return scanner, summary, calls

    async def _emitted(self, scan_id):
        rows = await self.storage.events(scan_id, limit=500, event_type="DNS_NAME")
        out = {}
        for e in rows:
            if e["module"] != "admin_plane":
                continue
            tags = json.loads(e["tags_json"] or "{}")
            out[e["data"]] = tags
        return out

    async def test_emits_hits_with_plane_and_category_tags(self) -> None:
        answers = {
            ("admin.example.com", "A"): [REAL_IP],
            ("test.example.com", "A"): [REAL_IP],
            # dev 不解析 → 不该产出
        }
        scanner, summary, _ = await self._run(answers)
        self.assertIn("admin_plane", summary["modules_enabled"])

        got = await self._emitted(scanner.scan_id)
        self.assertEqual(set(got), {"admin.example.com", "test.example.com"})
        self.assertEqual(got["admin.example.com"]["plane"], "admin")
        self.assertEqual(got["admin.example.com"]["category"], "管理后台")
        self.assertEqual(got["test.example.com"]["category"], "测试环境")
        self.assertEqual(got["admin.example.com"]["source"], "admin_plane")

    async def test_wildcard_hits_are_suppressed(self) -> None:
        """纯泛解析命中是噪声，不能入库 —— 但要留痕。"""
        answers = {
            ("admin.example.com", "A"): [REAL_IP],       # 真实资产
            ("test.example.com", "A"): [WILDCARD_IP],    # 纯噪声
            ("dev.example.com", "A"): [WILDCARD_IP, MIXED_IP],  # 混合 → 保留
        }
        scanner, _, _ = await self._run(answers, fallback=WILDCARD_IP)
        got = await self._emitted(scanner.scan_id)
        self.assertIn("admin.example.com", got)
        self.assertIn("dev.example.com", got, "混合解析应保留")
        self.assertNotIn("test.example.com", got, "纯泛解析应被过滤")

    async def test_finding_summarises_by_category(self) -> None:
        answers = {
            ("admin.example.com", "A"): [REAL_IP],
            ("manage.example.com", "A"): [REAL_IP],
            ("test.example.com", "A"): [REAL_IP],
        }
        scanner, _, _ = await self._run(answers)
        findings = await self.storage.findings(scanner.scan_id)
        hit = next((f for f in findings if f["kind"] == "admin_plane"), None)
        self.assertIsNotNone(hit, f"没发汇总 FINDING: {[f['kind'] for f in findings]}")
        detail = hit["detail"]
        self.assertIn("管理面 3 个", detail)
        self.assertIn("管理后台 2", detail)
        self.assertIn("测试环境 1", detail)
        # 具体名字也要列出来，否则还得自己去翻
        self.assertIn("admin.example.com", detail)
        self.assertEqual(hit["severity"], "medium")

    async def test_no_hits_no_finding(self) -> None:
        """一个都没命中时不要发空结论，避免把「发现」页刷满。"""
        scanner, _, _ = await self._run({})
        findings = await self.storage.findings(scanner.scan_id)
        self.assertNotIn("admin_plane", {f["kind"] for f in findings})

    async def test_candidates_are_root_level_prefixes(self) -> None:
        """候选必须是 ``{前缀}.{根域名}`` —— 同层插词是 ``dns_permute`` 的活。"""
        scanner, _, calls = await self._run({})
        probed = {name for name, rdtype in calls if rdtype == "A"}
        self.assertIn("admin.example.com", probed)
        self.assertIn("test.example.com", probed)
        self.assertIn("dev.example.com", probed)
        self.assertIn("manage.example.com", probed)
        # 不能凭空造出三层
        self.assertFalse(
            any(name.count(".") > 2 for name in probed), f"候选层级不对: {probed}"
        )

    async def test_max_prefixes_caps_the_candidates(self) -> None:
        scanner, _, calls = await self._run({}, max_prefixes=2)
        probed = {name for name, rdtype in calls if rdtype == "A" and "example.com" in name}
        self.assertLessEqual(len(probed), 2 + 5, f"上限没生效: {probed}")


# --------------------------------------------------------------------- 影子资产

class TestShadowAssetMatching(unittest.TestCase):
    """影子资产的**标签匹配** —— 这里最容易写成子串匹配然后全盘误报。

    ``device`` / ``attest`` / ``contest`` 都含 ``test`` 或 ``dev``，
    在真实域名里一点都不罕见。所以只认整标签。
    """

    def _matcher(self):
        from core.domains.subdomain.standalone.shadow_asset import shadow_asset
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        preset = Preset(name="t")
        preset.include = None
        preset.exclude = []
        scanner = Scanner(
            targets=["example.com", "panabit.com"], preset=preset, storage=None
        )
        m = shadow_asset(scanner)
        asyncio.run(m.setup())
        return m

    def test_hits(self) -> None:
        m = self._matcher()
        for name, want in (
            ("test.example.com", "测试环境"),
            ("test4.example.com", "测试环境"),
            ("test-api.example.com", "测试环境"),
            ("api-test.example.com", "测试环境"),
            ("dev.example.com", "测试环境"),
            ("staging.example.com", "测试环境"),
            ("uat.example.com", "测试环境"),
            ("preview.example.com", "测试环境"),
            ("alpha.example.com", "测试环境"),
            ("old.example.com", "废弃 / 历史系统"),
            ("legacy.example.com", "废弃 / 历史系统"),
            # 多租户 SaaS 的真实形态
            ("18602a6295834140.alpha.saas.panabit.com", "测试环境"),
        ):
            with self.subTest(name=name):
                self.assertEqual(m.match(name), want)

    def test_substring_traps_do_not_match(self) -> None:
        """**这是这个模块最容易写错的地方。**"""
        m = self._matcher()
        for name in (
            "device.example.com",     # 含 dev
            "attest.example.com",     # 含 test
            "contest.example.com",    # 含 test
            "developer.example.com",  # developer 不是影子词
            "www.example.com",
            "api.example.com",
            "example.com",            # 根域名自己
        ):
            with self.subTest(name=name):
                self.assertIsNone(m.match(name), f"误报: {name}")

    def test_root_labels_are_not_judged(self) -> None:
        """根域名自身的标签不参与判断。

        否则一个叫 ``dev.example.org`` 的**正式**域名会被自己的根标签误判。
        """
        from core.domains.subdomain.standalone.shadow_asset import shadow_asset
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        preset = Preset(name="t")
        preset.include = None
        preset.exclude = []
        scanner = Scanner(targets=["dev.example.org"], preset=preset, storage=None)
        m = shadow_asset(scanner)
        asyncio.run(m.setup())
        self.assertIsNone(m.match("dev.example.org"))
        self.assertIsNone(m.match("www.dev.example.org"))

    def test_categories_come_from_the_shadow_sections(self) -> None:
        m = self._matcher()
        self.assertEqual(
            sorted(set(m.words.values())), ["废弃 / 历史系统", "测试环境"]
        )
        self.assertGreater(len(m.words), 20)


SHADOW_EMITTER = '''
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_names(BaseModule):
    """把一批名字当 DNS_NAME 发出去，模拟"别的源已经发现了它们"。"""
    watched_events = (EventType.SEED,)
    produced_events = (EventType.DNS_NAME,)
    flags = ("passive", "safe")
    per_domain_only = True

    NAMES = %r

    async def handle_event(self, event):
        for name in self.NAMES:
            await self.emit_event(name, EventType.DNS_NAME, parent=event,
                                  tags={"source": "fake_source"})
'''


class TestShadowAssetModule(EngineTestCase):
    """走引擎：打标要落到 ``domain.shadow_kind``，而且**不发 FINDING**。

    "不发 FINDING" 是刻意的：实测 ``panabit.com`` 一次扫描 3205 个域名里有
    326 个影子资产，逐个发会把「发现」页刷满，反而看不见重点。可见性靠
    资产表的标签列 + 概览计数。
    """

    NAMES = [
        "www.example.com",
        "test.example.com",
        "old.example.com",
        "device.example.com",     # 子串陷阱，不该打标
    ]

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.add_module_file("emit_names", SHADOW_EMITTER % (self.NAMES,))

    async def _run(self, names=None):
        if names is not None:
            self.add_module_file("emit_names", SHADOW_EMITTER % (names,))
        return await self.run_scan(
            targets=["example.com"],
            include=["emit_names", "shadow_asset"],
        )

    async def test_marks_shadow_domains_only(self) -> None:
        scanner, _ = await self._run()
        rows = {d["name"]: d for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(rows["test.example.com"]["shadow_kind"], "测试环境")
        self.assertEqual(rows["old.example.com"]["shadow_kind"], "废弃 / 历史系统")
        self.assertIsNone(rows["www.example.com"]["shadow_kind"])
        self.assertIsNone(rows["device.example.com"]["shadow_kind"], "子串误报")

    async def test_no_finding_is_emitted(self) -> None:
        """刻意不发 FINDING —— 影子资产可能上百个。"""
        scanner, _ = await self._run()
        findings = await self.storage.findings(scanner.scan_id)
        self.assertEqual(
            [f for f in findings if "shadow" in str(f["kind"])], [],
            f"不该发影子 FINDING: {[f['kind'] for f in findings]}",
        )

    async def test_summary_counts_shadow_domains(self) -> None:
        scanner, _ = await self._run()
        summary = await self.storage.summary(scanner.scan_id)
        self.assertEqual(summary["domains_shadow"], 2, f"summary={summary}")

    async def test_summary_is_zero_when_nothing_matches(self) -> None:
        scanner, _ = await self._run(names=["www.example.com", "api.example.com"])
        summary = await self.storage.summary(scanner.scan_id)
        self.assertEqual(summary["domains_shadow"], 0)

    async def test_does_not_loop(self) -> None:
        """模块收到 DNS_NAME 又发 DNS_NAME —— 必须收敛。

        靠的是引擎"重复事件不再分发给模块"（但**投影照跑**，标记才落得了库）。
        这里用模块自己的 ok 计数确认它没被自己的产出再喂一遍。
        """
        scanner, summary = await self._run()
        self.assertEqual(summary["stats"].get("module.shadow_asset.error", 0), 0)
        # 4 个名字，模块最多处理 4 次（含根域名共 5 个事件）
        self.assertLessEqual(
            summary["stats"].get("module.shadow_asset.ok", 0), 6,
            f"可能自我循环了: {summary['stats']}",
        )

    async def test_runs_in_pure_passive_preset(self) -> None:
        """纯被动预设里也要跑 —— 它不发任何请求，影子资产识别不该依赖你愿不愿意发包。"""
        from core.engine.preset import Preset

        preset = Preset.load_builtin("passive")
        scanner_mod = __import__(
            "core.domains.subdomain.standalone.shadow_asset", fromlist=["shadow_asset"]
        ).shadow_asset
        flags = scanner_mod.flags
        self.assertTrue(preset.allows("shadow_asset", flags), "纯被动预设里没启用")


class TestPermute(EngineTestCase):
    async def test_does_not_permute_already_permuted_names(self) -> None:
        self.add_module_file("permuted_seed", PERMUTED_SEED)
        wordlist = self.root / "words.txt"
        wordlist.write_text("dev\ntest\n", encoding="utf-8")

        calls: list[tuple[str, str]] = []
        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query({}, None, calls)
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["dns_permute", "permuted_seed"],
                module_config={
                    "dns_permute": {"wordlist": str(wordlist), "concurrency": 4}
                },
            )

        # 一条查询都没发出去 —— 证明 permuted 标签的短路生效, 不会指数爆炸
        self.assertEqual(calls, [])

    async def test_permutes_normal_names(self) -> None:
        wordlist = self.root / "words.txt"
        wordlist.write_text("dev\ntest\n", encoding="utf-8")

        answers = {("dev.www.example.com", "A"): [REAL_IP]}
        calls: list[tuple[str, str]] = []
        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query(answers, None, calls)
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["demo_expand", "dns_permute"],
                module_config={
                    "dns_permute": {
                        "wordlist": str(wordlist),
                        "concurrency": 8,
                        "max_total_candidates": 100,
                    }
                },
            )

        self.assertGreater(len(calls), 0)
        self.assertIn(("dev.www.example.com", "A"), calls)
        domains = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("dev.www.example.com", domains)
        # 置换产出应当带上 permuted 标签, 便于事后区分来源
        events = await self.storage.events(scanner.scan_id, limit=500)
        hit = next(e for e in events if e["data"] == "dev.www.example.com")
        self.assertIn('"permuted": true', hit["tags_json"] or "")


# --------------------------------------------------------------------- CDN + 富化

class TestCdnProjection(EngineTestCase):
    async def test_cdn_finding_marks_domain_and_ip(self) -> None:
        # 用 paths.resources_dir() 而不是自己数 parents —— 目录一调整就会指错
        from core.util.paths import resources_dir

        raw = resources_dir() / "cdn_info.json"
        entries = json.loads(raw.read_text(encoding="utf-8"))
        entry = next(e for e in entries if e.get("cname_domain"))
        cname = f"edge.{entry['cname_domain'][0]}"

        answers = {
            ("www.example.com", "CNAME"): [cname],
            ("www.example.com", "A"): [REAL_IP],
        }
        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query(answers, None)
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["demo_expand", "dns_resolve"],
            )

        # IP 侧: 命中 CDN -> is_cloud
        ips = {i["addr"]: i for i in await self.storage.ips(scanner.scan_id)}
        self.assertEqual(ips[REAL_IP]["is_cloud"], 1)

        # 域名侧: FINDING 回写 is_cdn
        domains = {d["name"]: d for d in await self.storage.domains(scanner.scan_id)}
        self.assertEqual(domains["www.example.com"]["is_cdn"], 1)

        findings = await self.storage.findings(scanner.scan_id)
        self.assertIn("cdn", {f["kind"] for f in findings})


    async def test_all_cnames_are_kept_and_checked(self) -> None:
        """**一条 CNAME 查询可以返回多条记录**（多 CDN / 多线路是常态）。

        早先只取 ``cnames[0]``，第二条之后全被丢掉 —— 表现是"CDN 挂在第二条上
        就漏判"，而且漏得没有任何痕迹。这条测试钉住两件事：
        多条都要进 tags，且**逐条**参与 CDN 判定。
        """
        from core.util.paths import resources_dir

        entries = json.loads((resources_dir() / "cdn_info.json").read_text(encoding="utf-8"))
        cdn_entry = next(e for e in entries if e.get("cname_domain"))
        cdn_cname = f"edge.{cdn_entry['cname_domain'][0]}"

        # 第一条**不是** CDN，第二条才是 —— 旧实现只会看第一条
        answers = {
            ("www.example.com", "CNAME"): ["plain.example.net", cdn_cname],
            ("www.example.com", "A"): [REAL_IP],
        }
        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query(answers, None)
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"], include=["demo_expand", "dns_resolve"]
            )

        # ① 多条 CNAME 都要留下来
        events = await self.storage.events(scanner.scan_id, limit=500, event_type="IP_ADDRESS")
        hit = next(e for e in events if e["data"] == REAL_IP)
        tags = json.loads(hit["tags_json"] or "{}")
        self.assertEqual(tags.get("cname"), "plain.example.net", "首条仍走 cname 键")
        self.assertEqual(
            tags.get("cnames"), ["plain.example.net", cdn_cname],
            f"多条 CNAME 没被保留: {tags}",
        )

        # ② 第二条上的 CDN 必须被认出来（旧实现这里会漏）
        ips = {i["addr"]: i for i in await self.storage.ips(scanner.scan_id)}
        self.assertEqual(
            ips[REAL_IP]["is_cloud"], 1,
            "CDN 在第二条 CNAME 上，逐条判定没生效",
        )
        findings = await self.storage.findings(scanner.scan_id)
        cdn_finding = next((f for f in findings if f["kind"] == "cdn"), None)
        self.assertIsNotNone(cdn_finding, f"没发 CDN FINDING: {[f['kind'] for f in findings]}")
        self.assertIn(cdn_entry["name"], cdn_finding["detail"])

    async def test_single_cname_keeps_the_old_shape(self) -> None:
        """单条 CNAME 时不额外塞 ``cnames`` —— 别为了兼容性把既有数据改形。"""
        answers = {
            ("www.example.com", "CNAME"): ["only.example.net"],
            ("www.example.com", "A"): [REAL_IP],
        }
        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query(answers, None)
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"], include=["demo_expand", "dns_resolve"]
            )
        events = await self.storage.events(scanner.scan_id, limit=500, event_type="IP_ADDRESS")
        hit = next(e for e in events if e["data"] == REAL_IP)
        tags = json.loads(hit["tags_json"] or "{}")
        self.assertEqual(tags.get("cname"), "only.example.net")
        self.assertNotIn("cnames", tags)

    async def test_specific_ip_name_beats_generic_cname_heuristic(self) -> None:
        """CNAME 的通用启发式("CDN")不能把 IP 段给出的具体名字顶掉。"""
        entry = next(e for e in load_cdn_entries() if e.get("ip_cidr"))
        network = ipaddress.ip_network(entry["ip_cidr"][0], strict=False)
        ip = str(network.network_address + 1)
        expected = get_matcher().by_ip(ip)
        self.assertTrue(expected and expected != "CDN", "内置 CDN 库应能给出具体名字")

        answers = {
            # 这个 CNAME 会命中 gslb/dns/cache 子串启发式 -> 通用 "CDN"
            ("www.example.com", "CNAME"): ["edge.gslb.example.net"],
            ("www.example.com", "A"): [ip],
        }
        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query(answers, None)
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["demo_expand", "dns_resolve"],
            )

        findings = await self.storage.findings(scanner.scan_id)
        cdn_finding = next(f for f in findings if f["kind"] == "cdn")
        self.assertIn(expected, cdn_finding["detail"])


ENRICH_SOURCE = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class fake_resolve(BaseModule):
        watched_events = (EventType.DNS_NAME,)
        produced_events = (EventType.IP_ADDRESS,)
        flags = ("active", "safe")

        async def handle_event(self, event):
            await self.emit_event("1.2.3.4", EventType.IP_ADDRESS, parent=event)


    class enrich(BaseModule):
        watched_events = (EventType.IP_ADDRESS,)
        produced_events = (EventType.IP_ADDRESS,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            # 用同一个 IP 再发一次, 只是带上富化信息。
            # 引擎会把它当作重复事件不再分发 -> 不会死循环;
            # 但资产投影照常执行 -> ip 行被补全。
            await self.emit_event(
                event.data, EventType.IP_ADDRESS, parent=event,
                tags={"asn": "AS12345", "org": "TestOrg", "country": "CN"},
            )
"""


class TestEnrichmentProjection(EngineTestCase):
    async def test_duplicate_event_enriches_asset_without_looping(self) -> None:
        self.add_module_file("enrich", ENRICH_SOURCE)
        scanner, summary = await self.run_scan(
            targets=["example.com"],
            include=["demo_expand", "fake_resolve", "enrich"],
        )

        ips = {i["addr"]: i for i in await self.storage.ips(scanner.scan_id)}
        self.assertIn(REAL_IP, ips)
        self.assertEqual(ips[REAL_IP]["asn"], "AS12345")
        self.assertEqual(ips[REAL_IP]["org"], "TestOrg")
        self.assertEqual(ips[REAL_IP]["country"], "CN")

        # 富化模块只被触发一次: 它自己发出的重复事件不会回头再喂给它
        self.assertEqual(summary["stats"].get("module.enrich.ok"), 1)
        self.assertEqual(summary["stats"].get("module.enrich.error", 0), 0)
        # 扫描能返回本身就证明收敛了(没有死循环), 这里再确认事件数符合预期:
        # SEED + 4 个 DNS_NAME + 1 个 IP = 6
        self.assertEqual(summary["events_new"], 6)


TWO_FINDINGS = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class twin_findings(BaseModule):
        watched_events = (EventType.SEED,)
        produced_events = (EventType.FINDING,)
        flags = ("passive", "safe")

        async def handle_event(self, event):
            await self.emit_finding("alpha", "第一条结论", parent=event, target=event.data)
            await self.emit_finding("beta", "第二条结论", parent=event, target=event.data)
            # 同 kind 同目标重复发一次, 应当被去重
            await self.emit_finding("alpha", "第一条结论", parent=event, target=event.data)
"""


class TestFindingDedupe(EngineTestCase):
    """同一个目标上的多条 FINDING 不能被去重键互相顶掉。"""

    async def test_distinct_kinds_coexist(self) -> None:
        self.add_module_file("twin_findings", TWO_FINDINGS)
        scanner, summary = await self.run_scan(
            targets=["example.com"], include=["twin_findings"]
        )

        findings = await self.storage.findings(scanner.scan_id)
        self.assertEqual(sorted(f["kind"] for f in findings), ["alpha", "beta"])
        # 同 kind 的重复汇报仍然被去重: SEED + alpha + beta = 3
        self.assertEqual(summary["events_new"], 3)
        self.assertEqual(summary["findings"], 2)


TWO_IPS = """
    from core.engine.event import EventType
    from core.engine.module import BaseModule


    class two_ips(BaseModule):
        watched_events = (EventType.DNS_NAME,)
        produced_events = (EventType.IP_ADDRESS,)
        flags = ("active", "safe")

        async def handle_event(self, event):
            await self.emit_event("8.8.8.8", EventType.IP_ADDRESS, parent=event)
            await self.emit_event("10.1.2.3", EventType.IP_ADDRESS, parent=event)
"""


class TestAsnEnrich(EngineTestCase):
    async def test_enriches_global_ip_and_skips_private(self) -> None:
        self.add_module_file("two_ips", TWO_IPS)
        calls: list[str] = []

        async def fake_get_json(self, url, *, params=None, headers=None):  # noqa: ANN001
            calls.append(url)
            return {"ip": "8.8.8.8", "country": "US", "org": "AS15169 Google LLC"}

        with mock.patch.object(HTTPClient, "get_json", fake_get_json):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["demo_expand", "two_ips", "asn_enrich"],
                module_config={"asn_enrich": {"qps": 0}},
            )

        # 只查了公网那个, 私网地址被跳过（既不浪费请求, 也不把内网拓扑发出去）
        self.assertEqual(len(calls), 1)
        self.assertIn("8.8.8.8", calls[0])

        ips = {i["addr"]: i for i in await self.storage.ips(scanner.scan_id)}
        self.assertEqual(ips["8.8.8.8"]["asn"], "AS15169")
        self.assertEqual(ips["8.8.8.8"]["org"], "Google LLC")
        self.assertEqual(ips["8.8.8.8"]["country"], "US")
        # 私网地址仍然是未富化的状态
        self.assertIsNone(ips["10.1.2.3"]["asn"])


if __name__ == "__main__":
    unittest.main()
