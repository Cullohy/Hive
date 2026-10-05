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
import contextlib
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
        # 语义变了：现在按**来源分级配额**取，**允许少于**上限。
        # 高价值来源不够猜时硬凑出来的全是纯猜，为了凑数发 DNS 查询是纯亏。
        self.assertLessEqual(len(gen.permutations_of("www.example.com")), 5)

    def test_root_domain_has_no_permutation(self) -> None:
        gen = DnsGen([], ["dev"], "example.com")
        self.assertEqual(gen.permutations_of("example.com"), [])


# --------------------------------------------------------------------- 泛解析画像

class TestPermutationYield(unittest.TestCase):
    """置换的**产出质量**（2026-10-04）。

    起因是一次真实扫描（``dayinmao.com``，泛解析 + 腾讯云 EO）跑完只得到一堆
    噪声。量化后发现三个病根，逐一治：

    * 截断按**策略顺序**，最有价值的 ``replace`` 永远排不到（配额被前两个
      策略吃光）；
    * 词表是通用的 —— ``ai.jwc.example.com`` 这种拿英文词猜中文高校缩写，
      命中率基本为 0；
    * 数字只会 +1/+2/+3，且会给已带数字的标签再拼一个（``db-0011``）。
    """

    WORDS = ["dev", "staging", "beta", "admin", "api", "test", "gw", "db"]

    def _gen(self, seeds, **kw):
        kw.setdefault("max_per_domain", 500)
        return DnsGen(seeds, self.WORDS, "example.com", **kw)

    # ------------------------------------------------------------ ① 排序
    def test_high_value_candidates_come_before_generic_guessing(self) -> None:
        """``replace`` / ``enriched`` 必须排在 ``dict`` 前面。

        原来按策略顺序产出，``max_per_domain`` 一满就 ``return``，
        排在最后的 ``replace_word_with_word`` 一次都跑不到。
        """
        gen = self._gen(["www.example.com"])
        gen.extract_target_words(["www.example.com", "oa.example.com"])
        kept = gen._apply_budget(gen.candidates_of("www.example.com"))
        self.assertTrue(kept, "一条都没留")
        first_generic = next(
            (i for i, c in enumerate(kept) if c.source == "dict"), len(kept)
        )
        self.assertTrue(
            any(c.source != "dict" for c in kept[:first_generic]),
            "有根据的候选一条都没排在纯猜前面",
        )

    def test_ordering_is_deterministic(self) -> None:
        """同一份输入必须给出同一份输出。

        排序键带域名做次键就是为了这个 —— 否则每次跑截断出的前 N 条可能不同，
        线上出问题就复现不了。
        """
        gen = self._gen(["uat.api.example.com"])
        gen.extract_target_words(["uat.api.example.com", "oa.example.com"])
        a = gen.permutations_of("uat.api.example.com")
        b = gen.permutations_of("uat.api.example.com")
        self.assertEqual(a, b)

    # ------------------------------------------------------------ ② 分级配额
    def test_generic_guessing_never_outnumbers_grounded_candidates(self) -> None:
        """**纯猜的条数不超过有根据的条数。**

        这是这次改造的核心不变量。固定比例在小目标上会失真：某个种子只产出
        57 条有根据的候选时，固定配额 100 反而让纯猜占 64%。
        """
        for seed in ("www.example.com", "uat.api.example.com", "oa.example.com"):
            with self.subTest(seed=seed):
                gen = self._gen([seed])
                gen.extract_target_words([seed, "oa.example.com", "jwc.example.com"])
                kept = gen._apply_budget(gen.candidates_of(seed))
                grounded = [c for c in kept if c.source != "dict"]
                guessed = [c for c in kept if c.source == "dict"]
                self.assertLessEqual(
                    len(guessed), len(grounded),
                    f"{seed}: 纯猜 {len(guessed)} 条 > 有根据 {len(grounded)} 条",
                )

    def test_output_actually_shrinks(self) -> None:
        """改造要**真的少发** DNS 查询，而不是换个顺序。

        对照必须是**同一个生成器**（同样做过词表增强），只开关配额 ——
        拿「没增强的」当基线是比错了对象：增强会带来更多高价值候选，
        开着配额的产出反而可能更大，那不是配额的问题。
        """
        seeds = ["api.example.com", "v2.api.example.com", "uat.api.example.com",
                 "test-api.example.com", "oa.example.com", "jwc.example.com"]
        gen = self._gen(seeds, max_per_domain=0)      # 0 = 不截断
        gen.extract_target_words(seeds)
        raw = sum(len(gen.candidates_of(s)) for s in seeds)
        gen.max_per_domain = 500
        kept = sum(len(gen.permutations_of(s)) for s in seeds)
        self.assertGreater(raw, 0)
        self.assertLess(kept, raw, f"开了配额 {kept} 反而没少于原始 {raw}")

    # ------------------------------------------------------------ ③ 词表增强
    def test_target_words_are_mined_from_known_subdomains(self) -> None:
        """目标自有的词汇只能从**它自己的子域**里抽出来。

        通用词表里不会有 ``jwc`` / ``oa`` 这种中文站缩写。
        """
        gen = self._gen([], max_per_domain=0)
        got = gen.extract_target_words([
            "jwc.example.com", "oa.example.com", "test-api.example.com",
            "other-domain.com",            # 不同根，应被忽略
        ])
        self.assertIn("jwc", got)
        self.assertIn("oa", got)
        self.assertIn("test", got)       # test-api 按 - 切开
        self.assertIn("test-api", got)   # 整段也留
        self.assertNotIn("other", got)   # 不同根
        self.assertNotIn("com", got)     # 根域名本身

    def test_pure_numbers_are_not_treated_as_words(self) -> None:
        """纯数字交给数字邻域，不进词表 —— 否则会造出 ``v2oa`` 这种。"""
        gen = self._gen([], max_per_domain=0)
        got = gen.extract_target_words(["v2.example.com", "db-001.example.com"])
        # 含字母的混合 token（v2）**要**留 —— alterx 的规则也是收它；
        # 该排除的是纯数字。
        self.assertIn("v2", got)
        self.assertNotIn("001", got)   # 纯数字交给数字邻域
        self.assertIn("db", got)

    def test_enriched_words_actually_reach_the_candidates(self) -> None:
        """抽出来的词要**真的进候选**，否则抽了也白抽。"""
        gen = self._gen(["oa.example.com"])
        gen.extract_target_words(["oa.example.com", "jwc.example.com"])
        out = set(gen.permutations_of("oa.example.com"))
        self.assertTrue(
            any("jwc" in d for d in out),
            f"目标自有词 jwc 没进候选: {sorted(out)[:10]}",
        )

    # ------------------------------------------------------------ ④ 数字邻域
    def test_number_neighborhood_is_bidirectional_and_keeps_width(self) -> None:
        """``db-001`` 的邻域要双向、且**保持三位**。

        借鉴 dnsgen 的 ``modify_numbers``。原来只会 +1/+2/+3，
        还会给已带数字的标签再拼一个（``db-0011``）。
        """
        gen = self._gen(["db-001.example.com"], max_per_domain=0)
        out = set(gen.permutations_of("db-001.example.com"))
        for want in ("db-000.example.com", "db-002.example.com", "db-003.example.com"):
            self.assertIn(want, out, f"缺 {want}")
        self.assertNotIn("db-0011.example.com", out,
                         "给已带数字的标签又拼了一个 1")

    def test_long_digit_runs_are_skipped_whole(self) -> None:
        """8 位以上的连续数字**整段跳过**，不能被切成两段各自邻域。

        踩过的坑：正则是 ``\\d{1,4}`` 且没有边界，于是 ``web20250115`` 被切成
        ``2025`` + ``0115``，产出 ``web20250112`` 这种**看着像真的、其实是
        垃圾**的域名 —— 比不产出更坏，它会占查询预算并混进资产表。

        时间戳、雪花 ID、日期式发布名的 ±1 邻域本来就没意义。
        """
        gen = self._gen(["web20250115.example.com"], max_per_domain=0)
        out = set(gen.permutations_of("web20250115.example.com"))
        self.assertNotIn(
            "web20250112.example.com", out,
            "8 位数字被切段后产生了假的邻域",
        )
        for cand in out:
            # 不变式是「那段长数字原样还在」—— 前后缀产出是合法的，
            # 被切段才会让它缺一块（20250115 变成 20250112）。
            self.assertIn("20250115", cand, f"长数字标签被动过了: {cand}")
        # 短数字仍然要正常出邻域（对照组）
        gen2 = self._gen(["web25.example.com"], max_per_domain=0)
        self.assertIn("web24.example.com", set(gen2.permutations_of("web25.example.com")))


    def test_number_neighborhood_of_a_short_number(self) -> None:
        gen = self._gen(["v2.example.com"], max_per_domain=0)
        out = set(gen.permutations_of("v2.example.com"))
        self.assertIn("v1.example.com", out)
        self.assertIn("v3.example.com", out)

    # ------------------------------------------------------------ ⑤ 深度上限
    def test_permutation_does_not_go_deeper_than_the_cap(self) -> None:
        """二级子域不该被猜成三级。

        实测 dayinmao.com（泛解析）上，二级嵌套候选占了产出绝大多数，
        而它们**注定是泛解析产物** —— 猜得越深越是在给泛解析烧钱。
        """
        gen = self._gen(["uat.api.example.com"], max_per_domain=0)
        for cand in gen.candidates_of("uat.api.example.com"):
            labels = cand.domain[: -len(".example.com")].split(".")
            self.assertLessEqual(
                len(labels), gen.max_result_labels,
                f"{cand.domain} 超过深度上限 {gen.max_result_labels}",
            )

    def test_one_level_seed_can_still_grow_by_one(self) -> None:
        """深度上限不能把「加一级」也掐掉 —— ``oa`` → ``admin.oa`` 有意义。"""
        gen = self._gen(["oa.example.com"], max_per_domain=0)
        out = set(gen.permutations_of("oa.example.com"))
        self.assertIn("admin.oa.example.com", out)



class TestGlobalQueryTimeoutStillReachesResolver(EngineTestCase):
    """全局 ``settings.dns_timeout`` 必须继续到达解析器。

    2026-10-04 删掉 ``dnsx_idle_timeout`` 这个键之后，这条更该留着 ——
    删键的目的就是让"单次查询超时"只有一个来源（``settings.dns_timeout``），
    四个用解析器的模块都得继续拿到它。
    """

    def test_the_global_query_timeout_still_reaches_the_resolver(self) -> None:
        """对照组：解析器那条路**仍然**是 3。"""
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        preset = Preset.load_builtin("active")
        scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
        scanner.load_modules()
        for name in ("dns_resolve", "ip_ptr", "admin_plane", "wildcard_detect"):
            with self.subTest(module=name):
                self.assertEqual(scanner.modules[name].cfg("dns_timeout", 3), 3)



class TestCatchAllFrequency(unittest.TestCase):
    """**频次兜底层**：同一批里过多候选共享同一个 IP / CNAME → 判 catch-all。

    起因是两次真实扫描：

    * ``dayinmao.com``（泛解析 + 腾讯云 EO）漏进 **702 个**假子域
    * ``bjsxtx.com`` 漏进 **590 个** —— 590 个子域全指向 ``39.106.205.137``

    采样层（``wildcard_detect`` 只看 5 个随机子域）在这两个场景里都**看不出**
    泛解析：CDN 的 IP 池无界，5 个样本覆盖不住，每个候选都「有不在集合里的
    IP」→ 逐条判据全部放行。

    思路借鉴 OneForAll 的 ``deal_wildcard``（先统计再过滤），但阈值改成
    **绝对数 + 比率两条**，而且比率**必须配下限**。
    """

    @staticmethod
    def _rows(n, ip="39.106.205.137"):
        return [(f"h{i}.example.com", [ip], []) for i in range(n)]

    # ------------------------------------------------------------ 正例
    def test_bjsxtx_shape_is_caught(self) -> None:
        """590 个候选全指向一个 IP —— 这正是 bjsxtx.com 那次。

        绝对数先命中（590 > 100），所以理由串是"被 N 个候选共用"那条。
        """
        from core.domains.subdomain._lib.sweep import find_catch_all

        hot = find_catch_all(self._rows(590))
        self.assertIn("39.106.205.137", hot)
        self.assertIn("590", hot["39.106.205.137"])

    def test_ratio_fires_when_absolute_does_not(self) -> None:
        """集中度过半但没到 100 时，靠比率那条兜底。"""
        from core.domains.subdomain._lib.sweep import find_catch_all

        rows = self._rows(80) + [(f"x{i}.example.com", [f"9.9.9.{i}"], [])
                                for i in range(20)]
        hot = find_catch_all(rows)
        self.assertIn("39.106.205.137", hot)
        self.assertIn("/100", hot["39.106.205.137"], "比率那条没生效")

    def test_dayinmao_shape_is_caught_by_cname(self) -> None:
        """CNAME 侧同样要能判（腾讯云 EO 的尾巴是固定父域）。"""
        from core.domains.subdomain._lib.sweep import find_catch_all

        rows = [(f"h{i}.example.com", [f"1.2.3.{i % 5}"],
                 ["xyz.dayinmao.com.eo.dnse2.com"]) for i in range(400)]
        hot = find_catch_all(rows)
        self.assertIn("xyz.dayinmao.com.eo.dnse2.com", hot)

    def test_absolute_rule_fires_even_when_ratio_stays_low(self) -> None:
        """绝对数那条必须能**独立**判掉 —— 比率接不住时它得顶上来。

        ⚠️ 这里原来叫 ``test_absolute_rule_also_catches``，可它的夹具是
        ``80 + 20``（比率 0.8），**和上面 ``test_ratio_fires_when_absolute_does_not``
        一模一样** —— 两条判据里真正在起作用的只有比率。把 ``ip_appear_maximum``
        整条删掉它照样绿（变异验证第 4 处实测：0 条挂）。

        现在用 120/320：比率 0.375 接不住，但 120 > 100 —— 只有绝对数能判。
        """
        from core.domains.subdomain._lib.sweep import find_catch_all

        rows = self._rows(120) + [(f"x{i}.example.com", [f"9.9.9.{i}"], [])
                                  for i in range(200)]
        hot = find_catch_all(rows)
        self.assertIn("39.106.205.137", hot)
        why = hot["39.106.205.137"]
        self.assertIn("120", why)
        self.assertNotIn("/", why, "命中的是比率那条 —— 绝对数判据没被钉住")


    def test_cname_absolute_rule_fires_independently(self) -> None:
        """CNAME 侧的绝对数（>50）同样得能独立判掉。

        ``test_dayinmao_shape_is_caught_by_cname`` 是 400/400，比率也够，
        删掉 ``cname_appear_maximum`` 一样不会红。这里用 60/260。
        """
        from core.domains.subdomain._lib.sweep import find_catch_all

        tail = "xyz.dayinmao.com.eo.dnse2.com"
        rows = [(f"h{i}.example.com", [f"1.2.3.{i}"], [tail]) for i in range(60)]
        rows += [(f"x{i}.example.com", [f"9.9.9.{i}"], [f"cdn{i}.example.net"])
                 for i in range(200)]
        hot = find_catch_all(rows)
        self.assertIn(tail, hot)
        why = hot[tail]
        self.assertIn("60", why)
        self.assertNotIn("/", why, "命中的是比率那条 —— CNAME 绝对数没被钉住")

    # ------------------------------------------------------------ 反例
    def test_small_cluster_is_not_misjudged(self) -> None:
        """**12 个子域共用一台机器**是小站点的常态，不能当 catch-all。"""
        from core.domains.subdomain._lib.sweep import find_catch_all

        self.assertEqual(find_catch_all(self._rows(12)), {})

    def test_ratio_needs_a_floor(self) -> None:
        """1 个候选也是 100% 集中 —— 比率在小批量上根本没有统计意义。

        ⚠️ 第一版实现没配下限，把测试里「1 个候选」和「4 个候选」的批次
        全判成了 catch-all，5 条老测试直接红。这是实测打脸的典型。
        """
        from core.domains.subdomain._lib.sweep import find_catch_all

        self.assertEqual(find_catch_all(self._rows(1)), {})
        self.assertEqual(find_catch_all(self._rows(4)), {})

    def test_spread_out_batch_is_not_misjudged(self) -> None:
        """候选分散在很多 IP 上 —— 真集群，什么都不该判。"""
        from core.domains.subdomain._lib.sweep import find_catch_all

        rows = [(f"h{i}.example.com", [f"10.0.{i // 250}.{i % 250}"], [])
                for i in range(500)]
        self.assertEqual(find_catch_all(rows), {})

    def test_comma_separated_records_are_split(self) -> None:
        """一条记录里多个 IP（``a,b``）也要各算一次，否则计数会被低估。"""
        from core.domains.subdomain._lib.sweep import find_catch_all

        rows = [(f"h{i}.example.com", ["1.2.3.4,5.6.7.8"], []) for i in range(150)]
        hot = find_catch_all(rows)
        self.assertIn("1.2.3.4", hot)
        self.assertIn("5.6.7.8", hot)


#: 频次兜底层的四个配置键，``dns_brute`` / ``dns_permute`` 共用。
FREQ_KEYS = ("ip_appear_maximum", "cname_appear_maximum",
             "ip_appear_ratio", "cname_appear_ratio")


class TestCatchAllConfigWiring(unittest.TestCase):
    """频次兜底层的**配置接线** —— 阈值得真调得动，且调了不被全局吃掉。

    为什么要单独测：``BaseModule.cfg()`` 的解析顺序是
    **模块段 → 全局 ``settings`` → 代码默认**。模块段缺键就会掉到全局去 ——
    ``dns_timeout`` 当初就是这样被全局的 ``3`` 静默盖掉的：模块里写的 120
    压根没生效，一轮 19706 条的字典跑到一半被 kill，日志只留一行 timeout warning。

    这四个键如果只留代码默认值，今天不炸，以后谁往 ``settings`` 里加个同名的
    就炸。防御分在两层（yml + 代码默认）还会**互相掩盖**，所以这里钉的是
    **不变量**：键必须在模块段里，且模块段必须压过全局。
    """

    @staticmethod
    def _modules(preset):
        from core.engine.scanner import Scanner

        scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
        scanner.load_modules()
        return scanner

    def test_keys_live_in_each_module_section(self) -> None:
        """四个键都写在模块自己的段里，不是只靠代码默认值兜着。"""
        from core.engine.preset import Preset

        scanner = self._modules(Preset.load_builtin("active"))
        for name in ("dns_brute", "dns_permute"):
            with self.subTest(module=name):
                cfg = scanner.modules[name].config
                for key in FREQ_KEYS:
                    self.assertIn(
                        key, cfg,
                        f"{key} 不在 {name} 的 module_config 里 —— cfg() 会先掉到"
                        f"全局 settings、再掉到代码默认，yml 怎么改都不生效",
                    )

    def test_module_section_beats_a_conflicting_global(self) -> None:
        """**同一个键在全局也写一份**时，模块段必须赢。

        这是 ``dns_timeout`` 那次事故的直接形状：两边同名、值不同，
        谁生效决定了 19706 条字典是跑完还是腰斩。
        """
        from core.engine.preset import Preset

        # 加载真预设再只扰动这四个键 —— 手工 new Preset 会绕过 flag 门闩，
        # 测出来的模块集合就不是生产那一套了
        preset = Preset.load_builtin("active")
        preset.settings.update({key: -1 for key in FREQ_KEYS})
        preset.module_config["dns_brute"].update({k: 999999 for k in FREQ_KEYS})
        preset.module_config["dns_permute"].update({k: 7 for k in FREQ_KEYS})

        scanner = self._modules(preset)
        for name, want in (("dns_brute", 999999), ("dns_permute", 7)):
            with self.subTest(module=name):
                module = scanner.modules[name]
                for key in FREQ_KEYS:
                    self.assertEqual(
                        module.cfg(key, "该键压根没读到"), want,
                        f"{name}.{key} 被全局 settings 的 -1 盖掉了",
                    )

    def test_active_preset_has_no_global_twins(self) -> None:
        """``active`` 的全局 ``settings`` 里不许出现同名的键。"""
        from core.engine.preset import Preset

        settings = Preset.load_builtin("active").settings
        for key in FREQ_KEYS:
            with self.subTest(key=key):
                self.assertNotIn(
                    key, settings,
                    f"settings 里有全局 {key} —— 模块段一旦漏写就会被它盖掉，"
                    f"和 dns_timeout 当初一模一样",
                )

    def test_code_default_alone_still_keeps_the_layer_on(self) -> None:
        """**不吃 yml** 时，代码默认值也得能判掉实测那 590 个。

        同一类的另一条：``active.yml`` 是给人调的，代码默认是给「预设写漏了」
        兜底的，两边都得站得住。
        """
        from core.domains.subdomain._lib.sweep import find_catch_all

        rows = [(f"h{i}.example.com", ["39.106.205.137"], []) for i in range(590)]
        self.assertIn("39.106.205.137", find_catch_all(rows))


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


class TestWildcardCnameSignature(unittest.TestCase):
    """CNAME 签名要认「随机首标签」形态 —— 2026-10-03 补。

    起因是一次真实扫描（``dayinmao.com``，腾讯云 EO 加速）：

    * ``wildcard_detect`` **正确**判出泛解析：5/5 个随机名有响应，
      CNAME 落在 ``*.dayinmao.com.eo.dnse2.com``（首标签每次都不同）；
    * 但 ``dns_permute`` / ``dns_brute`` 的过滤**只看 IP 集合**，而 CDN 的
      IP 池无界、5 个样本只代表其中极小一部分 → 702 个假子域进了资产表。

    两处根因：``matches_cname`` 只比完整名（首标签一变就失效），
    以及 CNAME 虽然解析层一直查得到、却**从头到尾没人用**（2026-10-04 之前
    它挂在 ``DnsxResult`` 上，那个字段连生产消费方都没有）。
    """

    def setUp(self) -> None:
        from core.engine.state import WildcardProfile

        self.p = WildcardProfile(root="dayinmao.com", wildcard=True, probes=5, resolved=5)
        # 5 个随机名各自 CNAME 到「首标签不同、父域相同」的地址
        self.p.cnames = {
            "3t8tgklygjyt.dayinmao.com.eo.dnse2.com",
            "zz9k2m1p.dayinmao.com.eo.dnse2.com",
        }
        # 采样只拿到 4 个 IP —— 真实的 CDN 池远不止这些
        self.p.ips = {"112.13.210.66", "36.150.72.68",
                      "43.174.246.33", "43.174.247.33"}

    def test_random_first_label_still_matches(self) -> None:
        """首标签不同的同父域 CNAME，必须认成同一条泛解析链路。"""
        self.assertTrue(self.p.matches_cname("qqq111.dayinmao.com.eo.dnse2.com"))
        self.assertTrue(self.p.matches_cname("3t8tgklygjyt.dayinmao.com.eo.dnse2.com"))

    def test_an_unrelated_cname_does_not_match(self) -> None:
        self.assertFalse(self.p.matches_cname("elsewhere.example.net"))
        self.assertFalse(self.p.matches_cname(""))

    def test_cname_hit_wins_over_an_ip_outside_the_sample(self) -> None:
        """**这是那个 bug 本身**：CNAME 命中就不该再看 IP。

        候选的 A 记录落在采样集合外（CDN 池很大）——但它的 CNAME 走的是
        同一条泛解析链路，所以它就是噪声。以前这里会当成真资产放行。
        """
        self.assertTrue(self.p.is_artifact(
            ips=["43.174.999.1"],
            cnames=["zzzz.dayinmao.com.eo.dnse2.com"],
        ))

    def test_cname_elsewhere_means_it_has_its_own_resolution(self) -> None:
        """CNAME 不在签名里 = 有自己的解析 = 真资产。

        ⚠️ 即便 A 记录恰好落在采样集合内也一样 —— CNAME 的证据比 IP 强，
        因为 IP 池无界而 CNAME 链是确定的。
        """
        self.assertFalse(self.p.is_artifact(
            ips=["112.13.210.66"],
            cnames=["origin.other-cdn.com"],
        ))

    def test_without_cname_it_falls_back_to_the_ip_set(self) -> None:
        """没有 CNAME 时只能退回 IP 判据（采样少会漏判，但那是采样边界）。"""
        self.assertTrue(self.p.is_artifact(
            ips=["112.13.210.66", "43.174.246.33"], cnames=[]))
        self.assertFalse(self.p.is_artifact(ips=["1.2.3.4"], cnames=[]))



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


def make_fake_records(
    answers: dict[str, list[str]],
    wildcard_ip: str | None = None,
    calls: list[tuple[str, str]] | None = None,
    failures: set[str] | None = None,
    cnames: dict[str, list[str]] | None = None,
):
    """``AsyncResolverPool.records`` 的替身 —— 一次调用同时返回 ``(ips, cnames)``。

    ## 打在哪个缝隙上

    打在 ``records()``：``dns_brute`` / ``dns_permute`` 与解析层之间的**唯一**
    边界。不起子进程、不发真实 DNS，``answers`` 查表返回。

    泛解析画像仍走 ``AsyncResolverPool`` 的 ``a_records`` / ``cnames``（那是
    ``wildcard_detect`` 用的，仍经由 ``_query``），所以这两道桩要一起打：
    **画像**用 ``_query``，**爆破/置换**用本函数。

    ``failures`` 里的名字返回 ``None`` —— 模拟"查询故障"，与"域名不存在"
    （返回 ``([], [])``）分开。爆破模块必须能把这两者分开记账。
    """
    cname_map = cnames or {}

    async def fake_records(self, name: str):
        if calls is not None:
            calls.append((name, "A"))
        if failures and name in failures:
            return None                      # 查询失败
        ips = list(answers.get(name) or ())
        if not ips and wildcard_ip and name.endswith(".example.com"):
            ips = [wildcard_ip]
        return ips, list(cname_map.get(name) or ())

    return fake_records


@contextlib.contextmanager
def patch_sweep(**kw):
    """把 ``records()`` 换成假实现（``dns_brute`` / ``dns_permute`` 的唯一入口）。"""
    with mock.patch.object(AsyncResolverPool, "records", make_fake_records(**kw)):
        yield


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
        ), patch_sweep(
            answers={name: ips for (name, _t), ips in answers.items()},
            wildcard_ip=WILDCARD_IP,
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
        ), patch_sweep(
            answers={name: ips for (name, _t), ips in answers.items()},
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

    async def test_all_queries_failing_is_not_reported_as_no_subdomains(self) -> None:
        """**查询全挂 ≠ 没有子域** —— 两者必须分开，而且要留痕。

        钉的是 2026-10-04 换掉 dnsx 之后新增的能力。以前 ``DnsxResult.error``
        字段从来没被赋值（恒为空串），SERVFAIL / 超时 / NXDOMAIN 三种情况
        全掉进"没有 IP"同一个分支被静默丢弃 —— 表现是"爆破一条都没跑出来"，
        而扫描结果里没有任何东西能告诉你"这是网络故障"还是"这站真没子域"。

        现在 ``records()`` 用 ``None`` 表示查询故障，``([], [])`` 表示域名不存在，
        两者分别记进 ``outcome.failed`` 与 ``outcome.no_records``，并且全挂时
        额外发一条 ``dns_query_all_failed`` finding。
        """
        wordlist = self.root / "words.txt"
        wordlist.write_text(BRUTE_WORDS, encoding="utf-8")
        all_names = {f"{w}.example.com" for w in BRUTE_WORDS.split()}

        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query({}, None)
        ), patch_sweep(answers={}, failures=all_names):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["wildcard_detect", "dns_brute"],
                module_config={
                    "dns_brute": {"wordlist": str(wordlist), "concurrency": 8}
                },
            )

        # 确实一条子域都没产出
        domains = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertNotIn("api.example.com", domains)

        # 但必须留下一条"这是故障"的结论
        findings = await self.storage.findings(scanner.scan_id)
        kinds = {f["kind"] for f in findings}
        self.assertIn("dns_query_all_failed", kinds)
        self.assertNotIn("wildcard_filtered", kinds,
                         "一条都没解析成功，不该报泛解析过滤")

        detail = next(f for f in findings if f["kind"] == "dns_query_all_failed")["detail"]
        self.assertIn("不是「没有子域」", detail)

    async def test_nonexistent_names_are_counted_separately_from_failures(self) -> None:
        """NXDOMAIN 是**有效答案**，不是故障 —— 不能混进 failed。

        这两种情况在结果里必须可区分：一个"这站真没子域"，一个"网络炸了"。
        """
        wordlist = self.root / "words.txt"
        wordlist.write_text(BRUTE_WORDS, encoding="utf-8")
        only_failures = {"www.example.com"}

        with mock.patch.object(
            AsyncResolverPool, "_query", make_fake_query({}, None)
        ), patch_sweep(
            answers={"api.example.com": [REAL_IP]},
            failures=only_failures,
        ):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["wildcard_detect", "dns_brute"],
                module_config={
                    "dns_brute": {"wordlist": str(wordlist), "concurrency": 8}
                },
            )

        # 部分成功 → 不该发"全挂"那条 finding
        findings = await self.storage.findings(scanner.scan_id)
        self.assertNotIn("dns_query_all_failed", {f["kind"] for f in findings})

        # 真资产还是出来了
        domains = {d["name"] for d in await self.storage.domains(scanner.scan_id)}
        self.assertIn("api.example.com", domains)


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
        rows, _ = await self.storage.events(scan_id, limit=500, event_type="DNS_NAME")
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
        ), patch_sweep(
            answers={"dev.www.example.com": [REAL_IP]},
            calls=calls,
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
        events, _ = await self.storage.events(scanner.scan_id, limit=500)
        hit = next(e for e in events if e["data"] == "dev.www.example.com")
        self.assertIn('"permuted": true', hit["tags_json"] or "")


    async def test_target_words_are_mined_from_all_known_subdomains(self) -> None:
        """词表增强要吃掉**所有**已知的同根子域，不只是当前那一个。

        通用词表里只有 ``dev``。而 ``jwc`` 是**另一个种子**
        （``mine_three`` 一轮给了 ``www`` / ``jwc`` / ``oa``）的标签 ——
        所以 ``jwc.www.example.com`` 这种候选，**只有把 jwc 抽进词表
        才可能生成**。

        ⚠️ 上一版写得太弱：断言是「``sent`` 里有含 jwc 的话」，而
        ``dev.oa.example.com`` 不抽词也能拿到（``oa`` 自己就是种子，
        拿 ``dev`` 前缀即可）。那样把抽词整个去掉都测不出来。
        """
        wordlist = self.root / "words.txt"
        wordlist.write_text("dev\n", encoding="utf-8")
        self.add_module_file("mine_three", MINE_THREE)

        calls: list[tuple[str, str]] = []
        with patch_sweep(answers={"jwc.www.example.com": [REAL_IP]}, calls=calls):
            await self.run_scan(
                targets=["example.com"],
                include=["mine_three", "dns_permute"],
                module_config={
                    "dns_permute": {
                        "wordlist": str(wordlist),
                        "max_total_candidates": 50,
                        "enrich_from_known": True,
                    }
                },
            )

        self.assertIn(
            ("jwc.www.example.com", "A"), calls,
            "另一个种子里的标签没被抽进词表 —— 词表增强白做了",
        )

    async def test_evidence_hosts_are_permuted(self) -> None:
        """JS 里写着的后端地址**要**能拿到邻域扩展。

        ``js_assets`` 发的 ``DNS_NAME`` 挂在 URL 事件上，而子事件类型是
        ``DNS_NAME`` 就计一次递归（``BaseModule.emit_event`` 的规矩），
        于是 ``scope_distance == 2``。它曾经被 ``max_input_distance``（默认 1）
        挡掉 —— 那道闸 2026-10-04 已删除。
        """
        wordlist = self.root / "words.txt"
        wordlist.write_text("dev\n", encoding="utf-8")
        self.add_module_file("js_seed", JS_SEED)

        calls: list[tuple[str, str]] = []
        with patch_sweep(answers={"dev.jwc.example.com": [REAL_IP]}, calls=calls):
            await self.run_scan(
                targets=["example.com"],
                include=["js_seed", "dns_permute"],
                module_config={
                    "dns_permute": {
                        "wordlist": str(wordlist),
                        "max_total_candidates": 50,
                    }
                },
            )

        self.assertIn(
            ("dev.jwc.example.com", "A"), calls,
            "证据级主机名没被扩展 —— JS 里写着的后端地址白看到了",
        )

    async def test_nested_names_are_permuted_too(self) -> None:
        """距离门删掉后，**任何**非置换来源的二级域名都会拿到扩展。

        这条原来是反的（``test_ordinary_nested_names_are_still_gated``
        断言它们要被拦住）。删闸是有意的取舍：真实数据显示那道闸一条都没挡，
        却把 ``tls_cert`` 的证书 SAN 和 ``ip_ptr`` 的 PTR 全丢了 —— 库里
        ``source=tls_san`` 事件是 0 条，而 tls_cert 同时成功产出了 32 条
        ``SSL_CERTIFICATE``。证书拿到了，SAN 里的兄弟站全被下游丢掉。

        防爆改由**可数的预算**兜（``max_permutations_per_name`` /
        ``max_total_candidates``）和 ``permuted`` 标记，而不是距离这个代理指标。
        """
        wordlist = self.root / "words.txt"
        wordlist.write_text("dev\n", encoding="utf-8")
        self.add_module_file("nested_seed", NESTED_SEED)

        calls: list[tuple[str, str]] = []
        with patch_sweep(answers={"dev.www.example.com": [REAL_IP]}, calls=calls):
            await self.run_scan(
                targets=["example.com"],
                include=["nested_seed", "dns_permute"],
                module_config={
                    "dns_permute": {
                        "wordlist": str(wordlist),
                        "max_total_candidates": 50,
                    }
                },
            )

        self.assertIn(
            ("dev.www.example.com", "A"), calls,
            "普通二级事件没被扩展 —— 距离门可能没删干净",
        )

    async def test_the_gate_it_survives_on_is_the_permuted_tag(self) -> None:
        """对照组：证明夹具**真的被加载了**。

        同类里 ``test_does_not_permute_already_permuted_names`` 断言的是
        「一条查询都没发出去」，而模块没被加载时它也会这么过 —— 实测踩过：
        另一个改动定义了同名夹具把它覆盖掉，那条测试立刻变成假绿
        （``assertEqual(calls, [])`` 对「什么都没发生」和「正确地被拦下」
        同样成立）。所以先用一条**确实会发查询**的对照组把前提钉住。
        """
        wordlist = self.root / "words.txt"
        wordlist.write_text("dev\n", encoding="utf-8")
        self.add_module_file("nested_seed", NESTED_SEED)

        calls: list[tuple[str, str]] = []
        with patch_sweep(answers={"dev.www.example.com": [REAL_IP]}, calls=calls):
            await self.run_scan(
                targets=["example.com"],
                include=["nested_seed", "dns_permute"],
                module_config={
                    "dns_permute": {
                        "wordlist": str(wordlist),
                        "max_total_candidates": 50,
                    }
                },
            )

        self.assertTrue(
            calls, "对照组一条查询都没发 —— 夹具没被加载，后面的断言都是空转",
        )



#: 一轮给出 3 个同根真子域（模拟被动源）。用来验「词表增强吃的是**所有**已知
#: 子域」，而不只是当前正在置换的那一个。
MINE_THREE = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class mine_three(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.DNS_NAME,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        # 顺序有意义：模块是**串行**消费的，词表随事件流逐步变厚，
        # 所以后到的种子才拿得到前面那些种子贡献的词。
        for d in ("jwc", "www", "oa"):
            await self.emit_event(
                f"{d}.{event.data}", EventType.DNS_NAME, parent=event)
"""

#: 复刻 ``js_assets`` 的产出形状：主机名挂在一条 ``scope_distance=1`` 的 URL
#: 事件上，且带 ``kind=js_host``。
#:
#: ⚠️ 那条 URL 事件**必须手工构造**成 distance=1：正常链路是
#: SEED(0) -> OPEN_TCP_PORT(1) -> URL(1) -> DNS_NAME(2)，用 ``emit_event``
#: 从 SEED 直接发 URL 只会得到 distance=0，那条子事件的距离就成了 1，
#: 测不到距离门。
JS_SEED = """
from core.engine.event import Event, EventType
from core.engine.module import BaseModule


class js_seed(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.URL, EventType.DNS_NAME)
    flags = ("active", "safe")

    async def handle_event(self, event):
        url = Event(
            type=EventType.URL, data=f"http://{event.data}/app.js",
            module=self.name, parent_id=event.id, parent_data=event.data,
            scope_distance=1,
        )
        await self.scanner.submit(url)
        await self.emit_event(
            "jwc." + event.data, EventType.DNS_NAME, parent=url,
            tags={"kind": "js_host", "source": self.name},
        )
"""

#: 对照组：一条 distance=2 的普通 DNS_NAME（**没有** js_host 标记）。
NESTED_SEED = """
from core.engine.event import Event, EventType
from core.engine.module import BaseModule


class nested_seed(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.DNS_NAME,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.scanner.submit(Event(
            type=EventType.DNS_NAME, data="www." + event.data,
            module=self.name, parent_id=event.id, parent_data=event.data,
            scope_distance=2, tags={"source": "nested"},
        ))
"""


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
        events, _ = await self.storage.events(scanner.scan_id, limit=500, event_type="IP_ADDRESS")
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
        events, _ = await self.storage.events(scanner.scan_id, limit=500, event_type="IP_ADDRESS")
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


class TestResolveFailureIsNotNonexistence(EngineTestCase):
    """**查询失败绝不能被当成"域名不存在"。**

    起因（2026-10-05 查 scan 50 / yealink.com.cn 发现的真实问题）：

    ``license.yealink.com.cn`` 与 ``supportx.yealink.com.cn`` 在界面上显示
    "未解析"，但它们其实活着 —— ``dir_brute`` 用 HTTP 摸到了 200 和真实标题
    （"Yealink License" / "Yealink Support"），DNS 也确实有 A 记录
    （202.109.248.212，CNAME waf212.yealink-inc.com）。

    根因在 ``resolver._query``：它把"所有解析器都没答复"也返回 ``[]``，
    于是网络故障在资产表里和"这域名真的不存在"完全同形。重新逐个分类 84 个
    域名后发现：**21 个（25%）本来能解析的域名被判成了不存在**，而界面、
    stats、日志三处都看不出异常。
    """

    async def _scan_with_fake_dns(self, fake):
        with mock.patch.object(AsyncResolverPool, "_query", fake):
            return await self.run_scan(
                targets=["example.com"],
                include=["demo_expand", "dns_resolve"],
            )

    async def test_a_failed_lookup_is_not_reported_as_a_domain_without_ip(self) -> None:
        """全失败时：不能当成"扫过了、没有"，必须留下痕迹。"""
        calls: list[tuple[str, str]] = []

        async def always_fails(self, name: str, rdtype: str):  # noqa: ANN001
            calls.append((name, rdtype))
            if rdtype == "A" and name == "www.example.com":
                return None  # 查询失败（不是"不存在"）
            return []

        scanner, _ = await self._scan_with_fake_dns(always_fails)

        # 没产出 IP_ADDRESS —— 这是对的，没有 IP 可发
        ips = await self.storage.ips(scanner.scan_id)
        self.assertEqual(ips, [])

        # ❗ 修复点：失败要在 stats 里显形。改回"静默当不存在"这条就红。
        stats = scanner.modules["dns_resolve"].stats
        self.assertEqual(
            stats["resolve_failed"], 1,
            f"查询失败没有记进 stats，失败被伪装成了『未解析』: {stats}",
        )
        self.assertEqual(stats["unresolved_due_to_failure"], 1)

        # 而且必须**重试过**一次（池内轮换之外，模块自己还要再试一次）
        a_queries = [c for c in calls if c[1] == "A" and c[0] == "www.example.com"]
        self.assertEqual(len(a_queries), 2, f"失败后没有重试: {a_queries}")

    async def test_a_retry_that_succeeds_still_emits_the_ip(self) -> None:
        """瞬时故障（限速 / 冷启动）重试成功时，资产**不能丢**。"""
        seen: list[int] = []

        async def fails_once(self, name: str, rdtype: str):  # noqa: ANN001
            if rdtype == "A" and name == "www.example.com":
                seen.append(1)
                return None if len(seen) == 1 else [REAL_IP]
            return []

        scanner, _ = await self._scan_with_fake_dns(fails_once)

        ips = {i["addr"] for i in await self.storage.ips(scanner.scan_id)}
        self.assertIn(REAL_IP, ips, "重试成功了却没落库 —— 资产被故障吃掉了")
        stats = scanner.modules["dns_resolve"].stats
        self.assertEqual(stats["resolve_failed"], 0)

    async def test_a_genuinely_missing_domain_is_not_counted_as_a_failure(self) -> None:
        """对照组：NXDOMAIN 那种**有效回答**不该被算成故障。

        这条是给上一条的 —— 判据不能是"查不到就报失败"，否则真正死掉的域名
        会把失败计数刷满，统计又失去意义。
        """
        async def nxdomain_everywhere(self, name: str, rdtype: str):  # noqa: ANN001
            return []

        scanner, _ = await self._scan_with_fake_dns(nxdomain_everywhere)

        stats = scanner.modules["dns_resolve"].stats
        self.assertEqual(stats["resolve_failed"], 0, "有效回答被误记成故障")
        self.assertEqual(stats.get("unresolved_due_to_failure", 0), 0)

    async def test_end_to_end_all_resolvers_timing_out_is_not_nonexistence(self) -> None:
        """**端到端**：真的让所有解析器超时，走**真实**的 ``_query`` 代码路径。

        单独一条的理由是变异验证逼出来的：上面三条把 ``_query`` 整个替换掉了，
        所以它们只测到"模块能处理 ``None``"，测不到"**池子能不能把失败报成
        ``None``**"。实测把 ``_query`` 的 ``return None`` 改回 ``return []``，
        上面三条**依然全绿** —— 真根因没被钉住。这条才是钉住根因的那条：
        它只替换最底层的 ``Resolver.resolve``，上面每一层都是真代码。
        """
        import dns.asyncresolver
        import dns.resolver

        async def always_timeout(self, *a, **kw):  # noqa: ANN001
            raise dns.resolver.Timeout()

        with mock.patch.object(dns.asyncresolver.Resolver, "resolve", always_timeout):
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["demo_expand", "dns_resolve"],
                module_config={"dns_resolve": {
                    # 内联地址串（`load_resolvers` 支持逗号/空白分隔）—— 传列表
                    # 会被预设层字符串化成 "['8.8.8.8']"，dnspython 直接拒收
                    "resolvers": "8.8.8.8",
                    # 跳过启动健康校验：让**每次查询**都超时，而不是让池子建不起来
                    "verify_resolvers": False,
                }},
            )

        ips = await self.storage.ips(scanner.scan_id)
        self.assertEqual(ips, [], "全超时不该产出 IP")

        stats = scanner.modules["dns_resolve"].stats
        # ❗ 这条就是根因判据：池子把超时报成 None，模块据此记成"查询失败"，
        # 而不是让它悄悄变成"这个域名不存在"。
        #
        # 刻意**不**钉死具体个数（种子与 demo_expand 产出的名字有去重，
        # 数一数就会变成另一条与本判据无关的脆弱断言）。要钉的是这三条不变量：
        #   1) 确实有失败发生        —— 变异掉修复后这里是 0，测试立刻红
        #   2) 每次失败都上浮到模块   —— query_failed == resolve_failed
        #   3) 一次都没丢            —— unresolved_due_to_failure == resolve_failed
        self.assertGreater(
            stats["resolve_failed"], 0,
            f"真实超时一条都没记成查询失败，仍被伪装成了『未解析』: {stats}",
        )
        self.assertEqual(stats["query_failed"], stats["resolve_failed"], stats)
        self.assertEqual(
            stats["unresolved_due_to_failure"], stats["resolve_failed"], stats)


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


#: 发一个裸 IP 事件（``seed_asset`` 之外直接造，链路更短）
EMIT_IP = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_ip(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.IP_ADDRESS,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event(
            "203.0.113.10", EventType.IP_ADDRESS, parent=event, tags={}
        )
"""


class TestPtrClassification(unittest.TestCase):
    """``classify_ptr`` 的纯函数判定 —— 四类结果各钉一条。

    这层最容易写错且最难在端到端里看出来：判错的代价是**静默丢资产**
    （把真域名当云厂商默认名）或**越界**（把第三方域名推进下游）。
    """

    def test_no_ptr_is_empty(self) -> None:
        from core.domains.resolve.ip_ptr import classify_ptr

        name, kind, _ = classify_ptr([])
        self.assertIsNone(name)
        self.assertEqual(kind, "empty")

    def test_valid_domain_is_a_candidate(self) -> None:
        from core.domains.resolve.ip_ptr import classify_ptr

        name, kind, _ = classify_ptr(["host1.example.com."])
        # 尾点已被解析器去掉；这里再确认一次归一化
        self.assertEqual(name, "host1.example.com")
        self.assertEqual(kind, "candidate")

    def test_provider_default_name_is_never_an_asset(self) -> None:
        """云厂商默认名**绝不能**成为候选域名。

        误判的代价是把共享主机的默认名推进下游，然后对着一台不属于目标的
        机器跑完整链路。
        """
        from core.domains.resolve.ip_ptr import classify_ptr

        for ptr in (
            "ec2-1-2-3-4.compute-1.amazonaws.com",
            "ip-10-0-0-1.eu-west-1.compute.amazonaws.com",
            "server.mysql.hosted.googleusercontent.com",
            "vm.cx22.azure.com",
            "box.vps.ovh.net",
            "ns1.aliyun.com",
        ):
            name, kind, _ = classify_ptr([ptr])
            self.assertIsNone(name, f"{ptr} 不该成为资产")
            self.assertEqual(kind, "provider", ptr)

    def test_non_domain_ptr_is_invalid(self) -> None:
        """``localhost.`` / 单标签名字不是域名，不能推进。"""
        from core.domains.resolve.ip_ptr import classify_ptr

        name, kind, detail = classify_ptr(["localhost", "host1"])
        self.assertIsNone(name)
        self.assertEqual(kind, "invalid")
        self.assertIn("localhost", detail)

    def test_provider_wins_when_both_present(self) -> None:
        """同一台机器既有云默认名又有真名时，按"共享主机"处理更保守。"""
        from core.domains.resolve.ip_ptr import classify_ptr

        name, kind, detail = classify_ptr(
            ["ec2-1-2-3-4.compute-1.amazonaws.com", "real.example.com"]
        )
        self.assertIsNone(name)
        self.assertEqual(kind, "provider")
        self.assertIn("amazonaws", detail)


class TestIpPtrModule(EngineTestCase):
    """``ip_ptr`` 模块端到端：三种 PTR 结果的三种处置。"""

    def _patch_ptr(self, mapping: dict[str, list[str]]):
        """按 IP 返回 PTR 结果，并记录查了哪些 IP。"""
        from core.domains.resolve._lib.resolver import AsyncResolverPool

        seen: list[str] = []

        async def fake_ptr(self, ip: str) -> list[str]:  # noqa: ANN001
            seen.append(ip)
            return list(mapping.get(ip, []))

        return seen, mock.patch.object(AsyncResolverPool, "ptr", fake_ptr)

    async def _scan(self, ptrs: dict[str, list[str]]):
        self.add_module_file("emit_ip", EMIT_IP)
        seen, patch = self._patch_ptr(ptrs)
        with patch:
            scanner, _ = await self.run_scan(
                targets=["example.com"],
                include=["emit_ip", "ip_ptr"],
            )
        return scanner, seen

    async def test_no_ptr_produces_nothing_and_is_not_an_error(self) -> None:
        """没有 PTR 是**常态**（云主机普遍不配），不能报错也不能发事件。"""
        scanner, seen = await self._scan({})
        self.assertEqual(seen, ["203.0.113.10"], "该 IP 仍要被查一次")
        events, _ = await self.storage.events(scanner.scan_id, limit=200)
        kinds = [e["type"] for e in events]
        self.assertNotIn("DNS_NAME", kinds)
        self.assertNotIn("FINDING", kinds, "没有 PTR 不是问题，不该刷 finding")

    async def test_in_scope_ptr_advances_downstream(self) -> None:
        """落在目标下的 PTR → 发 DNS_NAME，走完整下游。"""
        scanner, _ = await self._scan({"203.0.113.10": ["srv.example.com."]})
        events, _ = await self.storage.events(scanner.scan_id, limit=200)
        dns = [e for e in events if e["type"] == "DNS_NAME"]
        self.assertTrue(dns, "范围内的 PTR 必须推进下游")
        self.assertEqual(dns[0]["data"], "srv.example.com")
        self.assertEqual(dns[0]["module"], "ip_ptr")

    async def test_out_of_scope_ptr_is_recorded_but_not_advanced(self) -> None:
        """范围外的 PTR → 只记 finding，**绝不发 DNS_NAME**。

        这是授权边界：发出去虽然会被 ``in_scope()`` 拦掉，但用户只会看到
        越界计数 +1，得自己猜为什么。
        """
        scanner, _ = await self._scan({"203.0.113.10": ["host.other.com."]})
        events, _ = await self.storage.events(scanner.scan_id, limit=200)
        self.assertFalse(
            [e for e in events if e["type"] == "DNS_NAME"],
            "范围外的域名绝不能推进下游",
        )
        findings = [e for e in events if e["type"] == "FINDING"]
        self.assertTrue(findings, "范围外也必须留痕")
        detail = str(findings[0]["tags_json"])
        self.assertIn("ip_ptr_out_of_scope", detail)
        self.assertIn("host.other.com", detail)

    async def test_provider_ptr_is_flagged_as_shared_host(self) -> None:
        """云厂商默认名 → 明确告诉用户"这是共享主机"。"""
        scanner, _ = await self._scan(
            {"203.0.113.10": ["ec2-1-2-3-4.compute-1.amazonaws.com"]}
        )
        events, _ = await self.storage.events(scanner.scan_id, limit=200)
        self.assertFalse([e for e in events if e["type"] == "DNS_NAME"])
        findings = [e for e in events if e["type"] == "FINDING"]
        self.assertTrue(findings)
        detail = str(findings[0]["tags_json"])
        self.assertIn("ip_ptr_provider", detail)
        self.assertIn("共享主机", detail)

    async def test_each_ip_is_queried_only_once(self) -> None:
        """同一个 IP 被多个模块/多条路径重复发过来时，只查一次。"""
        scanner, seen = await self._scan({"203.0.113.10": ["srv.example.com"]})
        self.assertEqual(seen, ["203.0.113.10"])
        # 仍然只有一个 DNS_NAME（去重后）
        events, _ = await self.storage.events(scanner.scan_id, limit=200)
        dns = [e for e in events if e["type"] == "DNS_NAME" and e["module"] == "ip_ptr"]
        self.assertEqual(len(dns), 1)

    async def test_module_is_active_and_safe(self) -> None:
        """``active, safe``：问 DNS 是冲着目标去的（不是查第三方数据库），
        但只读 PTR、不碰端口、不发 HTTP，所以是 ``safe``。"""
        from core.domains.resolve.ip_ptr import ip_ptr

        self.assertEqual(set(ip_ptr.flags), {"active", "safe"})


# --------------------------------------------------------------------- 域传送

#: 伪造一条 AXFR 应答。只用到 ``rcode()`` 与 ``answer[].name/.rdtype`` ——
#: 本模块**只收名字**，所以不需要真的构造 dns.message。
class _FakeName:
    def __init__(self, text: str) -> None:
        self._text = text

    def to_text(self) -> str:
        return self._text


class _FakeRRSet:
    def __init__(self, name: str, rdtype: int) -> None:
        self.name = _FakeName(name)
        self.rdtype = rdtype


class _FakeMsg:
    def __init__(self, names, rcode: int) -> None:
        self.answer = [_FakeRRSet(n, 1) for n in names]
        self._rcode = rcode

    def rcode(self) -> int:
        return self._rcode


@contextlib.contextmanager
def patch_xfr(*, servers=None, addrs=None, zone=None, refused=()):
    """把域传送那条链的三个接缝一起打上。

    * ``servers`` —— NS 查询返回什么（注意：**不在目标之下的一律不算权威 NS**）
    * ``addrs``   —— NS 主机名解析成什么地址（``dns.query.xfr`` 要的是地址）
    * ``zone``    —— 传送成功时区域里有哪些名字
    * ``refused`` —— 这些地址会拒绝传送
    """
    import dns.query
    import dns.rcode

    async def fake_ns(self, name):  # noqa: ANN001
        return list(servers or ())

    async def fake_a(self, name):  # noqa: ANN001
        if addrs is not None:
            return list(addrs)
        return ["203.0.113.1"] if name in (servers or ()) else []

    def fake_xfr(addr, zone_name, **kwargs):  # noqa: ANN001
        if addr in refused:
            return iter([_FakeMsg([], dns.rcode.REFUSED)])
        return iter([_FakeMsg(zone or (), dns.rcode.NOERROR)])

    with mock.patch.object(AsyncResolverPool, "ns_records", fake_ns), \
            mock.patch.object(AsyncResolverPool, "a_records", fake_a), \
            mock.patch.object(dns.query, "xfr", fake_xfr):
        yield


class TestZoneTransfer(EngineTestCase):
    """域传送（AXFR）—— 成功就把整份区域名单白拿。"""

    HOST = "example.com"

    async def _scan(self, targets=None, enforce_scope: bool = True, **cfg):
        return await self.run_scan(
            targets=targets or [self.HOST],
            include=["zone_transfer"],
            enforce_scope=enforce_scope,
            module_config={"zone_transfer": cfg},
        )

    async def _names(self, scan_id: int) -> set[str]:
        rows, _ = await self.storage.events(scan_id, limit=2000, event_type="DNS_NAME")
        return {r["data"] for r in rows}

    async def test_successful_transfer_yields_every_in_scope_name(self) -> None:
        with patch_xfr(
            servers=["ns1.example.com"],
            zone=["a.example.com.", "b.example.com.", "example.com."],
        ):
            scanner, _ = await self._scan()

        got = await self._names(scanner.scan_id)
        # 根本身要排除掉（它已经是 SEED 了）
        self.assertEqual(got, {"a.example.com", "b.example.com"})

        findings = await self.storage.findings(scanner.scan_id)
        kinds = [f["kind"] for f in findings]
        self.assertIn("zone_transfer", kinds)
        finding = next(f for f in findings if f["kind"] == "zone_transfer")
        self.assertEqual(finding["severity"], "high")
        self.assertIn("2 条记录", finding["detail"])

    async def test_refused_transfer_is_silent_and_not_a_finding(self) -> None:
        """被拒是**常态** —— 不允许传送不是发现，不该进 findings。"""
        with patch_xfr(
            servers=["ns1.example.com"],
            refused=["203.0.113.1"],
        ):
            scanner, _ = await self._scan()

        self.assertEqual(await self._names(scanner.scan_id), set())
        findings = await self.storage.findings(scanner.scan_id)
        self.assertEqual([f["kind"] for f in findings], [])

    async def test_names_outside_the_target_are_dropped(self) -> None:
        """区域里混进域外的名字（委派、CNAME 落域外）不能当成子域。

        ⚠️ **必须关掉引擎的范围闸门**（``enforce_scope=False``）。开着的时候
        域外的名字会被 ``Scanner.in_scope`` 挡掉，于是这条用例即使**模块自己
        的过滤被整行删掉也照样是绿的** —— 它钉的是引擎那道闸，不是本模块的。
        关掉之后，模块里那两行 ``is_subdomain_of`` 才是唯一防线。
        """
        with patch_xfr(
            servers=["ns1.example.com"],
            zone=["a.example.com.", "evil.other.org.", "x.com."],
        ):
            scanner, _ = await self._scan(enforce_scope=False)

        self.assertEqual(await self._names(scanner.scan_id), {"a.example.com"})

    async def test_ns_outside_the_target_is_not_an_authoritative_server(self) -> None:
        """NS 落在目标之下才是它的权威 NS；域外的是委派，不能去撞。"""
        with patch_xfr(
            servers=["ns1.other.org."],
            addrs=["203.0.113.9"],
            zone=["a.example.com."],
        ):
            scanner, _ = await self._scan(enforce_scope=False)

        # 域外 NS 被剔除 → 拿不到可用服务器 → 一条都不发，也没有 finding
        self.assertEqual(await self._names(scanner.scan_id), set())
        findings = await self.storage.findings(scanner.scan_id)
        self.assertEqual([f["kind"] for f in findings], [])

    async def test_max_names_truncates_and_is_counted(self) -> None:
        """区域有几万条是常事，不设上限就是拿事件预算换一份名单。"""
        zone = [f"h{i}.example.com." for i in range(50)]
        with patch_xfr(servers=["ns1.example.com"], zone=zone):
            scanner, _ = await self._scan(max_names=10)

        self.assertEqual(len(await self._names(scanner.scan_id)), 10)

    async def test_no_ns_is_quietly_skipped(self) -> None:
        """拿不到 NS 是常态（有些域不给外网查 NS），不该报错。"""
        with patch_xfr(servers=[]):
            scanner, summary = await self._scan()

        self.assertEqual(await self._names(scanner.scan_id), set())
        self.assertIn("zone_transfer", summary["modules_enabled"])
        self.assertEqual(
            [f["kind"] for f in await self.storage.findings(scanner.scan_id)], []
        )

    async def test_module_is_active_and_safe(self) -> None:
        """它是 ``active, safe``：会发真实 DNS 查询，但只有几次。"""
        from core.domains.resolve.zone_transfer import zone_transfer as zt

        self.assertEqual(set(zt.flags), {"active", "safe"})
        self.assertTrue(zt.per_domain_only)

    async def test_duplicate_targets_do_not_trigger_a_second_transfer(self) -> None:
        """重复目标只探一次。

        ⚠️ 注意去重发生在**引擎层**（`Event.key()` 按 ``(type, data)``），
        比模块的 ``per_domain_only`` 门闩更早 —— 所以这里观察不到
        ``module.*.skipped``，该看的是"传送只发生了一次"。
        """
        with patch_xfr(
            servers=["ns1.example.com"], zone=["a.example.com."]
        ):
            scanner, summary = await self._scan(targets=[self.HOST, self.HOST])

        self.assertGreaterEqual(summary["events_deduped"], 1, "重复目标没被去重")
        findings = await self.storage.findings(scanner.scan_id)
        transfer = [f for f in findings if f["kind"] == "zone_transfer"]
        self.assertEqual(len(transfer), 1, f"传送发生了 {len(transfer)} 次")


if __name__ == "__main__":
    unittest.main()
