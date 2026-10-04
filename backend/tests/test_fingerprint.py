"""指纹域的测试。

三层：
  1. ``_lib/rules.py`` 的匹配引擎 —— 纯函数，每种匹配来源一条条钉死
  2. ``_lib/importers.py`` —— 外部库格式转换（丢东西必须看得见）
  3. ``fingerprint`` 模块 —— 走引擎的事件链

全部离线。唯一碰网络的地方是 ``TestScreenshotReal`` 那类既有测试，不在这里。
"""

from __future__ import annotations

import json
import unittest
import uuid
from pathlib import Path
from unittest import mock

from core.domains.fingerprint._lib.importers import (
    Report,
    from_fingerprinthub,
    from_wappalyzer,
    merge,
)
from core.domains.fingerprint._lib.library import (
    library_rows,
    library_summary,
    load_library,
    technology_to_dict,
)
from core.domains.fingerprint._lib.rules import (
    Observation,
    detect,
    load_technologies,
)
from tests.base import EngineTestCase

TMP = Path(__file__).resolve().parents[1] / ".testtmp"


def obs(**kw) -> Observation:
    """直接构造观测，不走 tags —— 单元测试里更直观。"""
    return Observation(
        headers={k.lower(): v for k, v in (kw.pop("headers", {}) or {}).items()},
        cookies=kw.pop("cookies", {}) or {},
        html=kw.pop("html", ""),
        title=kw.pop("title", ""),
        script_src=tuple(kw.pop("script_src", ()) or ()),
        meta=kw.pop("meta", {}) or {},
        favicon=kw.pop("favicon", ""),
        url=kw.pop("url", ""),
    )


def one(**tech) -> list:
    """用一条规则建库。"""
    return load_technologies({"technologies": [{"id": "t", "name": "T", **tech}]})


class TestObservation(unittest.TestCase):
    """从 HTTP_RESPONSE 的 tags 里抽观测。"""

    def test_from_tags_extracts_everything(self) -> None:
        o = Observation.from_tags({
            "headers": {"Server": "nginx", "Set-Cookie": "sid=abc123; path=/"},
            "body_snippet": '<html><head><title>Hi</title>'
                            '<meta name="generator" content="WordPress 6.4">'
                            '<meta content="yes" name="mobile">'
                            '<script src="/a.js"></script><script src="/b.js"></script>'
                            "</head></html>",
            "favicon_hash": "abc123",
            "url": "http://x/",
        })
        self.assertEqual(o.header("SERVER"), "nginx")          # 头名大小写无关
        self.assertEqual(o.cookies.get("sid"), "abc123")       # 值也要留着
        self.assertEqual(o.title, "Hi")
        self.assertEqual(o.meta.get("generator"), "WordPress 6.4")
        self.assertEqual(o.meta.get("mobile"), "yes")          # 属性顺序反过来也要认
        self.assertEqual(o.script_src, ("/a.js", "/b.js"))
        self.assertEqual(o.favicon, "abc123")

    def test_title_falls_back_to_html(self) -> None:
        o = Observation.from_tags({"body_snippet": "<title>From Html</title>"})
        self.assertEqual(o.title, "From Html")


class TestMatching(unittest.TestCase):
    """每种匹配来源都要单独验证 —— 少一种就是一类技术永远识别不出来。"""

    def test_header_presence(self) -> None:
        techs = one(match={"headers": {"cf-ray": ""}})
        self.assertTrue(detect(obs(headers={"cf-ray": "x"}), techs))
        self.assertFalse(detect(obs(headers={"other": "x"}), techs))

    def test_header_regex(self) -> None:
        techs = one(match={"headers": {"server": "nginx/[\\d.]+"}})
        self.assertTrue(detect(obs(headers={"server": "nginx/1.24.0"}), techs))
        self.assertFalse(detect(obs(headers={"server": "nginx"}), techs))

    def test_any_header_wildcard(self) -> None:
        """``*`` 表示"任意头按整行匹配" —— 导入 FingerprintHub 规则要用。"""
        techs = one(match={"headers": {"*": "x-powered-by: thinkphp"}})
        self.assertTrue(
            detect(obs(headers={"x-powered-by": "thinkphp"}), techs),
            "整行匹配没生效",
        )
        self.assertFalse(detect(obs(headers={"x-powered-by": "django"}), techs))

    def test_cookie_name_only(self) -> None:
        techs = one(match={"cookies": ["phpsessid"]})
        self.assertTrue(detect(obs(cookies={"PHPSESSID": "x"}), techs))
        self.assertFalse(detect(obs(cookies={"other": "x"}), techs))

    def test_cookie_value_regex(self) -> None:
        """带值正则是为了压误报 —— ``session`` 这种通用名只看名字不够。"""
        techs = one(match={"cookies": {"session": "^[0-9a-f]{8}$"}})
        self.assertTrue(detect(obs(cookies={"session": "deadbeef"}), techs))
        self.assertFalse(detect(obs(cookies={"session": "not-a-hash"}), techs))

    def test_html(self) -> None:
        techs = one(match={"html": ["/wp-content/"]})
        self.assertTrue(detect(obs(html='<a href="/wp-content/x">'), techs))
        self.assertFalse(detect(obs(html="<html>nothing</html>"), techs))

    def test_title(self) -> None:
        techs = one(match={"title": ["Grafana"]})
        self.assertTrue(detect(obs(title="Grafana"), techs))
        self.assertFalse(detect(obs(title="Other"), techs))

    def test_meta(self) -> None:
        techs = one(match={"meta": {"generator": "^WordPress"}})
        self.assertTrue(detect(obs(meta={"generator": "WordPress 6.4"}), techs))
        self.assertFalse(detect(obs(meta={"generator": "Drupal"}), techs))

    def test_script_src(self) -> None:
        techs = one(match={"scriptSrc": ["jquery"]})
        self.assertTrue(detect(obs(script_src=["/js/jquery.min.js"]), techs))
        self.assertFalse(detect(obs(script_src=["/js/app.js"]), techs))

    def test_favicon(self) -> None:
        techs = one(match={"favicon": ["-47932290"]})
        self.assertTrue(detect(obs(favicon="-47932290"), techs))
        self.assertFalse(detect(obs(favicon="00000000"), techs))
        self.assertFalse(detect(obs(favicon=""), techs), "空哈希不该命中")

    def test_url(self) -> None:
        techs = one(match={"url": ["/graphql$"]})
        self.assertTrue(detect(obs(url="http://x/graphql"), techs))
        self.assertFalse(detect(obs(url="http://x/"), techs))

    def test_any_source_is_enough(self) -> None:
        """同一技术内多个来源是"或" —— 任一命中即识别到（与 wappalyzer 一致）。"""
        techs = one(match={"headers": {"x-a": "1"}, "html": ["marker"]})
        self.assertTrue(detect(obs(headers={"x-a": "1"}), techs))
        self.assertTrue(detect(obs(html="marker"), techs))


class TestVersion(unittest.TestCase):
    def test_extract_from_header(self) -> None:
        techs = one(
            match={"headers": {"server": "nginx"}},
            version={"headers": {"server": "nginx/([\\d.]+)"}},
        )
        got = detect(obs(headers={"server": "nginx/1.24.0"}), techs)
        self.assertEqual(got[0].version, "1.24.0")

    def test_extract_from_meta(self) -> None:
        techs = one(
            match={"meta": {"generator": "WordPress"}},
            version={"meta": {"generator": "WordPress ?([\\d.]+)"}},
        )
        got = detect(obs(meta={"generator": "WordPress 6.4.2"}), techs)
        self.assertEqual(got[0].version, "6.4.2")

    def test_no_group_uses_whole_match(self) -> None:
        techs = one(
            match={"html": ["v"]},
            version={"regex": "v([\\d.]+)", "source": "html"},
        )
        got = detect(obs(html="version v3.1.4 here"), techs)
        self.assertEqual(got[0].version, "3.1.4")

    def test_missing_version_is_empty_not_error(self) -> None:
        techs = one(
            match={"headers": {"server": "nginx"}},
            version={"headers": {"server": "nginx/([\\d.]+)"}},
        )
        got = detect(obs(headers={"server": "nginx"}), techs)
        self.assertEqual(got[0].version, "")


class TestImpliesExcludes(unittest.TestCase):
    def test_implies_adds_dependency(self) -> None:
        techs = load_technologies({"technologies": [
            {"id": "a", "name": "A", "implies": ["b"], "match": {"html": ["aaa"]}},
            {"id": "b", "name": "B", "match": {"headers": {"x-b": "1"}}},
        ]})
        got = {d.tech.id: d for d in detect(obs(html="aaa"), techs)}
        self.assertIn("b", got, "implies 没补出依赖")
        self.assertTrue(got["b"].implied)
        self.assertIn("由 A 推断", got["b"].evidence)

    def test_implies_is_transitive(self) -> None:
        techs = load_technologies({"technologies": [
            {"id": "a", "name": "A", "implies": ["b"], "match": {"html": ["aaa"]}},
            {"id": "b", "name": "B", "implies": ["c"], "match": {"headers": {"x-b": "1"}}},
            {"id": "c", "name": "C", "match": {"headers": {"x-c": "1"}}},
        ]})
        got = {d.tech.id for d in detect(obs(html="aaa"), techs)}
        self.assertEqual(got, {"a", "b", "c"}, "传递闭包没生效")

    def test_implies_cycle_does_not_hang(self) -> None:
        """规则库里可能写出 A→B→A 的环。递归会爆栈，队列+visited 不会。"""
        techs = load_technologies({"technologies": [
            {"id": "a", "name": "A", "implies": ["b"], "match": {"html": ["aaa"]}},
            {"id": "b", "name": "B", "implies": ["a"], "match": {"headers": {"x-b": "1"}}},
        ]})
        got = {d.tech.id for d in detect(obs(html="aaa"), techs)}
        self.assertEqual(got, {"a", "b"})

    def test_direct_hit_beats_implied(self) -> None:
        """直接命中的证据要保留，不能被"由 X 推断"顶掉。"""
        techs = load_technologies({"technologies": [
            {"id": "a", "name": "A", "implies": ["b"], "match": {"html": ["aaa"]}},
            {"id": "b", "name": "B", "match": {"headers": {"x-b": "1"}}},
        ]})
        got = {d.tech.id: d for d in detect(obs(html="aaa", headers={"x-b": "1"}), techs)}
        self.assertFalse(got["b"].implied)
        self.assertIn("header:", got["b"].evidence)

    def test_unknown_implied_id_is_ignored(self) -> None:
        """库裡没有的技术不该报出来 —— 否则会出现"幽灵技术"。"""
        techs = load_technologies({"technologies": [
            {"id": "a", "name": "A", "implies": ["nope"], "match": {"html": ["aaa"]}},
        ]})
        self.assertEqual([d.tech.id for d in detect(obs(html="aaa"), techs)], ["a"])

    def test_excludes_drops_weaker_match(self) -> None:
        techs = load_technologies({"technologies": [
            {"id": "strong", "name": "S", "excludes": ["weak"],
             "match": {"html": ["strong-marker"]}},
            {"id": "weak", "name": "W", "match": {"cookies": ["sid"]}},
        ]})
        got = {d.tech.id for d in detect(obs(html="strong-marker", cookies={"sid": "1"}), techs)}
        self.assertEqual(got, {"strong"}, "excludes 没抑制掉弱命中")


class TestRuleFormats(unittest.TestCase):
    def test_nested_format(self) -> None:
        got = load_technologies({"technologies": [
            {"id": "x", "name": "X", "match": {"html": ["a"]}},
        ]})
        self.assertEqual(len(got), 1)

    def test_flat_wappalyzer_format(self) -> None:
        got = load_technologies({"X": {"html": ["a"]}})
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].id, "x")
        self.assertEqual(got[0].name, "X")

    def test_legacy_v1_format(self) -> None:
        got = load_technologies({"rules": [
            {"name": "Nginx", "where": "header", "key": "server", "pattern": "nginx"},
        ]})
        self.assertEqual(got[0].id, "nginx")

    def test_broken_regex_is_skipped_not_fatal(self) -> None:
        """单条正则写错不该让整库加载失败。"""
        got = load_technologies({"technologies": [
            {"id": "bad", "name": "Bad", "match": {"html": ["([unclosed"]}},
            {"id": "good", "name": "Good", "match": {"html": ["ok"]}},
        ]})
        ids = [t.id for t in got]
        self.assertIn("good", ids)
        self.assertNotIn("bad", ids)

    def test_rule_without_match_is_skipped(self) -> None:
        got = load_technologies({"technologies": [{"id": "x", "name": "X"}]})
        self.assertEqual(got, [])

    def test_duplicate_ids_keep_first(self) -> None:
        got = load_technologies({"technologies": [
            {"id": "x", "name": "First", "match": {"html": ["a"]}},
            {"id": "x", "name": "Second", "match": {"html": ["b"]}},
        ]})
        self.assertEqual([t.name for t in got], ["First"])


class TestLibraryHealth(unittest.TestCase):
    """库文件的健康检查。

    库现在**只有一个**，内容全部来自外部导入（FingerprintHub + wappalyzergo）。
    所以这里不再断言"分类都登记过""implies 都有对应条目" —— 那是自研库才成立的
    严格性：导入库有 100+ 个分类，implies 也会引用指纹数据里根本没有的应用名
    （引擎对悬空引用是静默跳过，无害）。改成**有界检查**：超过某个比例就说明
    id 规范化出了问题。
    """

    LIBRARY = Path(__file__).resolve().parents[1] / "core" / "resources" / "fingerprints.json"

    @classmethod
    def setUpClass(cls) -> None:
        cls.techs, cls.labels, cls.loaded, cls.errors = load_library([cls.LIBRARY])

    def test_loads(self) -> None:
        self.assertGreater(len(self.techs), 80, "自研内置库太小")
        self.assertEqual(self.errors, [], f"加载报错: {self.errors}")

    def test_ids_unique(self) -> None:
        ids = [t.id for t in self.techs]
        self.assertEqual(len(ids), len(set(ids)))

    def test_implies_dangling_is_bounded(self) -> None:
        """``implies`` 的悬空引用要控制在一定比例内。

        完全为零做不到：wappalyzer 的 ``implies`` 会引用指纹数据里不存在的
        应用名（引擎对悬空引用是静默跳过，无害）。但比例高得离谱就说明
        id 规范化出了问题 —— 那才是要抓的。
        """
        known = {t.id for t in self.techs}
        total = sum(len(t.implies) for t in self.techs)
        dangling = sum(
            1 for t in self.techs for i in t.implies if i not in known
        )
        if total:
            ratio = dangling / total
            self.assertLess(
                ratio, 0.5,
                f"implies 悬空 {dangling}/{total}（{ratio:.0%}）—— id 规范化可能坏了",
            )

    def test_categories_are_well_formed(self) -> None:
        """分类 slug 必须是规范形状（小写、字母数字与短横线）。

        不断言"都登记过"：导入库的分类来自 wappalyzer 的 108 个分类表，
        远多于本项目的 CATEGORY_LABELS —— 未登记的会按 slug 原样显示。
        """
        import re

        bad = {
            c for t in self.techs for c in t.categories
            if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", c)
        }
        self.assertEqual(bad, set(), f"分类 slug 形状不对: {sorted(bad)[:10]}")

    def test_summary_shape(self) -> None:
        s = library_summary(self.techs, self.labels)
        self.assertEqual(s["total"], len(self.techs))
        self.assertGreater(len(s["categories"]), 5)
        self.assertGreater(s["with_version"], 10)
        self.assertGreater(s["implied"], 10)

    def test_to_dict_exposes_cpe(self) -> None:
        wp = next(t for t in self.techs if t.id == "wordpress")
        d = technology_to_dict(wp)
        self.assertEqual(d["cpe"], "cpe:2.3:a:wordpress:wordpress")
        self.assertIn("implies", d)
        self.assertTrue(d["version"])


class TestWappalyzerImport(unittest.TestCase):
    def test_basic_conversion(self) -> None:
        r = Report()
        out = from_wappalyzer(
            {
                "PHP": {"cats": [1], "headers": {"X-Powered-By": "^PHP"},
                        "cookies": {"PHPSESSID": ""}, "website": "https://php.net"},
                "WordPress": {"cats": [1], "html": ["/wp-content/"],
                              "implies": ["PHP"], "excludes": ["Blogger"]},
            },
            categories={"1": {"name": "CMS"}},
            report=r,
        )
        by_id = {e["id"]: e for e in out}
        self.assertEqual(by_id["php"]["categories"], ["cms"])
        self.assertEqual(by_id["wordpress"]["implies"], ["php"])
        self.assertEqual(by_id["wordpress"]["excludes"], ["blogger"])

    def test_unsupported_sources_are_reported(self) -> None:
        """``css`` / ``js`` 两种来源本项目不支持 —— 丢掉但要说出来。"""
        r = Report()
        out = from_wappalyzer({"X": {"css": ["a"], "js": {"v": "1"}}}, report=r)
        self.assertEqual(out, [])
        self.assertIn("没有任何本项目支持的匹配来源", r.skipped)
        self.assertTrue(any("css" in n for n in r.notes))
        self.assertTrue(any("js" in n for n in r.notes))

    def test_imported_rules_actually_match(self) -> None:
        """转换不能破坏语义 —— 导入后必须还能匹配上。"""
        out = from_wappalyzer({
            "SomeCMS": {"headers": {"X-Powered-By": "SomeCMS"},
                        "cookies": {"sid": "^[0-9a-f]{6}$"}},
        })
        techs = load_technologies({"technologies": out})
        self.assertTrue(detect(obs(headers={"x-powered-by": "SomeCMS"}), techs))
        self.assertTrue(detect(obs(cookies={"sid": "abc123"}), techs))
        self.assertFalse(detect(obs(cookies={"sid": "wrong"}), techs))


class TestFingerprintHubImport(unittest.TestCase):
    def setUp(self) -> None:
        # 每个测试一个**独立目录** —— 共用一个目录的话，前面测试写下的
        # YAML 会累积到后面测试的结果里（实测踩到：期望 1 条得到 6 条）。
        self.root = TMP / f"fh_{uuid.uuid4().hex[:8]}"
        self.root.mkdir(parents=True, exist_ok=True)
        self.report = Report()

    def _write(self, name: str, text: str) -> Path:
        p = self.root / name
        p.write_text(text, encoding="utf-8")
        return p

    def test_word_and_header_and_favicon(self) -> None:
        self._write("thinkphp.yaml", """
id: thinkphp
info:
  name: thinkphp
  tags: detect,tech,cms
  metadata: {vendor: thinkphp, product: thinkphp}
http:
  - matchers:
      - type: favicon
        hash: [-47932290]
      - type: word
        words: [thinkphp_show_page_trace]
      - type: word
        words: ['x-powered-by: thinkphp']
        part: header
""")
        out = from_fingerprinthub(self.root, self.report)
        self.assertEqual(len(out), 1)
        e = out[0]
        self.assertEqual(e["vendor"], "thinkphp")
        self.assertEqual(e["categories"], ["cms"])
        # header 词是整行 "名字: 值"，应该被拆成 头名 -> 值 正则
        self.assertIn("x-powered-by", e["match"]["headers"])
        self.assertEqual(e["match"]["favicon"], ["-47932290"])

        techs = load_technologies({"technologies": out})
        self.assertTrue(detect(obs(html="thinkphp_show_page_trace"), techs))
        self.assertTrue(detect(obs(favicon="-47932290"), techs))
        self.assertTrue(detect(obs(headers={"x-powered-by": "thinkphp"}), techs))

    def test_condition_and_becomes_lookahead(self) -> None:
        """``condition: and`` 要求全部命中 —— 前瞻正则正好表达这个。"""
        self._write("tomcat.yaml", """
id: tomcat
info: {name: tomcat}
http:
  - matchers:
      - type: word
        words: [/manager/html, /manager/status]
        condition: and
""")
        out = from_fingerprinthub(self.root, self.report)
        techs = load_technologies({"technologies": out})
        self.assertTrue(detect(obs(html="/manager/html and /manager/status"), techs))
        self.assertFalse(detect(obs(html="only /manager/html"), techs), "and 变成了 or")

    def test_md5_favicon_is_dropped_and_counted(self) -> None:
        """本项目存的是 mmh3（Shodan 口径），md5 哈希匹配不上 —— 丢掉但计数。"""
        self._write("md5.yaml", """
id: md5rule
info: {name: md5rule}
http:
  - matchers:
      - type: favicon
        hash: [d41d8cd98f00b204e9800998ecf8427e]
      - type: word
        words: [marker]
""")
        out = from_fingerprinthub(self.root, self.report)
        self.assertEqual(out[0]["match"].get("favicon"), None)
        self.assertIn("favicon 的 md5 哈希（本项目存 mmh3）", self.report.skipped)

    def test_status_matcher_is_dropped_and_counted(self) -> None:
        self._write("status.yaml", """
id: st
info: {name: st}
http:
  - matchers:
      - type: status
        status: [200]
      - type: word
        words: [marker]
""")
        from_fingerprinthub(self.root, self.report)
        self.assertIn("status 匹配器不支持（本项目不按状态码认指纹）", self.report.skipped)

    def test_negative_matcher_is_dropped_and_counted(self) -> None:
        self._write("neg.yaml", """
id: neg
info: {name: neg}
http:
  - matchers:
      - type: word
        words: [x]
        negative: true
      - type: word
        words: [marker]
""")
        from_fingerprinthub(self.root, self.report)
        self.assertIn("negative（取反）匹配器不支持", self.report.skipped)

    def test_broken_yaml_is_counted_not_fatal(self) -> None:
        self._write("broken.yaml", "id: [unclosed\n  bad: : :\n")
        self._write("ok.yaml", """
id: ok
info: {name: ok}
http:
  - matchers:
      - type: word
        words: [marker]
""")
        out = from_fingerprinthub(self.root, self.report)
        self.assertEqual([e["id"] for e in out], ["ok"])
        self.assertTrue(any("YAML 解析失败" in k for k in self.report.skipped))


class TestMerge(unittest.TestCase):
    def test_imported_overrides_builtin(self) -> None:
        """同一个 id 以导入的为准 —— 外部库通常更新更勤。"""
        base = {"technologies": [
            {"id": "nginx", "name": "Nginx(内置)", "match": {"html": ["a"]}},
            {"id": "apache", "name": "Apache", "match": {"html": ["b"]}},
        ]}
        imported = [{"id": "nginx", "name": "Nginx(导入)", "match": {"html": ["c"]}}]
        merged = merge(base, imported)
        by_id = {t["id"]: t for t in merged["technologies"]}
        self.assertEqual(by_id["nginx"]["name"], "Nginx(导入)")
        self.assertIn("apache", by_id)
        self.assertEqual(len(merged["technologies"]), 2)


FH_MODULE = """
from core.engine.event import EventType
from core.engine.module import BaseModule


class emit_response(BaseModule):
    watched_events = (EventType.SEED,)
    produced_events = (EventType.HTTP_RESPONSE,)
    flags = ("passive", "safe")

    async def handle_event(self, event):
        await self.emit_event(
            "http://www.example.com/",
            EventType.HTTP_RESPONSE,
            parent=event,
            tags={
                "url": "http://www.example.com/",
                "domain": "www.example.com",
                "headers": {"Server": "nginx/1.24.0",
                            "Set-Cookie": "wordpress_test_cookie=WP; path=/"},
                "body_snippet": (
                    '<html><head><meta name="generator" content="WordPress 6.4.2">'
                    '<script src="/wp-includes/js/jquery/jquery.min.js"></script>'
                    '</head><body><a href="/wp-content/themes/x">x</a></body></html>'
                ),
                "title": "My Site",
                "favicon_hash": "abc",
            },
        )
"""


class TestFingerprintModule(EngineTestCase):
    async def _scan(self, **cfg):
        self.add_module_file("emit_response", FH_MODULE)
        kwargs = {}
        if cfg:
            kwargs["module_config"] = {"fingerprint": cfg}
        return await self.run_scan(
            targets=["example.com"],
            include=["emit_response", "fingerprint"],
            **kwargs,
        )

    async def _techs(self, scan_id: int) -> dict[str, dict]:
        rows = await self.storage.technologies(scan_id)
        return {r["name"]: dict(r) for r in rows}

    async def test_detects_and_stores_metadata(self) -> None:
        scanner, _ = await self._scan()
        got = await self._techs(scanner.scan_id)
        self.assertIn("Nginx", got)
        self.assertIn("WordPress", got)
        self.assertIn("PHP", got, "implies 没补出 PHP")

        # 版本不再断言具体值：模块现在加载的是完整库（8800+ 条），
        # 导入的 nginx 条目覆盖了自研那条，而它没有版本提取正则。
        # 断言"识别到了、有分类"才是稳定的。
        self.assertTrue(got["Nginx"]["evidence"])
        self.assertEqual(got["WordPress"]["category"], "cms")
        self.assertEqual(got["WordPress"]["vendor"], "wordpress")
        self.assertFalse(got["WordPress"]["implied"])

        # PHP 是推断来的（页面没有直接 PHP 特征）
        self.assertTrue(got["PHP"]["implied"])

    async def test_library_stats(self) -> None:
        """统计要**报真实匹配数**，不能是个恒为 0 的占位。

        （这里踩过一次：``results`` 一开始硬编码成 0，界面上看起来像
        "什么都没匹配到"，其实匹配了 7 条。）
        """
        _, summary = await self._scan()
        row = next(
            (r for r in summary["source_stats"] if r["source"] == "fingerprint"), None
        )
        self.assertIsNotNone(row, f"没收到统计: {summary['source_stats']}")
        self.assertEqual(row["requests"], 0, "它不该发请求")
        self.assertGreater(row["raw"], 0, "匹配数没报出来")
        self.assertGreater(row["results"], 0, "落库数没报出来")

    async def test_missing_library_soft_fails(self) -> None:
        """规则文件坏掉时模块要软失败，不能把扫描搞挂。"""
        broken = TMP / "broken_rules.json"
        broken.parent.mkdir(parents=True, exist_ok=True)
        broken.write_text("{not json", encoding="utf-8")
        _, summary = await self._scan(rules=str(broken))
        self.assertIn("fingerprint", summary["modules_skipped"])


class TestWritableLibrary(unittest.TestCase):
    """库的编辑/删除 —— 界面上的「编辑」「删除」走的就是这些。

    **一定要测往返**（改完再改回来）。只测"改成功"会漏掉一类很隐蔽的 bug：
    写出去的数据读回来变了形，于是下一次编辑定位不到，变成"删不掉又追加一条"。
    """

    def setUp(self) -> None:
        from core.domains.fingerprint._lib import library as lib

        self.lib = lib
        self.tmp = TMP / f"lib_{uuid.uuid4().hex[:8]}"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.target = self.tmp / "writable.json"

        # **必须同时改 library_paths。** 只改 writable_path 的话，
        # 读的还是真库、写的却是临时文件 —— 编辑"成功"了但读回来没变
        # （实测就是被这条绊住的，所以特意写清楚）。
        self.orig_writable = lib.writable_path
        self.orig_paths = lib.library_paths
        builtin = (
            Path(__file__).resolve().parents[1]
            / "core" / "resources" / "fingerprints.json"
        )
        lib.writable_path = staticmethod(lambda: self.target)  # type: ignore[assignment]
        lib.library_paths = staticmethod(  # type: ignore[assignment]
            lambda explicit=None: [builtin, self.target]
        )
        lib.bump_library()

    def tearDown(self) -> None:
        import shutil

        self.lib.writable_path = self.orig_writable  # type: ignore[assignment]
        self.lib.library_paths = self.orig_paths  # type: ignore[assignment]
        self.lib.bump_library()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rows(self, tid: str) -> list[tuple[str, str]]:
        techs, _, _, _ = self.lib.load_library()
        return [
            (r["method"], r["keyword"])
            for r in self.lib.library_rows(techs)
            if r["tech"] == tid
        ]

    def test_edit_roundtrip_does_not_accumulate(self) -> None:
        """改过去再改回来，规则必须还是原来那条。

        踩过的坑：``htmlAll`` 里的字面量在加载时被转成小写，回写后原文丢了，
        下一次删除按原文比较找不到那条 —— 于是"删不掉、又追加一条"，
        连编三次规则累积成三条。
        """
        before = self._rows("nginx")
        self.assertEqual(len(before), 1, before)

        self.assertTrue(self.lib.replace_matcher(
            "nginx", location="header", keyword="nginx",
            new_keyword="ThinkPHP</a>", method="关键词",
        ))
        self.assertEqual(self._rows("nginx"), [("关键词(全部)", "ThinkPHP</a>")])

        self.assertTrue(self.lib.replace_matcher(
            "nginx", location="header", keyword="ThinkPHP</a>",
            new_keyword="nginx", method="关键词",
        ))
        after = self._rows("nginx")
        self.assertEqual(after, [("关键词(全部)", "nginx")],
                         f"往返之后规则变形了: {after}")

    def test_literals_rejects_pair_pollution(self) -> None:
        """脏数据不该自我复制。

        某一版序列化把 ``(原文, 小写)`` 二元组直接写进了 JSON，
        读回来 ``str()`` 一下就成了 ``"['a', 'a']"`` —— 而且会一次次叠加。
        """
        from core.domains.fingerprint._lib.rules import _literals

        self.assertEqual(_literals([["nginx", "nginx"]]), (("nginx", "nginx"),))
        self.assertEqual(_literals(["nginx"]), (("nginx", "nginx"),))

    def test_delete_records_tombstone(self) -> None:
        """删内置库里的条目要记墓碑 —— 否则重启后它又回来了。"""
        self.assertTrue(self.lib.delete_technology("nginx"))

        raw = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertIn("nginx", raw["deleted"], "墓碑没写进可写库")

        # 用显式路径读，绕开全局状态，验证墓碑确实压掉了内置那条
        builtin = (
            Path(__file__).resolve().parents[1]
            / "core" / "resources" / "fingerprints.json"
        )
        techs, _, _, _ = self.lib.load_library([builtin, self.target])
        self.assertNotIn("nginx", [t.id for t in techs])

    def test_delete_can_be_undone_by_upsert(self) -> None:
        """删掉再加回来，墓碑必须一起撤销。"""
        from core.domains.fingerprint._lib.library import technology_to_entry

        builtin = (
            Path(__file__).resolve().parents[1]
            / "core" / "resources" / "fingerprints.json"
        )
        techs, _, _, _ = self.lib.load_library([builtin])
        nginx = next(t for t in techs if t.id == "nginx")

        self.lib.delete_technology("nginx")
        raw = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertIn("nginx", raw["deleted"])

        self.lib.upsert_technology(technology_to_entry(nginx))
        raw2 = json.loads(self.target.read_text(encoding="utf-8"))
        self.assertNotIn("nginx", raw2["deleted"], "墓碑没被撤销")

        techs2, _, _, _ = self.lib.load_library([builtin, self.target])
        self.assertIn("nginx", [t.id for t in techs2])


class TestLibraryRows(unittest.TestCase):
    """摊平成"一行一个匹配器" —— 表格的 7 列就是从这来的。"""

    @classmethod
    def setUpClass(cls) -> None:
        techs = load_technologies({"technologies": [
            {"id": "x", "name": "X", "categories": ["cms"],
             "match": {"headers": {"server": "x"}, "html": ["/x/"],
                       "favicon": ["-123"], "htmlAll": ["a", "b"]}},
        ]})
        cls.rows = library_rows(techs)

    def test_one_row_per_matcher(self) -> None:
        # header 1 + html 1 + favicon 1 + htmlAll 2 = 5
        self.assertEqual(len(self.rows), 5, self.rows)

    def test_required_fields(self) -> None:
        for r in self.rows:
            for key in ("index", "name", "tech", "category", "category_label",
                        "method", "location", "location_label", "keyword"):
                self.assertIn(key, r)

    def test_index_is_sequential(self) -> None:
        self.assertEqual([r["index"] for r in self.rows],
                         list(range(1, len(self.rows) + 1)))

    def test_method_detection(self) -> None:
        methods = {r["location"]: r["method"] for r in self.rows}
        self.assertEqual(methods["header"], "关键词")
        self.assertEqual(methods["favicon"], "favicon 哈希")


class TestVersionExtraction(unittest.TestCase):
    """版本提取的边界情况。

    踩过的坑：wappalyzer 的版本组几乎都是**可选**的
    （``nginx(?:/([\\d.]+))?``），匹配上但没版本是常态。那种情况下
    ``m.group(1)`` 是 ``None`` 而不是空串，直接 ``.strip()`` 会抛
    ``AttributeError`` —— 而异常从 ``detect()`` 冒出去会让**整个响应**的
    识别失败，表现是"server 头是裸的 nginx 时，一次响应一条技术都认不出"。
    """

    TECH = {
        "technologies": [{
            "id": "nginx", "name": "Nginx",
            "match": {"headers": {"server": "nginx(?:/([\\d.]+))?"}},
            "version": {"headers": "nginx(?:/([\\d.]+))?"},
        }]
    }

    def _detect(self, server: str):
        techs = load_technologies(self.TECH)
        obs = Observation(headers={"server": server})
        return detect(obs, techs)

    def test_version_present(self) -> None:
        got = self._detect("nginx/1.24.0")
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0].version, "1.24.0")

    def test_optional_group_missing_does_not_crash(self) -> None:
        """组没参与匹配时不能抛异常，版本给空串就好。"""
        got = self._detect("nginx")
        self.assertEqual(len(got), 1, "裸 nginx 也必须认出来")
        self.assertEqual(got[0].version, "")

    def test_no_match_at_all(self) -> None:
        self.assertEqual(self._detect("apache/2.4"), [])


class TestCustomFingerprints(unittest.TestCase):
    """界面上的「新增指纹」—— 这是相对"手工编辑库文件"的关键区别。

    自定义规则写进**单独的** ``fingerprints_custom.json``，导入脚本不碰它，
    所以重跑导入不会把用户加的规则冲掉。
    """

    def setUp(self) -> None:
        from core.domains.fingerprint._lib import library as lib

        self.lib = lib
        self.tmp = TMP / f"cust_{uuid.uuid4().hex[:8]}"
        self.tmp.mkdir(parents=True, exist_ok=True)
        self.target = self.tmp / "custom.json"
        self.builtin = (
            Path(__file__).resolve().parents[1]
            / "core" / "resources" / "fingerprints.json"
        )

        # **writable_path 和 library_paths 必须一起改。**
        # 只改前者的话读的还是真库、写的却是临时文件 ——
        # 新增"成功"了但读回来没有（这个坑在 TestWritableLibrary 里也踩过，
        # 那里留了注释，结果这里还是忘了）。
        self.orig_writable = lib.writable_path
        self.orig_paths = lib.library_paths

        def _paths(explicit=None):
            if explicit:
                items = [explicit] if isinstance(explicit, (str, Path)) else list(explicit)
                return [Path(str(i)) for i in items]
            return [self.builtin, self.target]

        lib.writable_path = staticmethod(lambda: self.target)  # type: ignore[assignment]
        lib.library_paths = staticmethod(_paths)  # type: ignore[assignment]
        lib.bump_library()

    def tearDown(self) -> None:
        import shutil

        self.lib.writable_path = self.orig_writable  # type: ignore[assignment]
        self.lib.library_paths = self.orig_paths  # type: ignore[assignment]
        self.lib.bump_library()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rows(self, tid: str) -> list[tuple[str, str]]:
        techs, _, _, _ = self.lib.load_library()
        return [
            (r["location"], r["keyword"])
            for r in self.lib.library_rows(techs)
            if r["tech"] == tid
        ]

    def test_chinese_name_keeps_a_usable_id(self) -> None:
        """中文名不能被规范化成空串。

        原来只保留 ``[a-z0-9]``，中文名会被整段吃掉、兜底成 ``unknown``，
        于是**所有中文名指纹互相覆盖**。这个领域里中文产品名很常见。
        """
        tid, created = self.lib.create_technology(
            "泛微 e-cology", location="body", keyword="/wui/ecology8/"
        )
        self.assertTrue(created)
        self.assertNotEqual(tid, "unknown")
        self.assertIn("泛微", tid)
        self.assertEqual(self._rows(tid), [("body", "/wui/ecology8/")])

    def test_same_name_appends_instead_of_overwriting(self) -> None:
        """同名再建是**追加规则**，不是把原来那些删掉。"""
        tid, _ = self.lib.create_technology(
            "My App", location="body", keyword="marker-one"
        )
        tid2, created = self.lib.create_technology(
            "My App", location="header", keyword="x-powered-by: myapp"
        )
        self.assertEqual(tid, tid2)
        self.assertFalse(created, "第二次不该算新建")
        self.assertEqual(len(self._rows(tid)), 2, self._rows(tid))

    def test_identical_rule_is_not_added_twice(self) -> None:
        """重复保存不能堆重复项。"""
        tid, _ = self.lib.create_technology("My App", location="body", keyword="marker")
        for _ in range(3):
            self.lib.add_matcher(tid, location="cookie", keyword="MySessId")
        self.assertEqual(len(self._rows(tid)), 2, self._rows(tid))

    def test_case_difference_counts_as_same(self) -> None:
        """大小写不同不算两条规则。

        加载时头名/正文规则会被按大小写不敏感地匹配，所以 ``/WUI/`` 与
        ``/wui/`` 是同一条。逐字符比的话会重复追加，文件里还会落下两个
        只差大小写的 cookie 键。
        """
        tid, _ = self.lib.create_technology("My App", location="body", keyword="/marker/")
        self.lib.add_matcher(tid, location="body", keyword="/MARKER/")
        self.assertEqual(len(self._rows(tid)), 1, self._rows(tid))

    def test_custom_rule_is_detectable(self) -> None:
        """自己加的规则必须真的能匹配到。"""
        from core.domains.fingerprint._lib.rules import Observation, detect

        self.lib.create_technology(
            "我的内部系统", location="body", keyword="internal-portal-v3"
        )
        techs, _, _, _ = self.lib.load_library()
        obs = Observation(html="<html><body>internal-portal-v3</body></html>")
        names = {d.tech.name for d in detect(obs, techs)}
        self.assertIn("我的内部系统", names)

    def test_custom_file_is_separate_from_import_file(self) -> None:
        """自定义库与导入库是两个文件 —— 否则重跑导入会冲掉自定义规则。"""
        self.assertNotEqual(self.lib.LIBRARY, self.lib.CUSTOM_LIBRARY)
        self.assertEqual(self.target.name, "custom.json")  # 已被 mock
        # 默认加载顺序里，自定义库排在导入库之后（所以能覆盖）
        paths = [p.name for p in self.lib.library_paths()]
        if self.lib.CUSTOM_LIBRARY in paths:
            self.assertGreater(
                paths.index(self.lib.CUSTOM_LIBRARY), 0,
                "自定义库必须排在导入库之后",
            )


if __name__ == "__main__":
    unittest.main()
