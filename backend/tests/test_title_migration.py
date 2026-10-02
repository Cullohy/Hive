"""Tests for routing ``<title>``-shaped html patterns to the title dimension.

Five layers:

1. **Criterion** (``title_migration.classify_html_pattern``) -- pure function
2. **Move** (``migrate_html_patterns`` / ``migrate_match_dict``) -- idempotent, lossless
3. **Importer wiring** -- re-import lands in ``title`` too, sharing one criterion
4. **Migration engine** -- a small fixture mirroring the measured shapes, PRE -> POST
5. **Shipped artifact** -- the repo's ``fingerprints.json`` in its post-migration state

Fully offline: no network, and the real library is never modified (all work
happens on copies under ``.testtmp``).

NOTE ON ENCODING: this file is deliberately ASCII-only in its prose. The
Chinese text in this repo has already been mangled once by a PowerShell
``Get-Content | Set-Content`` round-trip (see ``core/storage/postgres.py``),
which is irreversible -- so nothing essential lives in non-ASCII bytes here.
"""

from __future__ import annotations

import json
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core.domains.fingerprint._lib.importers import (  # noqa: E402
    Report,
    from_fingerprinthub_json,
    from_wappalyzer,
)
from core.domains.fingerprint._lib.library import load_library  # noqa: E402
from core.domains.fingerprint._lib.rules import (  # noqa: E402
    Observation,
    detect,
    load_technologies,
)
from core.domains.fingerprint._lib.title_migration import (  # noqa: E402
    KIND_OTHER,
    KIND_PLAIN,
    KIND_STRICT,
    REASON_META_PLAIN,
    REASON_META_STRICT,
    REASON_NOT_CAPTURABLE,
    classify_html_pattern,
    is_literal,
    migrate_html_patterns,
    migrate_match_dict,
)
from scripts.migrate_title_dimension import dedupe_note, migrate_library  # noqa: E402

LIBRARY = ROOT / "core" / "resources" / "fingerprints.json"
TMP = ROOT / ".testtmp"

#: Measured numbers (see the migration report). Changing these means the
#: migration surface changed, which must be deliberate.
EXPECTED_TECHNOLOGIES = 8843
EXPECTED_TITLE_MOVED = 541           # 512 strict + 29 plain moved out of html
EXPECTED_TITLE_PATTERNS_AFTER = 535  # minus 6 absorbed by a broader form
EXPECTED_TITLE_TECHS = 493           # technologies with a title dimension
EXPECTED_HTML_KEPT = 76              # 42 other + 33 plain-meta + 1 strict-meta
EXPECTED_TITLE_PATTERNS_BEFORE = 0
EXPECTED_HTML_PATTERNS_BEFORE = 3311
EXPECTED_HTML_PATTERNS_AFTER = 2770  # 3311 - 541
EXPECTED_HTML_KEYS_AFTER = 2600      # 3014 - 414


class TestCriterion(unittest.TestCase):
    """The criterion itself -- the single source of truth."""

    def test_strict_literal_moves_without_anchor(self):
        """Strict form -> title gets X, with NO anchor (X was followed by .*?)."""
        rule = classify_html_pattern("(?mi)<title[^>]*>tenda 11n.*?</title>")
        self.assertEqual(rule.kind, KIND_STRICT)
        self.assertEqual(rule.literal, "tenda 11n")
        self.assertIsNotNone(rule.pattern)
        assert rule.pattern is not None
        # the space is escaped as a literal, but there must be no ^ or $
        self.assertEqual(rule.pattern, r"tenda\ 11n")
        self.assertFalse(rule.pattern.startswith("^"))
        self.assertFalse(rule.pattern.endswith("$"))

    def test_strict_without_anchor_matches_title_with_site_suffix(self):
        """No anchor is what keeps ``X - Site Name`` style tails matching."""
        techs = load_technologies({"technologies": [{
            "id": "t", "name": "T",
            "match": {"title": [r"tenda\ 11n"]},
        }]})
        det = detect(Observation(title="Tenda 11n - Login"), techs)
        self.assertEqual([d.tech.id for d in det], ["t"])

    def test_plain_literal_moves_with_anchor(self):
        """Plain literal form -> title gets ``^\\s*X\\s*$``, anchored."""
        rule = classify_html_pattern("<title>apache activemq</title>")
        self.assertEqual(rule.kind, KIND_PLAIN)
        self.assertEqual(rule.literal, "apache activemq")
        self.assertEqual(rule.pattern, r"^\s*apache\ activemq\s*$")

    def test_plain_without_anchor_would_over_match(self):
        """The anchor is the whole point: unanchored ``login`` matches way more.

        This test is why this file exists -- it pins "the plain form MUST be
        anchored", which the original analysis missed.
        """
        anchored = load_technologies({"technologies": [{
            "id": "t", "name": "T", "match": {"title": [r"^\s*login\s*$"]},
        }]})
        loose = load_technologies({"technologies": [{
            "id": "t", "name": "T", "match": {"title": [r"login"]},
        }]})

        self.assertEqual(detect(Observation(title="Login"), anchored)[0].tech.id, "t")
        self.assertEqual(detect(Observation(title="  login  "), anchored)[0].tech.id, "t")
        # anchored -> does not match a longer title
        self.assertEqual(detect(Observation(title="Please Login Here"), anchored), [])
        # unanchored -> false positive (exactly what we must avoid)
        self.assertEqual(
            detect(Observation(title="Please Login Here"), loose)[0].tech.id, "t"
        )

    def test_meta_char_literal_not_moved(self):
        """X containing a regex metacharacter is not moved -- semantics would change."""
        strict = classify_html_pattern(
            "(?mi)<title[^>]*>landesk(r) cloud services appliance.*?</title>"
        )
        self.assertIsNone(strict.pattern)
        self.assertEqual(strict.reason, REASON_META_STRICT)

        plain = classify_html_pattern(r"<title>xampp(?: version ([\d\.]+))?</title>")
        self.assertIsNone(plain.pattern)
        self.assertEqual(plain.reason, REASON_META_PLAIN)

    def test_escaped_metachar_not_moved(self):
        """``\\`` is a metacharacter too -- upstream escaped spaces/dashes.

        We deliberately do NOT unescape: ``\\ `` is a literal space and ``\\-``
        a literal dash, but ``\\.`` would become "any character", so
        unescaping silently widens 33 patterns.
        """
        for pattern in (
            r"<title>apache\ activemq</title>",
            r"<title>ip\-guard</title>",
        ):
            with self.subTest(pattern=pattern):
                rule = classify_html_pattern(pattern)
                self.assertIsNone(rule.pattern)
                self.assertEqual(rule.reason, REASON_META_PLAIN)

    def test_multi_branch_not_moved(self):
        """A multi-branch alternation has no single X -- stays in html."""
        rule = classify_html_pattern(
            r"<title>superset</title>|src=\"/static/assets/images/superset\-logo\-"
        )
        self.assertEqual(rule.kind, KIND_OTHER)
        self.assertIsNone(rule.pattern)
        self.assertEqual(rule.reason, REASON_NOT_CAPTURABLE)

    def test_unclosed_title_not_moved(self):
        """``<title>astrbot`` has no closing tag -- not a whole-string shape."""
        rule = classify_html_pattern("<title>astrbot")
        self.assertIsNone(rule.pattern)
        self.assertEqual(rule.reason, REASON_NOT_CAPTURABLE)

    def test_non_title_pattern_has_no_reason(self):
        """Patterns without ``<title`` must not be counted as "left in html"."""
        rule = classify_html_pattern("/wp-content/")
        self.assertIsNone(rule.pattern)
        self.assertIsNone(rule.reason)

    def test_is_literal(self):
        self.assertTrue(is_literal("tenda 11n"))
        self.assertTrue(is_literal("ip-guard"))
        self.assertTrue(is_literal("acmailer4.0"))   # a dot in literal text
        self.assertFalse(is_literal(r"a\ b"))
        self.assertFalse(is_literal("x(?:y)"))
        self.assertFalse(is_literal("a|b"))
        self.assertFalse(is_literal("^anchored$"))


class TestMigratePatterns(unittest.TestCase):
    """The move itself: nothing lost, order kept, idempotent."""

    def test_moves_and_keeps_everything_else(self):
        patterns = [
            "/wp-content/",
            "(?mi)<title[^>]*>tenda 11n.*?</title>",
            "<title>apache activemq</title>",
            r"<title>ip\-guard</title>",                       # escaped -> stays
            "<title>x</title>|other",                          # multi-branch -> stays
        ]
        result = migrate_html_patterns(patterns, tech_id="t")
        self.assertEqual(result.remaining_html, [
            "/wp-content/",
            r"<title>ip\-guard</title>",
            "<title>x</title>|other",
        ])
        self.assertEqual(result.new_titles, [r"tenda\ 11n", r"^\s*apache\ activemq\s*$"])
        self.assertEqual(len(result.moved), 2)
        # a move, not a filter: kept + moved == total
        self.assertEqual(len(result.remaining_html) + len(result.new_titles), len(patterns))

    def test_idempotent_on_pattern_list(self):
        patterns = [
            "/a/",
            "(?mi)<title[^>]*>tenda 11n.*?</title>",
            "<title>b</title>",
        ]
        first = migrate_html_patterns(patterns)
        second = migrate_html_patterns(first.remaining_html)
        self.assertEqual(second.moved, [])
        self.assertEqual(second.new_titles, [])
        self.assertEqual(second.remaining_html, first.remaining_html)

    def test_match_dict_removes_empty_html_key(self):
        """An emptied html key is removed -- no ``"html": []`` noise."""
        match = {"html": ["(?mi)<title[^>]*>only.*?</title>"]}
        migrate_match_dict(match, tech_id="t")
        self.assertNotIn("html", match)
        self.assertEqual(match["title"], ["only"])

    def test_match_dict_keeps_existing_title_and_appends(self):
        match = {"html": ["<title>new</title>"], "title": ["existing"]}
        migrate_match_dict(match, tech_id="t")
        self.assertIn("existing", match["title"])
        self.assertIn(r"^\s*new\s*$", match["title"])

    def test_broader_form_wins_over_anchored_form(self):
        """When both shapes share a literal, the narrower one must not shadow.

        Six technologies in the real library have this shape: harbor /
        jupyterhub / jupyterlab / kibana / mlflow / sonarqube.
        """
        match = {"html": ["<title>harbor</title>", "(?mi)<title[^>]*>harbor.*?</title>"]}
        result = migrate_match_dict(match, tech_id="harbor")
        self.assertEqual(len(result.moved), 2)      # both are moved out of html
        self.assertEqual(result.added, 1)           # only one lands in title
        self.assertEqual(match["title"], ["harbor"])  # the broader one wins
        self.assertNotIn("html", match)

    def test_anchored_kept_when_no_broader_form(self):
        """With no broader form present, the anchored pattern is added normally."""
        match = {"html": ["<title>nacos</title>"]}
        result = migrate_match_dict(match, tech_id="nacos")
        self.assertEqual(result.added, 1)
        self.assertEqual(match["title"], [r"^\s*nacos\s*$"])

    def test_match_dict_is_idempotent(self):
        match = {
            "html": ["/a/", "(?mi)<title[^>]*>x.*?</title>", "<title>y</title>"],
            "title": ["manual"],
        }
        migrate_match_dict(match, tech_id="t")
        snapshot = json.dumps(match, sort_keys=True)
        result = migrate_match_dict(match, tech_id="t")
        self.assertEqual(result.moved, [])
        self.assertEqual(json.dumps(match, sort_keys=True), snapshot)


class TestImporterWiring(unittest.TestCase):
    """A future re-import must classify correctly, sharing the same criterion."""

    def _fh(self, matchers):
        raw = [{
            "id": "demo",
            "info": {"name": "Demo"},
            "http": [{"matchers": matchers}],
        }]
        return from_fingerprinthub_json(raw, Report())

    def test_regex_matcher_title_shape_lands_in_title(self):
        entries = self._fh([{
            "type": "regex",
            "regex": ["(?mi)<title[^>]*>tenda 11n.*?</title>"],
        }])
        match = entries[0]["match"]
        self.assertNotIn("html", match)
        self.assertEqual(match["title"], [r"tenda\ 11n"])

    def test_word_matcher_title_shape_without_spaces_lands_in_title(self):
        """Word matchers escape their words, so use a word without spaces."""
        entries = self._fh([{
            "type": "word",
            "words": ["<title>apacheactivemq</title>"],
        }])
        match = entries[0]["match"]
        self.assertNotIn("html", match)
        self.assertEqual(match["title"], [r"^\s*apacheactivemq\s*$"])

    def test_word_matcher_escaped_space_stays_in_html(self):
        """Measured real shape: the word matcher runs its words through re.escape.

        ``"apache activemq"`` becomes ``apache\\ activemq`` (the space escaped),
        so the whole pattern is ``<title>apache\\ activemq</title>`` -- X contains
        ``\\``, so the criterion conservatively leaves it in html.

        This is deliberate, and it is why 33 plain-shaped patterns do not move:
        unescaping changes semantics, and the migration script and the importer
        must agree on one criterion.
        """
        entries = self._fh([{
            "type": "word",
            "words": ["<title>apache activemq</title>"],
        }])
        match = entries[0]["match"]
        self.assertNotIn("title", match)
        self.assertEqual(match["html"], [r"<title>apache\ activemq</title>"])

    def test_non_title_patterns_stay_in_html(self):
        entries = self._fh([{
            "type": "regex",
            "regex": ["/wp-content/", "(?mi)<title[^>]*>x.*?</title>"],
        }])
        match = entries[0]["match"]
        self.assertEqual(match["html"], ["/wp-content/"])
        self.assertEqual(match["title"], ["x"])

    def test_meta_char_pattern_stays_in_html(self):
        entries = self._fh([{
            "type": "regex",
            "regex": [r"<title>xampp(?: version ([\d\.]+))?</title>"],
        }])
        match = entries[0]["match"]
        self.assertNotIn("title", match)
        self.assertEqual(len(match["html"]), 1)

    def test_html_all_title_literal_lands_in_title(self):
        """``condition: and`` literals are title assertions too."""
        entries = self._fh([{
            "type": "word", "condition": "and",
            "words": ["<title>ambari</title>", "ambari"],
        }])
        match = entries[0]["match"]
        self.assertEqual(match["title"], [r"^\s*ambari\s*$"])
        # htmlAll stores literal substrings; the title one moves, the body one stays
        self.assertEqual(match["htmlAll"], ["ambari"])

    def test_importer_and_migration_share_one_criterion(self):
        """Importer and one-shot migration must agree (two copies would drift)."""
        patterns = [
            "(?mi)<title[^>]*>tenda 11n.*?</title>",
            "<title>apache activemq</title>",
            r"<title>ip\-guard</title>",
            "<title>x</title>|other",
            "/plain/path/",
        ]
        entries = self._fh([{"type": "regex", "regex": patterns}])
        match = entries[0]["match"]

        expected_titles = [
            classify_html_pattern(p).pattern
            for p in patterns
            if classify_html_pattern(p).pattern is not None
        ]
        self.assertEqual(match["title"], expected_titles)
        # what stays must be exactly what the criterion declined to move
        kept = [p for p in patterns if classify_html_pattern(p).pattern is None]
        self.assertEqual(match.get("html", []), kept)

    def test_wappalyzer_html_path_also_normalises(self):
        """The wappalyzer entry point normalises as well."""
        raw = {"apps": {"Demo": {
            "html": ["(?mi)<title[^>]*>demo app.*?</title>", "/demo/"],
        }}}
        entries = from_wappalyzer(raw, report=Report())
        match = entries[0]["match"]
        self.assertEqual(match["title"], [r"demo\ app"])
        self.assertEqual(match["html"], ["/demo/"])

    def test_imported_entry_loads_and_matches(self):
        """After wiring, imported rules must load and actually detect."""
        entries = self._fh([{
            "type": "regex",
            "regex": ["(?mi)<title[^>]*>demo app.*?</title>"],
        }])
        techs = load_technologies({"technologies": entries})
        self.assertEqual(len(techs), 1)
        det = detect(Observation(title="Demo App - Home"), techs)
        self.assertEqual(len(det), 1)
        self.assertIn("title:", det[0].evidence)


class TestDownloadMirror(unittest.TestCase):
    """Download hosts: offline shape checks only, no requests.

    ``raw.githubusercontent.com`` is unreachable from this machine (TLS resets)
    and ``download()`` swallows exceptions and retries 25 times, so the symptom
    is a silent failure.
    """

    def test_all_sources_use_jsdelivr_mirror(self):
        from scripts.import_fingerprints import SOURCES

        for key, spec in SOURCES.items():
            with self.subTest(source=key):
                url = spec["url"]
                self.assertNotIn("raw.githubusercontent.com", url)
                self.assertTrue(
                    url.startswith("https://cdn.jsdelivr.net/gh/"),
                    f"{key} is not on the jsDelivr mirror: {url}",
                )
                # the branch must be in the path, not left implicit
                self.assertIn("@main/", url)
                self.assertTrue(url.endswith(".json"))

    def test_jsdelivr_path_shape_is_valid(self):
        """``/gh/<owner>/<repo>@<branch>/<path>`` -- every part must be present."""
        import re

        from scripts.import_fingerprints import SOURCES

        shape = re.compile(
            r"^https://cdn\.jsdelivr\.net/gh/"
            r"(?P<owner>[^/@]+)/(?P<repo>[^/@]+)@(?P<branch>[^/]+)/(?P<path>.+)$"
        )
        for key, spec in SOURCES.items():
            with self.subTest(source=key):
                m = shape.match(spec["url"])
                self.assertIsNotNone(m, f"{key} mirror URL is malformed: {spec['url']}")
                assert m is not None
                self.assertTrue(m.group("owner"))
                self.assertTrue(m.group("repo"))
                self.assertEqual(m.group("branch"), "main")
                self.assertTrue(m.group("path").endswith(".json"))


#: A small fixture mirroring the real library's measured shapes one-for-one.
#:
#: Real distribution of the 617 patterns: strict literal 512 / strict meta 1 /
#: plain literal 29 / plain meta 33 / other 42.
PRE_FIXTURE: dict = {
    "note": ["imported from external libraries (MIT), not in-house data."],
    "technologies": [
        # strict shape, literal X -> moved, NOT anchored
        {"id": "tenda", "name": "Tenda",
         "match": {"html": ["(?mi)<title[^>]*>tenda 11n.*?</title>"]}},
        {"id": "solar", "name": "Solar",
         "match": {"html": ["(?mi)<title[^>]*>123solar.*?</title>", "/123solar/"]}},
        # plain shape, literal X -> moved, anchored
        {"id": "nacos", "name": "Nacos",
         "match": {"html": ["<title>nacos</title>"]}},
        # both shapes, same literal -> both moved, anchored one absorbed
        {"id": "harbor", "name": "Harbor",
         "match": {"html": ["<title>harbor</title>",
                            "(?mi)<title[^>]*>harbor.*?</title>"]}},
        # strict shape, meta X -> stays
        {"id": "landesk", "name": "Landesk",
         "match": {"html": ["(?mi)<title[^>]*>landesk(r) cloud.*?</title>"]}},
        # plain shape, escaped X -> stays
        {"id": "activemq", "name": "ActiveMQ",
         "match": {"html": [r"<title>apache\ activemq</title>"]}},
        {"id": "ipguard", "name": "IP-Guard",
         "match": {"html": [r"<title>ip\-guard</title>"]}},
        # multi-branch / unclosed -> stays
        {"id": "superset", "name": "Superset",
         "match": {"html": [r"<title>superset</title>|src=\"/static/x"]}},
        {"id": "astrbot", "name": "AstrBot",
         "match": {"html": ["<title>astrbot"]}},
        # no <title at all -> untouched
        {"id": "wp", "name": "WordPress",
         "match": {"html": ["/wp-content/"], "headers": {"x-powered-by": "PHP"}}},
        # pre-existing hand-written title -> kept and appended to
        {"id": "manual", "name": "Manual",
         "match": {"html": ["<title>manualapp</title>"], "title": ["handwritten"]}},
    ],
}

FIXTURE_TECH = 11
FIXTURE_TITLE_SHAPED = 11   # every tech except wp has a <title pattern in html
FIXTURE_TITLES_BEFORE = 1   # manual's hand-written entry
FIXTURE_MOVED = 6           # tenda1 solar1 nacos1 harbor2 manual1
FIXTURE_ADDED = 5           # harbor's anchored one absorbed, so 5 not 6
FIXTURE_HTML_BEFORE = 13
FIXTURE_HTML_AFTER = 7      # 13 - 6


class TestMigrationEngine(unittest.TestCase):
    """Engine layer: PRE fixture -> POST, with before/after counts + idempotence."""

    def _load(self) -> dict:
        return json.loads(json.dumps(PRE_FIXTURE))

    def test_counts_before_and_after(self):
        raw = self._load()
        before_titles = sum(
            len((t.get("match") or {}).get("title") or []) for t in raw["technologies"]
        )
        before_html = sum(
            len((t.get("match") or {}).get("html") or []) for t in raw["technologies"]
        )
        self.assertEqual(before_titles, FIXTURE_TITLES_BEFORE)
        self.assertEqual(before_html, FIXTURE_HTML_BEFORE)

        migrated, stats = migrate_library(raw)
        after = migrated["technologies"]
        after_titles = sum(len((t.get("match") or {}).get("title") or []) for t in after)
        after_html = sum(len((t.get("match") or {}).get("html") or []) for t in after)

        # 1) not one technology lost
        self.assertEqual(len(after), FIXTURE_TECH)
        # 2) title 1 -> 6; six patterns moved (harbor's anchored one absorbed)
        self.assertEqual(stats["moved"], FIXTURE_MOVED)
        self.assertEqual(stats["added"], FIXTURE_ADDED)
        self.assertEqual(after_titles, FIXTURE_TITLES_BEFORE + FIXTURE_ADDED)
        # 3) html drops by exactly the number moved
        self.assertEqual(before_html - after_html, FIXTURE_MOVED)
        self.assertEqual(after_html, FIXTURE_HTML_AFTER)
        # 4) the move invariant
        self.assertEqual(
            stats["moved"] + sum(stats["skipped"].values()),
            stats["title_shaped_total"],
        )
        self.assertEqual(stats["title_shaped_total"], FIXTURE_TITLE_SHAPED)

        # 5) anchored vs not anchored
        by_id = {t["id"]: t["match"] for t in after}
        self.assertEqual(by_id["tenda"]["title"], [r"tenda\ 11n"])       # no anchor
        self.assertEqual(by_id["nacos"]["title"], [r"^\s*nacos\s*$"])    # anchored
        self.assertEqual(by_id["harbor"]["title"], ["harbor"])           # broader wins
        self.assertEqual(by_id["manual"]["title"],
                         ["handwritten", r"^\s*manualapp\s*$"])
        # 6) everything left in html is byte-for-byte untouched
        self.assertEqual(by_id["activemq"]["html"],
                         [r"<title>apache\ activemq</title>"])
        self.assertEqual(by_id["ipguard"]["html"], [r"<title>ip\-guard</title>"])
        self.assertEqual(by_id["landesk"]["html"],
                         ["(?mi)<title[^>]*>landesk(r) cloud.*?</title>"])
        self.assertEqual(by_id["astrbot"]["html"], ["<title>astrbot"])
        self.assertNotIn("title", by_id["astrbot"])
        # 7) patterns without <title are unaffected
        self.assertEqual(by_id["wp"]["html"], ["/wp-content/"])
        self.assertEqual(by_id["wp"]["headers"], {"x-powered-by": "PHP"})

    def test_engine_is_idempotent(self):
        first, _ = migrate_library(self._load())
        text1 = json.dumps(first, ensure_ascii=False, indent=1)
        second, stats2 = migrate_library(json.loads(text1))
        self.assertEqual(stats2["moved"], 0)
        self.assertEqual(json.dumps(second, ensure_ascii=False, indent=1), text1)

    def test_engine_leaves_no_empty_html_arrays(self):
        migrated, _ = migrate_library(self._load())
        for tech in migrated["technologies"]:
            match = tech.get("match") or {}
            if "html" in match:
                self.assertTrue(match["html"], f"{tech['id']} left an empty html array")


class TestShippedLibrary(unittest.TestCase):
    """End to end: pin the repo's ``fingerprints.json`` post-migration state.

    Measured numbers (from the migration script's ``--apply`` output):

    =====================  =========  =========
    item                   before     after
    =====================  =========  =========
    technologies             8843       8843
    title patterns              0        535
    html patterns            3311       2770
    techs with title            0        493
    techs with html          3014       2600
    =====================  =========  =========

    535 rather than 541: of the 541 moved patterns, 6 are absorbed by a broader
    form on the same technology (harbor has both ``<title>harbor</title>`` and
    ``(?mi)<title[^>]*>harbor.*?</title>``; keeping only the narrow one would
    silently miss real titles like ``Harbor - Projects``).

    The shipped file is already migrated, so these assertions verify the
    deliverable itself; the before/after count comparison lives in
    :class:`TestMigrationEngine`, driven by a fixture that mirrors the shapes.
    """

    @classmethod
    def setUpClass(cls):
        TMP.mkdir(parents=True, exist_ok=True)
        cls.work = TMP / "titlemig"
        shutil.rmtree(cls.work, ignore_errors=True)
        cls.work.mkdir(parents=True, exist_ok=True)
        cls.shipped = cls.work / "fingerprints.json"
        shutil.copy2(LIBRARY, cls.shipped)
        cls.text = cls.shipped.read_text(encoding="utf-8")
        cls.raw = json.loads(cls.text)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work, ignore_errors=True)

    @staticmethod
    def _counts(raw: dict) -> dict:
        techs = raw["technologies"]
        return {
            "tech": len(techs),
            "title": sum(len((t.get("match") or {}).get("title") or []) for t in techs),
            "html": sum(len((t.get("match") or {}).get("html") or []) for t in techs),
            "title_shaped": sum(
                1
                for t in techs
                for p in ((t.get("match") or {}).get("html") or [])
                if "<title" in str(p)
            ),
            "title_keys": sum(1 for t in techs if (t.get("match") or {}).get("title")),
            "html_keys": sum(1 for t in techs if (t.get("match") or {}).get("html")),
        }

    def test_shipped_counts(self):
        """Item-by-item numbers; no technology may be lost."""
        got = self._counts(self.raw)
        self.assertEqual(got["tech"], EXPECTED_TECHNOLOGIES)
        self.assertEqual(got["title"], EXPECTED_TITLE_PATTERNS_AFTER)
        self.assertEqual(got["html"], EXPECTED_HTML_PATTERNS_AFTER)
        self.assertEqual(got["title_keys"], EXPECTED_TITLE_TECHS)
        self.assertEqual(got["html_keys"], EXPECTED_HTML_KEYS_AFTER)
        # only the 76 conservatively kept <title patterns remain in html
        self.assertEqual(got["title_shaped"], EXPECTED_HTML_KEPT)

    def test_shipped_is_byte_stable_under_rerun(self):
        """Hard evidence of idempotence: re-running changes not one byte."""
        again, stats = migrate_library(json.loads(self.text))
        self.assertEqual(stats["moved"], 0)
        self.assertEqual(stats["added"], 0)
        self.assertEqual(json.dumps(again, ensure_ascii=False, indent=1), self.text)

    def test_shipped_has_no_empty_match_arrays(self):
        """No ``"html": []`` noise anywhere."""
        for tech in self.raw["technologies"]:
            match = tech.get("match") or {}
            if "html" in match:
                self.assertTrue(match["html"], f"{tech['id']} left an empty html array")
            if "title" in match:
                self.assertTrue(match["title"], f"{tech['id']} left an empty title array")

    def test_note_trace_is_exactly_one_and_idempotent(self):
        """Audit trail: exactly one note, and re-running does not multiply it."""
        note = self.raw["note"]
        hits = [n for n in note if n.startswith("指纹改判:")]
        self.assertEqual(len(hits), 1)
        self.assertIn("title", hits[0])
        self.assertIn("617", hits[0])
        self.assertEqual(dedupe_note(note), note)
        self.assertEqual(migrate_library(json.loads(self.text))[0]["note"], note)

    def test_load_library_on_the_shipped_file(self):
        """``load_library()`` must load it cleanly with matching dimensions."""
        techs, _labels, _loaded, errors = load_library(explicit=[str(self.shipped)])
        self.assertEqual(errors, [])
        self.assertEqual(len(techs), EXPECTED_TECHNOLOGIES)
        self.assertEqual(
            sum(len(t.match.title) for t in techs), EXPECTED_TITLE_PATTERNS_AFTER
        )
        self.assertEqual(
            sum(len(t.match.html) for t in techs), EXPECTED_HTML_PATTERNS_AFTER
        )

    def test_no_migratable_pattern_left_in_html(self):
        """After the migration no migratable shape may remain in html."""
        techs = load_technologies({"technologies": self.raw["technologies"]})
        for tech in techs:
            for rx in tech.match.html:
                self.assertIsNone(
                    classify_html_pattern(rx.pattern).pattern,
                    f"{tech.id} still has a migratable html pattern: {rx.pattern!r}",
                )

    def test_title_dimension_actually_detects(self):
        """The title dimension must not just exist, it must detect."""
        techs = load_technologies({"technologies": self.raw["technologies"]})
        by_id = {t.id: t for t in techs}

        # one of the 512 strict shapes: NOT anchored, so a site suffix still hits
        tenda = by_id["11n-firmware"]
        self.assertTrue(tenda.match.title)
        self.assertEqual(tenda.match.title[0].pattern, r"tenda\ 11n")
        self.assertEqual(
            [d.tech.id for d in
             detect(Observation(title="Tenda 11n Router - Login"), [tenda])],
            ["11n-firmware"],
        )

        # one of the 29 plain shapes: MUST be anchored
        nacos = by_id["alibaba-nacos"]
        self.assertTrue(nacos.match.title)
        self.assertEqual(nacos.match.title[0].pattern, r"^\s*nacos\s*$")
        self.assertEqual(
            [d.tech.id for d in detect(Observation(title="Nacos"), [nacos])],
            ["alibaba-nacos"],
        )
        # anchored, so a longer title must not match
        self.assertEqual(detect(Observation(title="Nacos Console"), [nacos]), [])

        # the 33 escaped-space plain shapes stay in html by design
        amq = by_id["apache-activemq"]
        self.assertFalse(amq.match.title)
        self.assertTrue(any("<title" in p.pattern for p in amq.match.html))

        # both shapes, same literal: the broader one must survive
        harbor = by_id["harbor"]
        self.assertIn("harbor", {p.pattern for p in harbor.match.title})
        self.assertEqual(
            {d.tech.id for d in detect(Observation(title="Harbor - Projects"), [harbor])},
            {"harbor"},
        )
        self.assertEqual(
            {d.tech.id for d in detect(Observation(title="harbor"), [harbor])},
            {"harbor"},
        )


if __name__ == "__main__":
    unittest.main()
