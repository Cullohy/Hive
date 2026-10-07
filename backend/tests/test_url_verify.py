"""``url_verify`` 的判据层测试 —— 不发网络请求。

要钉的四件事，每一件都对应一种"会把不该验的验了 / 该验的没验"：

1. **已经验过的 URL 不重复验** —— http_probe 发的那对孪生兄弟带 ``status``
2. **.js 不碰** —— 那是 js_assets 的活，重复验证只是白花请求
3. **范围外的 URL 不碰** —— 引擎的 in_scope 只管 DNS_NAME，URL 事件不过闸
4. **同名 URL 在并发下只入队一次** —— 先占位再 await
"""
from __future__ import annotations

import unittest

from core.domains.web_hunter._lib.urlverify import VerifiedPath
from core.domains.web_hunter.url_verify import url_verify
from core.engine.event import Event, EventType


class _Scanner:
    def __init__(self, targets=("example.com",)) -> None:
        self.targets = list(targets)
        self.state = None

    def root_domain_of(self, d: str) -> str | None:
        d = (d or "").strip().lower().rstrip(".")
        for t in self.targets:
            if d == t or d.endswith("." + t):
                return t
        return None


def build(**cfg) -> tuple[url_verify, dict]:
    m = url_verify.__new__(url_verify)
    m.config = dict(cfg)
    m.name = "url_verify"
    # ⚠️ ``scanner`` 是**只读属性**（基类刻意如此，子类一覆盖就启动即报错），
    # 所以必须设底层那个 ``_engine``。直接 ``m.scanner = ...`` 会抛
    # AttributeError —— 那是基类设计，不是本模块的问题。
    m._engine = cfg.pop("_scanner", _Scanner())
    m._seen = set()
    m._per_host = {}
    m._total = 0
    m.max_per_host = cfg.get("max_per_host", 40)
    m.max_total = cfg.get("max_total", 2000)
    m.waf_entries = []          # 关掉 WAF 闸门，聚焦其它判据
    m.waf_min_confidence = "medium"
    m.stats = {"urls_seen": 0, "queued": 0, "verified": 0, "exists": 0,
               "noise": 0, "waf_skipped": 0}
    m.verifier = _Recorder()
    m.log = type("L", (), {"info": lambda *a, **k: None,
                           "debug": lambda *a, **k: None})()
    return m, {}


class _Recorder:
    """替掉真 Verifier：只记录"被叫去验了什么"，不发请求。

    返回值必须是真的 :class:`VerifiedPath` —— 模块按契约读 ``.exists``，
    这里用"判成不存在"让 ``handle_event`` 在那里收手，后面的发事件逻辑
    由 :class:`TestUrlVerifyEmission` 单独覆盖。
    """

    def __init__(self) -> None:
        self.seen: list[tuple[str, str]] = []

    async def profile(self, origin: str):
        return object()

    async def verify_one(self, origin: str, path: str, *, profile=None,
                         directory: str = ""):
        self.seen.append((origin, path))
        return VerifiedPath(url=origin + path, path=path, exists=False)

    async def verify_many(self, *a, **k):
        return []


def url_event(u: str, **tags) -> Event:
    return Event(type=EventType.URL, data=u, module="url_extract", tags=tags)


async def dispatch(m: url_verify, event: Event) -> bool:
    """按**引擎真实的顺序**送一个事件：先闸门，通过了才进 ``handle_event``。

    直接调 ``handle_event`` 是绕过引擎的 —— 那样测不到预算闸门，而闸门恰恰
    是 2026-10-07 那个「4630 条把扫描堵住」的修复所在。
    """
    if not m.should_run_on(event):
        return False
    await m.handle_event(event)
    return True


class TestUrlVerifyGates(unittest.IsolatedAsyncioTestCase):

    async def test_in_scope_link_is_queued(self) -> None:
        m, _ = build()
        await dispatch(m, url_event("https://www.example.com/onepage/request-demo"))
        self.assertEqual(m.verifier.seen, [("https://www.example.com",
                                            "/onepage/request-demo")])
        self.assertEqual(m.stats["queued"], 1)

    async def test_out_of_scope_link_is_skipped(self) -> None:
        """外链必须挡掉 —— 引擎的 in_scope 只看 DNS_NAME，URL 事件不过闸。"""
        m, _ = build()
        await dispatch(m, url_event("https://cdn.othersite.com/lib/a.js".replace(".js", ".css"))
        )
        await dispatch(m, url_event("https://www.google-analytics.com/x"))
        self.assertEqual(m.verifier.seen, [], "范围外的 URL 被拿去验证了")
        self.assertEqual(m.stats["queued"], 0)

    async def test_already_verified_url_is_skipped(self) -> None:
        """``status`` 已经在 tags 里 = http_probe 探活时验过了，不重复。"""
        m, _ = build()
        await dispatch(m, url_event("https://www.example.com/a", status=200, ip="1.2.3.4"))
        self.assertEqual(m.verifier.seen, [])
        self.assertEqual(m.stats["queued"], 0)

    async def test_js_is_left_to_js_assets(self) -> None:
        m, _ = build()
        await dispatch(m, url_event("https://www.example.com/public/lib/jquery.js"))
        self.assertEqual(m.verifier.seen, [], ".js 被重复验证了")

    async def test_duplicate_url_is_claimed_once(self) -> None:
        """先占位再 await —— 同一条 URL 重复到达只验一次。"""
        m, _ = build()
        e = url_event("https://www.example.com/x")
        await dispatch(m, e)
        await dispatch(m, e)
        self.assertEqual(m.verifier.seen, [("https://www.example.com", "/x")])
        self.assertEqual(m.stats["queued"], 1)

    async def test_non_http_scheme_is_ignored(self) -> None:
        m, _ = build()
        for u in ("ftp://example.com/x", "javascript:void(0)", "not a url"):
            await dispatch(m, url_event(u))
        self.assertEqual(m.verifier.seen, [])

    async def test_per_host_budget(self) -> None:
        m, _ = build(max_per_host=2)
        for i in range(5):
            await dispatch(m, url_event(f"https://www.example.com/p{i}"))
        self.assertEqual(len(m.verifier.seen), 2)

    async def test_total_budget(self) -> None:
        m, _ = build(max_per_host=10, max_total=3)
        for i in range(8):
            await dispatch(m, url_event(f"https://h{i}.example.com/p"))
        self.assertEqual(len(m.verifier.seen), 3)

    async def test_directory_is_passed_for_per_directory_baseline(self) -> None:
        """有的站点按目录返回不同的错误页，所以要带上目录。"""
        m, _ = build()
        await dispatch(m, url_event("https://www.example.com/onepage/request-demo"))
        self.assertEqual(m._directory("/onepage/request-demo"), "/onepage")
        self.assertEqual(m._directory("/"), "")


class TestUrlVerifyEmission(unittest.IsolatedAsyncioTestCase):
    """确认存在的 URL 要发 HTTP_RESPONSE，且**不带易失标签**。"""

    async def test_hit_emits_response_without_volatile_tags(self) -> None:
        m, _ = build()
        sent: list[tuple] = []

        async def emit_event(data, etype, *, parent=None, tags=None):
            sent.append((str(etype), data, dict(tags or {})))

        m.emit_event = emit_event

        class _R:
            status = 200
            url = "https://www.example.com/onepage/demo"
            orig_status = 200
            history = []
            text = "<html><head><title>  申请演示  </title></head></html>"
            headers = {"content-type": "text/html", "server": "nginx/1.20"}

        class _V:
            async def profile(self, o): return object()
            async def verify_one(self, *a, **k):
                return type("V", (), {"exists": True, "status": 200,
                                      "is_auth_wall": False,
                                      "response": _R()})()

        m.verifier = _V()
        await dispatch(m, url_event("https://www.example.com/onepage/demo"))
        kinds = [s[0] for s in sent]
        self.assertIn(EventType.HTTP_RESPONSE, kinds)
        self.assertIn(EventType.URL, kinds)

        tags = next(s[2] for s in sent if s[0] == EventType.HTTP_RESPONSE)
        self.assertEqual(tags["status"], 200)
        self.assertEqual(tags["title"], "申请演示", "标题里的标签与空白没剥")
        self.assertEqual(tags["server"], "nginx/1.20")
        # 易失标签绝不能带：带上等于让 url_extract / fingerprint
        # 在这两条上各再跑一遍，事件量翻倍
        for volatile in ("headers", "body_snippet"):
            self.assertNotIn(
                volatile, tags,
                f"HTTP_RESPONSE 带了易失标签 {volatile} —— "
                f"会触发下游重跑，事件量翻倍",
            )


class TestUrlVerifyGate(unittest.IsolatedAsyncioTestCase):
    """**预算必须在闸门上卡，不能只在 ``handle_event`` 里。**

    ## 这个 bug 的形状（2026-10-07 实跑抓到的）

    预算原本写在 ``handle_event`` 开头：「超预算就 return」。看着对，但
    **事件早就被引擎塞进本模块的队列、早就计入 ``pending`` 了** ——
    你只是不去碰它，队列并不会因此变短。

    实跑 ``yealink.com.cn``：产出 4630 条 URL，本模块**逐条串行**发请求
    （1~2 秒一个），``pending`` 只增不减，界面上就是卡死 —— 要跑一两个小时。

    闸门 ``should_run_on`` 在**扇出之前**判，被拒的事件压根不进队列。
    ``dir_brute`` 当年为同一个问题声明了 ``workers = 3``；这里是同一个坑的
    另一面 —— 那一面只能靠闸门解决，加 worker 没用。
    """

    def _m(self, **cfg) -> url_verify:
        m, _ = build(**cfg)
        return m

    def test_gate_rejects_over_total_budget(self) -> None:
        m = self._m(max_total=2)
        ev = url_event("https://www.example.com/a")
        self.assertTrue(m.should_run_on(ev), "预算内不该被拒")
        m._total = 2
        self.assertFalse(
            m.should_run_on(url_event("https://www.example.com/b")),
            "超预算的事件仍被放行 —— 它会进队列并计入 pending",
        )

    def test_gate_rejects_per_host_over_budget(self) -> None:
        m = self._m(max_per_host=1)
        self.assertTrue(m.should_run_on(url_event("https://www.example.com/a")))
        self.assertFalse(m.should_run_on(url_event("https://www.example.com/b")))
        # 另一台主机不受影响
        self.assertTrue(m.should_run_on(url_event("https://h2.example.com/a")))

    def test_gate_rejects_the_cheap_filters_too(self) -> None:
        """形状类的筛选也是不花流量的判断，没理由为它们排队。"""
        m = self._m()
        for u, why in (
            ("ftp://example.com/x", "非 http(s)"),
            ("https://cdn.othersite.com/x", "范围外"),
        ):
            self.assertFalse(m.should_run_on(url_event(u)), why)

    def test_gate_counts_what_it_rejected(self) -> None:
        m = self._m(max_total=1)
        m.should_run_on(url_event("https://www.example.com/a"))
        m._total = 1
        m.should_run_on(url_event("https://www.example.com/b"))
        self.assertEqual(m.stats.get("over_budget"), 1,
                         "被闸门挡下的要计数，否则界面上查不出为什么没产出")


if __name__ == "__main__":
    unittest.main()
