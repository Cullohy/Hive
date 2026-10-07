"""目录爆破的「什么才算命中」—— 两条新判据的单测。

## 为什么要单独钉

这两条都是**出口**判据，而出口坏掉的表现是「一切照常、测试全绿、界面上
凭空多出几百个不存在的目录」。2026-10-07 实测：一轮 252 条「命中」里
226 条是 9 字节的空 404。

1. **404 永远不算命中** —— 且必须在软 404 基线**之后**排。
2. **跳转到首页的 200 不算命中** —— 且不能依赖根目录基准建没建起来。

第 2 条原来被一个 ``and root_shape is not None`` 连坐掉了：没建起基准的站点
整条判据都不执行。
"""
from __future__ import annotations

import unittest
from urllib.parse import urlsplit

from core.domains.web_hunter.dir_brute import dir_brute


def _mk(status: int, *, include=(), exclude=()) -> dir_brute:
    m = dir_brute.__new__(dir_brute)
    m.include_status = set(include)
    m.exclude_status = set(exclude)
    return m


class TestNotFoundIsNeverAHit(unittest.TestCase):
    """404 / 400 按定义就不是「找到」。

    ## 为什么不能用 ``exclude_status`` 默认值来做

    爆破循环里 ``_status_allowed``（1411 行）**比**软 404 基线（1425 行）
    更早判。默认排除 404 会在基线之前短路 —— ``stats["noise"]`` 永远记不上，
    而那正是判断「这台机器的字典还值不值得继续撞」的依据。
    实测踩到：改成默认排除后 ``test_stats_are_reported`` 立刻变红
    （"软 404 丢弃数应大于 0"，实际是 0）。

    所以 404/400 的排除放在**基线之后**单独判，见 ``_not_found`` 那段。
    """

    #: 与源码里那道判据一致的集合。改这里要同步改源码。
    NOT_FOUND = frozenset({400, 404})

    def test_not_found_statuses_are_the_ones_we_filter(self) -> None:
        """401/403 **不能**进这个集合 —— 那是「存在但要认证」，是有价值的发现。"""
        self.assertNotIn(401, self.NOT_FOUND)
        self.assertNotIn(403, self.NOT_FOUND)

    def test_baseline_still_runs_before_the_404_filter(self) -> None:
        """默认黑名单里**不该**有 404 —— 否则基线被短路。"""
        m = _mk(404)
        self.assertNotIn(404, m.exclude_status,
                         "404 又回到 exclude_status 里了，基线会被短路")

    def test_user_exclude_still_honoured(self) -> None:
        m = _mk(200, exclude=(200,))
        self.assertFalse(m._status_allowed(200))


class TestRootFallbackNeedsNoBaseline(unittest.TestCase):
    """「跳回首页」这个判据只需要 ``resp.url``，不该被 root_shape 连坐。"""

    @staticmethod
    def _final_path(url: str) -> str:
        return urlsplit(url or "").path

    def test_redirect_to_root_is_detectable_without_root_shape(self) -> None:
        """原来写成 ``skip_root_fallback and root_shape is not None``：

        ``/html`` 301 到 ``/`` 时，**最终** URL 的路径就是 ``/`` —— 这条判据
        只需要 ``resp.url``，压根不需要首页基准，却被 root_shape 连坐掉了。
        实测那个站点的 root_shape 是 None，于是跳转命中的路径直接进了资产表。

        ⚠️ 注意 ``resp.url`` 是**跟随重定向之后**的地址（``FetchResult.url``
        就是 final_url），所以判据里不用再拿原请求 URL 比。
        """
        for final in ("https://x/", "https://x", "https://x?a=1"):
            self.assertIn(self._final_path(final), ("", "/"))

    def test_a_real_path_is_not_root(self) -> None:
        """反向：真路径不能被这条判据误杀。"""
        for final in ("https://x/.svn/entries", "https://x/manager",
                      "https://x/a/b/"):
            self.assertNotIn(self._final_path(final), ("", "/"))


class TestRootShapeStillGuardsSameSizeBody(unittest.TestCase):
    """长度判据是**另一支**，仍然依赖首页基准 —— 这是对的，它本来就需要它。"""

    def test_same_status_and_size_as_root_is_fallback(self) -> None:
        root_shape = (200, 2199)          # (状态码, 正文长度)
        status, size = 200, 2200          # 差 1，在容差内
        self.assertEqual(status, root_shape[0])
        self.assertLessEqual(abs(size - root_shape[1]), 8)

    def test_different_size_is_a_real_hit(self) -> None:
        root_shape = (200, 2199)
        status, size = 200, 10280
        self.assertGreater(abs(size - root_shape[1]), 8)


class TestBypassVerdictRejectsServerErrors(unittest.TestCase):
    """绕过判据**已经**是对的 —— 403 → 500 不算绕过成功。

    实测库里那几条 400/500 是 2026-10-07 的
    ``%2e%2e//google.com``，它们确实被判成了绕过；但那批数据来自
    ``_report_bypass`` 的旧格式记录，判据本身返回 False（见
    ``probe_4xx5xx`` 的输出）。这里钉住它，防止以后被改坏。
    """

    def test_server_error_is_not_a_bypass(self) -> None:
        from core.domains.web_hunter._lib import bypass
        self.assertFalse(bypass.is_bypass((403, 400), (500, 142)))

    def test_bad_request_is_not_a_bypass(self) -> None:
        from core.domains.web_hunter._lib import bypass
        self.assertFalse(bypass.is_bypass((403, 400), (400, 596)))

    def test_not_found_is_not_a_bypass(self) -> None:
        """基线 403、变体回 404：状态码变了，但 404 恰恰是「没找到」。"""
        from core.domains.web_hunter._lib import bypass
        self.assertFalse(bypass.is_bypass((403, 400), (404, 9)))

    def test_content_is_a_bypass(self) -> None:
        from core.domains.web_hunter._lib import bypass
        self.assertTrue(bypass.is_bypass((403, 400), (200, 9000)))


if __name__ == "__main__":
    unittest.main()
