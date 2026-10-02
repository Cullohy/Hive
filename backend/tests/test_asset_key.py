"""资产身份函数（``core/util/asset_key.py``）。

这个文件钉的是**跨 scan 去重**的地基。两种写歪的方式都不会报错：

* **写松了**（把大小写也归一化）→ 两条不同的资产被合成一条，信息静默丢失
* **写紧了**（把 query string 算进身份）→ 去重形同虚设，每次扫描都新增一批

所以下面既有"规则本身"的单测，也有**拿真实采集数据当输入**的回归测试
（``TestRealWorldUrls``）—— 后者才是真正防退化的一层。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.util.asset_key import (  # noqa: E402
    dedup_key_for,
    domain_key,
    endpoint_key,
    ip_key,
    normalize_path,
    port_key,
    split_url,
    technology_key,
    url_key,
)


class TestNormalizePath(unittest.TestCase):
    def test_empty_becomes_root(self) -> None:
        self.assertEqual(normalize_path(""), "/")
        self.assertEqual(normalize_path("   "), "/")

    def test_root_stays_root(self) -> None:
        """根路径**不能**被去尾斜杠去掉 —— 那是 ``/`` 不是空。"""
        self.assertEqual(normalize_path("/"), "/")
        self.assertEqual(normalize_path("///"), "/")

    def test_trailing_slash_removed(self) -> None:
        self.assertEqual(normalize_path("/admin/"), "/admin")
        self.assertEqual(normalize_path("/a/b/"), "/a/b")

    def test_query_is_dropped(self) -> None:
        """**这是整套去重的地基。**

        实测 ``forum.panabit.com/search.php`` 有 12 条 URL，参数是搜索词和
        CSRF token（``formhash=62efac51``，**每次会话都变**）。把 query 算进
        身份，定期监控每跑一轮都会"新增"一批资产。
        """
        self.assertEqual(normalize_path("/admin?page=2"), "/admin")
        self.assertEqual(normalize_path("/search.php?mod=forum&srchtxt=AP"), "/search.php")
        self.assertEqual(normalize_path("/invoice?goodsId=0000&orderId="), "/invoice")

    def test_fragment_is_dropped(self) -> None:
        self.assertEqual(normalize_path("/doc#section-3"), "/doc")
        self.assertEqual(normalize_path("/a?b=1#c"), "/a")

    def test_duplicate_slashes_collapsed(self) -> None:
        self.assertEqual(normalize_path("//a///b"), "/a/b")
        self.assertEqual(normalize_path("/a//"), "/a")

    def test_missing_leading_slash_is_added(self) -> None:
        self.assertEqual(normalize_path("admin"), "/admin")

    def test_case_is_preserved(self) -> None:
        """RFC 3986 里路径是 case-sensitive 的 —— ``/Admin`` 与 ``/admin``
        在 Linux 上完全可以是两个资源。

        错合的代价是**永久丢掉一条资产**（而且没人知道丢了）；错分只是多一行。
        """
        self.assertNotEqual(normalize_path("/Admin"), normalize_path("/admin"))
        self.assertEqual(normalize_path("/Admin"), "/Admin")

    def test_percent_encoding_is_preserved(self) -> None:
        """``/a%2Fb`` 解码后是 ``/a/b``，但服务端**未必等价** —— 不解码。"""
        self.assertNotEqual(normalize_path("/a%2Fb"), normalize_path("/a/b"))
        self.assertEqual(normalize_path("/a%2Fb"), "/a%2Fb")

    def test_query_without_path(self) -> None:
        self.assertEqual(normalize_path("?a=1"), "/")


class TestSplitUrl(unittest.TestCase):
    def test_full_url(self) -> None:
        self.assertEqual(
            split_url("https://a.b.com:8443/x/y?z=1#f"),
            ("https", "a.b.com", "/x/y"),
        )

    def test_scheme_and_host_lowercased(self) -> None:
        self.assertEqual(
            split_url("HTTPS://Example.COM/Path"),
            ("https", "example.com", "/Path"),
        )

    def test_userinfo_stripped(self) -> None:
        self.assertEqual(
            split_url("https://user:pw@example.com/a"),
            ("https", "example.com", "/a"),
        )

    def test_bare_path(self) -> None:
        self.assertEqual(split_url("/just/a/path?x=1"), ("", "", "/just/a/path"))
        self.assertEqual(split_url("relative/path"), ("", "", "/relative/path"))

    def test_empty(self) -> None:
        self.assertEqual(split_url(""), ("", "", "/"))

    def test_ipv6_host_is_not_mangled(self) -> None:
        """**回归测试。**

        第一版这里把 ``parts.hostname`` 无条件交给 ``normalize_domain`` ——
        而那个函数会按 ``:`` 切端口（对域名是对的），于是
        ``2001:db8::1`` 被切成 ``2001``。**静默地把 IPv6 资产改成了一个
        完全不存在的地址。**
        """
        self.assertEqual(
            split_url("http://[2001:db8::1]:8080/admin"),
            ("http", "2001:db8::1", "/admin"),
        )
        self.assertEqual(split_url("https://[::1]/a"), ("https", "::1", "/a"))

    def test_no_port_leaks_into_host(self) -> None:
        self.assertEqual(split_url("http://x.com:8080/a")[1], "x.com")


class TestUrlKey(unittest.TestCase):
    def test_http_and_https_are_the_same_asset(self) -> None:
        """http 与 https 是**同一个资源**的两种协议暴露，不是两个资源。

        协议差异不丢 —— 另存 ``schemes TEXT[]``。
        """
        self.assertEqual(url_key("http://x.com/admin"), url_key("https://x.com/admin"))
        self.assertEqual(url_key("http://x.com/admin"), "x.com|/admin")

    def test_query_does_not_split(self) -> None:
        keys = {
            url_key(f"https://forum.panabit.com/search.php?mod=forum&srchtxt={kw}")
            for kw in ("流量控制", "AP", "SD-WAN")
        }
        self.assertEqual(len(keys), 1, f"参数不同不该产生不同身份: {keys}")
        self.assertEqual(keys.pop(), "forum.panabit.com|/search.php")

    def test_case_difference_does_split(self) -> None:
        self.assertNotEqual(url_key("https://x.com/Admin"), url_key("https://x.com/admin"))

    def test_non_default_port_does_split(self) -> None:
        """``:8080`` 上是**另一个服务** —— 不带端口去重会把两条资产合成一条。

        （第一版把端口整个丢了，就是这条测试抓出来的。）
        """
        self.assertNotEqual(url_key("http://x.com:8080/a"), url_key("http://x.com/a"))
        self.assertEqual(url_key("http://x.com:8080/a"), "x.com:8080|/a")

    def test_default_port_does_not_split(self) -> None:
        self.assertEqual(url_key("http://x.com:80/a"), url_key("http://x.com/a"))
        self.assertEqual(url_key("https://x.com:443/a"), url_key("https://x.com/a"))

    def test_ipv6_with_port(self) -> None:
        self.assertEqual(url_key("http://[2001:db8::1]:8080/a"), "2001:db8::1:8080|/a")

    def test_host_case_does_not_split(self) -> None:
        self.assertEqual(url_key("https://X.COM/a"), url_key("https://x.com/a"))

    def test_root_path(self) -> None:
        self.assertEqual(url_key("https://x.com"), "x.com|/")
        self.assertEqual(url_key("https://x.com/"), "x.com|/")
        self.assertEqual(url_key("https://x.com/?a=1"), "x.com|/")


class TestEndpointKey(unittest.TestCase):
    def test_scheme_is_part_of_the_key(self) -> None:
        """``http_endpoint`` 存的是**响应观测**，而 status/title/favicon/截图
        全是 per-scheme 的 —— 合并会丢真实观测。所以这张表与 ``url_key``
        **故意不一致**。
        """
        self.assertNotEqual(
            endpoint_key("http://x.com/admin"), endpoint_key("https://x.com/admin")
        )
        self.assertEqual(endpoint_key("http://x.com/admin"), "http://x.com|/admin")

    def test_this_is_the_deliberate_difference_from_url_key(self) -> None:
        """把这条不一致**写死成断言** —— 免得以后有人"顺手统一"掉。"""
        u, e = "https://x.com/a", "http://x.com/a"
        self.assertEqual(url_key(u), url_key(e), "url 表该合并")
        self.assertNotEqual(endpoint_key(u), endpoint_key(e), "http_endpoint 表该分开")

    def test_default_port_does_not_split(self) -> None:
        self.assertEqual(endpoint_key("http://x.com:80/a"), endpoint_key("http://x.com/a"))
        self.assertEqual(endpoint_key("https://x.com:443/a"), endpoint_key("https://x.com/a"))

    def test_non_default_port_does_split(self) -> None:
        self.assertNotEqual(endpoint_key("http://x.com:8080/a"), endpoint_key("http://x.com/a"))

    def test_query_dropped(self) -> None:
        self.assertEqual(
            endpoint_key("https://x.com/a?token=1"), endpoint_key("https://x.com/a")
        )


class TestDomainAndIpKeys(unittest.TestCase):
    def test_domain_key_normalizes(self) -> None:
        self.assertEqual(domain_key("*.Example.COM."), "example.com")
        self.assertEqual(domain_key(" example.com "), "example.com")
        self.assertEqual(domain_key("a.b.com:8443"), "a.b.com")

    def test_domain_key_strips_invisible(self) -> None:
        """零宽字符是 CT 日志里真实存在的脏数据 —— 不剥掉会产生"看起来一样
        但比不相等"的两条资产。"""
        self.assertEqual(domain_key("exa\u200bmple.com"), "example.com")

    def test_ipv4(self) -> None:
        self.assertEqual(ip_key("1.2.3.4"), "1.2.3.4")

    def test_ipv6_is_compressed(self) -> None:
        """``2001:0db8:0:0:0:0:0:1`` 与 ``2001:db8::1`` 是同一个地址，
        不压缩就会变成两条资产。"""
        self.assertEqual(ip_key("2001:0db8:0:0:0:0:0:1"), "2001:db8::1")
        self.assertEqual(ip_key("2001:db8::1"), "2001:db8::1")
        self.assertEqual(ip_key("[2001:db8::1]"), "2001:db8::1")

    def test_invalid_ip_is_kept_not_dropped(self) -> None:
        """解析不了的原样返回 —— **不能丢数据**（宁可留个不规范的键）。"""
        self.assertEqual(ip_key("not-an-ip"), "not-an-ip")
        self.assertEqual(ip_key(""), "")

    def test_port_key(self) -> None:
        self.assertEqual(port_key("1.2.3.4", 80), "1.2.3.4|80|tcp")
        self.assertEqual(port_key("1.2.3.4", "443", "TCP"), "1.2.3.4|443|tcp")

    def test_technology_key(self) -> None:
        self.assertEqual(technology_key("WWW.X.com", "Nginx"), "www.x.com|Nginx")


class TestDispatch(unittest.TestCase):
    def test_dispatch_by_asset_type(self) -> None:
        self.assertEqual(dedup_key_for("domain", "a.example.com"), "a.example.com")
        self.assertEqual(dedup_key_for("url", "https://x.com/a?b=1"), "x.com|/a")
        self.assertEqual(dedup_key_for("http_endpoint", "https://x.com/a"), "https://x.com|/a")
        self.assertEqual(dedup_key_for("port", "1.2.3.4", port=443), "1.2.3.4|443|tcp")
        self.assertEqual(dedup_key_for("technology", "x.com", name="Nginx"), "x.com|Nginx")

    def test_unknown_type_raises(self) -> None:
        with self.assertRaises(ValueError):
            dedup_key_for("nonsense", "x")

    def test_missing_extra_raises(self) -> None:
        """缺参数**必须炸**，不能猜 —— 猜错会静默产生错误的键。"""
        with self.assertRaises(KeyError):
            dedup_key_for("port", "1.2.3.4")


class TestRealWorldUrls(unittest.TestCase):
    """用**真实采集到的 URL** 当输入 —— 这层才是真正防退化的。

    样本取自本机库里的实际数据（``panabit.com`` / ``chinazy.org`` /
    ``sinosoft.com.cn`` 三次扫描）。
    """

    def test_discuz_search_variants_collapse_to_one(self) -> None:
        """实测：同一个 ``search.php`` 下 12 条 URL，参数是搜索词 + CSRF token。"""
        urls = [
            "http://forum.panabit.com/search.php?mod=forum&amp;srchtxt=%C1%F7%C1%BF%BF%D8%D6%C6"
            "&amp;formhash=62efac51&amp;searchsubmit=true",
            "http://forum.panabit.com/search.php?mod=forum&amp;srchtxt=AP&amp;formhash=62efac51",
            "https://forum.panabit.com/search.php?mod=forum&amp;srchtxt=SD-WAN"
            "&amp;formhash=150ae651&amp;searchsubmit=true",
            "http://forum.panabit.com/search.php?searchsubmit=yes",
            "https://forum.panabit.com/search.php?searchsubmit=yes",
        ]
        keys = {url_key(u) for u in urls}
        self.assertEqual(keys, {"forum.panabit.com|/search.php"}, f"没合并干净: {keys}")

    def test_discuz_thread_urls_collapse(self) -> None:
        urls = [
            "http://forum.panabit.com/forum.php?mod=viewthread&tid=23028&fromuid=264015",
            "http://forum.panabit.com/forum.php?mod=viewthread&tid=3616&fromuid=264015",
            "https://forum.panabit.com/forum.php?mod=guide&amp;view=new",
        ]
        self.assertEqual({url_key(u) for u in urls}, {"forum.panabit.com|/forum.php"})

    def test_versioned_js_collapses(self) -> None:
        """``?v=2017121309`` 是静态资源版本号 —— 同一份文件的不同版本号
        不该算两条资产。"""
        urls = [
            "https://cloud.sinosoft.com.cn/common/js/app.js?v=2017121309",
            "https://cloud.sinosoft.com.cn/common/js/app.js?v=20200815",
            "https://cloud.sinosoft.com.cn/common/js/app.js",
        ]
        self.assertEqual(
            {url_key(u) for u in urls}, {"cloud.sinosoft.com.cn|/common/js/app.js"}
        )

    def test_distinct_paths_stay_distinct(self) -> None:
        """**反面用例**：去重不能把不相关的路径合掉。"""
        urls = [
            "https://cloud.sinosoft.com.cn/customer/project/project-list.js",
            "https://cloud.sinosoft.com.cn/customer/project/project-edit.js",
            "https://cloud.sinosoft.com.cn/customer/order/order-list.js",
        ]
        self.assertEqual(len({url_key(u) for u in urls}), 3)

    def test_http_and_https_variants_merge_in_url_key(self) -> None:
        urls = [
            "http://forum.panabit.com/forum.php",
            "https://forum.panabit.com/forum.php",
        ]
        self.assertEqual(len({url_key(u) for u in urls}), 1)

    def test_same_path_different_host_stays_distinct(self) -> None:
        urls = [
            "https://forum.panabit.com/forum.php",
            "https://bbs.panabit.com/forum.php",
        ]
        self.assertEqual(len({url_key(u) for u in urls}), 2)


if __name__ == "__main__":
    unittest.main()
