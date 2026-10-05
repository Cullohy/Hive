"""配置里的布尔值必须认得 "false" 这一类写法。

## 起因：一个安全闸门会反转

``WebSettings.source_options`` 的值类型是 ``dict[str, dict[str, str]]`` ——
**值一律是字符串**（Web 表单 / `source_options` 那条路）。而模块里普遍写的是
``bool(self.cfg("allow_private", False))``。Python 里非空字符串一律真，于是：

    bool("false")  ->  True

``port_scan.allow_private`` 默认 ``False``，是**拒绝扫内网/保留地址**的闸门。
用户在设置里显式填一个 ``false``，拿到的是 ``True`` ——
**"我明确不要扫内网" 变成了 "要扫内网"**，而且不报任何错。

全仓曾有 32 处这样的写法（``prefer_https`` / ``abort_on_waf`` /
``soft404_simhash`` / ``check_cdn`` / ``allow_private`` …），症状统一是
**在界面上把这个开关关掉，它纹丝不动**。
"""
from __future__ import annotations

import unittest


class TestAsBool(unittest.TestCase):
    def test_false_like_strings_are_false(self) -> None:
        from core.util.coerce import as_bool

        for v in ("false", "False", "FALSE", "  false  ", "0", "no", "off", "n",
                  "f", "否", "关", ""):
            self.assertFalse(as_bool(v, default=True),
                             f"{v!r} 被当成了真 —— 这正是那个闸门反转")

    def test_true_like_strings_are_true(self) -> None:
        from core.util.coerce import as_bool

        for v in ("true", "True", "TRUE", "1", "yes", "on", "y", "t", "是", "开"):
            self.assertTrue(as_bool(v, default=False), f"{v!r} 被当成了假")

    def test_real_bools_pass_through(self) -> None:
        """预设 YAML 里的真布尔、命令行 `-c ...=true` 解析出的 bool，都原样。"""
        from core.util.coerce import as_bool

        self.assertTrue(as_bool(True))
        self.assertFalse(as_bool(False))
        self.assertFalse(as_bool(False, default=True))

    def test_numbers(self) -> None:
        from core.util.coerce import as_bool

        self.assertTrue(as_bool(1))
        self.assertFalse(as_bool(0))
        self.assertTrue(as_bool(2.5))

    def test_garbage_falls_back_to_default_instead_of_guessing(self) -> None:
        """认不出来就回落 default，**不猜** —— 猜错的方向可能不安全。"""
        from core.util.coerce import as_bool

        self.assertFalse(as_bool("garbage", default=False))
        self.assertTrue(as_bool("garbage", default=True))
        self.assertFalse(as_bool(None))
        self.assertTrue(as_bool(None, default=True))


class TestSafetyGateCannotBeInverted(unittest.TestCase):
    """真实模块 + 真实配置形状：闸门不许反转。"""

    @staticmethod
    def _module(cls, config: dict):
        m = cls.__new__(cls)
        m.config = config
        m.name = cls.__name__
        # ``scanner`` 是只读属性（读它取 ``self._engine``），补一个 None 让它可读
        m._engine = None
        return m

    def test_port_scan_allow_private_stays_false(self) -> None:
        from core.domains.web_hunter.port_scan import port_scan

        # 模拟"用户在 web 设置里填了 false"
        m = self._module(port_scan, {"allow_private": "false"})
        from core.util.coerce import as_bool

        self.assertFalse(
            as_bool(m.cfg("allow_private", False)),
            'port_scan 的内网闸门被反转了："false" 变成了 True')

    def test_dns_resolve_check_cdn_can_actually_be_turned_off(self) -> None:
        from core.domains.resolve.dns_resolve import dns_resolve
        from core.util.coerce import as_bool

        m = self._module(dns_resolve, {"check_cdn": "false"})
        self.assertFalse(as_bool(m.cfg("check_cdn", True)),
                         'check_cdn 关不掉 —— 界面上填 false 无效')

    def test_dir_brute_soft404_can_be_turned_off(self) -> None:
        from core.domains.web_hunter.dir_brute import dir_brute
        from core.util.coerce import as_bool

        m = self._module(dir_brute, {"soft404": "false"})
        self.assertFalse(as_bool(m.cfg("soft404", True)),
                         '软 404 过滤关不掉 —— 界面上填 false 无效')


class TestNoBareBoolCfgRemains(unittest.TestCase):
    """回归护栏：别再有人写回 `bool(self.cfg(...))`。

    ⚠️ 判定用**词边界**（前面不能是字母/下划线），否则 ``as_bool(self.cfg(``
    里那个 ``bool(`` 子串会被误判。
    """

    def test_no_module_uses_bare_bool_on_cfg(self) -> None:
        import re
        from pathlib import Path

        import core.domains as domains_pkg

        root = Path(domains_pkg.__file__).parent
        pat = re.compile(r"(?<![_A-Za-z])bool\(\s*self\.cfg\(")
        bad: list[str] = []
        for p in root.rglob("*.py"):
            for i, line in enumerate(
                    p.read_text(encoding="utf-8").splitlines(), 1):
                if pat.search(line):
                    bad.append(f"{p.relative_to(root)}:{i}: {line.strip()}")
        self.assertFalse(
            bad,
            "这些地方又用回 bool(self.cfg(...)) 了 —— 填 \"false\" 会变成 True：\n"
            + "\n".join(bad))
