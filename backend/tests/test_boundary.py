"""平台宪法：三条"不做"必须是**能跑的断言**，不能只写在设计文档里。

设计文档 §1.2 说这三条 **「不是"暂时不做"，是"永远不做"」**，§1.4 要求
**「写进 preset 闸门、写进 CI 断言测试、写进代码评审清单」**。

这个文件负责中间那一样。它拦的是两类东西：

1. **声明了 ``verify`` flag 的模块** —— 那是"我要对资产做漏洞验证"的自认。
   闸门在 ``preset.PLATFORM_DENY_FLAGS``，这里验它**逃不掉**。
2. **名字带 PoC/利用前缀的模块** —— 有人可能忘了打 flag，但很难把文件命名成
   ``sqli_scanner.py`` 还说自己不是漏洞扫描器。

## 为什么这件事值得单独一个测试文件

平台的全部身份就建立在这三条上。前两道闸门（规则闸门、披露闸门）已经有人
在守；**第三道如果只靠"代码评审时的自觉"，它就不是闸门，是口号。**

> 这里刻意**不**检查"有没有正则抓敏感信息" —— 那个没有可靠的静态判据
> （正则本身是中性工具，抓路径和抓密钥用的是同一个机制）。它靠的是
> 模块边界的书面界定（见 ``urls/__init__.py`` 与 ``dir_brute`` 的文档），
> 不是断言。**断言不出来就别假装断言了** —— 一条会误报的 CI 很快就会被
> 加 ``skip``，那比没有更糟。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.engine.module import (  # noqa: E402
    FLAG_VERIFY,
    FORBIDDEN_MODULE_PREFIXES,
    VALID_FLAGS,
    BaseModule,
    validate_flags,
)
from core.engine.preset import PLATFORM_DENY_FLAGS, Preset  # noqa: E402
from core.engine.scanner import Scanner  # noqa: E402


def _all_builtin_module_classes() -> dict[str, type]:
    """拿到**全部**内置模块类，**绕过预设闸门**。

    ⚠ 刻意不用 ``scanner.modules`` —— 那是"闸门放行之后"的结果。而
    ``verify`` 模块**正是会被闸门挡掉的那一批**，用放行后的结果去枚举
    "有没有 verify 模块"，等于先把要抓的东西过滤掉再去找它。
    （这个错误我第一版就犯了，被 ``test_module_loads_but_preset_denies_it``
    暴露出来：合成模块明明被发现了，却没出现在 ``modules`` 里。）
    """
    import importlib

    from core.engine.scanner import DEFAULT_MODULE_PACKAGE

    preset = Preset(name="discover")
    preset.include = None
    preset.exclude = []
    scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
    pkg = importlib.import_module(DEFAULT_MODULE_PACKAGE)
    return dict(scanner._collect_from_package(pkg))


class TestPlatformConstitution(unittest.TestCase):
    def test_verify_flag_is_registered(self) -> None:
        """``verify`` 必须在合法 flag 词汇表里。

        否则两种坏结果二选一：要么有人加了这个 flag 时 ``validate_flags()``
        直接抛异常（模块加载失败，看起来像 bug），要么它被当成未知 flag
        静默忽略（闸门失效）。**必须先能声明，才谈得上拦截。**
        """
        self.assertIn(FLAG_VERIFY, VALID_FLAGS)
        self.assertEqual(FLAG_VERIFY, "verify")

    def test_platform_deny_is_not_empty(self) -> None:
        """宪法不能是空集合 —— 那等于没配。"""
        self.assertIn(FLAG_VERIFY, PLATFORM_DENY_FLAGS)

    def test_no_builtin_module_declares_verify(self) -> None:
        """当前没有任何内置模块声明 ``verify``。

        这条挂了说明有人真的加了漏洞验证模块 —— **别急着删它**，
        先去看那个模块是干什么的。
        """
        offenders = [
            name for name, cls in _all_builtin_module_classes().items()
            if FLAG_VERIFY in cls.flags
        ]
        self.assertEqual(offenders, [], f"这些模块自认会做漏洞验证: {offenders}")

    def test_no_module_name_uses_a_forbidden_prefix(self) -> None:
        """模块名不许带 PoC / 利用类前缀。

        与 flag 是两道独立闸门：flag 管"声明的能力"，名字管"搬进来的东西"。
        """
        offenders = [
            name for name in _all_builtin_module_classes()
            if name.lower().startswith(FORBIDDEN_MODULE_PREFIXES)
        ]
        self.assertEqual(
            offenders, [],
            f"模块名踩了禁用前缀 {FORBIDDEN_MODULE_PREFIXES}: {offenders}",
        )

    def test_no_verify_module_is_enabled_in_any_builtin_preset(self) -> None:
        """**核心断言**：任何内置预设都不许放行 ``verify`` 模块。

        遍历的是"预设认为可用的模块"而不是"所有模块" —— 后者只能证明
        "现在没人这么写"，前者才是"写出来也进不来"。
        """
        for preset_name in Preset.list_builtin():
            with self.subTest(preset=preset_name):
                preset = Preset.load_builtin(preset_name)
                enabled = [
                    name for name, cls in _all_builtin_module_classes().items()
                    if preset.allows(name, cls.flags)
                ]
                offenders = [
                    name for name in enabled
                    if FLAG_VERIFY in _all_builtin_module_classes()[name].flags
                ]
                self.assertEqual(
                    offenders, [],
                    f"预设 {preset_name} 放行了 verify 模块: {offenders}",
                )

    def test_every_builtin_preset_denies_verify(self) -> None:
        """每个内置预设的 ``deny_flags`` 里都得有 ``verify``。

        上面那条测的是"结果"，这条测的是"机制" —— 两条都留着：机制坏了但
        恰好没有 verify 模块时，只有这条会红。
        """
        for preset_name in Preset.list_builtin():
            with self.subTest(preset=preset_name):
                preset = Preset.load_builtin(preset_name)
                self.assertIn(
                    FLAG_VERIFY, preset.deny_flags,
                    f"预设 {preset_name} 的 deny_flags 里没有 verify",
                )

    def test_user_preset_cannot_escape_the_constitution(self) -> None:
        """**用户自己写的预设也逃不掉。**

        这是这个设计里最容易漏的一环：如果只在 ``load_builtin`` 里并入
        deny，那么 ``preset.load(我的.yml)`` 就是一条绕过宪法的后门。
        所以并入点在 ``from_dict`` —— 所有入口共用。
        """
        import tempfile

        path = Path(tempfile.mkdtemp()) / "mine.yml"
        path.write_text(
            "name: mine\ninclude: []\ndeny_flags: []\n", encoding="utf-8"
        )
        preset = Preset.load(path)
        self.assertIn(
            FLAG_VERIFY, preset.deny_flags,
            "自定义预设把平台 deny 挤掉了 —— 宪法有后门",
        )

    def test_platform_deny_merge_is_idempotent(self) -> None:
        """重复并入不能把 deny_flags 撑出重复项。"""
        from core.engine.preset import _with_platform_deny

        once = _with_platform_deny(["heavy"])
        twice = _with_platform_deny(once)
        self.assertEqual(once, twice)
        self.assertEqual(len(twice), len(set(twice)))


class TestVerifyGateActuallyBlocks(unittest.TestCase):
    """造一个**真的声明了 verify** 的模块，验证它进不来。

    前面那些测的是"当前没有 verify 模块"；这条测的是"有的话会被拦住"。
    没有这条，整个文件可能只是"恰好没人这么写"的同义反复。
    """

    SOURCE = '''
from core.engine.event import EventType
from core.engine.module import BaseModule


class verify_poc_scanner(BaseModule):
    """假装自己是个 PoC 扫描器 —— 用来验证闸门真的会拦。"""
    watched_events = (EventType.URL,)
    produced_events = (EventType.FINDING,)
    flags = ("active", "loud", "verify")

    async def handle_event(self, event):
        return None
'''

    def test_module_loads_but_preset_denies_it(self) -> None:
        import tempfile

        root = Path(tempfile.mkdtemp())
        (root / "mods").mkdir()
        (root / "mods" / "verify_poc.py").write_text(self.SOURCE, encoding="utf-8")

        preset = Preset.load_builtin("active")
        scanner = Scanner(targets=["example.com"], preset=preset, storage=None)
        # module_dirs 要**显式传**给 load_modules —— 引擎不会自己去读
        # preset.module_dirs（见 manager.py 的调用点）
        scanner.load_modules([str(root / "mods")])

        # 关键：它**能被发现**（所以不是"文件没被读到"），但**没被启用**。
        # 被拒用的模块落在 skipped_modules 里、带原因 —— 那才是"闸门工作了"
        # 的证据，而不是"闸门根本没看见它"。
        enabled = {n for n, m in scanner.modules.items() if m.enabled}
        self.assertNotIn(
            "verify_poc_scanner", enabled,
            "声明了 verify 的模块居然被启用了 —— 闸门失效",
        )
        self.assertIn(
            "verify_poc_scanner", scanner.skipped_modules,
            "合成模块压根没被发现 —— 那样这个测试什么都没证明",
        )
        self.assertIn(
            "未启用", scanner.skipped_modules["verify_poc_scanner"],
            f"它不是被预设拒用的，而是别的原因: "
            f"{scanner.skipped_modules['verify_poc_scanner']}",
        )

    def test_declaring_verify_is_allowed_by_the_vocabulary(self) -> None:
        """``validate_flags`` 不该因为 ``verify`` 而拒绝加载。

        拒绝加载看起来像"拦住了"，实际是把错误报在了错误的地方：
        模块会整个消失（连统计都没有），而不是"被预设拒用"。
        闸门应该在**预设层**，不在词汇表层。
        """
        cls = type("t", (BaseModule,), {"flags": ("active", FLAG_VERIFY)})
        validate_flags(cls)  # 不该抛

    def test_unknown_flag_still_rejected(self) -> None:
        """词汇表本身仍然严格 —— 别把闸门开成"什么都收"。"""
        cls = type("t", (BaseModule,), {"flags": ("active", "definitely_not_a_flag")})
        with self.assertRaises(ValueError):
            validate_flags(cls)


if __name__ == "__main__":
    unittest.main()
