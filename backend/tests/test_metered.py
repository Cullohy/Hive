"""**按需启用**消耗额度的源（``metered``）。

## 背景

`passive_fofa` / `passive_quake` / `passive_hunter` 每跑一次就扣真金白银的
查询额度。所以内置预设一律 **deny 掉 ``metered``** —— 不主动勾选就一条请求
都不发。

## 为什么需要一条专门的 ``Preset.enable`` 通道

``include`` 表达不了"默认禁掉、按需加回来"：

    def allows(...):
        if module_name in self.exclude: return False
        if self.include and module_name not in self.include: return False   # 白名单
        ...
        if self.deny_flags and (flags & deny): return False                 # 在 include 之后

* ``include`` 一旦设了就**只跑列出的**（是白名单，不是"额外加这些"）
* ``deny_flags`` 又在 ``include`` **之后**判定 —— 所以 deny 赢

于是加了 ``Preset.enable``：一条明确的"越过 flag 拦截"通道。
优先级顺序即代码顺序：``exclude`` > ``include`` > ``enable`` > flag 规则。

## 这批测试想钉住的三件事

1. **默认不跑**（不勾选时 FOFA 一条请求都不发）
2. **勾了才跑**，而且只跑勾了的那个
3. **测试连接不受影响** —— 它是给"还没启用这些源的人"用的，
   被 metered 挡住就会出现"填完 key 点测试说找不到模块"
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.engine.module import FLAG_METERED  # noqa: E402
from core.engine.preset import Preset  # noqa: E402
from core.domains.subdomain.passive.fofa import passive_fofa  # noqa: E402

# WebTestCase 住在 test_m5 里（不是 base.py）—— 它带着起 Web 应用、
# 临时库、鉴权头那一整套脚手架。
from .test_m5 import WebTestCase  # noqa: E402


class TestPresetEnableChannel(unittest.TestCase):
    """``Preset.enable`` 的优先级语义。"""

    def _preset(self, name: str = "passive") -> Preset:
        return Preset.load_builtin(name)

    def test_builtin_presets_deny_metered(self) -> None:
        """**所有**内置预设都默认拒绝 —— 包括「主动模式」。

        额度不该因为选了"全量"就默认烧起来。
        """
        for name in Preset.list_builtin():
            with self.subTest(preset=name):
                self.assertIn(
                    FLAG_METERED, self._preset(name).deny_flags,
                    f"{name} 没 deny metered —— 会出现「默认就花额度」",
                )

    def test_denied_by_default(self) -> None:
        p = self._preset()
        self.assertFalse(p.allows("passive_fofa", tuple(passive_fofa.flags)))

    def test_enable_grants_it(self) -> None:
        p = self._preset()
        p.enable = ["passive_fofa"]
        self.assertTrue(p.allows("passive_fofa", tuple(passive_fofa.flags)))

    def test_enable_is_per_module(self) -> None:
        """只放行**列出的**那个，不是整类。"""
        p = self._preset()
        p.enable = ["passive_fofa"]
        self.assertTrue(p.allows("passive_fofa", ("passive", "safe", "metered")))
        self.assertFalse(p.allows("passive_quake", ("passive", "safe", "metered")))

    def test_exclude_still_wins(self) -> None:
        """逐模块的显式否决比 enable 更具体，应当赢。"""
        p = self._preset()
        p.enable = ["passive_fofa"]
        p.exclude = ["passive_fofa"]
        self.assertFalse(p.allows("passive_fofa", tuple(passive_fofa.flags)))

    def test_include_whitelist_still_wins(self) -> None:
        """``include`` 是白名单（"只跑这些"），enable 不该把它撑开。"""
        p = self._preset()
        p.include = ["seed_asset"]
        p.enable = ["passive_fofa"]
        self.assertFalse(p.allows("passive_fofa", tuple(passive_fofa.flags)))

    def test_override_form(self) -> None:
        """``enable.<模块>=1`` —— 监控任务只有 overrides 这条路。"""
        p = self._preset()
        p.apply_overrides(["enable.passive_fofa=1"])
        self.assertTrue(p.allows("passive_fofa", tuple(passive_fofa.flags)))
        p.apply_overrides(["enable.passive_fofa=0"])
        self.assertFalse(p.allows("passive_fofa", tuple(passive_fofa.flags)))


class TestMeteredNotRunByDefault(WebTestCase):
    """**核心行为**：不勾选时源不跑、勾选时才跑。

    用 API 层验证 —— 那是用户实际走的路（前端把勾选放进 ``enable_sources``）。
    """

    def _scan(self, body: dict) -> dict:
        # 名称是必填的（见 ScanRequest）；这组用例只关心 metered 勾选，统一补一个
        body.setdefault("name", "计量源测试")
        resp = self.client.post("/api/scans", json=body)
        self.assertIn(resp.status_code, (200, 201), resp.text)
        return resp.json()

    def test_modules_api_exposes_metered_separately(self) -> None:
        """被 metered 挡下的模块要能被前端看到，否则**没有勾选入口**。

        它们不在 ``modules``（那是已启用的列表）里，所以必须单列一份。
        """
        data = self.client.get("/api/modules", params={"preset": "passive"}).json()
        enabled = [m["name"] for m in data["modules"]]
        metered = [m["name"] for m in data.get("metered", [])]
        self.assertNotIn("passive_fofa", enabled, "FOFA 默认不该在启用清单里")
        self.assertIn("passive_fofa", metered, "FOFA 该出现在可勾选清单里")
        self.assertIn("passive_quake", metered)

    def test_enable_sources_is_accepted(self) -> None:
        """接了 ``enable_sources`` 字段，而且不报错。"""
        created = self._scan({
            "targets": ["example.com"], "preset": "passive",
            "enable_sources": ["passive_fofa"],
        })
        self.assertIn("scan_id", created)

    def test_omitting_enable_sources_is_fine(self) -> None:
        created = self._scan({"targets": ["example.com"], "preset": "passive"})
        self.assertIn("scan_id", created)


class TestTestConnectionStillWorks(WebTestCase):
    """**回归测试**：``metered`` 的引入曾把「测试连接」打成 404。

    原因：那个接口用 ``active`` 预设找模块，而 ``active`` 现在 deny 了
    ``metered`` —— 于是"填完 key 点测试"得到「找不到模块 'passive_fofa'」，
    而真正原因跟 key 毫无关系。

    它是给**还没启用**这些源的人用的，所以必须不受额度拦截约束。
    """

    def test_metered_source_can_be_tested(self) -> None:
        resp = self.client.post("/api/sources/passive_fofa/test", json={})
        # 没配 key 时应当是"还没填 API Key"，**不能**是 404
        self.assertNotEqual(resp.status_code, 404,
                            f"测试连接又找不到 metered 模块了: {resp.text[:200]}")
        self.assertEqual(resp.status_code, 200, resp.text)
        self.assertFalse(resp.json()["ok"])
        self.assertIn("API Key", resp.json()["detail"])


if __name__ == "__main__":
    unittest.main()
