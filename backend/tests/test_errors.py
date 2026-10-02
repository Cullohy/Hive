"""异常描述工具与「日志不能空转」的约束。

起因是一次真实排查：对 qq.com 跑被动收集时日志打出

    passive_crtsh 查询 qq.com 失败:

——冒号后面什么都没有。因为 ``TimeoutError()`` 的 ``str()`` 是空串。
一条不含任何信息的错误日志比不打印更糟：它让人以为"已经报过错了"。
"""

from __future__ import annotations

import asyncio
import unittest

from core.util.errors import describe


class TestDescribe(unittest.TestCase):
    def test_empty_str_exception_still_names_the_type(self) -> None:
        """超时类异常的 str() 是空的，此时至少要有类型名。"""
        self.assertEqual(str(TimeoutError()), "")
        self.assertEqual(describe(TimeoutError()), "TimeoutError")

        self.assertEqual(str(asyncio.TimeoutError()), "")
        self.assertEqual(describe(asyncio.TimeoutError()), "TimeoutError")

    def test_normal_exception_keeps_type_and_message(self) -> None:
        self.assertEqual(describe(ValueError("bad input")), "ValueError: bad input")
        self.assertEqual(describe(KeyError("missing")), "KeyError: 'missing'")

    def test_whitespace_only_message_falls_back_to_type(self) -> None:
        self.assertEqual(describe(ValueError("   ")), "ValueError")

    def test_never_returns_empty(self) -> None:
        for exc in (
            TimeoutError(),
            asyncio.CancelledError(),
            ValueError(""),
            RuntimeError(" "),
            Exception(),
        ):
            self.assertTrue(describe(exc).strip(), f"{type(exc).__name__} 描述为空")

    def test_dns_query_module_uses_it(self) -> None:
        """被动源的失败日志必须走 describe, 不能退回 str(e)。"""
        import inspect

        from core.domains.subdomain._lib import dns_query

        source = inspect.getsource(dns_query.PassiveSourceModule.handle_event)
        self.assertIn("describe(e)", source)
        self.assertNotIn('失败: %s", self.name, target, e)', source)


if __name__ == "__main__":
    unittest.main()
