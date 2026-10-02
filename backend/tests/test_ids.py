"""``core/util/ids.py`` —— 对外展示用的任务短码。

这个模块的价值全在"双射"两个字上：它替代了"加一列存随机码"和"用哈希"。
两种替代方案的问题分别是迁移麻烦和会撞，所以这里的测试重点就是
**唯一 + 可逆**，而不是"看起来像随机"。
"""

from __future__ import annotations

import unittest

from core.util.ids import _ALPHABET, _BITS, decode_task_code, task_code


class TestTaskCode(unittest.TestCase):
    def test_shape(self) -> None:
        """8 位、只用约定的 32 个字符（去掉了 I/L/O/U，避免看错）。"""
        self.assertEqual(len(_ALPHABET), 32, "必须正好 32 个 —— 按 5 位一组取值")
        for scan_id in (0, 1, 7, 999, 123456, 10**12):
            with self.subTest(scan_id=scan_id):
                code = task_code(scan_id)
                self.assertEqual(len(code), _BITS // 5)
                self.assertTrue(set(code) <= set(_ALPHABET), code)
                self.assertNotIn("I", code)
                self.assertNotIn("L", code)
                self.assertNotIn("O", code)
                self.assertNotIn("U", code)

    def test_unique_no_collision(self) -> None:
        """**不同的 scan_id 必须得到不同的码。**

        这是它不用哈希的原因 —— 哈希要查重、要处理冲突，
        而这个变换是 40 位空间上的双射，天生不撞。
        """
        codes = [task_code(i) for i in range(1, 50_001)]
        self.assertEqual(len(codes), len(set(codes)), "短码撞了 —— 变换不是双射")

    def test_round_trip(self) -> None:
        """``decode_task_code`` 能把码解回原值（排查问题时要靠它）。"""
        for scan_id in range(0, 5_000):
            with self.subTest(scan_id=scan_id):
                self.assertEqual(decode_task_code(task_code(scan_id)), scan_id)

    def test_round_trip_large(self) -> None:
        for scan_id in (10**6, 2**31, 10**12, (1 << _BITS) - 1):
            with self.subTest(scan_id=scan_id):
                self.assertEqual(decode_task_code(task_code(scan_id)), scan_id)

    def test_neighbours_look_unrelated(self) -> None:
        """相邻 ID 的码不能长得像。

        只用「乘一个奇数」时，低位的变化传不到高位 —— 实测 ``1..10``
        编出来全以 ``K`` 开头，一眼看得出是连号。所以 ``_mix`` 里补了
        xorshift。这里钉住雪崩效应，免得以后有人觉得那两步多余给删了。
        """
        codes = [task_code(i) for i in range(1, 11)]
        first = {c[0] for c in codes}
        self.assertGreater(len(first), 5, f"相邻 ID 的码首字符太集中: {codes}")
        # 逐位都该有变化，不能只有最后一位在动
        diff_positions = {
            i for i in range(8) if len({c[i] for c in codes}) > 1
        }
        self.assertGreaterEqual(len(diff_positions), 6, f"变化位太少: {codes}")

    def test_first_char_is_spread(self) -> None:
        """首字符要铺满整个字母表 —— 否则等于码变短了。"""
        counts: dict[str, int] = {}
        for i in range(1, 20_001):
            ch = task_code(i)[0]
            counts[ch] = counts.get(ch, 0) + 1
        # 32 个字符各约 1/32（2 万次里约 625 次），给足余量
        self.assertEqual(len(counts), len(_ALPHABET), f"只用到 {len(counts)} 种首字符")
        self.assertGreater(min(counts.values()), 300)

    def test_bad_input_returns_none(self) -> None:
        for bad in ("", "   ", "ABC", "TOOLONGCODE", "!!!!!!!!", "IIIIIIII", None):
            with self.subTest(bad=bad):
                self.assertIsNone(decode_task_code(bad))

    def test_negative_rejected(self) -> None:
        with self.assertRaises(ValueError):
            task_code(-1)

    def test_case_insensitive_decode(self) -> None:
        code = task_code(42)
        self.assertEqual(decode_task_code(code.lower()), 42)
        self.assertEqual(decode_task_code(f"  {code}  "), 42)


if __name__ == "__main__":
    unittest.main()
