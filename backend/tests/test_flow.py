"""出站流量闸门：令牌桶限速 + 失败主机预算。

**这两条闸门是"流量压不住"的直接解药**，所以每一条都要钉住 ——
尤其是"默认关"这件事：加闸门不能悄悄改变吞吐，漏了这一点用户会发现
"升级之后扫描慢了三倍"却查不出原因。
"""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest import mock

from core.services.flow import (
    DEFAULT_MAX_HOSTS, FlowGate, HostErrors, RateLimiter, host_key,
)


class TestRateLimiter(unittest.TestCase):
    """令牌桶。"""

    def test_zero_rate_is_rejected(self) -> None:
        """不限速就别建这个对象 —— 靠构造失败比靠"建了但没人用"可靠。"""
        for bad in (0, -1, -0.5):
            with self.subTest(rate=bad):
                with self.assertRaises(ValueError):
                    RateLimiter(bad)

    def test_burst_defaults_to_rate(self) -> None:
        """桶容量默认等于速率：开跑能一口气发一秒的量。

        桶太小会让扫描开头把并发压死，第一批请求互相等令牌，
        看起来像"刚启动就卡住"。
        """
        self.assertEqual(RateLimiter(5).burst, 5)
        self.assertEqual(RateLimiter(5, burst=20).burst, 20)

    def test_burst_never_exceeds_configured(self) -> None:
        rl = RateLimiter(10, burst=3)
        self.assertEqual(rl.burst, 3)

    def test_tokens_do_not_accumulate_while_idle(self) -> None:
        """闲置再久，桶也只涨到 burst —— 不限速就恢复了，不是攒了半小时的额度。"""
        rl = RateLimiter(10)
        rl._tokens = 0
        rl._updated = time.monotonic() - 600      # 假装闲置了十分钟
        asyncio.run(_drain(rl, 3))
        self.assertLessEqual(rl._tokens, rl.burst - 1)

    def test_throughput_is_capped(self) -> None:
        """真正要验的：**速率真的压住了**。"""
        rate = 40.0
        rl = RateLimiter(rate)
        n = 24

        async def go():
            t0 = time.monotonic()
            # burst = rate = 40，前 40 枚不排队；24 枚全在突发内，
            # 所以这里量的是"突发够不够"，稳态另测
            for _ in range(n):
                await rl.acquire()
            return time.monotonic() - t0

        elapsed = asyncio.run(go())
        self.assertLess(elapsed, 1.0, f"{n} 次取令牌花了 {elapsed:.2f}s，突发没生效")

    def test_steady_state_rate_is_respected(self) -> None:
        """突发用完之后就该按速率放行 —— 这才是限速的意义。"""
        rate = 50.0
        rl = RateLimiter(rate, burst=1)          # 桶里只有 1 枚，逼它排队
        n = 6                                   # 还要再等 5 枚 ≈ 0.1s

        async def go():
            t0 = time.monotonic()
            for _ in range(n):
                await rl.acquire()
            return time.monotonic() - t0

        elapsed = asyncio.run(go())
        # 5 枚 × 1/50s = 0.1s，留足余量给 CI 的抖动
        self.assertGreaterEqual(elapsed, 0.09,
                                f"{n} 次只花了 {elapsed:.3f}s，限速没生效")

    def test_concurrent_acquirers_all_get_through(self) -> None:
        """**并发下不能有人饿死** —— 这是惰性重算要解决的问题。

        固定间隔 sleep 的写法会让所有协程同时醒来再互相排队，
        尾部的可能反复落空。
        """
        rl = RateLimiter(200, burst=5)

        async def go():
            await asyncio.gather(*(rl.acquire() for _ in range(60)))
            return rl.stats["acquired"]

        total = asyncio.run(asyncio.wait_for(go(), timeout=20))
        self.assertEqual(total, 60, f"只有 {total} 个拿到令牌，有人饿死了")

    def test_describe_reports_config(self) -> None:
        self.assertIn("200", RateLimiter(200).describe())


async def _drain(rl: RateLimiter, n: int) -> None:
    for _ in range(n):
        await rl.acquire()


class TestHostErrors(unittest.TestCase):
    """失败主机预算。"""

    def test_zero_threshold_is_rejected(self) -> None:
        for bad in (0, -3):
            with self.subTest(n=bad):
                with self.assertRaises(ValueError):
                    HostErrors(bad)

    def test_blocked_only_after_threshold(self) -> None:
        he = HostErrors(3)
        self.assertFalse(he.record_error("a:80"), "第 1 次不该拉黑")
        self.assertFalse(he.record_error("a:80"), "第 2 次不该拉黑")
        self.assertTrue(he.is_blocked("a:80") is False)
        self.assertTrue(he.record_error("a:80"), "第 3 次该拉黑")
        self.assertTrue(he.is_blocked("a:80"))

    def test_success_resets_the_counter(self) -> None:
        """成功一次就清零 —— 否则偶尔抖一下的主机会被永久拉黑。"""
        he = HostErrors(3)
        he.record_error("a:80")
        he.record_error("a:80")
        he.record_success("a:80")
        he.record_error("a:80")
        he.record_error("a:80")
        self.assertFalse(he.is_blocked("a:80"), "成功过就不该被拉黑")

    def test_success_on_unknown_host_is_a_noop(self) -> None:
        he = HostErrors(1)
        he.record_success("never-seen:80")      # 不该凭空建条目
        self.assertEqual(len(he._counts), 0)

    def test_lru_evicts_oldest(self) -> None:
        """主机数量必须有上界 —— 扫大范围时一路涨会吃内存。"""
        he = HostErrors(2, max_hosts=3)
        for i in range(5):
            he.record_error(f"h{i}:80")
        self.assertEqual(len(he._counts), 3)
        self.assertEqual(he.stats["evicted"], 2)

    def test_touch_marks_as_recently_used(self) -> None:
        """被访问过的条目不能是最先淘汰的那个。"""
        he = HostErrors(5, max_hosts=2)
        he.record_error("a:80")
        he.record_error("b:80")
        he.record_error("a:80")            # a 变"最近用过"
        he.record_error("c:80")            # 触发淘汰
        self.assertIn("a:80", he._counts)
        self.assertNotIn("b:80", he._counts)

    def test_empty_key_is_ignored(self) -> None:
        he = HostErrors(1)
        self.assertFalse(he.is_blocked(""))
        self.assertFalse(he.record_error(""))
        self.assertEqual(he.stats["errors"], 0)


class TestHostKey(unittest.TestCase):
    """记账的键：``host:port``。"""

    def test_default_port_by_scheme(self) -> None:
        self.assertEqual(host_key("https://a.example.com/x"), "a.example.com:443")
        self.assertEqual(host_key("http://a.example.com/x"), "a.example.com:80")

    def test_explicit_port_is_kept(self) -> None:
        """带端口是因为 :443 与 :8443 是两台机器，一台挂了不该拉黑另一台。"""
        self.assertEqual(host_key("https://a.example.com:8443/x"),
                         "a.example.com:8443")

    def test_host_is_lowercased(self) -> None:
        self.assertEqual(host_key("https://A.Example.COM/x"), "a.example.com:443")

    def test_junk_gives_empty_key(self) -> None:
        for bad in ("", "not a url", "http://", "://x"):
            with self.subTest(url=bad):
                self.assertEqual(host_key(bad), "")


class TestFlowGate(unittest.TestCase):
    """合装对象。"""

    def test_defaults_are_off(self) -> None:
        """**默认两个都关** —— 行为必须与加这项之前完全一致。"""
        gate = FlowGate()
        self.assertFalse(gate.active)
        self.assertIsNone(gate.rate)
        self.assertIsNone(gate.hosts)
        self.assertIn("未启用", gate.describe())

    def test_either_switch_enables_the_gate(self) -> None:
        self.assertTrue(FlowGate(rate_limit=10).active)
        self.assertTrue(FlowGate(host_error_max=3).active)

    def test_zero_means_off_not_unlimited(self) -> None:
        """``0`` / 空值 = 不限速（不是"限速 0"）—— 预设里没写就当没开。"""
        for kwargs in ({"rate_limit": 0}, {"rate_limit": None},
                       {"host_error_max": 0}, {"host_error_max": None}):
            with self.subTest(**kwargs):
                self.assertFalse(FlowGate(**kwargs).active)

    def test_describe_mentions_both_when_on(self) -> None:
        text = FlowGate(rate_limit=20, host_error_max=3).describe()
        self.assertIn("限速", text)
        self.assertIn("失败主机", text)


class TestGateInHttpClient(unittest.TestCase):
    """闸门接在 ``HTTPClient`` 上 —— 接线对不对，比闸门本身更要紧。"""

    def _client(self, **gate_kw):
        from core.services.http import HTTPClient

        gate = FlowGate(**gate_kw) if gate_kw else None
        return HTTPClient(timeout=1.0, gate=gate), gate

    def test_no_gate_keeps_old_behavior(self) -> None:
        """不传闸门 → 空闸门 → 一行请求都不该被拦。"""
        client, _ = self._client()
        self.assertFalse(client.gate.active)
        self.assertEqual(await_gate(client, "https://a.example.com/x"), "")

    def test_blocked_host_short_circuits_before_the_request(self) -> None:
        """被拉黑的主机**连令牌都不该占** —— 不值得为它排一次队。"""
        client, gate = self._client(rate_limit=1000, host_error_max=1)
        gate.hosts.record_error("a.example.com:443")     # 已达上限
        self.assertTrue(gate.hosts.is_blocked("a.example.com:443"))

        reason = await_gate(client, "https://a.example.com/x")
        self.assertIn("不可达", reason)
        self.assertEqual(gate.rate.stats["acquired"], 0,
                         "被跳过的请求不该消耗令牌")

    def test_other_hosts_are_unaffected(self) -> None:
        """拉黑一台不能连坐别的 —— 这正是"按 host 记账"要守的。"""
        client, gate = self._client(host_error_max=1)
        gate.hosts.record_error("bad.example.com:443")
        self.assertEqual(await_gate(client, "https://good.example.com/x"), "")

    def test_5xx_counts_but_4xx_does_not(self) -> None:
        """4xx 是**有效答案**（"没有权限"也是结论），不能计进失败。"""
        from core.services.http import HTTPClient

        client = HTTPClient(timeout=1.0, gate=FlowGate(host_error_max=2))
        for _ in range(5):
            client._gate_result("https://a.example.com/x", ok=True, status=404)
        self.assertFalse(client.gate.hosts.is_blocked("a.example.com:443"),
                         "连续 404 被算成不可达了 —— 那是误伤")

        for _ in range(2):
            client._gate_result("https://a.example.com/x", ok=True, status=503)
        self.assertTrue(client.gate.hosts.is_blocked("a.example.com:443"))

    def test_transport_failure_counts(self) -> None:
        from core.services.http import HTTPClient

        client = HTTPClient(timeout=1.0, gate=FlowGate(host_error_max=1))
        client._gate_result("https://a.example.com/x", ok=False)
        self.assertTrue(client.gate.hosts.is_blocked("a.example.com:443"))


def await_gate(client, url: str) -> str:
    """跑一次过闸，返回被跳过的理由（空串 = 放行）。"""
    return asyncio.run(client._gate_wait(url))


class TestModuleGetsTheGate(unittest.TestCase):
    """模块必须拿到**这一轮扫描共用**的那个闸门。"""

    def _module(self, gate: FlowGate):
        from core.engine.module import BaseModule

        fake = mock.Mock()
        fake.gate = gate
        # 走真正的构造器：``scanner`` 是只读属性（引擎的硬约定），
        # 绕开它去 setattr 反而测不到真实路径
        return BaseModule(fake, {})

    def test_http_client_factory_injects_scanner_gate(self) -> None:
        gate = FlowGate(rate_limit=7, host_error_max=2)
        client = self._module(gate).http_client(timeout=3.0)
        self.assertIs(client.gate, gate, "模块的客户端没挂上扫描级闸门")

    def test_explicit_gate_wins(self) -> None:
        """显式传了就用显式的（个别模块要单独限速时用）。"""
        own = FlowGate(rate_limit=3)
        client = self._module(FlowGate(rate_limit=99)).http_client(gate=own)
        self.assertIs(client.gate, own)

    def test_factory_forwards_other_kwargs(self) -> None:
        """闸门是**加上去的**，不是替换掉的 —— timeout/proxy 等照常能用。"""
        client = self._module(FlowGate()).http_client(
            timeout=12.0, retries=0, max_connections=8
        )
        self.assertEqual(client.retries, 0)
        self.assertEqual(client.max_connections, 8)


class TestScannerWiring(unittest.TestCase):
    """预设的 ``settings`` 真的变成了扫描级的闸门。

    ⚠️ **只测 ``FlowGate()`` 是不够的。** 上一轮的变异验证里，把
    ``Scanner`` 里的默认从 0 改成 20（等于偷偷打开限速），``FlowGate``
    那一层的测试全绿 —— 因为它测的是类默认，而出问题的是**接线**。
    漏了这一条，"默认关"就只是一句注释。
    """

    def _scanner(self, **settings):
        from core.engine.preset import Preset
        from core.engine.scanner import Scanner

        return Scanner(
            targets=["example.com"],
            preset=Preset(name="t", description="", settings=settings),
            storage=None,
            enforce_scope=False,
        )

    def test_gate_is_off_without_settings(self) -> None:
        """不配 = 不限速。行为必须与加这项之前完全一致。"""
        sc = self._scanner()
        self.assertFalse(sc.gate.active)
        self.assertIsNone(sc.gate.rate)
        self.assertIsNone(sc.gate.hosts)

    def test_rate_limit_turns_on_the_limiter(self) -> None:
        sc = self._scanner(rate_limit=15, rate_burst=30)
        self.assertIsNotNone(sc.gate.rate)
        self.assertEqual(sc.gate.rate.rate, 15)
        self.assertEqual(sc.gate.rate.burst, 30)

    def test_host_error_max_turns_on_the_budget(self) -> None:
        sc = self._scanner(host_error_max=4, host_error_hosts=50)
        self.assertIsNotNone(sc.gate.hosts)
        self.assertEqual(sc.gate.hosts.max_errors, 4)
        self.assertEqual(sc.gate.hosts.max_hosts, 50)

    def test_zero_and_none_both_mean_off(self) -> None:
        for settings in ({"rate_limit": 0}, {"rate_limit": None},
                         {"host_error_max": 0}, {"host_error_max": None}):
            with self.subTest(**settings):
                self.assertFalse(self._scanner(**settings).gate.active)

    def test_each_scan_gets_its_own_gate(self) -> None:
        """**每轮扫描一个，不是进程全局。**

        同一进程可以并行跑多轮（``max_concurrent_scans``），全局的话
        A 轮的请求会算进 B 轮的额度，而且测试之间会互相污染。
        """
        a = self._scanner(rate_limit=10, host_error_max=2)
        b = self._scanner(rate_limit=10, host_error_max=2)
        self.assertIsNot(a.gate, b.gate)
        a.gate.hosts.record_error("x.example.com:80")
        self.assertFalse(b.gate.hosts.is_blocked("x.example.com:80"),
                         "两轮扫描共用了同一张失败表")


if __name__ == "__main__":
    unittest.main()
