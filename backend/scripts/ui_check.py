"""用真实浏览器检查前端：渲染、JS 报错、布局尺寸与配色，并截图。

对着 ARL 的布局规格做断言，而不是只看"页面不报错"：
  * 侧边栏宽 170px、背景 #1a1a1a（近黑）
  * 顶栏高 64px
  * 选中菜单项左边条是橙红 #c2410c

用法::

    python scripts/ui_check.py                                  # http://127.0.0.1:8000
    python scripts/ui_check.py http://127.0.0.1:5173 .shots      # 对着 Vite dev server 跑
"""

from __future__ import annotations

import asyncio
import sys
import urllib.request
from pathlib import Path

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000").rstrip("/")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else ".shots")

ROUTES = [
    ("taskList", "任务管理"),
    ("search", "资产搜索"),
    ("fingerprints", "指纹规则"),
]

#: 每个路由可见文本的**最少字数**。空白页/渲染崩溃的直接症状就是文本极少，
#: 而它未必伴随 console 报错 —— 所以要有独立的一条断言守着。
#: （踩过一次：指纹规则页因为多解构了一层 `response.data` 而整片空白。）
MIN_TEXT = {
    # 任务列表现在还要放得下「创建任务」按钮，正文比原来的列表页多
    "taskList": 40,
    "search": 40,
    "fingerprints": 200,
}

EXPECT_SIDER = "170px"
EXPECT_SIDER_BG = "rgb(26, 26, 26)"  # #1a1a1a
EXPECT_HEADER_H = "64px"


def first_scan_id() -> int | None:
    """挑一个**已完成**的扫描来看详情页。

    不能直接取第一个：正在跑的扫描，详情页会挂着 SSE 长连接，
    ``networkidle`` 永远等不到（实测超时 30 秒）。
    """
    try:
        with urllib.request.urlopen(f"{BASE}/api/scans", timeout=10) as resp:
            import json

            scans = json.loads(resp.read())
    except Exception:
        return None
    if not scans:
        return None
    for s in scans:
        if str(s.get("status")) == "finished":
            return int(s["scan_id"])
    return int(scans[0]["scan_id"])


async def main() -> int:
    from playwright.async_api import async_playwright

    OUT.mkdir(parents=True, exist_ok=True)
    problems: list[str] = []
    failures: list[str] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch()
        context = await browser.new_context(
            viewport={"width": 1440, "height": 900}, ignore_https_errors=True
        )
        page = await context.new_page()

        page.on(
            "console",
            lambda m: problems.append(f"[console.{m.type}] {m.text}")
            if m.type == "error"
            else None,
        )
        page.on("pageerror", lambda e: problems.append(f"[pageerror] {e}"))

        for route, expect_title in ROUTES:
            url = f"{BASE}/{route}"
            await page.goto(url, wait_until="networkidle")
            await page.wait_for_timeout(700)

            title_el = await page.query_selector(".header-title")
            title = (await title_el.inner_text()).strip() if title_el else ""
            if title != expect_title:
                failures.append(f"{route}: 顶栏标题应为「{expect_title}」，实际「{title}」")

            # 内容量断言 —— 空白页最直接的证据
            body_text = (await page.inner_text("body")).strip()
            floor = MIN_TEXT.get(route, 0)
            if len(body_text) < floor:
                failures.append(
                    f"{route}: 页面文本只有 {len(body_text)} 字（至少应有 {floor}）"
                    f" —— 很可能是渲染崩了。开头：{body_text[:80]!r}"
                )

            shot = OUT / f"{route}.png"
            # 显式 type="png": 否则 Playwright 会按扩展名查 MIME, 而这台机器的
            # Windows 注册表把 .png 映射成了 silenteye/png, 直接报错。
            await page.screenshot(path=str(shot), type="png")
            print(f"  {route:12} 标题「{title}」 文本 {len(body_text):5} 字 截图 {shot.name}")

        # ── 布局规格断言（拿计算样式，不看感觉）──
        await page.goto(f"{BASE}/taskList", wait_until="networkidle")
        await page.wait_for_timeout(400)

        sider = await page.query_selector(".app-sider")
        if sider is None:
            failures.append("找不到 .app-sider 侧边栏")
        else:
            box = await sider.bounding_box()
            bg = await sider.evaluate("el => getComputedStyle(el).backgroundColor")
            width = f"{round(box['width'])}px" if box else "?"
            print(f"  侧边栏        宽 {width}  背景 {bg}")
            if width != EXPECT_SIDER:
                failures.append(f"侧边栏宽应为 {EXPECT_SIDER}，实际 {width}")
            if bg != EXPECT_SIDER_BG:
                failures.append(f"侧边栏背景应为 {EXPECT_SIDER_BG}（#1a1a1a），实际 {bg}")

        header = await page.query_selector(".header")
        if header is None:
            failures.append("找不到 .header 顶栏")
        else:
            box = await header.bounding_box()
            height = f"{round(box['height'])}px" if box else "?"
            print(f"  顶栏          高 {height}")
            if height != EXPECT_HEADER_H:
                failures.append(f"顶栏高应为 {EXPECT_HEADER_H}，实际 {height}")

        selected = await page.query_selector(".ant-menu-item-selected")
        if selected is None:
            failures.append("没有选中态的菜单项")
        else:
            border = await selected.evaluate("el => getComputedStyle(el).borderLeftColor")
            print(f"  选中菜单左边条 {border}")
            if border != "rgb(194, 65, 12)":  # #c2410c
                failures.append(f"选中菜单左边条应为 rgb(194, 65, 12)，实际 {border}")

        # ── 任务详情（有扫描数据时才测）──
        scan_id = first_scan_id()
        if scan_id:
            url = f"{BASE}/taskList/taskDetail?id={scan_id}"
            # 用 domcontentloaded 而不是 networkidle：详情页挂着 SSE 长连接
            # （实时进度），网络永远不会"空闲"。
            await page.goto(url, wait_until="domcontentloaded")
            await page.wait_for_timeout(2000)
            tabs = await page.query_selector_all(".ant-tabs-tab")
            title_el = await page.query_selector(".head-title")
            heading = (await title_el.inner_text()).strip().replace("\n", " ") if title_el else ""
            print(f"  任务详情      标题「{heading[:40]}」 标签页 {len(tabs)} 个")
            if not tabs:
                failures.append("任务详情没有渲染出资产标签页")

            # URL 与 HTTP 端点已合并成一个页签（两者本来是包含关系：
            # 探活过的 URL 在 url 表里也有一行）。分开显示会让人以为
            # "已知存在"和"已知活着"是两批东西。
            labels = [(await t.inner_text()).strip().split("\n")[0]
                      for t in tabs]
            joined = " ".join(labels)
            if not any(lbl.startswith("URL") for lbl in labels):
                failures.append(f"任务详情没有「URL」页签：{labels}")
            if "HTTP 端点" in joined:
                failures.append(
                    f"「HTTP 端点」应该已经并进「URL」，但页签里还有：{labels}"
                )
            print(f"                页签: {', '.join(labels)}")

            # **顶部卡片必须和下面页签同一个口径。**
            #
            # 踩过的坑：卡片取 summary 里的原始总数、页签取 *_live，于是同一个
            # 页面顶部写"域名 14333"、下面写"域名 (255)"。两处都能从后端拿到
            # 数，所以路由检查、文本量检查全都会绿 —— 只有摆在一起比才看得出。
            cards = await page.evaluate(
                """() => {
                    const out = {};
                    document.querySelectorAll('.tk-stat').forEach((e) => {
                        const l = e.querySelector('.tk-stat-label')?.innerText.trim();
                        const v = e.querySelector('.tk-stat-value')?.innerText.trim();
                        if (l) out[l] = v;
                    });
                    return out;
                }"""
            )
            for card_label, tab_prefix in (
                ("域名", "域名"), ("IP", "IP"), ("开放端口", "端口"), ("URL", "URL"),
                ("技术栈", "技术栈"), ("发现", "发现"), ("事件", "事件"),
                # 影子资产：卡片和页签也必须一致。这个尤其重要 —— 影子资产
                # 大多没被探活，页签要是跟着 live 过滤就会是 0 而卡片是 326，
                # 表现为"数得出来但一条都找不到"。
                ("影子资产", "影子资产"),
            ):
                tab_text = next((lbl for lbl in labels if lbl.startswith(tab_prefix)), "")
                if not tab_text:
                    continue
                # 页签可能写 "2,000 / 8,297"（被 limit 截断），取总数那一半
                inside = tab_text[tab_text.find("(") + 1:tab_text.rfind(")")]
                tab_value = inside.split("/")[-1].strip().replace(",", "")
                card_value = (cards.get(card_label) or "").replace(",", "")
                if card_value != tab_value:
                    failures.append(
                        f"顶部卡片「{card_label}」={card_value} 与页签"
                        f"「{tab_text}」对不上 —— 两处口径不一致"
                    )
            print(f"  统计卡片      {len(cards)} 张，与页签一致")

            # 界面上**只展示探活确认过的资产**，没有开关（用户明确要求去掉
            # 那个开关：原始清单里 96% 是没探过的 URL，混在一起没有意义）。
            # 所以这里反过来断言：不该再有开关。
            sw = await page.query_selector(".asset-toolbar .ant-switch")
            if sw:
                failures.append(
                    "任务详情不该再有「只看探活通过的」开关 —— "
                    "现在永远只看探活确认过的资产"
                )
            # 页签数字必须是**存活条数**，不能是"这次取回来的行数"
            # （曾经写「域名 (2000)」，其实是 14333 条里只取了 2000 行）。
            domain_tab = next((lbl for lbl in labels if lbl.startswith("域名")), "")
            if " / " in domain_tab:
                failures.append(
                    f"页签不该出现截断标记（存活数远小于 limit），实际是「{domain_tab}」"
                )
            await page.screenshot(path=str(OUT / "taskDetail.png"), type="png")

            # 「返回」按钮放**最后**测 —— 它要点一下导航走，之前抓到的元素句柄
            # （tabs 那些）会全部失效，再读就是
            # "Execution context was destroyed"。所以先做完不导航的检查。
            #
            # 没有这个键就只能靠浏览器后退，而直接输 URL 进来时浏览器后退
            # 会把人带出站点。
            back_btn = await page.query_selector(".back-btn")
            if not back_btn:
                failures.append("任务详情缺少「返回」按钮")
            else:
                await back_btn.click()
                await page.wait_for_timeout(1500)
                if not page.url.rstrip("/").endswith("/taskList"):
                    failures.append(f"点「返回」后没回到任务列表：{page.url}")
                else:
                    print(f"  返回键        点后 -> {page.url.split('8000')[-1]}")

                # 再验一遍退化路径：直接输 URL 进来时没有上一页，
                # router.back() 会把人带出站点，必须落到任务列表
                await page.goto(url, wait_until="domcontentloaded")
                await page.wait_for_timeout(1500)
                direct = await page.query_selector(".back-btn")
                if direct:
                    await direct.click()
                    await page.wait_for_timeout(1500)
                    if not page.url.rstrip("/").endswith("/taskList"):
                        failures.append(
                            f"直接输 URL 进详情后点「返回」被带出了站点：{page.url}"
                        )
                    else:
                        print("  返回键        直接输 URL 时也能回列表")
        else:
            print("  任务详情      跳过（库里还没有扫描）")

        # ── 系统设置抽屉 ──
        # **这个必须测。** 保存按钮曾经因为 `#footer` 写在了 <a-spin> 里面
        # 而完全不渲染 —— Vue 对不存在的插槽是静默丢弃，控制台一句错都不报，
        # 页面文本量也够（抽屉里字段很多），按路由跑的检查全都会绿。
        # 是用户手动点开才发现的。所以这里显式打开抽屉并找那个按钮。
        await page.goto(f"{BASE}/taskList", wait_until="networkidle")
        await page.wait_for_timeout(400)
        gear = await page.query_selector(".footer-btn")
        if not gear:
            failures.append("侧边栏找不到打开系统设置的按钮（.footer-btn）")
        else:
            await gear.click()
            await page.wait_for_timeout(600)
            footer = await page.query_selector(".ant-drawer-footer")
            save_btn = await page.query_selector(
                ".ant-drawer-footer button.ant-btn-primary"
            )
            drawer = await page.query_selector(".ant-drawer")
            if not drawer:
                failures.append("点了设置按钮但抽屉没打开")
            elif not footer or not save_btn:
                failures.append(
                    "系统设置抽屉里没有保存按钮 —— "
                    "通常是 #footer 插槽没放在 a-drawer 的直接子节点上"
                )
            else:
                label = (await save_btn.inner_text()).strip()
                print(f"  系统设置      抽屉已打开，底部按钮「{label}」")
            await page.screenshot(path=str(OUT / "settings.png"), type="png")
            # 关掉，免得影响后面的截图
            await page.keyboard.press("Escape")
            await page.wait_for_timeout(300)

        await browser.close()

    print()
    if problems:
        # **JS 报错也算失败**，不能只打印一行警告就当通过。
        # 之前这里只 print，于是"页面整片空白"也能拿到退出码 0。
        print(f"  ✗ 浏览器报错 {len(problems)} 条:")
        for item in problems[:12]:
            print(f"    {item[:200]}")
        failures.append(f"浏览器报错 {len(problems)} 条")
    else:
        print("  ✓ 没有 JS 报错")

    if failures:
        print(f"\n  ✗ 失败 {len(failures)} 条:")
        for item in failures:
            print(f"    {item}")
        return 1

    print("\n  ✓ 布局规格全部符合 ARL 目标")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
