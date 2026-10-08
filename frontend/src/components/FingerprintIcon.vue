<!--
  指纹图标（本地自绘）。

  **为什么不用图标库**：``@ant-design/icons-vue`` 793 个图标、底层
  ``@ant-design/icons-svg`` 848 个里都**没有**指纹 —— ant-design 的
  ``FingerprintOutlined`` 是后加的，这个版本（icons-vue ^7.0.1）没收录。
  「指纹规则」页原来挂的是 ``DeploymentUnitOutlined``（部署拓扑图），
  和"指纹"没关系，用户一眼认不出是什么。

  **画法**：三道**同心弧**（由外到内收窄）+ 两侧长短不一的纹路尾部。
  这是指纹的通用视觉符号，比用 ScanOutlined 这类近似图标贴切。

  ⚠️ **弧的条数是被 16px 逼出来的**：第一版画了六道弧，96px 下很漂亮，
  放进侧栏（菜单只有 16px）就糊成一坨黑 —— 1.6 描边在 16px 上只有约
  1.07px，六条挤在一起完全分不开。所以减到**三道**、描边加到 1.9，
  尾巴左右错开，让弧与弧之间有白。

  ⚠️ **撑满 viewBox 还不够，得撑得"过分"**：第二版画得太"含蓄"，弧只占
  24×24 里 y≈11..20 那一小块；第三版把弧撑到 x=3..21 / y=3..20，几何上
  已经满盒了，但**看着还是比旁边的 antd 图标小一号**。

  真因是**视觉重量**、不是几何尺寸：同心弧之间全是空隙，ink 是断开的几笔，
  而 antd 的 ``DatabaseOutlined`` 之类是连片的实心图形。同样大的盒子，
  断笔的墨看着就"轻"，就显小 —— 用户两次反馈"太小"都是这个。

  第三版补了两手：
  1. ``viewBox`` 从 ``0 0 24 24`` 收到 ``1.5 1.5 21 21`` —— **盒子不变大**，
     但同样的图形在盒子里画得更大（占比从 ~75% 提到 ~90%）
  2. 盒子本身再放大到 ``1.15em``（14px 的 ``.anticon`` → 约 16px）

  合起来墨迹面积约 +50%。⚠️ 别把 viewBox 再放宽回去，那正是"太小"的成因。

  **规格对齐 antd**：只用 ``currentColor``，颜色跟着菜单文字走。
-->
<template>
  <span class="fp-icon" aria-hidden="true">
    <!-- viewBox 收到 1.5 1.5 21 21：盒子尺寸不变，图在盒子里画得更大 -->
    <svg viewBox="1.5 1.5 21 21" fill="none" stroke="currentColor"
         stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round">
      <!-- 外弧（顶点 y=3）+ 右侧垂到 y≈20 -->
      <path d="M3 12a9 9 0 0 1 18 0v8.5" />
      <!-- 外弧左侧尾 -->
      <path d="M3 12v3.5a11 11 0 0 0 2.2 6.6" />
      <!-- 中弧（顶点 y=8）+ 右侧垂 -->
      <path d="M7 13a5 5 0 0 1 10 0v5" />
      <!-- 内弧（顶点 y≈12.7） -->
      <path d="M10.5 14.2a1.5 1.5 0 0 1 3 0v3" />
    </svg>
  </span>
</template>

<style scoped>
.fp-icon {
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.fp-icon svg {
  /* 1.15em 而不是 1em：antd 的 .anticon 是 14px，1em 会比旁边的图标小一圈。
     想再调只改这一个数。 */
  width: 1.15em;
  height: 1.15em;
  /* 与 antd 图标一致：颜色跟文字走 */
  color: inherit;
}
</style>