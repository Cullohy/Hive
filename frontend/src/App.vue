<template>
  <a-config-provider :theme="theme" :locale="zhCN">
    <a-layout class="app-layout">
      <!-- 侧边栏：固定定位，不随内容滚动（与 ARL 一致） -->
      <a-layout-sider
        v-model:collapsed="collapsed"
        :trigger="null"
        :width="170"
        :collapsed-width="50"
        class="app-sider"
      >
        <p class="logo-word" :class="{ collapsed }">
          <!-- 图标与文字是**两个独立元素**：图标是 SVG（橙色放大镜，
               与背景色无关，所以深色侧边栏和浅色的令牌页能共用同一个
               文件），文字是真正的 HTML —— 可选中、跟随字体设置，
               以后改名只动这一个 span，不用再去改 SVG。 -->
          <img src="/logo.svg" alt="Hive" class="logo-icon" />
          <span v-if="!collapsed" class="logo-text">Hive蜂巢</span>
        </p>

        <div class="sider-body">
          <a-menu mode="inline" :selected-keys="[selectedKey]" :inline-collapsed="collapsed">
            <a-menu-item v-for="item in menuItems" :key="item.key" @click="go(item)">
              <component :is="item.icon" class="anticon" />
              <span class="menu-title">{{ item.label }}</span>
            </a-menu-item>
          </a-menu>

          <div class="sidebar-footer" :class="{ collapsed }">
            <a-button type="link" size="small" class="footer-btn" @click="showSettings = true">
              <SettingOutlined />
              <span v-if="!collapsed" class="footer-text">系统设置</span>
            </a-button>
            <!-- 侧栏底部只留版本号（2026-10-07）。
                 「运行中 N/4」**在顶栏右上角，不在这里** —— 它是实时心跳，
                 要一眼可见；版本号是静态署名，压在角落就够。两者别再互换。
                 折叠时整行不渲染：版本号没有图标可留，留一行空白没意义。 -->
            <div v-if="!collapsed" class="footer-version">v{{ version }}</div>
          </div>
        </div>
      </a-layout-sider>

      <div class="main-wrapper" :class="{ 'is-collapsed': collapsed }">
        <a-layout-header class="header">
          <div class="header-left">
            <div class="trigger" @click="collapsed = !collapsed">
              <component :is="collapsed ? MenuUnfoldOutlined : MenuFoldOutlined" />
            </div>
            <h2 class="header-title">{{ currentTitle }}</h2>
          </div>
          <!-- 「运行中 N/4」——心跳放顶栏右上角，一眼可见。
               ⚠️ 字色用 `--tk-text-secondary`：顶栏是**白底**，
               侧栏那套 `--tk-side-text`（深底反色）搬过来几乎看不见（踩过一次）。
               「后端离线」时圆点变红 —— 这是唯一的排查入口，别删。 -->
          <div class="header-right">
            <div class="health">
              <span class="dot" :class="healthClass" />
              <span>{{ healthText }}</span>
            </div>
          </div>
        </a-layout-header>

        <a-layout-content class="content">
          <router-view v-slot="{ Component, route }">
            <component :is="Component" :key="route.fullPath" />
          </router-view>
        </a-layout-content>
      </div>
    </a-layout>

    <SettingsDrawer v-model:open="showSettings" @saved="loadHealth" />
  </a-config-provider>
</template>

<script setup>
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import {
  AppstoreOutlined,
  ClusterOutlined,
  DatabaseOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  SearchOutlined,
  SettingOutlined,
} from '@ant-design/icons-vue'

import { getHealth } from '@/api'
import SettingsDrawer from '@/components/SettingsDrawer.vue'
import FingerprintIcon from '@/components/FingerprintIcon.vue'
//: ant-design-vue 的默认语言是 en_US：日期选择器会显示英文月份、Su/Mo/Tu
//: 星期缩写、Now / Today，以及 "Start date" / "End date" 提示。
//: 没有 locale 时这套文案**静默**是英文的（没有任何报错），所以必须显式给。
//:
//: 注意它只管**格式串**（「2026年」「今天」「确定」）。月份表和星期头走的是
//: dayjs，要靠 main.js 里的 `import 'dayjs/locale/zh-cn'` 才变中文 —— 只加
//: 这一行会看到「2026年」是中文、月份却是 Oct 的半吊子状态。
import zhCN from 'ant-design-vue/es/locale/zh_CN'

const theme = {
  token: {
    colorPrimary: '#c2410c',
    colorLink: '#c2410c',
    colorInfo: '#c2410c',
    borderRadius: 4,
    colorText: '#1a1a1a',
    colorBorder: '#e5e7eb',
  },
}

const collapsed = ref(false)
const showSettings = ref(false)
const health = ref({ ok: false, running: 0, max_concurrent: 0 })
const version = ref('')

const route = useRoute()
const router = useRouter()

// 菜单只放真正支持的页面。ARL 有 10 项，其余（PoC / 资产分组…）
// 这台后端还没有对应能力，硬摆上去只会点开一片空白。
//
// 「一键收集」曾经单独占一页，现在收进任务管理的工具栏（创建任务按钮）——
// 它的产物本来就是任务，单独一页只是多一次跳转。
const menuItems = [
  { key: 'task', label: '任务管理', icon: AppstoreOutlined, path: '/taskList' },
  { key: 'assets', label: '资产管理', icon: DatabaseOutlined, path: '/assets' },
  { key: 'asset-groups', label: '资产分组', icon: ClusterOutlined, path: '/asset-groups' },
  // 「指纹规则」原来是 DeploymentUnitOutlined（部署拓扑图，节点+连线），
  // 和「指纹」毫无关系，看着像网络拓扑页。图标库（icons-vue 793 个 /
  // icons-svg 848 个）里都没有指纹 —— ant-design 的 FingerprintOutlined
  // 是后加的、这个版本没收录，所以本地画了一个 SVG（见 FingerprintIcon.vue）。
  { key: 'fingerprints', label: '指纹规则', icon: FingerprintIcon, path: '/fingerprints' },
]

const selectedKey = computed(() => route.meta?.menu || 'task')
const currentTitle = computed(() => route.meta?.title || '任务管理')

const healthText = computed(() =>
  health.value.ok ? `运行中 ${health.value.running}/${health.value.max_concurrent}` : '后端离线',
)
const healthClass = computed(() => (health.value.ok ? 'ok' : 'bad'))

function go(item) {
  if (route.path !== item.path) router.push(item.path)
}

async function loadHealth() {
  try {
    const data = await getHealth()
    health.value = data
    version.value = data.version || ''
  } catch {
    health.value = { ok: false, running: 0, max_concurrent: 0 }
  }
}

let timer = null
onMounted(() => {
  loadHealth()
  timer = setInterval(loadHealth, 15000)
})
onUnmounted(() => {
  if (timer) clearInterval(timer)
})
</script>

<style scoped>
/* ── 侧边栏 ── */
:deep(.ant-layout-sider) {
  background: var(--tk-primary) !important;
  border-right: 1px solid rgba(255, 255, 255, 0.06);
  box-shadow: 2px 0 8px rgba(0, 0, 0, 0.15);
}
.app-sider {
  position: fixed !important;
  left: 0;
  top: 0;
  height: 100vh;
  z-index: 100;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.main-wrapper {
  margin-left: var(--tk-sider-width);
  transition: margin-left 0.2s;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  flex: 1;
  min-width: 0;
  overflow-x: hidden;
}
.main-wrapper.is-collapsed {
  margin-left: var(--tk-sider-collapsed);
}

.sider-body {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
  overflow: hidden;
}

:deep(.ant-menu) {
  flex: 1;
  overflow-y: auto;
  background: transparent !important;
  border-inline-end: none !important;
}
:deep(.ant-menu-item) {
  color: var(--tk-side-text) !important;
  border-left: 3px solid transparent;
  border-radius: 0;
  height: 40px !important;
  line-height: 40px !important;
  padding: 0 16px 0 21px !important;
  margin: 4px 0 !important;
  width: 100%;
}
:deep(.ant-menu-item:hover) {
  color: #fff !important;
  background: var(--tk-accent-soft) !important;
}
:deep(.ant-menu-item-selected) {
  color: #fff !important;
  border-left-color: var(--tk-accent) !important;
  background: var(--tk-accent-soft-2) !important;
}
:deep(.ant-menu-inline-collapsed > .ant-menu-item) {
  padding: 0 !important;
  display: flex;
  align-items: center;
  justify-content: center;
}
:deep(.ant-menu-inline-collapsed > .ant-menu-item .anticon + .menu-title) {
  display: inline-block;
  max-width: 0;
  opacity: 0;
  overflow: hidden;
}

.logo-word {
  height: 56px;
  flex-shrink: 0;
  display: flex;
  align-items: center;
  /* **左对齐，不居中** —— 图标要和下面菜单的图标落在同一列。
     居中时图标在 x=47，而菜单图标在 x=24，看起来就是"logo 缩进去了"。 */
  justify-content: flex-start;
  /* 图标与文字之间的间距 —— 拆成两个元素之后这里能单独调 */
  gap: 8px;
  /* 左边的 24px 是为了让图标左边缘与菜单图标对齐（菜单项 padding-left: 21px） */
  padding: 0 12px 0 24px;
  margin: 0;
  overflow: hidden;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}
.logo-word.collapsed {
  /* 折叠时只剩图标，居中更好看 */
  padding: 0;
  gap: 0;
  justify-content: center;
}
.logo-icon {
  height: 26px;
  width: 26px;
  flex-shrink: 0;
}
.logo-text {
  font-size: 19px;
  font-weight: 600;
  letter-spacing: 0.6px;
  line-height: 1;
  color: #fff;
  white-space: nowrap;
}

.sidebar-footer {
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  flex-shrink: 0;
  display: flex;
  flex-direction: column;
}
/* 选择器**故意写长**（.app-sider .sidebar-footer .footer-btn = 0,3,0）。
 *
 * 「系统设置」是 `type="link"` 按钮，而 global.css 有
 * `.ant-btn-link:not(.ant-btn-dangerous) { color: accent !important }`，
 * 那条是 (0,2,0)。两条都带 !important，**比的是特异性**不是源码顺序 ——
 * 本规则原来只有 `.footer-btn` (0,1,0)，之前靠"写在后面"险胜，
 * 一旦 global.css 给 link 规则加了 `:not()`，特异性涨到 (0,2,0)，
 * 侧栏的「系统设置」立刻被染成主色橙。
 *
 * 别把这段前缀"简化"回去 —— 简化了就是一次静默的视觉回归。 */
.app-sider .sidebar-footer .footer-btn {
  color: var(--tk-side-text) !important;
  height: 40px !important;
  padding: 0 16px 0 21px !important;
  display: flex;
  align-items: center;
  gap: 6px;
  border-radius: 0;
  justify-content: flex-start;
  width: 100%;
}
.sidebar-footer.collapsed .footer-btn {
  padding: 0 !important;
  justify-content: center;
}
.app-sider .sidebar-footer .footer-btn:hover {
  color: var(--tk-accent-hover) !important;
  background: var(--tk-accent-soft) !important;
}
.footer-text {
  font-size: 13px;
  white-space: nowrap;
}
/* 「运行中 N/4」——**顶栏右上角**（2026-10-07 最终位置）。
   字色是 `--tk-text-secondary`：顶栏白底。要是哪天又把它搬回侧栏，
   **字色必须一起换成 `--tk-side-text`**，两套颜色不能混用
   （深底反色搬到白底上几乎看不见 —— 这次已经来回踩过两轮）。 */
.health {
  display: flex;
  align-items: center;
  gap: 6px;
  color: var(--tk-text-secondary);
  font-size: 12.5px;
}
/* 版本号在**侧栏底部**，缩进跟「系统设置」对齐；折叠时整行不渲染。 */
.footer-version {
  padding: 0 16px 10px 24px;
  color: var(--tk-side-text);
  font-size: 11.5px;
}
.dot {
  width: 7px;
  height: 7px;
  border-radius: 50%;
  flex-shrink: 0;
}
.dot.ok {
  background: #22c55e;
}
.dot.bad {
  background: #ef4444;
}

/* ── 顶栏 ── */
.app-layout {
  width: 100vw;
  min-height: 100vh;
  background: var(--tk-bg);
  display: flex;
  flex-direction: row;
  align-items: stretch;
  overflow-x: hidden;
}
.header {
  background: var(--tk-surface) !important;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 24px;
  box-shadow: 0 1px 4px rgba(0, 0, 0, 0.08);
  position: sticky;
  top: 0;
  z-index: 10;
  border-bottom: 1px solid var(--tk-border);
  flex-shrink: 0;
  height: var(--tk-header-height);
  line-height: normal;
}
.header-left {
  display: flex;
  align-items: center;
  gap: 16px;
}
.trigger {
  font-size: 18px;
  cursor: pointer;
  color: var(--tk-text);
  display: flex;
}
.trigger:hover {
  color: var(--tk-accent);
}
.header-title {
  margin: 0;
  font-size: 18px;
  font-weight: 600;
  color: var(--tk-text);
}
.header-right {
  display: flex;
  align-items: center;
  gap: 10px;
}
/* 版本号**不在顶栏**（2026-10-07 挪到侧栏底部 `.footer-version`），
   顶栏右边只剩「运行中 N/4」。 */

/* ── 内容区 ── */
.content {
  background: var(--tk-bg-soft) !important;
  min-height: calc(100vh - var(--tk-header-height));
  padding: 24px 32px;
  overflow-x: hidden;
}
</style>
