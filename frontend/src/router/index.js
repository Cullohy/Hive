import { createRouter, createWebHistory } from 'vue-router'

const TaskListView = () => import('@/views/TaskListView.vue')
const TaskDetailView = () => import('@/views/TaskDetailView.vue')
const AssetView = () => import('@/views/AssetView.vue')
const AssetGroupView = () => import('@/views/AssetGroupView.vue')
const FingerprintView = () => import('@/views/FingerprintView.vue')

// 菜单结构对标 ARL：图标 + 中文标签，顺序也保持一致的观感
const routes = [
  // 首页就是任务管理 —— 创建任务的入口在那一页的工具栏上，
  // 不再单独占一个「一键收集」页面。
  { path: '/', redirect: '/taskList' },
  {
    path: '/taskList',
    name: 'task-list',
    component: TaskListView,
    meta: { title: '任务管理', menu: 'task' },
  },
  {
    path: '/taskList/taskDetail',
    name: 'task-detail',
    component: TaskDetailView,
    meta: { title: '任务详情', menu: 'task' },
  },
  {
    path: '/assets',
    name: 'assets',
    component: AssetView,
    meta: { title: '资产管理', menu: 'assets' },
  },
  {
    path: '/asset-groups',
    name: 'asset-groups',
    component: AssetGroupView,
    meta: { title: '资产分组', menu: 'asset-groups' },
  },
  {
    path: '/fingerprints',
    name: 'fingerprints',
    component: FingerprintView,
    meta: { title: '指纹规则', menu: 'fingerprints' },
  },
  // 兜底：未知路径回任务列表
  { path: '/:pathMatch(.*)*', redirect: '/taskList' },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

router.afterEach((to) => {
  const title = to.meta?.title
  document.title = title ? `${title} · Hive蜂巢` : 'Hive蜂巢 · 信息收集引擎'
})

export default router
