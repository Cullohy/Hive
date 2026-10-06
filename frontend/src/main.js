import { createApp } from 'vue'
import Antd from 'ant-design-vue'
import 'ant-design-vue/dist/reset.css'

// dayjs 的中文语言包。**必须显式 import**，ant-design-vue 自己不会带：
//
//   - ConfigProvider 的 locale 只管「今天 / 确定 / YYYY年M月D日」这类格式串，
//     所以加了 :locale="zhCN" 之后「2026年」确实变中文了；
//   - 但月份表和星期头走的是 dayjs（vc-picker/generate/dayjs.js:178-179 的
//     getShortMonths / getShortWeekDays → dayjs().locale('zh-cn').localeData()），
//     而 dayjs 的语言包是**按需注册**的：不 import，`dayjs().locale('zh-cn')`
//     会静默回落到 en（不抛错、不警告），于是面板上就是 Oct / Nov / Su Mo Tu。
//
// 顺带把每周首日从周日(0) 纠正成周一(1)。只给 ConfigProvider 传 locale 数组
// 也能让文字变中文，但首日仍是周日，表头会跟日期列错位 —— 所以走这条。
import 'dayjs/locale/zh-cn'

import App from './App.vue'
import router from './router'
import './styles/global.css'

createApp(App).use(router).use(Antd).mount('#app')
