<script setup>
/**
 * 血缘图 —— 「这个资产是怎么被发现的」。
 *
 * ## 为什么是树布局，不是力导向
 *
 * 数据本身就是一棵树：每条事件只有一个 `parent_id`，SEED 是根。
 * 力导向（bbot 用的那种）是为**无向有环图**设计的，放在树上会做无意义的
 * 力学迭代，而且实测有一类扫描里单个节点能连出 90+ 条边 —— 那种扇出
 * 放到力导向里必然成一团毛球，而且每帧重算 = 掉帧。
 *
 * `breadthfirst` 是 O(n) 的一次性布局，不迭代，所以不卡。
 *
 * ## 为什么高扇出默认折叠
 *
 * 同一个节点下挂几十个孩子，竖着铺出去就是一堵墙。超过阈值就折起来，
 * 节点上标 "+N"，点一下展开。默认阈值 10 —— 再大就真的看不了了。
 */
import { computed, nextTick, onBeforeUnmount, ref, shallowRef, watch } from 'vue'
import { message } from 'ant-design-vue'
import { getLineage } from '@/api'

const props = defineProps({ scanId: { type: Number, required: true } })
const emit = defineEmits(['open-trace'])

/** 超过这个子节点数就默认折叠。
 *  包括根节点在内 —— scan 54 的种子下面直接挂着 72 个子域，全展开是一条约
 *  3000px 宽、100px 高的**窄带**，画布 90% 空着，一个名字都读不出来。
 *  与其硬摊成不可读的形状，不如默认收成一个点、点一下展开，
 *  并把"这里有 72 个"写在工具栏上。 */
const COLLAPSE_AT = 10
/** 初始缩放下限 */
const MIN_ZOOM = 0.3
/** 缩放到这个倍数以上才显示节点名。低于它就只画点 ——
 *  72 个兄弟节点一行铺开有近 3000px 宽，标签互相压着重叠，**一个字都读不出来**，
 *  而点本身在 0.3 倍下清清楚楚。跟成熟工具的「概览看形状、放大看名字」一致。 */
const LABEL_ZOOM = 0.85

//: 事件类型 -> 颜色 + 形状。颜色沿用 ant 的色板，和事件表里的 tag 同一套，
//: 两处看同一个类型颜色一样，不用记两遍映射。
//: 形状也带信息：根、域名、IP、端口、证书/技术/发现 各用一种，扫一眼能分辨。
const TYPE_STYLE = {
  SEED: { color: '#8c8c8c', shape: 'round-rectangle' },
  DNS_NAME: { color: '#1677ff', shape: 'ellipse' },
  IP_ADDRESS: { color: '#13c2c2', shape: 'round-diamond' },
  OPEN_TCP_PORT: { color: '#2f54eb', shape: 'hexagon' },
  SSL_CERTIFICATE: { color: '#722ed1', shape: 'rectangle' },
  TECHNOLOGY: { color: '#eb2f96', shape: 'rectangle' },
  FINDING: { color: '#f5222d', shape: 'rectangle' },
  URL: { color: '#bfbfbf', shape: 'round-rectangle' },
  HTTP_RESPONSE: { color: '#bfbfbf', shape: 'round-rectangle' },
}
const ALL_TYPES = Object.keys(TYPE_STYLE)

const box = ref(null)
const cy = shallowRef(null)
const busy = ref(false)
const stats = ref({ nodes: 0, edges: 0, total: 0, shown: 0, truncated: false, orphans: 0 })
/** 扇出最大的那个折叠节点 —— 用来在工具栏说清"这里还藏着多少" */
const hubInfo = ref(null)

//: ⚠️ 默认 kind='all'、maxDepth=2，不是「结论型 + 全部深度」。
//: 原因：**按类型一筛，它就不是树了**。scan 54 的结论型 350 个节点里有
//: 98 个断头（父事件是 URL/HTTP_RESPONSE，被滤掉了），breadthfirst 会把
//: 98 棵树并排铺开 —— 又宽又不成链，"怎么被发现的"这个问题反而答不了。
//: 全部模式下 779 节点是**一棵**单根树（778 边 / 0 断头），深度才有意义。
//: 规模靠深度控制：深度 ≤2 是 123 个节点，一屏看得完；想看全把深度放开。
const kind = ref('all')
const wantTypes = ref([])
const maxDepth = ref(2)
const q = ref('')
const depthOptions = [
  { value: 2, label: '前 2 层（概览）' },
  { value: 3, label: '前 3 层' },
  { value: 4, label: '前 4 层' },
  { value: 5, label: '前 5 层' },
  { value: 6, label: '前 6 层' },
  { value: null, label: '全部深度' },
]
const typeOptions = ALL_TYPES.map((t) => ({ value: t, label: t }))

/** 断头：父事件被类型筛选滤掉了。把它们当根画，但要说清楚，别让人以为图是完整的。 */
const orphanCount = computed(() => stats.value.orphans || 0)

function shortLabel(s) {
  s = String(s ?? '')
  return s.length > 30 ? `${s.slice(0, 29)}…` : s
}

//: cytoscape 的样式表。**只在这里**写一次，图例和实际颜色同源。
const CY_STYLE = [
  {
    selector: 'node',
    style: {
      // label 由 zoom 事件动态开关（见 LABEL_ZOOM），初始不画。
      label: '',
      'background-color': 'data(color)',
      shape: 'data(shape)',
      width: 12,
      height: 12,
      'font-size': 9,
      color: '#333',
      'text-valign': 'bottom',
      'text-margin-y': 3,
      'text-max-width': 160,
      'text-wrap': 'ellipsis',
      'border-width': 1,
      'border-color': '#fff',
    },
  },
  // 根节点大一点，一眼能找到从哪儿开始
  { selector: 'node[root]', style: { width: 18, height: 18, 'font-size': 11, 'font-weight': 600 } },
  // 断头：虚线框 + 浅色，提示"它的上游被你筛掉了"
  { selector: 'node[orphan]', style: { 'border-width': 2, 'border-color': '#ffa940', 'border-style': 'dashed' } },
  // ⚠️ 这里**不能**覆盖 label 去画 "+N" 徽标：
  // 那会把节点的名字整个抹掉（data(label2) 这个字段根本不存在），
  // 折叠后只剩一个空圆圈，看不出是什么。徽标改用 border-width 表达，
  // 数字放在 tooltip 里。
  {
    selector: 'node[folded > 0]',
    style: { 'border-width': 3, 'border-color': '#fa8c16' },
  },
  // 折叠时被藏起来的后代。display:none 也会连带把相连的边一起藏掉。
  { selector: 'node.folded', style: { display: 'none' } },
  {
    selector: 'node:selected',
    style: { 'border-width': 3, 'border-color': '#1677ff', 'overlay-opacity': 0 },
  },
  {
    selector: 'edge',
    style: {
      width: 1,
      'line-color': '#d9d9d9',
      'target-arrow-color': '#d9d9d9',
      'target-arrow-shape': 'triangle',
      'arrow-scale': 0.5,
      // 直线比贝塞尔便宜很多。778 条边时这个差别看得出来。
      'curve-style': 'straight',
    },
  },
  { selector: 'edge.highlighted', style: { width: 2, 'line-color': '#1677ff', 'target-arrow-color': '#1677ff' } },
]

let timer = null
let ro = null
/** applyCollapse 建好的展开函数，供「一次展开」按钮复用 */
let unfoldNode = null
/** 标签的缩放阈值同步函数，fit 之后要再叫一次（zoom 变了但不一定触发事件） */
let syncLabelsFn = null

function destroy() {
  ro?.disconnect()
  ro = null
  cy.value?.destroy()
  cy.value = null
}

async function load() {
  if (!props.scanId) return
  busy.value = true
  try {
    const params = { kind: kind.value, limit: 4000 }
    // 空串/空数组不要发：后端会当成"筛一个空的东西"
    if (wantTypes.value.length) params.types = wantTypes.value.join(',')
    if (maxDepth.value !== null) params.max_depth = maxDepth.value
    if (q.value) params.q = q.value
    const g = await getLineage(props.scanId, params)
    stats.value = {
      nodes: g.nodes.length,
      edges: g.edges.length,
      total: g.total,
      shown: g.shown,
      truncated: g.truncated,
      orphans: g.orphans.length,
    }

    const elements = [
      ...g.nodes.map((n) => ({
        data: {
          id: String(n.id),
          // ⚠️ 这个键**不能叫 parent**。cytoscape 会把 data.parent 当成
          // 「复合节点的父节点」，于是整棵血缘树被当成一堆嵌套盒子布局，
          // 结果是一团压扁的窄带。存成 src，语义才是我们自己定义的。
          src: n.parent === null ? null : String(n.parent),
          label: shortLabel(n.data),
          type: n.type,
          color: (TYPE_STYLE[n.type] || {}).color || '#bfbfbf',
          shape: (TYPE_STYLE[n.type] || {}).shape || 'ellipse',
          depth: n.depth,
          orphan: g.orphans.includes(n.id) ? 1 : 0,
          raw: n.data,
        },
      })),
      ...g.edges.map((e, i) => ({
        data: { id: `e${i}`, source: String(e.from), target: String(e.to) },
      })),
    ]

    destroy()
    // ⚠️ **必须等容器有真实尺寸再建图**。
    // ant 的 tab pane 首次激活时容器可能还是 0×0（或 display:none 没布局），
    // cytoscape 会按 0×0 算布局，fit() 再把缩放压到 minZoom —— 结果是
    // "图建好了、一个节点也看不见"，而且不会报任何错。
    // nextTick 解决不了全部情况（父级布局未稳定），所以下面还有 ResizeObserver 兜底。
    await nextTick()
    const { default: cytoscape } = await import('cytoscape')
    const inst = cytoscape({
      container: box.value,
      elements,
      style: CY_STYLE,
      // animate: false —— 布局动画在几百个节点时是最明显的卡顿来源，
      // 而它带来的"优雅"对这个数据量毫无价值。
      layout: {
        name: 'breadthfirst',
        directed: true,
        // ⚠️ 不写 orientation 的话，有向 breadthfirst 默认是**从左往右** ——
        // 实测整棵树被压成一条又宽又扁的横带，完全读不出层级。
        orientation: 'top-down',
        padding: 24,
        // 1.3 太松：72 个兄弟节点一行本来就有近 3000px，再乘 1.3 更读不了。
        spacingFactor: 1.1,
        animate: false,
      },
      minZoom: 0.02,
      maxZoom: 3,
      wheelSensitivity: 0.2,
      boxSelectionEnabled: false,
    })
    cy.value = inst

    // 根 = 没有上游的（也包括断头：父事件被筛掉了）。断头节点也当根画。
    inst.nodes().forEach((n) => {
      const p = n.data('src')
      if (!p || !inst.getElementById(p).length) n.addClass('root')
    })

    try {
      applyCollapse(inst)
    } catch (err) {
      message.error(`图渲染失败：${err && err.message ? err.message : String(err)}`)
    }
    bindEvents(inst)

    // ⚠️ **必须等布局落定再 fit**。breadthfirst 的节点定位不是构造完就好的，
    // 在那之前调 fit() 会按旧坐标算缩放和平移 —— 症状是"图画出来了，
    // 但大半张画布空着，图缩在左下角"，而且不报任何错。
    const fitNow = () => {
      if (!box.value?.clientWidth || !box.value?.clientHeight) return
      inst.resize()
      inst.fit(undefined, 30)
      // 一屏塞下 72 个节点时 fit 会把缩放压到 0.3 以下，字全糊成一团。
      // 给个可读下限：太小就退到 MIN_ZOOM 并把根摆到中间。
      if (inst.zoom() < MIN_ZOOM) {
        inst.zoom(MIN_ZOOM)
        // 只平移视口，**不动节点坐标** —— 用 positions() 改根的位置会破坏
        // breadthfirst 算好的布局，根一动整棵树就错位重叠。
        const r = inst.nodes('.root')
        if (r.length) {
          const p = r[0].position()
          inst.panBy({ x: inst.width() / 2 - p.x, y: 56 - p.y })
        }
      }
      // 折叠到只剩根节点时 fit 会把缩放拉得很高，此时**必须**把标签打开，
      // 否则画布上就剩一个没名字的点。
      syncLabelsFn?.()
    }
    inst.one('layoutready', fitNow)
    // 容器本身也要有尺寸。tab 首次激活时可能是 0×0（vh 也算不出高度），
    // 那种情况下 resize 之后才谈得上 fit。
    if (box.value?.clientWidth && box.value?.clientHeight) {
      fitNow()
    } else {
      ro = new ResizeObserver(() => {
        if (box.value?.clientWidth && box.value?.clientHeight) {
          fitNow()
          ro.disconnect()
          ro = null
        }
      })
      ro.observe(box.value)
    }
  } catch (e) {
    message.error(e.message)
  } finally {
    busy.value = false
  }
}

/** 高扇出节点默认折叠。descendants 记忆化，避免每次点击都全图遍历。 */
function applyCollapse(inst) {
  const kids = new Map()
  inst.edges().forEach((e) => {
    const s = e.source().id()
    if (!kids.has(s)) kids.set(s, [])
    kids.get(s).push(e.target().id())
  })

  const descCache = new Map()
  const descendantsOf = (id) => {
    if (descCache.has(id)) return descCache.get(id)
    const out = []
    const stack = [...(kids.get(id) || [])]
    while (stack.length) {
      const cur = stack.pop()
      out.push(cur)
      for (const k of kids.get(cur) || []) stack.push(k)
    }
    descCache.set(id, out)
    return out
  }

  inst.nodes().forEach((n) => {
    // ⚠️ cytoscape 的 id 是**方法** ``n.id()``，不是属性 ``n.id``。
    // 写成属性会拿到 undefined，于是 kids.get(undefined) 永远是空 ——
    // 症状是「图画得好好的，折叠永远不生效，工具栏也不出现」。
    // 这个坑静悄悄的：不报错、不抛异常，只是什么都不发生。
    const k = kids.get(n.id())
    if (!k || k.length <= COLLAPSE_AT) {
      n.data('folded', 0)
      return
    }
    n.data('folded', k.length)
    n.addClass('folded')
    // ⚠️ 用 ``hide()`` 而不是「加个 class 让样式表 display:none」——
    // 后者实测不生效。hide() 是元素级 API，相连的边也会自动跟着藏。
    for (const d of descendantsOf(n.id())) inst.getElementById(d).hide()
  })

  const unfold = (n) => {
    for (const d of descendantsOf(n.id())) inst.getElementById(d).show()
    n.removeClass('folded')
    n.data('folded', 0)
  }
  inst.on('tap', 'node', (evt) => {
    const n = evt.target
    if (!n.data('folded')) return
    // 别顺手把溯源框也弹出来：第一次点这个节点是「展开」，
    // 展开完再点一次才是「看它怎么被发现的」。
    evt.stopPropagation()
    unfold(n)
  })
  unfoldNode = unfold

  // 把"这里还藏着多少"摆到工具栏。不说的话默认折叠的 hub 会被误读成
  // 「就只找到这一个」。
  // ⚠️ 别用 collection.sortBy() —— 新版 cytoscape（3.28+）把它挪进了扩展，
  // 基类上已经没有了，实测直接抛 "sortBy is not a function"。
  // 这里的异常会把后面 hubInfo 的赋值一起带走，表现为「折叠永远不生效」。
  // 一律 toArray() 后用原生数组排序，不挑版本。
  const hub = inst
    .nodes()
    .toArray()
    .filter((n) => (n.data('folded') || 0) > 0)
    .sort((a, b) => (b.data('folded') || 0) - (a.data('folded') || 0))
  const top = hub[0]
  hubInfo.value = top
    ? { id: top.id(), folded: top.data('folded'), label: top.data('label') }
    : null
}

function bindEvents(inst) {
  inst.on('tap', 'node', (evt) => {
    emit('open-trace', Number(evt.target.id()))
  })
  inst.on('mouseover', 'node', (evt) => {
    const d = evt.target.data()
    evt.target.data('tip', `${d.type}\n${d.raw}`)
  })

  // 标签只在放得够大时出现。**只在跨过阈值时改样式**，不是在 zoom 里
  // 每次都重设 —— 后者在连续缩放时是明显的卡顿来源。
  let labelsOn = null
  const syncLabels = () => {
    const on = inst.zoom() >= LABEL_ZOOM
    if (on === labelsOn) return
    labelsOn = on
    inst
      .style()
      .selector('node')
      .style('label', on ? 'data(label)' : '')
      .style('font-size', on ? 9 : 1)
      .update()
  }
  inst.on('zoom', syncLabels)
  // 首次也要同步一次（fit 之后 zoom 可能已经在阈值之上）
  queueMicrotask(syncLabels)
  syncLabelsFn = syncLabels
}

function fit() {
  cy.value?.fit(undefined, 30)
}

/** 把折叠着的那一支展开。seed 下面挂着几十个子域，全展开是条读不了的窄带，
 *  所以默认收着，这里给一个"一次展开"而不是逼用户逐个点。 */
function expandTop() {
  const inst = cy.value
  if (!inst || !hubInfo.value || !unfoldNode) return
  const n = inst.getElementById(hubInfo.value.id)
  if (!n.length) return
  unfoldNode(n)
  hubInfo.value = null
  inst.fit(undefined, 30)
}
function zoom(step) {
  const inst = cy.value
  if (!inst) return
  const z = inst.zoom()
  inst.zoom({ level: Math.min(3, Math.max(0.02, z * step)), renderedPosition: { x: inst.width() / 2, y: inst.height() / 2 } })
}

function onSearch(v) {
  q.value = v
  clearTimeout(timer)
  timer = setTimeout(load, 400)
}

function onFilterChange() {
  load()
}

watch(() => props.scanId, load, { immediate: true })
onBeforeUnmount(() => {
  clearTimeout(timer)
  destroy()
})

defineExpose({ reload: load, fit })
</script>

<template>
  <div class="lin">
    <div class="lin-bar">
      <a-radio-group v-model:value="kind" size="small" @change="onFilterChange">
        <a-radio-button value="all">完整链路</a-radio-button>
        <a-radio-button value="conclusion">只看结论</a-radio-button>
      </a-radio-group>

      <a-select
        v-model:value="wantTypes"
        mode="multiple"
        placeholder="类型（不选=按上面）"
        size="small"
        style="width: 230px"
        allow-clear
        :max-tag-count="1"
        :options="typeOptions"
        @change="onFilterChange"
      />
      <a-select
        v-model:value="maxDepth"
        size="small"
        style="width: 140px"
        :options="depthOptions"
        @change="onFilterChange"
      />
      <a-input
        :value="q"
        placeholder="搜数据（子串）"
        size="small"
        style="width: 180px"
        allow-clear
        @change="(e) => onSearch(e.target.value)"
      />

      <span class="tk-muted" style="margin-left: auto; font-size: 12px">
        <template v-if="stats.truncated">
          <span style="color: #fa8c16">只画了 {{ stats.shown }} / 共 {{ stats.total }} 个节点</span>
        </template>
        <template v-else>
          {{ stats.nodes }} 个节点 · {{ stats.edges }} 条边
        </template>
        <template v-if="orphanCount"> · {{ orphanCount }} 个断头</template>
      </span>

      <a-button v-if="hubInfo" size="small" @click="expandTop">
        展开 {{ hubInfo.folded }} 个子节点
      </a-button>
      <a-button size="small" @click="fit">适配</a-button>
      <a-button size="small" @click="zoom(1.2)">＋</a-button>
      <a-button size="small" @click="zoom(1 / 1.2)">－</a-button>
    </div>

    <a-alert
      v-if="stats.truncated || orphanCount"
      type="warning"
      show-icon
      banner
      class="lin-note"
    >
      <template #message>
        <span v-if="stats.truncated">节点太多，只画了前 {{ stats.shown }} 个（共 {{ stats.total }}），收窄类型或深度能看全。</span>
        <span v-else-if="orphanCount">
          虚线框的 {{ orphanCount }} 个节点是<b>断头</b>：父事件被类型筛选滤掉了，所以各画成一个根。切到「完整链路」能看到从种子一路下来的完整因果。
        </span>
      </template>
    </a-alert>

    <a-spin :spinning="busy">
      <div ref="box" class="lin-canvas" />
    </a-spin>

    <div class="lin-legend">
      <span v-for="t in ALL_TYPES" :key="t" class="lin-key">
        <i :style="{ background: TYPE_STYLE[t].color }" />{{ t }}
      </span>
    </div>
  </div>
</template>

<style scoped>
.lin-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.lin-note {
  margin-bottom: 8px;
}
/* 给一个明确的高度：cytoscape 在没有尺寸的容器里会算出 0 高度，
   表现为「什么都没有」而且不报错。
   ⚠️ 用 calc 而不是 vh：概览卡片在这个 tab 里已隐藏，上面还占着
   head + tab 栏，所以要减掉那部分，否则底部会被视口切掉。 */
.lin-canvas {
  height: calc(100vh - 330px);
  min-height: 360px;
  max-height: 900px;
  border: 1px solid var(--tk-border);
  border-radius: 6px;
  background: #fbfbfb;
}
.lin-legend {
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
  margin-top: 8px;
  font-size: 11px;
  color: #888;
}
.lin-key i {
  display: inline-block;
  width: 9px;
  height: 9px;
  border-radius: 50%;
  margin-right: 4px;
  vertical-align: middle;
}
</style>
