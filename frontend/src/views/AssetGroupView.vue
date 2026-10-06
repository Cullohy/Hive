<template>
  <div class="tk-page">
    <!-- ── 概览 ── -->
    <div class="tk-stat-grid" style="margin-bottom: 16px">
      <div v-for="card in statCards" :key="card.label" class="tk-stat">
        <div class="tk-stat-label">{{ card.label }}</div>
        <div class="tk-stat-value" :class="{ accent: card.accent }">{{ card.value }}</div>
      </div>
    </div>

    <!-- ── 分组列表 ── -->
    <div class="tk-card">
      <div class="toolbar">
        <h3 class="tk-card-title" style="margin: 0">资产分组</h3>
        <span class="grow" />
        <a-button type="primary" @click="openCreate">
          <PlusOutlined /> 新建分组
        </a-button>
      </div>

      <a-table
        :columns="groupColumns"
        :data-source="groups"
        :loading="loading"
        row-key="id"
        size="middle"
        :pagination="false"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'name'">
            <a class="tk-mono group-link" @click="openDetail(record)">{{ record.name }}</a>
            <div v-if="record.description" class="tk-muted group-desc">
              {{ record.description }}
            </div>
          </template>

          <!-- 任务：名字优先，附资产量。列表页就要能看出"这个组由哪几次扫描构成" -->
          <template v-else-if="column.key === 'scans'">
            <span v-if="(record.scans || []).length" class="tk-mono tk-small">
              {{ record.scans.slice(0, 2).map((s) => s.name || `#${s.scan_id}`).join('、')
              }}<template v-if="record.scans.length > 2">
                等 {{ record.scans.length }} 个</template>
            </span>
            <span v-else class="tk-muted">未选任务</span>
          </template>

          <template v-else-if="column.key === 'counts'">
            <span class="tk-mono">
              合计 <b>{{ assetTotalOf(record) }}</b>
              <span v-if="record.domain_count" class="tk-muted">
                （域名 {{ record.domain_count }} · IP {{ record.ip_count || 0 }}）</span>
            </span>
          </template>

          <template v-else-if="column.key === 'created_at'">
            <span class="tk-muted">{{ (record.created_at || '').slice(0, 10) }}</span>
          </template>

          <template v-else-if="column.key === 'actions'">
            <a-button type="link" size="small" style="padding: 0; margin-right: 8px" @click="openDetail(record)">
              资产
            </a-button>
            <a-button type="link" size="small" style="padding: 0; margin-right: 8px" @click="openEdit(record)">
              编辑
            </a-button>
            <a-popconfirm
              title="删除这个分组？组内已归集的资产记录会一起删除。"
              ok-text="删除"
              cancel-text="取消"
              @confirm="onDelete(record)"
            >
              <a-button type="link" danger size="small" style="padding: 0">删除</a-button>
            </a-popconfirm>
          </template>
        </template>
        <template #emptyText>
          <div class="tk-empty">
            还没有资产分组。新建一个，勾上几个任务 —— 这些任务扫出来的资产
            就是一个组。
          </div>
        </template>
      </a-table>
    </div>

    <!-- ── 新建 / 编辑分组 ── -->
    <a-modal
      v-model:open="formOpen"
      :title="editing ? '编辑分组' : '新建分组'"
      :width="640"
      :confirm-loading="saving"
      ok-text="保存"
      cancel-text="取消"
      @ok="save"
    >
      <a-form layout="vertical" style="margin-bottom: 0">
        <a-form-item label="分组名称">
          <a-input v-model:value="form.name" placeholder="例如：亿联网络（主站 + 复测）" />
        </a-form-item>
        <a-form-item label="包含的任务">
          <a-select
            v-model:value="form.scanIds"
            mode="multiple"
            show-search
            allow-clear
            :filter-option="filterScan"
            placeholder="选择任务（可多选）。组内资产 = 这些任务扫出资产的并集"
            style="width: 100%"
            :not-found-content="scans.length ? undefined : '还没有任务，先去扫一个'"
          >
            <a-select-option
              v-for="s in scans"
              :key="s.scan_id"
              :value="s.scan_id"
              :label="scanLabel(s)"
            >
              {{ scanLabel(s) }}
              <!-- ⚠️ 用 ``domains`` 而不是 ``asset_count``：``/api/scans`` 只回
                   domains / urls 两个现算计数，没有全类型总数。写一个不存在的
                   字段名，下拉里就会恒显示「0 资产」—— 那是假数据。 -->
              <span class="tk-muted opt-meta">
                {{ (s.targets || []).join(', ') }} · 域名 {{ s.domains ?? 0 }}
              </span>
            </a-select-option>
          </a-select>
          <div class="tk-muted tk-small" style="margin-top: 6px">
            勾几个任务就是一组。取消勾选时，**只被那个任务扫到**的资产会离组；
            几个任务都扫到的仍然留在组里。
          </div>
        </a-form-item>
        <a-form-item label="描述（可选）">
          <a-input v-model:value="form.description" placeholder="这个分组是干什么的" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- ── 分组详情（抽屉）：包含的任务 + 资产 ── -->
    <a-drawer
      v-model:open="detailOpen"
      :title="current ? `${current.name} · 资产` : '分组资产'"
      width="72%"
    >
      <a-spin :spinning="detailLoading">
        <template v-if="current">
          <!-- 包含的任务 -->
          <div class="section">
            <div class="section-head">
              <span class="section-title">包含的任务</span>
              <a-button size="small" @click="openEdit(current)">
                <EditOutlined /> 调整
              </a-button>
            </div>
            <a-tag
              v-for="s in current.scans || []"
              :key="s.scan_id"
              class="tk-mono scope-tag"
              :closable="!removing"
              @close="onRemoveScan(s)"
            >
              {{ s.name || `#${s.scan_id}` }}
              <span class="tk-muted tk-small"> · {{ s.asset_count ?? 0 }}</span>
            </a-tag>
            <span v-if="!(current.scans || []).length" class="tk-muted">
              还没有勾选任务 —— 组内资产为空。
            </span>
          </div>

          <!-- 资产 -->
          <div class="section">
            <div class="section-head">
              <span class="section-title">组内资产</span>
              <a-input-search
                v-model:value="assetKeyword"
                placeholder="过滤资产"
                style="width: 220px"
                allow-clear
                @search="loadAssets"
              />
            </div>

            <a-tabs v-model:activeKey="assetTab" @change="onTabChange">
              <a-tab-pane
                v-for="t in assetTabs"
                :key="t.key"
                :tab="`${t.label} (${assetCounts[t.key] || 0})`"
              />
            </a-tabs>

            <a-table
              :columns="assetColumns"
              :data-source="assets"
              :loading="assetLoading"
              row-key="id"
              size="small"
              :pagination="{
                pageSize: assetPageSize,
                showSizeChanger: true,
                current: assetPage,
                total: assetTotal,
                // ant-design-vue 4.2.6 的 `usePagination.onInternalChange` 调的是
                // `onChange(current, pageSize)` —— **两个位置参数**，不是分页对象。
                onChange: (p, size) => { onAssetPageChange(p, size) },
              }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'asset_key'">
                  <span class="tk-mono">{{ record.asset_key }}</span>
                </template>
                <template v-else-if="column.key === 'asset_type'">
                  <a-tag :color="typeColor(record.asset_type)">
                    {{ typeLabel(record.asset_type) }}
                  </a-tag>
                </template>
                <template v-else-if="column.key === 'url'">
                  <span class="tk-muted tk-small">{{ record.url || '-' }}</span>
                </template>
                <template v-else-if="column.key === 'first_seen'">
                  <span class="tk-muted">{{ (record.first_seen || '').slice(0, 19).replace('T', ' ') }}</span>
                </template>
              </template>
            </a-table>
          </div>
        </template>
      </a-spin>
    </a-drawer>
  </div>
</template>

<script setup>
import { EditOutlined, PlusOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, onMounted, reactive, ref } from 'vue'

import {
  createGroup,
  deleteGroup,
  getGroup,
  getGroupAssets,
  listGroups,
  listScans,
  updateGroup,
} from '@/api'

/** 资产类型 → 展示名。顺序即 tab 顺序。
 *
 *  ⚠️ **不要写成写死的两三个 tab。** 范围改成"按任务"之后，组内资产就是
 *  所选任务的 scan_asset 并集，类型由任务扫出什么决定 —— 早先写死
 *  「域名 / IP」两个 tab 的结果是：点进去是空的，tab 上的数字却非零
 *  （counts 里有、过滤条件对不上）。
 */
const ASSET_TYPES = [
  { key: 'domain', label: '域名' },
  { key: 'ip', label: 'IP' },
  { key: 'port', label: '端口' },
  { key: 'url', label: 'URL' },
  { key: 'http_endpoint', label: 'HTTP 端点' },
  { key: 'technology', label: '技术栈' },
  { key: 'url_path', label: '路径' },
]

// ── 分组列表 ─────────────────────────────────────────────────────────
const groups = ref([])
const scans = ref([])
const loading = ref(false)

const statCards = computed(() => [
  { label: '分组数', value: groups.value.length, accent: true },
  {
    label: '归集域名',
    value: groups.value.reduce((n, g) => n + (g.domain_count || 0), 0),
  },
  { label: '归集 IP', value: groups.value.reduce((n, g) => n + (g.ip_count || 0), 0) },
  { label: '归集资产', value: groups.value.reduce((n, g) => n + assetTotalOf(g), 0) },
])

const groupColumns = [
  { title: '名称', key: 'name', width: 260 },
  { title: '包含的任务', key: 'scans', width: 240 },
  { title: '资产', key: 'counts', width: 220 },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 120 },
  { title: '操作', key: 'actions', width: 180 },
]

/** 组内资产总数。列表接口不带分类型明细，用 domain+ip 兜底显示。 */
function assetTotalOf(g) {
  if (typeof g.asset_count === 'number') return g.asset_count
  return (g.domain_count || 0) + (g.ip_count || 0)
}

async function load() {
  loading.value = true
  try {
    groups.value = await listGroups()
  } catch (e) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  load()
  listScans(100)
    .then((s) => (scans.value = s || []))
    .catch(() => {})
})

// ── 新建 / 编辑 ──────────────────────────────────────────────────────
const formOpen = ref(false)
const editing = ref(null)
const saving = ref(false)
const form = reactive({ name: '', description: '', scanIds: [] })

function openCreate() {
  editing.value = null
  form.name = ''
  form.description = ''
  form.scanIds = []
  formOpen.value = true
}

async function openEdit(record) {
  // 列表行可能不含完整 scans，编辑前先取详情
  let full = record
  if (!full.scans) {
    try {
      full = await getGroup(record.id)
    } catch (e) {
      message.error(e.message)
      return
    }
  }
  editing.value = full
  form.name = full.name
  form.description = full.description || ''
  form.scanIds = (full.scans || []).map((s) => s.scan_id)
  formOpen.value = true
}

async function save() {
  const name = form.name.trim()
  if (!name) {
    message.warning('分组名称不能为空')
    return
  }
  saving.value = true
  try {
    if (editing.value) {
      await updateGroup(editing.value.id, {
        name,
        description: form.description,
        scan_ids: form.scanIds,
      })
      message.success('已保存')
    } else {
      await createGroup({
        name,
        description: form.description,
        scan_ids: form.scanIds,
      })
      message.success('已创建')
    }
    formOpen.value = false
    await load()
    if (detailOpen.value && current.value) await refreshDetail()
  } catch (e) {
    message.error(e.message)
  } finally {
    saving.value = false
  }
}

async function onDelete(record) {
  try {
    await deleteGroup(record.id)
    message.success('已删除')
    if (current.value?.id === record.id) detailOpen.value = false
    await load()
  } catch (e) {
    message.error(e.message)
  }
}

// ── 详情抽屉 ─────────────────────────────────────────────────────────
const detailOpen = ref(false)
const detailLoading = ref(false)
const current = ref(null)
const removing = ref(false)

const assets = ref([])
const assetLoading = ref(false)
const assetCounts = ref({})
const assetTotal = ref(0)
const assetPage = ref(1)
//: 页大小。**必须与 loadAssets 里发出去的 limit 同源** —— 两处各写一份，
//: 一旦放开 showSizeChanger 就必然对不上（offset 按一个值算、limit 发另一个）。
const assetPageSize = ref(20)
const assetKeyword = ref('')
const assetTab = ref('domain')

const assetTabs = computed(() => {
  const present = ASSET_TYPES.filter((t) => (assetCounts.value[t.key] || 0) > 0)
  return present.length ? present : ASSET_TYPES.slice(0, 2)
})

const assetColumns = [
  { title: '资产', key: 'asset_key' },
  { title: '类型', key: 'asset_type', width: 100 },
  { title: 'URL', key: 'url', ellipsis: true },
  { title: '首次归集', dataIndex: 'first_seen', key: 'first_seen', width: 180 },
]

function typeLabel(k) {
  return ASSET_TYPES.find((t) => t.key === k)?.label || k
}

function typeColor(k) {
  return (
    {
      domain: 'blue',
      ip: 'cyan',
      port: 'purple',
      url: 'green',
      http_endpoint: 'gold',
      technology: 'magenta',
    }[k] || undefined
  )
}

async function openDetail(record) {
  current.value = record
  detailOpen.value = true
  assetPage.value = 1
  await refreshDetail()
}

/** 拉分组详情（带它包含的任务）并刷新资产表。 */
async function refreshDetail() {
  if (!current.value) return
  detailLoading.value = true
  try {
    current.value = await getGroup(current.value.id)
  } catch (e) {
    message.error(e.message)
  } finally {
    detailLoading.value = false
  }
  await loadAssets()
}

/**
 * 从组里移出一个任务。
 *
 * 走的是「整体替换任务集合」那条路（PUT /api/groups/{id}），而不是某个
 * 单独的删接口 —— 任务的增删就是"这个组的范围"的增删，本来就是一回事。
 */
async function onRemoveScan(s) {
  if (!current.value) return
  removing.value = true
  try {
    const keep = (current.value.scans || [])
      .filter((x) => x.scan_id !== s.scan_id)
      .map((x) => x.scan_id)
    await updateGroup(current.value.id, {
      name: current.value.name,
      description: current.value.description || '',
      scan_ids: keep,
    })
    message.success(`已移出「${s.name || `#${s.scan_id}`}」`)
    await refreshDetail()
    await load()
  } catch (e) {
    message.error(e.message)
  } finally {
    removing.value = false
  }
}

/**
 * 分页回调。antd 传的是 `(current, pageSize)` 两个位置参数。
 *
 * **改页大小必须回到第 1 页**：vc-pagination 的 `changePageSize` 会保留
 * 当前页并连发 `change(current, size)`，停在第 5 页改页大小的话，
 * offset 算出来落在中段 —— 用户以为在看第一页，实际看到的是中段数据。
 */
function onAssetPageChange(page, size) {
  const sizeChanged = size && size !== assetPageSize.value
  if (sizeChanged) assetPageSize.value = size
  assetPage.value = sizeChanged ? 1 : page
  loadAssets()
}

function onTabChange(key) {
  assetTab.value = key
  assetPage.value = 1
  loadAssets()
}

async function loadAssets() {
  if (!current.value) return
  assetLoading.value = true
  try {
    const data = await getGroupAssets(current.value.id, {
      type: assetTab.value,
      q: assetKeyword.value,
      limit: assetPageSize.value,
      offset: (assetPage.value - 1) * assetPageSize.value,
    })
    assets.value = data.rows
    assetCounts.value = data.counts
    assetTotal.value = data.total
  } catch (e) {
    message.error(e.message)
  } finally {
    assetLoading.value = false
  }
}

/**
 * 任务下拉里的一行：**任务名称在前** —— 它才是人挑的依据（名称是必填的），
 * 后面缀上目标与资产量：同名任务很常见（"每月巡检"），光看名字分不出是哪一次，
 * 而"它带出多少资产"正是决定要不要勾进这个组的关键信息。
 */
function scanLabel(s) {
  const name = s.name || `未命名 #${s.scan_id}`
  const targets = (s.targets || []).join(', ')
  return targets ? `${name} · ${targets}` : name
}

/** 按任务名/目标过滤。``option-filter-prop="label"`` 只认 label 里的文本。 */
function filterScan(input, option) {
  const kw = (input || '').toLowerCase()
  if (!kw) return true
  return String(option?.label || '').toLowerCase().includes(kw)
}
</script>

<style scoped>
.toolbar {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
}
.grow {
  flex: 1;
}
.group-link {
  font-weight: 600;
  cursor: pointer;
}
.group-desc {
  font-size: 12px;
  margin-top: 2px;
}
.section {
  margin-bottom: 24px;
}
.section-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 10px;
}
.section-title {
  font-weight: 600;
  font-size: 14px;
}
.scope-tag {
  margin-bottom: 6px;
}
.opt-meta {
  display: block;
  font-size: 11px;
  line-height: 1.4;
}
</style>
