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

          <template v-else-if="column.key === 'counts'">
            <span class="tk-mono">
              域名 <b>{{ record.domain_count ?? 0 }}</b> · IP <b>{{ record.ip_count ?? 0 }}</b>
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
            还没有资产分组。新建一个，把域名 / IP 网段圈进来，之后每次扫描
            都能把「新发现」同步进组里。
          </div>
        </template>
      </a-table>
    </div>

    <!-- ── 新建 / 编辑分组 ── -->
    <a-modal
      v-model:open="formOpen"
      :title="editing ? '编辑分组' : '新建分组'"
      :width="620"
      :confirm-loading="saving"
      ok-text="保存"
      cancel-text="取消"
      @ok="save"
    >
      <a-form layout="vertical" style="margin-bottom: 0">
        <a-form-item label="分组名称">
          <a-input v-model:value="form.name" placeholder="例如：核心业务资产" />
        </a-form-item>
        <a-form-item label="范围（每行一条）">
          <a-textarea
            v-model:value="scopeText"
            :rows="4"
            :placeholder="scopePlaceholder"
          />
        </a-form-item>
        <a-form-item label="描述（可选）">
          <a-input v-model:value="form.description" placeholder="这个分组是干什么的" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- ── 分组详情（抽屉）：范围 + 资产 + 同步 ── -->
    <a-drawer
      v-model:open="detailOpen"
      :title="current ? `${current.name} · 资产` : '分组资产'"
      width="72%"
    >
      <a-spin :spinning="detailLoading">
        <template v-if="current">
          <!-- 范围 -->
          <div class="section">
            <div class="section-head">
              <span class="section-title">范围</span>
              <a-button size="small" @click="openAddScope">
                <PlusOutlined /> 添加范围
              </a-button>
            </div>
            <a-tag
              v-for="s in current.scopes || []"
              :key="s.id"
              class="tk-mono scope-tag"
              closable
              @close="onDeleteScope(s)"
            >
              {{ s.scope }}
            </a-tag>
            <span v-if="!(current.scopes || []).length" class="tk-muted">
              还没有范围。范围决定「哪些资产算这个组的」。
            </span>
          </div>

          <!-- 同步 -->
          <div class="section">
            <div class="section-head">
              <span class="section-title">同步扫描资产</span>
            </div>
            <div class="sync-bar">
              <a-select
                v-model:value="syncScanId"
                show-search
                option-filter-prop="label"
                placeholder="选择要同步的任务（按名称搜）"
                style="min-width: 260px"
              >
                <a-select-option
                  v-for="s in scans"
                  :key="s.scan_id"
                  :value="s.scan_id"
                  :label="scanLabel(s)"
                >
                  {{ scanLabel(s) }}
                </a-select-option>
              </a-select>
              <a-button type="primary" :disabled="!syncScanId" :loading="syncing" @click="onSync">
                同步到本组
              </a-button>
              <span class="tk-muted sync-hint">
                只把这次扫描「新发现」的资产记进来，已在组里的不会重复计。
              </span>
            </div>
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

            <a-tabs v-model:activeKey="assetTab" @change="loadAssets">
              <a-tab-pane key="domain" :tab="`域名 (${assetCounts.domain || 0})`" />
              <a-tab-pane key="ip" :tab="`IP (${assetCounts.ip || 0})`" />
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
                // 原来写成 `(p) => { assetPage = p; loadAssets() }`：单参写法在
                // 这里恰好拿到页码数字，能用；但 pageSize 被整个丢弃，而
                // `showSizeChanger` 又允许改页大小 —— 改了之后表格还按 20 条一页
                // 算 offset，页大小与实际条数对不上，翻页会漏数据/重复。
                onChange: (p, size) => { onAssetPageChange(p, size) },
              }"
            >
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'asset_key'">
                  <span class="tk-mono">{{ record.asset_key }}</span>
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

    <!-- 添加范围 -->
    <a-modal
      v-model:open="scopeOpen"
      title="添加范围"
      :width="520"
      ok-text="添加"
      cancel-text="取消"
      @ok="onAddScope"
    >
      <a-textarea
        v-model:value="newScopeText"
        :rows="3"
        placeholder="输入域名或 CIDR 范围"
      />
    </a-modal>
  </div>
</template>

<script setup>
import { PlusOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, onMounted, reactive, ref } from 'vue'

import {
  addGroupScopes,
  createGroup,
  deleteGroup,
  deleteGroupScope,
  getGroup,
  getGroupAssets,
  listGroups,
  listScans,
  syncScanToGroup,
  updateGroup,
} from '@/api'

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
])

const groupColumns = [
  { title: '名称', key: 'name', width: 260 },
  { title: '范围', dataIndex: 'scope_count', key: 'scope_count', width: 80 },
  { title: '资产', key: 'counts', width: 200 },
  { title: '创建时间', dataIndex: 'created_at', key: 'created_at', width: 120 },
  { title: '操作', key: 'actions', width: 180 },
]

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
const form = reactive({ name: '', description: '' })
const scopeText = ref('')

// 提示文案放 computed：多行三元写进模板属性会被 Vue 的 tokenizer 拆坏
const scopePlaceholder = 'panabit.com\nexample.org'

function openCreate() {
  editing.value = null
  form.name = ''
  form.description = ''
  scopeText.value = ''
  formOpen.value = true
}

async function openEdit(record) {
  // 列表行不含 scopes（只有 scope_count），编辑要先取详情
  let full = record
  try {
    full = await getGroup(record.id)
  } catch (e) {
    message.error(e.message)
    return
  }
  editing.value = full
  form.name = full.name
  form.description = full.description || ''
  scopeText.value = (full.scopes || []).map((s) => s.scope).join('\n')
  formOpen.value = true
}

async function save() {
  const name = form.name.trim()
  if (!name) {
    message.warning('分组名称不能为空')
    return
  }
  const scopes = scopeText.value.split('\n').map((s) => s.trim()).filter(Boolean)
  saving.value = true
  try {
    if (editing.value) {
      await updateGroup(editing.value.id, { name, description: form.description, scopes })
      message.success('已保存')
    } else {
      await createGroup({ name, description: form.description, scopes })
      message.success('已创建')
    }
    formOpen.value = false
    await load()
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

const assets = ref([])
const assetLoading = ref(false)
const assetCounts = ref({})
const assetTotal = ref(0)
const assetPage = ref(1)
//: 页大小。**必须与 loadAssets 里发出去的 limit 同源** —— 原来 limit 在
//: loadAssets 里硬编码 20、分页配置也写死 pageSize:20，两处各写一份，
//: 一旦放开 showSizeChanger 就必然对不上（offset 按一个值算、limit 发另一个）。
const assetPageSize = ref(20)
const assetKeyword = ref('')
const assetTab = ref('domain')

const syncScanId = ref(null)
const syncing = ref(false)

const assetColumns = [
  { title: '资产', key: 'asset_key' },
  { title: 'URL', key: 'url', ellipsis: true },
  { title: '首次归集', dataIndex: 'first_seen', key: 'first_seen', width: 180 },
]

async function openDetail(record) {
  current.value = record
  detailOpen.value = true
  assetPage.value = 1
  await refreshDetail()
}

/** 拉分组详情（带 scopes）并刷新资产表。 */
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
 * 同步下拉里的一行：**任务名称在前** —— 它才是人挑"同步哪一次"的依据
 * （名称是必填的），后面缀上目标，因为同名任务很常见（"每月巡检"），
 * 光看名字分不出是哪一次。
 */
function scanLabel(s) {
  const name = s.name || `未命名 #${s.scan_id}`
  const targets = (s.targets || []).join(', ')
  return targets ? `${name} · ${targets}` : name
}

async function onSync() {
  if (!syncScanId.value) return
  syncing.value = true
  try {
    const res = await syncScanToGroup(current.value.id, syncScanId.value)
    const { domain = 0, ip = 0 } = res.added
    const picked = scans.value.find((s) => s.scan_id === syncScanId.value)
    // 报名字而不是 scan_id：用户是照名字挑的，回执里也该是名字
    const label = picked?.name || `#${syncScanId.value}`
    message.success(`已把「${label}」同步进本组：新增域名 ${domain} · IP ${ip}`)
    await refreshDetail()
    await load()
  } catch (e) {
    message.error(e.message)
  } finally {
    syncing.value = false
  }
}

// ── 范围增删 ─────────────────────────────────────────────────────────
const scopeOpen = ref(false)
const newScopeText = ref('')

function openAddScope() {
  newScopeText.value = ''
  scopeOpen.value = true
}

async function onAddScope() {
  const scopes = newScopeText.value.split('\n').map((s) => s.trim()).filter(Boolean)
  if (!scopes.length) {
    message.warning('至少需要一个范围')
    return
  }
  try {
    await addGroupScopes(current.value.id, scopes)
    message.success('已添加')
    scopeOpen.value = false
    await refreshDetail()
    await load()
  } catch (e) {
    message.error(e.message)
  }
}

async function onDeleteScope(scope) {
  try {
    await deleteGroupScope(scope.id)
    message.success('已删除')
    await refreshDetail()
    await load()
  } catch (e) {
    message.error(e.message)
  }
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
.sync-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.sync-hint {
  font-size: 12px;
}
</style>
