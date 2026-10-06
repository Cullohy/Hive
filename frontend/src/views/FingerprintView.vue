<template>
  <div class="tk-page">
    <div class="tk-card">
      <h3 class="tk-card-title"><DeploymentUnitOutlined /> 指纹库</h3>

      <div class="stat-row">
        <div class="stat">
          <div class="stat-num accent-text">{{ (summary.total || 0).toLocaleString() }}</div>
          <div class="stat-label">系统（技术）</div>
        </div>
        <div class="stat">
          <div class="stat-num">{{ (summary.matchers || 0).toLocaleString() }}</div>
          <div class="stat-label">匹配规则</div>
        </div>
        <div class="stat">
          <div class="stat-num">{{ customCount }}</div>
          <div class="stat-label">自定义规则</div>
        </div>
        <div class="stat">
          <div class="stat-num">{{ summary.with_favicon || 0 }}</div>
          <div class="stat-label">favicon 指纹</div>
        </div>
      </div>

      <div class="tk-muted hint">
        <template v-if="library.errors?.length">
          加载错误：{{ library.errors.join('；') }}
        </template>
      </div>
    </div>

    <div class="tk-card">
      <div class="search-bar">
        <a-input
          v-model:value="keyword"
          size="large"
          placeholder="搜系统名 / 分类 / 匹配方式 / 关键词，例如 wordpress、正文、nginx"
          allow-clear
        />
        <a-select v-model:value="category" size="large" style="width: 190px">
          <a-select-option value="">全部分类</a-select-option>
          <a-select-option v-for="c in visibleCategories" :key="c.slug" :value="c.slug">
            {{ c.label }}（{{ c.count }}）
          </a-select-option>
        </a-select>
        <a-button size="large" :loading="loading" @click="reload">重载</a-button>
        <a-button type="primary" size="large" @click="openCreate">
          <PlusOutlined /> 新增指纹
        </a-button>
      </div>

      <div class="tk-muted hint">
        命中 <b class="accent-text">{{ (library.matched || 0).toLocaleString() }}</b> 条匹配规则，
        当前显示第 {{ (library.offset || 0) + 1 }}–{{ (library.offset || 0) + (library.shown || 0) }} 条。
        一行是一条匹配规则 —— 一个系统通常有多条（分布在正文/响应头/Cookie…）。
      </div>

      <a-table
        :columns="columns"
        :data-source="rows"
        row-key="rowkey"
        size="small"
        :loading="loading"
        :pagination="{
          current: page,
          pageSize,
          total: library.matched || 0,
          showSizeChanger: true,
          pageSizeOptions: ['20', '50', '100'],
          showTotal: (t) => `共 ${t.toLocaleString()} 条`,
        }"
        @change="onTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'index'">
            <span class="tk-muted">{{ record.index }}</span>
          </template>
          <template v-else-if="column.key === 'name'">
            <strong>{{ record.name }}</strong>
            <a-tag v-if="record.custom" color="green" class="mine">自定义</a-tag>
            <div class="tk-muted tk-mono id-line">{{ record.tech }}</div>
          </template>
          <template v-else-if="column.key === 'category'">
            <a-tag v-if="record.category_label" color="blue">{{ record.category_label }}</a-tag>
            <span v-else class="tk-muted">—</span>
          </template>
          <template v-else-if="column.key === 'method'">
            <a-tag :color="methodColor(record.method)">{{ record.method }}</a-tag>
          </template>
          <template v-else-if="column.key === 'location'">
            {{ record.location_label }}
          </template>
          <template v-else-if="column.key === 'keyword'">
            <span class="tk-mono kw">{{ record.keyword }}</span>
          </template>
          <template v-else-if="column.key === 'action'">
            <a-button type="link" size="small" @click="openEdit(record)">编辑</a-button>
            <a-popconfirm
              title="确认删除这条匹配规则？只删这一行。"
              ok-text="删除"
              cancel-text="取消"
              @confirm="doDelete(record)"
            >
              <a-button type="link" size="small" danger>删除</a-button>
            </a-popconfirm>
          </template>
        </template>
      </a-table>
    </div>

    <!-- ── 新增 ── -->
    <a-modal
      v-model:open="creating"
      title="新增指纹"
      ok-text="保存"
      cancel-text="取消"
      :confirm-loading="saving"
      @ok="saveCreate"
    >
      <a-form layout="vertical">
        <a-form-item label="系统名称" required>
          <a-input v-model:value="form.name" placeholder="例如 泛微 e-cology、我的内部系统" />
          <div class="tk-muted tiny">
            <b>名字已存在时会追加一条规则</b>，不会覆盖原有的 —— 想给 nginx 再加一条特征，
            直接填 nginx 就行。
          </div>
        </a-form-item>
        <a-form-item label="分类（可选）">
          <a-input v-model:value="form.category" placeholder="例如 cms、oa、security" />
        </a-form-item>
        <a-form-item label="匹配位置">
          <a-select v-model:value="form.location">
            <a-select-option v-for="o in locOptions" :key="o.value" :value="o.value">
              {{ o.label }}
            </a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="匹配方式">
          <a-select v-model:value="form.method">
            <a-select-option value="关键词">关键词（字面量子串，最稳）</a-select-option>
            <a-select-option value="正则">正则表达式</a-select-option>
            <a-select-option value="favicon 哈希">favicon 哈希（mmh3，十进制）</a-select-option>
            <a-select-option value="关键词(全部)">
              关键词(全部) —— 多个用逗号分隔，都要出现
            </a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="关键词 / 正则" required>
          <a-textarea
            v-model:value="form.keyword"
            :rows="3"
            class="tk-mono"
            :placeholder="keywordPlaceholder"
          />
          <div class="tk-muted tiny">
            响应头写 <span class="tk-mono">头名: 值</span>，例如
            <span class="tk-mono">x-powered-by: thinkphp</span>；
            meta 写 <span class="tk-mono">generator: wordpress</span>
          </div>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- ── 编辑 ── -->
    <a-modal
      v-model:open="editing"
      title="编辑匹配规则"
      ok-text="保存"
      cancel-text="取消"
      :confirm-loading="saving"
      @ok="saveEdit"
    >
      <div v-if="form" class="edit-form">
        <div class="tk-muted">
          系统 <b>{{ form.name }}</b>（{{ form.tech }}）
        </div>
        <a-form layout="vertical">
          <a-form-item label="匹配位置">
            <a-select v-model:value="form.new_location">
              <a-select-option v-for="o in locOptions" :key="o.value" :value="o.value">
                {{ o.label }}
              </a-select-option>
            </a-select>
          </a-form-item>
          <a-form-item label="匹配方式">
            <a-select v-model:value="form.method">
              <a-select-option value="关键词">关键词（字面量子串）</a-select-option>
              <a-select-option value="正则">正则表达式</a-select-option>
              <a-select-option value="favicon 哈希">favicon 哈希（mmh3，十进制）</a-select-option>
            </a-select>
          </a-form-item>
          <a-form-item label="关键词 / 正则">
            <a-textarea v-model:value="form.new_keyword" :rows="3" class="tk-mono" />
          </a-form-item>
        </a-form>
      </div>
    </a-modal>

    <div class="tk-card">
      <h3 class="tk-card-title">导入外部库</h3>
      <div class="tk-muted hint">
        导入库里的规则来自外部开源指纹库（<b>MIT</b>）：
        <a href="https://github.com/0x727/FingerprintHub" target="_blank" rel="noreferrer">FingerprintHub</a>
        ·
        <a href="https://github.com/projectdiscovery/wappalyzergo" target="_blank" rel="noreferrer">wappalyzergo</a>。
        它会被整体覆盖，所以<b>界面上加的规则走另一个文件</b>，两者互不影响。
      </div>
      <pre class="cmd">{{ library.import_hint }}</pre>
    </div>
  </div>
</template>

<script setup>
import { computed, onMounted, ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import { DeploymentUnitOutlined, PlusOutlined } from '@ant-design/icons-vue'

import {
  createFingerprint,
  deleteFingerprint,
  editFingerprint,
  getFingerprints,
  reloadFingerprints,
} from '@/api'

const loading = ref(false)
const keyword = ref('')
const category = ref('')
const library = ref({})
const page = ref(1)
const pageSize = ref(20)

const creating = ref(false)
const editing = ref(false)
const saving = ref(false)
const form = ref({ name: '', category: '', location: 'body', method: '关键词', keyword: '' })

const locOptions = [
  { value: 'body', label: 'body' },
  { value: 'header', label: 'header' },
  { value: 'cookie', label: 'cookie' },
  { value: 'title', label: 'title' },
  { value: 'meta', label: 'meta' },
  { value: 'scriptSrc', label: 'script' },
  { value: 'url', label: 'url' },
  { value: 'favicon', label: 'favicon' },
]

const columns = [
  { title: '#', key: 'index', width: 60 },
  { title: '系统', key: 'name', width: 240 },
  { title: '分类', key: 'category', width: 150 },
  { title: '匹配方式', key: 'method', width: 110 },
  { title: '匹配位置', key: 'location', width: 130 },
  { title: '关键词/正则', key: 'keyword' },
  { title: '操作', key: 'action', width: 130, fixed: 'right' },
]

const summary = computed(() => library.value.summary || {})
// 过滤掉少于 10 条的杂项分类，避免下拉菜单太长
const visibleCategories = computed(() =>
  (summary.value.categories || []).filter(c => c.count >= 10)
)
const customCount = computed(() => library.value.custom_count || 0)
const keywordPlaceholder = computed(() => {
  if (form.value.method === '正则') return '例如 (?mi)<title[^>]*>myapp.*?</title>'
  if (form.value.method === 'favicon 哈希') return '例如 -47932290'
  if (form.value.location === 'header') return '例如 x-powered-by: myapp'
  if (form.value.method === '关键词(全部)') return '用逗号分隔，例如 /admin/,我的系统'
  return '例如 internal-portal-v3'
})

const rows = computed(() =>
  (library.value.rows || []).map((r, i) => ({
    ...r,
    rowkey: `${r.tech}|${r.location}|${r.keyword}|${r.index}|${i}`,
  })),
)

function methodColor(method) {
  if (method === '关键词') return 'green'
  if (method === '正则') return 'orange'
  if (method === 'favicon 哈希') return 'purple'
  return 'default'
}

async function fetchLibrary() {
  loading.value = true
  try {
    // 注意：api/http.js 的拦截器已经 `response => response.data`，
    // 这里拿到的是响应体本身，**不能再解构一次 .data**
    library.value = await getFingerprints({
      q: keyword.value,
      category: category.value,
      limit: pageSize.value,
      offset: (page.value - 1) * pageSize.value,
    })
  } catch (e) {
    message.error(e.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function onTableChange(pagination) {
  // 改页大小时**必须回到第 1 页**：vc-pagination 的 changePageSize 会保留
  // 当前页并连发 change(current, size)，停在第 5 页从 20 改成 50 的话
  // offset = (5-1)*50 = 200，落在中段 —— 用户以为在看第一页，实际是中段数据。
  // 同 TaskDetailView 的 onEventPageChange。
  const sizeChanged = pagination.pageSize !== pageSize.value
  if (sizeChanged) {
    pageSize.value = pagination.pageSize
    page.value = 1
  } else {
    page.value = pagination.current
  }
  fetchLibrary()
}

let timer = null
watch([keyword, category], () => {
  page.value = 1
  clearTimeout(timer)
  timer = setTimeout(fetchLibrary, 250)
})

function openCreate() {
  form.value = {
    name: '', category: '', location: 'body', method: '关键词', keyword: '',
  }
  creating.value = true
}

/** 「关键词(全部)」在界面上用逗号分隔；落库是多个字面量，都要出现。 */
function splitKeyword(raw, method) {
  if (method !== '关键词(全部)') return [raw]
  return raw.split(/[,，]/).map((s) => s.trim()).filter(Boolean)
}

async function saveCreate() {
  const f = form.value
  if (!f.name.trim()) return message.warning('系统名称不能为空')
  if (!f.keyword.trim()) return message.warning('关键词不能为空')
  saving.value = true
  try {
    const parts = splitKeyword(f.keyword, f.method)
    let created = false
    for (const [i, part] of parts.entries()) {
      const r = await createFingerprint({
        name: f.name,
        category: f.category,
        location: f.location,
        method: f.method === '关键词(全部)' ? '关键词' : f.method,
        keyword: part,
      })
      // 同名多次调用时只有第一次算"新建"，后面都是追加
      if (i === 0) created = r.created
    }
    message.success(created ? `已新增指纹「${f.name}」` : `已给「${f.name}」追加规则`)
    creating.value = false
    await fetchLibrary()
  } catch (e) {
    message.error(e.message || '保存失败')
  } finally {
    saving.value = false
  }
}

function openEdit(record) {
  form.value = {
    tech: record.tech,
    name: record.name,
    location: record.location,
    keyword: record.keyword,
    new_location: record.location,
    new_keyword: record.keyword,
    method: record.method === '存在性' ? '关键词' : record.method,
  }
  editing.value = true
}

async function saveEdit() {
  const f = form.value
  if (!f) return
  saving.value = true
  try {
    await editFingerprint(f.tech, {
      location: f.location,
      keyword: f.keyword,
      new_location: f.new_location,
      new_keyword: f.new_keyword,
      method: f.method,
    })
    message.success('已保存')
    editing.value = false
    await fetchLibrary()
  } catch (e) {
    message.error(e.message || '保存失败')
  } finally {
    saving.value = false
  }
}

async function doDelete(record) {
  try {
    await deleteFingerprint(record.tech, record.keyword)
    message.success(`已删除 ${record.name} 的这条匹配规则`)
    await fetchLibrary()
  } catch (e) {
    message.error(e.message || '删除失败')
  }
}

async function reload() {
  loading.value = true
  try {
    const r = await reloadFingerprints()
    message.success(`已重载，共 ${r.total.toLocaleString()} 个系统`)
    await fetchLibrary()
  } catch (e) {
    message.error(e.message || '重载失败')
  } finally {
    loading.value = false
  }
}

onMounted(fetchLibrary)
</script>

<style scoped>
.stat-row {
  display: flex;
  gap: 24px;
  flex-wrap: wrap;
  margin-bottom: 12px;
  justify-content: space-evenly;
}
.stat-num {
  font-size: 26px;
  font-weight: 600;
  line-height: 1.2;
}
.stat-label {
  font-size: 12px;
  color: #8c8c8c;
}
.search-bar {
  display: flex;
  gap: 12px;
  margin-bottom: 12px;
}
.hint {
  font-size: 12px;
  line-height: 1.7;
}
.tiny {
  font-size: 11px;
  margin-top: 4px;
}
.id-line {
  font-size: 11px;
}
.kw {
  font-size: 12px;
  word-break: break-all;
}
.warn-text {
  color: #d4380d;
}
.ok-text {
  color: #389e0d;
}
.mine {
  margin-left: 6px;
  font-size: 11px;
  line-height: 16px;
}
.cmd {
  background: #fafafa;
  border: 1px solid #f0f0f0;
  border-radius: 4px;
  padding: 12px;
  font-size: 12px;
  line-height: 1.7;
  overflow-x: auto;
  white-space: pre;
  margin: 0;
}
</style>
