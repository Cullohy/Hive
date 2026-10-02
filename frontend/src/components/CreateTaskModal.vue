<template>
  <a-modal
    :open="open"
    title="创建任务"
    :width="760"
    :confirm-loading="starting"
    :ok-button-props="{ disabled: !canStart }"
    ok-text="开始收集"
    cancel-text="取消"
    @ok="start"
    @update:open="$emit('update:open', $event)"
  >
    <a-form layout="vertical" style="margin-bottom: 0">
      <a-form-item label="目标（每行一个根域名或 IP，可含 CIDR）">
        <a-textarea
          v-model:value="targets"
          :rows="4"
          placeholder="example.com&#10;example.org"
        />
      </a-form-item>

      <a-form-item label="收集策略">
        <a-select v-model:value="preset" style="width: 100%" @change="loadPresetInfo">
          <a-select-option v-for="p in presets" :key="p.name" :value="p.name">
            <span class="preset-name">{{ p.name }}</span>
            <span class="tk-muted preset-desc">{{ p.description }}</span>
          </a-select-option>
        </a-select>
      </a-form-item>

      <!--
        **会消耗 API 额度的源，默认一个都不勾。**
        额度不该是默认行为 —— 不勾就一条请求都不会发出去。
      -->
      <a-form-item v-if="meteredModules.length">
        <template #label>
          <span>
            消耗 API 额度的源
            <a-tooltip
              title="这些源会扣你买的查询额度。默认不勾选，勾了才跑。配置好的 Key 在这里被使用。"
            >
              <QuestionCircleOutlined class="tk-muted" />
            </a-tooltip>
          </span>
        </template>
        <a-checkbox-group v-model:value="meteredChecked" style="width: 100%">
          <div v-for="m in meteredModules" :key="m.name" class="metered-row">
            <a-checkbox :value="m.name">
              <span class="metered-name">{{ m.name }}</span>
              <span class="tk-muted metered-desc">
                {{ m.description }}
                <!-- 只说"需要 Key"，**不猜有没有配** —— 模块清单接口不返回
                     密钥配置状态（那是设置接口的事），凭它判断会永远显示
                     "还没配"，属于误导。 -->
                <b v-if="m.requires_key">（需要 API Key）</b>
              </span>
            </a-checkbox>
          </div>
        </a-checkbox-group>
      </a-form-item>

      <a-form-item>
        <template #label>
          配置覆盖（可选，<code>-c KEY=VALUE</code> 风格，每行一条）
          <a-tooltip title="例如：modules.dns_brute.wordlist=D:/words.txt 或 modules.port_scan.ports=top100">
            <QuestionCircleOutlined class="tk-muted" />
          </a-tooltip>
        </template>
        <a-textarea
          v-model:value="overrides"
          :rows="2"
          placeholder="modules.port_scan.ports=top100"
        />
      </a-form-item>
    </a-form>

    <!-- 主动/被动预告：发包之前必须让人看清楚 -->
    <div class="mode-bar" :class="modeClass">
      <div class="mode-main">
        <span class="mode-tag">{{ modeText }}</span>
        <span class="mode-desc">{{ modeHint }}</span>
      </div>
      <div class="mode-stats">
        <span>启用模块 <b>{{ moduleCount }}</b></span>
        <span>主动模块 <b>{{ activeCount }}</b></span>
        <span>高噪声 <b>{{ loudCount }}</b></span>
      </div>
    </div>
  </a-modal>
</template>

<script setup>
import { QuestionCircleOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { computed, ref, watch } from 'vue'

import { createScan, getModules, getPresets } from '@/api'

const props = defineProps({ open: Boolean })
const emit = defineEmits(['update:open', 'created'])

const targets = ref('')
const preset = ref('default')
const overrides = ref('')
const presets = ref([])
const mode = ref('unknown')
const activeModules = ref([])
const loudModules = ref([])
const starting = ref(false)
//: 启用/主动/高噪声的条数 —— 模块明细不展示了，但数字还要放在预告条上
const enabledCount = ref(0)
//: **会消耗 API 额度的源**（flags 含 metered）。默认一个都不勾 ——
//: 额度不该是默认行为，要人主动选。
const meteredModules = ref([])
//: 用户勾选了的 metered 模块名
const meteredChecked = ref([])

const targetList = computed(() =>
  targets.value.split('\n').map((s) => s.trim()).filter(Boolean),
)
const canStart = computed(() => targetList.value.length > 0 && !starting.value)
const moduleCount = computed(() => enabledCount.value + meteredChecked.value.length)
const activeCount = computed(() => activeModules.value.length)
const loudCount = computed(() => loudModules.value.length)

const modeText = computed(() =>
  mode.value === 'active' ? '主动模式' : mode.value === 'passive' ? '被动模式' : '未知',
)
const modeHint = computed(() => {
  if (mode.value === 'active') {
    return '会向目标发送 DNS 查询、TCP 连接与 HTTP 请求。请确认你已获得授权。'
  }
  if (mode.value === 'passive') {
    return '只查询第三方数据源（证书透明度、公开 DNS 数据集），不直接触碰目标。'
  }
  return '未能判定。'
})
const modeClass = computed(() => (mode.value === 'active' ? 'is-active' : 'is-passive'))

async function loadPresetInfo() {
  try {
    const info = await getModules(preset.value)
    enabledCount.value = (info.modules || []).length
    mode.value = info.mode || 'unknown'
    activeModules.value = info.active || []
    loudModules.value = info.loud || []
    // 换了预设就把勾选清掉：不同预设下可选项可能不同，
    // 留着旧勾选会出现"勾了这个但当前预设根本没有它"的鬼状态。
    meteredModules.value = info.metered || []
    meteredChecked.value = []
  } catch (e) {
    message.error(e.message)
  }
}

/** 每次打开都重新拉预设，避免显示过期数据。 */
async function init() {
  try {
    presets.value = await getPresets()
  } catch (e) {
    message.error(e.message)
  }
  await loadPresetInfo()
}

watch(
  () => props.open,
  (open) => {
    if (open) init()
  },
)

async function start() {
  starting.value = true
  try {
    const record = await createScan({
      targets: targetList.value,
      preset: preset.value,
      // 勾了的额度源显式启用 —— 不勾就什么都不传，预设默认 deny 掉它们
      enable_sources: meteredChecked.value,
      overrides: overrides.value
        .split('\n')
        .map((s) => s.trim())
        .filter(Boolean),
    })
    message.success(`已下发扫描 #${record.scan_id}`)
    emit('update:open', false)
    // 交给父组件决定去哪 —— 任务列表刷新一下就能看到新任务
    emit('created', record.scan_id)
  } catch (e) {
    message.error(e.message)
  } finally {
    starting.value = false
  }
}
</script>

<style scoped>
.metered-row {
  margin-bottom: 4px;
}
.metered-name {
  font-family: ui-monospace, monospace;
}
.metered-desc {
  margin-left: 8px;
  font-size: 12px;
}

.preset-name {
  font-weight: 600;
  margin-right: 8px;
}
.preset-desc {
  font-size: 12px;
}
.mode-bar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  border-radius: 6px;
  padding: 10px 14px;
  border: 1px solid #f0f0f0;
  background: #fafafa;
}
.mode-bar.is-active {
  border-color: #ffbb96;
  background: #fff2e8;
}
.mode-bar.is-passive {
  border-color: #adc6ff;
  background: #f0f5ff;
}
.mode-main {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.mode-tag {
  font-weight: 600;
}
.mode-desc {
  font-size: 12px;
  color: #8c8c8c;
}
.mode-stats {
  display: flex;
  gap: 16px;
  font-size: 12px;
  color: #595959;
}
</style>
