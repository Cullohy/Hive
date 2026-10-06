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
      <a-form-item required>
        <template #label>
          任务名称
          <a-tooltip
            title="必填。会显示在「任务管理」与「任务分组」里 —— 分组同步就是按名字挑哪次扫描。只是标签：不参与扫描逻辑，也允许重名（每月都叫「月度巡检」没问题）。"
          >
            <QuestionCircleOutlined class="tk-muted" />
          </a-tooltip>
        </template>
        <a-input
          v-model:value="name"
          :maxlength="120"
          placeholder="例如：每月巡检 · 主站"
          allow-clear
        />
        <div class="tk-muted name-hint">
          必填。「任务管理」和「任务分组」都用它标识这次扫描。
        </div>
      </a-form-item>

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
//: 任务名称。**必填**（后端也强制）—— 任务管理与任务分组都靠它标识一次扫描。
const name = ref('')
//: 默认选**被动**。这个工具会向目标发包，默认就该是安全的那一档 ——
//: 以前叫 `default`，合并成两模式后它的能力被 `passive` 完整吸收了。
const preset = ref('passive')
const overrides = ref('')
const presets = ref([])
const starting = ref(false)
//: **会消耗 API 额度的源**（flags 含 metered）。默认一个都不勾 ——
//: 额度不该是默认行为，要人主动选。
const meteredModules = ref([])
//: 用户勾选了的 metered 模块名
const meteredChecked = ref([])

const targetList = computed(() =>
  targets.value.split('\n').map((s) => s.trim()).filter(Boolean),
)
const canStart = computed(
  () => targetList.value.length > 0 && name.value.trim().length > 0 && !starting.value,
)
async function loadPresetInfo() {
  try {
    const info = await getModules(preset.value)
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
  // 按钮已经被 canStart 禁掉了，这里再兜一道：回车提交 / 程序化调用也拦得住。
  if (!name.value.trim()) {
    message.warning('请填写任务名称')
    return
  }
  starting.value = true
  try {
    const record = await createScan({
      // 留空就传空串：后端统一把空串当成"没填"，存 NULL
      name: name.value.trim(),
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
/* 必填说明紧贴输入框，别和下一个表单项的间距混在一起 */
.name-hint {
  font-size: 12px;
  margin-top: 4px;
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
</style>
