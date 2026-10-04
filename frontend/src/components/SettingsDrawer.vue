<template>
  <a-drawer
    :open="open"
    title="系统设置"
    :width="460"
    @close="$emit('update:open', false)"
  >
    <a-spin :spinning="loading">
      <a-form layout="vertical">
        <a-form-item label="并发扫描上限">
          <a-input-number v-model:value="form.max_concurrent_scans" :min="1" :max="16" />
        </a-form-item>

        <a-form-item>
          <template #label>
            <span>访问令牌</span>
          </template>
          <a-input-password
            v-model:value="form.auth_token"
            :placeholder="settings.auth_token_set ? '已设置（留空表示不修改）' : '未设置（不认证）'"
            autocomplete="off"
          />
          <div class="tk-muted hint">
            设置后 <code>/api/*</code> 需要 <code>Authorization: Bearer &lt;token&gt;</code>
          </div>
        </a-form-item>

        <a-divider style="margin: 4px 0 16px" />

        <a-collapse ghost>
          <a-collapse-panel key="keys" header="网络空间测绘配置">
            <div class="tk-muted hint" style="margin-bottom: 10px">
              存在本机设置文件里，<b>会回显到这里</b> —— 点右侧眼睛可明文查看、复制。
              建任务时自动注入，不必每次重填；<b>清空某一格再保存 = 删掉该 Key</b>。
              某次任务想临时换 Key 时，仍可在「配置覆盖」里覆盖。
            </div>
            <a-empty v-if="!keyModules.length" description="当前没有需要 Key 的源" />
            <a-form-item v-for="m in keyModules" :key="m.name" :label="m.name">
              <!--
                用 ``a-input-password`` —— 它自带那个「眼睛」按钮，而且抽屉里
                所有密钥类字段（访问令牌 / Webhook Token / 钉钉加签 / 飞书签名 /
                邮箱密码）都是这个形状，源 API Key 原先是唯一一个例外。
                Key 仍然**回显**：值就填在框里，点眼睛即可明文查看，
                不需要像以前那样"整条重填一遍"；默认显示成圆点，
                旁边有人时不会被直接看到。
              -->
              <a-input-password
                v-model:value="form.source_keys[m.name]"
                :placeholder="isKeySet(m.name) ? '已设置（清空并保存=删除）' : '未设置'"
                autocomplete="off"
              />
              <!--
                接口地址单独一个框，而不是塞进通用"附加配置"里。

                原因是它**必须**被改对：中转站的 key 打到官方域名上会返回
                「账号无效」，那个提示看起来像 key 错，实际是地址没换。
                给它一个标了名的输入框，比让用户在 key=value 里手写要可靠。

                `api_url` 是 API 类源的通用配置名，不特指某一家。
              -->
              <a-input
                v-model:value="form.source_options[m.name].api_url"
                placeholder="接口地址（可选，用中转站时必填）"
                style="margin-top: 6px"
                allow-clear
              />
              <div class="tk-muted hint">
                {{ m.description }}
                <template v-if="m.name === 'passive_fofa'">
                  <br />
                  用第三方中转时<b>必须</b>改上面那格。填 base 地址即可
                  （<code>https://fofoapi.com</code>，会自动补上
                  <code>/api/v1/search/all</code>）。不改会拿到「账号无效」——
                  <b>那不是 key 的问题</b>。
                </template>
              </div>
              <!--
                「测试连接」测的是**上面两格里还没保存的值** —— 填完先确认
                再保存，比存下去再发现不对要省事。
                它调的是源的 check_key()，FOFA 那边走的是不计费的账号接口。
              -->
              <div class="test-row">
                <a-button
                  size="small"
                  :loading="testingSource === m.name"
                  @click="onTestSource(m)"
                >
                  测试连接
                </a-button>
                <span
                  v-if="testResults[m.name]"
                  class="hint test-result"
                  :class="testResults[m.name].ok === true ? 'ok-text'
                          : testResults[m.name].ok === false ? 'err-text' : ''"
                >
                  <template v-if="testResults[m.name].ok === true">✓ </template>
                  <template v-else-if="testResults[m.name].ok === false">✗ </template>
                  <template v-else>· </template>
                  {{ testResults[m.name].detail }}
                </span>
              </div>
            </a-form-item>
          </a-collapse-panel>
        </a-collapse>

        <a-collapse ghost>
          <a-collapse-panel key="notify" header="告警推送（周期监控命中有变更时发送）">
            <a-form-item>
              <a-checkbox v-model:checked="form.notify.enabled">启用告警推送</a-checkbox>
            </a-form-item>
            <a-form-item label="通用 Webhook">
              <a-input v-model:value="form.notify.webhook_url" placeholder="https://..." />
            </a-form-item>
            <a-form-item label="Webhook Token（可选）">
              <a-input-password
                v-model:value="form.notify.webhook_token"
                :placeholder="settings.notify?.webhook_token_set ? '已设置（留空=不修改）' : '未设置'"
              />
            </a-form-item>
            <a-form-item label="钉钉 access_token">
              <a-input v-model:value="form.notify.dingtalk_access_token" placeholder="未设置" />
            </a-form-item>
            <a-form-item label="钉钉加签密钥">
              <a-input-password
                v-model:value="form.notify.dingtalk_secret"
                :placeholder="settings.notify?.dingtalk_secret_set ? '已设置（留空=不修改）' : '未设置'"
              />
            </a-form-item>
            <a-form-item label="飞书 Webhook">
              <a-input v-model:value="form.notify.feishu_webhook" placeholder="未设置" />
            </a-form-item>
            <a-form-item label="飞书签名密钥">
              <a-input-password
                v-model:value="form.notify.feishu_secret"
                :placeholder="settings.notify?.feishu_secret_set ? '已设置（留空=不修改）' : '未设置'"
              />
            </a-form-item>
            <a-form-item label="企业微信 Webhook">
              <a-input v-model:value="form.notify.wxwork_webhook" placeholder="未设置" />
            </a-form-item>
            <a-form-item label="邮件">
              <a-input
                v-model:value="form.notify.email_host"
                placeholder="smtp.example.com"
                style="margin-bottom: 6px"
              />
              <a-input-number
                v-model:value="form.notify.email_port"
                :min="1"
                :max="65535"
                placeholder="465"
                style="width: 120px; margin-bottom: 6px"
              />
              <a-input
                v-model:value="form.notify.email_username"
                placeholder="账号"
                style="margin-bottom: 6px"
              />
              <a-input-password
                v-model:value="form.notify.email_password"
                :placeholder="settings.notify?.email_password_set ? '密码已设置（留空=不修改）' : '密码'"
                style="margin-bottom: 6px"
              />
              <a-input v-model:value="form.notify.email_to" placeholder="收件人" />
            </a-form-item>
            <a-form-item label="至少多少处变化才推送">
              <a-input-number v-model:value="form.notify.min_changes" :min="1" />
            </a-form-item>
            <a-button size="small" :loading="testing" @click="onTestNotify">发送测试消息</a-button>
            <div v-if="testResult" class="hint" :class="testOk ? 'ok-text' : 'err-text'">
              {{ testResult }}
            </div>
          </a-collapse-panel>
        </a-collapse>
      </a-form>
    </a-spin>

    <!--
      `#footer` 必须是 **a-drawer 的直接子节点**。

      之前它写在 <a-spin> 里面 —— 那样它就成了 a-spin 的插槽，而 a-spin
      没有 footer 插槽，于是整个插槽被**静默丢弃**，保存按钮根本不渲染。
      表现是"系统设置没有保存按钮"，而且不报任何错。
    -->
    <template #footer>
      <div class="drawer-footer">
        <a-button type="primary" :loading="saving" @click="save">保存</a-button>
        <a-button @click="$emit('update:open', false)">关闭</a-button>
      </div>
    </template>
  </a-drawer>
</template>

<script setup>
import { message } from 'ant-design-vue'
import { reactive, ref, watch } from 'vue'

import { getModules, getSettings, saveSettings, testNotify, testSource } from '@/api'

const props = defineProps({ open: Boolean })
const emit = defineEmits(['update:open', 'saved'])

const loading = ref(false)
const saving = ref(false)
const testing = ref(false)
const testResult = ref('')
const testOk = ref(false)
const settings = ref({})
//: 需要 API Key 的源。**从模块接口动态取**，不在前端硬编码清单 ——
//: 硬编码的话，后端加了新的 key 源而前端没同步，那个源就会在设置里"消失"。
const keyModules = ref([])

// 表单里既放非密钥字段（每次都提交）也放密钥字段（只在填了东西时提交）
const form = reactive({
  max_concurrent_scans: 2,
  auth_token: '',
  //: {模块名: 已保存的 key}。**回显自服务端**，所以清空 = 删除，见 save()
  source_keys: {},
  //: {模块名: {附加配置}}。**非密钥**，会回显 —— 所以要带出当前值。
  source_options: {},
  notify: {
    enabled: false,
    webhook_url: '',
    webhook_token: '',
    dingtalk_access_token: '',
    dingtalk_secret: '',
    feishu_webhook: '',
    feishu_secret: '',
    wxwork_webhook: '',
    email_host: '',
    email_port: 465,
    email_username: '',
    email_password: '',
    email_to: '',
    min_changes: 1,
  },
})

//: 某个源是否已经配过 Key。服务端只回传**模块名列表**，不回传值。
function isKeySet(name) {
  return (settings.value.source_keys_set || []).includes(name)
}

//: 正在测的源（按钮转圈用）。同一时刻只测一个。
const testingSource = ref('')
//: {模块名: {ok, detail}}。ok 可能是 `null` —— 表示该源没实现连接检测。
const testResults = reactive({})

async function onTestSource(m) {
  testingSource.value = m.name
  delete testResults[m.name]
  try {
    // 把**当前表单里**的值发过去（而不是已保存的）—— 填完先验再保存。
    // key 留空（或没填）时传 null，服务端回落到已保存的那个 —— 所以
    // "测试连接"测的永远是"保存后会用的那个 key"。
    const res = await testSource(m.name, {
      api_key: (form.source_keys[m.name] || '').trim() || null,
      options: { ...(form.source_options[m.name] || {}) },
    })
    testResults[m.name] = { ok: res.ok, detail: res.detail }
  } catch (e) {
    testResults[m.name] = { ok: false, detail: e.message }
  } finally {
    testingSource.value = ''
  }
}

async function load() {
  loading.value = true
  try {
    const [data, mods] = await Promise.all([
      getSettings(),
      // 用 active 预设取 —— 它是模块的超集，能覆盖到所有源
      getModules('active').catch(() => ({ modules: [] })),
    ])
    settings.value = data
    form.max_concurrent_scans = data.max_concurrent_scans || 2
    form.auth_token = ''
    form.source_keys = data.source_keys ? JSON.parse(JSON.stringify(data.source_keys)) : {}
    // ⚠️ **两个清单都要看。** 需要 Key 的源大多带 `metered` 标记，
    // 因而不在 `modules`（已启用）里，而是在 `metered`（可勾选）里 ——
    // 只看 modules 的话，设置里会**一个填 Key 的地方都不剩**。
    keyModules.value = [...(mods.modules || []), ...(mods.metered || [])].filter(
      (m) => m.requires_key,
    )
    // 附加配置带出当前值（它是非密钥，服务端会回显）—— 不回显的话用户
    // 一打开抽屉就看不见现在配的是哪个接口地址，容易以为是空的又填一遍。
    form.source_options = {}
    for (const m of keyModules.value) {
      form.source_options[m.name] = { ...(data.source_options?.[m.name] || {}) }
    }
    Object.assign(form.notify, {
      ...data.notify,
      // 密钥类字段清空，靠 placeholder 提示"已设置"
      webhook_token: '',
      dingtalk_secret: '',
      feishu_secret: '',
      email_password: '',
    })
  } catch (e) {
    message.error(e.message)
  } finally {
    loading.value = false
  }
}

// 每次打开都重新拉，避免显示过期数据
watch(() => props.open, (open) => { if (open) load() })

async function save() {
  saving.value = true
  try {
    const body = {
      max_concurrent_scans: Number(form.max_concurrent_scans) || 2,
      notify: {
        enabled: form.notify.enabled,
        webhook_url: (form.notify.webhook_url || '').trim(),
        dingtalk_access_token: (form.notify.dingtalk_access_token || '').trim(),
        feishu_webhook: (form.notify.feishu_webhook || '').trim(),
        wxwork_webhook: (form.notify.wxwork_webhook || '').trim(),
        email_host: (form.notify.email_host || '').trim(),
        email_port: Number(form.notify.email_port) || 465,
        email_username: (form.notify.email_username || '').trim(),
        email_to: (form.notify.email_to || '').trim(),
        min_changes: Number(form.notify.min_changes) || 1,
      },
    }
    // 密钥只在用户真的填了内容时才提交，否则会把服务端已有值抹掉
    if (form.auth_token.trim()) body.auth_token = form.auth_token.trim()
    // 源 API Key：**整块提交**（含空值），与附加配置同一套语义。
    //
    // 旧语义是"留空 = 不修改"，但那是在 Key **回显不了**的前提下定的 ——
    // 输入框恒为空，留空也只能表示"没动"。现在 Key 会回显（框里有值），
    // "清空再保存"就是一个明确的意思：删掉它。若继续只提交非空值，
    // 用户清空后保存会发现 Key 还在。
    //
    // 只遍历 keyModules（服务端声明的"需要 Key 的源"），所以不会碰那些
    // 没列在这里的源；服务端按模块合并，空串 = 清掉该项。
    const keys = {}
    for (const m of keyModules.value) {
      keys[m.name] = (form.source_keys[m.name] || '').trim()
    }
    if (Object.keys(keys).length) body.source_keys = keys
    // 附加配置：**整块提交**（含空值）。
    //
    // 和上面源 API Key 现在是同一个语义（清空 = 删除）。差别只在"为什么"：
    // 附加配置一直能回显，Key 是后来才改成回显的；而 ``auth_token`` 与
    // 告警里的那几个密钥（webhook_token / *_secret / email_password）**仍然
    // 不回显**，所以它们保留"留空 = 不修改"：框里没有值可对照，留空只能
    // 表示"没动"。服务端把空串解释为"清掉该项"。
    const options = {}
    for (const [name, opts] of Object.entries(form.source_options || {})) {
      if (opts && Object.keys(opts).length) options[name] = { ...opts }
    }
    if (Object.keys(options).length) body.source_options = options
    for (const field of ['webhook_token', 'dingtalk_secret', 'feishu_secret', 'email_password']) {
      const value = (form.notify[field] || '').trim()
      if (value) body.notify[field] = value
    }

    await saveSettings(body)
    message.success('已保存')
    emit('saved')
    await load()
  } catch (e) {
    message.error(e.message)
  } finally {
    saving.value = false
  }
}

async function onTestNotify() {
  testing.value = true
  testResult.value = ''
  try {
    const res = await testNotify({})
    testResult.value = res.results
      .map((r) => `${r.channel}: ${r.ok ? 'OK' : r.detail}`)
      .join(' · ')
    testOk.value = res.results.some((r) => r.ok)
  } catch (e) {
    testResult.value = e.message
    testOk.value = false
  } finally {
    testing.value = false
  }
}
</script>

<style scoped>
.hint {
  font-size: 12px;
  margin-top: 4px;
  line-height: 1.6;
}
.test-row {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  margin-top: 6px;
}
.test-result {
  margin-top: 0;
  word-break: break-word;
}
.drawer-footer {
  display: flex;
  gap: 8px;
  justify-content: flex-end;
}
.ok-text {
  color: #16a34a;
}
.err-text {
  color: #dc2626;
}
code {
  background: var(--tk-surface-2);
  padding: 1px 4px;
  border-radius: 3px;
}
</style>
