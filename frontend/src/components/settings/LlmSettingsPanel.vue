<script setup>
import { computed, ref, watch } from "vue";
import { api } from "../../api.js";
import LlmModelPicker from "../LlmModelPicker.vue";
import TemperatureRecommend from "../TemperatureRecommend.vue";

const props = defineProps({
  form: { type: Object, required: true },
  singleModels: { type: Object, required: true },
  singleModelsLoading: { type: Object, required: true },
  singleModelsError: { type: Object, required: true },
  llm: { type: Object, required: true },
});

const singleModels = computed(() => props.singleModels);
const singleModelsLoading = computed(() => props.singleModelsLoading);
const singleModelsError = computed(() => props.singleModelsError);

const {
  llmMode,
  llmTest,
  selectedLlmProvider,
  selectedLlm,
  providerHealthClass,
  providerHealthText,
  providerHealthTitle,
  addLlmProvider,
  removeLlmProvider,
  moveLlmProvider,
  invalidateSingleKey,
  invalidateProviderKey,
  loadSingleModels,
  loadProviderModels,
  testLlmProvider,
  healthLoading,
  refreshHealthActive,
  schedulePreview,
  scheduleLoading,
  refreshSchedule,
  resultText,
  copyLlmTest,
} = props.llm;

// —— 模型商连接向导（单端点）：① 选模型商 → ② 填 Key 并测试 → ③ 选模型 ——
const wizardStep = ref(0);
const providerPresets = ref([]);
const presetsLoading = ref(false);
const selectedPresetId = ref("");
const WIZARD_STEPS = [
  { id: "provider", label: "选模型商" },
  { id: "key", label: "填 Key 并测试" },
  { id: "model", label: "选模型" },
];
async function loadProviderPresets() {
  if (providerPresets.value.length) return;
  presetsLoading.value = true;
  try {
    const res = await api.llmPresets();
    providerPresets.value = res?.presets || [];
  } catch (e) {
    providerPresets.value = [];
  } finally {
    presetsLoading.value = false;
  }
}
function pickProvider(p) {
  selectedPresetId.value = p.id;
  // 同一模型商（base_url 相同）时保留已保存的 key，避免换模型还要重填
  const sameEndpoint = !!(p.base_url && props.form.base_url && p.base_url === props.form.base_url);
  props.form.base_url = p.base_url || "";
  props.form.protocol = p.protocol || "auto";
  if (p.recommended) props.form.model = p.recommended;
  if (!sameEndpoint) invalidateSingleKey();
  wizardStep.value = 1;
}
watch(
  () => llmMode.value,
  (mode) => {
    if (mode === "single") {
      loadProviderPresets();
      // 已配置好（有端点且有 key）→ 直接到选模型步骤，方便直接换模型名
      wizardStep.value = props.form.base_url && (props.form.api_key_set || props.form.key_ref) ? 2 : 0;
    }
  },
  { immediate: true },
);
// 初始加载完成后（base_url 从后端带回）已配置好 → 直接到选模型步骤，避免每次重填 key
watch(
  () => props.form.base_url,
  () => {
    if (wizardStep.value === 0 && props.form.base_url && (props.form.api_key_set || props.form.key_ref)) {
      wizardStep.value = 2;
    }
  },
);
const selectedPresetName = computed(() => {
  const p = providerPresets.value.find((x) => x.id === selectedPresetId.value);
  return p?.name || "自定义";
});

// 单端点测试连接（复用 /settings/test-llm，只测不落库、不碰生产熔断器）
const singleTest = ref(null);
async function testSingleModel() {
  singleTest.value = { loading: true, ok: false, latency_ms: 0, tool_calling: "", error: "" };
  try {
    const res = await api.testLLM({
      base_url: props.form.base_url,
      api_key: String(props.form.api_key || "").trim(),
      key_ref: props.form.key_ref,
      model: props.form.model,
      protocol: props.form.protocol,
      temperature: props.form.temperature,
    });
    const r = res?.results?.[0];
    singleTest.value = {
      loading: false,
      ok: !!r?.ok,
      latency_ms: r?.latency_ms || 0,
      tool_calling: r?.tool_calling || "",
      error: r?.error || res?.error || "",
    };
  } catch (e) {
    singleTest.value = { loading: false, ok: false, latency_ms: 0, tool_calling: "", error: String(e.message || e).replace(/^\d+\s*/, "") };
  }
}

// —— 单端点多模型灾备：主模型之外可多选同供应商模型，主模型不可用时自动顶替 ——
const backupDraft = ref("");
const backupDraftText = ref("");
const backupCandidates = computed(() => {
  const list = (props.singleModels || []).filter(Boolean);
  const taken = new Set([props.form.model, ...(props.form.models || [])].filter(Boolean));
  return list.filter((m) => !taken.has(m));
});
function addBackupModel(name) {
  const v = String(name || "").trim();
  if (!v || v === props.form.model) return;
  const list = props.form.models || [];
  if (list.includes(v)) return;
  props.form.models = [...list, v];
}
function addBackupModelFromSelect() {
  if (backupDraft.value) {
    addBackupModel(backupDraft.value);
    backupDraft.value = "";
  }
}
function addBackupModelFromInput() {
  if (backupDraftText.value.trim()) {
    addBackupModel(backupDraftText.value);
    backupDraftText.value = "";
  }
}
function removeBackupModel(idx) {
  const list = [...(props.form.models || [])];
  list.splice(idx, 1);
  props.form.models = list;
}
// 主模型变化时，若灾备列表里出现同名模型则剔除，避免重复
watch(
  () => props.form.model,
  (m) => {
    if (m && (props.form.models || []).includes(m)) {
      props.form.models = (props.form.models || []).filter((x) => x !== m);
    }
  },
);
</script>

<template>
  <div class="llm-settings">
    <div class="llm-mode-switch" role="tablist" aria-label="LLM 调用模式">
      <button
        type="button"
        role="tab"
        :aria-selected="llmMode === 'single'"
        :class="{ active: llmMode === 'single' }"
        @click="llmMode = 'single'; llmTest = null"
      >单端点</button>
      <button
        type="button"
        role="tab"
        :aria-selected="llmMode === 'pool'"
        :class="{ active: llmMode === 'pool' }"
        @click="llmMode = 'pool'; llmTest = null"
      >端点池</button>
    </div>

    <div v-if="llmMode === 'single'" class="llm-config-pane">
      <div class="wizard-steps model-wizard-steps" aria-label="模型连接向导">
        <button
          v-for="(s, i) in WIZARD_STEPS"
          :key="s.id"
          type="button"
          class="wizard-step"
          :class="{ on: wizardStep === i, done: wizardStep > i, linked: wizardStep > i }"
          :disabled="i > wizardStep"
          @click="wizardStep = i"
        >
          <span class="ws-dot">{{ wizardStep > i ? "✓" : i + 1 }}</span>
          <span class="ws-txt"><b>{{ s.label }}</b></span>
        </button>
      </div>

      <div v-if="wizardStep === 0" class="provider-preset-pane">
        <p v-if="presetsLoading" class="create-mini">加载模型商预设…</p>
        <div v-else class="provider-preset-grid">
          <button
            v-for="p in providerPresets"
            :key="p.id"
            type="button"
            class="provider-preset-card"
            :class="{ on: selectedPresetId === p.id }"
            @click="pickProvider(p)"
          >
            <b>{{ p.name }}</b>
            <small>{{ p.desc }}</small>
            <code>{{ p.base_url || "手动填写" }}</code>
            <span class="preset-tags">
              <em v-for="t in p.tags" :key="t">{{ t }}</em>
            </span>
            <i v-if="p.recommended">推荐 {{ p.recommended }}</i>
          </button>
        </div>
        <p class="create-mini">选一个模型商自动填充 base_url / 协议 / 推荐模型；选「自定义」则手动配置。</p>
      </div>

      <div v-else-if="wizardStep === 1" class="settings-grid">
        <label class="full">base_url
          <input v-model="form.base_url" required placeholder="https://api.deepseek.com/v1" @input="invalidateSingleKey" />
          <small class="muted">Coding Plan 填官方根地址即可（智谱 <code>…/api/coding/paas/v4</code>、方舟 <code>…/api/coding/v3</code>），不要再加 /v1。无版本号的根会自动补 /v1。</small>
        </label>
        <label class="full">api_key
          <input v-model="form.api_key" type="password"
            :required="!form.key_ref"
            :placeholder="form.api_key_set ? '已配置，留空不修改' : 'sk-...'" />
        </label>
        <label>协议
          <select v-model="form.protocol" @change="invalidateSingleKey">
            <option value="auto">自动判断</option>
            <option value="openai_chat">OpenAI Chat</option>
            <option value="anthropic_messages">Anthropic Messages</option>
          </select>
        </label>
        <div class="settings-test">
          <button type="button" :disabled="singleTest?.loading" @click="testSingleModel">
            {{ singleTest?.loading ? "测试中…" : "测试连接" }}
          </button>
          <span v-if="singleTest && !singleTest.loading" class="model-test-result" :class="singleTest.ok ? 'ok' : 'fail'">
            <template v-if="singleTest.ok">
              ✓ 连通 · {{ singleTest.latency_ms }}ms
              <em v-if="singleTest.tool_calling === 'yes'" class="tc-yes">工具调用 ✓</em>
              <em v-else-if="singleTest.tool_calling === 'no'" class="tc-no">工具调用 ✗</em>
            </template>
            <template v-else>{{ singleTest.error }}</template>
          </span>
        </div>
        <div class="wizard-nav full">
          <button type="button" class="ghost-btn" @click="wizardStep = 0">← 上一步</button>
          <button type="button" class="primary" :disabled="!form.base_url.trim() || (!form.api_key.trim() && !form.key_ref)" @click="wizardStep = 2">下一步：选模型 →</button>
        </div>
      </div>

      <div v-else class="settings-grid">
        <label class="full">模型名
          <LlmModelPicker
            v-model="form.model"
            :models="singleModels"
            :loading="singleModelsLoading"
            :error="singleModelsError"
            required
            @refresh="loadSingleModels"
          />
        </label>
        <div class="full backup-models">
          <span class="backup-models-title">灾备模型（可选，多选）</span>
          <small class="muted">主模型不可用时自动切换到这些同供应商模型顶替，无需中断任务。</small>
          <div class="backup-models-chips">
            <span v-for="(m, i) in form.models" :key="m" class="backup-model-chip">
              {{ m }}
              <button type="button" class="backup-chip-remove" :aria-label="`移除 ${m}`" @click="removeBackupModel(i)">×</button>
            </span>
            <span v-if="!form.models.length" class="backup-models-empty">未配置灾备模型</span>
          </div>
          <div class="backup-models-add">
            <select v-model="backupDraft" @change="addBackupModelFromSelect">
              <option value="" disabled>从模型列表选择…</option>
              <option v-for="m in backupCandidates" :key="m" :value="m">{{ m }}</option>
            </select>
            <input v-model="backupDraftText" placeholder="或手动输入模型名" @keydown.enter.prevent="addBackupModelFromInput" />
            <button type="button" class="ghost-btn" :disabled="!backupDraftText.trim()" @click="addBackupModelFromInput">添加</button>
          </div>
        </div>
        <label class="full">temperature
          <TemperatureRecommend v-model="form.temperature" :model="form.model" />
        </label>
        <div class="wizard-recap full">
          <span>模型商</span><b>{{ selectedPresetName }}</b>
          <span>端点</span><code>{{ form.base_url }}</code>
          <span>模型</span><b>{{ form.model || "未选" }}</b>
        </div>
        <div class="wizard-nav full">
          <button type="button" class="ghost-btn" @click="wizardStep = 1">← 上一步</button>
        </div>
      </div>
    </div>

    <div v-else class="llm-pool-pane">
      <div class="llm-pool-toolbar">
        <div>
          <b>端点列表</b>
          <span>{{ form.llm_providers.length }} 个</span>
        </div>
        <div class="llm-pool-toolbar-actions">
          <button type="button" :disabled="healthLoading || !form.llm_providers.length" @click="refreshHealthActive">
            {{ healthLoading ? "…" : "刷新健康" }}
          </button>
          <button type="button" @click="addLlmProvider">+ 添加端点</button>
        </div>
      </div>

      <div v-if="!form.llm_providers.length" class="provider-empty">
        <span>端点池为空</span>
        <button type="button" @click="addLlmProvider">+ 添加端点</button>
      </div>

      <div v-else class="provider-selector" role="listbox" aria-label="LLM 端点列表">
        <button
          v-for="(provider, idx) in form.llm_providers"
          :key="provider._uid || idx"
          type="button"
          role="option"
          :aria-selected="selectedLlmProvider === idx"
          class="provider-selector-row"
          :class="[{ active: selectedLlmProvider === idx, disabled: provider.enabled === false }, `health-${providerHealthClass(provider)}`]"
          @click="selectedLlmProvider = idx"
        >
          <span class="provider-dot" :class="providerHealthClass(provider)"></span>
          <b>{{ provider.name || `llm-${idx + 1}` }}</b>
          <small>{{ provider.model || "未设置模型" }}</small>
          <em>{{ provider.protocol === "auto" ? "Auto" : provider.protocol === "anthropic_messages" ? "Anthropic" : "OpenAI" }}</em>
          <i>权重 {{ provider.weight || 1 }}</i>
        </button>
      </div>

      <div v-if="selectedLlm" class="provider-detail">
        <div class="provider-detail-head">
          <div>
            <span>端点 {{ selectedLlmProvider + 1 }}</span>
            <strong class="provider-health" :class="providerHealthClass(selectedLlm)" :title="providerHealthTitle(selectedLlm)">
              {{ providerHealthText(selectedLlm) }}
            </strong>
          </div>
          <div class="provider-head-actions">
            <button type="button" class="provider-act" title="上移" aria-label="上移端点" :disabled="selectedLlmProvider === 0" @click="moveLlmProvider(selectedLlmProvider, -1)">
              <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true"><path d="M8 4.2 12.2 9H3.8z" fill="currentColor"/></svg>
            </button>
            <button type="button" class="provider-act" title="下移" aria-label="下移端点" :disabled="selectedLlmProvider === form.llm_providers.length - 1" @click="moveLlmProvider(selectedLlmProvider, 1)">
              <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true"><path d="M8 11.8 3.8 7h8.4z" fill="currentColor"/></svg>
            </button>
            <label class="provider-enabled" :class="{ on: selectedLlm.enabled !== false }">
              <input v-model="selectedLlm.enabled" type="checkbox" />
              <span class="switch-track" aria-hidden="true"><span class="switch-knob"></span></span>
              <span>启用</span>
            </label>
            <button type="button" class="provider-act danger" title="删除端点" aria-label="删除端点" @click="removeLlmProvider(selectedLlmProvider)">
              <svg viewBox="0 0 16 16" width="15" height="15" aria-hidden="true"><path d="M4.6 4.6l6.8 6.8m0-6.8-6.8 6.8" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round"/></svg>
            </button>
          </div>
        </div>

        <div class="provider-fields">
          <div class="provider-fields-group">
            <span class="provider-fields-title">连接</span>
            <div class="provider-fields-grid">
              <label>名称 <input v-model="selectedLlm.name" placeholder="primary" /></label>
              <label>协议
                <select v-model="selectedLlm.protocol" @change="invalidateProviderKey(selectedLlm)">
                  <option value="auto">自动判断</option>
                  <option value="openai_chat">OpenAI Chat</option>
                  <option value="anthropic_messages">Anthropic Messages</option>
                </select>
              </label>
              <label class="wide">base_url
                <input v-model="selectedLlm.base_url" placeholder="https://api.deepseek.com/v1" @input="invalidateProviderKey(selectedLlm)" />
                <small class="muted">Coding Plan 填官方根地址，不要再加 /v1。</small>
              </label>
            </div>
          </div>

          <div class="provider-fields-group">
            <span class="provider-fields-title">认证</span>
            <div class="provider-fields-grid">
              <label class="wide">api_key
                <input
                  v-model="selectedLlm.api_key"
                  type="password"
                  :required="!selectedLlm.key_ref"
                  :placeholder="selectedLlm.api_key_set ? `${selectedLlm.api_key_masked}，留空不修改` : 'sk-...'"
                />
              </label>
            </div>
          </div>

          <div class="provider-fields-group">
            <span class="provider-fields-title">模型与参数</span>
            <div class="provider-fields-grid">
              <label class="wide">模型名
                <LlmModelPicker
                  v-model="selectedLlm.model"
                  :models="selectedLlm.models"
                  :loading="selectedLlm.modelsLoading"
                  :error="selectedLlm.modelsError"
                  required
                  @refresh="loadProviderModels(selectedLlmProvider)"
                />
              </label>
              <label>temperature
                <TemperatureRecommend
                  :model-value="selectedLlm.temperature"
                  :model="selectedLlm.model"
                  @update:model-value="selectedLlm.temperature = $event"
                />
              </label>
              <label>权重
                <input v-model="selectedLlm.weight" type="number" min="1" max="100" />
              </label>
            </div>
          </div>

          <div class="provider-test wide">
            <button type="button" :disabled="selectedLlm.testing" @click="testLlmProvider(selectedLlmProvider)">
              {{ selectedLlm.testing ? "测试中…" : "测试当前端点" }}
            </button>
          </div>
        </div>
      </div>

      <div v-if="form.llm_providers.length" class="pool-schedule">
        <div class="pool-schedule-head">
          <b>调度预览</b>
          <button type="button" class="ghost-btn" :disabled="scheduleLoading" @click="refreshSchedule">
            {{ scheduleLoading ? "…" : "刷新" }}
          </button>
        </div>
        <template v-if="schedulePreview">
          <p class="pool-schedule-explain">{{ schedulePreview.explanation }}</p>
          <div class="pool-schedule-bars">
            <div v-for="d in schedulePreview.distribution" :key="d.name" class="pool-schedule-row">
              <span class="psr-name" :title="d.name">{{ d.name }}</span>
              <span class="psr-track">
                <i :style="{ width: (d.share * 100).toFixed(1) + '%' }" :class="{ off: !d.enabled }"></i>
              </span>
              <span class="psr-share">{{ d.enabled ? (d.share * 100).toFixed(1) + "%" : "停用" }}</span>
            </div>
          </div>
          <p class="pool-schedule-total">总权重 {{ schedulePreview.total_weight }} · 策略 {{ schedulePreview.strategy }}</p>
        </template>
        <p v-else class="pool-schedule-explain">调度预览加载中…</p>
      </div>
    </div>

    <div v-if="llmTest" class="settings-test-result" :class="{ ok: llmTest.ok }">
      <div class="settings-test-head">
        <b>{{ llmTest.ok ? "LLM 可用" : "LLM 不可用" }}</b>
        <button type="button" class="mini-action" @click="copyLlmTest()">复制错误信息</button>
      </div>
      <p v-if="llmTest.error">{{ llmTest.error }}</p>
      <pre v-if="!llmTest.ok && (llmTest.error_copy || llmTest.error)" class="settings-test-raw">{{ llmTest.error_copy || llmTest.error }}</pre>
      <ul v-if="llmTest.results?.length">
        <li v-for="item in llmTest.results" :key="`${item.name}-${item.base_url}`" :class="{ ok: item.ok }">
          <div class="settings-test-item-head">
            <strong>{{ item.ok ? "通过" : "失败" }} · {{ item.name || "single" }}</strong>
            <button type="button" class="mini-action" @click="copyLlmTest(item)">复制</button>
          </div>
          <small>{{ resultText(item) }}</small>
          <pre v-if="!item.ok && (item.error_copy || item.error)" class="settings-test-raw">{{ item.error_copy || item.error }}</pre>
        </li>
      </ul>
    </div>
  </div>
</template>
