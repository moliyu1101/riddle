<script setup>
import { computed, nextTick, onMounted, onUnmounted, reactive, ref, watch } from "vue";
import { api } from "../api.js";
import { applyUi, loadUiPrefs, prefsFromApi, saveUiPrefs } from "../uiTheme.js";
import { useLlmProviders } from "../composables/useLlmProviders.js";
import { useAppearance } from "../composables/useAppearance.js";
import { useBackup } from "../composables/useBackup.js";
import { useWorkdir } from "../composables/useWorkdir.js";
import { useUpdate } from "../composables/useUpdate.js";
import SettingsSidebar from "../components/settings/SettingsSidebar.vue";
import AppearancePanel from "../components/settings/AppearancePanel.vue";
import LlmSettingsPanel from "../components/settings/LlmSettingsPanel.vue";
import ReconSettingsPanel from "../components/settings/ReconSettingsPanel.vue";
import RuntimeSettingsPanel from "../components/settings/RuntimeSettingsPanel.vue";
import SecurityPanel from "../components/settings/SecurityPanel.vue";
import DataBackupPanel from "../components/settings/DataBackupPanel.vue";
import ConfigTransferPanel from "../components/settings/ConfigTransferPanel.vue";
import WorkdirPanel from "../components/settings/WorkdirPanel.vue";
import UpdatePanel from "../components/settings/UpdatePanel.vue";

const loading = ref(true);
const saving = ref(false);
const toastMsg = ref("");
const meta = ref({ updated_at: null });
/** 与后端 mask_secret 一致的脱敏占位：已设置且未改动时回传，让后端保持原值 */
const MASKED = "••••••••";
/** 全局健康总览（/api/settings/health-overview）：LLM / 测绘引擎 / 磁盘 */
const healthOverview = ref(null);
const healthOverviewLoading = ref(false);
const llmMode = ref("single");
const llmTest = ref(null);
const singleModels = ref([]);
const singleModelsLoading = ref(false);
const singleModelsError = ref("");
const testingLlm = ref(false);
/** 自动保存状态：idle | pending | saving | saved | error | incomplete */
const autoSaveStatus = ref("idle");
const autoSaveError = ref("");
/** 令牌保存完成信号：时间戳变化时 SecurityPanel 显示「已保存并生效」 */
const authSaveFlash = ref(0);
let autoSaveTimer = null;
const suppressAutoSave = ref(false); // load / 保存回写期间屏蔽 watch
let dirtyDuringSave = false; // 保存飞行中又有改动 → finally 后补一次调度
let healthPoll = null;
let restartPoll = null;   // pollHealth 的重启轮询计时器（组件卸载时清理，防泄漏）

const form = reactive({
  base_url: "",
  api_key: "",
  key_ref: "",
  model: "",
  models: [],   // 单端点多模型灾备：主模型之外的同供应商灾备模型
  protocol: "openai_chat",
  temperature: 0.3,
  api_key_set: false,
  llm_providers: [],
  fofa_key: "",
  fofa_key_set: false,
  fofa_base_url: "",
  max_pages: 20,
  page_size: 100,
  default_intent_mode: "",
  default_engine: "fofa",
  engines: {},
  available_engines: [],
  concurrency: 3,
  deepen_cap: 2,
  skip_score_threshold: -10,
  worker_prompt_version: "legacy",
  // 访问令牌：输入值 + 已设置/环境变量标志（来自 /api/settings 的 auth 段）
  full_token: "",
  full_token_set: false,
  env_full: false,
  read_token: "",
  read_token_set: false,
  env_read: false,
  observer_token: "",
  observer_token_set: false,
  env_observer: false,
});

const engineKeysSetCount = computed(() =>
  Object.values(form.engines || {}).filter((e) => e && e.key_set).length
);

/** 外观面板 props：将嵌套 ref 解包为普通值，避免子组件模板未解包导致 NaN */
const appearanceProps = computed(() => ({
  uiPrefs: appearance.uiPrefs.value,
  wallpaperBusy: appearance.wallpaperBusy.value,
  wallpaperError: appearance.wallpaperError.value,
  wallpaperPreviewStyle: appearance.wallpaperPreviewStyle.value,
}));

/** 数据备份面板 props：嵌套 ref 解包 */
const backupProps = computed(() => ({
  backupStats: backup.backupStats.value,
  backupLoading: backup.backupLoading.value,
  backupBusy: backup.backupBusy.value,
  restoreFile: backup.restoreFile.value,
  backupRestarting: backup.backupRestarting.value,
}));

/** 工作目录面板 props：嵌套 ref 解包 */
const workdirProps = computed(() => ({
  workdirStats: workdir.workdirStats.value,
  workdirLoading: workdir.workdirLoading.value,
  workdirCleaning: workdir.workdirCleaning.value,
  workdirResult: workdir.workdirResult.value,
}));

function toast(m) {
  toastMsg.value = m;
  setTimeout(() => (toastMsg.value = ""), 2600);
}

function pollHealth() {
  let attempts = 0;
  clearInterval(restartPoll);
  restartPoll = setInterval(async () => {
    attempts++;
    try {
      const r = await fetch("/health");
      if (r.ok) {
        clearInterval(restartPoll);
        const fromBackup = backup.backupRestarting.value;
        update.updateState.restarting = false;
        backup.backupRestarting.value = false;
        toast(fromBackup ? "备份恢复完成，服务已重启" : "更新完成，服务已重启 🎉");
        update.updateState.info = null;
        load();
      }
    } catch {}
    if (attempts > 60) { clearInterval(restartPoll); update.updateState.restarting = false; backup.backupRestarting.value = false; update.updateState.error = "重启超时，请手动刷新页面"; }
  }, 3000);
}

function secretReady(value) {
  // 密钥输入中途不自动提交（避免 "sk-" 半成品写进 DB）；留空=不覆盖
  const v = String(value || "").trim();
  return v.length >= 8;
}

function scheduleAutoSave() {
  if (loading.value) return;
  if (saving.value) {
    // 飞行中改动（含 suppressAutoSave=true 的回写窗口）：标记脏，finally 再调度
    dirtyDuringSave = true;
    autoSaveStatus.value = "pending";
    return;
  }
  if (suppressAutoSave.value) return;
  autoSaveStatus.value = "pending";
  autoSaveError.value = "";
  clearTimeout(autoSaveTimer);
  // 端点详情输入中拉长防抖，避免打字过程中频繁落库抢焦点/冲选中态
  const typingPool = typeof document !== "undefined"
    && !!document.activeElement?.closest?.(".provider-detail, .provider-fields, .llm-pool-pane .model-picker");
  autoSaveTimer = setTimeout(() => {
    save({ silent: true }).catch(() => {});
  }, typingPool ? 2500 : 1200);
}

async function save({ silent = false } = {}) {
  if (saving.value || loading.value) return;
  // 配置不完整时：静默跳过自动保存，手动保存仍提示
  try {
    llm.validateLlmProviders();
  } catch (e) {
    autoSaveStatus.value = "incomplete";
    autoSaveError.value = String(e.message || e);
    if (!silent) toast(autoSaveError.value);
    return;
  }

  saving.value = true;
  dirtyDuringSave = false;
  autoSaveStatus.value = "saving";
  autoSaveError.value = "";
  const clearedKeyIndexes = [];
  // 记录本次保存前令牌输入框的值：非空 = 用户本次设置了新令牌，保存后要给明确反馈
  const authInput = {
    full: String(form.full_token || "").trim(),
    read: String(form.read_token || "").trim(),
    observer: String(form.observer_token || "").trim(),
  };
  try {
    const body = {
      llm: {
        mode: llmMode.value,
        base_url: form.base_url,
        model: form.model,
        models: form.models,
        protocol: form.protocol,
        temperature: Number(form.temperature),
        providers: llm.buildLlmProviders(),
      },
      fofa: {
        max_pages: Number(form.max_pages),
        page_size: Number(form.page_size),
        default_intent_mode: form.default_intent_mode,
      },
      engines: {},
      defaults: {
        concurrency: Number(form.concurrency),
        deepen_cap: Number(form.deepen_cap),
        skip_score_threshold: Number(form.skip_score_threshold),
        worker_prompt_version: form.worker_prompt_version,
        engine: form.default_engine || "fofa",
      },
      auth: {
        full_token: form.full_token_set && !form.full_token ? MASKED : form.full_token,
        read_token: form.read_token_set && !form.read_token ? MASKED : form.read_token,
        observer_token: form.observer_token_set && !form.observer_token ? MASKED : form.observer_token,
      },
    };
    if (secretReady(form.api_key)) body.llm.api_key = form.api_key.trim();
    for (const [name, eng] of Object.entries(form.engines || {})) {
      const patch = { base_url: eng.base_url || "" };
      if (secretReady(eng.key)) patch.key = eng.key.trim();
      body.engines[name] = patch;
    }
    const fofaEng = form.engines?.fofa;
    if (fofaEng) {
      body.fofa.base_url = fofaEng.base_url || "";
      if (secretReady(fofaEng.key)) body.fofa.key = fofaEng.key.trim();
    }
    // 端点池密钥：半成品不提交，靠 key_ref 让后端保留原值
    if (llmMode.value === "pool") {
      body.llm.providers = body.llm.providers.map((provider, idx) => {
        if (secretReady(provider.api_key)) {
          clearedKeyIndexes.push(idx);
          return provider;
        }
        return { ...provider, api_key: "" };
      });
    }

    suppressAutoSave.value = true;
    const s = await api.updateSettings(body);
    meta.value = { updated_at: s.updated_at };
    form.api_key = "";
    form.fofa_key = "";
    form.api_key_set = s.llm?.api_key_set;
    form.key_ref = s.llm?.key_ref || "";
    form.models = (s.llm?.models || []).filter((m) => m && m !== form.model);
    llmMode.value = s.llm?.mode === "pool" ? "pool" : "single";
    form.protocol = llm.normalizeLlmProtocol(s.llm?.protocol);
    form.fofa_key_set = s.fofa?.key_set;
    const engView = s.engines || {};
    for (const name of Object.keys(form.engines || {})) {
      const cur = engView[name] || {};
      form.engines[name].key = "";
      form.engines[name].key_set = !!cur.key_set || (name === "fofa" && !!s.fofa?.key_set);
      form.engines[name].base_url = cur.base_url || (name === "fofa" ? (s.fofa?.base_url || "") : "") || form.engines[name].base_url || "";
      if (cur.display_name) form.engines[name].display_name = cur.display_name;
    }
    form.default_engine = s.defaults?.engine || form.default_engine;
    // 令牌：保存后刷新已设置/环境变量标志，输入框清空（已设置时留空=不修改）
    const authView = s.auth || {};
    form.full_token = "";
    form.full_token_set = !!authView.full_token_set;
    form.env_full = !!authView.env_full;
    form.read_token = "";
    form.read_token_set = !!authView.read_token_set;
    form.env_read = !!authView.env_read;
    form.observer_token = "";
    form.observer_token_set = !!authView.observer_token_set;
    form.env_observer = !!authView.env_observer;
    // 关键：禁止 loadLlmProviders 整表替换；就地合并，不强制改写选中索引（用户飞行中换端点不被抢回）
    if (llmMode.value === "pool") {
      llm.mergeProvidersAfterSave(s.llm?.providers || [], clearedKeyIndexes);
      if (form.llm_providers.length && llm.selectedLlmProvider.value >= form.llm_providers.length) {
        llm.selectedLlmProvider.value = form.llm_providers.length - 1;
      }
    }
    autoSaveStatus.value = dirtyDuringSave ? "pending" : "saved";
    // 令牌是敏感操作：即使自动保存也要明确反馈，避免用户以为没生效
    const authChanged = Object.values(authInput).some(Boolean);
    if (authChanged) {
      toast("访问令牌已保存并生效");
      authSaveFlash.value = Date.now();
    } else if (!silent) {
      toast("系统配置已保存");
    }
  } catch (e) {
    const msg = String(e.message || e).replace(/^\d+\s*/, "");
    autoSaveStatus.value = "error";
    autoSaveError.value = msg;
    toast(msg);
  } finally {
    saving.value = false;
    await nextTick();
    suppressAutoSave.value = false;
    if (dirtyDuringSave) {
      dirtyDuringSave = false;
      scheduleAutoSave();
    }
  }
}

async function load() {
  clearTimeout(autoSaveTimer);
  autoSaveTimer = null;
  dirtyDuringSave = false;
  loading.value = true;
  suppressAutoSave.value = true;
  try {
    const s = await api.getSettings();
    meta.value = { updated_at: s.updated_at };
    form.base_url = s.llm?.base_url || "";
    form.model = s.llm?.model || "";
    form.models = (s.llm?.models || []).filter((m) => m && m !== form.model);
    form.protocol = llm.normalizeLlmProtocol(s.llm?.protocol);
    form.temperature = s.llm?.temperature ?? 0.3;
    form.api_key = "";
    form.key_ref = s.llm?.key_ref || "";
    form.api_key_set = s.llm?.api_key_set;
    llmMode.value = s.llm?.mode === "pool" ? "pool" : "single";
    llm.loadLlmProviders(s.llm?.providers || []);
    form.fofa_key = "";
    form.fofa_key_set = s.fofa?.key_set;
    form.fofa_base_url = s.fofa?.base_url || "";
    form.max_pages = s.fofa?.max_pages ?? 20;
    form.page_size = s.fofa?.page_size ?? 100;
    form.default_intent_mode = s.fofa?.default_intent_mode || "";
    form.default_engine = s.defaults?.engine || "fofa";
    form.available_engines = s.available_engines || [];
    const engView = s.engines || {};
    const nextEngines = {};
    for (const meta of form.available_engines) {
      const name = meta.name;
      const cur = engView[name] || {};
      nextEngines[name] = {
        display_name: meta.display_name || cur.display_name || name,
        key: "",
        key_set: !!cur.key_set,
        base_url: cur.base_url || "",
      };
    }
    if (nextEngines.fofa && !nextEngines.fofa.key_set && s.fofa?.key_set) {
      nextEngines.fofa.key_set = true;
    }
    if (nextEngines.fofa && !nextEngines.fofa.base_url && s.fofa?.base_url) {
      nextEngines.fofa.base_url = s.fofa.base_url;
    }
    form.engines = nextEngines;
    form.concurrency = s.defaults?.concurrency ?? 3;
    form.deepen_cap = s.defaults?.deepen_cap ?? 2;
    form.skip_score_threshold = s.defaults?.skip_score_threshold ?? -10;
    form.worker_prompt_version = s.defaults?.worker_prompt_version || "legacy";
    const authView = s.auth || {};
    form.full_token = "";
    form.full_token_set = !!authView.full_token_set;
    form.env_full = !!authView.env_full;
    form.read_token = "";
    form.read_token_set = !!authView.read_token_set;
    form.env_read = !!authView.env_read;
    form.observer_token = "";
    form.observer_token_set = !!authView.observer_token_set;
    form.env_observer = !!authView.env_observer;
    if (s.ui) {
      appearance.uiPrefs.value = saveUiPrefs(prefsFromApi(s.ui));
      await applyUi(appearance.uiPrefs.value);
    }
    autoSaveStatus.value = "idle";
    autoSaveError.value = "";
  } finally {
    loading.value = false;
    await nextTick();
    suppressAutoSave.value = false;
  }
}

watch([form, llmMode], () => scheduleAutoSave(), { deep: true });

async function loadHealthOverview() {
  healthOverviewLoading.value = true;
  try {
    healthOverview.value = await api.healthOverview();
  } catch {
    healthOverview.value = null;
  } finally {
    healthOverviewLoading.value = false;
  }
}

/** 配置导入完成后：重载全部配置并刷新健康总览 */
async function onConfigImported() {
  toast("配置导入成功");
  await load();
  await loadHealthOverview();
}

/** 头部「刷新」：全量重载配置 + 健康 + 备份 + 磁盘统计 */
async function reloadAll() {
  await load();
  await Promise.allSettled([
    loadHealthOverview(),
    workdir.loadWorkdirStats(),
    backup.loadBackupStats(),
    llm.refreshProviderHealth(),
  ]);
}

const autoSaveLabel = computed(() => {
  if (autoSaveStatus.value === "pending") return "将自动保存…";
  if (autoSaveStatus.value === "saving") return "自动保存中…";
  if (autoSaveStatus.value === "saved") {
    const t = meta.value.updated_at?.slice(11, 19) || "";
    return t ? `已自动保存 ${t}` : "已自动保存";
  }
  if (autoSaveStatus.value === "incomplete") return autoSaveError.value || "完善配置后将自动保存";
  if (autoSaveStatus.value === "error") return autoSaveError.value || "自动保存失败";
  return "改动后约 1 秒自动保存";
});

const settingsTab = ref("appearance");
const SETTINGS_TABS = [
  { id: "appearance", label: "外观", hint: "颜色与背景" },
  { id: "llm", label: "模型", hint: "LLM 通道" },
  { id: "recon", label: "测绘", hint: "引擎与 Key" },
  { id: "runtime", label: "调度", hint: "并发深挖" },
  { id: "security", label: "安全", hint: "访问令牌" },
  { id: "data", label: "数据", hint: "备份磁盘" },
  { id: "update", label: "更新", hint: "版本检查" },
];
const visibleTabs = computed(() =>
  SETTINGS_TABS.filter((t) => t.id !== "update" || update.updateState.supported)
);

const llm = useLlmProviders({
  form, llmMode, llmTest,
  singleModels, singleModelsLoading, singleModelsError, testingLlm,
  toast, suppressAutoSave, scheduleAutoSave,
});
const appearance = useAppearance({ toast });
const backup = useBackup({ toast, pollHealth });
const workdir = useWorkdir({ toast });
const update = useUpdate({ toast, pollHealth, load });

onMounted(async () => {
  appearance.uiPrefs.value = loadUiPrefs();
  window.addEventListener("ah-ui-changed", appearance.onUiChanged);
  await load();
  llm.refreshProviderHealth().catch(() => {});
  healthPoll = setInterval(() => llm.refreshProviderHealth().catch(() => {}), 10000);
  // 探测后端是否支持更新 API（原版不注册 → supported=false → 隐藏区块）
  update.checkUpdate();
  workdir.loadWorkdirStats();
  backup.loadBackupStats();
  loadHealthOverview();
});
onUnmounted(() => {
  window.removeEventListener("ah-ui-changed", appearance.onUiChanged);
  appearance.disposeAppearance();
  clearInterval(healthPoll);
  clearInterval(restartPoll);
  clearTimeout(autoSaveTimer);
});
</script>

<template>
  <section class="view settings-view">
    <nav class="crumb" aria-label="面包屑">
      <span>指挥中心</span>
      <span class="crumb-sep">/</span>
      <b>系统配置</b>
    </nav>
    <header class="page-head">
      <div class="settings-head-main">
        <h2>系统配置</h2>
        <p class="page-sub">
          左侧切换分组。模型/测绘/调度约 1 秒自动保存；外观写入服务器，换浏览器也还在。
          <span v-if="meta.updated_at" class="settings-updated">上次保存 {{ meta.updated_at?.slice(0, 19).replace("T", " ") }}</span>
        </p>
      </div>
      <div class="settings-head-actions">
        <span class="autosave-chip" :class="autoSaveStatus" :title="autoSaveError">{{ autoSaveLabel }}</span>
        <button type="button" class="settings-head-btn" :disabled="loading" @click="reloadAll">
          <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M13.5 8a5.5 5.5 0 1 1-1.6-3.9M13.5 1.5v3h-3" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
          {{ loading ? "加载中…" : "刷新" }}
        </button>
        <button type="button" class="settings-head-btn primary" :disabled="saving" @click="save()">
          <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M3 8.5 6.2 11.5 13 4.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>
          {{ saving ? "保存中…" : "立即保存" }}
        </button>
      </div>
    </header>

    <!-- 骨架屏：镜像真实的「摘要侧栏 + 配置块」两栏布局，与加载后的结构对齐（不再是一行“加载中…”）。 -->
    <div v-if="loading" class="settings-layout settings-skeleton" aria-hidden="true">
      <aside class="settings-summary skeleton-panel">
        <div class="skeleton-block lg" style="height:16px;width:58%"></div>
        <div class="skeleton-line" style="margin-top:16px"></div>
        <div class="skeleton-line"></div>
        <div class="skeleton-line"></div>
        <div class="skeleton-line" style="width:68%"></div>
      </aside>
      <div class="settings-form">
        <div v-for="i in 3" :key="i" class="settings-block skeleton-panel">
          <div class="skeleton-block lg" style="height:15px;width:38%;margin-bottom:16px"></div>
          <div class="skeleton-line"></div>
          <div class="skeleton-line"></div>
          <div class="skeleton-line" style="width:84%"></div>
          <div class="skeleton-row" style="margin-top:14px">
            <div class="skeleton-chip"></div>
            <div class="skeleton-chip wide"></div>
          </div>
        </div>
      </div>
    </div>
    <div v-else class="settings-layout">
      <SettingsSidebar
        :visible-tabs="visibleTabs"
        :settings-tab="settingsTab"
        :llm-mode="llmMode"
        :form="form"
        :engine-keys-set-count="engineKeysSetCount"
        :health-overview="healthOverview"
        :health-overview-loading="healthOverviewLoading"
        @update:settings-tab="settingsTab = $event"
      />

      <form class="form settings-form" novalidate @submit.prevent="save">
        <fieldset v-show="settingsTab === 'appearance'" class="settings-block">
          <legend>
            <span>外观</span>
            <small>主题色与背景保存在本实例服务器，换电脑也能带上</small>
          </legend>
          <AppearancePanel
            v-bind="appearanceProps"
            :set-theme-mode="appearance.setThemeMode"
            :persist-ui="appearance.persistUi"
            :set-accent-hue="appearance.setAccentHue"
            :on-custom-accent="appearance.onCustomAccent"
            :set-accent2-hue="appearance.setAccent2Hue"
            :on-custom-accent2="appearance.onCustomAccent2"
            :set-glow="appearance.setGlow"
            :set-bg-hue="appearance.setBgHue"
            :active-preset-id="appearance.activePresetId"
            :apply-theme-preset="appearance.applyThemePreset"
            :set-ui-scale="appearance.setUiScale"
            :set-motion="appearance.setMotion"
            :on-wallpaper-file="appearance.onWallpaperFile"
            :apply-wallpaper-url="appearance.applyWallpaperUrl"
            :on-clear-wallpaper="appearance.onClearWallpaper"
            :reset-appearance="appearance.resetAppearance"
          />
        </fieldset>

        <fieldset v-show="settingsTab === 'llm'" class="settings-block">
          <legend>
            <span>AI / LLM</span>
            <small>Worker、Reviewer、报告助手共用的默认模型通道</small>
          </legend>
          <LlmSettingsPanel
            :form="form"
            :single-models="singleModels"
            :single-models-loading="singleModelsLoading"
            :single-models-error="singleModelsError"
            :llm="llm"
          />
        </fieldset>

        <fieldset v-show="settingsTab === 'recon'" class="settings-block">
          <legend>
            <span>资产测绘</span>
            <small>多引擎搜集默认；创建任务可选引擎，Key 在此统一配置</small>
          </legend>
          <ReconSettingsPanel :form="form" />
        </fieldset>

        <fieldset v-show="settingsTab === 'runtime'" class="settings-block">
          <legend>
            <span>调度默认</span>
            <small>新任务创建时的保守默认值</small>
          </legend>
          <RuntimeSettingsPanel :form="form" />
        </fieldset>

        <fieldset v-show="settingsTab === 'security'" class="settings-block">
          <legend>
            <span>访问安全</span>
            <small>自定义访问令牌，控制谁能登录本实例。留空不修改，输入新值覆盖。</small>
          </legend>
          <SecurityPanel :form="form" :save-flash="authSaveFlash" />
        </fieldset>

        <fieldset v-show="settingsTab === 'data'" class="settings-block">
          <legend>
            <span>数据备份</span>
            <small>导出/导入是主路径。SQLite 在线备份打一致快照，不要直接拷正在写的库文件。</small>
          </legend>
          <DataBackupPanel
            v-bind="backupProps"
            v-model:backup-include-work="backup.backupIncludeWork"
            v-model:restore-include-work="backup.restoreIncludeWork"
            :export-backup="backup.exportBackup"
            :snapshot-now="backup.snapshotNow"
            :download-snapshot="backup.downloadSnapshot"
            :on-restore-file="backup.onRestoreFile"
            :restore-backup="backup.restoreBackup"
            :load-backup-stats="backup.loadBackupStats"
          />
        </fieldset>

        <fieldset v-show="settingsTab === 'data'" class="settings-block">
          <legend>
            <span>配置迁移</span>
            <small>导出/导入系统配置 JSON，跨实例迁移或本地备份。密钥留空不覆盖现有值。</small>
          </legend>
          <ConfigTransferPanel :on-imported="onConfigImported" />
        </fieldset>

        <fieldset v-show="settingsTab === 'data'" class="settings-block">
          <legend>
            <span>工作目录管理</span>
            <small>Worker / Escalate 等 agent 产生的临时文件磁盘占用与清理</small>
          </legend>
          <WorkdirPanel
            v-bind="workdirProps"
            v-model:cleanup-retention-days="workdir.cleanupRetentionDays"
            v-model:cleanup-dry-run="workdir.cleanupDryRun"
            :run-cleanup="workdir.runCleanup"
            :load-workdir-stats="workdir.loadWorkdirStats"
          />
        </fieldset>

        <fieldset v-if="update.updateState.supported" v-show="settingsTab === 'update'" class="settings-block update-section">
          <legend>
            <span>版本更新</span>
            <small>检查 GitHub 最新代码；git 部署可一键热更，镜像部署给出手动指引</small>
          </legend>
          <UpdatePanel
            :update-state="update.updateState"
            :check-update="update.checkUpdate"
            :run-update="update.runUpdate"
          />
        </fieldset>

        <div v-show="['llm','recon','runtime'].includes(settingsTab)" class="settings-actions">
          <span class="settings-actions-hint">密钥留空不覆盖；输入完成后会随自动保存写入。改动约 1 秒自动保存。</span>
          <button type="submit" class="primary" :disabled="saving">
            {{ saving ? "保存中…" : "立即保存" }}
          </button>
        </div>
      </form>
    </div>

    <div v-if="toastMsg" class="toast settings-toast">{{ toastMsg }}</div>
  </section>
</template>
