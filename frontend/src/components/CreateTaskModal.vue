<script setup>
import { computed, reactive, ref, watch, onMounted, onBeforeUnmount } from "vue";
import { useRouter } from "vue-router";
import { api } from "../api.js";
import { useAuthBindings, emptyBinding } from "../composables/useAuthBindings.js";
import { useCreateTask, closeCreateTask } from "../composables/useCreateTask.js";
import LlmModelPicker from "./LlmModelPicker.vue";
import LlmPoolEditor from "./LlmPoolEditor.vue";
import AuthTargetInput from "./AuthTargetInput.vue";
import TemperatureRecommend from "./TemperatureRecommend.vue";

defineOptions({ name: "CreateTaskModal" });

const router = useRouter();
const modal = useCreateTask();
const step = ref(1);
const bodyRef = ref(null);
const stepError = ref("");
const invalidField = ref("");
const draftRestored = ref(false);
const DRAFT_KEY = "riddle.create_task.draft.v1";
let saveTimer = null;
// 默认聚焦的高价值漏洞类型（与后端 dedup 规范类别一致；初始口径为 edusrc，即 EduSRC 推荐集）
const DEFAULT_VULN_TYPES = "sql_injection,rce,unauthorized_access,idor,file_upload,captcha_bypass,weak_password,info_leak,backdoor_compromised";
const form = reactive({
  name: "",
  src_type: "edusrc",
  vuln_types: DEFAULT_VULN_TYPES,
  target_source: "fofa",
  engine: "",
  fofa_query: "",
  intent_mode: "",
  manual_targets: "",
  src_rules: "",
  guard_ops: [],   // 任务级八大类拦截勾选（空=全不拦，勾什么拦什么）
  // inherit | single | pool
  model_mode: "inherit",
  base_url: "", api_key: "", key_ref: "", model: "", models: [], protocol: "auto", temperature: 0.3, prompt_version: "legacy",
  fofa_key: "", fofa_base_url: "", max_pages: 20, page_size: 100, concurrency: 3, deepen_cap: 2,
  skip_site_recon: false,
  skip_recon_touched: false,   // 用户是否手动调过这个开关（调过就不再自动跟随凭据）
});
const taskProviders = ref([]);
const singleModels = ref([]);
const singleModelsLoading = ref(false);
const singleModelsError = ref("");
const poolEditor = ref(null);
// 编辑模式：modal.editTaskId 非空时，弹窗预填任务数据、保存走 updateTask
const isEdit = computed(() => !!modal.editTaskId);
const editTask = ref(null);
const editLoading = ref(false);
const editError = ref("");
// 编辑模式：记录任务原始值，保存时只提交变更（密钥留空保留原值）
const original = reactive({
  base_url: "", model: "", protocol: "auto", prompt_version: "legacy",
  intent_mode: "", fofa_base_url: "", max_pages: 20, page_size: 100,
});
const { authBindings, addBinding, removeBinding, clearBindings, importBindings, bindingSummary, bindingKinds, kindLabel, exportAuthBindings, bindingOptions } =
  useAuthBindings(() => form.manual_targets, (v) => { form.manual_targets = v; });
const submitting = ref(false);
// 各测绘引擎是否已配置 Key（来自设置 → 资产测绘），用于引擎选项旁的状态点
const engineStatus = ref({});

const inherited = reactive({
  base_url: "",
  model: "",
  models: [],   // 全局设置的单端点多模型灾备列表
  protocol: "auto",
  llm_provider_count: 0,
  llm_mode: "single",
  prompt_version: "legacy",
  fofa_base_url: "",
  max_pages: 20,
  intent_mode: "",
  concurrency: 3,
});
// 漏洞类型与后端 dedup.normalize_vuln_type 的规范类别一一对应（19 类），分组便于挑选。
// hot 表示该类型在哪些口径下是"重点推荐"，切换口径时据此自动应用推荐集并打"推荐"徽标。
const VULN_GROUPS = [
  {
    title: "注入与执行",
    items: [
      { id: "sql_injection", label: "SQL 注入", hot: ["edusrc", "enterprise"] },
      { id: "rce", label: "命令执行", hot: ["edusrc", "enterprise"] },
      { id: "ssti", label: "模板注入", hot: ["enterprise"] },
      { id: "xxe", label: "XXE", hot: [] },
      { id: "deserialization", label: "反序列化", hot: ["enterprise"] },
    ],
  },
  {
    title: "越权与认证",
    items: [
      { id: "unauthorized_access", label: "未授权访问", hot: ["edusrc", "enterprise"] },
      { id: "idor", label: "水平越权", hot: ["edusrc", "enterprise"] },
      { id: "privilege_escalation", label: "垂直越权", hot: ["enterprise"] },
      { id: "captcha_bypass", label: "验证码绕过", hot: ["edusrc"] },
      { id: "weak_password", label: "弱口令", hot: ["edusrc"] },
    ],
  },
  {
    title: "文件与数据",
    items: [
      { id: "file_upload", label: "文件上传", hot: ["edusrc", "enterprise"] },
      { id: "file_read", label: "任意文件读取", hot: ["enterprise"] },
      { id: "info_leak", label: "敏感信息泄露", hot: ["edusrc"] },
    ],
  },
  {
    title: "客户端与逻辑",
    items: [
      { id: "xss", label: "XSS", hot: [] },
      { id: "csrf", label: "CSRF", hot: [] },
      { id: "ssrf", label: "SSRF", hot: ["enterprise"] },
      { id: "open_redirect", label: "开放重定向", hot: [] },
      { id: "logic_flaw", label: "业务逻辑", hot: ["enterprise"] },
    ],
  },
  {
    title: "主机与后门",
    items: [
      { id: "backdoor_compromised", label: "已控后门", hot: ["edusrc"] },
    ],
  },
];
const VULN_OPTIONS = VULN_GROUPS.flatMap((g) => g.items);
// SRC 口径：审核标准说明（与后端 prompts 的 edusrc / enterprise 两套口径对齐）
const SRC_OPTIONS = [
  {
    id: "edusrc",
    title: "EduSRC",
    sub: "教育行业",
    desc: "面向高校 / 教育机构资产，按教育行业 SRC 审核标准",
    focus: "统一认证、教务、学工、OA、图书馆等教育业务系统",
    accepts: "SQL 注入、命令执行、未授权访问、水平越权、文件上传、敏感信息泄露（身份证 / 人脸 / 密码哈希）、弱口令、已控后门",
    rejects: "纯开放重定向、无危害的 XSS、仅公开展示数据、无实证的猜测",
  },
  {
    id: "enterprise",
    title: "企业 SRC",
    sub: "商业资产",
    desc: "面向企业 / 商业资产，按企业 SRC 审核标准",
    focus: "OA、CRM、ERP、API、运维后台等商业系统",
    accepts: "SQL 注入、命令执行、未授权访问、越权、文件上传、敏感信息泄露、弱口令、已控后门",
    rejects: "纯开放重定向、无危害的 XSS、仅公开展示数据、无实证的猜测",
  },
];
const srcOption = computed(() => SRC_OPTIONS.find((s) => s.id === form.src_type) || SRC_OPTIONS[0]);
const SOURCE_OPTIONS = [
  { id: "fofa", title: "自动测绘", desc: "用引擎按语法或意图拉一批站", icon: "🛰", tag: "广撒网", scene: "没有具体目标时，按域名/标题/组织批量捞资产" },
  { id: "manual", title: "手动清单", desc: "自己贴域名 / URL，清理后入队", icon: "📋", tag: "精准", scene: "手里已有目标清单，直接粘贴开打，支持实时解析预览" },
  { id: "both", title: "测绘 + 手动", desc: "搜到的和你贴的一起打", icon: "🔀", tag: "组合", scene: "既有清单又想补一批测绘资产，两条腿走路" },
  { id: "site", title: "单站深挖", desc: "少数 URL 协作，可带登录凭据", icon: "🎯", tag: "深挖", scene: "重点打一两个站，可挂 Cookie/账密做深度测试" },
];
const ENGINE_OPTIONS = [
  { id: "", label: "系统默认", desc: "跟随「设置 → 资产测绘」里的默认引擎" },
  { id: "fofa", label: "FOFA", desc: "国内资产测绘，field=\"value\" 语法，教育资产覆盖好" },
  { id: "quake", label: "Quake", desc: "360 出品，field:value 语法，AND / OR 连接" },
  { id: "hunter", label: "Hunter", desc: "奇安信鹰图，web.title / domain.suffix 字段" },
  { id: "zoomeye", label: "ZoomEye", desc: "知道创宇，v2 语法接近 FOFA" },
  { id: "shodan", label: "Shodan", desc: "全球资产，filter:value 语法，空格连接" },
  { id: "censys", label: "Censys", desc: "CenQL，host./web./cert. 前缀字段" },
];
// 常用查询语法模板：按引擎 + 口径过滤，点击一键填入查询框；group 用于分组展示
const QUERY_TEMPLATES = {
  fofa: [
    { label: "统一认证", query: 'title="统一身份认证" && domain=".edu.cn"', src: "edusrc", group: "登录认证" },
    { label: "教务系统", query: 'title="教务" && domain=".edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "OA 系统", query: 'title="OA" && domain=".edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "教育 IP 段", query: 'org="中国教育和科研计算机网"', src: "edusrc", group: "资产测绘" },
    { label: "企业 OA/ERP", query: 'title="OA" || title="ERP"', src: "enterprise", group: "企业系统" },
    { label: "企业登录页", query: 'title="登录" && status_code="200"', src: "enterprise", group: "企业系统" },
  ],
  quake: [
    { label: "统一认证", query: 'title:"统一身份认证" AND domain:"edu.cn"', src: "edusrc", group: "登录认证" },
    { label: "教务系统", query: 'title:"教务" AND domain:"edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "OA 系统", query: 'title:"OA" AND domain:"edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "教育 IP 段", query: 'org:"中国教育和科研计算机网"', src: "edusrc", group: "资产测绘" },
    { label: "企业 OA", query: 'title:"OA"', src: "enterprise", group: "企业系统" },
  ],
  hunter: [
    { label: "统一认证", query: 'web.title="统一身份认证" && domain.suffix="edu.cn"', src: "edusrc", group: "登录认证" },
    { label: "教务系统", query: 'web.title="教务" && domain.suffix="edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "OA 系统", query: 'web.title="OA" && domain.suffix="edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "教育 IP 段", query: 'ip.isp="中国教育网"', src: "edusrc", group: "资产测绘" },
    { label: "企业 OA", query: 'web.title="OA"', src: "enterprise", group: "企业系统" },
  ],
  zoomeye: [
    { label: "统一认证", query: 'title="统一身份认证" && domain="edu.cn"', src: "edusrc", group: "登录认证" },
    { label: "教务系统", query: 'title="教务" && domain="edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "OA 系统", query: 'title="OA" && domain="edu.cn"', src: "edusrc", group: "教务OA" },
    { label: "企业 OA", query: 'title="OA"', src: "enterprise", group: "企业系统" },
  ],
  shodan: [
    { label: "登录页", query: 'http.title:"login" hostname:edu.cn', src: "edusrc", group: "登录认证" },
    { label: "教育 IP 段", query: 'org:"China Education and Research Network"', src: "edusrc", group: "资产测绘" },
    { label: "企业 OA", query: 'http.title:"OA"', src: "enterprise", group: "企业系统" },
  ],
  censys: [
    { label: "登录页", query: 'host.services.http.response.html_title:"Login" and host.dns.names: edu.cn', src: "edusrc", group: "登录认证" },
    { label: "教育 IP 段", query: 'host.autonomous_system.organization:"China Education and Research Network"', src: "edusrc", group: "资产测绘" },
    { label: "企业 OA", query: 'host.services.http.response.html_title:"OA"', src: "enterprise", group: "企业系统" },
  ],
};

const STEPS = [
  { n: 1, title: "任务定义", sub: "名称 · 口径 · 漏洞" },
  { n: 2, title: "目标来源", sub: "从哪来 · 怎么搜" },
  { n: 3, title: "规则与运行", sub: "红线 · 模型 · 并发" },
];

// 常用额外规则快捷模板：按类别分组（重点收 / 不收 / 禁止操作），点击插入/移除到 src_rules（按行追加，去重）
const RULE_PRESET_GROUPS = [
  {
    id: "focus",
    label: "重点收",
    hint: "加大挖掘权重",
    items: [
      { id: "focus_authz", label: "越权与未授权", text: "重点收越权与未授权" },
      { id: "focus_upload", label: "文件上传", text: "重点测文件上传" },
      { id: "focus_logic", label: "逻辑漏洞", text: "重点测逻辑漏洞" },
    ],
  },
  {
    id: "reject",
    label: "不收",
    hint: "审核过滤",
    items: [
      { id: "no_weak_pwd", label: "弱口令", text: "不收弱口令" },
      { id: "no_default_pwd", label: "默认口令", text: "不收默认口令" },
      { id: "no_info_leak", label: "信息泄露", text: "不收信息泄露/低危" },
      { id: "no_cors", label: "CORS/点击劫持", text: "不收CORS与点击劫持" },
      { id: "no_sms", label: "短信轰炸", text: "不收短信轰炸" },
    ],
  },
];
const RULE_PRESETS = RULE_PRESET_GROUPS.flatMap((g) => g.items);
const ruleCharCount = computed(() => String(form.src_rules || "").length);
function rulePresetActive(p) {
  return String(form.src_rules || "").split("\n").map((s) => s.trim()).includes(p.text);
}
function toggleRulePreset(p) {
  const lines = String(form.src_rules || "").split("\n").map((s) => s.trim()).filter(Boolean);
  const idx = lines.indexOf(p.text);
  if (idx >= 0) lines.splice(idx, 1);
  else lines.push(p.text);
  form.src_rules = lines.join("\n");
}
// —— 禁止操作硬约束实时预览（防抖调 /parse-forbidden-ops，不落库）——
const forbiddenPreview = ref(null);
const forbiddenLoading = ref(false);
const forbiddenError = ref("");
// 八大类拦截勾选区：id + label，来自 parse-forbidden-ops 的 all 字段
const guardCats = ref([]);
const guardCatsLoaded = ref(false);
let forbiddenTimer = null;
let forbiddenSeq = 0;
async function loadGuardCats() {
  if (guardCatsLoaded.value) return;
  try {
    const res = await api.parseForbiddenOps("");
    if (Array.isArray(res?.all) && res.all.length) {
      guardCats.value = res.all;
      guardCatsLoaded.value = true;
    }
  } catch { /* 拉取失败静默，勾选区隐藏 */ }
}
function toggleGuardOp(id) {
  const list = form.guard_ops || [];
  form.guard_ops = list.includes(id) ? list.filter((x) => x !== id) : [...list, id];
}
async function runForbiddenPreview() {
  const text = form.src_rules;
  if (!text.trim()) { forbiddenPreview.value = null; forbiddenError.value = ""; return; }
  const seq = ++forbiddenSeq;
  forbiddenLoading.value = true;
  try {
    const res = await api.parseForbiddenOps(text);
    if (seq !== forbiddenSeq) return;   // 过期响应丢弃
    forbiddenPreview.value = res;
    if (Array.isArray(res?.all) && res.all.length) guardCats.value = res.all;
    forbiddenError.value = "";
  } catch (e) {
    if (seq !== forbiddenSeq) return;
    forbiddenError.value = String(e.message || e);
  } finally {
    if (seq === forbiddenSeq) forbiddenLoading.value = false;
  }
}
watch(() => form.src_rules, () => {
  clearTimeout(forbiddenTimer);
  forbiddenTimer = setTimeout(runForbiddenPreview, 350);
});

// 模型方案三模式说明（布局与信息密度：选中模式下方显示一句话解释）
const MODEL_MODES = {
  inherit: { title: "跟随系统", desc: "用设置页配置的全局模型，任务不单独指定，改动最省心" },
  single: { title: "单端点", desc: "本任务用一个独立 LLM 端点，可测试连接与工具调用能力" },
  pool: { title: "端点池", desc: "多端点轮询/容灾，适合大批量并发，端点可配权重与温度" },
};
const modelModeDesc = computed(() => MODEL_MODES[form.model_mode]?.desc || "");
// 单端点测试连接（复用 /settings/test-llm，只测不落库、不碰生产熔断器）
const singleTest = ref(null);
async function testSingleModel() {
  singleTest.value = { loading: true, ok: false, latency_ms: 0, tool_calling: "", error: "" };
  try {
    const res = await api.testLLM({
      base_url: form.base_url,
      api_key: form.api_key.trim(),
      key_ref: form.key_ref,
      model: form.model,
      protocol: form.protocol,
      temperature: form.temperature,
      task_id: modal.editTaskId || undefined,
    });
    const r = res?.results?.[0];
    singleTest.value = {
      loading: false,
      ok: !!r?.ok,
      latency_ms: r?.latency_ms || 0,
      tool_calling: r?.tool_calling || "",
      error: r?.error || res?.error || "",
      available_models: r?.available_models || [],
    };
  } catch (e) {
    singleTest.value = { loading: false, ok: false, latency_ms: 0, tool_calling: "", error: String(e.message || e).replace(/^\d+\s*/, "") };
  }
}

// —— 模型商连接向导（单端点模式）：① 选模型商 → ② 填 Key 并测试 → ③ 选模型 ——
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
  const sameEndpoint = !!(p.base_url && form.base_url && p.base_url === form.base_url);
  form.base_url = p.base_url || "";
  form.protocol = p.protocol || "auto";
  if (p.recommended) form.model = p.recommended;
  if (!sameEndpoint) invalidateModelKey();
  wizardStep.value = 1;
}
watch(
  () => form.model_mode,
  (mode) => {
    if (mode === "single") {
      loadProviderPresets();
      // 已配置好（有端点且有 key）→ 直接到选模型步骤，方便直接换模型名
      wizardStep.value = form.base_url && (form.api_key.trim() || form.key_ref) ? 2 : 0;
    }
  },
  { immediate: true },
);
// 编辑任务加载完成后（base_url 从后端带回）已配置好 → 直接到选模型步骤，避免每次重填 key
watch(
  () => form.base_url,
  () => {
    if (wizardStep.value === 0 && form.base_url && (form.api_key.trim() || form.key_ref)) {
      wizardStep.value = 2;
    }
  },
);
const selectedPresetName = computed(() => {
  const p = providerPresets.value.find((x) => x.id === selectedPresetId.value);
  return p?.name || "自定义";
});

// —— 单端点多模型灾备：主模型之外可多选同供应商模型，主模型不可用时自动顶替 ——
const backupDraft = ref("");
const backupDraftText = ref("");
const backupCandidates = computed(() => {
  const list = (singleModels.value || []).filter(Boolean);
  const taken = new Set([form.model, ...(form.models || [])].filter(Boolean));
  return list.filter((m) => !taken.has(m));
});
function addBackupModel(name) {
  const v = String(name || "").trim();
  if (!v || v === form.model) return;
  if (form.models.includes(v)) return;
  form.models = [...form.models, v];
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
  const list = [...form.models];
  list.splice(idx, 1);
  form.models = list;
}
watch(
  () => form.model,
  (m) => {
    if (m && form.models.includes(m)) {
      form.models = form.models.filter((x) => x !== m);
    }
  },
);

const isSiteMode = computed(() => form.target_source === "site");
const isFofaMode = computed(() => form.target_source === "fofa");
// 使用搜索引擎的来源（自动测绘 / 测绘+手动）才需要引擎与查询条件
const isSearchMode = computed(() => form.target_source === "fofa" || form.target_source === "both");
const engineIsFofa = computed(() => !form.engine || form.engine === "fofa");
const engineLabel = computed(() => {
  const map = { fofa: "FOFA", quake: "360 Quake", hunter: "Hunter", zoomeye: "ZoomEye", shodan: "Shodan", censys: "Censys" };
  return map[form.engine] || (form.engine ? form.engine : "系统默认引擎");
});
const vulnSelected = computed(() => new Set(form.vuln_types.split(",").map((s) => s.trim()).filter(Boolean)));
function hasVuln(id) { return vulnSelected.value.has(id); }
function toggleVuln(id) {
  vulnCustomized.value = true;
  const known = VULN_OPTIONS.map((o) => o.id);
  const next = new Set(vulnSelected.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  const ordered = known.filter((k) => next.has(k));
  const extra = [...next].filter((k) => !known.includes(k));
  form.vuln_types = [...ordered, ...extra].join(",");
}
// —— 口径联动：推荐漏洞集 + 徽标 + 切换自动应用 ——
const vulnCustomized = ref(false);   // 用户手动改过漏洞类型后，切换口径不再覆盖
let srcApplySuppressed = false;      // 草稿恢复 / 重置时抑制自动应用
const recommendedVulnIds = computed(() => {
  const set = new Set();
  for (const g of VULN_GROUPS) for (const o of g.items) {
    if (o.hot && o.hot.includes(form.src_type)) set.add(o.id);
  }
  return set;
});
const recommendedVulnList = computed(() =>
  VULN_OPTIONS.filter((o) => recommendedVulnIds.value.has(o.id)).map((o) => o.label)
);
const vulnGroupsForSrc = computed(() =>
  VULN_GROUPS.map((g) => ({
    ...g,
    items: [...g.items].sort((a, b) => (recommendedVulnIds.value.has(a.id) ? 0 : 1) - (recommendedVulnIds.value.has(b.id) ? 0 : 1)),
  }))
);
function isHot(id) { return recommendedVulnIds.value.has(id); }
function applyRecommendedVulns() {
  form.vuln_types = VULN_OPTIONS.filter((o) => recommendedVulnIds.value.has(o.id)).map((o) => o.id).join(",");
}
watch(() => form.src_type, () => {
  if (srcApplySuppressed) return;
  if (!vulnCustomized.value) applyRecommendedVulns();
});
const manualCount = computed(() =>
  form.manual_targets.split("\n").map((s) => s.trim()).filter(Boolean).length
);
// —— 目标清单实时解析预览（防抖调 /parse-targets，不落库）——
const preview = ref(null);
const previewLoading = ref(false);
const previewError = ref("");
let previewTimer = null;
let previewSeq = 0;
async function runPreview() {
  if (isFofaMode.value) { preview.value = null; previewError.value = ""; return; }
  const text = form.manual_targets;
  if (!text.trim()) { preview.value = null; previewError.value = ""; return; }
  const seq = ++previewSeq;
  previewLoading.value = true;
  try {
    const res = await api.parseTargets(text);
    if (seq !== previewSeq) return;   // 过期响应丢弃
    preview.value = res;
    previewError.value = "";
  } catch (e) {
    if (seq !== previewSeq) return;
    previewError.value = String(e.message || e);
  } finally {
    if (seq === previewSeq) previewLoading.value = false;
  }
}
// 校验用有效目标数：预览就绪时用真实解析数，否则退回行数
const effectiveManualCount = computed(() => {
  if (preview.value && !previewLoading.value) return preview.value.valid;
  return manualCount.value;
});
watch(() => form.manual_targets, () => {
  clearTimeout(previewTimer);
  previewTimer = setTimeout(runPreview, 350);
});
watch(isFofaMode, (v) => { if (v) { preview.value = null; previewError.value = ""; } });
// —— 手动清单增强：剪贴板粘贴 / 文件导入 ——
const fileInput = ref(null);
function appendManualText(text) {
  const t = (text || "").trim();
  if (!t) return;
  form.manual_targets = form.manual_targets.trimEnd() ? form.manual_targets.trimEnd() + "\n" + t : t;
}
async function pasteFromClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (!text.trim()) { previewError.value = "剪贴板是空的"; return; }
    appendManualText(text);
  } catch {
    previewError.value = "无法读取剪贴板，请手动粘贴";
  }
}
function importTargetFile(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => appendManualText(String(reader.result || ""));
  reader.readAsText(file);
  e.target.value = "";
}
function selectAllVulns() {
  vulnCustomized.value = true;
  form.vuln_types = VULN_OPTIONS.map((o) => o.id).join(",");
}
function clearVulns() {
  vulnCustomized.value = true;
  form.vuln_types = "";
}
const recapSource = computed(() => SOURCE_OPTIONS.find((s) => s.id === form.target_source)?.title || "未选");
const recapModel = computed(() => {
  if (form.model_mode === "pool") return "任务端点池";
  if (form.model_mode === "single") return form.model || "单端点";
  return inherited.llm_mode === "pool" ? `跟随系统 · ${inherited.llm_provider_count} 端点` : "跟随系统";
});
const recapLine = computed(() => {
  const bits = [
    form.src_type === "enterprise" ? "企业 SRC" : "EduSRC",
    recapSource.value,
    isSearchMode.value ? engineLabel.value : null,
    `${vulnSelected.value.size} 类漏洞`,
  ].filter(Boolean);
  if (!isFofaMode.value && effectiveManualCount.value) bits.push(`${effectiveManualCount.value} 个有效目标`);
  return bits.join(" · ");
});
const missingHint = computed(() => {
  if (!form.name.trim()) return "还差任务名称";
  if (form.model_mode === "single" && !form.api_key.trim() && !form.key_ref) return "单端点还缺 API Key";
  if ((form.target_source === "manual" || form.target_source === "site") && !effectiveManualCount.value) return "还没贴有效目标清单";
  if ((form.target_source === "fofa" || form.target_source === "both") && !form.fofa_query.trim()) return "还没写搜集条件";
  if (!vulnSelected.value.size) return "至少选一类漏洞";
  return "";
});
// 各步骤的完成度提示（用于步骤指示器打勾）
const step1Done = computed(() => !!form.name.trim() && vulnSelected.value.size > 0);
const step2Done = computed(() => {
  if (form.target_source === "manual" || form.target_source === "site") return effectiveManualCount.value > 0;
  if (form.target_source === "fofa" || form.target_source === "both") return !!form.fofa_query.trim();
  return true;
});
const step3Done = computed(() => {
  if (form.model_mode === "single" && !form.api_key.trim() && !form.key_ref) return false;
  if (form.model_mode === "pool") {
    const rows = poolEditor.value?.exportProviders?.() || taskProviders.value;
    return rows.length > 0 && !rows.some((p) => !p.base_url || !p.model || (!p.api_key && !p.key_ref));
  }
  return true;
});
const stepDone = computed(() => [step1Done.value, step2Done.value, step3Done.value]);

const engineKey = computed(() => form.engine || "fofa");
const queryPlaceholder = computed(() => {
  if (form.intent_mode === "intent") {
    return form.src_type === "enterprise"
      ? "例：找某集团 OA/CRM/ERP/API/运维后台资产"
      : "例：找全国高校的统一身份认证登录系统";
  }
  const samples = {
    fofa: form.src_type === "enterprise"
      ? 'domain="example.com" || cert="示例集团" || org="示例集团"'
      : 'title="统一身份认证" && domain=".edu.cn"',
    quake: 'title:"统一身份认证" AND domain:"edu.cn"',
    hunter: 'ip.isp="中国教育网"&&header.status_code="200"',
    zoomeye: 'title="统一身份认证" && country="CN"',
    shodan: 'http.title:"login" hostname:edu.cn',
    censys: 'host.services.http.response.html_title:"Login" and host.dns.names: edu.cn',
  };
  return samples[engineKey.value] || samples.fofa;
});
const queryHintSample = computed(() => {
  const samples = {
    fofa: 'title="统一身份认证" && domain=".edu.cn"',
    quake: 'title:"登录" AND domain:"edu.cn"',
    hunter: 'ip.isp="中国教育网"&&header.status_code="200"',
    zoomeye: 'title="login" && country="CN"',
    shodan: 'http.title:"nginx" port:443',
    censys: 'host.dns.names: edu.cn',
  };
  return samples[engineKey.value] || samples.fofa;
});
const currentEngine = computed(() => ENGINE_OPTIONS.find((e) => e.id === form.engine) || ENGINE_OPTIONS[0]);
const queryTemplates = computed(() => {
  const list = QUERY_TEMPLATES[engineKey.value] || QUERY_TEMPLATES.fofa;
  const filtered = list.filter((t) => !t.src || t.src === form.src_type);
  const groups = {};
  for (const t of filtered) (groups[t.group || "其他"] ||= []).push(t);
  return groups;
});
const appliedTemplate = ref("");
function applyQueryTemplate(tpl) {
  form.fofa_query = tpl.query;
  appliedTemplate.value = tpl.label;
  if (form.intent_mode === "intent") form.intent_mode = "syntax";
}
// 字段速查：点击把当前引擎的字段模板追加到查询框（等号 / 冒号风格跟随引擎）
const ENGINE_JOIN = { fofa: " && ", hunter: " && ", zoomeye: " && ", quake: " AND ", shodan: " ", censys: " and " };
function insertField(f) {
  const eng = engineKey.value;
  const joiner = eng === "quake" || eng === "shodan" || eng === "censys" ? ":" : "=";
  const piece = `${f.field}${joiner}""`;
  const cur = form.fofa_query.trim();
  form.fofa_query = cur ? cur + (ENGINE_JOIN[eng] || " && ") + piece : piece;
}
// —— 查询条件实时解析预览（防抖调 /parse-query，不落库）——
const queryPreview = ref(null);
const queryPreviewLoading = ref(false);
const queryPreviewError = ref("");
let queryTimer = null;
let querySeq = 0;
async function runQueryPreview() {
  if (isSiteMode.value) { queryPreview.value = null; queryPreviewError.value = ""; return; }
  const q = form.fofa_query;
  const seq = ++querySeq;
  queryPreviewLoading.value = true;
  try {
    const res = await api.parseQuery({ engine: engineKey.value, query: q, src_type: form.src_type, intent_mode: form.intent_mode });
    if (seq !== querySeq) return;   // 过期响应丢弃
    queryPreview.value = res;
    queryPreviewError.value = "";
  } catch (e) {
    if (seq !== querySeq) return;
    queryPreviewError.value = String(e.message || e);
  } finally {
    if (seq === querySeq) queryPreviewLoading.value = false;
  }
}
// 语法模式常驻拉一次字段速查（空查询也返回 field_sheet）
watch([engineKey, () => form.src_type], () => {
  if (form.intent_mode !== "intent" && !isSiteMode.value) runQueryPreview();
});
watch([() => form.fofa_query, engineKey, () => form.intent_mode, () => form.src_type], () => {
  clearTimeout(queryTimer);
  queryTimer = setTimeout(runQueryPreview, 350);
});
const CAT_LABELS = { domain: "域名", title: "标题", org: "组织", ip: "IP", port: "端口", app: "应用", cert: "证书/图标", text: "文本" };
function catLabel(cat) { return CAT_LABELS[cat] || cat; }

const manualTargetsPlaceholder = computed(() =>
  isSiteMode.value
    ? "https://target.example.com/\nhttps://target.example.com/admin 后台"
    : "www.example.edu.cn\nhttps://a.example.edu.cn/path?x=1\nhttps://b.example.edu.cn/ 港澳台\n(203.0.113.10)"
);
// 凭据区只对「用户自己指定目标」有意义：手动 / 两者 / 单站。纯 FOFA 自动搜不展示。
const showAuthBindings = computed(() => !isFofaMode.value);

// —— 登录凭据批量导入 ——
const importOpen = ref(false);
const authImportText = ref("");
const authPreview = ref(null);
const authImportLoading = ref(false);
const authImportError = ref("");
const authImportNotice = ref("");
const authFileInput = ref(null);
let authImportTimer = null;
let authImportSeq = 0;
const credCount = computed(() => exportAuthBindings().length);

function toggleImportPanel() {
  importOpen.value = !importOpen.value;
  if (importOpen.value) runAuthImportPreview();
}
function closeAuthImport() {
  importOpen.value = false;
  authImportText.value = "";
  authPreview.value = null;
  authImportError.value = "";
}
async function runAuthImportPreview() {
  const text = authImportText.value;
  if (!text.trim()) { authPreview.value = null; authImportError.value = ""; return; }
  const seq = ++authImportSeq;
  authImportLoading.value = true;
  try {
    const res = await api.parseAuthBatch(text);
    if (seq !== authImportSeq) return;   // 过期响应丢弃
    authPreview.value = res;
    authImportError.value = "";
  } catch (e) {
    if (seq !== authImportSeq) return;
    authImportError.value = String(e.message || e);
  } finally {
    if (seq === authImportSeq) authImportLoading.value = false;
  }
}
watch(authImportText, () => {
  clearTimeout(authImportTimer);
  authImportTimer = setTimeout(runAuthImportPreview, 350);
});
function applyAuthImport() {
  if (!authPreview.value || !authPreview.value.parsed) return;
  const { added, targetsAdded } = importBindings(authPreview.value.bindings);
  closeAuthImport();
  if (!added && !targetsAdded) {
    authImportNotice.value = "没有新凭据（已全部存在）";
  } else {
    const bits = [];
    if (added) bits.push(`已导入 ${added} 条凭据`);
    if (targetsAdded) bits.push(`已补 ${targetsAdded} 个目标到清单`);
    authImportNotice.value = bits.join("，");
  }
  setTimeout(() => { authImportNotice.value = ""; }, 3500);
}
async function pasteAuthClipboard() {
  try {
    const text = await navigator.clipboard.readText();
    if (!text.trim()) { authImportError.value = "剪贴板是空的"; return; }
    authImportText.value = authImportText.value.trimEnd() ? authImportText.value.trimEnd() + "\n" + text : text;
  } catch {
    authImportError.value = "无法读取剪贴板，请手动粘贴";
  }
}
function importAuthFile(e) {
  const file = e.target.files?.[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const t = String(reader.result || "");
    authImportText.value = authImportText.value.trimEnd() ? authImportText.value.trimEnd() + "\n" + t : t;
  };
  reader.readAsText(file);
  e.target.value = "";
}

function invalidateModelKey() {
  form.key_ref = "";
  singleModels.value = [];
  singleModelsError.value = "";
}

async function loadSingleModels() {
  singleModelsLoading.value = true;
  singleModelsError.value = "";
  try {
    // 编辑已有任务时走任务级模型接口，能解析任务自带的 API Key；
    // 新建任务走全局接口，用全局/表单里填的 Key。
    const payload = {
      base_url: form.base_url,
      api_key: form.api_key.trim(),
      key_ref: form.key_ref,
      model: form.model,
      protocol: form.protocol,
    };
    const res = modal.editTaskId
      ? await api.taskModels(modal.editTaskId, payload)
      : await api.listModels(payload);
    if (res?.ok && res.models?.length) {
      singleModels.value = res.models;
      if (!form.model || !singleModels.value.includes(form.model)) form.model = singleModels.value[0];
    } else {
      singleModels.value = [];
      singleModelsError.value = res?.error || "未获取到模型列表";
    }
  } catch (e) {
    singleModels.value = [];
    singleModelsError.value = String(e.message || e).replace(/^\d+\s*/, "");
  } finally {
    singleModelsLoading.value = false;
  }
}

function ensurePoolSeed() {
  if (taskProviders.value.length) return;
  taskProviders.value = [{
    name: "llm-1",
    base_url: form.base_url || inherited.base_url || "https://api.deepseek.com/v1",
    api_key: "",
    api_key_set: false,
    api_key_masked: "",
    key_ref: "",
    model: form.model || inherited.model || "deepseek-chat",
    protocol: form.protocol || inherited.protocol || "auto",
    temperature: 0.3,
    weight: 1,
    enabled: true,
    models: [],
    modelsLoading: false,
    modelsError: "",
  }];
}

watch(() => form.model_mode, (mode) => {
  if (mode === "pool") ensurePoolSeed();
});

// 粗略识别用户是否在方向说明或凭据区给了登录凭据。
const looksHasCreds = computed(() => {
  const t = (form.fofa_query || "");
  if (/(账号|帐号|账户|用户名|user(name)?|密码|pass(word|wd)?|cookie|token|authorization|bearer|jsessionid|session|登录态|凭据|凭证)/i.test(t)) {
    return true;
  }
  return exportAuthBindings().length > 0;
});
watch([() => form.fofa_query, isSiteMode, authBindings], () => {
  if (isSiteMode.value && !form.skip_recon_touched) {
    form.skip_site_recon = looksHasCreds.value;
  }
});

function onKeydown(e) {
  if (e.key === "Escape" && modal.open) closeCreateTask();
}

async function initForm() {
  try {
    const s = await api.getSettings();
    if (!form.base_url) form.base_url = s.llm?.base_url || "";
    if (!form.model) form.model = s.llm?.model || "";
    form.protocol = s.llm?.protocol || form.protocol;
    form.key_ref = s.llm?.key_ref || "";
    form.prompt_version = s.defaults?.worker_prompt_version || form.prompt_version;
    form.max_pages = s.fofa?.max_pages ?? form.max_pages;
    if (!form.intent_mode) form.intent_mode = s.fofa?.default_intent_mode || "";
    if (!form.fofa_base_url) form.fofa_base_url = s.fofa?.base_url || "";
    form.concurrency = s.defaults?.concurrency ?? form.concurrency;
    form.deepen_cap = s.defaults?.deepen_cap ?? form.deepen_cap;
    inherited.base_url = form.base_url;
    inherited.model = form.model;
    inherited.models = Array.isArray(s.llm?.models) ? s.llm.models.filter((m) => m && m !== inherited.model) : [];
    inherited.protocol = form.protocol;
    inherited.llm_provider_count = s.llm?.provider_count || 0;
    inherited.llm_mode = s.llm?.mode || "single";
    inherited.prompt_version = form.prompt_version;
    inherited.fofa_base_url = form.fofa_base_url;
    inherited.max_pages = Number(form.max_pages);
    inherited.intent_mode = form.intent_mode;
    inherited.concurrency = Number(form.concurrency);
    inherited.deepen_cap = Number(form.deepen_cap);
    // 引擎配置状态：{ fofa: true/false, quake: ... }，用于引擎选项旁的点
    const eng = {};
    for (const [name, cfg] of Object.entries(s.engines || {})) eng[name] = !!cfg?.key_set;
    engineStatus.value = eng;
  } catch {}
}

async function resetForm() {
  step.value = 1;
  stepError.value = "";
  invalidField.value = "";
  draftRestored.value = false;
  vulnCustomized.value = false;
  srcApplySuppressed = true;
  Object.assign(form, {
    name: "",
    src_type: "edusrc",
    vuln_types: DEFAULT_VULN_TYPES,
    target_source: "fofa",
    engine: "",
    fofa_query: "",
    intent_mode: "",
    manual_targets: "",
    src_rules: "",
    guard_ops: [],
    model_mode: "inherit",
    base_url: "", api_key: "", key_ref: "", model: "", protocol: "auto", temperature: 0.3, prompt_version: "legacy",
    fofa_key: "", fofa_base_url: "", max_pages: 20, page_size: 100, concurrency: 3, deepen_cap: 2,
    skip_site_recon: false,
    skip_recon_touched: false,
  });
  srcApplySuppressed = false;
  taskProviders.value = [];
  await initForm();
}

// —— 编辑模式：预填任务数据 ——
function loadAuthBindings(task) {
  const rows = Array.isArray(task?.auth_bindings) ? task.auth_bindings : [];
  if (!rows.length) {
    authBindings.value = [emptyBinding()];
    return;
  }
  authBindings.value = rows.map((b) => ({
    target: b.target || "*",
    raw: b.raw || "",
    username: b.username || "",
    password: b.password || "",
    cookie: b.cookie || "",
    authorization: b.authorization || "",
    login_url: b.login_url || "",
    note: b.note || "",
  }));
}

function fill(task) {
  if (!task) return;
  const modelCfg = task.model_config_data || {};
  const fofaCfg = task.fofa_config || {};
  srcApplySuppressed = true;
  form.name = task.name || "";
  form.src_type = task.src_type || "edusrc";
  form.vuln_types = (task.vuln_types || []).join(",");
  form.target_source = task.target_source || "fofa";
  form.engine = task.engine || "";
  form.fofa_query = task.fofa_query || "";
  form.intent_mode = fofaCfg.intent_mode || "";
  form.manual_targets = (task.manual_targets || []).join("\n");
  form.src_rules = task.src_rules || "";
  form.guard_ops = Array.isArray(task.guard_ops) ? task.guard_ops.filter((g) => g) : [];
  form.base_url = modelCfg.base_url || "";
  form.api_key = "";
  form.key_ref = modelCfg.key_ref || "";
  form.model = modelCfg.model || "";
  form.models = Array.isArray(modelCfg.models) ? modelCfg.models.filter((m) => m && m !== form.model) : [];
  form.protocol = modelCfg.protocol || "auto";
  form.temperature = modelCfg.temperature ?? 0.3;
  form.prompt_version = modelCfg.prompt_version || "legacy";
  form.fofa_key = "";
  form.fofa_base_url = fofaCfg.base_url || "";
  form.max_pages = fofaCfg.max_pages ?? 20;
  form.page_size = fofaCfg.page_size ?? 100;
  form.skip_site_recon = !!fofaCfg.skip_site_recon;
  form.skip_recon_touched = true;   // 编辑已有配置，不再自动跟随凭据
  form.concurrency = task.concurrency || 3;
  form.deepen_cap = task.deepen_cap ?? 2;
  vulnCustomized.value = true;      // 保留任务原有漏洞选择，切换口径不覆盖
  loadAuthBindings(task);
  srcApplySuppressed = false;

  const providers = Array.isArray(modelCfg.providers) ? modelCfg.providers : [];
  taskProviders.value = providers.map((p, idx) => ({
    name: p.name || `llm-${idx + 1}`,
    base_url: p.base_url || "",
    api_key: "",
    api_key_set: !!p.api_key_set,
    api_key_masked: p.api_key_masked || "",
    key_ref: p.key_ref || "",
    model: p.model || "",
    protocol: p.protocol || "auto",
    temperature: p.temperature ?? 0.3,
    weight: p.weight ?? 1,
    enabled: p.enabled !== false,
    models: [],
    modelsLoading: false,
    modelsError: "",
  }));

  if (modelCfg.inherit_global !== false && !providers.length) {
    form.model_mode = "inherit";
  } else if (providers.length || modelCfg.mode === "pool") {
    form.model_mode = "pool";
  } else {
    form.model_mode = "single";
  }

  original.base_url = form.base_url;
  original.model = form.model;
  original.protocol = form.protocol;
  original.prompt_version = form.prompt_version;
  original.intent_mode = form.intent_mode;
  original.fofa_base_url = form.fofa_base_url;
  original.max_pages = Number(form.max_pages);
  original.page_size = Number(form.page_size);
  singleModels.value = [];
  singleModelsError.value = "";
}

async function loadEditTask(id) {
  editLoading.value = true;
  editError.value = "";
  try {
    await initForm();   // 先加载引擎状态点等系统信息
    const task = await api.getTask(id);
    fill(task);
    editTask.value = task;
  } catch (e) {
    editError.value = `加载任务失败：${e?.message || e}`;
    closeCreateTask();
  } finally {
    editLoading.value = false;
  }
}

// —— 草稿自动保存 / 恢复（不落盘 API Key 等敏感字段）——
function hasDraftContent() {
  return !!(form.name.trim() || form.fofa_query.trim() || form.manual_targets.trim() || form.src_rules.trim());
}
function saveDraft() {
  const d = {
    name: form.name,
    src_type: form.src_type,
    vuln_types: form.vuln_types,
    target_source: form.target_source,
    engine: form.engine,
    fofa_query: form.fofa_query,
    intent_mode: form.intent_mode,
    manual_targets: form.manual_targets,
    src_rules: form.src_rules,
    guard_ops: form.guard_ops || [],
    model_mode: form.model_mode,
    base_url: form.base_url,
    key_ref: form.key_ref,
    model: form.model,
    protocol: form.protocol,
    temperature: form.temperature,
    prompt_version: form.prompt_version,
    fofa_base_url: form.fofa_base_url,
    max_pages: form.max_pages,
    concurrency: form.concurrency,
    deepen_cap: form.deepen_cap,
    skip_site_recon: form.skip_site_recon,
  };
  try { localStorage.setItem(DRAFT_KEY, JSON.stringify(d)); } catch {}
}
function loadDraft() {
  try {
    const raw = localStorage.getItem(DRAFT_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}
function clearDraft() {
  try { localStorage.removeItem(DRAFT_KEY); } catch {}
}
function clearDraftNow() {
  clearDraft();
  resetForm();
}

// —— 分步校验：返回错误文案，同时标记具体字段 ——
function validateStep(n) {
  if (n === 1) {
    if (!form.name.trim()) { invalidField.value = "name"; return "先给任务起个名字"; }
    if (!vulnSelected.value.size) { invalidField.value = "vuln"; return "至少选一类漏洞"; }
  }
  if (n === 2) {
    if ((form.target_source === "manual" || form.target_source === "site") && !effectiveManualCount.value) {
      invalidField.value = "manual"; return "还没贴有效目标清单";
    }
    if ((form.target_source === "fofa" || form.target_source === "both") && !form.fofa_query.trim()) {
      invalidField.value = "query"; return "还没写搜集条件";
    }
  }
  if (n === 3) {
    if (form.model_mode === "single" && !form.api_key.trim() && !form.key_ref) {
      invalidField.value = "api_key"; return "单端点还缺 API Key";
    }
    if (form.model_mode === "pool") {
      const rows = poolEditor.value?.exportProviders?.() || taskProviders.value;
      if (!rows.length) { invalidField.value = "pool"; return "端点池还没有任何端点"; }
      if (rows.some((p) => !p.base_url || !p.model || (!p.api_key && !p.key_ref))) {
        invalidField.value = "pool"; return "端点池每个端点都需要 base_url / 模型 / api_key";
      }
    }
  }
  invalidField.value = "";
  return "";
}

onMounted(async () => {
  window.addEventListener("keydown", onKeydown);
  await initForm();
  loadGuardCats();
  const draft = loadDraft();
  if (draft) {
    srcApplySuppressed = true;
    Object.assign(form, draft);
    srcApplySuppressed = false;
    draftRestored.value = true;
  }
});

onBeforeUnmount(() => {
  window.removeEventListener("keydown", onKeydown);
});

// 表单变化：清掉校验标记 + 防抖存草稿（编辑模式不写草稿）
watch(form, () => {
  invalidField.value = "";
  stepError.value = "";
  clearTimeout(saveTimer);
  if (isEdit.value) return;
  saveTimer = setTimeout(() => {
    if (hasDraftContent()) saveDraft();
    else clearDraft();
  }, 400);
}, { deep: true });

// 切步骤：清错误 + 滚动回顶部
watch(step, () => {
  stepError.value = "";
  bodyRef.value?.scrollTo({ top: 0, behavior: "smooth" });
});

// 每次打开都回到第一步；编辑模式加载任务数据，关闭后清空表单
let wasEdit = false;
watch(() => modal.open, (open) => {
  if (open) {
    step.value = 1;
    stepError.value = "";
    invalidField.value = "";
    if (modal.editTaskId) {
      wasEdit = true;
      loadEditTask(modal.editTaskId);
    }
  } else if (wasEdit) {
    wasEdit = false;
    resetForm();
  }
});

// 分步导航：下一步校验当前步骤
function nextStep() {
  const err = validateStep(step.value);
  if (err) { stepError.value = err; return; }
  stepError.value = "";
  if (step.value < 3) step.value += 1;
}

function prevStep() {
  if (step.value > 1) step.value -= 1;
}

function goStep(n) {
  // 只能回到已完成的步骤或相邻下一步
  if (n < step.value) { step.value = n; return; }
  if (n === step.value + 1) { nextStep(); }
}

async function submit() {
  if (submitting.value) return;   // 防抖：慢网络/双击不重复建任务
  for (let n = 1; n <= 3; n++) {
    const err = validateStep(n);
    if (err) {
      stepError.value = err;
      step.value = n;
      return;
    }
  }
  submitting.value = true;
  try {
  let modelConfig;
  if (form.model_mode === "inherit") {
    modelConfig = { inherit_global: true };
  } else if (form.model_mode === "pool") {
    const rows = poolEditor.value?.exportProviders?.() || taskProviders.value;
    modelConfig = { inherit_global: false, providers: rows };
  } else {
    modelConfig = {
      inherit_global: false,
      base_url: form.base_url,
      model: form.model,
      protocol: form.protocol,
    };
    modelConfig.models = [...form.models];
    if (form.api_key.trim()) modelConfig.api_key = form.api_key.trim();
    if (form.temperature !== undefined && form.temperature !== null && form.temperature !== "") {
      modelConfig.temperature = Math.max(0, Math.min(Number(form.temperature) || 0, 2));
    }
  }
  if (form.prompt_version !== (isEdit.value ? original.prompt_version : inherited.prompt_version)) modelConfig.prompt_version = form.prompt_version;

  const maxPages = parseInt(form.max_pages) || 20;
  const pageSize = parseInt(form.page_size) || 100;
  const fofaConfig = {};
  if (form.fofa_key.trim()) fofaConfig.key = form.fofa_key.trim();
  if (isEdit.value) {
    // 编辑：只提交变更，避免覆盖任务原有配置
    if (form.fofa_base_url && form.fofa_base_url !== original.fofa_base_url) fofaConfig.base_url = form.fofa_base_url;
    if (maxPages !== original.max_pages) fofaConfig.max_pages = maxPages;
    if (pageSize !== original.page_size) fofaConfig.page_size = pageSize;
    if (form.intent_mode !== original.intent_mode) fofaConfig.intent_mode = form.intent_mode;
    if (isSiteMode.value && form.skip_site_recon) fofaConfig.skip_site_recon = true;
  } else {
    if (form.fofa_base_url && form.fofa_base_url !== inherited.fofa_base_url) fofaConfig.base_url = form.fofa_base_url;
    fofaConfig.max_pages = maxPages;  // 始终写入，避免任务配置缺省时掉回硬编码 20
    if (form.intent_mode !== inherited.intent_mode) fofaConfig.intent_mode = form.intent_mode;
    if (isSiteMode.value && form.skip_site_recon) fofaConfig.skip_site_recon = true;
  }

  const body = {
    name: form.name,
    src_type: form.src_type,
    vuln_types: form.vuln_types.split(",").map((s) => s.trim()).filter(Boolean),
    target_source: form.target_source,
    engine: form.engine,
    fofa_query: form.fofa_query,
    manual_targets: form.manual_targets.split("\n").map((s) => s.trim()).filter(Boolean),
    auth_bindings: showAuthBindings.value ? exportAuthBindings() : [],
    src_rules: form.src_rules,
    guard_ops: form.guard_ops || [],
    concurrency: parseInt(form.concurrency) || 3,
    deepen_cap: Math.max(0, Math.min(parseInt(form.deepen_cap) || 0, 10)),
    model_config_data: modelConfig,
    fofa_config: fofaConfig,
  };
  if (isEdit.value) {
    // closeCreateTask 会清空 modal.editTaskId，先存局部变量再跳转，避免跳到 /task/null
    const editId = modal.editTaskId;
    const updated = await api.updateTask(editId, body);
    closeCreateTask();
    resetForm();
    if (router.currentRoute.value.path === `/task/${editId}`) {
      window.dispatchEvent(new CustomEvent("riddle:task-saved", { detail: updated }));
    } else {
      router.push(`/task/${editId}`);
    }
  } else {
    const task = await api.createTask(body);
    clearDraft();
    closeCreateTask();
    resetForm();
    router.push(`/task/${task.id}`);
  }
  } finally {
    submitting.value = false;
  }
}
</script>

<template>
  <Teleport to="body">
    <Transition name="create-modal">
      <div v-if="modal.open" class="create-modal-mask" @mousedown.self="closeCreateTask">
        <div class="create-modal" role="dialog" aria-modal="true" :aria-label="isEdit ? '编辑任务' : '新建任务'">
          <header class="create-modal-head">
            <div class="create-modal-title">
              <h3>{{ isEdit ? "编辑任务" : "新建任务" }}</h3>
              <p>{{ isEdit ? "修改任务参数，保存后下一轮调度生效" : "分步配置，填完直接进指挥台开打" }}</p>
            </div>
            <button class="create-modal-close" type="button" title="关闭" @click="closeCreateTask">×</button>
          </header>

          <!-- 编辑加载遮罩 -->
          <div v-if="editLoading" class="edit-loading-mask">
            <span>正在加载任务参数…</span>
          </div>

          <!-- 步骤指示器 -->
          <nav class="wizard-steps" aria-label="创建步骤">
            <button
              v-for="s in STEPS"
              :key="s.n"
              type="button"
              class="wizard-step"
              :class="{
                on: step === s.n,
                done: s.n < step,
                linked: s.n < step || stepDone[s.n - 1],
                reachable: s.n < step,
              }"
              :disabled="s.n > step && !stepDone[s.n - 1]"
              @click="goStep(s.n)"
            >
              <span class="ws-dot">
                <svg v-if="s.n < step" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12"/></svg>
                <template v-else>{{ s.n }}</template>
              </span>
              <span class="ws-txt">
                <b>{{ s.title }}</b>
                <small>{{ s.sub }}</small>
              </span>
            </button>
          </nav>

          <!-- 草稿恢复提示 -->
          <div v-if="draftRestored && !isEdit" class="draft-bar">
            <span>已恢复上次未完成的草稿</span>
            <button type="button" class="linkish" @click="clearDraftNow">清空草稿</button>
          </div>

          <form class="create-layout form" @submit.prevent="submit">
            <div ref="bodyRef" class="create-modal-body">
              <div class="create-main">
                <!-- 步骤1：任务定义 -->
                <Transition name="step" mode="out-in">
                  <div v-if="step === 1" key="s1" class="wizard-pane">
                    <section class="create-block">
                      <header class="create-block-head">
                        <b>任务名称</b>
                        <small>给自己看，方便日后区分</small>
                      </header>
                      <input v-model="form.name" required class="create-name-input"
                             :class="{ invalid: invalidField === 'name' }"
                             :placeholder="form.src_type === 'enterprise' ? '企业 SRC 批量挖掘' : 'EduSRC 批量挖掘'"
                             @keydown.enter.prevent="nextStep" />
                    </section>

                    <section class="create-block">
                      <header class="create-block-head">
                        <b>SRC 口径</b>
                        <small>决定审核红线，不可放宽</small>
                      </header>
                      <div class="create-seg big" role="radiogroup" aria-label="SRC 口径">
                        <button type="button" role="radio" :aria-checked="form.src_type === 'edusrc'" :class="{ active: form.src_type === 'edusrc' }" @click="form.src_type = 'edusrc'">
                          <b>EduSRC</b><small>教育行业</small>
                        </button>
                        <button type="button" role="radio" :aria-checked="form.src_type === 'enterprise'" :class="{ active: form.src_type === 'enterprise' }" @click="form.src_type = 'enterprise'">
                          <b>企业 SRC</b><small>商业资产</small>
                        </button>
                      </div>
                      <div class="src-info">
                        <p class="src-info-desc">{{ srcOption.desc }}</p>
                        <div class="src-info-grid">
                          <div class="src-info-item">
                            <b>重点资产</b>
                            <span>{{ srcOption.focus }}</span>
                          </div>
                          <div class="src-info-item">
                            <b>通常收</b>
                            <span>{{ srcOption.accepts }}</span>
                          </div>
                          <div class="src-info-item">
                            <b>通常不收</b>
                            <span>{{ srcOption.rejects }}</span>
                          </div>
                        </div>
                      </div>
                    </section>

                    <section class="create-block">
                      <header class="create-block-head">
                        <b>要挖的漏洞</b>
                        <small>已选 {{ vulnSelected.size }} / {{ VULN_OPTIONS.length }} 类</small>
                      </header>
                      <div class="vuln-toolbar">
                        <button type="button" class="linkish" @click="applyRecommendedVulns">应用推荐</button>
                        <button type="button" class="linkish" @click="selectAllVulns">全选</button>
                        <button type="button" class="linkish" @click="clearVulns">清空</button>
                      </div>
                      <div v-for="group in vulnGroupsForSrc" :key="group.title" class="vuln-group">
                        <span class="vuln-group-title">{{ group.title }}</span>
                        <div class="create-chips" role="group" :aria-label="group.title">
                          <button
                            v-for="opt in group.items"
                            :key="opt.id"
                            type="button"
                            :class="{ on: hasVuln(opt.id) }"
                            :aria-pressed="hasVuln(opt.id)"
                            @click="toggleVuln(opt.id)"
                          >{{ opt.label }}<em v-if="isHot(opt.id)" class="vuln-hot">推荐</em></button>
                        </div>
                      </div>
                      <p class="create-mini">
                        {{ srcOption.title }} 推荐 {{ recommendedVulnIds.size }} 类：{{ recommendedVulnList.join("、") }}。切换口径自动应用推荐集，手动改过则保留你的选择。
                      </p>
                    </section>
                  </div>

                  <!-- 步骤2：目标来源 -->
                  <div v-else-if="step === 2" key="s2" class="wizard-pane">
                    <section class="create-block">
                      <header class="create-block-head">
                        <b>目标从哪来</b>
                        <small>这一步决定下面要填什么</small>
                      </header>
                      <div class="create-source" role="radiogroup" aria-label="目标来源">
                        <button
                          v-for="opt in SOURCE_OPTIONS"
                          :key="opt.id"
                          type="button"
                          role="radio"
                          :aria-checked="form.target_source === opt.id"
                          :class="{ on: form.target_source === opt.id }"
                          @click="form.target_source = opt.id"
                        >
                          <span class="cs-icon">{{ opt.icon }}</span>
                          <b><span class="cs-title">{{ opt.title }}</span><em v-if="opt.tag" class="cs-tag">{{ opt.tag }}</em></b>
                          <small>{{ opt.desc }}</small>
                          <span class="cs-scene">{{ opt.scene }}</span>
                        </button>
                      </div>
                    </section>

                    <template v-if="isSearchMode">
                      <section class="create-block">
                        <header class="create-block-head">
                          <b>搜索引擎</b>
                          <small>Key 在「设置 → 资产测绘」</small>
                        </header>
                        <div class="create-chips" role="radiogroup" aria-label="搜索引擎">
                          <button
                            v-for="opt in ENGINE_OPTIONS"
                            :key="opt.id || 'default'"
                            type="button"
                            role="radio"
                            :aria-checked="form.engine === opt.id"
                            :class="{ on: form.engine === opt.id }"
                            :title="opt.id ? (engineStatus[opt.id] ? '已配置 Key' : '未配置 Key，去「设置 → 资产测绘」填写') : '跟随默认引擎'"
                            @click="form.engine = opt.id"
                          >
                            <i
                              v-if="opt.id"
                              class="engine-dot"
                              :class="engineStatus[opt.id] ? 'ok' : 'no'"
                              aria-hidden="true"
                            ></i>
                            {{ opt.label }}
                          </button>
                        </div>
                        <p class="field-hint">{{ currentEngine.desc }}</p>
                      </section>

                      <section class="create-block">
                        <header class="create-block-head">
                          <b>怎么写条件</b>
                          <small>自动判断 / 语法 / 大白话</small>
                        </header>
                        <div class="create-seg" role="radiogroup" aria-label="搜集方式">
                          <button type="button" role="radio" :aria-checked="form.intent_mode === ''" :class="{ active: form.intent_mode === '' }" @click="form.intent_mode = ''">自动判断</button>
                          <button type="button" role="radio" :aria-checked="form.intent_mode === 'syntax'" :class="{ active: form.intent_mode === 'syntax' }" @click="form.intent_mode = 'syntax'">查询语法</button>
                          <button type="button" role="radio" :aria-checked="form.intent_mode === 'intent'" :class="{ active: form.intent_mode === 'intent' }" @click="form.intent_mode = 'intent'">大白话意图</button>
                        </div>
                        <div v-if="form.intent_mode !== 'intent'" class="query-templates">
                          <span class="qt-label">常用模板</span>
                          <template v-for="(tpls, group) in queryTemplates" :key="group">
                            <span class="qt-group">{{ group }}</span>
                            <button v-for="tpl in tpls" :key="tpl.label" type="button" class="qt-chip" :class="{ active: appliedTemplate === tpl.label }" @click="applyQueryTemplate(tpl)">{{ tpl.label }}</button>
                          </template>
                        </div>
                        <label class="create-label">
                          {{ form.intent_mode === "intent" ? "要找什么（大白话）" : "查询语法" }}
                          <textarea v-model="form.fofa_query" rows="4" :class="{ invalid: invalidField === 'query' }" :placeholder="queryPlaceholder"></textarea>
                        </label>
                        <p v-if="form.intent_mode !== 'intent'" class="field-hint">
                          按当前引擎官网语法原样请求。示例 <code>{{ queryHintSample }}</code>
                        </p>
                        <p v-else class="create-mini">搜集 Agent 会把意图翻成语法，并按结果逐轮演化。</p>

                        <!-- 字段速查：点击追加当前引擎字段模板 -->
                        <div v-if="form.intent_mode !== 'intent' && queryPreview && queryPreview.field_sheet.length" class="field-sheet">
                          <span class="fs-label">字段速查</span>
                          <button
                            v-for="f in queryPreview.field_sheet"
                            :key="f.field"
                            type="button"
                            class="fs-chip"
                            :title="f.example"
                            @click="insertField(f)"
                          >{{ f.label }}<em>{{ f.field }}</em></button>
                        </div>

                        <!-- 查询条件实时解析预览 -->
                        <div v-if="(form.intent_mode !== 'intent' && form.fofa_query.trim() && (queryPreview || queryPreviewError))" class="query-preview">
                          <div class="tp-head">
                            <b>条件解析</b>
                            <span v-if="queryPreviewLoading" class="tp-loading">解析中…</span>
                            <span v-else-if="queryPreview && queryPreview.issues.length" class="tp-warn">有 {{ queryPreview.issues.length }} 个问题</span>
                            <span v-else-if="queryPreview" class="tp-ok">{{ queryPreview.token_count }} 个条件</span>
                          </div>
                          <p v-if="queryPreviewError" class="tp-error">{{ queryPreviewError }}</p>
                          <template v-else-if="queryPreview">
                            <p v-if="queryPreview.syntax_mismatch" class="qp-mismatch">{{ queryPreview.syntax_mismatch }}</p>
                            <p class="qp-summary">{{ queryPreview.summary }}</p>
                            <div v-if="queryPreview.fields.length" class="qp-fields">
                              <span v-for="f in queryPreview.fields" :key="f" class="qp-field">{{ f }}</span>
                            </div>
                            <div v-if="Object.keys(queryPreview.keywords).length" class="qp-keywords">
                              <div v-for="(vals, cat) in queryPreview.keywords" :key="cat" class="qp-kw">
                                <b>{{ catLabel(cat) }}</b>
                                <span v-for="v in vals" :key="v">{{ v }}</span>
                              </div>
                            </div>
                            <div v-if="queryPreview.issues.length" class="tp-ignored">
                              <b>语法提示：</b>
                              <code v-for="(msg, i) in queryPreview.issues" :key="i">{{ msg }}</code>
                            </div>
                          </template>
                        </div>
                      </section>
                    </template>
                    <section v-else-if="isSiteMode" class="create-block">
                      <header class="create-block-head">
                        <b>协作重点</b>
                        <small>后台位置、重点方向</small>
                      </header>
                      <textarea v-model="form.fofa_query" rows="4" placeholder="后台位置、重点方向。登录凭据请填下面「登录凭据」。&#10;例：后台在 /admin，重点测 API、越权、上传。"></textarea>
                    </section>

                    <section v-if="!isFofaMode" class="create-block">
                      <header class="create-block-head">
                        <b>{{ isSiteMode ? "主目标 URL" : "手动目标清单" }}</b>
                        <small v-if="effectiveManualCount">已识别 {{ effectiveManualCount }} 个有效目标</small>
                        <small v-else>每行一个，可直接粘贴杂乱资产表</small>
                        <span class="mt-tools">
                          <button type="button" class="linkish" @click="pasteFromClipboard">从剪贴板粘贴</button>
                          <button type="button" class="linkish" @click="fileInput.click()">导入 .txt</button>
                          <input ref="fileInput" type="file" accept=".txt,.csv,text/plain" hidden @change="importTargetFile" />
                        </span>
                      </header>
                      <textarea v-model="form.manual_targets" rows="6" :class="{ invalid: invalidField === 'manual' }" :placeholder="manualTargetsPlaceholder"></textarea>
                      <p class="create-mini">
                        自动去掉行尾中文备注、括号 IP 入队、裸域名补协议、去重。AI 会自动侦察识别目标业务类型（教务/OA/支付等）并按业务逻辑差异化挖洞；入队时按根域挂泄露凭据。
                      </p>

                      <!-- 实时解析预览 -->
                      <div class="target-preview">
                        <div class="tp-head">
                          <b>实时解析</b>
                          <span v-if="previewLoading" class="tp-loading">解析中…</span>
                          <span v-else-if="preview && preview.valid" class="tp-ok">{{ preview.valid }} 个有效目标</span>
                          <span v-else-if="preview" class="tp-warn">未识别到有效目标</span>
                        </div>
                        <p v-if="previewError" class="tp-error">{{ previewError }}</p>
                        <template v-else-if="preview">
                          <div class="tp-stats">
                            <span>域名 <b>{{ preview.domains }}</b></span>
                            <span>IP <b>{{ preview.ips }}</b></span>
                            <span>带备注 <b>{{ preview.with_note }}</b></span>
                            <span>忽略行 <b :class="{ warn: preview.ignored_total }">{{ preview.ignored_total }}</b></span>
                          </div>
                          <div v-if="preview.ignored_total" class="tp-ignored">
                            <b>以下 {{ preview.ignored_total }} 行未识别为目标，创建时会被忽略：</b>
                            <code v-for="(ln, i) in preview.ignored" :key="i">{{ ln }}</code>
                            <span v-if="preview.ignored_total > preview.ignored.length" class="tp-more">…等 {{ preview.ignored_total }} 行</span>
                          </div>
                          <ul v-if="preview.targets.length" class="tp-list">
                            <li v-for="(t, i) in preview.targets" :key="i">
                              <code>{{ t.url }}</code>
                              <span v-if="t.note" class="tp-note">{{ t.note }}</span>
                            </li>
                            <li v-if="preview.valid > preview.targets.length" class="tp-more">
                              …共 {{ preview.valid }} 个目标，其余创建后入队
                            </li>
                          </ul>
                        </template>
                      </div>

                      <section v-if="showAuthBindings" class="auth-bindings">
                        <div class="auth-bindings-head">
                          <strong>登录凭据（可选）<em v-if="credCount" class="auth-count">{{ credCount }} 条</em></strong>
                          <div class="auth-actions">
                            <button type="button" class="linkish" @click="toggleImportPanel">{{ importOpen ? "收起批量导入" : "批量导入" }}</button>
                            <button type="button" class="linkish" @click="addBinding">+ 添加一条</button>
                            <button v-if="credCount" type="button" class="linkish danger" @click="clearBindings">清空</button>
                          </div>
                        </div>
                        <p class="create-mini">
                          不填不影响挖掘。填了会强制尝试：Cookie / Token 注入会话，账密走登录。绑定 <code>*</code> 表示本任务都用。
                        </p>
                        <p v-if="authImportNotice" class="auth-import-notice">{{ authImportNotice }}</p>

                        <!-- 批量导入面板 -->
                        <div v-if="importOpen" class="auth-import">
                          <div class="auth-import-head">
                            <b>批量导入凭据</b>
                            <span class="mt-tools">
                              <button type="button" class="linkish" @click="pasteAuthClipboard">从剪贴板粘贴</button>
                              <button type="button" class="linkish" @click="authFileInput.click()">导入 .txt/.csv</button>
                              <input ref="authFileInput" type="file" accept=".txt,.csv,text/plain" hidden @change="importAuthFile" />
                            </span>
                          </div>
                          <textarea v-model="authImportText" rows="5" placeholder="每行一条，支持：&#10;admin:admin123&#10;admin:admin123@example.com&#10;example.com|admin|admin123&#10;Cookie: JSESSIONID=xxx&#10;Authorization: Bearer eyJ...&#10;账号: admin 密码: admin123&#10;# 井号开头是注释"></textarea>
                          <p class="create-mini">每行一条凭据；<code>#</code> / <code>//</code> / <code>;</code> 开头视为注释忽略，识别不了的整行跳过。</p>

                          <div class="target-preview">
                            <div class="tp-head">
                              <b>解析预览</b>
                              <span v-if="authImportLoading" class="tp-loading">解析中…</span>
                              <span v-else-if="authPreview && authPreview.parsed" class="tp-ok">识别 {{ authPreview.parsed }} 条凭据</span>
                              <span v-else-if="authPreview" class="tp-warn">未识别到凭据</span>
                            </div>
                            <p v-if="authImportError" class="tp-error">{{ authImportError }}</p>
                            <template v-else-if="authPreview">
                              <div class="tp-stats">
                                <span>账密 <b>{{ authPreview.by_kind.password || 0 }}</b></span>
                                <span>Cookie <b>{{ authPreview.by_kind.cookie || 0 }}</b></span>
                                <span>Bearer <b>{{ authPreview.by_kind.bearer || 0 }}</b></span>
                                <span>忽略行 <b :class="{ warn: authPreview.ignored_total }">{{ authPreview.ignored_total }}</b></span>
                              </div>
                              <div v-if="authPreview.ignored_total" class="tp-ignored">
                                <b>以下 {{ authPreview.ignored_total }} 行未识别为凭据：</b>
                                <code v-for="(ln, i) in authPreview.ignored" :key="i">{{ ln }}</code>
                                <span v-if="authPreview.ignored_total > authPreview.ignored.length" class="tp-more">…等 {{ authPreview.ignored_total }} 行</span>
                              </div>
                              <ul v-if="authPreview.bindings.length" class="tp-list">
                                <li v-for="(b, i) in authPreview.bindings" :key="i">
                                  <span v-for="k in b.kinds" :key="k" class="auth-kind">{{ kindLabel(k) }}</span>
                                  <code>{{ bindingSummary(b) }}</code>
                                </li>
                                <li v-if="authPreview.parsed > authPreview.bindings.length" class="tp-more">
                                  …共 {{ authPreview.parsed }} 条，其余导入后并入列表
                                </li>
                              </ul>
                            </template>
                          </div>

                          <div class="auth-import-actions">
                            <button type="button" class="primary" :disabled="!authPreview || !authPreview.parsed" @click="applyAuthImport">导入 {{ authPreview?.parsed || 0 }} 条</button>
                            <button type="button" class="btn-ghost" @click="closeAuthImport">取消</button>
                          </div>
                        </div>

                        <div v-for="(b, i) in authBindings" :key="i" class="auth-binding-row">
                          <div class="auth-binding-head">
                            <div class="auth-binding-target">
                              <span class="auth-target-label">绑定目标</span>
                              <AuthTargetInput v-model="b.target" :options="bindingOptions" placeholder="* 全部目标，或填 URL / 域名" />
                              <button v-if="b.target && b.target !== '*'" type="button" class="auth-target-all" title="设为全部目标" @click="b.target = '*'">全部</button>
                            </div>
                            <div class="auth-binding-side">
                              <span v-if="bindingKinds(b).length" class="auth-kind-badges">
                                <em v-for="k in bindingKinds(b)" :key="k" class="auth-kind">{{ kindLabel(k) }}</em>
                              </span>
                              <button type="button" class="icon-btn" title="删除" @click="removeBinding(i)">×</button>
                            </div>
                          </div>
                          <label class="auth-raw-label">快捷粘贴（自动分辨 Cookie / Bearer / 账密）
                            <textarea v-model="b.raw" rows="2" placeholder="Cookie: JSESSIONID=xxx&#10;Authorization: Bearer eyJ...&#10;账号: test  密码: Test@123"></textarea>
                          </label>
                          <details>
                            <summary>展开填结构化字段</summary>
                            <div class="auth-grid">
                              <label>账号 <input v-model="b.username" autocomplete="off" /></label>
                              <label>密码 <input v-model="b.password" type="password" autocomplete="new-password" /></label>
                              <label class="span2">Cookie 串 <input v-model="b.cookie" placeholder="JSESSIONID=...; other=..." /></label>
                              <label class="span2">Authorization <input v-model="b.authorization" placeholder="Bearer eyJ..." /></label>
                              <label class="span2">登录 URL（可选） <input v-model="b.login_url" placeholder="https://host/login" /></label>
                            </div>
                          </details>
                        </div>
                      </section>

                      <p v-if="isSiteMode && looksHasCreds && !(exportAuthBindings().length)" class="field-hint warn-hint">
                        协作备注里像有凭据，但凭据区是空的。挪到凭据区才能强制尝试并在看板反馈。
                      </p>
                    </section>
                  </div>

                  <!-- 步骤3：规则与运行 -->
                  <div v-else key="s3" class="wizard-pane">
                    <section class="create-block">
                      <header class="create-block-head">
                        <b>本任务规则</b>
                        <small>叠加在内置 {{ form.src_type === "enterprise" ? "企业 SRC" : "EduSRC" }} 标准之上，内置红线始终生效，这里仅额外收紧</small>
                        <span class="rule-count" :class="{ on: ruleCharCount > 0 }">{{ ruleCharCount }} 字</span>
                      </header>

                      <div class="guard-block">
                        <div class="guard-block-head">
                          <b>八大类硬拦截</b>
                          <small>勾选后才拦截，未勾选一律放行</small>
                        </div>
                        <div class="guard-grid">
                          <label
                            v-for="c in guardCats"
                            :key="c.id"
                            class="guard-opt"
                            :class="{ on: (form.guard_ops || []).includes(c.id) }"
                          >
                            <input
                              type="checkbox"
                              :checked="(form.guard_ops || []).includes(c.id)"
                              @change="toggleGuardOp(c.id)"
                            />
                            <span class="guard-name">{{ c.label }}</span>
                          </label>
                          <p v-if="!guardCats.length" class="guard-empty">拦截类别加载失败，请在规则文本框写「禁止…」也能生效。</p>
                        </div>
                        <p class="guard-summary">
                          <template v-if="(form.guard_ops || []).length">
                            已勾选 <b>{{ form.guard_ops.length }}</b> 类，命中即报错，worker 不会执行
                          </template>
                          <template v-else>未勾选任务级拦截，内置红线（自毁/破坏性/企业）仍生效</template>
                        </p>
                      </div>

                      <div class="extra-rules">
                        <div class="guard-block-head extra-head">
                          <b>额外规则</b>
                          <small>审核语义：重点收 / 不收；禁止类请在上方勾选</small>
                        </div>
                        <div class="rule-groups">
                          <div v-for="g in RULE_PRESET_GROUPS" :key="g.id" class="rule-group" :class="`rg-${g.id}`">
                            <span class="rg-label" :title="g.hint">{{ g.label }}</span>
                            <div class="rg-chips">
                              <button
                                v-for="p in g.items"
                                :key="p.id"
                                type="button"
                                class="rule-chip"
                                :class="{ on: rulePresetActive(p) }"
                                @click="toggleRulePreset(p)"
                              >{{ p.label }}</button>
                            </div>
                          </div>
                        </div>
                        <textarea v-model="form.src_rules" rows="3" placeholder="例：本校不收弱口令；重点收越权与未授权。&#10;点上方快捷规则可一键插入/移除，多条规则每行一条。"></textarea>
                        <div v-if="forbiddenLoading" class="fb-preview">
                          <span class="fb-loading">解析禁止操作中…</span>
                        </div>
                        <div v-else-if="forbiddenError" class="fb-preview fb-error">{{ forbiddenError }}</div>
                        <div v-else-if="forbiddenPreview && forbiddenPreview.count > 0" class="fb-preview fb-active">
                          <span class="fb-head">
                            <b>额外禁止操作 {{ forbiddenPreview.count }} 类</b>
                            <em>文本规则命中即报错，与上方勾选合并生效</em>
                          </span>
                          <span class="fb-chips">
                            <em v-for="f in forbiddenPreview.forbidden" :key="f.id" class="fb-chip">{{ f.label }}</em>
                          </span>
                        </div>
                        <div v-else-if="forbiddenPreview" class="fb-preview fb-idle">
                          <span class="fb-head"><b>未检测到额外禁止操作</b></span>
                          <span class="fb-note">文本规则仅审核语义（如"不收弱口令"）；禁止类请在上方八大类勾选</span>
                        </div>
                      </div>

                      <p class="create-mini">快捷规则是常见口径，点一下即插入；再点一下移除。自定义规则请直接写在文本框；勾选八大类后命中即报错，worker 不会执行，也不会弹确认。</p>
                    </section>

                    <section class="create-block">
                      <header class="create-block-head">
                        <b>模型方案</b>
                        <small>当前系统是{{ inherited.llm_mode === "pool" ? inherited.llm_provider_count + " 个模型端点" : "单模型" }}</small>
                      </header>
                      <div class="create-seg" role="tablist" aria-label="任务模型方案">
                        <button type="button" role="tab" :aria-selected="form.model_mode === 'inherit'" :class="{ active: form.model_mode === 'inherit' }" @click="form.model_mode = 'inherit'">跟随系统</button>
                        <button type="button" role="tab" :aria-selected="form.model_mode === 'single'" :class="{ active: form.model_mode === 'single' }" @click="form.model_mode = 'single'">单端点</button>
                        <button type="button" role="tab" :aria-selected="form.model_mode === 'pool'" :class="{ active: form.model_mode === 'pool' }" @click="form.model_mode = 'pool'">端点池</button>
                      </div>
                      <p class="model-mode-desc">{{ modelModeDesc }}</p>

                      <div v-if="form.model_mode === 'inherit'" class="model-inherit">
                        <span>系统模型</span>
                        <code>{{ inherited.model || "未配置" }}</code>
                        <em>{{ inherited.base_url || "默认端点" }}</em>
                        <small v-if="inherited.llm_mode === 'pool'">{{ inherited.llm_provider_count }} 个端点轮询</small>
                      </div>
                      <div v-if="form.model_mode === 'inherit' && inherited.llm_mode === 'single'" class="model-inherit">
                        <span>灾备模型</span>
                        <template v-if="inherited.models.length">
                          <code v-for="m in inherited.models" :key="m">{{ m }}</code>
                        </template>
                        <em v-else>未配置，主模型不可用时不会自动顶替</em>
                      </div>

                      <template v-if="form.model_mode === 'single'">
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
                        <div class="wizard-pane">
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

                          <div v-else-if="wizardStep === 1" class="wizard-pane">
                            <div class="create-grid">
                              <label class="wide">模型 base_url
                                <input v-model="form.base_url" required placeholder="https://api.deepseek.com/v1" @input="invalidateModelKey" />
                              </label>
                              <label class="wide">模型 api_key
                                <span class="key-line">
                                  <input v-model="form.api_key" :class="{ invalid: invalidField === 'api_key' }" :required="!form.key_ref" type="password" :placeholder="form.key_ref ? '已配置，留空复用' : 'sk-...'" />
                                  <em v-if="form.key_ref" class="key-badge">已配置</em>
                                </span>
                              </label>
                              <label>模型协议
                                <select v-model="form.protocol" @change="invalidateModelKey">
                                  <option value="auto">自动识别</option>
                                  <option value="openai_chat">OpenAI Chat Completions</option>
                                  <option value="anthropic_messages">Anthropic Messages</option>
                                </select>
                              </label>
                            </div>
                            <div class="model-test">
                              <button type="button" class="ghost-btn" :disabled="singleTest?.loading" @click="testSingleModel">
                                {{ singleTest?.loading ? "测试中…" : "测试连接" }}
                              </button>
                              <span v-if="singleTest && !singleTest.loading" class="model-test-result" :class="singleTest.ok ? 'ok' : 'fail'">
                                <template v-if="singleTest.ok">
                                  ✓ 连通 · {{ singleTest.latency_ms }}ms
                                  <em v-if="singleTest.tool_calling === 'yes'" class="tc-yes">工具调用 ✓</em>
                                  <em v-else-if="singleTest.tool_calling === 'no'" class="tc-no">工具调用 ✗</em>
                                </template>
                                <template v-else>
                                  {{ singleTest.error }}
                                  <span v-if="singleTest.available_models?.length" class="model-avail">
                                    可用模型：
                                    <em v-for="m in singleTest.available_models" :key="m" class="avail-chip" @click="form.model = m">{{ m }}</em>
                                    <small>点模型名填入</small>
                                  </span>
                                </template>
                              </span>
                            </div>
                            <p class="create-mini">测试连接会真实发一次小请求验证 base_url / Key / 协议，并探测模型是否支持工具调用（全流程依赖）。</p>
                            <div class="wizard-nav">
                              <button type="button" class="ghost-btn" @click="wizardStep = 0">← 上一步</button>
                              <button type="button" class="primary" :disabled="!form.base_url.trim() || (!form.api_key.trim() && !form.key_ref)" @click="wizardStep = 2">下一步：选模型 →</button>
                            </div>
                          </div>

                          <div v-else class="wizard-pane">
                            <div class="create-grid">
                              <label class="wide">模型名
                                <LlmModelPicker
                                  v-model="form.model"
                                  :models="singleModels"
                                  :loading="singleModelsLoading"
                                  :error="singleModelsError"
                                  required
                                  @refresh="loadSingleModels"
                                />
                              </label>
                              <div class="wide backup-models">
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
                              <label class="wide">temperature
                                <TemperatureRecommend v-model="form.temperature" :model="form.model" />
                              </label>
                            </div>
                            <div class="wizard-recap">
                              <span>模型商</span><b>{{ selectedPresetName }}</b>
                              <span>端点</span><code>{{ form.base_url }}</code>
                              <span>模型</span><b>{{ form.model || "未选" }}</b>
                            </div>
                            <div class="wizard-nav">
                              <button type="button" class="ghost-btn" @click="wizardStep = 1">← 上一步</button>
                            </div>
                          </div>
                        </div>
                      </template>

                      <LlmPoolEditor
                        v-else-if="form.model_mode === 'pool'"
                        ref="poolEditor"
                        v-model="taskProviders"
                        :defaults="{ base_url: form.base_url || inherited.base_url, model: form.model || inherited.model, protocol: form.protocol || inherited.protocol }"
                      />
                    </section>

                    <section class="create-block">
                      <header class="create-block-head">
                        <b>运行参数</b>
                        <small>并发 · 回炉 · 入口侦察</small>
                      </header>
                      <div class="create-grid">
                        <label v-if="!isSiteMode">搜集最大页数
                          <input v-model="form.max_pages" type="number" min="1" max="200" />
                          <small class="field-hint">引擎翻页上限，1–200，默认 20</small>
                        </label>
                        <label>worker 并发
                          <input v-model="form.concurrency" type="number" min="1" max="32" />
                          <small class="field-hint">同时打几个目标，1–32</small>
                        </label>
                        <label>深挖次数
                          <input v-model="form.deepen_cap" type="number" min="0" max="10" />
                          <small class="field-hint">同一目标被打回的上限，0 关闭回炉</small>
                        </label>
                        <label v-if="isSiteMode" class="run-check">
                          <span class="run-check-line">
                            <input type="checkbox" v-model="form.skip_site_recon" @change="form.skip_recon_touched = true" />
                            跳过入口盘点侦察（省 LLM 调用与流量）
                          </span>
                          <small class="field-hint">默认先泛扒首页 / robots / API 文档做一轮入口侦察。已带登录凭据、或你已明确要打的接口时，勾选可跳过这轮，更省时省 token。</small>
                        </label>
                      </div>
                      <template v-if="isSearchMode && engineIsFofa">
                        <details class="create-adv">
                          <summary>FOFA Key 覆盖（可选）</summary>
                          <label>FOFA Key（本任务覆盖） <input v-model="form.fofa_key" type="password" placeholder="留空用系统设置" /></label>
                          <label>FOFA API 端点 <input v-model="form.fofa_base_url" placeholder="https://fofa.info" /></label>
                          <p class="create-mini">仅 FOFA 生效。Quake / Hunter 等到设置页配 Key。</p>
                        </details>
                      </template>
                      <p v-else-if="isSearchMode" class="create-mini">当前不是 FOFA：Key 用设置页「各引擎 API Key」。</p>
                    </section>
                  </div>
                </Transition>
              </div>

              <aside class="create-aside">
                <div class="create-recap">
                  <span>{{ isEdit ? "正在编辑" : "即将创建" }}</span>
                  <b>{{ form.name.trim() || "未命名任务" }}</b>
                  <dl>
                    <div><dt>口径</dt><dd>{{ form.src_type === "enterprise" ? "企业 SRC" : "EduSRC" }}</dd></div>
                    <div><dt>来源</dt><dd>{{ recapSource }}</dd></div>
                    <div v-if="isSearchMode"><dt>引擎</dt><dd>{{ engineLabel }}</dd></div>
                    <div><dt>漏洞</dt><dd>{{ vulnSelected.size }} 类</dd></div>
                    <div v-if="!isFofaMode"><dt>有效目标</dt><dd>{{ effectiveManualCount }} 个</dd></div>
                    <div><dt>模型</dt><dd>{{ recapModel }}</dd></div>
                    <div><dt>并发</dt><dd>{{ form.concurrency }}</dd></div>
                  </dl>
                  <p v-if="missingHint" class="create-missing">{{ missingHint }}</p>
                  <button type="submit" class="primary" :disabled="submitting">{{ submitting ? (isEdit ? "保存中…" : "创建中…") : (isEdit ? "保存修改" : "创建任务") }}</button>
                </div>
              </aside>
            </div>

            <div class="create-dock">
              <div class="dock-info">
                <p v-if="stepError" class="dock-error">{{ stepError }}</p>
                <p v-else>{{ recapLine }}</p>
              </div>
              <div class="dock-actions">
                <button v-if="step > 1" type="button" class="btn-ghost" @click="prevStep">上一步</button>
                <button v-if="step < 3" type="button" class="primary" @click="nextStep">下一步</button>
                <button v-else type="submit" class="primary" :disabled="submitting">{{ submitting ? (isEdit ? "保存中…" : "创建中…") : (isEdit ? "保存" : "创建") }}</button>
              </div>
            </div>
          </form>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>
