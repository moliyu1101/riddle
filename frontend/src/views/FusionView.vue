<script setup>
import { computed, onMounted, ref, watch } from "vue";
import { useRoute } from "vue-router";
import { api } from "../api.js";
import FusionGoalEditor from "../components/FusionGoalEditor.vue";
import { fromGoalPayload, toGoalPayload, validateGoalRows } from "../fusionGoals.js";

defineOptions({ name: "FusionView" });
const route = useRoute();

const TABS = [
  { id: "overview", label: "总览与路由", pillar: "P1 · 运行控制" },
  { id: "goals", label: "目标闸门", pillar: "P2 · 闸门与审批" },
  { id: "gates", label: "证据·范围·拦截", pillar: "P2 · 闸门与审批" },
  { id: "graphs", label: "双图血缘", pillar: "P3 · 图谱与留痕" },
  { id: "traffic", label: "流量留痕", pillar: "P3 · 图谱与留痕" },
  { id: "intel", label: "CVE 时间流", pillar: "P4 · 知识与报告" },
  { id: "report", label: "公文与复测", pillar: "P4 · 知识与报告" },
  { id: "skills", label: "技能速查", pillar: "P4 · 知识与报告" },
];
const TAB_GROUPS = [
  { key: "p1", label: "⚡ 控制路由", tabs: ["overview"] },
  { key: "p2", label: "🛡️ 闸门与命令审批", tabs: ["goals", "gates"] },
  { key: "p3", label: "🕸️ 双图与流量留痕", tabs: ["graphs", "traffic"] },
  { key: "p4", label: "🧠 情报·报告·技能", tabs: ["intel", "report", "skills"] },
];
const pendingInterceptCount = computed(() =>
  interceptItems.value.filter((x) => x?.status === "pending").length
);
const activeTab = ref("overview");
const status = ref(null);
const skillIndex = ref(null);
const cfgMeta = ref(null);
const loading = ref(true);
const busy = ref("");
const notice = ref("");
const error = ref("");

// 任务与漏洞联动上下文（免去手填 ID）
const tasks = ref([]);
const selectedTaskId = ref("");
const taskFindings = ref([]);
const selectedSampleFindingId = ref("");

const BOOL_FIELDS = [
  { key: "evidence_gate_hard", label: "证据硬闸门", desc: "submit_finding 真正拦截缺凭据的 critical/high" },
  { key: "scope_guard_hard", label: "范围硬守卫", desc: "拦截越界资产写回" },
  { key: "traffic_enabled", label: "流量留痕", desc: "http_request 逐请求写 JSONL" },
  { key: "goal_gate_enabled", label: "目标闸门", desc: "目标与验收标准机制" },
  { key: "skill_index_enabled", label: "技能速查注入", desc: "常驻注入 worker system prompt" },
  { key: "role_routing_enabled", label: "角色路由", desc: "按角色配模型" },
  { key: "intel_sync_enabled", label: "情报同步", desc: "允许 CVE 时间流同步" },
  { key: "graphs_enabled", label: "双图架构", desc: "资产图 / 探索图" },
  { key: "report_enabled", label: "公文报告", desc: "允许导出公文级 Word" },
];
const INTERVAL_PRESETS = [
  { label: "关闭 (0h)", value: 0 },
  { label: "每 6h", value: 6 },
  { label: "每 12h", value: 12 },
  { label: "每 24h", value: 24 },
];
const configForm = ref({});
const roleInputs = ref({});

// 目标闸门：可视化行 + 可选 JSON 源码切换
const taskId = ref("");
const goalsJsonMode = ref(false);
const goalRows = ref([
  { id: "g1", title: "未授权接口返回业务数据", kind: "existence", criteria: "匿名 GET 返回 200 且响应 JSON 含业务字段，可用 curl 复现", matchText: "未授权" },
]);
const goalsText = ref(JSON.stringify(toGoalPayload(goalRows.value), null, 2));
const goalResult = ref(null);

// 证据闸门：可视化表单 + JSON 批量切换
const evidenceJsonMode = ref(false);
const evidenceForm = ref({
  severity_claimed: "critical",
  vuln_type: "rce",
  title: "远程命令执行",
  poc: "curl -s 'http://target.example/run?cmd=id'",
  raw_request: "GET /run?cmd=id HTTP/1.1\nHost: target.example\n\n",
  raw_response: "HTTP/1.1 200 OK\n\nuid=0(root)",
});
const findingText = ref(JSON.stringify({ ...evidenceForm.value, steps: [] }, null, 2));
const evidenceResult = ref(null);

// 范围守卫：可视化表单 + JSON 切换
const scopeJsonMode = ref(false);
const scopeTarget = ref("api.example.edu.cn");
const scopeForm = ref({
  rootsText: "example.edu.cn",
  sourcesText: "",
  cidrsText: "",
});
const scopeText = ref(JSON.stringify({ roots: ["example.edu.cn"], sources: [], cidrs: [] }, null, 2));
const scopeResult = ref(null);

// 情报时间流
const recent = ref([]);
const syncResult = ref(null);
const techText = ref("nginx/1.18.0, php");
const includeUnaffected = ref(false);
const matchResult = ref(null);

// 命令三层拦截与审批队列
const interceptCmd = ref("sqlmap -u 'http://target.example/item?id=1' --os-shell");
const interceptSrcType = ref("edusrc");
const interceptResult = ref(null);
const interceptItems = ref([]);
const interceptFilter = ref("");

// 双图架构
const graphTaskId = ref("");
const graphData = ref(null);
const lineageNodeId = ref("");
const lineageDirection = ref("both");
const lineageResult = ref(null);

// 流量留痕与勾选绑定
const trafficTaskId = ref("");
const trafficDirs = ref([]);
const trafficWorkDir = ref("");
const trafficItems = ref([]);
const selectedTrafficIds = ref([]);
const importResult = ref(null);
const bindFindingId = ref("");
const bindIds = ref("");
const bindRole = ref("proof");

// 公文报告与复测闭环
const reportFindingId = ref("");
const reportData = ref(null);
const retestMode = ref("manual");
const retestStatus = ref("reproduced");
const retestUrl = ref("");
const retestMethod = ref("GET");
const retestMatchText = ref("");
const retestNotes = ref("");
const retestsList = ref([]);
const retestSummary = ref(null);

const TASK_STATUS_LABELS = {
  running: "运行中",
  idle: "空闲",
  paused: "暂停",
  stopped: "已停止",
  created: "未启动",
};
const HARD_GATE_META = {
  evidence_gate_hard: { desc: "submit_finding 强验证 L2/L3 可复现凭据，缺凭据直接拦截写入" },
  scope_guard_hard: { desc: "强制划分 own / source / foreign，阻断越界与内网基础设施写回" },
  traffic_enabled: { desc: "http_request 逐请求记录 JSONL，自动支撑四类证据绑定" },
};
const ROLE_DESCS = {
  planner: "任务规划与验收目标拆解",
  worker: "漏洞探测与 PoC 验证执行",
  reviewer: "证据复核与误报/弱证剔除",
  judge: "高危命令安全研判（窄视野防注入）",
};
const INTERCEPT_PRESETS = [
  { label: "sqlmap --os-shell", cmd: "sqlmap -u 'http://target.example/item?id=1' --os-shell" },
  { label: "rm -rf /", cmd: "rm -rf /" },
  { label: "nc 反弹 Shell", cmd: "nc -lvp 4444 -e /bin/sh" },
  { label: "nmap 常规探测", cmd: "nmap -sV -p 80,443 127.0.0.1" },
];
const INTEL_SAMPLE_TECHS = [
  "nginx/1.18.0",
  "Spring Boot 2.6.3",
  "Fastjson 1.2.47",
  "Apache Log4j 2.14.1",
];

const showManualTaskInput = ref(false);
const skillSearch = ref("");

const hardGates = computed(() => {
  const c = configForm.value || {};
  return [
    { key: "evidence_gate_hard", label: "证据硬闸门", on: !!c.evidence_gate_hard, desc: HARD_GATE_META.evidence_gate_hard.desc },
    { key: "scope_guard_hard", label: "范围硬守卫", on: !!c.scope_guard_hard, desc: HARD_GATE_META.scope_guard_hard.desc },
    { key: "traffic_enabled", label: "流量自动留痕", on: !!c.traffic_enabled, desc: HARD_GATE_META.traffic_enabled.desc },
  ];
});

const selectedTaskObj = computed(() => tasks.value.find((t) => t.id === selectedTaskId.value) || null);

const roleMatrixRows = computed(() => {
  const routingMap = Object.fromEntries((status.value?.role_routing || []).map((r) => [r.role, r]));
  const roles = cfgMeta.value?.config?.roles?.length
    ? cfgMeta.value.config.roles
    : ["planner", "worker", "reviewer", "judge"];
  return roles.map((role) => ({
    role,
    desc: ROLE_DESCS[role] || routingMap[role]?.hint || "子系统专用路由",
    effectiveModel: routingMap[role]?.model || "",
    hint: routingMap[role]?.hint || "",
  }));
});

const filteredSkillBlock = computed(() => {
  const raw = skillIndex.value?.block || "";
  const kw = skillSearch.value.trim().toLowerCase();
  if (!kw) return raw;
  return raw
    .split("\n")
    .filter((line) => line.toLowerCase().includes(kw))
    .join("\n");
});

const graphLayout = computed(() => {
  const nodes = graphData.value?.nodes || [];
  const edges = graphData.value?.edges || [];
  const byGraph = {
    asset: nodes.filter((n) => n.graph === "asset"),
    exploration: nodes.filter((n) => n.graph === "exploration"),
  };
  const points = [];
  const cols = 3;
  Object.entries(byGraph).forEach(([g, list], gi) => {
    list.slice(0, 36).forEach((n, i) => {
      points.push({
        id: n.id,
        label: (n.label || n.kind).slice(0, 14),
        kind: n.kind,
        x: 34 + gi * 380 + (i % cols) * 116,
        y: 44 + Math.floor(i / cols) * 44,
        graph: g,
      });
    });
  });
  const maxRows = Math.max(
    1,
    Math.ceil(Math.min(byGraph.asset.length, 36) / cols),
    Math.ceil(Math.min(byGraph.exploration.length, 36) / cols),
  );
  const svgHeight = Math.max(300, 48 + maxRows * 44);
  const coords = Object.fromEntries(points.map((p) => [p.id, p]));
  const lines = edges.filter((e) => coords[e.src] && coords[e.dst]).slice(0, 80).map((e) => ({
    x1: coords[e.src].x, y1: coords[e.src].y, x2: coords[e.dst].x, y2: coords[e.dst].y, kind: e.kind,
  }));
  return { points, lines, assetNodes: byGraph.asset, explorationNodes: byGraph.exploration, svgHeight };
});

function toast(msg, isError = false) {
  if (isError) error.value = msg; else notice.value = msg;
  setTimeout(() => { notice.value = ""; error.value = ""; }, 4500);
}
function parseJson(text, label) {
  try { return JSON.parse(text); } catch (e) { throw new Error(`${label} 不是合法 JSON：${e.message}`); }
}
async function run(key, fn) {
  busy.value = key;
  try { await fn(); } catch (e) { toast(e?.message || String(e), true); } finally { busy.value = ""; }
}

function fillConfig(cfg, roles) {
  const next = {};
  for (const f of BOOL_FIELDS) next[f.key] = !!cfg[f.key];
  next.intel_lookback_days = Number(cfg.intel_lookback_days || 7);
  next.intel_sync_interval_hours = Number(cfg.intel_sync_interval_hours || 0);
  next.intel_fastlane_cvss = Number(cfg.intel_fastlane_cvss || 9);
  next.intel_timeout = Number(cfg.intel_timeout || 12);
  configForm.value = next;
  roleInputs.value = { ...(roles || {}) };
}

async function load() {
  loading.value = true;
  try {
    const [s, idx, rc, cm, tk, ic] = await Promise.all([
      api.fusionStatus(),
      api.fusionSkillIndex(),
      api.fusionIntelRecent(20),
      api.fusionConfig(),
      api.listTasks().catch(() => []),
      api.fusionInterceptList().catch(() => ({ items: [] })),
    ]);
    status.value = s;
    skillIndex.value = idx;
    recent.value = rc.items || [];
    cfgMeta.value = cm;
    tasks.value = Array.isArray(tk) ? tk : [];
    interceptItems.value = ic.items || [];
    fillConfig(cm.config || {}, cm.config?.role_models);
    if (!selectedTaskId.value && tasks.value.length && !taskId.value) {
      await onSelectTask(tasks.value[0].id);
    }
  } catch (e) { toast(e?.message || String(e), true); }
  finally { loading.value = false; }
}

async function onSelectTask(id) {
  selectedTaskId.value = id || "";
  if (!id) {
    taskFindings.value = [];
    return;
  }
  taskId.value = id;
  graphTaskId.value = id;
  trafficTaskId.value = id;
  try {
    const [gRes, evRes, fRows] = await Promise.all([
      api.fusionGoals(id).catch(() => ({ goals: [] })),
      api.fusionEvaluateGoals(id).catch(() => null),
      api.taskFindings(id, undefined, undefined, { compact: false, limit: 200 }).catch(() => []),
    ]);
    const list = Array.isArray(fRows) ? fRows : (fRows?.items || []);
    taskFindings.value = list;
    if (Array.isArray(gRes?.goals) && gRes.goals.length) {
      goalRows.value = fromGoalPayload(gRes.goals);
      goalsText.value = JSON.stringify(toGoalPayload(goalRows.value), null, 2);
    }
    goalResult.value = evRes;
    if (list.length) {
      if (!reportFindingId.value) reportFindingId.value = list[0].id;
      if (!bindFindingId.value) bindFindingId.value = list[0].id;
      if (reportFindingId.value) await loadRetests();
    }
  } catch { /* ignore task context preload error */ }
}

async function saveConfig() {
  await run("cfg", async () => {
    const payload = { ...configForm.value, role_models: roleInputs.value };
    const r = await api.fusionSaveConfig(payload);
    cfgMeta.value = { config: r.config, overlay: r.saved, source: "db" };
    fillConfig(r.config, r.config?.role_models);
    status.value = await api.fusionStatus();
    toast("配置已保存并即时生效");
  });
}

async function quickToggleGate(key) {
  configForm.value[key] = !configForm.value[key];
  await saveConfig();
}

async function quickSetInterval(hours) {
  configForm.value.intel_sync_interval_hours = hours;
  await saveConfig();
}

function toggleGoalsJsonMode() {
  if (!goalsJsonMode.value) {
    goalsText.value = JSON.stringify(toGoalPayload(goalRows.value), null, 2);
    goalsJsonMode.value = true;
    return;
  }
  try {
    const parsed = parseJson(goalsText.value, "目标清单");
    if (Array.isArray(parsed)) goalRows.value = fromGoalPayload(parsed);
    goalsJsonMode.value = false;
  } catch (e) {
    toast(e.message, true);
  }
}

async function saveGoals() {
  if (!taskId.value.trim()) return toast("先选择或填写任务 ID", true);
  await run("goals", async () => {
    let payload;
    if (goalsJsonMode.value) {
      payload = parseJson(goalsText.value, "目标清单");
    } else {
      const err = validateGoalRows(goalRows.value);
      if (err) throw new Error(err);
      payload = toGoalPayload(goalRows.value);
      goalsText.value = JSON.stringify(payload, null, 2);
    }
    await api.fusionSaveGoals(taskId.value.trim(), payload);
    goalResult.value = await api.fusionEvaluateGoals(taskId.value.trim());
    if (!graphTaskId.value) graphTaskId.value = taskId.value;
    toast("目标已保存并完成核对");
  });
}

async function evaluateGoals() {
  if (!taskId.value.trim()) return toast("先选择或填写任务 ID", true);
  await run("evaluate", async () => { goalResult.value = await api.fusionEvaluateGoals(taskId.value.trim()); });
}

function fillEvidenceFromSample(fid) {
  selectedSampleFindingId.value = fid;
  const f = taskFindings.value.find((x) => x.id === fid);
  if (!f) return;
  evidenceForm.value = {
    severity_claimed: f.severity_claimed || "medium",
    vuln_type: f.vuln_type || "",
    title: f.title || "",
    poc: f.poc || "",
    raw_request: f.raw_request || "",
    raw_response: f.raw_response || "",
  };
  findingText.value = JSON.stringify({ ...evidenceForm.value, steps: f.steps || [] }, null, 2);
}

function toggleEvidenceJsonMode() {
  if (!evidenceJsonMode.value) {
    findingText.value = JSON.stringify({ ...evidenceForm.value, steps: [] }, null, 2);
    evidenceJsonMode.value = true;
    return;
  }
  try {
    const obj = parseJson(findingText.value, "finding");
    if (obj && !Array.isArray(obj)) {
      evidenceForm.value = {
        severity_claimed: obj.severity_claimed || "medium",
        vuln_type: obj.vuln_type || "",
        title: obj.title || "",
        poc: obj.poc || "",
        raw_request: obj.raw_request || "",
        raw_response: obj.raw_response || "",
      };
    }
    evidenceJsonMode.value = false;
  } catch (e) {
    toast(e.message, true);
  }
}

async function checkEvidence() {
  await run("evidence", async () => {
    const payload = evidenceJsonMode.value
      ? parseJson(findingText.value, "finding")
      : { ...evidenceForm.value, steps: [] };
    evidenceResult.value = await api.fusionEvidenceCheck(payload);
  });
}

function splitLinesOrComma(text) {
  return String(text || "").split(/[,，\n\s]+/).map((s) => s.trim()).filter(Boolean);
}

function extractRootsFromTask() {
  const t = selectedTaskObj.value;
  const hosts = new Set();
  for (const item of t?.manual_targets || []) {
    const raw = typeof item === "string" ? item : (item?.url || item?.host || "");
    const m = String(raw || "").match(/^(?:https?:\/\/)?([^/:?#]+)/i);
    if (m && m[1]) hosts.add(m[1].toLowerCase());
  }
  for (const f of taskFindings.value || []) {
    const m = String(f.target_url || "").match(/^(?:https?:\/\/)?([^/:?#]+)/i);
    if (m && m[1]) hosts.add(m[1].toLowerCase());
  }
  if (!hosts.size) return toast("当前任务暂无可提取的域名/目标", true);
  const arr = [...hosts];
  scopeForm.value.rootsText = arr.join(", ");
  scopeTarget.value = arr[0];
  scopeText.value = JSON.stringify({
    roots: arr,
    sources: splitLinesOrComma(scopeForm.value.sourcesText),
    cidrs: splitLinesOrComma(scopeForm.value.cidrsText),
  }, null, 2);
  toast(`已从当前任务提取 ${arr.length} 个域`);
}

function toggleScopeJsonMode() {
  if (!scopeJsonMode.value) {
    scopeText.value = JSON.stringify({
      roots: splitLinesOrComma(scopeForm.value.rootsText),
      sources: splitLinesOrComma(scopeForm.value.sourcesText),
      cidrs: splitLinesOrComma(scopeForm.value.cidrsText),
    }, null, 2);
    scopeJsonMode.value = true;
    return;
  }
  try {
    const obj = parseJson(scopeText.value, "范围配置");
    scopeForm.value = {
      rootsText: (obj.roots || []).join(", "),
      sourcesText: (obj.sources || []).join(", "),
      cidrsText: (obj.cidrs || []).join(", "),
    };
    scopeJsonMode.value = false;
  } catch (e) {
    toast(e.message, true);
  }
}

async function checkScope() {
  await run("scope", async () => {
    const scope = scopeJsonMode.value
      ? parseJson(scopeText.value, "范围配置")
      : {
          roots: splitLinesOrComma(scopeForm.value.rootsText),
          sources: splitLinesOrComma(scopeForm.value.sourcesText),
          cidrs: splitLinesOrComma(scopeForm.value.cidrsText),
        };
    scopeResult.value = await api.fusionScopeCheck(scopeTarget.value, scope);
  });
}

async function syncIntel() {
  await run("sync", async () => {
    syncResult.value = await api.fusionIntelSync();
    if (syncResult.value.stored) recent.value = (await api.fusionIntelRecent(20)).items || [];
    toast("情报同步完成");
  });
}
async function matchIntel() {
  await run("match", async () => {
    matchResult.value = await api.fusionIntelMatch(
      techText.value.split(/[,，\n]+/).map((s) => s.trim()).filter(Boolean),
      includeUnaffected.value,
    );
  });
}

async function checkIntercept() {
  if (!interceptCmd.value.trim()) return toast("先输入要试算的命令", true);
  await run("intercept", async () => {
    interceptResult.value = await api.fusionInterceptCheck({
      command: interceptCmd.value.trim(),
      src_type: interceptSrcType.value,
      task_id: taskId.value.trim(),
      record: true,
    });
    await loadIntercepts();
  });
}

async function loadIntercepts() {
  const opts = {};
  if (interceptFilter.value) opts.status = interceptFilter.value;
  const res = await api.fusionInterceptList(opts);
  interceptItems.value = res?.items || [];
}

async function decideIntercept(itemId, decision) {
  await run("intercept-decide", async () => {
    await api.fusionInterceptDecide(itemId, decision, decision === "approve" ? "人工核准" : "人工拒绝");
    await loadIntercepts();
    toast(decision === "approve" ? "已批准同命令放行" : "已拒绝并入拦阻台账");
  });
}
async function rebuildGraph() {
  if (!graphTaskId.value.trim()) return toast("先选择或填写任务 ID", true);
  await run("rebuild", async () => {
    const r = await api.fusionGraphRebuild(graphTaskId.value.trim());
    toast(`双图已重建：${r.nodes} 节点 / ${r.edges} 边`);
    await loadGraph();
  });
}
async function loadGraph() {
  if (!graphTaskId.value.trim()) return toast("先选择或填写任务 ID", true);
  await run("graph", async () => { graphData.value = await api.fusionGraph(graphTaskId.value.trim()); });
}
async function selectGraphNode(node) {
  lineageNodeId.value = node.id;
  await queryLineage();
}
async function queryLineage() {
  if (!graphTaskId.value.trim() || !lineageNodeId.value.trim()) return toast("填任务 ID 与节点 ID", true);
  await run("lineage", async () => {
    lineageResult.value = await api.fusionGraphLineage(
      graphTaskId.value.trim(),
      lineageNodeId.value.trim(),
      lineageDirection.value,
    );
  });
}

async function discoverTraffic() {
  await run("discover", async () => {
    trafficDirs.value = (await api.fusionTrafficDiscover()).dirs || [];
    if (trafficDirs.value.length && !trafficWorkDir.value) trafficWorkDir.value = trafficDirs.value[0];
    toast(`发现 ${trafficDirs.value.length} 个工作目录`);
  });
}
async function importTraffic() {
  if (!trafficTaskId.value.trim()) return toast("先选择或填写任务 ID", true);
  await run("import", async () => {
    importResult.value = await api.fusionTrafficImport(trafficTaskId.value.trim(), trafficWorkDir.value.trim());
    await loadTraffic();
    toast(`导入 ${importResult.value.imported} 条流量`);
  });
}
async function loadTraffic() {
  if (!trafficTaskId.value.trim()) return toast("先选择或填写任务 ID", true);
  await run("traffic", async () => {
    trafficItems.value = (await api.fusionTrafficList(trafficTaskId.value.trim())).items || [];
    selectedTrafficIds.value = [];
  });
}
function toggleTrafficSelect(id) {
  const set = new Set(selectedTrafficIds.value);
  if (set.has(id)) set.delete(id); else set.add(id);
  selectedTrafficIds.value = [...set];
  bindIds.value = selectedTrafficIds.value.join(", ");
}
function selectAllTraffic() {
  selectedTrafficIds.value = trafficItems.value.map((t) => t.id);
  bindIds.value = selectedTrafficIds.value.join(", ");
}
function clearTrafficSelection() {
  selectedTrafficIds.value = [];
  bindIds.value = "";
}
async function bindTraffic() {
  if (!bindFindingId.value.trim()) return toast("先选择或填写漏洞 ID", true);
  await run("bind", async () => {
    const ids = bindIds.value.split(/[,，\s]+/).filter(Boolean);
    if (!ids.length) throw new Error("请先勾选或输入至少一条流量 ID");
    const r = await api.fusionTrafficBind(bindFindingId.value.trim(), ids, bindRole.value);
    toast(`已绑定 ${r.updated} 条（${r.role}）`);
    await loadTraffic();
  });
}

async function loadRetests() {
  if (!reportFindingId.value.trim()) {
    retestsList.value = [];
    retestSummary.value = null;
    return;
  }
  try {
    const res = await api.fusionRetests(reportFindingId.value.trim());
    retestsList.value = res?.retests || [];
    retestSummary.value = res?.summary || null;
    if (!retestUrl.value && res?.target_url) retestUrl.value = res.target_url;
  } catch { /* ignore when finding not selected */ }
}

async function submitRetest() {
  if (!reportFindingId.value.trim()) return toast("先选择或填写漏洞 ID", true);
  await run("retest-add", async () => {
    const res = await api.fusionAddRetest(reportFindingId.value.trim(), {
      mode: retestMode.value,
      status: retestStatus.value,
      url: retestUrl.value.trim(),
      method: retestMethod.value,
      match_text: retestMatchText.value.trim(),
      notes: retestNotes.value.trim(),
    });
    retestsList.value = res?.retests || [];
    retestSummary.value = res?.summary || null;
    retestNotes.value = "";
    if (reportData.value?.model) await loadReportModel();
    toast("复测记录已保存并同步报告");
  });
}

async function removeRetest(retestId) {
  if (!reportFindingId.value.trim()) return;
  await run("retest-del", async () => {
    const res = await api.fusionDeleteRetest(reportFindingId.value.trim(), retestId);
    retestsList.value = res?.retests || [];
    retestSummary.value = res?.summary || null;
    if (reportData.value?.model) await loadReportModel();
    toast("已删除复测记录");
  });
}

async function loadReportModel() {
  if (!reportFindingId.value.trim()) return toast("先选择或填写漏洞 ID", true);
  await run("report", async () => {
    reportData.value = await api.fusionReportModel(reportFindingId.value.trim());
    await loadRetests();
  });
}
async function downloadDocx() {
  if (!reportFindingId.value.trim()) return toast("先选择或填写漏洞 ID", true);
  await run("docx", async () => {
    await api.fusionReportDocx(reportFindingId.value.trim());
    toast("公文级 Word 已下载");
  });
}

function syncManualTaskId(val) {
  const clean = String(val || "").trim();
  taskId.value = clean;
  graphTaskId.value = clean;
  trafficTaskId.value = clean;
}

function appendSampleTech(sample) {
  const cur = techText.value.split(/[,，\n]+/).map((s) => s.trim()).filter(Boolean);
  if (!cur.includes(sample)) cur.push(sample);
  techText.value = cur.join(", ");
}

function prefillTechFromCve(it) {
  const prods = (it?.products || []).slice(0, 3).filter(Boolean);
  if (!prods.length) return;
  techText.value = prods.join(", ");
  toast(`已带入产品指纹：${prods.join(", ")}`);
}

async function copySkillBlock() {
  const text = filteredSkillBlock.value;
  if (!text) return toast("当前无技能文本可复制", true);
  try {
    await navigator.clipboard.writeText(text);
    toast("已复制技能速查手册到剪贴板");
  } catch {
    toast("浏览器剪贴板受限，请手动选择复制", true);
  }
}

function httpStatusClass(code) {
  const n = Number(code || 0);
  if (n >= 200 && n < 300) return "ok";
  if (n >= 300 && n < 500) return "warn";
  if (n >= 500) return "bad";
  return "";
}

function cvssBadgeClass(score) {
  const s = Number(score || 0);
  if (s >= 9) return "bad";
  if (s >= 7) return "warn";
  return "";
}

function taskStatusLabel(s) {
  return TASK_STATUS_LABELS[s] || s || "就绪";
}

async function applyQueryFromRoute() {
  const q = route.query || {};
  const tab = String(q.tab || "").trim();
  if (tab && TABS.some((t) => t.id === tab)) {
    activeTab.value = tab;
  }
  const qTaskId = String(q.taskId || "").trim();
  if (qTaskId) {
    await onSelectTask(qTaskId);
  }
  const qFindingId = String(q.findingId || "").trim();
  if (qFindingId) {
    reportFindingId.value = qFindingId;
    bindFindingId.value = qFindingId;
  }
}

watch(() => route.query, () => { applyQueryFromRoute(); });
onMounted(async () => {
  await Promise.all([load(), applyQueryFromRoute()]);
});
</script>

<template>
  <section class="fusion-studio">
    <!-- 顶部全局指挥栏 + 任务上下文选择 + 5维遥测 KPI -->
    <header class="fs-header-zone">
      <div class="fs-head">
        <div>
          <div class="fs-title-row">
            <span class="fs-pill-tag">FUSION ENGINE · P1–P4 架构治理中枢</span>
            <h2>融合架构控制台</h2>
          </div>
          <p class="fs-sub">目标闸门 · 证据硬核验 · 范围守卫 · 命令三层拦截 · 双图血缘 · HTTP 留痕 · CVE 同步 · 公文报告</p>
        </div>

        <div class="fs-context-bar">
          <div class="fs-task-picker">
            <label class="fs-ctx-lbl" for="fusion-task-select">当前任务</label>
            <select id="fusion-task-select" class="fs-select" :value="selectedTaskId" @change="onSelectTask($event.target.value)">
              <option value="">（手动指定任务 ID）</option>
              <option v-for="t in tasks" :key="t.id" :value="t.id">
                {{ t.name }} ({{ t.id.slice(0, 8) }}){{ t.goal_summary?.configured ? ` · ${t.goal_summary.summary}` : "" }}
              </option>
            </select>
            <button type="button" class="btn ghost fs-btn-sm" @click="showManualTaskInput = !showManualTaskInput">
              {{ showManualTaskInput ? "收起 ID" : "手动 ID" }}
            </button>
            <input
              v-if="showManualTaskInput || !selectedTaskId"
              :value="taskId"
              class="fs-id-input"
              placeholder="输入任务 ID…"
              @input="syncManualTaskId($event.target.value)"
            />
          </div>

          <div v-if="selectedTaskObj" class="fs-task-meta">
            <span class="badge" :class="selectedTaskObj.status">{{ taskStatusLabel(selectedTaskObj.status) }}</span>
            <span class="fs-meta-pill">{{ taskFindings.length }} 个漏洞</span>
          </div>

          <div class="fs-head-actions">
            <button class="btn ghost" :disabled="busy === 'reload'" @click="load">
              {{ busy === "reload" ? "刷新中…" : "↻ 刷新" }}
            </button>
            <router-link class="btn ghost" to="/">← 仪表盘</router-link>
          </div>
        </div>
      </div>

      <!-- 5-KPI 遥测矩阵 -->
      <div class="fs-kpi-strip">
        <button type="button" class="fs-kpi" @click="activeTab = 'gates'">
          <span class="fs-kpi-lbl">核心硬闸门</span>
          <strong class="fs-kpi-val" :class="hardGates.filter(g => g.on).length === 3 ? 'ok' : 'warn'">
            {{ hardGates.filter(g => g.on).length }} / {{ hardGates.length }}
          </strong>
          <span class="fs-kpi-sub">证据 · 范围 · 流量留痕</span>
        </button>

        <button type="button" class="fs-kpi" :class="{ alert: pendingInterceptCount > 0 }" @click="activeTab = 'gates'">
          <span class="fs-kpi-lbl">待审批命令拦截</span>
          <strong class="fs-kpi-val" :class="pendingInterceptCount > 0 ? 'warn' : ''">
            {{ pendingInterceptCount }}
          </strong>
          <span class="fs-kpi-sub">三层裁决台账 {{ interceptItems.length }} 条</span>
        </button>

        <button type="button" class="fs-kpi" @click="activeTab = 'goals'">
          <span class="fs-kpi-lbl">任务验收目标</span>
          <strong class="fs-kpi-val">{{ goalRows.length || status?.goal_count || 0 }}</strong>
          <span class="fs-kpi-sub">{{ goalResult ? (goalResult.goal_met ? "已全部达成" : "尚有未达成") : "点击管理目标闸门" }}</span>
        </button>

        <button type="button" class="fs-kpi" @click="activeTab = 'intel'">
          <span class="fs-kpi-lbl">CVE / KEV 情报池</span>
          <strong class="fs-kpi-val">{{ status?.intel_feed_count ?? 0 }}</strong>
          <span class="fs-kpi-sub">
            {{ Number(configForm.intel_sync_interval_hours || 0) > 0 ? `每 ${configForm.intel_sync_interval_hours}h 自动同步` : "当前仅手动同步" }}
          </span>
        </button>

        <button type="button" class="fs-kpi" @click="activeTab = 'skills'">
          <span class="fs-kpi-lbl">注入技能手册</span>
          <strong class="fs-kpi-val">{{ skillIndex?.count ?? 0 }} <small>篇</small></strong>
          <span class="fs-kpi-sub">配置源：{{ cfgMeta?.source === "db" ? "设置数据库" : ".env" }}</span>
        </button>
      </div>
    </header>

    <div class="fs-layout">
      <!-- 左侧 P1-P4 导航轨 -->
      <aside class="fs-rail" aria-label="融合模块导航">
        <nav class="fs-nav" role="tablist" aria-label="融合治理四大支柱">
          <div v-for="grp in TAB_GROUPS" :key="grp.key" class="fs-pillar-grp">
            <span class="fs-pillar-lbl">{{ grp.label }}</span>
            <div class="fs-pillar-tabs">
              <button
                v-for="t in TABS.filter((x) => grp.tabs.includes(x.id))"
                :key="t.id"
                type="button"
                class="fs-tab"
                :class="{ active: activeTab === t.id }"
                role="tab"
                :aria-selected="activeTab === t.id"
                @click="activeTab = t.id"
              >
                <span>{{ t.label }}</span>
                <span v-if="t.id === 'gates' && pendingInterceptCount > 0" class="fs-badge">{{ pendingInterceptCount }}</span>
                <span v-else-if="t.id === 'traffic' && trafficItems.length" class="fs-tab-count">{{ trafficItems.length }}</span>
              </button>
            </div>
          </div>
        </nav>

        <div class="fs-rail-health">
          <span class="fs-pillar-lbl">模块就绪概览</span>
          <div class="fs-rail-pills">
            <span v-for="m in (status?.modules || []).slice(0, 6)" :key="m.id" class="fs-mini-pill" :title="m.desc">
              {{ m.name }}
            </span>
          </div>
        </div>
      </aside>

      <!-- 右侧工作台主画布 -->
      <div class="fs-main">
        <div v-if="notice" class="fusion-alert ok">{{ notice }}</div>
        <div v-if="error" class="fusion-alert bad">{{ error }}</div>

        <div v-if="loading" class="fusion-card">正在读取融合层实时状态…</div>

        <!-- TAB 1: 总览与路由 -->
        <div v-else-if="activeTab === 'overview'" class="fs-stack">
          <!-- 第一行：三道核心防线开关 + CVE 后台同步周期卡片 -->
          <section class="fs-defense-grid">
            <button
              v-for="g in hardGates"
              :key="g.key"
              type="button"
              class="fs-defense-card"
              :class="{ on: g.on }"
              :disabled="!!busy"
              @click="quickToggleGate(g.key)"
            >
              <div class="fs-def-top">
                <strong>{{ g.label }}</strong>
                <span class="fusion-badge" :class="g.on ? 'ok' : 'warn'">{{ g.on ? "已启用" : "已旁路" }}</span>
              </div>
              <p class="fs-def-desc">{{ g.desc }}</p>
              <span class="fs-def-action">点击立即{{ g.on ? "降级为仅留痕" : "开启强制拦截" }} →</span>
            </button>

            <div class="fs-defense-card static">
              <div class="fs-def-top">
                <strong>CVE 后台自动同步周期</strong>
                <span class="fusion-badge" :class="Number(configForm.intel_sync_interval_hours || 0) > 0 ? 'ok' : ''">
                  {{ Number(configForm.intel_sync_interval_hours || 0) > 0 ? `${configForm.intel_sync_interval_hours}h / 次` : "手动" }}
                </span>
              </div>
              <p class="fs-def-desc">定时拉取近 {{ configForm.intel_lookback_days || 7 }} 天 NVD / KEV 情报并入库去重。</p>
              <div class="fs-seg-group">
                <button
                  v-for="p in INTERVAL_PRESETS"
                  :key="p.value"
                  type="button"
                  class="fs-seg-btn"
                  :class="{ active: Number(configForm.intel_sync_interval_hours || 0) === p.value }"
                  :disabled="!!busy"
                  @click="quickSetInterval(p.value)"
                >{{ p.label }}</button>
              </div>
            </div>
          </section>

          <!-- 第二行：左栏 四角色模型路由矩阵 + 右栏 九大子系统开关与参数 -->
          <section class="fs-overview-split">
            <article class="fusion-card">
              <div class="fusion-card-head">
                <div>
                  <h3>四角色模型路由与覆写矩阵</h3>
                  <p class="fusion-hint">为不同认知阶段指派独立模型或 LLM 通道，修改后点击下方「保存融合配置与角色路由」生效。</p>
                </div>
                <span class="fusion-pill" :class="configForm.role_routing_enabled ? 'on' : ''">
                  {{ configForm.role_routing_enabled ? "角色路由已启用" : "统一默认模型" }}
                </span>
              </div>

              <div class="fs-table-wrap">
                <table class="fs-table fs-table-fixed">
                  <thead>
                    <tr>
                      <th style="width: 108px;">角色</th>
                      <th>阶段职责与当前生效模型</th>
                      <th style="width: 240px;">模型覆写（留空沿用默认）</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="r in roleMatrixRows" :key="r.role">
                      <td><span class="fs-role-badge">{{ r.role }}</span></td>
                      <td>
                        <div class="fs-cell-stack">
                          <strong>{{ r.desc }}</strong>
                          <span class="fs-muted-sm">生效：<code>{{ r.effectiveModel || "默认主通道模型" }}</code></span>
                        </div>
                      </td>
                      <td>
                        <input v-model="roleInputs[r.role]" class="fusion-input fs-input-sm" placeholder="沿用默认模型" />
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

              <div class="fs-divider"></div>
              <div>
                <span class="fs-section-lbl">已挂载融合子系统（{{ status?.modules?.length || 0 }} 个）</span>
                <div class="fusion-modules" style="margin-top: 8px;">
                  <div v-for="m in status?.modules || []" :key="m.id" class="fusion-module">
                    <strong>{{ m.name }}</strong>
                    <span>{{ m.desc }}</span>
                  </div>
                </div>
              </div>
            </article>

            <article class="fusion-card">
              <div class="fusion-card-head">
                <div>
                  <h3>九大子系统开关与情报参数</h3>
                  <p class="fusion-hint">开关与设置页双向同步；敏感密钥仅保存在 <code>.env</code> 中，不落库、不回显。</p>
                </div>
              </div>

              <div class="fusion-switches">
                <label v-for="f in BOOL_FIELDS" :key="f.key" class="fusion-switch">
                  <input type="checkbox" v-model="configForm[f.key]" />
                  <span><strong>{{ f.label }}</strong><em>{{ f.desc }}</em></span>
                </label>
              </div>

              <div class="fusion-form-grid">
                <label class="fusion-label">情报回溯天数
                  <input class="fusion-input" type="number" min="1" max="90" v-model.number="configForm.intel_lookback_days" />
                </label>
                <label class="fusion-label">自动同步间隔 (h)
                  <input class="fusion-input" type="number" min="0" max="720" v-model.number="configForm.intel_sync_interval_hours" />
                </label>
                <label class="fusion-label">高危快通道 CVSS
                  <input class="fusion-input" type="number" min="0" max="10" step="0.1" v-model.number="configForm.intel_fastlane_cvss" />
                </label>
                <label class="fusion-label">HTTP 超时 (s)
                  <input class="fusion-input" type="number" min="1" max="60" v-model.number="configForm.intel_timeout" />
                </label>
              </div>

              <div class="fusion-actions end">
                <button class="btn primary" :disabled="!!busy" @click="saveConfig">
                  {{ busy === "cfg" ? "保存中…" : "保存融合配置与角色路由" }}
                </button>
              </div>
            </article>
          </section>
        </div>

        <!-- TAB 2: 目标闸门 -->
        <div v-else-if="activeTab === 'goals'" class="fs-stack">
          <article class="fusion-card">
            <div class="fusion-card-head">
              <div>
                <h3>目标闸门（TaskGoal 验收标准）</h3>
                <p class="fusion-hint">目标必须带可核验验收标准；能力型目标只认 high/critical 实证；未全达成时任务终态强制记为 incomplete。</p>
              </div>
              <div class="fusion-actions">
                <span class="fusion-pill">{{ selectedTaskObj ? `已绑定：${selectedTaskObj.name}` : (taskId ? `任务 ID：${taskId.slice(0, 12)}` : "未选择任务") }}</span>
                <button type="button" class="btn ghost" @click="toggleGoalsJsonMode">
                  {{ goalsJsonMode ? "切回可视化编辑" : "切换 JSON 源码" }}
                </button>
                <button type="button" class="btn ghost" :disabled="!!busy" @click="evaluateGoals">核对达成</button>
                <button type="button" class="btn primary" :disabled="!!busy" @click="saveGoals">保存目标</button>
              </div>
            </div>

            <div v-if="goalResult" class="fs-goal-verdict" :class="goalResult.goal_met ? 'good' : 'warn'">
              <div class="fs-verdict-main">
                <span class="fusion-badge" :class="goalResult.goal_met ? 'ok' : 'warn'">
                  {{ goalResult.goal_met ? "目标已全部达成" : "未全达成" }}
                </span>
                <strong>{{ goalResult.summary }} → 建议终态：<code>{{ goalResult.terminal_state }}</code></strong>
              </div>
              <div class="fs-verdict-meta">
                <span>已关联漏洞：{{ goalResult.finding_count ?? 0 }} 条</span>
                <span v-if="goalResult.unmet_ids?.length">未达成目标 ID：<code>{{ goalResult.unmet_ids.join("、") }}</code></span>
              </div>
            </div>

            <FusionGoalEditor
              v-if="!goalsJsonMode"
              v-model="goalRows"
              :evaluation="goalResult"
              :suggest-context="{ task_id: taskId.trim() }"
            />
            <template v-else>
              <label class="fusion-label">目标清单（JSON 数组）</label>
              <textarea v-model="goalsText" class="fusion-area" rows="12"></textarea>
            </template>
          </article>
        </div>

        <!-- TAB 3: 证据 · 范围 · 命令审批 -->
        <div v-else-if="activeTab === 'gates'" class="fs-stack">
          <!-- 置顶全宽：命令三层拦截试算与在线审批台账 -->
          <article class="fusion-card">
            <div class="fusion-card-head">
              <div>
                <h3>命令三层拦截试算与在线审批台账（deny / judge / ask）</h3>
                <p class="fusion-hint">第一层 deny 自毁硬拒；第二层 judge 窄视野防注入研判（严格 JSON）；第三层 ask 挂起交由人工放行或拒绝。</p>
              </div>
              <div class="fusion-actions">
                <select v-model="interceptFilter" class="fusion-input" style="width: 150px;" @change="loadIntercepts">
                  <option value="">全部状态 ({{ interceptItems.length }})</option>
                  <option value="pending">仅待审批 ({{ pendingInterceptCount }})</option>
                  <option value="approved">已批准放行</option>
                  <option value="denied">已拒绝拦截</option>
                </select>
                <button type="button" class="btn ghost" :disabled="!!busy" @click="loadIntercepts">↻ 刷新台账</button>
              </div>
            </div>

            <!-- 沙箱试算条 -->
            <div class="fs-sandbox-bar">
              <div class="fusion-inline">
                <select v-model="interceptSrcType" class="fusion-input" style="width: 140px;">
                  <option value="edusrc">EDU 严苛模式</option>
                  <option value="enterprise">企业内网模式</option>
                </select>
                <input
                  v-model="interceptCmd"
                  class="fusion-input"
                  style="flex: 1; min-width: 260px;"
                  placeholder="输入待测 Shell 命令，例如 sqlmap --os-shell / nc -lvp 4444 / rm -rf /"
                />
                <button type="button" class="btn primary" :disabled="!!busy" @click="checkIntercept">三层试算并记账</button>
              </div>
              <div class="fs-presets-row">
                <span class="fs-muted-sm">快捷试算样例：</span>
                <button
                  v-for="p in INTERCEPT_PRESETS"
                  :key="p.label"
                  type="button"
                  class="fusion-chip-btn"
                  @click="interceptCmd = p.cmd"
                >{{ p.label }}</button>
              </div>
            </div>

            <div v-if="interceptResult" class="fusion-result" :class="interceptResult.allowed ? 'good' : interceptResult.action === 'ask' ? 'warn' : 'bad'">
              <strong>层级 {{ interceptResult.tier }} → 动作 <code>{{ interceptResult.action }}</code>（{{ interceptResult.allowed ? "允许执行" : "拦截 / 待人工审批" }}）</strong>
              <span>规则：{{ interceptResult.rule || "allow" }} · {{ interceptResult.reason }}</span>
            </div>

            <!-- 审批结构化数据表格 -->
            <div class="fs-table-wrap">
              <table v-if="interceptItems.length" class="fs-table fs-table-fixed">
                <thead>
                  <tr>
                    <th style="width: 84px;">状态</th>
                    <th style="width: 112px;">层级 / 动作</th>
                    <th>执行命令与触发规则</th>
                    <th style="width: 136px; text-align: right;">审批操作</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="item in interceptItems" :key="item.id">
                    <td>
                      <span class="fusion-badge" :class="item.status === 'approved' ? 'ok' : item.status === 'pending' ? 'warn' : 'bad'">
                        {{ item.status === "pending" ? "待审批" : item.status === "approved" ? "已放行" : "已拒绝" }}
                      </span>
                    </td>
                    <td><span class="fusion-tag">{{ item.tier }} / {{ item.action }}</span></td>
                    <td>
                      <div class="fs-cell-stack">
                        <code class="fs-cmd-ellipsis" :title="item.command">{{ item.command }}</code>
                        <span class="fs-muted-sm">{{ item.reason || "-" }}</span>
                      </div>
                    </td>
                    <td style="text-align: right;">
                      <div v-if="item.status === 'pending'" class="fs-td-actions">
                        <button type="button" class="fusion-chip-btn ok" :disabled="!!busy" @click="decideIntercept(item.id, 'approve')">批准</button>
                        <button type="button" class="fusion-chip-btn bad" :disabled="!!busy" @click="decideIntercept(item.id, 'deny')">拒绝</button>
                      </div>
                      <span v-else class="fs-muted-sm">已归档</span>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-else class="fs-empty-box">当前筛选条件下暂无拦截或待审批命令记录，可使用上方沙箱试算生成记录。</div>
            </div>
          </article>

          <!-- 下方双栏：证据硬闸门试算 + 范围硬守卫试算 -->
          <section class="fs-gates-split">
            <article class="fusion-card">
              <div class="fusion-card-head">
                <div>
                  <h3>证据硬闸门 L1–L4 试算</h3>
                  <p class="fusion-hint">critical 要求 L3+、high 要求 L2+，且须含可复现 HTTP 请求/响应凭据。</p>
                </div>
                <button type="button" class="btn ghost" @click="toggleEvidenceJsonMode">
                  {{ evidenceJsonMode ? "切回表单" : "JSON 批量" }}
                </button>
              </div>

              <label v-if="taskFindings.length" class="fusion-label">从当前任务漏洞一键带入
                <select class="fusion-input" :value="selectedSampleFindingId" @change="fillEvidenceFromSample($event.target.value)">
                  <option value="">（选择漏洞快速填充试算表单）</option>
                  <option v-for="f in taskFindings" :key="f.id" :value="f.id">
                    [{{ f.severity_claimed || "-" }}] {{ f.title }} ({{ f.id.slice(0, 8) }})
                  </option>
                </select>
              </label>

              <template v-if="!evidenceJsonMode">
                <div class="fusion-form-grid">
                  <label class="fusion-label">申报等级
                    <select v-model="evidenceForm.severity_claimed" class="fusion-input">
                      <option value="critical">critical（严重）</option>
                      <option value="high">high（高危）</option>
                      <option value="medium">medium（中危）</option>
                      <option value="low">low（低危）</option>
                    </select>
                  </label>
                  <label class="fusion-label">漏洞类型
                    <input v-model="evidenceForm.vuln_type" class="fusion-input" placeholder="rce / sqli / idor..." />
                  </label>
                </div>
                <label class="fusion-label">漏洞标题
                  <input v-model="evidenceForm.title" class="fusion-input" />
                </label>
                <label class="fusion-label">PoC 命令（curl / 可执行脚本）
                  <input v-model="evidenceForm.poc" class="fusion-input" />
                </label>
                <label class="fusion-label">原始 HTTP 请求包
                  <textarea v-model="evidenceForm.raw_request" class="fusion-area" rows="3"></textarea>
                </label>
                <label class="fusion-label">原始 HTTP 响应 / 命中文案
                  <textarea v-model="evidenceForm.raw_response" class="fusion-area" rows="3"></textarea>
                </label>
              </template>
              <template v-else>
                <label class="fusion-label">finding（JSON 对象或数组）</label>
                <textarea v-model="findingText" class="fusion-area" rows="11"></textarea>
              </template>

              <div class="fusion-actions">
                <button class="btn primary" :disabled="!!busy" @click="checkEvidence">执行证据试算</button>
              </div>
              <div v-if="evidenceResult" class="fusion-result" :class="evidenceResult.allowed === false || evidenceResult.blocked ? 'bad' : 'good'">
                <template v-if="evidenceResult.rows">
                  <strong>批量试算 {{ evidenceResult.total }} 条：通过 {{ evidenceResult.passed }} 条 · 拦截 {{ evidenceResult.blocked }} 条</strong>
                </template>
                <template v-else>
                  <strong>{{ evidenceResult.allowed ? "✅ 准予落库" : "⛔ 闸门拦截" }} · {{ evidenceResult.impact_level }} {{ evidenceResult.impact_label }}</strong>
                  <span>识别凭据：{{ evidenceResult.evidence?.join("、") || "无有效凭据" }}</span>
                  <span v-for="(r, i) in evidenceResult.reasons || []" :key="i">• {{ r }}</span>
                </template>
              </div>
            </article>

            <article class="fusion-card">
              <div class="fusion-card-head">
                <div>
                  <h3>范围硬守卫 (own / source / foreign) 试算</h3>
                  <p class="fusion-hint">own 允许写回，source 只读参考，foreign 及内网保留地址严格拒绝。</p>
                </div>
                <button type="button" class="btn ghost" @click="toggleScopeJsonMode">
                  {{ scopeJsonMode ? "切回表单" : "JSON 模式" }}
                </button>
              </div>

              <div class="fusion-inline">
                <button type="button" class="btn ghost" :disabled="!selectedTaskObj" @click="extractRootsFromTask">
                  ⚡ 从当前任务自动提取根域
                </button>
              </div>

              <label class="fusion-label">待写回资产 URL / Host
                <input v-model="scopeTarget" class="fusion-input" />
              </label>

              <template v-if="!scopeJsonMode">
                <label class="fusion-label">授权根域名（逗号/换行分隔）
                  <input v-model="scopeForm.rootsText" class="fusion-input" placeholder="example.edu.cn, sub.example.com" />
                </label>
                <label class="fusion-label">只读共享源（可选）
                  <input v-model="scopeForm.sourcesText" class="fusion-input" placeholder="partner.example.org" />
                </label>
                <label class="fusion-label">授权 CIDR 网段（可选）
                  <input v-model="scopeForm.cidrsText" class="fusion-input" placeholder="203.0.113.0/24" />
                </label>
              </template>
              <template v-else>
                <label class="fusion-label">任务范围（JSON）</label>
                <textarea v-model="scopeText" class="fusion-area" rows="7"></textarea>
              </template>

              <div class="fusion-actions">
                <button class="btn primary" :disabled="!!busy" @click="checkScope">执行范围判定</button>
              </div>
              <div v-if="scopeResult" class="fusion-result" :class="scopeResult.allowed ? 'good' : 'bad'">
                <strong>分类：<code>{{ scopeResult.classification }}</code> · {{ scopeResult.allowed ? "✅ 允许写回" : "⛔ 拒绝写回" }}</strong>
                <span>{{ scopeResult.reason || "目标位于当前任务授权域范围之内" }}</span>
              </div>
            </article>
          </section>
        </div>

        <!-- TAB 4: 双图血缘 -->
        <div v-else-if="activeTab === 'graphs'" class="fs-stack">
          <article class="fusion-card">
            <div class="fusion-card-head">
              <div>
                <h3>双图架构工作台（AssetGraph + ExplorationGraph）</h3>
                <p class="fusion-hint">点击左侧拓扑节点或底部标签，沿 <code>proves / yields / derived_from</code> 追踪完整攻击血缘。</p>
              </div>
              <div class="fusion-actions">
                <input v-model="graphTaskId" class="fs-id-input" placeholder="任务 ID" style="width: 170px;" />
                <button class="btn ghost" :disabled="!!busy" @click="loadGraph">读取图谱</button>
                <button class="btn primary" :disabled="!!busy" @click="rebuildGraph">重建双图</button>
              </div>
            </div>

            <div v-if="graphData" class="fs-coverage-bar">
              <span class="fusion-pill">总节点 <strong>{{ graphData.nodes.length }}</strong></span>
              <span class="fusion-pill">血缘边 <strong>{{ graphData.edges.length }}</strong></span>
              <span class="fusion-pill on">资产图 {{ graphLayout.assetNodes.length }} · 探索图 {{ graphLayout.explorationNodes.length }}</span>
              <div class="fs-progress-wrap">
                <span>资产覆盖率 {{ (graphData.coverage.ratio * 100).toFixed(1) }}%（{{ graphData.coverage.covered }}/{{ graphData.coverage.asset_nodes }}）</span>
                <div class="fs-progress-track">
                  <div class="fs-progress-fill" :style="{ width: Math.min(100, graphData.coverage.ratio * 100) + '%' }"></div>
                </div>
              </div>
            </div>
          </article>

          <section class="fs-graph-workbench">
            <article class="fusion-card">
              <div class="fusion-card-head">
                <h3>双图关系拓扑画布</h3>
                <div class="fs-legend">
                  <span><i class="dot asset"></i>资产节点</span>
                  <span><i class="dot explore"></i>探索节点</span>
                </div>
              </div>

              <svg
                v-if="graphData"
                class="fusion-svg"
                :viewBox="`0 0 760 ${graphLayout.svgHeight}`"
                role="img"
                aria-label="双图节点关系图"
              >
                <line v-for="(l, i) in graphLayout.lines" :key="'l' + i" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" stroke="var(--border-strong)" stroke-width="0.9" stroke-opacity="0.7" />
                <g v-for="(p, i) in graphLayout.points" :key="'p' + i" class="fusion-svg-node" @click="selectGraphNode(p)">
                  <circle
                    :cx="p.x" :cy="p.y"
                    :r="lineageNodeId === p.id ? 8 : 6"
                    :fill="p.graph === 'asset' ? 'var(--info)' : 'var(--accent)'"
                    :stroke="lineageNodeId === p.id ? 'var(--ink)' : 'var(--surface)'"
                    stroke-width="2"
                  />
                  <text :x="p.x + 11" :y="p.y + 4" font-size="11" fill="var(--ink)">{{ p.label }}</text>
                </g>
              </svg>
              <div v-else class="fs-empty-box">请先点击右上角「读取图谱」或「重建双图」以可视化当前任务的资产图与探索图。</div>

              <div v-if="graphData?.nodes?.length" class="fusion-node-groups">
                <div>
                  <span class="fusion-group-title">资产图节点（点击直查血缘）</span>
                  <div class="fusion-node-pills">
                    <button
                      v-for="n in graphLayout.assetNodes"
                      :key="n.id"
                      type="button"
                      class="fusion-node-btn"
                      :class="{ active: lineageNodeId === n.id }"
                      @click="selectGraphNode(n)"
                    >{{ n.kind }} · {{ n.label }}</button>
                  </div>
                </div>
                <div>
                  <span class="fusion-group-title">探索图节点（点击直查血缘）</span>
                  <div class="fusion-node-pills">
                    <button
                      v-for="n in graphLayout.explorationNodes"
                      :key="n.id"
                      type="button"
                      class="fusion-node-btn explore"
                      :class="{ active: lineageNodeId === n.id }"
                      @click="selectGraphNode(n)"
                    >{{ n.kind }} · {{ n.label }}</button>
                  </div>
                </div>
              </div>
            </article>

            <article class="fusion-card">
              <h3>血缘推导链路面板</h3>
              <p class="fusion-hint">选择方向后点击查询，展示从源资产到最终实证节点的逐层推导深度。</p>
              <div class="fusion-inline">
                <input v-model="lineageNodeId" class="fusion-input" style="flex: 1;" placeholder="节点 ID" />
                <select v-model="lineageDirection" class="fusion-input" style="width: 155px;">
                  <option value="both">双向（both）</option>
                  <option value="backward">向上溯源（backward）</option>
                  <option value="forward">向下推导（forward）</option>
                </select>
                <button class="btn primary" :disabled="!!busy" @click="queryLineage">查询血缘</button>
              </div>

              <div v-if="lineageResult?.chain?.length" class="fs-lineage-steps">
                <div v-for="(n, i) in lineageResult.chain" :key="i" class="fs-lineage-card">
                  <div class="fs-lineage-step-badges">
                    <span class="fs-depth-badge">L{{ n.depth }}</span>
                    <span class="fusion-badge" :class="n.graph === 'asset' ? 'ok' : ''">{{ n.graph }}</span>
                    <span class="fusion-tag">{{ n.kind }}</span>
                  </div>
                  <div class="fs-lineage-label">{{ n.label }}</div>
                </div>
              </div>
              <div v-else class="fs-empty-box">
                {{ lineageResult ? "未找到该节点或当前方向无血缘关联边。" : "请在左侧点击任意图节点或输入节点 ID 查询血缘链路。" }}
              </div>
            </article>
          </section>
        </div>

        <!-- TAB 5: HTTP 流量留痕 -->
        <div v-else-if="activeTab === 'traffic'" class="fs-stack">
          <article class="fusion-card">
            <div class="fusion-card-head">
              <div>
                <h3>HTTP 流量留痕导入与四类证据绑定台账</h3>
                <p class="fusion-hint">自动记录每次 <code>http_request</code> 请求，支持从工作区导入、筛选多选并绑定为漏洞的 4 类证据。</p>
              </div>
              <div class="fusion-actions">
                <input v-model="trafficTaskId" class="fs-id-input" placeholder="任务 ID" style="width: 170px;" />
                <button class="btn ghost" :disabled="!!busy" @click="discoverTraffic">发现目录</button>
                <select v-if="trafficDirs.length" v-model="trafficWorkDir" class="fusion-input" style="width: 220px;">
                  <option value="">（扫描全部发现目录）</option>
                  <option v-for="d in trafficDirs" :key="d" :value="d">{{ d }}</option>
                </select>
                <button class="btn ghost" :disabled="!!busy" @click="loadTraffic">↻ 刷新列表</button>
                <button class="btn primary" :disabled="!!busy" @click="importTraffic">导入台账</button>
              </div>
            </div>

            <div v-if="importResult" class="fusion-result good">
              <strong>导入完成：扫描 {{ importResult.scanned_rows }} 行 · 去重 {{ importResult.unique_rows }} 行 · 新增 {{ importResult.imported }} 条留痕记录</strong>
            </div>

            <!-- 内联四类证据快速绑定栏 -->
            <div class="fs-traffic-bindbar">
              <div class="fs-bind-field">
                <label class="fs-ctx-lbl">目标漏洞</label>
                <select v-if="taskFindings.length" v-model="bindFindingId" class="fusion-input">
                  <option value="">（选择目标漏洞）</option>
                  <option v-for="f in taskFindings" :key="f.id" :value="f.id">
                    [{{ f.severity_claimed || "-" }}] {{ f.title }} ({{ f.id.slice(0, 8) }})
                  </option>
                </select>
                <input v-else v-model="bindFindingId" class="fusion-input" placeholder="输入漏洞 ID" />
              </div>

              <div class="fs-bind-field" style="width: 195px;">
                <label class="fs-ctx-lbl">证据角色</label>
                <select class="fusion-input" v-model="bindRole">
                  <option value="proof">proof 利用证明</option>
                  <option value="baseline">baseline 基线对照</option>
                  <option value="verification">verification 复测验证</option>
                  <option value="supporting">supporting 辅助证据</option>
                </select>
              </div>

              <div class="fs-bind-field" style="width: 180px;">
                <label class="fs-ctx-lbl">已选流量 ID</label>
                <input class="fusion-input" v-model="bindIds" placeholder="勾选表格行自动填充" />
              </div>

              <div class="fs-bind-actions">
                <button type="button" class="btn ghost fs-btn-sm" :disabled="!trafficItems.length" @click="selectAllTraffic">全选 ({{ trafficItems.length }})</button>
                <button type="button" class="btn ghost fs-btn-sm" :disabled="!selectedTrafficIds.length" @click="clearTrafficSelection">清空</button>
                <button type="button" class="btn primary" :disabled="!!busy || !bindIds.trim()" @click="bindTraffic">
                  绑定选中流量 ({{ selectedTrafficIds.length }})
                </button>
              </div>
            </div>

            <!-- 流量台账表格 -->
            <div class="fs-table-wrap">
              <table v-if="trafficItems.length" class="fs-table fs-table-click fs-table-fixed">
                <thead>
                  <tr>
                    <th style="width: 38px;">选</th>
                    <th style="width: 82px;">流量 ID</th>
                    <th style="width: 68px;">方法</th>
                    <th style="width: 72px;">状态码</th>
                    <th style="width: 96px;">证据角色</th>
                    <th>请求 URL</th>
                    <th style="width: 100px;">已绑定</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="t in trafficItems.slice(0, 60)"
                    :key="t.id"
                    :class="{ selected: selectedTrafficIds.includes(t.id) }"
                    @click="toggleTrafficSelect(t.id)"
                  >
                    <td @click.stop>
                      <input type="checkbox" class="fs-checkbox" :checked="selectedTrafficIds.includes(t.id)" @change="toggleTrafficSelect(t.id)" />
                    </td>
                    <td><code>{{ t.id.slice(0, 8) }}</code></td>
                    <td><span class="fs-method-badge">{{ t.method }}</span></td>
                    <td><span class="fusion-badge" :class="httpStatusClass(t.status_code)">{{ t.status_code }}</span></td>
                    <td><span class="fusion-tag">{{ t.role || "-" }}</span></td>
                    <td class="fs-td-mono" :title="t.url">{{ t.url }}</td>
                    <td>
                      <span v-if="t.finding_id" class="fusion-badge ok">→ {{ t.finding_id.slice(0, 8) }}</span>
                      <span v-else class="fs-muted-sm">未绑定</span>
                    </td>
                  </tr>
                </tbody>
              </table>
              <div v-else class="fs-empty-box">暂无台账记录。请先开启「流量自动留痕」并在任务中发出 HTTP 请求，再点击上方「导入台账」。</div>
            </div>
          </article>
        </div>

        <!-- TAB 6: CVE 时间流 -->
        <div v-else-if="activeTab === 'intel'" class="fs-intel-workbench">
          <article class="fusion-card">
            <div class="fusion-card-head">
              <div>
                <h3>CVE / CISA KEV 近期情报流</h3>
                <p class="fusion-hint">
                  同步近 {{ configForm.intel_lookback_days || 7 }} 天漏洞情报，复用情报库自动去重。
                  {{ configForm.intel_sync_interval_hours > 0 ? `后台每 ${configForm.intel_sync_interval_hours}h 自动同步` : "当前仅手动触发" }}
                </p>
              </div>
              <div class="fusion-actions">
                <router-link class="btn ghost" to="/intel">查看全部 CVE →</router-link>
                <button class="btn primary" :disabled="!!busy" @click="syncIntel">↻ 立即同步情报</button>
              </div>
            </div>

            <div v-if="syncResult" class="fusion-result" :class="syncResult.errors?.length ? 'warn' : 'good'">
              <strong>同步结果：抓取 {{ syncResult.entry_count }} 条 · 高危快通道 {{ syncResult.fastlane_count }} 条 · 新增入库 {{ syncResult.stored }} 条</strong>
              <span v-for="(e, i) in syncResult.errors || []" :key="i">{{ e }}</span>
            </div>

            <div class="fs-table-wrap">
              <table v-if="recent.length" class="fs-table fs-table-click fs-table-fixed">
                <thead>
                  <tr>
                    <th style="width: 145px;">CVE 编号</th>
                    <th style="width: 64px;">CVSS</th>
                    <th>受影响产品与摘要（点击带入反查）</th>
                  </tr>
                </thead>
                <tbody>
                  <tr v-for="(it, i) in recent.slice(0, 16)" :key="i" @click="prefillTechFromCve(it)">
                    <td>
                      <div class="fs-cell-stack">
                        <code class="fs-cve-code">{{ it.cve_id || it.match_key }}</code>
                        <span v-if="it.kev" class="fusion-badge bad" style="align-self: flex-start;">CISA KEV</span>
                      </div>
                    </td>
                    <td><span class="fusion-badge" :class="cvssBadgeClass(it.cvss)">{{ Number(it.cvss || 0).toFixed(1) }}</span></td>
                    <td><div class="fs-td-ellipsis" :title="it.summary">{{ (it.products || []).slice(0, 3).join(", ") || it.summary }}</div></td>
                  </tr>
                </tbody>
              </table>
              <div v-else class="fs-empty-box">暂无近期同步条目，点击右上角「立即同步情报」获取最新 CVE / KEV。</div>
            </div>
          </article>

          <article class="fusion-card">
            <div class="fusion-card-head">
              <div>
                <h3>资产指纹语义版本反查（version_in_range）</h3>
                <p class="fusion-hint">根据组件版本号判定 CVE 受影响区间，过滤已知安全版本以消除无效排查。</p>
              </div>
            </div>

            <div class="fs-presets-row">
              <span class="fs-muted-sm">示例指纹：</span>
              <button
                v-for="s in INTEL_SAMPLE_TECHS"
                :key="s"
                type="button"
                class="fusion-chip-btn"
                @click="appendSampleTech(s)"
              >+ {{ s }}</button>
            </div>

            <label class="fusion-label">资产技术栈与版本（逗号或换行分隔）
              <textarea v-model="techText" class="fusion-area" rows="3" placeholder="例如 nginx/1.18.0, Spring Boot 2.6.3"></textarea>
            </label>

            <label class="fusion-switch">
              <input type="checkbox" v-model="includeUnaffected" />
              <span><strong>包含版本不受影响项</strong><em>默认仅输出 affected 与 unknown 区间条目，勾选后展示全部命中</em></span>
            </label>

            <div class="fusion-actions">
              <button class="btn primary" :disabled="!!busy" @click="matchIntel">反查匹配 CVE</button>
            </div>

            <div v-if="matchResult" class="fusion-result good">
              <strong>共匹配 {{ matchResult.count }} 条候选 CVE 指纹线索</strong>
            </div>

            <div v-if="matchResult?.hints?.length" class="fs-intel-hits">
              <div v-for="(h, i) in matchResult.hints" :key="i" class="fs-hit-card">
                <div class="fs-hit-top">
                  <code>{{ h.cve_id }}</code>
                  <span class="fusion-badge" :class="h.version_in_range === 'affected' ? 'bad' : h.version_in_range === 'unaffected' ? 'ok' : 'warn'">
                    {{ h.version_in_range === "affected" ? "版本受影响" : h.version_in_range === "unaffected" ? "版本不受影响" : "区间待确认" }}
                  </span>
                </div>
                <div class="fs-hit-meta">
                  <span v-if="h.detected_version">检出版本：<code>v{{ h.detected_version }}</code></span>
                  <span>命中组件：{{ h.matched?.join("、") || "-" }}</span>
                </div>
              </div>
            </div>
          </article>
        </div>

        <!-- TAB 7: 公文报告与复测 -->
        <div v-else-if="activeTab === 'report'" class="fs-stack">
          <!-- 顶部漏洞选择器与 Word 导出栏 -->
          <article class="fusion-card">
            <div class="fs-report-topbar">
              <div class="fs-report-picker">
                <label class="fs-ctx-lbl">目标漏洞</label>
                <select v-if="taskFindings.length" v-model="reportFindingId" class="fusion-input" style="min-width: 280px; flex: 1;" @change="loadRetests">
                  <option value="">（选择当前任务的漏洞）</option>
                  <option v-for="f in taskFindings" :key="f.id" :value="f.id">
                    [{{ f.severity_claimed || "-" }}] {{ f.title }} ({{ f.id.slice(0, 8) }})
                  </option>
                </select>
                <input v-model="reportFindingId" class="fs-id-input" placeholder="或输入漏洞 ID…" style="width: 175px;" />
              </div>

              <div class="fusion-actions">
                <span v-if="retestSummary" class="fusion-pill">
                  复测 {{ retestSummary.total }} 次 · 仍复现 {{ retestSummary.reproduced_count }} / 已修复 {{ retestSummary.fixed_count }}
                </span>
                <button class="btn ghost" :disabled="!!busy" @click="loadReportModel">预览报告结构</button>
                <button class="btn primary" :disabled="!!busy" @click="downloadDocx">📄 导出公文 Word (.docx)</button>
              </div>
            </div>
          </article>

          <!-- 下方双栏：左 复测闭环台账 / 右 公文报告预览面板 -->
          <section class="fs-report-workbench">
            <article class="fusion-card">
              <div class="fusion-card-head">
                <div>
                  <h3>漏洞复测闭环（写入报告第六章）</h3>
                  <p class="fusion-hint">支持手动回归记录或经 SSRF netguard 防护发起单次只读 HTTP 复测探测。</p>
                </div>
                <button type="button" class="btn ghost fs-btn-sm" :disabled="!!busy || !reportFindingId.trim()" @click="loadRetests">↻ 刷新列表</button>
              </div>

              <div class="fusion-form-grid">
                <label class="fusion-label">复测方式
                  <select v-model="retestMode" class="fusion-input">
                    <option value="manual">手动复测录入</option>
                    <option value="http_probe">安全 HTTP 只读探测</option>
                  </select>
                </label>
                <label v-if="retestMode === 'manual'" class="fusion-label">复测结论
                  <select v-model="retestStatus" class="fusion-input">
                    <option value="reproduced">仍可复现（未修复）</option>
                    <option value="fixed">已修复</option>
                    <option value="partial">部分缓解</option>
                    <option value="error">探测异常</option>
                  </select>
                </label>
                <label v-else class="fusion-label">请求方法
                  <select v-model="retestMethod" class="fusion-input">
                    <option value="GET">GET</option>
                    <option value="HEAD">HEAD</option>
                    <option value="OPTIONS">OPTIONS</option>
                    <option value="POST">POST</option>
                  </select>
                </label>
                <label class="fusion-label">目标 URL
                  <input v-model="retestUrl" class="fusion-input" placeholder="留空自动沿用漏洞 target_url" />
                </label>
                <label v-if="retestMode === 'http_probe'" class="fusion-label">命中特征关键字（可选）
                  <input v-model="retestMatchText" class="fusion-input" placeholder="例：uid= 或敏感业务字段" />
                </label>
              </div>

              <label class="fusion-label">复测说明 / 观察摘要
                <input v-model="retestNotes" class="fusion-input" placeholder="填写回归验证现象、状态码差异或补丁确认情况" />
              </label>

              <div class="fusion-actions">
                <button type="button" class="btn primary" :disabled="!!busy || !reportFindingId.trim()" @click="submitRetest">
                  {{ retestMode === "http_probe" ? "⚡ 发起 HTTP 复测并记账" : "保存手动复测记录" }}
                </button>
              </div>

              <div class="fs-table-wrap">
                <table v-if="retestsList.length" class="fs-table">
                  <thead>
                    <tr>
                      <th style="width: 105px;">结论</th>
                      <th style="width: 92px;">方式</th>
                      <th>状态码与观察摘要</th>
                      <th style="width: 72px; text-align: right;">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr v-for="rt in retestsList" :key="rt.id">
                      <td>
                        <span class="fusion-badge" :class="rt.status === 'fixed' ? 'ok' : rt.status === 'reproduced' ? 'bad' : 'warn'">
                          {{ rt.status_label || rt.status }}
                        </span>
                      </td>
                      <td><span class="fusion-tag">{{ rt.mode === "http_probe" ? "HTTP探测" : "手动" }}</span></td>
                      <td>
                        <div class="fs-cell-stack">
                          <span>{{ rt.notes || rt.url || "-" }}</span>
                          <span class="fs-muted-sm">{{ rt.status_code ? `HTTP ${rt.status_code} · ` : "" }}{{ rt.created_at }}</span>
                        </div>
                      </td>
                      <td style="text-align: right;">
                        <button type="button" class="fusion-chip-btn bad" :disabled="!!busy" @click="removeRetest(rt.id)">删除</button>
                      </td>
                    </tr>
                  </tbody>
                </table>
                <div v-else class="fs-empty-box">暂无复测记录。选择目标漏洞后可提交手动结论或发起只读复测。</div>
              </div>
            </article>

            <article class="fusion-card">
              <h3>公文级 Word 报告结构预览</h3>
              <p class="fusion-hint">预览即将写入 Word 公文的封面摘要、目标核对、四类证据绑定统计与修复路线图。</p>

              <template v-if="reportData?.model">
                <div class="fusion-pills">
                  <span class="fusion-pill on">{{ reportData.model.title }}</span>
                  <span class="fusion-pill">等级：{{ reportData.model.severity || "待定" }}</span>
                  <span class="fusion-pill">{{ reportData.model.impact_level }} {{ reportData.model.impact_label }}</span>
                  <span class="fusion-pill">{{ reportData.model.goals?.summary || "未设置目标" }}</span>
                </div>

                <div class="fusion-report-card">
                  <strong>一、漏洞基础元数据</strong>
                  <span>目标资产：<code>{{ reportData.model.target_url }}</code></span>
                  <span>归属单位：{{ reportData.model.owner || "-" }} · 类型：{{ reportData.model.vuln_type }}</span>
                  <span>复核裁决：{{ reportData.model.review?.verdict }}（已复现：{{ reportData.model.review?.reproduced ? "是" : "否" }}）</span>
                </div>

                <div class="fusion-report-card">
                  <strong>二、四类流量证据归档统计</strong>
                  <div class="fs-evidence-bars">
                    <div class="fs-ev-row"><span>baseline 基线</span><strong>{{ reportData.model.traffic?.baseline?.length || 0 }} 条</strong></div>
                    <div class="fs-ev-row"><span>proof 利用证明</span><strong>{{ reportData.model.traffic?.proof?.length || 0 }} 条</strong></div>
                    <div class="fs-ev-row"><span>verification 复测</span><strong>{{ reportData.model.traffic?.verification?.length || 0 }} 条</strong></div>
                    <div class="fs-ev-row"><span>supporting 辅助</span><strong>{{ reportData.model.traffic?.supporting?.length || 0 }} 条</strong></div>
                  </div>
                </div>

                <div class="fusion-report-card">
                  <strong>三、分步修复路线图</strong>
                  <div v-if="(reportData.model.roadmap || []).length" class="fs-roadmap-list">
                    <div v-for="(step, idx) in reportData.model.roadmap" :key="idx" class="fs-roadmap-item">
                      <span class="fs-depth-badge">{{ idx + 1 }}</span>
                      <span>{{ step }}</span>
                    </div>
                  </div>
                  <span v-else class="fs-muted-sm">（暂无自定义修复建议步骤）</span>
                </div>
              </template>
              <div v-else class="fs-empty-box">点击上方「预览报告结构」加载完整公文结构，或直接点击「导出公文 Word (.docx)」。</div>
            </article>
          </section>
        </div>

        <!-- TAB 8: 技能速查手册 -->
        <div v-else-if="activeTab === 'skills'" class="fs-stack">
          <article class="fusion-card">
            <div class="fusion-card-head">
              <div>
                <h3>注入技能速查手册（Worker System Prompt）</h3>
                <p class="fusion-hint">共加载 <strong>{{ skillIndex?.count ?? 0 }}</strong> 篇攻防方法论索引，常驻注入 Worker 上下文以确保主动检索复用。</p>
              </div>
              <div class="fusion-actions">
                <input v-model="skillSearch" class="fs-id-input" placeholder="🔍 关键字筛选技能条目…" style="width: 210px;" />
                <button type="button" class="btn ghost" @click="copySkillBlock">📋 复制全文</button>
              </div>
            </div>
            <pre class="fusion-pre">{{ filteredSkillBlock || "（未匹配到关键字或本地方法论目录为空）" }}</pre>
          </article>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.fusion-studio {
  display: flex;
  flex-direction: column;
  gap: 18px;
  padding-bottom: 28px;
}
.fusion-studio .btn.ghost {
  border-color: var(--border);
  background: var(--surface);
  color: var(--ink-2);
}
.fusion-studio .btn.ghost:hover:not(:disabled) {
  background: var(--bg-soft);
  border-color: var(--border-strong);
  color: var(--ink);
}

/* 顶部全局指挥栏 + 5 维 KPI 矩阵 */
.fs-header-zone {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.fs-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  flex-wrap: wrap;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.fs-title-row {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 6px;
}
.fs-pill-tag {
  font-size: 12.5px;
  font-weight: 600;
  padding: 2px 10px;
  border-radius: 999px;
  background: var(--accent2-bg);
  border: 1px solid color-mix(in srgb, var(--accent2) 30%, var(--border));
  color: var(--accent2-ink);
}
.fs-title-row h2 { margin: 0; font-size: 24px; font-weight: 700; color: var(--ink); letter-spacing: -0.02em; }
.fs-sub { margin: 4px 0 0; color: var(--muted); font-size: 14px; }

.fs-context-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.fs-task-picker {
  display: flex;
  align-items: center;
  gap: 8px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 5px 8px 5px 12px;
  box-shadow: var(--shadow-sm);
}
.fs-ctx-lbl {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
  white-space: nowrap;
}
.fs-select {
  min-width: 210px;
  max-width: 300px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--ink);
  padding: 6px 10px;
  font-size: 13.5px;
}
.fs-id-input {
  width: 145px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--ink);
  padding: 6px 10px;
  font-size: 13.5px;
  font-family: var(--font-mono);
}
.fs-task-meta { display: flex; align-items: center; gap: 6px; }
.fs-meta-pill {
  padding: 3px 10px;
  border-radius: 999px;
  font-size: 13px;
  font-weight: 500;
  background: var(--surface-2);
  border: 1px solid var(--border);
  color: var(--ink-2);
}
.fs-head-actions { display: flex; align-items: center; gap: 8px; }
.fs-btn-sm { padding: 5px 10px; font-size: 13px; }

/* 5-KPI Telemetry Strip */
.fs-kpi-strip {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 12px;
}
.fs-kpi {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
  padding: 14px 16px;
  border-radius: 12px;
  border: 1px solid var(--border);
  background: var(--surface);
  box-shadow: var(--shadow-sm);
  text-align: left;
  cursor: pointer;
  white-space: normal;
  transition: border-color 0.14s ease, box-shadow 0.14s ease, transform 0.12s ease;
}
.fs-kpi:hover {
  border-color: var(--border-strong);
  background: var(--surface);
  box-shadow: var(--shadow);
  transform: translateY(-1px);
}
.fs-kpi.alert {
  border-color: color-mix(in srgb, var(--warn) 45%, var(--border));
  background: color-mix(in srgb, var(--warn) 6%, var(--surface));
}
.fs-kpi-lbl { font-size: 13px; font-weight: 500; color: var(--muted); }
.fs-kpi-val {
  font-size: 24px;
  font-weight: 700;
  line-height: 1.2;
  color: var(--ink);
  font-variant-numeric: tabular-nums;
}
.fs-kpi-val small { font-size: 14px; font-weight: 600; color: var(--muted); }
.fs-kpi-val.ok { color: var(--ok); }
.fs-kpi-val.warn { color: var(--warn); }
.fs-kpi-sub { font-size: 12.5px; color: var(--muted); }

/* Asymmetric 2-Column Studio Body */
.fs-layout {
  display: grid;
  grid-template-columns: 204px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}
.fs-rail {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px;
  display: flex;
  flex-direction: column;
  gap: 16px;
  position: sticky;
  top: 70px;
  box-shadow: var(--shadow-sm);
}
.fs-nav { display: flex; flex-direction: column; gap: 14px; }
.fs-pillar-grp { display: flex; flex-direction: column; gap: 6px; }
.fs-pillar-lbl {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--muted);
  padding-left: 6px;
}
.fs-pillar-tabs { display: flex; flex-direction: column; gap: 4px; }
.fs-tab {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  width: 100%;
  text-align: left;
  padding: 9px 12px;
  border-radius: 8px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--ink-2);
  font-size: 14px;
  font-weight: 500;
  cursor: pointer;
  transition: all 0.12s ease;
}
.fs-tab:hover { background: var(--bg-soft); color: var(--ink); }
.fs-tab.active {
  background: var(--ink);
  color: var(--bg);
  border-color: var(--ink);
  font-weight: 600;
}
.fs-badge {
  font-size: 12.5px;
  font-weight: 700;
  padding: 1px 8px;
  border-radius: 99px;
  background: var(--warn);
  color: #fff;
}
.fs-tab-count {
  font-size: 12.5px;
  font-weight: 600;
  padding: 1px 7px;
  border-radius: 99px;
  background: var(--surface-2);
  color: var(--muted);
}
.fs-tab.active .fs-tab-count {
  background: color-mix(in srgb, var(--bg) 20%, transparent);
  color: var(--bg);
}
.fs-rail-health {
  padding-top: 12px;
  border-top: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.fs-rail-pills { display: flex; flex-wrap: wrap; gap: 5px; }
.fs-mini-pill {
  font-size: 12.5px;
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  color: var(--muted);
}

.fs-main { min-width: 0; display: flex; flex-direction: column; gap: 14px; }
.fs-stack { display: flex; flex-direction: column; gap: 16px; }

/* Card Primitives */
.fusion-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  min-width: 0;
  box-shadow: var(--shadow-sm);
}
.fusion-card h3 { margin: 0; font-size: 16px; font-weight: 700; color: var(--ink); }
.fusion-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.fusion-hint { margin: 3px 0 0; color: var(--muted); font-size: 13.5px; line-height: 1.55; }
.fusion-label { color: var(--ink-2); font-size: 13.5px; font-weight: 500; display: flex; flex-direction: column; gap: 6px; }
.fusion-input, .fusion-area {
  width: 100%;
  box-sizing: border-box;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--ink);
  padding: 8px 12px;
  font-size: 13.5px;
  font-family: var(--font-mono);
}
.fusion-input:focus, .fusion-area:focus { outline: none; border-color: var(--accent); background: var(--surface); }
.fs-input-sm { padding: 6px 10px; font-size: 13px; }
.fusion-area { resize: vertical; line-height: 1.55; }
.fusion-actions, .fusion-inline { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.fusion-actions.end { justify-content: flex-end; }
.fusion-form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(185px, 1fr)); gap: 12px; }

/* Overview Grids */
.fs-defense-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 12px;
}
.fs-defense-card {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  justify-content: space-between;
  gap: 10px;
  padding: 15px 16px;
  border-radius: 12px;
  border: 1px solid var(--border);
  background: var(--surface);
  box-shadow: var(--shadow-sm);
  text-align: left;
  cursor: pointer;
  white-space: normal;
  transition: border-color 0.14s ease, background-color 0.14s ease;
}
.fs-defense-card:hover:not(.static):not(:disabled) {
  border-color: var(--border-strong);
  background: var(--bg-soft);
}
.fs-defense-card.on {
  border-color: color-mix(in srgb, var(--ok) 40%, var(--border));
  background: color-mix(in srgb, var(--ok) 5%, var(--surface));
}
.fs-defense-card.static { cursor: default; }
.fs-def-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.fs-def-top strong { font-size: 15px; color: var(--ink); font-weight: 700; }
.fs-def-desc { margin: 0; font-size: 13px; color: var(--muted); line-height: 1.5; }
.fs-def-action { font-size: 12.5px; font-weight: 600; color: var(--accent-ink); }
.fs-seg-group { display: flex; flex-wrap: wrap; gap: 6px; }
.fs-seg-btn {
  padding: 4px 10px;
  border-radius: 7px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--muted);
  font-size: 12.5px;
  font-weight: 500;
  cursor: pointer;
}
.fs-seg-btn.active {
  background: var(--ink);
  border-color: var(--ink);
  color: var(--bg);
  font-weight: 600;
}

.fs-overview-split {
  display: grid;
  grid-template-columns: 1fr;
  gap: 16px;
  align-items: start;
}

/* Role & Data Tables */
.fs-table-wrap {
  border: 1px solid var(--border);
  border-radius: 10px;
  overflow: auto;
  background: var(--surface);
}
.fs-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 13.5px;
  text-align: left;
}
.fs-table-fixed {
  table-layout: fixed;
}
.fs-cmd-ellipsis {
  display: block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: 13px;
  color: var(--ink);
}
.fs-table th {
  background: var(--bg-soft);
  color: var(--muted);
  font-weight: 600;
  font-size: 13px;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.fs-table td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border-soft);
  color: var(--ink);
  vertical-align: middle;
}
.fs-table tbody tr:last-child td { border-bottom: none; }
.fs-table-click tbody tr { cursor: pointer; transition: background-color 0.1s ease; }
.fs-table-click tbody tr:hover { background: var(--bg-soft); }
.fs-table-click tbody tr.selected { background: var(--accent-bg); }
.fs-role-badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 7px;
  font-family: var(--font-mono);
  font-size: 13px;
  font-weight: 700;
  background: var(--accent-bg);
  color: var(--accent-ink);
  border: 1px solid color-mix(in srgb, var(--accent) 30%, var(--border));
}
.fs-cell-stack { display: flex; flex-direction: column; gap: 3px; }
.fs-muted-sm { font-size: 12.5px; color: var(--muted); }
.fs-td-muted { color: var(--muted); font-size: 13px; max-width: 320px; }
.fs-td-mono {
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--ink);
  max-width: 360px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.fs-td-ellipsis {
  max-width: 320px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  color: var(--ink-2);
}
.fs-td-actions { display: inline-flex; gap: 6px; }
.fs-divider { height: 1px; background: var(--border); }
.fs-section-lbl { font-size: 13px; font-weight: 600; color: var(--muted); }

/* Switches & Modules */
.fusion-switches { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 10px; }
.fusion-switch {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-soft);
  font-size: 13.5px;
  cursor: pointer;
}
.fusion-switch input { margin-top: 3px; accent-color: var(--accent); width: auto; }
.fusion-switch span { display: flex; flex-direction: column; gap: 2px; color: var(--muted); }
.fusion-switch strong { color: var(--ink); font-size: 14px; }
.fusion-switch em { font-style: normal; font-size: 12.5px; line-height: 1.45; }

.fusion-modules { display: grid; grid-template-columns: repeat(auto-fit, minmax(195px, 1fr)); gap: 8px; }
.fusion-module {
  display: flex;
  flex-direction: column;
  gap: 3px;
  padding: 9px 11px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-soft);
  font-size: 12.5px;
  color: var(--muted);
}
.fusion-module strong { color: var(--ink); font-size: 13.5px; }

/* Goals Verdict */
.fs-goal-verdict {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
  padding: 12px 16px;
  border-radius: 10px;
  border: 1px solid var(--border);
  font-size: 14px;
}
.fs-goal-verdict.good { background: var(--ok-bg); border-color: color-mix(in srgb, var(--ok) 35%, var(--border)); }
.fs-goal-verdict.warn { background: var(--warn-bg); border-color: color-mix(in srgb, var(--warn) 35%, var(--border)); }
.fs-verdict-main { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.fs-verdict-meta { display: flex; align-items: center; gap: 12px; color: var(--muted); font-size: 13px; }

/* Gates Sandbox & Split */
.fs-sandbox-bar {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding: 14px;
  border-radius: 10px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
}
.fs-presets-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
.fs-gates-split {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 16px;
  align-items: start;
}

/* Graphs Workbench */
.fs-coverage-bar {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.fs-progress-wrap {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-left: auto;
  font-size: 13px;
  color: var(--ink-2);
}
.fs-progress-track {
  width: 140px;
  height: 8px;
  border-radius: 99px;
  background: var(--surface-2);
  border: 1px solid var(--border);
  overflow: hidden;
}
.fs-progress-fill { height: 100%; background: var(--ok); border-radius: 99px; transition: width 0.25s ease; }
.fs-graph-workbench {
  display: grid;
  grid-template-columns: minmax(0, 1.25fr) minmax(0, 0.95fr);
  gap: 16px;
  align-items: start;
}
.fs-legend { display: flex; align-items: center; gap: 14px; font-size: 13px; color: var(--muted); }
.fs-legend .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; margin-right: 5px; }
.fs-legend .dot.asset { background: var(--info); }
.fs-legend .dot.explore { background: var(--accent); }
.fusion-svg { width: 100%; min-height: 300px; background: var(--bg-soft); border: 1px solid var(--border); border-radius: 10px; }
.fusion-svg-node { cursor: pointer; }
.fusion-node-groups { display: grid; gap: 12px; }
.fusion-group-title { display: block; font-size: 13px; font-weight: 600; color: var(--muted); margin-bottom: 6px; }
.fusion-node-pills { display: flex; flex-wrap: wrap; gap: 6px; }
.fusion-node-btn {
  padding: 5px 12px;
  border-radius: 999px;
  font-size: 13px;
  cursor: pointer;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--ink);
}
.fusion-node-btn.active { border-color: var(--accent); background: var(--accent-bg); color: var(--accent-ink); font-weight: 600; }
.fs-lineage-steps { display: flex; flex-direction: column; gap: 8px; max-height: 440px; overflow: auto; }
.fs-lineage-card {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 11px 13px;
  border-radius: 10px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
}
.fs-lineage-step-badges { display: flex; align-items: center; gap: 8px; }
.fs-depth-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 28px;
  height: 22px;
  padding: 0 7px;
  border-radius: 6px;
  background: var(--ink);
  color: var(--bg);
  font-family: var(--font-mono);
  font-size: 12.5px;
  font-weight: 700;
}
.fs-lineage-label { font-size: 13.5px; font-weight: 600; color: var(--ink); word-break: break-all; }

/* Traffic Inline Bindbar */
.fs-traffic-bindbar {
  display: flex;
  align-items: flex-end;
  gap: 10px;
  flex-wrap: wrap;
  padding: 14px;
  border-radius: 10px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
}
.fs-bind-field {
  display: flex;
  flex-direction: column;
  gap: 5px;
  flex: 1;
  min-width: 165px;
}
.fs-bind-actions { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.fs-checkbox { width: 16px; height: 16px; accent-color: var(--accent); cursor: pointer; }
.fs-method-badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 6px;
  font-family: var(--font-mono);
  font-size: 12.5px;
  font-weight: 700;
  background: var(--info-bg);
  color: var(--info);
}

/* Intel Workbench */
.fs-intel-workbench {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(0, 0.95fr);
  gap: 16px;
  align-items: start;
}
.fs-cve-code { font-weight: 700; color: var(--ink); }
.fs-intel-hits { display: flex; flex-direction: column; gap: 8px; max-height: 360px; overflow: auto; }
.fs-hit-card {
  display: flex;
  flex-direction: column;
  gap: 6px;
  padding: 11px 14px;
  border-radius: 9px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
}
.fs-hit-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.fs-hit-meta { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; font-size: 13px; color: var(--muted); }

/* Report & Retest Workbench */
.fs-report-topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 14px;
  flex-wrap: wrap;
}
.fs-report-picker { display: flex; align-items: center; gap: 10px; flex: 1; flex-wrap: wrap; }
.fs-report-workbench {
  display: grid;
  grid-template-columns: minmax(0, 1.05fr) minmax(0, 0.95fr);
  gap: 16px;
  align-items: start;
}
.fusion-report-card {
  padding: 14px;
  border: 1px solid var(--border);
  border-radius: 10px;
  background: var(--bg-soft);
  display: flex;
  flex-direction: column;
  gap: 6px;
  font-size: 13.5px;
  color: var(--muted);
}
.fusion-report-card strong { color: var(--ink); font-size: 14.5px; margin-bottom: 2px; }
.fs-evidence-bars { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 8px; }
.fs-ev-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 12px;
  border-radius: 8px;
  background: var(--surface);
  border: 1px solid var(--border);
  font-size: 13px;
}
.fs-ev-row strong { margin: 0; font-size: 14px; color: var(--accent-ink); }
.fs-roadmap-list { display: flex; flex-direction: column; gap: 8px; }
.fs-roadmap-item { display: flex; align-items: flex-start; gap: 8px; font-size: 13.5px; color: var(--ink-2); line-height: 1.5; }

/* Shared Pills, Chips, Results, Empty Box, Code Viewer */
.fusion-chip-btn {
  padding: 5px 12px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--ink-2);
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
}
.fusion-chip-btn:hover { background: var(--surface-2); border-color: var(--border-strong); }
.fusion-chip-btn.ok { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 40%, var(--border)); background: var(--ok-bg); }
.fusion-chip-btn.bad { color: var(--danger); border-color: color-mix(in srgb, var(--danger) 40%, var(--border)); background: var(--danger-bg); }
.fusion-pills { display: flex; gap: 8px; flex-wrap: wrap; }
.fusion-pill {
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 4px 12px;
  font-size: 13px;
  color: var(--muted);
  background: var(--bg-soft);
}
.fusion-pill.on { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 45%, var(--border)); background: var(--ok-bg); font-weight: 600; }
.fusion-result {
  display: flex;
  flex-direction: column;
  gap: 5px;
  padding: 12px 14px;
  border-radius: 8px;
  font-size: 13.5px;
  line-height: 1.55;
  background: color-mix(in srgb, var(--accent2) 9%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--accent2) 25%, var(--border));
  color: var(--ink);
}
.fusion-result.good { background: var(--ok-bg); border-color: color-mix(in srgb, var(--ok) 30%, var(--border)); }
.fusion-result.warn { background: var(--warn-bg); border-color: color-mix(in srgb, var(--warn) 30%, var(--border)); }
.fusion-result.bad { background: var(--danger-bg); border-color: color-mix(in srgb, var(--danger) 30%, var(--border)); }
.fusion-alert { padding: 11px 14px; border-radius: 8px; font-size: 13.5px; font-weight: 500; border: 1px solid var(--border); }
.fusion-alert.ok { background: var(--ok-bg); color: var(--ok); border-color: color-mix(in srgb, var(--ok) 35%, var(--border)); }
.fusion-alert.bad { background: var(--danger-bg); color: var(--danger); border-color: color-mix(in srgb, var(--danger) 35%, var(--border)); }
.fusion-tag { color: var(--accent-ink); font-family: var(--font-mono); font-size: 13px; flex: none; }
.fusion-badge { padding: 2px 10px; border-radius: 999px; font-size: 12.5px; font-weight: 600; flex: none; border: 1px solid var(--border); white-space: nowrap; }
.fusion-badge.ok { background: var(--ok-bg); color: var(--ok); border-color: color-mix(in srgb, var(--ok) 40%, var(--border)); }
.fusion-badge.warn { background: var(--warn-bg); color: var(--warn); border-color: color-mix(in srgb, var(--warn) 40%, var(--border)); }
.fusion-badge.bad { background: var(--danger-bg); color: var(--danger); border-color: color-mix(in srgb, var(--danger) 40%, var(--border)); }
.fs-empty-box {
  padding: 20px;
  border: 1px dashed var(--border);
  border-radius: 10px;
  text-align: center;
  color: var(--muted);
  font-size: 13.5px;
  background: var(--bg-soft);
}
.fusion-pre {
  margin: 0;
  padding: 14px 16px;
  max-height: 480px;
  overflow: auto;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 10px;
  color: var(--ink);
  font-family: var(--font-mono);
  font-size: 13px;
  line-height: 1.6;
  white-space: pre-wrap;
}
code { font-family: var(--font-mono); color: var(--accent-ink); }

@media (min-width: 1620px) {
  .fs-overview-split { grid-template-columns: minmax(0, 1.05fr) minmax(0, 1fr); }
  .fusion-switches { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 1120px) {
  .fs-defense-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .fusion-switches { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 1040px) {
  .fs-layout { grid-template-columns: 1fr; }
  .fs-rail { position: static; }
  .fs-gates-split,
  .fs-graph-workbench,
  .fs-intel-workbench,
  .fs-report-workbench { grid-template-columns: 1fr; }
}
@media (max-width: 960px) {
  .fs-kpi-strip { grid-template-columns: repeat(3, minmax(0, 1fr)); }
}
@media (max-width: 720px) {
  .fs-kpi-strip,
  .fs-defense-grid,
  .fusion-switches,
  .fs-evidence-bars { grid-template-columns: 1fr; }
}
</style>
