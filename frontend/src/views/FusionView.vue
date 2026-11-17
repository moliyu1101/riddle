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

const hardGates = computed(() => {
  const c = configForm.value || {};
  return [
    { key: "evidence_gate_hard", label: "证据硬闸门", on: !!c.evidence_gate_hard },
    { key: "scope_guard_hard", label: "范围硬守卫", on: !!c.scope_guard_hard },
    { key: "traffic_enabled", label: "流量留痕", on: !!c.traffic_enabled },
  ];
});

const selectedTaskObj = computed(() => tasks.value.find((t) => t.id === selectedTaskId.value) || null);

const graphLayout = computed(() => {
  const nodes = graphData.value?.nodes || [];
  const edges = graphData.value?.edges || [];
  const byGraph = {
    asset: nodes.filter((n) => n.graph === "asset"),
    exploration: nodes.filter((n) => n.graph === "exploration"),
  };
  const points = [];
  Object.entries(byGraph).forEach(([g, list], gi) => {
    list.slice(0, 40).forEach((n, i) => {
      points.push({
        id: n.id,
        label: (n.label || n.kind).slice(0, 14),
        kind: n.kind,
        x: 30 + gi * 300 + (i % 4) * 68,
        y: 32 + Math.floor(i / 4) * 34,
        graph: g,
      });
    });
  });
  const coords = Object.fromEntries(points.map((p) => [p.id, p]));
  const lines = edges.filter((e) => coords[e.src] && coords[e.dst]).slice(0, 60).map((e) => ({
    x1: coords[e.src].x + 8, y1: coords[e.src].y, x2: coords[e.dst].x + 8, y2: coords[e.dst].y, kind: e.kind,
  }));
  return { points, lines, assetNodes: byGraph.asset, explorationNodes: byGraph.exploration };
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
    <header class="fs-head">
      <div>
        <div class="fs-title-row">
          <h2>融合治理与拦截审批</h2>
          <span class="fs-chip">四大支柱 · 八大模块</span>
        </div>
        <p class="fs-sub">目标闸门 · 证据闸门 · 范围守卫 · 情报时间流 · 资产双图 · 流量留痕 · 公文报告 · 角色路由</p>
      </div>
      <div class="fs-head-actions">
        <button class="fs-btn ghost" :disabled="busy === 'reload'" @click="load">
          {{ busy === "reload" ? "刷新中…" : "↻ 刷新全部状态" }}
        </button>
        <router-link class="fs-btn ghost" to="/">← 返回仪表盘</router-link>
      </div>
    </header>

    <div class="fs-layout">
      <!-- Left Vertical Governance Rail -->
      <aside class="fs-rail" aria-label="融合模块导航与任务选择">
        <div class="fs-rail-block">
          <label class="fs-rail-label" for="fusion-task-select">当前操作任务</label>
          <select id="fusion-task-select" class="fs-select" :value="selectedTaskId" @change="onSelectTask($event.target.value)">
            <option value="">（手动输入任务 ID）</option>
            <option v-for="t in tasks" :key="t.id" :value="t.id">
              {{ t.name }} ({{ t.id.slice(0, 8) }}){{ t.goal_summary?.configured ? ` · ${t.goal_summary.summary}` : "" }}
            </option>
          </select>
        </div>

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
              </button>
            </div>
          </div>
        </nav>
      </aside>

      <!-- Right Active Module Canvas -->
      <div class="fs-main">
        <div v-if="notice" class="fusion-alert ok">{{ notice }}</div>
        <div v-if="error" class="fusion-alert bad">{{ error }}</div>

        <div v-if="loading" class="fusion-card">正在读取融合层状态…</div>

    <!-- 总览与配置 -->
    <div v-else-if="activeTab === 'overview'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>核心拦截与后台同步快捷控制（点击即保存并即时生效）</h3>
        <div class="fusion-quick-gates">
          <button
            v-for="g in hardGates"
            :key="g.key"
            type="button"
            class="fusion-gate-btn"
            :class="{ on: g.on }"
            :disabled="!!busy"
            @click="quickToggleGate(g.key)"
          >
            <strong>{{ g.label }}</strong>
            <span>{{ g.on ? "已开启" : "已关闭（点击开启）" }}</span>
          </button>
          <div class="fusion-interval-bar">
            <span>情报后台自动同步周期：</span>
            <button
              v-for="p in INTERVAL_PRESETS"
              :key="p.value"
              type="button"
              class="fusion-chip-btn"
              :class="{ active: Number(configForm.intel_sync_interval_hours || 0) === p.value }"
              :disabled="!!busy"
              @click="quickSetInterval(p.value)"
            >{{ p.label }}</button>
          </div>
        </div>
      </article>

      <article class="fusion-card wide">
        <h3>运行状态</h3>
        <div class="fusion-pills">
          <span v-for="g in hardGates" :key="g.label" class="fusion-pill" :class="g.on ? 'on' : 'off'">{{ g.label }}：{{ g.on ? "已启用" : "仅留痕" }}</span>
          <span class="fusion-pill">目标 {{ status?.goal_count ?? 0 }} 条</span>
          <span class="fusion-pill">情报 {{ status?.intel_feed_count ?? 0 }} 条</span>
          <span class="fusion-pill">方法论 {{ skillIndex?.count ?? 0 }} 篇</span>
          <span class="fusion-pill">配置来源 {{ cfgMeta?.source === "db" ? "设置页" : ".env" }}</span>
        </div>
        <div class="fusion-modules">
          <div v-for="m in status?.modules || []" :key="m.id" class="fusion-module"><strong>{{ m.name }}</strong><span>{{ m.desc }}</span></div>
        </div>
      </article>

      <article class="fusion-card wide">
        <h3>融合配置（保存后即时生效，无需重启）</h3>
        <p class="fusion-hint">开关写入 SystemSettings.defaults.fusion（与「系统配置 → 融合闸门」双向同步）；密钥类配置仍只走 .env，不落库、不回显明文。</p>
        <div class="fusion-switches">
          <label v-for="f in BOOL_FIELDS" :key="f.key" class="fusion-switch">
            <input type="checkbox" v-model="configForm[f.key]" />
            <span><strong>{{ f.label }}</strong><em>{{ f.desc }}</em></span>
          </label>
        </div>
        <div class="fusion-form-grid">
          <label class="fusion-label">情报回溯天数<input class="fusion-input" type="number" min="1" max="90" v-model.number="configForm.intel_lookback_days" /></label>
          <label class="fusion-label">自动同步间隔（小时，0=关闭）<input class="fusion-input" type="number" min="0" max="720" v-model.number="configForm.intel_sync_interval_hours" /></label>
          <label class="fusion-label">高危快通道 CVSS<input class="fusion-input" type="number" min="0" max="10" step="0.1" v-model.number="configForm.intel_fastlane_cvss" /></label>
          <label class="fusion-label">请求超时（秒）<input class="fusion-input" type="number" min="1" max="60" v-model.number="configForm.intel_timeout" /></label>
        </div>
        <div class="fusion-form-grid">
          <label v-for="r in cfgMeta?.config?.roles || []" :key="r" class="fusion-label">{{ r }} 模型覆盖
            <input class="fusion-input" v-model="roleInputs[r]" placeholder="留空沿用默认模型" />
          </label>
        </div>
        <div class="fusion-actions"><button class="btn primary" :disabled="!!busy" @click="saveConfig">保存配置</button></div>
      </article>

      <article class="fusion-card wide">
        <h3>按角色模型路由</h3>
        <div class="fusion-modules">
          <div v-for="r in status?.role_routing || []" :key="r.role" class="fusion-module">
            <strong>{{ r.role }}</strong><span>{{ r.model || "沿用默认模型" }}｜{{ r.hint }}</span>
          </div>
        </div>
      </article>
    </div>

    <!-- 目标闸门 -->
    <div v-else-if="activeTab === 'goals'" class="fusion-grid">
      <article class="fusion-card wide">
        <div class="fusion-card-head">
          <div>
            <h3>目标闸门（可视化编辑）</h3>
            <p class="fusion-hint">目标必须带可核验验收标准；能力型目标只认 high/critical 实证；未全达成时终态强制 incomplete。</p>
          </div>
          <button type="button" class="btn ghost" @click="toggleGoalsJsonMode">
            {{ goalsJsonMode ? "切回可视化编辑" : "切换 JSON 源码编辑" }}
          </button>
        </div>

        <div class="fusion-inline">
          <label class="fusion-label" style="min-width: 240px;">任务 ID
            <input v-model="taskId" class="fusion-input" placeholder="从上方选择任务或直接输入任务 ID" />
          </label>
        </div>

        <FusionGoalEditor v-if="!goalsJsonMode" v-model="goalRows" :evaluation="goalResult" :suggest-context="{ task_id: taskId.trim() }" />
        <template v-else>
          <label class="fusion-label">目标清单（JSON 数组）</label>
          <textarea v-model="goalsText" class="fusion-area" rows="10"></textarea>
        </template>

        <div class="fusion-actions">
          <button class="btn primary" :disabled="!!busy" @click="saveGoals">保存目标</button>
          <button class="btn ghost" :disabled="!!busy" @click="evaluateGoals">核对达成</button>
        </div>
        <div v-if="goalResult" class="fusion-result" :class="goalResult.goal_met ? 'good' : 'warn'">
          <strong>{{ goalResult.summary }} → {{ goalResult.terminal_state }}</strong>
          <span v-if="goalResult.unmet_ids?.length">未达成：{{ goalResult.unmet_ids.join("、") }}</span>
          <span>已提交 finding {{ goalResult.finding_count ?? 0 }} 条</span>
        </div>
      </article>
    </div>

    <!-- 证据与范围 -->
    <div v-else-if="activeTab === 'gates'" class="fusion-grid">
      <article class="fusion-card">
        <div class="fusion-card-head">
          <h3>证据闸门试算</h3>
          <button type="button" class="btn ghost" @click="toggleEvidenceJsonMode">
            {{ evidenceJsonMode ? "表单模式" : "JSON 批量模式" }}
          </button>
        </div>
        <p class="fusion-hint">critical 要求 L3+、high 要求 L2+，且必须带机械可复现凭据。</p>

        <label v-if="taskFindings.length" class="fusion-label">从当前任务漏洞填充
          <select class="fusion-input" :value="selectedSampleFindingId" @change="fillEvidenceFromSample($event.target.value)">
            <option value="">（选择一条漏洞填充表单）</option>
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
          <label class="fusion-label">PoC 命令（curl / 可执行命令）
            <input v-model="evidenceForm.poc" class="fusion-input" />
          </label>
          <label class="fusion-label">原始 HTTP 请求包
            <textarea v-model="evidenceForm.raw_request" class="fusion-area" rows="3"></textarea>
          </label>
          <label class="fusion-label">原始响应 / 命中文案
            <textarea v-model="evidenceForm.raw_response" class="fusion-area" rows="3"></textarea>
          </label>
        </template>
        <template v-else>
          <label class="fusion-label">finding（JSON 对象或数组）</label>
          <textarea v-model="findingText" class="fusion-area" rows="10"></textarea>
        </template>

        <div class="fusion-actions"><button class="btn ghost" :disabled="!!busy" @click="checkEvidence">试算</button></div>
        <div v-if="evidenceResult" class="fusion-result" :class="evidenceResult.allowed === false || evidenceResult.blocked ? 'bad' : 'good'">
          <template v-if="evidenceResult.rows"><strong>共 {{ evidenceResult.total }} 条，通过 {{ evidenceResult.passed }}，拦截 {{ evidenceResult.blocked }}</strong></template>
          <template v-else>
            <strong>{{ evidenceResult.allowed ? "通过" : "拦截" }} · {{ evidenceResult.impact_level }} {{ evidenceResult.impact_label }}</strong>
            <span>凭据：{{ evidenceResult.evidence?.join("、") || "无" }}</span>
            <span v-for="(r, i) in evidenceResult.reasons || []" :key="i">{{ r }}</span>
          </template>
        </div>
      </article>

      <article class="fusion-card">
        <div class="fusion-card-head">
          <h3>范围守卫试算</h3>
          <button type="button" class="btn ghost" @click="toggleScopeJsonMode">
            {{ scopeJsonMode ? "表单模式" : "JSON 模式" }}
          </button>
        </div>
        <p class="fusion-hint">own 允许写回，source 只读共享，foreign 与基础设施地址拒绝。</p>
        <div class="fusion-inline">
          <button type="button" class="btn ghost" :disabled="!selectedTaskObj" @click="extractRootsFromTask">从所选任务自动提取根域</button>
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
          <textarea v-model="scopeText" class="fusion-area" rows="6"></textarea>
        </template>

        <div class="fusion-actions"><button class="btn ghost" :disabled="!!busy" @click="checkScope">判定</button></div>
        <div v-if="scopeResult" class="fusion-result" :class="scopeResult.allowed ? 'good' : 'bad'">
          <strong>{{ scopeResult.classification }} · {{ scopeResult.allowed ? "允许写回" : "拒绝写回" }}</strong>
          <span>{{ scopeResult.reason || "在授权范围内" }}</span>
        </div>
      </article>

      <article class="fusion-card wide">
        <div class="fusion-card-head">
          <div>
            <h3>命令三层拦截试算与审批队列（deny / judge / ask）</h3>
            <p class="fusion-hint">第一层 deny 自毁硬拒；第二层 judge 窄视野防注入研判（严格 JSON）；第三层 ask 需人工审批放行或拒绝。</p>
          </div>
          <div class="fusion-inline">
            <select v-model="interceptFilter" class="fusion-input" style="width: 140px;" @change="loadIntercepts">
              <option value="">全部审批状态</option>
              <option value="pending">仅待审批</option>
              <option value="approved">已批准</option>
              <option value="denied">已拒绝</option>
            </select>
            <button type="button" class="btn ghost" :disabled="!!busy" @click="loadIntercepts">刷新台账</button>
          </div>
        </div>
        <div class="fusion-inline">
          <select v-model="interceptSrcType" class="fusion-input" style="width: 130px;">
            <option value="edusrc">edusrc</option>
            <option value="enterprise">enterprise</option>
          </select>
          <input v-model="interceptCmd" class="fusion-input" style="flex: 1; min-width: 260px;" placeholder="输入 shell 命令测试三层裁决，例如 nc -lvp 4444 / sqlmap --os-shell / mysql -e 'DELETE FROM tmp_t'" />
          <button type="button" class="btn primary" :disabled="!!busy" @click="checkIntercept">三层试算并记账</button>
        </div>
        <div v-if="interceptResult" class="fusion-result" :class="interceptResult.allowed ? 'good' : interceptResult.action === 'ask' ? 'warn' : 'bad'">
          <strong>层 {{ interceptResult.tier }} → 动作 {{ interceptResult.action }}（{{ interceptResult.allowed ? "放行" : "拦截/待批" }}）</strong>
          <span>规则：{{ interceptResult.rule || "allow" }} · {{ interceptResult.reason }}</span>
        </div>
        <div class="fusion-list">
          <div v-for="item in interceptItems" :key="item.id" class="fusion-row">
            <span class="fusion-badge" :class="item.status === 'approved' ? 'ok' : item.status === 'pending' ? 'warn' : 'bad'">{{ item.status }}</span>
            <span class="fusion-tag">{{ item.tier }}/{{ item.action }}</span>
            <span class="fusion-muted-ellipsis" :title="item.command"><code>{{ item.command }}</code> · {{ item.reason }}</span>
            <template v-if="item.status === 'pending'">
              <button type="button" class="fusion-chip-btn" :disabled="!!busy" @click="decideIntercept(item.id, 'approve')">批准</button>
              <button type="button" class="fusion-chip-btn" :disabled="!!busy" @click="decideIntercept(item.id, 'deny')">拒绝</button>
            </template>
          </div>
          <p v-if="!interceptItems.length" class="fusion-hint">暂无拦截或待审批命令记录。</p>
        </div>
      </article>
    </div>

    <!-- 情报时间流 -->
    <div v-else-if="activeTab === 'intel'" class="fusion-grid">
      <article class="fusion-card">
        <h3>情报时间流</h3>
        <p class="fusion-hint">
          同步近 {{ configForm.intel_lookback_days || 7 }} 天 CVE 与在野利用清单，结果复用情报库去重。
          当前后台周期：<strong>{{ configForm.intel_sync_interval_hours > 0 ? `每 ${configForm.intel_sync_interval_hours} 小时自动同步` : "关闭（仅手动同步）" }}</strong>
        </p>
        <div class="fusion-actions">
          <button class="btn primary" :disabled="!!busy" @click="syncIntel">同步情报</button>
          <router-link class="btn ghost" to="/intel">去作战情报库查看全部 CVE →</router-link>
        </div>
        <div v-if="syncResult" class="fusion-result" :class="syncResult.errors?.length ? 'warn' : 'good'">
          <strong>条目 {{ syncResult.entry_count }}，快通道 {{ syncResult.fastlane_count }}，入库 {{ syncResult.stored }}</strong>
          <span v-for="(e, i) in syncResult.errors || []" :key="i">{{ e }}</span>
        </div>
        <div class="fusion-list">
          <div v-for="(it, i) in recent.slice(0, 16)" :key="i" class="fusion-row">
            <span class="fusion-tag" :class="it.kev ? 'bad' : ''">{{ it.cve_id || it.match_key }}</span>
            <span>CVSS {{ Number(it.cvss || 0).toFixed(1) }}</span>
            <span v-if="it.kev" class="fusion-tag bad">KEV</span>
            <span class="fusion-muted-ellipsis">{{ (it.products || []).slice(0, 3).join(", ") || it.summary }}</span>
          </div>
          <p v-if="!recent.length" class="fusion-hint">暂无条目。</p>
        </div>
      </article>
      <article class="fusion-card">
        <h3>资产指纹反查（含语义版本区间判定）</h3>
        <label class="fusion-label">资产指纹与版本（支持如 nginx/1.18.0, Spring Boot 2.6.3）</label>
        <input v-model="techText" class="fusion-input" />
        <label class="fusion-switch">
          <input type="checkbox" v-model="includeUnaffected" />
          <span><strong>包含版本不受影响项</strong><em>默认仅展示 affected 与 unknown 区间条目，勾选后显示全部</em></span>
        </label>
        <div class="fusion-actions"><button class="btn ghost" :disabled="!!busy" @click="matchIntel">反查</button></div>
        <div v-if="matchResult" class="fusion-result good"><strong>命中 {{ matchResult.count }} 条 hint</strong></div>
        <div class="fusion-list">
          <div v-for="(h, i) in matchResult?.hints || []" :key="i" class="fusion-row">
            <span class="fusion-tag">{{ h.cve_id }}</span>
            <span class="fusion-badge" :class="h.version_in_range === 'affected' ? 'bad' : h.version_in_range === 'unaffected' ? 'ok' : 'warn'">
              {{ h.version_in_range === "affected" ? "版本受影响" : h.version_in_range === "unaffected" ? "版本不受影响" : "区间未知" }}
            </span>
            <span v-if="h.detected_version" class="fusion-tag">v{{ h.detected_version }}</span>
            <span>{{ h.matched?.join("、") }}</span>
          </div>
        </div>
      </article>
    </div>

    <!-- 双图架构 -->
    <div v-else-if="activeTab === 'graphs'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>双图架构（旁路镜像，支持点击节点查询血缘）</h3>
        <div class="fusion-inline">
          <input v-model="graphTaskId" class="fusion-input" placeholder="任务 ID" />
          <button class="btn primary" :disabled="!!busy" @click="rebuildGraph">重建双图</button>
          <button class="btn ghost" :disabled="!!busy" @click="loadGraph">读取</button>
        </div>
        <div v-if="graphData" class="fusion-pills">
          <span class="fusion-pill">节点 {{ graphData.nodes.length }}</span>
          <span class="fusion-pill">边 {{ graphData.edges.length }}</span>
          <span class="fusion-pill">资产覆盖 {{ (graphData.coverage.ratio * 100).toFixed(1) }}%（{{ graphData.coverage.covered }}/{{ graphData.coverage.asset_nodes }}）</span>
        </div>
        <svg v-if="graphData" class="fusion-svg" viewBox="0 0 600 260" role="img" aria-label="双图节点关系图">
          <line v-for="(l, i) in graphLayout.lines" :key="'l' + i" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" stroke="var(--border-strong)" stroke-width="0.6" />
          <g v-for="(p, i) in graphLayout.points" :key="'p' + i" class="fusion-svg-node" @click="selectGraphNode(p)">
            <circle
              :cx="p.x" :cy="p.y"
              :r="lineageNodeId === p.id ? 7 : 5"
              :fill="p.graph === 'asset' ? 'var(--info)' : 'var(--accent)'"
              :stroke="lineageNodeId === p.id ? 'var(--ink)' : 'none'"
              stroke-width="1.5"
            />
            <text :x="p.x + 9" :y="p.y + 3" font-size="9" fill="var(--ink)">{{ p.label }}</text>
          </g>
        </svg>

        <div v-if="graphData?.nodes?.length" class="fusion-node-groups">
          <div>
            <span class="fusion-group-title">资产图节点（点击查询血缘）</span>
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
            <span class="fusion-group-title">探索图节点（点击查询血缘）</span>
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

      <article class="fusion-card wide">
        <h3>血缘回溯</h3>
        <p class="fusion-hint">点击上方任意图节点或手动输入节点 ID，沿 proves / yields / derived_from 追溯血缘链。</p>
        <div class="fusion-inline">
          <input v-model="lineageNodeId" class="fusion-input" placeholder="节点 ID" />
          <select v-model="lineageDirection" class="fusion-input" style="width: 150px;">
            <option value="both">双向（both）</option>
            <option value="backward">向上溯源（backward）</option>
            <option value="forward">向下推导（forward）</option>
          </select>
          <button class="btn ghost" :disabled="!!busy" @click="queryLineage">查询血缘</button>
        </div>
        <div class="fusion-list">
          <div v-for="(n, i) in lineageResult?.chain || []" :key="i" class="fusion-row">
            <span class="fusion-tag">L{{ n.depth }}</span>
            <span class="fusion-tag">{{ n.graph }}</span>
            <span>{{ n.kind }}｜{{ n.label }}</span>
          </div>
          <p v-if="lineageResult && !lineageResult.chain?.length" class="fusion-hint">未找到该节点或无血缘关联。</p>
        </div>
      </article>
    </div>

    <!-- 流量留痕 -->
    <div v-else-if="activeTab === 'traffic'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>流量留痕与四类证据绑定</h3>
        <p class="fusion-hint">启用「流量留痕」开关后，每次 http_request 会在工作区写结构化 JSONL；勾选下方流量记录后直接绑定到漏洞。</p>
        <div class="fusion-inline">
          <input v-model="trafficTaskId" class="fusion-input" placeholder="任务 ID" />
          <select v-if="trafficDirs.length" v-model="trafficWorkDir" class="fusion-input" style="width: 260px;">
            <option value="">（扫描全部发现目录）</option>
            <option v-for="d in trafficDirs" :key="d" :value="d">{{ d }}</option>
          </select>
          <button class="btn ghost" :disabled="!!busy" @click="discoverTraffic">发现工作目录</button>
          <button class="btn primary" :disabled="!!busy" @click="importTraffic">导入台账</button>
          <button class="btn ghost" :disabled="!!busy" @click="loadTraffic">刷新列表</button>
        </div>
        <div v-if="trafficDirs.length" class="fusion-hint">发现目录：{{ trafficDirs.join("、") }}</div>
        <div v-if="importResult" class="fusion-result good">
          <strong>扫描 {{ importResult.scanned_rows }} 行，去重 {{ importResult.unique_rows }} 行，新增 {{ importResult.imported }} 行</strong>
        </div>

        <div v-if="trafficItems.length" class="fusion-inline">
          <button type="button" class="btn ghost" @click="selectAllTraffic">全选 ({{ trafficItems.length }})</button>
          <button type="button" class="btn ghost" @click="clearTrafficSelection">清空选择</button>
          <span class="fusion-hint">已选 {{ selectedTrafficIds.length }} 条</span>
        </div>

        <div class="fusion-list">
          <label v-for="t in trafficItems.slice(0, 60)" :key="t.id" class="fusion-row fusion-check-row">
            <input type="checkbox" :checked="selectedTrafficIds.includes(t.id)" @change="toggleTrafficSelect(t.id)" />
            <span class="fusion-tag">{{ t.id.slice(0, 8) }}</span>
            <span>{{ t.method }} {{ t.status_code }}</span>
            <span class="fusion-tag">{{ t.role }}</span>
            <span class="fusion-muted-ellipsis">{{ t.url }}</span>
            <span v-if="t.finding_id" class="fusion-tag">→ {{ t.finding_id.slice(0, 8) }}</span>
          </label>
          <p v-if="!trafficItems.length" class="fusion-hint">暂无台账记录，先启用开关并产生请求，再导入。</p>
        </div>
      </article>

      <article class="fusion-card wide">
        <h3>绑定到 finding</h3>
        <div class="fusion-form-grid">
          <label class="fusion-label">选择目标漏洞
            <select v-if="taskFindings.length" v-model="bindFindingId" class="fusion-input">
              <option value="">（选择漏洞或右侧手动输入）</option>
              <option v-for="f in taskFindings" :key="f.id" :value="f.id">
                [{{ f.severity_claimed || "-" }}] {{ f.title }} ({{ f.id.slice(0, 8) }})
              </option>
            </select>
            <input v-model="bindFindingId" class="fusion-input" placeholder="漏洞 ID" />
          </label>
          <label class="fusion-label">已选流量 ID（勾选上方自动填充，或手动逗号分隔）
            <input class="fusion-input" v-model="bindIds" placeholder="勾选上方流量行自动汇总" />
          </label>
          <label class="fusion-label">证据角色
            <select class="fusion-input" v-model="bindRole">
              <option value="baseline">baseline 基线请求</option>
              <option value="proof">proof 利用证明</option>
              <option value="verification">verification 复测验证</option>
              <option value="supporting">supporting 辅助证据</option>
            </select>
          </label>
        </div>
        <div class="fusion-actions"><button class="btn primary" :disabled="!!busy" @click="bindTraffic">绑定选中流量</button></div>
      </article>
    </div>

    <!-- 公文报告 -->
    <div v-else-if="activeTab === 'report'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>公文级 Word 报告</h3>
        <p class="fusion-hint">封面 / 目录域 / 页眉页脚页码 / 严重度着色 / 目标达成情况 / 四类流量证据 / 复测记录 / 修复路线图。</p>
        <div class="fusion-inline">
          <select v-if="taskFindings.length" v-model="reportFindingId" class="fusion-input" style="width: 300px;" @change="loadRetests">
            <option value="">（选择当前任务的漏洞）</option>
            <option v-for="f in taskFindings" :key="f.id" :value="f.id">
              [{{ f.severity_claimed || "-" }}] {{ f.title }} ({{ f.id.slice(0, 8) }})
            </option>
          </select>
          <input v-model="reportFindingId" class="fusion-input" placeholder="漏洞 ID" />
          <button class="btn ghost" :disabled="!!busy" @click="loadReportModel">预览结构</button>
          <button class="btn primary" :disabled="!!busy" @click="downloadDocx">下载 docx</button>
        </div>

        <div class="fusion-subcard">
          <div class="fusion-card-head">
            <div>
              <strong>漏洞复测闭环（写入报告「六、复测记录」）</strong>
              <p class="fusion-hint">支持手动登记结论或经 SSRF netguard 保护发起单次只读 HTTP 复测探测。</p>
            </div>
            <span v-if="retestSummary" class="fusion-pill">
              共 {{ retestSummary.total }} 次 · 仍复现 {{ retestSummary.reproduced_count }} / 已修复 {{ retestSummary.fixed_count }}
            </span>
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
              {{ retestMode === "http_probe" ? "⚡ 发起 HTTP 复测并记录" : "保存手动复测记录" }}
            </button>
            <button type="button" class="btn ghost" :disabled="!!busy || !reportFindingId.trim()" @click="loadRetests">刷新复测列表</button>
          </div>
          <div v-if="retestsList.length" class="fusion-list">
            <div v-for="rt in retestsList" :key="rt.id" class="fusion-row">
              <span class="fusion-badge" :class="rt.status === 'fixed' ? 'ok' : rt.status === 'reproduced' ? 'bad' : 'warn'">
                {{ rt.status_label || rt.status }}
              </span>
              <span class="fusion-tag">{{ rt.mode === "http_probe" ? "HTTP探测" : "手动" }}</span>
              <span v-if="rt.status_code">HTTP {{ rt.status_code }}</span>
              <span class="fusion-muted-ellipsis">{{ rt.notes || rt.url || "-" }}</span>
              <span>{{ rt.created_at }}</span>
              <button type="button" class="fusion-chip-btn" :disabled="!!busy" @click="removeRetest(rt.id)">删除</button>
            </div>
          </div>
        </div>

        <template v-if="reportData?.model">
          <div class="fusion-pills">
            <span class="fusion-pill on">{{ reportData.model.title }}</span>
            <span class="fusion-pill">等级：{{ reportData.model.severity || "待定" }}</span>
            <span class="fusion-pill">{{ reportData.model.impact_level }} {{ reportData.model.impact_label }}</span>
            <span class="fusion-pill">{{ reportData.model.goals?.summary || "未设置目标" }}</span>
          </div>

          <div class="fusion-report-grid">
            <div class="fusion-report-card">
              <strong>基本信息</strong>
              <span>目标：{{ reportData.model.target_url }}</span>
              <span>单位：{{ reportData.model.owner }} · 类型：{{ reportData.model.vuln_type }}</span>
              <span>复核状态：{{ reportData.model.review?.verdict }}（已复现：{{ reportData.model.review?.reproduced ? "是" : "否" }}）</span>
            </div>
            <div class="fusion-report-card">
              <strong>四类流量证据统计</strong>
              <span>baseline 基线：{{ reportData.model.traffic?.baseline?.length || 0 }} 条</span>
              <span>proof 利用证明：{{ reportData.model.traffic?.proof?.length || 0 }} 条</span>
              <span>verification 复测：{{ reportData.model.traffic?.verification?.length || 0 }} 条</span>
              <span>supporting 辅助：{{ reportData.model.traffic?.supporting?.length || 0 }} 条</span>
            </div>
            <div class="fusion-report-card wide">
              <strong>修复路线图摘要</strong>
              <span v-for="(step, idx) in reportData.model.roadmap || []" :key="idx">{{ idx + 1 }}. {{ step }}</span>
            </div>
          </div>
        </template>
      </article>
    </div>

    <!-- 技能速查 -->
    <div v-else-if="activeTab === 'skills'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>技能速查块（已常驻注入 worker system prompt）</h3>
        <p class="fusion-hint">共 {{ skillIndex?.count ?? 0 }} 篇方法论 / 测试手册。元工具不进 system prompt，模型几乎不会主动调。</p>
        <pre class="fusion-pre">{{ skillIndex?.block || "（本地方法论目录为空）" }}</pre>
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
  gap: 16px;
  padding-bottom: 24px;
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
.fs-title-row { display: flex; align-items: center; gap: 12px; }
.fs-title-row h2 { margin: 0; font-size: 24px; font-weight: 700; color: var(--ink); }
.fs-chip {
  font-size: 12.5px;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 999px;
  background: var(--accent2-bg);
  border: 1px solid color-mix(in srgb, var(--accent2) 30%, var(--border));
  color: var(--accent2-ink);
}
.fs-sub { margin: 5px 0 0; color: var(--muted); font-size: 14px; }
.fs-head-actions { display: flex; align-items: center; gap: 8px; }
.fs-btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  padding: 8px 14px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--surface);
  color: var(--ink);
  font-size: 13.5px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
}
.fs-btn:hover:not(:disabled) { background: var(--bg-soft); }

/* Asymmetric 2-Column Studio Body */
.fs-layout {
  display: grid;
  grid-template-columns: 268px minmax(0, 1fr);
  gap: 18px;
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

.fs-rail-block {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.fs-rail-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
}
.fs-select {
  width: 100%;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--ink);
  padding: 8px 10px;
  font-size: 13.5px;
}

.fs-nav {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.fs-pillar-grp {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.fs-pillar-lbl {
  font-size: 12.5px;
  font-weight: 600;
  color: var(--muted);
  padding-left: 6px;
}
.fs-pillar-tabs {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
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
  font-size: 13.5px;
  font-weight: 700;
  padding: 1px 8px;
  border-radius: 99px;
  background: var(--warn);
  color: #fff;
}

.fs-main {
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

/* Studio Card & Control Styles for 8 Submodules */
.fusion-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }
.fusion-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-width: 0;
  box-shadow: var(--shadow-sm);
}
.fusion-card.wide { grid-column: 1 / -1; }
.fusion-card h3 { margin: 0; font-size: 16px; font-weight: 700; color: var(--ink); }
.fusion-card-head { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; }
.fusion-hint { margin: 0; color: var(--muted); font-size: 13.5px; line-height: 1.6; }
.fusion-label { color: var(--muted); font-size: 13.5px; font-weight: 500; display: flex; flex-direction: column; gap: 5px; }
.fusion-input, .fusion-area {
  width: 100%;
  box-sizing: border-box;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--ink);
  padding: 9px 12px;
  font-size: 13.5px;
  font-family: var(--font-mono);
}
.fusion-input:focus, .fusion-area:focus { outline: none; border-color: var(--accent); }
.fusion-area { resize: vertical; line-height: 1.55; }
.fusion-actions, .fusion-inline { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.fusion-inline .fusion-input { width: 240px; }
.fusion-form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr)); gap: 12px; }
.fusion-quick-gates { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.fusion-gate-btn {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 3px;
  padding: 11px 16px;
  border-radius: 8px;
  cursor: pointer;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--muted);
  min-width: 185px;
}
.fusion-gate-btn strong { font-size: 14px; color: var(--ink); }
.fusion-gate-btn span { font-size: 12.5px; }
.fusion-gate-btn.on {
  border-color: color-mix(in srgb, var(--ok) 45%, var(--border));
  background: var(--ok-bg);
  color: var(--ok);
}
.fusion-interval-bar { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; font-size: 13.5px; color: var(--muted); margin-left: auto; }
.fusion-chip-btn {
  padding: 5px 12px;
  border-radius: 999px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--muted);
  font-size: 13px;
  cursor: pointer;
}
.fusion-chip-btn.active {
  border-color: var(--accent);
  background: var(--accent-bg);
  color: var(--accent-ink);
  font-weight: 600;
}
.fusion-switches { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 10px; }
.fusion-switch {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-soft);
  font-size: 13.5px;
}
.fusion-switch input { margin-top: 3px; accent-color: var(--accent); width: auto; }
.fusion-switch span { display: flex; flex-direction: column; gap: 3px; color: var(--muted); }
.fusion-switch strong { color: var(--ink); font-size: 14px; }
.fusion-switch em { font-style: normal; font-size: 12.5px; }
.fusion-pills { display: flex; gap: 8px; flex-wrap: wrap; }
.fusion-pill {
  border: 1px solid var(--border);
  border-radius: 999px;
  padding: 4px 12px;
  font-size: 13px;
  color: var(--muted);
  background: var(--bg-soft);
}
.fusion-pill.on { color: var(--ok); border-color: color-mix(in srgb, var(--ok) 45%, var(--border)); background: var(--ok-bg); }
.fusion-modules { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 10px; }
.fusion-module {
  display: flex;
  flex-direction: column;
  gap: 4px;
  padding: 10px 12px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-soft);
  font-size: 13px;
  color: var(--muted);
}
.fusion-module strong { color: var(--ink); font-size: 14px; }
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
.fusion-result.good {
  background: var(--ok-bg);
  border-color: color-mix(in srgb, var(--ok) 30%, var(--border));
}
.fusion-result.warn {
  background: var(--warn-bg);
  border-color: color-mix(in srgb, var(--warn) 30%, var(--border));
}
.fusion-result.bad {
  background: var(--danger-bg);
  border-color: color-mix(in srgb, var(--danger) 30%, var(--border));
}
.fusion-alert { padding: 11px 14px; border-radius: 8px; font-size: 13.5px; font-weight: 500; border: 1px solid var(--border); }
.fusion-alert.ok { background: var(--ok-bg); color: var(--ok); border-color: color-mix(in srgb, var(--ok) 35%, var(--border)); }
.fusion-alert.bad { background: var(--danger-bg); color: var(--danger); border-color: color-mix(in srgb, var(--danger) 35%, var(--border)); }
.fusion-list { display: flex; flex-direction: column; gap: 6px; max-height: 280px; overflow: auto; }
.fusion-row { display: flex; gap: 10px; align-items: center; font-size: 13.5px; color: var(--muted); }
.fusion-check-row { cursor: pointer; padding: 6px 8px; border-radius: 6px; }
.fusion-check-row:hover { background: var(--bg-soft); }
.fusion-check-row input { width: auto; accent-color: var(--accent); }
.fusion-muted-ellipsis { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0; }
.fusion-tag { color: var(--accent-ink); font-family: var(--font-mono); flex: none; }
.fusion-tag.bad { color: var(--danger); }
.fusion-badge { padding: 2px 10px; border-radius: 999px; font-size: 12.5px; flex: none; border: 1px solid var(--border); }
.fusion-badge.ok { background: var(--ok-bg); color: var(--ok); border-color: color-mix(in srgb, var(--ok) 40%, var(--border)); }
.fusion-badge.warn { background: var(--warn-bg); color: var(--warn); border-color: color-mix(in srgb, var(--warn) 40%, var(--border)); }
.fusion-badge.bad { background: var(--danger-bg); color: var(--danger); border-color: color-mix(in srgb, var(--danger) 40%, var(--border)); }
.fusion-subcard { padding: 14px; border: 1px dashed var(--border); border-radius: 8px; background: var(--bg-soft); display: flex; flex-direction: column; gap: 10px; }
.fusion-pre {
  margin: 0;
  padding: 12px;
  max-height: 340px;
  overflow: auto;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 8px;
  color: var(--ink);
  font-family: var(--font-mono);
  font-size: 13px;
  line-height: 1.55;
  white-space: pre-wrap;
}
.fusion-svg { width: 100%; height: 280px; background: var(--bg-soft); border: 1px solid var(--border); border-radius: 8px; }
.fusion-svg-node { cursor: pointer; }
.fusion-node-groups { display: grid; gap: 10px; }
.fusion-group-title { display: block; font-size: 13px; color: var(--muted); margin-bottom: 6px; }
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
.fusion-report-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.fusion-report-card {
  padding: 12px 14px;
  border: 1px solid var(--border);
  border-radius: 8px;
  background: var(--bg-soft);
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 13.5px;
  color: var(--muted);
}
.fusion-report-card.wide { grid-column: 1 / -1; }
.fusion-report-card strong { color: var(--ink); font-size: 14px; margin-bottom: 2px; }
code { font-family: var(--font-mono); color: var(--accent-ink); }

@media (max-width: 1024px) {
  .fs-layout { grid-template-columns: 1fr; }
  .fs-rail { position: static; }
}
@media (max-width: 900px) {
  .fusion-grid, .fusion-report-grid { grid-template-columns: 1fr; }
  .fusion-inline .fusion-input { width: 100%; }
}
</style>
