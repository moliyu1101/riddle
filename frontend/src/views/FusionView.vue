<script setup>
import { computed, onMounted, ref } from "vue";
import { api } from "../api.js";

defineOptions({ name: "FusionView" });

const TABS = [
  { id: "overview", label: "总览与配置" },
  { id: "goals", label: "目标闸门" },
  { id: "gates", label: "证据与范围" },
  { id: "intel", label: "情报时间流" },
  { id: "graphs", label: "双图架构" },
  { id: "traffic", label: "流量留痕" },
  { id: "report", label: "公文报告" },
  { id: "skills", label: "技能速查" },
];
const activeTab = ref("overview");
const status = ref(null);
const skillIndex = ref(null);
const cfgMeta = ref(null);
const loading = ref(true);
const busy = ref("");
const notice = ref("");
const error = ref("");

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
const configForm = ref({});
const roleInputs = ref({});

const taskId = ref("");
const goalsText = ref(JSON.stringify([
  { title: "未授权接口返回业务数据", criteria: "匿名 GET 返回 200 且响应 JSON 含业务字段，可用 curl 复现", kind: "existence", match: ["未授权"] },
], null, 2));
const goalResult = ref(null);

const findingText = ref(JSON.stringify({
  severity_claimed: "critical", title: "远程命令执行", vuln_type: "rce",
  poc: "curl -s 'http://target.example/run?cmd=id'", raw_response: "HTTP/1.1 200 OK\nuid=0(root)", steps: [],
}, null, 2));
const evidenceResult = ref(null);
const scopeTarget = ref("api.example.edu.cn");
const scopeText = ref(JSON.stringify({ roots: ["example.edu.cn"], sources: [], cidrs: [] }, null, 2));
const scopeResult = ref(null);

const recent = ref([]);
const syncResult = ref(null);
const techText = ref("nginx, php");
const matchResult = ref(null);

const graphTaskId = ref("");
const graphData = ref(null);
const lineageNodeId = ref("");
const lineageResult = ref(null);

const trafficTaskId = ref("");
const trafficDirs = ref([]);
const trafficItems = ref([]);
const importResult = ref(null);
const bindFindingId = ref("");
const bindIds = ref("");
const bindRole = ref("proof");

const reportFindingId = ref("");
const reportData = ref(null);

const hardGates = computed(() => {
  const c = configForm.value || {};
  return [
    { label: "证据硬闸门", on: !!c.evidence_gate_hard },
    { label: "范围硬守卫", on: !!c.scope_guard_hard },
    { label: "流量留痕", on: !!c.traffic_enabled },
  ];
});

const graphLayout = computed(() => {
  const nodes = graphData.value?.nodes || [];
  const edges = graphData.value?.edges || [];
  const byGraph = { asset: nodes.filter((n) => n.graph === "asset"), exploration: nodes.filter((n) => n.graph === "exploration") };
  const points = [];
  Object.entries(byGraph).forEach(([g, list], gi) => {
    list.slice(0, 40).forEach((n, i) => {
      points.push({ id: n.id, label: (n.label || n.kind).slice(0, 14), kind: n.kind,
        x: 30 + gi * 300 + (i % 4) * 68, y: 32 + Math.floor(i / 4) * 34, graph: g });
    });
  });
  const coords = Object.fromEntries(points.map((p) => [p.id, p]));
  const lines = edges.filter((e) => coords[e.src] && coords[e.dst]).slice(0, 60).map((e) => ({
    x1: coords[e.src].x + 8, y1: coords[e.src].y, x2: coords[e.dst].x + 8, y2: coords[e.dst].y, kind: e.kind,
  }));
  return { points, lines };
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
  next.intel_fastlane_cvss = Number(cfg.intel_fastlane_cvss || 9);
  next.intel_timeout = Number(cfg.intel_timeout || 12);
  configForm.value = next;
  roleInputs.value = { ...(roles || {}) };
}
async function load() {
  loading.value = true;
  try {
    const [s, idx, rc, cm] = await Promise.all([
      api.fusionStatus(), api.fusionSkillIndex(), api.fusionIntelRecent(20), api.fusionConfig(),
    ]);
    status.value = s; skillIndex.value = idx; recent.value = rc.items || []; cfgMeta.value = cm;
    fillConfig(cm.config || {}, cm.config?.role_models);
  } catch (e) { toast(e?.message || String(e), true); }
  finally { loading.value = false; }
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
async function saveGoals() {
  if (!taskId.value.trim()) return toast("先填任务 ID", true);
  await run("goals", async () => {
    const goals = parseJson(goalsText.value, "目标清单");
    await api.fusionSaveGoals(taskId.value.trim(), goals);
    goalResult.value = await api.fusionEvaluateGoals(taskId.value.trim());
    if (!graphTaskId.value) graphTaskId.value = taskId.value;
    toast("目标已保存并完成核对");
  });
}
async function evaluateGoals() {
  if (!taskId.value.trim()) return toast("先填任务 ID", true);
  await run("evaluate", async () => { goalResult.value = await api.fusionEvaluateGoals(taskId.value.trim()); });
}
async function checkEvidence() {
  await run("evidence", async () => { evidenceResult.value = await api.fusionEvidenceCheck(parseJson(findingText.value, "finding")); });
}
async function checkScope() {
  await run("scope", async () => { scopeResult.value = await api.fusionScopeCheck(scopeTarget.value, parseJson(scopeText.value, "范围配置")); });
}
async function syncIntel() {
  await run("sync", async () => {
    syncResult.value = await api.fusionIntelSync();
    if (syncResult.value.stored) recent.value = (await api.fusionIntelRecent(20)).items || [];
    toast("情报同步完成");
  });
}
async function matchIntel() {
  await run("match", async () => { matchResult.value = await api.fusionIntelMatch(techText.value.split(/[,，\s]+/).filter(Boolean)); });
}
async function rebuildGraph() {
  if (!graphTaskId.value.trim()) return toast("先填任务 ID", true);
  await run("rebuild", async () => {
    const r = await api.fusionGraphRebuild(graphTaskId.value.trim());
    toast(`双图已重建：${r.nodes} 节点 / ${r.edges} 边`);
    await loadGraph();
  });
}
async function loadGraph() {
  if (!graphTaskId.value.trim()) return toast("先填任务 ID", true);
  await run("graph", async () => { graphData.value = await api.fusionGraph(graphTaskId.value.trim()); });
}
async function queryLineage() {
  if (!graphTaskId.value.trim() || !lineageNodeId.value.trim()) return toast("填任务 ID 与节点 ID", true);
  await run("lineage", async () => { lineageResult.value = await api.fusionGraphLineage(graphTaskId.value.trim(), lineageNodeId.value.trim()); });
}
async function discoverTraffic() {
  await run("discover", async () => { trafficDirs.value = (await api.fusionTrafficDiscover()).dirs || []; toast(`发现 ${trafficDirs.value.length} 个工作目录`); });
}
async function importTraffic() {
  if (!trafficTaskId.value.trim()) return toast("先填任务 ID", true);
  await run("import", async () => {
    importResult.value = await api.fusionTrafficImport(trafficTaskId.value.trim(), "");
    await loadTraffic();
    toast(`导入 ${importResult.value.imported} 条流量`);
  });
}
async function loadTraffic() {
  if (!trafficTaskId.value.trim()) return toast("先填任务 ID", true);
  await run("traffic", async () => { trafficItems.value = (await api.fusionTrafficList(trafficTaskId.value.trim())).items || []; });
}
async function bindTraffic() {
  if (!bindFindingId.value.trim()) return toast("先填漏洞 ID", true);
  await run("bind", async () => {
    const ids = bindIds.value.split(/[,，\s]+/).filter(Boolean);
    const r = await api.fusionTrafficBind(bindFindingId.value.trim(), ids, bindRole.value);
    toast(`已绑定 ${r.updated} 条（${r.role}）`);
    await loadTraffic();
  });
}
async function loadReportModel() {
  if (!reportFindingId.value.trim()) return toast("先填漏洞 ID", true);
  await run("report", async () => { reportData.value = await api.fusionReportModel(reportFindingId.value.trim()); });
}
async function downloadDocx() {
  if (!reportFindingId.value.trim()) return toast("先填漏洞 ID", true);
  await run("docx", async () => {
    await api.fusionReportDocx(reportFindingId.value.trim());
    toast("公文级 Word 已下载");
  });
}
onMounted(load);
</script>

<template>
  <section class="fusion-page">
    <header class="fusion-head">
      <div>
        <h2>融合层</h2>
        <p class="fusion-sub">目标闸门 · 证据闸门 · 范围守卫 · 情报时间流 · 双图 · 流量留痕 · 公文报告 · 角色路由</p>
      </div>
      <button class="btn ghost" :disabled="busy === 'reload'" @click="load">刷新</button>
    </header>

    <div v-if="notice" class="fusion-alert ok">{{ notice }}</div>
    <div v-if="error" class="fusion-alert bad">{{ error }}</div>

    <nav class="fusion-tabs" role="tablist" aria-label="融合层模块">
      <button v-for="t in TABS" :key="t.id" class="fusion-tab" :class="{ active: activeTab === t.id }"
        role="tab" :aria-selected="activeTab === t.id" @click="activeTab = t.id">{{ t.label }}</button>
    </nav>

    <div v-if="loading" class="fusion-card">正在读取融合层状态…</div>

    <!-- 总览与配置 -->
    <div v-else-if="activeTab === 'overview'" class="fusion-grid">
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
        <p class="fusion-hint">开关写入 SystemSettings.defaults.fusion；密钥类配置仍只走 .env，不落库、不回显明文。</p>
        <div class="fusion-switches">
          <label v-for="f in BOOL_FIELDS" :key="f.key" class="fusion-switch">
            <input type="checkbox" v-model="configForm[f.key]" />
            <span><strong>{{ f.label }}</strong><em>{{ f.desc }}</em></span>
          </label>
        </div>
        <div class="fusion-form-grid">
          <label class="fusion-label">情报回溯天数<input class="fusion-input" type="number" min="1" max="90" v-model.number="configForm.intel_lookback_days" /></label>
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
        <h3>目标闸门</h3>
        <p class="fusion-hint">目标必须带可核验验收标准；能力型目标只认 high/critical 实证；未全达成时终态强制 incomplete。</p>
        <label class="fusion-label">任务 ID</label>
        <input v-model="taskId" class="fusion-input" placeholder="从任务详情页复制" />
        <label class="fusion-label">目标清单（JSON 数组）</label>
        <textarea v-model="goalsText" class="fusion-area" rows="10"></textarea>
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
        <h3>证据闸门试算</h3>
        <p class="fusion-hint">critical 要求 L3+、high 要求 L2+，且必须带机械可复现凭据。</p>
        <label class="fusion-label">finding（JSON 对象或数组）</label>
        <textarea v-model="findingText" class="fusion-area" rows="9"></textarea>
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
        <h3>范围守卫试算</h3>
        <p class="fusion-hint">own 允许写回，source 只读共享，foreign 与基础设施地址拒绝。</p>
        <label class="fusion-label">待写回资产</label>
        <input v-model="scopeTarget" class="fusion-input" />
        <label class="fusion-label">任务范围（JSON）</label>
        <textarea v-model="scopeText" class="fusion-area" rows="5"></textarea>
        <div class="fusion-actions"><button class="btn ghost" :disabled="!!busy" @click="checkScope">判定</button></div>
        <div v-if="scopeResult" class="fusion-result" :class="scopeResult.allowed ? 'good' : 'bad'">
          <strong>{{ scopeResult.classification }} · {{ scopeResult.allowed ? "允许写回" : "拒绝写回" }}</strong>
          <span>{{ scopeResult.reason || "在授权范围内" }}</span>
        </div>
      </article>
    </div>

    <!-- 情报时间流 -->
    <div v-else-if="activeTab === 'intel'" class="fusion-grid">
      <article class="fusion-card">
        <h3>情报时间流</h3>
        <p class="fusion-hint">手动同步近 {{ configForm.intel_lookback_days || 7 }} 天 CVE 与在野利用清单，结果复用情报库去重。</p>
        <div class="fusion-actions"><button class="btn primary" :disabled="!!busy" @click="syncIntel">同步情报</button></div>
        <div v-if="syncResult" class="fusion-result" :class="syncResult.errors?.length ? 'warn' : 'good'">
          <strong>条目 {{ syncResult.entry_count }}，快通道 {{ syncResult.fastlane_count }}，入库 {{ syncResult.stored }}</strong>
          <span v-for="(e, i) in syncResult.errors || []" :key="i">{{ e }}</span>
        </div>
        <div class="fusion-list">
          <div v-for="(it, i) in recent.slice(0, 12)" :key="i" class="fusion-row">
            <span class="fusion-tag" :class="it.kev ? 'bad' : ''">{{ it.cve_id || it.match_key }}</span>
            <span>CVSS {{ Number(it.cvss || 0).toFixed(1) }}</span>
          </div>
          <p v-if="!recent.length" class="fusion-hint">暂无条目。</p>
        </div>
      </article>
      <article class="fusion-card">
        <h3>资产指纹反查</h3>
        <label class="fusion-label">资产指纹（逗号分隔）</label>
        <input v-model="techText" class="fusion-input" />
        <div class="fusion-actions"><button class="btn ghost" :disabled="!!busy" @click="matchIntel">反查</button></div>
        <div v-if="matchResult" class="fusion-result good"><strong>命中 {{ matchResult.count }} 条 hint</strong></div>
        <div class="fusion-list">
          <div v-for="(h, i) in matchResult?.hints || []" :key="i" class="fusion-row">
            <span class="fusion-tag">{{ h.cve_id }}</span><span>{{ h.matched?.join("、") }}</span>
          </div>
        </div>
      </article>
    </div>

    <!-- 双图架构 -->
    <div v-else-if="activeTab === 'graphs'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>双图架构（旁路镜像，不改主数据模型）</h3>
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
          <g v-for="(p, i) in graphLayout.points" :key="'p' + i">
            <circle :cx="p.x" :cy="p.y" r="5" :fill="p.graph === 'asset' ? 'var(--info)' : 'var(--accent)'" />
            <text :x="p.x + 8" :y="p.y + 3" font-size="9" fill="var(--ink)">{{ p.label }}</text>
          </g>
        </svg>
      </article>
      <article class="fusion-card wide">
        <h3>血缘回溯</h3>
        <p class="fusion-hint">填节点 ID（可从图上标签或接口返回里取），沿 proves / yields / derived_from 反向追溯来源。</p>
        <div class="fusion-inline">
          <input v-model="lineageNodeId" class="fusion-input" placeholder="节点 ID" />
          <button class="btn ghost" :disabled="!!busy" @click="queryLineage">查询血缘</button>
        </div>
        <div class="fusion-list">
          <div v-for="(n, i) in lineageResult?.chain || []" :key="i" class="fusion-row">
            <span class="fusion-tag">L{{ n.depth }}</span><span>{{ n.kind }}｜{{ n.label }}</span>
          </div>
          <p v-if="lineageResult && !lineageResult.chain?.length" class="fusion-hint">未找到该节点或无上游来源。</p>
        </div>
      </article>
    </div>

    <!-- 流量留痕 -->
    <div v-else-if="activeTab === 'traffic'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>流量留痕与四类证据绑定</h3>
        <p class="fusion-hint">启用「流量留痕」开关后，每次 http_request 会在工作区写结构化 JSONL；从这里导入台账并绑定到漏洞。</p>
        <div class="fusion-inline">
          <input v-model="trafficTaskId" class="fusion-input" placeholder="任务 ID" />
          <button class="btn ghost" :disabled="!!busy" @click="discoverTraffic">发现工作目录</button>
          <button class="btn primary" :disabled="!!busy" @click="importTraffic">导入台账</button>
          <button class="btn ghost" :disabled="!!busy" @click="loadTraffic">刷新列表</button>
        </div>
        <div v-if="trafficDirs.length" class="fusion-hint">发现目录：{{ trafficDirs.join("、") }}</div>
        <div v-if="importResult" class="fusion-result good">
          <strong>扫描 {{ importResult.scanned_rows }} 行，去重 {{ importResult.unique_rows }} 行，新增 {{ importResult.imported }} 行</strong>
        </div>
        <div class="fusion-list">
          <div v-for="(t, i) in trafficItems.slice(0, 30)" :key="i" class="fusion-row">
            <span class="fusion-tag">{{ t.id.slice(0, 8) }}</span>
            <span>{{ t.method }} {{ t.status_code }}</span>
            <span class="fusion-tag">{{ t.role }}</span>
            <span>{{ t.url.slice(0, 48) }}</span>
          </div>
          <p v-if="!trafficItems.length" class="fusion-hint">暂无台账记录，先启用开关并产生请求，再导入。</p>
        </div>
      </article>
      <article class="fusion-card wide">
        <h3>绑定到 finding</h3>
        <div class="fusion-form-grid">
          <label class="fusion-label">漏洞 ID<input class="fusion-input" v-model="bindFindingId" /></label>
          <label class="fusion-label">流量 ID（逗号分隔）<input class="fusion-input" v-model="bindIds" /></label>
          <label class="fusion-label">证据角色
            <select class="fusion-input" v-model="bindRole">
              <option value="baseline">baseline 基线请求</option>
              <option value="proof">proof 利用证明</option>
              <option value="verification">verification 复测验证</option>
              <option value="supporting">supporting 辅助证据</option>
            </select>
          </label>
        </div>
        <div class="fusion-actions"><button class="btn primary" :disabled="!!busy" @click="bindTraffic">绑定</button></div>
      </article>
    </div>

    <!-- 公文报告 -->
    <div v-else-if="activeTab === 'report'" class="fusion-grid">
      <article class="fusion-card wide">
        <h3>公文级 Word 报告</h3>
        <p class="fusion-hint">封面 / 目录域 / 页眉页脚页码 / 严重度着色 / 目标达成情况 / 四类流量证据 / 复测记录 / 修复路线图。</p>
        <div class="fusion-inline">
          <input v-model="reportFindingId" class="fusion-input" placeholder="漏洞 ID" />
          <button class="btn ghost" :disabled="!!busy" @click="loadReportModel">预览结构</button>
          <button class="btn primary" :disabled="!!busy" @click="downloadDocx">下载 docx</button>
        </div>
        <div v-if="reportData" class="fusion-pills">
          <span class="fusion-pill">{{ reportData.model.title }}</span>
          <span class="fusion-pill">{{ reportData.model.impact_level }} {{ reportData.model.impact_label }}</span>
          <span class="fusion-pill">{{ reportData.model.goals?.summary || "未设置目标" }}</span>
          <span v-for="(s, i) in reportData.sections" :key="i" class="fusion-pill">{{ s }}</span>
        </div>
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
  </section>
</template>

<style scoped>
.fusion-page { display: flex; flex-direction: column; gap: 14px; padding: 4px 2px 24px; }
.fusion-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 16px; }
.fusion-head h2 { margin: 0; font-size: 20px; color: var(--ink); }
.fusion-sub { margin: 4px 0 0; color: var(--muted); font-size: 13px; }
.fusion-tabs { display: flex; gap: 6px; flex-wrap: wrap; border-bottom: 1px solid var(--border); padding-bottom: 8px; }
.fusion-tab { background: transparent; border: 1px solid transparent; border-radius: var(--radius-sm); color: var(--muted); padding: 6px 12px; font-size: 12px; }
.fusion-tab:hover { color: var(--ink); border-color: var(--border); }
.fusion-tab.active { color: var(--accent-ink); background: var(--accent-bg); border-color: var(--accent); }
.fusion-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.fusion-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 18px; display: flex; flex-direction: column; gap: 10px; min-width: 0; }
.fusion-card.wide { grid-column: 1 / -1; }
.fusion-card h3 { margin: 0; font-size: 14px; color: var(--ink); }
.fusion-hint { margin: 0; color: var(--muted); font-size: 12px; line-height: 1.6; }
.fusion-label { color: var(--muted); font-size: 12px; display: flex; flex-direction: column; gap: 4px; }
.fusion-input, .fusion-area { width: 100%; box-sizing: border-box; background: var(--bg); border: 1px solid var(--border); border-radius: var(--radius-sm); color: var(--ink); padding: 8px 10px; font-size: 12px; font-family: var(--font-mono, monospace); }
.fusion-input:focus, .fusion-area:focus { outline: none; border-color: var(--focus-border); }
.fusion-area { resize: vertical; line-height: 1.5; }
.fusion-actions, .fusion-inline { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; }
.fusion-inline .fusion-input { width: 220px; }
.fusion-form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 10px; }
.fusion-switches { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 8px; }
.fusion-switch { display: flex; align-items: flex-start; gap: 8px; padding: 8px 10px; border: 1px solid var(--border-soft); border-radius: var(--radius-sm); font-size: 12px; }
.fusion-switch input { margin-top: 2px; accent-color: var(--accent); }
.fusion-switch span { display: flex; flex-direction: column; gap: 2px; color: var(--muted); }
.fusion-switch strong { color: var(--ink); font-size: 12px; }
.fusion-switch em { font-style: normal; font-size: 11px; }
.fusion-pills { display: flex; gap: 8px; flex-wrap: wrap; }
.fusion-pill { border: 1px solid var(--border); border-radius: 999px; padding: 3px 10px; font-size: 12px; color: var(--muted); }
.fusion-pill.on { color: var(--ok); border-color: var(--ok); }
.fusion-modules { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; }
.fusion-module { display: flex; flex-direction: column; gap: 3px; padding: 8px 10px; border: 1px solid var(--border-soft); border-radius: var(--radius-sm); font-size: 12px; color: var(--muted); }
.fusion-module strong { color: var(--ink); font-size: 13px; }
.fusion-result { display: flex; flex-direction: column; gap: 4px; padding: 10px 12px; border-radius: var(--radius-sm); font-size: 12px; line-height: 1.5; background: var(--info-bg); color: var(--ink); }
.fusion-result.good { background: var(--ok-bg); }
.fusion-result.warn { background: var(--warn-bg); }
.fusion-result.bad { background: var(--danger-bg); }
.fusion-alert { padding: 8px 12px; border-radius: var(--radius-sm); font-size: 12px; }
.fusion-alert.ok { background: var(--ok-bg); color: var(--ok); }
.fusion-alert.bad { background: var(--danger-bg); color: var(--danger); }
.fusion-list { display: flex; flex-direction: column; gap: 4px; max-height: 240px; overflow: auto; }
.fusion-row { display: flex; gap: 10px; align-items: center; font-size: 12px; color: var(--muted); }
.fusion-tag { color: var(--accent-ink); font-family: var(--font-mono, monospace); }
.fusion-tag.bad { color: var(--danger); }
.fusion-pre { margin: 0; padding: 10px; max-height: 320px; overflow: auto; background: var(--bg); border: 1px solid var(--border-soft); border-radius: var(--radius-sm); color: var(--muted); font-size: 11px; line-height: 1.5; white-space: pre-wrap; }
.fusion-svg { width: 100%; height: 260px; background: var(--bg); border: 1px solid var(--border-soft); border-radius: var(--radius-sm); }
code { font-family: var(--font-mono, monospace); color: var(--accent-ink); }
@media (max-width: 900px) { .fusion-grid { grid-template-columns: 1fr; } .fusion-inline .fusion-input { width: 100%; } }
</style>
