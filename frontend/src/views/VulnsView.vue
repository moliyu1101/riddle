<script setup>
import { computed, onActivated, onMounted, ref, watch } from "vue";
import { api, canWrite } from "../api.js";
import ReportDrawer from "../components/ReportDrawer.vue";
import { fmtLocalTime } from "../format.js";
import { useCountUp } from "../composables/useCountUp.js";
import { showToast } from "../composables/useToast.js";

defineOptions({ name: "VulnsView" });

const stats = ref({ total: 0, submitted: 0, ready: 0, by_severity: {} });
const statTotal = useCountUp(computed(() => stats.value.total));
const statSubmitted = useCountUp(computed(() => stats.value.submitted));
const statReady = useCountUp(computed(() => stats.value.ready));
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const submitted = ref("all");
const severity = ref("");
const sort = ref("time_desc");
const searchDraft = ref("");
const searchText = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);
const drawerId = ref(null);
const distillingId = ref(null);
const distilledIds = ref(new Set());
const exportingId = ref(null);
const writable = computed(() => canWrite());
let searchTimer = null;

function toast(m) { showToast(m, "info"); }

async function distillRow(row) {
  if (!writable.value || !row?.id || distillingId.value) return;
  distillingId.value = row.id;
  try {
    const res = await api.distillFindingToKb(row.id);
    const next = new Set(distilledIds.value);
    next.add(row.id);
    distilledIds.value = next;
    showToast(`已脱敏蒸馏入库：${res?.name || res?.item?.name || row.title}`, "ok");
  } catch (e) {
    showToast(`蒸馏失败：${String(e?.message || e).replace(/^\d+\s*/, "")}`, "danger");
  } finally {
    distillingId.value = null;
  }
}

async function exportDocxRow(row) {
  if (!row?.id || exportingId.value) return;
  exportingId.value = row.id;
  try {
    await api.fusionReportDocx(row.id);
    showToast(`已导出公文级 Word：${row.title}`, "ok");
  } catch (e) {
    showToast(`导出失败：${String(e?.message || e).replace(/^\d+\s*/, "")}`, "danger");
  } finally {
    exportingId.value = null;
  }
}

const SUBMIT_TABS = [
  { id: "all", label: "全部" },
  { id: "yes", label: "已提交" },
  { id: "no", label: "待提交" },
];

const SORT_OPTIONS = [
  { id: "time_desc", label: "时间最新" },
  { id: "time_asc", label: "时间最旧" },
  { id: "score_desc", label: "评分最高" },
  { id: "score_asc", label: "评分最低" },
];

const SEV_META = {
  critical: { label: "严重", hue: "danger" },
  high: { label: "高危", hue: "danger" },
  medium: { label: "中危", hue: "warn" },
  low: { label: "低危", hue: "info" },
  info: { label: "信息", hue: "ok" },
};

const SEV_ORDER = ["critical", "high", "medium", "low", "info"];

const CONF_META = {
  confirmed: { label: "已确认", hue: "ok" },
  likely: { label: "疑似", hue: "warn" },
  uncertain: { label: "不确定", hue: "muted" },
};

const severityOptions = computed(() => Object.keys(stats.value.by_severity || {}));

// 等级分布始终展示完整五级刻度，便于建立心智模型
const sevOrder = computed(() => {
  const present = Object.keys(stats.value.by_severity || {});
  const rest = present.filter((s) => !SEV_ORDER.includes(s));
  return [...SEV_ORDER, ...rest];
});

async function loadStats() {
  try { stats.value = await api.vulnStats(); } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    const res = await api.vulns(submitted.value, severity.value, searchText.value, {
      sort: sort.value,
      limit: pageSize,
      offset: page.value * pageSize,
    });
    rows.value = Array.isArray(res) ? res : (res.items || []);
    total.value = Array.isArray(res) ? rows.value.length : (res.total || 0);
    hasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

async function reload() {
  page.value = 0;
  await Promise.all([loadStats(), loadList()]);
}

function nextPage() {
  if (!hasMore.value || refreshing.value) return;
  page.value += 1;
  loadList();
}

function prevPage() {
  if (page.value <= 0 || refreshing.value) return;
  page.value -= 1;
  loadList();
}

function sevMeta(s) {
  return SEV_META[(s || "").toLowerCase()] || { label: s || "未定级", hue: "ok" };
}

function confMeta(c) {
  return CONF_META[(c || "").toLowerCase()] || { label: c || "", hue: "muted" };
}

function sevPct(s) {
  const t = stats.value.total || 1;
  return Math.round(((stats.value.by_severity?.[s] || 0) / t) * 100);
}

function shortId(id) {
  return id ? String(id).slice(0, 8) : "";
}

function openVuln(row) {
  drawerId.value = row.id;
}

function onDrawerUpdated() {
  reload();
}

watch([submitted, severity, sort], reload);
watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchText.value = v.trim();
    page.value = 0;
    loadList();
  }, 180);
});

onMounted(reload);
onActivated(() => {
  if (rows.value.length) reload();
});
</script>

<template>
  <section class="view vuln-studio" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="vuln-head">
      <div>
        <div class="vh-title-row">
          <h2>漏洞发现与档案库</h2>
          <span class="vh-chip">已过审成果账本</span>
        </div>
        <p class="vh-sub">跨任务汇总人工审核通过的高危与疑似发现 · 统一分级评分 · 一键脱敏蒸馏入库与公文报告导出。</p>
      </div>
      <router-link class="btn-vuln-ghost" to="/">← 返回仪表盘</router-link>
    </header>

    <!-- Spectral Summary Band -->
    <div class="vuln-spectrum-band">
      <div class="vsb-total">
        <span class="vsb-k">过审漏洞归档</span>
        <div class="vsb-v-row">
          <b>{{ statTotal }}</b>
          <span class="vsb-sub-tag">已确认</span>
        </div>
      </div>

      <button type="button" class="vsb-stat clickable" :class="{ on: submitted === 'yes' }" @click="submitted = submitted === 'yes' ? 'all' : 'yes'">
        <span class="vsb-k">✓ 已提交 SRC</span>
        <b>{{ statSubmitted }}</b>
      </button>

      <button type="button" class="vsb-stat clickable" :class="{ on: submitted === 'no' }" @click="submitted = submitted === 'no' ? 'all' : 'no'">
        <span class="vsb-k">◷ 待提交队列</span>
        <b class="warn-txt">{{ statReady }}</b>
      </button>

      <div class="vsb-spectrum">
        <div class="vsb-spec-head">
          <span class="vsb-k">五级危害分布</span>
          <span class="vsb-spec-hint">点击等级图例快速筛选</span>
        </div>
        <div class="vsb-bar" role="img" aria-label="漏洞等级分布">
          <i v-for="s in sevOrder" :key="s" :class="sevMeta(s).hue"
             :style="{ width: sevPct(s) + '%' }"
             :title="sevMeta(s).label + '：' + (stats.by_severity[s] || 0)"></i>
        </div>
        <div class="vsb-legend">
          <button v-for="s in sevOrder" :key="s" type="button" class="vsb-leg-btn"
                  :class="[sevMeta(s).hue, { on: severity === s }]"
                  @click="severity = severity === s ? '' : s">
            <i></i>{{ sevMeta(s).label }} <b>{{ stats.by_severity[s] || 0 }}</b>
          </button>
        </div>
      </div>
    </div>

    <!-- 2-Column Archive Workspace -->
    <div class="vuln-studio-grid">
      <aside class="vuln-rail" aria-label="漏洞筛选控制台">
        <div class="vr-block">
          <div class="vr-label">关键词检索</div>
          <div class="vr-search">
            <span>⌕</span>
            <input v-model="searchDraft" placeholder="标题 / 类型 / URL / 归属 / 任务..." />
          </div>
        </div>

        <div class="vr-block">
          <div class="vr-label">SRC 提交状态</div>
          <div class="vr-facets">
            <button v-for="t in SUBMIT_TABS" :key="t.id" type="button"
                    class="vr-facet" :class="{ on: submitted === t.id }" @click="submitted = t.id">
              <span>{{ t.label }}</span>
              <em v-if="t.id === 'all'">{{ statTotal }}</em>
              <em v-else-if="t.id === 'yes'">{{ statSubmitted }}</em>
              <em v-else-if="t.id === 'no'">{{ statReady }}</em>
            </button>
          </div>
        </div>

        <div class="vr-block">
          <div class="vr-label">危害等级与排序</div>
          <div class="vr-selects">
            <select v-model="severity" aria-label="等级筛选">
              <option value="">全部危害等级</option>
              <option v-for="s in severityOptions" :key="s" :value="s">{{ sevMeta(s).label }}</option>
            </select>
            <select v-model="sort" aria-label="排序方式">
              <option v-for="o in SORT_OPTIONS" :key="o.id" :value="o.id">按{{ o.label }}</option>
            </select>
          </div>
        </div>

        <div class="vr-block">
          <button type="button" class="btn-vuln-ghost full" @click="reload" :disabled="refreshing">
            {{ refreshing ? "刷新同步中…" : "↻ 刷新归档列表" }}
          </button>
        </div>
      </aside>

      <!-- Structured Ledger Table -->
      <div class="vuln-main">
        <div v-if="initialLoading" class="vr-skeletons">
          <div v-for="n in 6" :key="n" class="vr-skel-row"></div>
        </div>
        <div v-else-if="!rows.length" class="vr-empty">
          <b>漏洞档案库暂无匹配记录</b>
          <span>人工复审确认通过的漏洞会自动进入此归档账本。</span>
        </div>
        <div v-else class="vuln-table-wrap">
          <table class="vuln-table">
            <thead>
              <tr>
                <th style="width: 94px;">等级 / ID</th>
                <th>漏洞详情、载荷URL与攻击链路</th>
                <th style="width: 185px;">归属 / 任务 / 模型</th>
                <th style="width: 126px;">提交态 / 评分</th>
                <th style="width: 190px; text-align: right;">进化蒸馏与导出</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="row in rows" :key="row.id" class="vl-row" :class="sevMeta(row.effective_severity).hue"
                  role="button" tabindex="0" @click="openVuln(row)" @keyup.enter="openVuln(row)">
                <td>
                  <div class="vl-sev-col">
                    <span class="sev-badge" :class="sevMeta(row.effective_severity).hue">
                      {{ sevMeta(row.effective_severity).label }}
                    </span>
                    <code class="vl-id">#{{ shortId(row.id) }}</code>
                  </div>
                </td>
                <td>
                  <div class="vl-title-col">
                    <div class="vl-title-line">
                      <b class="vl-title">{{ row.title }}</b>
                      <span v-if="row.confidence" class="conf-pill" :class="confMeta(row.confidence).hue">
                        {{ confMeta(row.confidence).label }}
                      </span>
                      <span class="type-pill">{{ row.vuln_type }}</span>
                    </div>
                    <a class="vl-url" :href="row.target_url" target="_blank" rel="noopener noreferrer" @click.stop>
                      <span>{{ row.target_url }}</span>
                      <span aria-hidden="true">↗</span>
                    </a>
                    <div v-if="(row.kill_chain || []).length" class="vl-chain" @click.stop>
                      <span class="chain-lbl">LINK</span>
                      <template v-for="(s, idx) in row.kill_chain" :key="idx">
                        <span class="chain-node">{{ s.method }}</span>
                        <span v-if="idx < row.kill_chain.length - 1" class="chain-sep">→</span>
                      </template>
                    </div>
                  </div>
                </td>
                <td>
                  <div class="vl-owner-col">
                    <b>{{ row.owner || "归属待确认" }}</b>
                    <small>{{ row.task_name || (row.task_id ? row.task_id : "关联任务已清理") }}</small>
                    <span v-if="row.llm_model" class="vl-model">{{ row.llm_model }}</span>
                  </div>
                </td>
                <td>
                  <div class="vl-status-col">
                    <span class="sub-tag" :class="row.submitted ? 'ok' : 'pending'">
                      {{ row.submitted ? "✓ 已提交 SRC" : "◷ 待提交" }}
                    </span>
                    <div class="vl-score-line">
                      <span v-if="row.score" class="score-num">{{ row.score }} 分</span>
                      <time>{{ fmtLocalTime(row.user_reviewed_at || row.created_at) }}</time>
                    </div>
                  </div>
                </td>
                <td style="text-align: right;" @click.stop>
                  <div class="vl-actions">
                    <button
                      v-if="writable"
                      type="button"
                      class="vl-btn"
                      :class="{ done: distilledIds.has(row.id) }"
                      :disabled="distillingId === row.id"
                      title="脱敏蒸馏该漏洞攻击路径与载荷至知识库"
                      @click="distillRow(row)"
                    >
                      {{ distillingId === row.id ? "蒸馏中…" : distilledIds.has(row.id) ? "✓ 已蒸馏" : "⚡ 蒸馏入库" }}
                    </button>
                    <button
                      type="button"
                      class="vl-btn"
                      :disabled="exportingId === row.id"
                      title="直接生成并下载公文级 Word 报告"
                      @click="exportDocxRow(row)"
                    >
                      {{ exportingId === row.id ? "导出中…" : "📄 Word" }}
                    </button>
                    <button type="button" class="vl-btn detail" @click="openVuln(row)">审阅</button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div v-if="!initialLoading && total > pageSize" class="vl-pager">
          <button type="button" class="btn-vuln-ghost" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
          <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
          <button type="button" class="btn-vuln-ghost" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
        </div>
      </div>
    </div>

    <ReportDrawer :finding-id="drawerId" mode="view" @close="drawerId = null"
      @updated="onDrawerUpdated" @toast="toast" />
  </section>
</template>

<style scoped>
.vuln-studio {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.vuln-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.vh-title-row { display: flex; align-items: center; gap: 12px; }
.vh-title-row h2 { margin: 0; font-size: 24px; font-weight: 700; color: var(--ink); }
.vh-chip {
  font-size: 12.5px;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 999px;
  background: var(--accent2-bg);
  border: 1px solid color-mix(in srgb, var(--accent2) 30%, var(--border));
  color: var(--accent2-ink);
}
.vh-sub { margin: 5px 0 0; font-size: 14px; color: var(--muted); }

/* Top Spectral Summary Band */
.vuln-spectrum-band {
  display: grid;
  grid-template-columns: 205px 155px 155px minmax(0, 1fr);
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--surface);
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}
.vsb-total,
.vsb-stat,
.vsb-spectrum {
  padding: 16px 18px;
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  justify-content: center;
  gap: 7px;
}
.vsb-spectrum { border-right: none; }
.vsb-stat {
  appearance: none;
  background: transparent;
  border-top: none;
  border-bottom: none;
  border-left: none;
  border-radius: 0;
  text-align: left;
  cursor: pointer;
  transition: background 0.12s ease;
}
.vsb-stat:hover { background: var(--bg-soft); }
.vsb-stat.on {
  background: color-mix(in srgb, var(--accent) 7%, var(--surface));
  box-shadow: inset 0 -3px 0 var(--accent);
}
.vsb-k {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
}
.vsb-v-row { display: flex; align-items: baseline; gap: 8px; }
.vsb-total b,
.vsb-stat b {
  font-size: 28px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  line-height: 1.05;
  color: var(--ink);
}
.vsb-stat b.warn-txt { color: var(--warn); }
.vsb-sub-tag { font-size: 13px; color: var(--ok); font-weight: 600; }

.vsb-spec-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
}
.vsb-spec-hint { font-size: 12.5px; color: var(--muted); }
.vsb-bar {
  display: flex;
  height: 8px;
  border-radius: 4px;
  overflow: hidden;
  background: var(--bg-soft);
}
.vsb-bar i.danger, .vsb-bar i.critical { background: #dc2626; }
.vsb-bar i.high { background: #ea580c; }
.vsb-bar i.warn, .vsb-bar i.medium { background: #d97706; }
.vsb-bar i.info, .vsb-bar i.low { background: #0284c7; }
.vsb-bar i.muted { background: #6b7280; }

.vsb-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.vsb-leg-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 4px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  font-size: 13px;
  color: var(--ink);
  cursor: pointer;
}
.vsb-leg-btn.on {
  border-color: var(--accent);
  background: var(--accent-bg);
}
.vsb-leg-btn i { width: 8px; height: 8px; border-radius: 50%; background: var(--muted); display: inline-block; }
.vsb-leg-btn.danger i, .vsb-leg-btn.critical i { background: #dc2626; }
.vsb-leg-btn.high i { background: #ea580c; }
.vsb-leg-btn.warn i, .vsb-leg-btn.medium i { background: #d97706; }
.vsb-leg-btn.info i, .vsb-leg-btn.low i { background: #0284c7; }
.vsb-leg-btn b { font-variant-numeric: tabular-nums; }

/* Asymmetric 2-Column Layout */
.vuln-studio-grid {
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}

.vuln-rail {
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
.vr-block {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.vr-block:last-child { padding-bottom: 0; border-bottom: none; }
.vr-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
}
.vr-search {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
}
.vr-search span { color: var(--muted); font-size: 15px; }
.vr-search input {
  width: 100%;
  border: none;
  background: transparent;
  outline: none;
  color: var(--ink);
  font-size: 14px;
  padding: 0;
}
.vr-facets { display: flex; flex-direction: column; gap: 4px; }
.vr-facet {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--ink-2);
  font-size: 13.5px;
  cursor: pointer;
}
.vr-facet:hover { background: var(--bg-soft); color: var(--ink); }
.vr-facet.on {
  background: var(--accent-bg);
  border-color: color-mix(in srgb, var(--accent) 28%, transparent);
  color: var(--accent-ink);
  font-weight: 600;
}
.vr-facet em { font-style: normal; font-variant-numeric: tabular-nums; font-size: 12.5px; color: var(--muted); }

.vr-selects { display: flex; flex-direction: column; gap: 8px; }
.vr-selects select {
  width: 100%;
  padding: 8px 10px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--ink);
  font-size: 13.5px;
}

.btn-vuln-ghost {
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
.btn-vuln-ghost:hover:not(:disabled) { background: var(--bg-soft); }
.btn-vuln-ghost.full { width: 100%; }

/* Vulnerability Ledger Table */
.vuln-main { min-width: 0; display: flex; flex-direction: column; gap: 14px; }
.vuln-table-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  overflow-x: auto;
  box-shadow: var(--shadow-sm);
}
.vuln-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.vuln-table thead th {
  text-align: left;
  padding: 12px 16px;
  background: var(--bg-soft);
  border-bottom: 1px solid var(--border);
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
  white-space: nowrap;
}
.vuln-table tbody td {
  padding: 14px 16px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.vuln-table tbody tr:last-child td { border-bottom: none; }
.vl-row { cursor: pointer; transition: background 0.12s ease; }
.vl-row:hover { background: color-mix(in srgb, var(--bg-soft) 75%, transparent); }

.vl-sev-col { display: flex; flex-direction: column; gap: 6px; }
.sev-badge {
  display: inline-block;
  width: fit-content;
  padding: 3px 9px;
  border-radius: 6px;
  font-size: 12.5px;
  font-weight: 700;
}
.sev-badge.danger, .sev-badge.critical { background: rgba(220, 38, 38, 0.12); color: #dc2626; }
.sev-badge.high { background: rgba(234, 88, 12, 0.12); color: #ea580c; }
.sev-badge.warn, .sev-badge.medium { background: rgba(217, 119, 6, 0.12); color: #d97706; }
.sev-badge.info, .sev-badge.low { background: rgba(2, 132, 199, 0.12); color: #0284c7; }
.sev-badge.muted { background: var(--bg-soft); color: var(--muted); }
.vl-id { font-family: var(--font-mono); font-size: 12.5px; color: var(--muted); }

.vl-title-col { display: flex; flex-direction: column; gap: 6px; min-width: 0; }
.vl-title-line { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.vl-title { font-size: 15px; color: var(--ink); word-break: break-word; }
.conf-pill,
.type-pill {
  font-size: 12.5px;
  padding: 2px 8px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--muted);
}
.conf-pill.ok, .conf-pill.verified { background: var(--ok-bg); color: var(--ok); border-color: transparent; font-weight: 600; }
.vl-url {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  font-family: var(--font-mono);
  font-size: 13px;
  color: var(--accent-ink);
  text-decoration: none;
  word-break: break-all;
}
.vl-url:hover { text-decoration: underline; }
.vl-chain {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 6px;
  margin-top: 2px;
}
.chain-lbl {
  font-size: 13.5px;
  font-weight: 600;
  color: var(--muted);
  margin-right: 2px;
}
.chain-node {
  font-family: var(--font-mono);
  font-size: 12.5px;
  padding: 2px 8px;
  border-radius: 4px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  color: var(--ink);
}
.chain-sep { color: var(--muted); font-size: 12.5px; }

.vl-owner-col { display: flex; flex-direction: column; gap: 4px; }
.vl-owner-col b { font-size: 14px; color: var(--ink); }
.vl-owner-col small { font-size: 12.5px; color: var(--muted); }
.vl-model {
  font-family: var(--font-mono);
  font-size: 12.5px;
  color: var(--accent2-ink);
  width: fit-content;
}

.vl-status-col { display: flex; flex-direction: column; gap: 6px; }
.sub-tag {
  display: inline-block;
  width: fit-content;
  padding: 3px 9px;
  border-radius: 6px;
  font-size: 12.5px;
  font-weight: 600;
}
.sub-tag.ok { background: var(--ok-bg); color: var(--ok); }
.sub-tag.pending { background: var(--warn-bg); color: var(--warn); }
.vl-score-line { display: flex; flex-direction: column; gap: 3px; }
.score-num { font-size: 13.5px; font-weight: 700; color: var(--ink); }
.vl-score-line time { font-size: 12.5px; color: var(--muted); }

.vl-actions { display: inline-flex; flex-wrap: wrap; justify-content: flex-end; gap: 6px; }
.vl-btn {
  padding: 6px 11px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--ink);
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}
.vl-btn:hover:not(:disabled) { border-color: var(--accent); color: var(--accent-ink); }
.vl-btn.done { background: var(--ok-bg); color: var(--ok); border-color: color-mix(in srgb, var(--ok) 30%, var(--border)); }
.vl-btn.detail { background: var(--ink); color: var(--bg); border-color: var(--ink); }

.vl-pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 13.5px;
  color: var(--muted);
}

.vr-empty {
  background: var(--surface);
  border: 1px dashed var(--border-strong);
  border-radius: 12px;
  padding: 48px 24px;
  text-align: center;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.vr-empty b { font-size: 16px; color: var(--ink); }
.vr-empty span { font-size: 14px; color: var(--muted); }

.vr-skeletons { display: flex; flex-direction: column; gap: 8px; }
.vr-skel-row { height: 68px; border-radius: 8px; background: var(--surface); border: 1px solid var(--border); opacity: 0.6; }

@media (max-width: 1024px) {
  .vuln-spectrum-band { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .vsb-spectrum { grid-column: 1 / -1; border-top: 1px solid var(--border); }
  .vuln-studio-grid { grid-template-columns: 1fr; }
  .vuln-rail { position: static; }
}
</style>
