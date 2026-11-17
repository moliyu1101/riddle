<script setup>
import { computed, onActivated, onMounted, onUnmounted, ref, watch } from "vue";
import { api } from "../api.js";
import { fmtLocalTime } from "../format.js";
import { AGENT_LABEL, kindLabel } from "../composables/useEventFormat.js";

defineOptions({ name: "RuntimeLogsView" });

const stats = ref({ total: 0, errors: 0, warns: 0, by_agent: {} });
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const level = ref("all");
const agent = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const total = ref(0);
const page = ref(0);
const pageSize = 100;
const hasMore = ref(false);
let searchTimer = null;

const agentOptions = computed(() => {
  const names = Object.keys(stats.value.by_agent || {}).sort();
  return ["all", ...names];
});

async function loadStats() {
  try { stats.value = await api.runtimeLogStats(); } catch { /* keep */ }
}

async function loadList() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    const res = await api.runtimeLogs(level.value, agent.value, searchText.value, {
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

// 时间格式化统一走 format.js 的 fmtLocalTime（与其字节等价）；本地保留 fmtTime 名给模板。
const fmtTime = fmtLocalTime;

function agentLabel(a) {
  if (a === "all") return "全部 agent";
  return AGENT_LABEL[a] || a || "未知";
}

function payloadText(payload) {
  try { return JSON.stringify(payload || {}, null, 2); }
  catch { return String(payload || ""); }
}

watch([level, agent], reload);
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
  <section class="view rt-studio" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <header class="rt-head">
      <div>
        <div class="rt-title-row">
          <h2>系统运行日志</h2>
          <span class="rt-chip">实时审计流</span>
        </div>
        <p class="rt-sub">集中监控跨任务 LLM 调用、Reviewer 审查、Worker 执行及 Orchestrator 异常安全收敛事件。</p>
      </div>
      <router-link class="btn-rt-ghost" to="/">← 返回仪表盘</router-link>
    </header>

    <!-- 4-Cell KPI Strip -->
    <div class="rt-kpi-strip">
      <button type="button" class="rt-kpi" :class="{ on: level === 'all' }" @click="level = 'all'">
        <span class="rk-label">事件流总量</span>
        <b>{{ stats.total }}</b>
        <small>全部采集记录</small>
      </button>
      <button type="button" class="rt-kpi err" :class="{ on: level === 'error' }" @click="level = level === 'error' ? 'all' : 'error'">
        <span class="rk-label">致命错误 (Error)</span>
        <b>{{ stats.errors }}</b>
        <small>点击筛选仅看 Error</small>
      </button>
      <button type="button" class="rt-kpi warn" :class="{ on: level === 'warn' }" @click="level = level === 'warn' ? 'all' : 'warn'">
        <span class="rk-label">运行告警 (Warn)</span>
        <b>{{ stats.warns }}</b>
        <small>点击筛选仅看 Warn</small>
      </button>
      <div class="rt-kpi info">
        <span class="rk-label">活跃 Agent 来源</span>
        <b>{{ Object.keys(stats.by_agent || {}).length }}</b>
        <small>涉及运行模块</small>
      </div>
    </div>

    <!-- 2-Column Split Console -->
    <div class="rt-studio-grid">
      <aside class="rt-rail" aria-label="日志筛选控制台">
        <div class="rr-block">
          <div class="rr-label">日志全文检索引擎</div>
          <div class="rr-search">
            <span>⌕</span>
            <input v-model="searchDraft" placeholder="任务 / agent / kind / 报错详情..." />
          </div>
        </div>

        <div class="rr-block">
          <div class="rr-label">事件级别 / LEVEL</div>
          <div class="rr-facets">
            <button v-for="l in ['all','error','warn','info']" :key="l" type="button"
                    class="rr-facet" :class="[l, { on: level === l }]" @click="level = l">
              <span>{{ l === 'all' ? '全部事件 (ALL)' : l.toUpperCase() }}</span>
              <em v-if="l === 'all'">{{ stats.total }}</em>
              <em v-else-if="l === 'error'">{{ stats.errors }}</em>
              <em v-else-if="l === 'warn'">{{ stats.warns }}</em>
            </button>
          </div>
        </div>

        <div class="rr-block">
          <div class="rr-label">AGENT 来源模块</div>
          <div class="rr-facets scroll">
            <button v-for="a in agentOptions" :key="a" type="button"
                    class="rr-facet" :class="{ on: agent === a }" @click="agent = a">
              <span>{{ agentLabel(a) }}</span>
              <em v-if="a !== 'all' && stats.by_agent?.[a] != null">{{ stats.by_agent[a] }}</em>
            </button>
          </div>
        </div>

        <div class="rr-block">
          <button type="button" class="btn-rt-ghost full" @click="reload" :disabled="refreshing">
            {{ refreshing ? "同步拉取中…" : "↻ 刷新日志流" }}
          </button>
        </div>
      </aside>

      <!-- Telemetry Event Stream -->
      <div class="rt-main">
        <div v-if="initialLoading" class="rt-skeletons">
          <div v-for="n in 8" :key="n" class="rt-skel"></div>
        </div>
        <div v-else-if="!rows.length" class="rt-empty">
          <b>当前筛选条件下暂无异常事件</b>
          <span>系统运行平稳，未捕获到符合条件的新错误或警告。</span>
        </div>
        <div v-else class="rt-stream">
          <article v-for="row in rows" :key="row.id" class="rt-entry" :class="row.level || 'info'">
            <div class="re-top">
              <div class="re-tags">
                <span class="re-lvl" :class="row.level || 'info'">
                  {{ (row.level || 'info').toUpperCase() }}
                </span>
                <span class="re-kind">{{ kindLabel(row.kind) }}</span>
                <span class="re-agent">@{{ agentLabel(row.agent) }}</span>
                <router-link v-if="row.task_id" class="re-task-link" :to="`/task/${row.task_id}`">
                  TASK: {{ row.task_name || row.task_id }} ↗
                </router-link>
                <span v-else class="re-task-muted">TASK: {{ row.task_name || '-' }}</span>
              </div>
              <div class="re-meta">
                <span class="re-status">{{ row.task_status || 'unknown' }}</span>
                <time>{{ fmtTime(row.ts) }}</time>
              </div>
            </div>

            <div class="re-msg">{{ row.message }}</div>

            <details v-if="row.payload && Object.keys(row.payload).length" class="re-payload">
              <summary>查看结构化 Payload 上下文</summary>
              <pre>{{ payloadText(row.payload) }}</pre>
            </details>
          </article>
        </div>

        <div v-if="!initialLoading && total > pageSize" class="rt-pager">
          <button type="button" class="btn-rt-ghost" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
          <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
          <button type="button" class="btn-rt-ghost" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.rt-studio {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.rt-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.rt-title-row { display: flex; align-items: center; gap: 12px; }
.rt-title-row h2 { margin: 0; font-size: 24px; font-weight: 700; color: var(--ink); }
.rt-chip {
  font-size: 12.5px;
  font-weight: 600;
  padding: 3px 10px;
  border-radius: 999px;
  background: var(--warn-bg);
  border: 1px solid color-mix(in srgb, var(--warn) 35%, var(--border));
  color: var(--warn);
}
.rt-sub { margin: 5px 0 0; font-size: 14px; color: var(--muted); }

/* 4-Cell KPI Strip */
.rt-kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--surface);
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}
.rt-kpi {
  appearance: none;
  background: transparent;
  border: none;
  border-right: 1px solid var(--border);
  border-radius: 0;
  padding: 16px 18px;
  text-align: left;
  display: flex;
  flex-direction: column;
  gap: 6px;
  position: relative;
}
button.rt-kpi { cursor: pointer; transition: background 0.12s ease; }
button.rt-kpi:hover { background: var(--bg-soft); }
.rt-kpi:last-child { border-right: none; }
.rt-kpi.on { background: color-mix(in srgb, var(--accent) 6%, var(--surface)); }
.rt-kpi.on::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: 0;
  height: 3px;
  background: var(--accent);
}
.rk-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
}
.rt-kpi b {
  font-size: 26px;
  font-weight: 700;
  font-variant-numeric: tabular-nums;
  line-height: 1.08;
  color: var(--ink);
}
.rt-kpi.err b { color: var(--danger); }
.rt-kpi.warn b { color: var(--warn); }
.rt-kpi small { font-size: 13px; color: var(--muted); }

/* 2-Column Console */
.rt-studio-grid {
  display: grid;
  grid-template-columns: 260px minmax(0, 1fr);
  gap: 18px;
  align-items: start;
}
.rt-rail {
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
.rr-block {
  display: flex;
  flex-direction: column;
  gap: 10px;
  padding-bottom: 14px;
  border-bottom: 1px solid var(--border);
}
.rr-block:last-child { padding-bottom: 0; border-bottom: none; }
.rr-label {
  font-size: 13px;
  font-weight: 600;
  color: var(--muted);
}
.rr-search {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 8px 12px;
  border-radius: 8px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
}
.rr-search input {
  width: 100%;
  border: none;
  background: transparent;
  outline: none;
  color: var(--ink);
  font-size: 14px;
  padding: 0;
}
.rr-facets { display: flex; flex-direction: column; gap: 4px; }
.rr-facets.scroll { max-height: 260px; overflow-y: auto; }
.rr-facet {
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
  text-align: left;
}
.rr-facet:hover { background: var(--bg-soft); color: var(--ink); }
.rr-facet.on {
  background: var(--accent-bg);
  border-color: color-mix(in srgb, var(--accent) 28%, transparent);
  color: var(--accent-ink);
  font-weight: 600;
}
.rr-facet em { font-style: normal; font-variant-numeric: tabular-nums; font-size: 12.5px; color: var(--muted); }

.btn-rt-ghost {
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
.btn-rt-ghost:hover:not(:disabled) { background: var(--bg-soft); }
.btn-rt-ghost.full { width: 100%; }

/* Right Audit Log Stream */
.rt-main { min-width: 0; display: flex; flex-direction: column; gap: 14px; }
.rt-stream {
  display: flex;
  flex-direction: column;
  border: 1px solid var(--border);
  border-radius: 12px;
  background: var(--surface);
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}
.rt-entry {
  padding: 15px 18px;
  border-bottom: 1px solid var(--border);
  border-left: 3px solid var(--muted);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.rt-entry:last-child { border-bottom: none; }
.rt-entry.error { border-left-color: var(--danger); background: color-mix(in srgb, var(--danger) 3%, transparent); }
.rt-entry.warn { border-left-color: var(--warn); background: color-mix(in srgb, var(--warn) 2.5%, transparent); }
.rt-entry.info { border-left-color: var(--accent2); }

.re-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 10px;
}
.re-tags { display: flex; align-items: center; flex-wrap: wrap; gap: 8px; }
.re-lvl {
  font-size: 13.5px;
  font-weight: 700;
  padding: 2px 8px;
  border-radius: 6px;
}
.re-lvl.error { background: var(--danger-bg); color: var(--danger); }
.re-lvl.warn { background: var(--warn-bg); color: var(--warn); }
.re-lvl.info { background: var(--accent2-bg); color: var(--accent2-ink); }
.re-kind { font-size: 14.5px; font-weight: 700; color: var(--ink); }
.re-agent {
  font-family: var(--font-mono);
  font-size: 12.5px;
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  color: var(--muted);
}
.re-task-link {
  font-size: 13px;
  color: var(--accent-ink);
  text-decoration: none;
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--accent-bg);
}
.re-task-link:hover { text-decoration: underline; }
.re-task-muted { font-size: 13px; color: var(--muted); }

.re-meta {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 12.5px;
  color: var(--muted);
}
.re-status {
  padding: 2px 8px;
  border-radius: 6px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
}
.re-msg {
  font-size: 14px;
  line-height: 1.6;
  color: var(--ink);
  word-break: break-word;
}
.re-payload summary {
  font-size: 13px;
  color: var(--accent2-ink);
  cursor: pointer;
  user-select: none;
}
.re-payload pre {
  margin: 8px 0 0;
  padding: 12px;
  border-radius: 8px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  font-family: var(--font-mono);
  font-size: 13px;
  line-height: 1.55;
  overflow-x: auto;
  color: var(--ink);
}

.rt-pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 13.5px;
  color: var(--muted);
}

.rt-empty {
  background: var(--surface);
  border: 1px dashed var(--border-strong);
  border-radius: 12px;
  padding: 48px 24px;
  text-align: center;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.rt-empty b { font-size: 16px; color: var(--ink); }
.rt-empty span { font-size: 14px; color: var(--muted); }
.rt-skeletons { display: flex; flex-direction: column; gap: 8px; }
.rt-skel { height: 74px; border-radius: 8px; background: var(--surface); border: 1px solid var(--border); opacity: 0.6; }

@media (max-width: 1024px) {
  .rt-kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .rt-kpi { border-bottom: 1px solid var(--border); }
  .rt-studio-grid { grid-template-columns: 1fr; }
  .rt-rail { position: static; }
}
</style>
