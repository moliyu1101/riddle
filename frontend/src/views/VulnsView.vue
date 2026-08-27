<script setup>
import { computed, onActivated, onMounted, ref, watch } from "vue";
import { api } from "../api.js";
import ReportDrawer from "../components/ReportDrawer.vue";
import { fmtLocalTime } from "../format.js";
import { useCountUp } from "../composables/useCountUp.js";

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
const toastMsg = ref("");
let searchTimer = null;

function toast(m) { toastMsg.value = m; setTimeout(() => (toastMsg.value = ""), 2200); }

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
  <section class="view intel-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <nav class="crumb" aria-label="面包屑">
      <span>指挥中心</span>
      <span class="crumb-sep">/</span>
      <b>漏洞档案库</b>
    </nav>

    <header class="page-head split">
      <div>
        <h2>漏洞档案库 <span class="intel-chip">VULN</span></h2>
        <p class="page-sub">跨任务汇总人工审核通过的漏洞——含已提交 SRC 与待提交两类，统一归档、分级与复盘。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <!-- 总览区 -->
    <div class="vuln-dash">
      <div class="vd-hero">
        <div class="vd-hero-top">
          <span class="vd-label">过审漏洞</span>
          <span class="vd-chip">ARCHIVE</span>
        </div>
        <b class="vd-total">{{ statTotal }}</b>
        <div class="vd-hero-sub">
          <span class="vd-pill ok">✓ 已提交 {{ statSubmitted }}</span>
          <span class="vd-pill warn">◷ 待提交 {{ statReady }}</span>
        </div>
      </div>

      <div class="vd-sev">
        <div class="vd-sev-head">
          <span class="vd-label">等级分布</span>
          <span class="vd-sev-count">{{ sevOrder.length }} 级</span>
        </div>
        <div class="vd-bar" role="img" aria-label="漏洞等级分布">
          <i v-for="s in sevOrder" :key="s" :class="sevMeta(s).hue"
             :style="{ width: sevPct(s) + '%' }"
             :title="sevMeta(s).label + '：' + (stats.by_severity[s] || 0)"></i>
        </div>
        <div class="vd-sev-legend">
          <span v-for="s in sevOrder" :key="s" class="vd-sev-item" :class="sevMeta(s).hue">
            <i></i>{{ sevMeta(s).label }} {{ stats.by_severity[s] || 0 }}
          </span>
        </div>
      </div>

      <div class="vd-card" :class="{ on: submitted === 'yes' }" @click="submitted = 'yes'">
        <span class="vd-card-icon ok">✓</span>
        <b class="vd-card-v">{{ statSubmitted }}</b>
        <span class="vd-card-label">已提交 SRC</span>
      </div>
      <div class="vd-card pending" :class="{ on: submitted === 'no' }" @click="submitted = 'no'">
        <span class="vd-card-icon warn">◷</span>
        <b class="vd-card-v">{{ statReady }}</b>
        <span class="vd-card-label">待提交</span>
      </div>
    </div>

    <!-- 工具栏 -->
    <div class="intel-toolbar">
      <div class="kind-tabs">
        <button v-for="t in SUBMIT_TABS" :key="t.id" type="button"
                class="kind-tab" :class="{ on: submitted === t.id }" @click="submitted = t.id">
          {{ t.label }}
        </button>
      </div>
      <div class="search-box">
        <span>⌕</span>
        <input v-model="searchDraft" placeholder="搜索 标题 / 类型 / URL / 归属 / 任务" />
      </div>
      <select v-model="severity">
        <option value="">全部等级</option>
        <option v-for="s in severityOptions" :key="s" :value="s">{{ sevMeta(s).label }}</option>
      </select>
      <select v-model="sort" class="sort-select" aria-label="排序方式">
        <option v-for="o in SORT_OPTIONS" :key="o.id" :value="o.id">按{{ o.label }}</option>
      </select>
      <button class="btn-ghost" @click="reload" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
    </div>

    <!-- 列表 -->
    <div v-if="initialLoading" class="vuln-list">
      <div v-for="n in 5" :key="n" class="vuln-card skeleton-hard"></div>
    </div>
    <div v-else-if="!rows.length" class="empty">
      漏洞档案库暂无记录
      <span class="hint">人工审核通过的漏洞会自动归档到这里</span>
    </div>
    <div v-else class="vuln-list">
      <article v-for="(row, i) in rows" :key="row.id" class="vuln-card anim-fade-up" :class="sevMeta(row.effective_severity).hue"
               :style="{ '--i': i }" role="button" tabindex="0" @click="openVuln(row)" @keyup.enter="openVuln(row)">
        <div class="vc-left">
          <span class="vc-sev" :class="sevMeta(row.effective_severity).hue">
            {{ sevMeta(row.effective_severity).label }}
          </span>
          <span class="vc-id">#{{ shortId(row.id) }}</span>
        </div>

        <div class="vc-main">
          <div class="vc-title-row">
            <b class="vc-title">{{ row.title }}</b>
            <span v-if="row.confidence" class="vc-conf" :class="confMeta(row.confidence).hue">
              {{ confMeta(row.confidence).label }}
            </span>
          </div>
          <div class="vc-meta">
            <span class="vc-tag">{{ row.vuln_type }}</span>
            <a class="vc-url" :href="row.target_url" target="_blank" rel="noopener noreferrer" @click.stop>
              <span class="vc-url-text">{{ row.target_url }}</span>
              <svg class="vc-url-ico" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
                <polyline points="15 3 21 3 21 9"/>
                <line x1="10" y1="14" x2="21" y2="3"/>
              </svg>
            </a>
          </div>
          <div class="vc-owner">
            <span>归属 {{ row.owner || "待确认" }}</span>
            <span class="vc-dot">·</span>
            <span>任务 {{ row.task_name || (row.task_id ? row.task_id : "已删除") }}</span>
            <template v-if="row.llm_model">
              <span class="vc-dot">·</span>
              <span class="vc-model">{{ row.llm_model }}</span>
            </template>
          </div>
          <div v-if="(row.kill_chain || []).length" class="vuln-chain" @click.stop>
            <div class="vc-flow">
              <span class="vc-label">攻击链路</span>
              <template v-for="(s, i) in row.kill_chain" :key="i">
                <span class="vc-node">{{ s.method }}</span>
                <span v-if="i < row.kill_chain.length - 1" class="vc-arrow">→</span>
              </template>
            </div>
          </div>
        </div>

        <div class="vc-side">
          <span class="vc-status" :class="row.submitted ? 'verified' : 'likely'">
            {{ row.submitted ? "✓ 已提交" : "◷ 待提交" }}
          </span>
          <span v-if="row.score" class="vc-score">{{ row.score }} 分</span>
          <time>{{ fmtLocalTime(row.user_reviewed_at || row.created_at) }}</time>
        </div>
      </article>
    </div>

    <div v-if="!initialLoading && total > pageSize" class="hard-pager">
      <button type="button" @click="prevPage" :disabled="page <= 0 || refreshing">上一页</button>
      <span>第 {{ page + 1 }} 页 · {{ page * pageSize + 1 }}-{{ page * pageSize + rows.length }} / {{ total }}</span>
      <button type="button" @click="nextPage" :disabled="!hasMore || refreshing">下一页</button>
    </div>

    <ReportDrawer :finding-id="drawerId" mode="view" @close="drawerId = null"
      @updated="onDrawerUpdated" @toast="toast" />
    <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
  </section>
</template>
