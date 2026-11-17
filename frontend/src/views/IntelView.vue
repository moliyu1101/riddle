<script setup>
import { computed, onActivated, onMounted, ref, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { api, canWrite } from "../api.js";
import { showToast } from "../composables/useToast.js";

defineOptions({ name: "IntelView" });

const route = useRoute();
const router = useRouter();
const activeTab = ref("intel");
const intelSort = ref("utility");
const intelSignal = ref("all");
const kbOriginFilter = ref("all");
const selectedHardIds = ref([]);

/* ---------- 情报沉淀 ---------- */
const stats = ref({ total: 0, by_kind: {}, verified: 0, reused: 0 });
const hitStats = ref(null);
const rows = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const kind = ref("all");
const confidence = ref("all");
const searchDraft = ref("");
const searchText = ref("");
const curator = ref(null);
const curatorLoading = ref(false);
const curatorApplying = ref(false);
let searchTimer = null;
const writable = computed(() => canWrite());

const KIND_META = {
  cred: { label: "凭证", icon: "🔑", hue: "danger" },
  fingerprint: { label: "打法", icon: "🎯", hue: "info" },
  endpoint: { label: "端点", icon: "🧭", hue: "warn" },
  profile: { label: "画像", icon: "🪪", hue: "ok" },
  lesson: { label: "经验", icon: "📚", hue: "accent" },
  cve_feed: { label: "CVE 情报", icon: "🛡", hue: "warn" },
};

const KIND_TABS = [
  { id: "all", label: "全部" },
  { id: "cred", label: "凭证" },
  { id: "fingerprint", label: "打法" },
  { id: "endpoint", label: "端点" },
  { id: "profile", label: "画像" },
  { id: "lesson", label: "经验" },
  { id: "cve_feed", label: "CVE 情报" },
];

async function loadStats() {
  try { stats.value = await api.intelStats(); } catch { /* keep */ }
}

async function loadHitStats() {
  try { hitStats.value = await api.intelHitStats(); } catch { hitStats.value = null; }
}

async function loadList() {
  if (!rows.value.length) initialLoading.value = true;
  else refreshing.value = true;
  try {
    rows.value = await api.intelList(kind.value, confidence.value, searchText.value, 800);
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

async function reloadIntel() {
  await Promise.all([loadStats(), loadHitStats(), loadList(), previewCurator()]);
}

function fmtTime(iso) {
  if (!iso) return "-";
  return iso.slice(0, 19).replace("T", " ");
}

// 命中统计面板：复用分布比例 + 类别复用概况条宽
const reuseDistPct = computed(() => {
  const d = hitStats.value?.reuse_dist || {};
  const total = (d.once || 0) + (d.few || 0) + (d.many || 0);
  if (!total) return { once: 0, few: 0, many: 0 };
  return {
    once: Math.round(((d.once || 0) / total) * 100),
    few: Math.round(((d.few || 0) / total) * 100),
    many: Math.round(((d.many || 0) / total) * 100),
  };
});
const hitKinds = computed(() =>
  Object.keys(hitStats.value?.by_kind || {}).filter((k) => KIND_META[k])
);
function kindBarWidth(k) {
  const b = hitStats.value?.by_kind?.[k];
  if (!b || !b.avg_hit) return 0;
  const max = Math.max(1, ...Object.values(hitStats.value.by_kind).map((x) => x.avg_hit || 0));
  return Math.round((b.avg_hit / max) * 100);
}

function primaryText(row) {
  const p = row.payload || {};
  if (row.kind === "cred") return `${p.username || "?"} : ${p.password || "?"}`;
  if (row.kind === "endpoint") return p.path || row.summary || "-";
  if (row.kind === "fingerprint") return p.tactic || row.summary || "-";
  if (row.kind === "profile") return `${p.key || ""}：${p.value || ""}`;
  if (row.kind === "lesson") {
    const tag = p.lesson_type === "poc" ? "有效打法" : "易踩坑";
    return `${tag} [${p.vuln_type || "其他"}] ${p.title || ""}`.trim();
  }
  if (row.kind === "cve_feed") {
    const score = p.cvss ? `CVSS ${Number(p.cvss).toFixed(1)}` : "";
    const kev = p.kev ? " · KEV" : "";
    return `${p.cve_id || row.summary || "-"}${score ? ` · ${score}` : ""}${kev}`;
  }
  return row.summary || "-";
}

function secondaryText(row) {
  const p = row.payload || {};
  if (row.kind === "endpoint" && p.vuln_type) return p.vuln_type;
  if (row.kind === "fingerprint" && p.vuln_type) return p.vuln_type;
  if (row.kind === "lesson") {
    if (p.lesson_type === "poc" && p.repro) return `复现：${p.repro}`;
    if (p.lesson_type === "pitfall" && p.reason) return p.reason;
  }
  if (row.kind === "cve_feed") {
    const prods = Array.isArray(p.products) && p.products.length ? `受影响组件：${p.products.slice(0, 6).join(", ")}` : "";
    return prods ? `${prods} · ${row.summary || ""}` : (row.summary || "");
  }
  return row.summary || "";
}

async function removeOne(row) {
  if (!writable.value) return;
  if (!confirm(`确认删除这条情报？\n${row.match_key} · ${primaryText(row)}`)) return;
  try {
    await api.deleteIntel(row.id);
    showToast("情报条目已删除", "ok");
    await reloadIntel();
  } catch (e) {
    showToast(`删除失败：${e?.message || e}`, "danger");
  }
}

async function clearKind() {
  if (!writable.value) return;
  const label = kind.value === "all" ? "全部" : (KIND_META[kind.value]?.label || kind.value);
  if (!confirm(`确认清空【${label}】情报？此操作不可恢复。`)) return;
  try {
    await api.clearIntel(kind.value);
    showToast(`已清空【${label}】情报`, "ok");
    await reloadIntel();
  } catch (e) {
    showToast(`清空失败：${e?.message || e}`, "danger");
  }
}

async function previewCurator() {
  curatorLoading.value = true;
  try {
    curator.value = await api.previewIntelCurate(1000);
  } catch {
    curator.value = null;
  } finally {
    curatorLoading.value = false;
  }
}

async function applyCurator() {
  if (!writable.value) return;
  const flagged = curator.value?.flagged || 0;
  if (!flagged) return;
  if (!confirm(`Intel Curator 发现 ${flagged} 条低价值候选。\n将只清理未验证且未复用的明显垃圾，确认执行？`)) return;
  curatorApplying.value = true;
  try {
    const res = await api.applyIntelCurate(1000);
    const kept = res?.kept_hot || 0;
    showToast(
      `已清理 ${res?.deleted || 0} 条垃圾情报` + (kept ? `，保留 ${kept} 条高频复用项（hit≥3）` : ""),
      "ok",
    );
    curator.value = res;
    await reloadIntel();
  } catch (e) {
    showToast(`清理失败：${e?.message || e}`, "danger");
  } finally {
    curatorApplying.value = false;
  }
}

const convertedIntelCount = computed(() =>
  rows.value.filter((r) => (r.converted_count || 0) > 0).length
);
const pitfallCount = computed(() =>
  rows.value.filter((r) => r.payload?.lesson_type === "pitfall").length
);
const filteredAndSortedIntel = computed(() => {
  let list = rows.value.slice();
  if (intelSignal.value === "converted") {
    list = list.filter((r) => (r.converted_count || 0) > 0);
  } else if (intelSignal.value === "human_verified") {
    list = list.filter((r) => !!r.payload?.human_verified);
  } else if (intelSignal.value === "pitfall") {
    list = list.filter((r) => r.payload?.lesson_type === "pitfall");
  }
  if (intelSort.value === "utility") {
    list.sort((a, b) => (Number(b.utility_score || 0) - Number(a.utility_score || 0)) || ((b.hit_count || 0) - (a.hit_count || 0)));
  } else if (intelSort.value === "converted") {
    list.sort((a, b) => (Number(b.converted_count || 0) - Number(a.converted_count || 0)) || (Number(b.utility_score || 0) - Number(a.utility_score || 0)));
  } else if (intelSort.value === "hit") {
    list.sort((a, b) => (Number(b.hit_count || 0) - Number(a.hit_count || 0)));
  }
  return list;
});
function utilityBarPct(score) {
  const n = Number(score || 0);
  return Math.max(4, Math.min(100, Math.round((n / 6.0) * 100)));
}

watch([kind, confidence], reloadIntel);
watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => {
    searchText.value = v.trim();
    loadList();
  }, 180);
});

/* ---------- 硬骨头 ---------- */
const hardStats = ref({ total: 0, dead: 0, skipped: 0 });
const hardRows = ref([]);
const hardLoading = ref(true);
const hardRefreshing = ref(false);
const hardReviving = ref(false);
const hardStatus = ref("all");
const hardSearchDraft = ref("");
const hardSearchText = ref("");
const hardTotal = ref(0);
const hardPage = ref(0);
const hardPageSize = 100;
const hardHasMore = ref(false);
let hardSearchTimer = null;

const HARD_STATUS_LABEL = {
  dead: "硬骨头",
  skipped: "已跳过",
};

async function loadHardStats() {
  try { hardStats.value = await api.hardTargetsStats(); } catch { /* keep */ }
}

async function loadHardList() {
  if (!hardRows.value.length) hardLoading.value = true;
  else hardRefreshing.value = true;
  try {
    const res = await api.hardTargets(hardStatus.value, hardSearchText.value, {
      limit: hardPageSize,
      offset: hardPage.value * hardPageSize,
    });
    hardRows.value = Array.isArray(res) ? res : (res.items || []);
    hardTotal.value = Array.isArray(res) ? hardRows.value.length : (res.total || 0);
    hardHasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    hardLoading.value = false;
    hardRefreshing.value = false;
  }
}

async function reloadHard() {
  hardPage.value = 0;
  await Promise.all([loadHardStats(), loadHardList()]);
}

function hardNextPage() {
  if (!hardHasMore.value || hardRefreshing.value) return;
  hardPage.value += 1;
  loadHardList();
}

function hardPrevPage() {
  if (hardPage.value <= 0 || hardRefreshing.value) return;
  hardPage.value -= 1;
  loadHardList();
}

function hardReasonOf(row) {
  return row.dead_reason || row.last_error || row.priority_reason || "无记录";
}

function openTask(row) {
  router.push(`/task/${row.task_id}`);
}

async function reviveSingleHard(row) {
  if (!row?.id || hardReviving.value) return;
  hardReviving.value = true;
  try {
    const res = await api.reviveHardTargets({
      target_ids: [row.id],
      inject_latest_intel: true,
    });
    selectedHardIds.value = selectedHardIds.value.filter((x) => x !== row.id);
    await reloadHard();
    showToast(`已唤醒 ${res?.revived_count ?? 1} 个硬骨头目标重新入队`, "ok");
  } catch (e) {
    showToast(`唤醒失败：${e?.message || e}`, "danger");
  } finally {
    hardReviving.value = false;
  }
}

function toggleHardSelect(id) {
  const s = new Set(selectedHardIds.value);
  if (s.has(id)) s.delete(id); else s.add(id);
  selectedHardIds.value = [...s];
}
function toggleSelectAllHard() {
  if (selectedHardIds.value.length === hardRows.value.length) {
    selectedHardIds.value = [];
  } else {
    selectedHardIds.value = hardRows.value.map((r) => r.id);
  }
}
async function reviveSelectedHard() {
  if (!selectedHardIds.value.length || hardReviving.value) return;
  hardReviving.value = true;
  try {
    const res = await api.reviveHardTargets({
      target_ids: selectedHardIds.value,
      inject_latest_intel: true,
    });
    selectedHardIds.value = [];
    await reloadHard();
    showToast(`已唤醒 ${res?.revived_count ?? 0} 个选中目标重新入队（涉及 ${(res?.task_ids || []).length} 个任务）`, "ok");
  } catch (e) {
    showToast(`唤醒选中失败：${e?.message || e}`, "danger");
  } finally {
    hardReviving.value = false;
  }
}

async function reviveAllFilteredHard() {
  if (!hardRows.value.length || hardReviving.value) return;
  const est = Math.min(hardTotal.value || hardRows.value.length, 50);
  if (!confirm(`确定按当前筛选条件唤醒最多 ${est} 个硬骨头目标，并注入最新情报与蒸馏知识库重测吗？`)) return;
  hardReviving.value = true;
  try {
    const res = await api.reviveHardTargets({
      status: hardStatus.value,
      q: hardSearchText.value || undefined,
      limit: 50,
      inject_latest_intel: true,
    });
    selectedHardIds.value = [];
    await reloadHard();
    showToast(`已批量唤醒 ${res?.revived_count ?? 0} 个硬骨头目标重新入队（涉及 ${(res?.task_ids || []).length} 个任务）`, "ok");
  } catch (e) {
    showToast(`批量唤醒失败：${e?.message || e}`, "danger");
  } finally {
    hardReviving.value = false;
  }
}

/* ---------- 知识库 ---------- */
const kbRows = ref([]);
const kbLoading = ref(true);
const kbRefreshing = ref(false);
const kbCategory = ref("all");
const kbSearchDraft = ref("");
const kbSearchText = ref("");
const kbViewOpen = ref(false);
const kbViewed = ref(null);
const kbAddOpen = ref(false);
const kbEditId = ref(null);
const kbForm = ref({ title: "", category: "user", keyword: "", content: "", enabled: true });
const checking = ref(false);
let kbTimer = null;

// 种子条目标题 summary 带“（分类）”后缀，与列表的类型标签重复，展示时剥掉
function kbCleanTitle(row) {
  const s = (row?.summary || row?.match_key || "").replace(/（[^）]*）$/, "").trim();
  return s || "未命名知识";
}
function kbOrigin(row) {
  if (row?.origin === "distilled") return "⚡ 实战蒸馏";
  return row?.origin === "seed" ? "种子库导入" : "用户沉淀";
}

const KB_CATS = [
  { id: "all", label: "全部" },
  { id: "rules", label: "方法论" },
  { id: "kb", label: "测试手册" },
  { id: "user", label: "用户沉淀" },
];
const KB_CAT_LABEL = { rules: "方法论", kb: "测试手册", user: "用户沉淀" };
function kbCatLabel(c) { return KB_CAT_LABEL[c] || "知识"; }

async function loadKbList() {
  if (!kbRows.value.length) kbLoading.value = true;
  else kbRefreshing.value = true;
  try {
    kbRows.value = await api.knowledgeList(kbCategory.value, kbSearchText.value);
  } finally {
    kbLoading.value = false;
    kbRefreshing.value = false;
  }
}
function reloadKb() { return loadKbList(); }
watch(kbCategory, loadKbList);
watch(kbSearchDraft, (v) => {
  clearTimeout(kbTimer);
  kbTimer = setTimeout(() => {
    kbSearchText.value = v.trim();
    loadKbList();
  }, 180);
});

const distilledKbCount = computed(() => kbRows.value.filter((r) => r?.origin === "distilled").length);
const userKbCount = computed(() => kbRows.value.filter((r) => r?.origin !== "seed" && r?.origin !== "distilled").length);
const seedKbCount = computed(() => kbRows.value.filter((r) => r?.origin === "seed").length);
const visibleKbRows = computed(() => {
  if (kbOriginFilter.value === "all") return kbRows.value;
  if (kbOriginFilter.value === "distilled") return kbRows.value.filter((r) => r?.origin === "distilled");
  if (kbOriginFilter.value === "seed") return kbRows.value.filter((r) => r?.origin === "seed");
  return kbRows.value.filter((r) => r?.origin !== "seed" && r?.origin !== "distilled");
});

async function viewKb(row) {
  try {
    kbViewed.value = await api.knowledgeDetail(row.id);
    kbViewOpen.value = true;
  } catch (e) {
    showToast(`读取失败：${e?.message || e}`, "danger");
  }
}
// 关联篇目跳转：优先在当前列表按 match_key 命中，否则按名称查全库
async function viewKbByName(name) {
  const row = kbRows.value.find((r) => r.match_key === name || r.name === name);
  if (row) return viewKb(row);
  try {
    const list = await api.knowledgeList("all", name);
    const hit = list.find((r) => r.match_key === name || r.name === name);
    if (hit) return viewKb(hit);
    showToast(`未找到关联篇目：${name}`, "warn");
  } catch (e) {
    showToast(`跳转失败：${e?.message || e}`, "danger");
  }
}
function closeKbView() {
  kbViewOpen.value = false;
  kbViewed.value = null;
}
async function removeKb(row) {
  if (!writable.value) return;
  if (!confirm(`确认删除这篇知识？\n${row.summary || row.match_key}`)) return;
  try {
    await api.deleteIntel(row.id);
    showToast("知识条目已删除", "ok");
    await reloadKb();
    await loadStats();
  } catch (e) {
    showToast(`删除失败：${e?.message || e}`, "danger");
  }
}
async function toggleKb(row) {
  try {
    await api.knowledgeUpdate(row.id, { enabled: !row.enabled });
    showToast(!row.enabled ? "知识已启用" : "知识已停用", "ok");
    await reloadKb();
  } catch (e) {
    showToast(`操作失败：${e?.message || e}`, "danger");
  }
}
async function syncKb() {
  if (!writable.value || checking.value) return;
  checking.value = true;
  try {
    const res = await api.knowledgeSync();
    showToast(`种子同步完成：新增 ${res?.added ?? 0} 篇，跳过 ${res?.skipped ?? 0} 篇`, "ok");
    await reloadKb();
    await loadStats();
  } catch (e) {
    showToast(`同步失败：${e?.message || e}`, "danger");
  } finally {
    checking.value = false;
  }
}
function autoCloseKbView() {
  // 编辑保存后关闭详情/编辑弹层，复位编辑态
  kbViewOpen.value = false;
  kbViewed.value = null;
  kbEditId.value = null;
  kbAddOpen.value = false;
}
function openAddKb() {
  kbEditId.value = null;
  kbForm.value = { title: "", category: "user", keyword: "", content: "", enabled: true };
  kbAddOpen.value = true;
}
async function openEditKb(row) {
  try {
    const d = await api.knowledgeDetail(row.id);
    kbForm.value = {
      title: d.name || kbCleanTitle(d),
      category: d.category || "user",
      keyword: d.keyword || "",
      content: d.content || "",
      enabled: !!d.enabled,
    };
    kbEditId.value = row.id;
    kbViewOpen.value = false;
    kbAddOpen.value = true;
  } catch (e) {
    showToast(`读取失败：${e?.message || e}`, "danger");
  }
}
async function saveKb() {
  if (!writable.value) return;
  if (!kbForm.value.content.trim()) { showToast("内容不能为空", "warn"); return; }
  try {
    if (kbEditId.value) {
      await api.knowledgeUpdate(kbEditId.value, kbForm.value);
    } else {
      await api.knowledgeCreate(kbForm.value);
    }
    autoCloseKbView();
    showToast(kbEditId.value ? "知识修改已保存" : "知识条目已沉淀", "ok");
    await reloadKb();
    await loadStats();
  } catch (e) {
    showToast(`保存失败：${e?.message || e}`, "danger");
  }
}
async function copyKbContent(row) {
  const content = row?.content || "";
  if (!content) { showToast("内容为空，无可复制", "warn"); return; }
  try {
    await navigator.clipboard.writeText(content);
    showToast("知识正文已复制到剪贴板", "ok");
  } catch {
    showToast("复制失败，请手动选中复制", "warn");
  }
}

watch(hardStatus, reloadHard);
watch(hardSearchDraft, (v) => {
  clearTimeout(hardSearchTimer);
  hardSearchTimer = setTimeout(() => {
    hardSearchText.value = v.trim();
    hardPage.value = 0;
    loadHardList();
  }, 160);
});

/* ---------- CVE 时间流同步 ---------- */
const cveSyncing = ref(false);
const cveSyncMsg = ref("");
const cveSyncErr = ref("");
const fusionIntervalHours = ref(0);
const fusionLookbackDays = ref(7);

async function loadFusionIntelConfig() {
  try {
    const res = await api.fusionConfig();
    const cfg = res?.config || res || {};
    fusionIntervalHours.value = Number(cfg.intel_sync_interval_hours || 0);
    fusionLookbackDays.value = Number(cfg.intel_lookback_days || 7);
  } catch { /* keep */ }
}

async function syncCveIntel() {
  if (!writable.value || cveSyncing.value) return;
  cveSyncing.value = true;
  cveSyncErr.value = "";
  cveSyncMsg.value = "";
  try {
    const res = await api.fusionIntelSync();
    const errs = res?.errors?.length ? `（告警：${res.errors.join("；")}）` : "";
    cveSyncMsg.value = `同步完成：条目 ${res?.entry_count ?? 0}，快通道 ${res?.fastlane_count ?? 0}，入库 ${res?.stored ?? 0}${errs}`;
    await reloadIntel();
    await loadFusionIntelConfig();
  } catch (e) {
    cveSyncErr.value = `同步失败：${e?.message || e}`;
  } finally {
    cveSyncing.value = false;
  }
}

/* ---------- 公共 ---------- */
function applyRouteQuery() {
  const q = route.query || {};
  const tab = String(q.tab || "").trim();
  if (tab === "intel" || tab === "kb" || tab === "hard") {
    activeTab.value = tab;
  }
  const orig = String(q.origin || "").trim();
  if (orig === "distilled" || orig === "user" || orig === "seed" || orig === "all") {
    kbOriginFilter.value = orig;
  }
}

async function reload() {
  applyRouteQuery();
  await Promise.all([reloadIntel(), reloadHard(), loadKbList(), loadFusionIntelConfig()]);
}

watch(() => route.query, applyRouteQuery);
onMounted(reload);
onActivated(() => {
  applyRouteQuery();
  if (rows.value.length || hardRows.value.length) reload();
});
</script>

<template>
  <section class="view studio-view" :class="{ 'is-refreshing': refreshing || hardRefreshing }">
    <div v-if="(refreshing || hardRefreshing) && !initialLoading && !hardLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <!-- Compact Studio Breadcrumb + Header -->
    <header class="studio-head">
      <div class="sh-left">
        <div class="sh-crumb">
          <span>COMMAND CENTER</span>
          <span class="sh-sep">/</span>
          <b>EVOLUTION &amp; KNOWLEDGE STUDIO</b>
        </div>
        <div class="sh-title-row">
          <h2>自主知识与进化中心</h2>
          <span class="sh-tag">CLOSED-LOOP · 4 STAGES</span>
        </div>
        <p class="sh-sub">情报效用淘汰 · 人工复审正负向反馈 · 高危实战脱敏蒸馏入库 · 硬骨头携情报定向唤醒。</p>
      </div>
      <div class="sh-right">
        <router-link class="btn-studio-ghost" to="/">← 返回作战台</router-link>
      </div>
    </header>

    <!-- 四阶自主进化闭环管线 -->
    <div class="evo-pipeline" role="region" aria-label="自主能力进化闭环总览">
      <button type="button" class="evo-stage" :class="{ on: activeTab === 'intel' && intelSignal === 'all' }" @click="activeTab = 'intel'; intelSignal = 'all'">
        <div class="evo-meta"><span class="evo-step">01</span><span class="evo-tag">INGEST</span></div>
        <b>情报与 CVE 汇聚</b>
        <em>{{ stats.total }} 条 · CVE {{ stats.by_kind?.cve_feed || 0 }}</em>
      </button>
      <button type="button" class="evo-stage" :class="{ on: activeTab === 'intel' && intelSignal !== 'all' }" @click="activeTab = 'intel'; intelSignal = 'converted'">
        <div class="evo-meta"><span class="evo-step">02</span><span class="evo-tag">FEEDBACK</span></div>
        <b>效用评估与复审反哺</b>
        <em>成洞 {{ convertedIntelCount }} · 避坑 {{ pitfallCount }}</em>
      </button>
      <button type="button" class="evo-stage" :class="{ on: activeTab === 'kb' }" @click="activeTab = 'kb'; kbOriginFilter = 'distilled'">
        <div class="evo-meta"><span class="evo-step">03</span><span class="evo-tag">DISTILL</span></div>
        <b>实战脱敏蒸馏知识库</b>
        <em>总 {{ kbRows.length }} 篇 · ⚡ {{ distilledKbCount }} 蒸馏</em>
      </button>
      <button type="button" class="evo-stage" :class="{ on: activeTab === 'hard' }" @click="activeTab = 'hard'">
        <div class="evo-meta"><span class="evo-step">04</span><span class="evo-tag">REVIVE</span></div>
        <b>硬骨头携情报唤醒</b>
        <em>待唤醒 {{ hardStats.total }}（🦴 {{ hardStats.dead }} / ⏭ {{ hardStats.skipped }}）</em>
      </button>
    </div>

    <!-- Asymmetric 2-Column Studio Body -->
    <div class="studio-layout">
      <!-- Left Facet Control Rail -->
      <aside class="studio-rail" aria-label="情报与进化控制面板">
        <div class="rail-block">
          <div class="rail-label">核心数据存储区 / STORES</div>
          <div class="rail-stores" role="tablist" aria-label="情报分区">
            <button type="button" role="tab" :aria-selected="activeTab === 'intel'"
                    class="rail-store-btn" :class="{ on: activeTab === 'intel' }" @click="activeTab = 'intel'">
              <span class="rs-icon">🧠</span>
              <span class="rs-copy"><b>效用情报库</b><small>凭证 / 画像 / CVE / 经验</small></span>
              <span class="rs-num">{{ stats.total }}</span>
            </button>
            <button type="button" role="tab" :aria-selected="activeTab === 'kb'"
                    class="rail-store-btn" :class="{ on: activeTab === 'kb' }" @click="activeTab = 'kb'">
              <span class="rs-icon">📚</span>
              <span class="rs-copy"><b>挖洞知识库</b><small>实战蒸馏 / 手册 / 用户沉淀</small></span>
              <span class="rs-num">{{ kbRows.length }}</span>
            </button>
            <button type="button" role="tab" :aria-selected="activeTab === 'hard'"
                    class="rail-store-btn" :class="{ on: activeTab === 'hard' }" @click="activeTab = 'hard'">
              <span class="rs-icon">🦴</span>
              <span class="rs-copy"><b>硬骨头唤醒池</b><small>dead / skipped 定向重测</small></span>
              <span class="rs-num">{{ hardStats.total }}</span>
            </button>
          </div>
        </div>

        <!-- Contextual Controls for INTEL -->
        <template v-if="activeTab === 'intel'">
          <div class="rail-block">
            <div class="rail-label">全文检索</div>
            <div class="rail-search">
              <span>⌕</span>
              <input v-model="searchDraft" placeholder="域名 / 账号 / 路径 / 来源..." />
            </div>
          </div>

          <div class="rail-block">
            <div class="rail-label">反馈信号与排序</div>
            <div class="rail-facet-list">
              <button type="button" class="rail-facet" :class="{ on: intelSignal === 'all' }" @click="intelSignal = 'all'">
                <span>全部情报信号</span><em>{{ stats.total }}</em>
              </button>
              <button type="button" class="rail-facet" :class="{ on: intelSignal === 'converted' }" @click="intelSignal = 'converted'">
                <span>🔥 已转化成洞</span><em>{{ convertedIntelCount }}</em>
              </button>
              <button type="button" class="rail-facet" :class="{ on: intelSignal === 'human_verified' }" @click="intelSignal = 'human_verified'">
                <span>✓ 人工核准高可信</span>
              </button>
              <button type="button" class="rail-facet" :class="{ on: intelSignal === 'pitfall' }" @click="intelSignal = 'pitfall'">
                <span>⛔ 人工驳回避坑</span><em>{{ pitfallCount }}</em>
              </button>
            </div>
            <div class="rail-selects">
              <select v-model="intelSort" aria-label="排序方式">
                <option value="utility">按效用分最高</option>
                <option value="converted">按成洞转化最多</option>
                <option value="hit">按复用次数最多</option>
                <option value="recent">按最新沉淀</option>
              </select>
              <select v-model="confidence" aria-label="可信度过滤">
                <option value="all">全部可信度</option>
                <option value="verified">仅已验证</option>
                <option value="likely">仅疑似</option>
              </select>
            </div>
          </div>

          <div class="rail-block">
            <div class="rail-label">情报类型分面</div>
            <div class="rail-facet-list">
              <button v-for="t in KIND_TABS" :key="t.id" type="button"
                      class="rail-facet" :class="{ on: kind === t.id }" @click="kind = t.id">
                <span>{{ t.id === 'all' ? '全部类型' : `${KIND_META[t.id]?.icon || ''} ${t.label}` }}</span>
                <em>{{ t.id === 'all' ? stats.total : (stats.by_kind?.[t.id] || 0) }}</em>
              </button>
            </div>
          </div>

          <div class="rail-block">
            <div class="rail-label">CVE 时间流与库维护</div>
            <div class="rail-actions-col">
              <button type="button" class="btn-studio-primary" @click="syncCveIntel" :disabled="cveSyncing || !writable"
                      title="拉取 NVD / CISA KEV 近期漏洞情报写入 CVE 情报库">
                {{ cveSyncing ? "同步 CVE 中…" : "⚡ 同步 CVE 时间流" }}
              </button>
              <div class="rail-btn-row">
                <button type="button" class="btn-studio-ghost" @click="reloadIntel" :disabled="refreshing">{{ refreshing ? "刷新中…" : "↻ 刷新" }}</button>
                <button v-if="writable" type="button" class="btn-studio-danger" @click="clearKind">清空当前类</button>
              </div>
              <p class="rail-note">
                <template v-if="fusionIntervalHours > 0">
                  自动同步：每 {{ fusionIntervalHours }}h（回溯 {{ fusionLookbackDays }} 天）
                </template>
                <template v-else>
                  手动模式（回溯 {{ fusionLookbackDays }} 天 · <router-link to="/settings">设置</router-link>）
                </template>
              </p>
              <p v-if="cveSyncMsg" class="rail-msg ok">{{ cveSyncMsg }}</p>
              <p v-else-if="cveSyncErr" class="rail-msg err">{{ cveSyncErr }}</p>
            </div>
          </div>

          <div class="rail-block curator-rail-box">
            <div class="rail-label">INTEL CURATOR 质检</div>
            <p class="rail-note">
              {{ curatorLoading ? "检查中…" : `候选冗余/失效 ${curator?.flagged || 0} 条（共检 ${curator?.examined || 0} 条）` }}
            </p>
            <p v-if="curator?.items?.length" class="curator-sample">
              示例：{{ KIND_META[curator.items[0].kind]?.label || curator.items[0].kind }} · {{ curator.items[0].match_key }} · {{ curator.items[0].reasons?.join("、") }}
            </p>
            <div class="rail-btn-row">
              <button type="button" class="btn-studio-ghost" @click="previewCurator" :disabled="curatorLoading">重新检查</button>
              <button v-if="writable" type="button" class="btn-studio-danger" @click="applyCurator" :disabled="curatorApplying || !(curator?.flagged)">
                {{ curatorApplying ? "清理中…" : "维护清理" }}
              </button>
            </div>
          </div>
        </template>

        <!-- Contextual Controls for KB -->
        <template v-else-if="activeTab === 'kb'">
          <div class="rail-block">
            <div class="rail-label">检索知识库</div>
            <div class="rail-search">
              <span>⌕</span>
              <input v-model="kbSearchDraft" placeholder="篇名 / 关键词 / 漏洞类型..." />
            </div>
          </div>
          <div class="rail-block">
            <div class="rail-label">知识来源层级</div>
            <div class="rail-facet-list">
              <button type="button" class="rail-facet" :class="{ on: kbOriginFilter === 'all' }" @click="kbOriginFilter = 'all'">
                <span>全部知识条目</span><em>{{ kbRows.length }}</em>
              </button>
              <button type="button" class="rail-facet" :class="{ on: kbOriginFilter === 'distilled' }" @click="kbOriginFilter = 'distilled'">
                <span>⚡ 实战脱敏蒸馏</span><em>{{ distilledKbCount }}</em>
              </button>
              <button type="button" class="rail-facet" :class="{ on: kbOriginFilter === 'user' }" @click="kbOriginFilter = 'user'">
                <span>✍ 用户手工沉淀</span><em>{{ userKbCount }}</em>
              </button>
              <button type="button" class="rail-facet" :class="{ on: kbOriginFilter === 'seed' }" @click="kbOriginFilter = 'seed'">
                <span>📦 内置种子手册</span><em>{{ seedKbCount }}</em>
              </button>
            </div>
          </div>
          <div class="rail-block">
            <div class="rail-label">文档分类</div>
            <div class="rail-facet-list">
              <button v-for="t in KB_CATS" :key="t.id" type="button"
                      class="rail-facet" :class="{ on: kbCategory === t.id }" @click="kbCategory = t.id">
                <span>{{ t.label }}</span>
              </button>
            </div>
          </div>
          <div class="rail-block">
            <div class="rail-label">知识库维护</div>
            <div class="rail-actions-col">
              <button v-if="writable" type="button" class="btn-studio-primary" @click="openAddKb">＋ 手动添加知识</button>
              <button type="button" class="btn-studio-ghost" @click="syncKb" :disabled="checking || !writable">{{ checking ? "同步中…" : "↻ 同步本地种子库" }}</button>
            </div>
          </div>
        </template>

        <!-- Contextual Controls for HARD -->
        <template v-else>
          <div class="rail-block">
            <div class="rail-label">目标检索</div>
            <div class="rail-search">
              <span>⌕</span>
              <input v-model="hardSearchDraft" placeholder="任务 / 单位 / URL / 阻塞原因..." />
            </div>
          </div>
          <div class="rail-block">
            <div class="rail-label">目标状态筛选</div>
            <div class="rail-facet-list">
              <button type="button" class="rail-facet" :class="{ on: hardStatus === 'all' }" @click="hardStatus = 'all'">
                <span>全部待唤醒</span><em>{{ hardStats.total }}</em>
              </button>
              <button type="button" class="rail-facet" :class="{ on: hardStatus === 'dead' }" @click="hardStatus = 'dead'">
                <span>🦴 硬骨头 (dead)</span><em>{{ hardStats.dead }}</em>
              </button>
              <button type="button" class="rail-facet" :class="{ on: hardStatus === 'skipped' }" @click="hardStatus = 'skipped'">
                <span>⏭ 已跳过 (skipped)</span><em>{{ hardStats.skipped }}</em>
              </button>
            </div>
          </div>
          <div class="rail-block">
            <div class="rail-label">定向唤醒调度</div>
            <div class="rail-actions-col">
              <button type="button" class="btn-studio-primary" @click="reviveAllFilteredHard" :disabled="hardReviving || !hardRows.length"
                      title="将当前筛选下的硬骨头目标复位入队，并注入最新沉淀情报与知识库重测">
                {{ hardReviving ? "唤醒调度中…" : "⚡ 批量唤醒当前列表" }}
              </button>
              <button v-if="selectedHardIds.length" type="button" class="btn-studio-accent" @click="reviveSelectedHard" :disabled="hardReviving">
                {{ hardReviving ? "唤醒中…" : `⚡ 唤醒已选 (${selectedHardIds.length})` }}
              </button>
              <div class="rail-btn-row">
                <button v-if="hardRows.length" type="button" class="btn-studio-ghost" @click="toggleSelectAllHard">
                  {{ selectedHardIds.length === hardRows.length ? "取消全选" : `全选 (${hardRows.length})` }}
                </button>
                <button type="button" class="btn-studio-ghost" @click="reloadHard" :disabled="hardRefreshing">{{ hardRefreshing ? "刷新中…" : "↻ 刷新" }}</button>
              </div>
            </div>
          </div>
        </template>
      </aside>

      <!-- Right Studio Main Workbench -->
      <div class="studio-main">
        <!-- ============ 1. 效用情报库 ============ -->
        <template v-if="activeTab === 'intel'">
          <!-- Compact Analytics Summary Strip -->
          <div class="intel-kpi-strip">
            <div class="ik-cell hero">
              <span class="ik-label">情报总库存 / VALIDATED</span>
              <div class="ik-val-row">
                <b>{{ stats.total }}</b>
                <small>已验证 {{ stats.verified }} · 被复用 {{ stats.reused }}</small>
              </div>
            </div>
            <div class="ik-cell" v-if="hitStats">
              <span class="ik-label">命中复用分层</span>
              <div class="ik-dist-bar">
                <i class="once" :style="{ width: reuseDistPct.once + '%' }"></i>
                <i class="few" :style="{ width: reuseDistPct.few + '%' }"></i>
                <i class="many" :style="{ width: reuseDistPct.many + '%' }"></i>
              </div>
              <div class="ik-dist-meta">
                <span>1次: {{ hitStats.reuse_dist?.once || 0 }}</span>
                <span>2-5次: {{ hitStats.reuse_dist?.few || 0 }}</span>
                <span>6+次: {{ hitStats.reuse_dist?.many || 0 }}</span>
              </div>
            </div>
            <div class="ik-cell" v-if="hitStats && (hitStats.top_reused || []).length">
              <span class="ik-label">高频复用榜首</span>
              <div class="ik-top-item">
                <b>{{ hitStats.top_reused[0].summary || hitStats.top_reused[0].match_key }}</b>
                <em>×{{ hitStats.top_reused[0].hit_count }}</em>
              </div>
              <small>{{ KIND_META[hitStats.top_reused[0].kind]?.label || hitStats.top_reused[0].kind }} · {{ hitStats.top_reused[0].match_key }}</small>
            </div>
            <div class="ik-cell" v-if="hitStats && (hitStats.top_sources || []).length">
              <span class="ik-label">贡献主机 Top</span>
              <div class="ik-src-pills">
                <span v-for="s in (hitStats.top_sources || []).slice(0, 3)" :key="s.host" class="ik-src-pill">
                  {{ s.host }} <em>{{ s.count }}</em>
                </span>
              </div>
            </div>
          </div>

          <!-- Active Filter Summary Header -->
          <div class="main-toolbar">
            <div class="mt-title">
              <b>效用情报矩阵</b>
              <span class="mt-count">{{ filteredAndSortedIntel.length }} 条匹配记录</span>
            </div>
            <div class="mt-pills">
              <span v-if="kind !== 'all'" class="mt-pill" @click="kind = 'all'">类型：{{ KIND_META[kind]?.label || kind }} ✕</span>
              <span v-if="intelSignal !== 'all'" class="mt-pill" @click="intelSignal = 'all'">信号：{{ intelSignal }} ✕</span>
            </div>
          </div>

          <!-- High-Density Ledger Table -->
          <div v-if="initialLoading" class="studio-skeleton-list">
            <div v-for="n in 8" :key="n" class="skeleton-row"></div>
          </div>
          <div v-else-if="!filteredAndSortedIntel.length" class="studio-empty">
            <b>当前筛选下无情报记录</b>
            <span>Worker 出洞、跨目标撞库或人工复审反馈后会自动按效用加权沉淀至此。</span>
          </div>
          <div v-else class="studio-table-wrap">
            <table class="studio-table intel-ledger">
              <thead>
                <tr>
                  <th style="width: 145px;">类别与作用域</th>
                  <th>核心情报负载</th>
                  <th style="width: 148px;">效用分 &amp; 可信态</th>
                  <th style="width: 118px;">转化 / 复用</th>
                  <th style="width: 146px;">来源与时间</th>
                  <th style="width: 44px;" aria-label="操作"></th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in filteredAndSortedIntel" :key="row.id" class="ledger-row" :class="[KIND_META[row.kind]?.hue, { 'is-pitfall': row.payload?.human_rejected, 'is-verified-fb': row.payload?.human_verified }]">
                  <td>
                    <div class="td-kind-box">
                      <span class="kind-pill" :class="KIND_META[row.kind]?.hue">
                        {{ KIND_META[row.kind]?.icon }} {{ KIND_META[row.kind]?.label || row.kind }}
                      </span>
                      <code class="scope-code" :title="row.match_key">{{ row.match_key }}</code>
                    </div>
                  </td>
                  <td>
                    <div class="td-intel-copy">
                      <div class="tic-head">
                        <b>{{ primaryText(row) }}</b>
                        <span v-if="row.payload?.human_verified" class="fb-tag ok">✓ 人工核准</span>
                        <span v-else-if="row.payload?.human_rejected" class="fb-tag warn">⛔ 避坑指南</span>
                      </div>
                      <small v-if="secondaryText(row)" class="tic-sub">{{ secondaryText(row) }}</small>
                    </div>
                  </td>
                  <td>
                    <div class="td-utility-box">
                      <div class="u-top">
                        <span class="conf-tag" :class="row.confidence">{{ row.confidence === 'verified' ? '已验证' : '疑似' }}</span>
                        <b class="u-score">{{ Number(row.utility_score || 0).toFixed(1) }}</b>
                      </div>
                      <div class="u-meter"><i :style="{ width: utilityBarPct(row.utility_score) + '%' }"></i></div>
                    </div>
                  </td>
                  <td>
                    <div class="td-conv-box">
                      <span v-if="(row.converted_count || 0) > 0" class="conv-tag" title="注入给 Worker 后实际促成出洞的转化次数 / 注入次数">
                        🔥 {{ row.converted_count }}/{{ row.injected_count || row.converted_count }} 转化
                      </span>
                      <span v-else class="conv-muted">0 转化</span>
                      <small v-if="row.hit_count > 1" class="hit-tag">×{{ row.hit_count }} 复用</small>
                    </div>
                  </td>
                  <td>
                    <div class="td-src-box">
                      <span class="src-host" :title="row.source_host">{{ row.source_host || '未知来源' }}</span>
                      <time>{{ fmtTime(row.last_seen) }}</time>
                    </div>
                  </td>
                  <td class="td-act">
                    <button v-if="writable" class="row-del-btn" type="button" title="删除此情报" @click="removeOne(row)">✕</button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>

        <!-- ============ 2. 硬骨头唤醒池 ============ -->
        <template v-else-if="activeTab === 'hard'">
          <div class="intel-kpi-strip three">
            <div class="ik-cell hero">
              <span class="ik-label">待唤醒攻坚池 / TOTAL</span>
              <div class="ik-val-row">
                <b>{{ hardStats.total }}</b>
                <small>跨任务 dead / skipped 目标聚合</small>
              </div>
            </div>
            <div class="ik-cell clickable" :class="{ active: hardStatus === 'dead' }" @click="hardStatus = (hardStatus === 'dead' ? 'all' : 'dead')">
              <span class="ik-label">🦴 硬骨头 (DEAD)</span>
              <div class="ik-val-row"><b>{{ hardStats.dead }}</b><small>点击筛选仅看硬骨头</small></div>
            </div>
            <div class="ik-cell clickable" :class="{ active: hardStatus === 'skipped' }" @click="hardStatus = (hardStatus === 'skipped' ? 'all' : 'skipped')">
              <span class="ik-label">⏭ 已跳过 (SKIPPED)</span>
              <div class="ik-val-row"><b>{{ hardStats.skipped }}</b><small>点击筛选仅看跳过</small></div>
            </div>
          </div>

          <div class="main-toolbar">
            <div class="mt-title">
              <b>硬骨头定向唤醒队列</b>
              <span class="mt-count">唤醒时将自动注入最新情报与脱敏知识库重新入队</span>
            </div>
            <div class="mt-pills" v-if="selectedHardIds.length">
              <span class="mt-pill accent">已勾选 {{ selectedHardIds.length }} 项</span>
            </div>
          </div>

          <div v-if="hardLoading" class="studio-skeleton-list">
            <div v-for="n in 6" :key="n" class="skeleton-row"></div>
          </div>
          <div v-else-if="!hardRows.length" class="studio-empty">
            <b>当前暂无硬骨头目标</b>
            <span>打不动或暂时跳过的目标会自动沉淀至此，待新知识或新 CVE 到达时可一键唤醒。</span>
          </div>
          <div v-else class="studio-table-wrap">
            <table class="studio-table hard-ledger">
              <thead>
                <tr>
                  <th style="width: 38px;"><input type="checkbox" :checked="selectedHardIds.length === hardRows.length && hardRows.length > 0" @change="toggleSelectAllHard" aria-label="全选" /></th>
                  <th style="width: 100px;">状态</th>
                  <th>目标 URL 与归属任务</th>
                  <th style="width: 110px;">重试 / 权重</th>
                  <th style="width: 120px;">更新时间</th>
                  <th style="width: 112px; text-align: right;">唤醒操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in hardRows" :key="row.id" class="ledger-row is-clickable" :class="{ selected: selectedHardIds.includes(row.id) }" @click="openTask(row)">
                  <td @click.stop>
                    <input type="checkbox" :checked="selectedHardIds.includes(row.id)" @change="toggleHardSelect(row.id)" aria-label="选择此硬骨头目标" />
                  </td>
                  <td>
                    <span class="hard-badge" :class="row.status">{{ HARD_STATUS_LABEL[row.status] || row.status }}</span>
                  </td>
                  <td>
                    <div class="td-intel-copy">
                      <b class="hard-host">{{ row.host || row.url }}</b>
                      <small class="tic-sub">{{ row.task_name }} · {{ row.school || row.org || row.title || "归属待确认" }}</small>
                      <div class="hard-reason">{{ hardReasonOf(row) }}</div>
                    </div>
                  </td>
                  <td>
                    <div class="td-conv-box">
                      <b>重试 {{ row.retry_count }}</b>
                      <small>权重 {{ Number(row.priority_score || 0).toFixed(1) }}</small>
                    </div>
                  </td>
                  <td>
                    <time class="mono-time">{{ fmtTime(row.updated_at || row.created_at) }}</time>
                  </td>
                  <td style="text-align: right;" @click.stop>
                    <button type="button" class="btn-revive-inline" :disabled="hardReviving" @click="reviveSingleHard(row)"
                            title="复位此目标并携最新沉淀情报重新排队探测">
                      ⚡ 唤醒重测
                    </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div v-if="!hardLoading && hardTotal > hardPageSize" class="studio-pager">
            <button type="button" class="btn-studio-ghost" @click="hardPrevPage" :disabled="hardPage <= 0 || hardRefreshing">上一页</button>
            <span>第 {{ hardPage + 1 }} 页 · {{ hardPage * hardPageSize + 1 }}-{{ hardPage * hardPageSize + hardRows.length }} / {{ hardTotal }}</span>
            <button type="button" class="btn-studio-ghost" @click="hardNextPage" :disabled="!hardHasMore || hardRefreshing">下一页</button>
          </div>
        </template>

        <!-- ============ 3. 挖洞知识库 ============ -->
        <template v-else>
          <div class="intel-kpi-strip four">
            <div class="ik-cell hero">
              <span class="ik-label">双源知识库总篇目</span>
              <div class="ik-val-row">
                <b>{{ kbRows.length }}</b>
                <small>本地种子 + DB 蒸馏覆盖合并</small>
              </div>
            </div>
            <div class="ik-cell clickable" :class="{ active: kbOriginFilter === 'distilled' }" @click="kbOriginFilter = kbOriginFilter === 'distilled' ? 'all' : 'distilled'">
              <span class="ik-label">⚡ 实战脱敏蒸馏</span>
              <div class="ik-val-row"><b>{{ distilledKbCount }}</b><small>高危复审自动沉淀</small></div>
            </div>
            <div class="ik-cell clickable" :class="{ active: kbOriginFilter === 'user' }" @click="kbOriginFilter = kbOriginFilter === 'user' ? 'all' : 'user'">
              <span class="ik-label">✍ 用户手工沉淀</span>
              <div class="ik-val-row"><b>{{ userKbCount }}</b><small>人工编撰战术手册</small></div>
            </div>
            <div class="ik-cell clickable" :class="{ active: kbOriginFilter === 'seed' }" @click="kbOriginFilter = kbOriginFilter === 'seed' ? 'all' : 'seed'">
              <span class="ik-label">📦 内置种子手册</span>
              <div class="ik-val-row"><b>{{ seedKbCount }}</b><small>开箱方法论与指纹库</small></div>
            </div>
          </div>

          <div class="kb-dual-note">
            <b>双源自适应检索机制</b>
            <span>Worker 执行探测时自动融合本地规则手册与高危实战脱敏蒸馏条目（DB 同名优先覆盖本地种子）。</span>
          </div>

          <div v-if="kbLoading" class="studio-skeleton-list">
            <div v-for="n in 8" :key="n" class="skeleton-row"></div>
          </div>
          <div v-else-if="!visibleKbRows.length" class="studio-empty">
            <b>当前筛选下知识库暂无条目</b>
            <span>切换来源筛选、点击左侧「同步种子」或在漏洞报告点击「⚡ 蒸馏为知识库」。</span>
          </div>
          <div v-else class="studio-table-wrap">
            <table class="studio-table kb-ledger">
              <thead>
                <tr>
                  <th style="width: 100px;">分类</th>
                  <th>知识篇名与关联关键词</th>
                  <th style="width: 132px;">来源层级</th>
                  <th style="width: 96px;">复用频次</th>
                  <th style="width: 112px;">更新时间</th>
                  <th style="width: 158px; text-align: right;">状态与操作</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="row in visibleKbRows" :key="row.id" class="ledger-row is-clickable"
                    :class="{ 'is-disabled': !row.enabled, 'is-distilled': row.origin === 'distilled' }"
                    @click="viewKb(row)">
                  <td>
                    <span class="kb-cat-tag" :class="row.category">{{ kbCatLabel(row.category) }}</span>
                  </td>
                  <td>
                    <div class="td-intel-copy">
                      <b>{{ kbCleanTitle(row) }}</b>
                      <small class="tic-sub">
                        <span v-if="row.keyword && row.keyword !== kbCleanTitle(row)">关键词：{{ row.keyword }}</span>
                        <span v-if="row.payload?.source_finding_id"> · 源漏洞 #{{ String(row.payload.source_finding_id).slice(0, 8) }}</span>
                      </small>
                    </div>
                  </td>
                  <td>
                    <span class="kb-origin-tag" :class="row.origin">{{ kbOrigin(row) }}</span>
                  </td>
                  <td>
                    <span v-if="row.hit_count > 1" class="kb-reuse-num">×{{ row.hit_count }}</span>
                    <span v-else class="conv-muted">0</span>
                  </td>
                  <td>
                    <time class="mono-time">{{ row.updated_at ? fmtTime(row.updated_at) : "—" }}</time>
                  </td>
                  <td style="text-align: right;" @click.stop>
                    <div class="kb-row-actions">
                      <button type="button" class="kb-state-btn" :class="row.enabled ? 'yes' : 'no'"
                              title="点击切换启用/停用" @click="toggleKb(row)">
                        {{ row.enabled ? "已启用" : "已停用" }}
                      </button>
                      <button v-if="writable" class="kb-mini-btn" type="button" title="编辑" @click="openEditKb(row)">编辑</button>
                      <button v-if="writable" class="row-del-btn" type="button" title="删除" @click="removeKb(row)">✕</button>
                    </div>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </template>
      </div>
    </div>

    <!-- 查看详情弹层 -->
    <div v-if="kbViewOpen" class="kb-mask" @click.self="closeKbView">
      <div class="kb-dialog kb-dialog--wide">
        <header class="kb-dialog-head">
          <div class="kb-head-main">
            <span class="kb-cat-tag" :class="kbViewed?.category">{{ kbCatLabel(kbViewed?.category) }}</span>
            <b>{{ kbCleanTitle(kbViewed) }}</b>
          </div>
          <button type="button" class="kb-x" @click="closeKbView">✕</button>
        </header>
        <div class="kb-dialog-meta">
          <span>{{ kbOrigin(kbViewed) }}</span>
          <span v-if="kbViewed?.keyword && kbViewed.keyword !== kbCleanTitle(kbViewed)">关键词：{{ kbViewed.keyword }}</span>
          <span v-if="kbViewed?.hit_count > 1">已复用 {{ kbViewed.hit_count }}</span>
          <span v-if="kbViewed?.updated_at">更新于 {{ fmtTime(kbViewed.updated_at) }}</span>
        </div>
        <div v-if="kbViewed?.related?.length" class="kb-related">
          <span class="kb-related-label">关联篇目</span>
          <div class="kb-related-list">
            <button v-for="r in kbViewed.related" :key="r" type="button" class="kb-related-chip"
                    @click="viewKbByName(r)" :title="`跳转查看：${r}`">
              {{ r }} <i>→</i>
            </button>
          </div>
        </div>
        <pre class="kb-content">{{ kbViewed?.content }}</pre>
        <footer class="kb-actions" v-if="writable">
          <button class="btn-studio-ghost" type="button" @click="copyKbContent(kbViewed)">复制内容</button>
          <button class="btn-studio-ghost" type="button" @click="toggleKb(kbViewed); kbViewed.enabled = !kbViewed.enabled">
            {{ kbViewed?.enabled ? "停用" : "启用" }}
          </button>
          <button class="btn-studio-ghost" type="button" @click="openEditKb(kbViewed)">编辑</button>
          <button class="btn-studio-danger" type="button" @click="removeKb(kbViewed); kbViewed = null">删除</button>
        </footer>
      </div>
    </div>

    <!-- 手动添加 / 编辑弹层 -->
    <div v-if="kbAddOpen" class="kb-mask" @click.self="kbAddOpen = false">
      <div class="kb-dialog kb-dialog--wide">
        <header class="kb-dialog-head">
          <div>
            <b>{{ kbEditId ? "编辑知识" : "手动添加知识" }}</b>
            <small>{{ kbEditId ? "修改后保存，worker 检索会立即用到新内容" : "沉淀一条可复用的挖洞经验 / 手册（worker 会按关键词命中注入）" }}</small>
          </div>
          <button type="button" class="kb-x" @click="kbAddOpen = false">✕</button>
        </header>
        <div class="kb-form">
          <label><span>标题</span>
            <input v-model="kbForm.title" placeholder="例如：某系统越权验证技巧" />
          </label>
          <label><span>分类</span>
            <select v-model="kbForm.category">
              <option value="rules">方法论</option>
              <option value="kb">测试手册</option>
              <option value="user">用户沉淀</option>
            </select>
          </label>
          <label><span>关键词（命中用，可留空）</span>
            <input v-model="kbForm.keyword" placeholder="例如：越权 · idor · 任意登录（worker 据此检索）" />
          </label>
          <label><span>内容</span>
            <textarea v-model="kbForm.content" rows="10" placeholder="把这篇知识的正文粘贴/填写在这里…"></textarea>
          </label>
          <label class="kb-form-en"><input v-model="kbForm.enabled" type="checkbox" /> {{ kbEditId ? "保存后保持启用状态" : "创建后立即启用" }}</label>
          <div class="kb-form-actions">
            <button class="btn-studio-ghost" @click="kbAddOpen = false">取消</button>
            <button class="btn-studio-primary" @click="saveKb">{{ kbEditId ? "保存修改" : "保存" }}</button>
          </div>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.studio-view {
  position: relative;
  display: flex;
  flex-direction: column;
  gap: 14px;
}

.studio-head {
  display: flex;
  align-items: flex-end;
  justify-content: space-between;
  gap: 16px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.sh-crumb {
  display: flex;
  align-items: center;
  gap: 6px;
  font-family: var(--font-mono);
  font-size: 10.5px;
  letter-spacing: 0.08em;
  color: var(--muted);
  margin-bottom: 4px;
}
.sh-crumb b { color: var(--ink); font-weight: 600; }
.sh-title-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.sh-title-row h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--ink);
}
.sh-tag {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.06em;
  padding: 2px 7px;
  border-radius: 3px;
  border: 1px solid color-mix(in srgb, var(--accent) 35%, var(--border));
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 8%, transparent);
}
.sh-sub {
  margin: 4px 0 0;
  font-size: 12.5px;
  color: var(--muted);
}

/* 4-Stage Closed-Loop Pipeline */
.evo-pipeline {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  overflow: hidden;
}
.evo-stage {
  appearance: none;
  text-align: left;
  background: transparent;
  border: none;
  border-right: 1px solid var(--border);
  padding: 11px 14px;
  cursor: pointer;
  display: flex;
  flex-direction: column;
  gap: 4px;
  transition: background 0.14s ease;
  position: relative;
}
.evo-stage:last-child { border-right: none; }
.evo-stage:hover { background: var(--bg-soft); }
.evo-stage.on {
  background: color-mix(in srgb, var(--accent) 6%, var(--surface));
}
.evo-stage.on::after {
  content: "";
  position: absolute;
  left: 0;
  right: 0;
  bottom: 0;
  height: 2.5px;
  background: var(--accent);
}
.evo-meta {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-family: var(--font-mono);
  font-size: 10px;
  letter-spacing: 0.08em;
}
.evo-step { font-weight: 700; color: var(--accent); }
.evo-tag { color: var(--muted); }
.evo-stage b { font-size: 13px; color: var(--ink); font-weight: 600; }
.evo-stage em { font-style: normal; font-size: 11.5px; color: var(--muted); font-family: var(--font-mono); }

/* 2-Column Studio Body */
.studio-layout {
  display: grid;
  grid-template-columns: 268px minmax(0, 1fr);
  gap: 16px;
  align-items: start;
}

.studio-rail {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 14px;
  position: sticky;
  top: 64px;
}

.rail-block {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--border);
}
.rail-block:last-child {
  padding-bottom: 0;
  border-bottom: none;
}

.rail-label {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.08em;
  color: var(--muted);
  text-transform: uppercase;
}

.rail-stores {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.rail-store-btn {
  display: grid;
  grid-template-columns: 24px minmax(0, 1fr) auto;
  align-items: center;
  gap: 8px;
  width: 100%;
  text-align: left;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  cursor: pointer;
  transition: all 0.12s ease;
}
.rail-store-btn:hover { border-color: color-mix(in srgb, var(--accent) 40%, var(--border)); }
.rail-store-btn.on {
  background: var(--rail-bg);
  color: var(--rail-ink);
  border-color: var(--rail-bg);
}
.rs-icon { font-size: 15px; line-height: 1; text-align: center; }
.rs-copy { display: flex; flex-direction: column; min-width: 0; }
.rs-copy b { font-size: 12.5px; color: inherit; }
.rs-copy small { font-size: 10.5px; opacity: 0.7; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.rs-num {
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 700;
  padding: 2px 6px;
  border-radius: 4px;
  background: color-mix(in srgb, currentColor 12%, transparent);
}

.rail-search {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 6px 10px;
  border: 1px solid var(--border);
  border-radius: 6px;
  background: var(--bg-soft);
}
.rail-search span { color: var(--muted); font-size: 13px; }
.rail-search input {
  width: 100%;
  border: none;
  background: transparent;
  outline: none;
  color: var(--ink);
  font-size: 12.5px;
}

.rail-facet-list {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.rail-facet {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 8px;
  padding: 6px 8px;
  border-radius: 5px;
  border: 1px solid transparent;
  background: transparent;
  color: var(--ink);
  font-size: 12px;
  cursor: pointer;
  text-align: left;
}
.rail-facet:hover { background: var(--bg-soft); }
.rail-facet.on {
  background: color-mix(in srgb, var(--accent) 10%, transparent);
  border-color: color-mix(in srgb, var(--accent) 28%, transparent);
  color: var(--accent);
  font-weight: 600;
}
.rail-facet em {
  font-style: normal;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--muted);
}

.rail-selects {
  display: flex;
  flex-direction: column;
  gap: 6px;
  margin-top: 4px;
}
.rail-selects select {
  width: 100%;
  padding: 6px 8px;
  font-size: 12px;
  border-radius: 5px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--ink);
}

.rail-actions-col {
  display: flex;
  flex-direction: column;
  gap: 7px;
}
.rail-btn-row {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 6px;
}
.rail-note {
  margin: 0;
  font-size: 11.5px;
  color: var(--muted);
  line-height: 1.45;
}
.rail-note a { color: var(--accent); text-decoration: underline; }
.curator-sample {
  margin: 0;
  font-size: 11px;
  color: var(--warn);
  background: color-mix(in srgb, var(--warn) 8%, transparent);
  padding: 6px 8px;
  border-radius: 4px;
  word-break: break-word;
}
.rail-msg { margin: 0; font-size: 11.5px; font-weight: 500; }
.rail-msg.ok { color: var(--ok); }
.rail-msg.err { color: var(--danger); }

/* Studio Buttons */
.btn-studio-primary,
.btn-studio-accent,
.btn-studio-ghost,
.btn-studio-danger {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
  padding: 7px 11px;
  border-radius: 5px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  text-decoration: none;
  border: 1px solid var(--border);
  transition: all 0.12s ease;
}
.btn-studio-primary {
  background: var(--ink);
  color: var(--surface);
  border-color: var(--ink);
}
.btn-studio-primary:hover:not(:disabled) { opacity: 0.9; }
.btn-studio-accent {
  background: var(--accent);
  color: #fff;
  border-color: var(--accent);
}
.btn-studio-ghost {
  background: var(--surface);
  color: var(--ink);
}
.btn-studio-ghost:hover:not(:disabled) { background: var(--bg-soft); }
.btn-studio-danger {
  background: color-mix(in srgb, var(--danger) 8%, transparent);
  color: var(--danger);
  border-color: color-mix(in srgb, var(--danger) 30%, var(--border));
}
.btn-studio-primary:disabled,
.btn-studio-accent:disabled,
.btn-studio-ghost:disabled,
.btn-studio-danger:disabled {
  opacity: 0.48;
  cursor: not-allowed;
}

/* Right Studio Main */
.studio-main {
  display: flex;
  flex-direction: column;
  gap: 12px;
  min-width: 0;
}

.intel-kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  overflow: hidden;
}
.intel-kpi-strip.three { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.intel-kpi-strip.four { grid-template-columns: repeat(4, minmax(0, 1fr)); }
.ik-cell {
  padding: 12px 14px;
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  gap: 5px;
  min-width: 0;
}
.ik-cell:last-child { border-right: none; }
.ik-cell.clickable { cursor: pointer; transition: background 0.12s ease; }
.ik-cell.clickable:hover { background: var(--bg-soft); }
.ik-cell.clickable.active { background: color-mix(in srgb, var(--accent) 8%, var(--surface)); box-shadow: inset 0 -2px 0 var(--accent); }
.ik-label {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 600;
  color: var(--muted);
  letter-spacing: 0.05em;
}
.ik-val-row {
  display: flex;
  align-items: baseline;
  gap: 8px;
  flex-wrap: wrap;
}
.ik-val-row b {
  font-family: var(--font-mono);
  font-size: 22px;
  line-height: 1.1;
  color: var(--ink);
}
.ik-val-row small { font-size: 11px; color: var(--muted); }
.ik-dist-bar {
  display: flex;
  height: 6px;
  border-radius: 3px;
  overflow: hidden;
  background: var(--bg-soft);
  margin-top: 2px;
}
.ik-dist-bar .once { background: var(--muted); opacity: 0.45; }
.ik-dist-bar .few { background: var(--accent2); }
.ik-dist-bar .many { background: var(--accent); }
.ik-dist-meta {
  display: flex;
  gap: 10px;
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--muted);
}
.ik-top-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.ik-top-item b {
  font-size: 12.5px;
  color: var(--ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.ik-top-item em {
  font-style: normal;
  font-family: var(--font-mono);
  font-size: 11.5px;
  font-weight: 700;
  color: var(--accent);
}
.ik-cell small {
  font-size: 11px;
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.ik-src-pills {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}
.ik-src-pill {
  font-family: var(--font-mono);
  font-size: 10.5px;
  padding: 2px 6px;
  border-radius: 4px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  color: var(--ink);
}
.ik-src-pill em { font-style: normal; color: var(--accent); margin-left: 3px; }

.main-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  padding: 4px 2px;
}
.mt-title { display: flex; align-items: baseline; gap: 10px; }
.mt-title b { font-size: 14px; color: var(--ink); }
.mt-count { font-family: var(--font-mono); font-size: 11.5px; color: var(--muted); }
.mt-pills { display: flex; flex-wrap: wrap; gap: 6px; }
.mt-pill {
  font-size: 11.5px;
  padding: 3px 9px;
  border-radius: 99px;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--ink);
  cursor: pointer;
}
.mt-pill.accent {
  background: color-mix(in srgb, var(--accent) 12%, transparent);
  border-color: color-mix(in srgb, var(--accent) 32%, transparent);
  color: var(--accent);
}

.kb-dual-note {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 14px;
  border-radius: var(--radius);
  background: color-mix(in srgb, var(--accent2) 8%, var(--surface));
  border: 1px solid color-mix(in srgb, var(--accent2) 25%, var(--border));
  font-size: 12px;
}
.kb-dual-note b { color: var(--accent2); white-space: nowrap; }
.kb-dual-note span { color: var(--muted); }

/* Studio Ledger Table */
.studio-table-wrap {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow-x: auto;
}
.studio-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 12.5px;
}
.studio-table thead th {
  text-align: left;
  padding: 9px 12px;
  font-family: var(--font-mono);
  font-size: 10.5px;
  font-weight: 700;
  letter-spacing: 0.05em;
  color: var(--muted);
  background: var(--bg-soft);
  border-bottom: 1px solid var(--border);
  white-space: nowrap;
}
.studio-table tbody td {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}
.studio-table tbody tr:last-child td { border-bottom: none; }
.ledger-row:hover { background: color-mix(in srgb, var(--bg-soft) 70%, transparent); }
.ledger-row.is-clickable { cursor: pointer; }
.ledger-row.selected { background: color-mix(in srgb, var(--accent) 7%, transparent); }
.ledger-row.is-pitfall { background: color-mix(in srgb, var(--danger) 4%, transparent); }
.ledger-row.is-disabled { opacity: 0.6; }

.td-kind-box {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.kind-pill {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  width: fit-content;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  color: var(--ink);
}
.scope-code {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 135px;
}

.td-intel-copy {
  display: flex;
  flex-direction: column;
  gap: 4px;
  min-width: 0;
}
.tic-head {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 6px;
}
.tic-head b,
.td-intel-copy b {
  font-size: 13px;
  color: var(--ink);
  word-break: break-word;
}
.tic-sub {
  font-size: 11.5px;
  color: var(--muted);
  word-break: break-word;
}
.fb-tag {
  font-size: 10.5px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 3px;
}
.fb-tag.ok { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok); }
.fb-tag.warn { background: color-mix(in srgb, var(--danger) 12%, transparent); color: var(--danger); }

.td-utility-box {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.u-top {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}
.conf-tag {
  font-size: 10.5px;
  font-weight: 600;
  padding: 1px 6px;
  border-radius: 3px;
}
.conf-tag.verified { background: color-mix(in srgb, var(--ok) 14%, transparent); color: var(--ok); }
.conf-tag.likely { background: color-mix(in srgb, var(--warn) 14%, transparent); color: var(--warn); }
.u-score { font-family: var(--font-mono); font-size: 12.5px; color: var(--ink); }
.u-meter {
  height: 4px;
  border-radius: 2px;
  background: var(--bg-soft);
  overflow: hidden;
}
.u-meter i {
  display: block;
  height: 100%;
  background: var(--accent);
}

.td-conv-box {
  display: flex;
  flex-direction: column;
  gap: 3px;
  font-family: var(--font-mono);
  font-size: 11px;
}
.conv-tag { color: var(--accent); font-weight: 700; }
.conv-muted { color: var(--muted); font-family: var(--font-mono); font-size: 11px; }
.hit-tag { color: var(--accent2); font-weight: 600; }

.td-src-box {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.src-host {
  font-family: var(--font-mono);
  font-size: 11.5px;
  color: var(--ink);
  word-break: break-all;
}
.td-src-box time,
.mono-time {
  font-family: var(--font-mono);
  font-size: 10.5px;
  color: var(--muted);
}

.row-del-btn {
  appearance: none;
  background: transparent;
  border: 1px solid transparent;
  border-radius: 4px;
  color: var(--muted);
  cursor: pointer;
  padding: 3px 6px;
  font-size: 12px;
}
.row-del-btn:hover {
  color: var(--danger);
  border-color: color-mix(in srgb, var(--danger) 30%, var(--border));
  background: color-mix(in srgb, var(--danger) 8%, transparent);
}

.hard-badge {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 4px;
}
.hard-badge.dead { background: color-mix(in srgb, var(--danger) 12%, transparent); color: var(--danger); }
.hard-badge.skipped { background: color-mix(in srgb, var(--warn) 14%, transparent); color: var(--warn); }
.hard-host { font-family: var(--font-mono); font-size: 12.5px; }
.hard-reason { font-size: 11.5px; color: var(--muted); margin-top: 2px; word-break: break-word; }

.btn-revive-inline {
  padding: 5px 9px;
  border-radius: 5px;
  border: 1px solid color-mix(in srgb, var(--accent) 40%, var(--border));
  background: color-mix(in srgb, var(--accent) 10%, transparent);
  color: var(--accent);
  font-size: 11.5px;
  font-weight: 600;
  cursor: pointer;
}
.btn-revive-inline:hover:not(:disabled) {
  background: var(--accent);
  color: #fff;
}

.kb-cat-tag {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  color: var(--ink);
}
.kb-origin-tag {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  padding: 2px 7px;
  border-radius: 4px;
  background: var(--bg-soft);
  color: var(--muted);
}
.kb-origin-tag.distilled {
  background: color-mix(in srgb, var(--accent) 12%, transparent);
  color: var(--accent);
}
.kb-origin-tag.user {
  background: color-mix(in srgb, var(--accent2) 12%, transparent);
  color: var(--accent2);
}
.kb-reuse-num { font-family: var(--font-mono); font-weight: 700; color: var(--accent); }
.kb-row-actions {
  display: inline-flex;
  align-items: center;
  gap: 5px;
}
.kb-state-btn,
.kb-mini-btn {
  padding: 3px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 600;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--ink);
  cursor: pointer;
}
.kb-state-btn.yes {
  background: color-mix(in srgb, var(--ok) 12%, transparent);
  color: var(--ok);
  border-color: color-mix(in srgb, var(--ok) 30%, var(--border));
}
.kb-state-btn.no { color: var(--muted); }

.studio-pager {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 10px 4px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--muted);
}

.studio-empty {
  background: var(--surface);
  border: 1px dashed var(--border);
  border-radius: var(--radius);
  padding: 40px 24px;
  text-align: center;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.studio-empty b { font-size: 14px; color: var(--ink); }
.studio-empty span { font-size: 12.5px; color: var(--muted); }

.studio-skeleton-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.skeleton-row {
  height: 52px;
  border-radius: 6px;
  background: var(--surface);
  border: 1px solid var(--border);
  opacity: 0.65;
}

/* Modals cleanly styled with Solaris/Obsidian tokens */
.kb-mask {
  position: fixed;
  inset: 0;
  z-index: 60;
  background: rgba(12, 14, 18, 0.62);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 20px;
}
.kb-dialog {
  width: min(760px, 100%);
  max-height: 88vh;
  display: flex;
  flex-direction: column;
  gap: 12px;
  background: var(--surface);
  color: var(--ink);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 18px 20px;
  box-shadow: 0 24px 60px rgba(0, 0, 0, 0.28);
  overflow: hidden;
}
.kb-dialog-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 12px;
  padding-bottom: 10px;
  border-bottom: 1px solid var(--border);
}
.kb-head-main { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.kb-dialog-head b { font-size: 16px; color: var(--ink); }
.kb-dialog-head small { display: block; font-size: 12px; color: var(--muted); margin-top: 2px; }
.kb-x {
  background: var(--bg-soft);
  border: 1px solid var(--border);
  border-radius: 5px;
  color: var(--ink);
  padding: 4px 8px;
  cursor: pointer;
}
.kb-dialog-meta {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  font-size: 12px;
  color: var(--muted);
}
.kb-related { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.kb-related-label { font-size: 11.5px; color: var(--muted); }
.kb-related-list { display: flex; flex-wrap: wrap; gap: 6px; }
.kb-related-chip {
  font-size: 11.5px;
  padding: 3px 8px;
  border-radius: 4px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--ink);
  cursor: pointer;
}
.kb-content {
  margin: 0;
  padding: 14px;
  border-radius: 6px;
  background: var(--bg-soft);
  border: 1px solid var(--border);
  font-family: var(--font-mono);
  font-size: 12px;
  line-height: 1.6;
  white-space: pre-wrap;
  word-break: break-word;
  overflow-y: auto;
  flex: 1;
}
.kb-actions,
.kb-form-actions {
  display: flex;
  justify-content: flex-end;
  gap: 8px;
  padding-top: 8px;
  border-top: 1px solid var(--border);
}
.kb-form {
  display: flex;
  flex-direction: column;
  gap: 10px;
  overflow-y: auto;
}
.kb-form label {
  display: flex;
  flex-direction: column;
  gap: 5px;
  font-size: 12px;
  font-weight: 600;
  color: var(--ink);
}
.kb-form input,
.kb-form select,
.kb-form textarea {
  padding: 8px 10px;
  border-radius: 5px;
  border: 1px solid var(--border);
  background: var(--bg-soft);
  color: var(--ink);
  font-size: 12.5px;
}
.kb-form label.kb-form-en {
  flex-direction: row;
  align-items: center;
  gap: 8px;
  font-weight: 500;
}

@media (max-width: 1024px) {
  .evo-pipeline { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .evo-stage { border-bottom: 1px solid var(--border); }
  .studio-layout { grid-template-columns: 1fr; }
  .studio-rail { position: static; }
  .intel-kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
}
@media (max-width: 640px) {
  .evo-pipeline,
  .intel-kpi-strip,
  .intel-kpi-strip.three,
  .intel-kpi-strip.four { grid-template-columns: 1fr; }
}
</style>
