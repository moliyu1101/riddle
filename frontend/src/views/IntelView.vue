<script setup>
import { computed, onActivated, onMounted, ref, watch } from "vue";
import { useRouter } from "vue-router";
import { api, canWrite } from "../api.js";

defineOptions({ name: "IntelView" });

const router = useRouter();
const activeTab = ref("intel");

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
};

const KIND_TABS = [
  { id: "all", label: "全部" },
  { id: "cred", label: "凭证" },
  { id: "fingerprint", label: "打法" },
  { id: "endpoint", label: "端点" },
  { id: "profile", label: "画像" },
  { id: "lesson", label: "经验" },
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
  return row.summary || "";
}

async function removeOne(row) {
  if (!writable.value) return;
  if (!confirm(`确认删除这条情报？\n${row.match_key} · ${primaryText(row)}`)) return;
  try {
    await api.deleteIntel(row.id);
    await reloadIntel();
  } catch (e) {
    alert(`删除失败：${e?.message || e}`);
  }
}

async function clearKind() {
  if (!writable.value) return;
  const label = kind.value === "all" ? "全部" : (KIND_META[kind.value]?.label || kind.value);
  if (!confirm(`确认清空【${label}】情报？此操作不可恢复。`)) return;
  try {
    await api.clearIntel(kind.value);
    await reloadIntel();
  } catch (e) {
    alert(`清空失败：${e?.message || e}`);
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
    alert(`已清理 ${res?.deleted || 0} 条垃圾情报` + (kept ? `，保留 ${kept} 条高频复用项（hit≥3）需人工确认` : ""));
    curator.value = res;
    await reloadIntel();
  } catch (e) {
    alert(`清理失败：${e?.message || e}`);
  } finally {
    curatorApplying.value = false;
  }
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

async function viewKb(row) {
  try {
    kbViewed.value = await api.knowledgeDetail(row.id);
    kbViewOpen.value = true;
  } catch (e) {
    alert(`读取失败：${e?.message || e}`);
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
    await reloadKb();
    await loadStats();
  } catch (e) {
    alert(`删除失败：${e?.message || e}`);
  }
}
async function toggleKb(row) {
  try {
    await api.knowledgeUpdate(row.id, { enabled: !row.enabled });
    await reloadKb();
  } catch (e) {
    alert(`操作失败：${e?.message || e}`);
  }
}
async function syncKb() {
  if (!writable.value || checking.value) return;
  checking.value = true;
  try {
    const res = await api.knowledgeSync();
    alert(`知识库种子同步完成：新增 ${res?.added ?? 0} 篇，已存在 ${res?.skipped ?? 0} 篇（保留你的编辑）`);
    await reloadKb();
    await loadStats();
  } catch (e) {
    alert(`同步失败：${e?.message || e}`);
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
    alert(`读取失败：${e?.message || e}`);
  }
}
async function saveKb() {
  if (!writable.value) return;
  if (!kbForm.value.content.trim()) { alert("内容不能为空"); return; }
  try {
    if (kbEditId.value) {
      await api.knowledgeUpdate(kbEditId.value, kbForm.value);
    } else {
      await api.knowledgeCreate(kbForm.value);
    }
    autoCloseKbView();
    await reloadKb();
    await loadStats();
  } catch (e) {
    alert(`保存失败：${e?.message || e}`);
  }
}
async function copyKbContent(row) {
  const content = row?.content || "";
  if (!content) { alert("内容为空，无可复制"); return; }
  try {
    await navigator.clipboard.writeText(content);
    alert("内容已复制到剪贴板");
  } catch {
    alert("复制失败，请手动选中复制");
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

/* ---------- 公共 ---------- */
async function reload() {
  await Promise.all([reloadIntel(), reloadHard(), loadKbList()]);
}

onMounted(reload);
onActivated(() => {
  if (rows.value.length || hardRows.value.length) reload();
});
</script>

<template>
  <section class="view intel-view" :class="{ 'is-refreshing': refreshing || hardRefreshing }">
    <div v-if="(refreshing || hardRefreshing) && !initialLoading && !hardLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <nav class="crumb" aria-label="面包屑">
      <span>指挥中心</span>
      <span class="crumb-sep">/</span>
      <b>作战情报</b>
    </nav>

    <header class="page-head split">
      <div>
        <h2>作战情报中心 <span class="intel-chip">OPS-INTEL</span></h2>
        <p class="page-sub">跨任务沉淀的可复用作战情报与攻坚记录——情报越挖越聪明，硬骨头集中回捞复盘。</p>
      </div>
      <router-link class="head-action" to="/">返回任务</router-link>
    </header>

    <!-- 分区大标签 -->
    <div class="ops-tabs" role="tablist" aria-label="情报分区">
      <button type="button" role="tab" :aria-selected="activeTab === 'intel'"
              class="ops-tab" :class="{ on: activeTab === 'intel' }" @click="activeTab = 'intel'">
        <span class="ops-tab-ico">🧠</span>
        <span class="ops-tab-txt">
          <b>情报沉淀</b>
          <small>凭证 / 打法 / 端点 / 画像 / 经验</small>
        </span>
        <span class="ops-tab-num">{{ stats.total }}</span>
      </button>
      <button type="button" role="tab" :aria-selected="activeTab === 'hard'"
              class="ops-tab" :class="{ on: activeTab === 'hard' }" @click="activeTab = 'hard'">
        <span class="ops-tab-ico">🦴</span>
        <span class="ops-tab-txt">
          <b>硬骨头</b>
          <small>dead / skipped 攻坚记录</small>
        </span>
        <span class="ops-tab-num">{{ hardStats.total }}</span>
      </button>
      <button type="button" role="tab" :aria-selected="activeTab === 'kb'"
              class="ops-tab" :class="{ on: activeTab === 'kb' }" @click="activeTab = 'kb'">
        <span class="ops-tab-ico">📚</span>
        <span class="ops-tab-txt">
          <b>知识库</b>
          <small>挖洞测试手册 / 方法论 / 用户沉淀</small>
        </span>
        <span class="ops-tab-num">{{ kbRows.length }}</span>
      </button>
    </div>

    <!-- ============ 情报沉淀 ============ -->
    <template v-if="activeTab === 'intel'">
      <div class="intel-dash">
        <div class="dash-card hero">
          <span class="dash-k">情报总量</span>
          <b class="dash-v">{{ stats.total }}</b>
          <span class="dash-sub">已验证 {{ stats.verified }} · 被复用 {{ stats.reused }}</span>
        </div>
        <div v-for="k in ['cred','fingerprint','endpoint','profile','lesson']" :key="k"
             class="dash-card" :class="KIND_META[k].hue"
             :data-active="kind === k"
             @click="kind = (kind === k ? 'all' : k)">
          <span class="dash-icon">{{ KIND_META[k].icon }}</span>
          <b class="dash-v">{{ stats.by_kind[k] || 0 }}</b>
          <span class="dash-k">{{ KIND_META[k].label }}</span>
        </div>
      </div>

      <!-- 命中统计面板：复用分布 + 类别概况 + 高频复用 Top + 来源 Top -->
      <div v-if="hitStats" class="hit-panel">
        <div class="hit-col">
          <div class="hit-card">
            <div class="hit-card-head">
              <b>复用分布</b>
              <small>情报被再次命中的次数分层</small>
            </div>
            <div class="hit-dist-bar">
              <i class="once" :style="{ width: reuseDistPct.once + '%' }"></i>
              <i class="few" :style="{ width: reuseDistPct.few + '%' }"></i>
              <i class="many" :style="{ width: reuseDistPct.many + '%' }"></i>
            </div>
            <div class="hit-dist-legend">
              <span><i class="lg once"></i>一次 {{ hitStats.reuse_dist?.once || 0 }}</span>
              <span><i class="lg few"></i>2-5次 {{ hitStats.reuse_dist?.few || 0 }}</span>
              <span><i class="lg many"></i>6+次 {{ hitStats.reuse_dist?.many || 0 }}</span>
            </div>
          </div>
          <div class="hit-card">
            <div class="hit-card-head">
              <b>类别复用概况</b>
              <small>平均命中次数（越高越可信）</small>
            </div>
            <div v-for="k in hitKinds" :key="k" class="hit-kind-row">
              <span class="hit-kind-name">{{ KIND_META[k].icon }} {{ KIND_META[k].label }}</span>
              <div class="hit-kind-bar"><i :style="{ width: kindBarWidth(k) + '%' }"></i></div>
              <em>{{ hitStats.by_kind[k]?.avg_hit || 0 }}×</em>
              <small class="hit-kind-sub">{{ hitStats.by_kind[k]?.reused || 0 }}/{{ hitStats.by_kind[k]?.total || 0 }} 复用</small>
            </div>
          </div>
        </div>
        <div class="hit-col">
          <div class="hit-card">
            <div class="hit-card-head">
              <b>高频复用 Top</b>
              <small>被多个目标复用的高价值情报</small>
            </div>
            <div v-for="it in hitStats.top_reused || []" :key="it.id" class="hit-top-row">
              <span class="hit-top-kind">{{ KIND_META[it.kind]?.icon || '📄' }}</span>
              <div class="hit-top-main">
                <b>{{ it.summary || it.match_key }}</b>
                <small>{{ it.match_key }} · {{ KIND_META[it.kind]?.label || it.kind }}</small>
              </div>
              <em>×{{ it.hit_count }}</em>
            </div>
            <div v-if="!(hitStats.top_reused || []).length" class="hit-empty">暂无复用情报，出洞越多沉淀越厚</div>
          </div>
          <div class="hit-card">
            <div class="hit-card-head">
              <b>来源主机 Top</b>
              <small>贡献情报最多的目标</small>
            </div>
            <div v-for="s in hitStats.top_sources || []" :key="s.host" class="hit-src-row">
              <span class="hit-src-host">{{ s.host }}</span>
              <div class="hit-src-bar"><i :style="{ width: Math.min(100, s.count * 12) + '%' }"></i></div>
              <em>{{ s.count }}</em>
            </div>
            <div v-if="!(hitStats.top_sources || []).length" class="hit-empty">暂无来源记录</div>
          </div>
        </div>
      </div>

      <div class="intel-toolbar">
        <div class="kind-tabs">
          <button v-for="t in KIND_TABS" :key="t.id" type="button"
                  class="kind-tab" :class="{ on: kind === t.id }" @click="kind = t.id">
            {{ t.label }}
          </button>
        </div>
        <div class="search-box">
          <span>⌕</span>
          <input v-model="searchDraft" placeholder="搜索 域名 / 账号 / 路径 / 来源 / 内容" />
        </div>
        <select v-model="confidence">
          <option value="all">全部可信度</option>
          <option value="verified">仅已验证</option>
          <option value="likely">仅疑似</option>
        </select>
        <button class="btn-ghost" @click="reloadIntel" :disabled="refreshing">{{ refreshing ? "刷新中…" : "刷新" }}</button>
        <button v-if="writable" class="btn-danger" @click="clearKind">清空当前类</button>
      </div>

      <div class="curator-card">
        <div>
          <b>Intel Curator</b>
          <span>
            {{ curatorLoading ? "维护检查中…" : `候选垃圾 ${curator?.flagged || 0} 条，已检查 ${curator?.examined || 0} 条` }}
          </span>
        </div>
        <div class="curator-actions">
          <button class="btn-ghost" @click="previewCurator" :disabled="curatorLoading">重新检查</button>
          <button v-if="writable" class="btn-danger" @click="applyCurator" :disabled="curatorApplying || !(curator?.flagged)">
            {{ curatorApplying ? "清理中…" : "维护清理" }}
          </button>
        </div>
        <small v-if="curator?.items?.length" class="curator-reason">
          示例：{{ KIND_META[curator.items[0].kind]?.label || curator.items[0].kind }} · {{ curator.items[0].match_key }} · {{ curator.items[0].reasons?.join("、") }}
        </small>
      </div>

      <div v-if="initialLoading" class="intel-grid">
        <div v-for="n in 8" :key="n" class="intel-row skeleton-hard"></div>
      </div>
      <div v-else-if="!rows.length" class="empty">
        情报库暂无记录
        <span class="hint">worker 出洞 / 撞库成功后会自动沉淀，越挖越聪明</span>
      </div>
      <div v-else class="intel-grid">
        <article v-for="(row, i) in rows" :key="row.id" class="intel-row anim-fade-up" :class="KIND_META[row.kind]?.hue" :style="{ '--i': i }">
          <span class="ir-kind" :class="KIND_META[row.kind]?.hue">
            <i>{{ KIND_META[row.kind]?.icon }}</i>{{ KIND_META[row.kind]?.label || row.kind }}
          </span>
          <div class="ir-main">
            <b class="ir-primary">{{ primaryText(row) }}</b>
            <small class="ir-secondary" v-if="secondaryText(row)">{{ secondaryText(row) }}</small>
            <span class="ir-key">作用域：{{ row.match_key }}</span>
          </div>
          <div class="ir-side">
            <span class="ir-conf" :class="row.confidence">
              {{ row.confidence === 'verified' ? '✓ 已验证' : '· 疑似' }}
            </span>
            <span class="ir-hit" v-if="row.hit_count > 1" title="被复用次数">×{{ row.hit_count }} 复用</span>
            <small class="ir-src">{{ row.source_host || '未知来源' }}</small>
            <time>{{ fmtTime(row.last_seen) }}</time>
          </div>
          <button v-if="writable" class="ir-del" type="button" title="删除" @click="removeOne(row)">✕</button>
        </article>
      </div>
    </template>

    <!-- ============ 硬骨头 ============ -->
    <template v-else-if="activeTab === 'hard'">
      <div class="hard-dash">
        <div class="dash-card hero">
          <span class="dash-k">攻坚记录</span>
          <b class="dash-v">{{ hardStats.total }}</b>
          <span class="dash-sub">跨任务聚合 dead / skipped 目标</span>
        </div>
        <div class="dash-card danger" :data-active="hardStatus === 'dead'" @click="hardStatus = (hardStatus === 'dead' ? 'all' : 'dead')">
          <span class="dash-icon">🦴</span>
          <b class="dash-v">{{ hardStats.dead }}</b>
          <span class="dash-k">硬骨头</span>
        </div>
        <div class="dash-card warn" :data-active="hardStatus === 'skipped'" @click="hardStatus = (hardStatus === 'skipped' ? 'all' : 'skipped')">
          <span class="dash-icon">⏭</span>
          <b class="dash-v">{{ hardStats.skipped }}</b>
          <span class="dash-k">已跳过</span>
        </div>
      </div>

      <div class="intel-toolbar">
        <div class="search-box">
          <span>⌕</span>
          <input v-model="hardSearchDraft" placeholder="搜索任务 / 单位 / URL / 原因 / org" />
        </div>
        <select v-model="hardStatus">
          <option value="all">全部状态</option>
          <option value="dead">只看硬骨头</option>
          <option value="skipped">只看跳过</option>
        </select>
        <button class="btn-ghost" @click="reloadHard" :disabled="hardRefreshing">{{ hardRefreshing ? "刷新中…" : "刷新" }}</button>
      </div>

      <div v-if="hardLoading" class="hard-list">
        <div v-for="n in 6" :key="n" class="hard-row skeleton-hard"></div>
      </div>
      <div v-else-if="!hardRows.length" class="empty">
        暂无硬骨头记录
        <span class="hint">打不动的目标会沉淀到这里，便于回捞与复盘收敛质量</span>
      </div>
      <div v-else class="hard-list">
        <button v-for="(row, i) in hardRows" :key="row.id" class="hard-row anim-fade-up" :style="{ '--i': i }" type="button" @click="openTask(row)">
          <span class="hard-status" :class="row.status">{{ HARD_STATUS_LABEL[row.status] || row.status }}</span>
          <span class="hard-main">
            <b>{{ row.host || row.url }}</b>
            <small>{{ row.task_name }} · {{ row.school || row.org || row.title || "归属待确认" }}</small>
            <em>{{ hardReasonOf(row) }}</em>
          </span>
          <span class="hard-meta">
            <b>重试 {{ row.retry_count }}</b>
            <small>优先级 {{ Number(row.priority_score || 0).toFixed(1) }}</small>
            <time>{{ fmtTime(row.updated_at || row.created_at) }}</time>
          </span>
        </button>
      </div>

      <div v-if="!hardLoading && hardTotal > hardPageSize" class="hard-pager">
        <button type="button" @click="hardPrevPage" :disabled="hardPage <= 0 || hardRefreshing">上一页</button>
        <span>第 {{ hardPage + 1 }} 页 · {{ hardPage * hardPageSize + 1 }}-{{ hardPage * hardPageSize + hardRows.length }} / {{ hardTotal }}</span>
        <button type="button" @click="hardNextPage" :disabled="!hardHasMore || hardRefreshing">下一页</button>
      </div>
    </template>

    <!-- ============ 知识库 ============ -->
    <template v-else>
      <div class="kb-toolbar">
        <div class="kind-tabs">
          <button v-for="t in KB_CATS" :key="t.id" type="button"
                  class="kind-tab" :class="{ on: kbCategory === t.id }" @click="kbCategory = t.id">
            {{ t.label }}
          </button>
        </div>
        <div class="search-box">
          <span>⌕</span>
          <input v-model="kbSearchDraft" placeholder="搜索 篇名 / 关键词 / 内容" />
        </div>
        <button class="btn-ghost" @click="syncKb" :disabled="checking || !writable">{{ checking ? "同步中…" : "同步种子" }}</button>
        <button v-if="writable" class="btn-primary" @click="openAddKb">＋ 手动添加</button>
      </div>

      <div class="kb-hint">
        <b>知识库说明</b>
        <span>worker 挖洞时会按目标任务命中这些测试手册/方法论并注入；你可以「＋手动添加」沉淀自己的经验，或「同步种子」从本地文件补基础库。</span>
      </div>

      <div v-if="kbLoading" class="intel-grid">
        <div v-for="n in 8" :key="n" class="intel-row skeleton-hard"></div>
      </div>
      <div v-else-if="!kbRows.length" class="empty">
        知识库暂无条目
        <span class="hint">点击「同步种子」导入基础手册，或「手动添加」沉淀你的经验</span>
      </div>
      <div v-else class="kb-list">
        <article v-for="(row, i) in kbRows" :key="row.id" class="kb-row anim-fade-up" :style="{ '--i': i }"
                 :class="{ on: row.enabled, off: !row.enabled }" type="button" @click="viewKb(row)" :title="`查看：${kbCleanTitle(row)}`">
          <span class="kb-cat" :class="row.category">{{ kbCatLabel(row.category) }}</span>
          <div class="kb-main">
            <b>
              {{ kbCleanTitle(row) }}
              <em v-if="row.hit_count > 1" class="kb-reuse" title="已被 worker 复用次数">已复用 {{ row.hit_count }}</em>
            </b>
            <small>
              <span v-if="row.keyword && row.keyword !== kbCleanTitle(row)" class="kw">关键词：{{ row.keyword }}</span>
              <span v-else class="src" :class="row.origin">{{ kbOrigin(row) }}</span>
              <template v-if="row.updated_at">· {{ fmtTime(row.updated_at) }}</template>
            </small>
          </div>
          <span class="kb-side">
            <button v-if="writable" class="kb-act kb-edit" type="button" title="编辑" @click.stop="openEditKb(row)">编辑</button>
            <i class="kb-enabled" :class="row.enabled ? 'yes' : 'no'" title="点击切换启用/停用" @click.stop="toggleKb(row)">
              {{ row.enabled ? "已启用" : "已停用" }}
            </i>
            <button v-if="writable" class="kb-del" type="button" title="删除" @click.stop="removeKb(row)">✕</button>
          </span>
        </article>
      </div>

      <!-- 查看详情弹层 -->
      <div v-if="kbViewOpen" class="kb-mask" @click.self="closeKbView">
        <div class="kb-dialog kb-dialog--wide">
          <header class="kb-dialog-head">
            <div class="kb-head-main">
              <span class="kb-cat" :class="kbViewed?.category">{{ kbCatLabel(kbViewed?.category) }}</span>
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
          <pre class="kb-content">{{ kbViewed?.content }}</pre>
          <footer class="kb-actions" v-if="writable">
            <button class="btn-ghost" type="button" @click="copyKbContent(kbViewed)">复制内容</button>
            <button class="btn-ghost" type="button" @click="toggleKb(kbViewed); kbViewed.enabled = !kbViewed.enabled">
              {{ kbViewed?.enabled ? "停用" : "启用" }}
            </button>
            <button class="btn-ghost" type="button" @click="openEditKb(kbViewed)">编辑</button>
            <button class="btn-danger" type="button" @click="removeKb(kbViewed); kbViewed = null">删除</button>
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
              <button class="btn-ghost" @click="kbAddOpen = false">取消</button>
              <button class="btn-primary" @click="saveKb">{{ kbEditId ? "保存修改" : "保存" }}</button>
            </div>
          </div>
        </div>
      </div>
    </template>
  </section>
</template>
