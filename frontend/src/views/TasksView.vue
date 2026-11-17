<script setup>
import { ref, onActivated, onDeactivated, onMounted, onUnmounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { api, authReadyRef, authRequiredRef, authRoleRef, loadAuthRole, verifyToken } from "../api.js";
import TaskSituationMap from "../components/tasks/TaskSituationMap.vue";
import { openCreateTask, openEditTask } from "../composables/useCreateTask.js";
import { useCountUp } from "../composables/useCountUp.js";
import { showToast } from "../composables/useToast.js";

defineOptions({ name: "TasksView" });

const tasks = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const searchQuery = ref("");
const statusFilter = ref("all");
const onlyPendingReview = ref(false);
const viewMode = ref(localStorage.getItem("riddle-tasks-view") || "table"); // table | grid
const writable = computed(() => authRoleRef.value === "full");
const router = useRouter();
let pollTimer = null;

function setViewMode(mode) {
  viewMode.value = mode;
  localStorage.setItem("riddle-tasks-view", mode);
}

const loopMetrics = ref({
  intelTotal: 0,
  intelVerified: 0,
  intelReused: 0,
  kbTotal: 0,
  kbDistilled: 0,
  hardTotal: 0,
  vulnTotal: 0,
  pendingIntercepts: 0,
  runtimeErrors: 0,
  runtimeWarns: 0,
});

const STATUS_LABEL = {
  running: "运行中",
  idle: "空闲",
  paused: "已暂停",
  stopped: "已停止",
  created: "未启动",
};

const STATUS_SEGMENTS = [
  { value: "all", label: "全部" },
  { value: "running", label: "运行中" },
  { value: "idle", label: "空闲" },
  { value: "paused", label: "暂停" },
  { value: "stopped", label: "已停止" },
  { value: "created", label: "未启动" },
];

function taskModeLabel(t) {
  return t?.src_type === "enterprise" ? "企业SRC" : "EduSRC";
}
function engineLabel(engine) {
  return {
    fofa: "FOFA",
    quake: "Quake",
    hunter: "Hunter",
    zoomeye: "ZoomEye",
    shodan: "Shodan",
    censys: "Censys",
  }[engine] || engine || "";
}
function targetSourceLabel(t) {
  const source = t?.target_source;
  const eng = engineLabel(t?.engine);
  if (source === "manual") return "手动清单";
  if (source === "site") return "单站协作";
  if (source === "both") return eng ? `${eng}+手动` : "测绘+手动";
  if (source === "fofa") return eng || "测绘搜集";
  return source || "-";
}
function taskScopeText(t) {
  if (t?.target_source === "site") {
    return t.fofa_query || t.manual_targets?.[0] || "单站协作";
  }
  return t?.fofa_query || "手动清单";
}
function collabTag(t) {
  if (t?.target_source === "site") return { text: "单站多路线黑板", kind: "site" };
  if ((t?.concurrency || 1) >= 2) return { text: "并发共享黑板", kind: "multi" };
  return { text: "单目标独立", kind: "solo" };
}
function openTaskFusionGoals(taskId) {
  router.push({ path: `/task/${taskId}`, query: { fusion: "goals" } });
}

const stats = computed(() => {
  const total = tasks.value.length;
  const running = tasks.value.filter((t) => t.status === "running").length;
  const paused = tasks.value.filter((t) => t.status === "paused").length;
  const stopped = tasks.value.filter((t) => t.status === "stopped" || t.status === "idle").length;
  const pendingReview = tasks.value.reduce((sum, t) => sum + (t.pending_user_review || 0), 0);
  const totalVulns = tasks.value.reduce((sum, t) => sum + (t.total_vulns || 0), 0);
  return { total, running, paused, stopped, pendingReview, totalVulns };
});

const pendingReviewTasks = computed(() =>
  tasks.value.filter((t) => (t.pending_user_review || 0) > 0).slice(0, 4)
);

const statTotal = useCountUp(computed(() => stats.value.total));
const statRunning = useCountUp(computed(() => stats.value.running));
const statReview = useCountUp(computed(() => stats.value.pendingReview));
const statVulns = useCountUp(computed(() => Math.max(loopMetrics.value.vulnTotal, stats.value.totalVulns)));
const statIntel = useCountUp(computed(() => loopMetrics.value.intelTotal));
const statDistilled = useCountUp(computed(() => loopMetrics.value.kbDistilled));

const filteredTasks = computed(() => {
  const q = searchQuery.value.trim().toLowerCase();
  return tasks.value.filter((t) => {
    const matchStatus = statusFilter.value === "all" || t.status === statusFilter.value;
    const matchReview = !onlyPendingReview.value || (t.pending_user_review || 0) > 0;
    const matchSearch = !q ||
      (t.name || "").toLowerCase().includes(q) ||
      (t.fofa_query || "").toLowerCase().includes(q);
    return matchStatus && matchReview && matchSearch;
  });
});

const hasRunning = computed(() => tasks.value.some((t) => t.status === "running"));

function syncPoller() {
  clearInterval(pollTimer);
  pollTimer = null;
  const ms = hasRunning.value ? 5000 : 15000;
  pollTimer = setInterval(() => load({ background: true }), ms);
}

async function load(opts = {}) {
  const background = !!opts.background;
  if (!tasks.value.length) initialLoading.value = true;
  else if (!background) refreshing.value = true;
  try {
    const isPriv = authRoleRef.value !== "observer";
    const [taskRes, intelRes, kbRes, hardRes, icRes, vulnRes, logRes] = await Promise.all([
      api.listTasks(),
      isPriv ? api.intelStats().catch(() => null) : Promise.resolve(null),
      isPriv ? api.knowledgeList("all", "").catch(() => []) : Promise.resolve([]),
      isPriv ? api.hardTargetsStats().catch(() => null) : Promise.resolve(null),
      isPriv ? api.fusionInterceptList({ status: "pending" }).catch(() => null) : Promise.resolve(null),
      isPriv ? api.vulnStats().catch(() => null) : Promise.resolve(null),
      isPriv ? api.runtimeLogStats().catch(() => null) : Promise.resolve(null),
    ]);
    tasks.value = Array.isArray(taskRes) ? taskRes : [];
    const kbList = Array.isArray(kbRes) ? kbRes : [];
    loopMetrics.value = {
      intelTotal: Number(intelRes?.total || 0),
      intelVerified: Number(intelRes?.verified || 0),
      intelReused: Number(intelRes?.reused || 0),
      kbTotal: kbList.length,
      kbDistilled: kbList.filter((x) => x?.origin === "distilled").length,
      hardTotal: Number(hardRes?.total || 0),
      vulnTotal: Number(vulnRes?.total || 0),
      pendingIntercepts: Array.isArray(icRes?.items) ? icRes.items.length : 0,
      runtimeErrors: Number(logRes?.errors || 0),
      runtimeWarns: Number(logRes?.warns || 0),
    };
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
    syncPoller();
  }
}

// 删除确认弹窗状态
const delTarget = ref(null);
const delToken = ref("");
const delError = ref("");
const deleting = ref(false);

function askDelete(task) {
  delTarget.value = task;
  delToken.value = "";
  delError.value = "";
}
function cancelDelete() {
  if (deleting.value) return;
  delTarget.value = null;
  delToken.value = "";
  delError.value = "";
}
async function confirmDelete() {
  if (!delTarget.value || deleting.value) return;
  const task = delTarget.value;
  if (authRequiredRef.value) {
    if (!delToken.value.trim()) {
      delError.value = "请输入 full 权限令牌以确认删除";
      return;
    }
    deleting.value = true;
    delError.value = "";
    const role = await verifyToken(delToken.value);
    if (role !== "full") {
      deleting.value = false;
      delError.value = role === "none" ? "令牌无效" : "该令牌不是 full 权限，无法删除";
      return;
    }
  } else {
    deleting.value = true;
  }
  try {
    await api.deleteTask(task.id, delToken.value);
    tasks.value = tasks.value.filter((t) => t.id !== task.id);
    delTarget.value = null;
    delToken.value = "";
    showToast(`已删除任务「${task.name}」`, "ok");
  } catch (e) {
    delError.value = `删除失败：${e.message || e}`;
  } finally {
    deleting.value = false;
  }
}

onMounted(async () => {
  if (!authReadyRef.value) await loadAuthRole();
  await load();
});
onActivated(() => {
  if (tasks.value.length) load({ background: true });
  syncPoller();
});
onDeactivated(() => {
  clearInterval(pollTimer);
  pollTimer = null;
});
onUnmounted(() => {
  clearInterval(pollTimer);
  pollTimer = null;
});
watch(authReadyRef, (ready) => {
  if (ready) load();
});
watch(hasRunning, () => syncPoller());
</script>

<template>
  <section class="dash-view" :class="{ 'is-refreshing': refreshing }">
    <!-- Header -->
    <header class="dash-head">
      <div>
        <h1>总览与任务调度</h1>
        <p class="dash-sub">系统全局运行态势 · 多 Agent 自主渗透与漏洞挖掘实时刷新</p>
      </div>
      <div class="dash-head-actions">
        <button type="button" class="btn ghost" :disabled="refreshing" @click="load()">
          {{ refreshing ? "刷新中…" : "↻ 刷新" }}
        </button>
        <button v-if="writable" type="button" class="btn primary" @click="openCreateTask()">
          ＋ 新建任务
        </button>
      </div>
    </header>

    <!-- Row 1: 5 Shadcn Stat Cards (always visible, even when tasks.length === 0) -->
    <div class="dash-kpi-grid" :class="{ obs: authRoleRef === 'observer' }">
      <button type="button" class="kpi-card" :class="{ active: statusFilter === 'running' }"
              @click="statusFilter = statusFilter === 'running' ? 'all' : 'running'">
        <div class="kc-head">
          <span>活跃任务</span>
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3"/>
          </svg>
        </div>
        <div class="kc-val-row">
          <b class="kc-num">{{ statRunning }}</b>
          <span class="kc-den">/ {{ statTotal }}</span>
        </div>
        <div class="kc-foot">
          <template v-if="tasks.length > 0">
            <span v-if="stats.running > 0" class="c-ok">探索 {{ stats.running }}</span>
            <span v-if="stats.paused > 0" class="c-warn">暂停 {{ stats.paused }}</span>
            <span v-if="stats.stopped > 0">已停 {{ stats.stopped }}</span>
            <span v-if="stats.running === 0 && stats.paused === 0 && stats.stopped === 0">共 {{ stats.total }} 个任务</span>
          </template>
          <span v-else>暂无运行中任务</span>
        </div>
      </button>

      <button type="button" class="kpi-card" :class="{ active: onlyPendingReview }"
              @click="onlyPendingReview = !onlyPendingReview">
        <div class="kc-head">
          <span>确认发现与复审</span>
          <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
        </div>
        <div class="kc-val-row">
          <b class="kc-num c-danger">{{ statVulns }}</b>
          <span class="kc-den">过审 / 发现</span>
        </div>
        <div class="kc-foot">
          <span :class="{ 'c-warn': stats.pendingReview > 0 }">待人工审 {{ statReview }}</span>
          <span>·</span>
          <span>AI 候选 {{ stats.totalVulns }}</span>
        </div>
      </button>

      <template v-if="authRoleRef !== 'observer'">
        <button type="button" class="kpi-card" @click="router.push({ path: '/intel', query: { tab: 'intel' } })">
          <div class="kc-head">
            <span>有效情报沉淀</span>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M12 2a7 7 0 0 0-4 12.7V17a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-2.3A7 7 0 0 0 12 2z"/>
            </svg>
          </div>
          <div class="kc-val-row">
            <b class="kc-num">{{ statIntel }}</b>
            <span class="kc-den">条情报</span>
          </div>
          <div class="kc-foot">
            <span class="c-ok">已验证 {{ loopMetrics.intelVerified }}</span>
            <span>·</span>
            <span>被复用 {{ loopMetrics.intelReused }}</span>
          </div>
        </button>

        <button type="button" class="kpi-card" @click="router.push({ path: '/intel', query: { tab: 'kb', origin: 'distilled' } })">
          <div class="kc-head">
            <span>实战知识库</span>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>
            </svg>
          </div>
          <div class="kc-val-row">
            <b class="kc-num">{{ loopMetrics.kbTotal }}</b>
            <span class="kc-den">篇手册</span>
          </div>
          <div class="kc-foot">
            <span class="c-accent">⚡ 实战蒸馏 {{ statDistilled }} 篇</span>
          </div>
        </button>

        <button type="button" class="kpi-card"
                @click="router.push(loopMetrics.pendingIntercepts > 0 ? { path: '/fusion', query: { tab: 'gates' } } : { path: '/intel', query: { tab: 'hard' } })">
          <div class="kc-head">
            <span>硬骨头与拦截</span>
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
              <path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/>
            </svg>
          </div>
          <div class="kc-val-row">
            <b class="kc-num">{{ loopMetrics.hardTotal }}</b>
            <span class="kc-den">硬骨头</span>
          </div>
          <div class="kc-foot">
            <span :class="{ 'c-warn': loopMetrics.pendingIntercepts > 0 }">待审批 {{ loopMetrics.pendingIntercepts }}</span>
            <span>·</span>
            <span :class="{ 'c-danger': loopMetrics.runtimeErrors > 0 }">异常 {{ loopMetrics.runtimeErrors }}</span>
          </div>
        </button>
      </template>
    </div>

    <!-- Row 2: 任务调度列表卡片 -->
    <div class="dash-card">
      <div class="dash-card-head">
        <div class="dch-left">
          <h2>任务调度列表</h2>
          <span class="dch-badge">{{ filteredTasks.length }} 个任务</span>
        </div>

        <div class="dch-tools">
          <div class="dash-segs" role="tablist" aria-label="任务状态筛选">
            <button
              v-for="opt in STATUS_SEGMENTS"
              :key="opt.value"
              type="button"
              class="seg-btn"
              :class="{ on: statusFilter === opt.value }"
              @click="statusFilter = opt.value"
            >
              {{ opt.label }}
            </button>
          </div>

          <input
            v-model="searchQuery"
            type="text"
            class="dash-search"
            placeholder="搜索任务名称 / FOFA 语句..."
          />

          <div class="view-switch" role="group" aria-label="视图切换">
            <button type="button" :class="{ on: viewMode === 'table' }" @click="setViewMode('table')">表格</button>
            <button type="button" :class="{ on: viewMode === 'grid' }" @click="setViewMode('grid')">卡片</button>
          </div>
        </div>
      </div>

      <div v-if="initialLoading" class="dash-loading">
        <div v-for="n in 4" :key="n" class="dash-skel"></div>
      </div>

      <div v-else-if="!tasks.length" class="dash-empty">
        <b>暂无挖掘任务</b>
        <p>点击右上角「新建任务」配置目标、测绘引擎与验收标准，启动多 Agent 自主渗透与漏洞挖掘。</p>
        <button v-if="writable" type="button" class="btn primary" @click="openCreateTask()">
          ＋ 新建第一个任务
        </button>
        <span v-else class="dash-empty-note">当前为只读/观摩权限，无法创建任务</span>
      </div>

      <div v-else-if="!filteredTasks.length" class="dash-empty compact">
        <b>没有匹配的任务</b>
        <p>尝试清空搜索关键词或切换左侧状态筛选标签。</p>
      </div>

      <!-- 视图 A：表格 -->
      <div v-else-if="viewMode === 'table'" class="dash-table-wrap">
        <table class="dash-table">
          <thead>
            <tr>
              <th>任务名称与协同架构</th>
              <th>状态</th>
              <th>探测进度与并发</th>
              <th>漏洞 / 复审 / 目标闸门</th>
              <th class="th-right">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr
              v-for="t in filteredTasks"
              :key="t.id"
              :class="{ running: t.status === 'running' }"
              @click="router.push(`/task/${t.id}`)"
            >
              <td class="td-main">
                <div class="tm-title">
                  <span v-if="t.status === 'running'" class="tm-dot"></span>
                  <b>{{ t.name }}</b>
                  <span class="tm-collab" :class="collabTag(t).kind">{{ collabTag(t).text }}</span>
                </div>
                <div class="tm-sub">
                  <span>{{ taskModeLabel(t) }}</span>
                  <span>·</span>
                  <span>{{ targetSourceLabel(t) }}</span>
                  <span>·</span>
                  <code class="tm-query" :title="taskScopeText(t)">{{ taskScopeText(t) }}</code>
                </div>
              </td>
              <td>
                <span class="badge" :class="t.status">{{ STATUS_LABEL[t.status] || t.status }}</span>
              </td>
              <td class="td-prog">
                <div class="prog-num">{{ t.total_targets || 0 }} 目标 · <b>{{ t.progress || 0 }}%</b></div>
                <div class="prog-track"><i :style="{ width: `${Math.min(100, Math.max(2, t.progress || 0))}%` }"></i></div>
                <div class="prog-meta">{{ t.concurrency }} 并发 · 深挖×{{ t.deepen_cap ?? 2 }}</div>
              </td>
              <td class="td-vulns">
                <div class="tv-row">
                  <b>{{ t.total_vulns || 0 }} 个发现</b>
                  <span v-if="t.pending_user_review > 0" class="tv-rev">{{ t.pending_user_review }} 待审</span>
                </div>
                <div v-if="t.goal_summary?.configured" class="tv-goal" :class="t.goal_summary.goal_met ? 'met' : 'incomplete'">
                  {{ t.goal_summary.summary }} · {{ t.goal_summary.terminal_state }}
                </div>
                <span v-else class="tv-muted">未设目标闸门</span>
              </td>
              <td class="td-acts" @click.stop>
                <button type="button" class="act-btn go" @click="router.push(`/task/${t.id}`)">进入详情</button>
                <template v-if="writable">
                  <button type="button" class="act-btn" title="配置验收目标闸门" @click="openTaskFusionGoals(t.id)">目标</button>
                  <button type="button" class="act-btn" title="编辑参数" @click="openEditTask(t.id)">编辑</button>
                  <button type="button" class="act-btn danger" title="删除任务" @click="askDelete(t)">删除</button>
                </template>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 视图 B：卡片网格 -->
      <div v-else class="dash-bento-grid">
        <article
          v-for="t in filteredTasks"
          :key="t.id"
          class="bento-card"
          :class="{ running: t.status === 'running' }"
          @click="router.push(`/task/${t.id}`)"
        >
          <div class="bc-head">
            <span class="badge" :class="t.status">{{ STATUS_LABEL[t.status] || t.status }}</span>
            <span class="tm-collab" :class="collabTag(t).kind">{{ collabTag(t).text }}</span>
          </div>
          <h3 class="bc-title">{{ t.name }}</h3>
          <code class="bc-query">{{ taskScopeText(t) }}</code>
          <div class="bc-metrics">
            <div><b>{{ t.total_targets || 0 }}</b><span>目标</span></div>
            <div><b>{{ t.total_vulns || 0 }}</b><span>发现</span></div>
            <div><b class="warn">{{ t.pending_user_review || 0 }}</b><span>待复审</span></div>
          </div>
          <div class="prog-track"><i :style="{ width: `${Math.min(100, Math.max(2, t.progress || 0))}%` }"></i></div>
          <div class="bc-foot" @click.stop>
            <button type="button" class="act-btn go" @click="router.push(`/task/${t.id}`)">进入详情</button>
            <template v-if="writable">
              <button type="button" class="act-btn" @click="openTaskFusionGoals(t.id)">目标</button>
              <button type="button" class="act-btn" @click="openEditTask(t.id)">编辑</button>
              <button type="button" class="act-btn danger" @click="askDelete(t)">删除</button>
            </template>
          </div>
        </article>
      </div>
    </div>

    <!-- Row 3: 3-Column Bottom Overview Grid -->
    <div class="dash-bottom-grid">
      <section class="dash-card dash-map-panel">
        <div class="dash-card-subhead">
          <h3>全局目标态势分布</h3>
          <span>实时目标与发现拓扑</span>
        </div>
        <div class="dash-map-wrap">
          <TaskSituationMap :tasks="tasks" />
        </div>
      </section>

      <section v-if="authRoleRef !== 'observer'" class="dash-card">
        <div class="dash-card-subhead">
          <h3>自主进化闭环入口</h3>
          <span>数据沉淀与重测调度</span>
        </div>
        <div class="dash-link-list">
          <router-link :to="{ path: '/intel', query: { tab: 'intel' } }" class="ebox-link">
            <div class="el-copy">
              <b>效用情报库</b>
              <span>已验证 {{ loopMetrics.intelVerified }} 条 · 被复用 {{ loopMetrics.intelReused }} 条</span>
            </div>
            <em>{{ loopMetrics.intelTotal }} →</em>
          </router-link>
          <router-link :to="{ path: '/intel', query: { tab: 'kb', origin: 'distilled' } }" class="ebox-link">
            <div class="el-copy">
              <b>实战脱敏蒸馏知识库</b>
              <span>共 {{ loopMetrics.kbTotal }} 篇手册 · 自动融合注入</span>
            </div>
            <em>{{ loopMetrics.kbDistilled }} 篇 →</em>
          </router-link>
          <router-link :to="{ path: '/intel', query: { tab: 'hard' } }" class="ebox-link">
            <div class="el-copy">
              <b>硬骨头携情报唤醒池</b>
              <span>dead / skipped 目标携带最新知识复测</span>
            </div>
            <em>{{ loopMetrics.hardTotal }} 条 →</em>
          </router-link>
          <router-link :to="{ path: '/fusion', query: { tab: 'gates' } }" class="ebox-link">
            <div class="el-copy">
              <b>三层命令拦截与审批</b>
              <span>上下文 Judge 裁决与人工审批队列</span>
            </div>
            <em :class="{ 'c-warn': loopMetrics.pendingIntercepts > 0 }">{{ loopMetrics.pendingIntercepts }} 待批 →</em>
          </router-link>
        </div>
      </section>

      <section class="dash-card">
        <div class="dash-card-subhead">
          <h3>快速发现与系统导引</h3>
          <span>人工复审与异常追踪</span>
        </div>
        <div class="dash-link-list">
          <router-link v-if="authRoleRef !== 'observer'" to="/vulns" class="ebox-link">
            <div class="el-copy">
              <b>漏洞发现档案库</b>
              <span>跨任务过审成果归档、Word 报告导出</span>
            </div>
            <em>{{ statVulns }} 条 →</em>
          </router-link>
          <router-link v-if="authRoleRef !== 'observer'" to="/runtime-logs" class="ebox-link">
            <div class="el-copy">
              <b>系统运行审计日志</b>
              <span>警告 {{ loopMetrics.runtimeWarns }} 条 · 错误 {{ loopMetrics.runtimeErrors }} 条</span>
            </div>
            <em :class="{ 'c-danger': loopMetrics.runtimeErrors > 0 }">{{ loopMetrics.runtimeErrors }} 异常 →</em>
          </router-link>

          <div v-if="pendingReviewTasks.length" class="pending-rev-group">
            <div class="prg-title">待人工复审任务</div>
            <button
              v-for="pt in pendingReviewTasks"
              :key="pt.id"
              type="button"
              class="prg-item"
              @click="router.push(`/task/${pt.id}`)"
            >
              <span>{{ pt.name }}</span>
              <b class="c-warn">{{ pt.pending_user_review }} 待审 →</b>
            </button>
          </div>
          <div v-else class="dash-system-ok">
            当前无积压的人工待复审漏洞，系统处于常态监控状态。
          </div>
        </div>
      </section>
    </div>

    <!-- 删除确认弹窗 -->
    <div v-if="delTarget" class="modal-mask" @click.self="cancelDelete">
      <div class="modal-card del-modal" role="dialog" aria-modal="true">
        <div class="del-modal-head">
          <div class="del-icon-wrap">!</div>
          <h3 class="del-title">删除任务</h3>
        </div>
        <p class="del-desc">
          即将删除任务 <b>「{{ delTarget.name }}」</b>。
        </p>
        <div class="del-warn">
          <span>此操作会一并删除该任务的<b>全部目标、漏洞、审核与通杀记录</b>，且<b>不可恢复</b>。全局情报库不受影响。</span>
        </div>
        <label v-if="authRequiredRef" class="del-field">
          <span>请输入 <b>full 权限令牌</b> 以确认</span>
          <input v-model="delToken" type="password" autocomplete="off"
            placeholder="full 访问令牌" @keyup.enter="confirmDelete" />
        </label>
        <p v-if="delError" class="del-error">{{ delError }}</p>
        <div class="del-actions">
          <button class="btn ghost" type="button" :disabled="deleting" @click="cancelDelete">取消</button>
          <button class="btn danger" type="button" :disabled="deleting" @click="confirmDelete">
            {{ deleting ? "删除中…" : "确认删除" }}
          </button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.dash-view { display: flex; flex-direction: column; gap: 18px; }

.dash-head {
  display: flex; align-items: flex-end; justify-content: space-between; gap: 16px; flex-wrap: wrap;
}
.dash-head h1 { font-size: 24px; font-weight: 700; color: var(--ink); letter-spacing: -.02em; }
.dash-sub { margin-top: 4px; font-size: 14px; color: var(--muted); }
.dash-head-actions { display: flex; gap: 10px; flex-wrap: wrap; }

/* Row 1: 5 Shadcn Stat Cards */
.dash-kpi-grid {
  display: grid;
  grid-template-columns: repeat(5, minmax(0, 1fr));
  gap: 14px;
}
.dash-kpi-grid.obs { grid-template-columns: repeat(2, minmax(0, 1fr)); }
.kpi-card {
  display: flex; flex-direction: column; align-items: stretch; gap: 10px;
  padding: 18px 20px; border-radius: 12px;
  background: var(--surface); border: 1px solid var(--border);
  box-shadow: var(--shadow-sm); text-align: left; cursor: pointer;
  transition: border-color .15s ease, box-shadow .15s ease;
}
.kpi-card:hover { border-color: var(--border-strong); box-shadow: var(--shadow); }
.kpi-card.active { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent); }
.kc-head {
  display: flex; align-items: center; justify-content: space-between; gap: 8px;
  font-size: 13.5px; font-weight: 500; color: var(--muted);
}
.kc-val-row { display: flex; align-items: baseline; gap: 6px; }
.kc-num {
  font-size: 28px; font-weight: 700; line-height: 1.1;
  font-variant-numeric: tabular-nums; color: var(--ink);
}
.kc-den { font-size: 13.5px; color: var(--muted); }
.kc-foot {
  display: flex; flex-wrap: wrap; gap: 6px;
  font-size: 13px; color: var(--muted);
}

.c-ok { color: var(--ok); font-weight: 600; }
.c-warn { color: var(--warn); font-weight: 600; }
.c-danger { color: var(--danger); font-weight: 600; }
.c-accent { color: var(--accent-ink); font-weight: 600; }

/* Card Container */
.dash-card {
  background: var(--surface); border: 1px solid var(--border);
  border-radius: 12px; padding: 18px 20px;
  box-shadow: var(--shadow-sm);
  display: flex; flex-direction: column; gap: 14px;
  min-width: 0;
}
.dash-card-head {
  display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap;
}
.dch-left { display: flex; align-items: center; gap: 10px; }
.dch-left h2 { font-size: 16.5px; font-weight: 600; color: var(--ink); }
.dch-badge {
  font-size: 12.5px; font-weight: 600; padding: 2px 10px; border-radius: 999px;
  background: var(--surface-2); border: 1px solid var(--border); color: var(--muted);
}
.dch-tools { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; flex: 1; justify-content: flex-end; }
.dash-segs { display: flex; flex-wrap: wrap; gap: 4px; }
.seg-btn {
  padding: 6px 12px; font-size: 13.5px; font-weight: 500; border-radius: 6px;
  border: 1px solid transparent; background: transparent; color: var(--muted);
}
.seg-btn:hover { background: var(--surface-2); color: var(--ink); }
.seg-btn.on { background: var(--ink); color: var(--bg); font-weight: 600; }
.dash-search { max-width: 240px; padding: 7px 12px; font-size: 13.5px; }
.view-switch {
  display: inline-flex; border: 1px solid var(--border); border-radius: 6px; overflow: hidden;
}
.view-switch button {
  border: none; border-radius: 0; padding: 6px 12px; font-size: 13.5px;
  background: var(--surface); color: var(--muted);
}
.view-switch button.on { background: var(--ink); color: var(--bg); font-weight: 600; }

/* 表格 */
.dash-table-wrap {
  border: 1px solid var(--border); border-radius: 8px; overflow-x: auto;
}
.dash-table { width: 100%; border-collapse: collapse; font-size: 14px; }
.dash-table th {
  text-align: left; font-size: 13px; font-weight: 600; color: var(--muted);
  padding: 12px 16px; background: var(--surface-2); border-bottom: 1px solid var(--border); white-space: nowrap;
}
.dash-table th.th-right { text-align: right; }
.dash-table tbody tr {
  border-bottom: 1px solid var(--border); cursor: pointer; transition: background-color .12s;
}
.dash-table tbody tr:last-child { border-bottom: none; }
.dash-table tbody tr:hover { background: var(--surface-2); }
.dash-table tbody tr.running { box-shadow: inset 3px 0 0 var(--ok); }
.dash-table td { padding: 14px 16px; vertical-align: middle; }

.td-main { min-width: 260px; }
.tm-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 5px; }
.tm-title b { font-size: 15px; color: var(--ink); }
.tm-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--ok); animation: pulse-dot 1.6s infinite; }
.tm-collab {
  font-size: 12.5px; font-weight: 600; padding: 2px 8px; border-radius: 6px;
  border: 1px solid var(--border); background: var(--surface-2); color: var(--muted);
}
.tm-collab.site { color: var(--accent2-ink); background: var(--accent2-bg); border-color: color-mix(in oklch, var(--accent2) 35%, transparent); }
.tm-collab.multi { color: var(--info); background: var(--info-bg); border-color: color-mix(in oklch, var(--info) 35%, transparent); }
.tm-sub { display: flex; align-items: center; gap: 6px; font-size: 13px; color: var(--muted); max-width: 480px; }
.tm-query {
  font-size: 12.5px; color: var(--ink-2); background: var(--surface-2); padding: 2px 7px; border-radius: 4px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0;
}

.td-prog { min-width: 165px; }
.prog-num { font-size: 13.5px; color: var(--ink-2); margin-bottom: 5px; }
.prog-track { height: 6px; background: var(--surface-3); border-radius: 999px; overflow: hidden; margin-bottom: 4px; }
.prog-track i { display: block; height: 100%; background: var(--accent2); }
.prog-meta { font-size: 12.5px; color: var(--muted); }

.td-vulns { min-width: 160px; }
.tv-row { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.tv-rev { font-size: 12.5px; font-weight: 600; padding: 2px 8px; border-radius: 6px; background: var(--warn-bg); color: var(--warn); }
.tv-goal { font-size: 13px; font-weight: 600; }
.tv-goal.met { color: var(--ok); }
.tv-goal.incomplete { color: var(--warn); }
.tv-muted { font-size: 13px; color: var(--faint); }

.td-acts { text-align: right; white-space: nowrap; }
.td-acts .act-btn { margin-left: 6px; }
.act-btn {
  padding: 6px 12px; font-size: 13px; border-radius: 6px;
  border: 1px solid var(--border); background: var(--surface); color: var(--ink-2);
}
.act-btn:hover { border-color: var(--border-strong); background: var(--surface-2); color: var(--ink); }
.act-btn.go { background: var(--ink); border-color: var(--ink); color: var(--bg); font-weight: 600; }
.act-btn.go:hover { opacity: .9; }
.act-btn.danger:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-bg); }

/* 卡片网格 */
.dash-bento-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
.bento-card {
  display: flex; flex-direction: column; gap: 12px; padding: 18px;
  background: var(--surface); border: 1px solid var(--border); border-radius: 10px; cursor: pointer;
}
.bento-card.running { border-left: 3px solid var(--ok); }
.bento-card:hover { border-color: var(--border-strong); box-shadow: var(--shadow); }
.bc-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.bc-title { font-size: 16px; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bc-query { font-size: 13px; color: var(--muted); background: var(--surface-2); padding: 6px 10px; border-radius: 6px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bc-metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; text-align: center; padding: 10px; background: var(--surface-2); border-radius: 8px; }
.bc-metrics b { display: block; font-size: 18px; color: var(--ink); font-variant-numeric: tabular-nums; }
.bc-metrics b.warn { color: var(--warn); }
.bc-metrics span { font-size: 12.5px; color: var(--muted); }
.bc-foot { display: flex; gap: 8px; flex-wrap: wrap; }

/* 空状态 */
.dash-empty {
  border: 1px dashed var(--border-strong); border-radius: 10px;
  padding: 40px 24px; text-align: center; display: flex; flex-direction: column; align-items: center; gap: 10px;
  background: var(--surface-2);
}
.dash-empty.compact { padding: 28px 20px; }
.dash-empty b { font-size: 16px; color: var(--ink); }
.dash-empty p { font-size: 14px; color: var(--muted); max-width: 52ch; }
.dash-empty-note { font-size: 13.5px; color: var(--faint); }
.dash-loading { display: grid; gap: 10px; }
.dash-skel { height: 56px; border-radius: 8px; background: var(--surface-2); border: 1px solid var(--border); }

/* Row 3: 3-Column Bottom Grid */
.dash-bottom-grid {
  display: grid;
  grid-template-columns: 1.35fr 1fr 1fr;
  gap: 14px;
  align-items: stretch;
}
.dash-card-subhead {
  display: flex; align-items: baseline; justify-content: space-between; gap: 8px;
}
.dash-card-subhead h3 { font-size: 15.5px; font-weight: 600; color: var(--ink); }
.dash-card-subhead span { font-size: 13px; color: var(--muted); }
.dash-map-wrap :deep(.situation-canvas) { height: 260px; }

.dash-link-list { display: flex; flex-direction: column; gap: 8px; }
.ebox-link {
  display: flex; justify-content: space-between; align-items: center; gap: 12px;
  padding: 11px 14px; border-radius: 8px; background: var(--surface-2);
  border: 1px solid var(--border); color: var(--ink); text-decoration: none;
  transition: border-color .15s ease, background-color .15s ease;
}
.ebox-link:hover { border-color: var(--accent); background: var(--surface); text-decoration: none; }
.el-copy { display: flex; flex-direction: column; gap: 2px; min-width: 0; }
.el-copy b { font-size: 14px; color: var(--ink); }
.el-copy span { font-size: 12.5px; color: var(--muted); }
.ebox-link em { font-style: normal; font-size: 14px; font-weight: 600; color: var(--accent-ink); white-space: nowrap; }

.pending-rev-group { display: flex; flex-direction: column; gap: 6px; margin-top: 4px; }
.prg-title { font-size: 13px; font-weight: 600; color: var(--muted); }
.prg-item {
  display: flex; justify-content: space-between; align-items: center;
  padding: 9px 12px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--surface); font-size: 13.5px; color: var(--ink); cursor: pointer; text-align: left;
}
.prg-item:hover { border-color: var(--warn); background: var(--warn-bg); }
.dash-system-ok {
  padding: 14px; border-radius: 8px; background: var(--surface-2);
  border: 1px solid var(--border); font-size: 13.5px; color: var(--muted); text-align: center;
}

@media (max-width: 1280px) {
  .dash-kpi-grid { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .dash-bottom-grid { grid-template-columns: 1fr; }
}
@media (max-width: 768px) {
  .dash-kpi-grid,
  .dash-kpi-grid.obs,
  .dash-bento-grid { grid-template-columns: 1fr; }
}
</style>
