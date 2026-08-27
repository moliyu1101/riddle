<script setup>
import { ref, onActivated, onDeactivated, onMounted, onUnmounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { api, authReadyRef, authRequiredRef, authRoleRef, loadAuthRole, verifyToken } from "../api.js";
import TaskSituationMap from "../components/tasks/TaskSituationMap.vue";
import { openCreateTask, openEditTask } from "../composables/useCreateTask.js";
import { useCountUp } from "../composables/useCountUp.js";

defineOptions({ name: "TasksView" });

const tasks = ref([]);
const initialLoading = ref(true);
const refreshing = ref(false);
const searchQuery = ref("");
const statusFilter = ref("all");
const writable = computed(() => authRoleRef.value === "full");
const router = useRouter();
let pollTimer = null;

const STATUS_LABEL = {
  running: "运行中",
  idle: "空闲",
  paused: "已暂停",
  stopped: "已停止",
  created: "未启动",
};

const STATUS_OPTIONS = [
  { value: "all", label: "全部状态" },
  { value: "running", label: "运行中" },
  { value: "idle", label: "空闲" },
  { value: "paused", label: "已暂停" },
  { value: "stopped", label: "已停止" },
  { value: "created", label: "未启动" },
];

function taskModeLabel(t) {
  return t?.src_type === "enterprise" ? "企业SRC" : "EduSRC";
}
function engineLabel(engine) {
  return {
    fofa: "FOFA",
    quake: "360 Quake",
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

// 统计数据
const stats = computed(() => {
  const total = tasks.value.length;
  const running = tasks.value.filter((t) => t.status === "running").length;
  const pendingReview = tasks.value.reduce((sum, t) => sum + (t.pending_user_review || 0), 0);
  const totalVulns = tasks.value.reduce((sum, t) => sum + (t.total_vulns || 0), 0);
  return { total, running, pendingReview, totalVulns };
});

// 统计数字滚动
const statTotal = useCountUp(computed(() => stats.value.total));
const statRunning = useCountUp(computed(() => stats.value.running));
const statReview = useCountUp(computed(() => stats.value.pendingReview));
const statVulns = useCountUp(computed(() => stats.value.totalVulns));

// 筛选后的任务
const filteredTasks = computed(() => {
  return tasks.value.filter((t) => {
    const matchStatus = statusFilter.value === "all" || t.status === statusFilter.value;
    const matchSearch = !searchQuery.value ||
      t.name.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
      (t.fofa_query || "").toLowerCase().includes(searchQuery.value.toLowerCase());
    return matchStatus && matchSearch;
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
  try { tasks.value = await api.listTasks(); }
  finally {
    initialLoading.value = false;
    refreshing.value = false;
    syncPoller();
  }
}

// 删除任务
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
  <section class="view tasks-view" :class="{ 'is-refreshing': refreshing }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <!-- 面包屑 -->
    <nav class="crumb" aria-label="面包屑">
      <span>指挥中心</span>
      <span class="crumb-sep">/</span>
      <b>任务态势</b>
    </nav>

    <!-- 态势图横幅 -->
    <div v-if="!initialLoading && tasks.length" class="situation-banner">
      <TaskSituationMap :tasks="tasks" />
    </div>

    <!-- 统计条 -->
    <div v-if="!initialLoading && tasks.length" class="stats-row">
      <div class="stat-card">
        <div class="stat-icon total">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ statTotal }}</span>
          <span class="stat-label">任务总数</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon running">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ statRunning }}</span>
          <span class="stat-label">运行中</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon review">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
        </div>
        <div class="stat-info">
          <span class="stat-value review-value">{{ statReview }}</span>
          <span class="stat-label">待复审</span>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon vuln">
          <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        </div>
        <div class="stat-info">
          <span class="stat-value">{{ statVulns }}</span>
          <span class="stat-label">累计漏洞</span>
        </div>
      </div>
    </div>

    <!-- 筛选工具栏 -->
    <div v-if="!initialLoading && tasks.length" class="tasks-toolbar">
      <div class="toolbar-left">
        <div class="search-box">
          <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
          <input
            v-model="searchQuery"
            type="text"
            placeholder="搜索任务名称、查询语句..."
            class="search-input"
          />
        </div>
      </div>
      <div class="toolbar-right">
        <select v-model="statusFilter" class="toolbar-select">
          <option v-for="opt in STATUS_OPTIONS" :key="opt.value" :value="opt.value">
            {{ opt.label }}
          </option>
        </select>
        <span class="result-count">
          共 <b>{{ filteredTasks.length }}</b> 个任务
        </span>
      </div>
    </div>

    <!-- 加载骨架屏 -->
    <div v-if="initialLoading" class="task-list">
      <div v-for="n in 4" :key="n" class="task-card skeleton-task" aria-hidden="true">
        <div class="task-card-main">
          <div class="tc-title"><span class="sk-bar sk-title"></span></div>
          <div class="task-card-meta">
            <span class="sk-bar sk-badge"></span>
            <span class="sk-bar sk-meta"></span>
          </div>
          <div class="task-query sk-query-wrap">
            <span class="sk-bar sk-query"></span>
            <span class="sk-bar sk-query short"></span>
          </div>
        </div>
        <div class="task-card-side">
          <span class="sk-bar sk-time"></span>
          <div class="task-actions">
            <span class="sk-bar sk-action"></span>
            <span class="sk-bar sk-action"></span>
          </div>
        </div>
      </div>
    </div>

    <!-- 空状态 -->
    <div v-else-if="!tasks.length" class="empty empty-hero">
      <div class="empty-radar" aria-hidden="true">
        <svg viewBox="0 0 64 64" width="64" height="64" fill="none">
          <circle cx="32" cy="32" r="28" stroke="currentColor" stroke-width="1.5" opacity="0.25"/>
          <circle cx="32" cy="32" r="18" stroke="currentColor" stroke-width="1" opacity="0.18"/>
          <circle cx="32" cy="32" r="8" stroke="currentColor" stroke-width="1" opacity="0.18"/>
          <path d="M32 32 L32 6" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity="0.5"/>
          <path d="M32 32 L52 20" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity="0.5"/>
          <circle cx="32" cy="32" r="2.5" fill="currentColor"/>
          <path d="M32 4a28 28 0 0 1 24.2 12" stroke="currentColor" stroke-width="2" stroke-linecap="round" class="radar-sweep"/>
        </svg>
      </div>
      <b class="empty-title">还没有挖掘任务</b>
      <p class="empty-desc">创建第一个任务，Worker 将自动搜集资产、侦察目标并挖掘漏洞，产出进入复审队列。</p>
      <button v-if="writable" type="button" class="empty-cta" @click="openCreateTask()">
        <svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M12 5v14M5 12h14"/></svg>
        新建任务
      </button>
      <span v-else class="empty-note">当前为只读/观摩权限，无法创建任务</span>
    </div>

    <!-- 无搜索结果 -->
    <div v-else-if="!filteredTasks.length" class="empty empty-small">
      <b class="empty-title">没有匹配的任务</b>
      <p class="empty-desc">尝试调整搜索关键词或筛选条件</p>
    </div>

    <!-- 任务列表 -->
    <div v-else class="task-list">
      <article
        v-for="(t, i) in filteredTasks"
        :key="t.id"
        class="task-card anim-fade-up"
        :class="{ live: t.status === 'running' }"
        :style="{ '--i': i }"
        @click="router.push(`/task/${t.id}`)"
      >
        <div class="task-card-main">
          <div class="tc-title-row">
            <div class="tc-title">
              <span v-if="t.status === 'running'" class="pulse"></span>
              <b>{{ t.name }}</b>
            </div>
            <div v-if="t.pending_user_review > 0" class="review-badge"
                 :title="`${t.pending_user_review} 个漏洞待复审`">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/></svg>
              {{ t.pending_user_review }} 待复审
            </div>
          </div>

          <div class="task-card-meta">
            <span class="badge" :class="t.status">
              <span class="badge-dot"></span>
              {{ STATUS_LABEL[t.status] || t.status }}
            </span>
            <span class="meta-dot">·</span>
            <span class="meta">{{ taskModeLabel(t) }}</span>
            <span class="meta-dot">·</span>
            <span class="meta">{{ targetSourceLabel(t) }}</span>
            <span class="meta-dot">·</span>
            <span class="meta">
              <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
              {{ t.concurrency }} 并发
            </span>
            <span class="meta-dot">·</span>
            <span class="meta">深挖 ×{{ t.deepen_cap ?? 2 }}</span>
          </div>

          <div class="task-query-row">
            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="query-icon" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
            <code class="task-query">{{ taskScopeText(t) }}</code>
          </div>

          <!-- 进度条（仅运行中任务显示） -->
          <div v-if="t.status === 'running'" class="task-progress-row">
            <div class="task-progress-bar">
              <div class="task-progress-fill" :style="{ width: `${Math.min(t.progress || 15, 95)}%` }"></div>
            </div>
            <span class="task-progress-text">{{ t.progress || 0 }}%</span>
          </div>
        </div>

        <div class="task-card-side">
          <div class="task-stats-mini">
            <div class="mini-stat">
              <span class="mini-stat-value">{{ t.total_targets || 0 }}</span>
              <span class="mini-stat-label">目标</span>
            </div>
            <div class="mini-stat vuln">
              <span class="mini-stat-value">{{ t.total_vulns || 0 }}</span>
              <span class="mini-stat-label">漏洞</span>
            </div>
          </div>
          <time class="meta task-time">
            <svg viewBox="0 0 24 24" width="11" height="11" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
            {{ t.created_at.slice(0, 19).replace("T", " ") }}
          </time>
          <div v-if="writable" class="task-actions">
            <button class="mini-action" type="button" @click.stop="openEditTask(t.id)">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>
              编辑
            </button>
            <button class="mini-action danger" type="button" @click.stop="askDelete(t)">
              <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
              删除
            </button>
          </div>
          <span class="task-chevron" aria-hidden="true">
            <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          </span>
        </div>
      </article>
    </div>

    <!-- 删除确认弹窗 -->
    <div v-if="delTarget" class="modal-mask" @click.self="cancelDelete">
      <div class="modal-card del-modal" role="dialog" aria-modal="true">
        <div class="del-modal-head">
          <div class="del-icon-wrap">
            <svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
          </div>
          <h3 class="del-title">删除任务</h3>
        </div>
        <p class="del-desc">
          即将删除任务 <b>「{{ delTarget.name }}」</b>。
        </p>
        <div class="del-warn">
          <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
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
