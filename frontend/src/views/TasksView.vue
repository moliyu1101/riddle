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
  pendingIntercepts: 0,
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
  const pendingReview = tasks.value.reduce((sum, t) => sum + (t.pending_user_review || 0), 0);
  const totalVulns = tasks.value.reduce((sum, t) => sum + (t.total_vulns || 0), 0);
  return { total, running, pendingReview, totalVulns };
});

const statTotal = useCountUp(computed(() => stats.value.total));
const statRunning = useCountUp(computed(() => stats.value.running));
const statReview = useCountUp(computed(() => stats.value.pendingReview));
const statVulns = useCountUp(computed(() => stats.value.totalVulns));
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
    const [taskRes, intelRes, kbRes, hardRes, icRes] = await Promise.all([
      api.listTasks(),
      isPriv ? api.intelStats().catch(() => null) : Promise.resolve(null),
      isPriv ? api.knowledgeList("all", "").catch(() => []) : Promise.resolve([]),
      isPriv ? api.hardTargetsStats().catch(() => null) : Promise.resolve(null),
      isPriv ? api.fusionInterceptList({ status: "pending" }).catch(() => null) : Promise.resolve(null),
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
      pendingIntercepts: Array.isArray(icRes?.items) ? icRes.items.length : 0,
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
  <section class="ops-view" :class="{ 'is-refreshing': refreshing }">
    <!-- 顶部工业页面抬头 -->
    <header class="ops-head">
      <div>
        <div class="ops-kicker">MISSION CONTROL MATRIX · AUTONOMOUS SRC</div>
        <h1>作战调度矩阵</h1>
      </div>
      <div class="ops-head-actions">
        <button type="button" class="btn ghost" :disabled="refreshing" @click="load()">
          {{ refreshing ? "同步中…" : "↻ 刷新态势" }}
        </button>
        <button v-if="writable" type="button" class="btn primary" @click="openCreateTask()">
          ＋ 新建作战任务
        </button>
      </div>
    </header>

    <!-- 顶部 6 格编号遥测台账条 -->
    <div v-if="!initialLoading && tasks.length" class="ops-ledger-strip" :class="{ obs: authRoleRef === 'observer' }">
      <button type="button" class="ledger-cell" :class="{ on: statusFilter === 'running' }" @click="statusFilter = statusFilter === 'running' ? 'all' : 'running'">
        <span class="lc-num">01 / ACTIVE</span>
        <b class="lc-val">{{ statRunning }}<small>/{{ statTotal }}</small></b>
        <span class="lc-lbl">在侦 / 总任务</span>
      </button>
      <button type="button" class="ledger-cell warn" :class="{ on: onlyPendingReview }" @click="onlyPendingReview = !onlyPendingReview">
        <span class="lc-num">02 / REVIEW</span>
        <b class="lc-val">{{ statReview }}</b>
        <span class="lc-lbl">待人工复审</span>
      </button>
      <button type="button" class="ledger-cell danger" @click="router.push('/vulns')">
        <span class="lc-num">03 / ARCHIVE</span>
        <b class="lc-val">{{ statVulns }}</b>
        <span class="lc-lbl">过审漏洞档案</span>
      </button>
      <template v-if="authRoleRef !== 'observer'">
        <button type="button" class="ledger-cell" @click="router.push({ path: '/intel', query: { tab: 'intel' } })">
          <span class="lc-num">04 / UTILITY</span>
          <b class="lc-val">{{ statIntel }}</b>
          <span class="lc-lbl">效用情报 ({{ loopMetrics.intelVerified }} 核准)</span>
        </button>
        <button type="button" class="ledger-cell ok" @click="router.push({ path: '/intel', query: { tab: 'kb', origin: 'distilled' } })">
          <span class="lc-num">05 / DISTILL</span>
          <b class="lc-val">{{ statDistilled }}<small>/{{ loopMetrics.kbTotal }}</small></b>
          <span class="lc-lbl">实战蒸馏 / 知识库</span>
        </button>
        <button
          type="button"
          class="ledger-cell"
          @click="router.push(loopMetrics.pendingIntercepts > 0 ? { path: '/fusion', query: { tab: 'gates' } } : { path: '/intel', query: { tab: 'hard' } })"
        >
          <span class="lc-num">06 / RETRY_POOL</span>
          <b class="lc-val">{{ loopMetrics.hardTotal }}</b>
          <span class="lc-lbl">
            {{ loopMetrics.pendingIntercepts > 0 ? `硬骨头 · ${loopMetrics.pendingIntercepts} 待批命令` : "硬骨头唤醒池" }}
          </span>
        </button>
      </template>
    </div>

    <!-- 空状态 -->
    <div v-if="!initialLoading && !tasks.length" class="ops-empty">
      <div class="ops-empty-badge">READY TO DEPLOY</div>
      <h2>还没有挖掘任务</h2>
      <p>创建第一个任务后，系统将自动执行测绘侦察、并发黑板协同深挖、证据门校验与实战蒸馏入库。</p>
      <button v-if="writable" type="button" class="btn primary" @click="openCreateTask()">
        ＋ 新建作战任务
      </button>
      <span v-else class="ops-empty-note">当前为只读/观摩权限，无法创建任务</span>
    </div>

    <!-- 主体 7:3 双栏工作区 -->
    <div v-else class="ops-split-workspace">
      <!-- 左：任务调度表格 / Bento 网格 -->
      <div class="ops-primary-pane">
        <div class="ops-toolbar">
          <div class="ops-segs" role="tablist" aria-label="任务状态筛选">
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
          <div class="ops-tools-right">
            <input
              v-model="searchQuery"
              type="text"
              class="ops-search"
              placeholder="筛选任务名 / FOFA 查询..."
            />
            <div class="view-switch" role="group" aria-label="视图切换">
              <button type="button" :class="{ on: viewMode === 'table' }" @click="setViewMode('table')">列表</button>
              <button type="button" :class="{ on: viewMode === 'grid' }" @click="setViewMode('grid')">网格</button>
            </div>
          </div>
        </div>

        <div v-if="initialLoading" class="ops-skeleton-box">
          <div v-for="n in 5" :key="n" class="ops-skel-row"></div>
        </div>

        <div v-else-if="!filteredTasks.length" class="ops-empty compact">
          <h3>没有匹配的任务</h3>
          <p>尝试清空关键词或切换筛选状态。</p>
        </div>

        <!-- 视图 A：精密工程表格 -->
        <div v-else-if="viewMode === 'table'" class="ops-table-wrap">
          <table class="ops-table">
            <thead>
              <tr>
                <th>任务名称与协同架构</th>
                <th>状态</th>
                <th>进度 / 并发</th>
                <th>漏洞 / 复审 / 闸门</th>
                <th class="th-right">调度操作</th>
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
                  <small>{{ t.concurrency }} 并发 · 深挖×{{ t.deepen_cap ?? 2 }}</small>
                </td>
                <td class="td-vulns">
                  <div class="tv-row">
                    <b>{{ t.total_vulns || 0 }} 漏洞</b>
                    <span v-if="t.pending_user_review > 0" class="tv-rev">{{ t.pending_user_review }} 待审</span>
                  </div>
                  <div v-if="t.goal_summary?.configured" class="tv-goal" :class="t.goal_summary.goal_met ? 'met' : 'incomplete'">
                    {{ t.goal_summary.summary }} · {{ t.goal_summary.terminal_state }}
                  </div>
                  <small v-else class="tv-muted">未设目标闸门</small>
                </td>
                <td class="td-acts" @click.stop>
                  <button type="button" class="act-btn go" @click="router.push(`/task/${t.id}`)">作战室 →</button>
                  <template v-if="writable">
                    <button type="button" class="act-btn" title="配置验收目标闸门" @click="openTaskFusionGoals(t.id)">🎯</button>
                    <button type="button" class="act-btn" title="编辑参数" @click="openEditTask(t.id)">编辑</button>
                    <button type="button" class="act-btn danger" title="删除任务" @click="askDelete(t)">删</button>
                  </template>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- 视图 B：Bento 卡片网格 -->
        <div v-else class="ops-bento-grid">
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
              <div><b>{{ t.total_targets || 0 }}</b><small>目标</small></div>
              <div><b>{{ t.total_vulns || 0 }}</b><small>漏洞</small></div>
              <div><b class="warn">{{ t.pending_user_review || 0 }}</b><small>待复审</small></div>
            </div>
            <div class="prog-track"><i :style="{ width: `${Math.min(100, Math.max(2, t.progress || 0))}%` }"></i></div>
            <div class="bc-foot" @click.stop>
              <button type="button" class="act-btn go" @click="router.push(`/task/${t.id}`)">进入作战室 →</button>
              <template v-if="writable">
                <button type="button" class="act-btn" @click="openTaskFusionGoals(t.id)">🎯 目标</button>
                <button type="button" class="act-btn" @click="openEditTask(t.id)">编辑</button>
                <button type="button" class="act-btn danger" @click="askDelete(t)">删</button>
              </template>
            </div>
          </article>
        </div>
      </div>

      <!-- 右：态势拓扑雷达 + 自进化快捷箱 -->
      <aside class="ops-side-pane">
        <div class="ops-map-card">
          <TaskSituationMap :tasks="tasks" />
        </div>

        <div v-if="authRoleRef !== 'observer'" class="ops-evo-box">
          <div class="ebox-head">
            <b>自进化与治理直达</b>
            <small>CLOSED-LOOP</small>
          </div>
          <router-link :to="{ path: '/intel', query: { tab: 'kb', origin: 'distilled' } }" class="ebox-link">
            <span>⚡ 实战脱敏蒸馏知识库</span>
            <b>{{ loopMetrics.kbDistilled }} 篇 →</b>
          </router-link>
          <router-link :to="{ path: '/intel', query: { tab: 'hard' } }" class="ebox-link">
            <span>🦴 硬骨头携情报唤醒池</span>
            <b>{{ loopMetrics.hardTotal }} 条 →</b>
          </router-link>
          <router-link :to="{ path: '/fusion', query: { tab: 'gates' } }" class="ebox-link">
            <span>🛡️ 三层命令拦截与闸门</span>
            <b>{{ loopMetrics.pendingIntercepts }} 待批 →</b>
          </router-link>
        </div>
      </aside>
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
.ops-view { display: flex; flex-direction: column; gap: 16px; }

.ops-head {
  display: flex; align-items: flex-end; justify-content: space-between; gap: 14px; flex-wrap: wrap;
}
.ops-kicker {
  font-family: "IBM Plex Mono", monospace; font-size: 10.5px; font-weight: 700;
  color: var(--accent-ink); letter-spacing: .12em; margin-bottom: 3px;
}
.ops-head h1 { font-size: 22px; font-weight: 700; letter-spacing: -.02em; color: var(--ink); }
.ops-head-actions { display: flex; gap: 8px; flex-wrap: wrap; }

/* 6格编号遥测条 */
.ops-ledger-strip {
  display: grid;
  grid-template-columns: repeat(6, minmax(0, 1fr));
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}
.ops-ledger-strip.obs { grid-template-columns: repeat(3, minmax(0, 1fr)); }
.ledger-cell {
  display: flex; flex-direction: column; align-items: flex-start; gap: 3px;
  padding: 12px 14px; border: none; border-right: 1px solid var(--border-soft);
  border-radius: 0; background: var(--surface); text-align: left; cursor: pointer;
}
.ledger-cell:last-child { border-right: none; }
.ledger-cell:hover { background: var(--surface-2); }
.ledger-cell.on { background: var(--accent-bg); box-shadow: inset 0 -2px 0 var(--accent); }
.lc-num { font-family: "IBM Plex Mono", monospace; font-size: 10px; font-weight: 600; color: var(--faint); letter-spacing: .06em; }
.lc-val { font-size: 22px; font-weight: 700; font-variant-numeric: tabular-nums; color: var(--ink); line-height: 1.15; }
.lc-val small { font-size: 12.5px; font-weight: 500; color: var(--muted); }
.ledger-cell.warn .lc-val { color: var(--warn); }
.ledger-cell.danger .lc-val { color: var(--danger); }
.ledger-cell.ok .lc-val { color: var(--ok); }
.lc-lbl { font-size: 11.5px; color: var(--muted); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; max-width: 100%; }

/* 7:3 拆分主区 */
.ops-split-workspace {
  display: grid;
  grid-template-columns: minmax(0, 1.85fr) minmax(300px, 0.9fr);
  gap: 16px;
  align-items: start;
}
.ops-primary-pane { display: flex; flex-direction: column; gap: 12px; min-width: 0; }
.ops-toolbar {
  display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap;
  padding: 8px 10px; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
}
.ops-segs { display: flex; flex-wrap: wrap; gap: 4px; }
.seg-btn {
  padding: 5px 10px; font-size: 12px; font-weight: 500; border-radius: var(--radius-sm);
  border: 1px solid transparent; background: transparent; color: var(--muted);
}
.seg-btn:hover { background: var(--surface-2); color: var(--ink); }
.seg-btn.on { background: var(--ink); color: var(--bg); font-weight: 600; }
.ops-tools-right { display: flex; align-items: center; gap: 8px; flex: 1; justify-content: flex-end; min-width: 220px; }
.ops-search { max-width: 260px; padding: 6px 10px; font-size: 12.5px; }
.view-switch {
  display: inline-flex; border: 1px solid var(--border); border-radius: var(--radius-sm); overflow: hidden;
}
.view-switch button {
  border: none; border-radius: 0; padding: 5px 10px; font-size: 12px; background: var(--surface); color: var(--muted);
}
.view-switch button.on { background: var(--accent); color: var(--on-accent); font-weight: 600; }

/* 表格矩阵 */
.ops-table-wrap {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); overflow-x: auto; box-shadow: var(--shadow-sm);
}
.ops-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
.ops-table th {
  text-align: left; font-size: 11px; font-weight: 600; color: var(--muted); letter-spacing: .04em;
  padding: 10px 14px; background: var(--surface-2); border-bottom: 1px solid var(--border); white-space: nowrap;
}
.ops-table th.th-right { text-align: right; }
.ops-table tbody tr {
  border-bottom: 1px solid var(--border-soft); cursor: pointer; transition: background-color .12s;
}
.ops-table tbody tr:last-child { border-bottom: none; }
.ops-table tbody tr:hover { background: var(--surface-2); }
.ops-table tbody tr.running { box-shadow: inset 3px 0 0 var(--ok); }
.ops-table td { padding: 11px 14px; vertical-align: middle; }

.td-main { min-width: 240px; }
.tm-title { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }
.tm-title b { font-size: 13.5px; color: var(--ink); }
.tm-dot { width: 7px; height: 7px; border-radius: 50%; background: var(--ok); animation: pulse-dot 1.6s infinite; }
.tm-collab {
  font-size: 10.5px; font-weight: 600; padding: 1px 7px; border-radius: 4px;
  border: 1px solid var(--border); background: var(--surface-2); color: var(--muted);
}
.tm-collab.site { color: var(--accent2-ink); background: var(--accent2-bg); border-color: color-mix(in oklch, var(--accent2) 35%, transparent); }
.tm-collab.multi { color: var(--info); background: var(--info-bg); border-color: color-mix(in oklch, var(--info) 35%, transparent); }
.tm-sub { display: flex; align-items: center; gap: 6px; font-size: 11.5px; color: var(--muted); max-width: 440px; }
.tm-query {
  font-size: 11px; color: var(--ink-2); background: var(--surface-2); padding: 1px 5px; border-radius: 3px;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; min-width: 0;
}

.td-prog { min-width: 150px; }
.prog-num { font-size: 12px; color: var(--ink-2); margin-bottom: 4px; }
.prog-track { height: 5px; background: var(--surface-3); border-radius: 999px; overflow: hidden; margin-bottom: 3px; }
.prog-track i { display: block; height: 100%; background: var(--accent2); }
.td-prog small { font-size: 11px; color: var(--faint); }

.td-vulns { min-width: 140px; }
.tv-row { display: flex; align-items: center; gap: 6px; margin-bottom: 3px; }
.tv-rev { font-size: 10.5px; font-weight: 700; padding: 1px 6px; border-radius: 4px; background: var(--warn-bg); color: var(--warn); }
.tv-goal { font-size: 11px; font-weight: 600; }
.tv-goal.met { color: var(--ok); }
.tv-goal.incomplete { color: var(--warn); }
.tv-muted { font-size: 11px; color: var(--faint); }

.td-acts { text-align: right; white-space: nowrap; }
.td-acts .act-btn { margin-left: 4px; }
.act-btn {
  padding: 4px 9px; font-size: 11.5px; border-radius: 5px;
  border: 1px solid var(--border); background: var(--surface); color: var(--ink-2);
}
.act-btn:hover { border-color: var(--border-strong); background: var(--surface-3); color: var(--ink); }
.act-btn.go { background: var(--ink); border-color: var(--ink); color: var(--bg); font-weight: 600; }
.act-btn.go:hover { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.act-btn.danger:hover { border-color: var(--danger); color: var(--danger); background: var(--danger-bg); }

/* Bento 网格视图 */
.ops-bento-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 12px; }
.bento-card {
  display: flex; flex-direction: column; gap: 10px; padding: 14px 16px;
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); cursor: pointer;
}
.bento-card.running { border-left: 3px solid var(--ok); }
.bento-card:hover { border-color: var(--accent); box-shadow: var(--shadow-sm); }
.bc-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; }
.bc-title { font-size: 14.5px; color: var(--ink); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bc-query { font-size: 11.5px; color: var(--muted); background: var(--surface-2); padding: 4px 8px; border-radius: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bc-metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; text-align: center; padding: 8px; background: var(--surface-2); border-radius: var(--radius-sm); }
.bc-metrics b { display: block; font-size: 16px; color: var(--ink); font-variant-numeric: tabular-nums; }
.bc-metrics b.warn { color: var(--warn); }
.bc-metrics small { font-size: 10.5px; color: var(--muted); }
.bc-foot { display: flex; gap: 6px; flex-wrap: wrap; }

/* 右栏：雷达与快捷箱 */
.ops-side-pane { display: flex; flex-direction: column; gap: 12px; position: sticky; top: 70px; }
.ops-map-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); box-shadow: var(--shadow-sm); }
.ops-map-card :deep(.situation-canvas) { height: 270px; }
.ops-evo-box {
  background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius);
  padding: 12px 14px; display: flex; flex-direction: column; gap: 8px; box-shadow: var(--shadow-sm);
}
.ebox-head { display: flex; justify-content: space-between; align-items: center; }
.ebox-head b { font-size: 12.5px; color: var(--ink); }
.ebox-head small { font-family: "IBM Plex Mono", monospace; font-size: 10px; color: var(--accent2-ink); }
.ebox-link {
  display: flex; justify-content: space-between; align-items: center;
  padding: 8px 10px; border-radius: var(--radius-sm); background: var(--surface-2);
  border: 1px solid var(--border-soft); font-size: 12px; color: var(--ink-2); text-decoration: none;
}
.ebox-link:hover { border-color: var(--accent); color: var(--ink); text-decoration: none; }
.ebox-link b { color: var(--accent-ink); font-variant-numeric: tabular-nums; }

.ops-empty {
  background: var(--surface); border: 1px dashed var(--border-strong); border-radius: var(--radius-lg);
  padding: 46px 24px; text-align: center; display: flex; flex-direction: column; align-items: center; gap: 10px;
}
.ops-empty.compact { padding: 28px 20px; }
.ops-empty-badge { font-family: "IBM Plex Mono", monospace; font-size: 10.5px; padding: 3px 9px; border-radius: 4px; background: var(--accent-bg); color: var(--accent-ink); font-weight: 700; }
.ops-empty p { font-size: 13px; color: var(--muted); max-width: 48ch; }
.ops-empty-note { font-size: 12px; color: var(--faint); }
.ops-skeleton-box { display: grid; gap: 8px; }
.ops-skel-row { height: 54px; border-radius: var(--radius); background: var(--surface); border: 1px solid var(--border-soft); }

@media (max-width: 1200px) {
  .ops-ledger-strip { grid-template-columns: repeat(3, 1fr); }
  .ledger-cell { border-bottom: 1px solid var(--border-soft); }
  .ops-split-workspace { grid-template-columns: 1fr; }
  .ops-side-pane { position: static; }
}
@media (max-width: 720px) {
  .ops-ledger-strip { grid-template-columns: repeat(2, 1fr); }
  .ops-bento-grid { grid-template-columns: 1fr; }
}
</style>
