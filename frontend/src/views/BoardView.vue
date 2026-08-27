<script setup>
import { ref, onMounted, onUnmounted, computed, watch, nextTick } from "vue";
import { api, wsUrl, authRoleRef, authReadyRef, loadAuthRole } from "../api.js";
import { copyText, formatLlmErrorCopy } from "../clipboard.js";
import { buildReportMd, buildEdusrcToolReport } from "../report.js";
import { useEventFormat, TRACE_KINDS, DETAIL_KINDS } from "../composables/useEventFormat.js";
import { openEditTask } from "../composables/useCreateTask.js";
import ReportDrawer from "../components/ReportDrawer.vue";
import BoardDeck from "../components/board/BoardDeck.vue";
import CollabPanel from "../components/board/CollabPanel.vue";
import WorkerMatrix from "../components/board/WorkerMatrix.vue";
import ActivityStream from "../components/board/ActivityStream.vue";
import ReviewList from "../components/board/ReviewList.vue";
import SubmitList from "../components/board/SubmitList.vue";
import KillsweepList from "../components/board/KillsweepList.vue";
import RejectedList from "../components/board/RejectedList.vue";
import ArchivedList from "../components/board/ArchivedList.vue";
import WorkerTraceDrawer from "../components/board/WorkerTraceDrawer.vue";

defineOptions({ name: "BoardView" });

const props = defineProps({ id: String });
const task = ref(null);
const tab = ref("board");          // board | review | submit | killsweep | rejected | archived
const boardPanel = ref("workers"); // workers | stream（手机端看板切换）
const events = ref([]);
const liveWorkers = ref([]);       // 在跑 worker 活态
const liveEscalations = ref([]);   // 扩大危害活态
const workerSummary = ref({});     // worker 摘要（运行/扩大/空闲槽）
const concurrency = ref(0);        // 任务并发上限（空闲槽计算基准）
const throttle = ref(null);        // 智能节流状态（队列水位/LLM 健康度/同机构扎堆）
const vulnDist = ref([]);          // 漏洞类型分布（大屏可视化）
const siteCollab = ref(null);      // 单站协作态势（三阶段路线流水线，仅 site 任务）
const timeline = ref([]);          // 作战时间线（指挥横幅作战曲线）
const queue = ref([]);             // 复审队列
const submitItems = ref([]);       // 待提交
const killsweepItems = ref([]);    // 通杀列
const rejectedItems = ref([]);     // 已驳回
const archivedItems = ref([]);     // AI 未采纳归档（ignored/deepen，可救回）
const expandedKillsweeps = ref(new Set());
const searchDraft = ref("");
const searchText = ref("");
const pageSize = ref(50);
const pageMenuOpen = ref(false);
const sortOrder = ref("desc"); // desc=最新优先 asc=最早优先
const submittedFilter = ref(false);
const drawerId = ref(null);
const drawerMode = ref("view");
const toastMsg = ref("");
const invalidatingKillsweepId = ref(null);
const retryingKillsweepId = ref(null);
const enqueueingKillsweepId = ref(null);
const selectedKillsweeps = ref(new Set());
const killsweepBatchWorking = ref(false);
const traceOpen = ref(false);
const traceWorker = ref(null);
const traceEvents = ref([]);
const traceLoading = ref(false);
const directiveText = ref("");
const directiveSending = ref(false);
const cancellingEscalateId = ref(null);
const expandedEventKeys = ref(new Set());
const streamDetailLoading = ref({});
const eventLogRef = ref(null);
const readonly = computed(() => authRoleRef.value !== "full");
const initialLoading = ref(true);
const boardReady = ref(false);
const refreshing = ref(false);
const loadedTaskId = ref("");
const submitHasMore = ref(false);
const submitLoading = ref(false);
const archivedHasMore = ref(false);
const archivedLoading = ref(false);
const bulkWorking = ref(false);
const EXPORT_PAGE_SIZE = 80;
const STREAM_DETAIL_CAP = 40;
let ws = null, poll = null, boardPoll = null, searchTimer = null;
let collectRefreshTimer = null;
let wsReconnectTimer = null, wsReconnectAttempt = 0, wsIntentionalClose = false;
let eventRefreshTimer = null, eventRefreshPending = null;
const LIST_TABS = new Set(["review", "submit", "killsweep", "rejected", "archived"]);
// 记录哪些列表 tab 已经加载过数据：首屏只拉看板，列表按需加载；后台只刷新看过的列表。
const loadedTabs = ref(new Set());
// 内存中按 target 聚合的实时轨迹（WS 推送），配合落库 trace API 做回放。
const liveTraceByTarget = ref({});

const { fmtEvent, normalizeTimedEvent, isImportantEvent, traceDedupKey, evEpoch, streamEventStableKey, eventExpandKey, canExpandEvent, nextTraceUid } = useEventFormat(task);

function toast(m) { toastMsg.value = m; setTimeout(() => (toastMsg.value = ""), 2200); }

function onAuthOrTokenChange() {
  closeWs(true);
  connectWs();
  refreshAll({ background: true, includeTask: true, includeBoard: true });
}

function isListTab(t) {
  return LIST_TABS.has(t);
}

function markTabLoaded(t) {
  if (!isListTab(t)) return;
  const next = new Set(loadedTabs.value);
  next.add(t);
  loadedTabs.value = next;
}

async function loadTask() {
  const id = props.id;
  const t = await api.getTask(id);
  if (id === props.id && id === loadedTaskId.value) task.value = t;
}
async function loadQueue() {
  const id = props.id;
  const rows = await api.reviewQueue(id);
  if (id === props.id) queue.value = rows.map(withSearchCache);
}
async function loadSubmit(opts = {}) {
  const id = props.id;
  const reset = opts.reset !== false;
  const offset = reset ? 0 : submitItems.value.length;
  submitLoading.value = true;
  try {
    const res = await api.submitList(id, submittedFilter.value, undefined, {
      compact: true,
      limit: pageSize.value,
      offset,
    });
    const rows = Array.isArray(res) ? res : (res.items || []);
    const next = rows.map(withSearchCache);
    if (id !== props.id) return;
    submitItems.value = reset ? next : [...submitItems.value, ...next];
    submitHasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    submitLoading.value = false;
  }
}
async function loadKillsweeps() {
  const id = props.id;
  const rows = await api.killsweeps(id);
  if (id === props.id) killsweepItems.value = rows.map(withSearchCache);
}
async function loadRejected() {
  const id = props.id;
  const rows = await api.rejectedList(id);
  if (id === props.id) rejectedItems.value = rows.map(withSearchCache);
}
async function loadArchived(opts = {}) {
  const id = props.id;
  const reset = opts.reset !== false;
  const offset = reset ? 0 : archivedItems.value.length;
  archivedLoading.value = true;
  try {
    const res = await api.archivedList(id, undefined, {
      limit: pageSize.value,
      offset,
    });
    const rows = Array.isArray(res) ? res : (res.items || []);
    const next = rows.map(withSearchCache);
    if (id !== props.id) return;
    archivedItems.value = reset ? next : [...archivedItems.value, ...next];
    archivedHasMore.value = !Array.isArray(res) && !!res.has_more;
  } finally {
    archivedLoading.value = false;
  }
}
async function loadMoreArchived() {
  if (archivedLoading.value || !archivedHasMore.value) return;
  await loadArchived({ reset: false });
}

async function refreshAll(opts = {}) {
  const background = !!opts.background;
  const includeTask = opts.includeTask !== false;
  const includeBoard = !!opts.includeBoard;
  const includeCurrent = opts.includeCurrent !== false;
  if (background) refreshing.value = true;
  try {
    const tabs = new Set([...loadedTabs.value].filter(isListTab));
    if (includeCurrent && isListTab(tab.value)) tabs.add(tab.value);
    const jobs = [];
    if (includeTask) jobs.push(loadTask());
    if (includeBoard) jobs.push(loadBoard());
    for (const t of tabs) jobs.push(loadTabData(t));
    await Promise.all(jobs);
  } finally {
    if (background) refreshing.value = false;
  }
}

async function loadTabData(t = tab.value) {
  if (t === "review") await loadQueue();
  else if (t === "submit") await loadSubmit({ reset: true });
  else if (t === "killsweep") await loadKillsweeps();
  else if (t === "rejected") await loadRejected();
  else if (t === "archived") await loadArchived();
  else return;
  markTabLoaded(t);
}

function shouldRefreshTab(t) {
  return tab.value === t || loadedTabs.value.has(t);
}

function scheduleEventRefresh(ev) {
  eventRefreshPending = ev;
  clearTimeout(eventRefreshTimer);
  eventRefreshTimer = setTimeout(() => {
    const pending = eventRefreshPending;
    eventRefreshPending = null;
    if (pending) refreshFromEvent(pending);
  }, 280);
}

async function refreshFromEvent(ev) {
  const k = ev.kind || "";
  const jobs = [loadBoard()];
  if (k.includes("finding")) jobs.push(loadTimeline());   // 新发现落库 → 作战曲线随之更新
  if ((k.includes("finding") || k.includes("review")) && shouldRefreshTab("review")) {
    jobs.push(loadTabData("review"));
  }
  if ((k.includes("finding") || k.includes("review")) && shouldRefreshTab("rejected")) {
    jobs.push(loadTabData("rejected"));
  }
  if ((k.includes("finding") || k.includes("review")) && shouldRefreshTab("archived")) {
    jobs.push(loadTabData("archived"));
  }
  if ((k.includes("submit") || k.includes("review")) && shouldRefreshTab("submit")) {
    jobs.push(loadTabData("submit"));
  }
  if (k.includes("killsweep") && shouldRefreshTab("killsweep")) {
    jobs.push(loadTabData("killsweep"));
  }
  await Promise.all(jobs);
}

function closeWs(intentional = false) {
  wsIntentionalClose = intentional;
  clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
  if (!ws) return;
  const old = ws;
  ws = null;
  old.close();
}

function resetTaskState(full = true) {
  if (full) {
    task.value = null;
    queue.value = [];
    submitItems.value = [];
    killsweepItems.value = [];
    rejectedItems.value = [];
    archivedItems.value = [];
    archivedHasMore.value = false;
    submitHasMore.value = false;
    loadedTabs.value = new Set();
    clearSearch();
  }
  events.value = [];
  liveWorkers.value = [];
  liveEscalations.value = [];
  workerSummary.value = {};
  concurrency.value = 0;
  timeline.value = [];
  boardReady.value = false;
  liveTraceByTarget.value = {};
  expandedEventKeys.value = new Set();
  streamDetailLoading.value = {};
  siteCollab.value = null;
  drawerId.value = null;
  traceOpen.value = false;
  traceWorker.value = null;
  traceEvents.value = [];
  directiveText.value = "";
}

async function bootstrapTask() {
  if (!props.id) return;
  const switching = loadedTaskId.value && loadedTaskId.value !== props.id;
  if (!task.value || switching) initialLoading.value = true;
  else refreshing.value = true;

  closeWs(true);
  resetTaskState(!task.value || switching);
  loadedTaskId.value = props.id;

  try {
    // 先出任务壳（标题/指标），看板 worker/活动流后到，避免被 /board 拖成白屏。
    await loadTask();
    initialLoading.value = false;
    const extras = [loadBoard(), loadTimeline()];
    if (isListTab(tab.value)) extras.push(loadTabData(tab.value));
    try {
      await Promise.all(extras);
    } catch {
      /* 任务壳已出；看板失败不阻断 WS，避免活态停更 */
    }
    wsIntentionalClose = false;
    connectWs();
  } finally {
    initialLoading.value = false;
    refreshing.value = false;
  }
}

function prependStreamEvent(item) {
  const el = eventLogRef.value;
  const shouldPreserveScroll = !!el && el.scrollTop > 4;
  const beforeHeight = el?.scrollHeight || 0;
  events.value.unshift(item);
  if (events.value.length > 200) events.value.length = 200;
  if (!shouldPreserveScroll) return;
  nextTick(() => {
    if (!eventLogRef.value) return;
    eventLogRef.value.scrollTop += eventLogRef.value.scrollHeight - beforeHeight;
  });
}

function pushLiveTrace(ev) {
  const tid = ev.target_id;
  if (!tid || !TRACE_KINDS.has(ev.kind || "")) return;
  const map = { ...liveTraceByTarget.value };
  const list = [...(map[tid] || [])];
  // 兜底：万一某条实时事件没带 ts，落地为「收到时刻」的固定时间，
  // 避免缺失时间导致所有行都显示当前时间、且每次刷新一起变。
  const item = { ...ev, ts: ev.ts || new Date().toISOString(), _text: fmtEvent(ev) || ev.kind, _uid: nextTraceUid() };
  // 近端去重：同一事件的落库/实时两个副本只会挨得很近，扫最近若干条即可。
  const key = traceDedupKey(item);
  for (let i = list.length - 1, floor = Math.max(0, list.length - 60); i >= floor; i--) {
    if (traceDedupKey(list[i]) === key) return;
  }
  list.push(item);
  if (list.length > 300) list.splice(0, list.length - 300);
  map[tid] = list;
  liveTraceByTarget.value = map;
  if (traceOpen.value && traceWorker.value?.target_id === tid) {
    traceEvents.value = [...list].reverse();
  }
}

async function toggleEventExpand(ev, i) {
  if (!canExpandEvent(ev)) return;
  const key = eventExpandKey(ev, i);
  const next = new Set(expandedEventKeys.value);
  if (next.has(key)) {
    next.delete(key);
    expandedEventKeys.value = next;
    return;
  }
  next.add(key);
  expandedEventKeys.value = next;
  const tid = ev.target_id;
  if ((liveTraceByTarget.value[tid] || []).some((e) => DETAIL_KINDS.has(e.kind || ""))) return;
  if (streamDetailLoading.value[tid]) return;
  streamDetailLoading.value = { ...streamDetailLoading.value, [tid]: true };
  try {
    const res = await api.targetTrace(props.id, tid, 120);
    const rows = (res.events || []).map((e) => ({
      ...e,
      _text: fmtEvent(e) || e.message || e.kind,
    }));
    const seen = new Set();
    const merged = [];
    for (const e of [...(liveTraceByTarget.value[tid] || []), ...rows]) {
      const k = traceDedupKey(e);
      if (seen.has(k)) continue;
      seen.add(k);
      merged.push(e._uid != null ? e : { ...e, _uid: nextTraceUid() });
    }
    merged.sort((a, b) => evEpoch(a) - evEpoch(b));
    liveTraceByTarget.value = { ...liveTraceByTarget.value, [tid]: merged };
  } catch {
    /* 展开区显示空态即可 */
  } finally {
    const loading = { ...streamDetailLoading.value };
    delete loading[tid];
    streamDetailLoading.value = loading;
  }
}

async function copyLlmEvent(ev) {
  const ok = await copyText(formatLlmErrorCopy(ev));
  toast(ok ? "已复制 LLM 错误信息" : "复制失败，请手动选中");
}

async function loadBoard() {
  const id = props.id;
  try {
    const b = await api.board(id);
    if (id !== props.id) return;
    liveWorkers.value = b.live_workers || [];
    liveEscalations.value = b.live_escalations || [];
    workerSummary.value = b.worker_summary || {};
    concurrency.value = b.concurrency || 0;
    throttle.value = b.throttle || null;
    vulnDist.value = b.vuln_dist || [];
    siteCollab.value = b.site_collab || null;
    if (task.value) {
      if (b.task_status) task.value.status = b.task_status;
      if (b.stats) task.value.stats = b.stats;
      if (b.progress) task.value.progress = b.progress;
      if (b.fofa_config) task.value.fofa_config = b.fofa_config;
      if (b.model_config_data) task.value.model_config_data = b.model_config_data;
      if (b.llm_usage) task.value.llm_usage = b.llm_usage;
    }
    if (!events.value.length && b.events?.length) {
      const existingByKey = new Map(events.value.map((e) => [streamEventStableKey(e), e]));
      events.value = b.events
        .filter(isImportantEvent)
        .map((e) => normalizeTimedEvent(e, existingByKey))
        .filter(Boolean);
    }
  } finally {
    if (id === props.id) boardReady.value = true;
  }
}

async function loadTimeline() {
  const id = props.id;
  try {
    const res = await api.timeline(id, { bucket: "day", limit: 14 });
    if (id === props.id) timeline.value = res.buckets || [];
  } catch {
    /* 曲线属增强展示，失败不打扰主流程 */
  }
}

function connectWs() {
  if (ws) {
    wsIntentionalClose = true;
    ws.close();
    ws = null;
  }
  clearTimeout(wsReconnectTimer);
  wsReconnectTimer = null;
  if (!props.id) return;
  wsIntentionalClose = false;
  ws = new WebSocket(wsUrl(props.id));
  ws.onopen = () => { wsReconnectAttempt = 0; };
  ws.onmessage = (e) => {
    let ev;
    try { ev = JSON.parse(e.data); } catch { return; }   // 畸形帧不炸整个处理器
    if (ev.kind === "ping") return;
    pushLiveTrace(ev);
    if (!isImportantEvent(ev)) return;
    if (ev.kind === "collector_phase") updateCollectorStatus(ev);
    const text = fmtEvent(ev);
    if (!text) return;
    const item = normalizeTimedEvent({ ...ev, _text: text });
    prependStreamEvent(item);
    const k = ev.kind || "";
    if (k.includes("finding") || k.includes("review") || k.includes("target_done")
        || k.includes("submit") || k.includes("killsweep") || k.includes("worker")
        || k.includes("escalate")) {
      scheduleEventRefresh(ev);
    }
  };
  ws.onclose = () => {
    ws = null;
    if (wsIntentionalClose || !props.id) return;
    clearTimeout(wsReconnectTimer);
    const delay = Math.min(30000, 1000 * (2 ** wsReconnectAttempt));
    wsReconnectAttempt += 1;
    wsReconnectTimer = setTimeout(async () => {
      if (wsIntentionalClose || !props.id) return;
      connectWs();
      await loadBoard();
    }, delay);
  };
}

function updateCollectorStatus(ev) {
  if (!task.value) return;
  task.value.fofa_config = {
    ...(task.value.fofa_config || {}),
    collector_phase: ev.phase || "",
    collector_phase_text: ev.message || "",
    last_target_filter_total: Number(ev.survivors || 0),
    last_target_filter_evaluated: Number(ev.filter_evaluated || 0),
  };
  // 进度口径由后端统一计算：阶段推送后防抖拉一次 board 刷新进度环
  clearTimeout(collectRefreshTimer);
  collectRefreshTimer = setTimeout(loadBoard, 1200);
}

function syncPollers() {
  clearInterval(poll);
  clearInterval(boardPoll);
  const running = task.value?.status === "running";
  boardPoll = setInterval(loadBoard, running ? 2500 : 12000);
  poll = setInterval(() => refreshAll({
    background: true,
    includeTask: false,
    includeBoard: false,
  }), running ? 15000 : 30000);
}

onMounted(async () => {
  window.addEventListener("riddle-auth-role", onAuthOrTokenChange);
  window.addEventListener("riddle-token-changed", onAuthOrTokenChange);
  window.addEventListener("riddle:task-saved", onTaskSavedEvent);
  if (!authReadyRef.value) await loadAuthRole();
  await bootstrapTask();
  syncPollers();
});
onUnmounted(() => {
  window.removeEventListener("riddle-auth-role", onAuthOrTokenChange);
  window.removeEventListener("riddle-token-changed", onAuthOrTokenChange);
  window.removeEventListener("riddle:task-saved", onTaskSavedEvent);
  closeWs(true);
  clearInterval(poll);
  clearInterval(boardPoll);
  clearTimeout(searchTimer);
  clearTimeout(wsReconnectTimer);
  clearTimeout(eventRefreshTimer);
  clearTimeout(collectRefreshTimer);
});

watch(() => props.id, async (id, oldId) => {
  if (!id || id === oldId) return;
  await bootstrapTask();
  syncPollers();
});

watch(() => task.value?.status, () => {
  syncPollers();
});

watch(tab, (t) => {
  // 已加载过的 tab 直接用内存数据；未打开过的列表按需补拉一次。
  // 数据新鲜度由 WebSocket 事件后台刷新 + 后台轮询(refreshAll)保证。
  if (t === "board") return;
  if (loadedTabs.value.has(t)) return;
  loadTabData(t);
});

watch(searchDraft, (v) => {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(() => { searchText.value = v; }, 120);
});

async function ctl(action) {
  try {
    await api[action](props.id);
    toast(action === "start" ? "已启动" : action === "pause" ? "已暂停" : "已停止");
    await Promise.all([loadTask(), loadBoard()]);
  } catch (e) {
    toast(`操作失败：${e?.message || e}`);   // 403/网络失败给用户反馈，别静默
  }
}

// 编辑任务走全局三步向导；保存成功后由 riddle:task-saved 事件回刷看板
async function onTaskSaved(updated) {
  task.value = updated;
  toast("任务参数已保存");
  await Promise.all([loadBoard(), loadTimeline()]);
}
function onTaskSavedEvent(e) {
  if (e.detail && e.detail.id === props.id) onTaskSaved(e.detail);
}

function openReview(id) { drawerId.value = id; drawerMode.value = "review"; }
function openSubmit(id) { drawerId.value = id; drawerMode.value = "submit"; }
function openRejected(id) { drawerId.value = id; drawerMode.value = "rejected"; }
function openArchived(id) { drawerId.value = id; drawerMode.value = "archived"; }
async function skipTarget(w) {
  if (readonly.value) return;
  const host = w.host || w.target_id;
  const ok = window.confirm(
    `确认删除目标「${host}」？\n\n` +
    `· 立即取消它正在进行的挖掘，并跳过该目标（之后不再重新派发、回队，也不会被自动搜集回来）。\n` +
    `· 仅对【本任务】的目标列表生效，不影响其它任务，也不影响已挖到的漏洞。`
  );
  if (!ok) return;
  try {
    await api.skipTarget(props.id, w.target_id);
    liveWorkers.value = liveWorkers.value.filter((x) => x.target_id !== w.target_id);
    toast(`已删除目标 ${host}，将跳过`);
  } catch (e) {
    toast(`删除失败：${e?.message || e}`);
  }
}

async function openWorkerTrace(w) {
  if (!w?.target_id) return;
  traceWorker.value = w;
  traceOpen.value = true;
  directiveText.value = "";
  const live = liveTraceByTarget.value[w.target_id] || [];
  if (live.length) {
    traceEvents.value = [...live].reverse();
  } else {
    traceEvents.value = [];
  }
  traceLoading.value = true;
  try {
    const res = await api.targetTrace(props.id, w.target_id, 200);
    const rows = (res.events || []).map((e) => ({ ...e, _text: fmtEvent(e) || e.message || e.kind }));
    // 落库轨迹 + 内存实时轨迹合并去重（秒级内容键，抹平两副本的毫秒 ts 差异）
    const seen = new Set();
    const merged = [];
    for (const e of [...rows, ...(liveTraceByTarget.value[w.target_id] || [])]) {
      const item = { ...e, _text: e._text || fmtEvent(e) || e.message || e.kind };
      const key = traceDedupKey(item);
      if (seen.has(key)) continue;
      seen.add(key);
      merged.push(item._uid != null ? item : { ...item, _uid: nextTraceUid() });
    }
    merged.sort((a, b) => evEpoch(a) - evEpoch(b));   // 稳定时间序（数值比较，不受 tz/精度影响）
    traceEvents.value = [...merged].reverse();          // 展示为最新在上
    liveTraceByTarget.value = {
      ...liveTraceByTarget.value,
      [w.target_id]: merged,                            // 缓存保持时间正序，供实时追加
    };
  } catch (e) {
    if (!traceEvents.value.length) toast(`加载轨迹失败：${e?.message || e}`);
  } finally {
    traceLoading.value = false;
  }
}

function closeWorkerTrace() {
  traceOpen.value = false;
  traceWorker.value = null;
  directiveText.value = "";
}

async function sendDirective() {
  if (readonly.value || !traceWorker.value || directiveSending.value) return;
  const text = directiveText.value.trim();
  if (!text) return;
  directiveSending.value = true;
  try {
    await api.injectDirective(props.id, traceWorker.value.target_id, text);
    toast("指令已排队，下一轮 LLM 前生效");
    directiveText.value = "";
  } catch (e) {
    toast(`注入失败：${e?.message || e}`);
  } finally {
    directiveSending.value = false;
  }
}

async function cancelEscalation(e) {
  if (readonly.value || cancellingEscalateId.value) return;
  const title = shortText(e.title || e.finding_id || "扩大危害");
  if (!window.confirm(`确认取消「${title}」的扩大危害？`)) return;
  cancellingEscalateId.value = e.finding_id;
  try {
    await api.cancelEscalation(props.id, e.finding_id);
    liveEscalations.value = liveEscalations.value.filter((x) => x.finding_id !== e.finding_id);
    toast("已取消扩大危害");
  } catch (err) {
    toast(`取消失败：${err?.message || err}`);
  } finally {
    cancellingEscalateId.value = null;
  }
}

async function restoreArchived(id) {
  try {
    await api.restoreArchived(id);
    toast("已恢复到复审队列");
    archivedItems.value = archivedItems.value.filter((f) => f.id !== id);
    const jobs = [];
    if (shouldRefreshTab("review")) jobs.push(loadTabData("review"));
    jobs.push(loadBoard());
    await Promise.all(jobs);
  } catch (e) {
    toast(`恢复失败：${e?.message || e}`);
  }
}
function toggleKillsweep(id) {
  const next = new Set(expandedKillsweeps.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  expandedKillsweeps.value = next;
}
function shortText(text, max = 80) {
  const s = String(text || "").replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
async function invalidateKillsweep(k) {
  if (readonly.value || invalidatingKillsweepId.value) return;
  const name = shortText(k.product_name || k.vuln_summary || "这条通杀记录");
  if (!window.confirm(`确认把「${name}」标记为无效？\n标记后会从默认通杀列隐藏，原始记录仍保留用于审计。`)) return;
  invalidatingKillsweepId.value = k.id;
  try {
    await api.invalidateKillsweep(props.id, k.id, "人工复审判定该通杀候选无效");
    const next = new Set(expandedKillsweeps.value);
    next.delete(k.id);
    expandedKillsweeps.value = next;
    toast("已标记为无效");
    await Promise.all([loadTabData("killsweep"), loadBoard()]);
  } catch (e) {
    toast(`标记失败：${e.message || e}`);
  } finally {
    invalidatingKillsweepId.value = null;
  }
}
async function retryKillsweep(k) {
  if (readonly.value || retryingKillsweepId.value) return;
  retryingKillsweepId.value = k.id;
  try {
    await api.retryKillsweep(props.id, k.id);
    toast("已重新启动通杀分析");
    await Promise.all([loadTabData("killsweep"), loadBoard()]);
  } catch (e) {
    toast(`重启失败：${e.message || e}`);
  } finally {
    retryingKillsweepId.value = null;
  }
}
function toggleSelectKillsweep(id) {
  const next = new Set(selectedKillsweeps.value);
  if (next.has(id)) next.delete(id);
  else next.add(id);
  selectedKillsweeps.value = next;
}
function selectAllKillsweeps(ids) {
  selectedKillsweeps.value = new Set(ids);
}
async function enqueueKillsweep(k, count) {
  if (readonly.value || enqueueingKillsweepId.value) return;
  const name = shortText(k.product_name || k.vuln_summary || "这条通杀");
  if (!window.confirm(`确认把「${name}」的 ${count} 个已验证站点入队打洞？\n入队后 Worker 将逐个挖掘并产出完整报告。`)) return;
  enqueueingKillsweepId.value = k.id;
  try {
    const res = await api.enqueueKillsweepAssets(props.id, k.id, count);
    toast(`已入队 ${res.enqueued} 个通杀资产打洞${res.skipped ? `（${res.skipped} 个已入队过跳过）` : ""}`);
    await Promise.all([loadTabData("killsweep"), loadBoard()]);
  } catch (e) {
    toast(`入队失败：${e.message || e}`);
  } finally {
    enqueueingKillsweepId.value = null;
  }
}
function openDerivedFinding(findingId) {
  drawerId.value = findingId;
  drawerMode.value = "view";
}
async function batchInvalidateKillsweeps(ids) {
  if (readonly.value || killsweepBatchWorking.value || !ids.length) return;
  if (!window.confirm(`确认把选中的 ${ids.length} 条通杀记录标记为无效？\n标记后会从默认通杀列隐藏，原始记录仍保留用于审计。`)) return;
  killsweepBatchWorking.value = true;
  try {
    const res = await api.batchInvalidateKillsweeps(props.id, ids, "人工批量复审判定无效");
    toast(`已批量标记 ${res.count} 条为无效`);
    selectedKillsweeps.value = new Set();
    await Promise.all([loadTabData("killsweep"), loadBoard()]);
  } catch (e) {
    toast(`批量标记失败：${e.message || e}`);
  } finally {
    killsweepBatchWorking.value = false;
  }
}
async function batchRetryKillsweeps(ids) {
  if (readonly.value || killsweepBatchWorking.value || !ids.length) return;
  if (!window.confirm(`确认批量重启选中的 ${ids.length} 条通杀分析？`)) return;
  killsweepBatchWorking.value = true;
  try {
    const res = await api.batchRetryKillsweeps(props.id, ids);
    toast(`已重启 ${res.started} 条通杀分析${res.skipped ? `（${res.skipped} 条不可重启跳过）` : ""}`);
    selectedKillsweeps.value = new Set();
    await Promise.all([loadTabData("killsweep"), loadBoard()]);
  } catch (e) {
    toast(`批量重启失败：${e.message || e}`);
  } finally {
    killsweepBatchWorking.value = false;
  }
}
function exportKillsweeps(format) {
  api.killsweepExport(props.id, format).catch((e) => toast(`导出失败：${e.message || e}`));
}

async function loadMoreSubmit() {
  if (submitLoading.value || !submitHasMore.value) return;
  await loadSubmit({ reset: false });
}

async function fetchAllSubmitReports() {
  const reports = [];
  let offset = 0;
  for (;;) {
    const res = await api.submitList(props.id, submittedFilter.value, undefined, {
      compact: false,
      limit: EXPORT_PAGE_SIZE,
      offset,
    });
    const rows = Array.isArray(res) ? res : (res.items || []);
    reports.push(...rows);
    if (Array.isArray(res) || !res.has_more) break;
    offset += rows.length;
    await new Promise((resolve) => requestAnimationFrame(resolve));
  }
  return reports;
}

async function copyAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成全部 Markdown...");
    const reports = await fetchAllSubmitReports();
    const md = reports.map((f) => buildReportMd(f)).join("\n\n---\n\n");
    await copyText(md);
    toast(`已复制 ${reports.length} 份报告`);
  } catch {
    toast("复制失败，请使用导出按钮");
  } finally {
    bulkWorking.value = false;
  }
}
async function exportAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成 Markdown 文件...");
    const reports = await fetchAllSubmitReports();
    const md = reports.map((f) => buildReportMd(f)).join("\n\n---\n\n");
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `riddle-${props.id.slice(0, 8)}-submit.md`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);   // 释放 object URL，避免内存泄漏
    toast(`已导出 ${reports.length} 份报告`);
  } finally {
    bulkWorking.value = false;
  }
}
function edusrcReports(reports) {
  return reports.map((f) => buildEdusrcToolReport(f));
}
async function copyEdusrcAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成全部 EduSRC JSON...");
    const reports = await fetchAllSubmitReports();
    const text = JSON.stringify(edusrcReports(reports), null, 2);
    await copyText(text);
    toast(`已复制 ${reports.length} 份 EduSRC JSON`);
  } catch {
    toast("复制失败，请使用导出 reports.json");
  } finally {
    bulkWorking.value = false;
  }
}
async function exportEdusrcAll() {
  if (bulkWorking.value) return;
  bulkWorking.value = true;
  try {
    toast("正在生成 reports.json...");
    const reports = await fetchAllSubmitReports();
    const text = JSON.stringify(edusrcReports(reports), null, 2);
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `riddle-${props.id.slice(0, 8)}-edusrc-reports.json`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 0);   // 释放 object URL，避免内存泄漏
    toast(`已导出 ${reports.length} 份 EduSRC JSON`);
  } finally {
    bulkWorking.value = false;
  }
}

const stats = computed(() => task.value?.stats || {});
// Tab 徽标/指标卡计数：统一以 stats 为权威来源（stats 随 loadTask 在挂载时与每次实时事件刷新），
// 无需点开对应 Tab 就能显示并实时更新。当前已加载的 Tab 若数组数更大(刚增量加载更多页)则取较大值，
// 避免分页 compact 限制导致显示偏小。
const reviewCount = computed(() =>
  Math.max(stats.value.review_pending ?? 0, loadedTabs.value.has("review") ? queue.value.length : 0));
const submitCount = computed(() => {
  if (typeof stats.value.submit_ready === "number") return stats.value.submit_ready;
  if (submittedFilter.value) return 0;
  return loadedTabs.value.has("submit")
    ? submitItems.value.filter((f) => !f.review?.submitted).length
    : 0;
});
const sweepCount = computed(() =>
  Math.max(stats.value.killsweep ?? 0, loadedTabs.value.has("killsweep") ? killsweepItems.value.length : 0));
const rejectedCount = computed(() =>
  Math.max(stats.value.rejected ?? 0, loadedTabs.value.has("rejected") ? rejectedItems.value.length : 0));
const archivedCount = computed(() =>
  Math.max(stats.value.archived ?? 0, loadedTabs.value.has("archived") ? archivedItems.value.length : 0));
const archivedWriteCount = computed(() => Number(stats.value.archived_write || 0));
// Tab 徽标统一出口：顶级横向标签 + 子分类标签渲染（计数仍以 stats 为权威 + 已加载数组取大值）。
const tabCounts = computed(() => ({
  review: reviewCount.value,
  submit: submitCount.value,
  killsweep: sweepCount.value,
  rejected: rejectedCount.value,
  archived: archivedCount.value,
  archived_write: archivedWriteCount.value,
}));
const searchActive = computed(() => searchTokens.value.length > 0);
const isEnterpriseTask = computed(() => task.value?.src_type === "enterprise");

// 处置阶段分组：左侧导航顶级项 + 内容区顶部横向子分类标签
const SUB_GROUPS = [
  {
    key: "dispose",
    label: "处置中",
    items: [
      { key: "review", label: "复审队列", icon: "clipboard" },
      { key: "submit", label: "待提交", icon: "send" },
      { key: "archived", label: "AI 未采纳", icon: "archive" },
    ],
  },
  {
    key: "done",
    label: "已处置",
    items: [
      { key: "killsweep", label: "通杀列", icon: "target" },
      { key: "rejected", label: "已驳回", icon: "xcircle" },
    ],
  },
];
const currentGroup = computed(() => SUB_GROUPS.find((g) => g.items.some((n) => n.key === tab.value)) || null);
const subTabs = computed(() => currentGroup.value?.items || []);
const SUB_ICONS = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  clipboard: '<path d="M9 4h6v3H9z"/><path d="M9 4H6a1 1 0 0 0-1 1v14a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1V5a1 1 0 0 0-1-1h-3"/><path d="m9 14 2 2 4-4"/>',
  send: '<path d="M22 2 11 13"/><path d="M22 2 15 22l-4-9-9-4Z"/>',
  target: '<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="5"/><circle cx="12" cy="12" r="1.2"/>',
  xcircle: '<circle cx="12" cy="12" r="9"/><path d="m9 9 6 6M15 9l-6 6"/>',
  archive: '<path d="M4 8h16v12H4z"/><path d="M3 4h18v4H3z"/><path d="M10 12h4"/>',
};
function subCount(key) {
  return tabCounts.value[key] || 0;
}
function groupTotal(g) {
  return g.items.reduce((s, n) => s + (tabCounts.value[n.key] || 0), 0);
}
// 顶级分组点击：切到该组上次选中的子分类（默认第一个）
const lastSubByGroup = ref({});
function selectTopGroup(g) {
  if (currentGroup.value?.key === g.key) return;
  const key = lastSubByGroup.value[g.key] || g.items[0].key;
  lastSubByGroup.value = { ...lastSubByGroup.value, [g.key]: key };
  tab.value = key;
}
const searchPlaceholder = computed(() =>
  isEnterpriseTask.value
    ? "搜索漏洞：标题 / URL / 类型 / 单位 / 系统 / 报告正文 / 审核备注"
    : "搜索漏洞：标题 / URL / 类型 / 学校 / 报告正文 / 审核备注"
);

const searchTokens = computed(() =>
  searchText.value.trim().toLowerCase().split(/\s+/).filter(Boolean)
);
const searchEnabled = computed(() => tab.value !== "board");
function stringifyForSearch(v) {
  if (v?._searchText) return v._searchText;
  return buildSearchText(v);
}
function buildSearchText(v) {
  const parts = [];
  try { parts.push(JSON.stringify(v ?? "", null, 0)); }
  catch { parts.push(String(v ?? "")); }
  return parts.join("\n").toLowerCase();
}
function withSearchCache(v) {
  return { ...v, _searchText: buildSearchText(v) };
}
function clearSearch() {
  clearTimeout(searchTimer);
  searchDraft.value = "";
  searchText.value = "";
}
function matchSearch(item) {
  const tokens = searchTokens.value;
  if (!tokens.length) return true;
  const text = stringifyForSearch(item);
  return tokens.every((t) => text.includes(t));
}
const filteredQueue = computed(() => sortRows(queue.value.filter(matchSearch)));
const filteredSubmit = computed(() => sortRows(submitItems.value.filter(matchSearch)));
const filteredKillsweeps = computed(() => sortRows(killsweepItems.value.filter(matchSearch)));
const filteredRejected = computed(() => sortRows(rejectedItems.value.filter(matchSearch)));
const filteredArchived = computed(() => sortRows(archivedItems.value.filter(matchSearch)));
// 按时间排序：desc=最新优先 asc=最早优先（created_at 数值比较，不受 tz/精度影响）
function rowEpoch(r) {
  const t = r?.created_at;
  if (!t) return 0;
  const n = Date.parse(String(t));
  return Number.isNaN(n) ? 0 : n;
}
function sortRows(rows) {
  const dir = sortOrder.value === "asc" ? 1 : -1;
  return [...rows].sort((a, b) => dir * (rowEpoch(a) - rowEpoch(b)));
}
function toggleSort() {
  sortOrder.value = sortOrder.value === "desc" ? "asc" : "desc";
}
function pickPageSize(n) {
  pageSize.value = n;
  pageMenuOpen.value = false;
  // 重置并重新加载当前列表（条数变化后重新分页）
  if (tab.value === "submit") loadSubmit({ reset: true });
  else if (tab.value === "archived") loadArchived({ reset: true });
}
const visibleCount = computed(() => {
  if (tab.value === "review") return filteredQueue.value.length;
  if (tab.value === "submit") return filteredSubmit.value.length;
  if (tab.value === "killsweep") return filteredKillsweeps.value.length;
  if (tab.value === "rejected") return filteredRejected.value.length;
  if (tab.value === "archived") return filteredArchived.value.length;
  return 0;
});
const rawCount = computed(() => {
  if (tab.value === "review") return queue.value.length;
  if (tab.value === "submit") return submitItems.value.length;
  if (tab.value === "killsweep") return killsweepItems.value.length;
  if (tab.value === "rejected") return rejectedItems.value.length;
  if (tab.value === "archived") return archivedItems.value.length;
  return 0;
});
function onDrawerUpdated() {
  refreshFromEvent({ kind: "review_updated" });
}
function onSubmittedFilterChange(v) {
  submittedFilter.value = v;
  loadTabData("submit");
}

// Worker 轨迹抽屉：实时头部跟随活态 worker 刷新（轮次/耗时/动作），结束后回落到打开时快照。
const traceWorkerLive = computed(() => {
  const w = traceWorker.value;
  if (!w) return w;
  return liveWorkers.value.find((x) => x.target_id === w.target_id) || w;
});
const traceIsLive = computed(() => {
  const w = traceWorker.value;
  return !!w && liveWorkers.value.some((x) => x.target_id === w.target_id);
});
const liveTargetIds = computed(() => new Set(liveWorkers.value.map((w) => w.target_id)));
</script>

<template>
  <section class="view board-view" :class="{ 'is-refreshing': refreshing, 'is-skeleton-loading': initialLoading && !task }">
    <div v-if="refreshing && !initialLoading" class="view-progress" aria-hidden="true"><i></i></div>

    <nav class="crumb" aria-label="面包屑">
      <span>指挥中心</span>
      <span class="crumb-sep">/</span>
      <router-link to="/">任务</router-link>
      <span class="crumb-sep">/</span>
      <b>{{ task ? task.name : "任务详情" }}</b>
    </nav>

    <template v-if="initialLoading && !task">
      <div class="board-shell skeleton-shell">
        <div class="board-deck skeleton-deck">
          <div class="skeleton-block lg"></div>
          <div class="skeleton-row">
            <span class="skeleton-chip"></span>
            <span class="skeleton-chip"></span>
            <span class="skeleton-chip wide"></span>
          </div>
          <div class="skeleton-battle">
            <div class="skeleton-ring"></div>
            <div class="skeleton-rt">
              <div v-for="n in 3" :key="'rt' + n" class="skeleton-block"></div>
            </div>
            <div class="skeleton-spark"></div>
          </div>
          <div class="skeleton-metrics">
            <div v-for="n in 5" :key="'k' + n" class="skeleton-tile"></div>
          </div>
        </div>
        <div class="board-main skeleton-main">
          <div class="board-panel skeleton-panel">
            <div class="skeleton-line sm-head"></div>
            <div v-for="n in 3" :key="n" class="skeleton-worker"></div>
          </div>
        </div>
      </div>
    </template>

    <div v-else-if="task" class="board-shell">
      <BoardDeck
        :task="task"
        :readonly="readonly"
        :auth-role="authRoleRef"
        :review-count="reviewCount"
        :submit-count="submitCount"
        :sweep-count="sweepCount"
        :timeline="timeline"
        :vuln-dist="vulnDist"
        @edit="() => openEditTask(props.id)"
        @start="ctl('start')"
        @pause="ctl('pause')"
        @stop="ctl('stop')"
      />

      <div class="board-body">
        <div class="board-main">
          <!-- 单站协作态势：三阶段流水线（侦察→主题深挖→定向追打），体现同站多路线协同 -->
          <CollabPanel v-if="siteCollab" :site-collab="siteCollab" />

          <!-- 顶级横向标签：实时看板 / 处置中 / 已处置（左侧导航横向化） -->
          <div class="v-topnav" role="tablist" aria-label="视图切换">
            <button
              type="button"
              role="tab"
              :aria-selected="tab === 'board'"
              :class="{ active: tab === 'board' }"
              @click="tab = 'board'"
            >
              <svg class="nav-ico" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" v-html="SUB_ICONS.grid"></svg>
              <span>实时看板</span>
              <i v-if="task.status === 'running'" class="live-dot" title="任务运行中"></i>
            </button>
            <button
              v-for="g in SUB_GROUPS"
              :key="g.key"
              type="button"
              role="tab"
              :aria-selected="currentGroup?.key === g.key"
              :class="{ active: currentGroup?.key === g.key }"
              @click="selectTopGroup(g)"
            >
              <svg class="nav-ico" viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" v-html="SUB_ICONS[g.items[0].icon]"></svg>
              <span>{{ g.label }}</span>
              <i v-if="groupTotal(g)" class="nav-cnt">{{ groupTotal(g) }}</i>
            </button>
          </div>

          <!-- 处置阶段子分类：横向标签，切换当前组下的子列表（位于搜索框上方） -->
          <div v-if="searchEnabled && subTabs.length" class="v-subtabs" role="tablist" aria-label="处置阶段子分类">
            <button
              v-for="st in subTabs"
              :key="st.key"
              type="button"
              role="tab"
              :aria-selected="tab === st.key"
              :class="{ active: tab === st.key }"
              @click="tab = st.key"
            >
              <svg class="nav-ico" viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" v-html="SUB_ICONS[st.icon]"></svg>
              <span>{{ st.label }}</span>
              <i v-if="subCount(st.key)" class="nav-cnt">{{ subCount(st.key) }}</i>
            </button>
          </div>

          <!-- 搜索条：内容区顶部，仅列表视图显示 -->
          <div v-if="searchEnabled" class="v-search">
            <div class="search-box">
              <span>⌕</span>
              <input v-model="searchDraft" :placeholder="searchPlaceholder" />
              <button v-if="searchDraft.trim()" class="search-box-clear" title="清空搜索" @click="clearSearch">✕</button>
            </div>
            <div class="search-stat">
              <template v-if="searchActive">命中 {{ visibleCount }} / {{ rawCount }}</template>
              <template v-else>共 {{ rawCount }} 条</template>
            </div>
            <!-- 条数：每页条数选择器 -->
            <div class="search-page" :class="{ open: pageMenuOpen }">
              <button type="button" class="search-page-btn" @click="pageMenuOpen = !pageMenuOpen">
                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h10"/></svg>
                条数 {{ pageSize }}
                <svg class="chev" viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>
              </button>
              <div class="search-page-menu" role="menu">
                <button v-for="n in [50, 100, 200, 500]" :key="n" type="button" role="menuitem" :class="{ active: pageSize === n }" @click="pickPageSize(n)">{{ n }} 条/页</button>
              </div>
            </div>
            <!-- 按时间排序 -->
            <button class="search-sort" :class="{ asc: sortOrder === 'asc' }" title="按时间排序" @click="toggleSort">
              <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M8 6h13M8 12h10M8 18h7"/><path d="m3 8 2-2 2 2M3 14l2 2 2-2M3 20l2 2 2-2"/></svg>
              按时间排序
              <span class="sort-arrow">{{ sortOrder === 'desc' ? '↓' : '↑' }}</span>
            </button>
          </div>

      <!-- 看板 -->
      <div v-show="tab === 'board'" class="board-grid">
        <div class="board-mobile-switch" role="tablist" aria-label="看板视图">
          <button type="button" role="tab" :aria-selected="boardPanel === 'workers'"
            :class="{ active: boardPanel === 'workers' }" @click="boardPanel = 'workers'">
            Worker <i>{{ liveWorkers.length }}</i>
          </button>
          <button type="button" role="tab" :aria-selected="boardPanel === 'stream'"
            :class="{ active: boardPanel === 'stream' }" @click="boardPanel = 'stream'">
            活动流
          </button>
        </div>
        <WorkerMatrix
          :live-workers="liveWorkers"
          :live-escalations="liveEscalations"
          :worker-summary="workerSummary"
          :concurrency="concurrency"
          :throttle="throttle"
          :board-ready="boardReady"
          :readonly="readonly"
          :cancelling-escalate-id="cancellingEscalateId"
          @open-trace="openWorkerTrace"
          @skip-target="skipTarget"
          @cancel-escalation="cancelEscalation"
        />
        <ActivityStream
          :events="events"
          :board-ready="boardReady"
          :live="task.status === 'running'"
          :expanded-event-keys="expandedEventKeys"
          :stream-detail-loading="streamDetailLoading"
          :live-trace-by-target="liveTraceByTarget"
          :live-target-ids="liveTargetIds"
          :log-ref="eventLogRef"
          :detail-cap="STREAM_DETAIL_CAP"
          @toggle-expand="toggleEventExpand"
          @copy-llm="copyLlmEvent"
        />
      </div>

      <!-- 复审队列 -->
      <ReviewList v-show="tab === 'review'" :items="filteredQueue" :total="queue.length" @open="openReview" />

      <!-- 待提交 -->
      <SubmitList
        v-show="tab === 'submit'"
        :items="filteredSubmit"
        :total="submitItems.length"
        :has-more="submitHasMore"
        :loading="submitLoading"
        :bulk-working="bulkWorking"
        :is-enterprise-task="isEnterpriseTask"
        :submitted-filter="submittedFilter"
        @open="openSubmit"
        @load-more="loadMoreSubmit"
        @copy-all="copyAll"
        @export-all="exportAll"
        @copy-edusrc-all="copyEdusrcAll"
        @export-edusrc-all="exportEdusrcAll"
        @filter-change="onSubmittedFilterChange"
      />

      <!-- 通杀列 -->
      <KillsweepList
        v-show="tab === 'killsweep'"
        :items="filteredKillsweeps"
        :total="killsweepItems.length"
        :readonly="readonly"
        :expanded-killsweeps="expandedKillsweeps"
        :invalidating-id="invalidatingKillsweepId"
        :retrying-id="retryingKillsweepId"
        :is-enterprise-task="isEnterpriseTask"
        :selected="selectedKillsweeps"
        :enqueueing-id="enqueueingKillsweepId"
        :batch-working="killsweepBatchWorking"
        @toggle="toggleKillsweep"
        @invalidate="invalidateKillsweep"
        @retry="retryKillsweep"
        @enqueue="enqueueKillsweep"
        @open-derived="openDerivedFinding"
        @toggle-select="toggleSelectKillsweep"
        @select-all="selectAllKillsweeps"
        @batch-invalidate="batchInvalidateKillsweeps"
        @batch-retry="batchRetryKillsweeps"
        @export="exportKillsweeps"
      />

      <!-- 已驳回 -->
      <RejectedList v-show="tab === 'rejected'" :items="filteredRejected" :total="rejectedItems.length" @open="openRejected" />

      <!-- AI 未采纳归档：ignored（疑似误杀）/ deepen 未升级，保留可回看纠错，一键救回复审 -->
      <ArchivedList
        v-show="tab === 'archived'"
        :items="filteredArchived"
        :total="archivedItems.length"
        :has-more="archivedHasMore"
        :loading="archivedLoading"
        :write-count="archivedWriteCount"
        :readonly="readonly"
        @open="openArchived"
        @restore="restoreArchived"
        @load-more="loadMoreArchived"
      />

      <ReportDrawer :finding-id="drawerId" :mode="drawerMode" :src-type="task.src_type"
        @close="drawerId = null" @updated="onDrawerUpdated" @toast="toast" />

      <!-- Worker 执行轨迹抽屉 -->
      <WorkerTraceDrawer
        v-if="traceOpen"
        :worker="traceWorkerLive"
        :events="traceEvents"
        :loading="traceLoading"
        :is-live="traceIsLive"
        :readonly="readonly"
        :sending="directiveSending"
        :directive-text="directiveText"
        @close="closeWorkerTrace"
        @send-directive="sendDirective"
        @update:directive-text="directiveText = $event"
        @copy-llm="copyLlmEvent"
      />
        </div>
      </div>

      <div v-if="toastMsg" class="toast">{{ toastMsg }}</div>
    </div>
    <div v-else class="empty">任务不存在或加载失败，请返回任务列表重试</div>
  </section>
</template>
