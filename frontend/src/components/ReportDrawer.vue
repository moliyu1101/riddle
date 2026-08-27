<script setup>
import { ref, computed, watch, nextTick, onMounted, onUnmounted } from "vue";
import { marked } from "marked";
import DOMPurify from "dompurify";
import { api, canWrite, isReadonly } from "../api.js";
import { copyText } from "../clipboard.js";
import { CONF, buildReportMd, effectiveSeverity, severityToCn } from "../report.js";
import { fmtLocalTime } from "../format.js";

const props = defineProps({ findingId: String, mode: String, srcType: String }); // mode: view | review | submit | rejected | archived
const emit = defineEmits(["close", "updated", "toast"]);

const f = ref(null);
const report = ref(null);            // { template, data } —— 模板化分节数据
const viewMode = ref("structured");  // structured | markdown
const mdCopied = ref(false);
const editing = ref(false);
const edit = ref({});
const userSeverity = ref("");
const userNotes = ref("");
const deepenOpen = ref(false);
const deepenText = ref("");
const versionsOpen = ref(false);
const versions = ref([]);
const versionsLoading = ref(false);
const restoringVersion = ref(null);
const exportOpen = ref(false);
const activeSection = ref("");
const mainScroll = ref(null);
const assistantText = ref("");
const assistantBusy = ref(false);
const assistantMessages = ref([]);
const assistantAbort = ref(null);
const raLog = ref(null);
const DEFAULT_ASSISTANT_WELCOME = "我是这份漏洞的报告助手。点下面的快捷指令，或直接问证据、等级、复现怎么写。润色结果可以一键写进编辑器。";
const ASSISTANT_PRESETS = [
  { label: "审证据", text: "判断这份报告证据链是否足够提交 SRC：缺什么、有没有像误报的地方、过审概率怎么看。" },
  { label: "润色成SRC口径", text: "按当前 SRC 类型把标题、描述、影响范围、复现步骤和 PoC 改成可直接提交的口径，并调用改稿工具。" },
  { label: "补复现步骤", text: "把复现步骤写成审核员能跟着点的逐步操作，补齐请求要点和判定成功的标志。" },
  { label: "校准等级", text: "根据实际危害校准严重/高危/中危/低危，说明为什么现在这个等级站得住或应该下调。" },
  { label: "现场再验证", text: "对 PoC 或关键接口再发一次定向请求，看漏洞是否仍在，并解读状态码和关键响应。" },
];
const SEVS = ["严重", "高危", "中危", "低危"];
const EXPORT_FORMATS = [
  { key: "md", label: "Markdown", hint: ".md" },
  { key: "docx", label: "Word 文档", hint: ".docx" },
  { key: "html", label: "HTML（可打印 PDF）", hint: ".html" },
];
const SCORE_PARTS = [
  ["impact", "危害"],
  ["exploitability", "利用难度"],
  ["scope", "影响面"],
  ["reproducibility", "可复现性"],
];
const isEnterprise = computed(() => props.srcType === "enterprise");
const modeLabel = computed(() => ({
  view: "只读查看", review: "人工复审", submit: "待提交", rejected: "已驳回", archived: "AI 未采纳",
}[props.mode] || "查看"));

async function loadFinding() {
  f.value = await api.finding(props.findingId);
  const rv = f.value.review || {};
  const e = rv.user_edits || {};
  edit.value = {
    title: e.title ?? f.value.title,
    description: e.description ?? f.value.description,
    affected_scope: e.affected_scope ?? f.value.affected_scope,
    steps: (e.steps ?? f.value.steps ?? []).join("\n"),
    poc: e.poc ?? f.value.poc,
  };
  userSeverity.value = rv.user_severity || rv.severity_final || "";
  userNotes.value = rv.user_notes || "";
  editing.value = false;
  deepenOpen.value = false;
  deepenText.value = "";
  assistantText.value = "";
  assistantBusy.value = false;
  if (assistantAbort.value) {
    assistantAbort.value.abort();
    assistantAbort.value = null;
  }
  const saved = f.value.assistant_messages;
  assistantMessages.value = (saved?.length)
    ? saved
    : [{ role: "assistant", content: DEFAULT_ASSISTANT_WELCOME }];
  try {
    report.value = await api.findingReport(props.findingId, props.srcType);
  } catch {
    report.value = null;   // 模板接口失败不阻断正文（退化为本地渲染）
  }
  activeSection.value = "";
  await nextTick();
  scrollToSection(sections.value?.[0]?.key || "overview", false);
}

watch(() => props.findingId, async (id) => {
  if (!id) { f.value = null; report.value = null; return; }
  try {
    await loadFinding();
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
    emit("close");
  }
}, { immediate: true });

function renderSafeMd(text) {
  return DOMPurify.sanitize(marked.parse(text || ""));
}

function fmtFindingTime(value) {
  return fmtLocalTime(value) || "-";
}

const html = computed(() => f.value ? renderSafeMd(buildReportMd(f.value)) : "");
const effSev = computed(() => {
  if (!f.value) return "-";
  return severityToCn(effectiveSeverity(f.value));
});
const review = computed(() => f.value?.review || {});
const confidenceText = computed(() => CONF[review.value.confidence] || review.value.confidence || "-");
const readonly = computed(() => !canWrite());
const readonlyOnly = computed(() => isReadonly());

// 模板章节（后端 /report 返回），失败时按 edusrc 结构兜底
const sections = computed(() => {
  const t = report.value?.template;
  if (t?.sections?.length) return t.sections;
  return [
    { key: "overview", label: "概览", type: "overview" },
    { key: "description", label: "漏洞描述", type: "text" },
    { key: "scope", label: "影响范围", type: "text" },
    { key: "steps", label: "复现步骤", type: "steps" },
    { key: "poc", label: "验证 PoC", type: "code" },
    { key: "evidence", label: "证据链", type: "evidence" },
    { key: "chain", label: "攻击链路", type: "chain" },
    { key: "review", label: "审核结论", type: "quote" },
  ];
});
const templateLabel = computed(() => report.value?.template?.label || (isEnterprise.value ? "企业SRC" : "教育行业"));

// 结构化视图：用户编辑覆盖 > 原始值
function effVal(key) {
  const e = f.value?.review?.user_edits || {};
  return e[key] !== undefined && e[key] !== null && e[key] !== "" ? e[key] : f.value?.[key];
}
const descText = computed(() => String(effVal("description") || "").trim());
const scopeText = computed(() => String(effVal("affected_scope") || "").trim());
const stepList = computed(() => (effVal("steps") || []).filter(Boolean));
const pocText = computed(() => String(effVal("poc") || "").trim());

// 验证 PoC 请求包：优先用原始请求包 raw_request；否则把 curl 转成标准 HTTP 请求包。
// 便于直接粘进 yakit / Burp 等抓包复测工具。
function looksLikeHttpRequest(s) {
  return /^(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/\d/i.test(s);
}
function curlToRequest(curl) {
  if (!curl) return "";
  const tokens = (curl.match(/"[^"]*"|'[^']*'|\S+/g) || []).map((t) => t.replace(/^["']|["']$/g, ""));
  let method = "GET";
  const headers = [{ name: "User-Agent", value: "Mozilla/5.0" }];
  let url = "";
  let data = "";
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (t === "curl") continue;
    if (t === "-X") { method = (tokens[++i] || "GET").toUpperCase(); continue; }
    if (t === "-d" || t === "--data" || t === "--data-raw" || t === "--data-binary") { data = tokens[++i] || ""; if (method === "GET" && data) method = "POST"; continue; }
    if (t === "-H" || t === "--header") { const h = tokens[++i] || ""; const ci = h.indexOf(":"); if (ci > 0) headers.push({ name: h.slice(0, ci).trim(), value: h.slice(ci + 1).trim() }); continue; }
    if (t === "-A" || t === "--user-agent") { headers.push({ name: "User-Agent", value: tokens[++i] || "" }); continue; }
    if (t === "-b" || t === "--cookie") { headers.push({ name: "Cookie", value: tokens[++i] || "" }); continue; }
    if (!t.startsWith("-") && url === "" && !/^https?:$/.test(t)) { url = t; }
  }
  // 去掉重复的 User-Agent
  const seen = new Set(); const unique = headers.filter((h) => { if (seen.has(h.name.toLowerCase())) return false; seen.add(h.name.toLowerCase()); return true; });
  return { method: method || "GET", url, headers: unique, data };
}
const pocRequest = computed(() => {
  const rawReq = String(effVal("raw_request") || "").trim();
  if (rawReq && looksLikeHttpRequest(rawReq)) {
    // 已规范：补全缺失的 Host（若无），保证可直接发
    const lines = rawReq.split("\n");
    if (!lines.some((l) => /^Host:/i.test(l))) {
      const host = String(f.value?.target_url || "").match(/^https?:\/\/([^\/\s]+)/)?.[1];
      if (host) lines.splice(1, 0, `Host: ${host}`);
    }
    return lines.join("\n");
  }
  // 尝试从 curl 转
  const p = curlToRequest(pocText.value);
  if (p?.url) {
    const u = new URL(p.url);
    const head = `${p.method} ${u.pathname || "/"}${u.search} HTTP/1.1`;
    return [head, `Host: ${u.host}`, ...p.headers.filter((h) => h.name.toLowerCase() !== "host").map((h) => `${h.name}: ${h.value}`), "", p.data].join("\n");
  }
  return pocText.value;
});
const chainSteps = computed(() => (f.value?.kill_chain || []).filter((s) => s && s.method));
const reviewerNotes = computed(() => review.value.reviewer_notes || "");
const savedUserNotes = computed(() => review.value.user_notes || "");
const evidence = computed(() => f.value?.evidence || {});
const hasEvidence = computed(() => !!(
  f.value?.raw_request || f.value?.raw_response
  || evidence.value.extracted_data_sample || evidence.value.tool_output || evidence.value.notes
  || evidence.value.snapshot));
const scorePct = computed(() => {
  const s = Number(review.value.score);
  return Number.isFinite(s) ? Math.max(0, Math.min(100, s * 10)) : 0;
});
const scoreNum = computed(() => {
  const s = Number(review.value.score);
  return Number.isFinite(s) ? s.toFixed(1) : "-";
});
const scoreParts = computed(() => {
  // 优先用 report 接口自带的评分分解（与正文数据同源），api.finding 兜底
  const sb = report.value?.data?.overview?.score_breakdown || f.value?.score_breakdown;
  if (!sb) return [];
  return SCORE_PARTS.map(([key, label]) => ({ key, label, value: Number(sb[key]) || 0 }));
});
const scoreTotal = computed(() => {
  const sb = report.value?.data?.overview?.score_breakdown || f.value?.score_breakdown;
  return sb?.total != null ? Number(sb.total).toFixed(1) : "-";
});
const navBadge = (key) => {
  if (key === "steps") return stepList.value.length || "";
  if (key === "chain") return chainSteps.value.length || "";
  return "";
};

// 章节滚动定位 + 滚动监听（scroll-spy）
// 程序化滚动期间抑制 scroll-spy：点击导航后高亮必须停留在目标章节，
// 否则短章节会被 140px 探测偏移越界、被滚动事件立即覆盖成下一节。
let spySuppressed = false;
let spySuppressTimer = null;
function scrollToSection(key, smooth = true) {
  const el = document.getElementById(`rc-sec-${key}`);
  if (!el || !mainScroll.value) return;
  spySuppressed = true;
  if (spySuppressTimer) clearTimeout(spySuppressTimer);
  spySuppressTimer = setTimeout(() => { spySuppressed = false; }, 500);
  mainScroll.value.scrollTo({ top: el.offsetTop - mainScroll.value.offsetTop - 12, behavior: smooth ? "smooth" : "auto" });
  activeSection.value = key;
}
function onMainScroll() {
  if (spySuppressed) return;
  const sc = mainScroll.value;
  if (!sc) return;
  const items = sections.value.map((s) => document.getElementById(`rc-sec-${s.key}`)).filter(Boolean);
  const probe = sc.scrollTop + 140;
  let current = sections.value[0]?.key || "";
  for (const el of items) {
    if (el.offsetTop - sc.offsetTop <= probe) current = el.id.replace("rc-sec-", "");
  }
  if (current !== activeSection.value) activeSection.value = current;
}

function renderAssistantMd(text) {
  return renderSafeMd(text);
}

function snapStatusClass(status) {
  const s = Number(status);
  if (s >= 200 && s < 300) return "ok";
  if (s >= 400) return "bad";
  return "warn";
}

async function saveEdits() {
  try {
    const user_edits = {
      title: edit.value.title, description: edit.value.description,
      affected_scope: edit.value.affected_scope,
      steps: edit.value.steps.split("\n").map((s) => s.trim()).filter(Boolean),
      poc: edit.value.poc,
    };
    await api.userReview(f.value.id, { user_edits, user_severity: userSeverity.value, user_notes: userNotes.value });
    await loadFinding();
    editing.value = false;
    emit("toast", "已保存修改");
    emit("updated");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function decide(status) {
  try {
    const res = await api.userReview(f.value.id, {
      user_status: status, user_severity: userSeverity.value, user_notes: userNotes.value,
    });
    emit("toast", status === "passed"
      ? `已通过 → 进入待提交${res.killsweep_triggered ? "，通杀 Hunter 已启动" : ""}${res.killsweep_skipped_reason ? "，已断开通杀递归" : ""}`
      : "已驳回");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function submitDeepen() {
  const d = deepenText.value.trim();
  if (!d) { emit("toast", "请先写一句深挖指令"); return; }
  try {
    const r = await api.deepen(f.value.id, d);
    emit("toast", r.message || "已打回深挖，目标重新入队");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function markSubmitted() {
  try {
    await api.userReview(f.value.id, { submitted: true });
    emit("toast", "已标记为已提交");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function restore() {
  try {
    await api.userReview(f.value.id, { user_status: "pending" });
    emit("toast", "已恢复到复审队列");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function restoreArchived() {
  // AI 未采纳（ignored/deepen）：verdict 本非 accepted，只改 user_status 无效，
  // 必须走专用接口把 verdict 改回 accepted 才能真正进复审队列。
  try {
    await api.restoreArchived(f.value.id);
    emit("toast", "已恢复到复审队列");
    emit("updated");
    emit("close");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

function copyMd() {
  copyText(buildReportMd(f.value)).then(() => {
    mdCopied.value = true;
    emit("toast", "报告已复制（Markdown）");
    setTimeout(() => { mdCopied.value = false; }, 2000);
  }).catch(() => emit("toast", "复制失败，请使用导出按钮"));
}

async function exportReport(format) {
  exportOpen.value = false;
  try {
    await api.exportReport(f.value.id, format, props.srcType);
    emit("toast", `已导出 ${EXPORT_FORMATS.find((x) => x.key === format)?.label || format}`);
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  }
}

async function openVersions() {
  versionsOpen.value = true;
  versionsLoading.value = true;
  try {
    versions.value = await api.reportVersions(f.value.id);
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    versionsLoading.value = false;
  }
}
async function restoreVersion(v) {
  if (restoringVersion.value) return;
  const ok = window.confirm(`确认回滚到 v${v.version}？\n当前编辑内容会被该版本覆盖，并自动留一份新版本快照。`);
  if (!ok) return;
  restoringVersion.value = v.version;
  try {
    await api.restoreVersion(f.value.id, v.version, `人工回滚到 v${v.version}`);
    emit("toast", `已回滚到 v${v.version}`);
    versionsOpen.value = false;
    await loadFinding();
    emit("updated");
  } catch (e) {
    emit("toast", String(e.message || e).replace(/^\d+\s*/, ""));
  } finally {
    restoringVersion.value = null;
  }
}

const TOOL_LABEL = { http_request: "HTTP 请求", run_shell: "执行命令", propose_report_edits: "提出改稿" };

function stepLabel(ev) {
  if (ev.type === "thinking") return ev.text || "分析中…";
  if (ev.type === "tool_call") return `${TOOL_LABEL[ev.tool] || ev.tool}：${ev.summary || ""}`;
  if (ev.type === "tool_result") return `↳ ${ev.summary || "完成"}`;
  return ev.text || "";
}

function editFields(edits) {
  if (!edits) return [];
  return ["title", "description", "affected_scope", "steps", "poc", "severity"].filter((k) => edits[k]);
}

async function scrollAssistant() {
  await nextTick();
  const el = raLog.value;
  if (el) el.scrollTop = el.scrollHeight;
}

function stopAssistant() {
  if (assistantAbort.value) assistantAbort.value.abort();
}

function copyAssistant(m) {
  const text = (m.content || m.partial || "").trim();
  if (!text) { emit("toast", "还没有可复制的内容"); return; }
  copyText(text).then(() => emit("toast", "已复制助手回复")).catch(() => emit("toast", "复制失败"));
}

function applySuggestedEdits(edits) {
  if (!edits || !f.value) return;
  if (edits.title) edit.value.title = edits.title;
  if (edits.description) edit.value.description = edits.description;
  if (edits.affected_scope) edit.value.affected_scope = edits.affected_scope;
  if (Array.isArray(edits.steps)) edit.value.steps = edits.steps.join("\n");
  if (edits.poc) edit.value.poc = edits.poc;
  if (edits.severity) userSeverity.value = edits.severity;
  editing.value = true;
  emit("toast", "已填入编辑器，确认后点保存修改");
}

/** 聊天输入框 Enter 发送：跳过 IME 组合期（拼音输入法确认候选词时不触发发送）。 */
function onChatEnter(e, fn) {
  if (e.isComposing || e.keyCode === 229) return;
  e.preventDefault();
  fn();
}

async function askAssistant(preset = "") {
  const text = (preset || assistantText.value).trim();
  if (!text || assistantBusy.value || !f.value) return;
  assistantText.value = "";
  assistantMessages.value.push({ role: "user", content: text });
  assistantBusy.value = true;
  scrollAssistant();

  const liveMsg = { role: "assistant", content: "", steps: [], streaming: true };
  assistantMessages.value.push(liveMsg);
  const idx = assistantMessages.value.length - 1;
  const controller = new AbortController();
  assistantAbort.value = controller;

  const update = (patch) => {
    assistantMessages.value[idx] = { ...assistantMessages.value[idx], ...patch };
  };
  const pushStep = (ev) => {
    const cur = assistantMessages.value[idx];
    const steps = [...(cur.steps || [])];
    if (ev.type === "tool_result" && steps.length && steps[steps.length - 1].type === "tool_call") {
      steps[steps.length - 1] = { ...steps[steps.length - 1], result: stepLabel(ev) };
    } else {
      steps.push({ type: ev.type, label: stepLabel(ev), tool: ev.tool });
    }
    update({ steps });
    scrollAssistant();
  };

  try {
    await api.reportAssistantStream(f.value.id, text, (ev) => {
      switch (ev.type) {
        case "thinking":
        case "tool_call":
        case "tool_result":
          pushStep(ev);
          break;
        case "assistant_partial":
          update({ partial: ev.text });
          scrollAssistant();
          break;
        case "suggested_edits":
          update({ suggestedEdits: ev.edits || null });
          break;
        case "final":
          update({
            content: ev.text || "",
            partial: "",
            suggestedEdits: ev.suggested_edits || assistantMessages.value[idx].suggestedEdits || null,
          });
          scrollAssistant();
          break;
        case "done":
          update({
            content: ev.answer || assistantMessages.value[idx].content || "已完成。",
            streaming: false,
            partial: "",
            suggestedEdits: ev.suggested_edits || assistantMessages.value[idx].suggestedEdits || null,
          });
          break;
        default:
          break;
      }
    }, controller.signal);
    if (assistantMessages.value[idx].streaming) {
      update({ streaming: false });
    }
  } catch (e) {
    if (e?.name === "AbortError") {
      update({
        content: assistantMessages.value[idx].content || assistantMessages.value[idx].partial || "已停止。",
        streaming: false,
        partial: "",
      });
    } else {
      update({ content: `报告助手异常：${String(e.message || e)}`, streaming: false });
    }
  } finally {
    assistantBusy.value = false;
    assistantAbort.value = null;
    scrollAssistant();
  }
}

function onKeydown(e) {
  if (e.key === "Escape" && !versionsOpen.value && !exportOpen.value) emit("close");
}
onMounted(() => window.addEventListener("keydown", onKeydown));
onUnmounted(() => window.removeEventListener("keydown", onKeydown));
</script>

<template>
  <Teleport to="body">
    <Transition name="rc">
    <div v-if="findingId" class="rc-console" role="dialog" aria-modal="true">
      <div class="rc-mask" @click="emit('close')"></div>

      <div v-if="f" class="rc-shell">
        <!-- ============ 顶部档案条 ============ -->
        <header class="rc-topbar">
          <div class="rc-top-main">
            <div class="rc-eyebrow">
              <span class="rc-eyebrow-dot"></span>
              VULNERABILITY DOSSIER
              <span class="rc-mode-tag">{{ isEnterprise ? "企业SRC" : "教育SRC" }}</span>
              <span class="rc-template-tag">{{ templateLabel }}模板</span>
            </div>
            <h1 v-if="!editing" class="rc-title">{{ effVal("title") || f.title }}</h1>
            <input v-else v-model="edit.title" class="rc-title-input" placeholder="报告标题" />
            <div class="rc-target">{{ f.target_url }}</div>
          </div>

          <div class="rc-top-right">
            <div class="rc-score" :class="effSev" :style="{ '--pct': scorePct + '%' }">
              <span class="rc-score-arc" aria-hidden="true"></span>
              <b>{{ scoreNum }}</b>
              <small>review score</small>
            </div>
            <div class="rc-pills">
              <span class="sev-pill" :class="effSev">{{ effSev }}</span>
              <span class="conf-pill" :class="review.confidence">{{ confidenceText }}</span>
            </div>
            <div class="rc-actions">
              <div v-if="!editing" class="view-switch" role="tablist" aria-label="报告视图">
                <button type="button" role="tab" :aria-selected="viewMode === 'structured'"
                  :class="{ active: viewMode === 'structured' }" @click="viewMode = 'structured'">结构化</button>
                <button type="button" role="tab" :aria-selected="viewMode === 'markdown'"
                  :class="{ active: viewMode === 'markdown' }" @click="viewMode = 'markdown'">Markdown</button>
              </div>
              <button v-if="mode === 'review' && !readonly" class="rc-btn" @click="editing = !editing">
                {{ editing ? "预览" : "编辑内容" }}
              </button>
              <div class="rc-export">
                <button class="rc-btn" @click="exportOpen = !exportOpen">导出 ▾</button>
                <div v-if="exportOpen" class="rc-export-menu">
                  <button v-for="x in EXPORT_FORMATS" :key="x.key" type="button" @click="exportReport(x.key)">
                    <span>{{ x.label }}</span><small>{{ x.hint }}</small>
                  </button>
                  <button type="button" @click="copyMd"><span>复制 Markdown</span><small>剪贴板</small></button>
                </div>
              </div>
              <button class="rc-btn" @click="openVersions">版本</button>
              <button class="rc-close" @click="emit('close')" aria-label="关闭" title="关闭">×</button>
            </div>
          </div>

          <div class="rc-facts">
            <div><span>漏洞类型</span><b class="mono">{{ f.vuln_type }}</b></div>
            <div><span>归属单位</span><b>{{ f.edu_school || f.owner || "待确认" }}</b></div>
            <div><span>发现时间</span><b>{{ fmtFindingTime(f.created_at) }}</b></div>
            <div v-if="f.llm_model"><span>产出模型</span><b :title="f.llm_base_url || ''">{{ f.llm_model }}</b></div>
            <div><span>信度</span><b>{{ confidenceText }}</b></div>
            <div><span>复现步骤</span><b>{{ stepList.length }}</b></div>
            <div><span>攻击链路</span><b>{{ chainSteps.length }}</b></div>
          </div>
        </header>

        <!-- ============ 三区作战台 ============ -->
        <div class="rc-body">
          <!-- 左侧章节导航 -->
          <nav class="rc-nav" aria-label="报告章节">
            <div class="rc-nav-head">
              <span>报告章节</span>
              <small>{{ sections.length }} 节</small>
            </div>
            <div class="rc-nav-list">
              <button
                v-for="s in sections"
                :key="s.key"
                type="button"
                class="rc-nav-item"
                :class="{ active: activeSection === s.key }"
                @click="scrollToSection(s.key)"
              >
                <span class="rc-nav-ico">{{ s.type === "overview" ? "◈" : s.type === "steps" ? "▤" : s.type === "code" ? "⌘" : s.type === "evidence" ? "▣" : s.type === "chain" ? "⇶" : s.type === "quote" ? "❝" : "¶" }}</span>
                <span class="rc-nav-label">{{ s.label }}</span>
                <i v-if="navBadge(s.key)" class="rc-nav-badge">{{ navBadge(s.key) }}</i>
              </button>
            </div>
            <div v-if="scoreParts.length" class="rc-nav-score">
              <div class="rc-nav-score-head">
                <span>风险评分分解</span>
                <b>{{ scoreTotal }}</b>
              </div>
              <div v-for="p in scoreParts" :key="p.key" class="rc-score-row">
                <span>{{ p.label }}</span>
                <div class="rc-score-track"><i :style="{ width: (p.value * 10) + '%' }"></i></div>
                <b>{{ p.value.toFixed(1) }}</b>
              </div>
            </div>
          </nav>

          <!-- 中间报告正文 -->
          <div ref="mainScroll" class="rc-main" @scroll.passive="onMainScroll">
            <!-- 编辑模式 -->
            <div v-if="editing" class="edit-form">
              <div class="edit-head">编辑漏洞报告</div>
              <label>标题 <input v-model="edit.title" /></label>
              <label>等级
                <select v-model="userSeverity">
                  <option v-for="s in SEVS" :key="s" :value="s">{{ s }}</option>
                </select>
              </label>
              <label>描述 <textarea v-model="edit.description" rows="3" /></label>
              <label>影响范围 <textarea v-model="edit.affected_scope" rows="2" /></label>
              <label>复现步骤（每行一步） <textarea v-model="edit.steps" rows="4" /></label>
              <label>PoC <textarea v-model="edit.poc" rows="3" /></label>
              <label>复审备注 <textarea v-model="userNotes" rows="2" placeholder="人工复审意见…" /></label>
              <div class="edit-actions">
                <button class="ghost" @click="editing = false">取消</button>
                <button class="primary" @click="saveEdits">保存修改</button>
              </div>
            </div>

            <!-- 结构化视图：按模板分节渲染 -->
            <template v-else-if="viewMode === 'structured'">
              <section
                v-for="s in sections"
                :id="`rc-sec-${s.key}`"
                :key="s.key"
                class="rc-sec"
                :class="`rc-sec-${s.type}`"
              >
                <!-- 概览：档案头 + 事实网格 + 评分分解 -->
                <template v-if="s.type === 'overview'">
                  <div class="rc-sec-head">
                    <span>概览</span>
                    <small>漏洞档案 · {{ templateLabel }}模板</small>
                  </div>
                  <div class="report-facts">
                    <div><span>漏洞类型</span><b class="mono">{{ f.vuln_type }}</b></div>
                    <div><span>归属单位</span><b>{{ f.edu_school || f.owner || "待确认" }}</b></div>
                    <div><span>发现时间</span><b>{{ fmtFindingTime(f.created_at) }}</b></div>
                    <div v-if="f.llm_model"><span>产出模型</span><b :title="f.llm_base_url || ''">{{ f.llm_model }}</b></div>
                    <div><span>信度</span><b>{{ confidenceText }}</b></div>
                    <div><span>复现步骤</span><b>{{ stepList.length }}</b></div>
                    <div><span>攻击链路</span><b>{{ chainSteps.length }}</b></div>
                  </div>
                  <div v-if="scoreParts.length" class="rc-breakdown">
                    <div class="rc-breakdown-head">
                      <span>风险评分分解</span>
                      <b>{{ scoreTotal }} / 10</b>
                    </div>
                    <div class="rc-breakdown-grid">
                      <div v-for="p in scoreParts" :key="p.key" class="rc-bd-item">
                        <div class="rc-bd-top"><span>{{ p.label }}</span><b>{{ p.value.toFixed(1) }}</b></div>
                        <div class="rc-score-track"><i :style="{ width: (p.value * 10) + '%' }"></i></div>
                      </div>
                    </div>
                  </div>
                </template>

                <!-- 文本章节 -->
                <template v-else-if="s.type === 'text'">
                  <div class="rc-sec-head"><span>{{ s.label }}</span></div>
                  <div class="sec-body text">{{ effVal(s.key === "scope" ? "affected_scope" : s.key) || "-" }}</div>
                </template>

                <!-- 复现步骤 -->
                <template v-else-if="s.type === 'steps'">
                  <div class="rc-sec-head"><span>{{ s.label }}</span><small>{{ stepList.length }} 步</small></div>
                  <ol v-if="stepList.length" class="step-list">
                    <li v-for="(st, i) in stepList" :key="i">
                      <span class="step-idx">{{ i + 1 }}</span>
                      <span class="step-txt">{{ st }}</span>
                    </li>
                  </ol>
                  <div v-else class="sec-body text">-</div>
                </template>

                <!-- PoC 代码 -->
                <template v-else-if="s.type === 'code'">
                  <div class="rc-sec-head">
                    <span>{{ s.label }}</span>
                    <button class="mini-copy" type="button" @click="copyText(pocRequest)">复制请求包</button>
                  </div>
                  <div class="rc-code-meta">
                    <span class="rc-code-tag" :class="{ http: !!pocRequest }">{{ looksLikeHttpRequest(pocRequest) ? "HTTP 请求包 · 可直接导入 yakit / Burp" : "PoC" }}</span>
                    <span v-if="pocRequest && pocRequest !== pocText" class="rc-code-src">由原始请求 / curl 生成 · {{ pocText ? "原始 PoC 另见下方" : "" }}</span>
                  </div>
                  <pre class="code-block poc"><code>{{ pocRequest || "-" }}</code></pre>
                  <details v-if="pocRequest && pocRequest !== pocText" class="rc-poc-other">
                    <summary>查看原始 PoC / 说明</summary>
                    <pre class="code-block"><code>{{ pocText || "-" }}</code></pre>
                  </details>
                </template>

                <!-- 证据链 -->
                <template v-else-if="s.type === 'evidence'">
                  <div class="rc-sec-head"><span>{{ s.label }}</span><small>点击展开请求 / 响应 / 样本</small></div>
                  <div v-if="hasEvidence" class="evid">
                    <details v-if="f.raw_request">
                      <summary>原始请求</summary>
                      <pre class="code-block"><code>{{ f.raw_request }}</code></pre>
                    </details>
                    <details v-if="f.raw_response">
                      <summary>原始响应</summary>
                      <pre class="code-block"><code>{{ f.raw_response }}</code></pre>
                    </details>
                    <details v-if="evidence.extracted_data_sample">
                      <summary>数据样本</summary>
                      <pre class="code-block"><code>{{ evidence.extracted_data_sample }}</code></pre>
                    </details>
                    <details v-if="evidence.tool_output">
                      <summary>工具输出</summary>
                      <pre class="code-block"><code>{{ evidence.tool_output }}</code></pre>
                    </details>
                    <details v-if="evidence.notes">
                      <summary>说明</summary>
                      <div class="sec-body text">{{ evidence.notes }}</div>
                    </details>
                    <details v-if="evidence.snapshot" class="evid-snapshot">
                      <summary>存证快照</summary>
                      <div class="snap-meta">
                        <span class="snap-url">{{ evidence.snapshot.url }}</span>
                        <span class="snap-status" :class="snapStatusClass(evidence.snapshot.status)">HTTP {{ evidence.snapshot.status }}</span>
                        <span class="snap-len">{{ evidence.snapshot.body_len }}B · {{ evidence.snapshot.elapsed }}s</span>
                      </div>
                      <div v-if="evidence.snapshot.title" class="snap-title">标题：{{ evidence.snapshot.title }}</div>
                      <div v-if="evidence.snapshot.visible_text" class="snap-text">{{ evidence.snapshot.visible_text }}</div>
                      <pre v-if="evidence.snapshot.body_snippet" class="code-block"><code>{{ evidence.snapshot.body_snippet }}</code></pre>
                    </details>
                  </div>
                  <div v-else class="sec-body text">-</div>
                </template>

                <!-- 攻击链路 -->
                <template v-else-if="s.type === 'chain'">
                  <div class="rc-sec-head"><span>{{ s.label }}</span><small>{{ chainSteps.length }} 步 · 侦察→定位→利用→取证</small></div>
                  <div v-if="chainSteps.length" class="chain-flow">
                    <template v-for="(st, i) in chainSteps" :key="i">
                      <div class="chain-node">
                        <div class="chain-idx">{{ i + 1 }}</div>
                        <div class="chain-body">
                          <b>{{ st.method }}</b>
                          <p v-if="st.detail">{{ st.detail }}</p>
                        </div>
                      </div>
                      <i v-if="i < chainSteps.length - 1" class="chain-arrow">→</i>
                    </template>
                  </div>
                  <div v-else class="sec-body text">-</div>
                </template>

                <!-- 审核结论 / 备注引用 -->
                <template v-else-if="s.type === 'quote'">
                  <div class="rc-sec-head"><span>{{ s.label }}</span></div>
                  <blockquote v-if="s.key === 'review' && reviewerNotes" class="reviewer-quote">{{ reviewerNotes }}</blockquote>
                  <div v-else-if="s.key === 'review'" class="sec-body text">-</div>
                  <blockquote v-if="s.key === 'user_notes' && savedUserNotes" class="reviewer-quote user">{{ savedUserNotes }}</blockquote>
                </template>
              </section>
            </template>

            <!-- 完整 Markdown 视图 -->
            <template v-else>
              <div class="rc-md-toolbar">
                <span class="rc-md-hint">Markdown 源码</span>
                <button type="button" class="rc-md-copy" :class="{ copied: mdCopied }" @click="copyMd">
                  <span class="rc-md-copy-ico" aria-hidden="true">{{ mdCopied ? "✓" : "⧉" }}</span>
                  {{ mdCopied ? "已复制" : "复制 Markdown" }}
                </button>
              </div>
              <article class="markdown-body" v-html="html"></article>
            </template>
          </div>

          <!-- 右侧 AI 助手 + 操作面板 -->
          <aside class="rc-side">
            <!-- 操作面板（按 mode 渲染） -->
            <div v-if="!readonly" class="rc-ops">
              <div class="rc-ops-head"><span>作战操作</span><small>{{ modeLabel }}</small></div>

              <div v-if="mode === 'review'" class="rc-ops-body">
                <label class="rc-ops-sev">复审等级
                  <select v-model="userSeverity">
                    <option v-for="s in SEVS" :key="s" :value="s">{{ s }}</option>
                  </select>
                </label>
                <div class="rc-ops-btns">
                  <button class="deep" @click="deepenOpen = !deepenOpen">+ 继续深挖</button>
                  <button class="ok" @click="decide('passed')">✓ 通过（进待提交）</button>
                  <button class="no" @click="decide('rejected')">✕ 不通过</button>
                </div>
              </div>

              <div v-else-if="mode === 'submit' && !f.review?.submitted" class="rc-ops-body">
                <div class="rc-ops-btns">
                  <button class="ok" @click="markSubmitted">标记为已提交</button>
                </div>
              </div>

              <div v-else-if="mode === 'rejected'" class="rc-ops-body">
                <div class="rc-ops-btns">
                  <button class="deep" @click="deepenOpen = !deepenOpen">+ 继续深挖</button>
                  <button class="ok" @click="restore">↩ 恢复到复审队列</button>
                </div>
              </div>

              <div v-else-if="mode === 'archived'" class="rc-ops-body">
                <div class="rc-ops-btns">
                  <button class="deep" @click="deepenOpen = !deepenOpen">+ 继续深挖</button>
                  <button class="ok" @click="restoreArchived">↩ 恢复到复审队列</button>
                </div>
              </div>

              <div v-if="deepenOpen" class="deepen-box">
                <label>深挖指令（告诉 worker 这一轮去把什么打穿，越具体越好）</label>
                <textarea v-model="deepenText" rows="2"
                  placeholder="例：用 config.js 里的 SECRET 对 /ashx 接口做 sha1 签名，越权调用取出他人数据并贴出响应"></textarea>
                <div class="deepen-actions">
                  <button class="ghost" @click="deepenOpen = false">取消</button>
                  <button class="go" @click="submitDeepen">↻ 打回深挖并重新入队</button>
                </div>
              </div>
            </div>

            <!-- 报告助手 -->
            <section class="report-assistant">
              <div class="ra-head">
                <div>
                  <span>报告助手</span>
                  <small>{{ readonlyOnly ? "只读模式不可发送" : readonly ? "未认证，请先换令牌" : "问证据、等级、复现；可改稿进编辑器，也可做少量定向验证" }}</small>
                </div>
                <div v-if="!readonly" class="ra-actions">
                  <button v-if="assistantBusy" class="ra-stop" @click="stopAssistant">停止</button>
                </div>
              </div>
              <div v-if="!readonly" class="ra-chips">
                <button
                  v-for="p in ASSISTANT_PRESETS"
                  :key="p.label"
                  type="button"
                  :disabled="assistantBusy"
                  @click="askAssistant(p.text)"
                >{{ p.label }}</button>
              </div>
              <div ref="raLog" class="ra-log">
                <div v-for="(m, i) in assistantMessages" :key="i" class="ra-msg" :class="m.role">
                  <span>{{ m.role === "user" ? "你" : "助手" }}</span>
                  <div class="ra-body">
                    <ul v-if="m.steps && m.steps.length" class="ra-steps">
                      <li v-for="(s, si) in m.steps" :key="si" class="ra-step" :class="s.type">
                        <span class="ra-step-ico">{{ s.type === "tool_call" ? "⚙" : s.type === "thinking" ? "…" : "•" }}</span>
                        <span class="ra-step-txt">
                          {{ s.label }}
                          <em v-if="s.result" class="ra-step-res">{{ s.result }}</em>
                        </span>
                      </li>
                    </ul>
                    <div v-if="m.streaming && m.partial && !m.content" class="ra-md ra-partial" v-html="renderAssistantMd(m.partial)"></div>
                    <div v-if="m.content" class="ra-md" v-html="renderAssistantMd(m.content)"></div>
                    <div v-if="m.streaming && !m.content && !m.partial && !(m.steps && m.steps.length)" class="ra-md ra-pending"><p>正在分析…</p></div>
                    <span v-if="m.streaming" class="ra-cursor">▍</span>
                    <div v-if="m.suggestedEdits && editFields(m.suggestedEdits).length" class="ra-suggest">
                      <div>
                        <b>可应用改稿</b>
                        <small>{{ editFields(m.suggestedEdits).join("、") }}{{ m.suggestedEdits.rationale ? ` · ${m.suggestedEdits.rationale}` : "" }}</small>
                      </div>
                      <button class="primary" :disabled="readonly" @click="applySuggestedEdits(m.suggestedEdits)">写入编辑器</button>
                    </div>
                    <div v-if="m.role === 'assistant' && (m.content || m.partial) && !m.streaming" class="ra-msg-actions">
                      <button type="button" @click="copyAssistant(m)">复制</button>
                    </div>
                  </div>
                </div>
              </div>
              <div v-if="!readonly" class="ra-input">
                <textarea v-model="assistantText" rows="2"
                  placeholder="例：这个洞为什么不是普通信息泄露？再 curl 一下 PoC 看状态码。"
                  :disabled="assistantBusy"
                  @keydown.enter.exact="onChatEnter($event, askAssistant)"
                  @keydown.esc="stopAssistant"></textarea>
                <button v-if="assistantBusy" class="ra-stop" @click="stopAssistant">停止</button>
                <button v-else class="primary" @click="askAssistant()" :disabled="!assistantText.trim()">发送</button>
              </div>
              <p v-if="!readonly" class="ra-hint">Enter 发送 · Shift+Enter 换行 · Esc 停止</p>
            </section>
          </aside>
        </div>
      </div>

      <!-- 版本历史弹层 -->
      <div v-if="versionsOpen" class="rc-versions" @click.self="versionsOpen = false">
        <div class="rc-versions-panel">
          <div class="rc-versions-head">
            <div>
              <span>报告版本历史</span>
              <small>每次人工编辑 / 助手改稿 / 回滚都会留一份快照</small>
            </div>
            <button class="rc-close" @click="versionsOpen = false">×</button>
          </div>
          <div v-if="versionsLoading" class="empty sm">加载版本…</div>
          <div v-else-if="!versions.length" class="empty sm">暂无版本记录（编辑保存后自动生成）</div>
          <div v-else class="rc-versions-list">
            <div v-for="v in versions" :key="v.version" class="rc-version">
              <div class="rc-version-top">
                <span class="rc-version-no">v{{ v.version }}</span>
                <span class="rc-version-src">{{ v.source === "user_edit" ? "人工编辑" : v.source === "assistant" ? "助手改稿" : v.source === "system" ? "系统回滚" : v.source }}</span>
                <span class="rc-version-time">{{ fmtFindingTime(v.created_at) }}</span>
                <button class="mini-copy" :disabled="restoringVersion !== null" @click="restoreVersion(v)">回滚</button>
              </div>
              <p v-if="v.note" class="rc-version-note">{{ v.note }}</p>
              <div class="rc-version-snap">
                <span>{{ v.snapshot?.title || "（无标题快照）" }}</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    </Transition>
  </Teleport>
</template>
