// 简易 API 客户端
import { ref } from "vue";

const base = "";
const TOKEN_KEY = "ah-api-token";

/** 响应式鉴权态：模板必须依赖它，否则刷新后 v-if 不会更新。 */
export const authRoleRef = ref("none"); // full | readonly | observer | none
export const authReadyRef = ref(false);
export const authRequiredRef = ref(true); // 服务端是否开启了访问令牌鉴权

function bootstrapTokenFromCookie() {
  if (localStorage.getItem(TOKEN_KEY)) return;
  const m = document.cookie.match(/(?:^|;\s*)ah_api_token=([^;]+)/);
  if (m) localStorage.setItem(TOKEN_KEY, decodeURIComponent(m[1]));
}
bootstrapTokenFromCookie();

function normalizeRole(role) {
  if (role === "full" || role === "readonly" || role === "observer") return role;
  return "none";
}

function setAuthRole(role) {
  authRoleRef.value = normalizeRole(role);
  authReadyRef.value = true;
  window.dispatchEvent(new CustomEvent("riddle-auth-role", { detail: { role: authRoleRef.value } }));
}

function sanitizeToken(token) {
  return String(token || "")
    .replace(/[\u200B-\u200D\uFEFF]/g, "")
    .trim();
}

function apiToken() {
  return localStorage.getItem(TOKEN_KEY) || "";
}

function setApiToken(token) {
  const cleaned = sanitizeToken(token);
  if (!cleaned) return;
  localStorage.setItem(TOKEN_KEY, cleaned);
  const secure = location.protocol === "https:" ? "; Secure" : "";
  document.cookie = `ah_api_token=${encodeURIComponent(cleaned)}; Path=/; SameSite=Strict${secure}`;
}

export function clearAccessToken() {
  localStorage.removeItem(TOKEN_KEY);
  document.cookie = "ah_api_token=; Path=/; Max-Age=0; SameSite=Strict";
}

/** 会话失效：清令牌、复位鉴权态，并通知应用跳转登录页。 */
function handleAuthExpired() {
  clearAccessToken();
  authRoleRef.value = "none";
  authReadyRef.value = true;
  window.dispatchEvent(new CustomEvent("riddle-auth-expired"));
}

export function isReadonly() {
  return authRoleRef.value === "readonly";
}

export function canWrite() {
  return authRoleRef.value === "full";
}

export async function loadAuthRole() {
  try {
    const res = await req("GET", "/api/auth/status");
    authRequiredRef.value = !!res?.auth_required;
    if (!res?.auth_required) {
      setAuthRole("full");
      return authRoleRef.value;
    }
    setAuthRole(res?.role);
    return authRoleRef.value;
  } catch {
    authReadyRef.value = true;
    return authRoleRef.value;
  }
}

/**
 * 校验某个令牌的角色，但【不改变】当前登录态。返回 "full"|"readonly"|"observer"|"none"。
 * 若服务端未开启鉴权(auth_required=false)，视为 "full"（无需密码即可操作）。
 */
export async function verifyToken(token) {
  const cleaned = sanitizeToken(token);
  try {
    const res = await req("GET", "/api/auth/status", undefined, true, cleaned);
    if (!res?.auth_required) return "full";
    return normalizeRole(res?.role);
  } catch {
    return "none";
  }
}

export async function applyAccessToken(token) {
  const cleaned = sanitizeToken(token);
  if (!cleaned) return { ok: false, role: "none", error: "empty" };

  setApiToken(cleaned);
  try {
    const res = await req("GET", "/api/auth/status");
    if (!res?.auth_required) {
      setAuthRole("full");
      return { ok: true, role: "full" };
    }
    if (res.role === "full" || res.role === "readonly" || res.role === "observer") {
      setAuthRole(res.role);
      return { ok: true, role: res.role };
    }
    setAuthRole("none");
    return { ok: false, role: "none", error: "invalid" };
  } catch (e) {
    return { ok: false, role: authRoleRef.value, error: String(e.message || e) };
  }
}

async function req(method, url, body, retriedAuth = false, overrideToken = "") {
  const opt = { method, headers: {} };
  const token = overrideToken || apiToken();
  if (token) opt.headers["X-Riddle-Token"] = token;
  if (body !== undefined) {
    opt.headers["Content-Type"] = "application/json";
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(base + url, opt);
  const text = await res.text();
  if (res.status === 401 && !retriedAuth) {
    handleAuthExpired();
    throw new Error("401 未认证，请重新登录");
  }
  if (res.status === 403) throw new Error("只读令牌不允许此操作");
  if (!res.ok) throw new Error(`${res.status} ${text}`);
  if (res.status === 204 || !text) return null;
  try { return JSON.parse(text); }
  catch { return text; }
}

/**
 * 消费一个 SSE 流式接口。onEvent 收到每个解析出的事件对象。
 * signal 可选（AbortController），用于停止报告助手生成。
 * 返回 Promise，在流结束时 resolve。
 */
async function streamSSE(url, body, onEvent, retriedAuth = false, signal = null) {
  const headers = { "Content-Type": "application/json" };
  const token = apiToken();
  if (token) headers["X-Riddle-Token"] = token;
  const res = await fetch(base + url, { method: "POST", headers, body: JSON.stringify(body), signal });

  if (res.status === 401 && !retriedAuth) {
    handleAuthExpired();
    throw new Error("401 未认证，请重新登录");
  }
  if (res.status === 403) throw new Error("当前令牌不允许此操作");
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`${res.status} ${text}`);
  }
  if (!res.body) throw new Error("浏览器不支持流式响应");

  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const chunk = buffer.slice(0, idx);
      buffer = buffer.slice(idx + 2);
      for (const line of chunk.split("\n")) {
        const trimmed = line.startsWith("data:") ? line.slice(5).trim() : "";
        if (!trimmed) continue;
        try { onEvent(JSON.parse(trimmed)); }
        catch { /* 忽略心跳/非 JSON 行 */ }
      }
    }
  }
}

function qs(params = {}) {
  const s = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") s.set(k, v);
  }
  const out = s.toString();
  return out ? `?${out}` : "";
}

async function downloadFile(method, url) {
  const headers = {};
  const token = apiToken();
  if (token) headers["X-Riddle-Token"] = token;
  const res = await fetch(base + url, { method, headers });
  if (res.status === 403) throw new Error("只读令牌不允许此操作");
  if (!res.ok) throw new Error(`${res.status} ${await res.text()}`);
  const blob = await res.blob();
  let filename = "riddle-backup.tar.gz";
  const cd = res.headers.get("content-disposition") || "";
  const star = cd.match(/filename\*=UTF-8''([^;]+)/i);
  const plain = cd.match(/filename=\"?([^\";]+)\"?/i);
  if (star) filename = decodeURIComponent(star[1]);
  else if (plain) filename = plain[1];
  const href = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = href;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(href), 2000);
}

async function uploadUiWallpaper(file) {
  const headers = {};
  const token = apiToken();
  if (token) headers["X-Riddle-Token"] = token;
  const body = new FormData();
  body.append("file", file, file.name || "wallpaper.jpg");
  const res = await fetch(base + "/api/settings/ui/wallpaper", { method: "POST", headers, body });
  const text = await res.text();
  if (res.status === 403) throw new Error("只读令牌不允许此操作");
  if (!res.ok) throw new Error(`${res.status} ${text}`);
  try { return JSON.parse(text); }
  catch { throw new Error(text || "上传失败"); }
}

async function uploadBackup(file, includeWork) {
  const headers = {};
  const token = apiToken();
  if (token) headers["X-Riddle-Token"] = token;
  const body = new FormData();
  body.append("file", file);
  const res = await fetch(base + `/api/backup/restore${qs({ include_work: includeWork })}`, {
    method: "POST",
    headers,
    body,
  });
  const text = await res.text();
  if (res.status === 403) throw new Error("只读令牌不允许此操作");
  if (!res.ok) throw new Error(`${res.status} ${text}`);
  try { return JSON.parse(text); }
  catch { return { ok: true, message: text }; }
}

export const api = {
  listTasks: () => req("GET", "/api/tasks"),
  createTask: (data) => req("POST", "/api/tasks", data),
  parseTargets: (text) => req("POST", "/api/tasks/parse-targets", { text }),
  parseQuery: (data) => req("POST", "/api/tasks/parse-query", data),
  parseAuthBatch: (text) => req("POST", "/api/tasks/parse-auth-batch", { text }),
  parseForbiddenOps: (text) => req("POST", "/api/tasks/parse-forbidden-ops", { text }),
  getTask: (id) => req("GET", `/api/tasks/${id}`),
  updateTask: (id, data) => req("PATCH", `/api/tasks/${id}`, data),
  // 删除任务：必须带 full 令牌（作为二次身份校验，独立于当前登录令牌）。
  deleteTask: (id, token) => req("DELETE", `/api/tasks/${id}`, undefined, false, sanitizeToken(token)),
  board: (id, opts = {}) => req("GET", `/api/tasks/${id}/board${qs(opts)}`),
  timeline: (id, opts = {}) => req("GET", `/api/tasks/${id}/timeline${qs(opts)}`),
  hardTargets: (status, q, opts = {}) => req("GET", `/api/tasks/hard-targets${qs({ status, q, ...opts })}`),
  hardTargetsStats: () => req("GET", "/api/tasks/hard-targets/stats"),
  start: (id) => req("POST", `/api/tasks/${id}/start`),
  pause: (id) => req("POST", `/api/tasks/${id}/pause`),
  stop: (id) => req("POST", `/api/tasks/${id}/stop`),
  reviewQueue: (id, q) => req("GET", `/api/tasks/${id}/review-queue${qs({ q })}`),
  submitList: (id, submitted, q, opts = {}) =>
    req("GET", `/api/tasks/${id}/submit-list${qs({ submitted, q, ...opts })}`),
  rejectedList: (id, q) => req("GET", `/api/tasks/${id}/rejected${qs({ q })}`),
  archivedList: (id, q, opts = {}) => req("GET", `/api/tasks/${id}/archived${qs({ q, ...opts })}`),
  restoreArchived: (id) => req("POST", `/api/results/${id}/restore`),
  skipTarget: (taskId, targetId) => req("POST", `/api/tasks/${taskId}/targets/${targetId}/skip`),
  targetTrace: (taskId, targetId, limit = 200) =>
    req("GET", `/api/tasks/${taskId}/targets/${targetId}/trace${qs({ limit })}`),
  injectDirective: (taskId, targetId, directive) =>
    req("POST", `/api/tasks/${taskId}/targets/${targetId}/directive`, { directive }),
  cancelEscalation: (taskId, findingId) =>
    req("POST", `/api/tasks/${taskId}/escalations/${findingId}/cancel`),
  killsweeps: (id, q) => req("GET", `/api/tasks/${id}/killsweeps${qs({ q })}`),
  invalidateKillsweep: (taskId, killsweepId, reason) =>
    req("POST", `/api/tasks/${taskId}/killsweeps/${killsweepId}/invalidate`, { reason }),
  retryKillsweep: (taskId, killsweepId) =>
    req("POST", `/api/tasks/${taskId}/killsweeps/${killsweepId}/retry`),
  enqueueKillsweepAssets: (taskId, killsweepId, count) =>
    req("POST", `/api/tasks/${taskId}/killsweeps/${killsweepId}/enqueue`, { count }),
  batchInvalidateKillsweeps: (taskId, ids, reason) =>
    req("POST", `/api/tasks/${taskId}/killsweeps/batch-invalidate`, { ids, reason }),
  batchRetryKillsweeps: (taskId, ids) =>
    req("POST", `/api/tasks/${taskId}/killsweeps/batch-retry`, { ids }),
  killsweepStats: (taskId) => req("GET", `/api/tasks/${taskId}/killsweeps/stats`),
  killsweepExport: (taskId, format) =>
    downloadFile("GET", `/api/tasks/${taskId}/killsweeps/export${qs({ format })}`),
  finding: (id) => req("GET", `/api/findings/${id}`),
  findingReport: (id, srcType) => req("GET", `/api/findings/${id}/report${qs({ src_type: srcType })}`),
  exportReport: (id, format, srcType) =>
    downloadFile("GET", `/api/findings/${id}/export${qs({ format, src_type: srcType })}`),
  reportVersions: (id) => req("GET", `/api/findings/${id}/versions`),
  restoreVersion: (id, version, note) =>
    req("POST", `/api/findings/${id}/versions/${version}/restore`, { note }),
  reportAssistantStream: (id, message, onEvent, signal) =>
    streamSSE(`/api/findings/${id}/assistant/stream`, { message }, onEvent, false, signal),
  userReview: (id, data) => req("PATCH", `/api/results/${id}`, data),
  deepen: (id, directive) => req("POST", `/api/results/${id}/deepen`, { directive }),
  getSettings: () => req("GET", "/api/settings"),
  providerHealth: () => req("GET", "/api/settings/provider-health"),
  healthOverview: () => req("GET", "/api/settings/health-overview"),
  updateSettings: (data) => req("PUT", "/api/settings", data),
  testEngine: (data) => req("POST", "/api/settings/test-engine", data),
  exportSettings: () => req("GET", "/api/settings/export"),
  importSettings: (data) => req("POST", "/api/settings/import", data),
  listModels: (base_url, api_key, extra = {}) => req(
    "POST",
    "/api/settings/models",
    typeof base_url === "object" ? base_url : { base_url, api_key, ...extra }
  ),
  taskModels: (id, data) => req("POST", `/api/tasks/${id}/models`, data),
  testLLM: (data) => req("POST", "/api/settings/test-llm", data),
  llmPresets: () => req("GET", "/api/settings/llm-presets"),
  temperatureRecommend: (data) => req("POST", "/api/settings/temperature-recommend", data),
  poolSchedulePreview: (providers) => req("POST", "/api/settings/pool-schedule-preview", { providers }),
  providerHealthCheck: (providers) => req("POST", "/api/settings/provider-health-check", { providers }),
  // 工作目录管理
  workdirStats: () => req("GET", "/api/settings/workdir/stats"),
  workdirCleanup: (retentionDays, dryRun = true) =>
    req("POST", `/api/settings/workdir/cleanup${qs({ retention_days: retentionDays, dry_run: dryRun })}`),
  backupStatus: () => req("GET", "/api/backup/status"),
  backupSnapshot: () => req("POST", "/api/backup/snapshot"),
  downloadBackupExport: (includeWork = false) =>
    downloadFile("POST", `/api/backup/export${qs({ include_work: includeWork })}`),
  downloadBackupSnapshot: (name) =>
    downloadFile("GET", `/api/backup/snapshots/${encodeURIComponent(name)}`),
  restoreBackup: (file, includeWork = false) => uploadBackup(file, includeWork),
  uploadUiWallpaper: (file) => uploadUiWallpaper(file),
  deleteUiWallpaper: () => req("DELETE", "/api/settings/ui/wallpaper"),
  // 全局情报库
  intelStats: () => req("GET", "/api/intel/stats"),
  intelHitStats: () => req("GET", "/api/intel/hit-stats"),
  intelList: (kind, confidence, q, limit) =>
    req("GET", `/api/intel${qs({ kind, confidence, q, limit })}`),
  previewIntelCurate: (limit) => req("GET", `/api/intel/curate${qs({ limit })}`),
  applyIntelCurate: (limit) => req("POST", `/api/intel/curate${qs({ limit })}`),
  deleteIntel: (id) => req("DELETE", `/api/intel/${id}`),
  clearIntel: (kind) => req("DELETE", `/api/intel${qs({ kind })}`),
  // 全局漏洞库
  vulnStats: () => req("GET", "/api/vulns/stats"),
  vulns: (submitted, severity, q, opts = {}) =>
    req("GET", `/api/vulns${qs({ submitted, severity, q, ...opts })}`),
  // 全局运行异常日志
  runtimeLogStats: () => req("GET", "/api/runtime-logs/stats"),
  runtimeLogs: (level, agent, q, opts = {}) =>
    req("GET", `/api/runtime-logs${qs({ level, agent, q, ...opts })}`),
  // 一键更新
  checkUpdate: () => req("GET", "/api/update/check"),
  runUpdate: () => req("POST", "/api/update/run"),
};

export function wsUrl(taskId) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const host = location.host || "localhost:8000";
  const token = apiToken();
  const suffix = token ? `?token=${encodeURIComponent(token)}` : "";
  return `${proto}://${host}/api/tasks/${taskId}/stream${suffix}`;
}
