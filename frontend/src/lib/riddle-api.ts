import { auth } from "./auth";

export class RiddleApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public body?: unknown,
  ) {
    super(message);
    this.name = "RiddleApiError";
  }
}

function buildAuthHeaders(extra?: HeadersInit): Headers {
  const headers = new Headers(extra ?? {});
  const token = auth.getToken();
  if (token && !token.endsWith(".local") && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  return headers;
}

function handleUnauthorized(): void {
  auth.clearToken(false);
  if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
    const from = encodeURIComponent(window.location.pathname + window.location.search);
    window.location.replace(`/login?from=${from}`);
  }
}

export async function riddleFetch<T>(path: string, init: RequestInit = {}): Promise<T> {
  const url = path.startsWith("/api") ? path : `/api${path.startsWith("/") ? path : `/${path}`}`;
  const headers = buildAuthHeaders(init.headers);
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json");
  }
  const res = await fetch(url, { ...init, headers, credentials: "include" });
  if (res.status === 401) {
    handleUnauthorized();
    throw new RiddleApiError(401, "未授权或访问令牌已失效");
  }
  if (!res.ok) {
    const raw = await res.text();
    let parsed: unknown = raw;
    let message = `${res.status} ${res.statusText}`;
    try {
      parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object") {
        const obj = parsed as Record<string, unknown>;
        if (typeof obj.detail === "string") {
          message = obj.detail;
        } else if (obj.detail && typeof obj.detail === "object") {
          message = JSON.stringify(obj.detail);
        } else if (typeof obj.message === "string") {
          message = obj.message;
        }
      }
    } catch {
      if (raw.trim()) message = raw.trim().slice(0, 240);
    }
    throw new RiddleApiError(res.status, message, parsed);
  }
  if (res.status === 204) return undefined as T;
  const ct = res.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    return (await res.json()) as T;
  }
  return (await res.text()) as unknown as T;
}

export async function downloadWithAuth(path: string, fallbackFilename: string): Promise<void> {
  const url = path.startsWith("/api") ? path : `/api${path.startsWith("/") ? path : `/${path}`}`;
  const headers = buildAuthHeaders();
  const res = await fetch(url, { method: "GET", headers, credentials: "include" });
  if (res.status === 401) {
    handleUnauthorized();
    throw new RiddleApiError(401, "未授权或访问令牌已失效");
  }
  if (!res.ok) {
    const text = await res.text();
    throw new RiddleApiError(res.status, text || `下载失败 (${res.status})`);
  }
  const blob = await res.blob();
  const cd = res.headers.get("content-disposition") ?? "";
  let filename = fallbackFilename;
  const utfMatch = cd.match(/filename\*=UTF-8''([^;]+)/i);
  if (utfMatch?.[1]) {
    try {
      filename = decodeURIComponent(utfMatch[1]);
    } catch {
      filename = utfMatch[1];
    }
  } else {
    const plainMatch = cd.match(/filename="?([^"]+)"?/i);
    if (plainMatch?.[1]) filename = plainMatch[1];
  }
  const objUrl = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = objUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(objUrl), 5000);
}

// ============================================================================
// Domain Types (verified against Riddle backend app/api/*)
// ============================================================================

export interface RiddleTaskStats {
  total_targets?: number;
  done_targets?: number;
  queued_targets?: number;
  scanning_targets?: number;
  dead_targets?: number;
  skipped_targets?: number;
  raw_findings?: number;
  accepted?: number;
  rejected?: number;
  needs_deepen?: number;
  deepening?: number;
  user_passed?: number;
  user_rejected?: number;
  submitted?: number;
  killsweeps?: number;
}

export interface RiddleTask {
  id: string;
  name: string;
  status: string;
  src_type: string;
  vuln_types: string[];
  target_source: string;
  engine: string;
  fofa_query: string;
  concurrency: number;
  deepen_cap: number;
  src_rules: string;
  guard_ops: string[];
  manual_targets: string[];
  auth_bindings: Array<Record<string, unknown>>;
  model_config_data: Record<string, unknown>;
  llm_usage: Record<string, unknown>;
  created_at: string;
  updated_at: string;
  stats?: RiddleTaskStats | null;
  pending_user_review?: number;
  total_targets?: number;
  total_vulns?: number;
  progress?: number | Record<string, unknown>;
  goal_summary?: {
    configured?: boolean;
    total?: number;
    achieved?: number;
    terminal_state?: string;
    summary?: string;
  } | null;
}

export interface CreateRiddleTaskInput {
  name: string;
  src_type: "edusrc" | "enterprise" | string;
  vuln_types: string[];
  src_rules?: string;
  guard_ops?: string[];
  target_source: "fofa" | "manual" | "both" | "assist" | string;
  engine?: string;
  fofa_query?: string;
  manual_targets?: string[];
  concurrency?: number;
  deepen_cap?: number;
}

export interface RiddleTarget {
  id: string;
  task_id?: string;
  task_name?: string;
  url: string;
  host: string;
  ip: string;
  org: string;
  school: string;
  title: string;
  source?: string;
  status: string;
  verdict: string;
  is_edu?: boolean;
  retry_count: number;
  deepen_count?: number;
  priority_score: number;
  priority_reason: string;
  dead_reason: string;
  last_error: string;
  created_at: string;
  updated_at?: string;
}

export interface HardTargetsStats {
  total: number;
  dead: number;
  skipped: number;
}

export interface HardTargetsResponse {
  items: RiddleTarget[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface KillsweepItem {
  id: string;
  task_id: string;
  origin_finding_id: string;
  origin_title: string;
  product_name: string;
  vuln_type: string;
  vuln_summary: string;
  fofa_query: string;
  fingerprint: string;
  asset_count: number;
  edu_count: number;
  is_killsweep: boolean;
  has_sites: boolean;
  confidence: string;
  verified_url: string;
  verified: boolean;
  affected_table: Array<Record<string, unknown>>;
  notes: string;
  status: string;
  retryable: boolean;
  derived_count: number;
  fail_reason: string;
  created_at: string;
  updated_at: string;
}

export interface RiddleFindingReview {
  verdict: string;
  confidence: string;
  severity_final: string;
  score: number;
  in_scope: boolean;
  is_duplicate: boolean;
  ignore_reasons?: string[];
  downgrade_reasons?: string[];
  reproduced: boolean;
  reviewer_notes?: string;
  deepen_directive?: string;
  user_status: string;
  user_severity?: string | null;
  user_notes?: string;
  user_edits?: Record<string, unknown>;
  submitted: boolean;
  effective_severity: string;
}

export interface RiddleFinding {
  id: string;
  task_id: string;
  target_id: string;
  vuln_type: string;
  title: string;
  severity_claimed: string;
  target_url: string;
  owner: string;
  status: string;
  created_at: string;
  llm_model?: string;
  llm_base_url?: string;
  edu_school?: string | null;
  diff?: {
    score?: number;
    label?: string;
    hints?: string[];
  };
  fusion_evidence?: {
    tier?: string;
    tier_label?: string;
    passed?: boolean;
    reasons?: string[];
  };
  review?: RiddleFindingReview | null;
  description?: string;
  steps?: unknown[];
  poc?: string;
  poc_http?: string;
  raw_request?: string;
  raw_response?: string;
  evidence?: Record<string, unknown>;
  affected_scope?: string;
  kill_chain?: Array<{ method: string; detail: string }>;
}

export interface RiddleVulnStats {
  total: number;
  submitted: number;
  ready: number;
  by_severity: Record<string, number>;
}

export interface IntelStats {
  total: number;
  by_kind: Record<string, number>;
  verified: number;
  reused: number;
}

export interface IntelItem {
  id: string;
  kind: string;
  match_key: string;
  payload: Record<string, unknown>;
  summary: string;
  source_host: string;
  source_task_id: string;
  confidence: string;
  hit_count: number;
  utility_score: number;
  injected_count: number;
  converted_count: number;
  rejected_count: number;
  first_seen: string;
  last_seen: string;
}

export interface FusionConfigState {
  evidence_gate_hard: boolean;
  scope_guard_hard: boolean;
  goal_gate_enabled: boolean;
  skill_index_enabled: boolean;
  role_routing_enabled: boolean;
  intel_sync_enabled: boolean;
  traffic_enabled: boolean;
  graphs_enabled: boolean;
  report_enabled: boolean;
  intel_lookback_days: number;
  intel_sync_interval_hours: number;
  intel_fastlane_cvss: number;
  intel_timeout: number;
  nvd_api_key_set?: boolean;
  role_models?: Record<string, string>;
}

export interface FusionStatusResponse {
  config: FusionConfigState;
  goal_count: number;
  intel_feed_count: number;
  role_routing: Record<string, unknown>;
  modules: Array<{ id: string; name: string; desc: string }>;
}

export interface InterceptItem {
  id: string;
  task_id: string;
  src_type: string;
  tool: string;
  command: string;
  verdict: "deny" | "ask" | "judge" | "allow" | string;
  status: string;
  rule?: string;
  reason?: string;
  note?: string;
  created_at: string;
  decided_at?: string;
}

export interface CveFeedItem {
  cve_id: string;
  cvss: number;
  kev: boolean;
  products: string[];
  match_key: string;
  summary: string;
  last_seen: string;
}

export interface RiddleSettingsResponse {
  llm: {
    mode: string;
    base_url: string;
    model: string;
    models: string[];
    temperature: number;
    protocol: string;
    api_key: string;
    api_key_set: boolean;
    provider_count: number;
    providers: Array<Record<string, unknown>>;
    health?: Record<string, unknown>;
  };
  fofa: {
    base_url: string;
    max_pages: number;
    page_size: number;
    default_intent_mode: string;
    key: string;
    key_set: boolean;
  };
  engines: Record<
    string,
    {
      display_name: string;
      key: string;
      key_set: boolean;
      key_backup: string;
      key_backup_set: boolean;
      key_backup2: string;
      key_backup2_set: boolean;
      base_url: string;
    }
  >;
  defaults: {
    concurrency: number;
    deepen_cap: number;
    skip_score_threshold: number;
    worker_prompt_version: string;
    engine: string;
    fusion: FusionConfigState;
  };
  available_engines: Array<{ name: string; display_name: string; default_base_url?: string }>;
  auth: {
    full_token: string;
    full_token_set: boolean;
    read_token: string;
    read_token_set: boolean;
    observer_token: string;
    observer_token_set: boolean;
    env_full: boolean;
    env_read: boolean;
    env_observer: boolean;
  };
  updated_at?: string | null;
}

// ============================================================================
// API Client
// ============================================================================

export const riddleApi = {
  // Tasks
  listTasks: () => riddleFetch<RiddleTask[]>("/tasks"),
  getTask: (id: string) => riddleFetch<RiddleTask>(`/tasks/${encodeURIComponent(id)}`),
  createTask: (body: CreateRiddleTaskInput) =>
    riddleFetch<RiddleTask>("/tasks", { method: "POST", body: JSON.stringify(body) }),
  startTask: (id: string) => riddleFetch<RiddleTask>(`/tasks/${encodeURIComponent(id)}/start`, { method: "POST" }),
  pauseTask: (id: string) => riddleFetch<RiddleTask>(`/tasks/${encodeURIComponent(id)}/pause`, { method: "POST" }),
  stopTask: (id: string) => riddleFetch<RiddleTask>(`/tasks/${encodeURIComponent(id)}/stop`, { method: "POST" }),
  deleteTask: (id: string) => riddleFetch<void>(`/tasks/${encodeURIComponent(id)}`, { method: "DELETE" }),
  getTaskBoard: (id: string) => riddleFetch<Record<string, unknown>>(`/tasks/${encodeURIComponent(id)}/board`),
  getTaskTargets: (id: string, status?: string, limit = 200) => {
    const qs = new URLSearchParams({ limit: String(limit) });
    if (status && status !== "all") qs.set("status", status);
    return riddleFetch<RiddleTarget[]>(`/tasks/${encodeURIComponent(id)}/targets?${qs.toString()}`);
  },
  skipTaskTarget: (taskId: string, targetId: string) =>
    riddleFetch<{ ok: boolean }>(`/tasks/${encodeURIComponent(taskId)}/targets/${encodeURIComponent(targetId)}/skip`, {
      method: "POST",
    }),
  parseTargets: (text: string) =>
    riddleFetch<{ total_lines: number; valid: number; domains: number; ips: number; ignored: string[] }>(
      "/tasks/parse-targets",
      { method: "POST", body: JSON.stringify({ text }) },
    ),
  parseQuery: (engine: string, query: string, src_type: string) =>
    riddleFetch<{ looks_like_syntax: boolean; issues: string[]; summary: string; syntax_mismatch: string }>(
      "/tasks/parse-query",
      { method: "POST", body: JSON.stringify({ engine, query, src_type }) },
    ),

  // Hard Targets
  getHardTargetsStats: () => riddleFetch<HardTargetsStats>("/tasks/hard-targets/stats"),
  listHardTargets: (params: { status?: string; q?: string; limit?: number; offset?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.status && params.status !== "all") qs.set("status", params.status);
    if (params.q) qs.set("q", params.q);
    if (params.limit) qs.set("limit", String(params.limit));
    if (params.offset) qs.set("offset", String(params.offset));
    return riddleFetch<HardTargetsResponse>(`/tasks/hard-targets?${qs.toString()}`);
  },
  reviveHardTargets: (body: {
    target_ids?: string[];
    status?: string;
    q?: string;
    limit?: number;
    inject_latest_intel?: boolean;
  }) => riddleFetch<Record<string, unknown>>("/tasks/hard-targets/revive", { method: "POST", body: JSON.stringify(body) }),

  // Vulns & Findings & Killsweep
  getVulnStats: () => riddleFetch<RiddleVulnStats>("/vulns/stats"),
  listVulns: (params: { submitted?: "all" | "yes" | "no"; severity?: string; q?: string; sort?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.submitted) qs.set("submitted", params.submitted);
    if (params.severity && params.severity !== "all") qs.set("severity", params.severity);
    if (params.q) qs.set("q", params.q);
    if (params.sort) qs.set("sort", params.sort);
    if (params.limit) qs.set("limit", String(params.limit));
    return riddleFetch<{ items: Array<Record<string, unknown>>; total: number }>(`/vulns?${qs.toString()}`);
  },
  listTaskFindings: (taskId: string, params: { status?: string; q?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.status && params.status !== "all") qs.set("status", params.status);
    if (params.q) qs.set("q", params.q);
    if (params.limit) qs.set("limit", String(params.limit));
    return riddleFetch<{ items?: RiddleFinding[] } | RiddleFinding[]>(
      `/tasks/${encodeURIComponent(taskId)}/findings?${qs.toString()}`,
    );
  },
  listTaskResults: (taskId: string, params: { q?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.q) qs.set("q", params.q);
    if (params.limit) qs.set("limit", String(params.limit));
    return riddleFetch<{ items?: RiddleFinding[] } | RiddleFinding[]>(
      `/tasks/${encodeURIComponent(taskId)}/results?${qs.toString()}`,
    );
  },
  getFinding: (id: string) => riddleFetch<RiddleFinding>(`/findings/${encodeURIComponent(id)}`),
  reviewFinding: (
    findingId: string,
    body: {
      user_status?: "passed" | "rejected" | "pending";
      user_severity?: string;
      user_notes?: string;
      submitted?: boolean;
      user_edits?: Record<string, unknown>;
    },
  ) =>
    riddleFetch<{ ok: boolean; killsweep_triggered?: boolean; killsweep_skipped_reason?: string }>(
      `/results/${encodeURIComponent(findingId)}`,
      { method: "PATCH", body: JSON.stringify(body) },
    ),
  deepenFinding: (findingId: string, directive: string) =>
    riddleFetch<{ ok: boolean; message?: string }>(`/results/${encodeURIComponent(findingId)}/deepen`, {
      method: "POST",
      body: JSON.stringify({ directive }),
    }),
  distillFindingToKb: (findingId: string) =>
    riddleFetch<Record<string, unknown>>(`/intel/knowledge/distill/${encodeURIComponent(findingId)}`, {
      method: "POST",
    }),
  listKillsweeps: (taskId: string, params: { only_hits?: boolean; include_invalid?: boolean; q?: string } = {}) => {
    const qs = new URLSearchParams();
    if (params.only_hits) qs.set("only_hits", "true");
    if (params.include_invalid) qs.set("include_invalid", "true");
    if (params.q) qs.set("q", params.q);
    return riddleFetch<KillsweepItem[]>(`/tasks/${encodeURIComponent(taskId)}/killsweeps?${qs.toString()}`);
  },
  retryKillsweep: (taskId: string, killsweepId: string) =>
    riddleFetch<{ ok: boolean; status: string }>(
      `/tasks/${encodeURIComponent(taskId)}/killsweeps/${encodeURIComponent(killsweepId)}/retry`,
      { method: "POST" },
    ),
  enqueueKillsweep: (taskId: string, killsweepId: string, count = 3) =>
    riddleFetch<{ ok: boolean; enqueued?: number }>(
      `/tasks/${encodeURIComponent(taskId)}/killsweeps/${encodeURIComponent(killsweepId)}/enqueue`,
      { method: "POST", body: JSON.stringify({ count }) },
    ),
  invalidateKillsweep: (taskId: string, killsweepId: string, reason = "人工标记无效") =>
    riddleFetch<{ ok: boolean }>(
      `/tasks/${encodeURIComponent(taskId)}/killsweeps/${encodeURIComponent(killsweepId)}/invalidate`,
      { method: "POST", body: JSON.stringify({ reason }) },
    ),

  // Intel & Knowledge
  getIntelStats: () => riddleFetch<IntelStats>("/intel/stats"),
  listIntel: (params: { kind?: string; confidence?: string; q?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.kind) qs.set("kind", params.kind);
    if (params.confidence) qs.set("confidence", params.confidence);
    if (params.q) qs.set("q", params.q);
    if (params.limit) qs.set("limit", String(params.limit));
    return riddleFetch<IntelItem[]>(`/intel?${qs.toString()}`);
  },
  previewCurateIntel: (limit = 1000) => riddleFetch<Record<string, unknown>>(`/intel/curate?limit=${limit}`),
  applyCurateIntel: (limit = 1000) =>
    riddleFetch<Record<string, unknown>>(`/intel/curate?limit=${limit}`, { method: "POST" }),
  deleteIntel: (id: string) => riddleFetch<{ ok: boolean }>(`/intel/${encodeURIComponent(id)}`, { method: "DELETE" }),
  clearIntel: (kind = "all") =>
    riddleFetch<{ ok: boolean; deleted?: number }>(`/intel?kind=${encodeURIComponent(kind)}`, { method: "DELETE" }),

  // Fusion Governance, Goals, CVE, Retests & Reports
  getFusionStatus: () => riddleFetch<FusionStatusResponse>("/fusion/status"),
  getFusionConfig: () => riddleFetch<{ config: FusionConfigState; source: string }>("/fusion/config"),
  putFusionConfig: (config: Partial<FusionConfigState>) =>
    riddleFetch<{ ok: boolean; config: FusionConfigState }>("/fusion/config", {
      method: "PUT",
      body: JSON.stringify({ config }),
    }),
  getSkillIndex: () =>
    riddleFetch<{ count: number; entries: Array<Record<string, unknown>>; block: string }>("/fusion/skill-index"),
  getGoals: (taskId: string) =>
    riddleFetch<{ task_id: string; goals: Array<Record<string, unknown>> }>(`/fusion/goals/${encodeURIComponent(taskId)}`),
  saveGoals: (taskId: string, goals: Array<Record<string, unknown>>) =>
    riddleFetch<{ ok: boolean; saved: number }>(`/fusion/goals/${encodeURIComponent(taskId)}`, {
      method: "PUT",
      body: JSON.stringify({ goals }),
    }),
  suggestGoals: (body: {
    task_id?: string;
    name?: string;
    src_type?: string;
    vuln_types?: string[];
    targets?: unknown[];
    fofa_query?: string;
  }) =>
    riddleFetch<{ goals: Array<Record<string, unknown>>; count: number }>("/fusion/goals/suggest", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  checkEvidence: (finding: Record<string, unknown>) =>
    riddleFetch<Record<string, unknown>>("/fusion/evidence/check", {
      method: "POST",
      body: JSON.stringify({ finding }),
    }),
  checkScope: (target: Record<string, unknown>, scope: Record<string, unknown>) =>
    riddleFetch<Record<string, unknown>>("/fusion/scope/check", {
      method: "POST",
      body: JSON.stringify({ target, scope }),
    }),
  checkIntercept: (body: {
    command: string;
    tool?: string;
    cwd?: string;
    src_type?: string;
    task_id?: string;
    forbidden_ops?: string[];
    record?: boolean;
  }) =>
    riddleFetch<Record<string, unknown>>("/fusion/intercept/check", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  listIntercepts: (params: { task_id?: string; status?: string } = {}) => {
    const qs = new URLSearchParams();
    if (params.task_id) qs.set("task_id", params.task_id);
    if (params.status && params.status !== "all") qs.set("status", params.status);
    return riddleFetch<{ total: number; items: InterceptItem[] }>(`/fusion/intercept/list?${qs.toString()}`);
  },
  decideIntercept: (itemId: string, decision: "approved" | "rejected" | string, note = "") =>
    riddleFetch<{ ok: boolean; item: InterceptItem }>(`/fusion/intercept/decide/${encodeURIComponent(itemId)}`, {
      method: "POST",
      body: JSON.stringify({ decision, note }),
    }),
  getRecentCves: (limit = 50) => riddleFetch<{ items: CveFeedItem[] }>(`/fusion/intel/recent?limit=${limit}`),
  syncCves: () => riddleFetch<Record<string, unknown>>("/fusion/intel/sync", { method: "POST" }),
  matchCveTechnologies: (technologies: string[], include_unaffected = false) =>
    riddleFetch<{ count: number; hints: Array<Record<string, unknown>> }>("/fusion/intel/match", {
      method: "POST",
      body: JSON.stringify({ technologies, include_unaffected }),
    }),
  listRetests: (findingId: string) =>
    riddleFetch<{ finding_id: string; retests: Array<Record<string, unknown>>; summary: Record<string, unknown> }>(
      `/fusion/retests/${encodeURIComponent(findingId)}`,
    ),
  createRetest: (
    findingId: string,
    body: { mode?: "manual" | "http_probe"; status?: string; url?: string; method?: string; match_text?: string; notes?: string },
  ) =>
    riddleFetch<{ ok: boolean; retests: Array<Record<string, unknown>> }>(
      `/fusion/retests/${encodeURIComponent(findingId)}`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  downloadDocxReport: (findingId: string, title?: string) =>
    downloadWithAuth(
      `/fusion/report/docx/${encodeURIComponent(findingId)}`,
      `${(title || findingId).slice(0, 32)}.docx`,
    ),
  downloadFindingExport: (findingId: string, format: "md" | "json" | "html" | "docx") =>
    downloadWithAuth(`/findings/${encodeURIComponent(findingId)}/export?format=${format}`, `${findingId}.${format}`),

  // Settings, Workdir, Backup & Runtime Logs
  getSettings: () => riddleFetch<RiddleSettingsResponse>("/settings"),
  putSettings: (payload: Record<string, unknown>) =>
    riddleFetch<Record<string, unknown>>("/settings", { method: "PUT", body: JSON.stringify(payload) }),
  testEngine: (engine: string, key?: string, base_url?: string) =>
    riddleFetch<{ ok: boolean; engine: string; latency_ms?: number; size?: number; error?: string }>(
      "/settings/test-engine",
      { method: "POST", body: JSON.stringify({ engine, key: key || undefined, base_url: base_url || undefined }) },
    ),
  getWorkdirStats: () => riddleFetch<Record<string, unknown>>("/settings/workdir/stats"),
  cleanupWorkdir: (retention_days?: number, dry_run = true) => {
    const qs = new URLSearchParams({ dry_run: String(dry_run) });
    if (typeof retention_days === "number") qs.set("retention_days", String(retention_days));
    return riddleFetch<Record<string, unknown>>(`/settings/workdir/cleanup?${qs.toString()}`, { method: "POST" });
  },
  getBackupStatus: () => riddleFetch<Record<string, unknown>>("/backup/status"),
  createSnapshot: () => riddleFetch<Record<string, unknown>>("/backup/snapshot", { method: "POST" }),
  exportBackup: async (includeWork = false) => {
    const qs = `?include_work=${includeWork ? "true" : "false"}`;
    const headers = buildAuthHeaders();
    const res = await fetch(`/api/backup/export${qs}`, { method: "POST", headers, credentials: "include" });
    if (res.status === 401) {
      handleUnauthorized();
      throw new RiddleApiError(401, "未授权或访问令牌已失效");
    }
    if (!res.ok) throw new RiddleApiError(res.status, await res.text());
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `riddle-backup-${includeWork ? "full" : "db"}.tar.gz`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  },
  downloadSnapshot: (name: string) => downloadWithAuth(`/backup/snapshots/${encodeURIComponent(name)}`, name),
  restoreBackup: (file: File, includeWork = false, restart = true) => {
    const form = new FormData();
    form.append("file", file);
    const qs = `?include_work=${includeWork ? "true" : "false"}&restart=${restart ? "true" : "false"}`;
    return riddleFetch<Record<string, unknown>>(`/backup/restore${qs}`, { method: "POST", body: form });
  },
  getRuntimeLogStats: () => riddleFetch<{ total: number; errors: number; warns: number; by_agent: Record<string, number> }>("/runtime-logs/stats"),
  listRuntimeLogs: (params: { level?: string; agent?: string; q?: string; limit?: number } = {}) => {
    const qs = new URLSearchParams();
    if (params.level && params.level !== "all") qs.set("level", params.level);
    if (params.agent && params.agent !== "all") qs.set("agent", params.agent);
    if (params.q) qs.set("q", params.q);
    if (params.limit) qs.set("limit", String(params.limit));
    return riddleFetch<{ items: Array<Record<string, unknown>>; total: number }>(`/runtime-logs?${qs.toString()}`);
  },
};
