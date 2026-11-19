// Riddle console domain model — types used across the UI.
// Derived from the functional spec (section 7: 关键数据形状).

export type TaskStatus = "created" | "queued" | "running" | "paused" | "done" | "failed" | "timeout";
export type EngineMode = "exploring" | "paused" | "stalled" | "idle";

export interface Task {
  id: string;
  name?: string; // 可选任务名称;空/缺省=未命名,展示时回退到描述
  category_id?: number;
  category_name?: string;
  pinned?: boolean;
  pinned_at?: string | null;
  description: string;
  goal: string;
  status: TaskStatus;
  created_at: string;
  created_unix?: number; // created_at as unix seconds (run-duration calc)
  completed_at?: string; // RFC3339 finish time (done/failed); "" if unfinished
  completed_unix?: number; // completed_at as unix seconds (0/undef if unfinished)
  last_activity_unix?: number; // unix seconds of the last activity (0/undef if none)
  paused?: boolean;
  autopilot?: boolean;
  queued?: boolean;
  active?: boolean;
  in_flight?: number;
  findings?: { critical: number; high: number; medium: number; low: number }; // 已登记漏洞数(按严重度分档)
  last_activity?: string;
  stalled?: boolean;
  goals_total?: number;
  goals_met?: number;
  engine_mode?: EngineMode;
  tokens?: TokenTotal; // whole-task token consumption
  llm_profile_id?: number; // LLM profile used; absent = default profile
  llm_profile_ids?: number[]; // ordered task-level failover chain
  active_llm_profile_id?: number; // profile used by the next LLM call
  llm_failover_state?: "default" | "ready" | "chain_exhausted" | string;
  llm_failover_reason?: string;
  source_task_ids?: string[]; // directly related tasks inherited as read-only context
  archive_blocked_by_task_id?: string; // live direct dependent that must be archived first
  company_ids?: number[]; // associated company scopes; current company assets join the task at creation
  coverage_enabled?: boolean; // 资产覆盖度功能开关(创建时定,默认开)；false=不计算/不展示覆盖度
  // 任务级登录凭据（脱敏视图；未配置为省略）
  auth_config?: TaskAuthConfigView;
}

export interface TaskCategory {
  id: number;
  name: string;
  task_count: number;
  created_at: string;
  updated_at: string;
}

export interface TaskTemplate {
  id: number;
  name: string;
  description: string;
  goal: string;
  category_id?: number | null; // 预设分类；null/缺省=无
  intercept_rules?: AssetInterceptRuleInput[]; // 预设的任务级拦截/允许规则
  created_at: string;
  updated_at: string;
}

export interface DeleteTaskOptions {
  delete_assets: boolean;
  delete_traffic: boolean;
  delete_files: boolean;
  delete_findings: boolean;
  delete_llm_records: boolean;
}

export interface DeleteTaskResult {
  deleted: string;
  assets_deleted: number;
  assets_detached: number;
  traffic_deleted: number;
  files_deleted: boolean;
  findings_deleted: number;
  llm_records_deleted: number;
  cleanup_warning?: string;
}

export type TaskArchiveState =
  | "archive_queued"
  | "archiving"
  | "archive_failed"
  | "ready"
  | "restore_queued"
  | "restoring"
  | "restore_failed"
  | "delete_queued"
  | "deleting"
  | "delete_failed";

export interface TaskArchiveTokenStats {
  calls?: number;
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface TaskArchive {
  id: number;
  task_id: number;
  state: TaskArchiveState;
  phase: string;
  progress: number;
  error?: string;
  warnings?: string[];
  format_version: number;
  sha256?: string;
  original_size: number;
  compressed_size: number;
  task_name: string;
  task_description: string;
  task_goal: string;
  original_status: TaskStatus;
  category_id?: number;
  category_name?: string;
  source_task_ids: number[];
  remaining_timeout_seconds: number;
  data_counts: Record<string, number>;
  aggregate_stats: {
    tokens?: TaskArchiveTokenStats;
    skills?: Record<string, number>;
    tools?: Record<string, number>;
    findings?: Record<string, number>;
  };
  archived_at?: string;
  requested_at: string;
  created_at: string;
  updated_at: string;
}

export interface TaskArchivePage {
  items: TaskArchive[];
  total: number;
  page: number;
  size: number;
}

export interface ArchiveBatchItem {
  id: string;
  archive_id?: number;
  ok: boolean;
  queued: boolean;
  error?: string;
}

// ---- Asset graph (global, shared across tasks) ----
export type AssetType =
  | "company"
  | "domain"
  | "ip"
  | "port"
  | "service"
  | "site"
  | "endpoint"
  | "parameter"
  | "tech"
  | "credential"
  | "data";

export type NodeState = "observed" | "confirmed" | "tombstoned";

export interface AssetNode {
  id: string;
  type: AssetType;
  name: string;
  key: string; // nkey
  value?: string;
  company_id?: string; // 归属公司资产 id；空=未归属
  state: NodeState;
  confidence: number; // 0..1
  attrs?: Record<string, unknown>;
  first_seen: string;
  last_seen: string;
}

export type AssetRel =
  | "owns"
  | "resolves"
  | "exposes"
  | "runs"
  | "serves"
  | "has_endpoint"
  | "has_param"
  | "fingerprinted"
  | "authenticates_as"
  | "reachable"
  | "has_subdomain";

export interface Edge {
  src: string;
  dst: string;
  rel: AssetRel | ExploreRel;
}

// Task asset view — server-side enriched, paginated.
export interface TaskAssetRef {
  id: string;
  name?: string;
  key: string;
  attrs?: Record<string, unknown>;
}

export interface TaskAssetItem extends AssetNode {
  techs?: TaskAssetRef[];
  auth?: TaskAssetRef[];
  params?: TaskAssetRef[];
}

export interface TaskAssetView {
  counts: Record<string, number>;
  total: number;
  items: TaskAssetItem[];
}

// ---- New unified asset model (new backend) ----
export type NewAssetType = "root_domain" | "ip" | "subdomain" | "app" | "service" | "endpoint";

export interface Asset {
  id: number;
  type: NewAssetType;
  company_id?: number;
  task_ids: number[];
  domain?: string;
  root_domain?: string;
  ip?: string;
  c_segment?: string;
  port?: number;
  icp?: string;
  bound_domains?: string[];
  open_ports?: { port: number; service?: string }[];
  record_type?: string;
  record_value?: string[] | string;
  bundle_id?: string;
  app_name?: string;
  category?: string;
  app_description?: string;
  app_icp?: string;
  url?: string;
  service_type?: string;
  service_name?: string;
  favicon_mmh3?: string;
  status_code?: number;
  content_length?: number;
  page_title?: string;
  technologies?: string[];
  auth?: Record<string, unknown>[];
  method?: string;
  params?: Record<string, unknown>[];
  extra?: Record<string, unknown>;
  last_seen: string;
  task_source?: string;
  task_source_summary?: string;
  task_source_node_id?: number;
}

export interface IntentAsset {
  intent_id: number | string;
  asset_id: number;
  type: NewAssetType;
  label: string;
  source: string;
  source_summary: string;
  source_node_id?: number;
  source_task_id: number;
  inherited: boolean;
}

export interface TaskAssetMutation {
  requested: number;
  attached: number;
  existing: number;
}

export interface TaskAssetScopeMutation {
  requested: number;
  assets_linked: number;
  assets_existing: number;
  scopes_added: number;
  scopes_existing: number;
}

// ---- Asset coverage graph (per task) ----
// 力导向「资产覆盖图」的一个节点。key 唯一：资产="a:<id>"、公司="c:<id>"、
// 无资产行的根域名="r:<domain>"。in_scope=false 的是仅用于连线的灰色上下文节点。
export interface CoverageGraphNode {
  key: string;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint";
  label: string;
  tested: boolean;
  in_scope: boolean;
  asset_id?: number;
  company_id?: number;
  domain?: string;
  root_domain?: string;
  ip?: string;
  url?: string;
  port?: number;
  service_type?: string;
  app_name?: string;
  page_title?: string;
  status_code?: number;
}

export interface CoverageGraphEdge {
  src: string;
  dst: string;
}

export interface CoverageGraphData {
  nodes: CoverageGraphNode[];
  edges: CoverageGraphEdge[];
}

// 某资产在本任务探索图里关联到的意图/事实/发现（覆盖图节点抽屉用）。
export interface CoverageAssetRef {
  id: number;
  kind: string;
  state: string;
  summary: string;
  source_task_id?: string;
  inherited?: boolean;
}
export interface CoverageAssetRefs {
  intents: CoverageAssetRef[];
  facts: CoverageAssetRef[];
  findings: CoverageAssetRef[];
}

// ---- Workspace file manager (workDir) ----
export interface WorkspaceEntry {
  name: string;
  path: string; // workspace-relative, forward slashes
  dir: boolean;
  size: number;
  mtime: number; // unix millis
}
export interface WorkspaceListing {
  path: string;
  entries: WorkspaceEntry[];
}
export interface WorkspaceFile {
  path: string;
  size: number;
  binary: boolean;
  too_large?: boolean;
  content?: string;
}

// 任务测试范围的一条（覆盖度分母 + 授权边界）。
export interface TaskScopeRow {
  id: number;
  task_id: number;
  kind: "company" | "root_domain" | "subdomain" | "ip" | "cidr" | "icp" | "keyword";
  company_id?: number;
  company_name?: string; // 后端 JOIN companies 解析，仅 kind=company 有值
  domain?: string;
  net?: string;
  value?: string;
  source: "auto" | "agent" | "manual";
  reason?: string;
}

export type CompanyScopeKind = "domain" | "ip" | "cidr" | "icp" | "keyword";

// 新增企业时提交的结构化资产范围规则。
export interface CompanyScopeRule {
  kind: CompanyScopeKind;
  value: string;
}

// 资产范围写入的结果。errors 是本次提交里不合法的行；warnings 是与本次提交无关、
// 但会让归属结果不符合预期的既有数据问题（如 ip 字段存了主机名的资产）。
export interface CompanyScopeMutation {
  added: number;
  skipped: number;
  invalid: number;
  errors?: string[];
  warnings?: string[];
}

// 公司资产范围规则的一条（归属唯一真值来源）。
export interface ScopeRow {
  id: number;
  company_id: number;
  kind: CompanyScopeKind;
  domain?: string; // kind=domain 时有值
  net?: string; // kind=ip|cidr 时有值
  value?: string; // kind=icp|keyword 时可能由后端直接返回
  raw: string; // 原始用户输入，用于显示和回填
  reason?: string;
}

// 企业：type=company 的资产节点 + 图标 + 资产计数 + 资产范围规则。
export interface Company {
  id: number;
  name: string;
  logo?: string; // 远程图标 URL；空则前端用名称首字母
  asset_count: number;
  scope?: ScopeRow[];
}

// ---- Exploration graph (per task) ----
export type ExploreKind = "task" | "begin" | "goal" | "intent" | "fact" | "finding" | "hint" | "digest";
export type GoalState = "open" | "met" | "abandoned";
export type IntentState = "open" | "running" | "paused" | "done" | "blocked" | "exhausted" | "stopped";
export type FindingState = "confirmed" | "dismissed";
export type HintState = "active" | "consumed";
export type ExploreRel = "spawns" | "derived_from" | "yields" | "proves" | "covers";

export interface TaskNode {
  id: string;
  type: ExploreKind;
  payload?: string;
  priority: number; // 0..10
  state: string; // GoalState | IntentState | FindingState | HintState
  origin: string;
  ts: string;
  source_task_id?: string;
  inherited?: boolean;
  delete_reason?: string; // 意图假删除(state='deleted')时的删除原因
  blocked_reason?: string; // 意图为什么停（撞步数上限/运行超时/任务收尾/被终止/出错）
}

// 播报板一页:按创建顺序分页的节点 + 这一页涉及的边 + 边另一端的节点(refs,按 id 索引),
// 这样每条播报都能说清「从哪来、产出了什么」,而不用把整张图拉下来。
export interface ExplorationNodePage {
  items: TaskNode[];
  total: number;
  page: number;
  size: number;
  edges: Edge[];
  refs: Record<string, TaskNode>;
  // 节点 id → 该节点锚定的资产(播报板展开时顺带展示,含本页节点与其邻居)。
  assets: Record<string, FindingAsset[]>;
}

export interface ExplorationNodeQuery {
  page?: number;
  size?: number;
  kinds?: ExploreKind[];
  states?: string[];
  q?: string;
  order?: "asc" | "desc";
}

// 目标管理卡片用的目标(后端已把 payload 拆成 text/vulnclass)。
export interface TaskGoal {
  id: string;
  text: string;
  vulnclass?: string;
  state: string; // GoalState
  origin?: string;
  ts: string;
}

// 约束管理卡片用的操作约束(allow=允许 / deny=禁止)。
export type ConstraintKind = "allow" | "deny";
export interface TaskConstraint {
  id: string;
  kind: ConstraintKind;
  text: string;
  origin?: string;
  ts?: string;
}

// ---- Findings ----
export type Severity = "critical" | "high" | "medium" | "low";

// 漏洞处置状态:待处理 / 处理中 / 已确认 / 已处理 / 已修复 / 误报 / 忽略 / 重复 / 风险接受。
export type FindingStatus =
  | "pending"
  | "in_progress"
  | "confirmed"
  | "resolved"
  | "fixed"
  | "false_positive"
  | "ignored"
  | "duplicate"
  | "risk_accepted";

// FindingAsset 是一个漏洞绑定的资产(已在后端预渲染 label)。
export interface FindingAsset {
  id: string;
  type: string;
  label: string;
}

export interface Finding {
  traffic_count?: number;
  evidence_version?: number;
  report_evidence_version?: number;
  report_stale?: boolean;
  id: string;
  finding_id?: string; // 独立 findings 表的行 id,状态更新的句柄(任务内旧节点可能缺失)
  vulnclass: string;
  name?: string; // 漏洞名称;为空时展示回退到 vulnclass
  severity: Severity;
  status: FindingStatus;
  summary: string;
  evidence: string;
  report?: string; // 详细报告(Markdown);仅详情接口返回,列表为空
  intent_id?: string;
  param_id?: string;
  task_id?: string;
  task_description?: string;
  source_task_id?: string;
  inherited?: boolean;
  assets?: FindingAsset[];
  ts: string;
}

// FindingsPage 是发现列表的服务端分页响应。
export interface FindingsPage {
  items: Finding[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingGroup {
  task_id: string | number | null;
  task_name?: string; // 可选任务名称;空/缺省=未命名
  task_description: string;
  task_status: string;
  count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingGroupsPage {
  items: FindingGroup[];
  total: number;
  finding_total: number;
  page: number;
  page_size: number;
}

export interface FindingDeepenResponse {
  task_id: string;
  intent_id: string;
  state: IntentState;
  queued: boolean;
}

// FindingStats 是发现全表聚合(统计卡 + 漏洞类型下拉),服务端计算,不受分页影响。
export interface FindingStats {
  total: number;
  pending: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  vulnclasses: string[];
  tasks: FindingTaskOption[];
}

// FindingTaskOption 是发现页「按任务」筛选下拉的一项:有漏洞的任务(描述为空表示任务已删除,
// 前端回退展示 id)及其漏洞条数。
export interface FindingTaskOption {
  id: string | number;
  name?: string; // 可选任务名称;空/缺省=未命名
  description: string;
  count: number;
}

// FindingQuery 是发现列表分页/筛选/排序参数。
export interface FindingQuery {
  page: number;
  pageSize: number;
  severity?: "all" | Severity;
  status?: "all" | FindingStatus;
  vulnclass?: string;
  task?: string; // 任务 id;"all"/空 = 不按任务筛选
  query?: string;
  sort?: "severity" | "time";
  // 资产树节点 key;选中一个节点 = 选中它的整棵子树。空 = 不按资产筛选。
  assetScope?: string;
}

// ---- Findings by asset (资产视图) ----
export type FindingAssetKind = "company" | "root_domain" | "subdomain" | "ip" | "service" | "app" | "endpoint" | "none";

// FindingAssetNode 是资产树的一个节点。key 形如 a:<id>(资产)、c:<id>(企业)、
// r:<domain>(库里没有资产行的根域名)、__none__(未关联资产)。
export interface FindingAssetNode {
  key: string;
  parent?: string;
  kind: FindingAssetKind;
  label: string;
  asset_id?: number;
  company_id?: number;
  self: number; // 直接挂在该资产上的发现数
  total: number; // 含子孙、按发现去重
  critical: number;
  high: number;
  medium: number;
  low: number;
  last_found_at: string;
}

export interface FindingAssetTree {
  nodes: FindingAssetNode[];
  finding_total: number;
  truncated: boolean;
  dropped_kinds?: string[];
}

// FINDING_UNASSIGNED_ASSET 与后端 db.FindingUnassignedAsset 对应。
export const FINDING_UNASSIGNED_ASSET = "__none__";

// ---- Activity / sessions ----
export type ActivityKind =
  | "tool_use"
  | "tool_result"
  | "text"
  | "thinking"
  | "result"
  | "user"
  | "intent" // LLM-generated exploration objective leading a worker session (UI-synthesized)
  | "round" // planner round boundary marker (engine-emitted)
  | "usage" // live cumulative token usage (per model turn); not rendered
  | "llm_switch" // automatic/manual task-level LLM switch
  | "llm_failover" // task-level provider switch / chain exhaustion audit event
  | "intercept_request"; // user-approval request from the intercept layer

// ChatAttachment 是一次上传的文件:path 相对该会话/任务工作目录(即 agent 的 CWD)。
export interface ChatAttachment {
  name: string;
  path: string;
  size: number;
  abs?: string; // 绝对路径(scope=staging 暂存上传时返回;建任务前把它写进描述)
}

export interface Activity {
  seq: number;
  intent_id?: string;
  worker: string; // session owner: planner | mainagent | work#1 ...
  ts: string;
  kind: ActivityKind;
  tool?: string;
  tool_use_id?: string;
  is_error?: boolean;
  summary: string;
  detail?: string;
  metadata?: {
    llm_transition?: LLMTransition;
  };
  source_task_id?: string;
  inherited?: boolean;
  main_seg?: number; // main-agent conversation segment (present only on worker="mainagent" rows)
  // token usage (present only on kind='result')
  input_tokens?: number;
  output_tokens?: number;
  cache_read_tokens?: number;
  cache_write_tokens?: number;
}

export interface LLMAuditProfile {
  id: number;
  name: string;
  format: string;
  model: string;
}

export interface LLMTransition {
  mode: "automatic" | "manual" | "exhausted";
  reason: string;
  previous?: LLMAuditProfile;
  next?: LLMAuditProfile;
}

export interface TaskLLMResolution {
  profile_id?: number;
  name: string;
  format: string;
  model: string;
  source: "task_chain" | "agent_binding" | "global_profile" | "environment" | "global";
  available: boolean;
  reason?: string;
}

export interface TaskLLMResolutions {
  mainagent: TaskLLMResolution;
  planner: TaskLLMResolution;
  worker: TaskLLMResolution;
}

// ---- Agent triggers (P3 调度，仅自定义 agent) ----
export interface AgentTrigger {
  id: number;
  agent_key: string;
  enabled: boolean;
  interval_sec: number; // 定时:每 N 秒(0=不定时)
  on_finding: boolean; // 任意任务发现 finding 时触发
  on_goal_met: boolean; // 任意任务达成目标时触发
  on_task_timeout: boolean; // 任意任务超时时触发
  on_tool_call: boolean; // 选中工具被调用(执行完成)时触发
  on_task_create: boolean; // 任意任务被创建时触发
  interval_message: string; // 各触发条件的独立用户消息
  finding_message: string;
  goal_message: string;
  task_timeout_message: string;
  tool_call_message: string;
  task_create_message: string;
  tool_names: string[]; // on_tool_call 选中的工具 key(至少一个)
  last_fire?: string;
}

// ---- Conversations (chat page) ----
export interface ActiveFindingRetest {
  id: number;
  finding_id: string;
  conversation_id: number;
  status: "pending" | "running";
}

export interface FindingRetest {
  id: number;
  finding_id: number;
  conversation_id: number | null;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  verdict: "" | "reproduced" | "fixed" | "inconclusive";
  notes: string;
  summary: string;
  evidence: string;
  error: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
}

// 批量复测（v0.4.27）：候选清单条目 + 漏洞最新复测状态。
export interface RetestCandidate {
  id: number;
  vulnclass: string;
  name: string;
  severity: Severity;
  summary: string;
}

// 数据文件在线预览（v0.4.41）：后端按扩展名解析 JSON/JSONL/CSV/TSV/文本。
export interface DataPreviewPayload {
  type: "json" | "jsonl" | "csv" | "text";
  name: string;
  kind: string;
  bound_finding: number;
  total_rows: number;
  truncated: boolean;
  columns?: string[];
  rows?: unknown[][];
  text?: string;
  total_size: number;
}

export interface RetestState {
  finding_id: number;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  verdict: "" | "reproduced" | "fixed" | "inconclusive";
}

export interface Conversation {
  id: number;
  running?: boolean; // live server state, returned with the conversation list
  agent_key: string;
  title: string;
  llm_profile_id?: number;
  pinned?: boolean;
  pinned_at?: string | null;
  created_at: string;
  updated_at: string;
}

// ---- Backend logs (/logs page) ----
export interface LogLine {
  seq: number;
  db_id?: number; // server_logs.id; present for DB-persisted lines
  ts: string;
  level: "info" | "warn" | "error";
  tag: string;
  text: string;
}

export type SessionRole = "mainagent" | "planner" | "worker" | "system";
export type SessionStatus = "running" | "paused" | "done" | "blocked" | "exhausted" | "pending" | "stopped" | "deleted";

// Daily token aggregate bucket (GET /api/tokens/daily).
export interface DailyTokenBucket {
  date: string; // "YYYY-MM-DD"
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// Per-worker token usage (GET /api/exploration/tokens).
export interface TokenUsage {
  worker: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface SessionTokenUsage {
  session: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface BatchControlItem {
  id: string;
  ok: boolean;
  status?: string;
  queued?: boolean;
  error?: string;
}

// 批量改分类的逐任务结果。失败只可能是任务已被删除，分类本身的写入是原子的。
export interface BatchCategoryItem {
  id: string;
  ok: boolean;
  error?: string;
}

// Whole-task (all agents) token aggregate.
export interface TokenTotal {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// 任务级证据附件（v0.4.9）：截图/数据样本/日志，随报告导出证据包。
export interface TaskArtifact {
  id: number;
  task_id: string;
  finding_id?: number;
  name: string;
  kind: string; // image|document|spreadsheet|presentation|pdf|data|log|html|other
  mime?: string;
  size_bytes: number;
  sha256?: string;
  source_url?: string;
  note?: string;
  // 文档预览（v0.4.21）：Office/PDF 取样转图片的状态与页数。
  preview_state?: "pending" | "ready" | "failed" | "skipped" | "";
  preview_pages?: number;
  preview_error?: string;
  created_at: string;
}

// 任务级目标登录凭据（创建时输入；API 只回传视图，密码/TOTP 永不返回）。
export interface TaskAuthConfigInput {
  enabled: boolean;
  login_url: string;
  method: "POST" | "GET";
  content_type: "json" | "form";
  username_field?: string;
  password_field?: string;
  username?: string;
  password?: string;
  totp_secret?: string;
  extra_fields?: Record<string, string>;
  headers?: Record<string, string>;
  success_status?: number;
  success_contains?: string;
}

// API 返回的脱敏视图：has_password / has_totp 表示"配过"，不暴露内容。
export interface TaskAuthConfigView {
  enabled: boolean;
  login_url: string;
  method: string;
  content_type: string;
  username_field?: string;
  password_field?: string;
  username?: string;
  has_password?: boolean;
  has_totp?: boolean;
  extra_fields?: Record<string, string>;
  headers?: Record<string, string>;
  success_status?: number;
  success_contains?: string;
}

// 登录自检结果（POST /api/tasks/{id}/auth-check）。
export interface AuthCheckResult {
  ok: boolean;
  status_code?: number;
  matched: boolean;
  detail: string;
  elapsed_ms: number;
  used_totp?: boolean;
  checked_at: string;
}

// 单任务成本估算（GET /api/tokens/cost?task=）。金额按内置参考价换算，
// 仅用于相对对比；unpriced_models 非空说明有模型不在定价表，成本被低估。
export interface TaskCostEstimate {
  task: { task_id: string; calls: number; input_tokens: number; output_tokens: number };
  cost_usd: number;
  unpriced_models: string[];
  pricing_note: string;
}

// Global per-profile token spend from the llm_usage ledger (GET /api/tokens/usage).
export interface ProfileUsage {
  profile_name: string;
  calls: number;
  tasks: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// One (profile, UTC day) token bucket for the dashboard's daily chart (new source).
export interface ProfileDayUsage {
  profile_name: string;
  date: string; // YYYY-MM-DD
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
}

// Response of GET /api/tokens/usage — the dashboard's "new" (llm_usage) token view.
export interface UsageStats {
  by_profile: ProfileUsage[];
  daily: ProfileDayUsage[];
}

// Per-model token usage for one task (GET /api/llm/records/by-model), from the
// always-on llm_usage metering ledger. calls = number of LLM calls on this model.
export interface ModelTokenStat {
  model: string;
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

export interface Session {
  id: string;
  role: SessionRole;
  title: string;
  status: SessionStatus;
  live: boolean;
  last_activity: string;
  intent_id?: string;
  source_task_id?: string;
  inherited?: boolean;
  seg?: number; // main-agent session: which conversation segment (0 = original)
}

// ---- Security ----
export interface AuditEntry {
  ts: string;
  tool: string;
  action: "allow" | "block";
  reason?: string;
  command?: string;
}

export interface Audit {
  entries?: AuditEntry[];
  attributions?: Record<string, number>;
}

// ---- Traffic ----
export interface TrafficExchange {
  id: string;
  ts: string;
  host: string;
  method: string;
  url: string;
  status: number;
  content_type: string;
  resp_len: number;
}

export interface TrafficResp {
  enabled: boolean;
  proxy?: string;
  count?: number; // global total (unfiltered)
  total?: number; // rows matching the current filter (for pagination)
  page?: number;
  size?: number;
  exchanges?: TrafficExchange[];
}

// Full raw request/response of one exchange (lazy-loaded on row select).
export interface TrafficDetail {
  req: string;
  resp: string;
}

// One distinct recorded host with its exchange count (target picker).
export interface TrafficHost {
  host: string;
  count: number;
}

// ---- App settings (runtime toggles) ----
export interface Settings {
  traffic_capture: boolean;
  agent_traffic_binding: boolean; // Agent 自动绑定流量证据，默认关闭；不影响人工绑定
  llm_record: boolean; // LLM 录制开关（默认关）；关闭时不记录任何 LLM 调用
  // Web search. brave_key_set / tavily_key_set reflect whether a key is stored
  // (the values are never returned). On PUT, send the corresponding field to set/clear.
  web_search_enabled: boolean;
  web_search_backend: string; // "ddgs" | "brave-free" | "tavily" | "deepseek"
  brave_key_set: boolean;
  tavily_key_set: boolean;
  // write-only: only sent on PUT to store/clear the key.
  brave_search_api_key?: string;
  tavily_search_api_key?: string;
  // 独立出口代理(http/https/socks5)，用于访问搜索端点；与记录流量的 MITM 代理无关。空=直连。
  web_search_proxy?: string;
  // 全局出口代理(http/https/socks5，可带 user:pass)，所有目标流量走它。开启流量捕获时作为
  // MITM 上游；关闭捕获时直接注入 agent 的 bash/WebFetch。空=直连。
  global_proxy?: string;
  // 装机代理(http/https/socks5)，仅用于宿主工具安装时的 apt/curl/GitHub 下载。
  // 与目标流量代理、搜索代理、LLM 代理完全独立。空=直连。
  install_proxy?: string;
  python_interpreter?: string; // 自定义脚本工具的 python 解释器路径(空=运行时检测)
  workers?: number; // 并发工作 agent 数(默认3)；对之后启动的任务生效
  // 冷节点压缩的输出预算(思考+正文共用)与单次墙钟超时。0=用默认值
  // (32768 token / 1200 秒)。思考型模型的思考长度随这个预算线性膨胀,
  // 预算给小了模型会一直想、正文一个字都吐不出来。
  compaction_max_tokens?: number;
  compaction_timeout_seconds?: number;
  // 单次压缩请求的成员节点数上限。思考型模型能否收尾取决于单次输入规模
  // (实测 9 节点正常、26 节点把 32768 预算烧光也不出正文),所以要切分。
  compaction_max_members?: number;
  // B10:压缩器钉住的 LLM 配置 id。0/未设置=跟随任务链上的规划器配置（历史行为）；
  // >0=压缩调用永远跑在指定配置上，不参与任务链轮转。
  compactor_profile_id?: number;
  // 任务并发上限:同时「运行中」的任务数上限。关闭=不限;开启后新建任务超限则排队,有空位自动启动。
  task_concurrency_enabled?: boolean; // 默认 false
  task_concurrency_limit?: number; // 开启后默认 5
  // 任务自动收尾（v0.5.0）：连续无新增 / 覆盖率达标 / 最大规划轮数。
  auto_finish_enabled?: boolean; // 默认 true
  auto_finish_idle_rounds?: number; // 默认 3，范围 2–20
  auto_finish_min_rounds?: number; // 默认 5，范围 1–50
  auto_finish_coverage_pct?: number; // 默认 0=关闭，1–100
  auto_finish_max_rounds?: number; // 默认 80，0=不限
  // 意图级软预算（v0.4.28）：单意图累计 token 到顶注入收尾提醒（不杀进程）。
  intent_budget_enabled?: boolean; // 默认 true
  intent_budget_tokens?: number; // 默认 3000000，范围 500000–20000000
  // 证据逐字回验（v0.4.29）：off=关闭 / warn=只提示（默认）/ block=critical/high 无出处打回。
  finding_evidence_verify?: "off" | "warn" | "block";
  // 工具输出注入告警（v0.4.29）：命中高精度注入特征时提醒模型「当数据不当指令」。
  tool_output_injection_guard?: boolean; // 默认 true
  // LLM 轮询(故障转移)。默认关；开启后「未指定模型」的 agent 在当前配置不可用
  // （余额不足/key 失效/限流/服务异常）时自动切到下一个配置。
  llm_pool_enabled?: boolean; // 默认 false
  // 绑定了指定配置的 agent/任务失败时是否也回落到轮询链。默认 false = 绑定即独占。
  llm_pool_bind_fallback?: boolean;
  // 操作约束注入范围(默认都开):把任务的 allow/deny 约束拼进对应 agent 的系统提示。
  constraints_inject_planner?: boolean;
  constraints_inject_worker?: boolean;
  // 实验功能:noa 模型驱动上下文压缩(默认关)。开启后平台接入的四类 agent(planner/
  // worker/主 agent/对话)由 noa 接管上下文压缩,取代内置 compaction;每 run 读一次,对
  // 之后启动的 run 生效。
  noa_compaction?: boolean;
  // ---- 漏洞 IM 推送（渠道本身是独立资源，见 /api/notify/*，这里只有三项全局配置）----
  notify_enabled?: boolean; // 推送总开关，默认开；用于维护期一键止血
  notify_public_base_url?: string; // 漏洞详情回链的外部访问地址；空=消息不带回链
  notify_digest_interval_min?: number; // 汇总模式周期（分钟），默认 30
  // ---- 漏洞情报/回连（net_context 工具读取展示给 agent）----
  egress_hint?: string; // 对外可达地址说明(公网 IP/宿主内网地址等,自由文本)
  egress_port_map?: string; // 端口映射说明(容器端口→宿主端口)
}

// ---- 漏洞 IM 推送 ----

// NotificationFilter 是渠道的过滤条件，字段全部可选，缺省即不过滤。
// 后端对所有字段都不加校验：配置畸形时按「命中」处理（宁可多推不可漏推）。
export interface NotificationFilter {
  min_severity?: string; // "" | low | medium | high | critical
  task_ids?: number[]; // 空=不限；非空则要求与漏洞所属任务有交集
  asset_ids?: number[]; // 空=不限；非空则要求与漏洞锚定资产有交集
  vulnclass_include?: string[]; // 空=全收；非空则要求漏洞类型命中任一关键词（大小写不敏感子串）
  vulnclass_exclude?: string[]; // 命中任一关键词即排除（排除优先于包含）
  on_status_change?: boolean; // 是否也接收漏洞处置状态变更事件
}

// NotificationChannel 是一个渠道实例。config 的字段随 kind 而异，
// 且凭据字段在读取时被替换成 "__masked__" 开头的掩码值——原样回传即表示「不改」。
export interface NotificationChannel {
  id: number;
  name: string;
  kind: string;
  enabled: boolean;
  mode: "realtime" | "digest";
  config: Record<string, unknown>;
  filter: NotificationFilter;
  rate_per_min: number;
  created_at: string;
  updated_at: string;
  // secret_keys 由后端按渠道类型给出，前端据此渲染密码框与「留空即不改」提示，
  // 不硬编码任何渠道知识。
  secret_keys: string[];
}

// NotificationKind 是 /api/notify/meta 返回的渠道类型元数据。
export interface NotificationKind {
  kind: string;
  default_rate_per_min: number;
  secret_keys: string[];
}

export interface NotificationMeta {
  kinds: NotificationKind[];
  enabled: boolean;
  public_base_url: string;
  digest_interval_min: string;
  defaults: { digest_interval_min: number };
  stats: {
    channels: number;
    channels_on: number;
    pending: number;
    failed: number;
    sent_today: number;
    backlog_age_ms: number;
  };
}

// NotificationDelivery 是一条投递记录，用于投递历史与失败重发。
export interface NotificationDelivery {
  id: number;
  finding_id: string;
  event_kind: string; // finding_created | finding_status_changed
  channel_id: number;
  channel_name: string;
  channel_kind: string;
  state: "pending" | "sending" | "sent" | "failed" | "skipped";
  attempts: number;
  last_error: string;
  batch_id?: number;
  created_at: string;
  sent_at?: string;
  next_attempt_at: string;
  title: string;
  severity: string;
}

// ---- LLM config ----
export interface LLMProfile {
  id: string;
  name: string;
  format: "openai" | "anthropic" | "openai-responses";
  base_url?: string;
  proxy?: string;
  model: string;
  api_key_hint?: string;
  rate_per_second: number;
  rate_per_minute: number;
  context_window_k?: number;
  // 思考开关(thinking.type): ""=不发送(默认) | "disabled"=关闭 | "enabled"=开启
  thinking_type?: string;
  // 思考强度: ""=不发送(默认) | "low"/"medium"/"high"/"xhigh"/"max"
  reasoning_effort?: string;
  is_default: boolean;
  // 轮询顺位：越大越先被选中。激活配置恒为链首，与本值无关。
  priority?: number;
  // true = 不作为故障转移目标（仍可被 agent/任务显式绑定使用）。
  pool_exclude?: boolean;
  // true（默认）= 流式(SSE) | false = 真·非流式(stream:false，一次性返回)。
  streaming?: boolean;
  // 单次回复的输出上限(token)。0 = 不发送该字段，由服务端默认值决定。
  // 注意与 context_window_k 区分：后者是模型总容量，只在本地用于压缩阈值。
  max_tokens?: number;
  // 上限用哪个请求字段名，仅 format="openai" 有意义：
  // ""=max_tokens(默认) | "max_completion_tokens"(OpenAI 推理模型只认它)
  max_tokens_field?: string;
  // 自定义会话头名：非空时每次请求带该 HTTP 头，头值=当前会话/意图的 session id。
  // ""=不发送。用于按 session-id 头做提示缓存/粘性路由的网关。
  session_header_key?: string;
  // LLM 请求的 User-Agent：非空时替换每个模型请求的 UA；""=保持 SDK/Go 默认。
  // 用于网关/WAF 直接拦截 Go-http-client 默认 UA 的场景。
  user_agent?: string;
  // 本配置对重试的覆盖（建连/空响应/同 provider 安全窗口）。留空/全 0 = 跟随全局策略。
  retry?: LLMRetryOverride;
}

// ---- LLM 重试策略 ----
// 一层重试的两个旋钮。两者都是「0 = 未配置」：
//   attempts    0=用默认次数 | -1=关闭该层重试 | >0=重试次数
//   interval_ms 0=用默认的指数退避 | >0=改用这个固定毫秒间隔
export interface LLMRetryRule {
  attempts: number;
  interval_ms: number;
}

// 单个 LLM 配置能覆盖的三层（都是「跟着端点走」的重试）。
export interface LLMRetryOverride {
  connect: LLMRetryRule; // 建连重试：连接重置/超时/429/5xx，流开始前
  empty: LLMRetryRule; // 空响应重试：完成但没有任何内容（仅 openai 格式）
  stream: LLMRetryRule; // 同 provider 安全窗口重试：未交付输出前的断流重放
}

// 全局策略 = 上面三层的默认值 + 两层只有全局的：
//   breaker 轮询熔断（attempts=连续几次瞬时失败熔断，interval_ms=固定冷却时长）
//   intent  意图重跑（worker 以 model_error 收场后整条意图重跑）
export interface LLMRetryPolicy extends LLMRetryOverride {
  breaker: LLMRetryRule;
  intent: LLMRetryRule;
}

// ---- LLM 轮询（故障转移）----
// 一个配置在轮询链中的位置与健康状态。state:
//   ok       正常
//   degraded 有连续失败但未达熔断阈值
//   tripped  已熔断，冷却期内被跳过（cooldown_secs 为剩余秒数）
export interface LLMPoolMember {
  profile_id: string;
  name: string;
  model: string;
  format: string;
  priority: number;
  active: boolean; // 是否为当前激活配置（恒为链首）
  excluded: boolean; // pool_exclude：不参与轮询
  state: "ok" | "degraded" | "tripped";
  fails: number;
  trips: number;
  cooldown_secs: number;
  last_error?: string;
  last_at?: string;
}

export interface LLMPoolStatus {
  enabled: boolean;
  bind_fallback: boolean;
  chain: LLMPoolMember[];
}

// ---- Agents ----
export interface Agent {
  id: string;
  key: string; // 内置为 goals/planner/mainagent/worker；自定义为用户自定 key
  name: string;
  description?: string;
  role: string;
  builtin: boolean;
  enabled: boolean;
  llm_profile_id?: number | null; // 绑定的 LLM 配置；null/absent = 跟随任务/会话/全局
  max_turns?: number; // 0 = 无限制
  run_seconds?: number; // worker 单次运行墙钟上限(秒)；0 = 无限制
  web_search?: boolean; // 是否启用网络搜索(受系统全局开关门控)
  interactive_shell?: boolean; // 是否启用交互式 shell(持久 PTY 会话工具族)
  local_exec?: boolean; // 是否可在本机执行命令/写文件(Bash/Write/Edit)；false = 只能经工具操作平台(如派任务)
  // P3 触发后处理策略(仅自定义 agent 有意义)
  trigger_run_mode?: "serial" | "parallel"; // 串行排队 / 每次触发各自并发一个会话
  trigger_merge_mode?: "by_task" | "all" | "none"; // 仅 serial：同任务合并 / 全部合并 / 不合并
  trigger_max_parallel?: number; // 仅 parallel：每 agent 并发上限；0=不限
  // 绑定数量(仅列表接口返回)：可见 MCP / 可见 Skill / 绑定工具
  mcp_count?: number;
  skill_count?: number;
  tool_count?: number;
}

export interface PromptVar {
  name: string;
  description: string;
  example: string;
  source: "exploration" | "runtime" | "distilled";
}

export interface PromptVersion {
  version: number;
  ts: string;
  note: string;
  template_text: string;
}

export interface AgentDetail {
  agent: Agent;
  prompt: string;
  variables: PromptVar[];
  versions: PromptVersion[];
  visibility: { mcp: number[]; skill: string[] };
  // 可绑定的 LLM 配置候选(供「默认模型」下拉)；当前绑定见 agent.llm_profile_id
  llm_profiles?: { id: number; name: string; model: string; is_default: boolean }[];
  wrapup_prompt?: string; // 已保存的收尾提示词(空=用内置默认)
  wrapup_default?: string; // 内置默认收尾提示词(占位/恢复默认)
  wrapup_max_turns?: number; // 已保存的收尾轮数(0=用内置默认)
  wrapup_max_turns_default?: number; // 内置默认收尾轮数(供 "0=默认N" 提示)
  // 任务级超时收尾词(仅 worker/planner，task_timeout_wrapup_supported=true 时才显示该分区)
  task_timeout_wrapup_supported?: boolean;
  task_timeout_wrapup_prompt?: string;
  task_timeout_wrapup_default?: string;
  task_timeout_wrapup_max_turns?: number;
  task_timeout_wrapup_max_turns_default?: number;
}

// ---- MCP ----
export interface MCPServer {
  id: number;
  name: string;
  transport: "stdio" | "http" | "sse";
  command?: string;
  args: string[];
  env: Record<string, string>;
  url?: string;
  enabled: boolean;
  insecure?: boolean; // http: skip TLS cert verification (self-signed servers)
  tools?: string[]; // mcp_tools_cache (names only, for the count)
}

export interface MCPTool {
  name: string;
  description: string;
}

// ---- Skills ----
// Fields align with the agentskills.io open specification.
// description covers both "what the skill does" and "when to use it".
// SkillTags 是 skill 的标准化标签（SKILL.md frontmatter 的 tags 块）。
// cwe / attack 是 MITRE 框架编号，class 是平台内部类别。
export interface SkillTags {
  cwe?: string[];
  attack?: string[];
  class?: string[];
}

export interface SkillItem {
  name: string; // unique key = directory name
  description?: string; // required per spec; covers what + when to use
  license?: string; // optional: SPDX identifier or free text
  compatibility?: string; // optional: environment requirements
  mcps?: string[]; // MCP server names this skill unlocks on load
  tags?: SkillTags; // 标准化标签（CWE/ATT&CK/类别）——能力矩阵与按类检索的入口
  files: string[]; // files in the skill directory
  // 调用统计（skill_usage 账本）。从未被调用过的 skill：calls=0、last_used 缺省。
  calls: number;
  tasks: number; // 加载过它的任务数（chat 会话不计入）
  usage_agents: string[]; // 加载过它的 agent key
  last_used?: string;
}

// SkillCall 是一次 Skill() 调用（单个 skill 的最近调用列表）。
export interface SkillCall {
  ts: string;
  agent_key: string;
  task_id: number; // 0 = 非任务场景（对话会话）
  session_id: string;
  args_len: number;
}

// MissingSkill 是被点名但不存在的 skill —— "想用但没有"的缺口。
export interface MissingSkill {
  skill: string;
  calls: number;
  agents: string[];
  last_used?: string;
}

// ---- Tools (内置工具目录) ----
// key + handler live in Go; only these fields are page-editable. system tools lock
// the key and the parameter *structure* (name/type/required) — the per-param
// description/default and the agent binding are what move.
export interface Tool {
  key: string;
  system: boolean;
  description: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  schema: Record<string, any>; // full JSON-Schema (object with properties)
  agents: string[]; // bound agent keys
  enabled: boolean;
  kind?: "builtin" | "shell" | "command" | "script" | "http"; // 自定义工具类型
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  exec?: Record<string, any>; // 自定义工具执行规格(kind!=builtin)
  deferred?: boolean; // schema 延迟(SearchExtraTools/ExecuteExtraTool)
  calls?: number; // persistent runtime invocation count (older APIs may omit it)
}

// ---- Stats ----
export interface Stats {
  assets: number;
  engine_mode: EngineMode;
  llm_configured: boolean;
  roe_enabled: boolean;
  findings_confirmed: number;
  active_task?: Partial<Task>;
}

// ---- Intercept Rules ----
export type InterceptAction = "allow" | "deny" | "ask" | "judge";
export type InterceptMatchTarget = "tool_name" | "tool_input";
export type InterceptMatchType = "string" | "regex";

export interface InterceptRule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  match_target: InterceptMatchTarget;
  match_type: InterceptMatchType;
  // 本规则适用的工具名列表；空数组/缺省 = 不限工具。仅对 match_target=tool_input 有意义。
  tool_scope?: string[];
  pattern: string;
  action: InterceptAction;
  message: string;
  timeout_enabled: boolean;
  timeout_seconds: number;
  timeout_action: "deny" | "allow";
  created_at: string;
  updated_at: string;
}

// ---- Asset Intercept Rules（资产拦截：全局黑名单） ----
export type AssetInterceptKind =
  | "exact_domain"
  | "exact_ip"
  | "exact_url"
  | "fuzzy_domain"
  | "fuzzy_ip"
  | "fuzzy_url"
  | "cidr";

// action 仅用于任务级规则：block=拦截(禁止测试) allow=允许(白名单)。
export type AssetInterceptAction = "block" | "allow";

// 任务级资产拦截/允许规则的录入项（创建任务、任务详情编辑使用）。
export interface AssetInterceptRuleInput {
  action: AssetInterceptAction;
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  enabled: boolean;
}

export interface AssetInterceptRule {
  id: number;
  enabled: boolean;
  action?: AssetInterceptAction; // 全局规则不带此字段（恒为拦截）；任务级规则区分 block/allow
  kind: AssetInterceptKind;
  pattern: string;
  note: string;
  builtin: boolean;
  created_at: string;
  updated_at: string;
}

export interface InterceptPending {
  decision_source?: "rule" | "model" | "unknown" | "";
  id: number;
  rule_id?: number;
  conversation_id?: number;
  task_id?: string;
  agent_name: string;
  tool_name: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  tool_input: Record<string, any>;
  status: "pending" | "allowed" | "denied" | "timeout";
  reason: string; // 规则 message 或模型判定理由(模型判定带 [模型] 前缀)
  decided_at?: string;
  created_at: string;
}

// JudgeConfig: 模型兜底审批(仅当没有任何拦截规则命中时由模型判断)的全局配置。
export interface JudgeConfig {
  enabled: boolean;
  profile_id: number; // 0 = 跟随激活/默认配置
  prompt: string; // 判定提示词;GET 未设置时后端回填内置模板全文
  timeout_seconds: number; // 模型调用超时
  fail_action: "allow" | "ask" | "deny"; // 模型出错/超时/不可解析时的回退
  ask_timeout_seconds: number; // 模型判 ask 转人工后的审批等待超时
  ask_timeout_action: "allow" | "deny"; // 审批超时后的默认动作
}

// JudgeUsage: 模型兜底审批(judge 通道)的累计 token 用量 + 近 N 天每日序列。
export interface JudgeDayUsage {
  date: string; // YYYY-MM-DD (UTC)
  calls: number;
  input_tokens: number;
  output_tokens: number;
}
export interface JudgeUsage {
  calls: number;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
  daily: JudgeDayUsage[];
}

export interface InterceptApprovalFilter {
  status?: InterceptPending["status"];
  decision_source?: "rule" | "model" | "unknown";
}

// InterceptApprovalRow enriches InterceptPending with conversation/task and rule context.
export interface InterceptApprovalRow extends InterceptPending {
  conv_title: string; // "" if no linked conversation
  conv_agent_key: string; // "" if no linked conversation
  rule_name: string; // "" if rule was deleted
}

// ── 资产同步 (ScopeSentry 数据源) ──────────────────────────────────────────────
export interface SSProject {
  id: string; // MongoDB ObjectID — used as filter.project
  name: string;
  logo?: string;
  AssetCount?: number;
  tag?: string;
}

export interface SSTask {
  id: string;
  name: string; // used as filter.task
  status?: number;
  progress?: number;
  creatTime?: string;
  endTime?: string;
}

// ConvTokenSummary — one conversation's token total (+ profile/date) for merging
// chat usage into the dashboard token stats. GET /api/tokens/conversations.
export interface ConvTokenSummary {
  llm_profile_id: number | null;
  created_at: string;
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  cache_write_tokens: number;
}

// ---- Command recording (Bash execution history) ----
export interface CommandRecord {
  id: number;
  exploration_id: number;
  worker: string;
  tool: string;
  command: string; // raw tool input (JSON)
  output: string;
  is_error: boolean;
  created_at: string;
}

// 单个工具的调用统计（/commands/stats）；errors 为其中失败的次数。
export interface ToolStat {
  tool: string;
  total: number;
  errors: number;
}

// ---- LLM recording ----
export interface LLMRecordItem {
  id: number;
  ts: string;
  model: string;
  profile_name: string;
  session_id: string;
  task_id: string;
  worker: string;
  latency_ms: number;
  input_tokens: number;
  output_tokens: number;
  cache_read: number;
  cache_write: number;
  status: string;
  error?: string;
}

export interface LLMRecordDetail extends LLMRecordItem {
  request_body: string;
  response_body: string;
  // provider 实际收发的 HTTP 原文：请求为 buildBody() 发出的完整 body（含工具
  // schema），响应为原始 SSE 帧。上面的 request_body/response_body 是归一化视图，
  // 丢弃了工具 schema 与 tool_use 块。旧记录为空。
  raw_request?: string;
  raw_response?: string;
}

// One distinct task with its LLM-record count (task picker on the records page).
export interface LLMTask {
  task_id: string;
  count: number;
}

// The exact JSON sent to the review model, retained for all model verdicts.
export interface InterceptReviewInput {
  version: number;
  background?: {
    // worker_summary is retained only for immutable v2/v3 snapshots.
    source: "user_message" | "worker_summary";
    text: string;
    truncated?: boolean;
  };
  // Version 1 snapshots are immutable and remain readable in historical audits.
  task?: {
    task_id: number;
    description: string;
    goal: string;
    constraints: { id: number; kind: string; text: string; origin: string; created_at: number }[];
    truncated?: boolean;
  };
  working_directory?: string;
  worker_intent?: string;
  turn_input?: string;
  background_truncated?: boolean;
  // Legacy v1/v2 snapshots only; v3 never sends execution history.
  history?: {
    tool_use_id: string;
    tool: string;
    arguments_preview: string;
    result: string;
    status: "succeeded" | "failed";
    truncated?: boolean;
  }[];
  history_truncated?: boolean;
  correlation?: "exact" | "ambiguous" | "unavailable";
  tool_name: string;
  arguments: Record<string, unknown>;
}

// Immutable review snapshot plus separately recorded execution outcome.
export interface InterceptAudit {
  model_input?: InterceptReviewInput;
  model_input_digest?: string;
  run_id?: string;
  tool_use_id?: string;
  correlation: "exact" | "ambiguous" | "unavailable";
  input_digest: string;
  user_message: string;
  user_truncated?: boolean;
  context:
    | { kind: string; tool?: string; tool_use_id?: string; text: string; is_error?: boolean; truncated?: boolean }[]
    | null;
  context_truncated?: boolean;
  captured_at: string;
  model_fallback?: boolean;
  initial_action: "allow" | "ask" | "deny";
  initial_reason: string;
  effective_action?: "allow" | "deny";
  decision_reason?: string;
  rule_name?: string;
  config_digest?: string;
  profile_id?: number;
  execution_status: "not_started" | "not_executed" | "awaiting_result" | "succeeded" | "failed" | "unknown";
  output?: string;
  output_truncated?: boolean;
  execution_ended_at?: string;
}
export interface InterceptDetail extends InterceptApprovalRow {
  audit: InterceptAudit | null;
}

export type TrafficEvidenceRole = "baseline" | "proof" | "verification" | "supporting";
export interface TrafficEvidenceRef {
  traffic_id: string;
  role?: TrafficEvidenceRole;
  note?: string;
}
export interface TrafficEvidenceSnapshot {
  id: string;
  source_traffic_id: string;
  captured_at: number;
  url: string;
  method: string;
  status: number;
  content_type: string;
  req_head?: string;
  resp_head?: string;
  req_hash: string;
  resp_hash: string;
  req_len: number;
  resp_len: number;
}
export interface FindingTrafficBinding {
  id: string;
  finding_id: string;
  snapshot_id: string;
  role: TrafficEvidenceRole;
  note: string;
  position: number;
  created_at: string;
  snapshot: TrafficEvidenceSnapshot;
}
export interface FindingTraffic {
  finding_id: string;
  version: number;
  report_version: number;
  bindings: FindingTrafficBinding[];
}
export interface EvidenceBodyPreview {
  content: string;
  offset: number;
  total: number;
  next_offset: number;
  truncated: boolean;
  binary: boolean;
}
export interface FindingTrafficDetail {
  binding: FindingTrafficBinding;
  request: EvidenceBodyPreview;
  response: EvidenceBodyPreview;
}

/** GET /api/update/check —— 当前版本与 GitHub 最新正式版的比较结果。 */
export interface UpdateCheck {
  /** 当前运行的版本；开发构建为 "dev" 或 git describe 的带后缀形式。 */
  current: string;
  /** 运行形态。docker 下换装只作用于容器可写层，重建容器会退回镜像版本。 */
  mode: "docker" | "binary";
  os: string;
  arch: string;
  repo: string;
  /** 是否存在可回滚的上一版本（riddle.old）。 */
  has_backup: boolean;
  /** 本次启动时自更新自举的结论（换装失败 / 已回滚等），无事发生时为空。 */
  boot_notice?: string;
  rolled_back?: boolean;
  /** 查询 GitHub 失败时给出原因，此时下面的字段都不会有。 */
  error?: string;
  latest?: string;
  notes?: string;
  html_url?: string;
  published_at?: string;
  /** 当前平台对应的发布包名，以及该 Release 是否真的带了它。 */
  asset?: string;
  asset_available?: boolean;
  size?: number;
  has_update?: boolean;
  /** 双方版本号是否可比较；开发构建为 false，此时禁用一键更新。 */
  comparable?: boolean;
  /** comparable 为 false 时的说明。 */
  reason?: string;
}

/** /api/update/stream 推送的一条更新进度。 */
export interface UpdateProgress {
  phase: "idle" | "downloading" | "verifying" | "extracting" | "staged" | "failed";
  /** 仅下载阶段有意义（0-100）；其余阶段为 -1。 */
  percent: number;
  message: string;
  version?: string;
  error?: string;
}

// Original execution selected from an approval, never submitted to the reviewer.
export interface InterceptExecution {
  conversation_id: number | null;
  task_id: string | null;
  session: string;
  seq: number;
  items: Activity[];
}

// ── 宿主环境:工具体检 + 一键安装 ──────────────────────────────

/** 一条体检结果。installable=false 表示官方只提供交互式安装器（如 msfconsole）。 */
export interface HostTool {
  id: string;
  name: string;
  bin: string;
  available: boolean;
  installable: boolean;
  purpose: string;
  install?: string;
  kind: "apt" | "github" | "pip" | "manual";
  /** 攻击面分类，页面按它分组。 */
  category: "network" | "dns" | "web" | "cred" | "code" | "pivot" | "oob" | "exploit" | "material" | "runtime" | "middleware" | "";
}

/** 一键安装是否可用，取决于特权助手 riddle-hostd 是否在线（Docker 部署下不在线）。 */
export interface HostenvInstaller {
  available: boolean;
  reason: string;
  /** 助手版本；空串=老版本不支持上报（0.3.22 之前）。 */
  version?: string;
  /** 老助手既不上报版本也无法自我换装，需要重跑一次 install.sh 引导。 */
  upgrade_required?: boolean;
  socket: string;
  proxy: string;
}

export interface HostenvStatus {
  tools: HostTool[];
  deploy_mode: "docker" | "host";
  installer: HostenvInstaller;
}

/**
 * 代理自测结果。ok=false 表示「测了，不通」——不是接口错误。
 * hint 是可执行的修复建议（协议不匹配/认证缺失/超时等）。
 */
export interface ProxyCheckResult {
  ok: boolean;
  proxy: string;
  scheme?: string;
  latency_ms: number;
  status: number;
  /** 出口 IP；用于确认流量确实走了代理。 */
  exit_ip?: string;
  error?: string;
  hint?: string;
}

/** 一次安装任务。log 是累积输出，随轮询增长。 */
export interface InstallJob {
  id: string;
  tool_id: string;
  tool_name: string;
  state: "queued" | "running" | "done" | "failed" | "cancelled";
  exit_code: number;
  error?: string;
  started_at: string;
  ended_at?: string;
  log: string;
}

/** 批量安装结果：started 项已进入助手队列（串行执行），skipped 项带拒绝原因。 */
export interface InstallBatchResult {
  started: { job_id: string; tool_id: string }[];
  skipped: { tool_id: string; reason: string }[];
}

/** 代理池：一个上游代理的持久化条目。 */
export interface ProxyPoolEntry {
  url: string;
  name: string;
  enabled: boolean;
  weight: number;
}

/** 代理池运行态：熔断计数、最近成功/失败时间、熔断剩余秒数。 */
export interface ProxyPoolRunning {
  url: string;
  name: string;
  failures: number;
  weight?: number;
  last_ok?: string;
  last_fail?: string;
  break_remaining?: number;
}

export interface ProxyPoolState {
  entries: ProxyPoolEntry[];
  strategy: string;
  /** 总开关：false 时条目不参与出口选择（回退全局代理/直连）。 */
  enabled: boolean;
  running: ProxyPoolRunning[];
  /** 未被熔断的条目数（0 = 当前全部不可用）。 */
  usable?: number;
  total?: number;
  /** 实际参与出口选择的条目数（socks5 策略过滤后）。 */
  effective_total?: number;
  socks5_blocked?: number;
  socks5_allowed?: boolean;
  capturing: boolean;
  /** 严格出口：池已配置但全部不可用时禁止回退直连（默认开）。 */
  strict?: boolean;
  check_target?: string;
  health_minutes?: number;
  health_cooldown?: number;
  last_check?: { at: string; target: string; count: number; ok_count: number; auto?: boolean } | null;
}

/** 漏洞情报同步配置（读取时凭据已掩码，只回 *_set 布尔）。 */
export interface VulnIntelConfig {
  enabled: boolean;
  nvd_api_key: string;
  nvd_key_set: boolean;
  github_token: string;
  github_token_set: boolean;
  proxy: string;
  poc_enabled: boolean;
  backfill_days: number;
  max_runtime_minutes: number;
  maintenance_proxy: string;
}

/** 保存漏洞情报配置：凭据字段省略=保持不变，传 "-" 清除。 */
export interface VulnIntelConfigPatch {
  enabled?: boolean;
  nvd_api_key?: string;
  github_token?: string;
  proxy?: string;
  poc_enabled?: boolean;
  backfill_days?: number;
  max_runtime_minutes?: number;
}

export interface VulnIntelSource {
  source: string;
  last_sync_at?: string;
  cursor: string;
  total_synced: number;
  last_error: string;
  enabled: boolean;
  error_hint?: string;
  ok?: boolean;
}

export interface VulnIntelStatus {
  enabled: boolean;
  nuclei_templates_dir: string;
  sources: VulnIntelSource[];
  counts: { cves: number; kev: number; pocs: number };
  config?: VulnIntelConfig;
  sync_running?: boolean;
  sync_started_at?: number;
  /** 当前轮阶段描述（「漏洞情报同步中（CVE / KEV / GHSA / PoC）」等；空 = 未在跑）。 */
  sync_phase?: string;
  next_tick_hint?: string;
  nuclei?: {
    dir: string;
    exists: boolean;
    is_git: boolean;
    templates: number;
    updated_at?: string;
    hint: string;
  };
}

/** 回连接收器：单条会话捕获（后端 listener.Session）。 */
export interface ListenerSession {
  id: string;
  remote: string;
  connected_at: string;
  last_active: string;
  bytes_in: number;
  /** 捕获的前 64KB（UTF-8 容错解码）——反弹 shell 初始输出 / OOB 请求行 / banner。 */
  preview: string;
  open: boolean;
}

/** 回连接收器视图（GET /api/listeners 行）。 */
export interface ListenerView {
  name: string;
  port: number;
  started_at: string;
  sessions: ListenerSession[];
}

/** 监听器启动响应：connect_back 是 payload 回连地址的唯一可信来源。 */
export interface ListenerStartResp {
  name: string;
  port: number;
  started_at: string;
  connect_back: ConnectBack;
}

/** C2 出口解析结果：目标该连哪里由平台判定（direct/ssh 中继/manual 三形态）。 */
export interface ConnectBack {
  mode: "direct" | "ssh" | "manual" | string;
  lhost: string;
  lport: number;
  via?: string;
}

/** C2 出口配置（GET /api/c2/config，密码脱敏只回 has_pass）。 */
export interface C2Config {
  mode: "direct" | "ssh" | "manual" | string;
  host: string;
  ssh: string;
  key: string;
  iface: string;
  has_pass: boolean;
}

/** C2 配置保存体：字段为 undefined 时后端保持不变；password 传 "" 清空。 */
export interface C2ConfigPatch {
  mode?: string;
  host?: string;
  ssh?: string;
  password?: string;
  key?: string;
  iface?: string;
}

export interface ProxyPoolSubscription {
  format: "uri" | "clash";
  supported: string[];
  text: string;
  unsupported: number;
  invalid: number;
  /** 订阅里混入的非节点信息条数（剩余流量/到期时间/官网等），已忽略。 */
  ignored?: number;
  note?: string;
  /** 仅 format=clash：完整 YAML（含节点凭据，前端只用于启动 mihomo）。 */
  clash_yaml?: string;
  proxies?: number;
  direct_nodes?: number;
  local_ports?: number[];
  proxy_groups?: number;
  group_names?: string[];
  proxy_providers?: number;
  /** Clash 节点：只有名字与类型，不含账号/地址。 */
  nodes?: { name: string; type: string }[];
  /** Clash 分组：名字、类型与成员节点名（供节点管理页展示）。 */
  groups?: { name: string; type: string; members?: string[] }[];
}

export interface LocalProxyCandidate {
  url: string;
  port: number;
  ok: boolean;
  latency_ms: number;
  exit_ip?: string;
  error?: string;
  source: string;
}

export interface MihomoStatus {
  running: boolean;
  installed: boolean;
  port: number;
  pid: number;
  binary: string;
  config_path: string;
  log_path: string;
  started_at?: string;
  version?: string;
  last_error?: string;
  /** 配置文件里实际生效的出口（从 rules MATCH 反推）。 */
  outbound?: string;
  /** group/node/load-balance/url-test/fallback */
  mode?: string;
  /** 出口组包含的节点名（直接指定节点时为单个）。 */
  nodes?: string[];
  /** 本次启动的 external-controller 端口（只绑回环，用于节点测速）。 */
  controller_port?: number;
}

export interface SSHProvider {
  id: number;
  name: string;
  host: string;
  port: number;
  user: string;
  credential_id?: number;
  created_at?: string;
  status?: string;
  socks_addr?: string;
  started_at?: string;
}

