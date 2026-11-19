"use client";

import * as React from "react";

import {
  ActivityIcon,
  AlertTriangleIcon,
  BugIcon,
  CheckIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ClockIcon,
  ImageIcon,
  ImageOffIcon,
  KeyRoundIcon,
  CoinsIcon,
  ListChecksIcon,
  PencilIcon,
  PlusIcon,
  RefreshCwIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  TargetIcon,
  Trash2Icon,
  XIcon,
} from "lucide-react";

import { StatusBadge } from "@/components/status-badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ArtifactDataViewerDialog } from "@/components/artifact-data-viewer";
import { ZoomableImageDialog } from "@/components/zoomable-image-dialog";
import { Input } from "@/components/ui/input";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { toast } from "sonner";
import type {
  AuthCheckResult,
  AssetInterceptKind,
  AssetInterceptRule,
  Finding,
  ModelTokenStat,
  Stats,
  Task,
  TaskConstraint,
  TaskGoal,
  TaskArtifact,
  TaskAuthConfigView,
  TaskNode,
  TaskScopeRow,
} from "@/lib/types";

// 紧凑格式化 token 数（12345 → 12.3k，2000000 → 2M）。
function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(n >= 10_000_000 ? 0 : 1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k`;
  return String(n);
}

// 缓存命中率 = 缓存读 / 输入（InputTokens 已含 cache_read 子集，故比值在 0–100%）。
function cacheHitRate(cacheRead: number, input: number): string {
  if (input <= 0) return "—";
  return `${Math.round((cacheRead / input) * 100)}%`;
}

// 测试范围一条的显示值：域名 / 网段 / 公司。
function scopeValue(row: TaskScopeRow): string {
  if (row.value) return row.value;
  if (row.domain) return row.domain;
  if (row.net) return row.net;
  if (row.company_id) return row.company_name?.trim() ? row.company_name : `企业 #${row.company_id}`;
  return "—";
}

const SCOPE_KIND_LABELS: Record<TaskScopeRow["kind"], string> = {
  company: "公司",
  root_domain: "根域名",
  subdomain: "子域名",
  ip: "IP",
  cidr: "网段",
  icp: "ICP",
  keyword: "关键词",
};

const SCOPE_SOURCE_LABELS: Record<TaskScopeRow["source"], string> = {
  auto: "自动",
  agent: "Agent",
  manual: "手动",
};

function StatCard({
  label,
  value,
  sub,
  icon: Icon,
}: {
  label: string;
  value: React.ReactNode;
  sub?: string;
  icon: React.ElementType;
}) {
  return (
    <Card className="gap-1.5">
      <CardHeader className="pb-0">
        <CardDescription className="flex items-center gap-1.5">
          <Icon className="size-3.5" /> {label}
        </CardDescription>
        <CardTitle className="text-2xl tabular-nums">{value}</CardTitle>
      </CardHeader>
      {sub && <CardContent className="text-muted-foreground text-xs">{sub}</CardContent>}
    </Card>
  );
}

export function OverviewTab({ taskId }: { taskId: string }) {
  const [task, setTask] = React.useState<Task | null>(null);
  const [stats, setStats] = React.useState<Stats | null>(null);
  const [intents, setIntents] = React.useState<TaskNode[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [coverage, setCoverage] = React.useState<{
    enabled: boolean;
    scope_rows: number;
    denominator: number;
    tested: number;
    pct: number | null;
    by_type: { type: string; total: number; tested: number }[];
  } | null>(null);
  // 正在重跑的意图 id（含 "__all__" 表示批量），用于禁用按钮 + 转圈。
  const [rerunning, setRerunning] = React.useState<Set<string>>(new Set());
  // 测试范围列表 + 新增表单状态。
  const [scope, setScope] = React.useState<TaskScopeRow[]>([]);
  const [scopeKind, setScopeKind] = React.useState<TaskScopeRow["kind"]>("root_domain");
  const [scopeValueInput, setScopeValueInput] = React.useState("");
  const [scopeBusy, setScopeBusy] = React.useState(false);
  const [scopeErr, setScopeErr] = React.useState("");
  // 按模型的 token 用量（来自常开的 llm_usage 计量账本，逐次精确）。
  const [modelTokens, setModelTokens] = React.useState<ModelTokenStat[]>([]);
  // 目标管理：目标列表 + 新增表单 + 行内编辑状态。
  const [goals, setGoals] = React.useState<TaskGoal[]>([]);
  const [goalText, setGoalText] = React.useState("");
  const [goalVuln, setGoalVuln] = React.useState("");
  const [goalBusy, setGoalBusy] = React.useState(false);
  const [goalErr, setGoalErr] = React.useState("");
  const [editingGoalId, setEditingGoalId] = React.useState<string | null>(null);
  const [editText, setEditText] = React.useState("");
  const [editVuln, setEditVuln] = React.useState("");
  // 约束管理：约束列表 + 新增表单 + 行内编辑状态。
  const [constraints, setConstraints] = React.useState<TaskConstraint[]>([]);
  const [conText, setConText] = React.useState("");
  const [conKind, setConKind] = React.useState<TaskConstraint["kind"]>("deny");
  const [conBusy, setConBusy] = React.useState(false);
  const [conErr, setConErr] = React.useState("");
  const [editingConId, setEditingConId] = React.useState<string | null>(null);
  const [editConText, setEditConText] = React.useState("");
  const [editConKind, setEditConKind] = React.useState<TaskConstraint["kind"]>("deny");

  const loadTokens = React.useCallback(async () => {
    try {
      const resp = await api.tokensByModel(taskId);
      setModelTokens(resp.models);
    } catch {
      // 忽略：无 PG 时接口报错，卡片自然为空
    }
  }, [taskId]);

  const loadScope = React.useCallback(async () => {
    try {
      const resp = await api.taskScope(taskId);
      setScope(resp.scope);
    } catch {
      // 忽略：无 asset store 时接口 503，范围卡片自然为空
    }
  }, [taskId]);

  const loadGoals = React.useCallback(async () => {
    try {
      const resp = await api.taskGoals(taskId);
      setGoals(resp.goals);
    } catch {
      // 忽略：瞬时错误，下次轮询重试
    }
  }, [taskId]);

  const addGoal = async () => {
    const text = goalText.trim();
    if (!text) return;
    setGoalBusy(true);
    setGoalErr("");
    try {
      await api.addGoal(taskId, text, goalVuln.trim() || undefined);
      setGoalText("");
      setGoalVuln("");
      await loadGoals();
    } catch (e) {
      setGoalErr(e instanceof Error ? e.message : "添加失败");
    } finally {
      setGoalBusy(false);
    }
  };

  const startEditGoal = (g: TaskGoal) => {
    setEditingGoalId(g.id);
    setEditText(g.text);
    setEditVuln(g.vulnclass ?? "");
  };

  const cancelEditGoal = () => {
    setEditingGoalId(null);
    setEditText("");
    setEditVuln("");
  };

  const saveEditGoal = async (g: TaskGoal) => {
    const text = editText.trim();
    if (!text) return;
    setGoalBusy(true);
    setGoalErr("");
    try {
      await api.updateGoal(taskId, g.id, text, editVuln.trim() || undefined);
      cancelEditGoal();
      await loadGoals();
    } catch (e) {
      setGoalErr(e instanceof Error ? e.message : "保存失败");
    } finally {
      setGoalBusy(false);
    }
  };

  const removeGoal = async (g: TaskGoal) => {
    setGoals((prev) => prev.filter((x) => x.id !== g.id));
    try {
      await api.deleteGoal(taskId, g.id);
    } catch {
      await loadGoals(); // 删除失败：重新拉取还原
    }
  };

  const loadConstraints = React.useCallback(async () => {
    try {
      const resp = await api.taskConstraints(taskId);
      setConstraints(resp.constraints);
    } catch {
      // 忽略：瞬时错误，下次轮询重试
    }
  }, [taskId]);

  const addConstraint = async () => {
    const text = conText.trim();
    if (!text) return;
    setConBusy(true);
    setConErr("");
    try {
      await api.addConstraint(taskId, text, conKind);
      setConText("");
      await loadConstraints();
    } catch (e) {
      setConErr(e instanceof Error ? e.message : "添加失败");
    } finally {
      setConBusy(false);
    }
  };

  const startEditConstraint = (c: TaskConstraint) => {
    setEditingConId(c.id);
    setEditConText(c.text);
    setEditConKind(c.kind);
  };

  const cancelEditConstraint = () => {
    setEditingConId(null);
    setEditConText("");
    setEditConKind("deny");
  };

  const saveEditConstraint = async (c: TaskConstraint) => {
    const text = editConText.trim();
    if (!text) return;
    setConBusy(true);
    setConErr("");
    try {
      await api.updateConstraint(taskId, c.id, text, editConKind);
      cancelEditConstraint();
      await loadConstraints();
    } catch (e) {
      setConErr(e instanceof Error ? e.message : "保存失败");
    } finally {
      setConBusy(false);
    }
  };

  const removeConstraint = async (c: TaskConstraint) => {
    setConstraints((prev) => prev.filter((x) => x.id !== c.id));
    try {
      await api.deleteConstraint(taskId, c.id);
    } catch {
      await loadConstraints(); // 删除失败：重新拉取还原
    }
  };

  const addScope = async () => {
    const value = scopeValueInput.trim();
    if (!value) return;
    setScopeBusy(true);
    setScopeErr("");
    try {
      await api.addTaskScope(taskId, scopeKind, value);
      setScopeValueInput("");
      await loadScope();
    } catch (e) {
      setScopeErr(e instanceof Error ? e.message : "添加失败");
    } finally {
      setScopeBusy(false);
    }
  };

  const removeScope = async (row: TaskScopeRow) => {
    setScope((prev) => prev.filter((s) => s.id !== row.id));
    try {
      await api.deleteTaskScope(taskId, row.id);
    } catch {
      await loadScope(); // 删除失败：重新拉取还原
    }
  };

  const markRerun = (key: string, on: boolean) =>
    setRerunning((prev) => {
      const next = new Set(prev);
      if (on) next.add(key);
      else next.delete(key);
      return next;
    });

  // 重跑单条：置回 open（乐观更新本地 state，3s 轮询兜底），worker 会重新认领、从头再跑。
  const rerunOne = async (id: string) => {
    markRerun(id, true);
    try {
      await api.rerunIntent(taskId, id);
      setIntents((prev) => prev.map((i) => (i.id === id ? { ...i, state: "open" } : i)));
    } catch {
      // 失败忽略：下次轮询仍显示 blocked，用户可再点
    } finally {
      markRerun(id, false);
    }
  };

  // 批量重跑本任务全部 blocked。
  const rerunAll = async () => {
    markRerun("__all__", true);
    try {
      await api.rerunBlocked(taskId);
      setIntents((prev) => prev.map((i) => (i.state === "blocked" ? { ...i, state: "open" } : i)));
    } catch {
      // ignore
    } finally {
      markRerun("__all__", false);
    }
  };

  React.useEffect(() => {
    let cancelled = false;
    let loading = false;

    const load = async () => {
      if (loading) return;
      loading = true;
      try {
        const [taskResp, statsResp, intentsResp, findingsResp] = await Promise.all([
          api.task(taskId),
          api.stats(taskId),
          api.intents(taskId),
          api.findings(taskId),
        ]);
        if (cancelled) return;
        const activeTask = statsResp.active_task;
        setTask(
          activeTask
            ? {
                ...taskResp,
                in_flight: activeTask.in_flight,
                goals_total: activeTask.goals_total,
                goals_met: activeTask.goals_met,
                engine_mode: statsResp.engine_mode ?? activeTask.engine_mode,
                paused: activeTask.paused,
              }
            : taskResp,
        );
        setStats(statsResp);
        setIntents(intentsResp);
        setFindings(findingsResp);
        // coverage is independent + may 503 when no asset store — fetch separately so
        // its failure never blocks the others.
        api
          .taskCoverage(taskId)
          .then((c) => {
            if (!cancelled) setCoverage(c);
          })
          .catch(() => {
            // A transient coverage failure is retried by the next poll.
          });
      } catch {
        // transient errors are ignored; the next poll will retry
      } finally {
        loading = false;
      }
    };

    void load();
    void loadScope();
    void loadTokens();
    void loadGoals();
    void loadConstraints();
    const timer = setInterval(() => {
      void load();
      void loadTokens();
      void loadGoals();
      void loadConstraints();
    }, 3000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [taskId, loadScope, loadTokens, loadGoals, loadConstraints]);

  const running = intents.filter((i) => i.state === "running");
  const open = intents.filter((i) => i.state === "open");
  const blocked = intents.filter((i) => i.state === "blocked");
  const taskFindings = findings.filter((f) => f.task_id === taskId);
  const goalsPct = task?.goals_total ? Math.round(((task.goals_met ?? 0) / task.goals_total) * 100) : 0;
  // token 合计（跨全部模型），用于卡片头部总览。
  const tokenTotals = modelTokens.reduce(
    (acc, m) => {
      acc.input += m.input_tokens;
      acc.output += m.output_tokens;
      acc.cacheRead += m.cache_read_tokens;
      acc.cacheWrite += m.cache_write_tokens;
      acc.calls += m.calls;
      return acc;
    },
    { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, calls: 0 },
  );

  return (
    <div className="flex flex-col gap-4">
      {/* 原始任务描述与目标(创建时填写的),置顶便于随时回看。 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <TargetIcon className="size-4 text-primary" /> 任务描述与目标
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5">
            <div className="font-medium text-muted-foreground text-xs">描述</div>
            <p className="whitespace-pre-wrap break-words text-sm">{task?.description?.trim() || "—"}</p>
          </div>
          <div className="flex flex-col gap-1.5">
            <div className="font-medium text-muted-foreground text-xs">目标</div>
            <p className="whitespace-pre-wrap break-words text-sm">{task?.goal?.trim() || "—"}</p>
          </div>
        </CardContent>
      </Card>
      {/* 任务级登录凭据（v0.4.8）：摘要 + 一次真实登录自检；未配置时不渲染。 */}
      <TaskAuthCard taskId={taskId} />
      {/* 证据附件（v0.4.9）：截图缩略图 + 数据样本/日志列表 + 证据包下载。 */}
      <TaskArtifactsCard taskId={taskId} />
      {/* 目标管理：查看/新增/修改/删除本任务的探索目标。新增与修改会通知规划者并复活任务，
          删除仅通知规划者（不复活）。目标 = 最终可交付/可核验的结果，不是攻击步骤或侦察动作。 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ListChecksIcon className="size-4 text-primary" /> 目标管理
            <span className="font-normal text-muted-foreground text-xs">
              （最终可核验的目标，共 {goals.length} 条；新增/修改会通知规划者并复活任务）
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {/* 新增表单 */}
          <div className="flex flex-wrap items-center gap-2">
            <Input
              className="h-7 min-w-56 flex-1 text-sm"
              placeholder="新增目标，如『拿到管理员账号的越权访问』"
              value={goalText}
              onChange={(e) => setGoalText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addGoal();
              }}
              disabled={goalBusy}
            />
            <Input
              className="h-7 w-32 text-sm"
              placeholder="漏洞类(可选)"
              value={goalVuln}
              onChange={(e) => setGoalVuln(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addGoal();
              }}
              disabled={goalBusy}
            />
            <Button size="sm" variant="outline" disabled={goalBusy || !goalText.trim()} onClick={() => void addGoal()}>
              <PlusIcon className="size-3.5" /> 添加
            </Button>
            {goalErr && <span className="text-red-500 text-xs">{goalErr}</span>}
          </div>
          {/* 目标列表 */}
          {goals.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {goals.map((g) =>
                editingGoalId === g.id ? (
                  <div key={g.id} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
                    <Input
                      className="h-7 min-w-56 flex-1 text-sm"
                      value={editText}
                      onChange={(e) => setEditText(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void saveEditGoal(g);
                        if (e.key === "Escape") cancelEditGoal();
                      }}
                      disabled={goalBusy}
                      autoFocus
                    />
                    <Input
                      className="h-7 w-32 text-sm"
                      placeholder="漏洞类(可选)"
                      value={editVuln}
                      onChange={(e) => setEditVuln(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void saveEditGoal(g);
                        if (e.key === "Escape") cancelEditGoal();
                      }}
                      disabled={goalBusy}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy || !editText.trim()}
                      onClick={() => void saveEditGoal(g)}
                    >
                      <CheckIcon className="size-3.5 text-emerald-500" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy}
                      onClick={cancelEditGoal}
                    >
                      <XIcon className="size-3.5" />
                    </Button>
                  </div>
                ) : (
                  <div key={g.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                    <StatusBadge domain="goal" value={g.state} />
                    <span className="min-w-0 flex-1 break-words">{g.text}</span>
                    {g.vulnclass && (
                      <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-muted-foreground text-xs">
                        {g.vulnclass}
                      </span>
                    )}
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy}
                      onClick={() => startEditGoal(g)}
                    >
                      <PencilIcon className="size-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={goalBusy}
                      onClick={() => void removeGoal(g)}
                    >
                      <Trash2Icon className="size-3.5 text-red-500" />
                    </Button>
                  </div>
                ),
              )}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">暂无目标，添加后规划者会据此派发探索意图并判定达成。</p>
          )}
        </CardContent>
      </Card>
      {/* 操作约束管理：allow=允许 / deny=禁止。约束会在下一轮规划时注入 planner/worker 的系统
          提示以框定探索边界（注入范围可在 系统设置 里按 planner/worker 开关）。改动不即时打断，
          下一轮规划自然读到。 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldAlertIcon className="size-4 text-amber-500" /> 操作约束
            <span className="font-normal text-muted-foreground text-xs">
              （框定 planner/worker 的探索边界，共 {constraints.length} 条；改动下一轮规划生效）
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {/* 新增表单 */}
          <div className="flex flex-wrap items-center gap-2">
            <NativeSelect
              size="sm"
              value={conKind}
              onChange={(e) => setConKind(e.target.value as TaskConstraint["kind"])}
            >
              <NativeSelectOption value="deny">禁止</NativeSelectOption>
              <NativeSelectOption value="allow">允许</NativeSelectOption>
            </NativeSelect>
            <Input
              className="h-7 min-w-56 flex-1 text-sm"
              placeholder="一条操作约束，如『仅测当前端口，不扫其他端口』"
              value={conText}
              onChange={(e) => setConText(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addConstraint();
              }}
              disabled={conBusy}
            />
            <Button
              size="sm"
              variant="outline"
              disabled={conBusy || !conText.trim()}
              onClick={() => void addConstraint()}
            >
              <PlusIcon className="size-3.5" /> 添加
            </Button>
            {conErr && <span className="text-red-500 text-xs">{conErr}</span>}
          </div>
          {/* 约束列表 */}
          {constraints.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {constraints.map((c) =>
                editingConId === c.id ? (
                  <div key={c.id} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
                    <NativeSelect
                      size="sm"
                      value={editConKind}
                      onChange={(e) => setEditConKind(e.target.value as TaskConstraint["kind"])}
                    >
                      <NativeSelectOption value="deny">禁止</NativeSelectOption>
                      <NativeSelectOption value="allow">允许</NativeSelectOption>
                    </NativeSelect>
                    <Input
                      className="h-7 min-w-56 flex-1 text-sm"
                      value={editConText}
                      onChange={(e) => setEditConText(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") void saveEditConstraint(c);
                        if (e.key === "Escape") cancelEditConstraint();
                      }}
                      disabled={conBusy}
                      autoFocus
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy || !editConText.trim()}
                      onClick={() => void saveEditConstraint(c)}
                    >
                      <CheckIcon className="size-3.5 text-emerald-500" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy}
                      onClick={cancelEditConstraint}
                    >
                      <XIcon className="size-3.5" />
                    </Button>
                  </div>
                ) : (
                  <div key={c.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                    <span
                      className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                        c.kind === "allow"
                          ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                          : "bg-red-500/15 text-red-600 dark:text-red-400"
                      }`}
                    >
                      {c.kind === "allow" ? "允许" : "禁止"}
                    </span>
                    <span className="min-w-0 flex-1 break-words">{c.text}</span>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy}
                      onClick={() => startEditConstraint(c)}
                    >
                      <PencilIcon className="size-3.5" />
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      disabled={conBusy}
                      onClick={() => void removeConstraint(c)}
                    >
                      <Trash2Icon className="size-3.5 text-red-500" />
                    </Button>
                  </div>
                ),
              )}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">
              暂无操作约束。建任务时会自动从描述/目标抽取；也可在此手动增删改，用来框定「允许/禁止做哪些操作」。
            </p>
          )}
        </CardContent>
      </Card>
      <TaskInterceptRulesCard taskId={taskId} />
      {coverage?.enabled && coverage.scope_rows > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <TargetIcon className="size-4 text-emerald-500" /> 资产测试覆盖度
              <span className="font-normal text-muted-foreground text-xs">（粗估，仅供参考）</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-baseline gap-3">
              <span className="font-semibold text-2xl tabular-nums">
                {coverage.pct != null ? `${Math.round(coverage.pct * 100)}%` : "—"}
              </span>
              <span className="text-muted-foreground text-sm">
                已测 {coverage.tested} / 范围内 {coverage.denominator}
              </span>
            </div>
            {coverage.pct != null && <Progress value={Math.round(coverage.pct * 100)} />}
            {coverage.by_type.length > 0 && (
              <div className="flex flex-wrap gap-1.5 text-xs">
                {coverage.by_type.map((b) => (
                  <span key={b.type} className="rounded bg-muted px-1.5 py-0.5">
                    <span className="text-muted-foreground">{b.type}</span>{" "}
                    <span className="font-medium tabular-nums">
                      {b.tested}/{b.total}
                    </span>
                  </span>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      )}
      {/* LLM Token 用量：按模型分组，数据来自 llm_records（需开启 LLM 录制）。 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <CoinsIcon className="size-4 text-amber-500" /> LLM Token 用量
            <span className="font-normal text-muted-foreground text-xs">
              （按模型统计{tokenTotals.calls > 0 ? `，共 ${tokenTotals.calls} 次调用` : ""}）
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {modelTokens.length > 0 ? (
            <>
              {/* 合计总览 */}
              <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1 text-sm">
                <span className="tabular-nums">
                  <span className="text-muted-foreground">输入 </span>
                  <span className="font-semibold">{fmtTokens(tokenTotals.input)}</span>
                </span>
                <span className="tabular-nums">
                  <span className="text-muted-foreground">输出 </span>
                  <span className="font-semibold">{fmtTokens(tokenTotals.output)}</span>
                </span>
                <span className="tabular-nums">
                  <span className="text-muted-foreground">缓存读 </span>
                  <span className="font-semibold">{fmtTokens(tokenTotals.cacheRead)}</span>
                </span>
                <span className="tabular-nums">
                  <span className="text-muted-foreground">缓存命中率 </span>
                  <span className="font-semibold text-emerald-500">
                    {cacheHitRate(tokenTotals.cacheRead, tokenTotals.input)}
                  </span>
                </span>
              </div>
              {/* 按模型明细表 */}
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left text-muted-foreground text-xs">
                      <th className="py-1.5 pr-3 font-medium">模型</th>
                      <th className="py-1.5 pr-3 text-right font-medium">调用</th>
                      <th className="py-1.5 pr-3 text-right font-medium">输入</th>
                      <th className="py-1.5 pr-3 text-right font-medium">输出</th>
                      <th className="py-1.5 pr-3 text-right font-medium">缓存读</th>
                      <th className="py-1.5 text-right font-medium">命中率</th>
                    </tr>
                  </thead>
                  <tbody>
                    {modelTokens.map((m) => (
                      <tr key={m.model} className="border-b last:border-0">
                        <td className="max-w-[16rem] truncate py-1.5 pr-3 font-mono text-xs" title={m.model}>
                          {m.model}
                        </td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{m.calls}</td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{fmtTokens(m.input_tokens)}</td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{fmtTokens(m.output_tokens)}</td>
                        <td className="py-1.5 pr-3 text-right tabular-nums">{fmtTokens(m.cache_read_tokens)}</td>
                        <td className="py-1.5 text-right text-emerald-500 tabular-nums">
                          {cacheHitRate(m.cache_read_tokens, m.input_tokens)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          ) : (
            <p className="text-muted-foreground text-sm">暂无 LLM 用量（任务尚未产生调用，或记录仍在写入）。</p>
          )}
        </CardContent>
      </Card>
      {/* 测试范围：覆盖度分母 + 授权边界，可手动增删。 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ShieldCheckIcon className="size-4 text-emerald-500" /> 测试范围
            <span className="font-normal text-muted-foreground text-xs">
              （覆盖度分母 + 授权边界，共 {scope.length} 条）
            </span>
          </CardTitle>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {/* 新增表单 */}
          <div className="flex flex-wrap items-center gap-2">
            <NativeSelect
              size="sm"
              value={scopeKind}
              onChange={(e) => setScopeKind(e.target.value as TaskScopeRow["kind"])}
            >
              <NativeSelectOption value="root_domain">根域名</NativeSelectOption>
              <NativeSelectOption value="subdomain">子域名</NativeSelectOption>
              <NativeSelectOption value="ip">IP</NativeSelectOption>
              <NativeSelectOption value="cidr">网段</NativeSelectOption>
              <NativeSelectOption value="icp">ICP</NativeSelectOption>
              <NativeSelectOption value="keyword">关键词</NativeSelectOption>
              <NativeSelectOption value="company">公司</NativeSelectOption>
            </NativeSelect>
            <Input
              className="h-7 w-56 text-sm"
              placeholder={
                scopeKind === "company"
                  ? "公司名或 id"
                  : scopeKind === "ip" || scopeKind === "cidr"
                    ? "如 10.0.0.1 或 10.0.0.0/24"
                    : scopeKind === "icp"
                      ? "如 京ICP备12345678号-1"
                      : scopeKind === "keyword"
                        ? "如 企业名称关键词"
                        : "如 example.com"
              }
              value={scopeValueInput}
              onChange={(e) => setScopeValueInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") void addScope();
              }}
              disabled={scopeBusy}
            />
            <Button
              size="sm"
              variant="outline"
              disabled={scopeBusy || !scopeValueInput.trim()}
              onClick={() => void addScope()}
            >
              <PlusIcon className="size-3.5" /> 添加
            </Button>
            {scopeErr && <span className="text-red-500 text-xs">{scopeErr}</span>}
          </div>
          {/* 范围列表 */}
          {scope.length > 0 ? (
            <div className="flex flex-col gap-1.5">
              {scope.map((row) => (
                <div key={row.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                  <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-muted-foreground text-xs">
                    {SCOPE_KIND_LABELS[row.kind]}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs">{scopeValue(row)}</span>
                  <span className="shrink-0 text-muted-foreground text-xs">{SCOPE_SOURCE_LABELS[row.source]}</span>
                  {row.task_id.toString() === taskId ? (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-6 shrink-0 px-1.5"
                      onClick={() => void removeScope(row)}
                    >
                      <Trash2Icon className="size-3.5 text-red-500" />
                    </Button>
                  ) : (
                    <span className="shrink-0 text-muted-foreground text-xs">继承</span>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted-foreground text-sm">暂无测试范围，添加后可作为资产覆盖度的分母。</p>
          )}
        </CardContent>
      </Card>
      {/* Heartbeat */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ActivityIcon className="size-4 text-blue-500" /> 心跳
          </CardTitle>
        </CardHeader>
        <CardContent className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <div>
            <div className="text-muted-foreground text-xs">引擎态</div>
            <StatusBadge
              domain="engine"
              value={stats?.engine_mode ?? task?.engine_mode ?? "idle"}
              dot
              className="mt-1"
            />
          </div>
          <div>
            <div className="text-muted-foreground text-xs">运行中 Worker</div>
            <div className="mt-1 font-semibold text-lg tabular-nums">{running.length}</div>
          </div>
          <div>
            <div className="text-muted-foreground text-xs">最近活动</div>
            <div className="mt-1 inline-flex items-center gap-1 text-sm">
              <ClockIcon className="size-3.5" />
              {task?.last_activity ? new Date(task.last_activity).toLocaleTimeString("zh-CN") : "—"}
            </div>
          </div>
          <div>
            <div className="text-muted-foreground text-xs">
              目标 {task?.goals_met ?? 0}/{task?.goals_total ?? 0}
            </div>
            <Progress value={goalsPct} className="mt-2" />
          </div>
          {task?.completed_unix && task.completed_unix > 0 ? (
            <div>
              <div className="text-muted-foreground text-xs">完成时间</div>
              <div className="mt-1 inline-flex items-center gap-1 text-sm">
                <ClockIcon className="size-3.5" />
                {new Date(task.completed_unix * 1000).toLocaleString("zh-CN")}
              </div>
            </div>
          ) : null}
        </CardContent>
      </Card>

      {/* Work set */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <TargetIcon className="size-4" /> 进行中意图
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {running.slice(0, 6).map((i) => (
              <div key={i.id} className="flex items-center gap-2 text-sm">
                <StatusBadge domain="intent" value={i.state} />
                <span className="min-w-0 flex-1 truncate">{i.payload}</span>
              </div>
            ))}
            {running.length === 0 && <p className="text-muted-foreground text-sm">暂无进行中意图</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangleIcon className="size-4 text-amber-500" /> 需要关注
            </CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <div className="font-semibold text-2xl text-red-600 tabular-nums">{taskFindings.length}</div>
              <div className="text-muted-foreground text-xs">确认漏洞</div>
            </div>
            <div>
              <div className="font-semibold text-2xl text-blue-600 tabular-nums">{running.length}</div>
              <div className="text-muted-foreground text-xs">执行中</div>
            </div>
            <div>
              <div className="font-semibold text-2xl tabular-nums">{open.length}</div>
              <div className="text-muted-foreground text-xs">frontier 待领</div>
            </div>
            <div>
              <div className="font-semibold text-2xl text-red-600 tabular-nums">{blocked.length}</div>
              <div className="text-muted-foreground text-xs">被拦意图</div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-sm">
              <BugIcon className="size-4 text-red-500" /> 最近发现
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {taskFindings.slice(0, 6).map((f) => (
              <div key={f.id} className="flex items-center gap-2 text-sm">
                <StatusBadge domain="severity" value={f.severity} dot />
                <span className="min-w-0 flex-1 truncate">{f.summary}</span>
              </div>
            ))}
            {taskFindings.length === 0 && <p className="text-muted-foreground text-sm">暂无发现</p>}
          </CardContent>
        </Card>
      </div>

      {/* Blocked intents — 出错/被拦(如 LLM 网络问题)的意图，可一键重跑：置回 open，
          worker 会重新认领、从头再跑（已写回图谱的数据保留）；任务若已终态/暂停会自动复活。 */}
      {blocked.length > 0 && (
        <Card className="border-red-500/30">
          <CardHeader className="flex-row items-center justify-between gap-2 space-y-0">
            <CardTitle className="flex items-center gap-2 text-sm">
              <AlertTriangleIcon className="size-4 text-red-500" /> 被拦/出错意图
              <span className="font-normal text-muted-foreground text-xs">（共 {blocked.length} 条，可重跑）</span>
            </CardTitle>
            <Button size="sm" variant="outline" disabled={rerunning.has("__all__")} onClick={() => void rerunAll()}>
              <RefreshCwIcon className={`size-3.5 ${rerunning.has("__all__") ? "animate-spin" : ""}`} />
              全部重跑
            </Button>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {blocked.slice(0, 20).map((i) => (
              <div key={i.id} className="flex items-center gap-2 text-sm">
                <StatusBadge domain="intent" value={i.state} />
                <span className="min-w-0 flex-1 truncate">{i.payload}</span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 shrink-0 px-2 text-xs"
                  disabled={rerunning.has(i.id)}
                  onClick={() => void rerunOne(i.id)}
                >
                  <RefreshCwIcon className={`size-3 ${rerunning.has(i.id) ? "animate-spin" : ""}`} />
                  重跑
                </Button>
              </div>
            ))}
            {blocked.length > 20 && (
              <p className="text-muted-foreground text-xs">
                仅显示前 20 条，点「全部重跑」处理剩余 {blocked.length - 20} 条。
              </p>
            )}
          </CardContent>
        </Card>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        <StatCard label="待领意图" value={open.length} icon={ShieldCheckIcon} sub="frontier 开放" />
        <StatCard label="确认发现" value={taskFindings.length} icon={BugIcon} sub="本任务" />
        <StatCard label="意图总数" value={intents.length} icon={AlertTriangleIcon} sub="本任务全部意图" />
      </div>
    </div>
  );
}

const TASK_RULE_KIND_OPTIONS: { value: AssetInterceptKind; label: string; placeholder: string }[] = [
  { value: "exact_domain", label: "域名(全等)", placeholder: "example.gov.cn" },
  { value: "exact_ip", label: "IP(全等)", placeholder: "203.0.113.10" },
  { value: "exact_url", label: "URL(全等)", placeholder: "https://example.com/login" },
  { value: "fuzzy_domain", label: "域名(模糊)", placeholder: ".gov.cn" },
  { value: "fuzzy_ip", label: "IP(模糊)", placeholder: "203.0.113." },
  { value: "fuzzy_url", label: "URL(模糊)", placeholder: "/admin" },
  { value: "cidr", label: "CIDR 网段", placeholder: "192.168.0.0/16" },
];

const TASK_RULE_KIND_LABEL: Record<AssetInterceptKind, string> = Object.fromEntries(
  TASK_RULE_KIND_OPTIONS.map((o) => [o.value, o.label]),
) as Record<AssetInterceptKind, string>;

// TaskInterceptRulesCard 在任务详情总览里管理「任务级资产拦截 / 允许规则」：
// 列表 + 新增 + 行内编辑 + 删除 + 启用开关。规则仅本任务生效，不进全局表。
function TaskInterceptRulesCard({ taskId }: { taskId: string }) {
  const [rules, setRules] = React.useState<AssetInterceptRule[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState("");
  const [newAction, setNewAction] = React.useState<"block" | "allow">("block");
  const [newKind, setNewKind] = React.useState<AssetInterceptKind>("fuzzy_domain");
  const [newPattern, setNewPattern] = React.useState("");
  const [newNote, setNewNote] = React.useState("");
  const [editId, setEditId] = React.useState<number | null>(null);
  const [editAction, setEditAction] = React.useState<"block" | "allow">("block");
  const [editKind, setEditKind] = React.useState<AssetInterceptKind>("fuzzy_domain");
  const [editPattern, setEditPattern] = React.useState("");
  const [editNote, setEditNote] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      setRules(await api.taskInterceptRules(taskId));
    } catch {
      // 忽略瞬时错误
    }
  }, [taskId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function add() {
    if (!newPattern.trim()) return;
    setBusy(true);
    setErr("");
    try {
      await api.createTaskInterceptRule(taskId, {
        action: newAction,
        kind: newKind,
        pattern: newPattern.trim(),
        note: newNote.trim(),
        enabled: true,
      });
      setNewPattern("");
      setNewNote("");
      await load();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  function startEdit(r: AssetInterceptRule) {
    setEditId(r.id);
    setEditAction(r.action ?? "block");
    setEditKind(r.kind);
    setEditPattern(r.pattern);
    setEditNote(r.note);
    setErr("");
  }

  async function saveEdit(r: AssetInterceptRule) {
    if (!editPattern.trim()) return;
    setBusy(true);
    setErr("");
    try {
      await api.updateTaskInterceptRule(taskId, r.id, {
        action: editAction,
        kind: editKind,
        pattern: editPattern.trim(),
        note: editNote.trim(),
        enabled: r.enabled,
      });
      setEditId(null);
      await load();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function remove(r: AssetInterceptRule) {
    setRules((prev) => prev.filter((x) => x.id !== r.id));
    try {
      await api.deleteTaskInterceptRule(taskId, r.id);
    } catch {
      await load();
    }
  }

  async function toggle(r: AssetInterceptRule) {
    setRules((prev) => prev.map((x) => (x.id === r.id ? { ...x, enabled: !x.enabled } : x)));
    try {
      await api.toggleTaskInterceptRule(taskId, r.id, !r.enabled);
    } catch {
      await load();
    }
  }

  const placeholder = TASK_RULE_KIND_OPTIONS.find((o) => o.value === newKind)?.placeholder ?? "";

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheckIcon className="size-4 text-sky-500" /> 任务级资产拦截 / 允许
          <span className="font-normal text-muted-foreground text-xs">
            （仅本任务生效，不进全局；先拦截后允许，共 {rules.length} 条）
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {/* 新增表单 */}
        <div className="flex flex-wrap items-center gap-2">
          <NativeSelect size="sm" value={newAction} onChange={(e) => setNewAction(e.target.value as "block" | "allow")}>
            <NativeSelectOption value="block">拦截</NativeSelectOption>
            <NativeSelectOption value="allow">允许</NativeSelectOption>
          </NativeSelect>
          <NativeSelect size="sm" value={newKind} onChange={(e) => setNewKind(e.target.value as AssetInterceptKind)}>
            {TASK_RULE_KIND_OPTIONS.map((o) => (
              <NativeSelectOption key={o.value} value={o.value}>
                {o.label}
              </NativeSelectOption>
            ))}
          </NativeSelect>
          <Input
            className="h-7 min-w-56 flex-1 text-sm"
            placeholder={placeholder}
            value={newPattern}
            onChange={(e) => setNewPattern(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void add();
            }}
            disabled={busy}
          />
          <Input
            className="h-7 w-36 text-sm"
            placeholder="备注(可选)"
            value={newNote}
            onChange={(e) => setNewNote(e.target.value)}
            disabled={busy}
          />
          <Button size="sm" variant="outline" disabled={busy || !newPattern.trim()} onClick={() => void add()}>
            <PlusIcon className="size-3.5" /> 添加
          </Button>
          {err && <span className="text-red-500 text-xs">{err}</span>}
        </div>
        {/* 规则列表 */}
        {rules.length > 0 ? (
          <div className="flex flex-col gap-1.5">
            {rules.map((r) =>
              editId === r.id ? (
                <div key={r.id} className="flex flex-wrap items-center gap-2 rounded-md border px-2.5 py-1.5">
                  <NativeSelect
                    size="sm"
                    value={editAction}
                    onChange={(e) => setEditAction(e.target.value as "block" | "allow")}
                  >
                    <NativeSelectOption value="block">拦截</NativeSelectOption>
                    <NativeSelectOption value="allow">允许</NativeSelectOption>
                  </NativeSelect>
                  <NativeSelect
                    size="sm"
                    value={editKind}
                    onChange={(e) => setEditKind(e.target.value as AssetInterceptKind)}
                  >
                    {TASK_RULE_KIND_OPTIONS.map((o) => (
                      <NativeSelectOption key={o.value} value={o.value}>
                        {o.label}
                      </NativeSelectOption>
                    ))}
                  </NativeSelect>
                  <Input
                    className="h-7 min-w-56 flex-1 text-sm"
                    value={editPattern}
                    onChange={(e) => setEditPattern(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") void saveEdit(r);
                      if (e.key === "Escape") setEditId(null);
                    }}
                    disabled={busy}
                    autoFocus
                  />
                  <Input
                    className="h-7 w-36 text-sm"
                    placeholder="备注(可选)"
                    value={editNote}
                    onChange={(e) => setEditNote(e.target.value)}
                    disabled={busy}
                  />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy || !editPattern.trim()}
                    onClick={() => void saveEdit(r)}
                  >
                    <CheckIcon className="size-3.5 text-emerald-500" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy}
                    onClick={() => setEditId(null)}
                  >
                    <XIcon className="size-3.5" />
                  </Button>
                </div>
              ) : (
                <div key={r.id} className="flex items-center gap-2 rounded-md border px-2.5 py-1.5 text-sm">
                  <span
                    className={`shrink-0 rounded px-1.5 py-0.5 text-xs ${
                      r.action === "allow"
                        ? "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400"
                        : "bg-red-500/15 text-red-600 dark:text-red-400"
                    }`}
                  >
                    {r.action === "allow" ? "允许" : "拦截"}
                  </span>
                  <span className="shrink-0 text-muted-foreground text-xs">{TASK_RULE_KIND_LABEL[r.kind]}</span>
                  <code className="min-w-0 flex-1 truncate rounded bg-muted px-1.5 py-0.5 text-xs">{r.pattern}</code>
                  {r.note && (
                    <span className="max-w-[120px] shrink-0 truncate text-muted-foreground text-xs">{r.note}</span>
                  )}
                  <Switch checked={r.enabled} onCheckedChange={() => void toggle(r)} />
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy}
                    onClick={() => startEdit(r)}
                  >
                    <PencilIcon className="size-3.5" />
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-6 shrink-0 px-1.5"
                    disabled={busy}
                    onClick={() => void remove(r)}
                  >
                    <Trash2Icon className="size-3.5 text-red-500" />
                  </Button>
                </div>
              ),
            )}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">
            暂无任务级规则。「拦截」命中即禁止测试；「允许」为白名单——配置后本任务只允许命中允许规则的资产（未配置则不启用白名单）。
          </p>
        )}
      </CardContent>
    </Card>
  );
}


// TaskAuthCard 显示任务级登录凭据摘要，并提供一次真实登录自检（后端发真实请求，
// 回显只含状态码/命中说明，不含密码）。未配置凭据时整卡不渲染。
function TaskAuthCard({ taskId }: { taskId: string }) {
  const [cfg, setCfg] = React.useState<TaskAuthConfigView | null>(null);
  const [result, setResult] = React.useState<AuthCheckResult | null>(null);
  const [busy, setBusy] = React.useState(false);
  React.useEffect(() => {
    let alive = true;
    api
      .task(taskId)
      .then((t) => {
        if (alive) setCfg(t.auth_config ?? null);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [taskId]);
  if (!cfg?.enabled) return null;
  const check = async () => {
    setBusy(true);
    try {
      setResult(await api.taskAuthCheck(taskId));
    } catch (e) {
      setResult({ ok: false, matched: false, detail: (e as Error).message, elapsed_ms: 0, checked_at: "" });
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <KeyRoundIcon className="size-4 text-primary" /> 目标登录凭据
          <Button size="sm" variant="outline" className="ml-auto" disabled={busy} onClick={() => void check()}>
            {busy ? "验证中…" : "测试登录"}
          </Button>
        </CardTitle>
        <CardDescription>
          登录接口 {cfg.method} {cfg.login_url} · 用户名 {cfg.username || "—"}
          {cfg.has_password ? " · 密码已保存（不回显）" : ""}
          {cfg.has_totp ? " · 含 TOTP" : ""}。worker 会用它在会话内登录后再测试。
        </CardDescription>
      </CardHeader>
      {result && (
        <CardContent className="text-sm">
          <span className={result.ok ? "text-emerald-600" : "text-red-600"}>
            {result.ok ? "登录成功" : "登录未通过"}
          </span>
          <span className="text-muted-foreground">
            {" "}
            · {result.detail} · {result.elapsed_ms}ms
          </span>
        </CardContent>
      )}
    </Card>
  );
}


// TaskArtifactsCard 任务证据附件（v0.4.9 起；v0.4.15 交互重做）：
// 默认折叠；缩略图走服务端 480px 缩略图（一次拉几十张 3MB 原图会导致部分
// 加载失败）；悬停轻微放大；点击弹层看原图；下载走独立按钮。
function TaskArtifactsCard({ taskId }: { taskId: string }) {
  const [list, setList] = React.useState<TaskArtifact[]>([]);
  const [scanning, setScanning] = React.useState(false);
  const [expanded, setExpanded] = React.useState(false);
  const [preview, setPreview] = React.useState<TaskArtifact | null>(null);
  const [dataPreview, setDataPreview] = React.useState<TaskArtifact | null>(null);
  const [broken, setBroken] = React.useState<Record<number, boolean>>({});
  // v0.4.20：历史/任务级图片批量归属到漏洞。
  const [selected, setSelected] = React.useState<number[]>([]);
  const [findings, setFindings] = React.useState<Finding[]>([]);
  const [assignTo, setAssignTo] = React.useState("0");
  const [assigning, setAssigning] = React.useState(false);
  // v0.4.21：文档预览与筛选。
  const [filter, setFilter] = React.useState<"all" | "image" | "document" | "data" | "file">("all");
  const [docPreview, setDocPreview] = React.useState<{ artifact: TaskArtifact; page: number } | null>(null);
  const load = React.useCallback(
    (alive: { v: boolean }) =>
      api
        .taskArtifacts(taskId)
        .then((items) => {
          if (alive.v) setList(items);
        })
        .catch(() => {}),
    [taskId],
  );
  React.useEffect(() => {
    const alive = { v: true };
    void load(alive);
    return () => {
      alive.v = false;
    };
  }, [load]);
  React.useEffect(() => {
    if (!expanded) return;
    let alive = true;
    api
      .findings(taskId)
      .then((fs) => {
        if (alive) setFindings(fs);
      })
      .catch(() => {});
    return () => {
      alive = false;
    };
  }, [expanded, taskId]);
  const findingOptions = findings
    .filter((f) => f.finding_id && /^\d+$/.test(String(f.finding_id)))
    .map((f) => ({ id: String(f.finding_id), label: `#${f.finding_id} ${f.name || f.vulnclass}` }));
  const toggleSelected = (id: number) =>
    setSelected((cur) => (cur.includes(id) ? cur.filter((x) => x !== id) : [...cur, id]));
  const applyAssignment = async () => {
    if (selected.length === 0) return;
    setAssigning(true);
    try {
      for (const id of selected) {
        await api.updateTaskArtifact(taskId, id, Number(assignTo));
      }
      toast.success(`已更新 ${selected.length} 项归属`);
      setSelected([]);
      await load({ v: true });
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setAssigning(false);
    }
  };
  const scan = async () => {
    setScanning(true);
    try {
      const r = await api.scanTaskArtifacts(taskId);
      toast.success(`已补登记 ${r.added} 张（跳过 ${r.skipped}，超出 ${r.truncated}）`);
      await load({ v: true });
      setExpanded(true);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setScanning(false);
    }
  };
  const images = list.filter((a) => a.kind === "image");
  const isDoc = (a: TaskArtifact) =>
    ["document", "spreadsheet", "presentation", "pdf"].includes(a.kind) ||
    /\.(docx?|xlsx?|pptx?|pdf|odt|ods|odp|rtf)$/i.test(a.name);
  const isDataFile = (a: TaskArtifact) =>
    ["data", "log"].includes(a.kind) ||
    /\.(json|jsonl|ndjson|csv|tsv|txt|log|out|diff)$/i.test(a.name);
  const documents = list.filter((a) => a.kind !== "image" && isDoc(a) && !isDataFile(a));
  const dataFiles = list.filter((a) => a.kind !== "image" && isDataFile(a));
  const files = list.filter((a) => a.kind !== "image" && !isDoc(a) && !isDataFile(a));
  const docLabel = (a: TaskArtifact) => {
    const ext = (a.name.split(".").pop() || "").toLowerCase();
    if (["doc", "docx", "odt", "rtf"].includes(ext) || a.kind === "document") return "Word";
    if (["xls", "xlsx", "ods", "csv"].includes(ext) || a.kind === "spreadsheet") return "Excel/CSV";
    if (["ppt", "pptx", "odp"].includes(ext) || a.kind === "presentation") return "PPT";
    if (ext === "pdf" || a.kind === "pdf") return "PDF";
    return a.kind;
  };
  const fmtSize = (n: number) => (n >= 1 << 20 ? `${(n / (1 << 20)).toFixed(1)}MB` : `${Math.max(1, Math.round(n / 1024))}KB`);
  const thumbUrl = (id: number) => `${api.artifactUrl(taskId, id)}?thumb=1`;
  const fullUrl = (id: number) => api.artifactUrl(taskId, id);
  const downloadUrl = (id: number) => `${api.artifactUrl(taskId, id)}?download=1`;
  const previewUrl = (id: number, page: number) => api.artifactPreviewUrl(taskId, id, page);
  const [autoBinding, setAutoBinding] = React.useState(false);
  const autoBind = async () => {
    setAutoBinding(true);
    try {
      const r = await api.artifactsAutoBind(taskId);
      if (r.bound > 0) {
        toast.success(`智能关联：${r.bound} 条数据证据已归属到漏洞${r.skipped ? `（${r.skipped} 条歧义/无主机特征跳过）` : ""}`);
        await load({ v: true });
      } else {
        toast.info("没有可自动归属的数据证据（无主机特征或多漏洞歧义，已跳过）");
      }
    } catch (e) {
      toast.error(`智能关联失败：${(e as Error).message}`);
    } finally {
      setAutoBinding(false);
    }
  };
  const regeneratePreview = async (a: TaskArtifact) => {
    try {
      await api.regenerateArtifactPreview(taskId, a.id);
      toast.success("已提交预览生成，稍后自动刷新");
      await load({ v: true });
    } catch (e) {
      toast.error((e as Error).message);
    }
  };
  // 有文档在生成时自动轮询，完成后无需手动刷新。
  React.useEffect(() => {
    if (!expanded || !list.some((a) => a.preview_state === "pending")) return;
    const t = window.setInterval(() => {
      void load({ v: true });
    }, 4000);
    return () => window.clearInterval(t);
  }, [expanded, list, load]);
  const filterChips: { key: typeof filter; label: string }[] = [
    { key: "all", label: `全部 ${list.length}` },
    { key: "image", label: `图片 ${images.length}` },
    { key: "document", label: `文档 ${documents.length}` },
    { key: "data", label: `数据 ${dataFiles.length}` },
    { key: "file", label: `其他 ${files.length}` },
  ];
  const visibleIDs =
    filter === "image"
      ? images.map((a) => a.id)
      : filter === "document"
        ? documents.map((a) => a.id)
        : filter === "data"
          ? dataFiles.map((a) => a.id)
          : filter === "file"
            ? files.map((a) => a.id)
            : list.map((a) => a.id);
  const selectVisible = () =>
    setSelected((cur) => Array.from(new Set([...cur, ...visibleIDs])));
  return (
    <>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <ImageIcon className="size-4 text-primary" /> 证据附件（{list.length}）
            <div className="ml-auto flex flex-wrap items-center gap-2">
              <Button size="sm" variant="ghost" disabled={scanning || autoBinding} onClick={() => void autoBind()}>
                {autoBinding ? "关联中…" : "智能关联"}
              </Button>
              <Button size="sm" variant="ghost" disabled={scanning} onClick={() => void scan()}>
                {scanning ? "扫描中…" : "扫描补登记"}
              </Button>
              {list.length > 0 && (
                <>
                  <Button size="sm" variant="outline" onClick={() => setExpanded((v) => !v)}>
                    {expanded ? "收起" : "展开查看"}
                  </Button>
                  <Button size="sm" variant="outline" asChild>
                    <a href={api.artifactsExportUrl(taskId)}>下载证据包</a>
                  </Button>
                </>
              )}
            </div>
          </CardTitle>
          <CardDescription>
            截图与数据样本来自任务执行过程，全部明文保真展示。数据类证据（JSON/CSV/日志等）点「查看数据」可在线阅读；勾选可批量归属到漏洞，归属后只在该漏洞详情与单漏洞报告中出现。
          </CardDescription>
        </CardHeader>
        {expanded && (
          <CardContent className="flex flex-col gap-4">
            {list.length === 0 && (
              <p className="text-muted-foreground text-sm">
                暂无证据附件。可点右上「扫描补登记」把历史任务已抓到的图片纳入证据库；新任务会由 worker 在取证时自动登记。
              </p>
            )}
            {selected.length > 0 && (
              <div className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/30 px-3 py-2 text-sm">
                <span className="font-medium">已选 {selected.length} 项</span>
                <NativeSelect
                  size="sm"
                  value={assignTo}
                  onChange={(e) => setAssignTo(e.target.value)}
                  className="max-w-[22rem]"
                >
                  <NativeSelectOption value="0">任务级（不归属漏洞）</NativeSelectOption>
                  {findingOptions.map((f) => (
                    <NativeSelectOption key={f.id} value={f.id}>
                      {f.label}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
                <Button size="sm" disabled={assigning} onClick={() => void applyAssignment()}>
                  {assigning ? "保存中…" : "应用归属"}
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setSelected([])}>
                  清空
                </Button>
              </div>
            )}
            {list.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5">
                {filterChips.map((c) => (
                  <Button
                    key={c.key}
                    size="sm"
                    variant={filter === c.key ? "default" : "outline"}
                    onClick={() => setFilter(c.key)}
                  >
                    {c.label}
                  </Button>
                ))}
                <Button size="sm" variant="ghost" onClick={selectVisible}>
                  全选当前
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setSelected([])}>
                  清空
                </Button>
              </div>
            )}
            {(filter === "all" || filter === "image") && images.length > 0 && (
              <div className="grid grid-cols-3 gap-2 sm:grid-cols-4 lg:grid-cols-6">
                {images.map((a) => (
                  <div key={a.id} className="relative">
                    <button
                      type="button"
                      onClick={() => setPreview(a)}
                      className="group relative aspect-square w-full overflow-hidden rounded-md border bg-muted/40 text-left"
                      title={a.note || a.name}
                    >
                      {broken[a.id] ? (
                        <span className="flex h-full w-full flex-col items-center justify-center gap-1 p-2 text-center text-[11px] text-muted-foreground">
                          <ImageOffIcon className="size-5" />
                          无法预览
                          <span className="line-clamp-2 break-all">{a.name}</span>
                        </span>
                      ) : (
                        // eslint-disable-next-line @next/next/no-img-element
                        <img
                          src={thumbUrl(a.id)}
                          alt={a.note || a.name}
                          loading="lazy"
                          onError={() => setBroken((b) => ({ ...b, [a.id]: true }))}
                          className="h-full w-full object-cover transition-transform duration-200 group-hover:scale-105"
                        />
                      )}
                      <span className="pointer-events-none absolute inset-x-0 bottom-0 line-clamp-1 bg-black/55 px-1.5 py-0.5 text-[10px] text-white">
                        {a.finding_id ? `#${a.finding_id} · ` : ""}
                        {a.note || a.name}
                      </span>
                    </button>
                    <label className="absolute top-1.5 left-1.5 z-10 flex size-5 cursor-pointer items-center justify-center rounded bg-black/55">
                      <input
                        type="checkbox"
                        aria-label={`选择 ${a.name}`}
                        className="size-3.5 accent-primary"
                        checked={selected.includes(a.id)}
                        onChange={() => toggleSelected(a.id)}
                      />
                    </label>
                  </div>
                ))}
              </div>
            )}
            {(filter === "all" || filter === "document") && documents.length > 0 && (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-4">
                {documents.map((a) => {
                  const ready = a.preview_state === "ready" && (a.preview_pages ?? 0) > 0;
                  const stateText =
                    a.preview_state === "pending"
                      ? "预览生成中…"
                      : a.preview_state === "failed"
                        ? "预览失败"
                        : a.preview_state === "skipped"
                          ? "未生成预览"
                          : "点击生成预览";
                  return (
                    <div key={a.id} className="relative">
                      <button
                        type="button"
                        onClick={() => {
                          if (ready) setDocPreview({ artifact: a, page: 1 });
                          else void regeneratePreview(a);
                        }}
                        className="group relative flex aspect-[3/4] w-full flex-col overflow-hidden rounded-md border bg-muted/40 text-left"
                        title={a.preview_error || a.note || a.name}
                      >
                        {ready ? (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img
                            src={previewUrl(a.id, 1)}
                            alt={a.note || a.name}
                            loading="lazy"
                            className="h-full w-full object-cover object-top transition-transform duration-200 group-hover:scale-105"
                          />
                        ) : (
                          <span className="flex h-full w-full flex-col items-center justify-center gap-1 p-3 text-center text-[11px] text-muted-foreground">
                            <BugIcon className="size-5" />
                            {stateText}
                            {a.preview_error ? <span className="line-clamp-2 break-all">{a.preview_error}</span> : null}
                          </span>
                        )}
                        <span className="pointer-events-none absolute inset-x-0 bottom-0 bg-black/60 px-1.5 py-0.5 text-[10px] text-white">
                          {docLabel(a)}
                          {ready ? ` · ${a.preview_pages} 页` : ""}
                          {a.finding_id ? ` · #${a.finding_id}` : ""}
                          {" · "}
                          {a.name}
                        </span>
                      </button>
                      <label className="absolute top-1.5 left-1.5 z-10 flex size-5 cursor-pointer items-center justify-center rounded bg-black/55">
                        <input
                          type="checkbox"
                          aria-label={`选择 ${a.name}`}
                          className="size-3.5 accent-primary"
                          checked={selected.includes(a.id)}
                          onChange={() => toggleSelected(a.id)}
                        />
                      </label>
                      {!ready && a.preview_state !== "pending" && (
                        <Button
                          size="sm"
                          variant="secondary"
                          className="absolute right-1.5 bottom-7 z-10 h-6 px-2 text-[11px]"
                          onClick={() => void regeneratePreview(a)}
                        >
                          {a.preview_state === "failed" ? "重试" : "生成预览"}
                        </Button>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
            {(filter === "all" || filter === "data") && dataFiles.length > 0 && (
              <div className="flex flex-col divide-y rounded border">
                {dataFiles.map((a) => (
                  <div key={a.id} className="flex min-w-0 items-center gap-2 px-3 py-2 text-sm">
                    <input
                      type="checkbox"
                      aria-label={`选择 ${a.name}`}
                      className="size-3.5 shrink-0 accent-primary"
                      checked={selected.includes(a.id)}
                      onChange={() => toggleSelected(a.id)}
                    />
                    <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-muted-foreground text-xs">数据</span>
                    <span className="min-w-0 flex-1 truncate" title={a.note || a.name}>{a.name}</span>
                    {a.finding_id ? (
                      <span className="shrink-0 text-muted-foreground text-xs">#{a.finding_id}</span>
                    ) : null}
                    <span className="shrink-0 text-muted-foreground text-xs">{fmtSize(a.size_bytes)}</span>
                    <Button size="sm" variant="outline" onClick={() => setDataPreview(a)}>
                      查看数据
                    </Button>
                    <Button size="sm" variant="ghost" asChild>
                      <a href={downloadUrl(a.id)}>下载</a>
                    </Button>
                  </div>
                ))}
              </div>
            )}
            {(filter === "all" || filter === "file") && files.length > 0 && (
              <div className="flex flex-col divide-y rounded border">
                {files.map((a) => (
                  <div key={a.id} className="flex min-w-0 items-center gap-2 px-3 py-2 text-sm">
                    <input
                      type="checkbox"
                      aria-label={`选择 ${a.name}`}
                      className="size-3.5 shrink-0 accent-primary"
                      checked={selected.includes(a.id)}
                      onChange={() => toggleSelected(a.id)}
                    />
                    <span className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-muted-foreground text-xs">{a.kind}</span>
                    <span className="min-w-0 flex-1 truncate">{a.name}</span>
                    {a.finding_id ? (
                      <span className="shrink-0 text-muted-foreground text-xs">#{a.finding_id}</span>
                    ) : null}
                    <span className="shrink-0 text-muted-foreground text-xs">{fmtSize(a.size_bytes)}</span>
                    <Button size="sm" variant="ghost" asChild>
                      <a href={downloadUrl(a.id)}>下载</a>
                    </Button>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        )}
      </Card>
      {/* v0.4.53：图片预览接入 ZoomableImageDialog（滚轮缩放/拖拽平移），替代静态 img——
          此前 v0.4.48 只替换了漏洞详情页，任务总览漏掉，大图（2250x1500 曲线图等）看不清细节。 */}
      <ZoomableImageDialog
        open={!!preview}
        onClose={() => setPreview(null)}
        src={preview ? fullUrl(preview.id) : ""}
        title={preview?.note || preview?.name || ""}
        description={
          preview
            ? `${preview.name} · ${fmtSize(preview.size_bytes)}${preview.finding_id ? ` · 漏洞 #${preview.finding_id}` : ""}`
            : ""
        }
        downloadUrl={preview ? downloadUrl(preview.id) : ""}
      />
      <ArtifactDataViewerDialog
        taskId={taskId}
        artifact={dataPreview}
        open={!!dataPreview}
        onClose={() => setDataPreview(null)}
      />
      {/* v0.4.53：文档分页预览同样接入缩放组件——Word/PDF 转图后每页是一张静态图，
          报告细节（表格/签名/小字）不缩放看不清。翻页时 src 变化自动重置缩放。 */}
      <ZoomableImageDialog
        open={!!docPreview}
        onClose={() => setDocPreview(null)}
        src={docPreview ? previewUrl(docPreview.artifact.id, docPreview.page) : ""}
        title={docPreview?.artifact.note || docPreview?.artifact.name || ""}
        description={
          docPreview
            ? `${docPreview.artifact.name} · 第 ${docPreview.page} / ${docPreview.artifact.preview_pages ?? 0} 页${docPreview.artifact.finding_id ? ` · 漏洞 #${docPreview.artifact.finding_id}` : ""}`
            : ""
        }
        downloadUrl={docPreview ? downloadUrl(docPreview.artifact.id) : ""}
        footer={
          docPreview ? (
            <div className="flex items-center justify-center gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={docPreview.page <= 1}
                onClick={() => setDocPreview((cur) => (cur ? { ...cur, page: cur.page - 1 } : cur))}
              >
                <ChevronLeftIcon className="size-3.5" /> 上一页
              </Button>
              <Button
                size="sm"
                variant="outline"
                disabled={docPreview.page >= (docPreview.artifact.preview_pages ?? 1)}
                onClick={() => setDocPreview((cur) => (cur ? { ...cur, page: cur.page + 1 } : cur))}
              >
                下一页 <ChevronRightIcon className="size-3.5" />
              </Button>
            </div>
          ) : null
        }
      />
    </>
  );
}
