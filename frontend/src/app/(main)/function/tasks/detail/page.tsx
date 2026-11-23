"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  Activity,
  ArrowLeft,
  Bot,
  Bug,
  Check,
  CheckCircle2,
  Download,
  Flag,
  Flame,
  GitBranch,
  History,
  Pause,
  Pencil,
  Play,
  RefreshCw,
  Send,
  ShieldBan,
  Sparkles,
  Square,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  riddleApi,
  riddleFetch,
  type KillsweepItem,
  type RiddleFinding,
  type RiddleTarget,
  type RiddleTask,
} from "@/lib/riddle-api";

import { CreateTaskDialog } from "../_components/create-task-dialog";

interface LiveWorkerItem {
  worker_id?: string;
  target_id?: string;
  target?: string;
  url?: string;
  host?: string;
  status?: string;
  action?: string;
  score?: number;
  phase?: string;
  progress?: number;
  round?: number;
  findings?: number;
}

interface LiveEscalationItem {
  finding_id: string;
  title?: string;
  severity?: string;
  action?: string;
  started_at?: string;
}

interface BoardPayload {
  task_status?: string;
  live_workers?: LiveWorkerItem[];
  live_escalations?: LiveEscalationItem[];
  stats?: Record<string, number>;
  vuln_dist?: Array<{ type: string; count: number }>;
  concurrency?: number;
  worker_summary?: { running?: number; escalating?: number; idle?: number };
  throttle?: { cap?: number; base_cap?: number; reasons?: string[]; queued?: number; llm_under_cooldown?: boolean };
  tab_summary?: Record<string, number>;
  events?: Array<Record<string, unknown>>;
  goal_summary?: { configured?: boolean; total?: number; met_count?: number; achieved?: number; terminal_state?: string; summary?: string } | null;
}

function extractFindings(res: { items?: RiddleFinding[] } | RiddleFinding[]): RiddleFinding[] {
  return Array.isArray(res) ? res : res.items ?? [];
}

function TaskDetailInner() {
  const searchParams = useSearchParams();
  const taskId = searchParams.get("id") ?? "";

  const [task, setTask] = React.useState<RiddleTask | null>(null);
  const [board, setBoard] = React.useState<BoardPayload | null>(null);
  const [targets, setTargets] = React.useState<RiddleTarget[]>([]);
  const [targetStatus, setTargetStatus] = React.useState("all");
  const [findings, setFindings] = React.useState<RiddleFinding[]>([]);
  const [killsweeps, setKillsweeps] = React.useState<KillsweepItem[]>([]);
  const [goals, setGoals] = React.useState<Array<Record<string, unknown>>>([]);
  const [goalEval, setGoalEval] = React.useState<Record<string, unknown> | null>(null);
  const [graphData, setGraphData] = React.useState<{
    nodes: Array<Record<string, unknown>>;
    edges: Array<Record<string, unknown>>;
    coverage: Record<string, unknown>;
  } | null>(null);

  const [loading, setLoading] = React.useState(true);
  const [editOpen, setEditOpen] = React.useState(false);
  const [wsConnected, setWsConnected] = React.useState(false);
  const [liveEvents, setLiveEvents] = React.useState<Array<Record<string, unknown>>>([]);

  // Mid-run directive input map by target_id
  const [directiveMap, setDirectiveMap] = React.useState<Record<string, string>>({});

  // Target Trace Drawer
  const [traceTarget, setTraceTarget] = React.useState<{ id: string; label: string } | null>(null);
  const [traceEvents, setTraceEvents] = React.useState<Array<Record<string, unknown>>>([]);
  const [traceLoading, setTraceLoading] = React.useState(false);

  const loadCore = React.useCallback(
    async (quiet = false) => {
      if (!taskId) return;
      if (!quiet) setLoading(true);
      try {
        const [tRes, bRes, tgRes, fRes, kRes, gRes, grRes] = await Promise.allSettled([
          riddleApi.getTask(taskId),
          riddleApi.getTaskBoard(taskId),
          riddleApi.getTaskTargets(taskId, targetStatus, 200),
          riddleApi.listTaskFindings(taskId, { limit: 200 }),
          riddleApi.listKillsweeps(taskId),
          riddleApi.getGoals(taskId),
          riddleApi.getFusionGraph(taskId),
        ]);
        if (tRes.status === "fulfilled") setTask(tRes.value);
        if (bRes.status === "fulfilled") setBoard(bRes.value as BoardPayload);
        if (tgRes.status === "fulfilled") setTargets(tgRes.value);
        if (fRes.status === "fulfilled") setFindings(extractFindings(fRes.value));
        if (kRes.status === "fulfilled") setKillsweeps(kRes.value);
        if (gRes.status === "fulfilled") setGoals(gRes.value.goals ?? []);
        if (grRes.status === "fulfilled") setGraphData(grRes.value);
      } catch (err) {
        if (!quiet) toast.error(`加载任务详情失败：${err instanceof Error ? err.message : String(err)}`);
      } finally {
        setLoading(false);
      }
    },
    [taskId, targetStatus],
  );

  React.useEffect(() => {
    void loadCore(false);
    const timer = setInterval(() => void loadCore(true), 8000);
    return () => clearInterval(timer);
  }, [loadCore]);

  // Native WebSocket real-time event stream (/api/tasks/{id}/stream)
  React.useEffect(() => {
    if (!taskId) return;
    let ws: WebSocket | null = null;
    let closed = false;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;

    const connect = () => {
      if (closed) return;
      const url = riddleApi.taskStreamWsUrl(taskId);
      if (!url) return;
      try {
        ws = new WebSocket(url);
        ws.onopen = () => setWsConnected(true);
        ws.onclose = () => {
          setWsConnected(false);
          if (!closed) reconnectTimer = setTimeout(connect, 4000);
        };
        ws.onerror = () => setWsConnected(false);
        ws.onmessage = (evt) => {
          try {
            const msg = JSON.parse(evt.data) as Record<string, unknown>;
            if (msg.kind === "ping") return;
            setLiveEvents((prev) => [msg, ...prev].slice(0, 60));
            const k = String(msg.kind ?? "");
            if (k === "review_done" || k === "finding" || k === "worker_finish" || k.startsWith("killsweep")) {
              void loadCore(true);
            }
          } catch {
            // ignore non-json frames
          }
        };
      } catch {
        setWsConnected(false);
      }
    };

    connect();
    return () => {
      closed = true;
      if (reconnectTimer) clearTimeout(reconnectTimer);
      ws?.close();
    };
  }, [taskId, loadCore]);

  const handleControl = async (action: "start" | "pause" | "stop") => {
    if (!task) return;
    try {
      if (action === "start") await riddleApi.startTask(task.id);
      else if (action === "pause") await riddleApi.pauseTask(task.id);
      else await riddleApi.stopTask(task.id);
      toast.success(action === "start" ? "任务已启动" : action === "pause" ? "任务已暂停" : "任务已停止");
      await loadCore(true);
    } catch (err) {
      toast.error(`操作失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleInjectDirective = async (targetId: string) => {
    const text = (directiveMap[targetId] || "").trim();
    if (!text || !taskId) {
      toast.error("请输入人工干预指令");
      return;
    }
    try {
      await riddleApi.injectTargetDirective(taskId, targetId, text);
      toast.success("已注入实时人工指令，将在 Worker 下一步 LLM 调用前生效");
      setDirectiveMap((prev) => ({ ...prev, [targetId]: "" }));
    } catch (err) {
      toast.error(`注入指令失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const openTrace = async (targetId: string, label: string) => {
    setTraceTarget({ id: targetId, label });
    setTraceLoading(true);
    setTraceEvents([]);
    try {
      const res = await riddleApi.getTargetTrace(taskId, targetId, 200);
      setTraceEvents(res.events ?? []);
    } catch (err) {
      toast.error(`加载轨迹失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTraceLoading(false);
    }
  };

  const handleSkipTarget = async (targetId: string) => {
    try {
      await riddleApi.skipTaskTarget(taskId, targetId);
      toast.success("已跳过该目标");
      await loadCore(true);
    } catch (err) {
      toast.error(`跳过失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleCancelEscalation = async (findingId: string) => {
    try {
      await riddleApi.cancelEscalation(taskId, findingId);
      toast.success("已取消该扩大危害任务");
      await loadCore(true);
    } catch (err) {
      toast.error(`取消失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleQuickReview = async (f: RiddleFinding, status: "passed" | "rejected") => {
    try {
      const res = await riddleApi.reviewFinding(f.id, { user_status: status });
      toast.success(
        status === "passed"
          ? res.killsweep_triggered
            ? "复审通过并已触发通杀 Hunter"
            : "复审通过"
          : "已驳回该漏洞",
      );
      await loadCore(true);
    } catch (err) {
      toast.error(`复审失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSuggestGoals = async () => {
    try {
      const res = await riddleApi.suggestGoals({ task_id: taskId });
      setGoals(res.goals ?? []);
      toast.success(`已拆解 ${res.count} 条可核验目标，请点击保存`);
    } catch (err) {
      toast.error(`拆解失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSaveAndEvaluateGoals = async () => {
    try {
      await riddleApi.saveGoals(taskId, goals);
      const ev = await riddleFetch<Record<string, unknown>>(`/fusion/goals/${encodeURIComponent(taskId)}/evaluate`, {
        method: "POST",
      });
      setGoalEval(ev);
      toast.success("已保存并重新评估目标闸门");
      await loadCore(true);
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleRebuildGraph = async () => {
    try {
      await riddleApi.rebuildFusionGraph(taskId);
      toast.success("资产图 × 探索图重建完成");
      await loadCore(true);
    } catch (err) {
      toast.error(`重建双图失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  if (!taskId) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-12 text-center">
        <p className="text-sm text-muted-foreground">缺少任务 ID 参数</p>
        <Button variant="outline" size="sm" asChild>
          <Link href="/function/tasks">返回挖掘任务列表</Link>
        </Button>
      </div>
    );
  }

  const liveWorkers = board?.live_workers ?? [];
  const liveEscalations = board?.live_escalations ?? [];
  const vulnDist = board?.vuln_dist ?? [];
  const events = React.useMemo(() => {
    const combined = [...liveEvents, ...(board?.events ?? [])];
    return combined.slice(0, 60);
  }, [liveEvents, board?.events]);
  const stats = board?.stats ?? {};
  const totalTargets = Number(stats.total_targets ?? task?.total_targets ?? 0);
  const doneTargets = Number(stats.done_targets ?? task?.stats?.done_targets ?? 0);
  const progressPct = totalTargets > 0 ? Math.min(100, Math.round((doneTargets / totalTargets) * 100)) : 0;
  const pendingReview = Number(board?.tab_summary?.review ?? task?.pending_user_review ?? 0);
  const passedCount = Number(board?.tab_summary?.submit ?? task?.stats?.user_passed ?? 0);
  const throttle = board?.throttle;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Sticky Mission Control Header */}
      <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-3 border-b bg-background/85 px-4 backdrop-blur-md lg:px-6">
        <div className="flex min-w-0 items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="h-4" />
          <Button variant="ghost" size="sm" className="px-2" asChild>
            <Link href="/function/tasks">
              <ArrowLeft className="mr-1 size-4" /> 任务列表
            </Link>
          </Button>
          <Separator orientation="vertical" className="h-4" />
          <h1 className="truncate font-semibold text-base">{task?.name || (loading ? "加载中…" : taskId)}</h1>
          {task ? <StatusBadge domain="task" value={task.status} dot /> : null}
          {task ? (
            <Badge variant="outline" className="hidden sm:inline-flex text-xs">
              {task.src_type === "edusrc" ? "EduSRC" : "企业SRC"}
            </Badge>
          ) : null}
          <Badge variant={wsConnected ? "default" : "secondary"} className="hidden md:inline-flex text-[11px]">
            {wsConnected ? "实时流已连接" : "轮询同步"}
          </Badge>
        </div>

        <div className="flex shrink-0 items-center gap-1.5">
          <Button variant="outline" size="sm" onClick={() => void loadCore(true)}>
            <RefreshCw className="size-3.5" />
          </Button>
          {task ? (
            <>
              <Button variant="outline" size="sm" onClick={() => setEditOpen(true)}>
                <Pencil className="mr-1.5 size-3.5" /> 编辑
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() =>
                  void riddleApi
                    .downloadTaskReportsExport(task.id, "md")
                    .catch((e) => toast.error(e instanceof Error ? e.message : String(e)))
                }
              >
                <Download className="mr-1.5 size-3.5" /> 导出报告包
              </Button>
              {task.status === "running" ? (
                <Button variant="secondary" size="sm" onClick={() => void handleControl("pause")}>
                  <Pause className="mr-1.5 size-3.5" /> 暂停
                </Button>
              ) : (
                <Button size="sm" onClick={() => void handleControl("start")}>
                  <Play className="mr-1.5 size-3.5" /> 启动
                </Button>
              )}
              {task.status === "running" || task.status === "paused" ? (
                <Button variant="destructive" size="sm" onClick={() => void handleControl("stop")}>
                  <Square className="mr-1 size-3.5" /> 停止
                </Button>
              ) : null}
            </>
          ) : null}
        </div>
      </header>

      <div className="flex flex-1 flex-col gap-5 p-4 md:p-6">
        {/* Top 5 Live Telemetry Cards */}
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
          <Card>
            <CardHeader className="pb-1">
              <CardDescription className="text-xs">目标推进进度</CardDescription>
              <CardTitle className="text-xl tabular-nums">
                {doneTargets} / {totalTargets}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1">
              <Progress value={progressPct} className="h-1.5" />
              <div className="text-[11px] text-muted-foreground">完成 {progressPct}%</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardDescription className="text-xs">在跑 Worker / 节流上限</CardDescription>
              <CardTitle className="text-xl tabular-nums">
                {board?.worker_summary?.running ?? liveWorkers.length} / {throttle?.cap ?? task?.concurrency ?? 3}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-[11px] text-muted-foreground">
              扩大危害 {board?.worker_summary?.escalating ?? liveEscalations.length}
              {throttle?.llm_under_cooldown ? " · LLM 冷却中" : ""}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardDescription className="text-xs">待人工复审</CardDescription>
              <CardTitle className="text-xl tabular-nums text-amber-600 dark:text-amber-400">{pendingReview}</CardTitle>
            </CardHeader>
            <CardContent className="text-[11px] text-muted-foreground">总线索 {findings.length} 条</CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardDescription className="text-xs">复审通过 / 通杀</CardDescription>
              <CardTitle className="text-xl tabular-nums text-emerald-600 dark:text-emerald-400">
                {passedCount} / {killsweeps.length}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-[11px] text-muted-foreground">可一键打包导出 Markdown / EduSRC JSON</CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-1">
              <CardDescription className="text-xs">融合目标闸门</CardDescription>
              <CardTitle className="text-xl tabular-nums">
                {board?.goal_summary?.configured
                  ? `${board.goal_summary.met_count ?? board.goal_summary.achieved ?? 0} / ${board.goal_summary.total ?? 0}`
                  : "未配置"}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-[11px] text-muted-foreground truncate">
              {board?.goal_summary?.summary || "可在目标与双图页签拆解"}
            </CardContent>
          </Card>
        </div>

        {/* 6 Riddle Operational Tabs */}
        <Tabs defaultValue="live" className="space-y-4">
          <TabsList className="flex-wrap h-auto">
            <TabsTrigger value="live">
              <Activity className="mr-1.5 size-3.5" /> 实时作战矩阵 ({liveWorkers.length})
            </TabsTrigger>
            <TabsTrigger value="targets">目标队列与轨迹 ({targets.length})</TabsTrigger>
            <TabsTrigger value="findings">
              <Bug className="mr-1.5 size-3.5" /> 漏洞与复审 ({findings.length})
            </TabsTrigger>
            <TabsTrigger value="killsweep">
              <Zap className="mr-1.5 size-3.5" /> 通杀扩展 ({killsweeps.length})
            </TabsTrigger>
            <TabsTrigger value="goals">
              <GitBranch className="mr-1.5 size-3.5" /> 目标闸门与双图
            </TabsTrigger>
            <TabsTrigger value="config">配置快照</TabsTrigger>
          </TabsList>

          {/* Tab 1: Live Worker Matrix + Mid-Run Directive + Escalations + Events */}
          <TabsContent value="live" className="space-y-4">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
              {/* Active Workers */}
              <div className="space-y-3 lg:col-span-2">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="flex items-center gap-2 text-base">
                      <Bot className="size-4 text-primary" /> 在跑 Worker 矩阵与实时人工干预
                    </CardTitle>
                    <CardDescription className="text-xs">
                      每 5 秒自动同步；可向任意在跑 Worker 注入定向指令（下一轮 LLM 推理前即刻生效）或查看落库轨迹。
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {liveWorkers.length === 0 ? (
                      <div className="rounded-lg border border-dashed py-10 text-center text-xs text-muted-foreground">
                        当前无活跃运行中的 Worker。若任务处于暂停或已创建状态，点击右上角「启动」开始挖掘。
                      </div>
                    ) : (
                      liveWorkers.map((w, idx) => {
                        const tid = w.target_id || w.worker_id || String(idx);
                        const label = w.url || w.target || w.host || tid;
                        return (
                          <div key={tid} className="space-y-2.5 rounded-xl border bg-muted/15 p-3.5">
                            <div className="flex flex-wrap items-center justify-between gap-2">
                              <div className="min-w-0 flex-1">
                                <div className="truncate font-mono text-xs font-semibold">{label}</div>
                                <div className="mt-0.5 text-xs text-muted-foreground">
                                  {w.action || "正在探索目标…"}
                                </div>
                              </div>
                              <div className="flex items-center gap-1.5">
                                {w.phase ? <Badge variant="outline" className="text-[11px]">{w.phase}</Badge> : null}
                                <Button variant="ghost" size="sm" onClick={() => void openTrace(tid, label)}>
                                  <History className="mr-1 size-3.5" /> 轨迹
                                </Button>
                                <Button variant="ghost" size="sm" onClick={() => void handleSkipTarget(tid)}>
                                  <ShieldBan className="mr-1 size-3.5" /> 跳过
                                </Button>
                              </div>
                            </div>
                            <Progress value={Number(w.progress ?? 0)} className="h-1.5" />
                            <div className="flex items-center gap-2">
                              <Input
                                className="h-8 bg-background text-xs"
                                placeholder="向该 Worker 注入实时人工指令（如：重点测试 /api/admin 越权接口）…"
                                value={directiveMap[tid] ?? ""}
                                onChange={(e) => setDirectiveMap((prev) => ({ ...prev, [tid]: e.target.value }))}
                                onKeyDown={(e) => {
                                  if (e.key === "Enter") void handleInjectDirective(tid);
                                }}
                              />
                              <Button size="sm" variant="secondary" className="h-8" onClick={() => void handleInjectDirective(tid)}>
                                <Send className="mr-1 size-3.5" /> 下发
                              </Button>
                            </div>
                          </div>
                        );
                      })
                    )}
                  </CardContent>
                </Card>

                {/* Active Escalations */}
                {liveEscalations.length > 0 ? (
                  <Card className="border-amber-500/40">
                    <CardHeader className="pb-2">
                      <CardTitle className="flex items-center gap-2 text-sm">
                        <Flame className="size-4 text-amber-500" /> 正在进行的危害扩大任务 ({liveEscalations.length})
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2">
                      {liveEscalations.map((esc) => (
                        <div key={esc.finding_id} className="flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-xs">
                          <div className="min-w-0">
                            <div className="truncate font-medium">{esc.title || esc.finding_id}</div>
                            <div className="text-muted-foreground">{esc.action || "扩大危害深挖中…"}</div>
                          </div>
                          <Button size="sm" variant="outline" onClick={() => void handleCancelEscalation(esc.finding_id)}>
                            取消扩大
                          </Button>
                        </div>
                      ))}
                    </CardContent>
                  </Card>
                ) : null}
              </div>

              {/* Right Column: Vuln Dist + Live Events */}
              <div className="space-y-4">
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">漏洞类型分布</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {vulnDist.length === 0 ? (
                      <p className="text-xs text-muted-foreground">暂无发现分布数据</p>
                    ) : (
                      vulnDist.map((item) => (
                        <div key={item.type} className="flex items-center justify-between text-xs">
                          <span className="truncate">{item.type}</span>
                          <Badge variant="secondary" className="tabular-nums">{item.count}</Badge>
                        </div>
                      ))
                    )}
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">最新作战动态 ({events.length})</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="max-h-80 space-y-2 overflow-y-auto pr-1 text-xs">
                      {events.length === 0 ? (
                        <p className="text-muted-foreground">暂无作战事件记录</p>
                      ) : (
                        events.slice(0, 30).map((ev, i) => (
                          <div key={i} className="rounded border bg-muted/20 p-2 space-y-0.5">
                            <div className="flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
                              <span className="font-mono font-medium uppercase">{String(ev.agent ?? "system")}</span>
                              <span>{String(ev.ts ?? "").replace("T", " ").slice(11, 19)}</span>
                            </div>
                            <div className="break-all leading-relaxed">{String(ev.message ?? ev.kind ?? "")}</div>
                          </div>
                        ))
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          {/* Tab 2: Targets & Trace */}
          <TabsContent value="targets" className="space-y-3">
            <div className="flex items-center justify-between">
              <Select value={targetStatus} onValueChange={setTargetStatus}>
                <SelectTrigger className="w-[170px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部状态</SelectItem>
                  <SelectItem value="alive">队列 / 探测中</SelectItem>
                  <SelectItem value="done">已完成</SelectItem>
                  <SelectItem value="dead">硬骨头 (dead)</SelectItem>
                  <SelectItem value="skipped">已跳过</SelectItem>
                </SelectContent>
              </Select>
              <span className="text-xs text-muted-foreground">共 {targets.length} 条目标</span>
            </div>
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>目标 URL / 标题</TableHead>
                      <TableHead>学校 / 机构</TableHead>
                      <TableHead>优先级</TableHead>
                      <TableHead>状态</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {targets.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                          暂无匹配目标
                        </TableCell>
                      </TableRow>
                    ) : (
                      targets.map((t) => (
                        <TableRow key={t.id}>
                          <TableCell className="max-w-[320px]">
                            <div className="truncate font-mono text-xs font-medium">{t.url || t.host}</div>
                            <div className="truncate text-xs text-muted-foreground">{t.title || t.ip || "-"}</div>
                          </TableCell>
                          <TableCell className="text-xs">{t.school || t.org || "-"}</TableCell>
                          <TableCell className="text-xs tabular-nums">{Number(t.priority_score ?? 0).toFixed(1)}</TableCell>
                          <TableCell>
                            <Badge variant={t.status === "done" ? "default" : "secondary"}>{t.status}</Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="inline-flex gap-1">
                              <Button variant="ghost" size="sm" onClick={() => void openTrace(t.id, t.url || t.host)}>
                                <History className="mr-1 size-3.5" /> 轨迹
                              </Button>
                              {t.status === "queued" || t.status === "scanning" ? (
                                <Button variant="ghost" size="sm" onClick={() => void handleSkipTarget(t.id)}>
                                  跳过
                                </Button>
                              ) : null}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tab 3: Task Findings */}
          <TabsContent value="findings" className="space-y-3">
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>漏洞标题与目标</TableHead>
                      <TableHead>等级 / 证据门禁</TableHead>
                      <TableHead>复审状态</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {findings.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="h-24 text-center text-sm text-muted-foreground">
                          本任务暂未发现漏洞线索。
                        </TableCell>
                      </TableRow>
                    ) : (
                      findings.map((f) => {
                        const sev = f.review?.effective_severity || f.severity_claimed || "中危";
                        return (
                          <TableRow key={f.id}>
                            <TableCell className="max-w-[360px]">
                              <Link
                                href={`/function/findings/detail?id=${encodeURIComponent(f.id)}`}
                                className="block truncate font-medium text-sm hover:text-primary hover:underline"
                              >
                                {f.title}
                              </Link>
                              <div className="truncate text-xs text-muted-foreground">{f.target_url}</div>
                            </TableCell>
                            <TableCell>
                              <div className="flex items-center gap-1.5">
                                <StatusBadge domain="severity" value={sev} />
                                {f.fusion_evidence?.tier_label ? (
                                  <Badge variant="outline" className="text-[11px]">
                                    {f.fusion_evidence.tier_label}
                                  </Badge>
                                ) : null}
                              </div>
                            </TableCell>
                            <TableCell>
                              <StatusBadge
                                domain="finding"
                                value={f.review?.user_status || f.review?.verdict || f.status || "pending"}
                                dot
                              />
                            </TableCell>
                            <TableCell className="text-right">
                              <div className="inline-flex items-center gap-1">
                                <Button size="sm" variant="ghost" onClick={() => void handleQuickReview(f, "passed")}>
                                  <Check className="size-3.5 text-emerald-600" />
                                </Button>
                                <Button size="sm" variant="ghost" onClick={() => void handleQuickReview(f, "rejected")}>
                                  <X className="size-3.5 text-destructive" />
                                </Button>
                                <Button size="sm" variant="outline" asChild>
                                  <Link href={`/function/findings/detail?id=${encodeURIComponent(f.id)}`}>详情</Link>
                                </Button>
                              </div>
                            </TableCell>
                          </TableRow>
                        );
                      })
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tab 4: Killsweeps */}
          <TabsContent value="killsweep" className="space-y-3">
            <Card>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>通杀产品与源漏洞</TableHead>
                      <TableHead>FOFA 扩面语句</TableHead>
                      <TableHead>命中资产 / 衍生洞</TableHead>
                      <TableHead className="text-right">操作</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {killsweeps.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={4} className="h-24 text-center text-sm text-muted-foreground">
                          暂无通杀分析记录（人工复审通过漏洞后自动触发）。
                        </TableCell>
                      </TableRow>
                    ) : (
                      killsweeps.map((k) => (
                        <TableRow key={k.id}>
                          <TableCell className="max-w-[260px]">
                            <div className="truncate font-medium text-sm">{k.product_name || k.vuln_type}</div>
                            <div className="truncate text-xs text-muted-foreground">{k.origin_title}</div>
                          </TableCell>
                          <TableCell className="max-w-[240px] truncate font-mono text-xs">{k.fofa_query || "-"}</TableCell>
                          <TableCell className="text-xs tabular-nums">
                            资产 {k.asset_count} (高校 {k.edu_count}) · 衍生 {k.derived_count}
                          </TableCell>
                          <TableCell className="text-right">
                            <div className="inline-flex gap-1">
                              {k.has_sites ? (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={async () => {
                                    await riddleApi.enqueueKillsweep(taskId, k.id, 3);
                                    toast.success("已批量入队 3 个同款验证站点");
                                    await loadCore(true);
                                  }}
                                >
                                  入队 3 站
                                </Button>
                              ) : null}
                              {k.retryable ? (
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  onClick={async () => {
                                    await riddleApi.retryKillsweep(taskId, k.id);
                                    toast.success("已重启通杀分析");
                                    await loadCore(true);
                                  }}
                                >
                                  重试
                                </Button>
                              ) : null}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Tab 5: Goals & Dual Graph */}
          <TabsContent value="goals" className="space-y-4">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-3">
                  <div>
                    <CardTitle className="flex items-center gap-1.5 text-base">
                      <Flag className="size-4 text-primary" /> 融合验收目标闸门
                    </CardTitle>
                    <CardDescription className="text-xs">
                      {goalEval ? String(goalEval.summary ?? "") : board?.goal_summary?.summary || "定义可核验验收标准"}
                    </CardDescription>
                  </div>
                  <div className="flex gap-1.5">
                    <Button size="sm" variant="outline" onClick={() => void handleSuggestGoals()}>
                      <Sparkles className="mr-1 size-3.5" /> 智能拆解
                    </Button>
                    <Button size="sm" onClick={() => void handleSaveAndEvaluateGoals()} disabled={goals.length === 0}>
                      保存并评估
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-2">
                  {goals.length === 0 ? (
                    <p className="py-6 text-center text-xs text-muted-foreground">尚未设置目标闸门，点击右上角「智能拆解」。</p>
                  ) : (
                    goals.map((g, idx) => (
                      <div key={idx} className="space-y-1.5 rounded-lg border p-2.5">
                        <div className="flex items-center justify-between gap-2">
                          <Input
                            className="h-8 text-xs font-medium"
                            value={String(g.title ?? "")}
                            onChange={(e) =>
                              setGoals((prev) => prev.map((x, i) => (i === idx ? { ...x, title: e.target.value } : x)))
                            }
                          />
                          <Badge variant={g.status === "achieved" ? "default" : "secondary"}>
                            {g.status === "achieved" ? (
                              <span className="flex items-center gap-1">
                                <CheckCircle2 className="size-3" /> 达成
                              </span>
                            ) : (
                              String(g.status ?? "pending")
                            )}
                          </Badge>
                        </div>
                        <Input
                          className="h-7 text-xs text-muted-foreground"
                          value={String(g.criteria ?? "")}
                          onChange={(e) =>
                            setGoals((prev) => prev.map((x, i) => (i === idx ? { ...x, criteria: e.target.value } : x)))
                          }
                        />
                      </div>
                    ))
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-3">
                  <div>
                    <CardTitle className="flex items-center gap-1.5 text-base">
                      <GitBranch className="size-4 text-primary" /> 资产图 × 探索图覆盖度
                    </CardTitle>
                    <CardDescription className="text-xs">从主表旁路重建双图节点、血缘边与端点覆盖度</CardDescription>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => void handleRebuildGraph()}>
                    <RefreshCw className="mr-1.5 size-3.5" /> 重建双图
                  </Button>
                </CardHeader>
                <CardContent className="space-y-3 text-xs">
                  <div className="grid grid-cols-3 gap-2">
                    <div className="rounded-lg border p-2.5 text-center">
                      <div className="text-muted-foreground">图节点</div>
                      <div className="mt-1 font-semibold text-lg tabular-nums">{graphData?.nodes?.length ?? 0}</div>
                    </div>
                    <div className="rounded-lg border p-2.5 text-center">
                      <div className="text-muted-foreground">血缘边</div>
                      <div className="mt-1 font-semibold text-lg tabular-nums">{graphData?.edges?.length ?? 0}</div>
                    </div>
                    <div className="rounded-lg border p-2.5 text-center">
                      <div className="text-muted-foreground">覆盖率</div>
                      <div className="mt-1 font-semibold text-lg tabular-nums">
                        {Math.round(Number(graphData?.coverage?.ratio ?? 0) * 100)}%
                      </div>
                    </div>
                  </div>
                  {graphData?.coverage ? (
                    <pre className="max-h-48 overflow-auto rounded-lg border bg-muted/30 p-2.5 font-mono text-[11px]">
                      {JSON.stringify(graphData.coverage, null, 2)}
                    </pre>
                  ) : null}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Tab 6: Config Snapshot */}
          <TabsContent value="config">
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="text-base">任务配置快照</CardTitle>
                  <CardDescription className="text-xs">随时点击右侧按钮修改测绘语句、并发、凭据或八大护栏</CardDescription>
                </div>
                <Button size="sm" variant="outline" onClick={() => setEditOpen(true)}>
                  <Pencil className="mr-1.5 size-3.5" /> 编辑任务配置
                </Button>
              </CardHeader>
              <CardContent className="grid grid-cols-1 gap-4 text-xs md:grid-cols-2">
                <div className="space-y-2 rounded-lg border p-3">
                  <div><span className="text-muted-foreground">测绘来源：</span>{task?.target_source} ({task?.engine || "默认"})</div>
                  <div><span className="text-muted-foreground">查询语句：</span><span className="font-mono">{task?.fofa_query || "-"}</span></div>
                  <div><span className="text-muted-foreground">手动目标：</span>{task?.manual_targets?.length ?? 0} 条</div>
                  <div><span className="text-muted-foreground">绑定凭据：</span>{task?.auth_bindings?.length ?? 0} 条</div>
                </div>
                <div className="space-y-2 rounded-lg border p-3">
                  <div><span className="text-muted-foreground">并发 / 深挖上限：</span>{task?.concurrency} / {task?.deepen_cap}</div>
                  <div><span className="text-muted-foreground">漏洞方向：</span>{(task?.vuln_types || []).join("、") || "全面挖掘"}</div>
                  <div><span className="text-muted-foreground">八大操作护栏：</span>{(task?.guard_ops || []).join(", ") || "无"}</div>
                  <div><span className="text-muted-foreground">附加 SRC 规则：</span>{task?.src_rules || "-"}</div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>

      {/* Edit Task Modal (reusing CreateTaskDialog) */}
      <CreateTaskDialog
        open={editOpen}
        onOpenChange={setEditOpen}
        editTask={task}
        onCreated={async () => {
          await loadCore(true);
        }}
      />

      {/* Target Trace Drawer */}
      <Sheet open={Boolean(traceTarget)} onOpenChange={(o) => !o && setTraceTarget(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle>目标执行轨迹回放</SheetTitle>
            <SheetDescription className="truncate font-mono text-xs">{traceTarget?.label}</SheetDescription>
          </SheetHeader>
          <div className="mt-4 space-y-2">
            {traceLoading ? (
              <p className="py-10 text-center text-xs text-muted-foreground">正在拉取细粒度轨迹事件…</p>
            ) : traceEvents.length === 0 ? (
              <p className="py-10 text-center text-xs text-muted-foreground">暂无该目标的执行轨迹记录</p>
            ) : (
              traceEvents.map((ev, idx) => (
                <div key={idx} className="rounded-lg border bg-muted/20 p-2.5 text-xs space-y-1">
                  <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                    <Badge variant="outline" className="font-mono text-[10px]">{String(ev.kind ?? "trace")}</Badge>
                    <span>{String(ev.ts ?? "").replace("T", " ").slice(0, 19)}</span>
                  </div>
                  <div className="break-all leading-relaxed">{String(ev.message ?? "")}</div>
                </div>
              ))
            )}
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}

export default function TaskDetailPage() {
  return (
    <React.Suspense fallback={<div className="p-8 text-center text-sm text-muted-foreground">正在加载任务作战大屏…</div>}>
      <TaskDetailInner />
    </React.Suspense>
  );
}
