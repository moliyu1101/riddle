"use client";

import * as React from "react";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";

import { ArchiveIcon, ArrowLeftIcon, BotIcon, BrainIcon, CheckIcon, CircleAlertIcon, PauseIcon, PlayIcon } from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { TaskLLMProfileChain } from "@/components/task-llm-profile-chain";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverDescription,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { Spinner } from "@/components/ui/spinner";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { api } from "@/lib/api";
import type { LLMProfile, Task } from "@/lib/types";

import { AssetsTab } from "./_tabs/assets-tab";
import { BroadcastTab } from "./_tabs/broadcast-tab";
import { CoverageGraphTab } from "./_tabs/coverage-graph-tab";
import { FindingsTab } from "./_tabs/findings-tab";
import { GraphTab } from "./_tabs/graph-tab";
import { InterceptTab } from "./_tabs/intercept-tab";
import { OverviewTab } from "./_tabs/overview-tab";
import { ReportTab } from "./_tabs/report-tab";
import { RetestsTab } from "./_tabs/retests-tab";
import { SessionsTab } from "./_tabs/sessions-tab";

const TABS = [
  { value: "sessions", label: "会话" },
  { value: "overview", label: "总览" },
  { value: "graph", label: "探索链路" },
  { value: "broadcast", label: "播报板" },
  { value: "findings", label: "发现" },
  { value: "retests", label: "复测" },
  { value: "assets", label: "测试资产" },
  { value: "coverage", label: "资产覆盖图" },
  { value: "intercept", label: "拦截审批" },
  { value: "report", label: "报告" },
];

function taskProfileIDs(task: Task): string[] {
  if (task.llm_profile_ids && task.llm_profile_ids.length > 0) {
    return task.llm_profile_ids.map(String);
  }
  return task.llm_profile_id ? [String(task.llm_profile_id)] : [];
}

function TaskLLMControl({ task, profiles, onUpdated }: { task: Task; profiles: LLMProfile[]; onUpdated: () => void }) {
  const [open, setOpen] = React.useState(false);
  const [profileIDs, setProfileIDs] = React.useState<string[]>(() => taskProfileIDs(task));
  const [activeProfileID, setActiveProfileID] = React.useState(
    task.active_llm_profile_id ? String(task.active_llm_profile_id) : (taskProfileIDs(task)[0] ?? ""),
  );
  const [saving, setSaving] = React.useState(false);
  const popoverContentRef = React.useRef<HTMLDivElement>(null);

  const chain = taskProfileIDs(task);
  const exhausted = task.llm_failover_state === "chain_exhausted";
  // 任何状态都可以改链,终态也不例外:任务结束后主 Agent 对话仍走这条链,
  // 链上模型出问题时必须能换掉,否则已完成任务就没法继续交互。
  const terminal = ["done", "failed", "timeout"].includes(task.status);
  // A null active profile on an exhausted, non-empty chain is a persisted end
  // cursor. Keep the status display honest; choosing the first profile is only
  // the editor's reset draft and does not mean it is currently active.
  let activeID = chain[0] ?? "";
  if (exhausted) activeID = "";
  if (task.active_llm_profile_id) activeID = String(task.active_llm_profile_id);
  const activeProfile = profiles.find((profile) => profile.id === activeID);
  const currentLabel = exhausted
    ? "配置链已耗尽"
    : (activeProfile?.name ?? (activeID ? `配置 #${activeID}` : "跟随默认配置"));
  const activeIndex = chain.indexOf(activeID);
  const backupCount = activeIndex >= 0 ? Math.max(0, chain.length - activeIndex - 1) : 0;
  const currentTitle = [currentLabel, activeProfile?.model, backupCount > 0 ? `${backupCount} 个备用` : ""]
    .filter(Boolean)
    .join(" · ");
  let editorDescription = "调整顺序或当前配置后，将从下一次 LLM 调用开始生效。";
  if (terminal) editorDescription = "任务已结束，改动只影响后续的主 Agent 对话。";
  let saveLabel = "保存";
  if (exhausted) saveLabel = "保存并重置";
  if (saving) saveLabel = "保存中";

  const syncDraft = React.useCallback(() => {
    const next = taskProfileIDs(task);
    setProfileIDs(next);
    setActiveProfileID(task.active_llm_profile_id ? String(task.active_llm_profile_id) : (next[0] ?? ""));
  }, [task]);

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (next) syncDraft();
  };

  const handleProfileIDsChange = (next: string[]) => {
    setProfileIDs(next);
    setActiveProfileID((current) => (next.includes(current) ? current : (next[0] ?? "")));
  };

  const save = async () => {
    setSaving(true);
    try {
      const result = await api.updateTaskLLMProfiles(
        task.id,
        profileIDs.map(Number),
        activeProfileID ? Number(activeProfileID) : undefined,
      );
      if (result.switch_event) {
        toast.info(result.switch_event.summary, { id: `task-${task.id}-llm-${result.switch_event.seq}` });
      } else {
        toast.success(
          result.reopened_intents > 0
            ? `LLM 配置已更新，并恢复 ${result.reopened_intents} 条额度阻塞意图`
            : "LLM 配置已更新",
        );
      }
      setOpen(false);
      onUpdated();
    } catch (error) {
      toast.error(`更新失败：${(error as Error).message}`);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <Button
          size="sm"
          variant={exhausted ? "destructive" : "outline"}
          aria-label="查看或切换任务 LLM 配置"
          title={currentTitle}
        >
          <BrainIcon data-icon="inline-start" />
          <span className="hidden max-w-36 truncate lg:inline">{currentLabel}</span>
          {backupCount > 0 && <span className="hidden text-muted-foreground xl:inline">+{backupCount}</span>}
        </Button>
      </PopoverTrigger>
      <PopoverContent ref={popoverContentRef} align="start" className="w-[min(28rem,calc(100vw-2rem))] gap-4 p-4">
        <PopoverHeader>
          <PopoverTitle>任务 LLM 配置链</PopoverTitle>
          <PopoverDescription>{editorDescription}</PopoverDescription>
        </PopoverHeader>

        {exhausted && (
          <Alert variant="destructive">
            <CircleAlertIcon />
            <AlertTitle>配置链额度已耗尽</AlertTitle>
            <AlertDescription>
              {task.llm_failover_reason ?? "所有已选配置均被判定为额度不足。保存配置链可重置故障状态。"}
            </AlertDescription>
          </Alert>
        )}

        <TaskLLMProfileChain
          profiles={profiles}
          value={profileIDs}
          onValueChange={handleProfileIDsChange}
          activeProfileId={activeProfileID}
          onActiveProfileChange={setActiveProfileID}
          inputId="task-llm-profiles"
          disabled={saving}
          portalContainer={popoverContentRef}
        />

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" size="sm" onClick={() => setOpen(false)}>
            关闭
          </Button>
          <Button type="button" size="sm" onClick={save} disabled={saving}>
            {saving && <Spinner data-icon="inline-start" />}
            {saveLabel}
          </Button>
        </div>
      </PopoverContent>
    </Popover>
  );
}

function TaskDetailInner() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const id = searchParams.get("id") ?? "";
  const [task, setTask] = React.useState<Task | null>(null);
  const [paused, setPaused] = React.useState(false);
  const [loaded, setLoaded] = React.useState(false);
  const [tab, setTab] = React.useState(searchParams.get("tab") || "sessions");
  const [interceptPendingCount, setInterceptPendingCount] = React.useState(0);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [archiving, setArchiving] = React.useState(false);

  React.useEffect(() => {
    api
      .llmProfiles()
      .then(setProfiles)
      .catch(() => setProfiles([]));
  }, []);

  // 任务不存在时停止**所有**与该任务相关的轮询。
  //
  // 为什么：任务被删/归档后，/api/tasks/{id} 一直返回 404，但页面仍每 5 秒
  // 拉一次 —— 实测一个已删除的任务详情页在 50 秒内发了 10 次 404（外加同样
  // 次数的 stats 404），全程没有任何信息量。UI 本来就能显示「任务已被删除」
  // （见下面的 !task 分支），所以停掉轮询不会丢任何用户可见的信息。
  //
  // 只在 404（资源确实不存在）时停：网络抖动、5xx 属于临时故障，继续重试。
  //
  // 这个标志是**共享**的：本页有两处与任务相关的轮询（任务本身 + 该任务的
  // 待审批数），两处都要停——漏一处就等于没修。
  // 用 state 而不是 ref：两个轮询（任务本身 + 该任务的待审批数）是两个独立
  // 的 effect，用 ref 的话「谁先拿到 404」就变成竞态——拦截那个 API 对不存在的
  // 任务返回的是 200 空列表（不是 404），它自己永远发现不了任务没了。
  // 做成 state 后，任务轮询一旦确认缺失，另一个 effect 立即重建并停掉。
  const [taskMissing, setTaskMissing] = React.useState(false);

  React.useEffect(() => {
    if (taskMissing) return;
    let alive = true;
    const load = () => {
      api
        .interceptTask(id)
        .then((rows) => {
          if (alive) setInterceptPendingCount(rows.filter((r) => r.status === "pending").length);
        })
        .catch(() => {
          // Polling is best-effort; the next interval retries automatically.
        });
    };
    void load();
    const t = setInterval(load, 5000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [id, taskMissing]);

  const taskLoadInFlight = React.useRef<string | null>(null);
  const load = React.useCallback(() => {
    if (taskLoadInFlight.current === id) return;
    // 任务已确认不存在 → 不再拉。taskMissing 进依赖后，这个 useCallback 会重建，
    // 上面的 effect 也会随之重建（用的是新的 load），轮询就此停下。
    if (taskMissing) return;
    taskLoadInFlight.current = id;
    Promise.all([api.task(id), api.stats(id).catch(() => null)])
      .then(([task, s]) => {
        if (taskLoadInFlight.current !== id) return;
        const base = { ...task };
        const at = s?.active_task;
        if (at) {
          base.in_flight = at.in_flight;
          base.goals_total = at.goals_total;
          base.goals_met = at.goals_met;
          base.engine_mode = s?.engine_mode ?? at.engine_mode;
          base.paused = at.paused;
        }
        setTask(base);
        setPaused(at?.paused ?? base.paused ?? false);
        setAutopilot(Boolean(base.autopilot));
      })
      .catch((err: unknown) => {
        const status = (err as { status?: number } | null)?.status;
        if (status === 404) {
          // 任务真的不在了：停轮询，UI 显示「已被删除」。
          setTaskMissing(true);
        }
        // 其他错误（含 5xx/网络）保留上一次渲染状态，下一轮继续试。
      })
      .finally(() => {
        if (taskLoadInFlight.current === id) {
          taskLoadInFlight.current = null;
          setLoaded(true);
        }
      });
  }, [id, taskMissing]);
  React.useEffect(() => {
    load();
    const timer = setInterval(load, 5000);
    return () => clearInterval(timer);
  }, [load]);

  const [autopilot, setAutopilot] = React.useState(false);
  const [togglingAutopilot, setTogglingAutopilot] = React.useState(false);

  async function toggleAutopilot() {
    if (!task) return;
    const next = !autopilot;
    setTogglingAutopilot(true);
    try {
      // 开启时顺带 resume：暂停/排队中的任务一键继续，这就是「一键推进」。
      const r = await api.setTaskAutopilot(task.id, next, next);
      setAutopilot(next);
      if (r.resumed) setPaused(false);
      toast.success(next ? (r.resumed ? "已开启自主推进并恢复任务" : "已开启自主推进") : "已关闭自主推进");
    } catch (e) {
      toast.error(`操作失败：${(e as Error).message}`);
    } finally {
      setTogglingAutopilot(false);
    }
  }

  async function togglePause() {
    if (task && ["done", "failed", "timeout"].includes(task.status)) return;
    const next = !paused;
    try {
      await api.controlTask(id, next ? "pause" : "resume");
      setPaused(next);
      toast.success(next ? "已暂停探索" : "已恢复探索");
    } catch (e) {
      toast.error(`操作失败：${(e as Error).message}`);
    }
  }

  async function archiveTask() {
    if (!task || archiving) return;
    setArchiving(true);
    try {
      await api.archiveTask(task.id);
      toast.success("任务已加入归档队列");
      router.push("/function/tasks");
    } catch (error) {
      toast.error(`归档失败：${(error as Error).message}`);
      setArchiving(false);
    }
  }

  if (!task) {
    return (
      <div className="flex flex-1 flex-col items-center justify-center gap-3 p-10 text-center">
        <p className="text-muted-foreground">{loaded ? `任务 ${id} 已被删除、归档或不存在` : "加载中…"}</p>
        {loaded && (
          <Button asChild variant="outline">
            <Link href="/function/tasks">
              <ArrowLeftIcon /> 返回任务列表
            </Link>
          </Button>
        )}
      </div>
    );
  }

  const completed = task.status === "done";
  const terminal = ["done", "failed", "timeout"].includes(task.status);
  const archiveLifecycleEligible = terminal || paused || task.status === "paused";
  const canArchive = archiveLifecycleEligible && !task.archive_blocked_by_task_id;
  let archiveDisabledReason = task.queued ? "排队中的任务必须先暂停" : "运行中的任务必须先暂停";
  if (archiveLifecycleEligible && task.archive_blocked_by_task_id) {
    archiveDisabledReason = `任务被未归档任务 #${task.archive_blocked_by_task_id} 直接继承，请先归档依赖任务`;
  }
  const engineMode = paused ? "paused" : (task.engine_mode ?? "idle");
  let controlVariant: "default" | "secondary" | "outline" = "outline";
  let controlIcon = <PauseIcon data-icon="inline-start" />;
  let controlLabel = "暂停";
  if (terminal) {
    controlVariant = "secondary";
    controlIcon = <CheckIcon data-icon="inline-start" />;
    controlLabel = completed ? "已完成" : "已结束";
  } else if (paused) {
    controlVariant = "default";
    controlIcon = <PlayIcon data-icon="inline-start" />;
    controlLabel = "恢复";
  }
  const archiveTrigger = (
    <Button
      size="icon-sm"
      variant="ghost"
      disabled={!canArchive || archiving}
      aria-label={canArchive ? "归档任务" : archiveDisabledReason}
    >
      {archiving ? <Spinner /> : <ArchiveIcon />}
    </Button>
  );

  return (
    <Tabs value={tab} onValueChange={setTab} className="flex flex-1 flex-col gap-0">
      {/* Top fixed area */}
      <header className="sticky top-0 z-10 flex flex-col gap-2 border-b bg-background/95 px-4 py-2.5 backdrop-blur lg:px-6">
        <div className="flex items-center gap-2">
          <SidebarTrigger className="-ml-1" />
          <Button asChild variant="ghost" size="icon" className="size-7">
            <Link href="/function/tasks">
              <ArrowLeftIcon />
            </Link>
          </Button>
          <h1 className="min-w-0 flex-1 truncate font-semibold text-sm" title={task.name || task.description}>
            {task.name || task.description}
          </h1>
          <code className="hidden rounded bg-muted px-1.5 py-0.5 font-mono text-muted-foreground text-xs sm:inline">
            {task.id}
          </code>
          <Separator orientation="vertical" className="mx-1 hidden h-4 sm:block" />
          <span className="hidden sm:inline-flex">
            <TaskLLMControl task={task} profiles={profiles} onUpdated={load} />
          </span>
          <span className="hidden sm:inline-flex">
            <StatusBadge domain={terminal ? "task" : "engine"} value={terminal ? task.status : engineMode} dot />
          </span>
          <span className="hidden sm:inline-flex">{canArchive ? (
            <AlertDialog>
              <AlertDialogTrigger asChild>{archiveTrigger}</AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>归档任务 #{task.id}？</AlertDialogTitle>
                  <AlertDialogDescription>
                    任务图谱、关联记录、独占资产与流量、工作文件和 LLM
                    历史将压缩到冷存储。归档完成后可在任务列表的“已归档”页还原。
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>取消</AlertDialogCancel>
                  <AlertDialogAction onClick={() => void archiveTask()}>确认归档</AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          ) : (
            <Tooltip>
              <TooltipTrigger asChild>
                <span className="inline-flex">{archiveTrigger}</span>
              </TooltipTrigger>
              <TooltipContent>{archiveDisabledReason}</TooltipContent>
            </Tooltip>
          )}
          </span>
          <Button
            size="sm"
            variant={autopilot ? "default" : "outline"}
            onClick={toggleAutopilot}
            disabled={terminal || togglingAutopilot}
            title="自主推进：停滞自动重规划、目标未达成不收尾、deadline 自动延长（审批门照常生效）"
          >
            <BotIcon className="size-4" />
            {autopilot ? "自主推进中" : "自主推进"}
          </Button>
          <Button size="sm" variant={controlVariant} onClick={togglePause} disabled={terminal}>
            {controlIcon}
            {controlLabel}
          </Button>
        </div>
        {/* 手机端第二行：状态/模型/归档（桌面在首行） */}
        <div className="flex flex-wrap items-center gap-2 sm:hidden">
          <StatusBadge domain={terminal ? "task" : "engine"} value={terminal ? task.status : engineMode} dot />
          <TaskLLMControl task={task} profiles={profiles} onUpdated={load} />
          <span className="inline-flex">{archiveTrigger}</span>
        </div>
        <p className="line-clamp-2 text-muted-foreground text-xs sm:truncate">{task.goal}</p>
        {/* Tabs */}
        <div className="no-scrollbar min-w-0 overflow-x-auto max-sm:[mask-image:linear-gradient(to_right,#000_88%,transparent)]">
          <TabsList variant="default" className="min-w-max">
            {TABS.map((t) => (
              <TabsTrigger key={t.value} value={t.value}>
                {t.label}
                {t.value === "intercept" && interceptPendingCount > 0 && (
                  <span className="ml-1.5 inline-flex h-4 min-w-[16px] items-center justify-center rounded-full bg-amber-500 px-1 font-semibold text-[10px] text-white leading-none">
                    {interceptPendingCount > 99 ? "99+" : interceptPendingCount}
                  </span>
                )}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
      </header>

      {/* Tab content */}
      <div className="flex-1 p-4 lg:p-6">
        <TabsContent value="sessions" className="mt-0">
          <SessionsTab taskId={id} />
        </TabsContent>
        <TabsContent value="overview" className="mt-0">
          <OverviewTab taskId={id} />
        </TabsContent>
        <TabsContent value="graph" className="mt-0">
          <GraphTab taskId={id} />
        </TabsContent>
        <TabsContent value="broadcast" className="mt-0">
          <BroadcastTab taskId={id} />
        </TabsContent>
        <TabsContent value="findings" className="mt-0">
          <FindingsTab taskId={id} />
        </TabsContent>
        <TabsContent value="retests" className="mt-0">
          <RetestsTab key={id} taskId={id} />
        </TabsContent>
        <TabsContent value="assets" className="mt-0">
          <AssetsTab taskId={id} />
        </TabsContent>
        <TabsContent value="coverage" className="mt-0">
          <CoverageGraphTab taskId={id} coverageEnabled={task?.coverage_enabled !== false} />
        </TabsContent>
        <TabsContent value="intercept" className="mt-0">
          <InterceptTab taskId={id} />
        </TabsContent>
        <TabsContent value="report" className="mt-0">
          <ReportTab taskId={id} />
        </TabsContent>
      </div>
    </Tabs>
  );
}

// useSearchParams must sit under a Suspense boundary for static export.
export default function TaskDetailPage() {
  return (
    <React.Suspense fallback={null}>
      <TaskDetailInner />
    </React.Suspense>
  );
}
