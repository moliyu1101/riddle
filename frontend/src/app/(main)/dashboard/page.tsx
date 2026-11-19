"use client";

import * as React from "react";
import Link from "next/link";
import {
  Activity,
  ArrowRight,
  Brain,
  Bug,
  CheckCircle2,
  Flame,
  Pause,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Skeleton } from "@/components/ui/skeleton";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  riddleApi,
  type CveFeedItem,
  type FusionStatusResponse,
  type HardTargetsStats,
  type IntelStats,
  type InterceptItem,
  type RiddleTask,
  type RiddleVulnStats,
} from "@/lib/riddle-api";

const SRC_LABEL: Record<string, string> = {
  edusrc: "EduSRC",
  enterprise: "企业SRC",
};

const SOURCE_LABEL: Record<string, string> = {
  fofa: "测绘",
  manual: "手动",
  both: "测绘+手动",
  site: "单站协作",
};

function getProgressPct(t: RiddleTask): number {
  const total = Number(t.total_targets ?? t.stats?.total_targets ?? 0);
  const done = Number(t.stats?.done_targets ?? 0);
  if (total > 0) return Math.min(100, Math.round((done / total) * 100));
  if (typeof t.progress === "number") return Math.min(100, Math.max(0, Math.round(t.progress)));
  return 0;
}

export default function DashboardPage() {
  const [loading, setLoading] = React.useState(true);
  const [refreshing, setRefreshing] = React.useState(false);
  const [tasks, setTasks] = React.useState<RiddleTask[]>([]);
  const [vulnStats, setVulnStats] = React.useState<RiddleVulnStats | null>(null);
  const [vulns, setVulns] = React.useState<Array<Record<string, unknown>>>([]);
  const [hardStats, setHardStats] = React.useState<HardTargetsStats | null>(null);
  const [intelStats, setIntelStats] = React.useState<IntelStats | null>(null);
  const [fusion, setFusion] = React.useState<FusionStatusResponse | null>(null);
  const [intercepts, setIntercepts] = React.useState<InterceptItem[]>([]);
  const [cves, setCves] = React.useState<CveFeedItem[]>([]);
  const [logStats, setLogStats] = React.useState<{ total: number; errors: number; warns: number } | null>(null);
  const [skillCount, setSkillCount] = React.useState<number>(0);

  const loadAll = React.useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    setRefreshing(true);
    try {
      const [tRes, vsRes, vRes, hsRes, isRes, fRes, iRes, cRes, lRes, sRes] = await Promise.allSettled([
        riddleApi.listTasks(),
        riddleApi.getVulnStats(),
        riddleApi.listVulns({ sort: "time_desc", limit: 8 }),
        riddleApi.getHardTargetsStats(),
        riddleApi.getIntelStats(),
        riddleApi.getFusionStatus(),
        riddleApi.listIntercepts({ status: "pending" }),
        riddleApi.getRecentCves(6),
        riddleApi.getRuntimeLogStats(),
        riddleApi.getSkillIndex(),
      ]);
      if (tRes.status === "fulfilled") setTasks(tRes.value);
      if (vsRes.status === "fulfilled") setVulnStats(vsRes.value);
      if (vRes.status === "fulfilled") setVulns(vRes.value.items ?? []);
      if (hsRes.status === "fulfilled") setHardStats(hsRes.value);
      if (isRes.status === "fulfilled") setIntelStats(isRes.value);
      if (fRes.status === "fulfilled") setFusion(fRes.value);
      if (iRes.status === "fulfilled") setIntercepts(iRes.value.items ?? []);
      if (cRes.status === "fulfilled") setCves(cRes.value.items ?? []);
      if (lRes.status === "fulfilled") setLogStats(lRes.value);
      if (sRes.status === "fulfilled") setSkillCount(sRes.value.count ?? 0);
    } catch (err) {
      toast.error(`加载态势失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  React.useEffect(() => {
    void loadAll(false);
    const timer = setInterval(() => void loadAll(true), 12000);
    return () => clearInterval(timer);
  }, [loadAll]);

  const handleToggleTask = async (task: RiddleTask) => {
    try {
      if (task.status === "running") {
        await riddleApi.pauseTask(task.id);
        toast.success(`已暂停任务：${task.name}`);
      } else {
        await riddleApi.startTask(task.id);
        toast.success(`已启动任务：${task.name}`);
      }
      await loadAll(true);
    } catch (err) {
      toast.error(`操作失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const runningCount = tasks.filter((t) => t.status === "running").length;
  const pausedOrIdleCount = tasks.filter((t) => t.status !== "running" && t.status !== "done").length;
  const totalTargets = tasks.reduce((acc, t) => acc + Number(t.total_targets ?? t.stats?.total_targets ?? 0), 0);
  const pendingReviewTotal = tasks.reduce((acc, t) => acc + Number(t.pending_user_review ?? 0), 0);
  const totalRawVulns = tasks.reduce((acc, t) => acc + Number(t.total_vulns ?? 0), 0);
  const cfg = fusion?.config;
  const roleEntries = Object.entries((fusion?.role_routing as Record<string, { model?: string; enabled?: boolean }> | undefined) ?? {});

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="作战总览"
        description="知蠹 Riddle 全局作战态势：任务调度、AI/人工漏洞复审漏斗、硬骨头与通杀、融合三层护栏与多角色路由。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void loadAll(true)} disabled={refreshing}>
              <RefreshCw className={`mr-1.5 size-3.5 ${refreshing ? "animate-spin" : ""}`} />
              刷新
            </Button>
            <Button size="sm" asChild>
              <Link href="/function/tasks">
                <Target className="mr-1.5 size-3.5" />
                管理任务
              </Link>
            </Button>
            <Button variant="secondary" size="sm" asChild>
              <Link href="/function/findings">
                <Bug className="mr-1.5 size-3.5" />
                进入复审
              </Link>
            </Button>
          </>
        }
      />

      {/* Top 5 Riddle KPI Cards */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center justify-between text-xs">
              <span>挖掘任务</span>
              <Target className="size-4 text-muted-foreground" />
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {loading ? <Skeleton className="h-7 w-16" /> : `${runningCount} / ${tasks.length}`}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            运行中 {runningCount} · 待命/暂停 {pausedOrIdleCount}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center justify-between text-xs">
              <span>漏洞复审漏斗</span>
              <Bug className="size-4 text-muted-foreground" />
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {loading ? <Skeleton className="h-7 w-16" /> : pendingReviewTotal}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            待复审 {pendingReviewTotal} · 过审 {vulnStats?.total ?? 0} · 已提交 {vulnStats?.submitted ?? 0} (总发现 {totalRawVulns})
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center justify-between text-xs">
              <span>探测目标与硬骨头</span>
              <Flame className="size-4 text-muted-foreground" />
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {loading ? <Skeleton className="h-7 w-16" /> : totalTargets}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            硬骨头 {hardStats?.dead ?? 0} · 跳过 {hardStats?.skipped ?? 0}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center justify-between text-xs">
              <span>跨任务情报与技能</span>
              <Sparkles className="size-4 text-muted-foreground" />
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {loading ? <Skeleton className="h-7 w-16" /> : intelStats?.total ?? 0}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            验证 {intelStats?.verified ?? 0} · 复用 {intelStats?.reused ?? 0} · CVE {fusion?.intel_feed_count ?? 0} · 技能 {skillCount}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription className="flex items-center justify-between text-xs">
              <span>护栏审批与运行健康</span>
              <ShieldAlert className="size-4 text-muted-foreground" />
            </CardDescription>
            <CardTitle className="text-2xl tabular-nums">
              {loading ? <Skeleton className="h-7 w-16" /> : intercepts.length}
            </CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            待审批 {intercepts.length} · 异常日志 {logStats?.errors ?? 0} 错误 / {logStats?.warns ?? 0} 告警
          </CardContent>
        </Card>
      </div>

      {/* Main Operations & Fusion Governance Grid */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Left 2/3: Tasks Live Table */}
        <Card className="lg:col-span-2">
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-base">近期挖掘任务</CardTitle>
              <CardDescription className="text-xs">支持 EduSRC / 企业SRC 双模式与 6 大空间测绘引擎</CardDescription>
            </div>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/function/tasks">
                全部任务 <ArrowRight className="ml-1 size-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>任务名称</TableHead>
                    <TableHead>类型 / 来源</TableHead>
                    <TableHead className="w-[150px]">目标进度</TableHead>
                    <TableHead className="text-right">待审 / 漏洞</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={6} className="h-24 text-center text-sm text-muted-foreground">
                        正在加载任务数据…
                      </TableCell>
                    </TableRow>
                  ) : tasks.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="h-24 text-center text-sm text-muted-foreground">
                        暂无挖掘任务，点击右上角「管理任务」创建第一个 EduSRC / 企业SRC 自主挖掘任务。
                      </TableCell>
                    </TableRow>
                  ) : (
                    tasks.slice(0, 6).map((t) => {
                      const pct = getProgressPct(t);
                      const done = Number(t.stats?.done_targets ?? 0);
                      const total = Number(t.total_targets ?? t.stats?.total_targets ?? 0);
                      return (
                        <TableRow key={t.id}>
                          <TableCell className="font-medium">
                            <Link
                              href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}
                              className="hover:text-primary hover:underline"
                            >
                              {t.name}
                            </Link>
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap items-center gap-1">
                              <Badge variant="outline" className="text-xs">
                                {SRC_LABEL[t.src_type] ?? t.src_type}
                              </Badge>
                              <Badge variant="secondary" className="text-xs uppercase">
                                {t.engine || SOURCE_LABEL[t.target_source] || t.target_source}
                              </Badge>
                            </div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <Progress value={pct} className="h-1.5 flex-1" />
                              <span className="text-xs text-muted-foreground tabular-nums">
                                {done}/{total}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="text-right text-xs tabular-nums">
                            <span className="font-medium text-amber-600 dark:text-amber-400">
                              {t.pending_user_review ?? 0}
                            </span>
                            <span className="text-muted-foreground"> / {t.total_vulns ?? 0}</span>
                          </TableCell>
                          <TableCell>
                            <StatusBadge domain="task" value={t.status} dot />
                          </TableCell>
                          <TableCell className="text-right">
                            <Button variant="ghost" size="sm" onClick={() => void handleToggleTask(t)}>
                              {t.status === "running" ? (
                                <>
                                  <Pause className="mr-1 size-3.5" /> 暂停
                                </>
                              ) : (
                                <>
                                  <Play className="mr-1 size-3.5" /> 启动
                                </>
                              )}
                            </Button>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Right 1/3: Fusion Three Hard Gates & 4-Role Routing */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base">融合护栏与角色路由</CardTitle>
              <Link href="/system/intercept" className="text-xs text-primary hover:underline">
                治理中心
              </Link>
            </div>
            <CardDescription className="text-xs">三大硬闸门状态与 4 角色分层路由</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2 rounded-lg border p-3">
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 font-medium">
                  <ShieldCheck className="size-3.5 text-emerald-500" /> 证据硬闸门 (L1–L4)
                </span>
                <Badge variant={cfg?.evidence_gate_hard ? "default" : "secondary"}>
                  {cfg?.evidence_gate_hard ? "强拦截" : "仅试算"}
                </Badge>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 font-medium">
                  <ShieldAlert className="size-3.5 text-blue-500" /> 范围硬守卫
                </span>
                <Badge variant={cfg?.scope_guard_hard ? "default" : "secondary"}>
                  {cfg?.scope_guard_hard ? "强拦截" : "仅分类"}
                </Badge>
              </div>
              <div className="flex items-center justify-between text-xs">
                <span className="flex items-center gap-1.5 font-medium">
                  <Activity className="size-3.5 text-violet-500" /> 实证流量留痕
                </span>
                <Badge variant={cfg?.traffic_enabled ? "default" : "secondary"}>
                  {cfg?.traffic_enabled ? "已开启" : "已关闭"}
                </Badge>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-medium text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Brain className="size-3.5" /> 多角色模型路由
                </span>
                <span>{cfg?.role_routing_enabled ? "已启用" : "全局继承"}</span>
              </div>
              {roleEntries.length === 0 ? (
                <p className="text-xs text-muted-foreground">正在等待后端角色路由信息…</p>
              ) : (
                <div className="space-y-1.5">
                  {roleEntries.map(([role, info]) => (
                    <div key={role} className="flex items-center justify-between rounded border px-2.5 py-1.5 text-xs">
                      <span className="font-mono font-medium uppercase">{role}</span>
                      <span className="truncate max-w-[160px] text-muted-foreground">
                        {info?.model || "继承全局主力模型"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Bottom 2-Column Strip: Confirmed Vulns + Recent CVE Feeds */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-base">复审通过漏洞库速览</CardTitle>
              <CardDescription className="text-xs">人工复审通过的全局漏洞资产，可直接导出公文级 Word 报告</CardDescription>
            </div>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/function/findings">
                查看全部 <ArrowRight className="ml-1 size-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {vulns.length === 0 ? (
              <div className="flex h-24 items-center justify-center text-xs text-muted-foreground">
                暂无已过审漏洞，可在「漏洞与复审」中完成人工复审通过。
              </div>
            ) : (
              vulns.slice(0, 5).map((v) => {
                const sev = String(v.effective_severity ?? "中危");
                const submitted = Boolean(v.submitted);
                return (
                  <div key={String(v.id)} className="flex items-center justify-between gap-3 rounded-lg border px-3 py-2">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <StatusBadge domain="severity" value={sev} />
                        <span className="truncate font-medium text-sm">{String(v.title ?? "未命名漏洞")}</span>
                      </div>
                      <p className="mt-0.5 truncate text-xs text-muted-foreground">
                        {String(v.task_name ?? "")} · {String(v.target_url ?? "")}
                      </p>
                    </div>
                    <Badge variant={submitted ? "default" : "outline"} className="shrink-0 text-xs">
                      {submitted ? (
                        <span className="flex items-center gap-1">
                          <CheckCircle2 className="size-3" /> 已提交
                        </span>
                      ) : (
                        "待提交"
                      )}
                    </Badge>
                  </div>
                );
              })
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between pb-3">
            <div>
              <CardTitle className="text-base">最新 CVE / KEV 情报时间流</CardTitle>
              <CardDescription className="text-xs">来自 NVD / CISA KEV 实时同步，自动反查任务目标指纹</CardDescription>
            </div>
            <Button variant="ghost" size="sm" asChild>
              <Link href="/system/vulnintel">
                情报与 CVE <ArrowRight className="ml-1 size-3.5" />
              </Link>
            </Button>
          </CardHeader>
          <CardContent className="space-y-2">
            {cves.length === 0 ? (
              <div className="flex h-24 items-center justify-center text-xs text-muted-foreground">
                暂无最新 CVE 时间流记录，请前往「情报与 CVE」手动触发一次同步。
              </div>
            ) : (
              cves.slice(0, 5).map((cve) => (
                <div key={cve.cve_id || cve.match_key} className="flex items-start justify-between gap-3 rounded-lg border px-3 py-2">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="font-mono font-semibold text-xs">{cve.cve_id || cve.match_key}</span>
                      {cve.kev && <Badge variant="destructive" className="text-[11px]">KEV 在野</Badge>}
                      <Badge variant="outline" className="text-[11px] tabular-nums">
                        CVSS {Number(cve.cvss ?? 0).toFixed(1)}
                      </Badge>
                    </div>
                    <p className="mt-1 line-clamp-1 text-xs text-muted-foreground">{cve.summary || cve.products?.join(", ")}</p>
                  </div>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
