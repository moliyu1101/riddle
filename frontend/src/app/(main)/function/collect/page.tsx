"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  AlertCircle,
  Brain,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Database,
  FileText,
  Loader2,
  Network,
  Radar,
  RefreshCw,
  Rocket,
  Settings2,
  SlidersHorizontal,
  Sparkles,
  Square,
  Terminal,
  Wrench,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { RichMarkdown } from "@/app/(main)/chat/_components/chat-transcript";
import { AssetAutoCollectPanel } from "@/app/(main)/function/assets/_components/asset-auto-collect";
import { fmtDuration, fmtTokens } from "@/lib/chat-utils";
import {
  riddleApi,
  type AICollectPlan,
  type AICollectTraceItem,
  type AssetCollectJobItem,
  type AssetCompanyItem,
  type AssetsOverviewResponse,
} from "@/lib/riddle-api";
import { cn } from "@/lib/utils";

const EXAMPLE_PROMPTS = [
  "帮我全面收集 example.edu.cn 的子域名、IP C 段和存活 Web 服务，重点识别教务、OA、统一认证与管理后台，并自动建立归属主体。",
  "使用已配置的测绘引擎，检索与高校门户/财务/科研相关的暴露资产，完成 DNS 归并与 HTTP 指纹识别，汇总高价值目标清单。",
  "同步平台历史任务中已经发现的资产，对未探测的主机补充 DNS 解析与轻量 HTTP 存活指纹探测，梳理完整攻击面。",
];

function TraceStepCard({ item }: { item: AICollectTraceItem }) {
  const [open, setOpen] = React.useState(item.kind === "summary" || item.kind === "error");
  const hasDetail = Boolean(item.detail && item.detail.trim());

  const icon =
    item.kind === "thinking" ? (
      <Brain className="size-3.5 text-violet-500" />
    ) : item.kind === "tool_use" ? (
      <Wrench className="size-3.5 text-sky-500" />
    ) : item.kind === "tool_result" ? (
      <Terminal className="size-3.5 text-emerald-500" />
    ) : item.kind === "error" ? (
      <AlertCircle className="size-3.5 text-destructive" />
    ) : (
      <CheckCircle2 className="size-3.5 text-primary" />
    );

  const badgeText =
    item.kind === "thinking"
      ? "思考"
      : item.kind === "tool_use"
        ? item.tool_name || "调用工具"
        : item.kind === "tool_result"
          ? item.duration_ms
            ? fmtDuration(item.duration_ms)
            : "返回"
          : item.kind === "error"
            ? "异常"
            : "总结";

  return (
    <div
      className={cn(
        "rounded-lg border text-xs transition-colors",
        item.kind === "error" ? "border-destructive/40 bg-destructive/5" : "bg-background/80",
      )}
    >
      <button
        type="button"
        onClick={() => hasDetail && setOpen((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/40"
      >
        {hasDetail ? (
          open ? (
            <ChevronDown className="size-3.5 shrink-0 text-muted-foreground" />
          ) : (
            <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
          )
        ) : (
          <span className="w-3.5 shrink-0" />
        )}
        <span className="shrink-0">{icon}</span>
        <span className="min-w-0 flex-1 truncate font-medium text-foreground">{item.title}</span>
        <span className="shrink-0 font-mono text-[10px] text-muted-foreground">{item.ts?.slice(11, 19)}</span>
        <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
          {badgeText}
        </Badge>
      </button>
      {open && hasDetail ? (
        <div className="border-t bg-muted/20 px-3 py-2.5">
          {item.kind === "summary" ? (
            <RichMarkdown content={item.detail} />
          ) : (
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-5 text-muted-foreground">
              {item.detail}
            </pre>
          )}
        </div>
      ) : null}
    </div>
  );
}

export default function AIAssetCollectPage() {
  const router = useRouter();

  const [overview, setOverview] = React.useState<AssetsOverviewResponse | null>(null);
  const [companies, setCompanies] = React.useState<AssetCompanyItem[]>([]);
  const [jobs, setJobs] = React.useState<AssetCollectJobItem[]>([]);
  const [loadingJobs, setLoadingJobs] = React.useState(true);
  const [activeJobId, setActiveJobId] = React.useState<string | null>(null);

  // Natural Language Prompt Studio State
  const [prompt, setPrompt] = React.useState("");
  const [companyId, setCompanyId] = React.useState("auto");
  const [preferredEngine, setPreferredEngine] = React.useState("auto");
  const [maxRounds, setMaxRounds] = React.useState(8);

  const [planning, setPlanning] = React.useState(false);
  const [planPreview, setPlanPreview] = React.useState<AICollectPlan | null>(null);
  const [launching, setLaunching] = React.useState(false);
  const [convertingTask, setConvertingTask] = React.useState(false);

  const loadAll = React.useCallback(async () => {
    try {
      const [ov, comp, jRes] = await Promise.all([
        riddleApi.getAssetsOverview(),
        riddleApi.listAssetCompanies(),
        riddleApi.listAssetCollectJobs(30),
      ]);
      setOverview(ov);
      setCompanies(comp.companies ?? []);
      const list = jRes.jobs ?? [];
      setJobs(list);
      if (list.length > 0 && !activeJobId) {
        setActiveJobId(list[0].id);
      }
    } catch {
      // ignore transient polling error
    } finally {
      setLoadingJobs(false);
    }
  }, [activeJobId]);

  React.useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const anyRunning = React.useMemo(() => jobs.some((j) => j.status === "running" || j.running), [jobs]);

  React.useEffect(() => {
    if (!anyRunning) return;
    const timer = window.setInterval(() => {
      void loadAll();
    }, 1800);
    return () => window.clearInterval(timer);
  }, [anyRunning, loadAll]);

  const handlePreviewPlan = async () => {
    if (!prompt.trim()) {
      toast.error("请先输入自然语言资产收集需求");
      return;
    }
    setPlanning(true);
    try {
      const res = await riddleApi.previewAICollectPlan({
        prompt: prompt.trim(),
        preferred_engine: preferredEngine === "auto" ? "" : preferredEngine,
      });
      setPlanPreview(res.plan);
      toast.success("AI 已完成目标拆解与收集策略规划");
    } catch (err) {
      toast.error(`AI 规划失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setPlanning(false);
    }
  };

  const handleLaunchAI = async (customName?: string) => {
    if (!prompt.trim()) {
      toast.error("请用自然语言描述你想收集的资产目标");
      return;
    }
    setLaunching(true);
    try {
      const res = await riddleApi.startAICollectJob({
        prompt: prompt.trim(),
        name: customName || planPreview?.task_name || undefined,
        company_id: companyId === "auto" ? null : companyId,
        preferred_engine: preferredEngine === "auto" ? "" : preferredEngine,
        max_rounds: maxRounds,
      });
      toast.success(`已启动 AI 资产收集任务：${res.job.name}`);
      setActiveJobId(res.job.id);
      setPlanPreview(null);
      await loadAll();
    } catch (err) {
      toast.error(`启动 AI 资产收集失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLaunching(false);
    }
  };

  const handleStopJob = async (jobId: string) => {
    try {
      await riddleApi.stopAssetCollectJob(jobId);
      toast.info("已发送停止信号");
      await loadAll();
    } catch (err) {
      toast.error(`停止失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleConvertCompanyToTask = async (targetCompanyId: string, label: string) => {
    setConvertingTask(true);
    try {
      const res = await riddleApi.createTaskFromAssets({
        company_id: targetCompanyId,
        name: `[资产收集] ${label} 自动化挖掘`,
        start_immediately: true,
      });
      toast.success(`已将 ${res.target_count} 个收集资产转为挖掘任务并启动`);
      router.push(`/function/tasks/detail?id=${encodeURIComponent(res.task.id)}`);
    } catch (err) {
      toast.error(`转换挖掘任务失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setConvertingTask(false);
    }
  };

  const activeJob = jobs.find((j) => j.id === activeJobId) ?? jobs[0] ?? null;
  const llmReady = overview?.llm_ready !== false;

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="AI 自然语言资产收集"
        description="用自然语言描述目标资产与侦察意图，AI 自主思考拆解范围，多轮编排证书透明度、测绘引擎、DNS 解析与 HTTP 指纹探测，并实时沉淀至双图资产中心。"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link href="/function/assets">
                <Network className="mr-1.5 size-3.5" />
                双图资产中心 ({overview?.total_assets ?? 0})
              </Link>
            </Button>
            <Button variant="outline" size="sm" onClick={() => void loadAll()}>
              <RefreshCw className="mr-1.5 size-3.5" /> 刷新
            </Button>
          </div>
        }
      />

      {!llmReady ? (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-700 dark:text-amber-300">
          <span>当前尚未配置可用的大模型 API Key，配置完成后即可启用 AI 自然语言自主收集（或先使用下方「规则批量收集」）。</span>
          <Button size="sm" variant="outline" className="h-7 text-xs" asChild>
            <Link href="/system/llm">
              <Settings2 className="mr-1 size-3.5" /> 前往配置模型
            </Link>
          </Button>
        </div>
      ) : null}

      <Tabs defaultValue="ai" className="space-y-4">
        <TabsList>
          <TabsTrigger value="ai">
            <Sparkles className="mr-1.5 size-3.5" />
            AI 自然语言收集
            {anyRunning ? (
              <Badge variant="default" className="ml-1.5 h-4 px-1 text-[10px]">
                运行中
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="manual">
            <SlidersHorizontal className="mr-1.5 size-3.5" />
            规则批量收集（手动种子）
          </TabsTrigger>
        </TabsList>

        <TabsContent value="ai" className="space-y-4">
          {/* Natural Language Prompt Studio */}
          <Card className="border-primary/20">
            <CardHeader className="pb-3">
              <CardTitle className="flex items-center gap-2 text-base">
                <Brain className="size-4 text-primary" /> 自然语言收集指令台
              </CardTitle>
              <CardDescription className="text-xs">
                像对安全专家下达任务一样描述你要摸排的授权组织、域名、侧重业务系统或排除条件，AI 将自动制定测绘语法并调用工具执行。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3.5">
              <Textarea
                rows={3}
                className="text-sm leading-relaxed"
                placeholder="例如：帮我收集 XX 大学（example.edu.cn）名下的全部子域名、IP C 段、存活 Web 系统及登录入口，优先识别教务/OA/统一认证，并自动建档归属到主体…"
                value={prompt}
                onChange={(e) => setPrompt(e.target.value)}
              />

              {/* Quick example chips */}
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-[11px] text-muted-foreground">示例指令：</span>
                {EXAMPLE_PROMPTS.map((ex, idx) => (
                  <button
                    key={idx}
                    type="button"
                    onClick={() => setPrompt(ex)}
                    className="max-w-full truncate rounded-full border bg-muted/30 px-2.5 py-1 text-[11px] text-muted-foreground hover:border-primary/40 hover:bg-primary/5 hover:text-foreground transition-colors"
                  >
                    {ex.slice(0, 42)}…
                  </button>
                ))}
              </div>

              {/* Options + Action buttons */}
              <div className="flex flex-wrap items-end gap-3 pt-1">
                <div className="space-y-1">
                  <Label className="text-[11px] text-muted-foreground">归属主体</Label>
                  <Select value={companyId} onValueChange={setCompanyId}>
                    <SelectTrigger className="h-8 w-[180px] text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">由 AI 自动识别并创建</SelectItem>
                      {companies.map((c) => (
                        <SelectItem key={c.id} value={c.id}>
                          {c.name}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1">
                  <Label className="text-[11px] text-muted-foreground">优先测绘引擎</Label>
                  <Select value={preferredEngine} onValueChange={setPreferredEngine}>
                    <SelectTrigger className="h-8 w-[190px] text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">AI 自动选用已配 Key 引擎</SelectItem>
                      {(overview?.engines ?? []).map((e) => (
                        <SelectItem key={e.name} value={e.name}>
                          {e.display_name} ({e.key_set ? "已配 Key" : "未配置"})
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-1">
                  <Label className="text-[11px] text-muted-foreground">AI 最大推理轮次</Label>
                  <Select value={String(maxRounds)} onValueChange={(v) => setMaxRounds(Number(v) || 8)}>
                    <SelectTrigger className="h-8 w-[120px] text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="6">6 轮（快速）</SelectItem>
                      <SelectItem value="8">8 轮（均衡）</SelectItem>
                      <SelectItem value="10">10 轮（深度）</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="ml-auto flex flex-wrap items-center gap-2">
                  <Button
                    type="button"
                    variant="outline"
                    size="sm"
                    disabled={planning || launching || !prompt.trim() || !llmReady}
                    onClick={() => void handlePreviewPlan()}
                  >
                    {planning ? <Loader2 className="mr-1.5 size-3.5 animate-spin" /> : <Brain className="mr-1.5 size-3.5" />}
                    先预览 AI 规划
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    disabled={launching || !prompt.trim() || !llmReady}
                    onClick={() => void handleLaunchAI()}
                  >
                    {launching ? <Loader2 className="mr-1.5 size-3.5 animate-spin" /> : <Sparkles className="mr-1.5 size-3.5" />}
                    AI 自主思考并收集
                  </Button>
                </div>
              </div>

              {/* AI Plan Preview Card */}
              {planPreview ? (
                <div className="rounded-lg border border-primary/30 bg-primary/5 p-3.5 text-xs space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2 font-semibold text-sm">
                      <Sparkles className="size-4 text-primary" />
                      AI 规划预览：{planPreview.task_name}
                    </div>
                    <Button size="sm" className="h-7 text-xs" disabled={launching} onClick={() => void handleLaunchAI(planPreview.task_name)}>
                      <Rocket className="mr-1 size-3" /> 按此规划立即收集
                    </Button>
                  </div>
                  <p className="text-muted-foreground">{planPreview.summary}</p>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    <div className="rounded border bg-background/80 p-2 space-y-1">
                      <div className="font-medium">识别主体与种子</div>
                      <div className="text-muted-foreground">
                        主体：{planPreview.company_name || "自动归属"} · 推荐引擎：{planPreview.recommended_engine || "被动+DNS+HTTP"}
                      </div>
                      <div className="flex flex-wrap gap-1 pt-0.5">
                        {(planPreview.seeds ?? []).map((s) => (
                          <Badge key={s} variant="secondary" className="font-mono text-[10px]">
                            {s}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div className="rounded border bg-background/80 p-2 space-y-1">
                      <div className="font-medium">计划测绘语法</div>
                      {(planPreview.queries ?? []).length === 0 ? (
                        <div className="text-muted-foreground">将优先使用 crt.sh + DNS + HTTP 探活</div>
                      ) : (
                        <div className="space-y-1 font-mono text-[11px] text-primary">
                          {planPreview.queries.map((q, i) => (
                            <div key={i} className="truncate">{q}</div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                  {(planPreview.steps ?? []).length > 0 ? (
                    <div className="text-[11px] text-muted-foreground">
                      执行步骤：{planPreview.steps.map((s, i) => `${i + 1}. ${s}`).join(" → ")}
                    </div>
                  ) : null}
                </div>
              ) : null}
            </CardContent>
          </Card>

          {/* Split Live Execution Monitor */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
            {/* Left: Job History */}
            <Card className="lg:col-span-4">
              <CardHeader className="pb-2.5">
                <CardTitle className="text-sm">收集任务记录（{jobs.length}）</CardTitle>
                <CardDescription className="text-xs">点击查看实时思考轨迹、工具结果与摸排报告</CardDescription>
              </CardHeader>
              <CardContent className="space-y-1.5 max-h-[540px] overflow-y-auto">
                {loadingJobs ? (
                  <div className="py-10 text-center text-xs text-muted-foreground">正在加载收集任务…</div>
                ) : jobs.length === 0 ? (
                  <div className="py-10 text-center text-xs text-muted-foreground">
                    暂无收集任务，请在上方输入自然语言指令发起首次 AI 资产收集。
                  </div>
                ) : (
                  jobs.map((j) => {
                    const active = activeJob?.id === j.id;
                    return (
                      <button
                        key={j.id}
                        type="button"
                        onClick={() => setActiveJobId(j.id)}
                        className={cn(
                          "w-full rounded-lg border p-2.5 text-left transition-colors space-y-1",
                          active ? "border-primary bg-primary/10" : "hover:bg-muted/40",
                        )}
                      >
                        <div className="flex items-center gap-1.5">
                          {j.status === "running" ? (
                            <Loader2 className="size-3.5 shrink-0 animate-spin text-primary" />
                          ) : j.status === "done" ? (
                            <CheckCircle2 className="size-3.5 shrink-0 text-emerald-500" />
                          ) : j.status === "failed" ? (
                            <AlertCircle className="size-3.5 shrink-0 text-destructive" />
                          ) : (
                            <Radar className="size-3.5 shrink-0 text-muted-foreground" />
                          )}
                          <span className="min-w-0 flex-1 truncate font-medium text-xs">{j.name}</span>
                          <Badge variant={j.mode === "ai" ? "default" : "secondary"} className="h-4 px-1 text-[10px]">
                            {j.mode === "ai" ? "AI" : "规则"}
                          </Badge>
                        </div>
                        {j.prompt ? (
                          <p className="line-clamp-1 text-[11px] text-muted-foreground">{j.prompt}</p>
                        ) : null}
                        <div className="flex items-center justify-between text-[10px] text-muted-foreground">
                          <span>{j.created_at?.slice(5, 19).replace("T", " ")}</span>
                          <span className="font-mono text-foreground">+{j.stats?.total_upserted ?? 0} 资产</span>
                        </div>
                      </button>
                    );
                  })
                )}
              </CardContent>
            </Card>

            {/* Right: Active Job Live Trace & Summary */}
            <Card className="lg:col-span-8">
              <CardHeader className="pb-3">
                {activeJob ? (
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="space-y-1 min-w-0">
                      <div className="flex flex-wrap items-center gap-2">
                        <CardTitle className="text-base">{activeJob.name}</CardTitle>
                        <Badge
                          variant={
                            activeJob.status === "running"
                              ? "default"
                              : activeJob.status === "failed"
                                ? "destructive"
                                : "secondary"
                          }
                        >
                          {activeJob.status}
                        </Badge>
                        {activeJob.company_name ? <Badge variant="outline">{activeJob.company_name}</Badge> : null}
                        {(activeJob.stats?.input_tokens || activeJob.stats?.output_tokens) ? (
                          <Badge variant="outline" className="font-mono text-[10px]">
                            Token {fmtTokens(activeJob.stats.input_tokens || 0)}↑ / {fmtTokens(activeJob.stats.output_tokens || 0)}↓
                          </Badge>
                        ) : null}
                      </div>
                      {activeJob.prompt ? (
                        <CardDescription className="text-xs break-words">
                          指令：{activeJob.prompt}
                        </CardDescription>
                      ) : null}
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {activeJob.status === "running" ? (
                        <Button size="sm" variant="destructive" onClick={() => void handleStopJob(activeJob.id)}>
                          <Square className="mr-1 size-3.5" /> 停止
                        </Button>
                      ) : null}
                      {activeJob.company_id ? (
                        <Button
                          size="sm"
                          variant="default"
                          disabled={convertingTask}
                          onClick={() => void handleConvertCompanyToTask(activeJob.company_id!, activeJob.company_name || activeJob.name)}
                        >
                          {convertingTask ? <Loader2 className="mr-1 size-3.5 animate-spin" /> : <Rocket className="mr-1 size-3.5" />}
                          转挖掘任务
                        </Button>
                      ) : null}
                      <Button size="sm" variant="outline" asChild>
                        <Link href="/function/assets">
                          <Database className="mr-1 size-3.5" /> 查看双图资产
                        </Link>
                      </Button>
                    </div>
                  </div>
                ) : (
                  <div>
                    <CardTitle className="text-base">AI 收集实时监控</CardTitle>
                    <CardDescription className="text-xs">选择左侧任务或发起新的自然语言资产收集</CardDescription>
                  </div>
                )}
              </CardHeader>

              <CardContent className="space-y-4">
                {!activeJob ? (
                  <div className="py-16 text-center text-xs text-muted-foreground">
                    启动 AI 资产收集后，这里将实时呈现 AI 思考过程、工具调用结果、六类资产统计与最终摸排报告。
                  </div>
                ) : (
                  <>
                    {/* 7-category live scoreboard */}
                    <div className="grid grid-cols-4 gap-2 sm:grid-cols-7">
                      {[
                        ["根域", activeJob.stats?.root_domain ?? 0],
                        ["子域", activeJob.stats?.subdomain ?? 0],
                        ["IP", activeJob.stats?.ip ?? 0],
                        ["服务", activeJob.stats?.service ?? 0],
                        ["应用", activeJob.stats?.app ?? 0],
                        ["接口", activeJob.stats?.endpoint ?? 0],
                        ["探活", activeJob.stats?.probed ?? 0],
                      ].map(([label, val]) => (
                        <div key={String(label)} className="rounded-lg border bg-muted/20 px-2 py-1.5 text-center">
                          <div className="text-[10px] text-muted-foreground">{label}</div>
                          <div className="font-semibold text-sm tabular-nums">{val}</div>
                        </div>
                      ))}
                    </div>

                    {activeJob.error ? (
                      <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive">
                        执行错误：{activeJob.error}
                      </div>
                    ) : null}

                    <Tabs defaultValue={activeJob.ai_summary ? "summary" : "trace"} key={`${activeJob.id}-${Boolean(activeJob.ai_summary)}`}>
                      <TabsList>
                        <TabsTrigger value="trace" className="text-xs">
                          <Brain className="mr-1 size-3.5" />
                          AI 思考与工具轨迹 ({activeJob.ai_trace?.length ?? 0})
                        </TabsTrigger>
                        <TabsTrigger value="summary" className="text-xs">
                          <FileText className="mr-1 size-3.5" />
                          AI 资产摸排报告
                        </TabsTrigger>
                        <TabsTrigger value="logs" className="text-xs">
                          <Terminal className="mr-1 size-3.5" />
                          时间日志 ({activeJob.logs?.length ?? 0})
                        </TabsTrigger>
                      </TabsList>

                      <TabsContent value="trace" className="mt-3 space-y-2 max-h-[420px] overflow-y-auto pr-1">
                        {(activeJob.ai_trace ?? []).length === 0 ? (
                          <div className="py-8 text-center text-xs text-muted-foreground">
                            该任务为规则收集模式，请切换到「时间日志」查看执行明细。
                          </div>
                        ) : (
                          (activeJob.ai_trace ?? []).map((item, idx) => <TraceStepCard key={idx} item={item} />)
                        )}
                        {activeJob.status === "running" ? (
                          <div className="flex items-center gap-2 px-2 py-2 text-xs text-muted-foreground">
                            <Loader2 className="size-3.5 animate-spin text-primary" />
                            <span>AI 正在分析工具返回并执行下一轮收集…</span>
                          </div>
                        ) : null}
                      </TabsContent>

                      <TabsContent value="summary" className="mt-3">
                        {activeJob.ai_summary ? (
                          <div className="rounded-lg border bg-card p-4 max-h-[420px] overflow-y-auto">
                            <RichMarkdown content={activeJob.ai_summary} />
                          </div>
                        ) : (
                          <div className="py-10 text-center text-xs text-muted-foreground">
                            {activeJob.status === "running"
                              ? "收集仍在进行中，完成后将自动生成 Markdown 摸排总结报告…"
                              : "当前任务暂无 AI 总结报告。"}
                          </div>
                        )}
                      </TabsContent>

                      <TabsContent value="logs" className="mt-3">
                        <div className="max-h-[420px] space-y-1 overflow-y-auto rounded-lg border bg-muted/20 p-3 font-mono text-[11px]">
                          {(activeJob.logs ?? []).map((lg, idx) => (
                            <div key={idx} className="flex gap-2">
                              <span className="shrink-0 text-muted-foreground">{lg.ts?.slice(11, 19)}</span>
                              <span className="break-words text-foreground">{lg.message}</span>
                            </div>
                          ))}
                        </div>
                      </TabsContent>
                    </Tabs>
                  </>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Secondary Tab: Classic Deterministic Seed Collection */}
        <TabsContent value="manual">
          <AssetAutoCollectPanel
            companies={companies}
            overview={overview}
            onAssetsUpdated={() => void loadAll()}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}
