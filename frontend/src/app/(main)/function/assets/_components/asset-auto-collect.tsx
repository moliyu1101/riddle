"use client";

import * as React from "react";
import Link from "next/link";
import {
  CheckCircle2,
  Loader2,
  Radar,
  RefreshCw,
  Settings,
  Square,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  riddleApi,
  type AssetCollectJobItem,
  type AssetCompanyItem,
  type AssetsOverviewResponse,
} from "@/lib/riddle-api";

const SOURCE_OPTIONS = [
  { id: "crtsh", label: "被动证书透明度 (crt.sh)", desc: "按根域名被动发现历史与在用子域名" },
  { id: "dns", label: "并发 DNS 解析", desc: "解析子域 A/AAAA 记录、归并 C 段与 IP 绑定关系" },
  { id: "http_probe", label: "轻量 HTTP 存活与指纹探测", desc: "只读探活提取标题、状态码、技术栈与页面接口" },
  { id: "engine", label: "空间测绘引擎拉取", desc: "调用已配 Key 的 FOFA/Quake/Hunter 等引擎批量扩面" },
  { id: "task_sync", label: "同步平台历史任务资产", desc: "合并既有任务 Target 与流量库中的端点" },
];

export function AssetAutoCollectPanel({
  companies,
  overview,
  onAssetsUpdated,
}: {
  companies: AssetCompanyItem[];
  overview: AssetsOverviewResponse | null;
  onAssetsUpdated?: () => void;
}) {
  const [jobName, setJobName] = React.useState("");
  const [seedsText, setSeedsText] = React.useState("");
  const [companyId, setCompanyId] = React.useState("none");
  const [sources, setSources] = React.useState<string[]>(["crtsh", "dns", "http_probe"]);
  const [engine, setEngine] = React.useState("fofa");
  const [engineQuery, setEngineQuery] = React.useState("");
  const [maxPages, setMaxPages] = React.useState(3);
  const [submitting, setSubmitting] = React.useState(false);

  const [jobs, setJobs] = React.useState<AssetCollectJobItem[]>([]);
  const [activeJobId, setActiveJobId] = React.useState<string | null>(null);
  const [loadingJobs, setLoadingJobs] = React.useState(true);

  const loadJobs = React.useCallback(async () => {
    try {
      const res = await riddleApi.listAssetCollectJobs(25);
      const list = res.jobs ?? [];
      setJobs(list);
      if (list.length > 0 && !activeJobId) {
        setActiveJobId(list[0].id);
      }
    } catch {
      // ignore poll error
    } finally {
      setLoadingJobs(false);
    }
  }, [activeJobId]);

  React.useEffect(() => {
    void loadJobs();
  }, [loadJobs]);

  const anyRunning = React.useMemo(() => jobs.some((j) => j.status === "running" || j.running), [jobs]);

  React.useEffect(() => {
    if (!anyRunning) return;
    const timer = window.setInterval(() => {
      void loadJobs();
      onAssetsUpdated?.();
    }, 2000);
    return () => window.clearInterval(timer);
  }, [anyRunning, loadJobs, onAssetsUpdated]);

  const toggleSource = (id: string, checked: boolean) => {
    setSources((prev) => {
      if (checked) return prev.includes(id) ? prev : [...prev, id];
      return prev.filter((s) => s !== id);
    });
  };

  const selectedEngineInfo = React.useMemo(
    () => (overview?.engines ?? []).find((e) => e.name === engine),
    [overview, engine],
  );

  const handleStart = async () => {
    if (sources.includes("engine") && !selectedEngineInfo?.key_set) {
      toast.error(`测绘引擎 ${selectedEngineInfo?.display_name || engine} 尚未配置 API Key，请先配置或取消勾选测绘源`);
      return;
    }
    if (!seedsText.trim() && !engineQuery.trim() && !sources.includes("task_sync")) {
      toast.error("请输入至少一个根域名、URL、IP 或网段种子");
      return;
    }
    setSubmitting(true);
    try {
      const res = await riddleApi.startAssetCollectJob({
        name: jobName.trim() || undefined,
        seeds_text: seedsText.trim(),
        company_id: companyId === "none" ? null : companyId,
        sources,
        engine: sources.includes("engine") ? engine : "",
        engine_query: engineQuery.trim(),
        max_pages: Math.max(1, Math.min(10, Number(maxPages) || 3)),
      });
      toast.success(`已启动资产自动收集任务：${res.job.name}`);
      setActiveJobId(res.job.id);
      setJobName("");
      await loadJobs();
    } catch (err) {
      toast.error(`启动收集失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSubmitting(false);
    }
  };

  const handleStop = async (jobId: string) => {
    try {
      await riddleApi.stopAssetCollectJob(jobId);
      toast.info("已发送停止信号");
      await loadJobs();
    } catch (err) {
      toast.error(`停止失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const activeJob = jobs.find((j) => j.id === activeJobId) ?? jobs[0] ?? null;

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">
      {/* Left: Launch Form */}
      <Card className="lg:col-span-5">
        <CardHeader className="pb-3">
          <CardTitle className="flex items-center gap-2 text-base">
            <Radar className="size-4 text-primary" /> 新建资产自动收集任务
          </CardTitle>
          <CardDescription className="text-xs">
            输入授权范围内的根域名、URL、IP 或 CIDR，自动执行多源发现并将六类资产写入全局双图真值库。
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="space-y-1.5">
              <Label className="text-xs">任务名称（可选）</Label>
              <Input
                className="text-xs"
                placeholder="例如：某高校全资产摸排"
                value={jobName}
                onChange={(e) => setJobName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">归属企业/高校主体</Label>
              <Select value={companyId} onValueChange={setCompanyId}>
                <SelectTrigger className="text-xs">
                  <SelectValue placeholder="自动按范围规则归属" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">自动按范围规则匹配</SelectItem>
                  {companies.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-1.5">
            <Label className="text-xs">资产种子（每行一条：根域名 / URL / IP / CIDR，单网段安全上限 /24）</Label>
            <Textarea
              rows={4}
              className="font-mono text-xs"
              placeholder={"example.edu.cn\nhttps://portal.example.edu.cn\n10.20.30.0/28"}
              value={seedsText}
              onChange={(e) => setSeedsText(e.target.value)}
            />
          </div>

          <div className="space-y-2">
            <Label className="text-xs">采集流水线模块</Label>
            <div className="space-y-2 rounded-lg border bg-muted/20 p-3">
              {SOURCE_OPTIONS.map((opt) => (
                <label key={opt.id} className="flex items-start gap-2.5 cursor-pointer">
                  <Checkbox
                    checked={sources.includes(opt.id)}
                    onCheckedChange={(v) => toggleSource(opt.id, v === true)}
                    className="mt-0.5"
                  />
                  <div className="space-y-0.5">
                    <div className="text-xs font-medium leading-none">{opt.label}</div>
                    <div className="text-[11px] text-muted-foreground">{opt.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>

          {sources.includes("engine") ? (
            <div className="space-y-2.5 rounded-lg border border-primary/25 bg-primary/5 p-3">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-medium">空间测绘引擎参数</Label>
                <Link href="/system/settings" className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline">
                  <Settings className="size-3" /> 配置引擎 Key
                </Link>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Select value={engine} onValueChange={setEngine}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {(overview?.engines ?? []).map((e) => (
                      <SelectItem key={e.name} value={e.name}>
                        {e.display_name} ({e.key_set ? "已配 Key" : "未配置"})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Input
                  type="number"
                  min={1}
                  max={10}
                  className="h-8 text-xs"
                  value={maxPages}
                  onChange={(e) => setMaxPages(Number(e.target.value) || 3)}
                  placeholder="最大翻页数"
                />
              </div>
              <Input
                className="h-8 font-mono text-xs"
                placeholder='可选自定义语法（留空则自动按根域生成 domain="..."）'
                value={engineQuery}
                onChange={(e) => setEngineQuery(e.target.value)}
              />
            </div>
          ) : null}

          <Button className="w-full" disabled={submitting} onClick={() => void handleStart()}>
            {submitting ? <Loader2 className="mr-1.5 size-4 animate-spin" /> : <Radar className="mr-1.5 size-4" />}
            启动自动化资产收集
          </Button>
        </CardContent>
      </Card>

      {/* Right: Live Jobs Monitor */}
      <Card className="lg:col-span-7 flex flex-col">
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div>
            <CardTitle className="text-base">收集任务队列与实时进度</CardTitle>
            <CardDescription className="text-xs">自动轮询正在运行的任务，收集结果实时落盘全局资产库</CardDescription>
          </div>
          <Button size="sm" variant="outline" onClick={() => void loadJobs()}>
            <RefreshCw className="mr-1.5 size-3.5" /> 刷新
          </Button>
        </CardHeader>
        <CardContent className="space-y-4">
          {loadingJobs ? (
            <div className="py-10 text-center text-xs text-muted-foreground">正在加载收集任务…</div>
          ) : jobs.length === 0 ? (
            <div className="py-12 text-center text-xs text-muted-foreground">
              暂无资产自动收集记录，请在左侧输入种子发起首次自动收集。
            </div>
          ) : (
            <>
              <div className="flex flex-wrap gap-2">
                {jobs.slice(0, 8).map((j) => {
                  const isActive = activeJob?.id === j.id;
                  return (
                    <button
                      key={j.id}
                      type="button"
                      onClick={() => setActiveJobId(j.id)}
                      className={[
                        "inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1.5 text-xs transition-colors",
                        isActive ? "border-primary bg-primary/10 font-medium text-foreground" : "hover:bg-muted/50 text-muted-foreground",
                      ].join(" ")}
                    >
                      {j.status === "running" ? (
                        <Loader2 className="size-3 animate-spin text-primary" />
                      ) : j.status === "done" ? (
                        <CheckCircle2 className="size-3 text-emerald-500" />
                      ) : null}
                      <span className="max-w-[160px] truncate">{j.name}</span>
                      <Badge variant="secondary" className="h-4 px-1 text-[10px]">
                        +{j.stats?.total_upserted ?? 0}
                      </Badge>
                    </button>
                  );
                })}
              </div>

              {activeJob ? (
                <div className="space-y-3 rounded-lg border bg-muted/20 p-3.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="space-y-0.5">
                      <div className="flex items-center gap-2 font-medium text-sm">
                        <span>{activeJob.name}</span>
                        <Badge variant={activeJob.status === "running" ? "default" : activeJob.status === "failed" ? "destructive" : "secondary"}>
                          {activeJob.status}
                        </Badge>
                        {activeJob.company_name ? <Badge variant="outline">{activeJob.company_name}</Badge> : null}
                      </div>
                      <div className="text-[11px] text-muted-foreground">
                        创建于 {activeJob.created_at?.slice(0, 19).replace("T", " ")} · 采集源：{activeJob.sources.join(" / ")}
                      </div>
                    </div>
                    {activeJob.status === "running" ? (
                      <Button size="sm" variant="destructive" onClick={() => void handleStop(activeJob.id)}>
                        <Square className="mr-1 size-3.5" /> 停止收集
                      </Button>
                    ) : null}
                  </div>

                  {/* Per-type stats */}
                  <div className="grid grid-cols-3 gap-2 sm:grid-cols-7">
                    {[
                      ["根域", activeJob.stats?.root_domain ?? 0],
                      ["子域", activeJob.stats?.subdomain ?? 0],
                      ["IP", activeJob.stats?.ip ?? 0],
                      ["服务", activeJob.stats?.service ?? 0],
                      ["应用", activeJob.stats?.app ?? 0],
                      ["接口", activeJob.stats?.endpoint ?? 0],
                      ["探活", activeJob.stats?.probed ?? 0],
                    ].map(([label, val]) => (
                      <div key={String(label)} className="rounded border bg-background px-2 py-1.5 text-center">
                        <div className="text-[10px] text-muted-foreground">{label}</div>
                        <div className="font-semibold text-sm tabular-nums">{val}</div>
                      </div>
                    ))}
                  </div>

                  {activeJob.error ? (
                    <div className="rounded border border-destructive/40 bg-destructive/10 px-2.5 py-2 text-xs text-destructive">
                      错误：{activeJob.error}
                    </div>
                  ) : null}

                  {/* Real-time logs */}
                  <div className="max-h-56 space-y-1 overflow-y-auto rounded-md border bg-background p-2.5 font-mono text-[11px]">
                    {(activeJob.logs ?? []).map((lg, idx) => (
                      <div key={idx} className="flex gap-2">
                        <span className="shrink-0 text-muted-foreground">{lg.ts?.slice(11, 19)}</span>
                        <span className="break-words text-foreground">{lg.message}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
