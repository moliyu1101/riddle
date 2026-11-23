"use client";

import * as React from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  AlertTriangle,
  CheckCircle2,
  ExternalLink,
  Loader2,
  Rocket,
  Settings,
  Sparkles,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  riddleApi,
  type KillsweepPreviewResponse,
  type ParseQueryResult,
  type RiddleTask,
} from "@/lib/riddle-api";

export interface KillsweepLaunchDialogProps {
  findingId: string | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onLaunched?: (task: RiddleTask) => void;
}

export function KillsweepLaunchDialog({
  findingId,
  open,
  onOpenChange,
  onLaunched,
}: KillsweepLaunchDialogProps) {
  const router = useRouter();

  const [loading, setLoading] = React.useState(false);
  const [submitting, setSubmitting] = React.useState(false);
  const [preview, setPreview] = React.useState<KillsweepPreviewResponse | null>(null);
  const [loadError, setLoadError] = React.useState<string | null>(null);

  const [engine, setEngine] = React.useState("fofa");
  const [taskName, setTaskName] = React.useState("");
  const [srcType, setSrcType] = React.useState("edusrc");
  const [query, setQuery] = React.useState("");
  const [concurrency, setConcurrency] = React.useState(3);
  const [maxPages, setMaxPages] = React.useState(20);
  const [pageSize, setPageSize] = React.useState(100);
  const [extraRules, setExtraRules] = React.useState("");
  const [startImmediately, setStartImmediately] = React.useState(true);

  const [queryHint, setQueryHint] = React.useState<ParseQueryResult | null>(null);
  const [parsingQuery, setParsingQuery] = React.useState(false);

  React.useEffect(() => {
    if (!open || !findingId) return;
    let cancelled = false;
    setLoading(true);
    setLoadError(null);
    setQueryHint(null);
    riddleApi
      .getKillsweepPreview(findingId)
      .then((res) => {
        if (cancelled) return;
        setPreview(res);
        setEngine(res.default_engine || "fofa");
        setTaskName(res.suggested_name || "");
        setSrcType(res.default_src_type || "edusrc");
        setQuery(res.suggested_query || "");
        setConcurrency(res.defaults?.concurrency ?? 3);
        setMaxPages(res.defaults?.max_pages ?? 20);
        setPageSize(res.defaults?.page_size ?? 100);
        setExtraRules("");
        setStartImmediately(true);
      })
      .catch((err) => {
        if (cancelled) return;
        setLoadError(err instanceof Error ? err.message : String(err));
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [open, findingId]);

  React.useEffect(() => {
    if (!open || !query.trim()) {
      setQueryHint(null);
      return;
    }
    const timer = window.setTimeout(() => {
      setParsingQuery(true);
      riddleApi
        .parseQuery(engine, query.trim(), srcType)
        .then((res) => setQueryHint(res))
        .catch(() => setQueryHint(null))
        .finally(() => setParsingQuery(false));
    }, 350);
    return () => window.clearTimeout(timer);
  }, [open, engine, query, srcType]);

  const selectedEngineInfo = React.useMemo(
    () => preview?.engines.find((item) => item.name === engine) ?? null,
    [preview, engine],
  );
  const engineReady = Boolean(selectedEngineInfo?.key_set);

  const handleSubmit = async () => {
    if (!findingId) return;
    if (!engineReady) {
      toast.error("所选测绘引擎尚未配置 API Key，请先前往系统设置配置");
      return;
    }
    if (!query.trim()) {
      toast.error("请填写测绘查询语法");
      return;
    }
    setSubmitting(true);
    try {
      const res = await riddleApi.createKillsweepTask(findingId, {
        engine,
        query: query.trim(),
        name: taskName.trim() || undefined,
        src_type: srcType,
        concurrency: Math.max(1, Math.min(20, Number(concurrency) || 3)),
        max_pages: Math.max(1, Math.min(200, Number(maxPages) || 20)),
        page_size: Math.max(10, Math.min(500, Number(pageSize) || 100)),
        extra_src_rules: extraRules.trim(),
        start_immediately: startImmediately,
      });
      toast.success(
        res.started
          ? `已落盘通杀任务「${res.task.name}」并立即启动`
          : `已落盘通杀任务「${res.task.name}」（待手动启动）`,
      );
      onLaunched?.(res.task);
      onOpenChange(false);
      router.push(`/function/tasks/detail?id=${encodeURIComponent(res.task.id)}`);
    } catch (err) {
      toast.error(`发起一键通杀失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Zap className="size-4 text-amber-500" />
            漏洞库一键通杀 · 落盘为新任务
          </DialogTitle>
          <DialogDescription>
            基于已落盘漏洞特征与指纹自动构造测绘通杀任务，落盘持久化到任务中心并可立即启动执行。
          </DialogDescription>
        </DialogHeader>

        {loading ? (
          <div className="flex items-center justify-center gap-2 py-12 text-sm text-muted-foreground">
            <Loader2 className="size-4 animate-spin" />
            正在读取漏洞上下文与测绘引擎配置…
          </div>
        ) : loadError ? (
          <Alert variant="destructive">
            <AlertTriangle className="size-4" />
            <AlertTitle>加载预检信息失败</AlertTitle>
            <AlertDescription>{loadError}</AlertDescription>
          </Alert>
        ) : preview ? (
          <div className="space-y-4">
            {/* Origin finding summary */}
            <div className="rounded-lg border bg-muted/30 p-3 text-xs space-y-1.5">
              <div className="flex flex-wrap items-center gap-2">
                <StatusBadge domain="severity" value={preview.finding.effective_severity} />
                <Badge variant="secondary">{preview.finding.vuln_type || "通用漏洞"}</Badge>
                {preview.killsweep?.product_name ? (
                  <Badge variant="outline" className="gap-1">
                    <Sparkles className="size-3 text-amber-500" />
                    产品：{preview.killsweep.product_name}
                  </Badge>
                ) : null}
                {preview.killsweep?.verified ? (
                  <Badge variant="default" className="text-[11px]">
                    同款已验证
                  </Badge>
                ) : null}
              </div>
              <div className="font-medium text-sm text-foreground">{preview.finding.title}</div>
              <div className="font-mono text-[11px] text-muted-foreground break-all">
                样本：{preview.finding.target_url}
              </div>
              {preview.killsweep?.fingerprint ? (
                <div className="text-[11px] text-muted-foreground">
                  指纹依据：{preview.killsweep.fingerprint}
                </div>
              ) : null}
            </div>

            {/* Engine selector grid */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label className="text-xs font-medium">选择测绘引擎（需先配置 API Key）</Label>
                <Link
                  href="/system/settings"
                  className="inline-flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  <Settings className="size-3" /> 前往配置引擎 Key
                </Link>
              </div>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {preview.engines.map((eng) => {
                  const active = engine === eng.name;
                  return (
                    <button
                      key={eng.name}
                      type="button"
                      onClick={() => setEngine(eng.name)}
                      className={[
                        "flex items-center justify-between rounded-lg border px-3 py-2 text-left text-xs transition-colors",
                        active
                          ? "border-primary bg-primary/10 text-foreground"
                          : "border-border hover:bg-muted/50 text-muted-foreground",
                      ].join(" ")}
                    >
                      <span className="font-medium truncate">{eng.display_name}</span>
                      {eng.key_set ? (
                        <span className="inline-flex shrink-0 items-center gap-1 text-[11px] text-emerald-600 dark:text-emerald-400">
                          <CheckCircle2 className="size-3" /> 已配置
                        </span>
                      ) : (
                        <span className="shrink-0 text-[11px] text-muted-foreground">未配置</span>
                      )}
                    </button>
                  );
                })}
              </div>

              {!engineReady ? (
                <Alert className="border-amber-500/40 bg-amber-500/5">
                  <AlertTriangle className="size-4 text-amber-500" />
                  <AlertTitle className="text-xs font-medium">
                    {selectedEngineInfo?.display_name || engine} 尚未配置 API Key
                  </AlertTitle>
                  <AlertDescription className="flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span>
                      {preview.has_configured_engine
                        ? "请切换至上方带「已配置」标记的测绘引擎，或前往系统设置补充密钥。"
                        : "当前所有测绘引擎均未配置 API Key，配置完成后即可一键落盘并发起通杀。"}
                    </span>
                    <Button size="sm" variant="outline" className="h-7 text-xs" asChild>
                      <Link href="/system/settings">
                        打开系统设置 <ExternalLink className="ml-1 size-3" />
                      </Link>
                    </Button>
                  </AlertDescription>
                </Alert>
              ) : null}
            </div>

            {/* Task Name & SRC Type */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="space-y-1.5 sm:col-span-2">
                <Label className="text-xs">新任务名称</Label>
                <Input
                  value={taskName}
                  onChange={(e) => setTaskName(e.target.value)}
                  placeholder="例如：[通杀] 某管理系统未授权访问"
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">SRC 授权模式</Label>
                <Select value={srcType} onValueChange={setSrcType}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="edusrc">EduSRC (高校授权)</SelectItem>
                    <SelectItem value="enterprise">企业 SRC</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Mapping Query */}
            <div className="space-y-1.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <Label className="text-xs">测绘查询语法（将按所选引擎原样执行）</Label>
                <Badge variant="outline" className="text-[11px]">
                  {preview.query_source === "killsweep"
                    ? "已复用历史通杀指纹语法"
                    : "基于漏洞特征自动建议（建议核对）"}
                </Badge>
              </div>
              <Textarea
                rows={3}
                className="font-mono text-xs"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder='例如：title="某某管理系统" && domain="edu.cn"'
              />
              {parsingQuery ? (
                <div className="text-[11px] text-muted-foreground">正在校验测绘语法…</div>
              ) : queryHint ? (
                <div className="space-y-1 rounded-md border bg-muted/20 px-2.5 py-2 text-[11px]">
                  {queryHint.summary ? <div className="text-foreground">{queryHint.summary}</div> : null}
                  {queryHint.syntax_mismatch ? (
                    <div className="text-amber-600 dark:text-amber-400">⚠ {queryHint.syntax_mismatch}</div>
                  ) : null}
                  {queryHint.issues?.length ? (
                    <div className="text-amber-600 dark:text-amber-400">
                      提示：{queryHint.issues.join("；")}
                    </div>
                  ) : null}
                </div>
              ) : null}
            </div>

            {/* Execution params */}
            <div className="grid grid-cols-3 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">并发 Worker 数</Label>
                <Input
                  type="number"
                  min={1}
                  max={20}
                  value={concurrency}
                  onChange={(e) => setConcurrency(Number(e.target.value) || 3)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">最大翻页数</Label>
                <Input
                  type="number"
                  min={1}
                  max={200}
                  value={maxPages}
                  onChange={(e) => setMaxPages(Number(e.target.value) || 20)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">每页拉取条数</Label>
                <Input
                  type="number"
                  min={10}
                  max={500}
                  value={pageSize}
                  onChange={(e) => setPageSize(Number(e.target.value) || 100)}
                />
              </div>
            </div>

            {/* Extra rules */}
            <div className="space-y-1.5">
              <Label className="text-xs">附加通杀约束 / 规则（可选，已自动携带源漏洞验证上下文）</Label>
              <Textarea
                rows={2}
                className="text-xs"
                value={extraRules}
                onChange={(e) => setExtraRules(e.target.value)}
                placeholder="例如：仅验证默认接口未授权状态，跳过非高校资产…"
              />
            </div>

            {/* Start immediately switch */}
            <div className="flex items-center justify-between rounded-lg border px-3 py-2.5">
              <div className="space-y-0.5">
                <div className="text-xs font-medium">落盘后立即启动通杀</div>
                <div className="text-[11px] text-muted-foreground">
                  开启后将直接创建持久化任务并拉起 Collector + Worker 执行批量验证，完成后自动跳转任务详情页。
                </div>
              </div>
              <Switch checked={startImmediately} onCheckedChange={setStartImmediately} />
            </div>
          </div>
        ) : null}

        <DialogFooter className="gap-2 sm:gap-2">
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
            取消
          </Button>
          <Button
            onClick={() => void handleSubmit()}
            disabled={loading || submitting || !preview || !engineReady || !query.trim()}
          >
            {submitting ? (
              <Loader2 className="mr-1.5 size-4 animate-spin" />
            ) : (
              <Rocket className="mr-1.5 size-4" />
            )}
            {startImmediately ? "落盘为新任务并立即通杀" : "仅落盘为新任务"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
