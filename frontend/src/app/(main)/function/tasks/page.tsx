"use client";

import * as React from "react";
import Link from "next/link";
import {
  CheckCircle2,
  Eye,
  Flag,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Search,
  Sparkles,
  Square,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
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
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { riddleApi, riddleFetch, type RiddleTask } from "@/lib/riddle-api";

const VULN_DIRECTION_PRESETS = [
  "SQL注入",
  "RCE",
  "未授权访问",
  "文件上传",
  "任意文件读取",
  "逻辑越权",
  "信息泄露",
  "SSRF/XXE",
];

const GUARD_OP_DEFS = [
  { id: "db_dump", label: "脱库/拖库/删库" },
  { id: "db_delete", label: "删除数据" },
  { id: "db_write", label: "写入/篡改数据" },
  { id: "cache_clear", label: "清缓存" },
  { id: "cred_change", label: "改密/重置凭证" },
  { id: "brute_force", label: "爆破/暴力破解" },
  { id: "dos", label: "压测/DoS/轰炸" },
  { id: "webshell", label: "落 webshell/后门" },
];

const ENGINES = [
  { id: "fofa", label: "FOFA" },
  { id: "quake", label: "Quake (360)" },
  { id: "hunter", label: "Hunter (鹰图)" },
  { id: "zoomeye", label: "ZoomEye" },
  { id: "shodan", label: "Shodan" },
  { id: "censys", label: "Censys" },
];

const SOURCE_LABELS: Record<string, string> = {
  fofa: "测绘发现",
  manual: "手动导入",
  both: "测绘 + 手动",
  assist: "单站协作",
};

function calcProgress(t: RiddleTask): number {
  const total = Number(t.total_targets ?? t.stats?.total_targets ?? 0);
  const done = Number(t.stats?.done_targets ?? 0);
  if (total > 0) return Math.min(100, Math.round((done / total) * 100));
  if (typeof t.progress === "number") return Math.min(100, Math.max(0, Math.round(t.progress)));
  return 0;
}

export default function TasksPage() {
  const [tasks, setTasks] = React.useState<RiddleTask[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [search, setSearch] = React.useState("");
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [srcFilter, setSrcFilter] = React.useState("all");

  // Create Dialog state
  const [createOpen, setCreateOpen] = React.useState(false);
  const [creating, setCreating] = React.useState(false);
  const [name, setName] = React.useState("");
  const [srcType, setSrcType] = React.useState<"edusrc" | "enterprise">("edusrc");
  const [targetSource, setTargetSource] = React.useState<"fofa" | "manual" | "both" | "assist">("fofa");
  const [engine, setEngine] = React.useState("fofa");
  const [fofaQuery, setFofaQuery] = React.useState("");
  const [manualText, setManualText] = React.useState("");
  const [selectedVulns, setSelectedVulns] = React.useState<string[]>([]);
  const [guardOps, setGuardOps] = React.useState<string[]>(["db_dump", "db_delete", "dos", "webshell"]);
  const [srcRules, setSrcRules] = React.useState("");
  const [concurrency, setConcurrency] = React.useState(3);
  const [deepenCap, setDeepenCap] = React.useState(2);
  const [autoGoals, setAutoGoals] = React.useState(true);
  const [startImmediately, setStartImmediately] = React.useState(false);
  const [queryHint, setQueryHint] = React.useState("");
  const [parseHint, setParseHint] = React.useState("");

  // Fusion Goal Dialog state
  const [goalTask, setGoalTask] = React.useState<RiddleTask | null>(null);
  const [goals, setGoals] = React.useState<Array<Record<string, unknown>>>([]);
  const [goalEval, setGoalEval] = React.useState<Record<string, unknown> | null>(null);
  const [goalLoading, setGoalLoading] = React.useState(false);

  const loadTasks = React.useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const data = await riddleApi.listTasks();
      setTasks(data);
    } catch (err) {
      toast.error(`加载任务失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadTasks(false);
    const timer = setInterval(() => void loadTasks(true), 10000);
    return () => clearInterval(timer);
  }, [loadTasks]);

  const filtered = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    return tasks.filter((t) => {
      if (statusFilter !== "all" && t.status !== statusFilter) return false;
      if (srcFilter !== "all" && t.src_type !== srcFilter) return false;
      if (!q) return true;
      return (
        t.name.toLowerCase().includes(q) ||
        (t.fofa_query || "").toLowerCase().includes(q) ||
        (t.engine || "").toLowerCase().includes(q) ||
        t.id.toLowerCase().includes(q)
      );
    });
  }, [tasks, search, statusFilter, srcFilter]);

  const handleAction = async (t: RiddleTask, action: "start" | "pause" | "stop" | "delete") => {
    try {
      if (action === "start") {
        await riddleApi.startTask(t.id);
        toast.success(`已启动：${t.name}`);
      } else if (action === "pause") {
        await riddleApi.pauseTask(t.id);
        toast.success(`已暂停：${t.name}`);
      } else if (action === "stop") {
        await riddleApi.stopTask(t.id);
        toast.success(`已停止：${t.name}`);
      } else if (action === "delete") {
        if (!window.confirm(`确定删除任务「${t.name}」及其关联数据？`)) return;
        await riddleApi.deleteTask(t.id);
        toast.success(`已删除：${t.name}`);
      }
      await loadTasks(true);
    } catch (err) {
      toast.error(`操作失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleParseQuery = async () => {
    if (!fofaQuery.trim()) return;
    try {
      const res = await riddleApi.parseQuery(engine, fofaQuery.trim(), srcType);
      setQueryHint(res.syntax_mismatch || res.issues?.[0] || res.summary || "语法有效");
    } catch (err) {
      setQueryHint(err instanceof Error ? err.message : String(err));
    }
  };

  const handleParseTargets = async () => {
    if (!manualText.trim()) return;
    try {
      const res = await riddleApi.parseTargets(manualText);
      setParseHint(`共 ${res.total_lines} 行 · 有效 ${res.valid} 条（域名 ${res.domains} / IP ${res.ips}）`);
    } catch (err) {
      setParseHint(err instanceof Error ? err.message : String(err));
    }
  };

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      toast.error("请输入任务名称");
      return;
    }
    const manualTargets = manualText
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    if ((targetSource === "manual" || targetSource === "assist") && manualTargets.length === 0) {
      toast.error("手动/单站协作模式请至少输入一条目标 URL 或域名");
      return;
    }
    if (targetSource === "fofa" && !fofaQuery.trim()) {
      toast.error("测绘模式请输入查询语法");
      return;
    }

    setCreating(true);
    try {
      const created = await riddleApi.createTask({
        name: name.trim(),
        src_type: srcType,
        vuln_types: selectedVulns,
        src_rules: srcRules.trim(),
        guard_ops: guardOps,
        target_source: targetSource,
        engine,
        fofa_query: fofaQuery.trim(),
        manual_targets: manualTargets,
        concurrency,
        deepen_cap: deepenCap,
      });

      if (autoGoals) {
        try {
          const suggested = await riddleApi.suggestGoals({
            task_id: created.id,
            name: created.name,
            src_type: created.src_type,
            vuln_types: selectedVulns,
            targets: manualTargets,
            fofa_query: fofaQuery.trim(),
          });
          if (suggested.goals?.length) {
            await riddleApi.saveGoals(created.id, suggested.goals);
          }
        } catch {
          // Goal suggestion failure should not block task creation
        }
      }

      if (startImmediately) {
        await riddleApi.startTask(created.id);
      }

      toast.success(`任务「${created.name}」创建成功`);
      setCreateOpen(false);
      setName("");
      setFofaQuery("");
      setManualText("");
      setSrcRules("");
      setQueryHint("");
      setParseHint("");
      await loadTasks(true);
    } catch (err) {
      toast.error(`创建失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setCreating(false);
    }
  };

  const openGoalsModal = async (task: RiddleTask) => {
    setGoalTask(task);
    setGoalLoading(true);
    setGoalEval(null);
    try {
      const res = await riddleApi.getGoals(task.id);
      setGoals(res.goals ?? []);
      const ev = await riddleFetch<Record<string, unknown>>(`/fusion/goals/${encodeURIComponent(task.id)}/evaluate`, {
        method: "POST",
      });
      setGoalEval(ev);
    } catch (err) {
      toast.error(`读取目标闸门失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setGoalLoading(false);
    }
  };

  const handleSuggestGoalsForTask = async () => {
    if (!goalTask) return;
    setGoalLoading(true);
    try {
      const res = await riddleApi.suggestGoals({ task_id: goalTask.id });
      setGoals(res.goals ?? []);
      toast.success(`智能拆解了 ${res.count} 条可核验目标，请点击保存生效`);
    } catch (err) {
      toast.error(`拆解失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setGoalLoading(false);
    }
  };

  const handleSaveGoals = async () => {
    if (!goalTask) return;
    setGoalLoading(true);
    try {
      await riddleApi.saveGoals(goalTask.id, goals);
      toast.success("已保存目标闸门配置");
      const ev = await riddleFetch<Record<string, unknown>>(`/fusion/goals/${encodeURIComponent(goalTask.id)}/evaluate`, {
        method: "POST",
      });
      setGoalEval(ev);
      await loadTasks(true);
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setGoalLoading(false);
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="挖掘任务"
        description="知蠹 Riddle 自主挖掘任务控制台：支持 EduSRC / 企业SRC 模式、6 大测绘引擎、任务级八大操作护栏与融合目标闸门。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void loadTasks(true)}>
              <RefreshCw className="mr-1.5 size-3.5" />
              刷新
            </Button>
            <Button size="sm" onClick={() => setCreateOpen(true)}>
              <Plus className="mr-1.5 size-3.5" />
              新建挖掘任务
            </Button>
          </>
        }
      />

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[240px] flex-1 max-w-md">
          <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
          <Input
            placeholder="搜索任务名、测绘语句、引擎…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={srcFilter} onValueChange={setSrcFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="SRC 模式" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部 SRC 模式</SelectItem>
            <SelectItem value="edusrc">EduSRC (高校)</SelectItem>
            <SelectItem value="enterprise">企业 SRC</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[150px]">
            <SelectValue placeholder="任务状态" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部状态</SelectItem>
            <SelectItem value="running">运行中</SelectItem>
            <SelectItem value="created">已创建</SelectItem>
            <SelectItem value="paused">已暂停</SelectItem>
            <SelectItem value="stopped">已停止</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Tasks Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="min-w-[220px]">任务与目标闸门</TableHead>
                  <TableHead>SRC / 引擎来源</TableHead>
                  <TableHead className="w-[170px]">目标推进</TableHead>
                  <TableHead className="text-right">待复审 / 总漏洞</TableHead>
                  <TableHead>并发 / 护栏</TableHead>
                  <TableHead>状态</TableHead>
                  <TableHead className="text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={7} className="h-28 text-center text-sm text-muted-foreground">
                      正在加载任务列表…
                    </TableCell>
                  </TableRow>
                ) : filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="h-28 text-center text-sm text-muted-foreground">
                      暂无匹配任务，点击右上角「新建挖掘任务」发起探索。
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((t) => {
                    const total = Number(t.total_targets ?? t.stats?.total_targets ?? 0);
                    const done = Number(t.stats?.done_targets ?? 0);
                    const dead = Number(t.stats?.dead_targets ?? 0);
                    const pct = calcProgress(t);
                    return (
                      <TableRow key={t.id}>
                        <TableCell>
                          <div className="space-y-1">
                            <Link
                              href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}
                              className="font-medium text-sm hover:text-primary hover:underline"
                            >
                              {t.name}
                            </Link>
                            <div className="flex flex-wrap items-center gap-1.5 text-xs text-muted-foreground">
                              {t.fofa_query ? (
                                <span className="max-w-[240px] truncate font-mono">{t.fofa_query}</span>
                              ) : (
                                <span>手动目标 {t.manual_targets?.length ?? 0} 条</span>
                              )}
                              {t.goal_summary?.configured ? (
                                <Badge variant="outline" className="text-[11px]">
                                  目标 {t.goal_summary.achieved ?? 0}/{t.goal_summary.total ?? 0}
                                </Badge>
                              ) : null}
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex flex-wrap items-center gap-1">
                            <Badge variant={t.src_type === "edusrc" ? "default" : "secondary"} className="text-xs">
                              {t.src_type === "edusrc" ? "EduSRC" : "企业SRC"}
                            </Badge>
                            <Badge variant="outline" className="text-xs uppercase">
                              {t.engine || SOURCE_LABELS[t.target_source] || t.target_source}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="space-y-1">
                            <div className="flex items-center gap-2">
                              <Progress value={pct} className="h-1.5 flex-1" />
                              <span className="text-xs tabular-nums text-muted-foreground">
                                {done}/{total}
                              </span>
                            </div>
                            {dead > 0 ? (
                              <div className="text-[11px] text-amber-600 dark:text-amber-400">
                                硬骨头 {dead} 条
                              </div>
                            ) : null}
                          </div>
                        </TableCell>
                        <TableCell className="text-right text-sm tabular-nums">
                          <span className="font-semibold text-amber-600 dark:text-amber-400">
                            {t.pending_user_review ?? 0}
                          </span>
                          <span className="text-muted-foreground"> / {t.total_vulns ?? 0}</span>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          <div>{t.concurrency} 并发 · 深挖 {t.deepen_cap}</div>
                          <div>护栏 {t.guard_ops?.length ?? 0} 项</div>
                        </TableCell>
                        <TableCell>
                          <StatusBadge domain="task" value={t.status} dot />
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="inline-flex items-center gap-1">
                            <Button variant="ghost" size="icon" title="任务大屏" asChild>
                              <Link href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}>
                                <Eye className="size-4" />
                              </Link>
                            </Button>
                            <Button variant="ghost" size="icon" title="融合目标闸门" onClick={() => void openGoalsModal(t)}>
                              <Flag className="size-4" />
                            </Button>
                            {t.status === "running" ? (
                              <Button variant="ghost" size="icon" title="暂停" onClick={() => void handleAction(t, "pause")}>
                                <Pause className="size-4" />
                              </Button>
                            ) : (
                              <Button variant="ghost" size="icon" title="启动" onClick={() => void handleAction(t, "start")}>
                                <Play className="size-4 text-emerald-600" />
                              </Button>
                            )}
                            {t.status === "running" || t.status === "paused" ? (
                              <Button variant="ghost" size="icon" title="停止" onClick={() => void handleAction(t, "stop")}>
                                <Square className="size-4" />
                              </Button>
                            ) : null}
                            <Button variant="ghost" size="icon" title="删除任务" onClick={() => void handleAction(t, "delete")}>
                              <Trash2 className="size-4 text-destructive" />
                            </Button>
                          </div>
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

      {/* New Riddle Task Dialog */}
      <Dialog open={createOpen} onOpenChange={setCreateOpen}>
        <DialogContent className="max-h-[90vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>新建知蠹自主挖掘任务</DialogTitle>
            <DialogDescription>
              配置 SRC 模式、资产测绘来源、漏洞挖掘偏好与任务级高危操作护栏。
            </DialogDescription>
          </DialogHeader>
          <form onSubmit={(e) => void handleCreate(e)} className="space-y-4">
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="task-name">任务名称 *</Label>
                <Input
                  id="task-name"
                  placeholder="例如：华东高校 11 月 EduSRC 专项"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label>SRC 规则模式</Label>
                <Select value={srcType} onValueChange={(v) => setSrcType(v as "edusrc" | "enterprise")}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="edusrc">EduSRC (高校 / 公益 SRC)</SelectItem>
                    <SelectItem value="enterprise">企业 SRC / 授权项目</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label>资产来源方式</Label>
                <Select
                  value={targetSource}
                  onValueChange={(v) => setTargetSource(v as "fofa" | "manual" | "both" | "assist")}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="fofa">空间测绘发现</SelectItem>
                    <SelectItem value="manual">手动导入目标清单</SelectItem>
                    <SelectItem value="both">测绘 + 手动联合</SelectItem>
                    <SelectItem value="assist">单站协同定向挖掘</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label>空间测绘引擎</Label>
                <Select value={engine} onValueChange={setEngine}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ENGINES.map((eng) => (
                      <SelectItem key={eng.id} value={eng.id}>
                        {eng.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {(targetSource === "fofa" || targetSource === "both") && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <Label htmlFor="fofa-query">测绘查询语法 ({engine.toUpperCase()})</Label>
                  <Button type="button" variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => void handleParseQuery()}>
                    校验查询语法
                  </Button>
                </div>
                <Input
                  id="fofa-query"
                  className="font-mono text-xs"
                  placeholder='domain="edu.cn" && title="统一身份认证"'
                  value={fofaQuery}
                  onChange={(e) => setFofaQuery(e.target.value)}
                />
                {queryHint ? <p className="text-xs text-muted-foreground">{queryHint}</p> : null}
              </div>
            )}

            {(targetSource === "manual" || targetSource === "both" || targetSource === "assist") && (
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <Label htmlFor="manual-targets">手动目标列表（每行一个 URL / 域名 / IP）</Label>
                  <Button type="button" variant="link" size="sm" className="h-auto p-0 text-xs" onClick={() => void handleParseTargets()}>
                    预览解析统计
                  </Button>
                </div>
                <Textarea
                  id="manual-targets"
                  rows={4}
                  className="font-mono text-xs"
                  placeholder={"https://portal.example.edu.cn\n10.0.0.1:8080 # 备注"}
                  value={manualText}
                  onChange={(e) => setManualText(e.target.value)}
                />
                {parseHint ? <p className="text-xs text-muted-foreground">{parseHint}</p> : null}
              </div>
            )}

            <div className="space-y-2">
              <Label>重点漏洞方向（可选多选）</Label>
              <div className="flex flex-wrap gap-1.5">
                {VULN_DIRECTION_PRESETS.map((v) => {
                  const active = selectedVulns.includes(v);
                  return (
                    <Button
                      key={v}
                      type="button"
                      size="sm"
                      variant={active ? "default" : "outline"}
                      className="h-7 text-xs"
                      onClick={() =>
                        setSelectedVulns((prev) => (prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]))
                      }
                    >
                      {v}
                    </Button>
                  );
                })}
              </div>
            </div>

            <div className="space-y-2">
              <Label>任务级八大高危操作硬拦截</Label>
              <div className="grid grid-cols-2 gap-2 rounded-lg border p-3 sm:grid-cols-4">
                {GUARD_OP_DEFS.map((op) => {
                  const checked = guardOps.includes(op.id);
                  return (
                    <label key={op.id} className="flex cursor-pointer items-center gap-2 text-xs">
                      <Checkbox
                        checked={checked}
                        onCheckedChange={(val) =>
                          setGuardOps((prev) =>
                            val ? [...new Set([...prev, op.id])] : prev.filter((x) => x !== op.id),
                          )
                        }
                      />
                      <span>{op.label}</span>
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label htmlFor="concurrency">Worker 并发数</Label>
                <Input
                  id="concurrency"
                  type="number"
                  min={1}
                  max={20}
                  value={concurrency}
                  onChange={(e) => setConcurrency(Number(e.target.value) || 3)}
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="deepen-cap">深挖最大轮次</Label>
                <Input
                  id="deepen-cap"
                  type="number"
                  min={0}
                  max={10}
                  value={deepenCap}
                  onChange={(e) => setDeepenCap(Number(e.target.value) || 0)}
                />
              </div>
              <div className="flex flex-col justify-end gap-2 pb-1">
                <label className="flex cursor-pointer items-center gap-2 text-xs">
                  <Checkbox checked={autoGoals} onCheckedChange={(v) => setAutoGoals(Boolean(v))} />
                  <span>自动生成融合目标闸门</span>
                </label>
                <label className="flex cursor-pointer items-center gap-2 text-xs">
                  <Checkbox checked={startImmediately} onCheckedChange={(v) => setStartImmediately(Boolean(v))} />
                  <span>创建后立即启动任务</span>
                </label>
              </div>
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="src-rules">附加 SRC 范围说明 / 禁止事项（可选）</Label>
              <Textarea
                id="src-rules"
                rows={2}
                placeholder="例如：严禁脱库或压测登录接口，优先挖掘统一认证与教务系统漏洞"
                value={srcRules}
                onChange={(e) => setSrcRules(e.target.value)}
              />
            </div>

            <DialogFooter>
              <Button type="button" variant="outline" onClick={() => setCreateOpen(false)}>
                取消
              </Button>
              <Button type="submit" disabled={creating}>
                {creating ? "正在创建…" : "创建任务"}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>

      {/* Fusion Goal Gate Modal */}
      <Dialog open={Boolean(goalTask)} onOpenChange={(open) => !open && setGoalTask(null)}>
        <DialogContent className="max-h-[85vh] max-w-2xl overflow-y-auto">
          <DialogHeader>
            <DialogTitle>融合目标闸门 — {goalTask?.name}</DialogTitle>
            <DialogDescription>
              为任务定义可核验的验收标准（GoalGate），决定任务诚实终态（achieved / incomplete）。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-xs text-muted-foreground">
                {goalEval
                  ? `评估状态：${String(goalEval.summary ?? "未评估")}（终端状态：${String(goalEval.terminal_state ?? "incomplete")}）`
                  : "点击「智能拆解目标」自动生成可核验标准"}
              </div>
              <Button variant="outline" size="sm" onClick={() => void handleSuggestGoalsForTask()} disabled={goalLoading}>
                <Sparkles className="mr-1.5 size-3.5" />
                智能拆解目标
              </Button>
            </div>
            {goals.length === 0 ? (
              <div className="rounded-lg border border-dashed p-6 text-center text-xs text-muted-foreground">
                当前任务尚未配置目标闸门，可点击右上角「智能拆解目标」。
              </div>
            ) : (
              <div className="space-y-2">
                {goals.map((g, idx) => (
                  <div key={String(g.id ?? g.goal_key ?? idx)} className="rounded-lg border p-3 space-y-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <Input
                        value={String(g.title ?? "")}
                        onChange={(e) =>
                          setGoals((prev) =>
                            prev.map((item, i) => (i === idx ? { ...item, title: e.target.value } : item)),
                          )
                        }
                        className="h-8 font-medium text-sm"
                      />
                      <Badge variant={g.status === "achieved" ? "default" : "secondary"}>
                        {g.status === "achieved" ? (
                          <span className="flex items-center gap-1">
                            <CheckCircle2 className="size-3" /> 已达成
                          </span>
                        ) : (
                          String(g.status ?? "pending")
                        )}
                      </Badge>
                    </div>
                    <Input
                      value={String(g.criteria ?? "")}
                      placeholder="验收标准（如：至少发现 1 个高危以上可控漏洞）"
                      onChange={(e) =>
                        setGoals((prev) =>
                          prev.map((item, i) => (i === idx ? { ...item, criteria: e.target.value } : item)),
                        )
                      }
                      className="h-8 text-xs text-muted-foreground"
                    />
                  </div>
                ))}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setGoalTask(null)}>
              关闭
            </Button>
            <Button onClick={() => void handleSaveGoals()} disabled={goalLoading || goals.length === 0}>
              保存目标闸门
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
