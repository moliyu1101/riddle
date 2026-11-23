"use client";

import * as React from "react";
import Link from "next/link";
import {
  BookOpen,
  Check,
  CheckCircle2,
  Download,
  ExternalLink,
  FileText,
  FlaskConical,
  RefreshCw,
  Search,
  Send,
  ShieldCheck,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { KillsweepLaunchDialog } from "./_components/killsweep-launch-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import {
  riddleApi,
  type RiddleFinding,
  type RiddleTask,
  type RiddleVulnStats,
} from "@/lib/riddle-api";

const SEVERITIES = ["严重", "高危", "中危", "低危"];

type ReviewBucket = "all" | "pending_human" | "passed" | "submitted" | "deepen" | "rejected";

function extractFindingsArray(res: { items?: RiddleFinding[] } | RiddleFinding[]): RiddleFinding[] {
  return Array.isArray(res) ? res : res.items ?? [];
}

function getEffectiveSeverity(f: RiddleFinding): string {
  return f.review?.effective_severity || f.review?.user_severity || f.review?.severity_final || f.severity_claimed || "中危";
}

function isPendingHuman(f: RiddleFinding): boolean {
  return f.review?.verdict === "accepted" && f.review?.user_status === "pending" && f.status !== "superseded";
}

export default function FindingsPage() {
  const [tasks, setTasks] = React.useState<RiddleTask[]>([]);
  const [vulnStats, setVulnStats] = React.useState<RiddleVulnStats | null>(null);
  const [findings, setFindings] = React.useState<RiddleFinding[]>([]);
  const [loading, setLoading] = React.useState(true);

  const [selectedTaskId, setSelectedTaskId] = React.useState("all");
  const [bucket, setBucket] = React.useState<ReviewBucket>("all");
  const [sevFilter, setSevFilter] = React.useState("all");
  const [search, setSearch] = React.useState("");

  // Drawer state
  const [activeId, setActiveId] = React.useState<string | null>(null);
  const [detail, setDetail] = React.useState<RiddleFinding | null>(null);
  const [detailLoading, setDetailLoading] = React.useState(false);
  const [retests, setRetests] = React.useState<Array<Record<string, unknown>>>([]);
  const [editSeverity, setEditSeverity] = React.useState("高危");
  const [editNotes, setEditNotes] = React.useState("");
  const [deepenDirective, setDeepenDirective] = React.useState("");
  const [retestUrl, setRetestUrl] = React.useState("");
  const [retestMatch, setRetestMatch] = React.useState("");
  const [retestNotes, setRetestNotes] = React.useState("");
  const [actionBusy, setActionBusy] = React.useState(false);

  // One-click killsweep launch dialog state
  const [killsweepFindingId, setKillsweepFindingId] = React.useState<string | null>(null);

  const loadData = React.useCallback(
    async (quiet = false) => {
      if (!quiet) setLoading(true);
      try {
        const [taskList, vStats] = await Promise.all([riddleApi.listTasks(), riddleApi.getVulnStats()]);
        setTasks(taskList);
        setVulnStats(vStats);

        const targetTaskIds =
          selectedTaskId === "all" ? taskList.slice(0, 15).map((t) => t.id) : [selectedTaskId];
        const perTask = await Promise.allSettled(
          targetTaskIds.map((tid) => riddleApi.listTaskFindings(tid, { limit: 200 })),
        );
        const merged: RiddleFinding[] = [];
        for (const r of perTask) {
          if (r.status === "fulfilled") {
            merged.push(...extractFindingsArray(r.value));
          }
        }
        merged.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
        setFindings(merged);
      } catch (err) {
        toast.error(`加载漏洞列表失败：${err instanceof Error ? err.message : String(err)}`);
      } finally {
        setLoading(false);
      }
    },
    [selectedTaskId],
  );

  React.useEffect(() => {
    void loadData(false);
  }, [loadData]);

  const taskNameMap = React.useMemo(() => {
    const map: Record<string, string> = {};
    for (const t of tasks) map[t.id] = t.name;
    return map;
  }, [tasks]);

  const pendingHumanCount = React.useMemo(() => findings.filter(isPendingHuman).length, [findings]);
  const critHighCount = React.useMemo(
    () =>
      (vulnStats?.by_severity?.["严重"] ?? 0) +
      (vulnStats?.by_severity?.["高危"] ?? 0) +
      (vulnStats?.by_severity?.critical ?? 0) +
      (vulnStats?.by_severity?.high ?? 0),
    [vulnStats],
  );

  const filtered = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    return findings.filter((f) => {
      if (bucket === "pending_human" && !isPendingHuman(f)) return false;
      if (bucket === "passed" && f.review?.user_status !== "passed") return false;
      if (bucket === "submitted" && !f.review?.submitted) return false;
      if (
        bucket === "deepen" &&
        f.review?.verdict !== "needs_deepen" &&
        f.review?.user_status !== "deepening"
      ) {
        return false;
      }
      if (
        bucket === "rejected" &&
        f.review?.user_status !== "rejected" &&
        f.review?.verdict !== "rejected"
      ) {
        return false;
      }

      const sev = getEffectiveSeverity(f);
      if (sevFilter !== "all" && sev !== sevFilter) return false;
      if (!q) return true;
      return (
        f.title.toLowerCase().includes(q) ||
        f.vuln_type.toLowerCase().includes(q) ||
        f.target_url.toLowerCase().includes(q) ||
        (f.owner || "").toLowerCase().includes(q) ||
        (f.edu_school || "").toLowerCase().includes(q)
      );
    });
  }, [findings, bucket, sevFilter, search]);

  const openDetail = async (id: string) => {
    setActiveId(id);
    setDetailLoading(true);
    setDetail(null);
    setRetests([]);
    try {
      const [fRes, rRes] = await Promise.allSettled([riddleApi.getFinding(id), riddleApi.listRetests(id)]);
      if (fRes.status === "fulfilled") {
        const d = fRes.value;
        setDetail(d);
        setEditSeverity(getEffectiveSeverity(d));
        setEditNotes(d.review?.user_notes ?? "");
        setRetestUrl(d.target_url ?? "");
      }
      if (rRes.status === "fulfilled") {
        setRetests(rRes.value.retests ?? []);
      }
    } catch (err) {
      toast.error(`读取详情失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setDetailLoading(false);
    }
  };

  const handleReviewAction = async (status: "passed" | "rejected" | "pending") => {
    if (!detail) return;
    setActionBusy(true);
    try {
      const res = await riddleApi.reviewFinding(detail.id, {
        user_status: status,
        user_severity: editSeverity,
        user_notes: editNotes,
      });
      toast.success(
        status === "passed"
          ? res.killsweep_triggered
            ? "复审通过，已自动触发通杀 Hunter 分析！"
            : "复审已通过"
          : status === "rejected"
            ? "已驳回该漏洞"
            : "已重置为待复审",
      );
      await Promise.all([openDetail(detail.id), loadData(true)]);
    } catch (err) {
      toast.error(`提交复审失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionBusy(false);
    }
  };

  const handleToggleSubmitted = async () => {
    if (!detail) return;
    setActionBusy(true);
    try {
      const next = !detail.review?.submitted;
      await riddleApi.reviewFinding(detail.id, { submitted: next });
      toast.success(next ? "已标记为已提交 SRC" : "已取消提交标记");
      await Promise.all([openDetail(detail.id), loadData(true)]);
    } catch (err) {
      toast.error(`操作失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionBusy(false);
    }
  };

  const handleDeepen = async () => {
    if (!detail || !deepenDirective.trim()) {
      toast.error("请填写定向深挖指令");
      return;
    }
    setActionBusy(true);
    try {
      const res = await riddleApi.deepenFinding(detail.id, deepenDirective.trim());
      toast.success(res.message || "已加入定向深挖队列");
      setDeepenDirective("");
      setActiveId(null);
      await loadData(true);
    } catch (err) {
      toast.error(`发起深挖失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionBusy(false);
    }
  };

  const handleDistill = async () => {
    if (!detail) return;
    setActionBusy(true);
    try {
      await riddleApi.distillFindingToKb(detail.id);
      toast.success("已成功蒸馏为可复用漏洞知识条目！");
    } catch (err) {
      toast.error(`蒸馏失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionBusy(false);
    }
  };

  const handleRetest = async (mode: "http_probe" | "manual", status = "reproduced") => {
    if (!detail) return;
    setActionBusy(true);
    try {
      const res = await riddleApi.createRetest(detail.id, {
        mode,
        status,
        url: retestUrl || detail.target_url,
        match_text: retestMatch,
        notes: retestNotes,
      });
      setRetests(res.retests ?? []);
      toast.success(mode === "http_probe" ? "已执行 HTTP 只读探测复测" : "已登记复测结果");
      await openDetail(detail.id);
    } catch (err) {
      toast.error(`复测操作失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setActionBusy(false);
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="漏洞与复审中心"
        description="AI 初审与人工复审闭环 · L1–L4 机械凭据分级 · 定向深挖回炉 · 蒸馏知识库与公文级 Word (.docx) 报告。"
        actions={
          <>
            {selectedTaskId !== "all" ? (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    void riddleApi
                      .downloadTaskReportsExport(selectedTaskId, "md")
                      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)))
                  }
                >
                  <Download className="mr-1.5 size-3.5" /> 打包导出 Markdown
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    void riddleApi
                      .downloadTaskReportsExport(selectedTaskId, "edusrc")
                      .catch((e) => toast.error(e instanceof Error ? e.message : String(e)))
                  }
                >
                  EduSRC JSON
                </Button>
              </>
            ) : null}
            <Button variant="outline" size="sm" onClick={() => void loadData(true)}>
              <RefreshCw className="mr-1.5 size-3.5" />
              刷新队列
            </Button>
          </>
        }
      />

      {/* 6 KPI Cards */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-3 lg:grid-cols-6">
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">全局过审漏洞</CardDescription>
            <CardTitle className="text-2xl tabular-nums">{vulnStats?.total ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">待人工复审</CardDescription>
            <CardTitle className="text-2xl tabular-nums text-amber-600 dark:text-amber-400">
              {pendingHumanCount}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">已提交 SRC</CardDescription>
            <CardTitle className="text-2xl tabular-nums text-emerald-600 dark:text-emerald-400">
              {vulnStats?.submitted ?? 0}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">过审·待提交</CardDescription>
            <CardTitle className="text-2xl tabular-nums">{vulnStats?.ready ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">严重 / 高危</CardDescription>
            <CardTitle className="text-2xl tabular-nums text-rose-600 dark:text-rose-400">
              {critHighCount}
            </CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">当前列表条目</CardDescription>
            <CardTitle className="text-2xl tabular-nums">{filtered.length}</CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative min-w-[220px] flex-1 max-w-md">
          <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
          <Input
            placeholder="搜索漏洞标题、URL、类型、高校/归属…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8"
          />
        </div>
        <Select value={selectedTaskId} onValueChange={setSelectedTaskId}>
          <SelectTrigger className="w-[200px]">
            <SelectValue placeholder="所属任务" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部近期任务</SelectItem>
            {tasks.map((t) => (
              <SelectItem key={t.id} value={t.id}>
                {t.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={bucket} onValueChange={(v) => setBucket(v as ReviewBucket)}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="复审阶段" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部漏洞线索</SelectItem>
            <SelectItem value="pending_human">待人工复审</SelectItem>
            <SelectItem value="passed">人工复审通过</SelectItem>
            <SelectItem value="submitted">已提交 SRC</SelectItem>
            <SelectItem value="deepen">待深挖 / 深挖中</SelectItem>
            <SelectItem value="rejected">已驳回</SelectItem>
          </SelectContent>
        </Select>
        <Select value={sevFilter} onValueChange={setSevFilter}>
          <SelectTrigger className="w-[130px]">
            <SelectValue placeholder="危险等级" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部等级</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {/* Findings Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>漏洞标题与目标</TableHead>
                <TableHead className="w-[120px]">类型</TableHead>
                <TableHead className="w-[150px]">等级与证据闸门</TableHead>
                <TableHead className="w-[160px]">AI / 人工复审</TableHead>
                <TableHead className="w-[210px] text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={5} className="h-28 text-center text-sm text-muted-foreground">
                    正在加载漏洞与复审数据…
                  </TableCell>
                </TableRow>
              ) : filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="h-28 text-center text-sm text-muted-foreground">
                    当前筛选条件下暂无漏洞记录。
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((f) => {
                  const sev = getEffectiveSeverity(f);
                  const tierLabel = f.fusion_evidence?.tier_label || f.fusion_evidence?.tier || "";
                  return (
                    <TableRow
                      key={f.id}
                      className="cursor-pointer hover:bg-muted/40"
                      onClick={() => void openDetail(f.id)}
                    >
                      <TableCell className="max-w-[360px]">
                        <div className="truncate font-medium text-sm">{f.title}</div>
                        <div className="mt-0.5 flex items-center gap-2 truncate text-xs text-muted-foreground">
                          <span className="truncate">{f.target_url}</span>
                          {f.edu_school || f.owner ? (
                            <Badge variant="outline" className="shrink-0 text-[11px]">
                              {f.edu_school || f.owner}
                            </Badge>
                          ) : null}
                        </div>
                        <div className="mt-0.5 text-[11px] text-muted-foreground">
                          任务：{taskNameMap[f.task_id] || f.task_id}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs">
                          {f.vuln_type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <StatusBadge domain="severity" value={sev} />
                          {tierLabel ? (
                            <Badge variant={f.fusion_evidence?.passed ? "outline" : "destructive"} className="text-[11px]">
                              {tierLabel}
                            </Badge>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap items-center gap-1.5">
                          <StatusBadge
                            domain="finding"
                            value={f.review?.user_status || f.review?.verdict || f.status || "pending"}
                            dot
                          />
                          {f.review?.submitted ? (
                            <Badge variant="default" className="text-[11px]">
                              已提交
                            </Badge>
                          ) : null}
                        </div>
                      </TableCell>
                      <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                        <div className="inline-flex items-center gap-1">
                          <Button
                            variant="outline"
                            size="sm"
                            className="h-7 px-2 text-xs"
                            title="基于该漏洞一键落盘为测绘通杀任务"
                            onClick={() => setKillsweepFindingId(f.id)}
                          >
                            <Zap className="mr-1 size-3.5 text-amber-500" /> 一键通杀
                          </Button>
                          <Button variant="ghost" size="sm" onClick={() => void openDetail(f.id)}>
                            审核
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            title="导出公文级 Word (.docx)"
                            onClick={() => void riddleApi.downloadDocxReport(f.id, f.title)}
                          >
                            <Download className="size-4" />
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

      {/* Review & Deepen Drawer */}
      <Sheet open={Boolean(activeId)} onOpenChange={(open) => !open && setActiveId(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="pr-6">{detail?.title || "正在加载漏洞详情…"}</SheetTitle>
            <SheetDescription className="truncate">
              {detail?.target_url} {detail?.edu_school ? `· ${detail.edu_school}` : ""}
            </SheetDescription>
          </SheetHeader>

          {detailLoading || !detail ? (
            <div className="py-12 text-center text-sm text-muted-foreground">正在加载完整漏洞证据与复审记录…</div>
          ) : (
            <div className="mt-5 space-y-5">
              {/* Review Decision Controls */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm">人工复审裁决</CardTitle>
                  <CardDescription className="text-xs">
                    AI 结论：{detail.review?.verdict ?? "-"} ({detail.review?.confidence ?? "-"}, {detail.review?.score ?? 0} 分) ·
                    L1–L4 证据门禁：{detail.fusion_evidence?.passed ? "通过" : "未过硬门禁"}
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    <div className="space-y-1.5">
                      <Label className="text-xs">核定危险等级</Label>
                      <Select value={editSeverity} onValueChange={setEditSeverity}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {SEVERITIES.map((s) => (
                            <SelectItem key={s} value={s}>
                              {s}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="flex items-end gap-2">
                      <Button
                        size="sm"
                        className="flex-1"
                        disabled={actionBusy}
                        onClick={() => void handleReviewAction("passed")}
                      >
                        <Check className="mr-1 size-3.5" /> 通过 (触发通杀)
                      </Button>
                      <Button
                        size="sm"
                        variant="destructive"
                        disabled={actionBusy}
                        onClick={() => void handleReviewAction("rejected")}
                      >
                        <X className="mr-1 size-3.5" /> 驳回
                      </Button>
                    </div>
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">复审备注</Label>
                    <Textarea
                      rows={2}
                      placeholder="记录人工验证结论、绕过条件或危害定级依据…"
                      value={editNotes}
                      onChange={(e) => setEditNotes(e.target.value)}
                    />
                  </div>
                  <div className="flex flex-wrap items-center gap-2 pt-1">
                    <Button
                      size="sm"
                      variant="default"
                      onClick={() => setKillsweepFindingId(detail.id)}
                    >
                      <Zap className="mr-1.5 size-3.5" />
                      一键通杀（落盘新任务）
                    </Button>
                    <Button size="sm" variant="outline" disabled={actionBusy} onClick={() => void handleToggleSubmitted()}>
                      <Send className="mr-1.5 size-3.5" />
                      {detail.review?.submitted ? "已提交 SRC (点击取消)" : "标记为已提交 SRC"}
                    </Button>
                    <Button size="sm" variant="outline" disabled={actionBusy} onClick={() => void handleDistill()}>
                      <BookOpen className="mr-1.5 size-3.5" />
                      蒸馏入知识库
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      onClick={() => void riddleApi.downloadDocxReport(detail.id, detail.title)}
                    >
                      <FileText className="mr-1.5 size-3.5" />
                      导出 Word (.docx)
                    </Button>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => void riddleApi.downloadFindingExport(detail.id, "md")}
                    >
                      .md
                    </Button>
                    <Button size="sm" variant="ghost" asChild>
                      <Link href={`/function/findings/detail?id=${encodeURIComponent(detail.id)}`}>
                        完整详情 <ExternalLink className="ml-1 size-3" />
                      </Link>
                    </Button>
                  </div>
                </CardContent>
              </Card>

              {/* Detail Tabs: Evidence/PoC | Deepen | Retest */}
              <Tabs defaultValue="evidence">
                <TabsList className="w-full">
                  <TabsTrigger value="evidence" className="flex-1">
                    漏洞描述与 PoC
                  </TabsTrigger>
                  <TabsTrigger value="deepen" className="flex-1">
                    定向深挖回炉
                  </TabsTrigger>
                  <TabsTrigger value="retest" className="flex-1">
                    复测闭环 ({retests.length})
                  </TabsTrigger>
                </TabsList>

                <TabsContent value="evidence" className="mt-3 space-y-3">
                  {detail.description ? (
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">漏洞描述</Label>
                      <div className="rounded-lg border bg-muted/30 p-3 text-xs whitespace-pre-wrap leading-relaxed">
                        {detail.description}
                      </div>
                    </div>
                  ) : null}
                  {detail.poc || detail.raw_request ? (
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">PoC / 原始请求</Label>
                      <pre className="max-h-56 overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs">
                        {detail.poc || detail.raw_request}
                      </pre>
                    </div>
                  ) : null}
                  {detail.raw_response ? (
                    <div className="space-y-1">
                      <Label className="text-xs text-muted-foreground">响应证据</Label>
                      <pre className="max-h-48 overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs">
                        {detail.raw_response}
                      </pre>
                    </div>
                  ) : null}
                </TabsContent>

                <TabsContent value="deepen" className="mt-3 space-y-3">
                  <p className="text-xs text-muted-foreground">
                    将当前漏洞对应目标携定向指令重新入队，让 Worker 继续扩面或证明更高危害（原记录标记为 superseded）。
                  </p>
                  <Textarea
                    rows={3}
                    placeholder="例如：不要停在信息泄露，继续尝试利用泄漏凭证登录后台或寻找上传点实现 RCE"
                    value={deepenDirective}
                    onChange={(e) => setDeepenDirective(e.target.value)}
                  />
                  <Button size="sm" disabled={actionBusy} onClick={() => void handleDeepen()}>
                    <FlaskConical className="mr-1.5 size-3.5" />
                    携带指令退回深挖
                  </Button>
                </TabsContent>

                <TabsContent value="retest" className="mt-3 space-y-3">
                  <div className="space-y-2 rounded-lg border p-3">
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      <Input
                        placeholder="复测 URL（默认当前 target_url）"
                        value={retestUrl}
                        onChange={(e) => setRetestUrl(e.target.value)}
                      />
                      <Input
                        placeholder="断言文本（HTTP 只读探活用，可选）"
                        value={retestMatch}
                        onChange={(e) => setRetestMatch(e.target.value)}
                      />
                    </div>
                    <Input
                      placeholder="复测说明…"
                      value={retestNotes}
                      onChange={(e) => setRetestNotes(e.target.value)}
                    />
                    <div className="flex flex-wrap gap-2">
                      <Button size="sm" disabled={actionBusy} onClick={() => void handleRetest("http_probe")}>
                        <ShieldCheck className="mr-1.5 size-3.5" /> HTTP 安全探活复测
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={actionBusy}
                        onClick={() => void handleRetest("manual", "fixed")}
                      >
                        <CheckCircle2 className="mr-1.5 size-3.5" /> 手动登记：已修复
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={actionBusy}
                        onClick={() => void handleRetest("manual", "reproduced")}
                      >
                        手动登记：仍可复现
                      </Button>
                    </div>
                  </div>
                  {retests.length === 0 ? (
                    <p className="text-center text-xs text-muted-foreground py-4">暂无复测记录</p>
                  ) : (
                    <div className="space-y-2">
                      {retests.map((r, idx) => (
                        <div key={String(r.id ?? idx)} className="rounded border p-2.5 text-xs">
                          <div className="flex items-center justify-between font-medium">
                            <span>
                              [{String(r.mode ?? "manual")}] {String(r.status ?? "")}
                            </span>
                            <span className="text-muted-foreground">{String(r.created_at ?? "")}</span>
                          </div>
                          {r.notes ? <p className="mt-1 text-muted-foreground">{String(r.notes)}</p> : null}
                        </div>
                      ))}
                    </div>
                  )}
                </TabsContent>
              </Tabs>
            </div>
          )}
        </SheetContent>
      </Sheet>

      <KillsweepLaunchDialog
        findingId={killsweepFindingId}
        open={Boolean(killsweepFindingId)}
        onOpenChange={(open) => {
          if (!open) setKillsweepFindingId(null);
        }}
      />
    </div>
  );
}
