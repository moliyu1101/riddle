"use client";

import * as React from "react";
import Link from "next/link";
import {
  Activity,
  Building2,
  Check,
  ExternalLink,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Target,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  riddleApi,
  type AssetCompanyItem,
  type FusionConfigState,
  type InterceptItem,
  type RiddleFinding,
  type RiddleTask,
} from "@/lib/riddle-api";

function extractFindingsArray(res: { items?: RiddleFinding[] } | RiddleFinding[]): RiddleFinding[] {
  return Array.isArray(res) ? res : res.items ?? [];
}

export default function FusionGovernAndInterceptPage() {
  const [fusionCfg, setFusionCfg] = React.useState<FusionConfigState | null>(null);
  const [savingGate, setSavingGate] = React.useState(false);
  const [loading, setLoading] = React.useState(true);

  // Real live interception & approval queue
  const [intercepts, setIntercepts] = React.useState<InterceptItem[]>([]);
  const [statusFilter, setStatusFilter] = React.useState("all");

  // Real persisted findings for L1-L4 Evidence Gate audit
  const [findings, setFindings] = React.useState<RiddleFinding[]>([]);
  const [evidenceFilter, setEvidenceFilter] = React.useState<"all" | "passed" | "blocked">("all");

  // Real persisted Task & Company scope inventory
  const [tasks, setTasks] = React.useState<RiddleTask[]>([]);
  const [companies, setCompanies] = React.useState<AssetCompanyItem[]>([]);

  const loadAll = React.useCallback(async () => {
    setLoading(true);
    try {
      const [cfgRes, listRes, taskList, compRes] = await Promise.all([
        riddleApi.getFusionConfig(),
        riddleApi.listIntercepts({ status: statusFilter }),
        riddleApi.listTasks(),
        riddleApi.listAssetCompanies().catch(() => ({ companies: [] })),
      ]);
      setFusionCfg(cfgRes.config);
      setIntercepts(listRes.items ?? []);
      setTasks(taskList);
      setCompanies(compRes.companies ?? []);

      const perTask = await Promise.allSettled(
        taskList.slice(0, 12).map((t) => riddleApi.listTaskFindings(t.id, { limit: 100 })),
      );
      const merged: RiddleFinding[] = [];
      for (const r of perTask) {
        if (r.status === "fulfilled") merged.push(...extractFindingsArray(r.value));
      }
      merged.sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
      setFindings(merged);
    } catch (err) {
      toast.error(`加载护栏与审批数据失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  React.useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleToggleGate = async (
    key: "evidence_gate_hard" | "scope_guard_hard" | "traffic_enabled",
    val: boolean,
  ) => {
    setSavingGate(true);
    try {
      const res = await riddleApi.putFusionConfig({ [key]: val });
      setFusionCfg(res.config);
      toast.success("融合护栏策略已持久化并实时生效");
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSavingGate(false);
    }
  };

  const handleDecide = async (item: InterceptItem, decision: "approved" | "rejected") => {
    try {
      await riddleApi.decideIntercept(item.id, decision, decision === "approved" ? "人工核准放行" : "人工拒绝");
      toast.success(decision === "approved" ? "已批准放行" : "已拒绝执行");
      await loadAll();
    } catch (err) {
      toast.error(`审批操作失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const pendingCount = React.useMemo(
    () => intercepts.filter((it) => it.status === "pending").length,
    [intercepts],
  );

  const filteredFindings = React.useMemo(() => {
    if (evidenceFilter === "passed") return findings.filter((f) => Boolean(f.fusion_evidence?.passed));
    if (evidenceFilter === "blocked") return findings.filter((f) => !f.fusion_evidence?.passed);
    return findings;
  }, [findings, evidenceFilter]);

  const passedEvidenceCount = React.useMemo(
    () => findings.filter((f) => Boolean(f.fusion_evidence?.passed)).length,
    [findings],
  );

  const taskNameMap = React.useMemo(() => {
    const map: Record<string, string> = {};
    for (const t of tasks) map[t.id] = t.name;
    return map;
  }, [tasks]);

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="融合护栏与审批中心"
        description="全局三大硬闸门实时管控 · 生产命令拦截人工审批台账 · 实证漏洞 L1–L4 门禁合规审计 · 任务与主体授权范围总览。"
        actions={
          <Button variant="outline" size="sm" onClick={() => void loadAll()} disabled={loading}>
            <RefreshCw className={`mr-1.5 size-3.5 ${loading ? "animate-spin" : ""}`} />
            刷新实时数据
          </Button>
        }
      />

      {/* Top 3 Core Hard Gates Quick Controls */}
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <ShieldCheck className="size-4 text-emerald-500" />
                证据硬闸门 (evidence_gate_hard)
              </CardTitle>
              <CardDescription className="text-xs">开启后，未达 L2–L4 机械凭据的漏洞不允许自动通过</CardDescription>
            </div>
            <Switch
              disabled={savingGate || !fusionCfg}
              checked={Boolean(fusionCfg?.evidence_gate_hard)}
              onCheckedChange={(v) => void handleToggleGate("evidence_gate_hard", v)}
            />
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <ShieldAlert className="size-4 text-blue-500" />
                范围硬守卫 (scope_guard_hard)
              </CardTitle>
              <CardDescription className="text-xs">开启后，非 own 授权范围的外域资产禁止写入报告</CardDescription>
            </div>
            <Switch
              disabled={savingGate || !fusionCfg}
              checked={Boolean(fusionCfg?.scope_guard_hard)}
              onCheckedChange={(v) => void handleToggleGate("scope_guard_hard", v)}
            />
          </CardHeader>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <div className="space-y-1">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <Activity className="size-4 text-violet-500" />
                实证流量留痕 (traffic_enabled)
              </CardTitle>
              <CardDescription className="text-xs">逐请求落盘 JSONL 并绑定 baseline/proof 四类证据</CardDescription>
            </div>
            <Switch
              disabled={savingGate || !fusionCfg}
              checked={Boolean(fusionCfg?.traffic_enabled)}
              onCheckedChange={(v) => void handleToggleGate("traffic_enabled", v)}
            />
          </CardHeader>
        </Card>
      </div>

      {/* 3 Real Production Governance Tabs */}
      <Tabs defaultValue="intercept" className="space-y-4">
        <TabsList>
          <TabsTrigger value="intercept">
            命令拦截审批台账 ({intercepts.length})
            {pendingCount > 0 ? (
              <Badge variant="destructive" className="ml-1.5 h-4 px-1 text-[10px]">
                {pendingCount} 待审
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="evidence">
            漏洞 L1–L4 门禁合规审计 ({passedEvidenceCount}/{findings.length})
          </TabsTrigger>
          <TabsTrigger value="scope">
            任务与主体授权范围 ({tasks.length + companies.length})
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Real Interception Approval Ledger */}
        <TabsContent value="intercept" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-semibold text-sm">实时命令拦截与人工审批台账</h2>
              <p className="text-xs text-muted-foreground">
                展示任务执行过程中真实触发 deny / ask 策略的命令记录，待审批项可由操作员直接核准放行或拒绝。
              </p>
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[150px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部记录</SelectItem>
                <SelectItem value="pending">待人工审批</SelectItem>
                <SelectItem value="approved">已放行</SelectItem>
                <SelectItem value="rejected">已拒绝</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>拦截命令 / 工具</TableHead>
                    <TableHead className="w-[110px]">裁决级别</TableHead>
                    <TableHead className="w-[110px]">审批状态</TableHead>
                    <TableHead className="w-[180px] text-right">审批操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {intercepts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="h-24 text-center text-sm text-muted-foreground">
                        当前无真实命令拦截或待审批记录。
                      </TableCell>
                    </TableRow>
                  ) : (
                    intercepts.map((it) => (
                      <TableRow key={it.id}>
                        <TableCell className="max-w-[420px]">
                          <div className="truncate font-mono text-xs">{it.command}</div>
                          <div className="mt-0.5 text-xs text-muted-foreground">
                            {it.tool} · {it.src_type} {it.reason ? `· ${it.reason}` : ""}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant={it.verdict === "deny" ? "destructive" : "secondary"}>{it.verdict}</Badge>
                        </TableCell>
                        <TableCell>
                          <Badge variant={it.status === "pending" ? "outline" : "default"}>{it.status}</Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          {it.status === "pending" ? (
                            <div className="inline-flex gap-1">
                              <Button size="sm" variant="outline" onClick={() => void handleDecide(it, "approved")}>
                                <Check className="mr-1 size-3.5 text-emerald-600" /> 放行
                              </Button>
                              <Button size="sm" variant="outline" onClick={() => void handleDecide(it, "rejected")}>
                                <X className="mr-1 size-3.5 text-destructive" /> 拒绝
                              </Button>
                            </div>
                          ) : (
                            <span className="text-xs text-muted-foreground">{it.note || "-"}</span>
                          )}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 2: Real Evidence Gate Compliance Audit on Persisted Findings */}
        <TabsContent value="evidence" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="font-semibold text-sm">已落盘漏洞 L1–L4 证据门禁实时合规审计</h2>
              <p className="text-xs text-muted-foreground">
                基于真实入库漏洞的请求/响应证据与机械凭据自动评估，直接定位待补证或已通过硬闸门的记录。
              </p>
            </div>
            <Select value={evidenceFilter} onValueChange={(v) => setEvidenceFilter(v as "all" | "passed" | "blocked")}>
              <SelectTrigger className="w-[160px] text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部漏洞（{findings.length}）</SelectItem>
                <SelectItem value="passed">已通过硬闸门（{passedEvidenceCount}）</SelectItem>
                <SelectItem value="blocked">待补证/未过门禁（{findings.length - passedEvidenceCount}）</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>漏洞标题与目标</TableHead>
                    <TableHead className="w-[110px]">等级</TableHead>
                    <TableHead className="w-[150px]">L1–L4 证据等级</TableHead>
                    <TableHead>门禁核验依据</TableHead>
                    <TableHead className="w-[90px] text-right">详情</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredFindings.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        当前无已落盘漏洞记录。
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredFindings.map((f) => {
                      const ev = f.fusion_evidence;
                      return (
                        <TableRow key={f.id}>
                          <TableCell className="max-w-[320px]">
                            <div className="truncate font-medium text-sm">{f.title}</div>
                            <div className="truncate font-mono text-[11px] text-muted-foreground">
                              {f.target_url} · {taskNameMap[f.task_id] || f.task_id}
                            </div>
                          </TableCell>
                          <TableCell>
                            <StatusBadge
                              domain="severity"
                              value={f.review?.effective_severity || f.review?.severity_final || f.severity_claimed}
                            />
                          </TableCell>
                          <TableCell>
                            <Badge variant={ev?.passed ? "default" : "destructive"} className="text-xs">
                              {ev?.tier_label || ev?.tier || "待评估"}
                            </Badge>
                          </TableCell>
                          <TableCell className="max-w-[280px] text-xs text-muted-foreground">
                            {ev?.reasons?.length ? ev.reasons.join("；") : ev?.passed ? "已满足机械实证门禁" : "缺少可验证响应凭据"}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button size="sm" variant="ghost" asChild>
                              <Link href={`/function/findings/detail?id=${encodeURIComponent(f.id)}`}>
                                查看 <ExternalLink className="ml-1 size-3" />
                              </Link>
                            </Button>
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

        {/* Tab 3: Real Task & Company Scope Governance */}
        <TabsContent value="scope" className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-1.5 text-sm">
                  <Target className="size-4 text-primary" /> 挖掘任务授权范围与护栏（{tasks.length}）
                </CardTitle>
                <CardDescription className="text-xs">各正式任务的 SRC 场景、资产来源与高危操作护栏配置</CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>任务名称</TableHead>
                      <TableHead>范围定义</TableHead>
                      <TableHead>护栏拦截项</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {tasks.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={3} className="h-20 text-center text-xs text-muted-foreground">
                          暂无正式挖掘任务。
                        </TableCell>
                      </TableRow>
                    ) : (
                      tasks.slice(0, 20).map((t) => (
                        <TableRow key={t.id}>
                          <TableCell>
                            <Link
                              href={`/function/tasks/detail?id=${encodeURIComponent(t.id)}`}
                              className="font-medium text-xs hover:underline"
                            >
                              {t.name}
                            </Link>
                            <div className="text-[11px] text-muted-foreground">
                              {t.src_type} · {t.status}
                            </div>
                          </TableCell>
                          <TableCell className="max-w-[200px] truncate font-mono text-[11px] text-muted-foreground">
                            {t.fofa_query || `${t.manual_targets?.length ?? 0} 个手动目标`}
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1">
                              {(t.guard_ops ?? []).length === 0 ? (
                                <span className="text-[11px] text-muted-foreground">默认</span>
                              ) : (
                                (t.guard_ops ?? []).slice(0, 4).map((op) => (
                                  <Badge key={op} variant="outline" className="h-4 px-1 text-[10px]">
                                    {op}
                                  </Badge>
                                ))
                              )}
                            </div>
                          </TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="flex items-center gap-1.5 text-sm">
                  <Building2 className="size-4 text-primary" /> 企业/高校主体授权边界（{companies.length}）
                </CardTitle>
                <CardDescription className="text-xs">双图资产中心已落盘的正式主体及其域名/IP/CIDR 范围规则</CardDescription>
              </CardHeader>
              <CardContent className="p-0">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>归属主体</TableHead>
                      <TableHead>范围规则</TableHead>
                      <TableHead className="w-[70px] text-right">资产</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {companies.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={3} className="h-20 text-center text-xs text-muted-foreground">
                          暂未配置企业/高校主体，可前往「双图资产中心」或「AI 资产收集」建立。
                        </TableCell>
                      </TableRow>
                    ) : (
                      companies.map((c) => (
                        <TableRow key={c.id}>
                          <TableCell className="font-medium text-xs">{c.name}</TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1">
                              {(c.scope_rules ?? []).map((r, idx) => (
                                <Badge key={idx} variant="outline" className="h-4 px-1 font-mono text-[10px]">
                                  {r.kind}:{r.value}
                                </Badge>
                              ))}
                            </div>
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs">{c.asset_count}</TableCell>
                        </TableRow>
                      ))
                    )}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
