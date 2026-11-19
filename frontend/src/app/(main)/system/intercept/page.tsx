"use client";

import * as React from "react";
import {
  Activity,
  Check,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { riddleApi, type FusionConfigState, type InterceptItem } from "@/lib/riddle-api";

const FORBIDDEN_OPS = [
  { id: "db_dump", label: "脱库/拖库" },
  { id: "db_delete", label: "删除数据" },
  { id: "db_write", label: "篡改写入" },
  { id: "brute_force", label: "爆破字典" },
  { id: "dos", label: "压测轰炸" },
  { id: "webshell", label: "落马后门" },
];

export default function FusionGovernAndInterceptPage() {
  const [fusionCfg, setFusionCfg] = React.useState<FusionConfigState | null>(null);
  const [savingGate, setSavingGate] = React.useState(false);

  // Intercept Queue + Testbench
  const [intercepts, setIntercepts] = React.useState<InterceptItem[]>([]);
  const [statusFilter, setStatusFilter] = React.useState("all");
  const [testCmd, setTestCmd] = React.useState("sqlmap -u https://target.edu.cn/item?id=1 --dump-all");
  const [testSrcType, setTestSrcType] = React.useState("edusrc");
  const [testForbiddenOps, setTestForbiddenOps] = React.useState<string[]>(["db_dump", "webshell"]);
  const [testRecord, setTestRecord] = React.useState(false);
  const [cmdResult, setCmdResult] = React.useState<Record<string, unknown> | null>(null);

  // Evidence Gate L1-L4 Testbench
  const [evTitle, setEvTitle] = React.useState("统一认证接口 SQL 注入验证");
  const [evVulnType, setEvVulnType] = React.useState("SQL注入");
  const [evSeverity, setEvSeverity] = React.useState("高危");
  const [evPoc, setEvPoc] = React.useState("curl -isk 'https://auth.edu.cn/login?id=1%27'");
  const [evReq, setEvReq] = React.useState("GET /login?id=1' HTTP/1.1\nHost: auth.edu.cn");
  const [evResp, setEvResp] = React.useState("HTTP/1.1 500 Internal Server Error\nYou have an error in your SQL syntax;");
  const [evResult, setEvResult] = React.useState<Record<string, unknown> | null>(null);

  // Scope Guard Testbench
  const [scopeRoots, setScopeRoots] = React.useState("edu.cn\nexample.com");
  const [scopeCidrs, setScopeCidrs] = React.useState("10.0.0.0/8");
  const [scopeTargetUrl, setScopeTargetUrl] = React.useState("https://portal.demo.edu.cn/login");
  const [scopeResult, setScopeResult] = React.useState<Record<string, unknown> | null>(null);

  const loadAll = React.useCallback(async () => {
    try {
      const [cfgRes, listRes] = await Promise.all([
        riddleApi.getFusionConfig(),
        riddleApi.listIntercepts({ status: statusFilter }),
      ]);
      setFusionCfg(cfgRes.config);
      setIntercepts(listRes.items ?? []);
    } catch (err) {
      toast.error(`加载护栏配置失败：${err instanceof Error ? err.message : String(err)}`);
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
      toast.success("融合护栏开关已保存并实时生效");
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSavingGate(false);
    }
  };

  const handleCheckCommand = async () => {
    if (!testCmd.trim()) return;
    try {
      const res = await riddleApi.checkIntercept({
        command: testCmd.trim(),
        tool: "run_shell",
        src_type: testSrcType,
        forbidden_ops: testForbiddenOps,
        record: testRecord,
      });
      setCmdResult(res);
      if (testRecord) await loadAll();
    } catch (err) {
      toast.error(`裁决试算失败：${err instanceof Error ? err.message : String(err)}`);
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

  const handleCheckEvidence = async () => {
    try {
      const res = await riddleApi.checkEvidence({
        title: evTitle,
        vuln_type: evVulnType,
        severity_claimed: evSeverity,
        poc: evPoc,
        raw_request: evReq,
        raw_response: evResp,
      });
      setEvResult(res);
    } catch (err) {
      toast.error(`证据试算失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleCheckScope = async () => {
    try {
      const res = await riddleApi.checkScope(
        { url: scopeTargetUrl.trim(), host: scopeTargetUrl.trim() },
        {
          roots: scopeRoots
            .split(/[\r\n,]+/)
            .map((s) => s.trim())
            .filter(Boolean),
          cidrs: scopeCidrs
            .split(/[\r\n,]+/)
            .map((s) => s.trim())
            .filter(Boolean),
        },
      );
      setScopeResult(res);
    } catch (err) {
      toast.error(`范围守卫试算失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="融合护栏与审批中心"
        description="三大核心硬闸门快捷管控 · 命令三层拦截 (deny/judge/ask) 审批队列 · L1–L4 证据门禁与范围守卫试算台。"
        actions={
          <Button variant="outline" size="sm" onClick={() => void loadAll()}>
            <RefreshCw className="mr-1.5 size-3.5" />
            刷新队列
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

      {/* 3 Governance Tabs */}
      <Tabs defaultValue="intercept" className="space-y-4">
        <TabsList>
          <TabsTrigger value="intercept">命令三层拦截与审批 ({intercepts.length})</TabsTrigger>
          <TabsTrigger value="evidence">证据门禁 L1–L4 试算</TabsTrigger>
          <TabsTrigger value="scope">范围守卫分类试算</TabsTrigger>
        </TabsList>

        <TabsContent value="intercept" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Terminal className="size-4" /> 三层命令拦截沙箱试算
              </CardTitle>
              <CardDescription className="text-xs">
                验证命令在当前规则下命中 deny / judge / ask / allow 哪一层级，支持选择是否写入审批队列。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-4">
                <div className="md:col-span-3 space-y-1.5">
                  <Label className="text-xs">待评估 Shell 命令</Label>
                  <Input
                    className="font-mono text-xs"
                    value={testCmd}
                    onChange={(e) => setTestCmd(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">SRC 场景</Label>
                  <Select value={testSrcType} onValueChange={setTestSrcType}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="edusrc">EduSRC</SelectItem>
                      <SelectItem value="enterprise">企业 SRC</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <div className="flex flex-wrap items-center gap-4">
                {FORBIDDEN_OPS.map((op) => (
                  <label key={op.id} className="flex cursor-pointer items-center gap-1.5 text-xs">
                    <Checkbox
                      checked={testForbiddenOps.includes(op.id)}
                      onCheckedChange={(v) =>
                        setTestForbiddenOps((prev) =>
                          v ? [...new Set([...prev, op.id])] : prev.filter((x) => x !== op.id),
                        )
                      }
                    />
                    <span>{op.label}</span>
                  </label>
                ))}
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="flex cursor-pointer items-center gap-2 text-xs">
                  <Checkbox checked={testRecord} onCheckedChange={(v) => setTestRecord(Boolean(v))} />
                  <span>触发审批/拦截时写入下方台账</span>
                </label>
                <Button size="sm" onClick={() => void handleCheckCommand()}>
                  <Play className="mr-1.5 size-3.5" /> 执行三层拦截试算
                </Button>
              </div>
              {cmdResult ? (
                <div className="rounded-lg border bg-muted/40 p-3 text-xs space-y-1">
                  <div className="flex items-center gap-2 font-medium">
                    <span>裁决结果：</span>
                    <Badge variant={cmdResult.verdict === "allow" ? "default" : "destructive"}>
                      {String(cmdResult.verdict ?? "unknown")}
                    </Badge>
                    {cmdResult.rule ? <Badge variant="outline">{String(cmdResult.rule)}</Badge> : null}
                  </div>
                  <p className="text-muted-foreground">{String(cmdResult.reason ?? JSON.stringify(cmdResult))}</p>
                </div>
              ) : null}
            </CardContent>
          </Card>

          <div className="flex items-center justify-between">
            <h2 className="font-semibold text-sm">人工审批台账与拦截记录</h2>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[150px]">
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
                    <TableHead>命令 / 工具</TableHead>
                    <TableHead>裁决 / 规则</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead className="text-right">审批操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {intercepts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="h-24 text-center text-sm text-muted-foreground">
                        当前无匹配拦截审批记录。
                      </TableCell>
                    </TableRow>
                  ) : (
                    intercepts.map((it) => (
                      <TableRow key={it.id}>
                        <TableCell className="max-w-[380px]">
                          <div className="truncate font-mono text-xs">{it.command}</div>
                          <div className="text-xs text-muted-foreground">
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

        <TabsContent value="evidence" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">证据硬闸门 (L1–L4) 试算台</CardTitle>
              <CardDescription className="text-xs">只读校验一条漏洞证据能否达到高可信分级，不影响正式数据库。</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <Input value={evTitle} onChange={(e) => setEvTitle(e.target.value)} placeholder="漏洞标题" />
                <Input value={evVulnType} onChange={(e) => setEvVulnType(e.target.value)} placeholder="漏洞类型" />
                <Select value={evSeverity} onValueChange={setEvSeverity}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="严重">严重</SelectItem>
                    <SelectItem value="高危">高危</SelectItem>
                    <SelectItem value="中危">中危</SelectItem>
                    <SelectItem value="低危">低危</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Input className="font-mono text-xs" value={evPoc} onChange={(e) => setEvPoc(e.target.value)} placeholder="PoC" />
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Textarea className="font-mono text-xs" rows={4} value={evReq} onChange={(e) => setEvReq(e.target.value)} placeholder="原始请求" />
                <Textarea className="font-mono text-xs" rows={4} value={evResp} onChange={(e) => setEvResp(e.target.value)} placeholder="响应文本" />
              </div>
              <Button size="sm" onClick={() => void handleCheckEvidence()}>试算证据门禁分级</Button>
              {evResult ? (
                <pre className="overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs">
                  {JSON.stringify(evResult, null, 2)}
                </pre>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="scope" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">范围硬守卫 (own / source / foreign) 试算</CardTitle>
              <CardDescription className="text-xs">校验资产写回分类，判断目标域名或 IP 是否越界。</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <div className="space-y-1.5">
                  <Label className="text-xs">授权根域名（每行或逗号分隔）</Label>
                  <Textarea className="font-mono text-xs" rows={3} value={scopeRoots} onChange={(e) => setScopeRoots(e.target.value)} />
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">授权 CIDR 网段</Label>
                  <Textarea className="font-mono text-xs" rows={3} value={scopeCidrs} onChange={(e) => setScopeCidrs(e.target.value)} />
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Input
                  className="font-mono text-xs flex-1"
                  value={scopeTargetUrl}
                  onChange={(e) => setScopeTargetUrl(e.target.value)}
                  placeholder="https://portal.demo.edu.cn/login"
                />
                <Button size="sm" onClick={() => void handleCheckScope()}>执行范围守卫校验</Button>
              </div>
              {scopeResult ? (
                <pre className="overflow-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs">
                  {JSON.stringify(scopeResult, null, 2)}
                </pre>
              ) : null}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
