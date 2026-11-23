"use client";

import * as React from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  BookOpen,
  Bot,
  Check,
  CheckCircle2,
  FileText,
  FlaskConical,
  History,
  Loader2,
  RotateCcw,
  Save,
  Send,
  ShieldCheck,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

import { StatusBadge } from "@/components/status-badge";
import { KillsweepLaunchDialog } from "../_components/killsweep-launch-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { riddleApi, type RiddleFinding } from "@/lib/riddle-api";

const SEVERITIES = ["严重", "高危", "中危", "低危"];

function formatSteps(steps: unknown): string {
  if (typeof steps === "string") return steps;
  if (Array.isArray(steps)) return steps.map((s) => (typeof s === "string" ? s : JSON.stringify(s))).join("\n");
  return "";
}

function FindingDetailInner() {
  const searchParams = useSearchParams();
  const findingId = searchParams.get("id") ?? "";

  const [finding, setFinding] = React.useState<RiddleFinding | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [busy, setBusy] = React.useState(false);

  // Editable report fields (user_edits)
  const [editTitle, setEditTitle] = React.useState("");
  const [editScope, setEditScope] = React.useState("");
  const [editDesc, setEditDesc] = React.useState("");
  const [editSteps, setEditSteps] = React.useState("");
  const [editPoc, setEditPoc] = React.useState("");

  // Review Governance fields
  const [severity, setSeverity] = React.useState("高危");
  const [notes, setNotes] = React.useState("");
  const [deepenDirective, setDeepenDirective] = React.useState("");

  // Versions & Retests & Assistant
  const [versions, setVersions] = React.useState<
    Array<{ version: number; source: string; note: string; created_at: string; snapshot: Record<string, unknown> }>
  >([]);
  const [retests, setRetests] = React.useState<Array<Record<string, unknown>>>([]);
  const [retestUrl, setRetestUrl] = React.useState("");
  const [retestMatch, setRetestMatch] = React.useState("");
  const [retestNotes, setRetestNotes] = React.useState("");

  const [messages, setMessages] = React.useState<Array<{ role: string; content: string }>>([]);
  const [assistantInput, setAssistantInput] = React.useState("");
  const [assistantBusy, setAssistantBusy] = React.useState(false);
  const [killsweepOpen, setKillsweepOpen] = React.useState(false);

  const loadAll = React.useCallback(async () => {
    if (!findingId) return;
    setLoading(true);
    try {
      const [fRes, vRes, rRes] = await Promise.allSettled([
        riddleApi.getFinding(findingId),
        riddleApi.listFindingVersions(findingId),
        riddleApi.listRetests(findingId),
      ]);
      if (fRes.status === "fulfilled") {
        const d = fRes.value;
        setFinding(d);
        const edits = (d.review?.user_edits || {}) as Record<string, unknown>;
        setEditTitle(String(edits.title ?? d.title ?? ""));
        setEditScope(String(edits.affected_scope ?? d.affected_scope ?? ""));
        setEditDesc(String(edits.description ?? d.description ?? ""));
        setEditSteps(formatSteps(edits.steps ?? d.steps));
        setEditPoc(String(edits.poc ?? d.poc ?? ""));
        setSeverity(d.review?.effective_severity || d.review?.user_severity || d.review?.severity_final || d.severity_claimed || "高危");
        setNotes(d.review?.user_notes ?? "");
        setRetestUrl(d.target_url ?? "");
        setMessages(d.assistant_messages ?? []);
      }
      if (vRes.status === "fulfilled") setVersions(vRes.value);
      if (rRes.status === "fulfilled") setRetests(rRes.value.retests ?? []);
    } catch (err) {
      toast.error(`加载漏洞详情失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [findingId]);

  React.useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleSaveReportEdits = async () => {
    if (!finding) return;
    setBusy(true);
    try {
      await riddleApi.reviewFinding(finding.id, {
        user_severity: severity,
        user_notes: notes,
        user_edits: {
          title: editTitle.trim(),
          affected_scope: editScope.trim(),
          description: editDesc,
          steps: editSteps
            .split(/\r?\n/)
            .map((s) => s.trim())
            .filter(Boolean),
          poc: editPoc,
        },
      });
      toast.success("已保存报告修订并自动生成版本快照");
      await loadAll();
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleReviewDecision = async (status: "passed" | "rejected" | "pending") => {
    if (!finding) return;
    setBusy(true);
    try {
      const res = await riddleApi.reviewFinding(finding.id, {
        user_status: status,
        user_severity: severity,
        user_notes: notes,
      });
      toast.success(
        status === "passed"
          ? res.killsweep_triggered
            ? "复审通过，已自动触发通杀 Hunter 并回写知识/情报闭环！"
            : "复审通过，已回写情报反馈闭环"
          : status === "rejected"
            ? "已驳回该漏洞并记录避坑经验"
            : "已重置为待复审",
      );
      await loadAll();
    } catch (err) {
      toast.error(`裁决失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleToggleSubmitted = async () => {
    if (!finding) return;
    setBusy(true);
    try {
      const next = !finding.review?.submitted;
      await riddleApi.reviewFinding(finding.id, { submitted: next });
      toast.success(next ? "已标记为已提交 SRC" : "已取消提交状态");
      await loadAll();
    } catch (err) {
      toast.error(`操作失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleDeepen = async () => {
    if (!finding || !deepenDirective.trim()) {
      toast.error("请输入定向深挖指令");
      return;
    }
    setBusy(true);
    try {
      const res = await riddleApi.deepenFinding(finding.id, deepenDirective.trim());
      toast.success(res.message || "已带定向指令退回 Worker 深挖");
      setDeepenDirective("");
      await loadAll();
    } catch (err) {
      toast.error(`深挖失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleRestoreVersion = async (ver: number) => {
    if (!finding) return;
    if (!window.confirm(`确定回滚报告正文到版本 v${ver}？`)) return;
    setBusy(true);
    try {
      await riddleApi.restoreFindingVersion(finding.id, ver);
      toast.success(`已恢复到 v${ver} 并保留审计新快照`);
      await loadAll();
    } catch (err) {
      toast.error(`回滚失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const handleAskAssistant = async () => {
    if (!finding || !assistantInput.trim()) return;
    const question = assistantInput.trim();
    setAssistantBusy(true);
    setAssistantInput("");
    try {
      const res = await riddleApi.askFindingAssistant(finding.id, question);
      setMessages(res.messages ?? []);
    } catch (err) {
      toast.error(`AI 助手请求失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setAssistantBusy(false);
    }
  };

  const handleRetest = async (mode: "http_probe" | "manual", status = "reproduced") => {
    if (!finding) return;
    setBusy(true);
    try {
      const res = await riddleApi.createRetest(finding.id, {
        mode,
        status,
        url: retestUrl || finding.target_url,
        match_text: retestMatch,
        notes: retestNotes,
      });
      setRetests(res.retests ?? []);
      toast.success(mode === "http_probe" ? "HTTP 只读探活复测完成" : "已登记复测结果");
      await loadAll();
    } catch (err) {
      toast.error(`复测失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBusy(false);
    }
  };

  if (!findingId) {
    return (
      <div className="py-16 text-center text-sm text-muted-foreground">
        缺少漏洞 ID 参数，
        <Link href="/function/findings" className="text-primary underline">
          返回漏洞与复审中心
        </Link>
      </div>
    );
  }

  if (loading && !finding) {
    return <div className="py-16 text-center text-sm text-muted-foreground">正在加载完整漏洞档案与版本历史…</div>;
  }

  if (!finding) {
    return <div className="py-16 text-center text-sm text-muted-foreground">未找到该漏洞记录或已被删除。</div>;
  }

  return (
    <div className="flex flex-1 flex-col gap-5">
      {/* Top Action Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="ghost" size="sm" className="h-7 px-2" asChild>
              <Link href="/function/findings">
                <ArrowLeft className="mr-1 size-3.5" /> 漏洞列表
              </Link>
            </Button>
            <StatusBadge domain="severity" value={severity} />
            <StatusBadge domain="finding" value={finding.review?.user_status || finding.review?.verdict || finding.status} dot />
            {finding.fusion_evidence?.tier_label ? (
              <Badge variant={finding.fusion_evidence.passed ? "outline" : "destructive"} className="text-xs">
                {finding.fusion_evidence.tier_label}
              </Badge>
            ) : null}
            {finding.edu_school ? <Badge variant="secondary">{finding.edu_school}</Badge> : null}
          </div>
          <h1 className="font-semibold text-xl tracking-tight">{editTitle || finding.title}</h1>
          <p className="font-mono text-xs text-muted-foreground break-all">{finding.target_url}</p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button size="sm" variant="default" onClick={() => setKillsweepOpen(true)}>
            <Zap className="mr-1.5 size-3.5 text-amber-300" /> 一键通杀（落盘新任务）
          </Button>
          <Button size="sm" variant="secondary" onClick={() => void riddleApi.downloadDocxReport(finding.id, editTitle || finding.title)}>
            <FileText className="mr-1.5 size-3.5" /> 导出公文 Word (.docx)
          </Button>
          <Button size="sm" variant="outline" onClick={() => void riddleApi.downloadFindingExport(finding.id, "md")}>
            Markdown
          </Button>
          <Button size="sm" variant="outline" onClick={() => void riddleApi.downloadFindingExport(finding.id, "html")}>
            HTML
          </Button>
          <Button size="sm" variant="outline" onClick={() => void riddleApi.downloadFindingExport(finding.id, "json")}>
            JSON
          </Button>
        </div>
      </div>

      {/* Main 2-Column Workspace */}
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        {/* Left 2/3: Report Editor, Evidence, Retest, Versions, AI Assistant */}
        <div className="lg:col-span-2">
          <Tabs defaultValue="report" className="space-y-4">
            <TabsList className="flex-wrap h-auto">
              <TabsTrigger value="report">报告正文与编辑</TabsTrigger>
              <TabsTrigger value="raw">原始报文与利用链</TabsTrigger>
              <TabsTrigger value="retest">复测闭环 ({retests.length})</TabsTrigger>
              <TabsTrigger value="versions">
                <History className="mr-1 size-3.5" /> 版本快照 ({versions.length})
              </TabsTrigger>
              <TabsTrigger value="assistant">
                <Bot className="mr-1 size-3.5" /> AI 报告助手
              </TabsTrigger>
            </TabsList>

            <TabsContent value="report" className="space-y-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between pb-3">
                  <div>
                    <CardTitle className="text-base">在线修订报告内容 (user_edits)</CardTitle>
                    <CardDescription className="text-xs">
                      修改后保存将自动生成新版本快照，并直接应用于 Word 公文与 Markdown 导出。
                    </CardDescription>
                  </div>
                  <Button size="sm" disabled={busy} onClick={() => void handleSaveReportEdits()}>
                    <Save className="mr-1.5 size-3.5" /> 保存修订
                  </Button>
                </CardHeader>
                <CardContent className="space-y-3.5">
                  <div className="space-y-1.5">
                    <Label className="text-xs">漏洞标题</Label>
                    <Input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">影响范围</Label>
                    <Input value={editScope} onChange={(e) => setEditScope(e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">漏洞原理与危害描述</Label>
                    <Textarea rows={5} value={editDesc} onChange={(e) => setEditDesc(e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">复现步骤（每行一步）</Label>
                    <Textarea rows={5} value={editSteps} onChange={(e) => setEditSteps(e.target.value)} />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">PoC 验证命令 / Payload</Label>
                    <Textarea
                      rows={5}
                      className="font-mono text-xs"
                      value={editPoc}
                      onChange={(e) => setEditPoc(e.target.value)}
                    />
                  </div>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="raw" className="space-y-4">
              {finding.kill_chain && finding.kill_chain.length > 0 ? (
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm">攻击利用链 (Kill Chain)</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-1.5 text-xs">
                    {finding.kill_chain.map((step, i) => (
                      <div key={i} className="rounded border bg-muted/20 px-3 py-2">
                        <span className="font-semibold">{step.method}</span>：{step.detail}
                      </div>
                    ))}
                  </CardContent>
                </Card>
              ) : null}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">原始 HTTP 请求</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="max-h-72 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap">
                    {finding.raw_request || "(无原始请求记录)"}
                  </pre>
                </CardContent>
              </Card>
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">原始 HTTP 响应证据</CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="max-h-72 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap">
                    {finding.raw_response || "(无原始响应记录)"}
                  </pre>
                </CardContent>
              </Card>
            </TabsContent>

            <TabsContent value="retest" className="space-y-4">
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-base">发起安全探活或手工登记复测</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                    <Input value={retestUrl} onChange={(e) => setRetestUrl(e.target.value)} placeholder="复测目标 URL" />
                    <Input value={retestMatch} onChange={(e) => setRetestMatch(e.target.value)} placeholder="响应断言关键词（可选）" />
                  </div>
                  <Input value={retestNotes} onChange={(e) => setRetestNotes(e.target.value)} placeholder="复测备注…" />
                  <div className="flex flex-wrap gap-2">
                    <Button size="sm" disabled={busy} onClick={() => void handleRetest("http_probe")}>
                      <ShieldCheck className="mr-1.5 size-3.5" /> HTTP 安全探活
                    </Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => void handleRetest("manual", "fixed")}>
                      <CheckCircle2 className="mr-1.5 size-3.5" /> 登记已修复
                    </Button>
                    <Button size="sm" variant="outline" disabled={busy} onClick={() => void handleRetest("manual", "reproduced")}>
                      登记仍可复现
                    </Button>
                  </div>
                </CardContent>
              </Card>
              <div className="space-y-2">
                {retests.map((r, i) => (
                  <Card key={i}>
                    <CardContent className="p-3 text-xs space-y-1">
                      <div className="flex items-center justify-between font-medium">
                        <span>[{String(r.mode ?? "manual")}] {String(r.status ?? "")}</span>
                        <span className="text-muted-foreground">{String(r.created_at ?? "")}</span>
                      </div>
                      {r.notes ? <p className="text-muted-foreground">{String(r.notes)}</p> : null}
                    </CardContent>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="versions" className="space-y-2.5">
              {versions.length === 0 ? (
                <Card>
                  <CardContent className="py-10 text-center text-xs text-muted-foreground">
                    暂无历史版本快照（编辑报告正文、调整等级或备注后将自动生成审计快照）。
                  </CardContent>
                </Card>
              ) : (
                versions.map((v) => (
                  <Card key={v.version}>
                    <CardContent className="flex flex-wrap items-center justify-between gap-3 p-3.5 text-xs">
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2 font-medium">
                          <Badge variant="outline">v{v.version}</Badge>
                          <span>{v.note || v.source}</span>
                        </div>
                        <div className="text-muted-foreground">
                          {v.created_at} · 标题：{String(v.snapshot?.title ?? "-")}
                        </div>
                      </div>
                      <Button size="sm" variant="outline" disabled={busy} onClick={() => void handleRestoreVersion(v.version)}>
                        <RotateCcw className="mr-1 size-3.5" /> 恢复此版本
                      </Button>
                    </CardContent>
                  </Card>
                ))
              )}
            </TabsContent>

            <TabsContent value="assistant" className="space-y-3">
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">AI 漏洞报告润色与答疑助手</CardTitle>
                  <CardDescription className="text-xs">
                    围绕当前漏洞追问原理细节、补全修复建议或生成面向 SRC 审核人员的清晰表述。
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="max-h-96 space-y-2.5 overflow-y-auto rounded-lg border bg-muted/20 p-3 text-xs">
                    {messages.length === 0 ? (
                      <p className="py-6 text-center text-muted-foreground">在下方输入问题开始与报告助手对话。</p>
                    ) : (
                      messages.map((m, idx) => (
                        <div
                          key={idx}
                          className={`rounded-lg p-2.5 whitespace-pre-wrap leading-relaxed ${
                            m.role === "user"
                              ? "ml-8 bg-primary text-primary-foreground"
                              : "mr-8 border bg-background"
                          }`}
                        >
                          {m.content}
                        </div>
                      ))
                    )}
                  </div>
                  <div className="flex gap-2">
                    <Input
                      placeholder="例如：帮我润色漏洞危害描述并补充针对性的代码级修复建议…"
                      value={assistantInput}
                      onChange={(e) => setAssistantInput(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && !e.shiftKey) void handleAskAssistant();
                      }}
                    />
                    <Button disabled={assistantBusy} onClick={() => void handleAskAssistant()}>
                      {assistantBusy ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Right 1/3: Review Decision & Deepen Sidebar */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">人工复审与闭环动作</CardTitle>
              <CardDescription className="text-xs">
                AI 评审：{finding.review?.verdict ?? "-"} ({finding.review?.score ?? 0} 分) · 复现：
                {finding.review?.reproduced ? "已复现" : "待核验"}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="space-y-1.5">
                <Label className="text-xs">核定危险等级</Label>
                <Select value={severity} onValueChange={setSeverity}>
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
              <div className="space-y-1.5">
                <Label className="text-xs">人工复审备注</Label>
                <Textarea rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="填写人工验证结论…" />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <Button size="sm" disabled={busy} onClick={() => void handleReviewDecision("passed")}>
                  <Check className="mr-1 size-3.5" /> 复审通过
                </Button>
                <Button size="sm" variant="destructive" disabled={busy} onClick={() => void handleReviewDecision("rejected")}>
                  <X className="mr-1 size-3.5" /> 驳回
                </Button>
              </div>
              <Button size="sm" variant="outline" className="w-full" disabled={busy} onClick={() => void handleToggleSubmitted()}>
                <Send className="mr-1.5 size-3.5" />
                {finding.review?.submitted ? "已提交 SRC（点击取消）" : "标记为已提交 SRC"}
              </Button>
              <Button
                size="sm"
                variant="secondary"
                className="w-full"
                disabled={busy}
                onClick={async () => {
                  await riddleApi.distillFindingToKb(finding.id);
                  toast.success("已手动蒸馏入知识库");
                }}
              >
                <BookOpen className="mr-1.5 size-3.5" /> 蒸馏入知识库
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-1.5 text-sm">
                <FlaskConical className="size-4 text-primary" /> 携带人工指令退回深挖
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              <Textarea
                rows={3}
                className="text-xs"
                placeholder="告诉 Worker 下一轮去打穿什么更高危害…"
                value={deepenDirective}
                onChange={(e) => setDeepenDirective(e.target.value)}
              />
              <Button size="sm" variant="outline" className="w-full" disabled={busy} onClick={() => void handleDeepen()}>
                发起定向深挖回炉
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>

      <KillsweepLaunchDialog
        findingId={finding.id}
        open={killsweepOpen}
        onOpenChange={setKillsweepOpen}
      />
    </div>
  );
}

export default function FindingDetailPage() {
  return (
    <React.Suspense fallback={<div className="p-8 text-center text-sm text-muted-foreground">正在加载漏洞档案…</div>}>
      <FindingDetailInner />
    </React.Suspense>
  );
}
