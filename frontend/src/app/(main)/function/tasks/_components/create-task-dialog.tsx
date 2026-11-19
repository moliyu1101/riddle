"use client";

import * as React from "react";
import Link from "next/link";
import {
  AlertTriangle,
  Building2,
  Check,
  CheckCircle2,
  ChevronRight,
  Crosshair,
  Flag,
  GraduationCap,
  KeyRound,
  Layers,
  ListChecks,
  Loader2,
  Plus,
  Radar,
  ShieldAlert,
  Sparkles,
  Target,
  Trash2,
  Wand2,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import {
  riddleApi,
  type AuthBindingInput,
  type ParseAuthBatchResult,
  type ParseForbiddenOpsResult,
  type ParseQueryResult,
  type ParseTargetsResult,
  type RiddleSettingsResponse,
  type RiddleTask,
} from "@/lib/riddle-api";
import { cn } from "@/lib/utils";

type SrcMode = "edusrc" | "enterprise";
type TargetSourceMode = "fofa" | "manual" | "both" | "site";
type SectionTab = "basic" | "strategy" | "governance";

interface EditableGoal {
  id: string;
  title: string;
  criteria: string;
  kind?: string;
  match?: string[];
}

interface CreateTaskDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCreated: (task: RiddleTask) => void | Promise<void>;
  editTask?: RiddleTask | null;
}

const VULN_DIRECTION_PRESETS = [
  "SQL注入",
  "RCE",
  "未授权访问",
  "文件上传",
  "任意文件读取",
  "逻辑越权",
  "信息泄露",
  "SSRF/XXE",
  "认证绕过/弱口令",
  "反序列化",
];

const GUARD_OP_DEFS = [
  { id: "db_dump", label: "脱库/拖库/删库", hint: "拦截 sqlmap --dump / DROP" },
  { id: "db_delete", label: "删除数据", hint: "拦截 DELETE / rm -rf" },
  { id: "db_write", label: "写入/篡改数据", hint: "拦截 INSERT / UPDATE" },
  { id: "cache_clear", label: "清缓存", hint: "拦截 FLUSHALL / 清缓存" },
  { id: "cred_change", label: "改密/重置凭证", hint: "拦截改密/重置口令" },
  { id: "brute_force", label: "爆破/暴力破解", hint: "拦截 hydra / 大字典" },
  { id: "dos", label: "压测/DoS/轰炸", hint: "拦截压测与短信轰炸" },
  { id: "webshell", label: "落 webshell/后门", hint: "拦截木马与计划任务持久化" },
];

const DEFAULT_GUARD_OPS = ["db_dump", "db_delete", "dos", "webshell"];

const ENGINES = [
  { id: "fofa", label: "FOFA" },
  { id: "quake", label: "Quake" },
  { id: "hunter", label: "Hunter" },
  { id: "zoomeye", label: "ZoomEye" },
  { id: "shodan", label: "Shodan" },
  { id: "censys", label: "Censys" },
];

const QUERY_TEMPLATES: Record<SrcMode, Array<{ label: string; query: string }>> = {
  edusrc: [
    { label: "高校统一身份认证", query: 'domain="edu.cn" && title="统一身份认证"' },
    { label: "高校教务/选课系统", query: 'domain="edu.cn" && (title="教务" || body="正方教务")' },
    { label: "高校 OA / 门户", query: 'domain="edu.cn" && (title="办公" || title="OA")' },
    { label: "高校 WebVPN / SSLVPN", query: 'domain="edu.cn" && (title="WebVPN" || title="VPN")' },
  ],
  enterprise: [
    { label: "Swagger / API 文档", query: 'title="Swagger UI" || body="/v2/api-docs"' },
    { label: "Spring Boot Actuator", query: 'body="actuator" && status_code="200"' },
    { label: "企业管理后台", query: 'title="管理后台" && status_code="200"' },
    { label: "泛微 / 致远 OA", query: 'app="泛微-协同办公OA" || app="致远互联-OA"' },
  ],
};

const SOURCE_OPTIONS: Array<{
  id: TargetSourceMode;
  title: string;
  desc: string;
  icon: React.ComponentType<{ className?: string }>;
}> = [
  { id: "fofa", title: "空间测绘", desc: "6 大引擎按语法自动拉取", icon: Radar },
  { id: "manual", title: "手动清单", desc: "粘贴域名 / IP / URL 列表", icon: ListChecks },
  { id: "both", title: "测绘 + 手动", desc: "双源合并去重同时入队", icon: Layers },
  { id: "site", title: "单站协作", desc: "多 Worker 协同深挖单站", icon: Crosshair },
];

export function CreateTaskDialog({ open, onOpenChange, onCreated, editTask }: CreateTaskDialogProps) {
  const isEdit = Boolean(editTask);
  const [activeTab, setActiveTab] = React.useState<SectionTab>("basic");
  const [settings, setSettings] = React.useState<RiddleSettingsResponse | null>(null);
  const [creating, setCreating] = React.useState(false);

  // Section 1: Basic & Asset Source
  const [name, setName] = React.useState("");
  const [srcType, setSrcType] = React.useState<SrcMode>("edusrc");
  const [targetSource, setTargetSource] = React.useState<TargetSourceMode>("fofa");
  const [engine, setEngine] = React.useState("fofa");
  const [fofaQuery, setFofaQuery] = React.useState("");
  const [maxPages, setMaxPages] = React.useState(20);
  const [pageSize, setPageSize] = React.useState(100);
  const [manualText, setManualText] = React.useState("");
  const [skipSiteRecon, setSkipSiteRecon] = React.useState(false);

  // Live parser states
  const [queryParsed, setQueryParsed] = React.useState<ParseQueryResult | null>(null);
  const [queryParsing, setQueryParsing] = React.useState(false);
  const [targetsParsed, setTargetsParsed] = React.useState<ParseTargetsResult | null>(null);
  const [targetsParsing, setTargetsParsing] = React.useState(false);

  // Section 2: Strategy & Auth
  const [selectedVulns, setSelectedVulns] = React.useState<string[]>([]);
  const [authText, setAuthText] = React.useState("");
  const [authParsed, setAuthParsed] = React.useState<ParseAuthBatchResult | null>(null);
  const [authParsing, setAuthParsing] = React.useState(false);
  const [concurrency, setConcurrency] = React.useState(3);
  const [deepenCap, setDeepenCap] = React.useState(2);

  // Section 3: Guards & Fusion Goals
  const [guardOps, setGuardOps] = React.useState<string[]>(DEFAULT_GUARD_OPS);
  const [srcRules, setSrcRules] = React.useState("");
  const [rulesForbidden, setRulesForbidden] = React.useState<ParseForbiddenOpsResult | null>(null);
  const [autoGoals, setAutoGoals] = React.useState(true);
  const [previewGoals, setPreviewGoals] = React.useState<EditableGoal[]>([]);
  const [suggestingGoals, setSuggestingGoals] = React.useState(false);

  // Footer launch option
  const [startImmediately, setStartImmediately] = React.useState(false);

  // Load global defaults & engine availability (or prefill when editing)
  React.useEffect(() => {
    if (!open) return;
    let alive = true;
    riddleApi
      .getSettings()
      .then((s) => {
        if (!alive) return;
        setSettings(s);
        if (!editTask) {
          if (s.defaults?.engine) setEngine(s.defaults.engine);
          if (s.defaults?.concurrency) setConcurrency(s.defaults.concurrency);
          if (typeof s.defaults?.deepen_cap === "number") setDeepenCap(s.defaults.deepen_cap);
          if (s.fofa?.max_pages) setMaxPages(s.fofa.max_pages);
          if (s.fofa?.page_size) setPageSize(s.fofa.page_size);
        }
      })
      .catch(() => {
        // fallback silently to defaults
      });

    if (editTask) {
      setActiveTab("basic");
      setName(editTask.name || "");
      setSrcType(editTask.src_type === "enterprise" ? "enterprise" : "edusrc");
      const ts = editTask.target_source;
      setTargetSource(ts === "manual" || ts === "both" || ts === "site" ? ts : "fofa");
      setEngine(editTask.engine || "fofa");
      setFofaQuery(editTask.fofa_query || "");
      const fc = (editTask.fofa_config || {}) as Record<string, unknown>;
      if (typeof fc.max_pages === "number") setMaxPages(fc.max_pages);
      if (typeof fc.page_size === "number") setPageSize(fc.page_size);
      setSkipSiteRecon(Boolean(fc.skip_site_recon));
      setManualText((editTask.manual_targets || []).join("\n"));
      setSelectedVulns(editTask.vuln_types || []);
      setGuardOps(editTask.guard_ops || []);
      setSrcRules(editTask.src_rules || "");
      setConcurrency(editTask.concurrency || 3);
      setDeepenCap(typeof editTask.deepen_cap === "number" ? editTask.deepen_cap : 2);
      setAuthText("");
      setAuthParsed(null);
      setAutoGoals(false);
      riddleApi
        .getGoals(editTask.id)
        .then((res) => {
          if (!alive) return;
          const list: EditableGoal[] = (res.goals ?? []).map((g, idx) => ({
            id: String(g.id ?? g.goal_key ?? `g_${idx + 1}`),
            title: String(g.title ?? ""),
            criteria: String(g.criteria ?? ""),
            kind: typeof g.kind === "string" ? g.kind : "finding",
            match: Array.isArray(g.match) ? (g.match as string[]) : [],
          }));
          setPreviewGoals(list);
          if (list.length > 0) setAutoGoals(true);
        })
        .catch(() => setPreviewGoals([]));
    }
    return () => {
      alive = false;
    };
  }, [open, editTask]);

  // Debounced live parse-query
  React.useEffect(() => {
    if (!open || (targetSource !== "fofa" && targetSource !== "both")) return;
    const trimmed = fofaQuery.trim();
    if (!trimmed) {
      setQueryParsed(null);
      return;
    }
    const timer = setTimeout(() => {
      setQueryParsing(true);
      riddleApi
        .parseQuery(engine, trimmed, srcType)
        .then(setQueryParsed)
        .catch(() => setQueryParsed(null))
        .finally(() => setQueryParsing(false));
    }, 420);
    return () => clearTimeout(timer);
  }, [open, targetSource, engine, fofaQuery, srcType]);

  // Debounced live parse-targets
  React.useEffect(() => {
    if (!open || targetSource === "fofa") return;
    const trimmed = manualText.trim();
    if (!trimmed) {
      setTargetsParsed(null);
      return;
    }
    const timer = setTimeout(() => {
      setTargetsParsing(true);
      riddleApi
        .parseTargets(trimmed)
        .then(setTargetsParsed)
        .catch(() => setTargetsParsed(null))
        .finally(() => setTargetsParsing(false));
    }, 420);
    return () => clearTimeout(timer);
  }, [open, targetSource, manualText]);

  // Debounced live parse-auth-batch
  React.useEffect(() => {
    if (!open) return;
    const trimmed = authText.trim();
    if (!trimmed) {
      setAuthParsed(null);
      return;
    }
    const timer = setTimeout(() => {
      setAuthParsing(true);
      riddleApi
        .parseAuthBatch(trimmed)
        .then(setAuthParsed)
        .catch(() => setAuthParsed(null))
        .finally(() => setAuthParsing(false));
    }, 450);
    return () => clearTimeout(timer);
  }, [open, authText]);

  // Debounced live parse-forbidden-ops
  React.useEffect(() => {
    if (!open) return;
    const trimmed = srcRules.trim();
    if (!trimmed) {
      setRulesForbidden(null);
      return;
    }
    const timer = setTimeout(() => {
      riddleApi
        .parseForbiddenOps(trimmed)
        .then(setRulesForbidden)
        .catch(() => setRulesForbidden(null));
    }, 450);
    return () => clearTimeout(timer);
  }, [open, srcRules]);

  const ruleDetectedIds = React.useMemo(
    () => new Set((rulesForbidden?.forbidden ?? []).map((item) => item.id)),
    [rulesForbidden],
  );

  const effectiveGuardCount = React.useMemo(() => {
    const merged = new Set([...guardOps, ...ruleDetectedIds]);
    return merged.size;
  }, [guardOps, ruleDetectedIds]);

  const manualLines = React.useMemo(
    () =>
      manualText
        .split(/\r?\n/)
        .map((s) => s.trim())
        .filter(Boolean),
    [manualText],
  );

  const basicReady = React.useMemo(() => {
    if (!name.trim()) return false;
    if (targetSource === "fofa") return Boolean(fofaQuery.trim());
    if (targetSource === "manual" || targetSource === "site") return manualLines.length > 0;
    return Boolean(fofaQuery.trim()) || manualLines.length > 0;
  }, [name, targetSource, fofaQuery, manualLines.length]);

  const selectedEngineConfigured = Boolean(settings?.engines?.[engine]?.key_set);

  const handleAutoName = () => {
    const d = new Date();
    const mm = String(d.getMonth() + 1).padStart(2, "0");
    const dd = String(d.getDate()).padStart(2, "0");
    const srcLabel = srcType === "edusrc" ? "EduSRC" : "企业SRC";
    const modeLabel =
      targetSource === "fofa"
        ? engine.toUpperCase()
        : targetSource === "manual"
          ? "手动清单"
          : targetSource === "both"
            ? `${engine.toUpperCase()}+手动`
            : "单站协作";
    setName(`${srcLabel}-${modeLabel}-${mm}${dd}`);
  };

  const handlePreviewGoals = async () => {
    setSuggestingGoals(true);
    try {
      const res = await riddleApi.suggestGoals({
        name: name.trim() || (srcType === "edusrc" ? "高校专项挖掘" : "企业授权渗透"),
        src_type: srcType,
        vuln_types: selectedVulns,
        targets: manualLines,
        fofa_query: fofaQuery.trim(),
      });
      const list: EditableGoal[] = (res.goals ?? []).map((g, idx) => ({
        id: String(g.id ?? g.goal_key ?? `g_${idx + 1}`),
        title: String(g.title ?? ""),
        criteria: String(g.criteria ?? ""),
        kind: typeof g.kind === "string" ? g.kind : "finding",
        match: Array.isArray(g.match) ? (g.match as string[]) : [],
      }));
      setPreviewGoals(list);
      setAutoGoals(true);
      toast.success(`已智能拆解 ${list.length} 条可核验验收目标`);
    } catch (err) {
      toast.error(`目标拆解失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSuggestingGoals(false);
    }
  };

  const resetForm = () => {
    setActiveTab("basic");
    setName("");
    setFofaQuery("");
    setManualText("");
    setSkipSiteRecon(false);
    setSelectedVulns([]);
    setAuthText("");
    setAuthParsed(null);
    setGuardOps(DEFAULT_GUARD_OPS);
    setSrcRules("");
    setRulesForbidden(null);
    setPreviewGoals([]);
    setQueryParsed(null);
    setTargetsParsed(null);
    setStartImmediately(false);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) {
      setActiveTab("basic");
      toast.error("请输入任务名称");
      return;
    }
    if ((targetSource === "manual" || targetSource === "site") && manualLines.length === 0) {
      setActiveTab("basic");
      toast.error(targetSource === "site" ? "请输入单站目标 URL" : "请至少输入一条手动目标");
      return;
    }
    if (targetSource === "fofa" && !fofaQuery.trim()) {
      setActiveTab("basic");
      toast.error("空间测绘模式请输入查询语法");
      return;
    }
    if (targetSource === "both" && !fofaQuery.trim() && manualLines.length === 0) {
      setActiveTab("basic");
      toast.error("测绘 + 手动模式请至少填写测绘语法或手动目标之一");
      return;
    }

    setCreating(true);
    try {
      let authBindings: AuthBindingInput[] = authParsed?.bindings ?? [];
      if (authText.trim() && authBindings.length === 0) {
        try {
          const parsed = await riddleApi.parseAuthBatch(authText.trim());
          authBindings = parsed.bindings ?? [];
        } catch {
          // ignore if backend fails to parse
        }
      }

      const payload = {
        name: name.trim(),
        src_type: srcType,
        vuln_types: selectedVulns,
        src_rules: srcRules.trim(),
        guard_ops: guardOps,
        target_source: targetSource,
        engine: targetSource === "fofa" || targetSource === "both" ? engine : "",
        fofa_query: targetSource === "fofa" || targetSource === "both" ? fofaQuery.trim() : "",
        manual_targets: targetSource === "fofa" ? [] : manualLines,
        ...(authBindings.length > 0 || !isEdit ? { auth_bindings: authBindings } : {}),
        fofa_config: {
          max_pages: maxPages,
          page_size: pageSize,
          skip_site_recon: targetSource === "site" ? skipSiteRecon : false,
        },
        concurrency,
        deepen_cap: deepenCap,
      };

      const saved =
        isEdit && editTask
          ? await riddleApi.updateTask(editTask.id, payload)
          : await riddleApi.createTask(payload);

      if (autoGoals) {
        try {
          if (previewGoals.length > 0) {
            const validGoals = previewGoals.filter((g) => g.title.trim() && g.criteria.trim());
            if (validGoals.length > 0) {
              await riddleApi.saveGoals(
                saved.id,
                validGoals.map((g) => ({ ...g })),
              );
            }
          } else if (!isEdit) {
            const suggested = await riddleApi.suggestGoals({
              task_id: saved.id,
              name: saved.name,
              src_type: saved.src_type,
              vuln_types: selectedVulns,
              targets: manualLines,
              fofa_query: fofaQuery.trim(),
            });
            if (suggested.goals?.length) {
              await riddleApi.saveGoals(saved.id, suggested.goals);
            }
          }
        } catch {
          // Goal gate save is non-fatal
        }
      }

      if (!isEdit && startImmediately) {
        await riddleApi.startTask(saved.id);
      }

      toast.success(
        isEdit
          ? `任务「${saved.name}」配置已更新`
          : startImmediately
            ? `任务「${saved.name}」已创建并立即启动`
            : `任务「${saved.name}」创建成功`,
      );
      if (!isEdit) resetForm();
      onOpenChange(false);
      await onCreated(saved);
    } catch (err) {
      toast.error(`${isEdit ? "保存" : "创建"}任务失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setCreating(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[90vh] w-[95vw] max-w-4xl flex-col gap-0 overflow-hidden p-0 sm:max-w-4xl">
        {/* Fixed Top Header + Section Switcher */}
        <div className="shrink-0 border-b bg-muted/25 px-6 pt-5 pb-4">
          <DialogHeader className="space-y-1">
            <div className="flex items-center gap-2.5">
              <div className="flex size-8 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <Target className="size-4" />
              </div>
              <div>
                <DialogTitle className="text-lg">
                  {isEdit ? `编辑任务 — ${editTask?.name}` : "新建知蠹自主挖掘任务"}
                </DialogTitle>
                <DialogDescription className="text-xs">
                  {isEdit
                    ? "修改测绘语法将自动重置翻页进度重新探测；凭据留空则保留原绑定。"
                    : "配置 SRC 模式、资产来源、测试凭据与执行护栏；各分页可随时自由切换。"}
                </DialogDescription>
              </div>
            </div>
          </DialogHeader>

          <div className="mt-4 grid grid-cols-3 gap-2">
            {[
              {
                id: "basic" as const,
                step: "01",
                label: "基础与资产",
                badge: basicReady ? "已就绪" : "必填",
                badgeTone: basicReady ? "default" : "secondary",
              },
              {
                id: "strategy" as const,
                step: "02",
                label: "凭据与策略",
                badge:
                  (authParsed?.parsed ?? 0) > 0
                    ? `${authParsed?.parsed} 凭据`
                    : selectedVulns.length > 0
                      ? `${selectedVulns.length} 方向`
                      : "可选",
                badgeTone: (authParsed?.parsed ?? 0) > 0 || selectedVulns.length > 0 ? "default" : "outline",
              },
              {
                id: "governance" as const,
                step: "03",
                label: "护栏与目标",
                badge: `${effectiveGuardCount} 护栏`,
                badgeTone: effectiveGuardCount > 0 ? "default" : "outline",
              },
            ].map((tab) => {
              const active = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setActiveTab(tab.id)}
                  className={cn(
                    "flex items-center justify-between gap-2 rounded-lg border px-3 py-2 text-left transition-all",
                    active
                      ? "border-primary bg-background shadow-xs"
                      : "border-transparent bg-muted/50 text-muted-foreground hover:bg-muted/80 hover:text-foreground",
                  )}
                >
                  <div className="flex min-w-0 items-center gap-2">
                    <span
                      className={cn(
                        "flex size-5 shrink-0 items-center justify-center rounded text-[11px] font-mono font-semibold",
                        active ? "bg-primary text-primary-foreground" : "bg-background/80 text-muted-foreground",
                      )}
                    >
                      {tab.step}
                    </span>
                    <span className="truncate font-medium text-xs sm:text-sm">{tab.label}</span>
                  </div>
                  <Badge
                    variant={tab.badgeTone as "default" | "secondary" | "outline"}
                    className="hidden shrink-0 text-[10px] sm:inline-flex"
                  >
                    {tab.badge}
                  </Badge>
                </button>
              );
            })}
          </div>
        </div>

        {/* Scrollable Body */}
        <form id="riddle-create-task-form" onSubmit={(e) => void handleSubmit(e)} className="flex min-h-0 flex-1 flex-col">
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">
            {/* TAB 1: BASIC & ASSET SOURCE */}
            {activeTab === "basic" ? (
              <div className="space-y-5">
                {/* Task Name */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="riddle-task-name" className="text-xs font-medium">
                      任务名称 <span className="text-destructive">*</span>
                    </Label>
                    <Button
                      type="button"
                      variant="ghost"
                      size="sm"
                      className="h-6 px-2 text-xs text-muted-foreground"
                      onClick={handleAutoName}
                    >
                      <Wand2 className="mr-1 size-3" /> 按模式自动命名
                    </Button>
                  </div>
                  <Input
                    id="riddle-task-name"
                    placeholder="例如：华东高校 11 月 EduSRC 统一认证专项"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                    className="h-10"
                  />
                </div>

                {/* SRC Mode Cards */}
                <div className="space-y-2">
                  <Label className="text-xs font-medium">SRC 规则与评分模式</Label>
                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                    {[
                      {
                        id: "edusrc" as const,
                        title: "EduSRC (高校 / 公益 SRC)",
                        desc: "启用高校 IP 归属识别、教育网通杀扩面优先与公益合规标准",
                        icon: GraduationCap,
                      },
                      {
                        id: "enterprise" as const,
                        title: "企业 SRC / 授权项目",
                        desc: "启用企业边界校验、高危业务链深挖与公文级 Word 交付报告",
                        icon: Building2,
                      },
                    ].map((opt) => {
                      const active = srcType === opt.id;
                      const Icon = opt.icon;
                      return (
                        <button
                          key={opt.id}
                          type="button"
                          onClick={() => setSrcType(opt.id)}
                          className={cn(
                            "relative flex items-start gap-3 rounded-xl border p-3.5 text-left transition-all",
                            active
                              ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                              : "border-border hover:border-foreground/30 hover:bg-muted/30",
                          )}
                        >
                          <div
                            className={cn(
                              "mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-lg",
                              active ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground",
                            )}
                          >
                            <Icon className="size-4" />
                          </div>
                          <div className="min-w-0 flex-1 pr-5">
                            <div className="font-medium text-sm">{opt.title}</div>
                            <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{opt.desc}</p>
                          </div>
                          {active ? (
                            <span className="absolute top-3 right-3 flex size-5 items-center justify-center rounded-full bg-primary text-primary-foreground">
                              <Check className="size-3" />
                            </span>
                          ) : null}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Target Source 4-Card Selector */}
                <div className="space-y-2">
                  <Label className="text-xs font-medium">资产发现与入队方式</Label>
                  <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-4">
                    {SOURCE_OPTIONS.map((opt) => {
                      const active = targetSource === opt.id;
                      const Icon = opt.icon;
                      return (
                        <button
                          key={opt.id}
                          type="button"
                          onClick={() => setTargetSource(opt.id)}
                          className={cn(
                            "flex flex-col gap-1.5 rounded-xl border p-3 text-left transition-all",
                            active
                              ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                              : "border-border hover:border-foreground/30 hover:bg-muted/30",
                          )}
                        >
                          <div className="flex items-center justify-between">
                            <Icon className={cn("size-4", active ? "text-primary" : "text-muted-foreground")} />
                            {active ? <span className="size-2 rounded-full bg-primary" /> : null}
                          </div>
                          <div className="font-medium text-xs sm:text-sm">{opt.title}</div>
                          <div className="text-[11px] leading-snug text-muted-foreground">{opt.desc}</div>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Mapping Engine Section (fofa / both) */}
                {(targetSource === "fofa" || targetSource === "both") && (
                  <div className="space-y-3.5 rounded-xl border bg-muted/15 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <Label className="text-xs font-medium">空间测绘引擎</Label>
                      {!selectedEngineConfigured && settings ? (
                        <Link
                          href="/system/settings"
                          className="inline-flex items-center gap-1 text-xs text-amber-600 hover:underline dark:text-amber-400"
                        >
                          <AlertTriangle className="size-3.5" />
                          当前引擎尚未配置 API Key，前往设置
                        </Link>
                      ) : null}
                    </div>

                    <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
                      {ENGINES.map((eng) => {
                        const active = engine === eng.id;
                        const keySet = Boolean(settings?.engines?.[eng.id]?.key_set);
                        return (
                          <button
                            key={eng.id}
                            type="button"
                            onClick={() => setEngine(eng.id)}
                            className={cn(
                              "flex items-center justify-between gap-1.5 rounded-lg border px-2.5 py-2 text-xs font-medium transition-all",
                              active
                                ? "border-primary bg-primary text-primary-foreground shadow-xs"
                                : "border-border bg-background hover:bg-muted/50",
                            )}
                          >
                            <span className="truncate">{eng.label}</span>
                            <span
                              title={keySet ? "已配置 API Key" : "未配置 API Key"}
                              className={cn(
                                "size-2 shrink-0 rounded-full",
                                keySet
                                  ? active
                                    ? "bg-emerald-300"
                                    : "bg-emerald-500"
                                  : active
                                    ? "bg-primary-foreground/35"
                                    : "bg-muted-foreground/30",
                              )}
                            />
                          </button>
                        );
                      })}
                    </div>

                    {/* Quick Syntax Presets */}
                    <div className="space-y-1.5">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-[11px] text-muted-foreground">常用语句模板：</span>
                        {QUERY_TEMPLATES[srcType].map((tpl) => (
                          <button
                            key={tpl.label}
                            type="button"
                            onClick={() => setFofaQuery(tpl.query)}
                            className="rounded-md border bg-background px-2 py-0.5 text-[11px] text-muted-foreground transition-colors hover:border-primary/40 hover:text-foreground"
                          >
                            {tpl.label}
                          </button>
                        ))}
                      </div>
                      <Input
                        className="h-10 bg-background font-mono text-xs"
                        placeholder={
                          srcType === "edusrc"
                            ? 'domain="edu.cn" && title="统一身份认证"'
                            : 'domain="example.com" && status_code="200"'
                        }
                        value={fofaQuery}
                        onChange={(e) => setFofaQuery(e.target.value)}
                      />
                    </div>

                    {/* Live Query Analysis Bar */}
                    {queryParsing ? (
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <Loader2 className="size-3.5 animate-spin" /> 正在校验 {engine.toUpperCase()} 查询语法…
                      </div>
                    ) : queryParsed ? (
                      <div
                        className={cn(
                          "rounded-lg border px-3 py-2 text-xs space-y-1",
                          queryParsed.syntax_mismatch || queryParsed.issues?.length
                            ? "border-amber-500/40 bg-amber-500/10 text-amber-800 dark:text-amber-300"
                            : "border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-300",
                        )}
                      >
                        <div className="flex flex-wrap items-center gap-2 font-medium">
                          {queryParsed.syntax_mismatch || queryParsed.issues?.length ? (
                            <AlertTriangle className="size-3.5 shrink-0" />
                          ) : (
                            <CheckCircle2 className="size-3.5 shrink-0" />
                          )}
                          <span>
                            {queryParsed.syntax_mismatch || queryParsed.issues?.[0] || queryParsed.summary || "查询语法校验通过"}
                          </span>
                        </div>
                        {queryParsed.fields?.length > 0 ? (
                          <div className="flex flex-wrap items-center gap-1 pt-0.5">
                            <span className="opacity-75">命中字段：</span>
                            {queryParsed.fields.map((f) => (
                              <Badge key={f} variant="outline" className="h-4 px-1.5 font-mono text-[10px]">
                                {f}
                              </Badge>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    ) : null}

                    {/* Compact Pagination Tuning */}
                    <div className="grid grid-cols-2 gap-3 pt-1">
                      <div className="space-y-1">
                        <Label className="text-[11px] text-muted-foreground">最大拉取页数 (max_pages)</Label>
                        <Input
                          type="number"
                          min={1}
                          max={200}
                          value={maxPages}
                          onChange={(e) => setMaxPages(Math.max(1, Number(e.target.value) || 20))}
                          className="h-8 bg-background text-xs"
                        />
                      </div>
                      <div className="space-y-1">
                        <Label className="text-[11px] text-muted-foreground">每页资产数 (page_size)</Label>
                        <Input
                          type="number"
                          min={10}
                          max={1000}
                          value={pageSize}
                          onChange={(e) => setPageSize(Math.max(10, Number(e.target.value) || 100))}
                          className="h-8 bg-background text-xs"
                        />
                      </div>
                    </div>
                  </div>
                )}

                {/* Manual / Site Targets Section */}
                {targetSource !== "fofa" && (
                  <div className="space-y-3 rounded-xl border bg-muted/15 p-4">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="riddle-manual-targets" className="text-xs font-medium">
                        {targetSource === "site"
                          ? "单站目标入口 URL（支持附带备选子路径）"
                          : "手动目标列表（每行一条，支持 URL / 域名 / IP 与 # 备注）"}
                      </Label>
                      {manualLines.length > 0 ? (
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          className="h-6 px-2 text-xs text-muted-foreground"
                          onClick={() => setManualText("")}
                        >
                          清空
                        </Button>
                      ) : null}
                    </div>
                    <Textarea
                      id="riddle-manual-targets"
                      rows={targetSource === "site" ? 2 : 5}
                      className="bg-background font-mono text-xs leading-relaxed"
                      placeholder={
                        targetSource === "site"
                          ? "https://portal.target.edu.cn"
                          : "https://portal.example.edu.cn # 门户入口\n10.10.2.8:8080\nauth.example.com"
                      }
                      value={manualText}
                      onChange={(e) => setManualText(e.target.value)}
                    />

                    {/* Real-time Target Parse Badges */}
                    {targetsParsing ? (
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <Loader2 className="size-3.5 animate-spin" /> 正在解析目标清单…
                      </div>
                    ) : targetsParsed ? (
                      <div className="flex flex-wrap items-center gap-2 text-xs">
                        <Badge variant="default" className="font-normal">
                          有效目标 {targetsParsed.valid} 条
                        </Badge>
                        <Badge variant="outline" className="font-normal">
                          域名 {targetsParsed.domains}
                        </Badge>
                        <Badge variant="outline" className="font-normal">
                          IP {targetsParsed.ips}
                        </Badge>
                        {targetsParsed.with_note > 0 ? (
                          <Badge variant="secondary" className="font-normal">
                            含备注 {targetsParsed.with_note}
                          </Badge>
                        ) : null}
                        {targetsParsed.ignored_total > 0 ? (
                          <Badge variant="destructive" className="font-normal">
                            忽略无效行 {targetsParsed.ignored_total}
                          </Badge>
                        ) : null}
                      </div>
                    ) : null}

                    {/* Site Mode Option: skip_site_recon */}
                    {targetSource === "site" ? (
                      <div className="flex items-center justify-between gap-3 rounded-lg border bg-background px-3.5 py-2.5">
                        <div className="space-y-0.5">
                          <div className="font-medium text-xs">跳过单站入口盘点侦察 (skip_site_recon)</div>
                          <div className="text-[11px] text-muted-foreground">
                            若已明确入口或仅需快速验证，可跳过 site_map 盘点以节省 LLM Token。
                          </div>
                        </div>
                        <Switch checked={skipSiteRecon} onCheckedChange={setSkipSiteRecon} />
                      </div>
                    ) : null}
                  </div>
                )}
              </div>
            ) : null}

            {/* TAB 2: CREDENTIALS & ATTACK STRATEGY */}
            {activeTab === "strategy" ? (
              <div className="space-y-5">
                {/* Vulnerability Directions */}
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-xs font-medium">重点关注漏洞方向</Label>
                      <p className="text-[11px] text-muted-foreground">留空表示全面挖掘；勾选后 Worker 会优先投放对应测试向量。</p>
                    </div>
                    <div className="flex gap-1.5">
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={() => setSelectedVulns([...VULN_DIRECTION_PRESETS])}
                      >
                        全选
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={() => setSelectedVulns([])}
                      >
                        清空
                      </Button>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {VULN_DIRECTION_PRESETS.map((v) => {
                      const active = selectedVulns.includes(v);
                      return (
                        <button
                          key={v}
                          type="button"
                          onClick={() =>
                            setSelectedVulns((prev) => (prev.includes(v) ? prev.filter((x) => x !== v) : [...prev, v]))
                          }
                          className={cn(
                            "inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-all",
                            active
                              ? "border-primary bg-primary text-primary-foreground"
                              : "border-border bg-background hover:border-foreground/30 hover:bg-muted/40",
                          )}
                        >
                          {active ? <Check className="size-3" /> : null}
                          {v}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Auth Bindings Batch Import */}
                <div className="space-y-3 rounded-xl border bg-muted/15 p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <KeyRound className="size-4 text-primary" />
                      <div>
                        <Label htmlFor="riddle-auth-batch" className="text-xs font-medium">
                          登录态 / 测试账号凭据绑定（可选）
                        </Label>
                        <p className="text-[11px] text-muted-foreground">
                          每行一条，支持 <span className="font-mono">URL user:pass</span>、<span className="font-mono">URL Cookie: ...</span>、<span className="font-mono">* Authorization: Bearer ...</span>
                        </p>
                      </div>
                    </div>
                    {authText.trim() ? (
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-6 px-2 text-xs"
                        onClick={() => setAuthText("")}
                      >
                        清空
                      </Button>
                    ) : null}
                  </div>
                  <Textarea
                    id="riddle-auth-batch"
                    rows={4}
                    className="bg-background font-mono text-xs leading-relaxed"
                    placeholder={
                      "https://portal.example.edu.cn Cookie: JSESSIONID=xxxx\nhttps://api.example.com Authorization: Bearer eyJhbGci...\n* testuser:Test@123456"
                    }
                    value={authText}
                    onChange={(e) => setAuthText(e.target.value)}
                  />
                  {authParsing ? (
                    <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <Loader2 className="size-3.5 animate-spin" /> 正在识别登录凭据…
                    </div>
                  ) : authParsed ? (
                    <div className="flex flex-wrap items-center gap-2 text-xs">
                      <Badge variant="default" className="font-normal">
                        已绑定 {authParsed.parsed} 条有效凭据
                      </Badge>
                      {Object.entries(authParsed.by_kind ?? {}).map(([kind, cnt]) => (
                        <Badge key={kind} variant="outline" className="font-normal">
                          {kind}: {cnt}
                        </Badge>
                      ))}
                      {authParsed.ignored_total > 0 ? (
                        <Badge variant="destructive" className="font-normal">
                          忽略 {authParsed.ignored_total} 行
                        </Badge>
                      ) : null}
                    </div>
                  ) : null}
                </div>

                {/* Concurrency & Deepen Cap */}
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                  <div className="space-y-2.5 rounded-xl border p-4">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="riddle-concurrency" className="text-xs font-medium">
                        Worker 并发数
                      </Label>
                      <div className="flex gap-1">
                        {[1, 3, 5, 8].map((n) => (
                          <button
                            key={n}
                            type="button"
                            onClick={() => setConcurrency(n)}
                            className={cn(
                              "rounded border px-2 py-0.5 text-[11px] font-mono transition-colors",
                              concurrency === n
                                ? "border-primary bg-primary text-primary-foreground"
                                : "border-border hover:bg-muted",
                            )}
                          >
                            {n}
                          </button>
                        ))}
                      </div>
                    </div>
                    <Input
                      id="riddle-concurrency"
                      type="number"
                      min={1}
                      max={20}
                      value={concurrency}
                      onChange={(e) => setConcurrency(Math.max(1, Math.min(20, Number(e.target.value) || 1)))}
                    />
                    <p className="text-[11px] text-muted-foreground">同时运行的自主挖掘 Worker 数量（范围 1–20）。</p>
                  </div>

                  <div className="space-y-2.5 rounded-xl border p-4">
                    <div className="flex items-center justify-between">
                      <Label htmlFor="riddle-deepen-cap" className="text-xs font-medium">
                        单漏洞深挖最大轮次
                      </Label>
                      <div className="flex gap-1">
                        {[0, 2, 4, 6].map((n) => (
                          <button
                            key={n}
                            type="button"
                            onClick={() => setDeepenCap(n)}
                            className={cn(
                              "rounded border px-2 py-0.5 text-[11px] font-mono transition-colors",
                              deepenCap === n
                                ? "border-primary bg-primary text-primary-foreground"
                                : "border-border hover:bg-muted",
                            )}
                          >
                            {n}
                          </button>
                        ))}
                      </div>
                    </div>
                    <Input
                      id="riddle-deepen-cap"
                      type="number"
                      min={0}
                      max={10}
                      value={deepenCap}
                      onChange={(e) => setDeepenCap(Math.max(0, Math.min(10, Number(e.target.value) || 0)))}
                    />
                    <p className="text-[11px] text-muted-foreground">
                      AI 审核打回或人工定向指令退回继续深挖的上限轮次（0 = 关闭自动深挖）。
                    </p>
                  </div>
                </div>
              </div>
            ) : null}

            {/* TAB 3: GUARDS & FUSION GOALS */}
            {activeTab === "governance" ? (
              <div className="space-y-5">
                {/* 8 Guard Ops Grid */}
                <div className="space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="size-4 text-amber-500" />
                      <div>
                        <Label className="text-xs font-medium">任务级八大高危操作硬拦截</Label>
                        <p className="text-[11px] text-muted-foreground">
                          勾什么拦什么，命中后执行器直接拦截拒绝，避免影响生产业务。
                        </p>
                      </div>
                    </div>
                    <div className="flex gap-1.5">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={() => setGuardOps([...DEFAULT_GUARD_OPS])}
                      >
                        推荐默认
                      </Button>
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={() => setGuardOps(GUARD_OP_DEFS.map((o) => o.id))}
                      >
                        全选最严
                      </Button>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={() => setGuardOps([])}
                      >
                        全部放行
                      </Button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                    {GUARD_OP_DEFS.map((op) => {
                      const checked = guardOps.includes(op.id);
                      const fromRule = ruleDetectedIds.has(op.id);
                      const active = checked || fromRule;
                      return (
                        <button
                          key={op.id}
                          type="button"
                          onClick={() =>
                            setGuardOps((prev) =>
                              prev.includes(op.id) ? prev.filter((x) => x !== op.id) : [...prev, op.id],
                            )
                          }
                          className={cn(
                            "flex flex-col gap-1 rounded-lg border p-2.5 text-left transition-all",
                            active
                              ? "border-amber-500/60 bg-amber-500/10"
                              : "border-border bg-background hover:bg-muted/40",
                          )}
                        >
                          <div className="flex items-center justify-between gap-1">
                            <span className="font-medium text-xs">{op.label}</span>
                            {fromRule ? (
                              <Badge variant="outline" className="h-4 px-1 text-[10px] border-amber-500/50 text-amber-700 dark:text-amber-300">
                                规则命中
                              </Badge>
                            ) : checked ? (
                              <Check className="size-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
                            ) : null}
                          </div>
                          <span className="text-[11px] leading-tight text-muted-foreground">{op.hint}</span>
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Additional SRC Rules with live forbidden-ops detection */}
                <div className="space-y-2">
                  <Label htmlFor="riddle-src-rules" className="text-xs font-medium">
                    附加 SRC 范围规则与禁止事项（支持自然语言自动联动硬拦截）
                  </Label>
                  <Textarea
                    id="riddle-src-rules"
                    rows={3}
                    placeholder="例如：严禁脱库或对登录接口暴力破解；不收弱口令与低危信息泄露，优先挖掘统一认证与教务系统漏洞"
                    value={srcRules}
                    onChange={(e) => setSrcRules(e.target.value)}
                  />
                  {rulesForbidden && rulesForbidden.count > 0 ? (
                    <div className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-800 dark:text-amber-300">
                      <ShieldAlert className="size-3.5 shrink-0" />
                      <span>已从规则文本自动解析执行层硬拦截：{rulesForbidden.labels}</span>
                    </div>
                  ) : null}
                </div>

                {/* Fusion Goal Gate Preview & Customization */}
                <div className="space-y-3 rounded-xl border bg-muted/15 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <Flag className="size-4 text-primary" />
                      <div>
                        <div className="font-medium text-xs">融合层验收目标闸门 (FusionGoal)</div>
                        <p className="text-[11px] text-muted-foreground">
                          为任务设定可核验的成功验收标准，决定任务诚实终态（achieved / incomplete）。
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-3">
                      <Button
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs"
                        disabled={suggestingGoals}
                        onClick={() => void handlePreviewGoals()}
                      >
                        {suggestingGoals ? (
                          <Loader2 className="mr-1.5 size-3.5 animate-spin" />
                        ) : (
                          <Sparkles className="mr-1.5 size-3.5" />
                        )}
                        预览智能拆解
                      </Button>
                      <Switch checked={autoGoals} onCheckedChange={setAutoGoals} />
                    </div>
                  </div>

                  {autoGoals && previewGoals.length > 0 ? (
                    <div className="space-y-2 pt-1">
                      {previewGoals.map((g, idx) => (
                        <div key={g.id} className="flex items-start gap-2 rounded-lg border bg-background p-2.5">
                          <div className="flex-1 space-y-1.5">
                            <Input
                              value={g.title}
                              placeholder="目标标题"
                              onChange={(e) =>
                                setPreviewGoals((prev) =>
                                  prev.map((item, i) => (i === idx ? { ...item, title: e.target.value } : item)),
                                )
                              }
                              className="h-7 text-xs font-medium"
                            />
                            <Input
                              value={g.criteria}
                              placeholder="可核验验收标准"
                              onChange={(e) =>
                                setPreviewGoals((prev) =>
                                  prev.map((item, i) => (i === idx ? { ...item, criteria: e.target.value } : item)),
                                )
                              }
                              className="h-7 text-xs text-muted-foreground"
                            />
                          </div>
                          <Button
                            type="button"
                            variant="ghost"
                            size="icon"
                            className="size-7 shrink-0"
                            onClick={() => setPreviewGoals((prev) => prev.filter((_, i) => i !== idx))}
                          >
                            <Trash2 className="size-3.5 text-muted-foreground" />
                          </Button>
                        </div>
                      ))}
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        className="h-7 text-xs"
                        onClick={() =>
                          setPreviewGoals((prev) => [
                            ...prev,
                            { id: `custom_${Date.now()}`, title: "", criteria: "", kind: "finding", match: [] },
                          ])
                        }
                      >
                        <Plus className="mr-1 size-3.5" /> 追加一条自定义验收目标
                      </Button>
                    </div>
                  ) : autoGoals ? (
                    <p className="text-[11px] text-muted-foreground">
                      已开启自动生成：提交时将自动按任务配置生成默认目标闸门，也可点击上方「预览智能拆解」提前微调。
                    </p>
                  ) : null}
                </div>
              </div>
            ) : null}
          </div>

          {/* Sticky Footer with Live Summary + Actions */}
          <div className="shrink-0 border-t bg-muted/25 px-6 py-3.5">
            <div className="flex flex-wrap items-center justify-between gap-3">
              {/* Live Summary Strip + Launch Switch */}
              <div className="flex flex-wrap items-center gap-3">
                <div className="hidden flex-wrap items-center gap-1.5 text-[11px] text-muted-foreground md:flex">
                  <Badge variant="outline" className="font-normal text-[11px]">
                    {srcType === "edusrc" ? "EduSRC" : "企业SRC"}
                  </Badge>
                  <Badge variant="secondary" className="font-normal text-[11px] uppercase">
                    {targetSource === "fofa" || targetSource === "both" ? engine : targetSource === "site" ? "单站协作" : "手动"}
                  </Badge>
                  <span>{concurrency} 并发</span>
                  <span>·</span>
                  <span>护栏 {effectiveGuardCount} 项</span>
                  {(authParsed?.parsed ?? 0) > 0 ? (
                    <>
                      <span>·</span>
                      <span>凭据 {authParsed?.parsed} 条</span>
                    </>
                  ) : null}
                </div>
                {!isEdit ? (
                  <label className="flex cursor-pointer items-center gap-2 text-xs font-medium">
                    <Switch checked={startImmediately} onCheckedChange={setStartImmediately} />
                    <span>创建后立即启动</span>
                  </label>
                ) : null}
              </div>

              {/* Action Buttons */}
              <div className="flex items-center gap-2">
                {activeTab !== "governance" ? (
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    onClick={() => setActiveTab(activeTab === "basic" ? "strategy" : "governance")}
                  >
                    下一步
                    <ChevronRight className="ml-1 size-3.5" />
                  </Button>
                ) : null}
                <Button type="button" variant="outline" size="sm" onClick={() => onOpenChange(false)}>
                  取消
                </Button>
                <Button type="submit" size="sm" disabled={creating}>
                  {creating ? (
                    <>
                      <Loader2 className="mr-1.5 size-3.5 animate-spin" /> {isEdit ? "正在保存…" : "正在创建…"}
                    </>
                  ) : isEdit ? (
                    "保存修改"
                  ) : startImmediately ? (
                    "创建并立即启动"
                  ) : (
                    "创建挖掘任务"
                  )}
                </Button>
              </div>
            </div>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
}
