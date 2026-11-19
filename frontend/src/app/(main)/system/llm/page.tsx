"use client";

import * as React from "react";
import {
  Activity,
  Brain,
  CheckCircle2,
  Layers,
  Loader2,
  Plus,
  RefreshCw,
  Save,
  Server,
  Sparkles,
  Trash2,
  Wifi,
  XCircle,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { riddleApi, type FusionConfigState, type RiddleSettingsResponse } from "@/lib/riddle-api";
import { cn } from "@/lib/utils";

interface PoolProviderItem {
  name: string;
  base_url: string;
  api_key: string;
  api_key_set?: boolean;
  key_ref?: string;
  model: string;
  protocol: string;
  weight: number;
  enabled: boolean;
}

const ROLE_CARDS = [
  {
    id: "planner",
    title: "Planner · 战略规划",
    desc: "负责目标拆解、攻击面优先级调度与任务级多轮探索路线规划，推荐推理能力强的模型。",
  },
  {
    id: "worker",
    title: "Worker · 自主渗透执行",
    desc: "高频调用工具（HTTP / Shell / 浏览器）执行侦察、验证与深挖，推荐工具调用稳定且响应快的模型。",
  },
  {
    id: "reviewer",
    title: "Reviewer · AI 初审验证",
    desc: "负责漏洞复现确认、危害评级、去重与打回深挖指令，推荐严谨、低幻觉模型。",
  },
  {
    id: "judge",
    title: "Judge · 安全拦截裁决",
    desc: "对命中高危规则的命令做窄视野安全判官裁决，推荐高指令遵循的轻量快速模型。",
  },
];

export default function LlmAndRoutingPage() {
  const [settings, setSettings] = React.useState<RiddleSettingsResponse | null>(null);
  const [fusionCfg, setFusionCfg] = React.useState<FusionConfigState | null>(null);
  const [presets, setPresets] = React.useState<Array<Record<string, unknown>>>([]);
  const [healthSnap, setHealthSnap] = React.useState<Record<string, unknown> | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  // LLM Single & Pool State
  const [mode, setMode] = React.useState<"single" | "pool">("single");
  const [baseUrl, setBaseUrl] = React.useState("");
  const [apiKey, setApiKey] = React.useState("");
  const [model, setModel] = React.useState("");
  const [fallbackModels, setFallbackModels] = React.useState("");
  const [protocol, setProtocol] = React.useState("auto");
  const [temperature, setTemperature] = React.useState(0.2);
  const [providers, setProviders] = React.useState<PoolProviderItem[]>([]);

  // Probing & Testing State
  const [probedModels, setProbedModels] = React.useState<string[]>([]);
  const [probingModels, setProbingModels] = React.useState(false);
  const [testingLlm, setTestingLlm] = React.useState(false);
  const [testResult, setTestResult] = React.useState<Record<string, unknown> | null>(null);

  // Role Routing State
  const [roleRoutingEnabled, setRoleRoutingEnabled] = React.useState(true);
  const [roleModels, setRoleModels] = React.useState<Record<string, string>>({
    planner: "",
    worker: "",
    reviewer: "",
    judge: "",
  });

  const loadAll = React.useCallback(async () => {
    setLoading(true);
    try {
      const [sRes, fRes, pRes, hRes] = await Promise.allSettled([
        riddleApi.getSettings(),
        riddleApi.getFusionConfig(),
        riddleApi.getLlmPresets(),
        riddleApi.getProviderHealth(),
      ]);
      if (sRes.status === "fulfilled") {
        const s = sRes.value;
        setSettings(s);
        setMode(s.llm.mode === "pool" ? "pool" : "single");
        setBaseUrl(s.llm.base_url || "");
        setApiKey("");
        setModel(s.llm.model || "");
        const extras = (s.llm.models || []).filter((m) => m && m !== s.llm.model);
        setFallbackModels(extras.join(", "));
        setProtocol(s.llm.protocol || "auto");
        setTemperature(typeof s.llm.temperature === "number" ? s.llm.temperature : 0.2);
        const rawProviders = (s.llm.providers || []) as Array<Record<string, unknown>>;
        setProviders(
          rawProviders.map((item, idx) => ({
            name: String(item.name ?? `端点 ${idx + 1}`),
            base_url: String(item.base_url ?? ""),
            api_key: "",
            api_key_set: Boolean(item.api_key_set ?? item.api_key),
            key_ref: String(item.key_ref ?? ""),
            model: String(item.model ?? ""),
            protocol: String(item.protocol ?? "auto"),
            weight: Number(item.weight ?? 1),
            enabled: item.enabled !== false,
          })),
        );
      }
      if (fRes.status === "fulfilled") {
        const cfg = fRes.value.config;
        setFusionCfg(cfg);
        setRoleRoutingEnabled(Boolean(cfg.role_routing_enabled));
        setRoleModels({
          planner: cfg.role_models?.planner ?? "",
          worker: cfg.role_models?.worker ?? "",
          reviewer: cfg.role_models?.reviewer ?? "",
          judge: cfg.role_models?.judge ?? "",
        });
      }
      if (pRes.status === "fulfilled") {
        setPresets(pRes.value.presets ?? []);
      }
      if (hRes.status === "fulfilled") {
        setHealthSnap(hRes.value);
      }
    } catch (err) {
      toast.error(`加载模型配置失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const applyPreset = (preset: Record<string, unknown>) => {
    if (typeof preset.base_url === "string" && preset.base_url) setBaseUrl(preset.base_url);
    if (typeof preset.protocol === "string" && preset.protocol) setProtocol(preset.protocol);
    const recModels = Array.isArray(preset.models) ? (preset.models as string[]) : [];
    if (typeof preset.default_model === "string" && preset.default_model) {
      setModel(preset.default_model);
    } else if (recModels[0]) {
      setModel(recModels[0]);
    }
    if (recModels.length > 0) setProbedModels(recModels);
    toast.success(`已填充预设：${String(preset.name ?? preset.label ?? preset.id ?? "预设")}`);
  };

  const handleProbeModels = async () => {
    setProbingModels(true);
    try {
      const res = await riddleApi.probeLlmModels({
        base_url: baseUrl.trim() || undefined,
        api_key: apiKey.trim() || undefined,
        protocol,
        model: model.trim() || undefined,
      });
      const list = res.models ?? [];
      if (list.length > 0) {
        setProbedModels(list);
        toast.success(`拉取成功：共发现 ${list.length} 个可用模型`);
      } else {
        toast.error(res.error || "未能从该端点拉取到模型列表，请手动填写模型名");
      }
    } catch (err) {
      toast.error(`拉取模型列表失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setProbingModels(false);
    }
  };

  const handleRecommendTemp = async () => {
    try {
      const res = await riddleApi.recommendTemperature(model.trim(), "hunt");
      if (typeof res.temperature === "number") {
        setTemperature(res.temperature);
        toast.success(`推荐温度 ${res.temperature}${res.reason ? `：${res.reason}` : ""}`);
      }
    } catch (err) {
      toast.error(`获取推荐温度失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleTestLlm = async () => {
    setTestingLlm(true);
    setTestResult(null);
    try {
      const payload =
        mode === "pool"
          ? {
              providers: providers.map((p) => ({
                name: p.name,
                base_url: p.base_url,
                api_key: p.api_key.trim() || undefined,
                key_ref: p.key_ref || undefined,
                model: p.model,
                protocol: p.protocol,
                weight: p.weight,
                enabled: p.enabled,
              })),
            }
          : {
              base_url: baseUrl.trim() || undefined,
              api_key: apiKey.trim() || undefined,
              model: model.trim() || undefined,
              protocol,
              temperature,
            };
      const res = await riddleApi.testLlm(payload);
      setTestResult(res);
      if (res.ok) {
        toast.success("LLM 连通性与工具调用探测通过");
      } else {
        toast.error(String(res.error ?? "连通测试未通过，请查看详情"));
      }
    } catch (err) {
      toast.error(`连通测试失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTestingLlm(false);
    }
  };

  const handleSaveLlm = async () => {
    setSaving(true);
    try {
      const fallbackList = fallbackModels
        .split(/[\r\n,，]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const mergedModels = [model.trim(), ...fallbackList.filter((m) => m !== model.trim())].filter(Boolean);

      const llmPayload: Record<string, unknown> = {
        mode,
        base_url: baseUrl.trim(),
        model: model.trim(),
        models: mergedModels,
        protocol,
        temperature,
      };
      if (apiKey.trim()) llmPayload.api_key = apiKey.trim();
      if (mode === "pool") {
        llmPayload.providers = providers.map((p) => ({
          name: p.name.trim() || "端点",
          base_url: p.base_url.trim(),
          ...(p.api_key.trim() ? { api_key: p.api_key.trim() } : {}),
          ...(p.key_ref ? { key_ref: p.key_ref } : {}),
          model: p.model.trim(),
          protocol: p.protocol,
          weight: p.weight,
          enabled: p.enabled,
        }));
      }

      await riddleApi.putSettings({ llm: llmPayload });
      toast.success("主力模型与调度配置已保存并热生效");
      await loadAll();
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleSaveRouting = async () => {
    setSaving(true);
    try {
      await riddleApi.putFusionConfig({
        role_routing_enabled: roleRoutingEnabled,
        role_models: roleModels,
      });
      toast.success("融合四角色分层路由已保存");
      await loadAll();
    } catch (err) {
      toast.error(`保存角色路由失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const healthProviders = Array.isArray(healthSnap?.providers)
    ? (healthSnap.providers as Array<Record<string, unknown>>)
    : [];

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="模型与多角色路由"
        description="配置知蠹全局主力 LLM、单端点多模型灾备或端点池轮询，并按 Planner / Worker / Reviewer / Judge 独立分派模型。"
        actions={
          <Button variant="outline" size="sm" onClick={() => void loadAll()} disabled={loading}>
            <RefreshCw className={`mr-1.5 size-3.5 ${loading ? "animate-spin" : ""}`} />
            刷新状态
          </Button>
        }
      />

      <Tabs defaultValue="primary" className="space-y-4">
        <TabsList>
          <TabsTrigger value="primary">
            <Server className="mr-1.5 size-3.5" /> 主力模型与端点池
          </TabsTrigger>
          <TabsTrigger value="routing">
            <Brain className="mr-1.5 size-3.5" /> 四角色分层路由
          </TabsTrigger>
          <TabsTrigger value="health">
            <Activity className="mr-1.5 size-3.5" /> 端点健康与熔断
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Primary LLM & Pool */}
        <TabsContent value="primary" className="space-y-4">
          {/* Mode Switch Cards */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {[
              {
                id: "single" as const,
                title: "单端点模式（含多模型灾备）",
                desc: "配置单个供应商端点与主模型，可附带多个同商灾备模型在限流时自动顶替。",
                icon: Server,
              },
              {
                id: "pool" as const,
                title: "多端点池模式（加权轮询 + 熔断）",
                desc: "同时挂载多个供应商 API Key / 中转站，按权重均衡分流并在异常时自动冷却摘除。",
                icon: Layers,
              },
            ].map((opt) => {
              const active = mode === opt.id;
              const Icon = opt.icon;
              return (
                <button
                  key={opt.id}
                  type="button"
                  onClick={() => setMode(opt.id)}
                  className={cn(
                    "flex items-start gap-3 rounded-xl border p-4 text-left transition-all",
                    active
                      ? "border-primary bg-primary/5 ring-1 ring-primary/30"
                      : "border-border bg-card hover:border-foreground/30",
                  )}
                >
                  <div
                    className={cn(
                      "flex size-9 shrink-0 items-center justify-center rounded-lg",
                      active ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground",
                    )}
                  >
                    <Icon className="size-4" />
                  </div>
                  <div className="space-y-1">
                    <div className="font-medium text-sm">{opt.title}</div>
                    <p className="text-xs text-muted-foreground leading-relaxed">{opt.desc}</p>
                  </div>
                </button>
              );
            })}
          </div>

          {mode === "single" ? (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <CardTitle className="text-base">主力 LLM 端点配置</CardTitle>
                    <CardDescription className="text-xs">
                      API Key 加密落库且仅脱敏回显；留空保存则保留当前密钥。
                    </CardDescription>
                  </div>
                  <Badge variant={settings?.llm?.api_key_set ? "default" : "secondary"}>
                    {settings?.llm?.api_key_set ? `Key 已配置 (${settings.llm.api_key})` : "未配置 Key"}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Provider Presets */}
                {presets.length > 0 ? (
                  <div className="flex flex-wrap items-center gap-1.5">
                    <span className="text-xs text-muted-foreground">快捷填充供应商：</span>
                    {presets.map((p, idx) => (
                      <Button
                        key={String(p.id ?? idx)}
                        type="button"
                        variant="outline"
                        size="sm"
                        className="h-7 text-xs"
                        onClick={() => applyPreset(p)}
                      >
                        {String(p.name ?? p.label ?? p.id)}
                      </Button>
                    ))}
                  </div>
                ) : null}

                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <div className="md:col-span-2 space-y-1.5">
                    <Label className="text-xs">API Base URL</Label>
                    <Input
                      className="font-mono text-xs"
                      placeholder="https://api.openai.com/v1"
                      value={baseUrl}
                      onChange={(e) => setBaseUrl(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">接口协议</Label>
                    <Select value={protocol} onValueChange={setProtocol}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="auto">自动探测 (auto)</SelectItem>
                        <SelectItem value="openai_chat">OpenAI Compatible</SelectItem>
                        <SelectItem value="anthropic_messages">Anthropic Messages</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label className="text-xs">API Key</Label>
                    <Input
                      type="password"
                      placeholder={settings?.llm?.api_key_set ? "留空保持现有密钥不变" : "sk-..."}
                      value={apiKey}
                      onChange={(e) => setApiKey(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs">主力模型名</Label>
                      <Button
                        type="button"
                        variant="link"
                        size="sm"
                        className="h-auto p-0 text-xs"
                        disabled={probingModels}
                        onClick={() => void handleProbeModels()}
                      >
                        {probingModels ? "拉取中…" : "在线拉取可用模型"}
                      </Button>
                    </div>
                    <Input
                      className="font-mono text-xs"
                      placeholder="例如：deepseek-chat / claude-sonnet-4-5 / gpt-4o"
                      value={model}
                      onChange={(e) => setModel(e.target.value)}
                    />
                  </div>
                </div>

                {probedModels.length > 0 ? (
                  <div className="flex flex-wrap gap-1.5 rounded-lg border bg-muted/25 p-2.5">
                    {probedModels.slice(0, 24).map((m) => (
                      <button
                        key={m}
                        type="button"
                        onClick={() => setModel(m)}
                        className={cn(
                          "rounded border px-2 py-0.5 font-mono text-[11px] transition-colors",
                          model === m
                            ? "border-primary bg-primary text-primary-foreground"
                            : "bg-background hover:border-primary/40",
                        )}
                      >
                        {m}
                      </button>
                    ))}
                  </div>
                ) : null}

                <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                  <div className="md:col-span-2 space-y-1.5">
                    <Label className="text-xs">同商灾备模型列表（可选，逗号分隔）</Label>
                    <Input
                      className="font-mono text-xs"
                      placeholder="主模型限流或 5xx 时按序切换，如：deepseek-reasoner, gpt-4o-mini"
                      value={fallbackModels}
                      onChange={(e) => setFallbackModels(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <Label className="text-xs">采样温度 (Temperature)</Label>
                      <Button
                        type="button"
                        variant="link"
                        size="sm"
                        className="h-auto p-0 text-xs"
                        onClick={() => void handleRecommendTemp()}
                      >
                        <Sparkles className="mr-1 size-3" /> 智能推荐
                      </Button>
                    </div>
                    <Input
                      type="number"
                      step="0.1"
                      min={0}
                      max={2}
                      value={temperature}
                      onChange={(e) => setTemperature(Number(e.target.value))}
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader className="flex flex-row items-center justify-between pb-3">
                <div>
                  <CardTitle className="text-base">多端点池列表 ({providers.length})</CardTitle>
                  <CardDescription className="text-xs">按权重分配并发流量，单个端点连续异常时自动熔断冷却。</CardDescription>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    setProviders((prev) => [
                      ...prev,
                      {
                        name: `端点 ${prev.length + 1}`,
                        base_url: baseUrl || "https://api.openai.com/v1",
                        api_key: "",
                        model: model || "",
                        protocol: "auto",
                        weight: 1,
                        enabled: true,
                      },
                    ])
                  }
                >
                  <Plus className="mr-1.5 size-3.5" /> 添加端点
                </Button>
              </CardHeader>
              <CardContent className="space-y-3">
                {providers.length === 0 ? (
                  <div className="rounded-lg border border-dashed py-8 text-center text-xs text-muted-foreground">
                    端点池暂无配置，点击右上角「添加端点」创建第一个池成员。
                  </div>
                ) : (
                  providers.map((p, idx) => (
                    <div key={idx} className="space-y-3 rounded-lg border p-3.5">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <Switch
                            checked={p.enabled}
                            onCheckedChange={(v) =>
                              setProviders((prev) => prev.map((x, i) => (i === idx ? { ...x, enabled: v } : x)))
                            }
                          />
                          <Input
                            className="h-8 w-40 text-xs font-medium"
                            value={p.name}
                            onChange={(e) =>
                              setProviders((prev) => prev.map((x, i) => (i === idx ? { ...x, name: e.target.value } : x)))
                            }
                          />
                          {p.api_key_set ? <Badge variant="outline" className="text-[11px]">Key 已存</Badge> : null}
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-8"
                          onClick={() => setProviders((prev) => prev.filter((_, i) => i !== idx))}
                        >
                          <Trash2 className="size-4 text-destructive" />
                        </Button>
                      </div>
                      <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-4">
                        <Input
                          className="sm:col-span-2 font-mono text-xs"
                          placeholder="Base URL"
                          value={p.base_url}
                          onChange={(e) =>
                            setProviders((prev) => prev.map((x, i) => (i === idx ? { ...x, base_url: e.target.value } : x)))
                          }
                        />
                        <Input
                          className="font-mono text-xs"
                          placeholder="Model"
                          value={p.model}
                          onChange={(e) =>
                            setProviders((prev) => prev.map((x, i) => (i === idx ? { ...x, model: e.target.value } : x)))
                          }
                        />
                        <Input
                          type="password"
                          className="text-xs"
                          placeholder={p.api_key_set ? "留空不变" : "API Key"}
                          value={p.api_key}
                          onChange={(e) =>
                            setProviders((prev) => prev.map((x, i) => (i === idx ? { ...x, api_key: e.target.value } : x)))
                          }
                        />
                      </div>
                    </div>
                  ))
                )}
              </CardContent>
            </Card>
          )}

          {/* Action Bar & Test Result */}
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Button variant="outline" disabled={testingLlm} onClick={() => void handleTestLlm()}>
              {testingLlm ? <Loader2 className="mr-1.5 size-4 animate-spin" /> : <Wifi className="mr-1.5 size-4" />}
              测试连通与工具调用
            </Button>
            <Button disabled={saving} onClick={() => void handleSaveLlm()}>
              <Save className="mr-1.5 size-4" /> 保存 LLM 配置
            </Button>
          </div>

          {testResult ? (
            <Card className={testResult.ok ? "border-emerald-500/40 bg-emerald-500/5" : "border-destructive/40 bg-destructive/5"}>
              <CardContent className="p-4 text-xs space-y-2">
                <div className="flex items-center gap-2 font-medium">
                  {testResult.ok ? (
                    <CheckCircle2 className="size-4 text-emerald-600" />
                  ) : (
                    <XCircle className="size-4 text-destructive" />
                  )}
                  <span>{testResult.ok ? "连通测试成功" : "连通测试异常"}</span>
                </div>
                <pre className="max-h-52 overflow-auto rounded border bg-background/80 p-2.5 font-mono text-[11px]">
                  {JSON.stringify(testResult, null, 2)}
                </pre>
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>

        {/* Tab 2: 4-Role Routing */}
        <TabsContent value="routing" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
              <div>
                <CardTitle className="text-base">融合四角色分层模型路由 (role_routing_enabled)</CardTitle>
                <CardDescription className="text-xs">
                  按 Agent 职责覆写具体模型名；留空的角色自动继承主力模型配置，无需额外维护多份 Key。
                </CardDescription>
              </div>
              <Switch checked={roleRoutingEnabled} onCheckedChange={setRoleRoutingEnabled} />
            </CardHeader>
          </Card>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            {ROLE_CARDS.map((rc) => (
              <Card key={rc.id}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm">{rc.title}</CardTitle>
                    <Badge variant={roleModels[rc.id]?.trim() ? "default" : "secondary"} className="text-[11px]">
                      {roleModels[rc.id]?.trim() ? "独立覆写" : "继承全局"}
                    </Badge>
                  </div>
                  <CardDescription className="text-xs leading-relaxed">{rc.desc}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-1.5">
                  <Label className="text-xs">指定模型名（留空 = {model || "全局主力模型"}）</Label>
                  <Input
                    className="font-mono text-xs"
                    placeholder={`留空继承：${model || "全局默认模型"}`}
                    value={roleModels[rc.id] ?? ""}
                    onChange={(e) => setRoleModels((prev) => ({ ...prev, [rc.id]: e.target.value }))}
                  />
                </CardContent>
              </Card>
            ))}
          </div>

          <div className="flex justify-end">
            <Button disabled={saving || !fusionCfg} onClick={() => void handleSaveRouting()}>
              <Save className="mr-1.5 size-4" /> 保存四角色路由
            </Button>
          </div>
        </TabsContent>

        {/* Tab 3: Runtime Health */}
        <TabsContent value="health" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">运行时端点健康与熔断快照</CardTitle>
              <CardDescription className="text-xs">
                当前模式：{String(healthSnap?.mode ?? mode)} · 展示运行期实时健康状态与冷却记录。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {healthProviders.length > 0 ? (
                <div className="space-y-2">
                  {healthProviders.map((hp, i) => {
                    const h = (hp.health as Record<string, unknown>) || {};
                    return (
                      <div key={i} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border p-3 text-xs">
                        <div>
                          <div className="font-medium">{String(hp.name || hp.model || `端点 ${i + 1}`)}</div>
                          <div className="font-mono text-muted-foreground">
                            {String(hp.base_url || "")} · {String(hp.model || "")}
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={h.status === "healthy" ? "default" : "secondary"}>
                            {String(h.status ?? "unknown")}
                          </Badge>
                          <span className="text-muted-foreground">连续失败：{Number(h.consecutive_failures ?? 0)}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <pre className="rounded-lg border bg-muted/30 p-3 font-mono text-xs">
                  {JSON.stringify(healthSnap ?? { status: "暂无健康采样记录" }, null, 2)}
                </pre>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
