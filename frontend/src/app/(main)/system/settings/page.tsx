"use client";

import * as React from "react";
import {
  BellRing,
  Database,
  Download,
  HardDrive,
  KeyRound,
  RefreshCw,
  Save,
  Send,
  Shield,
  Sliders,
  Trash2,
  Upload,
  Wifi,
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

const ENGINE_ORDER = ["fofa", "quake", "hunter", "zoomeye", "shodan", "censys"];

const FUSION_SWITCH_DEFS: Array<{ key: keyof FusionConfigState; label: string; desc: string }> = [
  { key: "evidence_gate_hard", label: "证据硬闸门 (evidence_gate_hard)", desc: "未达 L2–L4 机械凭据不自动通过" },
  { key: "scope_guard_hard", label: "范围硬守卫 (scope_guard_hard)", desc: "非授权域外目标禁止自动写回" },
  { key: "goal_gate_enabled", label: "目标闸门 (goal_gate_enabled)", desc: "启用可核验任务验收目标与诚实终态" },
  { key: "skill_index_enabled", label: "技能速查注入 (skill_index_enabled)", desc: "Worker 启动自动加载技能速查卡" },
  { key: "role_routing_enabled", label: "四角色路由 (role_routing_enabled)", desc: "Planner/Worker/Reviewer/Judge 分层路由" },
  { key: "intel_sync_enabled", label: "CVE 时间流 (intel_sync_enabled)", desc: "自动同步 NVD/KEV 并按版本反查" },
  { key: "traffic_enabled", label: "实证流量留痕 (traffic_enabled)", desc: "逐请求写入 JSONL 证据链" },
  { key: "graphs_enabled", label: "双图溯源 (graphs_enabled)", desc: "资产图 × 探索图与血缘覆盖计算" },
  { key: "report_enabled", label: "公文级报告 (report_enabled)", desc: "支持导出含封面目录的 .docx 报告" },
];

export default function RiddleSettingsPage() {
  const [settings, setSettings] = React.useState<RiddleSettingsResponse | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  // Tab 1: Engines State
  const [engineDraft, setEngineDraft] = React.useState<Record<string, { key: string; base_url: string }>>({});
  const [fofaMaxPages, setFofaMaxPages] = React.useState(20);
  const [fofaPageSize, setFofaPageSize] = React.useState(100);
  const [defaultEngine, setDefaultEngine] = React.useState("fofa");
  const [testingEngine, setTestingEngine] = React.useState<string | null>(null);

  // Tab 2: Defaults & Fusion Switches
  const [concurrency, setConcurrency] = React.useState(3);
  const [deepenCap, setDeepenCap] = React.useState(2);
  const [skipThreshold, setSkipThreshold] = React.useState(-10);
  const [promptVersion, setPromptVersion] = React.useState("v1");
  const [fusionDraft, setFusionDraft] = React.useState<FusionConfigState | null>(null);

  // Tab 3: Workdir & Backup
  const [workdirStats, setWorkdirStats] = React.useState<Record<string, unknown> | null>(null);
  const [backupStatus, setBackupStatus] = React.useState<Record<string, unknown> | null>(null);
  const [retentionDays, setRetentionDays] = React.useState(7);
  const [restoreFile, setRestoreFile] = React.useState<File | null>(null);

  // Tab 4: Security Tokens
  const [fullToken, setFullToken] = React.useState("");
  const [readToken, setReadToken] = React.useState("");
  const [observerToken, setObserverToken] = React.useState("");

  // Tab 5: Real-time Alert Notifications
  const [notifyEnabled, setNotifyEnabled] = React.useState(false);
  const [notifyChannel, setNotifyChannel] = React.useState("feishu");
  const [notifyWebhook, setNotifyWebhook] = React.useState("");
  const [notifyWebhookSet, setNotifyWebhookSet] = React.useState(false);
  const [notifyTgToken, setNotifyTgToken] = React.useState("");
  const [notifyTgTokenSet, setNotifyTgTokenSet] = React.useState(false);
  const [notifyTgChat, setNotifyTgChat] = React.useState("");
  const [notifyConsoleUrl, setNotifyConsoleUrl] = React.useState("");
  const [notifyMinSev, setNotifyMinSev] = React.useState("高危");
  const [notifyOnFinding, setNotifyOnFinding] = React.useState(true);
  const [notifyOnIntercept, setNotifyOnIntercept] = React.useState(true);
  const [notifyOnTaskDone, setNotifyOnTaskDone] = React.useState(true);
  const [notifyHistory, setNotifyHistory] = React.useState<Array<Record<string, unknown>>>([]);
  const [testingNotify, setTestingNotify] = React.useState(false);

  const loadAll = React.useCallback(async () => {
    setLoading(true);
    try {
      const [sRes, wRes, bRes, nRes, nhRes] = await Promise.allSettled([
        riddleApi.getSettings(),
        riddleApi.getWorkdirStats(),
        riddleApi.getBackupStatus(),
        riddleApi.getNotifyConfig(),
        riddleApi.getNotifyHistory(20),
      ]);
      if (sRes.status === "fulfilled") {
        const s = sRes.value;
        setSettings(s);
        const draft: Record<string, { key: string; base_url: string }> = {};
        for (const name of ENGINE_ORDER) {
          const item = s.engines?.[name];
          draft[name] = { key: "", base_url: item?.base_url ?? "" };
        }
        setEngineDraft(draft);
        setFofaMaxPages(s.fofa?.max_pages ?? 20);
        setFofaPageSize(s.fofa?.page_size ?? 100);
        setDefaultEngine(s.defaults?.engine ?? "fofa");
        setConcurrency(s.defaults?.concurrency ?? 3);
        setDeepenCap(s.defaults?.deepen_cap ?? 2);
        setSkipThreshold(s.defaults?.skip_score_threshold ?? -10);
        setPromptVersion(s.defaults?.worker_prompt_version ?? "v1");
        setFusionDraft(s.defaults?.fusion ?? null);
      }
      if (wRes.status === "fulfilled") setWorkdirStats(wRes.value);
      if (bRes.status === "fulfilled") setBackupStatus(bRes.value);
      if (nRes.status === "fulfilled") {
        const nc = nRes.value.config;
        setNotifyEnabled(Boolean(nc.enabled));
        setNotifyChannel(nc.channel || "feishu");
        setNotifyWebhook("");
        setNotifyWebhookSet(Boolean(nc.webhook_url_set));
        setNotifyTgToken("");
        setNotifyTgTokenSet(Boolean(nc.telegram_bot_token_set));
        setNotifyTgChat(nc.telegram_chat_id || "");
        setNotifyConsoleUrl(nc.console_base_url || "");
        setNotifyMinSev(nc.min_severity || "高危");
        setNotifyOnFinding(nc.on_finding_accepted !== false);
        setNotifyOnIntercept(nc.on_intercept_pending !== false);
        setNotifyOnTaskDone(nc.on_task_done !== false);
      }
      if (nhRes.status === "fulfilled") setNotifyHistory(nhRes.value.items ?? []);
    } catch (err) {
      toast.error(`加载系统配置失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const handleSaveEngines = async () => {
    setSaving(true);
    try {
      const enginesPayload: Record<string, { key?: string; base_url?: string }> = {};
      for (const name of ENGINE_ORDER) {
        const row = engineDraft[name];
        if (!row) continue;
        const entry: { key?: string; base_url?: string } = { base_url: row.base_url };
        if (row.key.trim()) entry.key = row.key.trim();
        enginesPayload[name] = entry;
      }
      await riddleApi.putSettings({
        engines: enginesPayload,
        fofa: {
          max_pages: fofaMaxPages,
          page_size: fofaPageSize,
          ...(engineDraft.fofa?.key.trim() ? { key: engineDraft.fofa.key.trim() } : {}),
          ...(engineDraft.fofa?.base_url.trim() ? { base_url: engineDraft.fofa.base_url.trim() } : {}),
        },
        defaults: { engine: defaultEngine },
      });
      toast.success("已保存六大空间测绘引擎与 FOFA 参数");
      await loadAll();
    } catch (err) {
      toast.error(`保存引擎失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleTestEngine = async (name: string) => {
    setTestingEngine(name);
    try {
      const draft = engineDraft[name];
      const res = await riddleApi.testEngine(name, draft?.key.trim() || undefined, draft?.base_url.trim() || undefined);
      if (res.ok) {
        toast.success(`${name.toUpperCase()} 连通正常 (${res.latency_ms ?? 0}ms, 可见结果 ${res.size ?? 0})`);
      } else {
        toast.error(`${name.toUpperCase()} 测试失败：${res.error || "认证或网络异常"}`);
      }
    } catch (err) {
      toast.error(`探活失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTestingEngine(null);
    }
  };

  const handleSaveDefaultsAndFusion = async () => {
    setSaving(true);
    try {
      await riddleApi.putSettings({
        defaults: {
          concurrency,
          deepen_cap: deepenCap,
          skip_score_threshold: skipThreshold,
          worker_prompt_version: promptVersion,
        },
      });
      if (fusionDraft) {
        await riddleApi.putFusionConfig(fusionDraft);
      }
      toast.success("已保存挖掘默认策略与融合层九大开关");
      await loadAll();
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const handleCleanupWorkdir = async (dryRun: boolean) => {
    try {
      const res = await riddleApi.cleanupWorkdir(retentionDays, dryRun);
      toast.success(
        dryRun
          ? `模拟清理：可释放 ${Number(res.reclaimed_mb ?? 0).toFixed(1)} MB (${Number(res.removed_count ?? 0)} 目录)`
          : `清理完成：已移除 ${Number(res.removed_count ?? 0)} 个过期目录`,
      );
      await loadAll();
    } catch (err) {
      toast.error(`清理操作失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSaveAuth = async () => {
    const authPayload: Record<string, string> = {};
    if (fullToken.trim()) authPayload.full_token = fullToken.trim();
    if (readToken.trim()) authPayload.read_token = readToken.trim();
    if (observerToken.trim()) authPayload.observer_token = observerToken.trim();
    if (Object.keys(authPayload).length === 0) {
      toast.error("请输入需要更新或设置的新令牌内容");
      return;
    }
    setSaving(true);
    try {
      await riddleApi.putSettings({ auth: authPayload });
      toast.success("访问令牌已更新");
      setFullToken("");
      setReadToken("");
      setObserverToken("");
      await loadAll();
    } catch (err) {
      toast.error(`更新令牌失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSaving(false);
    }
  };

  const snapshots = Array.isArray(backupStatus?.snapshots)
    ? (backupStatus.snapshots as Array<{ name: string; size_bytes?: number; created_at?: string }>)
    : [];

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="系统与引擎配置"
        description="六大空间测绘引擎与连通探活 · 挖掘并发与融合九开关 · 工作目录磁盘清理与 SQLite 快照备份 · 访问令牌治理。"
        actions={
          <Button variant="outline" size="sm" onClick={() => void loadAll()} disabled={loading}>
            <RefreshCw className={`mr-1.5 size-3.5 ${loading ? "animate-spin" : ""}`} />
            刷新配置
          </Button>
        }
      />

      <Tabs defaultValue="engines" className="space-y-4">
        <TabsList className="flex-wrap h-auto">
          <TabsTrigger value="engines">测绘引擎与探活</TabsTrigger>
          <TabsTrigger value="fusion">挖掘并发与融合九开关</TabsTrigger>
          <TabsTrigger value="notify">
            <BellRing className="mr-1.5 size-3.5" /> 告警通知
          </TabsTrigger>
          <TabsTrigger value="backup">工作目录与备份恢复</TabsTrigger>
          <TabsTrigger value="auth">三权分立令牌</TabsTrigger>
        </TabsList>

        {/* Tab 1: 6 Engines + FOFA */}
        <TabsContent value="engines" className="space-y-4">
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
            {ENGINE_ORDER.map((name) => {
              const info = settings?.engines?.[name];
              const draft = engineDraft[name] ?? { key: "", base_url: "" };
              return (
                <Card key={name}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-base uppercase">{info?.display_name || name}</CardTitle>
                      <Badge variant={info?.key_set ? "default" : "secondary"}>
                        {info?.key_set ? "Key 已配置" : "未配置"}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="space-y-1">
                      <Label className="text-xs">API Key {info?.key_set ? `(${info.key})` : ""}</Label>
                      <Input
                        type="password"
                        placeholder={info?.key_set ? "留空保持现有密钥不变" : "输入引擎 API Key / Token"}
                        value={draft.key}
                        onChange={(e) =>
                          setEngineDraft((prev) => ({
                            ...prev,
                            [name]: { ...draft, key: e.target.value },
                          }))
                        }
                      />
                    </div>
                    <div className="space-y-1">
                      <Label className="text-xs">Base URL (可选)</Label>
                      <Input
                        placeholder="留空使用官方默认端点"
                        value={draft.base_url}
                        onChange={(e) =>
                          setEngineDraft((prev) => ({
                            ...prev,
                            [name]: { ...draft, base_url: e.target.value },
                          }))
                        }
                      />
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      className="w-full"
                      disabled={testingEngine === name}
                      onClick={() => void handleTestEngine(name)}
                    >
                      <Wifi className="mr-1.5 size-3.5" />
                      {testingEngine === name ? "正在探活…" : "测试连通性"}
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">测绘默认策略</CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              <div className="space-y-1.5">
                <Label className="text-xs">默认空间测绘引擎</Label>
                <Select value={defaultEngine} onValueChange={setDefaultEngine}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ENGINE_ORDER.map((e) => (
                      <SelectItem key={e} value={e}>
                        {e.toUpperCase()}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">单次拉取最大页数 (max_pages)</Label>
                <Input type="number" value={fofaMaxPages} onChange={(e) => setFofaMaxPages(Number(e.target.value) || 20)} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">每页拉取资产数 (page_size)</Label>
                <Input type="number" value={fofaPageSize} onChange={(e) => setFofaPageSize(Number(e.target.value) || 100)} />
              </div>
            </CardContent>
          </Card>

          <div className="flex justify-end">
            <Button disabled={saving} onClick={() => void handleSaveEngines()}>
              <Save className="mr-1.5 size-4" /> 保存测绘配置
            </Button>
          </div>
        </TabsContent>

        {/* Tab 2: Mining Defaults & 9 Fusion Switches */}
        <TabsContent value="fusion" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Sliders className="size-4" /> 全局挖掘默认参数
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-4 sm:grid-cols-4">
              <div className="space-y-1.5">
                <Label className="text-xs">默认 Worker 并发数</Label>
                <Input type="number" value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value) || 3)} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">深挖最大轮次 (deepen_cap)</Label>
                <Input type="number" value={deepenCap} onChange={(e) => setDeepenCap(Number(e.target.value) || 2)} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">预筛低分跳过阈值</Label>
                <Input type="number" value={skipThreshold} onChange={(e) => setSkipThreshold(Number(e.target.value))} />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">Worker Prompt 版本</Label>
                <Input value={promptVersion} onChange={(e) => setPromptVersion(e.target.value)} />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">融合治理层 9 大开关（写入立即热生效）</CardTitle>
              <CardDescription className="text-xs">
                优先级高于 .env 环境变量；核心硬闸门默认为按需启用。
              </CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-3 md:grid-cols-3">
              {FUSION_SWITCH_DEFS.map((item) => (
                <div key={item.key} className="flex items-center justify-between gap-3 rounded-lg border p-3">
                  <div className="space-y-0.5">
                    <div className="font-medium text-xs">{item.label}</div>
                    <div className="text-[11px] text-muted-foreground">{item.desc}</div>
                  </div>
                  <Switch
                    checked={Boolean(fusionDraft?.[item.key])}
                    onCheckedChange={(v) =>
                      setFusionDraft((prev) => (prev ? { ...prev, [item.key]: v } : prev))
                    }
                  />
                </div>
              ))}
            </CardContent>
          </Card>

          <div className="flex justify-end">
            <Button disabled={saving} onClick={() => void handleSaveDefaultsAndFusion()}>
              <Save className="mr-1.5 size-4" /> 保存挖掘与融合配置
            </Button>
          </div>
        </TabsContent>

        {/* Tab 3: Workdir Cleanup & SQLite Backup */}
        <TabsContent value="backup" className="space-y-4">
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <HardDrive className="size-4" /> 工作目录磁盘管理
                </CardTitle>
                <CardDescription className="text-xs">
                  当前占用：{Number(workdirStats?.total_mb ?? 0).toFixed(1)} MB · 目录数：
                  {Number(workdirStats?.dir_count ?? 0)}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center gap-3">
                  <Label className="text-xs whitespace-nowrap">保留最近天数</Label>
                  <Input
                    type="number"
                    className="w-28"
                    value={retentionDays}
                    onChange={(e) => setRetentionDays(Number(e.target.value) || 0)}
                  />
                  <Button variant="outline" size="sm" onClick={() => void handleCleanupWorkdir(true)}>
                    模拟统计可释放空间
                  </Button>
                  <Button variant="destructive" size="sm" onClick={() => void handleCleanupWorkdir(false)}>
                    <Trash2 className="mr-1 size-3.5" /> 执行清理
                  </Button>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Database className="size-4" /> SQLite 快照与数据迁移
                </CardTitle>
                <CardDescription className="text-xs">
                  支持一键热快照、数据库 / 全量工作区打包导出及上传恢复。
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="sm"
                    onClick={async () => {
                      await riddleApi.createSnapshot();
                      toast.success("已在服务端创建快照");
                      await loadAll();
                    }}
                  >
                    生成服务端快照
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => void riddleApi.exportBackup(false)}>
                    <Download className="mr-1.5 size-3.5" /> 导出 DB (.tar.gz)
                  </Button>
                  <Button size="sm" variant="outline" onClick={() => void riddleApi.exportBackup(true)}>
                    导出 DB+工作区
                  </Button>
                </div>
                <div className="flex items-center gap-2 pt-2">
                  <Input
                    type="file"
                    accept=".tar.gz,.tgz,.gz"
                    onChange={(e) => setRestoreFile(e.target.files?.[0] ?? null)}
                  />
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={!restoreFile}
                    onClick={async () => {
                      if (!restoreFile) return;
                      if (!window.confirm("确定使用该归档覆盖当前数据库并触发重启？")) return;
                      await riddleApi.restoreBackup(restoreFile, false, true);
                      toast.success("归档恢复请求已提交，服务端将重启加载新库");
                    }}
                  >
                    <Upload className="mr-1.5 size-3.5" /> 上传恢复
                  </Button>
                </div>
                {snapshots.length > 0 ? (
                  <div className="space-y-1.5 pt-2">
                    <div className="text-xs font-medium text-muted-foreground">服务端本地快照</div>
                    {snapshots.slice(0, 5).map((s) => (
                      <div key={s.name} className="flex items-center justify-between rounded border px-2.5 py-1.5 text-xs">
                        <span className="font-mono">{s.name}</span>
                        <Button variant="ghost" size="sm" onClick={() => void riddleApi.downloadSnapshot(s.name)}>
                          下载
                        </Button>
                      </div>
                    ))}
                  </div>
                ) : null}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Tab 4: Tri-Role Access Tokens */}
        <TabsContent value="auth" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <Shield className="size-4" /> 三权分立访问令牌管理
              </CardTitle>
              <CardDescription className="text-xs">
                为不同角色签发全权限 (full)、只读审核 (readonly)、观摩展示 (observer) 访问令牌；留空保存保持原值不变。
              </CardDescription>
            </CardHeader>
            <CardContent className="grid grid-cols-1 gap-4 md:grid-cols-3">
              <div className="space-y-1.5">
                <Label className="text-xs flex items-center justify-between">
                  <span>全权限令牌 (full_token)</span>
                  <Badge variant={settings?.auth?.full_token_set ? "default" : "secondary"}>
                    {settings?.auth?.full_token_set ? "已启用" : "未设置"}
                  </Badge>
                </Label>
                <Input
                  type="password"
                  placeholder="输入新的 full_token…"
                  value={fullToken}
                  onChange={(e) => setFullToken(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs flex items-center justify-between">
                  <span>只读令牌 (read_token)</span>
                  <Badge variant={settings?.auth?.read_token_set ? "default" : "secondary"}>
                    {settings?.auth?.read_token_set ? "已启用" : "未设置"}
                  </Badge>
                </Label>
                <Input
                  type="password"
                  placeholder="输入新的 read_token…"
                  value={readToken}
                  onChange={(e) => setReadToken(e.target.value)}
                />
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs flex items-center justify-between">
                  <span>观摩脱敏令牌 (observer_token)</span>
                  <Badge variant={settings?.auth?.observer_token_set ? "default" : "secondary"}>
                    {settings?.auth?.observer_token_set ? "已启用" : "未设置"}
                  </Badge>
                </Label>
                <Input
                  type="password"
                  placeholder="输入新的 observer_token…"
                  value={observerToken}
                  onChange={(e) => setObserverToken(e.target.value)}
                />
              </div>
            </CardContent>
          </Card>
          <div className="flex justify-end">
            <Button disabled={saving} onClick={() => void handleSaveAuth()}>
              <KeyRound className="mr-1.5 size-4" /> 更新访问令牌
            </Button>
          </div>
        </TabsContent>

        {/* Tab 5: Real-time Alert Notifications */}
        <TabsContent value="notify" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
              <div>
                <CardTitle className="flex items-center gap-2 text-base">
                  <BellRing className="size-4" /> 7×24 实时告警推送通道
                </CardTitle>
                <CardDescription className="text-xs">
                  支持飞书、钉钉、企业微信、Telegram 与自定义 Webhook；出网目标强制过 SSRF 校验。
                </CardDescription>
              </div>
              <Switch checked={notifyEnabled} onCheckedChange={setNotifyEnabled} />
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
                <div className="space-y-1.5">
                  <Label className="text-xs">通知渠道</Label>
                  <Select value={notifyChannel} onValueChange={setNotifyChannel}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="feishu">飞书机器人 (Feishu)</SelectItem>
                      <SelectItem value="dingtalk">钉钉机器人 (DingTalk)</SelectItem>
                      <SelectItem value="wecom">企业微信 (WeCom)</SelectItem>
                      <SelectItem value="telegram">Telegram Bot</SelectItem>
                      <SelectItem value="webhook">通用 JSON Webhook</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">漏洞推送最低危险等级</Label>
                  <Select value={notifyMinSev} onValueChange={setNotifyMinSev}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="严重">仅严重</SelectItem>
                      <SelectItem value="高危">高危及以上</SelectItem>
                      <SelectItem value="中危">中危及以上</SelectItem>
                      <SelectItem value="低危">全部等级</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <Label className="text-xs">控制台访问基地址（用于卡片直达链接）</Label>
                  <Input
                    placeholder="例如：http://127.0.0.1:18800"
                    value={notifyConsoleUrl}
                    onChange={(e) => setNotifyConsoleUrl(e.target.value)}
                  />
                </div>
              </div>

              {notifyChannel === "telegram" ? (
                <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
                  <div className="space-y-1.5">
                    <Label className="text-xs flex items-center justify-between">
                      <span>Telegram Bot Token</span>
                      <Badge variant={notifyTgTokenSet ? "default" : "secondary"}>
                        {notifyTgTokenSet ? "已配置" : "未设置"}
                      </Badge>
                    </Label>
                    <Input
                      type="password"
                      placeholder={notifyTgTokenSet ? "留空保持原 Token 不变" : "123456:ABC-DEF..."}
                      value={notifyTgToken}
                      onChange={(e) => setNotifyTgToken(e.target.value)}
                    />
                  </div>
                  <div className="space-y-1.5">
                    <Label className="text-xs">Chat ID</Label>
                    <Input
                      placeholder="-1001234567890"
                      value={notifyTgChat}
                      onChange={(e) => setNotifyTgChat(e.target.value)}
                    />
                  </div>
                </div>
              ) : (
                <div className="space-y-1.5">
                  <Label className="text-xs flex items-center justify-between">
                    <span>Webhook URL</span>
                    <Badge variant={notifyWebhookSet ? "default" : "secondary"}>
                      {notifyWebhookSet ? "已配置" : "未设置"}
                    </Badge>
                  </Label>
                  <Input
                    type="password"
                    placeholder={notifyWebhookSet ? "留空保持现有 Webhook 不变" : "https://open.feishu.cn/open-apis/bot/v2/hook/..."}
                    value={notifyWebhook}
                    onChange={(e) => setNotifyWebhook(e.target.value)}
                  />
                </div>
              )}

              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <div className="flex items-center justify-between rounded-lg border p-3 text-xs">
                  <span>AI 初审通过高危漏洞</span>
                  <Switch checked={notifyOnFinding} onCheckedChange={setNotifyOnFinding} />
                </div>
                <div className="flex items-center justify-between rounded-lg border p-3 text-xs">
                  <span>命令拦截等待人工审批</span>
                  <Switch checked={notifyOnIntercept} onCheckedChange={setNotifyOnIntercept} />
                </div>
                <div className="flex items-center justify-between rounded-lg border p-3 text-xs">
                  <span>任务完成或异常熔断</span>
                  <Switch checked={notifyOnTaskDone} onCheckedChange={setNotifyOnTaskDone} />
                </div>
              </div>

              <div className="flex flex-wrap justify-end gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={testingNotify}
                  onClick={async () => {
                    setTestingNotify(true);
                    try {
                      const res = await riddleApi.testNotify({
                        enabled: notifyEnabled,
                        channel: notifyChannel,
                        ...(notifyWebhook.trim() ? { webhook_url: notifyWebhook.trim() } : {}),
                        ...(notifyTgToken.trim() ? { telegram_bot_token: notifyTgToken.trim() } : {}),
                        telegram_chat_id: notifyTgChat.trim(),
                        console_base_url: notifyConsoleUrl.trim(),
                        min_severity: notifyMinSev,
                      });
                      if (res.ok) {
                        toast.success(`测试告警发送成功 (${res.latency_ms ?? 0}ms)`);
                      } else {
                        toast.error(`发送失败：${res.error || "未知错误"}`);
                      }
                      const hist = await riddleApi.getNotifyHistory(20);
                      setNotifyHistory(hist.items ?? []);
                    } catch (err) {
                      toast.error(`测试失败：${err instanceof Error ? err.message : String(err)}`);
                    } finally {
                      setTestingNotify(false);
                    }
                  }}
                >
                  <Send className="mr-1.5 size-3.5" /> {testingNotify ? "发送中…" : "发送测试告警"}
                </Button>
                <Button
                  size="sm"
                  disabled={saving}
                  onClick={async () => {
                    setSaving(true);
                    try {
                      await riddleApi.putNotifyConfig({
                        enabled: notifyEnabled,
                        channel: notifyChannel,
                        ...(notifyWebhook.trim() ? { webhook_url: notifyWebhook.trim() } : {}),
                        ...(notifyTgToken.trim() ? { telegram_bot_token: notifyTgToken.trim() } : {}),
                        telegram_chat_id: notifyTgChat.trim(),
                        console_base_url: notifyConsoleUrl.trim(),
                        min_severity: notifyMinSev,
                        on_finding_accepted: notifyOnFinding,
                        on_intercept_pending: notifyOnIntercept,
                        on_task_done: notifyOnTaskDone,
                      });
                      toast.success("告警通知配置已保存并热生效");
                      await loadAll();
                    } catch (err) {
                      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
                    } finally {
                      setSaving(false);
                    }
                  }}
                >
                  <Save className="mr-1.5 size-3.5" /> 保存通知配置
                </Button>
              </div>
            </CardContent>
          </Card>

          {notifyHistory.length > 0 ? (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">近期告警投递记录</CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 text-xs">
                {notifyHistory.slice(0, 10).map((item, idx) => (
                  <div key={idx} className="flex flex-wrap items-center justify-between gap-2 rounded border px-3 py-2">
                    <div className="flex items-center gap-2">
                      <Badge variant={item.ok ? "default" : "destructive"}>{item.ok ? "成功" : "失败"}</Badge>
                      <Badge variant="outline" className="uppercase">{String(item.channel ?? "")}</Badge>
                      <span className="font-medium">{String(item.title ?? "")}</span>
                    </div>
                    <span className="text-muted-foreground">
                      {item.error ? String(item.error) : `${Number(item.latency_ms ?? 0)}ms · ${String(item.ts ?? "").slice(11, 19)}`}
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}
