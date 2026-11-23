"use client";

import * as React from "react";
import { Database, Flame, GitBranch, Play, Radar, RefreshCw, RotateCcw, Search, ShieldBan, Sparkles, Zap } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  riddleApi,
  type AssetCompanyItem,
  type AssetsOverviewResponse,
  type HardTargetsStats,
  type KillsweepItem,
  type RiddleTarget,
  type RiddleTask,
} from "@/lib/riddle-api";
import { AssetAutoCollectPanel } from "./_components/asset-auto-collect";
import { DualGraphViewer } from "./_components/dual-graph-viewer";
import { GlobalAssetLibrary } from "./_components/global-asset-library";

export default function AssetsAndHardTargetsPage() {
  const [tasks, setTasks] = React.useState<RiddleTask[]>([]);
  const [selectedTaskId, setSelectedTaskId] = React.useState<string>("");

  // Dual-Graph Asset Center & Auto-Collect Meta
  const [assetOverview, setAssetOverview] = React.useState<AssetsOverviewResponse | null>(null);
  const [companies, setCompanies] = React.useState<AssetCompanyItem[]>([]);
  const [graphRefreshToken, setGraphRefreshToken] = React.useState(0);

  const loadAssetMeta = React.useCallback(async () => {
    try {
      const [ov, comp] = await Promise.all([
        riddleApi.getAssetsOverview(),
        riddleApi.listAssetCompanies(),
      ]);
      setAssetOverview(ov);
      setCompanies(comp.companies ?? []);
      setGraphRefreshToken((n) => n + 1);
    } catch {
      // ignore transient error
    }
  }, []);

  // Tab 1: Task Targets
  const [targetStatus, setTargetStatus] = React.useState("all");
  const [targetSearch, setTargetSearch] = React.useState("");
  const [targets, setTargets] = React.useState<RiddleTarget[]>([]);
  const [targetsLoading, setTargetsLoading] = React.useState(false);

  // Tab 2: Global Hard Targets
  const [hardStats, setHardStats] = React.useState<HardTargetsStats | null>(null);
  const [hardStatus, setHardStatus] = React.useState("all");
  const [hardQuery, setHardQuery] = React.useState("");
  const [hardItems, setHardItems] = React.useState<RiddleTarget[]>([]);
  const [hardTotal, setHardTotal] = React.useState(0);
  const [hardLoading, setHardLoading] = React.useState(false);
  const [selectedHardIds, setSelectedHardIds] = React.useState<string[]>([]);
  const [injectIntel, setInjectIntel] = React.useState(true);
  const [reviving, setReviving] = React.useState(false);
  const [revivedTaskIds, setRevivedTaskIds] = React.useState<string[]>([]);

  // Tab 3: Killsweep
  const [killsweeps, setKillsweeps] = React.useState<KillsweepItem[]>([]);
  const [ksLoading, setKsLoading] = React.useState(false);
  const [ksOnlyHits, setKsOnlyHits] = React.useState(false);

  const loadTasks = React.useCallback(async () => {
    try {
      const list = await riddleApi.listTasks();
      setTasks(list);
      if (list.length > 0 && !selectedTaskId) {
        setSelectedTaskId(list[0].id);
      }
    } catch (err) {
      toast.error(`加载任务失败：${err instanceof Error ? err.message : String(err)}`);
    }
  }, [selectedTaskId]);

  const loadHardTargets = React.useCallback(async () => {
    setHardLoading(true);
    try {
      const [statsRes, listRes] = await Promise.all([
        riddleApi.getHardTargetsStats(),
        riddleApi.listHardTargets({ status: hardStatus, q: hardQuery.trim() || undefined, limit: 100 }),
      ]);
      setHardStats(statsRes);
      setHardItems(listRes.items ?? []);
      setHardTotal(listRes.total ?? 0);
      setSelectedHardIds([]);
    } catch (err) {
      toast.error(`加载硬骨头库失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setHardLoading(false);
    }
  }, [hardStatus, hardQuery]);

  const loadTaskTargets = React.useCallback(async () => {
    if (!selectedTaskId) return;
    setTargetsLoading(true);
    try {
      const data = await riddleApi.getTaskTargets(selectedTaskId, targetStatus, 200);
      setTargets(data);
    } catch (err) {
      toast.error(`加载目标池失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setTargetsLoading(false);
    }
  }, [selectedTaskId, targetStatus]);

  const loadKillsweeps = React.useCallback(async () => {
    if (!selectedTaskId) return;
    setKsLoading(true);
    try {
      const data = await riddleApi.listKillsweeps(selectedTaskId, { only_hits: ksOnlyHits });
      setKillsweeps(data);
    } catch (err) {
      toast.error(`加载通杀候选失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setKsLoading(false);
    }
  }, [selectedTaskId, ksOnlyHits]);

  React.useEffect(() => {
    void loadTasks();
    void loadHardTargets();
    void loadAssetMeta();
  }, [loadTasks, loadHardTargets, loadAssetMeta]);

  React.useEffect(() => {
    if (selectedTaskId) {
      void loadTaskTargets();
      void loadKillsweeps();
    }
  }, [selectedTaskId, loadTaskTargets, loadKillsweeps]);

  const filteredTargets = React.useMemo(() => {
    const q = targetSearch.trim().toLowerCase();
    if (!q) return targets;
    return targets.filter(
      (t) =>
        (t.host || "").toLowerCase().includes(q) ||
        (t.url || "").toLowerCase().includes(q) ||
        (t.title || "").toLowerCase().includes(q) ||
        (t.school || "").toLowerCase().includes(q) ||
        (t.org || "").toLowerCase().includes(q),
    );
  }, [targets, targetSearch]);

  const handleSkipTarget = async (t: RiddleTarget) => {
    if (!selectedTaskId) return;
    try {
      await riddleApi.skipTaskTarget(selectedTaskId, t.id);
      toast.success(`已跳过目标：${t.host || t.url}`);
      await loadTaskTargets();
    } catch (err) {
      toast.error(`跳过失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleRevive = async (ids?: string[]) => {
    setReviving(true);
    try {
      const res = await riddleApi.reviveHardTargets({
        target_ids: ids && ids.length > 0 ? ids : undefined,
        status: hardStatus,
        q: hardQuery.trim() || undefined,
        limit: 50,
        inject_latest_intel: injectIntel,
      });
      const count = Number(res.revived_count ?? res.revived ?? res.count ?? 0);
      const tids = Array.isArray(res.task_ids) ? (res.task_ids as string[]) : [];
      setRevivedTaskIds(tids);
      toast.success(`唤醒回捞成功：已重置 ${count} 个硬骨头目标重新入队`);
      await loadHardTargets();
    } catch (err) {
      toast.error(`回捞失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setReviving(false);
    }
  };

  const handleKillsweepAction = async (
    k: KillsweepItem,
    action: "retry" | "enqueue" | "invalidate",
  ) => {
    try {
      if (action === "retry") {
        await riddleApi.retryKillsweep(k.task_id, k.id);
        toast.success(`已重启通杀分析：${k.product_name || k.origin_title}`);
      } else if (action === "enqueue") {
        const res = await riddleApi.enqueueKillsweep(k.task_id, k.id, 3);
        toast.success(`已入队 ${res.enqueued ?? 3} 个通杀验证站点`);
      } else {
        await riddleApi.invalidateKillsweep(k.task_id, k.id);
        toast.success("已将该通杀记录标记无效");
      }
      await loadKillsweeps();
    } catch (err) {
      toast.error(`操作失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="双图资产中心与自动收集工作台"
        description="全局共享六类资产真值库（企业/根域/子域/IP/服务/应用/接口）、资产图 × 探索图双图血缘拓扑、多源自动资产收集，以及硬骨头与通杀调度。"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              void loadAssetMeta();
              void loadHardTargets();
              void loadTaskTargets();
              void loadKillsweeps();
            }}
          >
            <RefreshCw className="mr-1.5 size-3.5" />
            刷新全部
          </Button>
        }
      />

      <Tabs defaultValue="library" className="space-y-4">
        <TabsList className="flex flex-wrap h-auto gap-1">
          <TabsTrigger value="library">
            <Database className="mr-1.5 size-3.5" />
            双图资产库 ({assetOverview?.total_assets ?? 0})
          </TabsTrigger>
          <TabsTrigger value="dualgraph">
            <GitBranch className="mr-1.5 size-3.5" />
            双图拓扑
          </TabsTrigger>
          <TabsTrigger value="collect">
            <Radar className="mr-1.5 size-3.5" />
            资产自动收集
            {(assetOverview?.running_jobs ?? 0) > 0 ? (
              <Badge variant="default" className="ml-1.5 h-4 px-1 text-[10px]">
                {assetOverview?.running_jobs} 运行中
              </Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="hard">
            <Flame className="mr-1.5 size-3.5" />
            硬骨头库 ({hardStats?.total ?? 0})
          </TabsTrigger>
          <TabsTrigger value="targets">探测目标池 ({targets.length})</TabsTrigger>
          <TabsTrigger value="killsweep">
            <Zap className="mr-1.5 size-3.5" />
            通杀候选 ({killsweeps.length})
          </TabsTrigger>
        </TabsList>

        <TabsContent value="library" className="space-y-4">
          <GlobalAssetLibrary
            overview={assetOverview}
            companies={companies}
            onReloadAll={() => void loadAssetMeta()}
          />
        </TabsContent>

        <TabsContent value="dualgraph" className="space-y-4">
          <DualGraphViewer
            tasks={tasks}
            companies={companies}
            refreshToken={graphRefreshToken}
          />
        </TabsContent>

        <TabsContent value="collect" className="space-y-4">
          <AssetAutoCollectPanel
            companies={companies}
            overview={assetOverview}
            onAssetsUpdated={() => void loadAssetMeta()}
          />
        </TabsContent>

        {/* Tab 2 first by usefulness: Global Hard Targets Revive */}
        <TabsContent value="hard" className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">硬骨头与跳过总数</CardDescription>
                <CardTitle className="text-2xl tabular-nums">{hardStats?.total ?? 0}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">死磕超限 (dead)</CardDescription>
                <CardTitle className="text-2xl tabular-nums text-amber-600 dark:text-amber-400">
                  {hardStats?.dead ?? 0}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">低分/人工跳过 (skipped)</CardDescription>
                <CardTitle className="text-2xl tabular-nums">{hardStats?.skipped ?? 0}</CardTitle>
              </CardHeader>
            </Card>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[220px]">
                <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
                <Input
                  placeholder="搜索主机、学校、原因、任务…"
                  value={hardQuery}
                  onChange={(e) => setHardQuery(e.target.value)}
                  className="pl-8"
                />
              </div>
              <Select value={hardStatus} onValueChange={setHardStatus}>
                <SelectTrigger className="w-[140px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部硬骨头</SelectItem>
                  <SelectItem value="dead">dead (死磕失败)</SelectItem>
                  <SelectItem value="skipped">skipped (已跳过)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <label className="flex cursor-pointer items-center gap-2 text-xs">
                <Checkbox checked={injectIntel} onCheckedChange={(v) => setInjectIntel(Boolean(v))} />
                <span>唤醒时注入最新全局沉淀情报</span>
              </label>
              {selectedHardIds.length > 0 ? (
                <Button size="sm" disabled={reviving} onClick={() => void handleRevive(selectedHardIds)}>
                  <RotateCcw className="mr-1.5 size-3.5" />
                  唤醒选中 ({selectedHardIds.length})
                </Button>
              ) : null}
              <Button size="sm" variant="secondary" disabled={reviving || hardTotal === 0} onClick={() => void handleRevive()}>
                <Sparkles className="mr-1.5 size-3.5" />
                按当前条件回捞前 50 条
              </Button>
            </div>
          </div>

          {revivedTaskIds.length > 0 ? (
            <Card className="border-emerald-500/40 bg-emerald-500/5">
              <CardContent className="flex flex-wrap items-center justify-between gap-3 p-3 text-xs">
                <span>
                  硬骨头目标已重新入队，涉及 <b>{revivedTaskIds.length}</b> 个任务（若任务处于暂停/停止状态需启动后继续挖掘）。
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    onClick={async () => {
                      let ok = 0;
                      for (const tid of revivedTaskIds) {
                        try {
                          await riddleApi.startTask(tid);
                          ok += 1;
                        } catch {
                          // task may already be running
                        }
                      }
                      toast.success(`已向 ${ok} 个涉及任务发送启动指令`);
                      setRevivedTaskIds([]);
                    }}
                  >
                    <Play className="mr-1.5 size-3.5" /> 立即启动涉及任务
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setRevivedTaskIds([])}>
                    关闭
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : null}

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={hardItems.length > 0 && selectedHardIds.length === hardItems.length}
                        onCheckedChange={(checked) =>
                          setSelectedHardIds(checked ? hardItems.map((i) => i.id) : [])
                        }
                      />
                    </TableHead>
                    <TableHead>目标主机 / 标题</TableHead>
                    <TableHead>所属任务与机构</TableHead>
                    <TableHead>评分 / 状态</TableHead>
                    <TableHead>失败 / 跳过原因</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {hardLoading ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        正在检索全球硬骨头目标…
                      </TableCell>
                    </TableRow>
                  ) : hardItems.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        当前筛选下暂无 dead / skipped 硬骨头目标。
                      </TableCell>
                    </TableRow>
                  ) : (
                    hardItems.map((it) => {
                      const checked = selectedHardIds.includes(it.id);
                      return (
                        <TableRow key={it.id}>
                          <TableCell>
                            <Checkbox
                              checked={checked}
                              onCheckedChange={(v) =>
                                setSelectedHardIds((prev) =>
                                  v ? [...prev, it.id] : prev.filter((x) => x !== it.id),
                                )
                              }
                            />
                          </TableCell>
                          <TableCell className="max-w-[280px]">
                            <div className="truncate font-mono text-xs font-medium">{it.url || it.host}</div>
                            <div className="truncate text-xs text-muted-foreground">{it.title || it.ip || "-"}</div>
                          </TableCell>
                          <TableCell className="text-xs">
                            <div className="font-medium">{it.task_name || it.task_id}</div>
                            <div className="text-muted-foreground">{it.school || it.org || "-"}</div>
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center gap-1.5">
                              <Badge variant={it.status === "dead" ? "destructive" : "secondary"} className="text-xs">
                                {it.status}
                              </Badge>
                              <span className="text-xs tabular-nums text-muted-foreground">
                                {Number(it.priority_score ?? 0).toFixed(1)}
                              </span>
                            </div>
                          </TableCell>
                          <TableCell className="max-w-[300px] truncate text-xs text-muted-foreground">
                            {it.dead_reason || it.last_error || it.priority_reason || "-"}
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

        {/* Tab 1: Per-Task Target Pool */}
        <TabsContent value="targets" className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <Select value={selectedTaskId} onValueChange={setSelectedTaskId}>
              <SelectTrigger className="w-[240px]">
                <SelectValue placeholder="选择任务" />
              </SelectTrigger>
              <SelectContent>
                {tasks.map((t) => (
                  <SelectItem key={t.id} value={t.id}>
                    {t.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={targetStatus} onValueChange={setTargetStatus}>
              <SelectTrigger className="w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部目标状态</SelectItem>
                <SelectItem value="alive">队列 / 探测中</SelectItem>
                <SelectItem value="done">已完成</SelectItem>
                <SelectItem value="dead">硬骨头 (dead)</SelectItem>
                <SelectItem value="skipped">已跳过</SelectItem>
              </SelectContent>
            </Select>
            <div className="relative min-w-[200px] flex-1 max-w-sm">
              <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
              <Input
                placeholder="筛选 URL、标题、学校…"
                value={targetSearch}
                onChange={(e) => setTargetSearch(e.target.value)}
                className="pl-8"
              />
            </div>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>目标 URL / 标题</TableHead>
                    <TableHead>学校 / 机构</TableHead>
                    <TableHead>优先级</TableHead>
                    <TableHead>状态 / 裁决</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {targetsLoading ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        正在加载任务目标池…
                      </TableCell>
                    </TableRow>
                  ) : filteredTargets.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        当前任务下暂无匹配目标。
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredTargets.map((t) => (
                      <TableRow key={t.id}>
                        <TableCell className="max-w-[320px]">
                          <div className="truncate font-mono text-xs font-medium">{t.url || t.host}</div>
                          <div className="truncate text-xs text-muted-foreground">{t.title || t.ip || "-"}</div>
                        </TableCell>
                        <TableCell className="text-xs">{t.school || t.org || "-"}</TableCell>
                        <TableCell className="text-xs tabular-nums">
                          <span className="font-medium">{Number(t.priority_score ?? 0).toFixed(1)}</span>
                          {t.is_edu ? <Badge variant="outline" className="ml-1.5 text-[11px]">EDU</Badge> : null}
                        </TableCell>
                        <TableCell>
                          <Badge variant={t.status === "done" ? "default" : "secondary"} className="text-xs">
                            {t.status}
                          </Badge>
                          {t.verdict ? <span className="ml-1.5 text-xs text-muted-foreground">{t.verdict}</span> : null}
                        </TableCell>
                        <TableCell className="text-right">
                          {t.status === "queued" || t.status === "scanning" ? (
                            <Button variant="ghost" size="sm" onClick={() => void handleSkipTarget(t)}>
                              <ShieldBan className="mr-1 size-3.5" /> 跳过
                            </Button>
                          ) : null}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 3: Killsweep */}
        <TabsContent value="killsweep" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <Select value={selectedTaskId} onValueChange={setSelectedTaskId}>
                <SelectTrigger className="w-[240px]">
                  <SelectValue placeholder="选择任务" />
                </SelectTrigger>
                <SelectContent>
                  {tasks.map((t) => (
                    <SelectItem key={t.id} value={t.id}>
                      {t.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <label className="flex cursor-pointer items-center gap-2 text-xs">
                <Checkbox checked={ksOnlyHits} onCheckedChange={(v) => setKsOnlyHits(Boolean(v))} />
                <span>仅看确认可通杀命中</span>
              </label>
            </div>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>通杀产品与源漏洞</TableHead>
                    <TableHead>FOFA 扩面语句</TableHead>
                    <TableHead>测绘命中 / 衍生洞</TableHead>
                    <TableHead>状态</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {ksLoading ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        正在加载通杀 Hunter 记录…
                      </TableCell>
                    </TableRow>
                  ) : killsweeps.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        暂无通杀记录（在「漏洞与复审」中人工通过任意漏洞后将自动触发通杀分析）。
                      </TableCell>
                    </TableRow>
                  ) : (
                    killsweeps.map((k) => (
                      <TableRow key={k.id}>
                        <TableCell className="max-w-[280px]">
                          <div className="truncate font-medium text-sm">
                            {k.product_name || k.vuln_type || "通杀分析"}
                          </div>
                          <div className="truncate text-xs text-muted-foreground">
                            源漏洞：{k.origin_title || k.vuln_summary}
                          </div>
                        </TableCell>
                        <TableCell className="max-w-[260px] truncate font-mono text-xs text-muted-foreground">
                          {k.fofa_query || k.fingerprint || "-"}
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">
                          资产 {k.asset_count} (高校 {k.edu_count}) · 衍生洞 {k.derived_count}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-1.5">
                            <Badge variant={k.is_killsweep ? "default" : "secondary"}>{k.status || "pending"}</Badge>
                            {k.verified ? <Badge variant="outline">已验证站点</Badge> : null}
                          </div>
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="inline-flex items-center gap-1">
                            {k.has_sites ? (
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => void handleKillsweepAction(k, "enqueue")}
                              >
                                <Play className="mr-1 size-3.5" /> 入队 3 站
                              </Button>
                            ) : null}
                            {k.retryable ? (
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => void handleKillsweepAction(k, "retry")}
                              >
                                重试
                              </Button>
                            ) : null}
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => void handleKillsweepAction(k, "invalidate")}
                            >
                              标记无效
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
