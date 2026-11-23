"use client";

import * as React from "react";
import { Flame, RefreshCw, Search, ShieldCheck, Sparkles, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { riddleApi, type CveFeedItem, type IntelItem, type IntelStats } from "@/lib/riddle-api";

const KIND_LABELS: Record<string, string> = {
  cred: "凭证凭据",
  fingerprint: "指纹产品",
  endpoint: "敏感端点",
  profile: "目标画像",
  lesson: "避坑经验",
  cve_feed: "CVE 时间流",
};

export default function VulnIntelPage() {
  // Tab 1: Cross-Task Practical Intel + Curator
  const [stats, setStats] = React.useState<IntelStats | null>(null);
  const [intelItems, setIntelItems] = React.useState<IntelItem[]>([]);
  const [kindFilter, setKindFilter] = React.useState("all");
  const [confFilter, setConfFilter] = React.useState("all");
  const [search, setSearch] = React.useState("");
  const [loadingIntel, setLoadingIntel] = React.useState(true);
  const [curatorPreview, setCuratorPreview] = React.useState<Record<string, unknown> | null>(null);

  // Tab 2: CVE / KEV Feed
  const [cves, setCves] = React.useState<CveFeedItem[]>([]);
  const [syncingCve, setSyncingCve] = React.useState(false);

  // Tab 3: Semantic Version Range Match
  const [techInput, setTechInput] = React.useState("Apache Shiro 1.7.0\nSpring Boot 2.6.3\nNginx 1.20.1");
  const [includeUnaffected, setIncludeUnaffected] = React.useState(false);
  const [matchResults, setMatchResults] = React.useState<Array<Record<string, unknown>>>([]);
  const [matching, setMatching] = React.useState(false);

  const loadIntel = React.useCallback(async () => {
    setLoadingIntel(true);
    try {
      const [sRes, lRes] = await Promise.all([
        riddleApi.getIntelStats(),
        riddleApi.listIntel({
          kind: kindFilter,
          confidence: confFilter,
          q: search.trim() || undefined,
          limit: 300,
        }),
      ]);
      setStats(sRes);
      setIntelItems(lRes);
    } catch (err) {
      toast.error(`加载情报失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoadingIntel(false);
    }
  }, [kindFilter, confFilter, search]);

  const loadCves = React.useCallback(async () => {
    try {
      const res = await riddleApi.getRecentCves(100);
      setCves(res.items ?? []);
    } catch (err) {
      toast.error(`加载 CVE 失败：${err instanceof Error ? err.message : String(err)}`);
    }
  }, []);

  React.useEffect(() => {
    void loadIntel();
  }, [loadIntel]);

  React.useEffect(() => {
    void loadCves();
  }, [loadCves]);

  const handleApplyCurate = async () => {
    try {
      const res = await riddleApi.applyCurateIntel(1000);
      setCuratorPreview(res);
      toast.success(`Curator 清理完成：已删除 ${Number(res.deleted ?? res.pruned ?? 0)} 条过期低价值情报`);
      await loadIntel();
    } catch (err) {
      toast.error(`执行清理失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDeleteIntel = async (id: string) => {
    try {
      await riddleApi.deleteIntel(id);
      toast.success("已删除情报");
      await loadIntel();
    } catch (err) {
      toast.error(`删除失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSyncCves = async () => {
    setSyncingCve(true);
    try {
      const res = await riddleApi.syncCves();
      toast.success(`CVE 同步完成：新增/更新 ${Number(res.stored ?? res.synced ?? 0)} 条`);
      await loadCves();
    } catch (err) {
      toast.error(`CVE 同步失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSyncingCve(false);
    }
  };

  const handleMatchVersions = async () => {
    const techs = techInput
      .split(/\r?\n/)
      .map((s) => s.trim())
      .filter(Boolean);
    if (techs.length === 0) {
      toast.error("请输入至少一条组件指纹与版本号");
      return;
    }
    setMatching(true);
    try {
      const res = await riddleApi.matchCveTechnologies(techs, includeUnaffected);
      setMatchResults(res.hints ?? []);
      toast.success(`反查命中 ${res.count ?? res.hints?.length ?? 0} 条关联情报`);
    } catch (err) {
      toast.error(`反查失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setMatching(false);
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="情报与 CVE 时间流"
        description="跨任务实战情报沉淀 (Utility 效用打分 + Intel Curator) · NVD/KEV 时间流同步 · 语义版本区间反查。"
        actions={
          <Button variant="outline" size="sm" onClick={() => { void loadIntel(); void loadCves(); }}>
            <RefreshCw className="mr-1.5 size-3.5" />
            刷新
          </Button>
        }
      />

      <Tabs defaultValue="practical" className="space-y-4">
        <TabsList>
          <TabsTrigger value="practical">实战情报沉淀 ({stats?.total ?? 0})</TabsTrigger>
          <TabsTrigger value="cve">CVE / KEV 时间流 ({cves.length})</TabsTrigger>
          <TabsTrigger value="match">语义版本反查</TabsTrigger>
        </TabsList>

        {/* Tab 1: Cross-Task Practical Intel */}
        <TabsContent value="practical" className="space-y-4">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-4">
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">累计情报总量</CardDescription>
                <CardTitle className="text-2xl tabular-nums">{stats?.total ?? 0}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">高可信 (verified)</CardDescription>
                <CardTitle className="text-2xl tabular-nums text-emerald-600 dark:text-emerald-400">
                  {stats?.verified ?? 0}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">跨任务复用 (hit &gt; 1)</CardDescription>
                <CardTitle className="text-2xl tabular-nums text-blue-600 dark:text-blue-400">
                  {stats?.reused ?? 0}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">情报分类覆盖</CardDescription>
                <CardTitle className="text-sm font-normal text-muted-foreground pt-1">
                  凭证 {stats?.by_kind?.cred ?? 0} · 指纹 {stats?.by_kind?.fingerprint ?? 0} · 端点{" "}
                  {stats?.by_kind?.endpoint ?? 0}
                </CardTitle>
              </CardHeader>
            </Card>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative min-w-[220px]">
                <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
                <Input
                  placeholder="检索 match_key、摘要、来源主机…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="pl-8"
                />
              </div>
              <Select value={kindFilter} onValueChange={setKindFilter}>
                <SelectTrigger className="w-[150px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部情报类型</SelectItem>
                  {Object.entries(KIND_LABELS).map(([k, v]) => (
                    <SelectItem key={k} value={k}>
                      {v}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={confFilter} onValueChange={setConfFilter}>
                <SelectTrigger className="w-[130px]">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">全部可信度</SelectItem>
                  <SelectItem value="verified">已验证</SelectItem>
                  <SelectItem value="likely">可能</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex items-center gap-2">
              <Button variant="secondary" size="sm" onClick={() => void handleApplyCurate()}>
                <Sparkles className="mr-1.5 size-3.5" /> 执行情报策展清理
              </Button>
            </div>
          </div>

          {curatorPreview ? (
            <Card className="border-amber-500/40 bg-amber-500/5">
              <CardContent className="p-3 text-xs">
                <span className="font-medium">Intel Curator 结果：</span>
                <span className="ml-2 text-muted-foreground">{JSON.stringify(curatorPreview)}</span>
              </CardContent>
            </Card>
          ) : null}

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>类型 / Match Key</TableHead>
                    <TableHead>情报摘要</TableHead>
                    <TableHead>效用分 / 命中复用</TableHead>
                    <TableHead>来源主机</TableHead>
                    <TableHead className="text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loadingIntel ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        正在加载跨任务实战情报…
                      </TableCell>
                    </TableRow>
                  ) : intelItems.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        当前筛选下暂无情报记录。
                      </TableCell>
                    </TableRow>
                  ) : (
                    intelItems.map((it) => (
                      <TableRow key={it.id}>
                        <TableCell className="max-w-[240px]">
                          <div className="flex items-center gap-1.5">
                            <Badge variant="outline" className="text-xs">
                              {KIND_LABELS[it.kind] ?? it.kind}
                            </Badge>
                            <Badge variant={it.confidence === "verified" ? "default" : "secondary"} className="text-[11px]">
                              {it.confidence}
                            </Badge>
                          </div>
                          <div className="mt-1 truncate font-mono text-xs">{it.match_key}</div>
                        </TableCell>
                        <TableCell className="max-w-[340px]">
                          <p className="line-clamp-2 text-xs text-muted-foreground">{it.summary || "-"}</p>
                        </TableCell>
                        <TableCell className="text-xs tabular-nums">
                          <div className="font-medium">效用 {it.utility_score}</div>
                          <div className="text-muted-foreground">
                            命中 {it.hit_count} · 注入 {it.injected_count} / 转化 {it.converted_count}
                          </div>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">{it.source_host || "-"}</TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" size="icon" onClick={() => void handleDeleteIntel(it.id)}>
                            <Trash2 className="size-4 text-destructive" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 2: CVE / KEV Feed */}
        <TabsContent value="cve" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              直接对接 NVD & CISA KEV 实时漏洞流，高 CVSS 漏洞自动走快车道注入 Worker 探索提示词。
            </p>
            <Button size="sm" disabled={syncingCve} onClick={() => void handleSyncCves()}>
              <RefreshCw className={`mr-1.5 size-3.5 ${syncingCve ? "animate-spin" : ""}`} />
              {syncingCve ? "正在同步 NVD / KEV…" : "立即同步最新 CVE / KEV"}
            </Button>
          </div>
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>CVE ID / KEV</TableHead>
                    <TableHead>CVSS</TableHead>
                    <TableHead>关联产品 / 组件</TableHead>
                    <TableHead>摘要描述</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {cves.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="h-24 text-center text-sm text-muted-foreground">
                        暂无已同步的 CVE / KEV 记录，请点击右上角立即同步。
                      </TableCell>
                    </TableRow>
                  ) : (
                    cves.map((c) => (
                      <TableRow key={c.cve_id || c.match_key}>
                        <TableCell className="font-mono text-xs font-semibold whitespace-nowrap">
                          <div className="flex items-center gap-1.5">
                            <span>{c.cve_id || c.match_key}</span>
                            {c.kev ? (
                              <Badge variant="destructive" className="text-[11px]">
                                <Flame className="mr-0.5 size-3" /> KEV
                              </Badge>
                            ) : null}
                          </div>
                        </TableCell>
                        <TableCell className="tabular-nums text-xs font-medium">
                          {Number(c.cvss ?? 0).toFixed(1)}
                        </TableCell>
                        <TableCell className="max-w-[200px] text-xs">
                          <div className="flex flex-wrap gap-1">
                            {(c.products ?? []).slice(0, 4).map((p) => (
                              <Badge key={p} variant="outline" className="text-[11px]">
                                {p}
                              </Badge>
                            ))}
                          </div>
                        </TableCell>
                        <TableCell className="max-w-[420px] text-xs text-muted-foreground">{c.summary}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 3: Semantic Version Range Match */}
        <TabsContent value="match" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">组件指纹 × 语义版本区间反查</CardTitle>
              <CardDescription className="text-xs">
                输入目标栈识别出的组件及版本号（每行一条），实时对照已落库 CVE 区间给出受影响结论与利用提示。
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              <Label className="text-xs">指纹与版本列表（每行一个，如 Apache Shiro 1.7.0）</Label>
              <Textarea
                rows={4}
                className="font-mono text-xs"
                value={techInput}
                onChange={(e) => setTechInput(e.target.value)}
              />
              <div className="flex flex-wrap items-center justify-between gap-2">
                <label className="flex cursor-pointer items-center gap-2 text-xs">
                  <Checkbox
                    checked={includeUnaffected}
                    onCheckedChange={(v) => setIncludeUnaffected(Boolean(v))}
                  />
                  <span>同时展示已知不受影响版本的排错说明</span>
                </label>
                <Button size="sm" disabled={matching} onClick={() => void handleMatchVersions()}>
                  <ShieldCheck className="mr-1.5 size-3.5" />
                  {matching ? "反查中…" : "执行版本区间反查"}
                </Button>
              </div>
            </CardContent>
          </Card>

          {matchResults.length > 0 ? (
            <div className="space-y-2">
              {matchResults.map((h, i) => (
                <Card key={i}>
                  <CardContent className="p-3 text-xs space-y-1">
                    <div className="flex flex-wrap items-center gap-2 font-medium">
                      <span className="font-mono">{String(h.cve_id ?? "")}</span>
                      <Badge variant="outline">CVSS {String(h.cvss ?? 0)}</Badge>
                      {h.affected === false ? (
                        <Badge variant="secondary">不受此区间影响</Badge>
                      ) : (
                        <Badge variant="default">命中受影响区间</Badge>
                      )}
                    </div>
                    <p className="text-muted-foreground">{String(h.reason ?? h.summary ?? JSON.stringify(h))}</p>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : null}
        </TabsContent>
      </Tabs>
    </div>
  );
}
