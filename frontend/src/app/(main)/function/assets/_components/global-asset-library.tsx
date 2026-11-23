"use client";

import * as React from "react";
import { useRouter } from "next/navigation";
import {
  Building2,
  Database,
  Globe,
  LayoutTemplate,
  Link2,
  Loader2,
  Network,
  Plus,
  RefreshCw,
  Rocket,
  Search,
  Smartphone,
  Trash2,
  Upload,
} from "lucide-react";
import { toast } from "sonner";

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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import {
  riddleApi,
  type AssetCompanyItem,
  type AssetScopeRule,
  type AssetsOverviewResponse,
  type GlobalAssetItem,
} from "@/lib/riddle-api";

const CATEGORY_TABS = [
  { key: "all", label: "全部资产", icon: Database },
  { key: "company", label: "企业主体", icon: Building2 },
  { key: "root_domain", label: "根域名", icon: Globe },
  { key: "subdomain", label: "子域名", icon: Globe },
  { key: "ip", label: "IP", icon: Network },
  { key: "service", label: "服务", icon: LayoutTemplate },
  { key: "app", label: "应用", icon: Smartphone },
  { key: "endpoint", label: "接口", icon: Link2 },
] as const;

const DSL_HINTS = ["port:443", "status:200", "tech:nginx", "domain:edu.cn"];

function parseRulesText(raw: string): AssetScopeRule[] {
  const rules: AssetScopeRule[] = [];
  for (const line of raw.split(/\r?\n/)) {
    const clean = line.trim();
    if (!clean) continue;
    if (clean.includes(":")) {
      const [k, ...rest] = clean.split(":");
      const kind = k.trim().toLowerCase();
      const val = rest.join(":").trim();
      if (["domain", "ip", "cidr", "icp", "keyword"].includes(kind) && val) {
        rules.push({ kind, value: val });
        continue;
      }
    }
    if (clean.includes("/")) rules.push({ kind: "cidr", value: clean });
    else if (/^\d+\.\d+\.\d+\.\d+$/.test(clean)) rules.push({ kind: "ip", value: clean });
    else rules.push({ kind: "domain", value: clean });
  }
  return rules;
}

export function GlobalAssetLibrary({
  overview,
  companies,
  onReloadAll,
}: {
  overview: AssetsOverviewResponse | null;
  companies: AssetCompanyItem[];
  onReloadAll: () => void;
}) {
  const router = useRouter();

  const [category, setCategory] = React.useState<string>("all");
  const [companyFilter, setCompanyFilter] = React.useState<string>("all");
  const [query, setQuery] = React.useState("");
  const [items, setItems] = React.useState<GlobalAssetItem[]>([]);
  const [total, setTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(false);

  const [selectedIds, setSelectedIds] = React.useState<string[]>([]);
  const [syncing, setSyncing] = React.useState(false);
  const [launchingTask, setLaunchingTask] = React.useState(false);

  // Import modal
  const [importOpen, setImportOpen] = React.useState(false);
  const [importSeeds, setImportSeeds] = React.useState("");
  const [importCompanyId, setImportCompanyId] = React.useState("none");
  const [importing, setImporting] = React.useState(false);

  // Company modal
  const [companyOpen, setCompanyOpen] = React.useState(false);
  const [compName, setCompName] = React.useState("");
  const [compRulesText, setCompRulesText] = React.useState("");
  const [compNotes, setCompNotes] = React.useState("");
  const [savingComp, setSavingComp] = React.useState(false);

  const loadAssets = React.useCallback(async () => {
    if (category === "company") return;
    setLoading(true);
    try {
      const res = await riddleApi.listGlobalAssets({
        asset_type: category,
        company_id: companyFilter,
        q: query.trim() || undefined,
        limit: 150,
      });
      setItems(res.items ?? []);
      setTotal(res.total ?? 0);
      setSelectedIds([]);
    } catch (err) {
      toast.error(`加载资产库失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [category, companyFilter, query]);

  React.useEffect(() => {
    void loadAssets();
  }, [loadAssets]);

  const handleSyncFromTasks = async () => {
    setSyncing(true);
    try {
      const res = await riddleApi.syncAssetsFromTasks();
      const totalSynced = Object.entries(res.synced || {})
        .filter(([k]) => k !== "processed")
        .reduce((acc, [, v]) => acc + Number(v || 0), 0);
      toast.success(`同步完成：扫描 ${res.synced?.processed ?? 0} 条记录，新增入库 ${totalSynced} 项全局资产`);
      onReloadAll();
      await loadAssets();
    } catch (err) {
      toast.error(`同步失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSyncing(false);
    }
  };

  const handleManualImport = async () => {
    if (!importSeeds.trim()) return;
    setImporting(true);
    try {
      const res = await riddleApi.manualImportAssets({
        seeds_text: importSeeds.trim(),
        company_id: importCompanyId === "none" ? null : importCompanyId,
      });
      toast.success(`导入成功：新增 ${res.total_inserted} 项全局资产`);
      setImportSeeds("");
      setImportOpen(false);
      onReloadAll();
      await loadAssets();
    } catch (err) {
      toast.error(`导入失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setImporting(false);
    }
  };

  const handleCreateCompany = async () => {
    if (!compName.trim()) {
      toast.error("请输入企业或高校名称");
      return;
    }
    setSavingComp(true);
    try {
      const res = await riddleApi.createAssetCompany({
        name: compName.trim(),
        scope_rules: parseRulesText(compRulesText),
        notes: compNotes.trim(),
      });
      toast.success(`已创建主体「${res.company.name}」，自动认领 ${res.claimed_assets} 项存量资产`);
      setCompName("");
      setCompRulesText("");
      setCompNotes("");
      setCompanyOpen(false);
      onReloadAll();
    } catch (err) {
      toast.error(`创建主体失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSavingComp(false);
    }
  };

  const handleDeleteCompany = async (comp: AssetCompanyItem) => {
    try {
      await riddleApi.deleteAssetCompany(comp.id, false);
      toast.success(`已删除主体「${comp.name}」（关联资产已保留）`);
      onReloadAll();
    } catch (err) {
      toast.error(`删除主体失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleBatchDelete = async () => {
    if (selectedIds.length === 0) return;
    try {
      const res = await riddleApi.batchDeleteGlobalAssets(selectedIds);
      toast.success(`已删除 ${res.deleted} 项资产`);
      onReloadAll();
      await loadAssets();
    } catch (err) {
      toast.error(`批量删除失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleLaunchTask = async (companyIdOverride?: string) => {
    setLaunchingTask(true);
    try {
      const res = await riddleApi.createTaskFromAssets({
        asset_ids: companyIdOverride ? undefined : selectedIds,
        company_id: companyIdOverride ?? null,
        start_immediately: true,
      });
      toast.success(`已将 ${res.target_count} 个资产落盘为挖掘任务并启动`);
      router.push(`/function/tasks/detail?id=${encodeURIComponent(res.task.id)}`);
    } catch (err) {
      toast.error(`转挖掘任务失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLaunchingTask(false);
    }
  };

  const allSelected = items.length > 0 && selectedIds.length === items.length;

  return (
    <div className="space-y-4">
      {/* Category Pills */}
      <div className="flex flex-wrap items-center gap-1.5">
        {CATEGORY_TABS.map((tab) => {
          const Icon = tab.icon;
          const cnt =
            tab.key === "all"
              ? overview?.total_assets ?? 0
              : overview?.counts?.[tab.key] ?? 0;
          const active = category === tab.key;
          return (
            <Button
              key={tab.key}
              type="button"
              size="sm"
              variant={active ? "default" : "outline"}
              className="h-8 text-xs"
              onClick={() => setCategory(tab.key)}
            >
              <Icon className="mr-1.5 size-3.5" />
              {tab.label}
              <Badge variant={active ? "secondary" : "outline"} className="ml-1.5 h-4 px-1 text-[10px] tabular-nums">
                {cnt}
              </Badge>
            </Button>
          );
        })}
      </div>

      {/* Action & DSL Search Bar */}
      <div className="flex flex-wrap items-center gap-2">
        {category !== "company" ? (
          <>
            <div className="relative min-w-[220px] flex-1 max-w-md">
              <Search className="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-muted-foreground" />
              <Input
                className="h-9 pl-8 font-mono text-xs"
                placeholder="DSL 检索：port:443 status:200 tech:nginx domain:edu.cn …"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
            </div>
            <div className="hidden xl:flex items-center gap-1">
              {DSL_HINTS.map((hint) => (
                <button
                  key={hint}
                  type="button"
                  onClick={() => setQuery((prev) => (prev ? `${prev} ${hint}` : hint))}
                  className="rounded border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground hover:text-foreground"
                >
                  {hint}
                </button>
              ))}
            </div>
            <Select value={companyFilter} onValueChange={setCompanyFilter}>
              <SelectTrigger className="h-9 w-[170px] text-xs">
                <SelectValue placeholder="按归属主体筛选" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部企业/高校</SelectItem>
                {companies.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </>
        ) : null}

        <div className="ml-auto flex flex-wrap items-center gap-2">
          {selectedIds.length > 0 && category !== "company" ? (
            <>
              <Button size="sm" disabled={launchingTask} onClick={() => void handleLaunchTask()}>
                {launchingTask ? <Loader2 className="mr-1.5 size-3.5 animate-spin" /> : <Rocket className="mr-1.5 size-3.5" />}
                转挖掘任务 ({selectedIds.length})
              </Button>
              <Button size="sm" variant="destructive" onClick={() => void handleBatchDelete()}>
                <Trash2 className="mr-1.5 size-3.5" /> 删除
              </Button>
            </>
          ) : null}
          <Button size="sm" variant="outline" onClick={() => setCompanyOpen(true)}>
            <Plus className="mr-1 size-3.5" /> 新增主体
          </Button>
          <Button size="sm" variant="outline" onClick={() => setImportOpen(true)}>
            <Upload className="mr-1 size-3.5" /> 手动导入
          </Button>
          <Button size="sm" variant="secondary" disabled={syncing} onClick={() => void handleSyncFromTasks()}>
            <RefreshCw className={`mr-1.5 size-3.5 ${syncing ? "animate-spin" : ""}`} />
            同步历史任务资产
          </Button>
        </div>
      </div>

      {/* Main Table */}
      {category === "company" ? (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>企业 / 高校主体</TableHead>
                  <TableHead>范围规则（自动认领存量资产）</TableHead>
                  <TableHead className="w-[100px]">资产数</TableHead>
                  <TableHead className="w-[200px] text-right">操作</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {companies.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={4} className="h-24 text-center text-xs text-muted-foreground">
                      暂无企业/高校主体，点击「新增主体」配置域名/IP/CIDR 范围后将自动认领匹配资产。
                    </TableCell>
                  </TableRow>
                ) : (
                  companies.map((c) => (
                    <TableRow key={c.id}>
                      <TableCell>
                        <div className="font-medium text-sm">{c.name}</div>
                        {c.notes ? <div className="text-xs text-muted-foreground">{c.notes}</div> : null}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {(c.scope_rules ?? []).length === 0 ? (
                            <span className="text-xs text-muted-foreground">未配置自动范围规则</span>
                          ) : (
                            c.scope_rules.map((r, idx) => (
                              <Badge key={idx} variant="outline" className="font-mono text-[11px]">
                                {r.kind}:{r.value}
                              </Badge>
                            ))
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="tabular-nums font-medium">{c.asset_count}</TableCell>
                      <TableCell className="text-right">
                        <div className="inline-flex items-center gap-1.5">
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-7 text-xs"
                            disabled={c.asset_count === 0 || launchingTask}
                            onClick={() => void handleLaunchTask(c.id)}
                          >
                            <Rocket className="mr-1 size-3" /> 一键挖掘
                          </Button>
                          <Button
                            size="icon"
                            variant="ghost"
                            className="size-7 text-destructive"
                            onClick={() => void handleDeleteCompany(c)}
                          >
                            <Trash2 className="size-3.5" />
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
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-10">
                    <Checkbox
                      checked={allSelected}
                      onCheckedChange={(v) => setSelectedIds(v === true ? items.map((i) => i.id) : [])}
                    />
                  </TableHead>
                  <TableHead className="w-[95px]">类型</TableHead>
                  <TableHead>资产标识 / 标题</TableHead>
                  <TableHead className="w-[150px]">IP / 端口 / 状态</TableHead>
                  <TableHead className="w-[180px]">技术栈与归属</TableHead>
                  <TableHead className="w-[110px]">来源</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {loading ? (
                  <TableRow>
                    <TableCell colSpan={6} className="h-24 text-center text-xs text-muted-foreground">
                      正在加载全局资产库…
                    </TableCell>
                  </TableRow>
                ) : items.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="h-28 text-center text-xs text-muted-foreground">
                      暂无匹配资产（总计 {total}）。可点击右上角「同步历史任务资产」或切换到「资产自动收集」发起采集。
                    </TableCell>
                  </TableRow>
                ) : (
                  items.map((a) => (
                    <TableRow key={a.id}>
                      <TableCell>
                        <Checkbox
                          checked={selectedIds.includes(a.id)}
                          onCheckedChange={(v) =>
                            setSelectedIds((prev) =>
                              v === true ? [...prev, a.id] : prev.filter((id) => id !== a.id),
                            )
                          }
                        />
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="font-mono text-[11px]">
                          {a.asset_type}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-[340px]">
                        <div className="flex items-center gap-1.5">
                          {a.method ? (
                            <Badge variant="outline" className="h-4 px-1 font-mono text-[10px]">
                              {a.method}
                            </Badge>
                          ) : null}
                          <span className="truncate font-mono text-xs font-medium">{a.value}</span>
                        </div>
                        {a.title ? (
                          <div className="mt-0.5 truncate text-[11px] text-muted-foreground">{a.title}</div>
                        ) : a.root_domain ? (
                          <div className="mt-0.5 truncate text-[11px] text-muted-foreground">根域：{a.root_domain}</div>
                        ) : null}
                      </TableCell>
                      <TableCell className="font-mono text-xs">
                        <div className="flex flex-wrap items-center gap-1">
                          {a.ip ? <span>{a.ip}</span> : <span className="text-muted-foreground">-</span>}
                          {a.port ? <Badge variant="outline" className="h-4 px-1 text-[10px]">:{a.port}</Badge> : null}
                          {a.status_code ? (
                            <Badge
                              variant="outline"
                              className={[
                                "h-4 px-1 text-[10px]",
                                a.status_code < 300
                                  ? "text-emerald-600"
                                  : a.status_code < 400
                                    ? "text-blue-600"
                                    : "text-amber-600",
                              ].join(" ")}
                            >
                              {a.status_code}
                            </Badge>
                          ) : null}
                        </div>
                        {a.c_segment ? <div className="text-[10px] text-muted-foreground">{a.c_segment}</div> : null}
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {a.company_name ? (
                            <Badge variant="default" className="h-4 px-1.5 text-[10px]">
                              {a.company_name}
                            </Badge>
                          ) : null}
                          {(a.technologies ?? []).slice(0, 3).map((t) => (
                            <Badge key={t} variant="outline" className="h-4 px-1 text-[10px]">
                              {t}
                            </Badge>
                          ))}
                        </div>
                      </TableCell>
                      <TableCell className="text-[11px] text-muted-foreground">{a.source}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Manual Import Dialog */}
      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>手动导入资产到双图真值库</DialogTitle>
            <DialogDescription>
              每行输入一个根域名、URL、IP 或网段，系统将自动拆解归并六类资产并去重。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label className="text-xs">归属主体（可选）</Label>
              <Select value={importCompanyId} onValueChange={setImportCompanyId}>
                <SelectTrigger className="text-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">按范围规则自动归属</SelectItem>
                  {companies.map((c) => (
                    <SelectItem key={c.id} value={c.id}>
                      {c.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">资产清单</Label>
              <Textarea
                rows={5}
                className="font-mono text-xs"
                placeholder={"example.edu.cn\nhttps://oa.example.edu.cn/login\n10.10.1.5"}
                value={importSeeds}
                onChange={(e) => setImportSeeds(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>取消</Button>
            <Button disabled={importing || !importSeeds.trim()} onClick={() => void handleManualImport()}>
              {importing ? <Loader2 className="mr-1.5 size-4 animate-spin" /> : null}
              确认导入
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Create Company Dialog */}
      <Dialog open={companyOpen} onOpenChange={setCompanyOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>新增企业 / 高校主体与范围规则</DialogTitle>
            <DialogDescription>
              保存后系统将自动按范围规则认领所有匹配的存量资产（不会覆盖人工显式归属）。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            <div className="space-y-1.5">
              <Label className="text-xs">主体名称</Label>
              <Input
                placeholder="例如：XX 大学 / XX 科技有限公司"
                value={compName}
                onChange={(e) => setCompName(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">范围规则（每行一条，支持 domain: / ip: / cidr: / icp: / keyword: 前缀）</Label>
              <Textarea
                rows={4}
                className="font-mono text-xs"
                placeholder={"domain:example.edu.cn\ncidr:202.120.1.0/24\nicp:沪ICP备123456号"}
                value={compRulesText}
                onChange={(e) => setCompRulesText(e.target.value)}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">备注（可选）</Label>
              <Input
                placeholder="授权范围说明或 SRC 要求…"
                value={compNotes}
                onChange={(e) => setCompNotes(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setCompanyOpen(false)}>取消</Button>
            <Button disabled={savingComp || !compName.trim()} onClick={() => void handleCreateCompany()}>
              {savingComp ? <Loader2 className="mr-1.5 size-4 animate-spin" /> : null}
              创建并自动认领
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
