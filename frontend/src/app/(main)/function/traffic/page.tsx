"use client";

import * as React from "react";
import {
  Activity,
  FolderSearch,
  Link2,
  Loader2,
  RefreshCw,
  Search,
  Upload,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
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
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { riddleApi, type RiddleFinding, type RiddleTask } from "@/lib/riddle-api";

interface TrafficRow {
  id: string;
  role: string;
  method: string;
  url: string;
  status_code: number;
  request_head: string;
  response_head: string;
  body_sha256: string;
  finding_id: string;
  created_at: string;
}

const ROLE_META: Record<string, { label: string; variant: "default" | "secondary" | "outline" | "destructive" }> = {
  baseline: { label: "基线 (baseline)", variant: "outline" },
  proof: { label: "实证 (proof)", variant: "destructive" },
  verification: { label: "复验 (verification)", variant: "default" },
  supporting: { label: "佐证 (supporting)", variant: "secondary" },
};

function statusTone(code: number): string {
  if (code >= 500) return "text-rose-600 dark:text-rose-400 font-semibold";
  if (code >= 400) return "text-amber-600 dark:text-amber-400 font-medium";
  if (code >= 200 && code < 300) return "text-emerald-600 dark:text-emerald-400 font-medium";
  return "text-muted-foreground";
}

export default function TrafficLedgerPage() {
  const [tasks, setTasks] = React.useState<RiddleTask[]>([]);
  const [selectedTaskId, setSelectedTaskId] = React.useState("");
  const [trafficEnabled, setTrafficEnabled] = React.useState(false);

  const [items, setItems] = React.useState<TrafficRow[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [roleFilter, setRoleFilter] = React.useState("all");
  const [methodFilter, setMethodFilter] = React.useState("all");
  const [search, setSearch] = React.useState("");

  // Import Dialog
  const [importOpen, setImportOpen] = React.useState(false);
  const [discoveredDirs, setDiscoveredDirs] = React.useState<string[]>([]);
  const [customDir, setCustomDir] = React.useState("");
  const [importing, setImporting] = React.useState(false);

  // Inspector & Binding Sheet
  const [activeRow, setActiveRow] = React.useState<TrafficRow | null>(null);
  const [taskFindings, setTaskFindings] = React.useState<RiddleFinding[]>([]);
  const [bindFindingId, setBindFindingId] = React.useState("");
  const [bindRole, setBindRole] = React.useState("proof");
  const [binding, setBinding] = React.useState(false);

  React.useEffect(() => {
    Promise.allSettled([riddleApi.listTasks(), riddleApi.getFusionConfig()]).then(([tRes, fRes]) => {
      if (tRes.status === "fulfilled") {
        setTasks(tRes.value);
        if (tRes.value.length > 0) setSelectedTaskId(tRes.value[0].id);
      }
      if (fRes.status === "fulfilled") {
        setTrafficEnabled(Boolean(fRes.value.config.traffic_enabled));
      }
    });
  }, []);

  const loadTraffic = React.useCallback(async () => {
    if (!selectedTaskId) return;
    setLoading(true);
    try {
      const [trRes, fRes] = await Promise.allSettled([
        riddleApi.listFusionTraffic(selectedTaskId, 200),
        riddleApi.listTaskFindings(selectedTaskId, { limit: 100 }),
      ]);
      if (trRes.status === "fulfilled") setItems(trRes.value.items ?? []);
      if (fRes.status === "fulfilled") {
        const arr = Array.isArray(fRes.value) ? fRes.value : fRes.value.items ?? [];
        setTaskFindings(arr);
      }
    } catch (err) {
      toast.error(`加载实证流量失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [selectedTaskId]);

  React.useEffect(() => {
    void loadTraffic();
  }, [loadTraffic]);

  const filtered = React.useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((it) => {
      if (roleFilter !== "all" && it.role !== roleFilter) return false;
      if (methodFilter !== "all" && it.method.toUpperCase() !== methodFilter) return false;
      if (!q) return true;
      return (
        it.url.toLowerCase().includes(q) ||
        it.request_head.toLowerCase().includes(q) ||
        it.body_sha256.toLowerCase().includes(q)
      );
    });
  }, [items, roleFilter, methodFilter, search]);

  const openImportModal = async () => {
    setImportOpen(true);
    try {
      const res = await riddleApi.discoverTrafficDirs();
      setDiscoveredDirs(res.dirs ?? []);
    } catch {
      setDiscoveredDirs([]);
    }
  };

  const handleImport = async (dir = "") => {
    if (!selectedTaskId) {
      toast.error("请先选择一个目标任务");
      return;
    }
    setImporting(true);
    try {
      const res = await riddleApi.importTraffic(selectedTaskId, dir);
      toast.success(`导入完成：扫描 ${res.scanned_rows} 条，新增入库 ${res.imported} 条`);
      setImportOpen(false);
      await loadTraffic();
    } catch (err) {
      toast.error(`导入失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setImporting(false);
    }
  };

  const handleBind = async () => {
    if (!activeRow || !bindFindingId) {
      toast.error("请选择要绑定的漏洞记录");
      return;
    }
    setBinding(true);
    try {
      await riddleApi.bindFusionTraffic(bindFindingId, [activeRow.id], bindRole);
      toast.success("已成功绑定至漏洞证据链，导出公文报告时将自动收录");
      await loadTraffic();
      setActiveRow((prev) => (prev ? { ...prev, finding_id: bindFindingId, role: bindRole } : null));
    } catch (err) {
      toast.error(`绑定失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBinding(false);
    }
  };

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="实证流量库"
        description="按任务归集 executor 留痕的 HTTP 原始流量，支持 baseline / proof / verification / supporting 四类证据链绑定与公文报告引用。"
        actions={
          <>
            <Badge variant={trafficEnabled ? "default" : "secondary"} className="h-8 px-2.5 text-xs">
              <Activity className="mr-1.5 size-3.5" />
              流量留痕：{trafficEnabled ? "已开启" : "未开启"}
            </Badge>
            <Button variant="outline" size="sm" onClick={() => void openImportModal()}>
              <FolderSearch className="mr-1.5 size-3.5" /> 导入工作区 JSONL
            </Button>
            <Button variant="outline" size="sm" onClick={() => void loadTraffic()}>
              <RefreshCw className="mr-1.5 size-3.5" /> 刷新
            </Button>
          </>
        }
      />

      {/* Filter Bar */}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={selectedTaskId} onValueChange={setSelectedTaskId}>
          <SelectTrigger className="w-[230px]">
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
        <Select value={roleFilter} onValueChange={setRoleFilter}>
          <SelectTrigger className="w-[170px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部证据角色</SelectItem>
            <SelectItem value="proof">实证 (proof)</SelectItem>
            <SelectItem value="verification">复验 (verification)</SelectItem>
            <SelectItem value="baseline">基线 (baseline)</SelectItem>
            <SelectItem value="supporting">佐证 (supporting)</SelectItem>
          </SelectContent>
        </Select>
        <Select value={methodFilter} onValueChange={setMethodFilter}>
          <SelectTrigger className="w-[130px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部方法</SelectItem>
            <SelectItem value="GET">GET</SelectItem>
            <SelectItem value="POST">POST</SelectItem>
            <SelectItem value="PUT">PUT</SelectItem>
            <SelectItem value="DELETE">DELETE</SelectItem>
          </SelectContent>
        </Select>
        <div className="relative min-w-[200px] flex-1 max-w-md">
          <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
          <Input
            placeholder="搜索 URL、请求头或 SHA256…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8"
          />
        </div>
      </div>

      {/* Traffic Table */}
      <Card>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-[80px]">方法</TableHead>
                <TableHead className="w-[80px]">状态码</TableHead>
                <TableHead>请求 URL</TableHead>
                <TableHead className="w-[150px]">证据角色</TableHead>
                <TableHead className="w-[140px]">绑定状态</TableHead>
                <TableHead className="w-[130px]">摘要</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-24 text-center text-sm text-muted-foreground">
                    正在加载任务实证流量…
                  </TableCell>
                </TableRow>
              ) : filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="h-28 text-center text-sm text-muted-foreground">
                    当前任务暂无入库流量。可在「融合护栏与审批」开启流量留痕后，点击右上角「导入工作区 JSONL」。
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((row) => {
                  const meta = ROLE_META[row.role] ?? { label: row.role || "supporting", variant: "secondary" as const };
                  return (
                    <TableRow
                      key={row.id}
                      className="cursor-pointer hover:bg-muted/40"
                      onClick={() => {
                        setActiveRow(row);
                        setBindFindingId(row.finding_id || "");
                        setBindRole(row.role || "proof");
                      }}
                    >
                      <TableCell>
                        <Badge variant="outline" className="font-mono text-xs">
                          {row.method}
                        </Badge>
                      </TableCell>
                      <TableCell className={`font-mono text-xs tabular-nums ${statusTone(row.status_code)}`}>
                        {row.status_code || "-"}
                      </TableCell>
                      <TableCell className="max-w-[360px] truncate font-mono text-xs">{row.url}</TableCell>
                      <TableCell>
                        <Badge variant={meta.variant} className="text-[11px]">
                          {meta.label}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">
                        {row.finding_id ? (
                          <Badge variant="default" className="text-[11px]">
                            <Link2 className="mr-1 size-3" /> 已绑定漏洞
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground">未绑定</span>
                        )}
                      </TableCell>
                      <TableCell className="font-mono text-[11px] text-muted-foreground">
                        {(row.body_sha256 || "").slice(0, 12) || "-"}
                      </TableCell>
                    </TableRow>
                  );
                })
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Import Dialog */}
      <Dialog open={importOpen} onOpenChange={setImportOpen}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>从工作区导入实证流量 JSONL</DialogTitle>
            <DialogDescription>
              自动发现 executor 落盘的 <span className="font-mono">fusion_traffic.jsonl</span> 并按 SHA256 幂等去重入库。
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-3">
            {discoveredDirs.length > 0 ? (
              <div className="space-y-1.5">
                <Label className="text-xs">已发现的工作区目录（点击单项导入）</Label>
                <div className="space-y-1.5 max-h-48 overflow-y-auto">
                  {discoveredDirs.map((dir) => (
                    <div key={dir} className="flex items-center justify-between gap-2 rounded border px-2.5 py-1.5 text-xs">
                      <span className="truncate font-mono">{dir}</span>
                      <Button size="sm" variant="outline" disabled={importing} onClick={() => void handleImport(dir)}>
                        导入
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="rounded-lg border border-dashed p-4 text-center text-xs text-muted-foreground">
                当前工作区暂未扫描到 <span className="font-mono">fusion_traffic.jsonl</span> 文件，也可手动指定路径。
              </div>
            )}
            <div className="space-y-1.5">
              <Label className="text-xs">自定义目录路径（留空则全量扫描）</Label>
              <Input
                className="font-mono text-xs"
                placeholder="例如：work/target_xxx"
                value={customDir}
                onChange={(e) => setCustomDir(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setImportOpen(false)}>
              取消
            </Button>
            <Button disabled={importing} onClick={() => void handleImport(customDir.trim())}>
              {importing ? <Loader2 className="mr-1.5 size-4 animate-spin" /> : <Upload className="mr-1.5 size-4" />}
              {customDir.trim() ? "导入指定目录" : "一键全量扫描导入"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* HTTP Inspector & Finding Binding Sheet */}
      <Sheet open={Boolean(activeRow)} onOpenChange={(o) => !o && setActiveRow(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-2xl">
          <SheetHeader>
            <SheetTitle className="font-mono text-sm">
              {activeRow?.method} {activeRow?.status_code}
            </SheetTitle>
            <SheetDescription className="break-all font-mono text-xs">{activeRow?.url}</SheetDescription>
          </SheetHeader>
          {activeRow ? (
            <div className="mt-5 space-y-4">
              <div className="space-y-2 rounded-lg border p-3">
                <Label className="text-xs font-medium">绑定到漏洞证据链</Label>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                  <Select value={bindFindingId} onValueChange={setBindFindingId}>
                    <SelectTrigger className="sm:col-span-2">
                      <SelectValue placeholder="选择本任务漏洞…" />
                    </SelectTrigger>
                    <SelectContent>
                      {taskFindings.map((f) => (
                        <SelectItem key={f.id} value={f.id}>
                          {f.title}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select value={bindRole} onValueChange={setBindRole}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="proof">实证 (proof)</SelectItem>
                      <SelectItem value="verification">复验 (verification)</SelectItem>
                      <SelectItem value="baseline">基线 (baseline)</SelectItem>
                      <SelectItem value="supporting">佐证 (supporting)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <Button size="sm" disabled={binding || !bindFindingId} onClick={() => void handleBind()}>
                  <Link2 className="mr-1.5 size-3.5" /> 确认绑定证据
                </Button>
              </div>

              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">请求报文头 (request_head)</Label>
                <pre className="max-h-56 overflow-auto rounded-lg border bg-muted/35 p-3 font-mono text-xs whitespace-pre-wrap">
                  {activeRow.request_head || "(空)"}
                </pre>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs text-muted-foreground">响应报文头 (response_head)</Label>
                <pre className="max-h-56 overflow-auto rounded-lg border bg-muted/35 p-3 font-mono text-xs whitespace-pre-wrap">
                  {activeRow.response_head || "(空)"}
                </pre>
              </div>
            </div>
          ) : null}
        </SheetContent>
      </Sheet>
    </div>
  );
}
