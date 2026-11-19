"use client";

import * as React from "react";
import { AlertTriangle, Pause, Play, Radio, RefreshCw, Search, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { sseUrl } from "@/lib/api";
import { riddleApi } from "@/lib/riddle-api";
import type { LogLine } from "@/lib/types";
import { cn } from "@/lib/utils";

const LEVEL_TONE: Record<string, string> = {
  error: "text-rose-600 dark:text-rose-400",
  warn: "text-amber-600 dark:text-amber-400",
  info: "text-foreground/80",
};

export default function RuntimeLogsPage() {
  // Tab 1: Structured Runtime Anomaly Logs
  const [stats, setStats] = React.useState<{ total: number; errors: number; warns: number; by_agent: Record<string, number> } | null>(null);
  const [logs, setLogs] = React.useState<Array<Record<string, unknown>>>([]);
  const [level, setLevel] = React.useState("all");
  const [agent, setAgent] = React.useState("all");
  const [search, setSearch] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  // Tab 2: Live SSE Stream
  const [streamLines, setStreamLines] = React.useState<LogLine[]>([]);
  const [paused, setPaused] = React.useState(false);
  const [connected, setConnected] = React.useState(false);
  const [streamQuery, setStreamQuery] = React.useState("");
  const pausedRef = React.useRef(false);
  pausedRef.current = paused;

  const loadAnomalies = React.useCallback(async () => {
    setLoading(true);
    try {
      const [sRes, lRes] = await Promise.all([
        riddleApi.getRuntimeLogStats(),
        riddleApi.listRuntimeLogs({ level, agent, q: search.trim() || undefined, limit: 150 }),
      ]);
      setStats(sRes);
      setLogs(lRes.items ?? []);
    } catch (err) {
      toast.error(`加载运行日志失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [level, agent, search]);

  React.useEffect(() => {
    void loadAnomalies();
  }, [loadAnomalies]);

  React.useEffect(() => {
    let es: EventSource | null = null;
    try {
      es = new EventSource(sseUrl("/logs/stream"));
      es.onopen = () => setConnected(true);
      es.onerror = () => setConnected(false);
      es.onmessage = (evt) => {
        if (pausedRef.current) return;
        try {
          const parsed = JSON.parse(evt.data) as LogLine;
          setStreamLines((prev) => [...prev.slice(-300), parsed]);
        } catch {
          // ignore non-json heartbeat
        }
      };
    } catch {
      setConnected(false);
    }
    return () => {
      es?.close();
    };
  }, []);

  const agentKeys = Object.keys(stats?.by_agent ?? {});
  const filteredStream = React.useMemo(() => {
    const q = streamQuery.trim().toLowerCase();
    if (!q) return streamLines;
    return streamLines.filter(
      (l) => l.text.toLowerCase().includes(q) || l.tag.toLowerCase().includes(q) || l.level.toLowerCase().includes(q),
    );
  }, [streamLines, streamQuery]);

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="运行日志与异常诊断"
        description="全局聚合各任务 Worker / Reviewer / Killsweep 运行异常，同时提供实时 SSE 事件流监控。"
        actions={
          <Button variant="outline" size="sm" onClick={() => void loadAnomalies()}>
            <RefreshCw className="mr-1.5 size-3.5" /> 刷新日志
          </Button>
        }
      />

      <Tabs defaultValue="anomalies" className="space-y-4">
        <TabsList>
          <TabsTrigger value="anomalies">
            <AlertTriangle className="mr-1.5 size-3.5" /> 全局异常诊断 ({stats?.total ?? 0})
          </TabsTrigger>
          <TabsTrigger value="stream">
            <Radio className="mr-1.5 size-3.5" /> 实时事件流
            <span
              className={cn(
                "ml-1.5 size-2 rounded-full",
                connected ? "bg-emerald-500" : "bg-muted-foreground/40",
              )}
            />
          </TabsTrigger>
        </TabsList>

        <TabsContent value="anomalies" className="space-y-4">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">累计异常事件</CardDescription>
                <CardTitle className="text-2xl tabular-nums">{stats?.total ?? 0}</CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">错误 (Error)</CardDescription>
                <CardTitle className="text-2xl tabular-nums text-rose-600 dark:text-rose-400">
                  {stats?.errors ?? 0}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">告警 (Warn)</CardDescription>
                <CardTitle className="text-2xl tabular-nums text-amber-600 dark:text-amber-400">
                  {stats?.warns ?? 0}
                </CardTitle>
              </CardHeader>
            </Card>
            <Card>
              <CardHeader className="pb-1">
                <CardDescription className="text-xs">涉及 Agent 模块</CardDescription>
                <CardTitle className="text-2xl tabular-nums">{agentKeys.length}</CardTitle>
              </CardHeader>
            </Card>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <div className="relative min-w-[220px] flex-1 max-w-md">
              <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
              <Input
                placeholder="检索错误详情、状态码、任务名…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8"
              />
            </div>
            <Select value={level} onValueChange={setLevel}>
              <SelectTrigger className="w-[140px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部级别</SelectItem>
                <SelectItem value="error">Error</SelectItem>
                <SelectItem value="warn">Warn</SelectItem>
                <SelectItem value="info">Info</SelectItem>
              </SelectContent>
            </Select>
            <Select value={agent} onValueChange={setAgent}>
              <SelectTrigger className="w-[160px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部 Agent</SelectItem>
                {agentKeys.map((a) => (
                  <SelectItem key={a} value={a}>
                    {a} ({stats?.by_agent?.[a] ?? 0})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-[155px]">时间</TableHead>
                    <TableHead className="w-[90px]">级别</TableHead>
                    <TableHead className="w-[120px]">Agent</TableHead>
                    <TableHead>异常详情</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loading ? (
                    <TableRow>
                      <TableCell colSpan={4} className="h-24 text-center text-sm text-muted-foreground">
                        正在加载全局运行异常日志…
                      </TableCell>
                    </TableRow>
                  ) : logs.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="h-24 text-center text-sm text-muted-foreground">
                        当前无运行异常日志，系统运行平稳。
                      </TableCell>
                    </TableRow>
                  ) : (
                    logs.map((row, idx) => {
                      const lv = String(row.level ?? "info");
                      return (
                        <TableRow key={String(row.id ?? idx)}>
                          <TableCell className="font-mono text-xs text-muted-foreground whitespace-nowrap">
                            {String(row.created_at ?? "").replace("T", " ").slice(0, 19)}
                          </TableCell>
                          <TableCell>
                            <Badge variant={lv === "error" ? "destructive" : lv === "warn" ? "secondary" : "outline"}>
                              {lv}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs">{String(row.agent ?? "-")}</TableCell>
                          <TableCell className="max-w-[560px]">
                            <div className="text-xs break-all leading-relaxed">{String(row.message ?? "")}</div>
                            {row.task_name ? (
                              <div className="mt-0.5 text-[11px] text-muted-foreground">
                                任务：{String(row.task_name)}
                              </div>
                            ) : null}
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

        <TabsContent value="stream" className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="relative min-w-[220px] flex-1 max-w-md">
              <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
              <Input
                placeholder="实时过滤日志关键词…"
                value={streamQuery}
                onChange={(e) => setStreamQuery(e.target.value)}
                className="pl-8"
              />
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" onClick={() => setPaused((p) => !p)}>
                {paused ? <Play className="mr-1.5 size-3.5" /> : <Pause className="mr-1.5 size-3.5" />}
                {paused ? "恢复接收" : "暂停滚屏"}
              </Button>
              <Button variant="ghost" size="sm" onClick={() => setStreamLines([])}>
                <Trash2 className="mr-1.5 size-3.5" /> 清空
              </Button>
            </div>
          </div>
          <Card>
            <CardContent className="p-3">
              <div className="h-[460px] overflow-y-auto rounded-lg bg-muted/30 p-3 font-mono text-xs space-y-1">
                {filteredStream.length === 0 ? (
                  <div className="flex h-full items-center justify-center text-muted-foreground">
                    {connected ? "已连接实时事件流，等待任务事件推送…" : "实时流连接中或暂无事件输出…"}
                  </div>
                ) : (
                  filteredStream.map((line, i) => (
                    <div key={`${line.seq}-${i}`} className="flex items-start gap-2 leading-relaxed">
                      <span className="shrink-0 text-muted-foreground">{line.ts.slice(11, 19)}</span>
                      <Badge variant="outline" className="h-4 px-1 text-[10px] shrink-0">
                        {line.tag}
                      </Badge>
                      <span className={cn("break-all", LEVEL_TONE[line.level] ?? "")}>{line.text}</span>
                    </div>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
