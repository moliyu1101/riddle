"use client";

import * as React from "react";

import Link from "next/link";

import { ArrowUpRightIcon, ChevronLeftIcon, ChevronRightIcon, Loader2Icon, PlayIcon, SquareIcon } from "lucide-react";

import { FindingRetestPanel } from "@/components/finding-retest-panel";
import { StatusBadge } from "@/components/status-badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Empty, EmptyDescription, EmptyHeader, EmptyTitle } from "@/components/ui/empty";
import { Separator } from "@/components/ui/separator";
import { Skeleton } from "@/components/ui/skeleton";
import { api } from "@/lib/api";
import type { Finding, FindingsPage, RetestState } from "@/lib/types";

const PAGE_SIZE = 20;

function findingLabel(finding: Finding) {
  return finding.name?.trim() || finding.vulnclass.trim() || "未分类";
}

// 最新复测状态徽标文案（v0.4.27 批量复测配套）。
function retestBadge(state: RetestState | undefined): { text: string; className: string } | null {
  if (!state) return null;
  if (state.status === "pending" || state.status === "running") {
    return { text: "复测中", className: "bg-sky-500/15 text-sky-600 dark:text-sky-400" };
  }
  switch (state.verdict) {
    case "fixed":
      return { text: "已修复", className: "bg-emerald-500/15 text-emerald-600 dark:text-emerald-400" };
    case "reproduced":
      return { text: "已复现", className: "bg-red-500/15 text-red-600 dark:text-red-400" };
    case "inconclusive":
      return { text: "无法确认", className: "bg-amber-500/15 text-amber-600 dark:text-amber-400" };
    default:
      return null;
  }
}

export function RetestsTab({ taskId }: { taskId: string }) {
  const [page, setPage] = React.useState(1);
  const [data, setData] = React.useState<FindingsPage | null>(null);
  const [selectedId, setSelectedId] = React.useState("");
  const [error, setError] = React.useState("");
  const [refreshVersion, setRefreshVersion] = React.useState(0);
  const refresh = React.useCallback(() => setRefreshVersion((version) => version + 1), []);

  // 批量复测（v0.4.27）：候选=本任务 pending 且无进行中复测的 critical/high。
  // 串行逐条发起（一次只跑一个复测会话），可随时停止。
  const [candidates, setCandidates] = React.useState(0);
  const [states, setStates] = React.useState<Record<number, RetestState>>({});
  const [batchRunning, setBatchRunning] = React.useState(false);
  const [batchDone, setBatchDone] = React.useState(0);
  const [batchTotal, setBatchTotal] = React.useState(0);
  const cancelBatch = React.useRef(false);

  React.useEffect(() => {
    let disposed = false;
    api
      .retestCandidates(taskId, ["critical", "high"])
      .then((r) => {
        if (disposed) return;
        setCandidates(r.candidates.length);
        setStates(Object.fromEntries(r.states.map((s) => [s.finding_id, s])));
      })
      .catch(() => {});
    return () => {
      disposed = true;
    };
  }, [taskId, refreshVersion]);

  const runBatch = React.useCallback(async () => {
    if (batchRunning) return;
    setBatchRunning(true);
    cancelBatch.current = false;
    try {
      const r = await api.retestCandidates(taskId, ["critical", "high"]);
      const queue = r.candidates;
      setStates(Object.fromEntries(r.states.map((s) => [s.finding_id, s])));
      setBatchTotal(queue.length);
      setBatchDone(0);
      for (let i = 0; i < queue.length; i += 1) {
        if (cancelBatch.current) break;
        const c = queue[i];
        try {
          await api.startFindingRetest(String(c.id), "");
          setStates((prev) => ({ ...prev, [c.id]: { finding_id: c.id, status: "running", verdict: "" } }));
        } catch {
          // 单条失败（如复测 Agent 未启用）不中断整批，继续下一条。
        }
        setBatchDone(i + 1);
        await new Promise((resolve) => setTimeout(resolve, 1500)); // 会话启动间隔，避免瞬时并发
      }
      refresh();
    } finally {
      setBatchRunning(false);
    }
  }, [batchRunning, refresh, taskId]);

  // Only this task's own findings, including those without graph nodes.
  // Fetch history only for the selection, and wait for each poll to finish.
  React.useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function load() {
      try {
        const result = await api.findingsPage({ task: taskId, page, pageSize: PAGE_SIZE, sort: "time" });
        if (disposed) return;
        const lastPage = Math.max(1, Math.ceil(result.total / PAGE_SIZE));
        if (page > lastPage) {
          setPage(lastPage);
          return;
        }
        setData(result);
        setSelectedId((current) =>
          result.items.some((finding) => finding.id === current) ? current : (result.items[0]?.id ?? ""),
        );
        setError("");
      } catch (e) {
        if (!disposed) setError((e as Error).message);
      } finally {
        if (!disposed) timer = setTimeout(() => void load(), 3000);
      }
    }
    void refreshVersion; // Refresh triage immediately after a retest completes.
    void load();
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [taskId, page, refreshVersion]);

  const loaded = data?.page === page;
  const findings = loaded ? data.items : [];
  const selected = findings.find((finding) => finding.id === selectedId);

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Alert variant="destructive">
          <AlertDescription>
            加载任务漏洞失败：{error}
            <Button variant="outline" size="sm" onClick={refresh}>
              重试
            </Button>
          </AlertDescription>
        </Alert>
      ) : null}
      {/* 批量复测条（v0.4.27）：把 pending 的 critical/high 逐条排进复测队列。 */}
      <Card>
        <CardContent className="flex flex-wrap items-center justify-between gap-3 py-3">
          <div className="text-sm">
            {batchRunning ? (
              <span className="flex items-center gap-2">
                <Loader2Icon className="size-4 animate-spin" />
                批量复测进行中：{batchDone}/{batchTotal}（critical/high，串行执行）
              </span>
            ) : (
              <span className="text-muted-foreground">
                待复测（critical/high 且无进行中复测）：<span className="text-foreground font-medium">{candidates}</span> 条
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            {batchRunning ? (
              <Button variant="outline" size="sm" onClick={() => (cancelBatch.current = true)}>
                <SquareIcon data-icon="inline-start" />
                停止排队
              </Button>
            ) : (
              <Button size="sm" disabled={candidates === 0} onClick={() => void runBatch()}>
                <PlayIcon data-icon="inline-start" />
                批量复测
              </Button>
            )}
          </div>
        </CardContent>
      </Card>
      <div className="grid items-start gap-4 lg:grid-cols-[minmax(16rem,22rem)_minmax(0,1fr)]">
        <Card className="min-w-0">
          <CardHeader>
            <CardTitle>选择漏洞{data ? ` · ${data.total}` : ""}</CardTitle>
            <CardDescription>查看本任务漏洞的复测记录，或发起新的复测。</CardDescription>
          </CardHeader>
          <CardContent className="flex max-h-[32rem] flex-col overflow-y-auto">
            {!loaded && !error ? <Skeleton className="h-24 w-full" /> : null}
            {findings.map((finding, index) => (
              <React.Fragment key={finding.id}>
                {index > 0 ? <Separator className="my-1" /> : null}
                <Button
                  variant={finding.id === selectedId ? "secondary" : "ghost"}
                  className="h-auto w-full shrink-0 flex-col items-start gap-2 whitespace-normal py-3 text-left"
                  aria-label={`选择漏洞：${findingLabel(finding)}`}
                  aria-pressed={finding.id === selectedId}
                  onClick={() => setSelectedId(finding.id)}
                >
                  <span className="line-clamp-2 break-words">{findingLabel(finding)}</span>
                  <span className="flex flex-wrap items-center gap-2">
                    <StatusBadge domain="severity" value={finding.severity} dot />
                    <StatusBadge domain="finding" value={finding.status} dot />
                    {(() => {
                      const badge = retestBadge(states[Number(finding.finding_id || finding.id)]);
                      if (!badge) return null;
                      return (
                        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${badge.className}`}>
                          {badge.text}
                        </span>
                      );
                    })()}
                  </span>
                </Button>
              </React.Fragment>
            ))}
            {loaded && findings.length === 0 ? (
              <Empty>
                <EmptyHeader>
                  <EmptyTitle>暂无可复测漏洞</EmptyTitle>
                  <EmptyDescription>本任务发现漏洞后，可在这里手动发起复测。</EmptyDescription>
                </EmptyHeader>
              </Empty>
            ) : null}
          </CardContent>
          {data && data.total > PAGE_SIZE ? (
            <CardFooter className="justify-between gap-2">
              <Button
                variant="outline"
                size="icon-sm"
                aria-label="上一页漏洞"
                disabled={page === 1}
                onClick={() => setPage(page - 1)}
              >
                <ChevronLeftIcon />
              </Button>
              <span className="text-muted-foreground text-xs">
                第 {page} / {Math.ceil(data.total / PAGE_SIZE)} 页
              </span>
              <Button
                variant="outline"
                size="icon-sm"
                aria-label="下一页漏洞"
                disabled={page * PAGE_SIZE >= data.total}
                onClick={() => setPage(page + 1)}
              >
                <ChevronRightIcon />
              </Button>
            </CardFooter>
          ) : null}
        </Card>
        {selected ? (
          <div className="flex min-w-0 flex-col gap-4">
            <div className="flex flex-col gap-2">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <h2 className="min-w-0 flex-1 break-words font-medium">{findingLabel(selected)}</h2>
                <Button asChild variant="ghost" size="sm">
                  <Link href={`/function/findings/detail?id=${selected.finding_id || selected.id}`}>
                    漏洞详情 <ArrowUpRightIcon data-icon="inline-end" />
                  </Link>
                </Button>
              </div>
              <p className="line-clamp-3 break-words text-muted-foreground text-sm">{selected.summary}</p>
            </div>
            <FindingRetestPanel
              key={selected.id}
              findingId={selected.finding_id || selected.id}
              findingName={findingLabel(selected)}
              onCompleted={refresh}
            />
          </div>
        ) : null}
      </div>
    </div>
  );
}
