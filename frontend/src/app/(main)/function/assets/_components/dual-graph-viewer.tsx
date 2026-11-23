"use client";

import * as React from "react";
import {
  GitBranch,
  Layers,
  Loader2,
  Maximize2,
  RefreshCw,
  Search,
  ZoomIn,
  ZoomOut,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  riddleApi,
  type AssetCompanyItem,
  type DualGraphEdge,
  type DualGraphNode,
  type DualGraphResponse,
  type RiddleTask,
} from "@/lib/riddle-api";

const KIND_STYLE: Record<string, { label: string; fill: string; stroke: string; text: string; col: number }> = {
  company: { label: "企业/组织", fill: "#1e293b", stroke: "#64748b", text: "#f8fafc", col: 0 },
  root_domain: { label: "根域名", fill: "#1d4ed8", stroke: "#60a5fa", text: "#eff6ff", col: 1 },
  subdomain: { label: "子域名", fill: "#0369a1", stroke: "#38bdf8", text: "#f0f9ff", col: 2 },
  ip: { label: "IP", fill: "#0f766e", stroke: "#2dd4bf", text: "#f0fdfa", col: 3 },
  service: { label: "服务", fill: "#047857", stroke: "#34d399", text: "#ecfdf5", col: 3 },
  app: { label: "应用", fill: "#4d7c0f", stroke: "#a3e635", text: "#f7fee7", col: 4 },
  endpoint: { label: "接口", fill: "#6d28d9", stroke: "#a78bfa", text: "#f5f3ff", col: 4 },
  finding: { label: "漏洞", fill: "#be123c", stroke: "#fb7185", text: "#fff1f2", col: 5 },
  fact: { label: "实证事实", fill: "#b45309", stroke: "#fbbf24", text: "#fffbeb", col: 6 },
  hint: { label: "探索线索", fill: "#92400e", stroke: "#f59e0b", text: "#fef3c7", col: 6 },
  goal: { label: "验收目标", fill: "#4338ca", stroke: "#818cf8", text: "#eef2ff", col: 7 },
};

const COL_TITLES = [
  "企业主体",
  "根域名",
  "子域名",
  "IP / 服务",
  "应用 / 接口",
  "漏洞（探索图）",
  "事实 / 线索",
  "验收目标",
];

interface PositionedNode extends DualGraphNode {
  x: number;
  y: number;
  col: number;
}

export function DualGraphViewer({
  tasks,
  companies,
  refreshToken = 0,
}: {
  tasks: RiddleTask[];
  companies: AssetCompanyItem[];
  refreshToken?: number;
}) {
  const [scopeTaskId, setScopeTaskId] = React.useState("global");
  const [scopeCompanyId, setScopeCompanyId] = React.useState("all");
  const [layerMode, setLayerMode] = React.useState<"both" | "asset" | "exploration">("both");
  const [search, setSearch] = React.useState("");
  const [zoom, setZoom] = React.useState(1);

  const [graph, setGraph] = React.useState<DualGraphResponse | null>(null);
  const [loading, setLoading] = React.useState(false);

  const [selectedNodeId, setSelectedNodeId] = React.useState<string | null>(null);
  const [lineageIds, setLineageIds] = React.useState<Set<string>>(() => new Set());
  const [lineageNodes, setLineageNodes] = React.useState<DualGraphNode[]>([]);

  const loadGraph = React.useCallback(async () => {
    setLoading(true);
    try {
      const res = await riddleApi.getDualGraph({
        task_id: scopeTaskId,
        company_id: scopeCompanyId,
        limit: 260,
      });
      setGraph(res);
      setSelectedNodeId(null);
      setLineageIds(new Set());
      setLineageNodes([]);
    } catch (err) {
      toast.error(`加载双图拓扑失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoading(false);
    }
  }, [scopeTaskId, scopeCompanyId]);

  React.useEffect(() => {
    void loadGraph();
  }, [loadGraph, refreshToken]);

  const handleSelectNode = async (node: DualGraphNode) => {
    setSelectedNodeId(node.id);
    try {
      const res = await riddleApi.getDualGraphLineage({
        node_id: node.id,
        task_id: scopeTaskId,
        company_id: scopeCompanyId,
        direction: "both",
      });
      const chain = res.lineage ?? [];
      setLineageNodes(chain);
      setLineageIds(new Set([node.id, ...chain.map((n) => n.id)]));
    } catch {
      setLineageIds(new Set([node.id]));
      setLineageNodes([]);
    }
  };

  const { positioned, visibleEdges, canvasWidth, canvasHeight, nodeMap } = React.useMemo(() => {
    const rawNodes = (graph?.nodes ?? []).filter((n) => {
      if (layerMode === "asset" && n.graph !== "asset") return false;
      if (layerMode === "exploration" && n.graph !== "exploration") return false;
      return true;
    });

    // Bucket into semantic columns
    const colBuckets = new Map<number, DualGraphNode[]>();
    for (const n of rawNodes) {
      const col = KIND_STYLE[n.kind]?.col ?? (n.graph === "exploration" ? 6 : 3);
      const arr = colBuckets.get(col) ?? [];
      arr.push(n);
      colBuckets.set(col, arr);
    }

    const activeCols = Array.from(colBuckets.keys()).sort((a, b) => a - b);
    const colXMap = new Map<number, number>();
    const colGap = 235;
    activeCols.forEach((col, idx) => {
      colXMap.set(col, 40 + idx * colGap);
    });

    const nodeW = 185;
    const nodeH = 44;
    const rowGap = 16;
    const topPad = 56;
    let maxRows = 1;

    const posList: PositionedNode[] = [];
    const map = new Map<string, PositionedNode>();

    for (const col of activeCols) {
      const bucket = colBuckets.get(col) ?? [];
      maxRows = Math.max(maxRows, bucket.length);
      bucket.forEach((n, rIdx) => {
        const pn: PositionedNode = {
          ...n,
          col,
          x: colXMap.get(col) ?? 40,
          y: topPad + rIdx * (nodeH + rowGap),
        };
        posList.push(pn);
        map.set(pn.id, pn);
      });
    }

    const edges: DualGraphEdge[] = (graph?.edges ?? []).filter(
      (e) => map.has(e.src) && map.has(e.dst),
    );

    return {
      positioned: posList,
      visibleEdges: edges,
      canvasWidth: Math.max(920, activeCols.length * colGap + nodeW + 60),
      canvasHeight: Math.max(440, topPad + maxRows * (nodeH + rowGap) + 40),
      nodeMap: map,
    };
  }, [graph, layerMode]);

  const selectedNode = selectedNodeId ? nodeMap.get(selectedNodeId) ?? null : null;
  const searchLower = search.trim().toLowerCase();

  const activeColHeaders = React.useMemo(() => {
    const seen = new Map<number, number>();
    for (const n of positioned) {
      if (!seen.has(n.col)) seen.set(n.col, n.x);
    }
    return Array.from(seen.entries()).sort((a, b) => a[0] - b[0]);
  }, [positioned]);

  return (
    <div className="space-y-4">
      {/* Control Bar */}
      <div className="flex flex-wrap items-center gap-2.5">
        <Select value={scopeTaskId} onValueChange={setScopeTaskId}>
          <SelectTrigger className="w-[220px] text-xs">
            <SelectValue placeholder="视图范围" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="global">全局共享双图（跨任务）</SelectItem>
            {tasks.map((t) => (
              <SelectItem key={t.id} value={t.id}>
                任务：{t.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={scopeCompanyId} onValueChange={setScopeCompanyId}>
          <SelectTrigger className="w-[180px] text-xs">
            <SelectValue placeholder="按企业主体筛选" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部企业/高校主体</SelectItem>
            {companies.map((c) => (
              <SelectItem key={c.id} value={c.id}>
                {c.name}（{c.asset_count}）
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={layerMode} onValueChange={(v) => setLayerMode(v as "both" | "asset" | "exploration")}>
          <SelectTrigger className="w-[140px] text-xs">
            <Layers className="mr-1.5 size-3.5 text-muted-foreground" />
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="both">双图联动</SelectItem>
            <SelectItem value="asset">仅资产图</SelectItem>
            <SelectItem value="exploration">仅探索图</SelectItem>
          </SelectContent>
        </Select>

        <div className="relative min-w-[180px] flex-1 max-w-xs">
          <Search className="pointer-events-none absolute top-2.5 left-2.5 size-3.5 text-muted-foreground" />
          <Input
            className="h-9 pl-8 text-xs"
            placeholder="高亮搜索节点（域名 / IP / 漏洞）…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>

        <div className="ml-auto flex items-center gap-1.5">
          <Button size="icon" variant="outline" className="size-8" onClick={() => setZoom((z) => Math.max(0.55, +(z - 0.15).toFixed(2)))} title="缩小">
            <ZoomOut className="size-3.5" />
          </Button>
          <span className="w-11 text-center font-mono text-xs text-muted-foreground">{Math.round(zoom * 100)}%</span>
          <Button size="icon" variant="outline" className="size-8" onClick={() => setZoom((z) => Math.min(1.6, +(z + 0.15).toFixed(2)))} title="放大">
            <ZoomIn className="size-3.5" />
          </Button>
          <Button size="icon" variant="outline" className="size-8" onClick={() => setZoom(1)} title="重置缩放">
            <Maximize2 className="size-3.5" />
          </Button>
          <Button size="sm" variant="outline" onClick={() => void loadGraph()} disabled={loading}>
            <RefreshCw className={`mr-1.5 size-3.5 ${loading ? "animate-spin" : ""}`} /> 刷新
          </Button>
        </div>
      </div>

      {/* Coverage Strip */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Card>
          <CardHeader className="py-3">
            <CardDescription className="text-xs">资产图节点（共享真值）</CardDescription>
            <CardTitle className="text-xl tabular-nums">{graph?.coverage.asset_nodes ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="py-3">
            <CardDescription className="text-xs">探索图节点（漏洞/事实/目标）</CardDescription>
            <CardTitle className="text-xl tabular-nums">{graph?.coverage.exploration_nodes ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="py-3">
            <CardDescription className="text-xs">关系边数（含跨图锚点）</CardDescription>
            <CardTitle className="text-xl tabular-nums">{graph?.coverage.edges ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="py-3">
            <CardDescription className="text-xs">资产漏洞锚定覆盖率</CardDescription>
            <CardTitle className="text-xl tabular-nums text-emerald-600 dark:text-emerald-400">
              {Math.round((graph?.coverage.ratio ?? 0) * 100)}%
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      {/* Graph Canvas + Side Inspector */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
        <Card className="lg:col-span-3 overflow-hidden">
          <CardContent className="p-0">
            {loading && !graph ? (
              <div className="flex h-[460px] items-center justify-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin" /> 正在构建双图拓扑…
              </div>
            ) : positioned.length === 0 ? (
              <div className="flex h-[420px] flex-col items-center justify-center gap-2 px-6 text-center text-sm text-muted-foreground">
                <GitBranch className="size-8 opacity-40" />
                <p>当前范围下暂无双图节点。</p>
                <p className="text-xs">请先在「资产自动收集」发起收集，或在「双图资产库」同步历史任务资产。</p>
              </div>
            ) : (
              <div className="h-[520px] w-full overflow-auto bg-slate-950/[0.03] dark:bg-slate-950/60">
                <svg
                  width={Math.round(canvasWidth * zoom)}
                  height={Math.round(canvasHeight * zoom)}
                  viewBox={`0 0 ${canvasWidth} ${canvasHeight}`}
                  className="select-none"
                >
                  <defs>
                    <marker id="arrow-solid" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
                    </marker>
                    <marker id="arrow-highlight" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                      <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b" />
                    </marker>
                  </defs>

                  {/* Column Headers */}
                  {activeColHeaders.map(([col, x]) => (
                    <g key={`col-${col}`}>
                      <rect x={x} y={12} width={185} height={26} rx={6} fill="rgba(100,116,139,0.12)" />
                      <text x={x + 92} y={29} textAnchor="middle" fontSize={11} fontWeight={600} fill="#64748b">
                        {COL_TITLES[col] ?? `层级 ${col}`}
                      </text>
                    </g>
                  ))}

                  {/* Edges */}
                  {visibleEdges.map((edge) => {
                    const src = nodeMap.get(edge.src);
                    const dst = nodeMap.get(edge.dst);
                    if (!src || !dst) return null;
                    const x1 = src.x <= dst.x ? src.x + 185 : src.x;
                    const y1 = src.y + 22;
                    const x2 = src.x <= dst.x ? dst.x : dst.x + 185;
                    const y2 = dst.y + 22;
                    const mx = (x1 + x2) / 2;
                    const isCrossGraph = src.graph !== dst.graph;
                    const inLineage =
                      selectedNodeId !== null && lineageIds.has(src.id) && lineageIds.has(dst.id);
                    const dimmed = selectedNodeId !== null && !inLineage;

                    return (
                      <path
                        key={edge.id}
                        d={`M ${x1} ${y1} C ${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`}
                        fill="none"
                        stroke={inLineage ? "#f59e0b" : isCrossGraph ? "#ec4899" : "#94a3b8"}
                        strokeWidth={inLineage ? 2.2 : 1.25}
                        strokeDasharray={isCrossGraph ? "5 4" : undefined}
                        strokeOpacity={dimmed ? 0.16 : 0.78}
                        markerEnd={inLineage ? "url(#arrow-highlight)" : "url(#arrow-solid)"}
                      />
                    );
                  })}

                  {/* Nodes */}
                  {positioned.map((node) => {
                    const st = KIND_STYLE[node.kind] ?? {
                      label: node.kind,
                      fill: "#334155",
                      stroke: "#94a3b8",
                      text: "#f8fafc",
                    };
                    const isSelected = node.id === selectedNodeId;
                    const inLineage = selectedNodeId !== null && lineageIds.has(node.id);
                    const searchMatch = searchLower ? node.label.toLowerCase().includes(searchLower) : false;
                    const dimmed =
                      (selectedNodeId !== null && !inLineage) ||
                      (Boolean(searchLower) && !searchMatch);

                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x}, ${node.y})`}
                        className="cursor-pointer"
                        opacity={dimmed ? 0.25 : 1}
                        onClick={() => void handleSelectNode(node)}
                      >
                        <rect
                          width={185}
                          height={44}
                          rx={8}
                          fill={st.fill}
                          stroke={isSelected || searchMatch ? "#f59e0b" : st.stroke}
                          strokeWidth={isSelected || searchMatch ? 2.5 : 1.2}
                        />
                        <text x={10} y={16} fontSize={9.5} fill={st.stroke} fontWeight={600}>
                          {st.label} · {node.graph === "exploration" ? "探索图" : "资产图"}
                        </text>
                        <text x={10} y={33} fontSize={11.5} fill={st.text} fontWeight={500}>
                          {node.label.length > 22 ? `${node.label.slice(0, 21)}…` : node.label}
                        </text>
                      </g>
                    );
                  })}
                </svg>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Side Lineage Inspector */}
        <Card className="flex flex-col">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">节点血缘与属性面板</CardTitle>
            <CardDescription className="text-xs">点击拓扑中任意节点查看双向血缘链</CardDescription>
          </CardHeader>
          <CardContent className="flex-1 space-y-3 text-xs">
            {!selectedNode ? (
              <div className="space-y-3 text-muted-foreground">
                <p>暂未选中节点。点击左侧画布任意节点可高亮它的完整上游与下游血缘路径。</p>
                <div className="space-y-1.5 pt-2 border-t">
                  <div className="font-medium text-foreground">图例说明</div>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.entries(KIND_STYLE).map(([k, v]) => (
                      <span
                        key={k}
                        className="inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px]"
                        style={{ backgroundColor: v.fill, color: v.text }}
                      >
                        {v.label}
                      </span>
                    ))}
                  </div>
                  <p className="text-[11px] pt-1">粉色虚线表示跨图锚点边（探索图漏洞 → 资产图节点），橙色实线表示当前选中节点的血缘路径。</p>
                </div>
              </div>
            ) : (
              <div className="space-y-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-1.5">
                    <Badge variant="secondary">{KIND_STYLE[selectedNode.kind]?.label ?? selectedNode.kind}</Badge>
                    <Badge variant="outline">{selectedNode.graph === "exploration" ? "探索图" : "资产图"}</Badge>
                  </div>
                  <div className="font-medium text-sm break-all">{selectedNode.label}</div>
                </div>

                {Object.keys(selectedNode.payload || {}).length > 0 ? (
                  <div className="rounded-md border bg-muted/30 p-2.5 space-y-1">
                    {Object.entries(selectedNode.payload).map(([k, v]) => {
                      if (v === "" || v === null || v === 0 || (Array.isArray(v) && v.length === 0)) return null;
                      return (
                        <div key={k} className="flex justify-between gap-2 text-[11px]">
                          <span className="text-muted-foreground shrink-0">{k}</span>
                          <span className="truncate font-mono text-right">
                            {Array.isArray(v) ? v.join(", ") : String(v)}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                ) : null}

                <div className="space-y-1.5 border-t pt-2">
                  <div className="flex items-center justify-between">
                    <span className="font-medium">关联血缘节点（{lineageNodes.length}）</span>
                    <Button variant="ghost" size="sm" className="h-6 px-1.5 text-[11px]" onClick={() => {
                      setSelectedNodeId(null);
                      setLineageIds(new Set());
                      setLineageNodes([]);
                    }}>
                      清除高亮
                    </Button>
                  </div>
                  {lineageNodes.length === 0 ? (
                    <div className="text-muted-foreground">暂无直接血缘关联节点。</div>
                  ) : (
                    <div className="max-h-56 space-y-1 overflow-y-auto pr-1">
                      {lineageNodes.map((ln) => (
                        <button
                          key={ln.id}
                          type="button"
                          onClick={() => void handleSelectNode(ln)}
                          className="flex w-full items-center gap-1.5 rounded border px-2 py-1 text-left hover:bg-muted/50"
                        >
                          <Badge variant="outline" className="shrink-0 text-[10px]">
                            {KIND_STYLE[ln.kind]?.label ?? ln.kind}
                          </Badge>
                          <span className="truncate">{ln.label}</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
