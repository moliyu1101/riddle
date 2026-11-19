"use client";

import * as React from "react";
import { toast } from "sonner";
import { PlusIcon, RefreshCwIcon, ServerIcon, Trash2Icon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { api } from "@/lib/api";
import type { MCPServer, MCPTool, Agent } from "@/lib/types";

type Transport = "stdio" | "http" | "sse";
type FormState = {
  name: string;
  transport: Transport;
  command: string;
  args: string;
  url: string;
  env: string;
  insecure: boolean;
};
const emptyForm: FormState = {
  name: "",
  transport: "stdio",
  command: "",
  args: "",
  url: "",
  env: "",
  insecure: false,
};

// 常用 MCP 预设目录（v0.4.56）：一键填充表单，不用手记包名与启动参数。
// 只收录公开可用的官方/主流实现；依赖缺失时对话框里会提示（如 uvx 需先装 uv）。
type MCPPreset = {
  name: string;
  title: string;
  description: string;
  transport: Transport;
  command?: string;
  args?: string;
  url?: string;
  requires?: string; // 运行前提提示
};

const mcpPresets: MCPPreset[] = [
  {
    name: "playwright",
    title: "Playwright 浏览器",
    description: "浏览器自动化：真实渲染页面、截图、读取 DOM、填表单。",
    transport: "stdio",
    command: "npx",
    args: "@playwright/mcp@latest --headless --no-sandbox",
    requires: "镜像已内置；裸机需 node ≥ 20",
  },
  {
    name: "chrome-devtools",
    title: "Chrome DevTools",
    description: "Chrome 原生调试协议：性能追踪、网络请求、控制台与 DOM 检查。",
    transport: "stdio",
    command: "npx",
    args: "chrome-devtools-mcp@latest --headless",
    requires: "需本机 Chrome/Chromium",
  },
  {
    name: "burp",
    title: "Burp Suite MCP",
    description: "接 Burp 的代理历史与扫描能力（官方 MCP 扩展）。",
    transport: "sse",
    url: "http://127.0.0.1:9876/sse",
    requires: "需 Burp 安装 MCP 扩展并开启 9876 端口",
  },
  {
    name: "fetch",
    title: "Fetch 网页抓取",
    description: "抓取网页并把正文转成 Markdown 供分析（外部资料、文档）。",
    transport: "stdio",
    command: "uvx",
    args: "mcp-server-fetch",
    requires: "需 uv（pip install uv）",
  },
  {
    name: "sequential-thinking",
    title: "Sequential Thinking",
    description: "分步推理草稿板：把复杂问题拆成可回退的思考链。",
    transport: "stdio",
    command: "npx",
    args: "@modelcontextprotocol/server-sequential-thinking",
    requires: "需 node ≥ 18",
  },
  {
    name: "memory",
    title: "Memory 知识库",
    description: "跨会话持久化的实体/关系记忆（本地 JSON）。",
    transport: "stdio",
    command: "npx",
    args: "@modelcontextprotocol/server-memory",
    requires: "需 node ≥ 18",
  },
  {
    name: "filesystem",
    title: "Filesystem 文件访问",
    description: "读写指定目录下的文件（默认限定任务数据目录）。",
    transport: "stdio",
    command: "npx",
    args: "@modelcontextprotocol/server-filesystem /opt/pojun/data",
    requires: "需 node ≥ 18；路径按需修改",
  },
  {
    name: "hexstrike",
    title: "HexStrike 工具桥",
    description: "桥接 150+ 安全工具（nmap/sqlmap/metasploit/nuclei/ghidra…），AI 统一调度。",
    transport: "stdio",
    command: "python3",
    args: "mcp-servers/hexstrike-ai/hexstrike_mcp.py --server http://127.0.0.1:5000",
    requires: "先把 hexstrike-ai 克隆到 mcp-servers/ 并启动 hexstrike_server.py（:5000）",
  },
  {
    name: "fofa",
    title: "FOFA 资产测绘",
    description: "按域名/证书/端口/指纹搜资产（内置 one-fox 通道与多账号轮换）。",
    transport: "stdio",
    command: "uv",
    args: "--directory mcp-servers/fofa run python fofa.py",
    requires: "需 uv（--with-tools 已装）；环境变量填 FOFA_EMAIL/FOFA_KEY",
  },
  {
    name: "context7",
    title: "Context7 文档检索",
    description: "按库名检索最新官方文档与用法（写 PoC 时查 API）。",
    transport: "stdio",
    command: "npx",
    args: "@upstash/context7-mcp",
    requires: "需 node ≥ 18；高频使用可在环境变量填 API_KEY",
  },
];

export default function MCPPage() {
  const [servers, setServers] = React.useState<MCPServer[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [visibility, setVisibility] = React.useState<Record<number, string[]>>({});

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<MCPServer | null>(null); // null = add mode
  // 删除二次确认（对齐 tasks/skills 的标准交互：删除直接改 agent 可用的工具面，必须确认）
  const [pendingDelete, setPendingDelete] = React.useState<MCPServer | null>(null);
  const [deleting, setDeleting] = React.useState(false);
  const [tab, setTab] = React.useState<"config" | "tools">("config");
  const [form, setForm] = React.useState<FormState>(emptyForm);
  const [saving, setSaving] = React.useState(false);
  const [tools, setTools] = React.useState<MCPTool[]>([]);
  const [toolsLoading, setToolsLoading] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  const load = React.useCallback(() => {
    api.agents().then(setAgents).catch(() => {});
    api
      .mcpServers()
      .then((ss) => {
        setServers(ss);
        ss.forEach((s) =>
          api
            .resourceVisibility("mcp", s.id)
            .then((ids) => setVisibility((v) => ({ ...v, [s.id]: ids })))
            .catch(() => {}),
        );
      })
      .catch(() => {});
  }, []);
  React.useEffect(() => {
    load();
  }, [load]);

  function setF(patch: Partial<FormState>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function parseEnv(text: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const idx = trimmed.indexOf("=");
      if (idx > 0) {
        const key = trimmed.slice(0, idx).trim();
        if (key) out[key] = trimmed.slice(idx + 1).trim();
      }
    }
    return out;
  }
  function envToText(env: Record<string, string> | undefined): string {
    return Object.entries(env ?? {})
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");
  }

  function openAdd() {
    setEditing(null);
    setForm(emptyForm);
    setTools([]);
    setTab("config");
    setOpen(true);
  }

  function openPreset(p: MCPPreset) {
    setEditing(null);
    setForm({
      name: p.name,
      transport: p.transport,
      command: p.command ?? "",
      args: p.args ?? "",
      url: p.url ?? "",
      env: "",
      insecure: false,
    });
    setTools([]);
    setTab("config");
    setOpen(true);
  }

  function openEdit(s: MCPServer) {
    setEditing(s);
    setForm({
      name: s.name,
      transport: s.transport,
      command: s.command ?? "",
      args: (s.args ?? []).join(" "),
      url: s.url ?? "",
      env: envToText(s.env),
      insecure: s.insecure ?? false,
    });
    setTab("config");
    setOpen(true);
    loadTools(s.id);
  }

  async function loadTools(id: number) {
    setToolsLoading(true);
    try {
      setTools(await api.mcpTools(id));
    } catch {
      setTools([]);
    } finally {
      setToolsLoading(false);
    }
  }

  async function saveForm() {
    if (!form.name.trim()) {
      toast.error("请填写名称");
      return;
    }
    if (form.transport === "stdio" && !form.command.trim()) {
      toast.error("请填写命令");
      return;
    }
    if (form.transport !== "stdio" && !form.url.trim()) {
      toast.error("请填写远程 URL");
      return;
    }
    setSaving(true);
    try {
      const base =
        form.transport !== "stdio"
          ? {
              transport: form.transport,
              url: form.url.trim(),
              command: "",
              args: [] as string[],
              env: parseEnv(form.env), // 远程模式下 env 即请求头
              insecure: form.insecure,
            }
          : {
              transport: "stdio" as const,
              command: form.command.trim(),
              args: form.args.trim() ? form.args.trim().split(/\s+/) : [],
              env: parseEnv(form.env),
              insecure: false,
            };
      await api.saveMcpServer({
        ...(editing ? { id: editing.id } : {}),
        name: form.name.trim(),
        enabled: editing ? editing.enabled : true,
        ...base,
      });
      toast.success(editing ? "已保存" : "已添加 MCP 服务器");
      if (!editing) setOpen(false);
      load();
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  async function refreshTools() {
    if (!editing) return;
    setRefreshing(true);
    try {
      const t = await api.refreshMcpServer(editing.id);
      setTools(t);
      toast.success(`发现 ${t.length} 个工具`);
      load();
    } catch (e) {
      toast.error(`刷新失败：${(e as Error).message}`);
    } finally {
      setRefreshing(false);
    }
  }

  async function removeServer(s: MCPServer) {
    setDeleting(true);
    try {
      await api.deleteMcpServer(s.id);
      toast.success(`已删除：${s.name}`);
      setOpen(false);
      load();
      setPendingDelete(null);
    } catch (e) {
      toast.error(`删除失败：${(e as Error).message}`);
    } finally {
      setDeleting(false);
    }
  }

  async function toggleEnabled(s: MCPServer) {
    try {
      await api.saveMcpServer({ ...s, enabled: !s.enabled });
      load();
    } catch (e) {
      toast.error(`操作失败：${(e as Error).message}`);
    }
  }

  async function toggleVisibility(serverId: number, agentId: string, agentName: string) {
    const on = (visibility[serverId] ?? []).includes(agentId);
    try {
      await api.toggleVisibility(agentId, "mcp", serverId, !on);
      toast.success(`${on ? "取消" : "授予"}「${agentName}」可见`);
      load();
    } catch (e) {
      toast.error(`操作失败：${(e as Error).message}`);
    }
  }

  function renderForm() {
    return (
      <div className="grid gap-4 py-4">
        <div className="grid gap-2">
          <Label>传输方式</Label>
          <div className="flex gap-2">
            <Button
              type="button"
              variant={form.transport === "stdio" ? "default" : "outline"}
              onClick={() => setF({ transport: "stdio" })}
            >
              stdio（本地）
            </Button>
            <Button
              type="button"
              variant={form.transport === "http" ? "default" : "outline"}
              onClick={() => setF({ transport: "http" })}
            >
              http（远程）
            </Button>
            <Button
              type="button"
              variant={form.transport === "sse" ? "default" : "outline"}
              onClick={() => setF({ transport: "sse" })}
            >
              sse（旧版）
            </Button>
          </div>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="m-name">名称</Label>
          <Input
            id="m-name"
            placeholder="filesystem"
            value={form.name}
            onChange={(e) => setF({ name: e.target.value })}
          />
        </div>
        {form.transport === "stdio" ? (
          <>
            <div className="grid gap-2">
              <Label htmlFor="m-cmd">命令</Label>
              <Input
                id="m-cmd"
                className="font-mono"
                placeholder="npx"
                value={form.command}
                onChange={(e) => setF({ command: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="m-args">参数（空格分隔）</Label>
              <Input
                id="m-args"
                className="font-mono"
                placeholder="-y @modelcontextprotocol/server-filesystem /data"
                value={form.args}
                onChange={(e) => setF({ args: e.target.value })}
              />
            </div>
          </>
        ) : (
          <div className="grid gap-2">
            <Label htmlFor="m-url">远程 URL</Label>
            <Input
              id="m-url"
              className="font-mono"
              placeholder="https://mcp.example.com/mcp"
              value={form.url}
              onChange={(e) => setF({ url: e.target.value })}
            />
            <label className="flex items-center gap-2 text-sm">
              <Checkbox
                checked={form.insecure}
                onCheckedChange={(v) => setF({ insecure: v === true })}
              />
              跳过 TLS 证书校验（自签证书）
            </label>
          </div>
        )}
        <div className="grid gap-2">
          <Label htmlFor="m-env">
            {form.transport !== "stdio"
              ? "请求头（每行 KEY=VALUE，如 Authorization=Bearer xxx）"
              : "环境变量（每行 KEY=VALUE）"}
          </Label>
          <Textarea
            id="m-env"
            className="font-mono"
            placeholder={
              form.transport !== "stdio" ? "Authorization=Bearer xxxx" : "API_KEY=xxxx\nFOO=bar"
            }
            value={form.env}
            onChange={(e) => setF({ env: e.target.value })}
          />
        </div>
      </div>
    );
  }

  function renderTools() {
    return (
      <div className="flex flex-col gap-3 py-4">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground text-sm">{tools.length} 个工具</span>
          <Button size="sm" variant="outline" disabled={refreshing} onClick={refreshTools}>
            <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> 刷新
          </Button>
        </div>
        {toolsLoading ? (
          <p className="text-muted-foreground text-sm">加载中…</p>
        ) : tools.length === 0 ? (
          <p className="text-muted-foreground text-sm">尚未发现工具，点击刷新重新获取。</p>
        ) : (
          <div className="flex flex-col divide-y">
            {tools.map((t) => (
              <div key={t.name} className="py-2.5">
                <code className="font-mono text-sm">{t.name}</code>
                {t.description && (
                  <p className="mt-0.5 text-muted-foreground text-xs leading-relaxed">
                    {t.description}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="font-semibold text-xl tracking-tight">MCP</h1>
        <p className="text-muted-foreground text-sm">外部 MCP 工具服务器 · 按 Agent 授权可见</p>
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex items-baseline gap-2">
          <h2 className="font-medium text-sm">常用 MCP 预设</h2>
          <span className="text-muted-foreground text-xs">
            点击即填充配置，确认后再保存（依赖见每个预设的说明）
          </span>
        </div>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-4">
          {mcpPresets.map((p) => (
            <button
              key={p.name}
              type="button"
              onClick={() => openPreset(p)}
              className="flex flex-col items-start gap-1 rounded-lg border bg-card p-3 text-left transition hover:border-primary/60 hover:shadow-sm"
            >
              <span className="flex items-center gap-2 font-medium text-sm">
                <ServerIcon className="size-4 text-muted-foreground" /> {p.title}
              </span>
              <span className="line-clamp-2 text-muted-foreground text-xs leading-relaxed">
                {p.description}
              </span>
              {p.requires ? (
                <span className="text-[11px] text-muted-foreground/80">{p.requires}</span>
              ) : null}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <button
          type="button"
          onClick={openAdd}
          className="flex min-h-[116px] flex-col items-center justify-center gap-2 rounded-xl border border-foreground/70 border-dashed text-foreground/70 transition hover:bg-muted/60 hover:shadow-sm"
        >
          <PlusIcon className="size-6" />
          <span className="text-sm">添加 MCP</span>
        </button>

        {servers.map((s) => (
          <Card
            key={s.id}
            onClick={() => openEdit(s)}
            className="cursor-pointer gap-3 transition hover:border-primary/60 hover:shadow-sm"
          >
            <CardHeader>
              <div className="flex items-center gap-2">
                <ServerIcon className="size-4 shrink-0 text-muted-foreground" />
                <CardTitle className="truncate text-base">{s.name}</CardTitle>
                <Badge variant="outline" className="uppercase">
                  {s.transport}
                </Badge>
                <div className="ml-auto flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  <Switch
                    checked={s.enabled}
                    onCheckedChange={() => toggleEnabled(s)}
                    aria-label="启用"
                  />
                  <Button
                    size="icon"
                    variant="outline"
                    aria-label="删除"
                    onClick={() => setPendingDelete(s)}
                  >
                    <Trash2Icon className="text-destructive" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="grid gap-3">
              <p className="text-muted-foreground text-sm">
                {s.tools && s.tools.length > 0 ? `${s.tools.length} 个工具` : "尚未发现工具"}
              </p>
              <div className="grid gap-2" onClick={(e) => e.stopPropagation()}>
                <span className="text-muted-foreground text-xs">可见性（按 Agent 授权）</span>
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {agents.map((a) => (
                    <label key={a.key} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={(visibility[s.id] ?? []).includes(a.id)}
                        onCheckedChange={() => toggleVisibility(s.id, a.id, a.name)}
                      />
                      {a.name}
                    </label>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent
          side="right"
          className="w-full data-[side=right]:sm:max-w-lg"
        >
          <SheetHeader>
            <SheetTitle>{editing ? editing.name : "添加 MCP 服务器"}</SheetTitle>
            <SheetDescription>
              stdio（本地起进程）或 http（远程 Streamable HTTP）
            </SheetDescription>
          </SheetHeader>

          {editing ? (
            <Tabs
              value={tab}
              onValueChange={(v) => setTab(v as "config" | "tools")}
              className="flex min-h-0 flex-1 flex-col px-4"
            >
              <TabsList>
                <TabsTrigger value="config">配置</TabsTrigger>
                <TabsTrigger value="tools">
                  工具列表{tools.length ? `（${tools.length}）` : ""}
                </TabsTrigger>
              </TabsList>
              <TabsContent value="config" className="min-h-0 flex-1 overflow-y-auto">
                {renderForm()}
                <div className="flex gap-2 pt-2 pb-6">
                  <Button onClick={saveForm} disabled={saving}>
                    保存
                  </Button>
                </div>
              </TabsContent>
              <TabsContent value="tools" className="min-h-0 flex-1 overflow-y-auto">
                {renderTools()}
              </TabsContent>
            </Tabs>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
              {renderForm()}
              <div className="pt-2 pb-6">
                <Button onClick={saveForm} disabled={saving}>
                  <PlusIcon /> 添加
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* ── 删除二次确认 ── */}
      <AlertDialog open={!!pendingDelete} onOpenChange={(o) => { if (!o) setPendingDelete(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>删除 MCP 服务器「{pendingDelete?.name}」？</AlertDialogTitle>
            <AlertDialogDescription>
              将移除该服务器及其全部工具发现结果；引用其工具的 Agent 会立即失去这些工具。此操作不可撤销。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={deleting}
              onClick={(e) => { e.preventDefault(); if (pendingDelete) void removeServer(pendingDelete); }}
            >
              {deleting ? "删除中…" : "删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
