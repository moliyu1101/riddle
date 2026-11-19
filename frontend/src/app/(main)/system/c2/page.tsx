"use client";

import * as React from "react";
import { toast } from "sonner";
import { PlayIcon, RadioTower, SquareIcon, RefreshCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
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
import { api } from "@/lib/api";
import type { C2Config, ListenerSession, ListenerView } from "@/lib/types";

const MODE_LABEL: Record<string, string> = {
  direct: "直连（本机可达）",
  ssh: "SSH 中继托管",
  manual: "手工转发",
};

function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return isNaN(d.getTime()) ? iso : d.toLocaleString();
}

export default function C2Page() {
  // ── C2 出口配置 ──
  const [cfg, setCfg] = React.useState<C2Config | null>(null);
  const [mode, setMode] = React.useState<string>("direct");
  const [host, setHost] = React.useState("");
  const [ssh, setSsh] = React.useState("");
  const [pass, setPass] = React.useState("");
  const [key, setKey] = React.useState("");
  const [iface, setIface] = React.useState("");
  const [hasPass, setHasPass] = React.useState(false);
  const [savingCfg, setSavingCfg] = React.useState(false);

  // ── 监听器 ──
  const [listeners, setListeners] = React.useState<ListenerView[]>([]);
  const [name, setName] = React.useState("");
  const [port, setPort] = React.useState("");
  const [starting, setStarting] = React.useState(false);
  const [pendingStop, setPendingStop] = React.useState<ListenerView | null>(null);
  const [stopping, setStopping] = React.useState(false);
  const [expanded, setExpanded] = React.useState<string | null>(null);
  const [refreshing, setRefreshing] = React.useState(false);

  const loadCfg = React.useCallback(async () => {
    try {
      const c = await api.c2Config();
      setCfg(c);
      setMode(c.mode || "direct");
      setHost(c.host || "");
      setSsh(c.ssh || "");
      setKey(c.key || "");
      setIface(c.iface || "");
      setHasPass(c.has_pass);
      setPass("");
    } catch (e) {
      toast.error(`加载 C2 配置失败：${(e as Error).message}`);
    }
  }, []);

  const loadListeners = React.useCallback(async () => {
    setRefreshing(true);
    try {
      const r = await api.listeners();
      setListeners(r.listeners ?? []);
    } catch (e) {
      toast.error(`加载监听器失败：${(e as Error).message}`);
    } finally {
      setRefreshing(false);
    }
  }, []);

  React.useEffect(() => {
    void loadCfg();
    void loadListeners();
    // 监听器状态与会话在变（目标回连随时进来），10s 轮询与任务列表同节奏。
    const t = setInterval(() => void loadListeners(), 10_000);
    return () => clearInterval(t);
  }, [loadCfg, loadListeners]);

  async function saveCfg() {
    setSavingCfg(true);
    try {
      const patch: Record<string, string> = { mode };
      if (mode === "manual" || mode === "ssh") patch.host = host;
      if (mode === "ssh") {
        patch.ssh = ssh;
        patch.key = key;
        // 密码留空=不变更；要清空输入一个空格再 trim 的歧义不值得——这里约定
        // 留空即不变，后端 has_pass 提示当前是否已设。
        if (pass !== "") patch.password = pass;
      }
      if (mode === "direct") patch.iface = iface;
      const saved = await api.saveC2Config(patch);
      setCfg(saved);
      setHasPass(saved.has_pass);
      setPass("");
      toast.success("C2 出口配置已保存");
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setSavingCfg(false);
    }
  }

  async function startListener() {
    const p = Number(port);
    const nm = name.trim();
    if (!nm) {
      toast.error("请填写监听器名称");
      return;
    }
    if (!Number.isInteger(p) || p < 1024 || p > 65535) {
      toast.error("端口须为 1024-65535 的整数（低端口绑定为特权操作，走外部转发）");
      return;
    }
    setStarting(true);
    try {
      const r = await api.startListener(nm, p);
      toast.success(`监听器 ${r.name} 已启动，回连地址 ${r.connect_back.lhost}:${r.connect_back.lport}`);
      setName("");
      setPort("");
      await loadListeners();
      setExpanded(r.name);
    } catch (e) {
      toast.error(`启动失败：${(e as Error).message}`);
    } finally {
      setStarting(false);
    }
  }

  async function stopListener(l: ListenerView) {
    setStopping(true);
    try {
      const r = await api.stopListener(l.name);
      toast.success(`已停止 ${r.stopped}（${r.sessions.length} 条会话已留档）`);
      setPendingStop(null);
      await loadListeners();
    } catch (e) {
      toast.error(`停止失败：${(e as Error).message}`);
    } finally {
      setStopping(false);
    }
  }

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      {/* ── C2 出口配置 ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2 text-base">
            <RadioTower className="size-4" /> C2 出口配置
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <p className="text-muted-foreground text-sm">
            决定反弹 shell / OOB 该连哪里：<b>direct</b>=本机可达（零配置）；
            <b>ssh</b>=本机无公网+公网中转机，平台自动建 SSH 反向隧道（断线重连，随监听器启停）；
            <b>manual</b>=已有手工转发，只展示中转地址。agent 调 <code>listener_start</code> 时
            回连地址以此配置解析，无需自行判断网络形态。
          </p>
          <div className="grid gap-2 sm:max-w-sm">
            <Label>出口形态</Label>
            <Select value={mode} onValueChange={setMode}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="direct">direct · 本机可达</SelectItem>
                <SelectItem value="ssh">ssh · 公网中转机托管</SelectItem>
                <SelectItem value="manual">manual · 已有手工转发</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {(mode === "ssh" || mode === "manual") && (
            <div className="grid gap-2 sm:max-w-sm">
              <Label>中转机公网地址（回显给目标的 LHOST）</Label>
              <Input value={host} onChange={(e) => setHost(e.target.value)} placeholder="例如 1.2.3.4" />
            </div>
          )}
          {mode === "ssh" && (
            <>
              <div className="grid gap-2 sm:max-w-sm">
                <Label>中转机 SSH（user@host[:port]）</Label>
                <Input value={ssh} onChange={(e) => setSsh(e.target.value)} placeholder="root@1.2.3.4:22" />
              </div>
              <div className="grid gap-2 sm:max-w-sm">
                <Label>SSH 密码{hasPass ? "（已设置，留空保持不变）" : ""}</Label>
                <Input
                  type="password"
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  placeholder={hasPass ? "••••••••" : "中转机 SSH 密码"}
                />
              </div>
              <div className="grid gap-2 sm:max-w-sm">
                <Label>SSH 私钥路径（可选，与密码二选一）</Label>
                <Input value={key} onChange={(e) => setKey(e.target.value)} placeholder="/root/.ssh/id_rsa" />
              </div>
            </>
          )}
          {mode === "direct" && (
            <div className="grid gap-2 sm:max-w-sm">
              <Label>出口网卡（可选，留空自动取默认路由源地址）</Label>
              <Input value={iface} onChange={(e) => setIface(e.target.value)} placeholder="例如 eth0" />
            </div>
          )}
          <div>
            <Button onClick={saveCfg} disabled={savingCfg}>
              {savingCfg ? "保存中…" : "保存配置"}
            </Button>
            {cfg && (
              <span className="text-muted-foreground ml-3 text-sm">
                当前：<b>{MODE_LABEL[cfg.mode] ?? cfg.mode}</b>
                {cfg.ssh ? ` · ${cfg.ssh}` : ""}
              </span>
            )}
          </div>
        </CardContent>
      </Card>

      {/* ── 监听器 ── */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center justify-between text-base">
            <span className="flex items-center gap-2">
              <RadioTower className="size-4" /> 回连接收器（{listeners.length}）
            </span>
            <Button size="sm" variant="outline" onClick={() => void loadListeners()} disabled={refreshing}>
              <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> 刷新
            </Button>
          </CardTitle>
        </CardHeader>
        <CardContent className="grid gap-4">
          <div className="grid items-end gap-2 sm:grid-cols-[1fr_140px_auto]">
            <div className="grid gap-1">
              <Label>监听器名称</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="例如 shell-main" />
            </div>
            <div className="grid gap-1">
              <Label>端口（1024-65535）</Label>
              <Input value={port} onChange={(e) => setPort(e.target.value)} placeholder="4444" inputMode="numeric" />
            </div>
            <Button onClick={() => void startListener()} disabled={starting}>
              <PlayIcon /> {starting ? "启动中…" : "启动监听"}
            </Button>
          </div>

          {listeners.length === 0 && (
            <p className="text-muted-foreground text-sm">
              暂无运行中的监听器。agent 在任务里调 <code>listener_start</code> 也会走到这里（启停需人工审批）。
            </p>
          )}

          {listeners.map((l) => (
            <div key={l.name} className="rounded-lg border">
              <div className="flex flex-wrap items-center gap-2 p-3">
                <Badge variant="secondary">{l.name}</Badge>
                <span className="font-mono text-sm">:{l.port}</span>
                <span className="text-muted-foreground text-sm">起于 {fmtTime(l.started_at)}</span>
                <Badge variant={l.sessions.some((s) => s.open) ? "default" : "outline"}>
                  {l.sessions.length} 会话
                </Badge>
                <div className="grow" />
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setExpanded(expanded === l.name ? null : l.name)}
                >
                  {expanded === l.name ? "收起会话" : "查看会话"}
                </Button>
                <Button size="sm" variant="outline" className="text-destructive" onClick={() => setPendingStop(l)}>
                  <SquareIcon /> 停止
                </Button>
              </div>
              {expanded === l.name && (
                <div className="border-t">
                  {l.sessions.length === 0 ? (
                    <p className="text-muted-foreground p-3 text-sm">尚无回连会话。</p>
                  ) : (
                    l.sessions.map((s) => <SessionRow key={s.id} s={s} />)
                  )}
                </div>
              )}
            </div>
          ))}
        </CardContent>
      </Card>

      {/* ── 停止确认 ── */}
      <AlertDialog open={!!pendingStop} onOpenChange={(o) => { if (!o) setPendingStop(null); }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>停止监听器「{pendingStop?.name}」？</AlertDialogTitle>
            <AlertDialogDescription>
              端口立即关闭，{pendingStop?.sessions.length ?? 0} 条会话随停止留档（数据保留，可在停止响应中导出）。
              SSH 中继模式下托管隧道将一并拆除。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={stopping}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={stopping}
              onClick={(e) => { e.preventDefault(); if (pendingStop) void stopListener(pendingStop); }}
            >
              {stopping ? "停止中…" : "停止"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}

function SessionRow({ s }: { s: ListenerSession }) {
  const [openView, setOpenView] = React.useState(false);
  return (
    <div className="border-b px-3 py-2 last:border-b-0">
      <button
        className="flex w-full flex-wrap items-center gap-2 text-left text-sm"
        onClick={() => setOpenView(!openView)}
      >
        <Badge variant={s.open ? "default" : "secondary"}>{s.open ? "在线" : "已断开"}</Badge>
        <span className="font-mono">{s.remote}</span>
        <span className="text-muted-foreground">接入 {fmtTime(s.connected_at)}</span>
        <span className="text-muted-foreground">{fmtBytes(Number(s.bytes_in))}</span>
        <span className="text-muted-foreground grow text-right text-xs">{openView ? "收起" : "查看捕获内容"}</span>
      </button>
      {openView && (
        <pre className="bg-muted mt-2 max-h-64 overflow-auto rounded p-2 text-xs whitespace-pre-wrap">
          {s.preview || "（无捕获内容）"}
        </pre>
      )}
    </div>
  );
}
