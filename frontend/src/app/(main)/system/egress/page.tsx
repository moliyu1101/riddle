"use client";

import * as React from "react";

import { CableIcon, PlayIcon, PlusIcon, RefreshCwIcon, SquareIcon, Trash2Icon, UploadCloudIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
import { api } from "@/lib/api";
import type { SSHProvider } from "@/lib/types";

// 执行 → SSH 跳板（v0.7.1）：用已授权主机做 SOCKS5 出口。
// 密码/私钥只进凭据保险库；启动后把本地 socks5://127.0.0.1:port 加进代理池即可。
export default function EgressPage() {
  const [rows, setRows] = React.useState<SSHProvider[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [addOpen, setAddOpen] = React.useState(false);
  const [saving, setSaving] = React.useState(false);
  const [busyId, setBusyId] = React.useState<number | null>(null);
  const [form, setForm] = React.useState({
    name: "",
    host: "",
    port: "22",
    user: "root",
    auth_kind: "key",
    secret: "",
  });

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.sshProviders();
      setRows(r.providers ?? []);
    } catch (e) {
      toast.error(`加载失败：${String(e)}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const add = async () => {
    if (!form.host.trim() || !form.user.trim() || !form.secret.trim()) {
      toast.error("host / user / 私钥或密码必填");
      return;
    }
    setSaving(true);
    try {
      await api.createSSHProvider({
        name: form.name.trim() || undefined,
        host: form.host.trim(),
        port: Number(form.port) || 22,
        user: form.user.trim(),
        auth_kind: form.auth_kind as "key" | "password",
        secret: form.secret,
      });
      toast.success("跳板已登记（密钥已加密入库）");
      setAddOpen(false);
      setForm({ name: "", host: "", port: "22", user: "root", auth_kind: "key", secret: "" });
      void load();
    } catch (e) {
      toast.error(`登记失败：${String(e)}`);
    } finally {
      setSaving(false);
    }
  };

  const start = async (row: SSHProvider) => {
    if (busyId !== null) return;
    setBusyId(row.id);
    try {
      const r = await api.startSSHProvider(row.id);
      toast.success(`已启动：${r.socks_addr}`);
      void load();
    } catch (e) {
      toast.error(`启动失败：${String(e)}`);
    } finally {
      setBusyId(null);
    }
  };
  const stop = async (row: SSHProvider) => {
    if (busyId !== null) return;
    setBusyId(row.id);
    try {
      await api.stopSSHProvider(row.id);
      toast.success("已停止");
      void load();
    } catch (e) {
      toast.error(`停止失败：${String(e)}`);
    } finally {
      setBusyId(null);
    }
  };
  const use = async (row: SSHProvider) => {
    if (busyId !== null) return;
    setBusyId(row.id);
    try {
      const r = await api.useSSHProvider(row.id);
      toast.success(`已加入代理池：${r.socks_addr}（socks5 上游已允许）`);
    } catch (e) {
      toast.error(`加入代理池失败：${String(e)}`);
    } finally {
      setBusyId(null);
    }
  };
  const del = async (row: SSHProvider) => {
    if (!window.confirm(`删除跳板「${row.name}」？`)) return;
    try {
      await api.deleteSSHProvider(row.id);
      toast.success("已删除");
      void load();
    } catch (e) {
      toast.error(`删除失败：${String(e)}`);
    }
  };

  return (
    <div className="space-y-4 p-4 md:p-6">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <div>
            <CardTitle className="flex items-center gap-2">
              <CableIcon className="size-5" /> SSH 跳板
            </CardTitle>
            <p className="mt-1 text-sm text-muted-foreground">
              用已授权主机做 SOCKS5 出口：启动后把 <code>socks5://127.0.0.1:port</code> 加进代理池即可。
              私钥/密码加密存保险库，接口只返回 credential_id。
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="icon" onClick={() => void load()} disabled={loading}>
              <RefreshCwIcon className={loading ? "size-4 animate-spin" : "size-4"} />
            </Button>
            <Button onClick={() => setAddOpen(true)}>
              <PlusIcon className="size-4" /> 登记跳板
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table className="w-full table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className="hidden w-12 sm:table-cell">ID</TableHead>
                <TableHead className="w-auto sm:w-28">名称</TableHead>
                <TableHead className="w-auto sm:w-32">地址</TableHead>
                <TableHead className="hidden w-24 lg:table-cell">用户</TableHead>
                <TableHead className="hidden w-20 lg:table-cell">状态</TableHead>
                <TableHead className="hidden w-28 xl:table-cell">本地出口</TableHead>
                <TableHead className="w-28 text-right">操作</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-10 text-center text-sm text-muted-foreground">
                    {loading ? "加载中…" : "还没有跳板。点右上角「登记跳板」，填 host/port/user 和私钥或密码。"}
                  </TableCell>
                </TableRow>
              )}
              {rows.map((r) => (
                <TableRow key={r.id}>
                  <TableCell className="hidden font-mono text-xs sm:table-cell">#{r.id}</TableCell>
                  <TableCell className="truncate" title={r.name}>{r.name}</TableCell>
                  <TableCell className="truncate font-mono text-xs" title={`${r.host}:${r.port}`}>
                    {r.host}:{r.port}
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs lg:table-cell">{r.user}</TableCell>
                  <TableCell className="hidden lg:table-cell">
                    {r.status === "running" ? <Badge>运行中</Badge> : <Badge variant="secondary">已停止</Badge>}
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs xl:table-cell">{r.socks_addr || "—"}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex justify-end gap-1">
                      {r.status === "running" ? (
                        <>
                          <Button variant="ghost" size="icon" title="停止" disabled={busyId === r.id} onClick={() => void stop(r)}>
                            <SquareIcon className="size-4" />
                          </Button>
                          <Button variant="ghost" size="icon" title="加入代理池" disabled={busyId === r.id} onClick={() => void use(r)}>
                            <UploadCloudIcon className="size-4" />
                          </Button>
                        </>
                      ) : (
                        <Button variant="ghost" size="icon" title="启动" disabled={busyId === r.id} onClick={() => void start(r)}>
                          <PlayIcon className="size-4" />
                        </Button>
                      )}
                      <Button variant="ghost" size="icon" title="删除" disabled={busyId === r.id} onClick={() => void del(r)}>
                        <Trash2Icon className="size-4 text-destructive" />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Dialog open={addOpen} onOpenChange={setAddOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>登记 SSH 跳板</DialogTitle>
            <DialogDescription>仅登记你已获得授权的主机。私钥/密码会加密存进凭据保险库。</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label>名称（可选）</Label>
                <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="香港跳板" />
              </div>
              <div className="space-y-1.5">
                <Label>认证方式</Label>
                <Select value={form.auth_kind} onValueChange={(v) => setForm({ ...form, auth_kind: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="key">私钥</SelectItem>
                    <SelectItem value="password">密码</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              <div className="col-span-2 space-y-1.5">
                <Label>Host</Label>
                <Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="1.2.3.4" />
              </div>
              <div className="space-y-1.5">
                <Label>端口</Label>
                <Input value={form.port} onChange={(e) => setForm({ ...form, port: e.target.value })} />
              </div>
            </div>
            <div className="space-y-1.5">
              <Label>用户</Label>
              <Input value={form.user} onChange={(e) => setForm({ ...form, user: e.target.value })} />
            </div>
            <div className="space-y-1.5">
              <Label>{form.auth_kind === "key" ? "私钥（PEM）" : "密码"}</Label>
              <Textarea
                rows={form.auth_kind === "key" ? 6 : 2}
                className="font-mono text-xs"
                value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })}
                placeholder={form.auth_kind === "key" ? "-----BEGIN OPENSSH PRIVATE KEY-----" : ""}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setAddOpen(false)}>
              取消
            </Button>
            <Button onClick={() => void add()} disabled={saving}>
              {saving ? "保存中…" : "保存"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
