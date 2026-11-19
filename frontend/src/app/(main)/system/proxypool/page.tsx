"use client";

import * as React from "react";
import Link from "next/link";

import {
  AlertTriangleIcon,
  CheckCircle2Icon,
  ClipboardPasteIcon,
  DownloadIcon,
  FlaskConicalIcon,
  PlayIcon,
  PlusIcon,
  RefreshCwIcon,
  SaveIcon,
  SquareIcon,
  Trash2Icon,
  WifiIcon,
  XCircleIcon,
} from "lucide-react";
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
  DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { api } from "@/lib/api";
import type {
  LocalProxyCandidate,
  MihomoStatus,
  ProxyPoolEntry,
  ProxyPoolRunning,
  ProxyPoolSubscription,
} from "@/lib/types";

const STRATEGY_LABEL: Record<string, string> = {
  round_robin: "轮询(按权重)",
  sticky_host: "按目标粘性(同目标固定出口)",
  sticky_host_random: "按目标粘性(首次随机)",
  random: "随机",
};

type CheckRow = {
  index: number;
  url: string;
  ok: boolean;
  latency_ms: number;
  exit_ip?: string;
  error?: string;
  checked_at: string;
};

// 系统 → 代理池:多上游出口配置(轮换/粘性/随机),条目启停与权重。
// 保存即热应用(upstream 钩子按请求选代理);连败 5 次自动熔断 10 分钟,
// 另有主动健康检查定时验证、不通即熔断。
export default function ProxyPoolPage() {
  const [entries, setEntries] = React.useState<ProxyPoolEntry[]>([]);
  const [strategy, setStrategy] = React.useState("round_robin");
  // 严格出口（默认关，公开版保持旧行为；UI 可开）：池已配置但全部不可用时，
  // 目标请求失败而不是回退直连。
  const [strict, setStrict] = React.useState(false);
  const [running, setRunning] = React.useState<ProxyPoolRunning[]>([]);
  const [capturing, setCapturing] = React.useState(false);
  const [checkTarget, setCheckTarget] = React.useState("");
  const [healthMinutes, setHealthMinutes] = React.useState(10);
  const [lastCheck, setLastCheck] = React.useState<{
    at: string;
    target: string;
    count: number;
    ok_count: number;
    auto?: boolean;
  } | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);
  const [checking, setChecking] = React.useState(false);
  const [checkRows, setCheckRows] = React.useState<CheckRow[]>([]);
  // 批量操作选择：按下标存，加载/保存/删除后清空（下标会变）。
  const [selected, setSelected] = React.useState<Set<number>>(new Set());
  const [bulkOpen, setBulkOpen] = React.useState(false);
  const [subOpen, setSubOpen] = React.useState(false);
  const [subURL, setSubURL] = React.useState("");
  const [subLoading, setSubLoading] = React.useState(false);
  const [subResult, setSubResult] = React.useState<ProxyPoolSubscription | null>(null);
  // 出口组：Clash MATCH 到哪个 proxy-group（空 = 默认第一个组）。
  const [outbound, setOutbound] = React.useState("");
  const [mihomo, setMihomo] = React.useState<MihomoStatus | null>(null);
  const [mihomoBusy, setMihomoBusy] = React.useState(false);
  // 安装源：官方 GitHub 资产在受限网络常连不上，提供「镜像 URL / 服务器本地文件」两条路。
  const [installSrcOpen, setInstallSrcOpen] = React.useState(false);
  const [installURL, setInstallURL] = React.useState("");
  const [installSHA, setInstallSHA] = React.useState("");
  const [installPath, setInstallPath] = React.useState("");
  const [localBusy, setLocalBusy] = React.useState(false);
  const [localCandidates, setLocalCandidates] = React.useState<LocalProxyCandidate[]>([]);
  const [bulkText, setBulkText] = React.useState("");
  const [bulkMode, setBulkMode] = React.useState<"append" | "replace">("append");
  // 导入前自动验活（默认开）：连不通的行不导入，逐行给出原因。
  const [bulkVerify, setBulkVerify] = React.useState(true);
  const [bulkRejected, setBulkRejected] = React.useState<
    { line: number; raw: string; reason: string }[]
  >([]);
  // 总开关与可用数（0 可用时任务会回退直连/全局代理）。
  const [enabled, setEnabled] = React.useState(true);
  const [usable, setUsable] = React.useState(0);

  const load = React.useCallback(() => {
    setLoading(true);
    api
      .proxyPoolGet()
      .then((r) => {
        setEntries(r.entries ?? []);
        setStrategy(r.strategy || "round_robin");
        setStrict(!!r.strict);
        setEnabled(r.enabled !== false);
        setRunning(r.running ?? []);
        setUsable(r.usable ?? (r.running ?? []).filter((x) => (x.break_remaining ?? 0) === 0).length);
        setCapturing(r.capturing);
        setCheckTarget(r.check_target ?? "");
        setHealthMinutes(r.health_minutes ?? 10);
        setLastCheck(r.last_check ?? null);
        setSelected(new Set());
      })
      .catch((e) => toast.error("加载失败: " + e))
      .finally(() => setLoading(false));
    api.proxyPoolMihomoStatus()
      .then((r) => setMihomo(r.status))
      .catch(() => {
        /* 老版本后端没有 mihomo 接口时静默降级 */
      });
  }, []);

  React.useEffect(load, [load]);

  // 批量导入一段文本（订阅 URI 列表 / 直连节点），并统一提示结果。
  const bulkImportText = async (text: string, note?: string) => {
    const res = await api.proxyPoolBulk({ text, mode: "append", verify: true });
    toast.success(
      `订阅导入：新增 ${res.added}、更新 ${res.updated}${note ? `；${note}` : ""}`,
      { duration: 6000 },
    );
    if (res.verify_skipped) toast.warning(res.verify_skipped);
  };

  // 订阅拉取：URI 列表直接导入；Clash YAML 展示「mihomo 启动 / 本机 Clash / 直连节点」三条路。
  const importSubscription = async () => {
    if (!subURL.trim()) {
      toast.error("请填写订阅地址");
      return;
    }
    setSubLoading(true);
    try {
      const r = await api.proxyPoolSubscriptionFetch(subURL.trim());
      setSubResult(r);
      setOutbound(r.group_names?.[0] ?? "");
      if (r.format === "clash") {
        toast.info(
          `识别到 Clash YAML：${r.proxies ?? 0} 个节点，${r.direct_nodes ?? 0} 个可直接用；请选择 mihomo 启动或检测本机 Clash`,
          { duration: 8000 },
        );
        return;
      }
      if (!(r.supported?.length ?? 0)) {
        toast.error(r.note || "订阅里没有可直接使用的 http/https/socks5 节点");
        return;
      }
      await bulkImportText(r.text, r.note);
      setSubOpen(false);
      setSubURL("");
      setSubResult(null);
      load();
    } catch (e) {
      toast.error("订阅导入失败: " + String(e));
    } finally {
      setSubLoading(false);
    }
  };

  // 仅导入 Clash YAML 里 type=http/socks5 的节点（不启动内核）。
  const importDirectNodes = async () => {
    if (!subResult?.text) {
      toast.error("这份 Clash 配置没有可直接导入的 http/socks5 节点");
      return;
    }
    try {
      await bulkImportText(subResult.text, subResult.note);
      load();
    } catch (e) {
      toast.error("导入直连节点失败: " + String(e));
    }
  };

  const installMihomo = async () => {
    setMihomoBusy(true);
    try {
      const r = await api.proxyPoolMihomoInstall();
      toast.success(`mihomo ${r.install.version} 已安装`, { duration: 6000 });
      const st = await api.proxyPoolMihomoStatus();
      setMihomo(st.status);
    } catch (e) {
      toast.error("安装 mihomo 失败: " + String(e), { duration: 10000 });
    } finally {
      setMihomoBusy(false);
    }
  };

  // 从镜像 URL / 服务器本地文件安装。官方 GitHub 资产在受限网络会 60s 超时。
  const installMihomoFrom = async (mode: "url" | "path") => {
    setMihomoBusy(true);
    try {
      const r = await api.proxyPoolMihomoInstall(
        mode === "url"
          ? { url: installURL.trim(), sha256: installSHA.trim() }
          : { path: installPath.trim() },
      );
      toast.success(`mihomo ${r.install.version || "已安装"}`, { duration: 6000 });
      const st = await api.proxyPoolMihomoStatus();
      setMihomo(st.status);
    } catch (e) {
      toast.error("安装 mihomo 失败: " + String(e), { duration: 10000 });
    } finally {
      setMihomoBusy(false);
    }
  };

  const startMihomo = async () => {
    const yaml = subResult?.clash_yaml;
    if (!yaml) {
      toast.error("先拉取 Clash 订阅");
      return;
    }
    setMihomoBusy(true);
    try {
      const r = await api.proxyPoolMihomoStart({
        yaml,
        use: true,
        outbound: outbound || undefined,
      });
      setMihomo(r.status);
      toast.success(
        `mihomo 已启动，mixed-port ${r.status.port}${r.status.last_error ? `；${r.status.last_error}` : ""}`,
        { duration: 8000 },
      );
      load();
    } catch (e) {
      toast.error("mihomo 启动失败: " + String(e), { duration: 10000 });
    } finally {
      setMihomoBusy(false);
    }
  };

  const stopMihomo = async () => {
    setMihomoBusy(true);
    try {
      await api.proxyPoolMihomoStop();
      toast.success("mihomo 已停止，对应池条目已移除");
      const st = await api.proxyPoolMihomoStatus();
      setMihomo(st.status);
      load();
    } catch (e) {
      toast.error("停止 mihomo 失败: " + String(e));
    } finally {
      setMihomoBusy(false);
    }
  };

  const detectLocal = async (use = true, ports?: number[]) => {
    setLocalBusy(true);
    try {
      const r = await api.proxyPoolDetectLocal({ ports, use });
      setLocalCandidates(r.candidates ?? []);
      const ok = (r.candidates ?? []).filter((c) => c.ok).length;
      if (ok === 0) {
        toast.warning("没有发现可用本机 Clash 端口；请先启动 Clash/mihomo，或检查端口设置");
      } else {
        toast.success(`发现 ${ok} 个可用本机端口${use ? `，已加入 ${r.added} 条` : ""}`);
      }
      if (use) load();
    } catch (e) {
      toast.error("检测本机代理失败: " + String(e));
    } finally {
      setLocalBusy(false);
    }
  };

  const save = async () => {
    // 空列表保存 = 清空整池：必须人工确认（页面状态过期时也不能静默清掉）。
    let confirmClear = false;
    if (entries.length === 0) {
      if (typeof window !== "undefined" && !window.confirm("当前列表为空，保存会清空代理池里的全部条目。确定？")) {
        return;
      }
      confirmClear = true;
    }
    setSaving(true);
    try {
      await api.proxyPoolPut({ entries, strategy, enabled, strict, confirm_clear: confirmClear });
      toast.success("代理池已保存并热应用");
      load();
    } catch (e) {
      toast.error("保存失败: " + e);
    } finally {
      setSaving(false);
    }
  };

  // 严格出口：立即热应用。开启后池全部熔断时请求失败而不是直连。
  const toggleStrict = async (v: boolean) => {
    setStrict(v);
    try {
      await api.proxyPoolPut({ entries, strategy, enabled, strict: v });
      toast.success(v ? "严格出口已开启：代理不可用时请求失败，不会回退直连" : "严格出口已关闭：代理不可用时会回退全局代理/直连");
      load();
    } catch (e) {
      setStrict(!v);
      toast.error("切换失败: " + e);
    }
  };

  // 总开关：立即热应用（不需要点保存）。
  const toggleEnabled = async (v: boolean) => {
    setEnabled(v);
    try {
      await api.proxyPoolPut({ entries, strategy, enabled: v, strict });
      toast.success(v ? "代理池已启用 · 新请求开始走池内出口" : "代理池已停用 · 回退全局代理/直连");
      load();
    } catch (e) {
      setEnabled(!v);
      toast.error("切换失败: " + e);
    }
  };

  const update = (i: number, patch: Partial<ProxyPoolEntry>) => {
    setEntries((prev) => prev.map((e, j) => (j === i ? { ...e, ...patch } : e)));
  };

  const failuresByURL = React.useMemo(() => {
    const m: Record<string, ProxyPoolRunning> = {};
    for (const r of running) m[r.url] = r;
    return m;
  }, [running]);

  // 失效 = 熔断中（被动连败或主动健康检查判定不通）。
  const deadURLs = React.useMemo(
    () => new Set(running.filter((r) => (r.break_remaining ?? 0) > 0).map((r) => r.url)),
    [running],
  );

  const runCheck = async (urls?: string[]) => {
    setChecking(true);
    try {
      const res = await api.proxyPoolCheck({
        urls,
        target: checkTarget || undefined,
        break_on_fail: true,
      });
      setCheckRows(res.results ?? []);
      const ok = (res.results ?? []).filter((r) => r.ok).length;
      const total = (res.results ?? []).length;
      if (total === 0) {
        toast.warning("没有可验证的条目（池为空或已全部停用）");
      } else {
        toast.success(`验证完成：${ok}/${total} 可用，不通的已熔断`);
      }
      load();
    } catch (e) {
      toast.error("验证失败: " + e);
    } finally {
      setChecking(false);
    }
  };

  const doBulk = async () => {
    try {
      const res = await api.proxyPoolBulk({
        text: bulkText,
        mode: bulkMode,
        verify: bulkVerify,
      });
      const bad = res.invalid?.length ?? 0;
      const rejected = res.rejected ?? [];
      setBulkRejected(rejected);
      const parts = [`新增 ${res.added}`, `更新 ${res.updated}`];
      if (bad) parts.push(`${bad} 行无效`);
      if (rejected.length) parts.push(`${rejected.length} 个连不通（新增已丢弃/原有已停用）`);
      if (res.verify_skipped) parts.push("验活已跳过");
      toast.success(`导入完成：${parts.join("、")}`);
      if (res.verify_skipped) toast.warning(res.verify_skipped);
      setBulkOpen(rejected.length > 0 || bad > 0);
      if (rejected.length === 0 && bad === 0) {
        setBulkText("");
        setBulkOpen(false);
      }
      load();
    } catch (e) {
      toast.error("导入失败: " + e);
    }
  };

  // 最近一次验证判失败的条目（按后端返回的全量下标映射回 entries）。
  const failedIndexes = React.useMemo(() => {
    const s = new Set<number>();
    for (const r of checkRows) {
      if (!r.ok && r.index >= 0 && r.index < entries.length) s.add(r.index);
    }
    return s;
  }, [checkRows, entries.length]);

  const deadIndexes = React.useMemo(() => {
    const s = new Set<number>();
    entries.forEach((e, i) => {
      if (deadURLs.has(e.url)) s.add(i);
    });
    return s;
  }, [entries, deadURLs]);

  const toggleSelect = (i: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  };

  const selectedURLs = React.useMemo(
    () => [...selected].map((i) => entries[i]?.url).filter((u): u is string => Boolean(u)),
    [selected, entries],
  );

  const removeSelected = () => {
    if (selected.size === 0) {
      toast.info("先勾选要删除的条目");
      return;
    }
    setEntries((prev) => prev.filter((_, i) => !selected.has(i)));
    toast.success(`已移除 ${selected.size} 个条目，点「保存并热应用」生效`);
    setSelected(new Set());
    setCheckRows([]);
  };

  const removeDead = () => {
    const doomed = new Set<number>([...deadIndexes, ...failedIndexes]);
    if (doomed.size === 0) {
      toast.info("没有失效条目（先「一键检测」拿到验证结果，或等熔断状态）");
      return;
    }
    setEntries((prev) => prev.filter((_, i) => !doomed.has(i)));
    toast.success(`已移除 ${doomed.size} 个失效条目，点「保存并热应用」生效`);
    setSelected(new Set());
    setCheckRows([]);
  };

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <h1 className="text-lg font-semibold">代理池</h1>
          <div className="flex items-center gap-1.5">
            <Switch
              checked={enabled}
              onCheckedChange={toggleEnabled}
              disabled={loading}
              aria-label="启用代理池"
            />
            <span className="text-xs text-muted-foreground">{enabled ? "已启用" : "已停用"}</span>
          </div>
          <Badge variant={enabled && entries.length > 0 ? "default" : "secondary"}>
            {!enabled
              ? `已停用 · ${entries.length} 条已保存`
              : entries.length === 0
                ? "空池(直连/全局代理)"
                : `${usable}/${entries.length} 可用`}
          </Badge>
          {deadURLs.size > 0 && <Badge variant="destructive">{deadURLs.size} 个不可用</Badge>}
          {mihomo && (
            <Badge
              variant={mihomo.running ? "default" : "secondary"}
              title={mihomo.last_error || mihomo.binary || "mihomo 未安装"}
            >
              mihomo {mihomo.running ? `:${mihomo.port}` : mihomo.installed ? "已安装" : "未安装"}
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void detectLocal(true)}
            disabled={localBusy}
          >
            <WifiIcon className="mr-1 size-4" />
            {localBusy ? "检测中…" : "检测本机代理"}
          </Button>
          {mihomo?.running && (
            <Button variant="outline" size="sm" onClick={() => void stopMihomo()} disabled={mihomoBusy}>
              <SquareIcon className="mr-1 size-4" />
              停止 mihomo
            </Button>
          )}
          <Dialog open={subOpen} onOpenChange={setSubOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <RefreshCwIcon className="mr-1 size-4" />
                订阅导入
              </Button>
            </DialogTrigger>
            <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-xl">
              <DialogHeader>
                <DialogTitle>从订阅导入</DialogTitle>
                <DialogDescription>
                  支持 URI 列表和 Clash/mihomo YAML。YAML 里 http/socks5 节点可直接入池；
                  vmess/ss/trojan/vless 用「mihomo 启动并接入」或复用本机 Clash 端口。
                  订阅地址会做私网/回环校验（防 SSRF）。
                </DialogDescription>
              </DialogHeader>
              <div className="space-y-2">
                <Label>订阅地址</Label>
                <Input
                  value={subURL}
                  onChange={(e) => setSubURL(e.target.value)}
                  placeholder="https://example.com/api/v1/client/subscribe?token=..."
                  className="font-mono text-xs"
                />
              </div>
              {subResult && (
                <div className="space-y-2 rounded-md border p-3 text-xs">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <Badge variant={subResult.format === "clash" ? "default" : "secondary"}>
                      {subResult.format === "clash" ? "Clash YAML" : "URI 列表"}
                    </Badge>
                    {typeof subResult.proxies === "number" && (
                      <Badge variant="secondary">节点 {subResult.proxies}</Badge>
                    )}
                    <Badge variant="secondary">
                      可直接用 {subResult.direct_nodes ?? subResult.supported?.length ?? 0}
                    </Badge>
                    {subResult.unsupported > 0 && (
                      <Badge variant="secondary">需内核 {subResult.unsupported}</Badge>
                    )}
                    {subResult.invalid > 0 && (
                      <Badge variant="destructive">无效 {subResult.invalid}</Badge>
                    )}
                    {(subResult.ignored ?? 0) > 0 && (
                      <Badge variant="outline">忽略信息 {subResult.ignored}</Badge>
                    )}
                  </div>
                  {subResult.note && (
                    <p className="break-words text-muted-foreground">{subResult.note}</p>
                  )}
                  {!!subResult.local_ports?.length && (
                    <p>
                      YAML 自带端口：
                      <span className="ml-1 font-mono">{subResult.local_ports.join(", ")}</span>
                    </p>
                  )}
                  {subResult.format === "clash" && !!subResult.group_names?.length && (
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-muted-foreground">出口组</span>
                      <Select
                        value={outbound || subResult.group_names[0]}
                        onValueChange={setOutbound}
                      >
                        <SelectTrigger className="h-7 w-48 text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {subResult.group_names.map((g) => (
                            <SelectItem key={g} value={g}>
                              {g}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <span className="text-[11px] text-muted-foreground">
                        启动后规则为 MATCH,&lt;出口组&gt;
                      </span>
                    </div>
                  )}
                  {subResult.format === "clash" && (
                    <div className="flex flex-wrap gap-2 pt-1">
                      <Button size="sm" onClick={() => void startMihomo()} disabled={mihomoBusy}>
                        <PlayIcon className="mr-1 size-4" />
                        mihomo 启动并接入
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void installMihomo()}
                        disabled={mihomoBusy}
                      >
                        <DownloadIcon className="mr-1 size-4" />
                        安装 mihomo
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => void detectLocal(true, subResult.local_ports)}
                        disabled={localBusy}
                      >
                        <WifiIcon className="mr-1 size-4" />
                        用本机 Clash 端口
                      </Button>
                      {(subResult.direct_nodes ?? 0) > 0 && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => void importDirectNodes()}
                        >
                          <PlusIcon className="mr-1 size-4" />
                          仅导入直连节点
                        </Button>
                      )}
                    </div>
                  )}
                  {subResult.format === "clash" && (
                    <div className="space-y-2 pt-1">
                      <p className="text-[11px] text-muted-foreground">
                        「安装 mihomo」优先走加速镜像（校验 GitHub 官方 SHA-256），失败自动回退官方源；也可用下方安装源。
                      </p>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="h-7 px-2 text-xs"
                        onClick={() => setInstallSrcOpen((v) => !v)}
                      >
                        {installSrcOpen ? "收起安装源" : "GitHub 连不上？换安装源（镜像 / 离线）"}
                      </Button>
                      {installSrcOpen && (
                        <div className="space-y-2 rounded border p-2">
                          <p className="break-words text-muted-foreground">
                            官方 GitHub 资产在受限网络会超时。可填内网镜像地址（.gz/.zip/裸二进制），
                            或先把安装包拷到服务器再按本地文件安装。
                          </p>
                          <Input
                            value={installURL}
                            onChange={(e) => setInstallURL(e.target.value)}
                            placeholder="https://内网镜像/mihomo-linux-amd64-vX.Y.Z.gz"
                            className="h-8 font-mono text-[11px]"
                          />
                          <Input
                            value={installSHA}
                            onChange={(e) => setInstallSHA(e.target.value)}
                            placeholder="sha256（可选，强烈建议；镜像来源务必填）"
                            className="h-8 font-mono text-[11px]"
                          />
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => void installMihomoFrom("url")}
                            disabled={mihomoBusy || !installURL.trim()}
                          >
                            从 URL 安装
                          </Button>
                          <div className="border-t pt-2">
                            <Input
                              value={installPath}
                              onChange={(e) => setInstallPath(e.target.value)}
                              placeholder="服务器本地路径，如 /tmp/mihomo-linux-amd64-vX.Y.Z.gz"
                              className="h-8 font-mono text-[11px]"
                            />
                            <Button
                              size="sm"
                              variant="outline"
                              className="mt-2"
                              onClick={() => void installMihomoFrom("path")}
                              disabled={mihomoBusy || !installPath.trim()}
                            >
                              从服务器文件安装
                            </Button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                  {localCandidates.length > 0 && (
                    <div className="max-h-32 overflow-y-auto rounded border p-2 font-mono text-[11px]">
                      {localCandidates.map((c) => (
                        <div key={c.url} className={c.ok ? "text-emerald-600" : "text-muted-foreground"}>
                          {c.ok ? "✓" : "×"} {c.url}
                          {c.ok
                            ? ` · ${c.latency_ms}ms${c.exit_ip ? ` · ${c.exit_ip}` : ""}`
                            : ` · ${c.error ?? "不可用"}`}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
              <DialogFooter>
                <Button variant="outline" onClick={() => setSubOpen(false)}>
                  取消
                </Button>
                <Button onClick={() => void importSubscription()} disabled={subLoading}>
                  {subLoading ? "拉取中…" : "拉取订阅"}
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
          <Dialog open={bulkOpen} onOpenChange={setBulkOpen}>
            <DialogTrigger asChild>
              <Button variant="outline" size="sm">
                <ClipboardPasteIcon className="mr-1 size-4" />
                批量导入
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-2xl">
              <DialogHeader>
                <DialogTitle>批量导入代理</DialogTitle>
                <DialogDescription>
                  一行一个。自动识别 <code>1.2.3.4:8080</code>、
                  <code>http://…</code>、<code>socks5://user:pass@…</code>、
                  <code>1.2.3.4:8080:user:pass</code>；<code>#</code> 开头是注释；
                  <code>名字 | 地址</code> 可指定名称。省略协议按 http 处理。
                </DialogDescription>
              </DialogHeader>
              <Textarea
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                rows={12}
                className="font-mono text-xs"
                placeholder={"# 名称 | 地址\nHK-01 | 1.2.3.4:8080\nsocks5://user:pass@5.6.7.8:1080\n10.0.0.1:3128:user:pass"}
              />
              <div className="flex flex-wrap items-center gap-4">
                <div className="flex items-center gap-3">
                  <Label className="text-xs">导入方式</Label>
                  <Select
                    value={bulkMode}
                    onValueChange={(v) => setBulkMode(v as "append" | "replace")}
                  >
                    <SelectTrigger className="w-40">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="append">追加到现有列表</SelectItem>
                      <SelectItem value="replace">替换整个列表</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center gap-2">
                  <Switch
                    id="bulk-verify"
                    checked={bulkVerify}
                    onCheckedChange={setBulkVerify}
                  />
                  <Label htmlFor="bulk-verify" className="text-xs font-normal">
                    导入前验证连通（不通的不导入）
                  </Label>
                </div>
              </div>
              {bulkRejected.length > 0 && (
                <div className="max-h-40 overflow-y-auto rounded-md border p-2 text-xs">
                  <p className="mb-1 font-medium text-destructive">
                    以下 {bulkRejected.length} 个连不通，已丢弃：
                  </p>
                  <ul className="space-y-0.5 font-mono">
                    {bulkRejected.slice(0, 50).map((r) => (
                      <li key={`${r.line}-${r.raw}`} className="truncate text-muted-foreground">
                        第 {r.line} 行 {r.raw} — {r.reason}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              <DialogFooter>
                <Button variant="outline" size="sm" onClick={() => setBulkOpen(false)}>
                  取消
                </Button>
                <Button size="sm" onClick={doBulk} disabled={!bulkText.trim()}>
                  导入
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>

          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCwIcon className={"mr-1 size-4" + (loading ? " animate-spin" : "")} />
            刷新
          </Button>
          <Button size="sm" onClick={save} disabled={saving}>
            <SaveIcon className="mr-1 size-4" />
            保存并热应用
          </Button>
        </div>
      </div>

      <p className="text-xs text-muted-foreground">
        {!enabled
          ? "代理池已停用：Agent 流量回退全局出口代理或直连。"
          : capturing
            ? "代理池已启用：Agent 流量经记录代理按策略轮换出口，并全量留痕。"
            : "代理池已启用：流量捕获关闭时直接注入 Bash/WebFetch 的 HTTP_PROXY；每个 worker 启动时固定一个出口（无流量留痕）。"}
      </p>
      {enabled && entries.length > 0 && usable === 0 && (
        <p className="text-sm text-destructive">
          {strict
            ? "当前 0 个可用出口：严格出口已开启，目标请求会直接失败（不会回退直连）。请重新验证或更换代理。"
            : "当前 0 个可用出口：任务会回退直连/全局代理（真实 IP 会暴露）。请重新验证或更换代理后再启用。"}
        </p>
      )}

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">轮换策略</CardTitle>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-3">
          <Select value={strategy} onValueChange={setStrategy}>
            <SelectTrigger className="w-72">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="round_robin">轮询(按权重)</SelectItem>
              <SelectItem value="sticky_host">按目标粘性(同目标固定出口)</SelectItem>
              <SelectItem value="sticky_host_random">按目标粘性(首次随机选定)</SelectItem>
              <SelectItem value="random">随机</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            连败 5 次自动熔断 10 分钟;池非空时优先于「全局出口代理」。
            「首次随机」= 同一目标第一次随机选一个出口并固定，该出口挂掉后自动换。
          </p>
          <label className="flex w-full items-center gap-2 text-xs">
            <input
              type="checkbox"
              className="size-4"
              checked={strict}
              onChange={(e) => void toggleStrict(e.target.checked)}
            />
            严格出口：代理已配置但不可用时，目标请求失败而不是回退直连（防止真实 IP 暴露）
          </label>
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">健康检查与验证</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex flex-wrap items-end gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="check-target" className="text-xs">
                探测地址
              </Label>
              <Input
                id="check-target"
                className="w-72"
                value={checkTarget}
                onChange={(e) => setCheckTarget(e.target.value)}
                placeholder="https://api.ipify.org?format=json"
              />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="health-min" className="text-xs">
                自动检查间隔（分钟，0=关闭）
              </Label>
              <Input
                id="health-min"
                type="number"
                min={0}
                className="w-32"
                value={healthMinutes}
                onChange={(e) => setHealthMinutes(Math.max(0, Number(e.target.value) || 0))}
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => runCheck()} disabled={checking}>
              <FlaskConicalIcon className={"mr-1 size-4" + (checking ? " animate-pulse" : "")} />
              验证全部
            </Button>
            {deadURLs.size > 0 && (
              <Button variant="outline" size="sm" onClick={removeDead}>
                <Trash2Icon className="mr-1 size-4" />
                移除失效条目
              </Button>
            )}
          </div>
          {lastCheck && (
            <p className="text-xs text-muted-foreground">
              最近检查：{new Date(lastCheck.at).toLocaleString()} · {lastCheck.ok_count}/{lastCheck.count} 可用
              {lastCheck.auto ? "（自动巡检）" : ""} · 探测 {lastCheck.target}
            </p>
          )}
          {checkRows.length > 0 && (
            <div className="overflow-x-hidden rounded-md border">
              <table className="w-full table-fixed text-sm">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="py-2 pr-4 font-medium">出口</th>
                    <th className="py-2 pr-4 font-medium">结果</th>
                    <th className="py-2 pr-4 font-medium">耗时</th>
                    <th className="py-2 pr-4 font-medium">出口 IP</th>
                    <th className="py-2 pr-4 font-medium">错误</th>
                  </tr>
                </thead>
                <tbody>
                  {checkRows.map((r) => (
                    <tr key={r.index} className="border-b last:border-0">
                      <td className="py-2 pr-4 font-mono text-xs">{r.url}</td>
                      <td className="py-2 pr-4">
                        {r.ok ? (
                          <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                            <CheckCircle2Icon className="size-4" /> 可用
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-destructive">
                            <XCircleIcon className="size-4" /> 不可用
                          </span>
                        )}
                      </td>
                      <td className="py-2 pr-4 tabular-nums">{r.latency_ms} ms</td>
                      <td className="py-2 pr-4 font-mono text-xs">{r.exit_ip ?? "—"}</td>
                      <td className="py-2 pr-4 text-destructive text-xs">{r.error ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="pb-2 flex-row flex items-center justify-between space-y-0">
          <CardTitle className="text-sm font-medium">上游代理</CardTitle>
          <div className="flex flex-wrap items-center gap-2">
            <Link href="/system/proxypool/clash">
              <Button variant="secondary" size="sm">
                <WifiIcon className="mr-1 size-4" />
                Clash 节点管理
              </Button>
            </Link>
            <Button
              variant="outline"
              size="sm"
              onClick={() => setEntries((p) => [...p, { url: "", name: "", enabled: true, weight: 1 }])}
            >
              <PlusIcon className="mr-1 size-4" />
              添加
            </Button>
          </div>
        </CardHeader>
        <CardContent className="space-y-2">
          {entries.length > 0 && (
            <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/30 px-2 py-1.5 text-xs">
              <span className="text-muted-foreground">批量：</span>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                onClick={() => setSelected(new Set(entries.map((_, i) => i)))}
              >
                全选
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                onClick={() =>
                  setSelected((prev) => {
                    const next = new Set<number>();
                    entries.forEach((_, i) => {
                      if (!prev.has(i)) next.add(i);
                    });
                    return next;
                  })
                }
              >
                反选
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-7 px-2"
                disabled={selected.size === 0}
                onClick={() => setSelected(new Set())}
              >
                清空
              </Button>
              <span className="tabular-nums text-muted-foreground">已选 {selected.size}</span>
              <span className="mx-1 h-4 w-px bg-border" />
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={selected.size === 0 || checking}
                onClick={() => void runCheck(selectedURLs)}
              >
                <FlaskConicalIcon className={"mr-1 size-3.5" + (checking ? " animate-pulse" : "")} />
                检测选中
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={selected.size === 0}
                onClick={removeSelected}
              >
                <Trash2Icon className="mr-1 size-3.5" />
                删除选中
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="h-7"
                disabled={deadIndexes.size + failedIndexes.size === 0}
                onClick={removeDead}
              >
                <AlertTriangleIcon className="mr-1 size-3.5" />
                删除失效（{new Set([...deadIndexes, ...failedIndexes]).size}）
              </Button>
            </div>
          )}
          {entries.length === 0 && (
            <p className="py-3 text-sm text-muted-foreground">
              暂无条目。用「批量导入」一次贴入整份代理列表，或点「添加」逐条录入
              （http/https/socks5，支持 user:pass）。
            </p>
          )}
          {entries.map((e, i) => {
            const live = failuresByURL[e.url];
            const dead = deadURLs.has(e.url);
            return (
              <div
                key={i}
                className={
                  "flex flex-wrap items-center gap-2 rounded-md px-1 py-0.5" +
                  (selected.has(i) ? " bg-primary/5 ring-1 ring-primary/20" : "")
                }
              >
                <input
                  type="checkbox"
                  aria-label={`选择第 ${i + 1} 条`}
                  className="size-4 shrink-0 accent-primary"
                  checked={selected.has(i)}
                  onChange={() => toggleSelect(i)}
                />
                <Input
                  className="flex-1 font-mono text-xs"
                  placeholder="socks5://user:pass@1.2.3.4:1080"
                  value={e.url}
                  onChange={(ev) => update(i, { url: ev.target.value })}
                />
                <Input
                  className="w-36"
                  placeholder="名称(可选)"
                  value={e.name}
                  onChange={(ev) => update(i, { name: ev.target.value })}
                />
                <div className="flex items-center gap-1">
                  <span className="text-xs text-muted-foreground">权重</span>
                  <Input
                    className="w-16"
                    type="number"
                    min={1}
                    value={e.weight}
                    onChange={(ev) => update(i, { weight: Math.max(1, Number(ev.target.value) || 1) })}
                  />
                </div>
                <Switch checked={e.enabled} onCheckedChange={(v) => update(i, { enabled: v })} />
                {dead && (
                  <Badge variant="destructive" title={live?.last_fail}>
                    <AlertTriangleIcon className="mr-1 size-3" />
                    熔断 {live?.break_remaining}s
                  </Badge>
                )}
                {!dead && live && live.failures > 0 && <Badge variant="destructive">连败 {live.failures}</Badge>}
                {!dead && live?.last_ok && (
                  <Badge variant="secondary" title={`最近成功 ${live.last_ok}`}>
                    可用
                  </Badge>
                )}
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => {
                    setEntries((p) => p.filter((_, j) => j !== i));
                    setSelected(new Set());
                    setCheckRows([]);
                  }}
                >
                  <Trash2Icon className="size-4" />
                </Button>
              </div>
            );
          })}
        </CardContent>
      </Card>
    </div>
  );
}
