"use client";

import * as React from "react";
import Link from "next/link";
import {
  ArrowLeftIcon,
  DownloadIcon,
  GaugeIcon,
  PlayIcon,
  RefreshCwIcon,
  SearchIcon,
  SquareIcon,
  ZapIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import { getLocalStorageValue, setLocalStorageValue } from "@/lib/local-storage.client";
import { useStoredSortPreference } from "@/lib/sort-preference";
import type { MihomoStatus, ProxyPoolSubscription } from "@/lib/types";

type PlanMode = "group" | "node" | "load-balance" | "url-test" | "fallback";

type DelayInfo = { ms: number; err?: string; at: number };

const MODES: { value: PlanMode; label: string; hint: string }[] = [
  {
    value: "group",
    label: "订阅分组（默认）",
    hint: "按订阅自带的策略组做出口（如「自动选择」「香港」）；组内规则由订阅作者定义。",
  },
  {
    value: "node",
    label: "指定节点（固定出口）",
    hint: "所有请求固定走某一个节点，适合需要稳定出口 IP 的场景。",
  },
  {
    value: "load-balance",
    label: "轮询（每请求换节点）",
    hint: "在勾选节点上建 POJUN-AUTO 组，strategy=round-robin；同一目标也会换出口。",
  },
  {
    value: "url-test",
    label: "自动测速（选最快）",
    hint: "在勾选节点上建 url-test 组，按 300s 周期测速自动选延迟最低的节点。",
  },
  {
    value: "fallback",
    label: "故障转移（按勾选顺序）",
    hint: "在勾选节点上建 fallback 组，按勾选顺序尝试，当前节点不可用时自动换下一个。",
  },
];

type AppliedPlan = {
  mode: PlanMode;
  outbound: string;
  nodes: string[];
  at: string;
};

const SUB_URL_KEY = "pojun_clash_sub_url_v1";
const SELECT_KEY = "pojun_clash_selection_v1";
const DELAY_KEY = "pojun_clash_delays_v1";
const PLAN_KEY = "pojun_clash_plan_v1";
const SORT_KEY = "pojun_clash_sort_v1";
const SORT_FIELDS = ["name", "delay"] as const;

function readJSON<T>(key: string, fallback: T): T {
  const raw = getLocalStorageValue(key);
  if (!raw) return fallback;
  try {
    return JSON.parse(raw) as T;
  } catch {
    return fallback;
  }
}

function writeJSON(key: string, value: unknown) {
  setLocalStorageValue(key, JSON.stringify(value));
}

const okDelay = (d?: DelayInfo): boolean => !!d && d.ms > 0 && !d.err;

// 延迟排序的可用值：失败/未测统一排到最后（ms=0 是失败，不是最快）。
function delayRank(delays: Record<string, DelayInfo>, name: string): number {
  const d = delays[name];
  return okDelay(d) ? d!.ms : Number.MAX_SAFE_INTEGER;
}

function delayBadge(info?: DelayInfo) {
  if (!info) return <span className="text-xs text-muted-foreground">—</span>;
  if (info.err || info.ms <= 0) {
    return (
      <Badge variant="destructive" title={info.err || "超时"}>
        超时
      </Badge>
    );
  }
  const cls =
    info.ms < 150 ? "bg-emerald-600" : info.ms < 400 ? "bg-amber-500" : "bg-orange-600";
  return <Badge className={cls + " tabular-nums"}>{info.ms} ms</Badge>;
}

export default function ClashNodesPage() {
  const [status, setStatus] = React.useState<MihomoStatus | null>(null);
  const [poolEnabled, setPoolEnabled] = React.useState(false);
  const [poolEntries, setPoolEntries] = React.useState(0);
  const [busy, setBusy] = React.useState(false);
  const [subURL, setSubURL] = React.useState("");
  const [subLoading, setSubLoading] = React.useState(false);
  const [sub, setSub] = React.useState<ProxyPoolSubscription | null>(null);
  const [mode, setMode] = React.useState<PlanMode>("group");
  const [groupPick, setGroupPick] = React.useState("");
  const [nodePick, setNodePick] = React.useState("");
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [delays, setDelays] = React.useState<Record<string, DelayInfo>>({});
  const [search, setSearch] = React.useState("");
  const [sortPref, setSortPref] = useStoredSortPreference<"name" | "delay">(
    SORT_KEY,
    SORT_FIELDS,
    "name",
    "asc",
  );
  const [testing, setTesting] = React.useState(false);
  const [testingOne, setTestingOne] = React.useState("");
  const [usePool, setUsePool] = React.useState(true);
  const [applied, setApplied] = React.useState<AppliedPlan | null>(null);

  const nodes = sub?.nodes ?? [];
  const groups = sub?.groups ?? [];
  const groupNames = sub?.group_names ?? [];

  const load = React.useCallback(() => {
    api.proxyPoolMihomoStatus()
      .then((r) => setStatus(r.status))
      .catch((e) => toast.error("读取 mihomo 状态失败: " + String(e)));
    api
      .proxyPoolGet()
      .then((r) => {
        setPoolEnabled(r.enabled !== false);
        setPoolEntries((r.entries ?? []).length);
      })
      .catch(() => {
        /* 池状态非关键 */
      });
  }, []);

  React.useEffect(load, [load]);

  React.useEffect(() => {
    const restored = readJSON<AppliedPlan | null>(PLAN_KEY, null);
    setApplied(restored);
    // 上次应用的策略要回填到表单：否则刷新后「上次应用策略」卡片显示故障转移，
    // 表单却是默认的「分组」，再点启动会静默把线上出口换成另一个策略。
    if (restored) {
      const restoredMode = MODES.find((m) => m.value === restored.mode)?.value;
      if (restoredMode) setMode(restoredMode);
      if (restored.mode === "node") setNodePick(restored.outbound);
      if (restored.mode === "group") setGroupPick(restored.outbound);
    }
    setDelays(readJSON<Record<string, DelayInfo>>(DELAY_KEY, {}));
    const savedURL = getLocalStorageValue(SUB_URL_KEY) || "";
    if (savedURL) {
      setSubURL(savedURL);
      // 刷新后自动重拉订阅，节点信息不再丢。
      void fetchSub(savedURL, true);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // 订阅没加载完之前不能写盘：这两个 effect 在挂载时就会跑一次，此时 selected 还是
  // 空集合、delays 还是空对象，先写会把上次保存的勾选/延迟覆盖掉（fetchSub 要等
  // await 之后才读 SELECT_KEY，挡不住这一轮）。sub 就绪后写入的都是已恢复的值。
  React.useEffect(() => {
    if (!sub) return;
    writeJSON(SELECT_KEY, [...selected]);
  }, [selected, sub]);

  React.useEffect(() => {
    if (!sub) return;
    writeJSON(DELAY_KEY, delays);
  }, [delays, sub]);

  const fetchSub = async (rawURL: string, silent = false) => {
    const u = rawURL.trim();
    if (!u) {
      toast.error("请填写订阅地址");
      return;
    }
    setSubLoading(true);
    try {
      const r = await api.proxyPoolSubscriptionFetch(u);
      if (r.format !== "clash") {
        toast.error(r.note || "这不是 Clash 订阅（节点管理需要 Clash/mihomo YAML）");
        return;
      }
      setSub(r);
      const names = (r.nodes ?? []).map((n) => n.name);
      // 换订阅时旧延迟与节点不再对应（同名节点可能已是另一台服务器），整份作废。
      const sameSub = (getLocalStorageValue(SUB_URL_KEY) || "") === u;
      // 与上次保存的勾选求交：保存过就沿用（含「故意清空」），没保存过或节点
      // 全部改名时才默认全选。
      const saved = readJSON<string[] | null>(SELECT_KEY, null);
      const kept = Array.isArray(saved) ? saved.filter((n) => names.includes(n)) : [];
      const keepSaved = Array.isArray(saved) && (saved.length === 0 || kept.length > 0);
      setSelected(new Set(keepSaved ? kept : names));
      setGroupPick((prev) =>
        prev && (r.group_names ?? []).includes(prev) ? prev : (r.group_names?.[0] ?? ""),
      );
      setNodePick((prev) => (prev && names.includes(prev) ? prev : (names[0] ?? "")));
      // 延迟结果只保留仍然存在的节点（写回 localStorage 由 delays 的持久化 effect 统一做）。
      setDelays((prev) => {
        if (!sameSub) return {};
        const next: Record<string, DelayInfo> = {};
        for (const n of names) if (prev[n]) next[n] = prev[n];
        return next;
      });
      setLocalStorageValue(SUB_URL_KEY, u);
      if (!silent) {
        toast.success(
          `订阅已解析：${r.nodes?.length ?? r.proxies ?? 0} 个节点、${r.group_names?.length ?? 0} 个分组`,
          { duration: 6000 },
        );
      }
    } catch (e) {
      toast.error("拉取订阅失败: " + String(e));
    } finally {
      setSubLoading(false);
    }
  };

  const ensureCore = async (): Promise<MihomoStatus> => {
    const yaml = sub?.clash_yaml;
    if (!yaml) {
      throw new Error("先拉取 Clash 订阅");
    }
    // 用服务端最新状态判断，别信本页可能过期的 status：另一个标签页已启动内核、或
    // 本次状态请求失败时，误判「未运行」会重启内核——mixed-port 一变，代理池里的
    // mihomo-local 条目就指向死端口，已应用的出口策略也会被这次重启改写。
    // 状态读不到就直接报错让用户重试：宁可测不了，也不能拿旧状态去猜、杀掉在跑的内核。
    const fresh = await api.proxyPoolMihomoStatus().then((r) => r.status);
    if (fresh.running && fresh.controller_port) {
      setStatus(fresh);
      return fresh;
    }
    const r = await api.proxyPoolMihomoStart({
      yaml,
      use: false,
      mode: "group",
      outbound: groupPick || undefined,
    });
    setStatus(r.status);
    toast.info("已启动内核用于测速（未接入代理池）", { duration: 6000 });
    return r.status;
  };

  const runDelays = async (names: string[]) => {
    if (!names.length) {
      toast.info("没有可测速的节点");
      return;
    }
    setTesting(true);
    try {
      await ensureCore();
      const r = await api.proxyPoolMihomoDelays({ names });
      setDelays((prev) => {
        const next = { ...prev };
        for (const res of r.results ?? []) {
          next[res.name] = { ms: res.delay_ms, err: res.error, at: Date.now() };
        }
        return next;
      });
      const ok = (r.results ?? []).filter((x) => x.delay_ms > 0).length;
      toast.success(`测速完成：${ok}/${names.length} 个节点可用`);
    } catch (e) {
      toast.error("测速失败: " + String(e), { duration: 10000 });
    } finally {
      setTesting(false);
    }
  };

  const testOne = async (name: string) => {
    setTestingOne(name);
    try {
      await runDelays([name]);
    } finally {
      setTestingOne("");
    }
  };

  const toggleSelected = (name: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });

  const applyAndStart = async () => {
    const yaml = sub?.clash_yaml;
    if (!yaml) {
      toast.error("先在右侧拉取 Clash 订阅");
      return;
    }
    if (mode === "group" && !groupPick) {
      toast.error("订阅里没有可用分组");
      return;
    }
    if (mode === "node" && !nodePick) {
      toast.error("订阅里没有可用节点");
      return;
    }
    if ((mode === "load-balance" || mode === "url-test" || mode === "fallback") && selected.size === 0) {
      toast.error("该模式需要至少勾选一个节点");
      return;
    }
    setBusy(true);
    try {
      const nodesArr =
        mode === "load-balance" || mode === "url-test" || mode === "fallback" ? [...selected] : [];
      const outbound = mode === "group" ? groupPick : mode === "node" ? nodePick : "";
      const r = await api.proxyPoolMihomoStart({
        yaml,
        use: usePool,
        mode,
        outbound: outbound || undefined,
        nodes: nodesArr.length ? nodesArr : undefined,
      });
      setStatus(r.status);
      const plan: AppliedPlan = {
        mode,
        outbound:
          r.status.outbound ||
          outbound ||
          (mode === "load-balance" || mode === "url-test" || mode === "fallback" ? "POJUN-AUTO" : ""),
        nodes: r.status.nodes?.length ? r.status.nodes : nodesArr,
        at: new Date().toISOString(),
      };
      setApplied(plan);
      writeJSON(PLAN_KEY, plan);
      toast.success(
        `mihomo 已启动（端口 ${r.status.port}）${usePool ? "，已接入代理池" : ""}${
          r.status.last_error ? `；${r.status.last_error}` : ""
        }`,
        { duration: 8000 },
      );
      load();
    } catch (e) {
      toast.error("启动失败: " + String(e), { duration: 10000 });
    } finally {
      setBusy(false);
    }
  };

  const stopMihomo = async () => {
    setBusy(true);
    try {
      await api.proxyPoolMihomoStop();
      toast.success("mihomo 已停止，代理池里的 mihomo-local 条目已移除");
      load();
    } catch (e) {
      toast.error("停止失败: " + String(e));
    } finally {
      setBusy(false);
    }
  };

  const installMihomo = async () => {
    setBusy(true);
    try {
      const r = await api.proxyPoolMihomoInstall({});
      toast.success(`mihomo ${r.install?.version || "已安装"}`, { duration: 6000 });
      load();
    } catch (e) {
      toast.error("安装失败: " + String(e), { duration: 10000 });
    } finally {
      setBusy(false);
    }
  };

  const visible = React.useMemo(() => {
    const kw = search.trim().toLowerCase();
    const list = nodes.filter((n) => !kw || n.name.toLowerCase().includes(kw));
    if (sortPref.field === "delay") {
      return [...list].sort((a, b) => delayRank(delays, a.name) - delayRank(delays, b.name));
    }
    return [...list].sort((a, b) => a.name.localeCompare(b.name, "zh-CN"));
  }, [nodes, search, sortPref.field, delays]);

  const selectedGroup = groups.find((g) => g.name === groupPick);
  const livePlan = React.useMemo(() => {
    if (!status?.outbound) return null;
    return { outbound: status.outbound, mode: status.mode ?? "", nodes: status.nodes ?? [] };
  }, [status]);
  const testedOK = Object.values(delays).filter(okDelay).length;
  // 只有「直接指定节点」模式 status.nodes 才是唯一当前出口；组模式下它是整组成员，
  // 逐行标「当前」会一次亮一排。
  const activeNodes = React.useMemo(
    () => new Set(status?.running && status.mode === "node" ? (status.nodes ?? []) : []),
    [status],
  );
  // 有搜索过滤时只测可见节点（按钮文案同步改），否则测全部；超大订阅可以靠过滤分批。
  const delayTargets = search.trim() ? visible : nodes;

  return (
    <div className="flex h-full flex-col gap-4 overflow-y-auto p-4">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <Link href="/system/proxypool">
            <Button variant="ghost" size="sm">
              <ArrowLeftIcon className="mr-1 size-4" />
              返回代理池
            </Button>
          </Link>
          <h1 className="text-lg font-semibold">Clash 节点管理</h1>
          {status?.running ? (
            <Badge>
              运行中 · 端口 {status.port}
              {status.version ? ` · ${status.version.split(" ").slice(0, 3).join(" ")}` : ""}
              {status.controller_port ? ` · 测速口 ${status.controller_port}` : ""}
            </Badge>
          ) : (
            <Badge variant="secondary">未运行</Badge>
          )}
          {status?.installed ? <Badge variant="outline">已安装</Badge> : <Badge variant="destructive">未安装</Badge>}
          <Badge variant={poolEnabled ? "default" : "secondary"}>
            代理池 {poolEnabled ? "启用" : "停用"} · {poolEntries} 条
          </Badge>
          {testedOK > 0 && <Badge variant="outline">已测速 {testedOK}</Badge>}
        </div>
        <div className="flex flex-wrap gap-2">
          {!status?.installed && (
            <Button variant="outline" size="sm" onClick={() => void installMihomo()} disabled={busy}>
              <DownloadIcon className="mr-1 size-4" />
              安装 mihomo
            </Button>
          )}
          {status?.running && (
            <Button variant="outline" size="sm" onClick={() => void stopMihomo()} disabled={busy || testing}>
              <SquareIcon className="mr-1 size-4" />
              停止
            </Button>
          )}
          <Button variant="outline" size="sm" onClick={load} disabled={busy}>
            <RefreshCwIcon className="mr-1 size-4" />
            刷新
          </Button>
        </div>
      </div>

      <Card>
        <CardContent className="grid gap-2 pt-4 text-xs text-muted-foreground sm:grid-cols-2">
          <div className="truncate">配置：{status?.config_path || "—"}</div>
          <div className="truncate">日志：{status?.log_path || "—"}</div>
          {livePlan && (
            <div className="sm:col-span-2 flex flex-wrap items-center gap-2 text-foreground">
              <span className="text-muted-foreground">当前生效：</span>
              <Badge variant="secondary">出口 {livePlan.outbound}</Badge>
              {livePlan.mode && <Badge variant="outline">策略 {livePlan.mode}</Badge>}
              {livePlan.nodes.length > 0 && (
                <span className="truncate">
                  节点 {livePlan.nodes.slice(0, 6).join("、")}
                  {livePlan.nodes.length > 6 ? ` 等 ${livePlan.nodes.length} 个` : ""}
                </span>
              )}
            </div>
          )}
          {status?.last_error && <div className="sm:col-span-2 text-destructive">最近错误：{status.last_error}</div>}
        </CardContent>
      </Card>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_400px]">
        <Card className="min-w-0">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">订阅与节点</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <Input
                className="min-w-0 flex-1 font-mono text-xs"
                value={subURL}
                onChange={(e) => setSubURL(e.target.value)}
                placeholder="https://example.com/api/v1/client/subscribe?token=..."
              />
              <Button size="sm" onClick={() => void fetchSub(subURL)} disabled={subLoading}>
                {subLoading ? "拉取中…" : sub ? "重新拉取" : "拉取订阅"}
              </Button>
            </div>
            {sub ? (
              <>
                <div className="flex flex-wrap items-center gap-1.5 text-xs">
                  <Badge variant="default">Clash YAML</Badge>
                  <Badge variant="secondary">节点 {nodes.length}</Badge>
                  <Badge variant="secondary">分组 {groupNames.length}</Badge>
                  {sub.ignored ? <Badge variant="outline">忽略信息 {sub.ignored}</Badge> : null}
                  <span className="text-muted-foreground">订阅地址已保存在本机浏览器，刷新会自动重拉</span>
                </div>
                {sub.note && <p className="break-words text-xs text-muted-foreground">{sub.note}</p>}
                <div className="flex flex-wrap items-center gap-2">
                  <div className="relative min-w-0 flex-1">
                    <SearchIcon className="pointer-events-none absolute left-2 top-2.5 size-4 text-muted-foreground" />
                    <Input
                      className="pl-8"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      placeholder="搜索节点名"
                    />
                  </div>
                  <Select
                    value={sortPref.field}
                    onValueChange={(v) => setSortPref({ field: v as "name" | "delay", direction: "asc" })}
                  >
                    <SelectTrigger className="h-9 w-28">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="name">按名称</SelectItem>
                      <SelectItem value="delay">按延迟</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button
                    size="sm"
                    variant="secondary"
                    disabled={testing || busy || delayTargets.length === 0}
                    onClick={() => void runDelays(delayTargets.map((n) => n.name))}
                  >
                    <GaugeIcon className={"mr-1 size-4" + (testing ? " animate-pulse" : "")} />
                    {testing
                      ? "测速中…"
                      : search.trim()
                        ? `测速当前 ${delayTargets.length} 个`
                        : "全部测速"}
                  </Button>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2"
                    onClick={() => setSelected(new Set(nodes.map((n) => n.name)))}
                  >
                    全选
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2"
                    onClick={() =>
                      setSelected((prev) => {
                        const next = new Set<string>();
                        nodes.forEach((n) => {
                          if (!prev.has(n.name)) next.add(n.name);
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
                    className="h-8 px-2"
                    onClick={() => setSelected(new Set())}
                  >
                    清空
                  </Button>
                  <span className="text-xs tabular-nums text-muted-foreground">已选 {selected.size}</span>
                  {!status?.running && (
                    <span className="text-xs text-muted-foreground">
                      （点「测速」会自动启动内核，但不会接入代理池）
                    </span>
                  )}
                </div>
                <div className="max-h-[460px] overflow-y-auto rounded-md border">
                  {visible.length === 0 ? (
                    <p className="p-3 text-sm text-muted-foreground">没有匹配的节点</p>
                  ) : (
                    visible.map((n) => {
                      const d = delays[n.name];
                      const active = activeNodes.has(n.name);
                      return (
                        <label
                          key={n.name}
                          className={
                            "flex cursor-pointer items-center gap-2 border-b px-3 py-2 text-sm last:border-0 hover:bg-muted/40 " +
                            (selected.has(n.name) ? "bg-primary/5" : "")
                          }
                        >
                          <input
                            type="checkbox"
                            className="size-4 shrink-0 accent-primary"
                            checked={selected.has(n.name)}
                            onChange={() => toggleSelected(n.name)}
                          />
                          <span className="min-w-0 flex-1 truncate" title={n.name}>
                            {n.name}
                          </span>
                          {active && <Badge variant="outline">当前</Badge>}
                          <Badge variant="outline" className="uppercase">
                            {n.type}
                          </Badge>
                          <span className="w-16 text-right">{delayBadge(d)}</span>
                          <Button
                            variant="ghost"
                            size="icon"
                            className="size-7"
                            title="测试该节点延迟"
                            disabled={testing || busy || testingOne === n.name}
                            onClick={(e) => {
                              // 行是 <label>：不拦住的话点测速会顺带切换勾选。
                              e.preventDefault();
                              e.stopPropagation();
                              void testOne(n.name);
                            }}
                          >
                            <ZapIcon
                              className={"size-3.5" + (testingOne === n.name ? " animate-pulse" : "")}
                            />
                          </Button>
                        </label>
                      );
                    })
                  )}
                </div>
                <p className="text-xs text-muted-foreground">
                  延迟来自 mihomo 真实探测（每个节点单独请求 gstatic/204）；测速需要内核运行。
                  勾选顺序影响「故障转移」优先级；轮询/测速模式只使用勾选节点。
                </p>
              </>
            ) : (
              <p className="py-6 text-sm text-muted-foreground">
                {subLoading
                  ? "正在按上次的订阅地址重新拉取…"
                  : "填入 Clash 订阅地址并拉取；地址会保存在本机浏览器，刷新后自动恢复节点列表。"}
              </p>
            )}
          </CardContent>
        </Card>

        <Card className="min-w-0">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">出口策略</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-1.5">
              <Label className="text-xs">策略</Label>
              <Select value={mode} onValueChange={(v) => setMode(v as PlanMode)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {MODES.map((m) => (
                    <SelectItem key={m.value} value={m.value}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">{MODES.find((m) => m.value === mode)?.hint}</p>
            </div>

            {mode === "group" && (
              <div className="grid gap-1.5">
                <Label className="text-xs">分组</Label>
                <Select value={groupPick} onValueChange={setGroupPick}>
                  <SelectTrigger>
                    <SelectValue placeholder="选择订阅分组" />
                  </SelectTrigger>
                  <SelectContent>
                    {groupNames.map((g) => (
                      <SelectItem key={g} value={g}>
                        {g}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedGroup?.members?.length ? (
                  <p className="break-words text-xs text-muted-foreground">
                    组内 {selectedGroup.members.length} 个节点：{selectedGroup.members.slice(0, 8).join("、")}
                    {selectedGroup.members.length > 8 ? " …" : ""}
                  </p>
                ) : null}
              </div>
            )}

            {mode === "node" && (
              <div className="grid gap-1.5">
                <Label className="text-xs">节点</Label>
                <Select value={nodePick} onValueChange={setNodePick}>
                  <SelectTrigger>
                    <SelectValue placeholder="选择节点" />
                  </SelectTrigger>
                  <SelectContent>
                    {[...nodes]
                      .sort((a, b) => delayRank(delays, a.name) - delayRank(delays, b.name))
                      .map((n) => (
                        <SelectItem key={n.name} value={n.name}>
                          {n.name}
                          {delays[n.name]?.ms ? ` · ${delays[n.name].ms}ms` : ""}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {(mode === "load-balance" || mode === "url-test" || mode === "fallback") && (
              <p className="text-xs text-muted-foreground">
                使用左侧勾选的 <span className="font-medium text-foreground">{selected.size}</span> 个节点
                {selected.size === 0 ? "（至少勾选一个）" : ""}
                {selected.size > 0 ? `，其中已测速 ${[...selected].filter((n) => okDelay(delays[n])).length} 个` : ""}。
              </p>
            )}

            <div className="flex items-center justify-between rounded-md border px-3 py-2">
              <div>
                <p className="text-sm">启动后接入代理池</p>
                <p className="text-xs text-muted-foreground">启用总开关并把 mihomo mixed-port 加入上游</p>
              </div>
              <Switch checked={usePool} onCheckedChange={setUsePool} />
            </div>

            <Button
              className="w-full"
              onClick={() => void applyAndStart()}
              disabled={busy || !sub || testing}
            >
              <PlayIcon className="mr-1 size-4" />
              {status?.running ? "重启并应用策略" : "启动并应用策略"}
            </Button>

            {applied && (
              <div className="rounded-md border bg-muted/30 p-2 text-xs">
                <p className="text-muted-foreground">
                  上次应用：{new Date(applied.at).toLocaleString()} · 策略 {applied.mode} · 出口 {applied.outbound || "—"}
                </p>
                {applied.nodes.length > 0 && (
                  <p className="mt-1 break-words">节点：{applied.nodes.join("、")}</p>
                )}
              </div>
            )}
            <p className="text-xs text-muted-foreground">
              每次启动都会重写配置（规则收敛为 MATCH,&lt;出口&gt;，去掉 GEO/rule-providers），
              避免受限网络下 MMDB 下载卡住启动。
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
