"use client";

import * as React from "react";
import Link from "next/link";
import {
  ArrowRight,
  Bot,
  Brain,
  CheckCircle2,
  Flame,
  RefreshCw,
  Scale,
  ShieldCheck,
  Sparkles,
  Zap,
} from "lucide-react";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { riddleApi, type FusionStatusResponse, type RiddleTask } from "@/lib/riddle-api";

const AGENTS_PIPELINE = [
  {
    id: "planner",
    roleKey: "planner",
    name: "Planner · 战略规划与任务编排",
    stage: "01 规划层",
    icon: Brain,
    desc: "拆解 SRC 规则与目标资产范围，按优先级编排探测队列并动态调节 Worker 并发节流。",
    capabilities: ["目标预筛打分", "融合目标闸门 (GoalGate)", "智能并发节流"],
    configHref: "/system/llm",
    configLabel: "配置 Planner 模型",
  },
  {
    id: "worker",
    roleKey: "worker",
    name: "Worker · 自主渗透与漏洞验证",
    stage: "02 执行层",
    icon: Bot,
    desc: "多 Worker 并发自主调用 HTTP / Shell / 浏览器 / 测绘工具，按技能速查卡与全局情报完成漏洞挖掘与证据留痕。",
    capabilities: ["技能速查卡注入", "跨任务情报自动命中", "实证流量 JSONL 留痕"],
    configHref: "/system/skills",
    configLabel: "管理技能与知识库",
  },
  {
    id: "reviewer",
    roleKey: "reviewer",
    name: "Reviewer · AI 初审与复现核验",
    stage: "03 审校层",
    icon: ShieldCheck,
    desc: "独立复现 Worker 提交的漏洞 PoC，结合 L1–L4 机械凭据门禁判定通过、降级或附带定向指令打回深挖。",
    capabilities: ["PoC 独立重放复现", "L1–L4 证据硬闸门", "自动打回深挖指令"],
    configHref: "/function/findings",
    configLabel: "前往复审队列",
  },
  {
    id: "escalate",
    roleKey: "worker",
    name: "Escalate · 危害扩大与深度利用",
    stage: "04 深挖层",
    icon: Flame,
    desc: "针对低危/中危线索或人工定向深挖指令，自动串联凭据泄露、越权链与后台入口尝试证明更高业务危害。",
    capabilities: ["定向深挖回炉", "利用链延伸证明", "新旧结果自动取代"],
    configHref: "/function/tasks",
    configLabel: "查看挖掘任务",
  },
  {
    id: "killsweep",
    roleKey: "worker",
    name: "Killsweep Hunter · 指纹通杀扩面",
    stage: "05 扩面层",
    icon: Zap,
    desc: "人工复审通过漏洞后自动提取产品指纹与测绘语句，全网检索同款受影响资产并批量验证衍生漏洞。",
    capabilities: ["指纹与测绘语句提炼", "同款资产批量验证", "防递归通杀熔断"],
    configHref: "/function/assets",
    configLabel: "进入通杀候选",
  },
  {
    id: "judge",
    roleKey: "judge",
    name: "Judge · 安全护栏与拦截判官",
    stage: "06 护栏层",
    icon: Scale,
    desc: "窄视野独立裁决触发高危模式的执行命令（deny / judge / ask），并与八大类任务级硬拦截协同守住合规红线。",
    capabilities: ["三层命令拦截裁决", "八大类硬拦截协同", "人工审批闭环"],
    configHref: "/system/intercept",
    configLabel: "进入护栏与审批",
  },
];

export default function AgentsCollaborationPage() {
  const [fusion, setFusion] = React.useState<FusionStatusResponse | null>(null);
  const [tasks, setTasks] = React.useState<RiddleTask[]>([]);
  const [primaryModel, setPrimaryModel] = React.useState("");
  const [loading, setLoading] = React.useState(true);

  const loadAll = React.useCallback(async () => {
    setLoading(true);
    try {
      const [fRes, tRes, sRes] = await Promise.allSettled([
        riddleApi.getFusionStatus(),
        riddleApi.listTasks(),
        riddleApi.getSettings(),
      ]);
      if (fRes.status === "fulfilled") setFusion(fRes.value);
      if (tRes.status === "fulfilled") setTasks(tRes.value);
      if (sRes.status === "fulfilled") setPrimaryModel(sRes.value.llm.model || "");
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void loadAll();
  }, [loadAll]);

  const runningTasks = tasks.filter((t) => t.status === "running");
  const totalConcurrency = runningTasks.reduce((sum, t) => sum + Number(t.concurrency || 0), 0);
  const routingMap = (fusion?.role_routing as Record<string, { model?: string; source?: string }> | undefined) ?? {};

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="多 Agent 协同架构"
        description="知蠹 Riddle 六大核心 Agent 协同闭环：规划 → 自主渗透 → AI 初审 → 危害扩大 → 指纹通杀 → 安全判官。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => void loadAll()} disabled={loading}>
              <RefreshCw className={`mr-1.5 size-3.5 ${loading ? "animate-spin" : ""}`} /> 刷新态势
            </Button>
            <Button size="sm" asChild>
              <Link href="/system/llm">
                <Sparkles className="mr-1.5 size-3.5" /> 调整角色模型路由
              </Link>
            </Button>
          </>
        }
      />

      {/* Runtime Summary Strip */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">活跃协同任务</CardDescription>
            <CardTitle className="text-2xl tabular-nums">{runningTasks.length}</CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            总任务数 {tasks.length} · 在跑最大并发预算 {totalConcurrency} Worker
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">全局主力模型</CardDescription>
            <CardTitle className="truncate font-mono text-base pt-1">{primaryModel || "未配置"}</CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            角色分层路由：{fusion?.config?.role_routing_enabled ? "已开启" : "统一继承主力"}
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-1">
            <CardDescription className="text-xs">核心融合能力模块</CardDescription>
            <CardTitle className="text-2xl tabular-nums">{fusion?.modules?.length ?? 10}</CardTitle>
          </CardHeader>
          <CardContent className="text-xs text-muted-foreground">
            已配置目标闸门 {fusion?.goal_count ?? 0} 条 · CVE 情报 {fusion?.intel_feed_count ?? 0} 条
          </CardContent>
        </Card>
      </div>

      {/* 6-Agent Pipeline Cards */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        {AGENTS_PIPELINE.map((ag) => {
          const Icon = ag.icon;
          const boundModel = routingMap[ag.roleKey]?.model || primaryModel || "继承全局主力模型";
          return (
            <Card key={ag.id} className="flex flex-col justify-between">
              <CardHeader className="space-y-2 pb-3">
                <div className="flex items-center justify-between gap-2">
                  <Badge variant="outline" className="font-mono text-[11px]">
                    {ag.stage}
                  </Badge>
                  <Badge variant="secondary" className="max-w-[160px] truncate font-mono text-[11px]">
                    {boundModel}
                  </Badge>
                </div>
                <div className="flex items-center gap-2.5 pt-1">
                  <div className="flex size-9 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary">
                    <Icon className="size-4" />
                  </div>
                  <CardTitle className="text-sm leading-snug">{ag.name}</CardTitle>
                </div>
                <CardDescription className="text-xs leading-relaxed">{ag.desc}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3 pt-0">
                <div className="space-y-1.5 rounded-lg border bg-muted/20 p-2.5">
                  {ag.capabilities.map((cap) => (
                    <div key={cap} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                      <CheckCircle2 className="size-3.5 shrink-0 text-emerald-500" />
                      <span>{cap}</span>
                    </div>
                  ))}
                </div>
                <Button variant="ghost" size="sm" className="w-full justify-between text-xs" asChild>
                  <Link href={ag.configHref}>
                    <span>{ag.configLabel}</span>
                    <ArrowRight className="size-3.5" />
                  </Link>
                </Button>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
