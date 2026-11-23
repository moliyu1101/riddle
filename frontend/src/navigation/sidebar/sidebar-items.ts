import {
  Activity,
  Bot,
  Brain,
  Bug,
  LayoutDashboard,
  type LucideIcon,
  MessageSquare,
  Network,
  Radar,
  ScrollText,
  Settings2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Target,
  Terminal,
} from "lucide-react";

export type NavBadge = "new" | "soon";

export interface NavSubItem {
  id: string;
  title: string;
  url: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

interface NavItemBase {
  id: string;
  title: string;
  icon?: LucideIcon;
  badge?: NavBadge;
  disabled?: boolean;
  newTab?: boolean;
}

export interface NavMainLinkItem extends NavItemBase {
  url: string;
  subItems?: never;
}

export interface NavMainParentItem extends NavItemBase {
  subItems: NavSubItem[];
}

export type NavMainItem = NavMainLinkItem | NavMainParentItem;

export interface NavGroup {
  id: number;
  label?: string;
  items: NavMainItem[];
}

export const sidebarItems: NavGroup[] = [
  {
    id: 1,
    label: "作战中心",
    items: [
      { id: "dashboard", title: "作战总览", url: "/dashboard", icon: LayoutDashboard },
      { id: "chat", title: "智能对话", url: "/chat", icon: MessageSquare },
      { id: "collect", title: "AI 资产收集", url: "/function/collect", icon: Radar, badge: "new" },
      { id: "assets", title: "双图资产中心", url: "/function/assets", icon: Network },
      { id: "tasks", title: "挖掘任务", url: "/function/tasks", icon: Target },
      { id: "findings", title: "漏洞与复审", url: "/function/findings", icon: Bug },
      { id: "traffic", title: "实证流量库", url: "/function/traffic", icon: Activity },
      { id: "commands", title: "执行回放", url: "/function/commands", icon: Terminal },
    ],
  },
  {
    id: 2,
    label: "知识与治理",
    items: [
      { id: "vulnintel", title: "情报与 CVE", url: "/system/vulnintel", icon: ShieldCheck },
      { id: "skills", title: "技能与知识库", url: "/system/skills", icon: Sparkles },
      { id: "intercept", title: "融合护栏与审批", url: "/system/intercept", icon: ShieldAlert },
    ],
  },
  {
    id: 3,
    label: "系统与模型",
    items: [
      { id: "llm", title: "模型与多角色路由", url: "/system/llm", icon: Brain },
      { id: "agents", title: "Agent 协同", url: "/system/agents", icon: Bot },
      { id: "logs", title: "运行日志", url: "/system/logs", icon: ScrollText },
      { id: "settings", title: "系统与引擎配置", url: "/system/settings", icon: Settings2 },
    ],
  },
];
