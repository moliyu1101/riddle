"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

interface PageHeaderProps {
  title: string;
  description?: React.ReactNode;
  /** 页面级主操作/次操作，右侧对齐；窄屏自动换行。 */
  actions?: React.ReactNode;
  /** 标题下方的视图切换（Tabs 等）。 */
  tabs?: React.ReactNode;
  className?: string;
}

/**
 * 统一页头：标题/说明在左，主操作在右，Tabs 独占下一行。
 * 高频页优先接入；新页面必须使用，避免各页标题层级与操作位置漂移。
 */
export function PageHeader({ title, description, actions, tabs, className }: PageHeaderProps) {
  return (
    <div className={cn("shrink-0 space-y-3", className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h1 className="font-semibold text-xl tracking-tight">{title}</h1>
          {description ? (
            <p className="mt-0.5 max-w-3xl text-muted-foreground text-xs leading-relaxed">{description}</p>
          ) : null}
        </div>
        {actions ? <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
      {tabs ? <div className="min-w-0">{tabs}</div> : null}
    </div>
  );
}

interface FilterBarProps {
  /** 第一行：筛选条件。 */
  children: React.ReactNode;
  /** 第二行：排序/导出/批量操作；为空则不渲染第二行。 */
  actions?: React.ReactNode;
  className?: string;
}

/**
 * 统一筛选区：条件行与操作行分离，避免筛选控件把排序/导出挤到孤立一行。
 * 容器只负责布局，不接管筛选状态。
 */
export function FilterBar({ children, actions, className }: FilterBarProps) {
  return (
    <div className={cn("flex flex-col gap-2", className)}>
      <div className="flex flex-wrap items-center gap-2">{children}</div>
      {actions ? <div className="flex flex-wrap items-center justify-between gap-2">{actions}</div> : null}
    </div>
  );
}
