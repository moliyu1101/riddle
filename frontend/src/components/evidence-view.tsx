"use client";

import * as React from "react";

import { CopyIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

// EvidenceView 把 agent 写的 evidence 自由文本（curl 命令 + # 小节注释 + JSON
// 响应混排）渲染成可读的分块排版（用户反馈：原来一整坨 pre 太草率）。纯展示层
// 解析，不改数据：
//   - '# ' 开头        → 小节标题（主色、上边距分隔）
//   - ``` 围栏          → 代码块
//   - '{' 开头的长行    → 尝试 JSON 美化（parse 失败原样），超长默认折叠到 12 行
//   - 其余行            → 等宽段落（保留 curl 命令原样）
export function EvidenceView({ text, className }: { text: string; className?: string }) {
  const blocks = React.useMemo(() => parseEvidence(text ?? ""), [text]);
  const [copied, setCopied] = React.useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard 不可用时静默 */
    }
  };

  return (
    <div className={cn("relative", className)}>
      <Button
        variant="ghost"
        size="icon-sm"
        className="absolute top-1 right-1 z-10"
        aria-label="复制证据原文"
        title="复制原文"
        onClick={() => void copy()}
      >
        <CopyIcon className={copied ? "text-primary" : undefined} />
      </Button>
      <div className="flex flex-col gap-2 font-mono text-xs">
        {blocks.map((b, i) => {
          if (b.kind === "title") {
            return (
              <div
                key={i}
                className="mt-2 mb-1 border-primary/40 border-l-2 pl-2 font-semibold text-foreground first:mt-0"
                >
                {b.text}
              </div>
            );
          }
          if (b.kind === "json") {
            return <JsonBlock key={i} raw={b.text} />;
          }
          if (b.kind === "code") {
            return (
              <pre
                key={i}
                className="overflow-x-auto rounded border bg-muted/60 px-2 py-1.5 whitespace-pre-wrap"
              >
                {b.text}
              </pre>
            );
          }
          if (b.kind === "list") {
            return (
              <div key={i} className="flex gap-1.5">
                <span className="text-muted-foreground select-none">•</span>
                <span className="whitespace-pre-wrap">{b.text}</span>
              </div>
            );
          }
          return (
            <div key={i} className="whitespace-pre-wrap">
              {b.text}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function JsonBlock({ raw }: { raw: string }) {
  const pretty = React.useMemo(() => {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }, [raw]);
  const [expanded, setExpanded] = React.useState(false);
  const lines = pretty.split("\n");
  const clipped = !expanded && lines.length > 12;
  return (
    <div className="rounded border bg-muted/60">
      <pre
        className={cn(
          "overflow-auto px-2 py-1.5 whitespace-pre",
          clipped ? "max-h-72 overflow-y-auto" : "",
        )}
      >
        {clipped ? lines.slice(0, 12).join("\n") + "\n…" : pretty}
      </pre>
      {lines.length > 12 && (
        <button
          type="button"
          className="text-muted-foreground hover:text-foreground w-full border-t px-2 py-1 text-left text-[11px]"
          onClick={() => setExpanded(!expanded)}
        >
          {expanded ? "收起 JSON" : `展开 JSON（共 ${lines.length} 行）`}
        </button>
      )}
    </div>
  );
}

type Block = { kind: "title" | "json" | "code" | "list" | "text"; text: string };

export function parseEvidence(text: string): Block[] {
  const lines = (text ?? "").replace(/\r\n/g, "\n").split("\n");
  const blocks: Block[] = [];
  let buf: string[] = [];
  let inFence = false;

  const flushText = () => {
    if (buf.length) {
      blocks.push({ kind: "text", text: buf.join("\n") });
      buf = [];
    }
  };

  for (const ln of lines) {
    const trimmed = ln.trim();
    if (trimmed.startsWith("```")) {
      flushText();
      inFence = !inFence;
      continue;
    }
    if (inFence) {
      blocks.push({ kind: "code", text: ln });
      continue;
    }
    // JSON 行（以 { 或 [ 开头且能 parse → 独立美化块；跨行 JSON 由 parse 失败兜底原样）
    if ((trimmed.startsWith("{") || trimmed.startsWith("[")) && trimmed.length > 40) {
      flushText();
      blocks.push({ kind: "json", text: trimmed });
      continue;
    }
    if (/^#{1,4}\s/.test(trimmed)) {
      flushText();
      blocks.push({ kind: "title", text: trimmed.replace(/^#+\s*/, "") });
      continue;
    }
    if (/^[-*]\s/.test(trimmed)) {
      flushText();
      blocks.push({ kind: "list", text: trimmed.replace(/^[-*]\s*/, "") });
      continue;
    }
    if (trimmed === "") {
      flushText();
      continue;
    }
    buf.push(ln);
  }
  flushText();
  return blocks;
}
