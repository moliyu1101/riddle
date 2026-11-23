"use client";

import * as React from "react";
import {
  AlertCircle,
  Bot,
  Brain,
  Check,
  ChevronDown,
  ChevronRight,
  Copy,
  Loader2,
  Paperclip,
  Square,
  Terminal,
  User,
  Wrench,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { fmtBytes, fmtDuration, fmtTokens } from "@/lib/chat-utils";
import { riddleApi, type ChatActivityItem } from "@/lib/riddle-api";

function CopyBtn({ text, label = "复制" }: { text: string; label?: string }) {
  const [copied, setCopied] = React.useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error("复制失败");
    }
  };
  return (
    <Button
      type="button"
      variant="ghost"
      size="sm"
      className="h-6 px-1.5 text-[11px] text-muted-foreground hover:text-foreground"
      onClick={() => void handleCopy()}
      title={label}
    >
      {copied ? <Check className="size-3 text-emerald-500" /> : <Copy className="size-3" />}
      <span className="ml-1">{copied ? "已复制" : label}</span>
    </Button>
  );
}

const MENTION_TOKEN_RE = /(@\[(?:漏洞|任务|目标|情报)#[A-Za-z0-9_-]+(?: [^\]]*)?\])/g;

function renderInlineMarkdown(text: string): React.ReactNode[] {
  const parts = text.split(MENTION_TOKEN_RE);
  return parts.map((segment, idx) => {
    if (segment.startsWith("@[") && segment.endsWith("]")) {
      return (
        <span
          key={`m-${idx}`}
          className="mx-0.5 inline-flex items-center rounded bg-primary/12 px-1.5 py-0.5 font-mono text-[11px] font-medium text-primary"
        >
          {segment.slice(2, -1)}
        </span>
      );
    }
    const inlineParts = segment.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
    return (
      <React.Fragment key={`t-${idx}`}>
        {inlineParts.map((tok, j) => {
          if (tok.startsWith("`") && tok.endsWith("`") && tok.length > 2) {
            return (
              <code
                key={j}
                className="rounded bg-muted px-1 py-0.5 font-mono text-[0.85em] text-foreground"
              >
                {tok.slice(1, -1)}
              </code>
            );
          }
          if (tok.startsWith("**") && tok.endsWith("**") && tok.length > 4) {
            return (
              <strong key={j} className="font-semibold text-foreground">
                {tok.slice(2, -2)}
              </strong>
            );
          }
          return tok;
        })}
      </React.Fragment>
    );
  });
}

export function RichMarkdown({ content }: { content: string }) {
  const blocks = React.useMemo(() => {
    const result: Array<{ type: "code"; lang: string; text: string } | { type: "text"; text: string }> = [];
    const fenceRe = /```([A-Za-z0-9_+-]*)\n([\s\S]*?)```/g;
    let last = 0;
    let match: RegExpExecArray | null;
    while ((match = fenceRe.exec(content)) !== null) {
      if (match.index > last) {
        result.push({ type: "text", text: content.slice(last, match.index) });
      }
      result.push({ type: "code", lang: match[1] || "text", text: match[2].replace(/\n$/, "") });
      last = match.index + match[0].length;
    }
    if (last < content.length) {
      result.push({ type: "text", text: content.slice(last) });
    }
    return result;
  }, [content]);

  return (
    <div className="space-y-2.5 text-sm leading-relaxed break-words">
      {blocks.map((block, bIdx) => {
        if (block.type === "code") {
          return (
            <div key={bIdx} className="overflow-hidden rounded-lg border bg-muted/40">
              <div className="flex items-center justify-between border-b bg-muted/60 px-3 py-1">
                <span className="font-mono text-[11px] uppercase text-muted-foreground">{block.lang}</span>
                <CopyBtn text={block.text} />
              </div>
              <pre className="overflow-x-auto p-3 font-mono text-xs leading-5 text-foreground">
                <code>{block.text}</code>
              </pre>
            </div>
          );
        }

        const lines = block.text.split("\n");
        return (
          <div key={bIdx} className="space-y-1">
            {lines.map((line, lIdx) => {
              const trimmed = line.trim();
              if (!trimmed) return <div key={lIdx} className="h-1.5" />;
              const h3 = /^###\s+(.+)$/.exec(trimmed);
              if (h3) {
                return (
                  <h4 key={lIdx} className="pt-1.5 font-semibold text-sm text-foreground">
                    {renderInlineMarkdown(h3[1])}
                  </h4>
                );
              }
              const h2 = /^##\s+(.+)$/.exec(trimmed);
              if (h2) {
                return (
                  <h3 key={lIdx} className="pt-2 font-semibold text-base text-foreground">
                    {renderInlineMarkdown(h2[1])}
                  </h3>
                );
              }
              const h1 = /^#\s+(.+)$/.exec(trimmed);
              if (h1) {
                return (
                  <h2 key={lIdx} className="pt-2 font-bold text-base text-foreground">
                    {renderInlineMarkdown(h1[1])}
                  </h2>
                );
              }
              const bullet = /^[-*•]\s+(.+)$/.exec(trimmed);
              if (bullet) {
                return (
                  <div key={lIdx} className="flex gap-2 pl-2">
                    <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-muted-foreground/70" />
                    <span className="min-w-0 flex-1">{renderInlineMarkdown(bullet[1])}</span>
                  </div>
                );
              }
              const ordered = /^(\d+)\.\s+(.+)$/.exec(trimmed);
              if (ordered) {
                return (
                  <div key={lIdx} className="flex gap-2 pl-1">
                    <span className="shrink-0 font-mono text-xs text-muted-foreground">{ordered[1]}.</span>
                    <span className="min-w-0 flex-1">{renderInlineMarkdown(ordered[2])}</span>
                  </div>
                );
              }
              if (trimmed.startsWith("> ")) {
                return (
                  <blockquote key={lIdx} className="border-l-2 border-primary/50 pl-3 text-muted-foreground">
                    {renderInlineMarkdown(trimmed.slice(2))}
                  </blockquote>
                );
              }
              return <p key={lIdx}>{renderInlineMarkdown(line)}</p>;
            })}
          </div>
        );
      })}
    </div>
  );
}

function ExpandableStepCard({
  convId,
  item,
  icon,
  title,
  badge,
}: {
  convId: string;
  item: ChatActivityItem;
  icon: React.ReactNode;
  title: string;
  badge?: string;
}) {
  const [open, setOpen] = React.useState(false);
  const [fullDetail, setFullDetail] = React.useState<string | null>(null);
  const [loadingDetail, setLoadingDetail] = React.useState(false);

  const toggle = async () => {
    const next = !open;
    setOpen(next);
    if (next && item.has_more_detail && fullDetail === null) {
      setLoadingDetail(true);
      try {
        const res = await riddleApi.getChatMessageDetail(convId, item.id);
        setFullDetail(res.detail ?? item.detail);
      } catch {
        setFullDetail(item.detail);
      } finally {
        setLoadingDetail(false);
      }
    }
  };

  const detailContent = fullDetail ?? item.detail;
  const expandable = Boolean(detailContent || item.has_more_detail);

  return (
    <div className="rounded-lg border bg-muted/25 text-xs">
      <button
        type="button"
        onClick={() => expandable && void toggle()}
        className="flex w-full items-center gap-2 px-3 py-2 text-left hover:bg-muted/40 transition-colors"
      >
        {expandable ? (
          open ? <ChevronDown className="size-3.5 shrink-0 text-muted-foreground" /> : <ChevronRight className="size-3.5 shrink-0 text-muted-foreground" />
        ) : (
          <span className="w-3.5 shrink-0" />
        )}
        <span className="shrink-0">{icon}</span>
        <span className="min-w-0 flex-1 truncate font-medium text-foreground">{title}</span>
        {badge ? (
          <Badge variant="outline" className="shrink-0 font-mono text-[10px]">
            {badge}
          </Badge>
        ) : null}
      </button>
      {open && expandable ? (
        <div className="border-t bg-background/60 px-3 py-2">
          {loadingDetail ? (
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Loader2 className="size-3 animate-spin" /> 正在加载完整输出…
            </div>
          ) : (
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-5 text-muted-foreground">
              {detailContent}
            </pre>
          )}
        </div>
      ) : null}
    </div>
  );
}

export function ChatTranscript({
  convId,
  items,
  running,
}: {
  convId: string;
  items: ChatActivityItem[];
  running: boolean;
}) {
  return (
    <div className="space-y-4">
      {items.map((item) => {
        if (item.kind === "user") {
          return (
            <div key={item.id} className="flex justify-end">
              <div className="max-w-[85%] rounded-2xl rounded-tr-sm border border-primary/20 bg-primary/10 px-4 py-3 text-sm">
                <div className="mb-1 flex items-center justify-between gap-3 text-[11px] text-muted-foreground">
                  <span className="inline-flex items-center gap-1 font-medium text-primary">
                    <User className="size-3" /> 我
                  </span>
                  <span>{item.created_at?.slice(11, 19)}</span>
                </div>
                <div className="whitespace-pre-wrap break-words leading-relaxed">
                  {renderInlineMarkdown(item.text)}
                </div>
                {item.attachments && item.attachments.length > 0 ? (
                  <div className="mt-2 flex flex-wrap gap-1.5">
                    {item.attachments.map((att, idx) => (
                      <span
                        key={`${att.path}-${idx}`}
                        className="inline-flex items-center gap-1 rounded-md border bg-background/80 px-2 py-0.5 text-[11px] text-foreground"
                      >
                        <Paperclip className="size-3 text-primary" />
                        <span className="max-w-[160px] truncate">{att.name}</span>
                        <span className="text-muted-foreground">{fmtBytes(att.size)}</span>
                      </span>
                    ))}
                  </div>
                ) : null}
              </div>
            </div>
          );
        }

        if (item.kind === "thinking") {
          return (
            <div key={item.id} className="max-w-[92%]">
              <ExpandableStepCard
                convId={convId}
                item={item}
                icon={<Brain className="size-3.5 text-violet-500" />}
                title={item.text || "思考过程"}
                badge="思考"
              />
            </div>
          );
        }

        if (item.kind === "tool_use") {
          return (
            <div key={item.id} className="max-w-[92%]">
              <ExpandableStepCard
                convId={convId}
                item={item}
                icon={<Wrench className="size-3.5 text-sky-500" />}
                title={item.text || `调用工具 ${item.tool_name || ""}`}
                badge={item.tool_name || "tool"}
              />
            </div>
          );
        }

        if (item.kind === "tool_result") {
          const durMs = Number(item.meta?.duration_ms ?? 0);
          return (
            <div key={item.id} className="max-w-[92%]">
              <ExpandableStepCard
                convId={convId}
                item={item}
                icon={<Terminal className="size-3.5 text-emerald-500" />}
                title={item.text || `${item.tool_name || "工具"} 返回结果`}
                badge={durMs > 0 ? fmtDuration(durMs) : "结果"}
              />
            </div>
          );
        }

        if (item.kind === "assistant") {
          return (
            <div key={item.id} className="flex items-start gap-2.5">
              <div className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-full border bg-primary/10 text-primary">
                <Bot className="size-4" />
              </div>
              <div className="min-w-0 flex-1 rounded-2xl rounded-tl-sm border bg-card px-4 py-3 shadow-xs">
                <div className="mb-1.5 flex items-center justify-between gap-2 text-[11px] text-muted-foreground">
                  <span className="font-medium text-foreground">知蠹助手</span>
                  <div className="flex items-center gap-1">
                    <span>{item.created_at?.slice(11, 19)}</span>
                    <CopyBtn text={item.text} />
                  </div>
                </div>
                <RichMarkdown content={item.text} />
              </div>
            </div>
          );
        }

        if (item.kind === "result") {
          const elapsed = Number(item.meta?.elapsed_ms ?? 0);
          const model = String(item.meta?.model ?? "");
          const totalTok = (item.input_tokens || 0) + (item.output_tokens || 0);
          return (
            <div key={item.id} className="flex flex-wrap items-center gap-2 pl-9 text-[11px] text-muted-foreground">
              {elapsed > 0 ? <span>耗时 {fmtDuration(elapsed)}</span> : null}
              {totalTok > 0 ? (
                <span>
                  · Token {fmtTokens(item.input_tokens || 0)}↑ / {fmtTokens(item.output_tokens || 0)}↓
                </span>
              ) : null}
              {model ? <span className="font-mono">· {model}</span> : null}
            </div>
          );
        }

        if (item.kind === "error") {
          return (
            <div
              key={item.id}
              className="flex items-start gap-2 rounded-lg border border-destructive/40 bg-destructive/10 px-3 py-2 text-xs text-destructive"
            >
              <AlertCircle className="mt-0.5 size-3.5 shrink-0" />
              <span className="break-words">{item.text}</span>
            </div>
          );
        }

        if (item.kind === "stopped") {
          return (
            <div
              key={item.id}
              className="flex items-center gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-300"
            >
              <Square className="size-3 shrink-0" />
              <span>{item.text || "已手动停止当前生成。"}</span>
            </div>
          );
        }

        return null;
      })}

      {running ? (
        <div className="flex items-center gap-2 pl-9 text-xs text-muted-foreground">
          <Loader2 className="size-3.5 animate-spin text-primary" />
          <span>Agent 正在思考与检索平台数据…</span>
        </div>
      ) : null}
    </div>
  );
}
