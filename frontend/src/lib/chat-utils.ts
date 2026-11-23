import type { ChatMentionItem } from "./riddle-api";

export const CHAT_MENTION_KINDS = [
  { kind: "finding", label: "漏洞", alias: "finding" },
  { kind: "task", label: "任务", alias: "task" },
  { kind: "target", label: "目标", alias: "target" },
  { kind: "intel", label: "情报", alias: "intel" },
] as const;

export type ChatMentionKind = (typeof CHAT_MENTION_KINDS)[number]["kind"];

export interface ActiveMentionSpan {
  start: number;
  end: number;
  query: string;
}

export function activeMention(value: string, caret: number): ActiveMentionSpan | null {
  const before = value.slice(0, caret);
  const start = before.lastIndexOf("@");
  if (start < 0 || (start > 0 && /[\w.+/-]/.test(before[start - 1]))) return null;
  const query = before.slice(start + 1);
  if (/[[\]\r\n@]/.test(query) || query.length > 160) return null;
  return { start, end: caret, query };
}

export function mentionSearch(query: string) {
  const text = query.trimStart().toLowerCase();
  for (const item of CHAT_MENTION_KINDS) {
    for (const alias of [item.label.toLowerCase(), item.alias]) {
      if (text === alias || text.startsWith(`${alias} `) || (/[^a-z]/.test(alias) && text.startsWith(alias))) {
        return { kind: item.kind, query: query.trimStart().slice(alias.length).trim(), categories: [] };
      }
    }
  }
  const categories = CHAT_MENTION_KINDS.filter(
    (item) => item.label.toLowerCase().startsWith(text) || item.alias.startsWith(text),
  );
  return { kind: "" as const, query: query.trim(), categories };
}

export function mentionToken(item: ChatMentionItem): string {
  const labelKind = CHAT_MENTION_KINDS.find((entry) => entry.kind === item.kind)?.label ?? "漏洞";
  const safeLabel = item.label
    .replace(/[[\]]/g, (ch) => (ch === "[" ? "（" : "）"))
    .replace(/\s+/g, " ")
    .slice(0, 60);
  return `@[${labelKind}#${item.id} ${safeLabel}]`;
}

export function parseBtwCommand(value: string): string | null {
  const trimmed = value.trim();
  const match = /^\/btw(?:\s+([\s\S]+))?$/i.exec(trimmed);
  if (!match) return null;
  return (match[1] ?? "").trim();
}

export type ChatSendMode = "enter" | "ctrl-enter";

const SEND_MODE_STORAGE_KEY = "riddle.chat.send-mode";

export function loadChatSendMode(): ChatSendMode {
  if (typeof window === "undefined") return "enter";
  const raw = window.localStorage.getItem(SEND_MODE_STORAGE_KEY);
  return raw === "ctrl-enter" ? "ctrl-enter" : "enter";
}

export function saveChatSendMode(mode: ChatSendMode): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(SEND_MODE_STORAGE_KEY, mode);
}

export function shouldSubmitChatKey(
  e: { key: string; shiftKey: boolean; ctrlKey: boolean; metaKey: boolean; nativeEvent?: { isComposing?: boolean } },
  mode: ChatSendMode,
): boolean {
  if (e.nativeEvent?.isComposing) return false;
  if (e.key !== "Enter") return false;
  if (mode === "ctrl-enter") {
    return e.ctrlKey || e.metaKey;
  }
  return !e.shiftKey && !e.ctrlKey && !e.metaKey;
}

export function fmtBytes(n: number): string {
  if (n >= 1 << 20) return `${(n / (1 << 20)).toFixed(1)} MB`;
  if (n >= 1 << 10) return `${(n / (1 << 10)).toFixed(1)} KB`;
  return `${n} B`;
}

export function fmtTokens(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(n >= 10_000_000 ? 0 : 1)}M`;
  if (n >= 1000) return `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k`;
  return String(n);
}

export function fmtDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  return `${m}m${String(s % 60).padStart(2, "0")}s`;
}
