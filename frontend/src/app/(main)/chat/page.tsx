"use client";

import * as React from "react";
import Link from "next/link";
import {
  ArrowUp,
  Bot,
  ChevronDown,
  ChevronRight,
  ListChecks,
  Loader2,
  MessageSquare,
  MoreHorizontal,
  Paperclip,
  Pencil,
  Pin,
  PinOff,
  Plus,
  Settings2,
  Sparkles,
  Square,
  Trash2,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";

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
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Select, SelectContent, SelectGroup, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  activeMention,
  CHAT_MENTION_KINDS,
  fmtBytes,
  fmtDuration,
  fmtTokens,
  loadChatSendMode,
  mentionSearch,
  mentionToken,
  parseBtwCommand,
  saveChatSendMode,
  shouldSubmitChatKey,
  type ActiveMentionSpan,
  type ChatSendMode,
} from "@/lib/chat-utils";
import {
  riddleApi,
  type ChatActivityItem,
  type ChatAgentInfo,
  type ChatAttachment,
  type ChatConversationItem,
  type ChatMentionItem,
  type ChatModelOption,
} from "@/lib/riddle-api";
import { cn } from "@/lib/utils";
import { ChatTranscript, RichMarkdown } from "./_components/chat-transcript";

const COLLAPSED_AGENTS_STORAGE_KEY = "riddle.chat.collapsed-agents";
const HISTORY_PAGE_SIZE = 150;

const STARTER_PROMPTS: Record<string, string[]> = {
  assistant: [
    "总结最近已落盘的高危漏洞与待提交 SRC 列表",
    "列出当前所有挖掘任务状态，并指出需要关注的异常任务",
    "检索全局情报库中命中次数最高的高价值指纹与端点",
  ],
  analyst: [
    "结合近期漏洞记录，梳理高危与严重漏洞的证据链完整性",
    "帮我按 EduSRC 审核口径润色一份未授权访问漏洞报告模板",
  ],
  recon: [
    "针对校园网常见通用教务/OA 系统，构造精准的 FOFA 与 Hunter 测绘语法",
    "帮我优化当前测绘查询语法，剔除蜜罐与静态宣传页资产",
  ],
  code_audit: [
    "请说明上传 Java/Python 源码后你会按什么维度排查越权与注入风险",
  ],
  ops: [
    "汇总各任务的硬骨头目标常见失败原因，给出并发与护栏调优建议",
  ],
};

interface AgentGroup {
  key: string;
  name: string;
  conversations: ChatConversationItem[];
  runningCount: number;
}

interface SideQuestionEntry {
  id: string;
  question: string;
  answer: string;
  model: string;
  durationMs: number;
  loading?: boolean;
  error?: string;
}

function groupConversationsByAgent(
  list: ChatConversationItem[],
  agentNameMap: Map<string, string>,
): AgentGroup[] {
  const map = new Map<string, AgentGroup>();
  for (const c of list) {
    let g = map.get(c.agent_key);
    if (!g) {
      g = {
        key: c.agent_key,
        name: agentNameMap.get(c.agent_key) || c.agent_name || c.agent_key,
        conversations: [],
        runningCount: 0,
      };
      map.set(c.agent_key, g);
    }
    g.conversations.push(c);
    if (c.running) g.runningCount += 1;
  }
  return Array.from(map.values());
}

export default function ChatPage() {
  const [agents, setAgents] = React.useState<ChatAgentInfo[]>([]);
  const [models, setModels] = React.useState<ChatModelOption[]>([]);
  const [llmReady, setLlmReady] = React.useState(true);
  const [convs, setConvs] = React.useState<ChatConversationItem[]>([]);
  const [loadingConvs, setLoadingConvs] = React.useState(true);

  const [selectedId, setSelectedId] = React.useState<string | null>(null);
  const [draftAgentKey, setDraftAgentKey] = React.useState("assistant");
  const [draftModel, setDraftModel] = React.useState("");

  // Left rail controls
  const [agentFilter, setAgentFilter] = React.useState<string>("all");
  const [collapsedAgents, setCollapsedAgents] = React.useState<Set<string>>(() => new Set());
  const [selectionMode, setSelectionMode] = React.useState(false);
  const [selectedIds, setSelectedIds] = React.useState<Set<string>>(() => new Set());
  const [bulkDeleteOpen, setBulkDeleteOpen] = React.useState(false);
  const [bulkDeleting, setBulkDeleting] = React.useState(false);
  const [renamingId, setRenamingId] = React.useState<string | null>(null);
  const [renameText, setRenameText] = React.useState("");

  // Active thread state
  const [activities, setActivities] = React.useState<ChatActivityItem[]>([]);
  const [cursor, setCursor] = React.useState(0);
  const [hasMore, setHasMore] = React.useState(false);
  const [loadingMessages, setLoadingMessages] = React.useState(false);
  const [loadingEarlier, setLoadingEarlier] = React.useState(false);
  const [running, setRunning] = React.useState(false);
  const [tokenUsage, setTokenUsage] = React.useState({ input_tokens: 0, output_tokens: 0 });

  // Composer & upload state
  const [input, setInput] = React.useState("");
  const [attachments, setAttachments] = React.useState<ChatAttachment[]>([]);
  const [uploading, setUploading] = React.useState(false);
  const [sending, setSending] = React.useState(false);
  const [sendMode, setSendMode] = React.useState<ChatSendMode>("enter");

  // @ Mention autocomplete state
  const [mentionSpan, setMentionSpan] = React.useState<ActiveMentionSpan | null>(null);
  const [mentionResults, setMentionResults] = React.useState<ChatMentionItem[]>([]);
  const [mentionLoading, setMentionLoading] = React.useState(false);
  const [mentionIdx, setMentionIdx] = React.useState(0);

  // Side question (/btw) state (scoped per conversation in memory)
  const [sideOpen, setSideOpen] = React.useState(false);
  const [sideInput, setSideInput] = React.useState("");
  const [sideBusy, setSideBusy] = React.useState(false);
  const [sideHistoryByConv, setSideHistoryByConv] = React.useState<Record<string, SideQuestionEntry[]>>({});

  const textareaRef = React.useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = React.useRef<HTMLInputElement | null>(null);
  const transcriptEndRef = React.useRef<HTMLDivElement | null>(null);
  const cursorRef = React.useRef(0);
  cursorRef.current = cursor;

  // Hydrate preferences & URL ?c=
  React.useEffect(() => {
    setSendMode(loadChatSendMode());
    try {
      const raw = window.localStorage.getItem(COLLAPSED_AGENTS_STORAGE_KEY);
      if (raw) {
        const arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          setCollapsedAgents(new Set(arr.filter((v): v is string => typeof v === "string")));
        }
      }
    } catch {
      // ignore corrupted storage
    }
    const params = new URLSearchParams(window.location.search);
    const cid = params.get("c");
    if (cid) setSelectedId(cid);
  }, []);

  React.useEffect(() => {
    const url = new URL(window.location.href);
    if (selectedId) url.searchParams.set("c", selectedId);
    else url.searchParams.delete("c");
    window.history.replaceState(null, "", url);
  }, [selectedId]);

  const loadMeta = React.useCallback(async () => {
    try {
      const res = await riddleApi.listChatAgents();
      setAgents(res.agents ?? []);
      setModels(res.models ?? []);
      setLlmReady(res.llm_ready !== false);
    } catch {
      // keep usable defaults
    }
  }, []);

  const reloadConvs = React.useCallback(async () => {
    try {
      const res = await riddleApi.listChatConversations();
      setConvs(res.conversations ?? []);
    } catch {
      // ignore transient poll errors
    } finally {
      setLoadingConvs(false);
    }
  }, []);

  React.useEffect(() => {
    void loadMeta();
  }, [loadMeta]);

  React.useEffect(() => {
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      await reloadConvs();
      if (!disposed) timer = setTimeout(() => void poll(), 3000);
    }
    void poll();
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [reloadConvs]);

  // Prune stale selectedIds when conversation list changes
  React.useEffect(() => {
    setSelectedIds((prev) => {
      if (prev.size === 0) return prev;
      const live = new Set(convs.map((c) => c.id));
      const next = new Set([...prev].filter((id) => live.has(id)));
      return next.size === prev.size ? prev : next;
    });
  }, [convs]);

  const selectedConv = React.useMemo(
    () => convs.find((c) => c.id === selectedId) ?? null,
    [convs, selectedId],
  );

  // Load latest message page whenever selectedId changes
  React.useEffect(() => {
    if (!selectedId) {
      setActivities([]);
      setCursor(0);
      setHasMore(false);
      setRunning(false);
      setTokenUsage({ input_tokens: 0, output_tokens: 0 });
      return;
    }
    let cancelled = false;
    setLoadingMessages(true);
    riddleApi
      .listChatMessages(selectedId, { limit: HISTORY_PAGE_SIZE })
      .then((res) => {
        if (cancelled) return;
        setActivities(res.items ?? []);
        setCursor(res.cursor ?? 0);
        setHasMore(Boolean(res.has_more));
        setRunning(Boolean(res.running));
        setTokenUsage(res.token_usage ?? { input_tokens: 0, output_tokens: 0 });
      })
      .catch((err) => {
        if (cancelled) return;
        toast.error(`加载对话记录失败：${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => {
        if (!cancelled) setLoadingMessages(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  // Incremental live polling while current conversation is running
  React.useEffect(() => {
    if (!selectedId || !running) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout>;

    async function pollIncremental() {
      if (!selectedId || cancelled) return;
      try {
        const res = await riddleApi.listChatMessages(selectedId, { since: cursorRef.current });
        if (cancelled) return;
        if (res.items && res.items.length > 0) {
          setActivities((prev) => {
            const seen = new Set(prev.map((p) => p.id));
            const merged = [...prev];
            for (const item of res.items) {
              if (!seen.has(item.id)) merged.push(item);
            }
            return merged;
          });
          setCursor(res.cursor);
        }
        setTokenUsage(res.token_usage ?? { input_tokens: 0, output_tokens: 0 });
        setRunning(Boolean(res.running));
        if (!res.running) {
          void reloadConvs();
          return;
        }
      } catch {
        // transient network error; retry on next tick
      }
      if (!cancelled) {
        timer = setTimeout(() => void pollIncremental(), 900);
      }
    }

    timer = setTimeout(() => void pollIncremental(), 750);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [selectedId, running, reloadConvs]);

  // Auto-scroll to bottom on new activity
  React.useEffect(() => {
    transcriptEndRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [activities.length, running]);

  // @ Mention search effect
  React.useEffect(() => {
    if (!mentionSpan) {
      setMentionResults([]);
      return;
    }
    const parsed = mentionSearch(mentionSpan.query);
    let cancelled = false;
    const timer = window.setTimeout(() => {
      setMentionLoading(true);
      riddleApi
        .searchChatMentions({ kind: parsed.kind || undefined, q: parsed.query, limit: 12 })
        .then((res) => {
          if (!cancelled) {
            setMentionResults(res.items ?? []);
            setMentionIdx(0);
          }
        })
        .catch(() => {
          if (!cancelled) setMentionResults([]);
        })
        .finally(() => {
          if (!cancelled) setMentionLoading(false);
        });
    }, 180);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [mentionSpan]);

  const agentNameMap = React.useMemo(
    () => new Map(agents.map((a) => [a.key, a.name])),
    [agents],
  );

  const filteredConvs = React.useMemo(
    () => (agentFilter === "all" ? convs : convs.filter((c) => c.agent_key === agentFilter)),
    [convs, agentFilter],
  );

  const pinnedConvs = React.useMemo(
    () => filteredConvs.filter((c) => c.pinned),
    [filteredConvs],
  );

  const agentGroups = React.useMemo(
    () => groupConversationsByAgent(filteredConvs.filter((c) => !c.pinned), agentNameMap),
    [filteredConvs, agentNameMap],
  );

  const toggleCollapsed = React.useCallback((key: string) => {
    setCollapsedAgents((prev) => {
      const next = new Set(prev);
      if (!next.delete(key)) next.add(key);
      try {
        window.localStorage.setItem(COLLAPSED_AGENTS_STORAGE_KEY, JSON.stringify([...next]));
      } catch {
        // ignore
      }
      return next;
    });
  }, []);

  const ensureConversation = React.useCallback(async (): Promise<string> => {
    if (selectedId) return selectedId;
    const created = await riddleApi.createChatConversation({
      agent_key: draftAgentKey,
      model_override: draftModel,
    });
    setConvs((prev) => [created, ...prev]);
    setSelectedId(created.id);
    return created.id;
  }, [selectedId, draftAgentKey, draftModel]);

  const handleLoadEarlier = async () => {
    if (!selectedId || activities.length === 0 || loadingEarlier) return;
    setLoadingEarlier(true);
    try {
      const oldestId = activities[0].id;
      const res = await riddleApi.listChatMessages(selectedId, {
        before: oldestId,
        limit: HISTORY_PAGE_SIZE,
      });
      setActivities((prev) => [...(res.items ?? []), ...prev]);
      setHasMore(Boolean(res.has_more));
    } catch (err) {
      toast.error(`加载历史消息失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoadingEarlier(false);
    }
  };

  const handlePickFiles = async (files: File[]) => {
    if (files.length === 0) return;
    setUploading(true);
    try {
      const cid = await ensureConversation();
      const uploaded: ChatAttachment[] = [];
      for (const f of files) {
        const res = await riddleApi.uploadChatFile(cid, f);
        uploaded.push(res);
      }
      setAttachments((prev) => [...prev, ...uploaded]);
      toast.success(`已上传 ${uploaded.length} 个附件`);
    } catch (err) {
      toast.error(`上传附件失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setUploading(false);
    }
  };

  const handleAskSideQuestion = async (questionText: string) => {
    const q = questionText.trim();
    if (!q) return;
    if (!selectedId) {
      toast.info("请先打开或发送一条对话后再使用旁路提问（/btw）");
      return;
    }
    const entryId = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    setSideOpen(true);
    setSideBusy(true);
    setSideHistoryByConv((prev) => ({
      ...prev,
      [selectedId]: [
        ...(prev[selectedId] ?? []),
        { id: entryId, question: q, answer: "", model: "", durationMs: 0, loading: true },
      ],
    }));
    try {
      const res = await riddleApi.askChatSideQuestion(selectedId, q);
      setSideHistoryByConv((prev) => ({
        ...prev,
        [selectedId]: (prev[selectedId] ?? []).map((item) =>
          item.id === entryId
            ? {
                ...item,
                answer: res.answer,
                model: res.model,
                durationMs: res.duration_ms,
                loading: false,
              }
            : item,
        ),
      }));
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      setSideHistoryByConv((prev) => ({
        ...prev,
        [selectedId]: (prev[selectedId] ?? []).map((item) =>
          item.id === entryId ? { ...item, loading: false, error: msg } : item,
        ),
      }));
      toast.error(`旁路提问失败：${msg}`);
    } finally {
      setSideBusy(false);
    }
  };

  const handleSend = async (overrideMessage?: string) => {
    const text = (overrideMessage ?? input).trim();
    const curAttachments = overrideMessage ? [] : attachments;
    if (!text && curAttachments.length === 0) return;

    // Support /btw <question> directly from main composer
    const btwQuestion = parseBtwCommand(text);
    if (btwQuestion !== null) {
      if (!btwQuestion) {
        setSideOpen(true);
        return;
      }
      if (!overrideMessage) setInput("");
      await handleAskSideQuestion(btwQuestion);
      return;
    }

    setSending(true);
    setMentionSpan(null);
    try {
      const cid = await ensureConversation();
      const res = await riddleApi.sendChatMessage(cid, {
        message: text,
        attachments: curAttachments,
      });
      if (!overrideMessage) {
        setInput("");
        setAttachments([]);
      }
      setActivities((prev) => {
        if (prev.some((a) => a.id === res.user_activity.id)) return prev;
        return [...prev, res.user_activity];
      });
      setCursor((prev) => Math.max(prev, res.user_activity.id));
      setRunning(true);
      void reloadConvs();
    } catch (err) {
      toast.error(`发送失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSending(false);
    }
  };

  const handleStop = async () => {
    if (!selectedId) return;
    try {
      await riddleApi.stopChatConversation(selectedId);
      toast.info("已发送停止信号");
    } catch (err) {
      toast.error(`停止失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleTogglePin = async (conv: ChatConversationItem) => {
    try {
      await riddleApi.updateChatConversation(conv.id, { pinned: !conv.pinned });
      void reloadConvs();
    } catch (err) {
      toast.error(`置顶更新失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleCommitRename = async (convId: string, nextTitle: string) => {
    const clean = nextTitle.trim();
    setRenamingId(null);
    if (!clean) return;
    try {
      await riddleApi.updateChatConversation(convId, { title: clean });
      void reloadConvs();
    } catch (err) {
      toast.error(`重命名失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDeleteOne = async (convId: string) => {
    try {
      await riddleApi.deleteChatConversation(convId);
      if (selectedId === convId) setSelectedId(null);
      void reloadConvs();
      toast.success("对话已删除");
    } catch (err) {
      toast.error(`删除失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleBulkDelete = async () => {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBulkDeleting(true);
    try {
      const res = await riddleApi.batchDeleteChatConversations(ids);
      const okIds = new Set(res.items.filter((i) => i.ok).map((i) => i.id));
      if (selectedId && okIds.has(selectedId)) setSelectedId(null);
      setSelectedIds(new Set());
      setSelectionMode(false);
      setBulkDeleteOpen(false);
      toast.success(`已批量删除 ${okIds.size} 个对话`);
      void reloadConvs();
    } catch (err) {
      toast.error(`批量删除失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setBulkDeleting(false);
    }
  };

  const handleChangeModelOverride = async (val: string) => {
    const nextModel = val === "__default__" ? "" : val;
    if (!selectedId) {
      setDraftModel(nextModel);
      return;
    }
    try {
      await riddleApi.updateChatConversation(selectedId, { model_override: nextModel });
      void reloadConvs();
      toast.success(nextModel ? `已切换当前对话模型为 ${nextModel}` : "已恢复跟随全局默认模型");
    } catch (err) {
      toast.error(`切换模型失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const insertMentionItem = (item: ChatMentionItem) => {
    if (!mentionSpan) return;
    const token = mentionToken(item) + " ";
    const next = input.slice(0, mentionSpan.start) + token + input.slice(mentionSpan.end);
    setInput(next);
    setMentionSpan(null);
    window.requestAnimationFrame(() => {
      const el = textareaRef.current;
      if (el) {
        const pos = mentionSpan.start + token.length;
        el.focus();
        el.setSelectionRange(pos, pos);
      }
    });
  };

  const insertMentionCategory = (label: string) => {
    if (!mentionSpan) return;
    const token = `@${label} `;
    const next = input.slice(0, mentionSpan.start) + token + input.slice(mentionSpan.end);
    setInput(next);
    const nextCaret = mentionSpan.start + token.length;
    setMentionSpan(activeMention(next, nextCaret));
    window.requestAnimationFrame(() => {
      const el = textareaRef.current;
      if (el) {
        el.focus();
        el.setSelectionRange(nextCaret, nextCaret);
      }
    });
  };

  const handleTextareaChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const val = e.target.value;
    setInput(val);
    const caret = e.target.selectionStart ?? val.length;
    setMentionSpan(activeMention(val, caret));
  };

  const handleTextareaKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (mentionSpan && mentionResults.length > 0) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setMentionIdx((prev) => (prev + 1) % mentionResults.length);
        return;
      }
      if (e.key === "ArrowUp") {
        e.preventDefault();
        setMentionIdx((prev) => (prev - 1 + mentionResults.length) % mentionResults.length);
        return;
      }
      if (e.key === "Enter" || e.key === "Tab") {
        e.preventDefault();
        insertMentionItem(mentionResults[mentionIdx]);
        return;
      }
      if (e.key === "Escape") {
        e.preventDefault();
        setMentionSpan(null);
        return;
      }
    }
    if (shouldSubmitChatKey(e, sendMode)) {
      e.preventDefault();
      if (!running && !sending) void handleSend();
    }
  };

  const renderConvRow = (conv: ChatConversationItem) => {
    const active = conv.id === selectedId;
    const checked = selectedIds.has(conv.id);
    const isRenaming = renamingId === conv.id;

    return (
      <div
        key={conv.id}
        className={cn(
          "group flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs transition-colors",
          active ? "bg-primary/12 text-foreground font-medium" : "text-muted-foreground hover:bg-muted/60 hover:text-foreground",
        )}
      >
        {selectionMode ? (
          <Checkbox
            checked={checked}
            onCheckedChange={(v) => {
              setSelectedIds((prev) => {
                const next = new Set(prev);
                if (v === true) next.add(conv.id);
                else next.delete(conv.id);
                return next;
              });
            }}
          />
        ) : null}

        {isRenaming ? (
          <Input
            autoFocus
            className="h-6 flex-1 px-1.5 text-xs"
            value={renameText}
            onChange={(e) => setRenameText(e.target.value)}
            onBlur={() => void handleCommitRename(conv.id, renameText)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleCommitRename(conv.id, renameText);
              if (e.key === "Escape") setRenamingId(null);
            }}
          />
        ) : (
          <button
            type="button"
            className="flex min-w-0 flex-1 items-center gap-1.5 text-left"
            onClick={() => {
              setSelectedId(conv.id);
              setSideOpen(false);
            }}
          >
            {conv.running ? (
              <Loader2 className="size-3 shrink-0 animate-spin text-primary" />
            ) : conv.pinned ? (
              <Pin className="size-3 shrink-0 text-amber-500" />
            ) : (
              <MessageSquare className="size-3 shrink-0 opacity-60" />
            )}
            <span className="truncate">{conv.title}</span>
          </button>
        )}

        {!selectionMode && !isRenaming ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="size-6 shrink-0 opacity-0 group-hover:opacity-100 focus:opacity-100"
              >
                <MoreHorizontal className="size-3.5" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-36">
              <DropdownMenuItem onClick={() => void handleTogglePin(conv)}>
                {conv.pinned ? <PinOff className="mr-2 size-3.5" /> : <Pin className="mr-2 size-3.5" />}
                {conv.pinned ? "取消置顶" : "置顶对话"}
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={() => {
                  setRenamingId(conv.id);
                  setRenameText(conv.title);
                }}
              >
                <Pencil className="mr-2 size-3.5" /> 重命名
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem className="text-destructive" onClick={() => void handleDeleteOne(conv.id)}>
                <Trash2 className="mr-2 size-3.5" /> 删除
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        ) : null}
      </div>
    );
  };

  const activeAgentKey = selectedConv?.agent_key ?? draftAgentKey;
  const activeAgent = agents.find((a) => a.key === activeAgentKey) ?? agents[0];
  const activeModel = selectedConv ? selectedConv.model_override || "__default__" : draftModel || "__default__";
  const sideEntries = selectedId ? sideHistoryByConv[selectedId] ?? [] : [];
  const allFilteredSelected =
    filteredConvs.length > 0 && filteredConvs.every((c) => selectedIds.has(c.id));

  return (
    <div className="flex h-[calc(100svh-4.25rem)] min-h-[540px] flex-col gap-3 overflow-hidden">
      <div className="grid min-h-0 flex-1 grid-cols-1 grid-rows-[minmax(10rem,14rem)_minmax(0,1fr)] gap-3 md:grid-cols-[18rem_minmax(0,1fr)] md:grid-rows-[minmax(0,1fr)] md:gap-4">
        {/* Left Conversation Rail */}
        <div className="flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card">
          <div className="flex flex-col gap-2 border-b p-2.5">
            <Button
              size="sm"
              className="w-full"
              onClick={() => {
                setSelectedId(null);
                setAttachments([]);
                setSideOpen(false);
              }}
            >
              <Plus className="mr-1.5 size-4" /> 新建对话
            </Button>

            <div className="flex items-center gap-1.5">
              <Select value={agentFilter} onValueChange={setAgentFilter}>
                <SelectTrigger className="h-8 flex-1 text-xs">
                  <Bot className="mr-1 size-3.5 shrink-0 text-muted-foreground" />
                  <SelectValue placeholder="全部 Agent" />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="all">全部角色（{convs.length}）</SelectItem>
                    {agents.map((a) => {
                      const cnt = convs.filter((c) => c.agent_key === a.key).length;
                      return (
                        <SelectItem key={a.key} value={a.key}>
                          {a.name}（{cnt}）
                        </SelectItem>
                      );
                    })}
                  </SelectGroup>
                </SelectContent>
              </Select>
              {convs.length > 0 ? (
                <Button
                  type="button"
                  size="icon"
                  variant={selectionMode ? "secondary" : "ghost"}
                  className="size-8 shrink-0"
                  title={selectionMode ? "退出批量管理" : "批量管理对话"}
                  onClick={() => {
                    setSelectionMode((v) => !v);
                    setSelectedIds(new Set());
                  }}
                >
                  <ListChecks className="size-4" />
                </Button>
              ) : null}
            </div>

            {selectionMode ? (
              <div className="flex items-center justify-between gap-2 rounded-md bg-muted/40 px-2 py-1 text-xs">
                <label className="flex items-center gap-1.5 cursor-pointer">
                  <Checkbox
                    checked={allFilteredSelected}
                    onCheckedChange={(checked) => {
                      if (checked === true) setSelectedIds(new Set(filteredConvs.map((c) => c.id)));
                      else setSelectedIds(new Set());
                    }}
                  />
                  <span>已选 {selectedIds.size}</span>
                </label>
                <Button
                  size="sm"
                  variant="destructive"
                  className="h-6 px-2 text-xs"
                  disabled={selectedIds.size === 0 || bulkDeleting}
                  onClick={() => setBulkDeleteOpen(true)}
                >
                  删除
                </Button>
              </div>
            ) : null}
          </div>

          <ScrollArea className="min-h-0 flex-1">
            <div className="space-y-3 p-2">
              {loadingConvs ? (
                <div className="py-8 text-center text-xs text-muted-foreground">正在加载对话列表…</div>
              ) : filteredConvs.length === 0 ? (
                <div className="py-8 text-center text-xs text-muted-foreground">
                  暂无历史对话，点击上方「新建对话」开始。
                </div>
              ) : (
                <>
                  {pinnedConvs.length > 0 ? (
                    <div className="space-y-1">
                      <div className="px-2 text-[11px] font-medium text-muted-foreground">置顶对话</div>
                      {pinnedConvs.map(renderConvRow)}
                    </div>
                  ) : null}

                  {agentGroups.map((group) => {
                    const collapsed = collapsedAgents.has(group.key);
                    return (
                      <div key={group.key} className="space-y-1">
                        <button
                          type="button"
                          onClick={() => toggleCollapsed(group.key)}
                          className="flex w-full items-center gap-1 rounded px-1.5 py-1 text-[11px] font-medium text-muted-foreground hover:bg-muted/40 hover:text-foreground"
                        >
                          {collapsed ? (
                            <ChevronRight className="size-3 shrink-0" />
                          ) : (
                            <ChevronDown className="size-3 shrink-0" />
                          )}
                          <span className="truncate">{group.name}</span>
                          <span className="ml-auto tabular-nums opacity-70">{group.conversations.length}</span>
                          {group.runningCount > 0 ? (
                            <Badge variant="secondary" className="h-4 px-1 text-[10px]">
                              {group.runningCount} 运行中
                            </Badge>
                          ) : null}
                        </button>
                        {!collapsed ? <div className="space-y-0.5 pl-1">{group.conversations.map(renderConvRow)}</div> : null}
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          </ScrollArea>
        </div>

        {/* Right Chat Workspace */}
        <div className="flex min-h-0 flex-col overflow-hidden rounded-xl border bg-card">
          {/* Top Header */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-b px-4 py-2.5">
            <div className="flex min-w-0 items-center gap-2">
              <Bot className="size-4 shrink-0 text-primary" />
              <div className="min-w-0">
                <div className="truncate font-semibold text-sm">
                  {selectedConv ? selectedConv.title : "新对话（草稿）"}
                </div>
                <div className="truncate text-[11px] text-muted-foreground">
                  {activeAgent?.name || "通用安全助手"} · {activeAgent?.description || "支持只读检索平台数据与 @实体引用"}
                </div>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {(tokenUsage.input_tokens > 0 || tokenUsage.output_tokens > 0) ? (
                <Badge variant="outline" className="font-mono text-[11px]">
                  {fmtTokens(tokenUsage.input_tokens)}↑ / {fmtTokens(tokenUsage.output_tokens)}↓
                </Badge>
              ) : null}

              <Select value={activeModel} onValueChange={(v) => void handleChangeModelOverride(v)}>
                <SelectTrigger className="h-8 w-[170px] text-xs">
                  <SelectValue placeholder="跟随全局模型" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__default__">跟随全局默认模型</SelectItem>
                  {models.map((m) => (
                    <SelectItem key={m.model} value={m.model}>
                      {m.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              {selectedId ? (
                <Button
                  type="button"
                  size="sm"
                  variant={sideOpen ? "secondary" : "outline"}
                  className="h-8 text-xs"
                  onClick={() => setSideOpen((v) => !v)}
                  title="旁路快答（/btw），不打断也不污染主对话上下文"
                >
                  <Zap className="mr-1 size-3.5 text-amber-500" />
                  旁路提问
                  {sideEntries.length > 0 ? (
                    <Badge variant="secondary" className="ml-1 h-4 px-1 text-[10px]">
                      {sideEntries.length}
                    </Badge>
                  ) : null}
                </Button>
              ) : null}
            </div>
          </div>

          {!llmReady ? (
            <div className="flex items-center justify-between gap-2 border-b bg-amber-500/10 px-4 py-2 text-xs text-amber-700 dark:text-amber-300">
              <span>当前尚未配置可用的大模型 API Key，请先完成模型配置后发起对话。</span>
              <Button size="sm" variant="outline" className="h-7 text-xs" asChild>
                <Link href="/system/llm">
                  <Settings2 className="mr-1 size-3.5" /> 前往配置模型
                </Link>
              </Button>
            </div>
          ) : null}

          {/* Side Question (/btw) Drawer Panel */}
          {sideOpen && selectedId ? (
            <div className="border-b bg-muted/25 px-4 py-3 space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-1.5 text-xs font-medium">
                  <Zap className="size-3.5 text-amber-500" />
                  旁路快答（/btw）
                  <span className="font-normal text-muted-foreground">
                    读取主会话摘要直接快答，不调用工具、不写入主对话记录
                  </span>
                </div>
                <Button type="button" variant="ghost" size="icon" className="size-6" onClick={() => setSideOpen(false)}>
                  <X className="size-3.5" />
                </Button>
              </div>
              {sideEntries.length > 0 ? (
                <div className="max-h-48 space-y-2 overflow-y-auto pr-1">
                  {sideEntries.map((entry) => (
                    <div key={entry.id} className="rounded-lg border bg-background p-2.5 text-xs space-y-1.5">
                      <div className="font-medium text-primary">问：{entry.question}</div>
                      {entry.loading ? (
                        <div className="flex items-center gap-1.5 text-muted-foreground">
                          <Loader2 className="size-3 animate-spin" /> 旁路思考中…
                        </div>
                      ) : entry.error ? (
                        <div className="text-destructive">{entry.error}</div>
                      ) : (
                        <>
                          <RichMarkdown content={entry.answer} />
                          <div className="text-[10px] text-muted-foreground">
                            {fmtDuration(entry.durationMs)} {entry.model ? `· ${entry.model}` : ""}
                          </div>
                        </>
                      )}
                    </div>
                  ))}
                </div>
              ) : null}
              <div className="flex items-center gap-2">
                <Input
                  className="h-8 text-xs"
                  placeholder="输入旁路快问，例如：把上面的结论压缩成 3 条汇报要点…"
                  value={sideInput}
                  onChange={(e) => setSideInput(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && !e.shiftKey && !sideBusy && sideInput.trim()) {
                      e.preventDefault();
                      const q = sideInput;
                      setSideInput("");
                      void handleAskSideQuestion(q);
                    }
                  }}
                />
                <Button
                  type="button"
                  size="sm"
                  className="h-8 text-xs"
                  disabled={sideBusy || !sideInput.trim()}
                  onClick={() => {
                    const q = sideInput;
                    setSideInput("");
                    void handleAskSideQuestion(q);
                  }}
                >
                  {sideBusy ? <Loader2 className="size-3.5 animate-spin" /> : "快答"}
                </Button>
              </div>
            </div>
          ) : null}

          {/* Main Transcript Area */}
          <div className="min-h-0 flex-1 overflow-y-auto px-4 py-4">
            {loadingMessages ? (
              <div className="flex h-full items-center justify-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="size-4 animate-spin" /> 正在加载对话记录…
              </div>
            ) : !selectedId || activities.length === 0 ? (
              <div className="mx-auto flex max-w-2xl flex-col items-center justify-center py-8 text-center space-y-5">
                <div className="flex size-12 items-center justify-center rounded-2xl border bg-primary/10 text-primary">
                  <Sparkles className="size-6" />
                </div>
                <div className="space-y-1">
                  <h2 className="font-semibold text-lg">知蠹 Riddle 智能对话工作台</h2>
                  <p className="text-xs text-muted-foreground">
                    选择专业 Agent 角色，支持 <code className="rounded bg-muted px-1">@漏洞 / @任务 / @目标 / @情报</code>{" "}
                    实体引用、附件上传分析、只读平台数据检索与 <code className="rounded bg-muted px-1">/btw</code> 旁路快答。
                  </p>
                </div>

                {!selectedId && agents.length > 0 ? (
                  <div className="grid w-full grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3 text-left">
                    {agents.map((a) => {
                      const active = draftAgentKey === a.key;
                      return (
                        <button
                          key={a.key}
                          type="button"
                          onClick={() => setDraftAgentKey(a.key)}
                          className={cn(
                            "rounded-lg border p-3 transition-colors",
                            active
                              ? "border-primary bg-primary/10"
                              : "border-border hover:bg-muted/40",
                          )}
                        >
                          <div className="flex items-center gap-1.5 font-medium text-xs text-foreground">
                            <Bot className="size-3.5 text-primary" />
                            {a.name}
                          </div>
                          <p className="mt-1 line-clamp-2 text-[11px] text-muted-foreground">{a.description}</p>
                        </button>
                      );
                    })}
                  </div>
                ) : null}

                <div className="flex w-full flex-wrap justify-center gap-2">
                  {(STARTER_PROMPTS[activeAgentKey] ?? STARTER_PROMPTS.assistant).map((prompt) => (
                    <button
                      key={prompt}
                      type="button"
                      disabled={!llmReady || sending}
                      onClick={() => void handleSend(prompt)}
                      className="rounded-full border bg-muted/30 px-3 py-1.5 text-xs text-muted-foreground hover:border-primary/40 hover:bg-primary/5 hover:text-foreground transition-colors"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="mx-auto max-w-4xl space-y-4">
                {hasMore ? (
                  <div className="flex justify-center">
                    <Button
                      type="button"
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs"
                      disabled={loadingEarlier}
                      onClick={() => void handleLoadEarlier()}
                    >
                      {loadingEarlier ? <Loader2 className="mr-1.5 size-3 animate-spin" /> : null}
                      加载更早历史消息
                    </Button>
                  </div>
                ) : null}

                <ChatTranscript convId={selectedId} items={activities} running={running} />
                <div ref={transcriptEndRef} />
              </div>
            )}
          </div>

          {/* Bottom Composer */}
          <div className="relative border-t bg-background/60 p-3">
            {/* @ Mention Floating Picker */}
            {mentionSpan ? (
              <div className="absolute right-3 bottom-full left-3 z-20 mb-2 max-h-64 overflow-y-auto rounded-lg border bg-popover p-2 shadow-lg">
                <div className="mb-1.5 flex flex-wrap items-center gap-1.5 border-b pb-1.5">
                  <span className="text-[11px] text-muted-foreground">@ 引用实体：</span>
                  {CHAT_MENTION_KINDS.map((k) => (
                    <button
                      key={k.kind}
                      type="button"
                      onMouseDown={(e) => {
                        e.preventDefault();
                        insertMentionCategory(k.label);
                      }}
                      className="rounded bg-muted px-1.5 py-0.5 text-[11px] hover:bg-primary/15 hover:text-primary"
                    >
                      @{k.label}
                    </button>
                  ))}
                </div>
                {mentionLoading ? (
                  <div className="py-3 text-center text-xs text-muted-foreground">正在检索平台实体…</div>
                ) : mentionResults.length === 0 ? (
                  <div className="py-3 text-center text-xs text-muted-foreground">
                    未找到匹配记录，可继续输入关键字筛选。
                  </div>
                ) : (
                  <div className="space-y-0.5">
                    {mentionResults.map((item, idx) => {
                      const kLabel = CHAT_MENTION_KINDS.find((k) => k.kind === item.kind)?.label ?? item.kind;
                      return (
                        <button
                          key={`${item.kind}-${item.id}`}
                          type="button"
                          onMouseDown={(e) => {
                            e.preventDefault();
                            insertMentionItem(item);
                          }}
                          className={cn(
                            "flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-xs",
                            idx === mentionIdx ? "bg-primary/12 text-foreground" : "hover:bg-muted/60",
                          )}
                        >
                          <Badge variant="secondary" className="shrink-0 text-[10px]">
                            {kLabel}
                          </Badge>
                          <span className="min-w-0 flex-1 truncate font-medium">{item.label}</span>
                          <span className="max-w-[40%] truncate text-[11px] text-muted-foreground">
                            {item.description}
                          </span>
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            ) : null}

            {/* Pending Attachments */}
            {attachments.length > 0 ? (
              <div className="mb-2 flex flex-wrap gap-1.5">
                {attachments.map((att) => (
                  <div
                    key={att.path}
                    className="inline-flex items-center gap-1.5 rounded-md border bg-muted/50 px-2 py-1 text-xs"
                  >
                    <Paperclip className="size-3 text-primary" />
                    <span className="max-w-[160px] truncate">{att.name}</span>
                    <span className="text-muted-foreground">{fmtBytes(att.size)}</span>
                    <button
                      type="button"
                      className="text-muted-foreground hover:text-foreground"
                      onClick={() => setAttachments((prev) => prev.filter((a) => a.path !== att.path))}
                    >
                      <X className="size-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : null}

            <div className="space-y-2">
              <Textarea
                ref={textareaRef}
                rows={3}
                className="min-h-[72px] resize-none text-sm"
                placeholder="输入问题… 输入 @ 引用漏洞/任务/目标/情报，输入 /btw 进行旁路快答"
                value={input}
                onChange={handleTextareaChange}
                onKeyDown={handleTextareaKeyDown}
                disabled={sending}
              />

              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-1.5">
                  <input
                    ref={fileInputRef}
                    type="file"
                    multiple
                    className="hidden"
                    onChange={(e) => {
                      const picked = Array.from(e.target.files ?? []);
                      e.target.value = "";
                      if (picked.length > 0) void handlePickFiles(picked);
                    }}
                  />
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    className="h-8 px-2 text-xs"
                    disabled={uploading || sending}
                    onClick={() => fileInputRef.current?.click()}
                    title="上传源码/日志/报文等附件供分析（单文件最大 10MB）"
                  >
                    {uploading ? <Loader2 className="mr-1 size-3.5 animate-spin" /> : <Paperclip className="mr-1 size-3.5" />}
                    附件
                  </Button>
                  <Button
                    type="button"
                    size="sm"
                    variant="ghost"
                    className="h-8 px-2 text-xs text-muted-foreground"
                    onClick={() => {
                      const next = input ? `${input} @` : "@";
                      setInput(next);
                      setMentionSpan(activeMention(next, next.length));
                      textareaRef.current?.focus();
                    }}
                  >
                    @ 引用
                  </Button>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    className="text-[11px] text-muted-foreground hover:text-foreground"
                    onClick={() => {
                      const next: ChatSendMode = sendMode === "enter" ? "ctrl-enter" : "enter";
                      setSendMode(next);
                      saveChatSendMode(next);
                    }}
                    title="点击切换发送快捷键"
                  >
                    {sendMode === "enter" ? "Enter 发送 · Shift+Enter 换行" : "Ctrl+Enter 发送 · Enter 换行"}
                  </button>

                  {running ? (
                    <Button type="button" size="sm" variant="destructive" className="h-8 px-3" onClick={() => void handleStop()}>
                      <Square className="mr-1 size-3.5" /> 停止
                    </Button>
                  ) : (
                    <Button
                      type="button"
                      size="sm"
                      className="h-8 px-3"
                      disabled={sending || (!input.trim() && attachments.length === 0)}
                      onClick={() => void handleSend()}
                    >
                      {sending ? <Loader2 className="mr-1 size-3.5 animate-spin" /> : <ArrowUp className="mr-1 size-3.5" />}
                      发送
                    </Button>
                  )}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Batch Delete Confirmation */}
      <AlertDialog open={bulkDeleteOpen} onOpenChange={setBulkDeleteOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>确认批量删除 {selectedIds.size} 个对话？</AlertDialogTitle>
            <AlertDialogDescription>
              删除后将同步移除所选对话的全部历史消息与上传附件，且不可恢复。
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={bulkDeleting}>取消</AlertDialogCancel>
            <AlertDialogAction
              disabled={bulkDeleting}
              onClick={(e) => {
                e.preventDefault();
                void handleBulkDelete();
              }}
            >
              {bulkDeleting ? "正在删除…" : "确认删除"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
