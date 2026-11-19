"use client";

import * as React from "react";
import {
  BookOpen,
  FilePlus2,
  FolderSync,
  RefreshCw,
  Save,
  Search,
  Sparkles,
  Trash2,
} from "lucide-react";
import { toast } from "sonner";

import { PageHeader } from "@/components/page-header";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { riddleApi } from "@/lib/riddle-api";

const CATEGORY_LABELS: Record<string, string> = {
  rules: "方法论规则",
  kb: "测试手册",
  user: "实战蒸馏 / 自定义",
};

export default function SkillsAndKnowledgePage() {
  // Tab 1: Distilled Knowledge Base
  const [kbItems, setKbItems] = React.useState<Array<Record<string, unknown>>>([]);
  const [category, setCategory] = React.useState("all");
  const [search, setSearch] = React.useState("");
  const [loadingKb, setLoadingKb] = React.useState(true);
  const [syncing, setSyncing] = React.useState(false);

  // Edit / Create Sheet
  const [sheetOpen, setSheetOpen] = React.useState(false);
  const [editId, setEditId] = React.useState<string | null>(null);
  const [editTitle, setEditTitle] = React.useState("");
  const [editCategory, setEditCategory] = React.useState("user");
  const [editKeyword, setEditKeyword] = React.useState("");
  const [editContent, setEditContent] = React.useState("");
  const [editEnabled, setEditEnabled] = React.useState(true);
  const [savingKb, setSavingKb] = React.useState(false);

  // Tab 2: Skill Index
  const [skillEntries, setSkillEntries] = React.useState<Array<Record<string, unknown>>>([]);
  const [skillBlock, setSkillBlock] = React.useState("");
  const [skillIndexEnabled, setSkillIndexEnabled] = React.useState(true);
  const [skillSearch, setSkillSearch] = React.useState("");

  const loadKnowledge = React.useCallback(async () => {
    setLoadingKb(true);
    try {
      const list = await riddleApi.listKnowledge({ category, q: search.trim() || undefined });
      setKbItems(list);
    } catch (err) {
      toast.error(`加载知识库失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setLoadingKb(false);
    }
  }, [category, search]);

  const loadSkillIndex = React.useCallback(async () => {
    try {
      const [idxRes, cfgRes] = await Promise.allSettled([
        riddleApi.getSkillIndex(),
        riddleApi.getFusionConfig(),
      ]);
      if (idxRes.status === "fulfilled") {
        setSkillEntries(idxRes.value.entries ?? []);
        setSkillBlock(idxRes.value.block ?? "");
      }
      if (cfgRes.status === "fulfilled") {
        setSkillIndexEnabled(Boolean(cfgRes.value.config.skill_index_enabled));
      }
    } catch {
      // ignore
    }
  }, []);

  React.useEffect(() => {
    void loadKnowledge();
  }, [loadKnowledge]);

  React.useEffect(() => {
    void loadSkillIndex();
  }, [loadSkillIndex]);

  const openCreateSheet = () => {
    setEditId(null);
    setEditTitle("");
    setEditCategory("user");
    setEditKeyword("");
    setEditContent("");
    setEditEnabled(true);
    setSheetOpen(true);
  };

  const openEditSheet = async (id: string) => {
    setEditId(id);
    setSheetOpen(true);
    try {
      const d = await riddleApi.getKnowledge(id);
      setEditTitle(String(d.name ?? d.match_key ?? ""));
      setEditCategory(String(d.category ?? "user"));
      setEditKeyword(String(d.keyword ?? ""));
      setEditContent(String(d.content ?? ""));
      setEditEnabled(d.enabled !== false);
    } catch (err) {
      toast.error(`读取知识全文失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSaveKb = async () => {
    if (!editTitle.trim() || !editContent.trim()) {
      toast.error("标题与正文内容不能为空");
      return;
    }
    setSavingKb(true);
    try {
      if (editId) {
        await riddleApi.updateKnowledge(editId, {
          title: editTitle.trim(),
          category: editCategory,
          keyword: editKeyword.trim(),
          content: editContent.trim(),
          enabled: editEnabled,
        });
        toast.success("已更新知识库条目");
      } else {
        await riddleApi.createKnowledge({
          title: editTitle.trim(),
          category: editCategory,
          keyword: editKeyword.trim(),
          content: editContent.trim(),
          enabled: editEnabled,
        });
        toast.success("已新建知识库条目");
      }
      setSheetOpen(false);
      await loadKnowledge();
    } catch (err) {
      toast.error(`保存失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSavingKb(false);
    }
  };

  const handleToggleEnabled = async (item: Record<string, unknown>, val: boolean) => {
    try {
      await riddleApi.updateKnowledge(String(item.id), { enabled: val });
      await loadKnowledge();
    } catch (err) {
      toast.error(`切换状态失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleDeleteKb = async (id: string) => {
    if (!window.confirm("确定删除这条知识库记录？")) return;
    try {
      await riddleApi.deleteIntel(id);
      toast.success("已删除知识条目");
      await loadKnowledge();
    } catch (err) {
      toast.error(`删除失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const handleSyncSeeds = async () => {
    setSyncing(true);
    try {
      const res = await riddleApi.syncKnowledge();
      toast.success(`种子文件同步完成：新增 ${Number(res.added ?? res.synced ?? 0)} 条`);
      await loadKnowledge();
    } catch (err) {
      toast.error(`同步失败：${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setSyncing(false);
    }
  };

  const handleToggleSkillIndex = async (val: boolean) => {
    try {
      await riddleApi.putFusionConfig({ skill_index_enabled: val });
      setSkillIndexEnabled(val);
      toast.success(val ? "已启用 Worker 技能速查注入" : "已关闭 Worker 技能速查注入");
    } catch (err) {
      toast.error(`操作失败：${err instanceof Error ? err.message : String(err)}`);
    }
  };

  const filteredSkills = React.useMemo(() => {
    const q = skillSearch.trim().toLowerCase();
    if (!q) return skillEntries;
    return skillEntries.filter((e) => JSON.stringify(e).toLowerCase().includes(q));
  }, [skillEntries, skillSearch]);

  return (
    <div className="flex flex-1 flex-col gap-5">
      <PageHeader
        title="技能与蒸馏知识库"
        description="统一管理知蠹的内置测试手册、实战蒸馏知识条目与 Worker 技能速查卡（热更新即时生效）。"
        actions={
          <>
            <Button variant="outline" size="sm" disabled={syncing} onClick={() => void handleSyncSeeds()}>
              <FolderSync className="mr-1.5 size-3.5" />
              {syncing ? "同步中…" : "同步本地种子"}
            </Button>
            <Button size="sm" onClick={openCreateSheet}>
              <FilePlus2 className="mr-1.5 size-3.5" />
              新建知识条目
            </Button>
          </>
        }
      />

      <Tabs defaultValue="knowledge" className="space-y-4">
        <TabsList>
          <TabsTrigger value="knowledge">
            <BookOpen className="mr-1.5 size-3.5" /> 实战蒸馏知识库 ({kbItems.length})
          </TabsTrigger>
          <TabsTrigger value="skills">
            <Sparkles className="mr-1.5 size-3.5" /> 技能速查卡 ({skillEntries.length})
          </TabsTrigger>
        </TabsList>

        {/* Tab 1: Knowledge Base */}
        <TabsContent value="knowledge" className="space-y-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative min-w-[220px] flex-1 max-w-md">
              <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
              <Input
                placeholder="检索知识标题、关键词或内容…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-8"
              />
            </div>
            <Select value={category} onValueChange={setCategory}>
              <SelectTrigger className="w-[180px]">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">全部分类</SelectItem>
                <SelectItem value="rules">方法论规则 (rules)</SelectItem>
                <SelectItem value="kb">测试手册 (kb)</SelectItem>
                <SelectItem value="user">实战蒸馏 / 自定义</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => void loadKnowledge()}>
              <RefreshCw className="mr-1.5 size-3.5" /> 刷新
            </Button>
          </div>

          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>知识标题与触发词</TableHead>
                    <TableHead className="w-[140px]">分类</TableHead>
                    <TableHead className="w-[100px] text-right">命中次数</TableHead>
                    <TableHead className="w-[100px]">启用状态</TableHead>
                    <TableHead className="w-[120px] text-right">操作</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {loadingKb ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        正在加载知识库…
                      </TableCell>
                    </TableRow>
                  ) : kbItems.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="h-24 text-center text-sm text-muted-foreground">
                        暂无知识条目，可点击右上角「同步本地种子」或「新建知识条目」。
                      </TableCell>
                    </TableRow>
                  ) : (
                    kbItems.map((it) => (
                      <TableRow
                        key={String(it.id)}
                        className="cursor-pointer hover:bg-muted/40"
                        onClick={() => void openEditSheet(String(it.id))}
                      >
                        <TableCell className="max-w-[400px]">
                          <div className="truncate font-medium text-sm">{String(it.name || it.match_key)}</div>
                          <div className="truncate text-xs text-muted-foreground">
                            触发词：{String(it.keyword || it.match_key || "-")}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {CATEGORY_LABELS[String(it.category)] || String(it.category || "user")}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right text-xs tabular-nums">
                          {Number(it.hit_count ?? 1)}
                        </TableCell>
                        <TableCell onClick={(e) => e.stopPropagation()}>
                          <Switch
                            checked={it.enabled !== false}
                            onCheckedChange={(v) => void handleToggleEnabled(it, v)}
                          />
                        </TableCell>
                        <TableCell className="text-right" onClick={(e) => e.stopPropagation()}>
                          <div className="inline-flex items-center gap-1">
                            <Button variant="ghost" size="sm" onClick={() => void openEditSheet(String(it.id))}>
                              编辑
                            </Button>
                            <Button variant="ghost" size="icon" onClick={() => void handleDeleteKb(String(it.id))}>
                              <Trash2 className="size-4 text-destructive" />
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tab 2: Worker Skill Index */}
        <TabsContent value="skills" className="space-y-4">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-3">
              <div>
                <CardTitle className="text-base">Worker 技能速查注入 (skill_index_enabled)</CardTitle>
                <CardDescription className="text-xs">
                  开启后自动将精炼技能目录注入 Worker 系统提示词，按需触发对应领域的攻防 playbook。
                </CardDescription>
              </div>
              <Switch checked={skillIndexEnabled} onCheckedChange={(v) => void handleToggleSkillIndex(v)} />
            </CardHeader>
          </Card>

          <div className="relative max-w-md">
            <Search className="pointer-events-none absolute top-2.5 left-2.5 size-4 text-muted-foreground" />
            <Input
              placeholder="筛选技能速查条目…"
              value={skillSearch}
              onChange={(e) => setSkillSearch(e.target.value)}
              className="pl-8"
            />
          </div>

          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {filteredSkills.map((sk, idx) => (
              <Card key={idx}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm font-medium">
                    {String(sk.name ?? sk.title ?? sk.id ?? `技能 #${idx + 1}`)}
                  </CardTitle>
                  <CardDescription className="text-xs">
                    {String(sk.category ?? sk.kind ?? sk.path ?? "")}
                  </CardDescription>
                </CardHeader>
                <CardContent className="text-xs text-muted-foreground leading-relaxed">
                  {String(sk.summary ?? sk.description ?? sk.trigger ?? "-")}
                </CardContent>
              </Card>
            ))}
          </div>

          {skillBlock ? (
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm">当前注入提示词速查块预览</CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="max-h-72 overflow-auto rounded-lg border bg-muted/30 p-3 font-mono text-xs whitespace-pre-wrap">
                  {skillBlock}
                </pre>
              </CardContent>
            </Card>
          ) : null}
        </TabsContent>
      </Tabs>

      {/* Edit / Create Knowledge Drawer */}
      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-xl">
          <SheetHeader>
            <SheetTitle>{editId ? "编辑知识库条目" : "新建知识库条目"}</SheetTitle>
            <SheetDescription>保存后立即刷新内存知识缓存，供运行中的 Worker 检索命中。</SheetDescription>
          </SheetHeader>
          <div className="mt-5 space-y-4">
            <div className="space-y-1.5">
              <Label className="text-xs">知识标题 *</Label>
              <Input value={editTitle} onChange={(e) => setEditTitle(e.target.value)} placeholder="例如：某校园网统一认证绕过手法" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="space-y-1.5">
                <Label className="text-xs">分类</Label>
                <Select value={editCategory} onValueChange={setEditCategory}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="user">实战蒸馏 / 自定义</SelectItem>
                    <SelectItem value="kb">测试手册 (kb)</SelectItem>
                    <SelectItem value="rules">方法论规则 (rules)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-1.5">
                <Label className="text-xs">匹配关键词</Label>
                <Input value={editKeyword} onChange={(e) => setEditKeyword(e.target.value)} placeholder="指纹 / 组件 / 漏洞关键词" />
              </div>
            </div>
            <div className="flex items-center justify-between rounded-lg border px-3 py-2">
              <span className="text-xs font-medium">启用该条目供 Worker 检索注入</span>
              <Switch checked={editEnabled} onCheckedChange={setEditEnabled} />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">正文内容（支持 Markdown）*</Label>
              <Textarea
                rows={12}
                className="font-mono text-xs leading-relaxed"
                value={editContent}
                onChange={(e) => setEditContent(e.target.value)}
                placeholder="记录指纹特征、探测路径、PoC 模板与验证要点…"
              />
            </div>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setSheetOpen(false)}>
                取消
              </Button>
              <Button disabled={savingKb} onClick={() => void handleSaveKb()}>
                <Save className="mr-1.5 size-4" />
                {savingKb ? "保存中…" : "保存知识"}
              </Button>
            </div>
          </div>
        </SheetContent>
      </Sheet>
    </div>
  );
}
