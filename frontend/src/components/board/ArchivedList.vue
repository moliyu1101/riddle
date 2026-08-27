<script setup>
import { effectiveSeverity } from "../../report.js";
import { fmtLocalTime } from "../../format.js";

defineOptions({ name: "ArchivedList" });
defineProps({
  items: { type: Array, default: () => [] },
  total: { type: Number, default: 0 },
  hasMore: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
  writeCount: { type: Number, default: 0 },
  readonly: { type: Boolean, default: false },
});
const emit = defineEmits(["open", "restore", "loadMore"]);

function sevClass(f) {
  const m = { "严重": "critical", "critical": "critical", "高危": "high", "high": "high", "中危": "medium", "medium": "medium", "低危": "low", "low": "low" };
  return m[effectiveSeverity(f)] || "";
}
</script>

<template>
  <div class="list-panel">
    <div class="list-head">
      <span>AI 未采纳</span>
      <small>AI 判为非漏洞或深挖未升级的洞，保留在此防误杀，可点开查看、必要时「恢复到复审」</small>
      <small v-if="writeCount" class="write-hint">有 {{ writeCount }} 条写/删类已置顶，优先人工看，别让真洞埋在这里</small>
      <small v-if="total" class="muted">已加载 {{ total }} 条{{ hasMore ? "，还有更多" : "" }}</small>
    </div>
    <div v-if="!total" class="empty">
      暂无 AI 未采纳的漏洞（AI 审核判「非漏洞」或「深挖未升级」的洞会沉淀到这里，防止误杀）
    </div>
    <div v-else-if="!items.length" class="empty">没有匹配当前关键词的未采纳漏洞</div>
    <div v-for="f in items" :key="f.id" class="result-row archived" :class="[{ 'write-op': f.is_write_op }, `rr-${sevClass(f)}`]" @click="emit('open', f.id)">
      <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
      <div class="rr-main">
        <div class="rr-title">
          <span class="arch-tag" :class="[f.archive_reason, { write: f.is_write_op }]">{{ f.archive_reason_text }}</span>
          {{ f.title }}
        </div>
        <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
        <div class="meta rr-time">发现 {{ fmtLocalTime(f.created_at) }}<template v-if="f.llm_model"> · 模型 {{ f.llm_model }}</template></div>
        <div v-if="f.ignore_reasons?.length" class="meta rr-note">AI 理由：{{ f.ignore_reasons.join("；") }}</div>
      </div>
      <div class="rr-side" @click.stop>
        <span class="score">{{ f.review?.score ?? "-" }}</span>
        <button v-if="!readonly" class="mini-action" type="button" @click="emit('restore', f.id)">恢复到复审</button>
      </div>
    </div>
    <button v-if="hasMore" class="load-more" @click="emit('loadMore')" :disabled="loading">
      {{ loading ? "加载中..." : "加载更多未采纳漏洞" }}
    </button>
  </div>
</template>
