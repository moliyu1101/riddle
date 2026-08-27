<script setup>
import { effectiveSeverity } from "../../report.js";
import { fmtLocalTime } from "../../format.js";

defineOptions({ name: "SubmitList" });
defineProps({
  items: { type: Array, default: () => [] },
  total: { type: Number, default: 0 },
  hasMore: { type: Boolean, default: false },
  loading: { type: Boolean, default: false },
  bulkWorking: { type: Boolean, default: false },
  isEnterpriseTask: { type: Boolean, default: false },
  submittedFilter: { type: Boolean, default: false },
});
const emit = defineEmits(["open", "loadMore", "copyAll", "exportAll", "copyEdusrcAll", "exportEdusrcAll", "filterChange"]);

function sevClass(f) {
  const m = { "严重": "critical", "critical": "critical", "高危": "high", "high": "high", "中危": "medium", "medium": "medium", "低危": "low", "low": "low" };
  return m[effectiveSeverity(f)] || "";
}

function diffTitle(d) {
  if (!d) return "";
  const parts = [];
  if (d.reasons?.length) parts.push(d.reasons.join("；"));
  if (d.suggestions?.length) parts.push("建议：" + d.suggestions.join(" "));
  return parts.join("\n");
}
</script>

<template>
  <div class="list-panel">
    <div class="list-head"><span>待提交</span><small>人工通过后的 SRC 报告池</small></div>
    <div class="submit-toolbar">
      <label class="inline"><input type="checkbox" :checked="submittedFilter" @change="emit('filterChange', $event.target.checked)" /> 只看已提交</label>
      <small v-if="total" class="muted">已加载 {{ total }} 条{{ hasMore ? "，还有更多" : "" }}</small>
      <span class="grow"></span>
      <button @click="emit('copyAll')" :disabled="!total || bulkWorking">复制全部 Markdown</button>
      <button @click="emit('exportAll')" :disabled="!total || bulkWorking">导出 .md</button>
      <button v-if="!isEnterpriseTask" @click="emit('copyEdusrcAll')" :disabled="!total || bulkWorking">复制 EduSRC JSON</button>
      <button v-if="!isEnterpriseTask" @click="emit('exportEdusrcAll')" :disabled="!total || bulkWorking">导出 reports.json</button>
    </div>
    <div v-if="!total" class="empty">还没有通过复审的漏洞</div>
    <div v-else-if="!items.length" class="empty">没有匹配当前关键词的待提交漏洞</div>
    <div v-for="f in items" :key="f.id" class="result-row" :class="[{ submitted: f.review?.submitted }, `rr-${sevClass(f)}`]" @click="emit('open', f.id)">
      <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
      <div class="rr-main">
        <div class="rr-title">
          {{ f.title }}
          <span v-if="f.review?.submitted" class="tag-done">已提交</span>
          <span v-if="f.diff" class="diff-pill" :class="'diff-' + f.diff.tier" :title="diffTitle(f.diff)">{{ f.diff.score }} {{ f.diff.label }}</span>
        </div>
        <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
        <div class="meta rr-time">发现 {{ fmtLocalTime(f.created_at) }}<template v-if="f.llm_model"> · 模型 {{ f.llm_model }}</template></div>
      </div>
      <span class="score">{{ f.review?.score ?? "-" }}</span>
    </div>
    <button v-if="hasMore" class="load-more" @click="emit('loadMore')" :disabled="loading">
      {{ loading ? "加载中..." : "加载更多已提交/待提交" }}
    </button>
  </div>
</template>
