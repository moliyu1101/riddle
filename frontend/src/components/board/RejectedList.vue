<script setup>
import { effectiveSeverity } from "../../report.js";
import { fmtLocalTime } from "../../format.js";

defineOptions({ name: "RejectedList" });
defineProps({
  items: { type: Array, default: () => [] },
  total: { type: Number, default: 0 },
});
const emit = defineEmits(["open"]);

function sevClass(f) {
  const m = { "严重": "critical", "critical": "critical", "高危": "high", "high": "high", "中危": "medium", "medium": "medium", "低危": "low", "low": "low" };
  return m[effectiveSeverity(f)] || "";
}
</script>

<template>
  <div class="list-panel">
    <div class="list-head"><span>已驳回</span><small>沉淀不收口径，可恢复或继续深挖</small></div>
    <div v-if="!total" class="empty">还没有被驳回的漏洞（复审点「不通过」会进这里，可回看与恢复）</div>
    <div v-else-if="!items.length" class="empty">没有匹配当前关键词的驳回漏洞</div>
    <div v-for="f in items" :key="f.id" class="result-row rejected" :class="`rr-${sevClass(f)}`" @click="emit('open', f.id)">
      <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
      <div class="rr-main">
        <div class="rr-title">{{ f.title }}</div>
        <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
        <div class="meta rr-time">发现 {{ fmtLocalTime(f.created_at) }}<template v-if="f.llm_model"> · 模型 {{ f.llm_model }}</template></div>
        <div v-if="f.review?.user_notes" class="meta rr-note">驳回备注：{{ f.review.user_notes }}</div>
      </div>
      <span class="score">{{ f.review?.score ?? "-" }}</span>
    </div>
  </div>
</template>
