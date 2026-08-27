<script setup>
import { effectiveSeverity } from "../../report.js";
import { fmtLocalTime } from "../../format.js";

defineOptions({ name: "ReviewList" });
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
    <div class="list-head"><span>复审队列</span><small>AI 采纳后等待人工裁决</small></div>
    <div v-if="!total" class="empty">没有待复审的漏洞（AI 采纳后会进这里）</div>
    <div v-else-if="!items.length" class="empty">没有匹配当前关键词的复审漏洞</div>
    <div v-for="f in items" :key="f.id" class="result-row" :class="`rr-${sevClass(f)}`" @click="emit('open', f.id)">
      <span class="sev-pill" :class="effectiveSeverity(f)">{{ effectiveSeverity(f) }}</span>
      <div class="rr-main">
        <div class="rr-title">{{ f.title }}</div>
        <div class="meta">{{ f.vuln_type }} · {{ f.target_url }}</div>
        <div class="meta rr-time">发现 {{ fmtLocalTime(f.created_at) }}<template v-if="f.llm_model"> · 模型 {{ f.llm_model }}</template></div>
      </div>
      <span class="score">{{ f.review?.score ?? "-" }}</span>
    </div>
  </div>
</template>
