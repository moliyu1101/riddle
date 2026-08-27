<script setup>
import { ref, reactive, computed } from "vue";
import { fmtLocalTime } from "../../format.js";
import { copyText } from "../../clipboard.js";

defineOptions({ name: "KillsweepList" });
const props = defineProps({
  items: { type: Array, default: () => [] },
  total: { type: Number, default: 0 },
  readonly: { type: Boolean, default: false },
  expandedKillsweeps: { type: Object, default: () => new Set() },
  invalidatingId: { type: String, default: null },
  retryingId: { type: String, default: null },
  isEnterpriseTask: { type: Boolean, default: false },
  selected: { type: Object, default: () => new Set() },
  enqueueingId: { type: String, default: null },
  batchWorking: { type: Boolean, default: false },
});
const emit = defineEmits([
  "toggle", "invalidate", "retry", "enqueue", "open-derived",
  "toggle-select", "select-all", "batch-invalidate", "batch-retry", "export",
]);

const FAIL_REASON_LABELS = {
  no_key: "缺少测绘 key",
  timeout: "分析超时",
  quota: "配额耗尽",
  llm_error: "LLM 失败",
  cancelled: "已取消",
  other: "分析异常",
};
const ENQUEUE_PRESETS = [1, 5, 10, 20, 50];
const enqueueCounts = reactive({});
const assetFilters = reactive({});
const exportOpen = ref(false);
const copiedUrl = ref("");

function assetRows(k) {
  const rows = Array.isArray(k?.affected_table) ? k.affected_table : [];
  if (rows.length) return rows;
  if (k?.verified_url) {
    return [{
      school: "待确认",
      url: k.verified_url,
      host: "",
      vuln_title: k.vuln_summary || k.origin_title || "通杀验证目标",
      status: k.verified ? "verified" : "candidate",
      evidence: k.verified ? "通杀 Hunter 已验证" : "通杀 Hunter 圈定候选",
    }];
  }
  return [];
}
function assetStatusLabel(status) {
  return status === "verified" ? "已验证" : "候选";
}
function verifiedCount(k) {
  return assetRows(k).filter((r) => r.status === "verified").length;
}
function derivedFindings(k) {
  return Array.isArray(k?.derived_findings) ? k.derived_findings : [];
}
function failReasonLabel(k) {
  return FAIL_REASON_LABELS[k?.fail_reason] || "";
}
function progressOf(k) {
  return k?.progress && typeof k.progress === "object" ? k.progress : {};
}
function shortText(text, max = 80) {
  const s = String(text || "").replace(/\s+/g, " ").trim();
  return s.length > max ? `${s.slice(0, max)}…` : s;
}
function isOpen(id) {
  return props.expandedKillsweeps.has(id);
}
function isSelected(id) {
  return props.selected.has(id);
}
function selectableItems() {
  return props.items.filter((k) => k.status !== "analyzing");
}
function selectableCount() {
  return selectableItems().length;
}
function allSelected() {
  const list = selectableItems();
  return list.length > 0 && list.every((k) => props.selected.has(k.id));
}
function partialSelected() {
  const list = selectableItems();
  if (!list.length) return false;
  const sel = list.filter((k) => props.selected.has(k.id)).length;
  return sel > 0 && sel < list.length;
}
function isEnqueueable(k) {
  return !!k.is_killsweep && verifiedCount(k) > 0;
}
function enqueueCount(k) {
  const c = enqueueCounts[k.id];
  if (c) return c;
  const v = verifiedCount(k);
  return Math.min(v || 1, 5);
}
function filteredAssetRows(k) {
  const f = assetFilters[k.id] || "all";
  if (f === "all") return assetRows(k);
  return assetRows(k).filter((r) => r.status === f);
}
function setAssetFilter(k, f) {
  assetFilters[k.id] = f;
}
async function copyUrl(url) {
  if (!url) return;
  await copyText(url);
  copiedUrl.value = url;
  setTimeout(() => { if (copiedUrl.value === url) copiedUrl.value = ""; }, 1600);
}
function toggleAll() {
  const list = selectableItems();
  const ids = allSelected() ? [] : list.map((k) => k.id);
  emit("select-all", ids);
}
</script>

<template>
  <div class="list-panel">
    <div class="list-head">
      <span>通杀列</span>
      <small>人工通过后进入此列；可先出 1 个最低单位洞证明通杀，再人工选择数量批量打洞</small>
      <div v-if="!readonly && items.length" class="ks-batch">
        <button class="ks-select-all" type="button"
          :class="{ checked: allSelected(), partial: partialSelected() }"
          :disabled="batchWorking || !selectableCount()"
          :title="allSelected() ? '取消全选' : '全选'"
          @click="toggleAll">
          <span class="ks-select-box">
            <span v-if="allSelected()" class="ks-select-mark">✓</span>
            <span v-else-if="partialSelected()" class="ks-select-mark">–</span>
          </span>
          <span>全选</span>
          <span v-if="selectableCount()" class="ks-select-n">{{ selectableCount() }}</span>
        </button>
        <span v-if="selected.size" class="ks-batch-count">已选 {{ selected.size }} 项</span>
        <button v-if="selected.size" class="ks-batch-clear" type="button" :disabled="batchWorking"
          title="清除选择" @click="emit('select-all', [])">✕ 清除</button>
        <button class="ks-batch-btn danger" type="button" :disabled="batchWorking || !selected.size"
          @click="emit('batch-invalidate', [...selected])">
          {{ batchWorking ? "处理中…" : "批量无效" }}
        </button>
        <button class="ks-batch-btn info" type="button" :disabled="batchWorking || !selected.size"
          @click="emit('batch-retry', [...selected])">
          {{ batchWorking ? "处理中…" : "批量重启" }}
        </button>
        <div class="ks-export">
          <button class="ks-batch-btn" type="button" :disabled="batchWorking" @click="exportOpen = !exportOpen">
            导出 ▾
          </button>
          <div v-if="exportOpen" class="ks-export-menu">
            <button type="button" @click="emit('export', 'md'); exportOpen = false">Markdown 报告</button>
            <button type="button" @click="emit('export', 'json'); exportOpen = false">JSON 原始数据</button>
            <button type="button" @click="emit('export', 'csv'); exportOpen = false">CSV 资产明细</button>
          </div>
        </div>
      </div>
    </div>

    <div v-if="!total" class="empty">还没有通杀记录（人工复审通过后，通杀 Hunter 会自动分析同款系统，失败也会留在这里）</div>
    <div v-else-if="!items.length" class="empty">没有匹配当前关键词的通杀记录</div>

    <div v-for="k in items" :key="k.id" class="killsweep-card"
      :class="{ open: isOpen(k.id), failed: k.status === 'failed', running: k.status === 'analyzing', selected: isSelected(k.id) }">
      <div class="ks-top">
        <label v-if="!readonly && k.status !== 'analyzing'" class="ks-check ks-check-row"
          :title="isSelected(k.id) ? '取消选择' : '选择'"
          @click.stop.prevent="emit('toggle-select', k.id)">
          <input type="checkbox" :checked="isSelected(k.id)" :disabled="batchWorking" />
        </label>
        <button class="ks-summary" type="button" :aria-expanded="isOpen(k.id)" @click="emit('toggle', k.id)">
          <span class="ks-chevron">{{ isOpen(k.id) ? "⌄" : "›" }}</span>
          <span class="ks-main">
            <span class="ks-title">{{ k.product_name || k.origin_title || k.vuln_summary || "通杀分析" }}</span>
            <span class="meta">{{ k.vuln_type }} · {{ k.origin_title || k.vuln_summary || "源漏洞" }}</span>
            <span class="meta rr-time">发现 {{ fmtLocalTime(k.created_at) }}</span>
          </span>
          <span class="ks-summary-metrics">
            <span><b>{{ assetRows(k).length }}</b>资产</span>
            <span><b>{{ isEnterpriseTask ? (k.asset_count ?? 0) : (k.edu_count ?? 0) }}</b>{{ isEnterpriseTask ? "范围" : "教育" }}</span>
            <span><b>{{ k.asset_count ?? 0 }}</b>全网</span>
          </span>
          <span class="ks-badges">
            <span class="tag-run" v-if="k.status === 'analyzing'">分析中</span>
            <span class="tag-fail" v-else-if="k.status === 'failed'">启动失败</span>
            <span class="tag-miss" v-else-if="k.status === 'cancelled'">已取消</span>
            <span class="tag-done" v-else-if="k.is_killsweep || k.has_sites">有通杀站{{ verifiedCount(k) > 1 ? ` ${verifiedCount(k)} 个` : "" }}</span>
            <span class="tag-miss" v-else>无通杀站</span>
            <span class="tag-done" v-if="k.verified">已验证{{ verifiedCount(k) > 1 ? ` ${verifiedCount(k)} 个` : "" }}</span>
            <span class="tag-derived" v-if="derivedFindings(k).length">已出洞 {{ derivedFindings(k).length }}</span>
            <span class="sev-pill" :class="k.confidence" v-if="k.confidence">{{ k.confidence }}</span>
          </span>
        </button>
      </div>

      <div v-if="k.status === 'analyzing'" class="ks-progress">
        <div class="ks-progress-head">
          <span>{{ progressOf(k).label || "通杀分析中…" }}</span>
          <b>{{ progressOf(k).pct ?? 0 }}%</b>
        </div>
        <div class="ks-progress-track">
          <div class="ks-progress-fill" :style="{ width: `${progressOf(k).pct ?? 0}%` }"></div>
        </div>
      </div>

      <div v-if="isOpen(k.id)" class="ks-detail">
        <div class="ks-compact">
          <div>
            <span>发现时间</span>
            <p>{{ fmtLocalTime(k.created_at) || "未知" }}</p>
          </div>
          <div>
            <span>测绘语法</span>
            <code>{{ k.fofa_query || "无测绘语法" }}</code>
          </div>
          <div>
            <span>指纹依据</span>
            <p>{{ k.fingerprint || (k.status === 'failed' || k.status === 'cancelled' ? k.notes : '') || k.notes || "无补充依据" }}</p>
          </div>
          <div v-if="k.status === 'failed' && failReasonLabel(k)">
            <span>失败原因</span>
            <p class="ks-fail-reason">{{ failReasonLabel(k) }}<template v-if="k.notes"> · {{ shortText(k.notes, 120) }}</template></p>
          </div>
        </div>

        <div v-if="derivedFindings(k).length" class="ks-derived">
          <div class="ks-derived-head">
            <span>已出洞 {{ derivedFindings(k).length }} 个</span>
            <small>点击查看完整报告</small>
          </div>
          <div class="ks-derived-list">
            <button v-for="d in derivedFindings(k)" :key="d.finding_id" type="button"
              class="ks-derived-row" @click="emit('open-derived', d.finding_id)">
              <span class="ks-derived-title">{{ d.title || "未命名漏洞" }}</span>
              <span class="ks-derived-meta">
                <span class="sev-pill" :class="d.severity" v-if="d.severity">{{ d.severity }}</span>
                <span class="ks-derived-school">{{ d.school || "待确认" }}</span>
                <span class="mono">{{ d.host || "" }}</span>
                <span class="ks-derived-status" :class="d.status">{{ d.status === "pending_review" ? "待复审" : (d.status || "") }}</span>
              </span>
              <span class="ks-derived-arrow">›</span>
            </button>
          </div>
        </div>

        <div class="ks-affected">
          <div class="ks-affected-head">
            <span>统一资产列表</span>
            <small>{{ filteredAssetRows(k).length }} / {{ assetRows(k).length }} 条 · 强制字段：单位/系统 / 目标 / 漏洞 / 状态 / 依据</small>
            <div class="ks-asset-filter">
              <button type="button" :class="{ on: (assetFilters[k.id] || 'all') === 'all' }" @click="setAssetFilter(k, 'all')">全部</button>
              <button type="button" :class="{ on: assetFilters[k.id] === 'verified' }" @click="setAssetFilter(k, 'verified')">已验证 {{ verifiedCount(k) }}</button>
              <button type="button" :class="{ on: assetFilters[k.id] === 'candidate' }" @click="setAssetFilter(k, 'candidate')">候选</button>
            </div>
          </div>
          <div v-if="!filteredAssetRows(k).length" class="empty sm">暂无资产明细，仅保留通杀摘要。</div>
          <table v-else>
            <thead>
              <tr>
                <th>单位</th>
                <th>目标</th>
                <th>通杀洞</th>
                <th>状态</th>
                <th>依据</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="(row, idx) in filteredAssetRows(k)" :key="row.dedup_key || row.url || row.host || idx">
                <td>{{ row.school || "待确认" }}</td>
                <td>
                  <span class="mono">{{ row.url || row.host || "-" }}</span>
                  <button v-if="row.url || row.host" class="ks-copy-url" type="button"
                    :title="`复制 ${row.url || row.host}`" @click="copyUrl(row.url || row.host)">
                    {{ copiedUrl === (row.url || row.host) ? "✓" : "⧉" }}
                  </button>
                </td>
                <td>{{ row.vuln_title || k.vuln_summary || k.origin_title || "-" }}</td>
                <td><span class="asset-status" :class="{ verified: row.status === 'verified' }">{{ assetStatusLabel(row.status) }}</span></td>
                <td>{{ row.evidence || "-" }}</td>
              </tr>
            </tbody>
          </table>
        </div>

        <div class="ks-actions" v-if="!readonly">
          <div v-if="isEnqueueable(k)" class="ks-enqueue">
            <span class="ks-enqueue-label">批量打洞</span>
            <div class="ks-enqueue-presets">
              <button v-for="n in ENQUEUE_PRESETS" :key="n" type="button"
                :class="{ on: enqueueCount(k) === n }"
                :disabled="n > verifiedCount(k)"
                @click="enqueueCounts[k.id] = n">{{ n }}</button>
            </div>
            <button class="ks-enqueue-go" type="button"
              :disabled="enqueueingId === k.id || !verifiedCount(k)"
              @click="emit('enqueue', k, enqueueCount(k))">
              {{ enqueueingId === k.id ? "入队中…" : `入队 ${enqueueCount(k)} 个打洞` }}
            </button>
            <span class="ks-enqueue-hint">已验证 {{ verifiedCount(k) }} 个站点，可批量入队出货</span>
          </div>
          <button v-if="k.retryable" class="ks-retry" type="button"
            :disabled="retryingId === k.id"
            @click="emit('retry', k)">
            {{ retryingId === k.id ? "启动中…" : "重新启动通杀" }}
          </button>
          <button class="ks-invalid" type="button" :disabled="invalidatingId === k.id || k.status === 'analyzing'" @click="emit('invalidate', k)">
            {{ invalidatingId === k.id ? "标记中…" : "标记为无效" }}
          </button>
          <span v-if="k.status === 'failed'">LLM/中转站失败后可直接重启，不用改复审状态。</span>
          <span v-else-if="!(k.is_killsweep || k.has_sites)">分析完成但没有圈到通杀站；也可再跑一轮。</span>
          <span v-else>误判、资产不稳定、未实际验证或通杀条件不成立时使用。</span>
        </div>
      </div>
    </div>
  </div>
</template>
