<script setup>
import { computed } from "vue";
import { isLlmErrorEvent } from "../../clipboard.js";
import { evCat, evTime, kindLabel, useEventFormat } from "../../composables/useEventFormat.js";

defineOptions({ name: "WorkerTraceDrawer" });
// full 模式：轨迹抽屉显示完整内容（主列表紧凑截断，这里不截断）
const { fmtEvent } = useEventFormat({ value: {} });
const props = defineProps({
  worker: { type: Object, default: null },
  events: { type: Array, default: () => [] },
  loading: { type: Boolean, default: false },
  isLive: { type: Boolean, default: false },
  readonly: { type: Boolean, default: false },
  sending: { type: Boolean, default: false },
  directiveText: { type: String, default: "" },
});
const emit = defineEmits(["close", "sendDirective", "update:directiveText", "copyLlm"]);

function elapsed(iso) {
  if (!iso) return "";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m${s % 60}s`;
}

function compactBaseUrl(url) {
  return String(url || "").replace(/^https?:\/\//, "").replace(/\/+$/, "");
}

// KPI 仪表盘：从当前轨迹事件实时聚合。
const kpis = computed(() => {
  const evs = props.events || [];
  let tools = 0, http = 0, hits = 0, errors = 0;
  for (const ev of evs) {
    const k = ev.kind || "";
    if (k.startsWith("tool_")) tools += 1;
    if (k === "tool_http") http += 1;
    const cat = evCat(ev);
    if (cat === "hit") hits += 1;
    if (cat === "error") errors += 1;
  }
  return { tools, http, hits, errors };
});

// 渲染序列：按轮次插入分区头 + 折叠相邻重复行（落库/实时两副本 text 差异导致去重键不匹配）。
const rows = computed(() => {
  const out = [];
  let prevRound = null;
  let prevKey = null;
  for (const ev of props.events || []) {
    const round = ev.round || 0;
    const text = ev._text || ev.message || ev.kind || "";
    const key = `${ev.kind || ""}|${round}|${text}`;
    if (prevKey === key) continue;
    prevKey = key;
    if (round !== prevRound) {
      out.push({ type: "round", round, ts: ev._displayTs || ev.ts });
      prevRound = round;
    }
    out.push({ type: "ev", ev });
  }
  return out;
});

// 事件类型标签：tool_ 前缀去掉，其余保留，用于日志行右侧的类型徽章。
function tagOf(ev) {
  return kindLabel(ev.kind);
}

// 裸 kind 行（无格式化文本）弱化显示。
function isBare(ev) {
  const text = ev._text || ev.message || "";
  return !text || text === ev.kind;
}
</script>

<template>
  <div class="drawer-mask trace-mask">
    <aside class="drawer open worker-trace-drawer" role="dialog" aria-modal="true">
      <div class="drawer-content">
        <!-- 作战日志头部 -->
        <header class="olog-head">
          <div class="olog-head-top">
            <div class="olog-brand">
              <span class="olog-live" :class="{ off: !isLive }"></span>
              <span class="olog-brand-text">OPS LOG</span>
            </div>
            <button type="button" class="olog-close" @click="emit('close')" aria-label="关闭" title="关闭">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg>
            </button>
          </div>
          <h3 class="olog-host">{{ worker?.host || "执行轨迹" }}</h3>
          <div class="olog-meta">
            <span class="olog-chip">R{{ worker?.round || 0 }}</span>
            <span class="olog-chip">{{ elapsed(worker?.started_at) }}</span>
            <span v-if="worker?.model" class="olog-chip olog-model" :title="worker.model_base_url ? `${worker.model} @ ${worker.model_base_url}` : worker.model">
              {{ worker.model }}{{ worker.model_base_url ? ` @ ${compactBaseUrl(worker.model_base_url)}` : "" }}
            </span>
            <span class="olog-state" :class="isLive ? 'live' : 'ended'">
              <i class="olog-state-dot"></i>{{ isLive ? "实时" : "已结束" }}
            </span>
          </div>
          <div v-if="worker?.action" class="olog-action">{{ worker.action }}</div>
        </header>

        <!-- KPI 仪表盘 -->
        <div v-if="rows.length" class="olog-kpis">
          <div class="olog-kpi" title="工具调用次数">
            <b>{{ kpis.tools }}</b><span>工具</span>
          </div>
          <div class="olog-kpi" title="HTTP 请求次数">
            <b>{{ kpis.http }}</b><span>请求</span>
          </div>
          <div class="olog-kpi kpi-hit" title="命中漏洞数">
            <b>{{ kpis.hits }}</b><span>命中</span>
          </div>
          <div class="olog-kpi kpi-err" title="错误事件数">
            <b>{{ kpis.errors }}</b><span>错误</span>
          </div>
        </div>

        <!-- 指挥注入 -->
        <div v-if="!readonly" class="olog-directive">
          <div class="olog-dir-head">
            <span class="olog-dir-ic">🎛</span>
            <span>指挥注入</span>
            <small>下一轮 LLM 前生效</small>
          </div>
          <textarea :value="directiveText" rows="3"
            placeholder="例如：优先验证 /api/user/list 的越权；不要再扫目录，直接打 IDOR"
            @input="emit('update:directiveText', $event.target.value)"></textarea>
          <div class="olog-dir-foot">
            <button type="button" class="olog-dir-btn" :disabled="sending || !directiveText.trim()"
              @click="emit('sendDirective')">
              {{ sending ? "发送中…" : "注入指令" }}
            </button>
          </div>
        </div>

        <!-- 日志流 -->
        <div class="olog-list">
          <div v-if="loading && !events.length" class="empty sm">加载轨迹…</div>
          <div v-else-if="!events.length" class="empty sm">{{ isLive ? "暂无轨迹（worker 运行中，产生工具调用后自动刷新）" : "该 worker 已结束，工具/思考明细已归档清理（仅保留关键节点）" }}</div>
          <template v-else>
            <template v-for="(row, i) in rows" :key="row.type === 'round' ? `r${row.round}` : `${row.ev._uid ?? row.ev.ts}|${row.ev.kind}|${i}`">
              <div v-if="row.type === 'round'" class="olog-sec">
                <span class="olog-sec-label">第 {{ row.round }} 轮</span>
                <span class="olog-sec-time">{{ evTime(row.ts) }}</span>
              </div>
              <div v-else class="olog-line" :class="[evCat(row.ev), { bare: isBare(row.ev) }]">
                <span class="olog-ts">{{ evTime(row.ev._displayTs || row.ev.ts) }}</span>
                <span v-if="row.ev.round" class="olog-rnd">R{{ row.ev.round }}</span>
                <span class="olog-tag">{{ tagOf(row.ev) }}</span>
                <span class="olog-msg">{{ fmtEvent(row.ev, true) || row.ev._text || row.ev.message || kindLabel(row.ev.kind) }}</span>
                <button
                  v-if="isLlmErrorEvent(row.ev)"
                  type="button"
                  class="olog-copy"
                  title="复制 LLM 真实错误"
                  @click.stop="emit('copyLlm', row.ev)"
                >复制错误</button>
              </div>
            </template>
          </template>
        </div>
      </div>
    </aside>
  </div>
</template>
