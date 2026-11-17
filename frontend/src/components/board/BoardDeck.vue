<script setup>
import { computed } from "vue";

defineOptions({ name: "BoardDeck" });
const props = defineProps({
  task: { type: Object, required: true },
  readonly: { type: Boolean, default: false },
  authRole: { type: String, default: "" },
  reviewCount: { type: Number, default: 0 },
  submitCount: { type: Number, default: 0 },
  sweepCount: { type: Number, default: 0 },
  timeline: { type: Array, default: () => [] },
  vulnDist: { type: Array, default: () => [] },
  liveEscalationsCount: { type: Number, default: 0 },
  hasBlackboard: { type: Boolean, default: false },
});
const emit = defineEmits(["edit", "start", "pause", "stop", "openFusion"]);

const stats = computed(() => props.task.stats || {});
const progress = computed(() => props.task.progress || null);
const collectorCfg = computed(() => props.task.fofa_config || {});
const goalSummary = computed(() => props.task.goal_summary || null);

const totalTargets = computed(() =>
  (stats.value.queued ?? 0) + (stats.value.scanning ?? 0) +
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0)
);
const resolvedTargets = computed(() =>
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0)
);
const isCollecting = computed(() => progress.value?.kind === "collect");
const progressPct = computed(() => progress.value?.pct ?? 0);
const progressKindText = computed(() => (isCollecting.value ? "搜集" : "处置"));
const ringIndet = computed(() => isCollecting.value && !collectorCfg.value.collector_phase);
const collectorVisible = computed(() => isCollecting.value && !!(progress.value?.phase_label || progress.value?.meta));
const collectorPct = computed(() => progress.value?.phase_pct ?? 0);
const collectorText = computed(() => progress.value?.phase_label || "正在初始化搜集引擎…");

const runState = computed(() => {
  const s = props.task.status || "unknown";
  const label = { running: "运行中", idle: "空闲", paused: "已暂停", stopped: "已停止", created: "未启动" }[s] || s;
  return { label, raw: s };
});
const modelName = computed(() =>
  props.task.model_config_data?.model || props.task.llm_usage?.model || "默认模型"
);
const tokenUsage = computed(() => props.task.llm_usage || {});
const cacheHitRate = computed(() => {
  const u = tokenUsage.value || {};
  const hit = Number(u.cache_hit_tokens || 0);
  const miss = Number(u.cache_miss_tokens || 0);
  const base = hit + miss || Number(u.prompt_tokens || 0);
  if (!base) return null;
  return Math.round((hit / base) * 100);
});
const taskModeName = computed(() => (props.task.src_type === "enterprise" ? "企业SRC" : "EduSRC"));
const targetSourceName = computed(() => (({
  fofa: "测绘搜集",
  manual: "手动清单",
  both: "测绘+手动",
  site: "单站协作",
})[props.task.target_source] || props.task.target_source || "-"));
const missionScopeText = computed(() => {
  if (props.task.target_source === "site") {
    return props.task.fofa_query || props.task.manual_targets?.[0] || "单站协作";
  }
  return props.task.fofa_query || "手动清单";
});
const collabStatusLabel = computed(() => {
  if (props.task.target_source === "site") return "单站多路线共享黑板";
  if (props.hasBlackboard || ((props.task.concurrency || 1) >= 2 && totalTargets.value >= 2)) {
    return "多目标并发共享黑板";
  }
  return "单目标专注模式";
});

const SPARK_W = 240;
const SPARK_H = 42;
const spark = computed(() => {
  const buckets = props.timeline || [];
  const n = buckets.length;
  if (!n) return null;
  const max = Math.max(1, ...buckets.map((b) => b.findings ?? 0));
  const step = n > 1 ? SPARK_W / (n - 1) : 0;
  const y = (v) => SPARK_H - Math.round((v / max) * (SPARK_H - 6)) - 2;
  const pts = buckets.map((b, i) => [Math.round(i * step), y(b.findings ?? 0)]);
  const acc = buckets.map((b, i) => [Math.round(i * step), y(b.accepted ?? 0)]);
  const line = pts.map((p, i) => `${i ? "L" : "M"}${p[0]},${p[1]}`).join(" ");
  const area = `${line} L${SPARK_W},${SPARK_H} L0,${SPARK_H} Z`;
  const accLine = acc.some((p) => p[1] < SPARK_H - 2)
    ? acc.map((p, i) => `${i ? "L" : "M"}${p[0]},${p[1]}`).join(" ")
    : "";
  return { area, line, accLine };
});
const sparkSummary = computed(() => {
  const b = props.timeline || [];
  return {
    findings: b.reduce((s, x) => s + (x.findings ?? 0), 0),
    accepted: b.reduce((s, x) => s + (x.accepted ?? 0), 0),
  };
});

function formatTokenCount(n) {
  const v = Number(n || 0);
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}K`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}K`;
  return String(v);
}

function vdPct(count) {
  const max = Math.max(1, ...props.vulnDist.map((v) => v.count || 0));
  return Math.round(((count || 0) / max) * 100);
}
</script>

<template>
  <section class="tac-deck">
    <!-- Row 1：任务身份与主调度控制 -->
    <header class="td-head">
      <div class="td-id">
        <div class="td-title-line">
          <span class="badge" :class="task.status">{{ runState.label }}</span>
          <h2 :title="task.name">{{ task.name }}</h2>
          <span class="td-tag">{{ taskModeName }} · {{ targetSourceName }} · 并发 {{ task.concurrency }} · 深挖 ×{{ task.deepen_cap ?? 2 }}</span>
        </div>
        <div class="td-sub-line">
          <span class="td-collab ok">{{ collabStatusLabel }}</span>
          <span class="td-collab info">Escalate 会话认知继承{{ liveEscalationsCount > 0 ? ` (${liveEscalationsCount} 活跃)` : "就绪" }}</span>
          <span
            v-if="goalSummary?.configured"
            class="td-collab"
            :class="goalSummary.goal_met ? 'ok' : 'warn'"
          >目标闸门：{{ goalSummary.summary }} · {{ goalSummary.terminal_state }}</span>
          <code class="td-scope" :title="missionScopeText">{{ missionScopeText }}</code>
        </div>
      </div>

      <div class="td-controls">
        <template v-if="!readonly">
          <button type="button" class="btn primary" :disabled="task.status === 'running'" @click="emit('start')">▶ 启动</button>
          <button type="button" class="btn" :disabled="task.status !== 'running'" @click="emit('pause')">❚❚ 暂停</button>
          <button type="button" class="btn danger" @click="emit('stop')">■ 停止</button>
          <button type="button" class="btn ghost" @click="emit('edit')">参数</button>
        </template>
        <span v-else class="td-ro">{{ authRole === "readonly" ? "只读审计" : "观摩模式" }}</span>
      </div>
    </header>

    <!-- 搜集期阶段条 -->
    <div v-if="collectorVisible" class="td-collector">
      <span>{{ collectorText }}</span>
      <div class="td-col-bar"><i :style="{ width: `${Math.min(100, Math.max(4, collectorPct))}%` }"></i></div>
      <small v-if="progress?.meta">{{ progress.meta }}</small>
    </div>

    <!-- Row 2：8 格水平遥测仪表带 -->
    <div class="td-ribbon">
      <div class="tr-cell wide">
        <span class="tr-k">{{ progressKindText }}进度</span>
        <div class="tr-prog-line">
          <b>{{ ringIndet ? "搜集中" : progressPct + "%" }}</b>
          <div class="tr-bar"><i :style="{ width: `${Math.min(100, progressPct)}%` }"></i></div>
        </div>
        <small>{{ resolvedTargets }} / {{ totalTargets }} 已收敛</small>
      </div>
      <div class="tr-cell">
        <span class="tr-k">在扫 / 失联 / 跳过</span>
        <b>{{ stats.scanning ?? 0 }} <small>/ {{ stats.dead ?? 0 }} / {{ stats.skipped ?? 0 }}</small></b>
      </div>
      <div class="tr-cell">
        <span class="tr-k">原始发现</span>
        <b>{{ stats.findings_total ?? 0 }}</b>
      </div>
      <div class="tr-cell warn">
        <span class="tr-k">待复审</span>
        <b>{{ reviewCount }}</b>
      </div>
      <div class="tr-cell ok">
        <span class="tr-k">待交 SRC</span>
        <b>{{ submitCount }}</b>
      </div>
      <div class="tr-cell">
        <span class="tr-k">通杀列</span>
        <b>{{ sweepCount }}</b>
      </div>
      <div class="tr-cell wide">
        <span class="tr-k">模型与开销</span>
        <b class="tr-model" :title="modelName">{{ modelName }}</b>
        <small>{{ formatTokenCount(tokenUsage.total_tokens) }} Tok · {{ tokenUsage.requests || 0 }} Req{{ cacheHitRate !== null ? ` · 缓存 ${cacheHitRate}%` : "" }}</small>
      </div>
    </div>

    <!-- Row 3：紧凑作战曲线 + 漏洞分布 + 融合快控 -->
    <div class="td-foot-strip">
      <div class="tdf-spark">
        <div class="tdf-lbl">
          <b>发现趋势</b>
          <small v-if="timeline.length">新增 {{ sparkSummary.findings }} · 过审 {{ sparkSummary.accepted }}</small>
          <small v-else>暂无趋势样本</small>
        </div>
        <svg v-if="spark" :viewBox="`0 0 ${SPARK_W} ${SPARK_H}`" preserveAspectRatio="none" aria-hidden="true">
          <path :d="spark.area" fill="var(--accent-bg)" />
          <path :d="spark.line" fill="none" stroke="var(--accent)" stroke-width="1.6" vector-effect="non-scaling-stroke" />
          <path v-if="spark.accLine" :d="spark.accLine" fill="none" stroke="var(--ok)" stroke-width="1.4" stroke-dasharray="3 2" vector-effect="non-scaling-stroke" />
        </svg>
      </div>

      <div class="tdf-dist">
        <div class="tdf-lbl"><b>高频漏洞类型</b><small>{{ vulnDist.length ? `Top ${vulnDist.length}` : "待产出" }}</small></div>
        <div v-if="vulnDist.length" class="tdf-bars">
          <div v-for="v in vulnDist.slice(0, 4)" :key="v.type" class="tdf-bar-row">
            <span>{{ v.type }}</span>
            <div><i :style="{ width: vdPct(v.count) + '%' }"></i></div>
            <em>{{ v.count }}</em>
          </div>
        </div>
        <small v-else class="tdf-empty">Worker 确认漏洞后自动统计分布</small>
      </div>

      <div v-if="authRole !== 'observer'" class="tdf-fusion">
        <span class="tdf-flbl">融合控制快捷入口</span>
        <div class="tdf-fbtns">
          <button type="button" class="btn" @click="emit('openFusion', 'goals')">🎯 验收目标</button>
          <button type="button" class="btn" @click="emit('openFusion', 'switches')">🛡️ 硬闸门与留痕</button>
          <button type="button" class="btn" @click="emit('openFusion', 'ops')">🕸️ 双图与流量台账</button>
        </div>
      </div>
    </div>
  </section>
</template>

<style scoped>
.tac-deck {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
  box-shadow: var(--shadow-sm);
}

.td-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; flex-wrap: wrap; }
.td-id { display: flex; flex-direction: column; gap: 6px; min-width: 0; flex: 1; }
.td-title-line { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.td-title-line h2 { font-size: 19px; font-weight: 700; color: var(--ink); letter-spacing: -.01em; }
.td-tag { font-size: 11.5px; color: var(--muted); }
.td-sub-line { display: flex; align-items: center; gap: 7px; flex-wrap: wrap; }
.td-collab {
  font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px;
  border: 1px solid var(--border); background: var(--surface-2); color: var(--muted);
}
.td-collab.ok { background: var(--ok-bg); color: var(--ok); border-color: color-mix(in oklch, var(--ok) 35%, transparent); }
.td-collab.info { background: var(--accent2-bg); color: var(--accent2-ink); border-color: color-mix(in oklch, var(--accent2) 35%, transparent); }
.td-collab.warn { background: var(--warn-bg); color: var(--warn); border-color: color-mix(in oklch, var(--warn) 35%, transparent); }
.td-scope {
  font-size: 11px; color: var(--ink-2); background: var(--surface-2); padding: 2px 7px; border-radius: 4px;
  max-width: 360px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.td-controls { display: flex; gap: 6px; flex-wrap: wrap; align-items: center; }
.td-ro { font-size: 12px; color: var(--muted); padding: 5px 10px; background: var(--surface-2); border-radius: 5px; }

.td-collector {
  display: flex; align-items: center; gap: 10px; padding: 6px 10px; border-radius: var(--radius-sm);
  background: var(--info-bg); color: var(--info); font-size: 12px;
}
.td-col-bar { flex: 1; height: 5px; border-radius: 999px; background: var(--surface); overflow: hidden; }
.td-col-bar i { display: block; height: 100%; background: var(--info); }

.td-ribbon {
  display: grid;
  grid-template-columns: 1.5fr 1.1fr repeat(4, 0.85fr) 1.5fr;
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  background: var(--surface-2);
}
.tr-cell {
  padding: 9px 12px; border-right: 1px solid var(--border-soft);
  display: flex; flex-direction: column; gap: 2px; min-width: 0;
}
.tr-cell:last-child { border-right: none; }
.tr-k { font-size: 10.5px; font-weight: 600; color: var(--muted); }
.tr-cell b { font-size: 17px; font-weight: 700; color: var(--ink); font-variant-numeric: tabular-nums; line-height: 1.25; }
.tr-cell b small { font-size: 11.5px; font-weight: 500; color: var(--muted); }
.tr-cell.warn b { color: var(--warn); }
.tr-cell.ok b { color: var(--ok); }
.tr-cell small { font-size: 10.5px; color: var(--faint); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.tr-model { font-size: 12.5px !important; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.tr-prog-line { display: flex; align-items: center; gap: 8px; }
.tr-bar { flex: 1; height: 6px; border-radius: 999px; background: var(--surface-3); overflow: hidden; }
.tr-bar i { display: block; height: 100%; background: var(--accent); }

.td-foot-strip {
  display: grid; grid-template-columns: 1fr 1fr auto; gap: 12px; align-items: center;
  padding-top: 8px; border-top: 1px solid var(--border-soft);
}
.tdf-spark, .tdf-dist {
  display: flex; flex-direction: column; gap: 4px; min-width: 0;
  padding: 8px 10px; background: var(--surface-2); border: 1px solid var(--border-soft); border-radius: var(--radius-sm);
}
.tdf-lbl { display: flex; justify-content: space-between; align-items: center; font-size: 11.5px; }
.tdf-lbl b { color: var(--ink-2); }
.tdf-lbl small { color: var(--faint); font-size: 11px; }
.tdf-spark svg { width: 100%; height: 42px; display: block; }
.tdf-bars { display: flex; flex-direction: column; gap: 4px; }
.tdf-bar-row { display: grid; grid-template-columns: 76px 1fr 24px; gap: 8px; align-items: center; font-size: 11px; }
.tdf-bar-row span { color: var(--ink-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.tdf-bar-row div { height: 5px; background: var(--surface-3); border-radius: 999px; overflow: hidden; }
.tdf-bar-row i { display: block; height: 100%; background: var(--accent2); }
.tdf-bar-row em { font-style: normal; text-align: right; color: var(--muted); font-variant-numeric: tabular-nums; }
.tdf-empty { font-size: 11px; color: var(--faint); padding: 10px 0; }

.tdf-fusion { display: flex; flex-direction: column; gap: 6px; }
.tdf-flbl { font-size: 10.5px; font-weight: 700; color: var(--muted); letter-spacing: .04em; }
.tdf-fbtns { display: flex; gap: 6px; flex-wrap: wrap; }
.tdf-fbtns .btn { font-size: 12px; padding: 6px 10px; }

@media (max-width: 1120px) {
  .td-ribbon { grid-template-columns: repeat(4, 1fr); }
  .tr-cell { border-bottom: 1px solid var(--border-soft); }
  .td-foot-strip { grid-template-columns: 1fr; }
}
@media (max-width: 640px) {
  .td-ribbon { grid-template-columns: repeat(2, 1fr); }
}
</style>
