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
});
const emit = defineEmits(["edit", "start", "pause", "stop"]);

const stats = computed(() => props.task.stats || {});
const progress = computed(() => props.task.progress || null);
const collectorCfg = computed(() => props.task.fofa_config || {});

const totalTargets = computed(() =>
  (stats.value.queued ?? 0) + (stats.value.scanning ?? 0) +
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0)
);
const resolvedTargets = computed(() =>
  (stats.value.done ?? 0) + (stats.value.dead ?? 0) + (stats.value.skipped ?? 0)
);
const isCollecting = computed(() => progress.value?.kind === "collect");
const progressPct = computed(() => progress.value?.pct ?? 0);
const progressKindText = computed(() => (isCollecting.value ? "搜集进度" : "处置进度"));
const ringIndet = computed(() => isCollecting.value && !collectorCfg.value.collector_phase);

// 搜集阶段条：仅活跃搜集阶段显示（终态/待命由后端 progress.kind=dispose 兜住）
const collectorVisible = computed(() => isCollecting.value && !!(progress.value?.phase_label || progress.value?.meta));
const collectorPct = computed(() => progress.value?.phase_pct ?? 0);
const collectorText = computed(() => progress.value?.phase_label || "正在初始化搜集引擎…");

const runState = computed(() => {
  const s = props.task.status || "unknown";
  const label = { running: "运行中", idle: "空闲", paused: "已暂停", stopped: "已停止", created: "未启动" }[s] || s;
  const hint = s === "running" ? "24×7 自动补队列" : s === "idle" ? "等待新目标或人工动作" : "调度已收敛";
  return { label, hint };
});
const modelName = computed(() =>
  props.task.model_config_data?.model || props.task.llm_usage?.model || "未配置模型"
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
const isEnterpriseTask = computed(() => props.task.src_type === "enterprise");
const taskModeName = computed(() => (isEnterpriseTask.value ? "企业SRC" : "EduSRC"));
const targetSourceName = computed(() => (({
  fofa: "测绘搜集",
  manual: "手动清单",
  both: "测绘+手动",
  site: "单站协作",
})[props.task.target_source] || props.task.target_source || "-"));
const engineName = computed(() => (({
  fofa: "FOFA",
  quake: "360 Quake",
  hunter: "Hunter",
  zoomeye: "ZoomEye",
  shodan: "Shodan",
  censys: "Censys",
})[props.task.engine] || props.task.engine || "FOFA"));
const missionScopeText = computed(() => {
  if (props.task.target_source === "site") {
    return props.task.fofa_query || props.task.manual_targets?.[0] || "单站协作";
  }
  return props.task.fofa_query || "手动清单";
});
const missionEyebrow = computed(() => {
  if (props.task.target_source === "site") return "COOPERATIVE SINGLE-SITE OPERATION";
  return isEnterpriseTask.value ? "AUTONOMOUS ENTERPRISE SRC OPERATION" : "AUTONOMOUS EDU SRC OPERATION";
});

// 作战曲线：时间线桶 → SVG 面积路径（findings 填充 + accepted 描边）
const SPARK_W = 260;
const SPARK_H = 56;
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
  return { area, line, accLine, max, n };
});
const sparkSummary = computed(() => {
  const b = props.timeline || [];
  return {
    findings: b.reduce((s, x) => s + (x.findings ?? 0), 0),
    accepted: b.reduce((s, x) => s + (x.accepted ?? 0), 0),
  };
});
const sparkRange = computed(() => {
  const b = props.timeline || [];
  if (!b.length) return "";
  const f = b[0].ts?.slice(5);
  const l = b[b.length - 1].ts?.slice(5);
  return f && l && f !== l ? `${f} ~ ${l}` : (f || "");
});

function formatTokenCount(n) {
  const v = Number(n || 0);
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(2)}M`;
  if (v >= 10_000) return `${Math.round(v / 1000)}K`;
  if (v >= 1000) return `${(v / 1000).toFixed(1)}K`;
  return String(v);
}

// 漏洞类型分布：横向条形，宽度按最大类型归一
const vulnTotal = computed(() => props.vulnDist.reduce((s, v) => s + (v.count || 0), 0));
function vdPct(count) {
  const max = Math.max(1, ...props.vulnDist.map((v) => v.count || 0));
  return Math.round(((count || 0) / max) * 100);
}
</script>

<template>
  <section class="board-deck">
    <!-- 身份带：任务名 + 状态 + 配置速览 -->
    <header class="deck-head">
      <div class="deck-id">
        <div class="eyebrow">{{ missionEyebrow }}</div>
        <div class="deck-title-row">
          <h2 :title="task.name">{{ task.name }}</h2>
          <button v-if="!readonly" class="hero-edit" type="button" title="编辑参数" @click="emit('edit')">
            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>
            </svg>
          </button>
          <span class="badge" :class="task.status">{{ runState.label }}</span>
          <small class="deck-hint">{{ runState.hint }}</small>
        </div>
      </div>
      <div class="deck-chips">
        <span>{{ taskModeName }}</span>
        <span>{{ targetSourceName }}</span>
        <span v-if="task.target_source !== 'manual' && task.target_source !== 'site'" class="engine-badge">{{ engineName }}</span>
        <span>并发 {{ task.concurrency }}</span>
        <span>深挖 ×{{ task.deepen_cap ?? 2 }}</span>
        <span class="deck-scope" :title="missionScopeText">{{ missionScopeText }}</span>
      </div>
    </header>

    <!-- 作战带：进度环+控制 · 运行时 · 作战曲线 -->
    <div class="deck-battle">
      <div class="deck-progress">
        <div class="progress-ring" :class="{ indet: ringIndet }" :style="{ '--p': progressPct }">
          <b>{{ ringIndet ? "…" : progressPct + "%" }}</b>
          <span>{{ progressKindText }}</span>
        </div>
        <div class="mission-actions" v-if="!readonly">
          <button class="primary" @click="emit('start')" :disabled="task.status === 'running'">启动</button>
          <button @click="emit('pause')" :disabled="task.status !== 'running'">暂停</button>
          <button class="danger" @click="emit('stop')">停止</button>
        </div>
        <div v-else class="aside-readonly-hint">{{ authRole === "readonly" ? "只读模式" : "未认证" }}</div>
        <div v-if="collectorVisible" class="collector-stage">
          <div class="collector-stage-head"><b>{{ collectorText }}</b></div>
          <div class="collector-stage-bar">
            <i :style="{ transform: `scaleX(${collectorPct / 100})` }"></i>
          </div>
          <small v-if="progress?.meta" class="collector-meta">{{ progress.meta }}</small>
        </div>
      </div>

      <div class="deck-runtime">
        <div class="ab-sec-title">模型运行时</div>
        <div class="rt-item">
          <i>模型</i>
          <b :title="modelName">{{ modelName }}</b>
        </div>
        <div class="rt-item">
          <i>Token</i>
          <b>{{ formatTokenCount(tokenUsage.total_tokens) }}</b>
          <small>入 {{ formatTokenCount(tokenUsage.prompt_tokens) }} / 出 {{ formatTokenCount(tokenUsage.completion_tokens) }}</small>
        </div>
        <div class="rt-item">
          <i>请求</i>
          <b>{{ tokenUsage.requests || 0 }}</b>
          <small v-if="cacheHitRate !== null">缓存命中 {{ cacheHitRate }}%</small>
        </div>
      </div>

      <div class="deck-spark">
        <div class="deck-spark-head">
          <b>作战曲线</b>
          <small v-if="sparkRange">{{ sparkRange }}</small>
          <small v-if="timeline.length">新增 {{ sparkSummary.findings }} · 过审 {{ sparkSummary.accepted }}</small>
        </div>
        <svg v-if="spark" class="spark-svg" :viewBox="`0 0 ${SPARK_W} ${SPARK_H}`" preserveAspectRatio="none" aria-hidden="true">
          <defs>
            <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="var(--ab-accent)" stop-opacity=".45"/>
              <stop offset="100%" stop-color="var(--ab-accent)" stop-opacity="0"/>
            </linearGradient>
          </defs>
          <path :d="spark.area" fill="url(#spark-fill)"/>
          <path :d="spark.line" fill="none" stroke="var(--ab-accent-ink)" stroke-width="1.5" vector-effect="non-scaling-stroke"/>
          <path v-if="spark.accLine" :d="spark.accLine" fill="none" stroke="var(--ab-ok)" stroke-width="1.25" stroke-dasharray="3 2" vector-effect="non-scaling-stroke"/>
        </svg>
        <div v-else class="spark-empty">暂无作战数据</div>
      </div>
    </div>

    <!-- 指标带：目标处置主卡 + 四枚语义磁贴 -->
    <div class="deck-metrics">
      <div class="kpi-tile lead">
        <div class="kpi-main">
          <span class="kpi-label"><i class="kpi-dot info"></i>目标处置</span>
          <b class="kpi-val">{{ totalTargets }}</b>
        </div>
        <div class="kpi-sub">扫描 {{ stats.scanning ?? 0 }} · 已扫 {{ stats.done ?? 0 }} · 失联 {{ stats.dead ?? 0 }} · 跳过 {{ stats.skipped ?? 0 }}</div>
        <div class="kpi-bar"><i :style="{ transform: `scaleX(${totalTargets ? resolvedTargets / totalTargets : 0})` }"></i></div>
      </div>
      <div class="kpi-tile hot">
        <span class="kpi-label"><i class="kpi-dot"></i>原始发现</span>
        <b class="kpi-val">{{ stats.findings_total ?? 0 }}</b>
      </div>
      <div class="kpi-tile warn">
        <span class="kpi-label"><i class="kpi-dot"></i>待复审</span>
        <b class="kpi-val">{{ reviewCount }}</b>
      </div>
      <div class="kpi-tile ok">
        <span class="kpi-label"><i class="kpi-dot"></i>待提交</span>
        <b class="kpi-val">{{ submitCount }}</b>
      </div>
      <div class="kpi-tile sweep">
        <span class="kpi-label"><i class="kpi-dot"></i>通杀列</span>
        <b class="kpi-val">{{ sweepCount }}</b>
      </div>
    </div>

    <!-- 漏洞类型分布：横向条形（大屏可视化） -->
    <div v-if="vulnDist.length" class="deck-vulndist">
      <div class="deck-vulndist-head">
        <b>漏洞类型分布</b>
        <small>Top {{ vulnDist.length }} 类型 · 共 {{ vulnTotal }} 条</small>
      </div>
      <div class="deck-vulndist-body">
        <div v-for="v in vulnDist" :key="v.type" class="vd-row">
          <span class="vd-name" :title="v.type">{{ v.type }}</span>
          <div class="vd-bar"><i :style="{ width: vdPct(v.count) + '%' }"></i></div>
          <em>{{ v.count }}</em>
        </div>
      </div>
    </div>
  </section>
</template>
