<script setup>
defineOptions({ name: "WorkerMatrix" });
const props = defineProps({
  liveWorkers: { type: Array, default: () => [] },
  liveEscalations: { type: Array, default: () => [] },
  workerSummary: { type: Object, default: () => ({}) },
  concurrency: { type: Number, default: 0 },
  throttle: { type: Object, default: null },
  boardReady: { type: Boolean, default: false },
  readonly: { type: Boolean, default: false },
  cancellingEscalateId: { type: String, default: null },
});
const emit = defineEmits(["openTrace", "skipTarget", "cancelEscalation"]);

// 阶段徽章元数据：label 展示文案 + cls 语义色（对应 board.css 的 .wc-phase.*）
const PHASE_META = {
  booting:   { label: "启动中", cls: "muted" },
  auth:      { label: "认证",   cls: "info" },
  recon:     { label: "侦察中", cls: "info" },
  thinking:  { label: "思考中", cls: "warn" },
  verify:    { label: "验证中", cls: "accent" },
  found:     { label: "已发现", cls: "ok" },
  finishing: { label: "收尾中", cls: "muted" },
};
function phaseMeta(w) {
  return PHASE_META[w?.phase] || PHASE_META.recon;
}
function elapsed(iso) {
  if (!iso) return "";
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m${s % 60}s`;
}
function authBadge(w) {
  const st = w?.auth || "";
  if (!st) return "";
  if (st === "injected") return "凭据·已注入";
  if (st === "login_ok") return "凭据·登录成功";
  if (st === "login_fail") return "凭据·登录失败";
  if (st === "unused") return "凭据·未匹配";
  return `凭据·${st}`;
}
function authBadgeClass(w) {
  const st = w?.auth || "";
  if (st === "injected" || st === "login_ok") return "ok";
  if (st === "login_fail") return "bad";
  return "muted";
}
function compactBaseUrl(value) {
  const raw = String(value || "").trim();
  if (!raw) return "";
  try { return new URL(raw).host; }
  catch { return raw.replace(/^https?:\/\//, "").split("/")[0]; }
}
// 优先级评分档位：优先解析后端 reason 前缀（[稀有]/[差异化]/[普通]/[大众]），
// 自动深挖等改写场景解析不到时按分数回退（>=100 视为深挖）。
const SCORE_TIER_META = {
  rare:   { label: "稀有", cls: "rare" },
  diff:   { label: "差异化", cls: "diff" },
  normal: { label: "普通", cls: "normal" },
  common: { label: "大众", cls: "common" },
  deep:   { label: "深挖", cls: "deep" },
};
const SCORE_TIER_BY_LABEL = { "稀有": "rare", "差异化": "diff", "普通": "normal", "大众": "common", "深挖": "deep" };
const SCORE_FALLBACK = [
  { min: 100, tier: "deep" },
  { min: 10, tier: "rare" },
  { min: 6, tier: "diff" },
  { min: 3, tier: "normal" },
  { min: -Infinity, tier: "common" },
];
function scoreTier(w) {
  const m = String(w?.score_reason || "").match(/^\[([^\]]+)\]/);
  if (m && SCORE_TIER_BY_LABEL[m[1]]) return SCORE_TIER_META[SCORE_TIER_BY_LABEL[m[1]]];
  const s = Number(w?.score) || 0;
  for (const f of SCORE_FALLBACK) {
    if (s >= f.min) return SCORE_TIER_META[f.tier];
  }
  return SCORE_TIER_META.common;
}
function scoreTooltip(w) {
  const t = scoreTier(w);
  const reason = String(w?.score_reason || "").trim();
  return reason ? `优先级评分 ${w?.score ?? 0}（${t.label}）｜${reason}` : `优先级评分 ${w?.score ?? 0}（${t.label}）`;
}
function workerModelTitle(worker) {
  return [worker?.model_role || "挖掘模型", worker?.model, worker?.model_base_url].filter(Boolean).join(" · ");
}
// 智能节流：cap < base_cap 说明本轮被降级；返回是否处于降级态。
function throttleActive() {
  const t = props.throttle;
  return !!(t && t.cap != null && t.base_cap != null && t.cap < t.base_cap);
}
function throttlePct() {
  const t = props.throttle;
  if (!t || !t.base_cap) return 100;
  return Math.round(((t.cap ?? t.base_cap) / t.base_cap) * 100);
}
// 是否有仍在推进的活跃单元（决定头部呼吸灯）
function hasActive() {
  return props.liveWorkers.some((w) => w.phase && w.phase !== "finishing");
}
</script>

<template>
  <div class="board-col board-panel unit-panel">
    <div class="col-head">
      <span>作战单元</span>
      <small>点击卡片查看轨迹</small>
      <i v-if="hasActive()" class="stream-live"></i>
      <i class="cnt">{{ liveWorkers.length }}</i>
    </div>

    <!-- 单元摘要：运行 / 扩大 / 空闲槽 三格大数字状态卡（后端 worker_summary 提供） -->
    <div v-if="boardReady" class="unit-summary">
      <div class="us-card running">
        <span class="us-ico">▶</span>
        <div class="us-body">
          <b>{{ workerSummary.running ?? liveWorkers.length }}</b>
          <small>运行中</small>
        </div>
      </div>
      <div class="us-card escalate">
        <span class="us-ico">↗</span>
        <div class="us-body">
          <b>{{ workerSummary.escalating ?? liveEscalations.length }}</b>
          <small>扩大危害</small>
        </div>
      </div>
      <div class="us-card idle">
        <span class="us-ico">◌</span>
        <div class="us-body">
          <b>{{ workerSummary.idle ?? Math.max(0, concurrency - liveWorkers.length) }}</b>
          <small>空闲槽</small>
        </div>
      </div>
    </div>

    <!-- 智能节流状态条：cap < base_cap 时展示降级原因（队列水位/LLM 健康度/同机构扎堆） -->
    <div v-if="boardReady && throttle" class="throttle-bar" :class="{ active: throttleActive() }"
      :title="(throttle.reasons || []).join('；') || '并发上限未被降级'">
      <span class="th-bar-ico">{{ throttleActive() ? '⏳' : '⚙' }}</span>
      <span class="th-bar-text">
        <b>智能节流</b>
        <small v-if="throttleActive()">{{ throttle.cap }}/{{ throttle.base_cap }} 并发（{{ throttlePct() }}%）</small>
        <small v-else>并发 {{ throttle.cap }} 正常</small>
      </span>
      <span v-if="throttleActive() && (throttle.reasons || []).length" class="th-bar-reasons">
        {{ throttle.reasons[0] }}<template v-if="throttle.reasons.length > 1"> 等 {{ throttle.reasons.length }} 项</template>
      </span>
    </div>

    <div v-if="!boardReady" class="board-hydrate" aria-hidden="true">
      <div v-for="n in 3" :key="n" class="skeleton-worker"></div>
    </div>
    <div v-else-if="!liveWorkers.length && !liveEscalations.length" class="empty sm unit-empty">
      <span class="unit-empty-ico">◈</span>
      <span>启动任务后，这里将显示各目标的作战单元</span>
    </div>

    <template v-else>
      <div v-for="(w, i) in liveWorkers" :key="w.target_id" class="worker-card clickable anim-fade-up"
        :class="`ph-${phaseMeta(w).cls}`"
        :style="{ '--i': Math.min(i, 6) }"
        @click="emit('openTrace', w)" title="查看执行轨迹 / 注入指令">
        <div class="wc-top">
          <span class="wc-host">
            <i class="wc-dot" :class="phaseMeta(w).cls"></i>
            <span class="wc-host-text">{{ w.host }}</span>
          </span>
          <span class="wc-meta">
            <span class="wc-round">R{{ w.round }}</span>
            <span class="wc-elapsed">{{ elapsed(w.started_at) }}</span>
          </span>
        </div>
        <div class="wc-sub">
          <span class="wc-badges">
            <span v-if="authBadge(w)" class="wc-auth" :class="authBadgeClass(w)" :title="w.auth_label || ''">{{ authBadge(w) }}</span>
            <span v-if="w.score > 0" class="wc-score" :class="scoreTier(w).cls" :title="scoreTooltip(w)">★{{ Math.round(w.score * 10) / 10 }}<em>{{ scoreTier(w).label }}</em></span>
          </span>
          <button v-if="!readonly" type="button" class="wc-del"
            title="删除该目标（跳过本次任务的这个目标）" @click.stop="emit('skipTarget', w)">✕</button>
        </div>
        <div class="wc-action">{{ w.action }}</div>
        <div v-if="w.model || w.model_base_url" class="wc-model" :title="workerModelTitle(w)">
          <span class="wc-model-ic">🤖</span>
          <span>{{ w.model_role || "挖掘模型" }}</span>
          <b>{{ w.model || "未知模型" }}</b>
          <small v-if="w.model_base_url">@ {{ compactBaseUrl(w.model_base_url) }}</small>
        </div>
        <div class="wc-foot">
          <span class="wc-phase" :class="phaseMeta(w).cls">
            <i></i>{{ phaseMeta(w).label }}
          </span>
          <span class="wc-find" :class="{ hit: w.findings > 0 }">
            {{ w.findings > 0 ? `🎯 ${w.findings} 个漏洞` : "侦察中…" }}
          </span>
          <span class="wc-bar" :title="`进度 ${w.progress ?? 0}%`">
            <i :style="{ transform: `scaleX(${Math.min(1, (w.progress ?? 0) / 100)})` }"></i>
          </span>
        </div>
      </div>

      <!-- 扩大危害活态 -->
      <div v-if="liveEscalations.length" class="escalate-block">
        <div class="col-head sub"><span>扩大危害</span><small>进行中</small><i class="cnt">{{ liveEscalations.length }}</i></div>
        <div v-for="(e, i) in liveEscalations" :key="e.finding_id" class="worker-card escalate-card anim-fade-up"
          :style="{ '--i': Math.min(i, 6) }">
          <div class="wc-top">
            <span class="wc-host">
              <i class="wc-dot warn"></i>
              <span class="wc-host-text">{{ e.title || e.finding_id }}</span>
            </span>
            <span class="wc-meta">
              <span v-if="e.severity" class="wc-score">{{ e.severity }}</span>
              <span class="wc-elapsed">{{ elapsed(e.started_at) }}</span>
            </span>
          </div>
          <div class="wc-action">{{ e.action || "扩大危害进行中…" }}</div>
          <div class="wc-sub">
            <span class="wc-badges"></span>
            <button v-if="!readonly" type="button" class="wc-del"
              title="取消扩大危害"
              :disabled="cancellingEscalateId === e.finding_id"
              @click.stop="emit('cancelEscalation', e)">✕</button>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
