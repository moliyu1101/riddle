<script setup>
import { computed, ref } from "vue";

defineOptions({ name: "CollabPanel" });
const props = defineProps({
  siteCollab: { type: Object, required: true },
});

function phaseStateText(state) {
  return { active: "进行中", pending: "排队中", done: "已完成", idle: "未开始" }[state] || "";
}
function collabRouteCount(r) {
  const n = Number(r?.count);
  return Number.isFinite(n) && n > 0 ? n : 1;
}
function collabRouteLabel(r) {
  return String(r?.label || "").replace(/\s*[×xX]\s*\d+\s*$/, "").trim() || r?.label || "路线";
}
function groupedCollabRoutes(routes) {
  if (!Array.isArray(routes) || !routes.length) return [];
  const map = new Map();
  const leftover = [];
  for (const r of routes) {
    const label = collabRouteLabel(r);
    const status = r?.status || "done";
    const findings = Number(r?.findings) || 0;
    const count = collabRouteCount(r);
    const running = Number(r?.running) || (status === "running" ? count : 0);
    const queued = Number(r?.queued) || (status === "queued" ? count : 0);
    const done = Number(r?.done) || (status === "done" ? count : 0);
    if (r?.is_aggregate) {
      leftover.push({ ...r, label, count, findings, running, queued, done });
      continue;
    }
    const existing = map.get(label);
    if (!existing) {
      map.set(label, { ...r, label, count, findings, running, queued, done });
      continue;
    }
    existing.count += count;
    existing.findings += findings;
    existing.running += running;
    existing.queued += queued;
    existing.done += done;
    if (status === "running" || (status === "queued" && existing.status !== "running")) {
      existing.status = status;
    }
  }
  return [...map.values(), ...leftover];
}
function collabRouteTitle(r) {
  const bits = [];
  if (collabRouteCount(r) > 1) {
    bits.push(`共 ${r.count} 条`);
    if (r.running) bits.push(`${r.running} 进行中`);
    if (r.queued) bits.push(`${r.queued} 排队`);
    if (r.done) bits.push(`${r.done} 完成`);
  }
  return [r.focus || r.label, bits.join(" · ")].filter(Boolean).join("\n");
}
const collabPhases = computed(() => {
  const phases = props.siteCollab?.phases;
  if (!Array.isArray(phases)) return [];
  return phases.map((p) => ({ ...p, routes: groupedCollabRoutes(p.routes) }));
});
const currentPhaseLabel = computed(() => {
  const cur = props.siteCollab?.current_phase;
  const p = collabPhases.value.find((x) => x.phase === cur);
  return p?.label || "";
});
const blackboard = computed(() => props.siteCollab?.blackboard || null);
// —— 黑板与协作态势联动：点某条路线时，黑板情报过滤为该路线贡献的部分 ——
const activeRoute = ref("");
function setActiveRoute(src) {
  activeRoute.value = activeRoute.value === src ? "" : (src || "");
}
function bbMatchSource(s) {
  const cur = activeRoute.value;
  const src = String(s || "");
  if (!cur) return true;
  if (cur === "site_focus") return src === "site_focus" || src.startsWith("site_f");
  return src === cur;
}
const activeRouteLabel = computed(() => {
  if (!activeRoute.value) return "";
  for (const p of collabPhases.value) {
    const c = p.routes.find((r) => r.source === activeRoute.value);
    if (c) return c.label;
  }
  return activeRoute.value;
});

const bbDirections = computed(() => {
  const d = blackboard.value?.directions;
  if (!d || typeof d !== "object") return [];
  return Object.entries(d).slice(0, 8).map(([wid, dir]) => ({ wid, dir: String(dir) }));
});
const bbProbed = computed(() => {
  const p = blackboard.value?.probed || [];
  return p.map((x) => ({ text: String(x.url || x || ""), source: x.source }))
    .filter((x) => bbMatchSource(x.source)).slice(-12).reverse();
});
const bbCoverage = computed(() => {
  const c = blackboard.value?.coverage || [];
  return c.filter((x) => bbMatchSource(x.source)).slice(-6).reverse();
});
const bbExcluded = computed(() => {
  const e = blackboard.value?.excluded || [];
  return e.filter((x) => bbMatchSource(x.source)).slice(-6).reverse();
});
const bbLeads = computed(() => {
  const l = blackboard.value?.leads || [];
  return l.filter((x) => bbMatchSource(x.source)).slice(-6).reverse();
});
const bbCounts = computed(() => {
  const c = blackboard.value?.counts;
  if (c && typeof c === "object") return c;
  return {
    probed: (blackboard.value?.probed || []).length,
    coverage: (blackboard.value?.coverage || []).length,
    leads: (blackboard.value?.leads || []).length,
    excluded: (blackboard.value?.excluded || []).length,
  };
});
function bbConfCn(conf) {
  return { high: "高", medium: "中", low: "低" }[conf] || "";
}

// —— 黑板态势图：中心黑板 + 四类情报节点绕椭圆轨道分布，连接线从中心辐射 ——
const BB_RX = 40, BB_RY = 46;
const bbNodes = computed(() => {
  const defs = [
    { key: "probed", label: "已探测", count: bbProbed.value.length, items: bbProbed.value.map((u) => ({ source: u.source, text: String(u.text) })) },
    { key: "coverage", label: "已覆盖", count: bbCoverage.value.length, items: bbCoverage.value.map((x) => ({ source: x.source, text: String(x.summary || x.route || "") })) },
    { key: "leads", label: "共享线索", count: bbLeads.value.length, items: bbLeads.value.map((l) => ({ source: l.source, text: String(l.text || ""), conf: l.confidence })) },
    { key: "excluded", label: "已排除", count: bbExcluded.value.length, items: bbExcluded.value.map((e) => ({ source: e.source, text: String(e.reason || e.url || e.summary || "") })) },
  ];
  return defs.map((d, i) => {
    const a = (45 + i * 90) * (Math.PI / 180);
    return { ...d, x: 50 + BB_RX * Math.cos(a), y: 50 + BB_RY * Math.sin(a), hot: d.count > 0 };
  });
});
const bbActive = ref("");
const bbDefaultKey = computed(() => bbNodes.value.find((n) => n.hot)?.key || bbNodes.value[0]?.key || "");
const activeNode = computed(() => bbNodes.value.find((n) => n.key === (bbActive.value || bbDefaultKey.value)) || null);
function setActive(key) { bbActive.value = key; }
const BB_BADGE = { probed: "info", coverage: "ok", leads: "warn", excluded: "muted" };
const detail = ref(null);
function openDetail(i) {
  const it = activeNode.value?.items?.[i];
  if (!it) return;
  detail.value = {
    label: activeNode.value.label,
    badge: BB_BADGE[activeNode.value.key] || "muted",
    count: activeNode.value.count,
    source: it.source,
    conf: it.conf,
    confCn: bbConfCn(it.conf),
    text: it.text || "—",
  };
}
function closeDetail() { detail.value = null; }
const bbTotal = computed(() => bbNodes.value.reduce((s, n) => s + n.count, 0));
</script>

<template>
  <section class="collab-panel">
    <header class="collab-head">
      <div class="collab-title">
        <span class="collab-brand">
          <span class="collab-live" :class="{ off: !(siteCollab.totals.running > 0) }"></span>
          <span class="collab-brand-text">COLLAB OPS</span>
        </span>
        <b>协作态势</b>
        <span v-if="currentPhaseLabel" class="c-phase-pill">{{ currentPhaseLabel }}</span>
        <small>同一目标拆成多条路线协同攻击，共享覆盖上下文、逐阶段深入</small>
      </div>
      <div class="collab-gauges">
        <div class="c-gauge">
          <span class="c-gauge-val">{{ siteCollab.totals.routes }}</span>
          <span class="c-gauge-lbl">任务路线</span>
        </div>
        <div class="c-gauge live">
          <span class="c-gauge-val">{{ siteCollab.totals.running }}</span>
          <span class="c-gauge-lbl">进行中</span>
        </div>
        <div class="c-gauge hit">
          <span class="c-gauge-val">{{ siteCollab.totals.findings }}</span>
          <span class="c-gauge-lbl">已出洞</span>
        </div>
      </div>
    </header>
    <div class="collab-flow">
      <div
        v-for="(p, pi) in collabPhases"
        :key="p.key"
        class="collab-phase"
        :class="[`state-${p.state}`, { current: p.phase === siteCollab.current_phase }]"
      >
        <div class="phase-rail">
          <span class="phase-dot"></span>
          <span v-if="pi < collabPhases.length - 1" class="phase-line"></span>
        </div>
        <div class="phase-body">
          <div class="phase-head">
            <span class="phase-orb" :class="`po-${p.state}`"><i v-if="p.state === 'done'">✓</i><template v-else>{{ p.phase + 1 }}</template></span>
            <b>{{ p.label }}</b>
            <span class="phase-state-tag" :class="`st-${p.state}`">{{ phaseStateText(p.state) }}</span>
            <span v-if="p.counts?.total" class="phase-n">{{ p.counts.total }} 条</span>
          </div>
          <p class="phase-desc">{{ p.desc }}</p>
          <div v-if="p.routes.length" class="phase-routes">
            <div
              v-for="r in p.routes"
              :key="`${r.source}:${r.label}`"
              class="route-chip"
              :class="[`rc-${r.status}`, { 'route-active': activeRoute === r.source }]"
              :title="collabRouteTitle(r)"
              @click="setActiveRoute(r.source)"
            >
              <span class="route-status-dot"></span>
              <span class="route-label">{{ collabRouteLabel(r) }}</span>
              <span v-if="collabRouteCount(r) > 1" class="route-count">×{{ collabRouteCount(r) }}</span>
              <span v-if="r.findings" class="route-hit">{{ r.findings }}</span>
            </div>
          </div>
          <p v-else class="phase-empty">
            {{ p.phase === 0 ? "待启动" : (p.phase === 1 ? "等侦察完成后自动派发" : "等待侦察发现具体入口") }}
          </p>
        </div>
      </div>
    </div>
    <div v-if="blackboard" class="collab-blackboard">
      <div class="bb-head">
        <b>共享黑板</b>
        <small>同站 worker 实时共享，错开路线不撞车</small>
        <button
          v-if="activeRoute"
          type="button"
          class="bb-filter"
          title="点击取消选中"
          @click="setActiveRoute(activeRoute)"
        >
          查看路线：{{ activeRouteLabel }} ×
        </button>
        <span class="bb-counts">
          <i>{{ bbCounts.probed }}</i>已探测
          <i>{{ bbCounts.coverage }}</i>已覆盖
          <i>{{ bbCounts.leads }}</i>线索
          <i>{{ bbCounts.excluded }}</i>排除
        </span>
      </div>

      <div class="bb-situation">
        <!-- 网格背景 + 雷达扫描（复用态势图视觉语言） -->
        <div class="sit-grid" aria-hidden="true"></div>
        <div class="sit-radar" aria-hidden="true"></div>

        <!-- 连接线：中心黑板 → 四类情报节点 -->
        <svg class="sit-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
          <line
            v-for="n in bbNodes"
            :key="n.key"
            x1="50" y1="50" :x2="n.x" :y2="n.y"
            :class="{ hot: n.hot }"
            vector-effect="non-scaling-stroke"
          />
        </svg>

        <!-- 中心枢纽 -->
        <div class="sit-hub">
          <div class="hub-core">
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
              <rect x="3" y="4" width="18" height="14" rx="2"/>
              <line x1="3" y1="10" x2="21" y2="10"/>
              <line x1="8" y1="21" x2="16" y2="21"/>
            </svg>
          </div>
          <div class="hub-text">
            <div class="hub-label">共享黑板</div>
            <div class="hub-meta" v-if="activeRoute">{{ activeRouteLabel }} 路线情报 · {{ bbDirections.length }} worker</div>
            <div class="hub-meta" v-else>{{ bbTotal }} 情报 · {{ bbDirections.length }} worker</div>
          </div>
        </div>

        <!-- 四类情报节点 -->
        <button
          v-for="n in bbNodes"
          :key="n.key"
          type="button"
          class="bb-node"
          :class="[{ hot: n.hot, active: (bbActive || bbDefaultKey) === n.key }]"
          :style="{ left: n.x + '%', top: n.y + '%' }"
          @click="setActive(n.key)"
        >
          <span class="bb-node-count">{{ n.count }}</span>
          <span class="bb-node-label">{{ n.label }}</span>
        </button>
      </div>

      <div v-if="activeNode" class="bb-ledge">
        <div class="bb-ledge-head">
          <span class="bb-ledge-badge" :class="`bd-${BB_BADGE[activeNode.key] || 'muted'}`">
            <i>{{ activeNode.count }}</i>{{ activeNode.label }}
          </span>
          <div v-if="bbDirections.length" class="bb-ledge-dirs">
            <em v-for="d in bbDirections" :key="d.wid" :title="d.wid">{{ d.dir }}</em>
          </div>
        </div>
        <ul v-if="activeNode.items.length" class="bb-list" :class="{ 'bb-leads': activeNode.key === 'leads' }">
          <li
            v-for="(it, i) in activeNode.items"
            :key="i"
            class="bb-item"
            :title="'点击查看详情'"
            @click="openDetail(i)"
          >
            <div v-if="it.source || it.conf" class="bb-item-meta">
              <span v-if="it.source" class="bb-item-src">{{ it.source }}</span>
              <span v-if="it.conf" class="bb-conf" :class="`cf-${it.conf}`">{{ bbConfCn(it.conf) }}</span>
            </div>
            <span class="bb-item-text">{{ it.text || "—" }}</span>
          </li>
        </ul>
        <p v-else class="bb-empty">{{ activeNode.hot ? "暂无明细" : "尚无记录，worker 命中后自动回填" }}</p>
      </div>

      <div v-if="detail" class="bb-detail" @click.self="closeDetail">
        <div class="bb-detail-dialog">
          <div class="bb-detail-head">
            <span class="bb-ledge-badge" :class="`bd-${detail.badge}`">
              <i>{{ detail.count }}</i>{{ detail.label }}
            </span>
            <span v-if="detail.source" class="bb-detail-src">{{ detail.source }}</span>
            <span v-if="detail.conf" class="bb-conf" :class="`cf-${detail.conf}`">{{ detail.confCn }}</span>
            <button type="button" class="bb-detail-close" @click="closeDetail">×</button>
          </div>
          <div class="bb-detail-text" v-text="detail.text"></div>
        </div>
      </div>

      <p v-if="activeRoute && !bbTotal" class="bb-empty bb-empty-full">
        该路线尚未往黑板贡献情报，选其它路线或点「×」取消查看
      </p>
      <p v-else-if="!bbDirections.length && !bbTotal" class="bb-empty bb-empty-full">
        黑板待激活：worker 开始探测后自动共享信息
      </p>
    </div>
  </section>
</template>
