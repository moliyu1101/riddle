<script setup>
import { ref, watch } from "vue";
import { api } from "../../api.js";
import FusionGoalEditor from "../FusionGoalEditor.vue";
import { fromGoalPayload, toGoalPayload, validateGoalRows } from "../../fusionGoals.js";

const props = defineProps({
  open: { type: Boolean, default: false },
  taskId: { type: String, default: "" },
  initialTab: { type: String, default: "goals" },
  readonly: { type: Boolean, default: false },
});

const emit = defineEmits(["close", "toast", "goalUpdated"]);

const activeTab = ref("goals");
const loading = ref(false);
const busy = ref("");

const goalRows = ref([]);
const goalEval = ref(null);
const cfg = ref({
  evidence_gate_hard: false,
  scope_guard_hard: false,
  traffic_enabled: false,
  intel_sync_interval_hours: 0,
});
const graphRes = ref(null);
const trafficRes = ref(null);

async function loadDrawer() {
  if (!props.open || !props.taskId) return;
  loading.value = true;
  try {
    const [gRes, evRes, cRes] = await Promise.all([
      api.fusionGoals(props.taskId).catch(() => ({ goals: [] })),
      api.fusionEvaluateGoals(props.taskId).catch(() => null),
      api.fusionConfig().catch(() => null),
    ]);
    goalRows.value = fromGoalPayload(gRes?.goals || []);
    goalEval.value = evRes;
    if (cRes?.config) {
      cfg.value = {
        evidence_gate_hard: !!cRes.config.evidence_gate_hard,
        scope_guard_hard: !!cRes.config.scope_guard_hard,
        traffic_enabled: !!cRes.config.traffic_enabled,
        intel_sync_interval_hours: Number(cRes.config.intel_sync_interval_hours || 0),
      };
    }
  } finally {
    loading.value = false;
  }
}

watch(
  () => [props.open, props.taskId],
  ([isOpen]) => {
    if (isOpen) {
      activeTab.value = props.initialTab || "goals";
      loadDrawer();
    }
  },
  { immediate: true },
);

async function saveAndEvalGoals() {
  if (props.readonly || busy.value) return;
  if (!goalRows.value.length) {
    emit("toast", "请至少添加一条验收目标后再保存");
    return;
  }
  const err = validateGoalRows(goalRows.value);
  if (err) {
    emit("toast", err);
    return;
  }
  busy.value = "goals";
  try {
    await api.fusionSaveGoals(props.taskId, toGoalPayload(goalRows.value));
    goalEval.value = await api.fusionEvaluateGoals(props.taskId);
    emit("toast", `目标已保存：${goalEval.value?.summary || "完成"}`);
    emit("goalUpdated");
  } catch (e) {
    emit("toast", String(e?.message || e).replace(/^\d+\s*/, ""));
  } finally {
    busy.value = "";
  }
}

async function evaluateOnly() {
  if (busy.value) return;
  busy.value = "eval";
  try {
    goalEval.value = await api.fusionEvaluateGoals(props.taskId);
    emit("toast", goalEval.value?.summary || "目标核对完成");
    emit("goalUpdated");
  } catch (e) {
    emit("toast", String(e?.message || e).replace(/^\d+\s*/, ""));
  } finally {
    busy.value = "";
  }
}

async function saveQuickConfig() {
  if (props.readonly || busy.value) return;
  busy.value = "cfg";
  try {
    const r = await api.fusionSaveConfig({
      evidence_gate_hard: !!cfg.value.evidence_gate_hard,
      scope_guard_hard: !!cfg.value.scope_guard_hard,
      traffic_enabled: !!cfg.value.traffic_enabled,
      intel_sync_interval_hours: Number(cfg.value.intel_sync_interval_hours || 0),
    });
    if (r?.config) {
      cfg.value = {
        evidence_gate_hard: !!r.config.evidence_gate_hard,
        scope_guard_hard: !!r.config.scope_guard_hard,
        traffic_enabled: !!r.config.traffic_enabled,
        intel_sync_interval_hours: Number(r.config.intel_sync_interval_hours || 0),
      };
    }
    emit("toast", "融合开关已保存并即时生效");
  } catch (e) {
    emit("toast", String(e?.message || e).replace(/^\d+\s*/, ""));
  } finally {
    busy.value = "";
  }
}

async function toggleSwitch(key) {
  if (props.readonly || busy.value) return;
  cfg.value[key] = !cfg.value[key];
  await saveQuickConfig();
}

async function rebuildTaskGraph() {
  if (props.readonly || busy.value) return;
  busy.value = "graph";
  try {
    graphRes.value = await api.fusionGraphRebuild(props.taskId);
    emit("toast", `双图已重建：${graphRes.value.nodes} 节点 / ${graphRes.value.edges} 边`);
  } catch (e) {
    emit("toast", String(e?.message || e).replace(/^\d+\s*/, ""));
  } finally {
    busy.value = "";
  }
}

async function importTaskTraffic() {
  if (props.readonly || busy.value) return;
  busy.value = "traffic";
  try {
    trafficRes.value = await api.fusionTrafficImport(props.taskId, "");
    emit("toast", `已导入 ${trafficRes.value.imported} 条流量记录`);
  } catch (e) {
    emit("toast", String(e?.message || e).replace(/^\d+\s*/, ""));
  } finally {
    busy.value = "";
  }
}
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="bfd-mask" @mousedown.self="emit('close')">
      <aside class="bfd-panel" role="dialog" aria-modal="true" aria-label="任务融合控制与目标">
        <header class="bfd-head">
          <div>
            <h3>融合控制与验收目标</h3>
            <small>任务 {{ taskId }} · 开关修改即时生效，目标即时核对</small>
          </div>
          <button type="button" class="bfd-close" title="关闭" @click="emit('close')">×</button>
        </header>

        <nav class="bfd-tabs" role="tablist">
          <button type="button" :class="{ active: activeTab === 'goals' }" @click="activeTab = 'goals'">验收目标</button>
          <button type="button" :class="{ active: activeTab === 'switches' }" @click="activeTab = 'switches'">硬闸门与留痕</button>
          <button type="button" :class="{ active: activeTab === 'ops' }" @click="activeTab = 'ops'">双图与流量</button>
        </nav>

        <div class="bfd-body">
          <div v-if="loading" class="bfd-loading">正在加载任务融合状态…</div>

          <template v-else-if="activeTab === 'goals'">
            <div v-if="goalEval?.configured" class="bfd-eval-banner" :class="goalEval.goal_met ? 'met' : 'incomplete'">
              <strong>{{ goalEval.summary }} → 终态 {{ goalEval.terminal_state }}</strong>
              <span>已纳入 {{ goalEval.finding_count ?? 0 }} 条发现参与核对</span>
            </div>
            <FusionGoalEditor v-model="goalRows" :evaluation="goalEval" :suggest-context="{ task_id: taskId }" compact />
            <div class="bfd-actions">
              <button v-if="!readonly" type="button" class="primary" :disabled="!!busy" @click="saveAndEvalGoals">
                {{ busy === "goals" ? "保存中…" : "保存并核对" }}
              </button>
              <button type="button" class="ghost-btn" :disabled="!!busy" @click="evaluateOnly">
                {{ busy === "eval" ? "核对中…" : "立即核对" }}
              </button>
              <router-link class="bfd-link" :to="{ path: '/fusion', query: { tab: 'goals', taskId } }" @click="emit('close')">
                在融合专页打开 →
              </router-link>
            </div>
          </template>

          <template v-else-if="activeTab === 'switches'">
            <p class="bfd-hint">以下为全局运行时开关，切换后立刻作用于正在跑的 Worker 与发包链路（无需重启）。</p>
            <div class="bfd-switches">
              <button
                type="button"
                class="bfd-switch-card"
                :class="{ on: cfg.evidence_gate_hard }"
                :disabled="readonly || !!busy"
                @click="toggleSwitch('evidence_gate_hard')"
              >
                <div>
                  <strong>证据硬闸门</strong>
                  <small>submit_finding 拦截无机械凭据的 high/critical</small>
                </div>
                <em>{{ cfg.evidence_gate_hard ? "已开启" : "已关闭" }}</em>
              </button>
              <button
                type="button"
                class="bfd-switch-card"
                :class="{ on: cfg.scope_guard_hard }"
                :disabled="readonly || !!busy"
                @click="toggleSwitch('scope_guard_hard')"
              >
                <div>
                  <strong>范围硬守卫</strong>
                  <small>拦截越界（foreign / infra）资产写回</small>
                </div>
                <em>{{ cfg.scope_guard_hard ? "已开启" : "已关闭" }}</em>
              </button>
              <button
                type="button"
                class="bfd-switch-card"
                :class="{ on: cfg.traffic_enabled }"
                :disabled="readonly || !!busy"
                @click="toggleSwitch('traffic_enabled')"
              >
                <div>
                  <strong>流量留痕</strong>
                  <small>http_request 逐请求旁路写 fusion_traffic.jsonl</small>
                </div>
                <em>{{ cfg.traffic_enabled ? "已开启" : "已关闭" }}</em>
              </button>
            </div>
            <div class="bfd-interval-box">
              <label>
                <span>情报后台自动同步周期（小时，0=关闭）</span>
                <div class="bfd-interval-row">
                  <input v-model.number="cfg.intel_sync_interval_hours" type="number" min="0" max="720" :disabled="readonly" />
                  <button v-if="!readonly" type="button" class="primary" :disabled="!!busy" @click="saveQuickConfig">保存周期</button>
                </div>
              </label>
            </div>
          </template>

          <template v-else>
            <p class="bfd-hint">对当前任务一键重建资产×探索双图，或从工作区 JSONL 导入最新请求流量台账。</p>
            <div class="bfd-ops-cards">
              <div class="bfd-op-card">
                <div>
                  <strong>双图旁路重建</strong>
                  <small>从目标、目标闸门、漏洞与事件重建拓扑与覆盖度</small>
                </div>
                <button v-if="!readonly" type="button" class="primary" :disabled="!!busy" @click="rebuildTaskGraph">
                  {{ busy === "graph" ? "重建中…" : "重建双图" }}
                </button>
                <p v-if="graphRes" class="bfd-op-res">
                  节点 {{ graphRes.nodes }} / 边 {{ graphRes.edges }} · 覆盖率 {{ ((graphRes.coverage?.ratio || 0) * 100).toFixed(1) }}%
                </p>
              </div>
              <div class="bfd-op-card">
                <div>
                  <strong>流量台账导入</strong>
                  <small>扫描工作区 fusion_traffic.jsonl 并按 sha256 幂等入库</small>
                </div>
                <button v-if="!readonly" type="button" class="primary" :disabled="!!busy" @click="importTaskTraffic">
                  {{ busy === "traffic" ? "导入中…" : "导入流量" }}
                </button>
                <p v-if="trafficRes" class="bfd-op-res">
                  扫描 {{ trafficRes.scanned_rows }} 行，去重 {{ trafficRes.unique_rows }} 行，新增 {{ trafficRes.imported }} 条
                </p>
              </div>
            </div>
            <div class="bfd-actions">
              <router-link class="bfd-link" :to="{ path: '/fusion', query: { tab: 'graphs', taskId } }" @click="emit('close')">
                打开双图血缘拓扑 →
              </router-link>
              <router-link class="bfd-link" :to="{ path: '/fusion', query: { tab: 'traffic', taskId } }" @click="emit('close')">
                前往勾选绑定流量证据 →
              </router-link>
            </div>
          </template>
        </div>
      </aside>
    </div>
  </Teleport>
</template>

<style scoped>
.bfd-mask {
  position: fixed; inset: 0; z-index: var(--z-modal, 200);
  background: rgba(6, 10, 18, 0.56); backdrop-filter: blur(4px);
  display: flex; justify-content: flex-end;
}
.bfd-panel {
  width: min(620px, 96vw); height: 100%; background: var(--surface);
  border-left: 1px solid var(--border); box-shadow: var(--shadow-lg);
  display: flex; flex-direction: column;
}
.bfd-head {
  display: flex; align-items: center; justify-content: space-between; gap: 12px;
  padding: 16px 20px; border-bottom: 1px solid var(--border);
}
.bfd-head h3 { margin: 0; font-size: 16px; color: var(--ink); }
.bfd-head small { color: var(--muted); font-size: 13px; font-family: var(--font-mono); }
.bfd-close {
  width: 32px; height: 32px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--bg); color: var(--muted); font-size: 18px; cursor: pointer;
}
.bfd-close:hover { color: var(--danger); border-color: var(--danger); }
.bfd-tabs { display: flex; gap: 6px; padding: 10px 20px; border-bottom: 1px solid var(--border-soft); }
.bfd-tabs button {
  padding: 6px 12px; border-radius: 8px; border: 1px solid transparent;
  background: transparent; color: var(--muted); font-size: 12.5px; font-weight: 600; cursor: pointer;
}
.bfd-tabs button.active { background: var(--accent-bg); color: var(--accent-ink); border-color: var(--accent); }
.bfd-body { flex: 1; overflow-y: auto; padding: 16px 20px 24px; display: flex; flex-direction: column; gap: 14px; }
.bfd-loading, .bfd-hint { font-size: 12.5px; color: var(--muted); margin: 0; line-height: 1.5; }
.bfd-eval-banner {
  padding: 10px 12px; border-radius: 10px; display: flex; justify-content: space-between; align-items: center;
  font-size: 12.5px; background: var(--warn-bg); color: var(--warn); border: 1px solid color-mix(in oklch, var(--warn) 35%, transparent);
}
.bfd-eval-banner.met { background: var(--ok-bg); color: var(--ok); border-color: color-mix(in oklch, var(--ok) 35%, transparent); }
.bfd-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 10px; }
.bfd-link { margin-left: auto; font-size: 13.5px; color: var(--accent-ink); text-decoration: none; font-weight: 600; }
.bfd-link:hover { text-decoration: underline; }
.bfd-switches { display: grid; gap: 10px; }
.bfd-switch-card {
  display: flex; align-items: center; justify-content: space-between; gap: 12px; text-align: left;
  padding: 12px 14px; border-radius: 12px; border: 1px solid var(--border); background: var(--bg); cursor: pointer;
}
.bfd-switch-card.on { border-color: color-mix(in oklch, var(--ok) 45%, var(--border)); background: color-mix(in oklch, var(--ok) 6%, var(--bg)); }
.bfd-switch-card strong { display: block; font-size: 13px; color: var(--ink); }
.bfd-switch-card small { display: block; font-size: 13px; color: var(--muted); margin-top: 2px; }
.bfd-switch-card em { font-style: normal; font-size: 13px; padding: 3px 9px; border-radius: 999px; background: var(--surface-2); color: var(--muted); flex: none; }
.bfd-switch-card.on em { background: var(--ok-bg); color: var(--ok); font-weight: 600; }
.bfd-interval-box { padding: 12px; border: 1px solid var(--border-soft); border-radius: 10px; background: var(--bg); }
.bfd-interval-box span { display: block; font-size: 13.5px; color: var(--muted); margin-bottom: 6px; }
.bfd-interval-row { display: flex; gap: 8px; }
.bfd-interval-row input { flex: 1; padding: 7px 10px; border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--ink); }
.bfd-ops-cards { display: grid; gap: 10px; }
.bfd-op-card {
  padding: 12px 14px; border: 1px solid var(--border-soft); border-radius: 12px; background: var(--bg);
  display: flex; flex-direction: column; gap: 8px; align-items: flex-start;
}
.bfd-op-card strong { display: block; font-size: 13px; color: var(--ink); }
.bfd-op-card small { display: block; font-size: 13px; color: var(--muted); margin-top: 2px; }
.bfd-op-res { margin: 0; font-size: 13.5px; color: var(--ok); }
</style>
