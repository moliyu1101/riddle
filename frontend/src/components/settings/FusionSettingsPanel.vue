<script setup>
import { computed, ref } from "vue";
import { api } from "../../api.js";

const props = defineProps({
  form: { type: Object, required: true },
  toast: { type: Function, default: null },
});

const syncing = ref(false);
const syncNote = ref("");

const HARD_SWITCHES = [
  {
    key: "evidence_gate_hard",
    title: "证据硬闸门",
    env: "FUSION_EVIDENCE_GATE_HARD",
    desc: "开启后在 Worker submit_finding 时硬拦截缺少机械凭据或未达 L2+/L3+ 影响层级的 high/critical 结论。",
  },
  {
    key: "scope_guard_hard",
    title: "范围硬守卫",
    env: "FUSION_SCOPE_GUARD_HARD",
    desc: "开启后硬拦截越界（foreign / infra）资产写回漏洞库或黑板，防止污染任务范围。",
  },
  {
    key: "traffic_enabled",
    title: "流量留痕",
    env: "FUSION_TRAFFIC",
    desc: "开启后每次 http_request 在工作目录旁路写入 fusion_traffic.jsonl，供双图与报告绑定真实请求证据。",
  },
];

const MODULE_SWITCHES = [
  { key: "goal_gate_enabled", title: "目标闸门", desc: "任务收官前逐条核验验收标准，未达成强制 incomplete" },
  { key: "skill_index_enabled", title: "技能速查注入", desc: "常驻注入方法论速查块到 Worker system prompt" },
  { key: "role_routing_enabled", title: "角色模型路由", desc: "按 planner / worker / reviewer / judge 分角色覆盖模型" },
  { key: "intel_sync_enabled", title: "情报时间流同步", desc: "允许同步 NVD 2.0 与 CISA KEV 近期高危情报" },
  { key: "graphs_enabled", title: "双图架构", desc: "启用资产图 × 探索图重建、血缘回溯与覆盖度统计" },
  { key: "report_enabled", title: "公文级报告", desc: "允许在融合页与报告抽屉导出公文级 Word (.docx)" },
];

const INTERVAL_PRESETS = [
  { label: "关闭 (0h)", value: 0 },
  { label: "每 6h", value: 6 },
  { label: "每 12h", value: 12 },
  { label: "每 24h", value: 24 },
];

const ROLES = [
  { id: "planner", label: "planner（规划）" },
  { id: "worker", label: "worker（挖掘）" },
  { id: "reviewer", label: "reviewer（初审）" },
  { id: "judge", label: "judge（裁决）" },
];

const activeHardCount = computed(() => {
  const f = props.form.fusion || {};
  return ["evidence_gate_hard", "scope_guard_hard", "traffic_enabled"].filter((k) => !!f[k]).length;
});

function enableAllStrict() {
  const f = props.form.fusion;
  f.evidence_gate_hard = true;
  f.scope_guard_hard = true;
  f.traffic_enabled = true;
  if (!Number(f.intel_sync_interval_hours)) f.intel_sync_interval_hours = 12;
  props.toast?.("已切换为严格门禁 + 留痕（约 1 秒自动保存）");
}

function restoreSafeDefaults() {
  const f = props.form.fusion;
  f.evidence_gate_hard = false;
  f.scope_guard_hard = false;
  f.traffic_enabled = false;
  f.intel_sync_interval_hours = 0;
  props.toast?.("已恢复默认旁路模式（仅留痕试算，不拦截）");
}

async function syncNow() {
  if (syncing.value) return;
  syncing.value = true;
  syncNote.value = "";
  try {
    const res = await api.fusionIntelSync();
    const errs = res?.errors?.length ? `（部分告警：${res.errors.join("；")}）` : "";
    syncNote.value = `同步完成：条目 ${res?.entry_count ?? 0}，快通道 ${res?.fastlane_count ?? 0}，入库 ${res?.stored ?? 0}${errs}`;
    props.toast?.("CVE 情报时间流同步完成");
  } catch (e) {
    syncNote.value = `同步失败：${e?.message || e}`;
    props.toast?.(syncNote.value);
  } finally {
    syncing.value = false;
  }
}
</script>

<template>
  <div class="fusion-settings">
    <div class="settings-subhead">
      <b>核心硬闸门与留痕（即时生效）</b>
      <span>当前已启用 {{ activeHardCount }} / 3 项严格控制 · 默认全部关闭，开启后立即作用于新发包与提交</span>
    </div>

    <div class="fs-quick-bar">
      <button type="button" class="ghost-btn" @click="enableAllStrict">一键开启严格门禁 + 留痕</button>
      <button type="button" class="ghost-btn" @click="restoreSafeDefaults">恢复默认（仅试算不拦截）</button>
      <router-link class="fs-link" to="/fusion">打开融合层工作台 →</router-link>
    </div>

    <div class="fs-hard-grid">
      <label
        v-for="item in HARD_SWITCHES"
        :key="item.key"
        class="fs-hard-card"
        :class="{ on: !!form.fusion[item.key] }"
      >
        <div class="fs-hard-head">
          <input type="checkbox" v-model="form.fusion[item.key]" />
          <strong>{{ item.title }}</strong>
          <em class="fs-state">{{ form.fusion[item.key] ? "已开启" : "已关闭" }}</em>
        </div>
        <p>{{ item.desc }}</p>
        <code>{{ item.env }}</code>
      </label>
    </div>

    <div class="settings-subhead" style="margin-top: 18px;">
      <b>情报时间流与后台自动同步</b>
      <span>定时拉取 NVD 2.0 + CISA KEV 写入全局情报库（kind=cve_feed）</span>
    </div>

    <div class="fs-interval-row">
      <div class="fs-presets">
        <button
          v-for="p in INTERVAL_PRESETS"
          :key="p.value"
          type="button"
          class="fs-preset"
          :class="{ active: Number(form.fusion.intel_sync_interval_hours || 0) === p.value }"
          @click="form.fusion.intel_sync_interval_hours = p.value"
        >{{ p.label }}</button>
      </div>
      <div class="fs-sync-actions">
        <span class="fs-key-pill" :class="{ on: form.fusion.nvd_api_key_configured }">
          NVD_API_KEY：{{ form.fusion.nvd_api_key_configured ? "环境变量已配置" : "未配置（公开限流）" }}
        </span>
        <button type="button" class="ghost-btn" :disabled="syncing" @click="syncNow">
          {{ syncing ? "同步中…" : "立即同步一次 CVE" }}
        </button>
      </div>
    </div>
    <p v-if="syncNote" class="fs-sync-note">{{ syncNote }}</p>

    <div class="settings-grid">
      <label>自动同步周期（小时，0=关闭）
        <input v-model.number="form.fusion.intel_sync_interval_hours" type="number" min="0" max="720" />
      </label>
      <label>情报回溯天数（1–90）
        <input v-model.number="form.fusion.intel_lookback_days" type="number" min="1" max="90" />
      </label>
      <label>高危快通道 CVSS 阈值（0–10）
        <input v-model.number="form.fusion.intel_fastlane_cvss" type="number" min="0" max="10" step="0.1" />
      </label>
      <label>单次抓取超时（秒，1–60）
        <input v-model.number="form.fusion.intel_timeout" type="number" min="1" max="60" />
      </label>
    </div>

    <div class="settings-subhead" style="margin-top: 18px;">
      <b>融合子模块开关</b>
      <span>控制目标校验、提示词注入、双图重建与公文报告功能</span>
    </div>
    <div class="fs-modules-grid">
      <label v-for="m in MODULE_SWITCHES" :key="m.key" class="fs-mod-item">
        <input type="checkbox" v-model="form.fusion[m.key]" />
        <span>
          <strong>{{ m.title }}</strong>
          <small>{{ m.desc }}</small>
        </span>
      </label>
    </div>

    <div class="settings-subhead" style="margin-top: 18px;">
      <b>按角色模型覆盖（可选）</b>
      <span>留空则沿用任务或全局默认模型</span>
    </div>
    <div class="settings-grid">
      <label v-for="r in ROLES" :key="r.id">{{ r.label }}
        <input v-model="form.fusion.role_models[r.id]" placeholder="留空沿用默认模型" />
      </label>
    </div>
  </div>
</template>

<style scoped>
.fusion-settings { display: grid; gap: 12px; }
.fs-quick-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.fs-link { margin-left: auto; font-size: 13.5px; color: var(--accent-ink); text-decoration: none; font-weight: 600; }
.fs-link:hover { text-decoration: underline; }
.fs-hard-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 10px; }
.fs-hard-card {
  display: flex; flex-direction: column; gap: 6px; padding: 12px;
  border: 1px solid var(--border); border-radius: 12px; background: var(--bg); cursor: pointer;
  transition: border-color .15s, background .15s;
}
.fs-hard-card.on { border-color: color-mix(in oklch, var(--ok) 45%, var(--border)); background: color-mix(in oklch, var(--ok) 6%, var(--bg)); }
.fs-hard-head { display: flex; align-items: center; gap: 8px; }
.fs-hard-head input { width: auto; accent-color: var(--accent); }
.fs-hard-head strong { font-size: 13px; color: var(--ink); }
.fs-state { margin-left: auto; font-style: normal; font-size: 13px; padding: 2px 7px; border-radius: 999px; background: var(--surface-2); color: var(--muted); }
.fs-hard-card.on .fs-state { background: var(--ok-bg); color: var(--ok); }
.fs-hard-card p { margin: 0; font-size: 13.5px; color: var(--muted); line-height: 1.5; }
.fs-hard-card code { font-size: 12.5px; color: var(--faint); font-family: var(--font-mono); }
.fs-interval-row { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 10px; }
.fs-presets { display: flex; flex-wrap: wrap; gap: 6px; }
.fs-preset {
  padding: 5px 11px; border-radius: 999px; border: 1px solid var(--border);
  background: var(--bg); color: var(--muted); font-size: 13.5px; cursor: pointer;
}
.fs-preset.active { background: var(--accent-bg); color: var(--accent-ink); border-color: var(--accent); font-weight: 600; }
.fs-sync-actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.fs-key-pill { font-size: 13px; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); background: var(--bg); }
.fs-key-pill.on { color: var(--ok); border-color: color-mix(in oklch, var(--ok) 35%, transparent); background: var(--ok-bg); }
.fs-sync-note { margin: 0; padding: 8px 10px; border-radius: 8px; background: var(--info-bg); color: var(--ink); font-size: 13.5px; }
.fs-modules-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 8px; }
.fs-mod-item {
  display: flex; align-items: flex-start; gap: 8px; padding: 9px 10px;
  border: 1px solid var(--border-soft); border-radius: 10px; background: var(--bg); cursor: pointer;
}
.fs-mod-item input { width: auto; margin-top: 2px; accent-color: var(--accent); }
.fs-mod-item span { display: flex; flex-direction: column; gap: 2px; }
.fs-mod-item strong { font-size: 12.5px; color: var(--ink); }
.fs-mod-item small { font-size: 13px; color: var(--muted); line-height: 1.4; }
</style>
