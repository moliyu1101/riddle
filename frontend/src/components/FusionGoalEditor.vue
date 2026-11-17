<script setup>
import { computed, ref } from "vue";
import { api } from "../api.js";
import { GOAL_PRESETS, createEmptyGoal, fromGoalPayload } from "../fusionGoals.js";

const props = defineProps({
  modelValue: { type: Array, default: () => [] },
  evaluation: { type: Object, default: null },
  compact: { type: Boolean, default: false },
  suggestContext: { type: Object, default: null },
});

const emit = defineEmits(["update:modelValue"]);
const suggesting = ref(false);
const suggestError = ref("");

const evalStatusById = computed(() => {
  const map = {};
  for (const g of props.evaluation?.met || []) map[g.id] = { met: true, reason: g.reason };
  for (const g of props.evaluation?.unmet || []) map[g.id] = { met: false, reason: g.reason };
  return map;
});

function nextId(rows) {
  const used = new Set(rows.map((r) => r.id));
  let i = rows.length + 1;
  while (used.has(`g${i}`)) i++;
  return `g${i}`;
}

function addEmpty() {
  const list = [...props.modelValue];
  const item = createEmptyGoal(list.length);
  item.id = nextId(list);
  list.push(item);
  emit("update:modelValue", list);
}

function addPreset(preset) {
  const list = [...props.modelValue];
  list.push({
    id: nextId(list),
    title: preset.title,
    kind: preset.kind,
    criteria: preset.criteria,
    matchText: preset.matchText,
  });
  emit("update:modelValue", list);
}

async function suggestGoals() {
  if (suggesting.value) return;
  suggesting.value = true;
  suggestError.value = "";
  try {
    const res = await api.fusionSuggestGoals(props.suggestContext || {});
    const generated = fromGoalPayload(res?.goals || []);
    const list = [...props.modelValue];
    const existingTitles = new Set(list.map((r) => String(r.title || "").trim()));
    for (const g of generated) {
      if (!existingTitles.has(g.title)) {
        list.push({ ...g, id: nextId(list) });
        existingTitles.add(g.title);
      }
    }
    emit("update:modelValue", list);
  } catch (e) {
    suggestError.value = `智能拆解失败：${e?.message || e}`;
  } finally {
    suggesting.value = false;
  }
}

function removeAt(idx) {
  const list = [...props.modelValue];
  list.splice(idx, 1);
  emit("update:modelValue", list);
}

function updateField(idx, field, val) {
  const list = props.modelValue.map((row, i) => (i === idx ? { ...row, [field]: val } : row));
  emit("update:modelValue", list);
}
</script>

<template>
  <div class="fge-wrap" :class="{ compact }">
    <div class="fge-toolbar">
      <div class="fge-presets">
        <span class="fge-lbl">预设模板：</span>
        <button
          v-for="p in GOAL_PRESETS"
          :key="p.title"
          type="button"
          class="fge-preset-btn"
          @click="addPreset(p)"
        >+ {{ p.title }}</button>
      </div>
      <div class="fge-actions-bar">
        <button type="button" class="fge-suggest-btn" :disabled="suggesting" @click="suggestGoals">
          {{ suggesting ? "拆解中…" : "✨ 智能拆解推荐目标" }}
        </button>
        <button type="button" class="fge-add-btn" @click="addEmpty">+ 添加自定义目标</button>
      </div>
    </div>

    <div v-if="suggestError" class="fge-err">{{ suggestError }}</div>

    <div v-if="!modelValue.length" class="fge-empty">
      未配置验收目标（可选）。点击上方预设或「添加自定义目标」后，任务将启用目标闸门核验，未全达成时终态诚实记为 incomplete。
    </div>

    <div v-else class="fge-list">
      <div v-for="(row, idx) in modelValue" :key="row.id + '-' + idx" class="fge-card">
        <div class="fge-card-head">
          <span class="fge-idx">#{{ idx + 1 }} · {{ row.id }}</span>
          <span
            v-if="evalStatusById[row.id]"
            class="fge-eval-pill"
            :class="evalStatusById[row.id].met ? 'met' : 'unmet'"
            :title="evalStatusById[row.id].reason"
          >{{ evalStatusById[row.id].met ? "已达成" : "未达成" }} · {{ evalStatusById[row.id].reason }}</span>
          <button type="button" class="fge-del-btn" @click="removeAt(idx)">移除</button>
        </div>

        <div class="fge-row-grid">
          <label class="fge-field">
            <span>目标标题（需为可核验结果）</span>
            <input
              :value="row.title"
              placeholder="例：未授权接口返回业务数据"
              @input="updateField(idx, 'title', $event.target.value)"
            />
          </label>
          <label class="fge-field">
            <span>目标类型</span>
            <select :value="row.kind" @change="updateField(idx, 'kind', $event.target.value)">
              <option value="existence">existence · 存在型（fact/任意漏洞）</option>
              <option value="capability">capability · 能力型（仅认 high/critical）</option>
            </select>
          </label>
          <label class="fge-field wide">
            <span>可核验验收标准（需含状态码 / 响应字段 / curl / uid= 等信号）</span>
            <input
              :value="row.criteria"
              placeholder="例：匿名 GET 返回 200 且响应 JSON 含业务字段，可用 curl 复现"
              @input="updateField(idx, 'criteria', $event.target.value)"
            />
          </label>
          <label class="fge-field wide">
            <span>匹配关键词（逗号分隔，用于关联漏洞或事实）</span>
            <input
              :value="row.matchText"
              placeholder="例：未授权, unauthorized"
              @input="updateField(idx, 'matchText', $event.target.value)"
            />
          </label>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.fge-wrap { display: flex; flex-direction: column; gap: 10px; }
.fge-toolbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 8px; }
.fge-presets, .fge-actions-bar { display: flex; flex-wrap: wrap; align-items: center; gap: 6px; }
.fge-lbl { font-size: 13px; color: var(--muted); }
.fge-preset-btn, .fge-add-btn, .fge-suggest-btn {
  padding: 4px 10px; border-radius: 999px; font-size: 13px; cursor: pointer;
  border: 1px solid var(--border); background: var(--bg); color: var(--ink-2);
}
.fge-preset-btn:hover, .fge-suggest-btn:hover { border-color: var(--accent); color: var(--accent-ink); }
.fge-suggest-btn { background: color-mix(in oklch, var(--accent) 12%, var(--surface)); border-color: color-mix(in oklch, var(--accent) 40%, var(--border)); color: var(--accent-ink); font-weight: 600; }
.fge-err { font-size: 13px; color: var(--danger); }
.fge-add-btn { background: var(--accent-bg); border-color: color-mix(in oklch, var(--accent) 45%, var(--border)); color: var(--accent-ink); font-weight: 600; }
.fge-empty {
  padding: 10px 12px; border: 1px dashed var(--border); border-radius: 10px;
  font-size: 13.5px; color: var(--muted); line-height: 1.5; background: var(--bg);
}
.fge-list { display: flex; flex-direction: column; gap: 8px; }
.fge-card {
  padding: 10px 12px; border: 1px solid var(--border-soft); border-radius: 10px;
  background: var(--bg); display: flex; flex-direction: column; gap: 8px;
}
.fge-card-head { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.fge-idx { font-size: 13px; font-family: var(--font-mono); color: var(--accent-ink); font-weight: 600; }
.fge-eval-pill {
  font-size: 13px; padding: 2px 8px; border-radius: 999px; max-width: 100%;
  overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.fge-eval-pill.met { background: var(--ok-bg); color: var(--ok); }
.fge-eval-pill.unmet { background: var(--warn-bg); color: var(--warn); }
.fge-del-btn {
  margin-left: auto; padding: 2px 8px; border-radius: 6px; font-size: 13px; cursor: pointer;
  border: 1px solid var(--border); background: transparent; color: var(--muted);
}
.fge-del-btn:hover { color: var(--danger); border-color: var(--danger); }
.fge-row-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
.fge-field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
.fge-field.wide { grid-column: 1 / -1; }
.fge-field span { font-size: 13px; color: var(--muted); }
.fge-field input, .fge-field select {
  width: 100%; box-sizing: border-box; padding: 7px 9px; font-size: 13.5px;
  border: 1px solid var(--border); border-radius: 8px; background: var(--surface); color: var(--ink);
}
@media (max-width: 700px) { .fge-row-grid { grid-template-columns: 1fr; } }
</style>
