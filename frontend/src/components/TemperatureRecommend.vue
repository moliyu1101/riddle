<script setup>
import { ref, nextTick } from "vue";
import { api } from "../api.js";

const props = defineProps({
  modelValue: { type: [Number, String], default: 0.3 },
  disabled: { type: Boolean, default: false },
  model: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue"]);

const TEMP_ROLES = [
  { id: "hunt", label: "挖洞" },
  { id: "review", label: "审核" },
  { id: "report", label: "报告" },
];
const tempRole = ref("hunt");
const rec = ref(null);
const loading = ref(false);
const resultEl = ref(null);

async function recommend() {
  // toggle：已展开时再点「推荐」收起，避免面板常驻
  if (rec.value && !loading.value) {
    rec.value = null;
    return;
  }
  loading.value = true;
  try {
    const res = await api.temperatureRecommend({ model: props.model, role: tempRole.value });
    rec.value = res;
  } catch (e) {
    rec.value = { error: String(e.message || e).replace(/^\d+\s*/, "") };
  } finally {
    loading.value = false;
  }
  // 内嵌展开后滚动到可见区域，避免被弹窗滚动容器裁切
  await nextTick();
  resultEl.value?.scrollIntoView({ block: "nearest", behavior: "smooth" });
}
function setRole(role) {
  tempRole.value = role;
  loading.value = true;
  api.temperatureRecommend({ model: props.model, role })
    .then((res) => { rec.value = res; })
    .catch((e) => { rec.value = { error: String(e.message || e).replace(/^\d+\s*/, "") }; })
    .finally(() => { loading.value = false; });
}
function apply() {
  if (rec.value?.temperature != null) emit("update:modelValue", rec.value.temperature);
  rec.value = null;
}
</script>

<template>
  <div ref="wrapEl" class="temp-recommend-wrap">
    <span class="temp-line">
      <input
        :value="modelValue"
        type="number" step="0.1" min="0" max="2"
        :disabled="disabled"
        @input="emit('update:modelValue', $event.target.value)"
      />
      <button
        type="button"
        class="temp-recommend"
        :disabled="disabled || loading"
        :title="model ? '按模型类型 + 任务角色推荐' : '先填模型名再推荐'"
        @click="recommend"
      >{{ loading ? "…" : "推荐" }}</button>
    </span>
    <div v-if="rec" ref="resultEl" class="temp-recommend-result" :class="{ error: rec.error }">
      <template v-if="rec.error">{{ rec.error }}</template>
      <template v-else>
        <span class="tr-roles">
          <button
            v-for="r in TEMP_ROLES"
            :key="r.id"
            type="button"
            class="tr-role"
            :class="{ on: tempRole === r.id }"
            @click="setRole(r.id)"
          >{{ r.label }}</button>
        </span>
        <span class="tr-value">推荐 <b>{{ rec.temperature }}</b></span>
        <span class="tr-reason">{{ rec.reason }}</span>
        <button type="button" class="tr-apply" @click="apply">应用</button>
      </template>
    </div>
  </div>
</template>
