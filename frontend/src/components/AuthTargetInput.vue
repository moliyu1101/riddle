<template>
  <div class="auth-ac" ref="rootRef">
    <input
      ref="inputRef"
      class="auth-target-input"
      :value="modelValue"
      :placeholder="placeholder"
      autocomplete="off"
      spellcheck="false"
      @input="onInput"
      @focus="open = true"
      @keydown="onKeydown"
      @blur="onBlur"
    />
    <div v-if="open && filtered.length" class="auth-ac-menu">
      <button
        v-for="(opt, idx) in filtered"
        :key="opt.value"
        type="button"
        class="auth-ac-item"
        :class="{ active: idx === activeIdx, selected: opt.value === modelValue }"
        @mousedown.stop.prevent="select(opt)"
        @mouseenter="activeIdx = idx"
      >
        <template v-for="(part, pi) in highlightParts(opt.label)" :key="pi">
          <mark v-if="part.hit" class="auth-ac-mark">{{ part.text }}</mark>
          <span v-else>{{ part.text }}</span>
        </template>
        <em v-if="opt.value === '*'" class="auth-ac-tag">默认</em>
      </button>
    </div>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, onBeforeUnmount } from "vue";

const props = defineProps({
  modelValue: { type: String, default: "" },
  options: { type: Array, default: () => [] },
  placeholder: { type: String, default: "" },
});
const emit = defineEmits(["update:modelValue"]);

const rootRef = ref(null);
const inputRef = ref(null);
const open = ref(false);
const activeIdx = ref(0);

const query = computed(() => String(props.modelValue || "").trim().toLowerCase());

const filtered = computed(() => {
  const q = query.value;
  return props.options.filter((o) => !q || String(o.label || o.value).toLowerCase().includes(q));
});

function highlightParts(label) {
  const q = query.value;
  if (!q) return [{ text: label, hit: false }];
  const idx = String(label).toLowerCase().indexOf(q);
  if (idx === -1) return [{ text: label, hit: false }];
  return [
    { text: label.slice(0, idx), hit: false },
    { text: label.slice(idx, idx + q.length), hit: true },
    { text: label.slice(idx + q.length), hit: false },
  ];
}

function onInput(e) {
  emit("update:modelValue", e.target.value);
  open.value = true;
  activeIdx.value = 0;
}

function onKeydown(e) {
  if (!open.value || !filtered.value.length) return;
  if (e.key === "ArrowDown") {
    e.preventDefault();
    activeIdx.value = (activeIdx.value + 1) % filtered.value.length;
  } else if (e.key === "ArrowUp") {
    e.preventDefault();
    activeIdx.value = (activeIdx.value - 1 + filtered.value.length) % filtered.value.length;
  } else if (e.key === "Enter") {
    e.preventDefault();
    select(filtered.value[activeIdx.value]);
  } else if (e.key === "Escape") {
    open.value = false;
  }
}

function onBlur() {
  setTimeout(() => { open.value = false; }, 120);
}

function select(opt) {
  emit("update:modelValue", opt.value);
  open.value = false;
  inputRef.value?.focus();
}

function onClickOutside(e) {
  if (rootRef.value && !rootRef.value.contains(e.target)) {
    open.value = false;
  }
}
onMounted(() => document.addEventListener("mousedown", onClickOutside));
onBeforeUnmount(() => document.removeEventListener("mousedown", onClickOutside));
</script>
