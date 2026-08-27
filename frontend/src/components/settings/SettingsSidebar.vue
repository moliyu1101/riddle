<script setup>
import { computed } from "vue";

const props = defineProps({
  visibleTabs: { type: Array, required: true },
  settingsTab: { type: String, required: true },
  llmMode: { type: String, required: true },
  form: { type: Object, required: true },
  engineKeysSetCount: { type: Number, default: 0 },
  healthOverview: { type: Object, default: null },
  healthOverviewLoading: { type: Boolean, default: false },
});

defineEmits(["update:settingsTab"]);

/** 分组图标（16×16 stroke） */
const TAB_ICONS = {
  appearance: "M8 2.2C8 2.2 3.4 7.3 3.4 10.3a4.6 4.6 0 0 0 9.2 0C12.6 7.3 8 2.2 8 2.2Z",
  llm: "M5.2 5.2h5.6v5.6H5.2zM8 2v3.2M8 10.8V14M2 8h3.2M10.8 8H14",
  recon: "M8 8m-5.5 0a5.5 5.5 0 1 0 11 0a5.5 5.5 0 1 0-11 0M8 5.8a2.2 2.2 0 1 0 0 4.4 2.2 2.2 0 0 0 0-4.4M2.5 8h1.8M11.7 8h1.8M8 2.5v1.8M8 11.7v1.8",
  runtime: "M2.5 4.5H6M10 4.5h3.5M6.5 4.5a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0M2.5 8h6M11.5 8h2M8 8a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0M2.5 11.5h2M9 11.5h4M5 11.5a1.5 1.5 0 1 0 3 0a1.5 1.5 0 1 0-3 0",
  security: "M8 1.8 3 3.6v3.4c0 3.4 2.2 5.6 5 6.6 2.8-1 5-3.2 5-6.6V3.6L8 1.8ZM6 8.2l1.4 1.4L10.2 6.6",
  data: "M3 4.2c0-1.1 2.2-2 5-2s5 .9 5 2v7.6c0 1.1-2.2 2-5 2s-5-.9-5-2V4.2ZM3 4.2c0 1.1 2.2 2 5 2s5-.9 5-2M3 8c0 1.1 2.2 2 5 2s5-.9 5-2",
  update: "M13.5 8a5.5 5.5 0 1 1-1.6-3.9M13.5 1.5v3h-3",
};

const TAB_BADGES = computed(() => {
  const llm = props.healthOverview?.llm;
  const engines = props.healthOverview?.engines;
  return {
    llm: llm ? (llm.healthy ? "ok" : "warn") : "",
    recon: engines ? (engines.configured > 0 ? `${engines.configured}/${engines.total}` : "off") : "",
  };
});

const llmText = computed(() => {
  if (props.llmMode === "pool") return `${props.form.llm_providers.length} 个端点`;
  return props.form.model || "未设置模型";
});

const llmBadge = computed(() => {
  if (props.llmMode === "pool") {
    return props.form.llm_providers.some((p) => p.enabled !== false) ? "pool" : "off";
  }
  return props.form.api_key_set ? "key set" : "no key";
});

const llmBadgeOn = computed(() => {
  if (props.llmMode === "pool") return props.form.llm_providers.some((p) => p.enabled !== false);
  return !!props.form.api_key_set;
});

/** 健康总览派生：LLM 是否健康（pool 模式看 enabled 端点是否 degraded） */
const llmHealth = computed(() => props.healthOverview?.llm || null);

const engineText = computed(() => {
  const ov = props.healthOverview?.engines;
  if (ov) return `${ov.default || "fofa"} · ${ov.configured}/${ov.total} key`;
  return `${props.form.default_engine || "fofa"} · ${props.form.max_pages} 页`;
});

const engineBadge = computed(() => {
  const ov = props.healthOverview?.engines;
  if (ov) return ov.configured > 0 ? `${ov.configured}/${ov.total}` : "no key";
  return props.engineKeysSetCount > 0 ? `${props.engineKeysSetCount} key` : "no key";
});

const engineBadgeOn = computed(() => {
  const ov = props.healthOverview?.engines;
  if (ov) return ov.configured > 0;
  return props.engineKeysSetCount > 0;
});

const diskText = computed(() => {
  const ov = props.healthOverview?.disk;
  if (ov) return `${ov.work_size_human} · ${ov.work_dirs} 目录`;
  return "—";
});

const diskBadge = computed(() => {
  const ov = props.healthOverview?.disk;
  if (!ov) return "";
  return ov.auto_cleanup ? "自动清理" : "手动";
});

const diskBadgeOn = computed(() => !!props.healthOverview?.disk?.auto_cleanup);
</script>

<template>
  <aside class="settings-summary" aria-label="设置分组">
    <div class="settings-summary-head">
      <span>SETTINGS</span>
      <b>分组</b>
    </div>
    <nav class="settings-nav" aria-label="设置分组">
      <button
        v-for="tab in visibleTabs"
        :key="tab.id"
        type="button"
        :class="{ active: settingsTab === tab.id }"
        @click="$emit('update:settingsTab', tab.id)"
      >
        <span class="settings-nav-icon" aria-hidden="true">
          <svg viewBox="0 0 16 16" width="15" height="15">
            <path :d="TAB_ICONS[tab.id]" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </span>
        <span class="settings-nav-text">
          <b>{{ tab.label }}</b>
          <small>{{ tab.hint }}</small>
        </span>
        <i v-if="TAB_BADGES[tab.id]" class="settings-nav-badge" :class="TAB_BADGES[tab.id]"></i>
      </button>
    </nav>

    <div class="settings-status-head">
      <span>状态总览</span>
      <i v-if="healthOverviewLoading" class="settings-status-spin" aria-hidden="true"></i>
    </div>

    <div class="settings-health" :class="{ degraded: llmHealth?.degraded }">
      <div>
        <span>LLM</span>
        <b>{{ llmText }}</b>
        <small v-if="llmHealth" class="settings-health-sub">
          {{ llmHealth.mode === "pool" ? `${llmHealth.enabled_count}/${llmHealth.provider_count} 启用` : (llmHealth.healthy ? "健康" : "降级") }}
        </small>
      </div>
      <i :class="{ on: llmHealth ? llmHealth.healthy : llmBadgeOn }">
        {{ llmHealth ? (llmHealth.healthy ? "healthy" : "degraded") : llmBadge }}
      </i>
    </div>

    <div class="settings-health">
      <div>
        <span>测绘</span>
        <b>{{ engineText }}</b>
      </div>
      <i :class="{ on: engineBadgeOn }">{{ engineBadge }}</i>
    </div>

    <div class="settings-health">
      <div>
        <span>磁盘</span>
        <b>{{ diskText }}</b>
      </div>
      <i v-if="diskBadge" :class="{ on: diskBadgeOn }">{{ diskBadge }}</i>
    </div>

    <p class="settings-note">任务创建时可覆盖模型与调度默认值。外观写入本实例数据库与数据卷。</p>
  </aside>
</template>
