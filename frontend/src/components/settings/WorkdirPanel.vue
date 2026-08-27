<script setup>
import { computed } from "vue";

const props = defineProps({
  workdirStats: { type: Object, default: null },
  workdirLoading: { type: Boolean, default: false },
  workdirCleaning: { type: Boolean, default: false },
  workdirResult: { type: Object, default: null },
  cleanupRetentionDays: { type: Number, default: 7 },
  cleanupDryRun: { type: Boolean, default: true },
  runCleanup: { type: Function, required: true },
  loadWorkdirStats: { type: Function, required: true },
});

const emit = defineEmits(["update:cleanupRetentionDays", "update:cleanupDryRun"]);

const cleanupRetentionDays = computed({
  get: () => props.cleanupRetentionDays,
  set: (v) => emit("update:cleanupRetentionDays", v),
});
const cleanupDryRun = computed({
  get: () => props.cleanupDryRun,
  set: (v) => emit("update:cleanupDryRun", v),
});
</script>

<template>
  <div class="workdir-panel">
    <div v-if="workdirLoading" class="field-hint">加载中…</div>
    <div v-else-if="workdirStats" class="workdir-panel">
      <div class="settings-subhead">
        <b>磁盘统计</b>
        <span>Worker / Escalate 等任务运行产生的临时文件占用。</span>
      </div>
      <div class="workdir-stats-grid">
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">磁盘占用</span>
          <b class="workdir-stat-value">{{ workdirStats.total_size_human }}</b>
        </div>
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">目标目录数</span>
          <b class="workdir-stat-value">{{ workdirStats.total_dirs }}</b>
        </div>
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">自动清理</span>
          <b class="workdir-stat-value" :class="workdirStats.auto_cleanup_enabled ? 'on' : 'off'">
            {{ workdirStats.auto_cleanup_enabled ? `已开启（${workdirStats.retention_days}天）` : '已关闭' }}
          </b>
        </div>
        <div v-if="workdirStats.oldest_dir" class="workdir-stat-item">
          <span class="workdir-stat-label">最旧目录</span>
          <b class="workdir-stat-value small">{{ workdirStats.oldest_dir.age_days }}天前</b>
        </div>
      </div>
      <p class="field-hint">工作路径：<code>{{ workdirStats.work_root }}</code></p>
      <p v-if="workdirStats.auto_cleanup_enabled" class="field-hint">
        系统将自动清理超过 {{ workdirStats.retention_days }} 天未修改的工作目录（间隔由 WORKER_WORK_CLEANUP_INTERVAL_HOURS 控制，默认 6 小时）。
      </p>

      <div class="settings-subhead">
        <b>清理操作</b>
        <span>按保留天数清理过期工作目录，默认模拟运行先看会删什么。</span>
      </div>
      <div class="workdir-cleanup-controls">
        <label class="workdir-retention-label">
          清理保留天数
          <input v-model.number="cleanupRetentionDays" type="number" min="0" max="365" />
        </label>
        <label class="workdir-dryrun-label">
          <input type="checkbox" v-model="cleanupDryRun" />
          模拟运行（不实际删除）
        </label>
        <button type="button" :disabled="workdirCleaning" @click="runCleanup">
          {{ workdirCleaning ? "清理中…" : (cleanupDryRun ? "模拟清理" : "执行清理") }}
        </button>
        <button type="button" @click="loadWorkdirStats" :disabled="workdirLoading">
          刷新统计
        </button>
      </div>

      <div v-if="workdirResult" class="workdir-result">
        <div class="workdir-result-summary">
          <span>{{ workdirResult.dry_run ? "模拟清理" : "清理" }}完成</span>
          <span>扫描 {{ workdirResult.scanned_dirs }} 个目录</span>
          <span>删除 {{ workdirResult.deleted_dirs }} 个</span>
          <span v-if="workdirResult.failed_dirs">失败 {{ workdirResult.failed_dirs }} 个</span>
          <span>释放 {{ workdirResult.freed_human }}</span>
        </div>
        <details v-if="workdirResult.deleted?.length" class="workdir-result-details">
          <summary>已清理目录（{{ workdirResult.deleted.length }}）</summary>
          <div class="workdir-result-list">
            <div v-for="d in workdirResult.deleted.slice(0, 100)" :key="d.name" class="workdir-result-item">
              <span class="workdir-item-name">{{ d.name }}</span>
              <span class="workdir-item-age">{{ d.age_days }}天</span>
              <span class="workdir-item-size">{{ d.size_human }}</span>
            </div>
            <p v-if="workdirResult.deleted.length > 100" class="field-hint">
              仅显示前 100 条，共 {{ workdirResult.deleted.length }} 条
            </p>
          </div>
        </details>
        <details v-if="workdirResult.failed?.length" class="workdir-result-details">
          <summary>失败目录（{{ workdirResult.failed.length }}）</summary>
          <div class="workdir-result-list">
            <div v-for="d in workdirResult.failed" :key="d.name" class="workdir-result-item">
              <span class="workdir-item-name">{{ d.name }}</span>
              <span class="workdir-item-age">{{ d.error }}</span>
            </div>
          </div>
        </details>
      </div>
    </div>
  </div>
</template>
