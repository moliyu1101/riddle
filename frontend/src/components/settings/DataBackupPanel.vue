<script setup>
import { computed } from "vue";

const props = defineProps({
  backupStats: { type: Object, default: null },
  backupLoading: { type: Boolean, default: false },
  backupBusy: { type: String, default: "" },
  backupIncludeWork: { type: Boolean, default: false },
  restoreIncludeWork: { type: Boolean, default: false },
  restoreFile: { type: Object, default: null },
  backupRestarting: { type: Boolean, default: false },
  exportBackup: { type: Function, required: true },
  snapshotNow: { type: Function, required: true },
  downloadSnapshot: { type: Function, required: true },
  onRestoreFile: { type: Function, required: true },
  restoreBackup: { type: Function, required: true },
  loadBackupStats: { type: Function, required: true },
});

const emit = defineEmits(["update:backupIncludeWork", "update:restoreIncludeWork"]);

const backupIncludeWork = computed({
  get: () => props.backupIncludeWork,
  set: (v) => emit("update:backupIncludeWork", v),
});
const restoreIncludeWork = computed({
  get: () => props.restoreIncludeWork,
  set: (v) => emit("update:restoreIncludeWork", v),
});
</script>

<template>
  <div class="data-backup-panel">
    <div v-if="backupRestarting" class="update-restarting">
      <div class="update-spinner"></div>
      <p>备份已写入，服务正在重启…</p>
    </div>
    <div v-else-if="backupLoading && !backupStats" class="field-hint">加载中…</div>
    <div v-else-if="backupStats" class="workdir-panel">
      <div class="settings-subhead">
        <b>备份统计</b>
        <span>数据库快照与磁盘占用情况，自动备份按设定间隔覆盖留一份。</span>
      </div>
      <div class="workdir-stats-grid">
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">数据库</span>
          <b class="workdir-stat-value">{{ backupStats.db_human }}</b>
        </div>
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">库盘剩余</span>
          <b class="workdir-stat-value small">{{ backupStats.disk?.free_human || '未知' }}</b>
        </div>
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">本地快照</span>
          <b class="workdir-stat-value small">{{ backupStats.snapshots_human || '0 B' }}</b>
        </div>
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">自动备份</span>
          <b class="workdir-stat-value" :class="backupStats.auto_backup?.enabled ? 'on' : 'off'">
            {{ backupStats.auto_backup?.enabled ? `每 ${backupStats.auto_backup.interval_hours} 小时` : '已关闭' }}
          </b>
        </div>
        <div class="workdir-stat-item">
          <span class="workdir-stat-label">工作目录</span>
          <b class="workdir-stat-value small">{{ backupStats.work?.human || '0 B' }}</b>
        </div>
      </div>
      <div class="settings-subhead">
        <b>备份与快照</b>
        <span>日常请点「下载备份」把文件带走。服务器只覆盖留 1 份 gzip 快照，不自动堆多份。</span>
      </div>
      <p class="field-hint">
        当前库盘剩余 {{ backupStats.disk?.free_human || '未知' }}，快照占用 {{ backupStats.snapshots_human || '0 B' }}。
        工作目录可选打包，上限 {{ backupStats.work?.max_human }}。
      </p>
      <div class="workdir-cleanup-controls">
        <label class="workdir-dryrun-label">
          <input type="checkbox" v-model="backupIncludeWork" />
          下载时同时打包工作目录
        </label>
        <button type="button" :disabled="!!backupBusy" @click="exportBackup">
          {{ backupBusy === 'export' ? '打包中…' : '下载备份' }}
        </button>
        <button type="button" :disabled="!!backupBusy" @click="snapshotNow">
          {{ backupBusy === 'snapshot' ? '覆盖中…' : '在服务器覆盖留一份' }}
        </button>
        <button type="button" :disabled="backupLoading" @click="loadBackupStats">刷新</button>
      </div>
      <details v-if="backupStats.snapshots?.length" class="workdir-result-details">
        <summary>服务器快照（{{ backupStats.snapshots.length }}）</summary>
        <div class="workdir-result-list">
          <div v-for="s in backupStats.snapshots" :key="s.name" class="workdir-result-item">
            <span class="workdir-item-name">{{ s.name }}</span>
            <span class="workdir-item-size">{{ s.human }}</span>
            <button type="button" class="mini-action" :disabled="!!backupBusy" @click="downloadSnapshot(s.name)">下载</button>
          </div>
        </div>
      </details>
      <div class="backup-restore">
        <div class="settings-subhead">
          <b>从备份恢复</b>
          <span>恢复会覆盖当前数据库并重启服务，执行前请先下载一份当前备份。</span>
        </div>
        <div class="workdir-cleanup-controls">
          <input type="file" accept=".gz,.tgz,.tar.gz,application/gzip" @change="onRestoreFile" />
          <label class="workdir-dryrun-label">
            <input type="checkbox" v-model="restoreIncludeWork" />
            同时恢复工作目录
          </label>
          <button type="button" class="danger" :disabled="!!backupBusy || !restoreFile" @click="restoreBackup">
            {{ backupBusy === 'restore' ? '恢复中…' : '恢复并重启' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>
