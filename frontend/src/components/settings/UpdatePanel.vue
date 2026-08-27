<script setup>
defineProps({
  updateState: { type: Object, required: true },
  checkUpdate: { type: Function, required: true },
  runUpdate: { type: Function, required: true },
});
</script>

<template>
  <div class="update-panel">
    <div v-if="updateState.restarting" class="update-restarting">
      <div class="update-spinner"></div>
      <p>服务正在重启，自动重连中…</p>
    </div>
    <div v-else class="update-body">
      <button type="button" class="btn-check" @click="checkUpdate" :disabled="updateState.checking">
        {{ updateState.checking ? "检测中…" : "检查更新" }}
      </button>
      <div v-if="updateState.error" class="update-error">{{ updateState.error }}</div>
      <div v-if="updateState.info?.error" class="update-error">
        <p>{{ updateState.info.error }}</p>
        <p v-if="updateState.info.hint" class="update-hint">{{ updateState.info.hint }}</p>
        <a
          class="update-link"
          :href="updateState.info.releases_url || 'https://github.com/moliyu1101/Riddle'"
          target="_blank"
          rel="noopener"
        >打开 GitHub 仓库 / Releases</a>
      </div>
      <div v-if="updateState.info?.update_available" class="update-info">
        <div class="update-version">
          <span class="version-old">{{ updateState.info.current_commit }}</span>
          <span class="version-arrow">→</span>
          <span class="version-new">{{ updateState.info.latest_commit }}</span>
          <span class="update-badge">落后 {{ updateState.info.commits_behind }} 个提交</span>
        </div>
        <div class="update-latest-msg">{{ updateState.info.latest_message }}</div>
        <details class="update-files">
          <summary>变更文件 ({{ updateState.info.changed_files?.length || 0 }})</summary>
          <ul>
            <li v-for="f in updateState.info.changed_files" :key="f">{{ f }}</li>
          </ul>
        </details>
        <div v-if="updateState.info.hot_updateable" class="update-actions">
          <button type="button" class="primary" @click="runUpdate" :disabled="updateState.updating">
            {{ updateState.updating ? "更新中…" : "一键更新并重启" }}
          </button>
          <span class="update-hint">仅后端代码变更，可热更新（git pull + 自动重启）</span>
        </div>
        <div v-else class="update-actions rebuild">
          <p class="update-warn">⚠ 本次更新包含前端/Dockerfile 变更，需在服务器执行完整重建：</p>
          <code class="rebuild-cmd">{{ updateState.info.rebuild_command || 'git pull && docker compose up -d --build' }}</code>
        </div>
      </div>
      <div v-else-if="updateState.info && !updateState.info.update_available && !updateState.info.error" class="update-uptodate">
        ✓ 已是最新版本（{{ updateState.info.current_commit }}）
      </div>
    </div>
  </div>
</template>
