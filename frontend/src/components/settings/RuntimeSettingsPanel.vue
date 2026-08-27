<script setup>
defineProps({
  form: { type: Object, required: true },
});
</script>

<template>
  <div class="runtime-settings">
    <div class="settings-subhead">
      <b>任务默认值</b>
      <span>新任务创建时的保守默认值，可在任务内覆盖</span>
    </div>
    <div class="settings-grid">
      <label>新建任务默认并发 <input v-model="form.concurrency" type="number" min="1" max="32" /></label>
      <label>新建任务默认深挖次数 <input v-model="form.deepen_cap" type="number" min="0" max="10" /></label>
      <p class="field-hint full">同一目标被打回深挖的最大次数（人工 + AI 审核 + 自动 deepen_lead 合计）。默认 2，范围 0–10；0 表示关闭回炉。</p>
      <label>低分跳过阈值
        <input v-model="form.skip_score_threshold" type="number" step="1" />
      </label>
      <p class="field-hint full">Collector 评分低于此值的目标直接跳过，避免 worker 消耗在垃圾资产上。</p>
    </div>
  </div>
</template>
