<script setup>
import { computed } from "vue";
import { useRouter } from "vue-router";

defineOptions({ name: "TaskSituationMap" });
const props = defineProps({
  tasks: { type: Array, default: () => [] },
});
const router = useRouter();

const STATUS_LABEL = {
  running: "运行中",
  idle: "空闲",
  paused: "已暂停",
  stopped: "已停止",
  created: "未启动",
};

const MAX_NODES = 6;
const visibleTasks = computed(() => props.tasks.slice(0, MAX_NODES));
const extraCount = computed(() => Math.max(0, props.tasks.length - MAX_NODES));
const runningCount = computed(() => props.tasks.filter((t) => t.status === "running").length);
const reviewCount = computed(() => props.tasks.reduce((s, t) => s + (t.pending_user_review || 0), 0));
const vulnCount = computed(() => props.tasks.reduce((s, t) => s + (t.total_vulns || 0), 0));

// 环形布局：枢纽居中，任务节点沿椭圆轨道均匀环绕（百分比坐标，SVG 同步）
const positioned = computed(() => {
  const n = visibleTasks.value.length;
  if (!n) return [];
  const RX = 38, RY = 34;
  return visibleTasks.value.map((t, i) => {
    const angle = (-90 + i * (360 / n)) * (Math.PI / 180);
    const x = 50 + RX * Math.cos(angle);
    const y = 50 + RY * Math.sin(angle);
    return { task: t, x, y };
  });
});

function nodeProgress(t) {
  return Math.max(0, Math.min(t.progress || 0, 100));
}

function go(id) {
  router.push(`/task/${id}`);
}
</script>

<template>
  <div class="situation-map" :class="{ empty: !tasks.length }">
    <div class="situation-head">
      <div class="situation-title">
        <span class="sit-live-dot" :class="{ on: runningCount > 0 }"></span>
        <b>任务态势图</b>
        <span class="sit-sub">实时任务拓扑 · {{ runningCount }} 在侦</span>
      </div>
      <div class="situation-legend">
        <span class="legend-item"><i class="lg running"></i>运行中</span>
        <span class="legend-item"><i class="lg idle"></i>空闲</span>
        <span class="legend-item"><i class="lg stopped"></i>已停止</span>
      </div>
    </div>

    <div class="situation-canvas">
      <!-- 网格背景 -->
      <div class="sit-grid" aria-hidden="true"></div>
      <!-- 雷达扫描 -->
      <div class="sit-radar" aria-hidden="true"></div>

      <!-- 连接线：non-scaling-stroke 防止画布非正方形拉伸导致虚线变形 -->
      <svg class="sit-links" viewBox="0 0 100 100" preserveAspectRatio="none" aria-hidden="true">
        <line
          v-for="p in positioned"
          :key="p.task.id"
          x1="50" y1="50" :x2="p.x" :y2="p.y"
          :class="{ hot: p.task.status === 'running' }"
          vector-effect="non-scaling-stroke"
        />
      </svg>

      <!-- 中心枢纽：圆心精确锚定画布中心，连线从圆心辐射 -->
      <div class="sit-hub">
        <div class="hub-core">
          <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="2" x2="12" y2="22"/>
            <line x1="2" y1="12" x2="22" y2="12"/>
          </svg>
        </div>
        <div class="hub-text">
          <div class="hub-label">指挥中心</div>
          <div class="hub-meta">{{ tasks.length }} 任务 · {{ vulnCount }} 漏洞</div>
        </div>
      </div>

      <!-- 任务节点 -->
      <div
        v-for="p in positioned"
        :key="p.task.id"
        class="sit-node"
        :class="[p.task.status, { working: p.task.status === 'running' && !nodeProgress(p.task) }]"
        :style="{ left: p.x + '%', top: p.y + '%', '--p': nodeProgress(p.task) }"
        @click="go(p.task.id)"
      >
        <span class="node-orb"></span>
        <span class="node-name">{{ p.task.name }}</span>
        <span class="node-status">{{ STATUS_LABEL[p.task.status] || p.task.status }}</span>
        <span class="node-vuln">{{ p.task.total_vulns || 0 }} 漏洞</span>
        <span v-if="p.task.pending_user_review" class="node-review">{{ p.task.pending_user_review }}</span>
      </div>

      <!-- 超出折叠 -->
      <div v-if="extraCount" class="sit-extra" aria-hidden="true">+{{ extraCount }}</div>
    </div>
  </div>
</template>
