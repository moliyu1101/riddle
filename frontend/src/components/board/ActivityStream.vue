<script setup>
import { isLlmErrorEvent } from "../../clipboard.js";
import {
  AGENT_LABEL, DETAIL_KINDS,
  evClass, evTime, eventExpandKey, canExpandEvent, kindLabel, useEventFormat,
} from "../../composables/useEventFormat.js";

defineOptions({ name: "ActivityStream" });
// full 模式：展开细节显示完整内容（主列表紧凑截断，这里不截断）
const { fmtEvent } = useEventFormat({ value: {} });
const props = defineProps({
  events: { type: Array, default: () => [] },
  boardReady: { type: Boolean, default: false },
  live: { type: Boolean, default: false },
  expandedEventKeys: { type: Object, default: () => new Set() },
  streamDetailLoading: { type: Object, default: () => ({}) },
  liveTraceByTarget: { type: Object, default: () => ({}) },
  liveTargetIds: { type: Object, default: () => new Set() },
  logRef: { type: Object, default: null },
  detailCap: { type: Number, default: 40 },
});
const emit = defineEmits(["toggleExpand", "copyLlm"]);

function isEventExpanded(key) {
  return props.expandedEventKeys.has(key);
}
function detailsForTarget(targetId) {
  const list = props.liveTraceByTarget[targetId] || [];
  const details = list.filter((e) => DETAIL_KINDS.has(e.kind || ""));
  const ordered = [...details].reverse();
  return ordered.slice(0, props.detailCap);
}
function targetIsLive(tid) {
  return !!tid && props.liveTargetIds.has(tid);
}
</script>

<template>
  <div class="board-col board-panel">
    <div class="col-head">
      <span>事件流</span>
      <small>点击带目标的行展开细节</small>
      <i v-if="live" class="stream-live" title="实时推送中"></i>
      <i class="cnt">{{ events.length }}</i>
    </div>
    <div :ref="logRef" class="event-log">
      <div v-if="!boardReady && !events.length" class="board-hydrate" aria-hidden="true">
        <div v-for="n in 6" :key="n" class="skeleton-line"></div>
      </div>
      <div v-else-if="!events.length" class="empty sm">等待事件…</div>
      <template v-for="(ev, i) in events" :key="eventExpandKey(ev, i)">
        <div
          :class="[evClass(ev), { expandable: canExpandEvent(ev), open: isEventExpanded(eventExpandKey(ev, i)) }]"
          :style="{ '--i': Math.min(i, 8) }"
          @click="emit('toggleExpand', ev, i)"
        >
          <span class="ev-time">{{ evTime(ev._displayTs || ev.ts) }}</span>
          <span class="ev-agent" :class="`ag-${ev.agent}`">{{ AGENT_LABEL[ev.agent] || ev.agent }}</span>
          <span class="ev-msg" :title="fmtEvent(ev, true) || ev._text">{{ ev._text }}</span>
          <button
            v-if="isLlmErrorEvent(ev)"
            type="button"
            class="ev-copy"
            title="复制 LLM 真实错误"
            @click.stop="emit('copyLlm', ev)"
          >复制</button>
          <span v-if="canExpandEvent(ev)" class="ev-toggle" aria-hidden="true">
            {{ isEventExpanded(eventExpandKey(ev, i)) ? "−" : "+" }}
          </span>
          <span v-else class="ev-toggle spacer" aria-hidden="true"></span>
        </div>
        <div
          v-if="canExpandEvent(ev) && isEventExpanded(eventExpandKey(ev, i))"
          class="ev-details"
        >
          <div v-if="streamDetailLoading[ev.target_id]" class="ev-detail-row muted">加载细节…</div>
          <div v-else-if="!detailsForTarget(ev.target_id).length" class="ev-detail-row muted">
            {{ targetIsLive(ev.target_id) ? "暂无工具/思考细节（worker 运行中，稍等产出）" : "该 worker 已结束，工具/思考明细已归档清理（仅保留关键节点）" }}
          </div>
          <div
            v-for="(d, di) in detailsForTarget(ev.target_id)"
            :key="di"
            class="ev-detail-row"
          >
            <span class="ev-detail-round" v-if="d.round">R{{ d.round }}</span>
            <span class="ev-detail-kind">{{ kindLabel(d.kind) }}</span>
            <span class="ev-detail-msg">{{ fmtEvent(d, true) || d._text || d.message || d.kind }}</span>
            <button
              v-if="isLlmErrorEvent(d)"
              type="button"
              class="ev-copy"
              title="复制 LLM 真实错误"
              @click.stop="emit('copyLlm', d)"
            >复制</button>
            <span class="ev-detail-time">{{ evTime(d._displayTs || d.ts) }}</span>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>
