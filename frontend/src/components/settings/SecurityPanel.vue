<script setup>
import { reactive, ref, watch } from "vue";

const props = defineProps({
  form: { type: Object, required: true },
  /** 保存完成信号：时间戳变化即提示「已保存并生效」 */
  saveFlash: { type: Number, default: 0 },
});

/** 每个令牌的展示状态：是否明文显示 */
const show = reactive({ full: false, read: false, observer: false });

/** 保存成功的内联反馈 */
const savedFlash = ref(false);
let savedTimer = null;
watch(
  () => props.saveFlash,
  (v) => {
    if (!v) return;
    savedFlash.value = true;
    clearTimeout(savedTimer);
    savedTimer = setTimeout(() => (savedFlash.value = false), 3200);
  }
);

/** 令牌字段定义：值键 / 已设置标志键 / 环境变量标志键 / 角色名 / 说明 */
const TOKEN_ROWS = [
  {
    key: "full",
    valKey: "full_token",
    setKey: "full_token_set",
    envKey: "env_full",
    role: "全权限",
    desc: "读写全部数据，可启停任务、复审、提交、管理配置。登录页默认用它。",
  },
  {
    key: "read",
    valKey: "read_token",
    setKey: "read_token_set",
    envKey: "env_read",
    role: "只读",
    desc: "只能查看看板、漏洞与报告，禁止一切写操作与敏感信息。",
  },
  {
    key: "observer",
    valKey: "observer_token",
    setKey: "observer_token_set",
    envKey: "env_observer",
    role: "观摩",
    desc: "仅安全概览，隐藏目标、漏洞与报告等敏感内容。",
  },
];

function statusOf(row) {
  if (props.form[row.setKey]) return { text: "已设置", cls: "on" };
  if (props.form[row.envKey]) return { text: "环境变量", cls: "env" };
  return { text: "未设置", cls: "" };
}

function clearToken(row) {
  props.form[row.valKey] = "";
  props.form[row.setKey] = false;
}
</script>

<template>
  <div class="security-settings">
    <div class="settings-subhead">
      <b>访问令牌</b>
      <span>三种权限令牌控制谁能访问本实例。留空不修改；输入新值覆盖；点「清除」删除。未设置时回退到环境变量。</span>
    </div>

    <transition name="security-flash">
      <p v-if="savedFlash" class="security-saved" role="status">
        <svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path d="M3 8.5 6.2 11.5 13 4.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        访问令牌已保存并生效
      </p>
    </transition>

    <div class="security-token-list">
      <div v-for="row in TOKEN_ROWS" :key="row.key" class="security-token-row">
        <div class="security-token-head">
          <div class="security-token-title">
            <b>{{ row.role }}</b>
            <i :class="statusOf(row).cls">{{ statusOf(row).text }}</i>
          </div>
          <p class="security-token-desc">{{ row.desc }}</p>
        </div>
        <div class="security-token-input">
          <input
            v-model="form[row.valKey]"
            :type="show[row.key] ? 'text' : 'password'"
            :placeholder="form[row.setKey] ? '已配置，留空不修改' : '输入新令牌…'"
            autocomplete="new-password"
            spellcheck="false"
          />
          <button
            type="button"
            class="security-eye"
            :title="show[row.key] ? '隐藏' : '显示'"
            :aria-label="show[row.key] ? '隐藏令牌' : '显示令牌'"
            @click="show[row.key] = !show[row.key]"
          >
            <svg v-if="!show[row.key]" viewBox="0 0 16 16" width="15" height="15" aria-hidden="true">
              <path d="M1.8 8s2.4-4 6.2-4 6.2 4 6.2 4-2.4 4-6.2 4S1.8 8 1.8 8Z" fill="none" stroke="currentColor" stroke-width="1.4"/>
              <circle cx="8" cy="8" r="1.8" fill="none" stroke="currentColor" stroke-width="1.4"/>
            </svg>
            <svg v-else viewBox="0 0 16 16" width="15" height="15" aria-hidden="true">
              <path d="M2 2.5 14 13.5M5.4 4.9A6.6 6.6 0 0 1 8 4.6c3.8 0 6.2 3.4 6.2 3.4a9.6 9.6 0 0 1-2 2.3M4.4 6.1A8.6 8.6 0 0 0 1.8 8s2.4 4 6.2 4a6.2 6.2 0 0 0 2.4-.5" fill="none" stroke="currentColor" stroke-width="1.4" stroke-linecap="round"/>
            </svg>
          </button>
          <button
            v-if="form[row.setKey] || form[row.valKey]"
            type="button"
            class="security-clear"
            title="清除该令牌"
            @click="clearToken(row)"
          >
            清除
          </button>
        </div>
      </div>
    </div>

    <p class="field-hint full security-note">
      令牌通过请求头 <code>X-Riddle-Token</code> 或 <code>Authorization: Bearer &lt;token&gt;</code> 传入。
      环境变量兜底：<code>RIDDLE_API_TOKEN</code>（全权限）、<code>RIDDLE_READ_TOKEN</code>（只读）、
      <code>RIDDLE_OBSERVER_TOKEN</code>（观摩）。DB 中设置的令牌优先于环境变量。
    </p>
  </div>
</template>
