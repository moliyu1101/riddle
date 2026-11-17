<script setup>
import { ref, computed, onMounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import { applyAccessToken, authRequiredRef, authRoleRef, loadAuthRole } from "../api.js";

defineOptions({ name: "LoginView" });

const route = useRoute();
const router = useRouter();

const token = ref("");
const showToken = ref(false);
const loading = ref(false);
const errorMsg = ref("");
const checking = ref(true);

const redirectTarget = computed(() => {
  const r = typeof route.query.redirect === "string" ? route.query.redirect : "";
  return r && r.startsWith("/") ? r : "/";
});

const noAuth = computed(() => authRequiredRef.value === false);

const PILLARS = [
  { tag: "COLLAB", title: "多目标黑板协同 & 会话继承", desc: "并发 Worker 实时共享凭据与侦察覆盖，Escalate 继承认证 Cookie、笔记与认知卡无缝深化。" },
  { tag: "EVOLVE", title: "情报效用评分 & 实战蒸馏", desc: "按注入转化率动态优胜劣汰；人工复审高危自动脱敏蒸馏入库，驳回即入避坑指南。" },
  { tag: "FUSION", title: "融合治理闸门 & 三层命令裁决", desc: "deny / judge / ask 命令拦截审批、证据机械校验闸门与授权域写回守卫。" },
  { tag: "REPORT", title: "双图血缘溯源 & 公文复测闭环", desc: "资产×探索双图映射、全流量 JSONL 留痕绑定，一键生成带复测记录的公文报告。" },
];

onMounted(async () => {
  await loadAuthRole();
  checking.value = false;
  if (authRequiredRef.value && authRoleRef.value !== "none") {
    router.replace(redirectTarget.value);
  }
});

function toggleShow() {
  showToken.value = !showToken.value;
}

async function submit() {
  const raw = token.value.trim();
  if (!raw) {
    errorMsg.value = "请输入访问令牌";
    return;
  }
  loading.value = true;
  errorMsg.value = "";
  const result = await applyAccessToken(raw);
  loading.value = false;
  if (result.ok) {
    router.replace(redirectTarget.value);
  } else if (result.error === "invalid") {
    errorMsg.value = "令牌无效，请检查后重试";
  } else {
    errorMsg.value = "无法连接服务，请稍后重试";
  }
}

function enterDirectly() {
  router.replace(redirectTarget.value);
}
</script>

<template>
  <div class="login-page">
    <div class="login-shell">
      <!-- 左侧：平台架构纵览 -->
      <aside class="login-brief">
        <div class="brief-head">
          <div class="login-logo">
            <img src="/logo.png" alt="知蠹 Riddle" width="44" height="44" />
          </div>
          <div>
            <b>知蠹 RIDDLE</b>
            <small>PRISM TACTICAL WORKBENCH · 24×7</small>
          </div>
        </div>
        <h1 class="brief-title">自主挖掘 · 知识自进化<br />全闭环安全作战工作台</h1>
        <p class="brief-sub">从资产测绘、多 Worker 协同深挖到人工复审反哺、实战脱敏蒸馏与硬骨头回捞重测的统一控制中枢。</p>

        <div class="brief-pillars">
          <article v-for="p in PILLARS" :key="p.tag" class="pillar-item">
            <span class="pillar-tag">{{ p.tag }}</span>
            <div>
              <strong>{{ p.title }}</strong>
              <p>{{ p.desc }}</p>
            </div>
          </article>
        </div>

        <footer class="brief-foot">
          <span>Powered By <b>moliyu1101</b></span>
          <span class="dot">·</span>
          <span>CC BY-NC 4.0</span>
        </footer>
      </aside>

      <!-- 右侧：令牌认证控制台 -->
      <section class="login-card">
        <div class="login-title">
          <span class="login-kicker">ACCESS GATE</span>
          <h2>控制台身份认证</h2>
          <p>{{ noAuth ? "当前环境未配置访问令牌鉴权" : "输入全权限 / 只读 / 观摩令牌进入作战工作台" }}</p>
        </div>

        <div v-if="noAuth" class="login-noauth">
          <div class="login-noauth-ico">✓</div>
          <p>服务端处于免鉴权模式，可直接进入全部作战视图。</p>
          <button class="btn primary login-submit" type="button" :disabled="loading" @click="enterDirectly">
            进入作战工作台 →
          </button>
        </div>

        <form v-else class="login-form" @submit.prevent="submit">
          <label class="login-field">
            <span class="login-field-label">访问令牌（RIDDLE_API_TOKEN）</span>
            <div class="login-input-wrap">
              <input
                v-model="token"
                :type="showToken ? 'text' : 'password'"
                class="login-input"
                autocomplete="off"
                spellcheck="false"
                placeholder="粘贴 full / readonly / observer 令牌"
                :disabled="loading"
                @input="errorMsg = ''"
              />
              <button
                type="button"
                class="login-eye"
                :title="showToken ? '隐藏令牌' : '显示令牌'"
                :aria-label="showToken ? '隐藏令牌' : '显示令牌'"
                @click="toggleShow"
              >
                <svg v-if="showToken" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94"/>
                  <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19"/>
                  <path d="M14.12 14.12a3 3 0 1 1-4.24-4.24"/>
                  <line x1="1" y1="1" x2="23" y2="23"/>
                </svg>
                <svg v-else viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
                  <circle cx="12" cy="12" r="3"/>
                </svg>
              </button>
            </div>
          </label>

          <p v-if="errorMsg" class="login-error" role="alert">{{ errorMsg }}</p>

          <button class="btn primary login-submit" type="submit" :disabled="loading || !token.trim()">
            <span v-if="loading" class="login-spinner" aria-hidden="true"></span>
            <span>{{ loading ? "验证中…" : "进入控制台" }}</span>
          </button>

          <p class="login-hint">令牌仅加密存于本机浏览器会话，不上传第三方</p>
        </form>
      </section>
    </div>
  </div>
</template>
