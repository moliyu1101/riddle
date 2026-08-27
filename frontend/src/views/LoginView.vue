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

const roleLabel = computed(() => {
  const map = { full: "全权限", readonly: "只读", observer: "观摩" };
  return map[authRoleRef.value] || "";
});

onMounted(async () => {
  await loadAuthRole();
  checking.value = false;
  // 已持有有效令牌：直接放行
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
    <div class="login-grid" aria-hidden="true"></div>
    <div class="login-scanline" aria-hidden="true"></div>

    <div class="login-card">
      <div class="login-brand">
        <div class="login-logo">
          <img src="/logo.png" alt="知蠹 Riddle" width="52" height="52" style="object-fit:contain;border-radius:12px;display:block;" />
        </div>
        <div class="login-brand-text">
          <b>知蠹 Riddle</b>
          <small>NEON OPS · 24×7</small>
        </div>
      </div>

      <div class="login-title">
        <h2>访问控制台</h2>
        <p>输入访问令牌以进入作战终端</p>
      </div>

      <!-- 未启用令牌：直接进入 -->
      <div v-if="noAuth" class="login-noauth">
        <div class="login-noauth-ico">◈</div>
        <p>当前未启用访问令牌鉴权<br/>可直接进入控制台</p>
        <button class="btn primary login-submit" type="button" :disabled="loading" @click="enterDirectly">
          进入控制台
        </button>
      </div>

      <!-- 令牌登录 -->
      <form v-else class="login-form" @submit.prevent="submit">
        <label class="login-field">
          <span class="login-field-label">访问令牌</span>
          <div class="login-input-wrap">
            <input
              v-model="token"
              :type="showToken ? 'text' : 'password'"
              class="login-input"
              autocomplete="off"
              spellcheck="false"
              placeholder="粘贴 RIDDLE_API_TOKEN / 只读 / 观摩令牌"
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
          <span>{{ loading ? "验证中…" : "登 录" }}</span>
        </button>

        <p class="login-hint">
          全权限 / 只读 / 观摩令牌均可登录<br/>
          令牌仅保存在本机浏览器
        </p>
      </form>

      <div class="login-foot">
        <span>Powered By <b>moliyu1101</b></span>
        <span class="dot">·</span>
        <span>CC BY-NC 4.0</span>
      </div>
    </div>
  </div>
</template>
