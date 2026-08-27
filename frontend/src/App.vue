<script setup>
import { ref, computed, onMounted, onUnmounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  api,
  authReadyRef,
  authRoleRef,
  loadAuthRole,
} from "./api.js";
import { applyUi, loadUiPrefs, markUiMigrated, prefsFromApi, prefsToApi, saveUiPrefs, uiNeedsMigrate } from "./uiTheme.js";
import { openCreateTask } from "./composables/useCreateTask.js";
import CreateTaskModal from "./components/CreateTaskModal.vue";

const route = useRoute();
const router = useRouter();
const KEEP_ALIVE_VIEWS = [
  "TasksView",
  "VulnsView",
  "IntelView",
  "RuntimeLogsView",
];

const theme = ref("dark");
const toastMsg = ref("");

async function applyTheme(t) {
  const prefs = saveUiPrefs({ ...loadUiPrefs(), theme: t });
  theme.value = prefs.theme;
  await applyUi(prefs);
  api.updateSettings({ ui: prefsToApi(prefs) }).catch(() => {});
}

async function hydrateUiFromServer() {
  try {
    const s = await api.getSettings();
    const remote = s.ui || {};
    if (!remote.saved && uiNeedsMigrate()) {
      const local = loadUiPrefs();
      await api.updateSettings({ ui: prefsToApi(local) });
      markUiMigrated();
      await applyUi(saveUiPrefs(local));
      theme.value = local.theme;
      return;
    }
    markUiMigrated();
    const prefs = saveUiPrefs(prefsFromApi(remote));
    await applyUi(prefs);
    theme.value = prefs.theme;
  } catch {
    const prefs = await applyUi(loadUiPrefs());
    theme.value = prefs.theme;
  }
}
function toggleTheme() { applyTheme(theme.value === "dark" ? "light" : "dark"); }

function onUiChanged(e) {
  if (e.detail?.theme) theme.value = e.detail.theme;
}

function toast(m, ms = 2600) {
  toastMsg.value = m;
  setTimeout(() => { if (toastMsg.value === m) toastMsg.value = ""; }, ms);
}

function onAuthExpired() {
  if (route.path === "/login") return;
  router.replace({ path: "/login", query: { redirect: route.fullPath } });
}

const navItems = computed(() => {
  const items = [
    {
      id: "tasks",
      label: "任务",
      to: "/",
      exact: true,
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="4" rx="1"/><rect x="3" y="11" width="18" height="4" rx="1"/><rect x="3" y="18" width="18" height="3" rx="1"/></svg>`,
    },
    {
      id: "vulns",
      label: "漏洞库",
      to: "/vulns",
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
      role: ["full", "readonly"],
    },
    {
      id: "intel",
      label: "作战情报",
      to: "/intel",
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>`,
      role: ["full", "readonly"],
    },
    {
      id: "runtime-logs",
      label: "运行异常",
      to: "/runtime-logs",
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
      role: ["full", "readonly"],
    },
  ];
  return items.filter((item) => {
    if (!item.role) return true;
    return item.role.includes(authRoleRef.value || "full");
  });
});

const bottomNavItems = computed(() => {
  const items = [];
  if (authRoleRef.value === "full") {
    items.push({
      id: "create",
      label: "新建任务",
      to: "/create",
      variant: "primary",
      icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg>`,
    });
  }
  items.push({
    id: "settings",
    label: "设置",
    to: "/settings",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  });
  return items;
});

function isActiveNav(item) {
  if (item.exact) return route.path === item.to;
  return route.path.startsWith(item.to);
}

function onBottomAction(item) {
  if (item.id === "settings") {
    router.push(item.to);
    return;
  }
  openCreateTask();
}

const roleLabel = computed(() => {
  const map = { full: "全权限", readonly: "只读", observer: "观摩", none: "未认证" };
  return map[authRoleRef.value] || authRoleRef.value;
});

const isLogin = computed(() => route.path === "/login");

onMounted(async () => {
  const prefs = await applyUi(loadUiPrefs());
  theme.value = prefs.theme;
  window.addEventListener("riddle-auth-expired", onAuthExpired);
  window.addEventListener("ah-ui-changed", onUiChanged);
  await loadAuthRole();
  await hydrateUiFromServer();
});
onUnmounted(() => {
  window.removeEventListener("riddle-auth-expired", onAuthExpired);
  window.removeEventListener("ah-ui-changed", onUiChanged);
});
</script>

<template>
  <div id="ah-wallpaper" class="ah-wallpaper" aria-hidden="true"></div>

  <div class="app-shell" :class="{ 'login-mode': isLogin }">
    <template v-if="!isLogin">
      <!-- 顶部霓虹扫描线 -->
      <div class="neon-scanline" aria-hidden="true"></div>

    <!-- 顶部指挥条 -->
    <header class="cmd-topbar" aria-label="主导航">
      <div class="cmd-brand">
        <div class="brand-logo">
          <img src="/logo.png" alt="知蠹 Riddle" width="24" height="24" style="object-fit:contain;border-radius:4px;" />
        </div>
        <div class="brand-text">
          <b>知蠹 Riddle</b>
          <small>NEON OPS · 24×7</small>
        </div>
      </div>

      <!-- 悬浮胶囊导航 -->
      <nav class="cmd-nav" aria-label="主导航">
        <router-link
          v-for="item in navItems"
          :key="item.id"
          :to="item.to"
          class="cmd-nav-item"
          :class="{ active: isActiveNav(item) }"
        >
          <span class="nav-icon" v-html="item.icon"></span>
          <span class="nav-label">{{ item.label }}</span>
        </router-link>
      </nav>

      <!-- 右侧操作区 -->
      <div class="cmd-actions">
        <span class="cmd-role" :class="authRoleRef" :title="roleLabel">
          <span class="status-dot" :class="authRoleRef"></span>
          <span class="role-text">{{ roleLabel }}</span>
        </span>
        <button
          v-for="item in bottomNavItems"
          :key="item.id"
          type="button"
          class="cmd-action"
          :class="[item.variant || '']"
          @click="onBottomAction(item)"
        >
          <span class="action-icon" v-html="item.icon"></span>
          <span class="action-label">{{ item.label }}</span>
        </button>
        <button class="cmd-icon-btn" @click="toggleTheme" :title="theme === 'dark' ? '切换到亮色' : '切换到暗色'" :aria-label="theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'">
          <svg v-if="theme === 'dark'" viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="4"/>
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
          </svg>
          <svg v-else viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
        </button>
        <a class="cmd-icon-btn" href="https://github.com/moliyu1101/Riddle" target="_blank" rel="noopener noreferrer" title="GitHub" aria-label="在 GitHub 上查看项目">
          <svg viewBox="0 0 16 16" width="17" height="17" aria-hidden="true" focusable="false">
            <path fill="currentColor" fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
          </svg>
        </a>
      </div>
    </header>

    <!-- 内容区 -->
    <main class="cmd-content">
      <router-view v-slot="{ Component }">
        <transition name="route" mode="out-in">
          <keep-alive :include="KEEP_ALIVE_VIEWS" :max="6">
            <component :is="Component" :key="route.path" />
          </keep-alive>
        </transition>
      </router-view>
    </main>

    <!-- 底部署名 -->
    <footer class="app-footer" aria-label="署名">
      <span>Powered By <b>moliyu1101</b></span>
      <span class="dot">·</span>
      <span>CC BY-NC 4.0</span>
    </footer>
    </template>

    <!-- 登录页：全屏独立，不显示主应用导航 -->
    <template v-else>
      <router-view v-slot="{ Component }">
        <component :is="Component" :key="route.path" />
      </router-view>
    </template>
  </div>

  <div v-if="toastMsg" class="toast app-toast">{{ toastMsg }}</div>

  <CreateTaskModal />
</template>
