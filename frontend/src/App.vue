<script setup>
import { ref, computed, onMounted, onUnmounted } from "vue";
import { useRoute, useRouter } from "vue-router";
import {
  api,
  authRoleRef,
  loadAuthRole,
} from "./api.js";
import { applyUi, loadUiPrefs, markUiMigrated, prefsFromApi, prefsToApi, saveUiPrefs, uiNeedsMigrate } from "./uiTheme.js";
import { openCreateTask } from "./composables/useCreateTask.js";
import { useToast } from "./composables/useToast.js";
import CreateTaskModal from "./components/CreateTaskModal.vue";

const route = useRoute();
const router = useRouter();
const { toastState, dismissToast } = useToast();
const KEEP_ALIVE_VIEWS = [
  "TasksView",
  "VulnsView",
  "IntelView",
  "RuntimeLogsView",
];

const theme = ref("dark");
const sidebarCollapsed = ref(localStorage.getItem("riddle-sidebar") === "1");
const mobileNavOpen = ref(false);
const pulse = ref({
  runningTasks: 0,
  pendingReview: 0,
  distilledKb: 0,
  hardTotal: 0,
  pendingIntercepts: 0,
  runtimeErrors: 0,
});
let pulseTimer = null;

function toggleSidebar() {
  sidebarCollapsed.value = !sidebarCollapsed.value;
  localStorage.setItem("riddle-sidebar", sidebarCollapsed.value ? "1" : "0");
}

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

async function refreshGlobalPulse() {
  if (route.path === "/login" || authRoleRef.value === "none") return;
  try {
    const taskReq = api.listTasks().catch(() => []);
    const isPriv = authRoleRef.value !== "observer";
    const [tasksRes, kbRes, hardRes, icRes, logRes] = await Promise.all([
      taskReq,
      isPriv ? api.knowledgeList("all", "").catch(() => []) : Promise.resolve([]),
      isPriv ? api.hardTargetsStats().catch(() => null) : Promise.resolve(null),
      isPriv ? api.fusionInterceptList({ status: "pending" }).catch(() => null) : Promise.resolve(null),
      isPriv ? api.runtimeLogStats().catch(() => null) : Promise.resolve(null),
    ]);
    const tasksList = Array.isArray(tasksRes) ? tasksRes : [];
    const kbList = Array.isArray(kbRes) ? kbRes : [];
    pulse.value = {
      runningTasks: tasksList.filter((t) => t.status === "running").length,
      pendingReview: tasksList.reduce((s, t) => s + (t.pending_user_review || 0), 0),
      distilledKb: kbList.filter((k) => k?.origin === "distilled").length,
      hardTotal: Number(hardRes?.total || 0),
      pendingIntercepts: Array.isArray(icRes?.items) ? icRes.items.length : 0,
      runtimeErrors: Number(logRes?.errors || 0),
    };
  } catch { /* ignore pulse errors */ }
}

function onAuthExpired() {
  if (route.path === "/login") return;
  router.replace({ path: "/login", query: { redirect: route.fullPath } });
}

const navSections = computed(() => {
  const p = pulse.value;
  const role = authRoleRef.value || "full";
  const allowPriv = role === "full" || role === "readonly";
  const sections = [
    {
      id: "ops",
      title: "作战调度",
      items: [
        {
          id: "tasks",
          label: "作战指挥台",
          to: "/",
          exact: true,
          badge: p.runningTasks,
          badgeKind: p.runningTasks > 0 ? "live" : "",
          icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/></svg>`,
        },
      ],
    },
    ...(allowPriv ? [{
      id: "evo",
      title: "知识与自进化",
      items: [
        {
          id: "intel",
          label: "知识与进化中心",
          to: "/intel",
          badge: p.distilledKb || p.hardTotal,
          badgeKind: p.distilledKb > 0 ? "accent" : p.hardTotal > 0 ? "warn" : "",
          icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a7 7 0 0 0-4 12.7V17a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1v-2.3A7 7 0 0 0 12 2z"/><path d="M9 21h6"/></svg>`,
        },
        {
          id: "vulns",
          label: "过审漏洞档案",
          to: "/vulns",
          badge: 0,
          badgeKind: "",
          icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>`,
        },
      ],
    },
    {
      id: "gov",
      title: "融合治理与系统",
      items: [
        {
          id: "fusion",
          label: "融合治理中枢",
          to: "/fusion",
          badge: p.pendingIntercepts,
          badgeKind: p.pendingIntercepts > 0 ? "warn" : "",
          icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><circle cx="18" cy="18" r="3"/><path d="M8.5 8.5 15.5 15.5M18 6v4M6 18v-4"/></svg>`,
        },
        {
          id: "runtime-logs",
          label: "运行异常监控",
          to: "/runtime-logs",
          badge: p.runtimeErrors,
          badgeKind: p.runtimeErrors > 0 ? "danger" : "",
          icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`,
        },
        {
          id: "settings",
          label: "引擎与系统设置",
          to: "/settings",
          badge: 0,
          badgeKind: "",
          icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
        },
      ],
    }] : []),
  ];
  return sections;
});

function isActiveNav(item) {
  if (item.exact) return route.path === item.to;
  return route.path.startsWith(item.to);
}

const currentAreaLabel = computed(() => {
  if (route.path === "/") return "全局作战指挥台";
  if (route.path.startsWith("/task/")) return "单任务协同作战看板";
  if (route.path.startsWith("/intel")) return "自主知识与进化中心";
  if (route.path.startsWith("/vulns")) return "过审漏洞档案库";
  if (route.path.startsWith("/fusion")) return "融合治理中枢";
  if (route.path.startsWith("/runtime-logs")) return "全局运行异常监控";
  if (route.path.startsWith("/settings")) return "系统设置与引擎池";
  return "工作台";
});

const roleLabel = computed(() => {
  const map = { full: "全权限操作员", readonly: "只读审计员", observer: "观摩访客", none: "未认证" };
  return map[authRoleRef.value] || authRoleRef.value;
});

const isLogin = computed(() => route.path === "/login");

onMounted(async () => {
  const prefs = await applyUi(loadUiPrefs());
  theme.value = prefs.theme;
  window.addEventListener("riddle-auth-expired", onAuthExpired);
  window.addEventListener("riddle-ui-changed", onUiChanged);
  await loadAuthRole();
  await hydrateUiFromServer();
  await refreshGlobalPulse();
  pulseTimer = setInterval(refreshGlobalPulse, 15000);
});
onUnmounted(() => {
  window.removeEventListener("riddle-auth-expired", onAuthExpired);
  window.removeEventListener("riddle-ui-changed", onUiChanged);
  clearInterval(pulseTimer);
});
</script>

<template>
  <div id="ah-wallpaper" class="ah-wallpaper" aria-hidden="true"></div>

  <div class="tac-workbench" :class="{ 'login-mode': isLogin, 'sidebar-collapsed': sidebarCollapsed }">
    <template v-if="!isLogin">
      <!-- 移动端遮罩 -->
      <div v-if="mobileNavOpen" class="tac-drawer-mask" @click="mobileNavOpen = false"></div>

      <!-- 左侧可折叠战术导航轨 -->
      <aside class="tac-sidebar" :class="{ collapsed: sidebarCollapsed, open: mobileNavOpen }" aria-label="主导航">
        <div class="tac-brand">
          <div class="brand-logo">
            <img src="/logo.png" alt="知蠹 Riddle" width="28" height="28" />
          </div>
          <div v-show="!sidebarCollapsed" class="brand-text">
            <b>知蠹 RIDDLE</b>
            <small>SOLARIS STUDIO</small>
          </div>
          <button
            type="button"
            class="tac-collapse-btn"
            :title="sidebarCollapsed ? '展开导航' : '折叠导航'"
            @click="toggleSidebar"
          >
            {{ sidebarCollapsed ? "»" : "«" }}
          </button>
        </div>

        <div class="tac-nav-scroll">
          <div v-for="sec in navSections" :key="sec.id" class="tac-nav-sec">
            <div v-show="!sidebarCollapsed" class="tac-nav-title">{{ sec.title }}</div>
            <router-link
              v-for="item in sec.items"
              :key="item.id"
              :to="item.to"
              class="tac-nav-item"
              :class="{ active: isActiveNav(item) }"
              :title="item.label"
              @click="mobileNavOpen = false"
            >
              <span class="nav-icon" v-html="item.icon"></span>
              <span v-show="!sidebarCollapsed" class="nav-label">{{ item.label }}</span>
              <span v-if="item.badge > 0 && !sidebarCollapsed" class="nav-badge" :class="item.badgeKind">
                {{ item.badge }}
              </span>
            </router-link>
          </div>

          <button
            v-if="authRoleRef === 'full'"
            type="button"
            class="tac-create-btn"
            :title="sidebarCollapsed ? '新建任务' : ''"
            @click="openCreateTask(); mobileNavOpen = false"
          >
            <span>＋</span>
            <span v-show="!sidebarCollapsed">新建作战任务</span>
          </button>
        </div>

        <!-- 侧栏底部闭环脉搏 -->
        <div class="tac-sidebar-foot">
          <div v-if="!sidebarCollapsed && authRoleRef !== 'observer'" class="tac-pulse-card">
            <div class="tpc-head">
              <span>闭环自进化脉搏</span>
              <i>LIVE</i>
            </div>
            <div class="tpc-grid">
              <div><b>{{ pulse.runningTasks }}</b><small>在侦</small></div>
              <div><b>{{ pulse.pendingReview }}</b><small>待审</small></div>
              <div><b>{{ pulse.distilledKb }}</b><small>蒸馏KB</small></div>
              <div><b>{{ pulse.hardTotal }}</b><small>硬骨头</small></div>
            </div>
          </div>
          <div class="tac-role-row" :title="roleLabel">
            <span class="status-dot" :class="authRoleRef"></span>
            <span v-show="!sidebarCollapsed" class="role-text">{{ roleLabel }}</span>
          </div>
        </div>
      </aside>

      <!-- 右侧主工作台区 -->
      <div class="tac-workspace">
        <!-- 顶部态势状态栏 -->
        <header class="tac-topbar">
          <div class="tac-topbar-left">
            <button type="button" class="tac-menu-btn" aria-label="打开菜单" @click="mobileNavOpen = !mobileNavOpen">☰</button>
            <div class="tac-area">
              <span class="tac-area-dot" :class="{ live: pulse.runningTasks > 0 }"></span>
              <b>{{ currentAreaLabel }}</b>
            </div>
          </div>

          <!-- 顶部等宽遥测脉冲带 -->
          <nav v-if="authRoleRef !== 'observer'" class="tac-loop-rail" aria-label="系统遥测与闭环直达">
            <span class="tel-sys"><i>●</i>SYS:ONLINE</span>
            <span class="loop-sep">|</span>
            <router-link to="/" class="loop-step">
              <span>RUN</span><b>{{ pulse.runningTasks }}</b>
            </router-link>
            <router-link to="/" class="loop-step warn">
              <span>REV</span><b>{{ pulse.pendingReview }}</b>
            </router-link>
            <router-link :to="{ path: '/intel', query: { tab: 'kb', origin: 'distilled' } }" class="loop-step accent">
              <span>KB_DISTILL</span><b>{{ pulse.distilledKb }}</b>
            </router-link>
            <router-link :to="{ path: '/intel', query: { tab: 'hard' } }" class="loop-step info">
              <span>HARD_POOL</span><b>{{ pulse.hardTotal }}</b>
            </router-link>
            <router-link v-if="pulse.pendingIntercepts > 0" :to="{ path: '/fusion', query: { tab: 'gates' } }" class="loop-step warn">
              <span>INTERCEPT</span><b>{{ pulse.pendingIntercepts }}</b>
            </router-link>
          </nav>

          <div class="tac-topbar-right">
            <button
              class="cmd-icon-btn"
              @click="toggleTheme"
              :title="theme === 'dark' ? '切换到亮色' : '切换到暗色'"
              :aria-label="theme === 'dark' ? '切换到亮色主题' : '切换到暗色主题'"
            >
              <svg v-if="theme === 'dark'" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <circle cx="12" cy="12" r="4"/>
                <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/>
              </svg>
              <svg v-else viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
                <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
              </svg>
            </button>
            <a class="cmd-icon-btn" href="https://github.com/moliyu1101/Riddle" target="_blank" rel="noopener noreferrer" title="GitHub" aria-label="在 GitHub 上查看项目">
              <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true">
                <path fill="currentColor" fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/>
              </svg>
            </a>
          </div>
        </header>

        <main class="tac-main">
          <router-view v-slot="{ Component }">
            <transition name="route" mode="out-in">
              <keep-alive :include="KEEP_ALIVE_VIEWS" :max="6">
                <component :is="Component" :key="route.path" />
              </keep-alive>
            </transition>
          </router-view>
        </main>

        <footer class="app-footer" aria-label="署名">
          <span>Powered By <b>moliyu1101</b></span>
          <span class="dot">·</span>
          <span>CC BY-NC 4.0</span>
          <span class="dot">·</span>
          <span>Solaris &amp; Obsidian Studio</span>
        </footer>
      </div>
    </template>

    <!-- 登录页：全屏独立 -->
    <template v-else>
      <router-view v-slot="{ Component }">
        <component :is="Component" :key="route.path" />
      </router-view>
    </template>
  </div>

  <div v-if="toastState" class="toast app-toast" :class="toastState.type" role="status" @click="dismissToast">
    {{ toastState.message }}
  </div>

  <CreateTaskModal />
</template>
