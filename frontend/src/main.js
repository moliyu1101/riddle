import { createApp } from "vue";
import { createRouter, createWebHashHistory } from "vue-router";
import App from "./App.vue";
import { authReadyRef, authRoleRef, loadAuthRole } from "./api.js";
import "./styles/base.css";
import "./styles/layout.css";
import "./styles/settings.css";
import "./styles/board.css";
import "./styles/responsive.css";
import "./styles/intel.css";
import "./styles/create.css";
import "./styles/login.css";

// 按路由懒加载视图，避免首屏打包成单一巨型 chunk
const LoginView = () => import("./views/LoginView.vue");
const TasksView = () => import("./views/TasksView.vue");
const BoardView = () => import("./views/BoardView.vue");
const SettingsView = () => import("./views/SettingsView.vue");
const IntelView = () => import("./views/IntelView.vue");
const VulnsView = () => import("./views/VulnsView.vue");
const RuntimeLogsView = () => import("./views/RuntimeLogsView.vue");
const FusionView = () => import("./views/FusionView.vue");

const router = createRouter({
  history: createWebHashHistory(),
  routes: [
    { path: "/login", component: LoginView },
    { path: "/", component: TasksView },
    { path: "/create", redirect: "/" },
    { path: "/hard-targets", redirect: "/intel" },
    { path: "/intel", component: IntelView },
    { path: "/vulns", component: VulnsView },
    { path: "/runtime-logs", component: RuntimeLogsView },
    { path: "/fusion", component: FusionView },
    { path: "/settings", component: SettingsView },
    { path: "/task/:id", component: BoardView, props: true },
  ],
});

router.beforeEach(async (to) => {
  if (!authReadyRef.value) await loadAuthRole();
  const authed = authRoleRef.value !== "none";
  if (to.path === "/login") {
    return authed ? "/" : true;
  }
  if (!authed) {
    return { path: "/login", query: { redirect: to.fullPath } };
  }
  if (authRoleRef.value === "observer" && ["/settings", "/intel", "/vulns", "/runtime-logs", "/fusion"].includes(to.path)) {
    return "/";
  }
  return true;
});

createApp(App).use(router).mount("#app");
