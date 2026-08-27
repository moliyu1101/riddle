import { createApp } from "vue";
import { createRouter, createWebHashHistory } from "vue-router";
import App from "./App.vue";
import LoginView from "./views/LoginView.vue";
import TasksView from "./views/TasksView.vue";
import BoardView from "./views/BoardView.vue";
import SettingsView from "./views/SettingsView.vue";
import IntelView from "./views/IntelView.vue";
import VulnsView from "./views/VulnsView.vue";
import RuntimeLogsView from "./views/RuntimeLogsView.vue";
import { authReadyRef, authRoleRef, loadAuthRole } from "./api.js";
import "./styles/base.css";
import "./styles/layout.css";
import "./styles/settings.css";
import "./styles/board.css";
import "./styles/responsive.css";
import "./styles/intel.css";
import "./styles/create.css";
import "./styles/login.css";

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
  if (authRoleRef.value === "observer" && ["/settings", "/intel", "/vulns", "/runtime-logs"].includes(to.path)) {
    return "/";
  }
  return true;
});

createApp(App).use(router).mount("#app");
