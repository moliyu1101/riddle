import { reactive } from "vue";
import { api } from "../api.js";

// 一键更新：检查 GitHub 最新代码、热更/重建指引。
// 状态由 SettingsView 持有，通过 ctx 注入 toast / pollHealth / load。
export function useUpdate(ctx) {
  const { toast, pollHealth, load } = ctx;

  const updateState = reactive({
    checking: false,
    info: null,
    updating: false,
    restarting: false,
    error: "",
    supported: true,
  });

  async function checkUpdate() {
    updateState.checking = true;
    updateState.error = "";
    updateState.info = null;
    try {
      updateState.info = await api.checkUpdate();
      // 非 git / 网络失败：区块仍显示，把原因和手动更新指引给用户看
    } catch (e) {
      const msg = String(e.message || e);
      // 仅原版未注册 update 路由（404）时隐藏；发布版始终保留入口
      if (/^\s*404\b|not found/i.test(msg)) {
        updateState.supported = false;
      } else {
        updateState.error = msg.replace(/^\d+\s*/, "");
      }
    } finally {
      updateState.checking = false;
    }
  }

  async function runUpdate() {
    if (!confirm("确认更新？服务会自动重启，进行中的任务会优雅暂停。")) return;
    updateState.updating = true;
    updateState.error = "";
    try {
      const r = await api.runUpdate();
      if (r.ok) {
        updateState.restarting = true;
        pollHealth();
      } else {
        updateState.error = r.error || "更新失败";
        if (r.command) updateState.info = { ...updateState.info, rebuild_command: r.command };
      }
    } catch (e) {
      updateState.error = String(e.message || e).replace(/^\d+\s*/, "");
    } finally {
      updateState.updating = false;
    }
  }

  return { updateState, checkUpdate, runUpdate };
}
