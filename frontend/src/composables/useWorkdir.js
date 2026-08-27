import { ref } from "vue";
import { api } from "../api.js";

// 工作目录管理：磁盘占用统计与清理。
// 状态由 SettingsView 持有，通过 ctx 注入 toast。
export function useWorkdir(ctx) {
  const { toast } = ctx;

  const workdirLoading = ref(false);
  const workdirCleaning = ref(false);
  const workdirStats = ref(null);
  const workdirResult = ref(null);
  const cleanupRetentionDays = ref(7);
  const cleanupDryRun = ref(true);

  async function loadWorkdirStats() {
    workdirLoading.value = true;
    try {
      workdirStats.value = await api.workdirStats();
      if (workdirStats.value) {
        cleanupRetentionDays.value = workdirStats.value.retention_days || 7;
      }
    } catch (e) {
      toast(String(e.message || e).replace(/^\d+\s*/, ""));
    } finally {
      workdirLoading.value = false;
    }
  }

  async function runCleanup() {
    workdirCleaning.value = true;
    workdirResult.value = null;
    try {
      const res = await api.workdirCleanup(cleanupRetentionDays.value, cleanupDryRun.value);
      workdirResult.value = res;
      const prefix = res.dry_run ? "模拟清理" : "清理";
      toast(`${prefix}完成：删除 ${res.deleted_dirs} 个目录，释放 ${res.freed_human}`);
      if (!res.dry_run) {
        await loadWorkdirStats();
      }
    } catch (e) {
      toast(String(e.message || e).replace(/^\d+\s*/, ""));
    } finally {
      workdirCleaning.value = false;
    }
  }

  return {
    workdirLoading,
    workdirCleaning,
    workdirStats,
    workdirResult,
    cleanupRetentionDays,
    cleanupDryRun,
    loadWorkdirStats,
    runCleanup,
  };
}
