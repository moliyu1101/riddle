import { ref } from "vue";
import { api } from "../api.js";

// 数据备份：导出/快照/恢复的状态与操作。
// 状态由 SettingsView 持有，通过 ctx 注入 toast / pollHealth。
export function useBackup(ctx) {
  const { toast, pollHealth } = ctx;

  const backupLoading = ref(false);
  const backupBusy = ref("");
  const backupStats = ref(null);
  const backupIncludeWork = ref(false);
  const restoreIncludeWork = ref(false);
  const restoreFile = ref(null);
  const backupRestarting = ref(false);

  async function loadBackupStats() {
    backupLoading.value = true;
    try {
      backupStats.value = await api.backupStatus();
    } catch (e) {
      toast(String(e.message || e).replace(/^\d+\s*/, ""));
    } finally {
      backupLoading.value = false;
    }
  }

  function pollBackupRestart() {
    backupRestarting.value = true;
    pollHealth();
  }

  async function exportBackup() {
    backupBusy.value = "export";
    try {
      await api.downloadBackupExport(backupIncludeWork.value);
      toast(backupIncludeWork.value ? "已开始下载（含工作目录）" : "已开始下载数据库备份");
    } catch (e) {
      toast(String(e.message || e).replace(/^\d+\s*/, ""));
    } finally {
      backupBusy.value = "";
    }
  }

  async function snapshotNow() {
    backupBusy.value = "snapshot";
    try {
      const r = await api.backupSnapshot();
      toast(`已在服务器覆盖保存 ${r.name}（${r.human}）`);
      await loadBackupStats();
    } catch (e) {
      toast(String(e.message || e).replace(/^\d+\s*/, ""));
    } finally {
      backupBusy.value = "";
    }
  }

  async function downloadSnapshot(name) {
    backupBusy.value = name;
    try {
      await api.downloadBackupSnapshot(name);
    } catch (e) {
      toast(String(e.message || e).replace(/^\d+\s*/, ""));
    } finally {
      backupBusy.value = "";
    }
  }

  function onRestoreFile(ev) {
    restoreFile.value = ev.target.files?.[0] || null;
  }

  async function restoreBackup() {
    if (!restoreFile.value) {
      toast("请先选择备份文件（.tar.gz）");
      return;
    }
    if (!confirm("将覆盖当前数据库并重启服务。进行中的任务会中断。确定恢复？")) return;
    backupBusy.value = "restore";
    try {
      const r = await api.restoreBackup(restoreFile.value, restoreIncludeWork.value);
      toast(r.message || "已恢复");
      if (r.restarted) pollBackupRestart();
    } catch (e) {
      toast(String(e.message || e).replace(/^\d+\s*/, ""));
    } finally {
      backupBusy.value = "";
    }
  }

  return {
    backupLoading,
    backupBusy,
    backupStats,
    backupIncludeWork,
    restoreIncludeWork,
    restoreFile,
    backupRestarting,
    loadBackupStats,
    pollBackupRestart,
    exportBackup,
    snapshotNow,
    downloadSnapshot,
    onRestoreFile,
    restoreBackup,
  };
}
