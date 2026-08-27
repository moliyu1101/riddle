<script setup>
import { computed, ref } from "vue";
import { api } from "../../api.js";

const props = defineProps({
  onImported: { type: Function, required: true },
});

const exporting = ref(false);
const exportError = ref("");

/** 导入状态 */
const importText = ref("");
const importFileName = ref("");
const importBusy = ref(false);
const importError = ref("");
const importResult = ref(null); // { sections: [...], ok: true }

/** 解析导入文本 → 结构预览。解析失败返回 null 并写 importError */
const importPreview = computed(() => {
  const text = importText.value.trim();
  if (!text) return null;
  try {
    const data = JSON.parse(text);
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      importError.value = "不是有效的配置 JSON 对象";
      return null;
    }
    importError.value = "";
    const sections = [];
    const SECTION_META = {
      llm: { label: "LLM 通道", detail: (v) => v.mode === "pool" ? `端点池 ${v.providers?.length || 0} 个` : (v.model || "单端点") },
      fofa: { label: "FOFA 兼容", detail: (v) => `${v.max_pages ?? "?"} 页 × ${v.page_size ?? "?"}` },
      engines: { label: "测绘引擎", detail: (v) => `${Object.keys(v).length} 个引擎` },
      defaults: { label: "调度默认", detail: (v) => `并发 ${v.concurrency ?? "?"} · 深挖 ${v.deepen_cap ?? "?"}` },
      ui: { label: "界面外观", detail: (v) => v.theme === "light" ? "亮色" : (v.theme === "dark" ? "暗色" : "含外观项") },
    };
    for (const [key, meta] of Object.entries(SECTION_META)) {
      if (data[key] && typeof data[key] === "object") {
        sections.push({ key, label: meta.label, detail: meta.detail(data[key]) });
      }
    }
    if (!sections.length) {
      importError.value = "未找到可导入的配置分区（llm / fofa / engines / defaults / ui）";
      return null;
    }
    importError.value = "";
    return { sections, exportedAt: data.exported_at || "" };
  } catch {
    importError.value = "JSON 解析失败，请检查格式";
    return null;
  }
});

async function exportConfig() {
  exporting.value = true;
  exportError.value = "";
  try {
    const data = await api.exportSettings();
    const json = JSON.stringify(data, null, 2);
    const stamp = new Date().toISOString().slice(0, 10).replace(/-/g, "");
    const blob = new Blob([json], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = `riddle-settings-${stamp}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(href), 2000);
  } catch (e) {
    exportError.value = String(e.message || e).replace(/^\d+\s*/, "");
  } finally {
    exporting.value = false;
  }
}

function onImportFile(ev) {
  const file = ev.target.files?.[0];
  if (!file) return;
  importFileName.value = file.name;
  const reader = new FileReader();
  reader.onload = () => {
    importText.value = String(reader.result || "");
  };
  reader.onerror = () => {
    importError.value = "文件读取失败";
  };
  reader.readAsText(file, "utf-8");
  ev.target.value = "";
}

async function applyImport() {
  const preview = importPreview.value;
  if (!preview) return;
  if (!confirm("确认导入配置？将覆盖对应分区的现有配置（密钥留空不覆盖）。")) return;
  importBusy.value = true;
  importError.value = "";
  importResult.value = null;
  try {
    const payload = JSON.parse(importText.value.trim());
    const res = await api.importSettings(payload);
    importResult.value = {
      sections: preview.sections.map((s) => s.label),
      ok: true,
      updated_at: res?.updated_at || "",
    };
    importText.value = "";
    importFileName.value = "";
    await props.onImported();
  } catch (e) {
    importError.value = String(e.message || e).replace(/^\d+\s*/, "");
  } finally {
    importBusy.value = false;
  }
}

function clearImport() {
  importText.value = "";
  importFileName.value = "";
  importError.value = "";
  importResult.value = null;
}
</script>

<template>
  <div class="config-transfer">
    <div class="settings-subhead">
      <b>导出配置</b>
      <span>下载完整配置 JSON（含 API Key 明文），用于跨实例迁移或本地备份。请妥善保管文件。</span>
    </div>
    <div class="config-transfer-actions">
      <button type="button" class="primary" :disabled="exporting" @click="exportConfig">
        {{ exporting ? "导出中…" : "下载配置 JSON" }}
      </button>
      <p v-if="exportError" class="engine-test-result">{{ exportError }}</p>
    </div>

    <div class="settings-subhead">
      <b>导入配置</b>
      <span>粘贴或选择导出的 JSON，可整体或分区导入。密钥字段留空时保留现有值，不会清空。</span>
    </div>
    <div class="config-import">
      <textarea
        v-model="importText"
        class="config-import-textarea"
        rows="6"
        placeholder='粘贴配置 JSON，或点击下方「选择文件」导入 riddle-settings-*.json'
        spellcheck="false"
      ></textarea>
      <div class="config-import-toolbar">
        <label class="mini-action config-import-file" style="cursor:pointer">
          选择文件
          <input type="file" accept=".json,application/json" hidden @change="onImportFile" />
        </label>
        <span v-if="importFileName" class="config-import-filename">{{ importFileName }}</span>
        <button type="button" class="ghost-btn" :disabled="!importText" @click="clearImport">清空</button>
        <button
          type="button"
          class="primary"
          :disabled="!importText || importBusy || !importPreview"
          @click="applyImport"
        >
          {{ importBusy ? "导入中…" : "执行导入" }}
        </button>
      </div>

      <div v-if="importPreview" class="config-import-preview">
        <div class="config-import-preview-head">
          <b>将导入 {{ importPreview.sections.length }} 个分区</b>
          <small v-if="importPreview.exportedAt">导出于 {{ importPreview.exportedAt.slice(0, 19).replace("T", " ") }}</small>
        </div>
        <div class="config-import-sections">
          <span v-for="s in importPreview.sections" :key="s.key" class="config-import-chip">
            <b>{{ s.label }}</b>
            <small>{{ s.detail }}</small>
          </span>
        </div>
      </div>

      <p v-if="importError" class="engine-test-result">{{ importError }}</p>
      <div v-if="importResult?.ok" class="engine-test-result ok">
        ✓ 已导入：{{ importResult.sections.join("、") }}{{ importResult.updated_at ? `（${importResult.updated_at.slice(0, 19).replace("T", " ")}）` : "" }}
      </div>
    </div>
  </div>
</template>
