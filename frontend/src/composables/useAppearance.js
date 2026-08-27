import { computed, ref } from "vue";
import { api } from "../api.js";
import {
  applyUi,
  compressImageFile,
  DEFAULTS,
  hexToHue,
  loadUiPrefs,
  prefsFromApi,
  prefsToApi,
  resetUiLocal,
  saveUiPrefs,
  matchedThemePreset,
} from "../uiTheme.js";

// 外观偏好：主题色、明暗、壁纸的本地 + 服务器持久化。
// 状态由 SettingsView 持有（uiPrefs 等），通过 ctx 注入，避免 props 层层透传。
export function useAppearance(ctx) {
  const { toast } = ctx;

  const uiPrefs = ref(loadUiPrefs());
  const wallpaperBusy = ref(false);
  const wallpaperError = ref("");
  const wallpaperPreviewStyle = computed(() => {
    const kind = uiPrefs.value.wallpaperKind;
    const src = kind === "file"
      ? (uiPrefs.value.wallpaperSrc || "/api/settings/ui/wallpaper")
      : kind === "url"
        ? (uiPrefs.value.wallpaperSrc || uiPrefs.value.wallpaperUrl || "")
        : "";
    if (!src || !/^https?:\/\//i.test(src) && !src.startsWith("/")) return {};
    return { backgroundImage: `url(${JSON.stringify(src)})` };
  });
  let uiSaveTimer = null;

  async function syncUiToServer(prefs) {
    const s = await api.updateSettings({ ui: prefsToApi(prefs) });
    const next = saveUiPrefs(prefsFromApi(s.ui || prefs));
    uiPrefs.value = next;
    await applyUi(next);
  }

  async function persistUi(patch) {
    uiPrefs.value = saveUiPrefs({ ...uiPrefs.value, ...patch });
    await applyUi(uiPrefs.value);
    clearTimeout(uiSaveTimer);
    uiSaveTimer = setTimeout(() => {
      syncUiToServer(uiPrefs.value).catch((e) => {
        wallpaperError.value = String(e.message || e).replace(/^\d+\s*/, "");
      });
    }, 400);
  }

  function setAccentHue(h) {
    persistUi({ accentHue: Number(h) });
  }

  function onCustomAccent(ev) {
    const next = hexToHue(ev.target.value, uiPrefs.value.accentHue);
    setAccentHue(next);
  }

  function setAccent2Hue(h) {
    persistUi({ accent2Hue: Number(h) });
  }

  function onCustomAccent2(ev) {
    const next = hexToHue(ev.target.value, uiPrefs.value.accent2Hue);
    setAccent2Hue(next);
  }

  function setGlow(g) {
    persistUi({ glow: Number(g) });
  }

  function setBgHue(h) {
    persistUi({ bgHue: Number(h) });
  }

  /** 当前命中的主题预设 id（自定义配色时为空串） */
  const activePresetId = computed(() => matchedThemePreset(uiPrefs.value));

  function applyThemePreset(preset) {
    persistUi({
      accentHue: preset.accentHue,
      accent2Hue: preset.accent2Hue,
      bgHue: preset.bgHue,
      glow: preset.glow,
    });
  }

  function setUiScale(v) {
    persistUi({ uiScale: Number(v) });
  }

  function setMotion(m) {
    persistUi({ motion: m === "off" ? "off" : "on" });
  }

  function setThemeMode(t) {
    persistUi({ theme: t });
  }

  async function onWallpaperFile(ev) {
    const file = ev.target.files?.[0];
    ev.target.value = "";
    if (!file) return;
    wallpaperBusy.value = true;
    wallpaperError.value = "";
    try {
      const blob = await compressImageFile(file);
      const uploaded = new File([blob], "wallpaper.jpg", { type: "image/jpeg" });
      const s = await api.uploadUiWallpaper(uploaded);
      uiPrefs.value = saveUiPrefs(prefsFromApi(s.ui || {}));
      await applyUi(uiPrefs.value);
    } catch (e) {
      wallpaperError.value = String(e.message || e).replace(/^\d+\s*/, "");
    } finally {
      wallpaperBusy.value = false;
    }
  }

  async function applyWallpaperUrl() {
    const url = (uiPrefs.value.wallpaperUrl || "").trim();
    if (!url) {
      await onClearWallpaper();
      return;
    }
    if (!/^https?:\/\//i.test(url)) {
      wallpaperError.value = "请填写 http(s) 图片地址";
      return;
    }
    wallpaperError.value = "";
    await persistUi({ wallpaperKind: "url", wallpaperUrl: url });
  }

  async function onClearWallpaper() {
    wallpaperError.value = "";
    try {
      const s = await api.deleteUiWallpaper();
      uiPrefs.value = saveUiPrefs(prefsFromApi(s.ui || { ...DEFAULTS }));
    } catch {
      uiPrefs.value = saveUiPrefs({ ...uiPrefs.value, wallpaperKind: "none", wallpaperUrl: "", wallpaperSrc: "" });
    }
    await applyUi(uiPrefs.value);
  }

  async function resetAppearance() {
    wallpaperError.value = "";
    try { await api.deleteUiWallpaper(); } catch { /* ignore */ }
    const prefs = resetUiLocal();
    await syncUiToServer(prefs);
  }

  function onUiChanged(e) {
    if (e.detail) uiPrefs.value = { ...loadUiPrefs(), ...e.detail };
  }

  function disposeAppearance() {
    clearTimeout(uiSaveTimer);
  }

  return {
    uiPrefs,
    wallpaperBusy,
    wallpaperError,
    wallpaperPreviewStyle,
    syncUiToServer,
    persistUi,
    setAccentHue,
    onCustomAccent,
    setAccent2Hue,
    onCustomAccent2,
    setGlow,
    setBgHue,
    activePresetId,
    applyThemePreset,
    setUiScale,
    setMotion,
    setThemeMode,
    onWallpaperFile,
    applyWallpaperUrl,
    onClearWallpaper,
    resetAppearance,
    onUiChanged,
    disposeAppearance,
  };
}
