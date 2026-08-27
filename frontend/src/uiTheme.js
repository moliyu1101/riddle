/** 外观偏好：服务端持久化，localStorage 只做启动缓存。 */

export const UI_STORAGE_KEY = "ah-ui";
export const THEME_STORAGE_KEY = "ah-theme";
const MIGRATED_KEY = "ah-ui-migrated";

export const ACCENT_PRESETS = [
  { h: 330, name: "品红" },
  { h: 285, name: "霓虹紫" },
  { h: 228, name: "电光蓝" },
  { h: 195, name: "青" },
  { h: 140, name: "荧光绿" },
  { h: 45, name: "琥珀" },
];

export const ACCENT2_PRESETS = [
  { h: 195, name: "青" },
  { h: 330, name: "品红" },
  { h: 228, name: "电光蓝" },
  { h: 140, name: "荧光绿" },
  { h: 285, name: "霓虹紫" },
  { h: 45, name: "琥珀" },
];

export const BG_PRESETS = [
  { h: 295, name: "深紫" },
  { h: 255, name: "深蓝" },
  { h: 220, name: "深青" },
  { h: 300, name: "近黑" },
];

/** 整套主题预设：一键切换 主色/副色/背景色调/辉光强度（不动明暗与壁纸） */
export const THEME_PRESETS = [
  { id: "neon",  name: "霓虹终端", accentHue: 330, accent2Hue: 195, bgHue: 295, glow: 1.0, desc: "品红 × 青，默认作战形态" },
  { id: "cyber", name: "赛博朋克", accentHue: 285, accent2Hue: 195, bgHue: 300, glow: 1.4, desc: "高辉光紫青，最浓夜色" },
  { id: "ice",   name: "冰蓝管制", accentHue: 228, accent2Hue: 195, bgHue: 255, glow: 0.7, desc: "低辉光电光蓝，克制冷静" },
  { id: "matrix",name: "矩阵绿", accentHue: 140, accent2Hue: 45,  bgHue: 220, glow: 1.1, desc: "荧光绿 × 琥珀，老派终端" },
  { id: "amber", name: "琥珀暖夜", accentHue: 45,  accent2Hue: 285, bgHue: 300, glow: 0.9, desc: "琥珀 × 霓虹紫，护眼暖色" },
  { id: "blood", name: "赤红警戒", accentHue: 350, accent2Hue: 45,  bgHue: 300, glow: 1.2, desc: "红 × 琥珀，高压氛围" },
];

/** 界面缩放档位 */
export const UI_SCALE_STEPS = [
  { value: 0.85, label: "紧凑" },
  { value: 0.925, label: "偏小" },
  { value: 1, label: "标准" },
  { value: 1.075, label: "偏大" },
  { value: 1.15, label: "最大" },
];

export const DEFAULTS = {
  theme: "dark",
  accentHue: 330,
  accent2Hue: 195,
  glow: 1,
  bgHue: 295,
  wallpaperKind: "none",
  wallpaperUrl: "",
  wallpaperFit: "cover",
  wallpaperDim: 0.28,
  uiScale: 1,
  motion: "on",
};

let appliedSrc = "";

function clampHue(h, fallback = DEFAULTS.accentHue) {
  const n = Number(h);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, min360(Math.round(n)));
}
function min360(n) { return Math.max(0, Math.min(360, n)); }

function clampDim(d) {
  const n = Number(d);
  if (!Number.isFinite(n)) return DEFAULTS.wallpaperDim;
  if (n >= 0.65) return DEFAULTS.wallpaperDim;
  return Math.max(0.08, Math.min(0.62, n));
}

function clampGlow(g) {
  const n = Number(g);
  if (!Number.isFinite(n) || n <= 0) return DEFAULTS.glow;
  return Math.max(0.2, Math.min(2, n));
}

function clampScale(s) {
  const n = Number(s);
  if (!Number.isFinite(n) || n <= 0) return DEFAULTS.uiScale;
  return Math.max(0.85, Math.min(1.15, Math.round(n * 1000) / 1000));
}

export function prefsFromApi(ui = {}) {
  return {
    theme: ui.theme === "light" ? "light" : "dark",
    accentHue: clampHue(ui.accentHue),
    accent2Hue: clampHue(ui.accent2Hue, DEFAULTS.accent2Hue),
    glow: clampGlow(ui.glow),
    bgHue: clampHue(ui.bgHue, DEFAULTS.bgHue),
    wallpaperKind: ["none", "url", "file"].includes(ui.wallpaperKind) ? ui.wallpaperKind : "none",
    wallpaperUrl: typeof ui.wallpaperUrl === "string" ? ui.wallpaperUrl.trim() : "",
    wallpaperFit: ui.wallpaperFit === "contain" ? "contain" : "cover",
    wallpaperDim: clampDim(ui.wallpaperDim),
    wallpaperSrc: typeof ui.wallpaperSrc === "string" ? ui.wallpaperSrc : "",
    uiScale: clampScale(ui.uiScale),
    motion: ui.motion === "off" ? "off" : "on",
  };
}

export function prefsToApi(prefs) {
  return {
    theme: prefs.theme,
    accentHue: clampHue(prefs.accentHue),
    accent2Hue: clampHue(prefs.accent2Hue),
    glow: clampGlow(prefs.glow),
    bgHue: clampHue(prefs.bgHue),
    wallpaperKind: prefs.wallpaperKind,
    wallpaperUrl: prefs.wallpaperUrl || "",
    wallpaperFit: prefs.wallpaperFit,
    wallpaperDim: clampDim(prefs.wallpaperDim),
    uiScale: clampScale(prefs.uiScale),
    motion: prefs.motion === "off" ? "off" : "on",
    saved: true,
  };
}

export function loadUiPrefs() {
  let parsed = {};
  try {
    parsed = JSON.parse(localStorage.getItem(UI_STORAGE_KEY) || "{}") || {};
  } catch {
    parsed = {};
  }
  const legacyTheme = localStorage.getItem(THEME_STORAGE_KEY);
  return prefsFromApi({
    ...parsed,
    theme: parsed.theme || (legacyTheme === "light" ? "light" : DEFAULTS.theme),
  });
}

export function saveUiPrefs(prefs) {
  const next = { ...DEFAULTS, ...prefs };
  localStorage.setItem(UI_STORAGE_KEY, JSON.stringify(next));
  localStorage.setItem(THEME_STORAGE_KEY, next.theme);
  return next;
}

// 亮色主题固定蓝白配色：主/次强调色与背景统一蓝系，霓虹偏好只作用于暗色主题
const LIGHT_ACCENT_H = 228;
const LIGHT_ACCENT2_H = 195;
const LIGHT_BG_H = 230;

export function applyChrome(prefs) {
  const root = document.documentElement;
  root.setAttribute("data-theme", prefs.theme);
  const isLight = prefs.theme === "light";
  root.style.setProperty("--accent-h", String(isLight ? LIGHT_ACCENT_H : prefs.accentHue));
  root.style.setProperty("--accent2-h", String(isLight ? LIGHT_ACCENT2_H : prefs.accent2Hue));
  root.style.setProperty("--glow", String(prefs.glow));
  root.style.setProperty("--bg-h", String(isLight ? LIGHT_BG_H : prefs.bgHue));
  root.style.setProperty("--wallpaper-dim", String(prefs.wallpaperDim));
  root.style.setProperty("--wallpaper-fit", prefs.wallpaperFit);
  root.style.setProperty("--ui-scale", String(clampScale(prefs.uiScale)));
  root.setAttribute("data-motion", prefs.motion === "off" ? "off" : "on");
  const hasPaper = prefs.wallpaperKind === "url" || prefs.wallpaperKind === "file";
  root.setAttribute("data-wallpaper", hasPaper ? "on" : "off");
}

/** 当前配色命中的主题预设 id（无命中返回 ""，表示自定义配色） */
export function matchedThemePreset(prefs) {
  const p = THEME_PRESETS.find((t) =>
    t.accentHue === Number(prefs.accentHue)
    && t.accent2Hue === Number(prefs.accent2Hue)
    && t.bgHue === Number(prefs.bgHue)
    && t.glow === Number(prefs.glow),
  );
  return p ? p.id : "";
}

function setWallpaperEl(src) {
  const el = document.getElementById("ah-wallpaper");
  if (!el) return;
  el.style.backgroundImage = src ? `url("${src}")` : "none";
}

export function applyWallpaper(prefs) {
  let src = "";
  if (prefs.wallpaperKind === "url" && /^https?:\/\//i.test(prefs.wallpaperUrl || prefs.wallpaperSrc || "")) {
    src = prefs.wallpaperSrc || prefs.wallpaperUrl;
  } else if (prefs.wallpaperKind === "file") {
    src = prefs.wallpaperSrc || "/api/settings/ui/wallpaper";
  }
  appliedSrc = src;
  setWallpaperEl(src);
}

export async function applyUi(prefs) {
  applyChrome(prefs);
  applyWallpaper(prefs);
  window.dispatchEvent(new CustomEvent("ah-ui-changed", { detail: prefs }));
  return prefs;
}

export function hexToHue(hex, fallback = DEFAULTS.accentHue) {
  const m = String(hex || "").trim().match(/^#?([0-9a-f]{6})$/i);
  if (!m) return fallback;
  const n = parseInt(m[1], 16);
  const r = ((n >> 16) & 255) / 255;
  const g = ((n >> 8) & 255) / 255;
  const b = (n & 255) / 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  if (max - min < 0.08) return fallback;
  const d = max - min;
  let h = 0;
  if (max === r) h = ((g - b) / d + (g < b ? 6 : 0));
  else if (max === g) h = (b - r) / d + 2;
  else h = (r - g) / d + 4;
  return Math.round(h * 60) % 360;
}

export function hueToHex(h) {
  const hue = clampHue(h) / 360;
  const a = (p, q, t) => {
    if (t < 0) t += 1;
    if (t > 1) t -= 1;
    if (t < 1 / 6) return p + (q - p) * 6 * t;
    if (t < 1 / 2) return q;
    if (t < 2 / 3) return p + (q - p) * (2 / 3 - t) * 6;
    return p;
  };
  const q = 0.62;
  const p = 0.28;
  const r = Math.round(a(p, q, hue + 1 / 3) * 255);
  const g = Math.round(a(p, q, hue) * 255);
  const b = Math.round(a(p, q, hue - 1 / 3) * 255);
  return `#${[r, g, b].map((x) => x.toString(16).padStart(2, "0")).join("")}`;
}

export function compressImageFile(file, { maxEdge = 1920, quality = 0.72 } = {}) {
  return new Promise((resolve, reject) => {
    if (!file || !file.type?.startsWith("image/")) {
      reject(new Error("请选择图片文件"));
      return;
    }
    if (file.size > 12 * 1024 * 1024) {
      reject(new Error("图片太大，请选 12MB 以内"));
      return;
    }
    const img = new Image();
    const src = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(src);
      const scale = Math.min(1, maxEdge / Math.max(img.width, img.height));
      const w = Math.max(1, Math.round(img.width * scale));
      const h = Math.max(1, Math.round(img.height * scale));
      const canvas = document.createElement("canvas");
      canvas.width = w;
      canvas.height = h;
      const ctx = canvas.getContext("2d");
      ctx.drawImage(img, 0, 0, w, h);
      canvas.toBlob(
        (blob) => {
          if (!blob) {
            reject(new Error("图片压缩失败"));
            return;
          }
          if (blob.size > 3 * 1024 * 1024) {
            reject(new Error("压缩后仍超过 3MB，请换一张更小的图"));
            return;
          }
          resolve(blob);
        },
        "image/jpeg",
        quality,
      );
    };
    img.onerror = () => {
      URL.revokeObjectURL(src);
      reject(new Error("无法读取这张图片"));
    };
    img.src = src;
  });
}

export function resetUiLocal() {
  appliedSrc = "";
  return saveUiPrefs({ ...DEFAULTS });
}

export function markUiMigrated() {
  localStorage.setItem(MIGRATED_KEY, "1");
}

export function uiNeedsMigrate() {
  return localStorage.getItem(MIGRATED_KEY) !== "1";
}
