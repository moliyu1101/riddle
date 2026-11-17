/** 外观偏好：服务端持久化，localStorage 只做启动缓存。 */

export const UI_STORAGE_KEY = "riddle-ui-v4";
export const THEME_STORAGE_KEY = "riddle-theme";
const MIGRATED_KEY = "riddle-ui-v4-migrated";

export const ACCENT_PRESETS = [
  { h: 250, name: "极简靛蓝（默认）" },
  { h: 215, name: "钴蓝工控" },
  { h: 162, name: "翡翠绿" },
  { h: 26, name: "信号朱红" },
  { h: 38, name: "工业琥珀" },
  { h: 350, name: "赤红警戒" },
];

export const ACCENT2_PRESETS = [
  { h: 162, name: "深青翡翠" },
  { h: 215, name: "钴蓝" },
  { h: 250, name: "靛蓝" },
  { h: 38, name: "工业琥珀" },
  { h: 192, name: "天青" },
  { h: 26, name: "信号朱红" },
];

export const BG_PRESETS = [
  { h: 220, name: "纯净曜黑" },
  { h: 210, name: "冷灰石墨" },
  { h: 235, name: "碳岩蓝黑" },
  { h: 195, name: "深海矿石" },
];

/** 整套主题预设 */
export const THEME_PRESETS = [
  { id: "studio",   name: "精工极简（默认）", accentHue: 250, accent2Hue: 162, bgHue: 220, glow: 0.25, desc: "极简素雅浅灰白底 × 靛蓝翡翠，对齐现代工程工作台" },
  { id: "cobalt",   name: "精工钴蓝",         accentHue: 215, accent2Hue: 162, bgHue: 218, glow: 0.25, desc: "钴蓝 × 翡翠绿，冷静数据分析视角" },
  { id: "emerald",  name: "翡翠猎手",         accentHue: 162, accent2Hue: 250, bgHue: 205, glow: 0.30, desc: "翡翠绿 × 靛蓝，渗透工程终端感" },
  { id: "solaris",  name: "信号朱红",         accentHue: 26,  accent2Hue: 168, bgHue: 220, glow: 0.25, desc: "朱红 × 深青翡翠，高对比警戒视觉" },
  { id: "amber",    name: "钨金指挥",         accentHue: 38,  accent2Hue: 210, bgHue: 225, glow: 0.30, desc: "琥珀金 × 钢蓝，长时间高密度审阅" },
  { id: "crimson",  name: "赤红战备",         accentHue: 355, accent2Hue: 162, bgHue: 230, glow: 0.35, desc: "赤红 × 翠青，高危攻坚响应态" },
];

/** 界面缩放档位 */
export const UI_SCALE_STEPS = [
  { value: 0.9,  label: "紧凑" },
  { value: 0.95, label: "偏小" },
  { value: 1,    label: "标准" },
  { value: 1.075, label: "偏大" },
  { value: 1.15, label: "最大" },
];

export const DEFAULTS = {
  v: 4,
  theme: "light",
  accentHue: 250,
  accent2Hue: 162,
  glow: 0.25,
  bgHue: 220,
  wallpaperKind: "none",
  wallpaperUrl: "",
  wallpaperFit: "cover",
  wallpaperDim: 0.22,
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
  // 无感迁移至 v4 Pojun-aligned Studio 默认体系
  const isLegacy = Number(ui.v || 1) < 4;
  return {
    v: 4,
    theme: isLegacy ? DEFAULTS.theme : (ui.theme === "dark" ? "dark" : "light"),
    accentHue: isLegacy ? DEFAULTS.accentHue : clampHue(ui.accentHue),
    accent2Hue: isLegacy ? DEFAULTS.accent2Hue : clampHue(ui.accent2Hue, DEFAULTS.accent2Hue),
    glow: isLegacy ? DEFAULTS.glow : clampGlow(ui.glow),
    bgHue: isLegacy ? DEFAULTS.bgHue : clampHue(ui.bgHue, DEFAULTS.bgHue),
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
    v: 4,
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

export function applyChrome(prefs) {
  const root = document.documentElement;
  root.setAttribute("data-theme", prefs.theme);
  const isLight = prefs.theme === "light";
  root.style.setProperty("--accent-h", String(clampHue(prefs.accentHue)));
  root.style.setProperty("--accent2-h", String(clampHue(prefs.accent2Hue, DEFAULTS.accent2Hue)));
  root.style.setProperty("--glow", String(prefs.glow));
  root.style.setProperty("--bg-h", String(isLight ? DEFAULTS.bgHue : clampHue(prefs.bgHue, DEFAULTS.bgHue)));
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
  window.dispatchEvent(new CustomEvent("riddle-ui-changed", { detail: prefs }));
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
