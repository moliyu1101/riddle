/** 外观偏好：服务端持久化，localStorage 只做启动缓存。 */

export const UI_STORAGE_KEY = "riddle-ui-v2";
export const THEME_STORAGE_KEY = "riddle-theme";
const MIGRATED_KEY = "riddle-ui-v2-migrated";

export const ACCENT_PRESETS = [
  { h: 212, name: "战术钴蓝" },
  { h: 168, name: "信号翠青" },
  { h: 155, name: "战地翡翠" },
  { h: 42, name: "钨金琥珀" },
  { h: 12, name: "赤红警戒" },
  { h: 265, name: "量子紫晶" },
];

export const ACCENT2_PRESETS = [
  { h: 168, name: "信号翠青" },
  { h: 212, name: "战术钴蓝" },
  { h: 42, name: "钨金琥珀" },
  { h: 195, name: "冰川天青" },
  { h: 145, name: "矩阵绿" },
  { h: 25, name: "铜橘" },
];

export const BG_PRESETS = [
  { h: 222, name: "碳灰岩" },
  { h: 210, name: "深海石墨" },
  { h: 240, name: "曜石蓝黑" },
  { h: 195, name: "极夜深青" },
];

/** 整套主题预设：棱镜战术工作台六套工业风配色 */
export const THEME_PRESETS = [
  { id: "prism",   name: "棱镜战术蓝", accentHue: 212, accent2Hue: 168, bgHue: 222, glow: 0.45, desc: "碳黑岩灰 × 钴蓝翠青（重构默认）" },
  { id: "emerald", name: "深林猎手",   accentHue: 158, accent2Hue: 195, bgHue: 210, glow: 0.55, desc: "翡翠绿 × 天青，高频侦察视野" },
  { id: "amber",   name: "钨金指挥",   accentHue: 42,  accent2Hue: 205, bgHue: 230, glow: 0.5,  desc: "暖金琥珀 × 钢蓝，长时审阅护眼" },
  { id: "crimson", name: "红队攻坚",   accentHue: 12,  accent2Hue: 38,  bgHue: 235, glow: 0.6,  desc: "战术赤红 × 琥珀，高压攻防态" },
  { id: "arctic",  name: "极昼冰岩",   accentHue: 205, accent2Hue: 172, bgHue: 220, glow: 0.35, desc: "极低微光，干净精密仪表风" },
  { id: "violet",  name: "量子紫外",   accentHue: 265, accent2Hue: 185, bgHue: 245, glow: 0.65, desc: "冷紫 × 青光，高对比科技感" },
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
  v: 2,
  theme: "dark",
  accentHue: 212,
  accent2Hue: 168,
  glow: 0.45,
  bgHue: 222,
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
  // 从旧版赛博品红紫无感迁移至 v2 棱镜战术蓝默认值（保留壁纸与明暗选择）
  const isLegacyDefault = Number(ui.v || 1) < 2;
  return {
    v: 2,
    theme: ui.theme === "light" ? "light" : "dark",
    accentHue: isLegacyDefault ? DEFAULTS.accentHue : clampHue(ui.accentHue),
    accent2Hue: isLegacyDefault ? DEFAULTS.accent2Hue : clampHue(ui.accent2Hue, DEFAULTS.accent2Hue),
    glow: isLegacyDefault ? DEFAULTS.glow : clampGlow(ui.glow),
    bgHue: isLegacyDefault ? DEFAULTS.bgHue : clampHue(ui.bgHue, DEFAULTS.bgHue),
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
    v: 2,
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
