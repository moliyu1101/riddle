<script setup>
import { ACCENT_PRESETS, ACCENT2_PRESETS, BG_PRESETS, THEME_PRESETS, UI_SCALE_STEPS, hueToHex } from "../../uiTheme.js";

defineProps({
  uiPrefs: { type: Object, required: true },
  wallpaperBusy: { type: Boolean, default: false },
  wallpaperError: { type: String, default: "" },
  wallpaperPreviewStyle: { type: Object, default: () => ({}) },
  setThemeMode: { type: Function, required: true },
  persistUi: { type: Function, required: true },
  setAccentHue: { type: Function, required: true },
  onCustomAccent: { type: Function, required: true },
  setAccent2Hue: { type: Function, required: true },
  onCustomAccent2: { type: Function, required: true },
  setGlow: { type: Function, required: true },
  setBgHue: { type: Function, required: true },
  activePresetId: { type: String, default: "" },
  applyThemePreset: { type: Function, required: true },
  setUiScale: { type: Function, required: true },
  setMotion: { type: Function, required: true },
  onWallpaperFile: { type: Function, required: true },
  applyWallpaperUrl: { type: Function, required: true },
  onClearWallpaper: { type: Function, required: true },
  resetAppearance: { type: Function, required: true },
});
</script>

<template>
  <div class="appearance-panel">
    <div class="settings-subhead">
      <b>主题</b>
      <span>暗色是作战终端默认形态；亮色固定蓝白配色，适合投影与文档截图。</span>
    </div>
    <div class="appearance-row">
      <div class="create-field">
        <span>明暗</span>
        <div class="llm-mode-switch" role="radiogroup" aria-label="明暗主题">
          <button type="button" :class="{ active: uiPrefs.theme === 'dark' }" @click="setThemeMode('dark')">暗色</button>
          <button type="button" :class="{ active: uiPrefs.theme === 'light' }" @click="setThemeMode('light')">亮色</button>
        </div>
      </div>
      <label>铺满方式
        <select :value="uiPrefs.wallpaperFit" @change="persistUi({ wallpaperFit: $event.target.value })">
          <option value="cover">铺满裁切</option>
          <option value="contain">完整显示</option>
        </select>
      </label>
    </div>

    <p v-if="uiPrefs.theme === 'light'" class="appearance-light-note">
      亮色主题固定蓝白配色（主蓝 / 次青），下方主题预设与霓虹配色只作用于暗色主题。
    </p>

    <div class="settings-subhead">
      <b>主题预设</b>
      <span>整套配色一键切换（主色 × 副色 × 背景 × 辉光强度）。选预设后再微调任意色相即成自定义配色。</span>
    </div>
    <div class="theme-presets" role="list">
      <button
        v-for="preset in THEME_PRESETS"
        :key="preset.id"
        type="button"
        class="theme-preset-card"
        :class="{ active: activePresetId === preset.id }"
        role="listitem"
        @click="applyThemePreset(preset)"
      >
        <span class="theme-preset-preview" aria-hidden="true">
          <i class="tp-bg" :style="{ background: `oklch(18% 0.045 ${preset.bgHue})` }"></i>
          <i class="tp-a1" :style="{ background: `oklch(76% 0.15 ${preset.accentHue})` }"></i>
          <i class="tp-a2" :style="{ background: `oklch(76% 0.15 ${preset.accent2Hue})` }"></i>
          <i class="tp-glow" :style="{ boxShadow: `0 0 ${10 * preset.glow}px oklch(76% 0.15 ${preset.accentHue} / ${0.55 * preset.glow})` }"></i>
        </span>
        <span class="theme-preset-name">
          <b>{{ preset.name }}</b>
          <small>{{ preset.desc }}</small>
        </span>
      </button>
    </div>

    <div class="settings-subhead">
      <b>霓虹配色</b>
      <span>只作用于暗色主题。主色管按钮与选中态，副色管进度与网格线，背景色调定整体氛围。</span>
    </div>
    <div class="appearance-colors">
      <!-- 主霓虹色 -->
      <div class="create-field full">
        <span>主霓虹色</span>
        <div class="appearance-swatches" role="list">
          <button
            v-for="sw in ACCENT_PRESETS"
            :key="sw.h"
            type="button"
            class="appearance-swatch"
            :class="{ active: Number(uiPrefs.accentHue) === sw.h }"
            :style="{ '--swatch-h': sw.h + 'deg' }"
            :title="sw.name"
            :aria-label="sw.name"
            @click="setAccentHue(sw.h)"
          ></button>
          <input
            type="color"
            :value="hueToHex(uiPrefs.accentHue)"
            aria-label="自定义主霓虹色"
            title="自定义"
            @change="onCustomAccent"
          />
        </div>
        <small class="muted">主色相 {{ uiPrefs.accentHue }} · 按钮、选中态、焦点、主辉光</small>
      </div>

      <!-- 副霓虹色 -->
      <div class="create-field full">
        <span>副霓虹色</span>
        <div class="appearance-swatches" role="list">
          <button
            v-for="sw in ACCENT2_PRESETS"
            :key="sw.h"
            type="button"
            class="appearance-swatch"
            :class="{ active: Number(uiPrefs.accent2Hue) === sw.h }"
            :style="{ '--swatch-h': sw.h + 'deg' }"
            :title="sw.name"
            :aria-label="sw.name"
            @click="setAccent2Hue(sw.h)"
          ></button>
          <input
            type="color"
            :value="hueToHex(uiPrefs.accent2Hue)"
            aria-label="自定义副霓虹色"
            title="自定义"
            @change="onCustomAccent2"
          />
        </div>
        <small class="muted">副色相 {{ uiPrefs.accent2Hue }} · 进度条、网格线、次级辉光</small>
      </div>

      <!-- 背景色调 -->
      <div class="create-field full">
        <span>背景色调</span>
        <div class="appearance-swatches bg-swatches" role="list">
          <button
            v-for="bg in BG_PRESETS"
            :key="bg.h"
            type="button"
            class="bg-swatch"
            :class="{ active: Number(uiPrefs.bgHue) === bg.h }"
            :style="{ '--bg-swatch-h': bg.h + 'deg' }"
            :title="bg.name"
            :aria-label="bg.name"
            @click="setBgHue(bg.h)"
          >
            {{ bg.name }}
          </button>
        </div>
        <small class="muted">背景色相 {{ uiPrefs.bgHue }} · 深紫 / 深蓝 / 深青 / 近黑</small>
      </div>

      <!-- 霓虹强度 -->
      <label class="full">霓虹强度 {{ Math.round(uiPrefs.glow * 100) }}%
        <input type="range" min="0.2" max="2" step="0.05" :value="uiPrefs.glow" @input="setGlow($event.target.value)" />
        <small class="muted">往右拖辉光更亮更浓，往左拖更克制</small>
      </label>
    </div>

    <div class="settings-subhead">
      <b>界面与动效</b>
      <span>缩放影响全站字号与间距；关动效可去掉过渡与闪烁动画，低配机器或录屏时更稳。</span>
    </div>
    <div class="appearance-row">
      <div class="create-field">
        <span>界面缩放</span>
        <div class="llm-mode-switch theme-scale-switch" role="radiogroup" aria-label="界面缩放">
          <button
            v-for="step in UI_SCALE_STEPS"
            :key="step.value"
            type="button"
            :class="{ active: Number(uiPrefs.uiScale) === step.value }"
            @click="setUiScale(step.value)"
          >{{ step.label }}</button>
        </div>
      </div>
      <div class="create-field">
        <span>动效</span>
        <div class="llm-mode-switch" role="radiogroup" aria-label="动效开关">
          <button type="button" :class="{ active: uiPrefs.motion !== 'off' }" @click="setMotion('on')">开</button>
          <button type="button" :class="{ active: uiPrefs.motion === 'off' }" @click="setMotion('off')">关</button>
        </div>
      </div>
    </div>

    <div class="settings-subhead">
      <b>背景图</b>
      <span>网络图片或本机图片均可（本机自动压缩后上传），全局生效。</span>
    </div>
    <div class="appearance-drop">
      <label class="full">背景图链接
        <input v-model="uiPrefs.wallpaperUrl" placeholder="https://example.com/wallpaper.jpg" @keydown.enter.prevent="applyWallpaperUrl" />
      </label>
      <div class="appearance-actions">
        <button type="button" @click="applyWallpaperUrl">使用链接</button>
        <label class="mini-action" style="cursor:pointer">
          上传图片
          <input type="file" accept="image/*" hidden :disabled="wallpaperBusy" @change="onWallpaperFile" />
        </label>
        <button type="button" :disabled="uiPrefs.wallpaperKind === 'none'" @click="onClearWallpaper">去掉背景</button>
        <button type="button" @click="resetAppearance">恢复默认外观</button>
      </div>
      <p v-if="wallpaperBusy" class="field-hint">正在压缩并保存图片…</p>
      <p v-if="wallpaperError" class="field-hint" style="color:var(--danger)">{{ wallpaperError }}</p>
      <div class="appearance-preview" :style="wallpaperPreviewStyle">
        {{ uiPrefs.wallpaperKind === 'none' ? '当前没有自定义背景' : (uiPrefs.wallpaperKind === 'file' ? '已使用本机图片' : '使用网络图片') }}
      </div>
      <label class="full">背景压暗 {{ Math.round(uiPrefs.wallpaperDim * 100) }}%
        <input type="range" min="0.08" max="0.62" step="0.01" :value="uiPrefs.wallpaperDim" @input="persistUi({ wallpaperDim: Number($event.target.value) })" />
        <small class="muted">往左拖图更清楚，往右拖字更好读</small>
      </label>
    </div>
  </div>
</template>
