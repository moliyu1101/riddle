<script setup>
import { ref } from "vue";
import { api } from "../../api.js";

const props = defineProps({
  form: { type: Object, required: true },
});

/** 每个引擎的测试状态：{ loading, ok, latency_ms, size, error, error_type } */
const engineTests = ref({});

async function testEngine(name) {
  const eng = props.form.engines?.[name];
  engineTests.value = {
    ...engineTests.value,
    [name]: { loading: true, ok: false, latency_ms: 0, size: 0, error: "", error_type: "" },
  };
  try {
    const res = await api.testEngine({
      engine: name,
      key: String(eng?.key || "").trim() || undefined,
      base_url: String(eng?.base_url || "").trim() || undefined,
    });
    engineTests.value = {
      ...engineTests.value,
      [name]: {
        loading: false,
        ok: !!res?.ok,
        latency_ms: res?.latency_ms || 0,
        size: res?.size || 0,
        error: res?.error || "",
        error_type: res?.error_type || "other",
      },
    };
  } catch (e) {
    engineTests.value = {
      ...engineTests.value,
      [name]: {
        loading: false,
        ok: false,
        latency_ms: 0,
        size: 0,
        error: String(e.message || e).replace(/^\d+\s*/, ""),
        error_type: "other",
      },
    };
  }
}

function engineTestLabel(name) {
  const t = engineTests.value[name];
  if (!t || t.loading) return "";
  if (t.ok) return `✓ 连通 · ${t.latency_ms}ms · ${t.size} 条`;
  if (t.error_type === "auth") return `✗ 认证失败：${t.error}`;
  if (t.error_type === "network") return `✗ 网络错误：${t.error}`;
  return `✗ ${t.error}`;
}
</script>

<template>
  <div class="recon-settings">
    <div class="settings-subhead">
      <b>默认参数</b>
      <span>新建任务未指定时的保守默认值</span>
    </div>
    <div class="settings-grid">
      <label class="full">默认搜索引擎
        <select v-model="form.default_engine">
          <option v-for="eng in form.available_engines" :key="eng.name" :value="eng.name">
            {{ eng.display_name || eng.name }}
          </option>
        </select>
      </label>
      <p class="field-hint full">新建任务「搜索引擎」留空时使用此项。任务里仍可临时换引擎。</p>
      <label>默认最大页数 <input v-model="form.max_pages" type="number" min="1" /></label>
      <label>每页条数 <input v-model="form.page_size" type="number" min="1" /></label>
      <label class="full">默认搜集方式
        <select v-model="form.default_intent_mode">
          <option value="">自动判断</option>
          <option value="syntax">查询语法（当前引擎官网语法）</option>
          <option value="intent">自然语言意图</option>
        </select>
      </label>
      <p class="field-hint full">分页与搜集方式对当前选用的测绘引擎生效。</p>
    </div>

    <div class="settings-subhead">
      <b>各引擎 API Key</b>
      <span>按需配置；未配 Key 的引擎在任务里选中时无法搜资产。密钥留空表示不修改。</span>
    </div>
    <div class="engine-keys">
      <div v-for="eng in form.available_engines" :key="eng.name" class="engine-key-card">
        <div class="engine-key-head">
          <div class="engine-key-name">
            <strong>{{ form.engines[eng.name]?.display_name || eng.display_name || eng.name }}</strong>
            <i :class="{ on: form.engines[eng.name]?.key_set }">
              {{ form.engines[eng.name]?.key_set ? "已配置" : "未配置" }}
            </i>
          </div>
          <button
            type="button"
            class="engine-test-btn"
            :disabled="engineTests[eng.name]?.loading"
            @click="testEngine(eng.name)"
          >
            {{ engineTests[eng.name]?.loading ? "测试中…" : "测试连接" }}
          </button>
        </div>
        <div class="settings-grid" v-if="form.engines[eng.name]">
          <label class="full">API Key
            <input v-model="form.engines[eng.name].key" type="password"
              :placeholder="form.engines[eng.name]?.key_set ? '已配置，留空不修改' : (
                eng.name === 'censys' ? 'Platform Personal Access Token，或旧版 API_ID:SECRET' :
                eng.name === 'quake' ? 'X-QuakeToken（个人中心 API Token）' :
                ((eng.display_name || eng.name) + ' API Key')
              )" />
          </label>
          <template v-if="eng.name === 'fofa'">
            <label class="full">备用账号 1（可选）
              <input v-model="form.engines[eng.name].key_backup" type="password"
                :placeholder="form.engines[eng.name]?.key_backup_set ? '已配置，留空不修改' : '主号限流时自动切换'" />
            </label>
            <label class="full">备用账号 2（可选）
              <input v-model="form.engines[eng.name].key_backup2" type="password"
                :placeholder="form.engines[eng.name]?.key_backup2_set ? '已配置，留空不修改' : '前两个用尽才用'" />
            </label>
            <p class="field-hint full">
              多账号自动切换：主号遇 429 / 请求频繁 / 今日上限 / F点不足 时自动换备用账号，全部限流才报错。
            </p>
          </template>
          <p v-if="eng.name === 'censys'" class="field-hint full">
            新账号用 Censys Platform 的 Personal Access Token；仅旧 Legacy Search 才填 <code>API_ID:SECRET</code>。
          </p>
          <label class="full">API 端点（可选）
            <input v-model="form.engines[eng.name].base_url"
              :placeholder="eng.name === 'fofa' ? 'https://fofa.info' : '留空用官方默认'" />
          </label>
        </div>
        <p v-if="engineTestLabel(eng.name)" class="engine-test-result" :class="{ ok: engineTests[eng.name]?.ok }">
          {{ engineTestLabel(eng.name) }}
        </p>
      </div>
    </div>
  </div>
</template>
