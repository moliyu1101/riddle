import { ref, computed, watch, nextTick } from "vue";
import { api } from "../api.js";
import { copyText, formatLlmTestCopy } from "../clipboard.js";

// LLM 端点管理：单端点 + 端点池的增删改查、模型拉取、健康检查与连通性测试。
// 状态由 SettingsView 持有（form/llmMode 等），通过 ctx 注入，避免 props 层层透传。
export function useLlmProviders(ctx) {
  const {
    form, llmMode, llmTest,
    singleModels, singleModelsLoading, singleModelsError, testingLlm,
    toast, suppressAutoSave, scheduleAutoSave,
  } = ctx;

  let _providerUidSeq = 1;
  function nextProviderUid() {
    return `llm-uid-${_providerUidSeq++}`;
  }

  function newLlmProvider() {
    return {
      _uid: nextProviderUid(),
      name: `llm-${form.llm_providers.length + 1}`,
      base_url: form.base_url || "https://api.deepseek.com/v1",
      api_key: "",
      api_key_set: false,
      api_key_masked: "",
      key_ref: "",
      health_ref: "",
      model: form.model || "deepseek-chat",
      protocol: form.protocol || "openai_chat",
      temperature: Number(form.temperature ?? 0.3),
      weight: 1,
      enabled: true,
      testing: false,
      models: [],
      modelsLoading: false,
      modelsError: "",
      health: {},
    };
  }

  const selectedLlmProvider = ref(0);
  const selectedLlm = computed(() => form.llm_providers[selectedLlmProvider.value] || null);

  function normalizeLlmProtocol(protocol) {
    return ["auto", "openai_chat", "anthropic_messages"].includes(protocol) ? protocol : "auto";
  }

  function loadLlmProviders(items = [], { resetSelection = true } = {}) {
    form.llm_providers = items.map((provider, idx) => ({
      _uid: provider._uid || nextProviderUid(),
      name: provider.name || `llm-${idx + 1}`,
      base_url: provider.base_url || "",
      api_key: "",
      api_key_set: !!provider.api_key_set,
      api_key_masked: provider.api_key_masked || "",
      key_ref: provider.key_ref || "",
      health_ref: provider.health_ref || "",
      model: provider.model || "",
      protocol: normalizeLlmProtocol(provider.protocol),
      temperature: provider.temperature ?? form.temperature ?? 0.3,
      weight: provider.weight ?? 1,
      enabled: provider.enabled !== false,
      testing: false,
      models: [],
      modelsLoading: false,
      modelsError: "",
      health: provider.health || {},
    }));
    if (resetSelection) {
      selectedLlmProvider.value = form.llm_providers.length ? 0 : -1;
    } else if (!form.llm_providers.length) {
      selectedLlmProvider.value = -1;
    } else {
      selectedLlmProvider.value = Math.min(
        Math.max(selectedLlmProvider.value, 0),
        form.llm_providers.length - 1,
      );
    }
  }

  /** 保存成功后就地合并服务端回写，禁止整表替换（否则选中端点会跳回第 1 个，正在编辑的内容也丢）。 */
  function mergeProvidersAfterSave(saved = [], clearedKeyIndexes = []) {
    const cleared = new Set(clearedKeyIndexes);
    for (let i = 0; i < form.llm_providers.length; i++) {
      const local = form.llm_providers[i];
      const remote = saved[i];
      if (!remote) continue;
      if (cleared.has(i)) local.api_key = "";
      local.api_key_set = !!remote.api_key_set;
      local.api_key_masked = remote.api_key_masked || local.api_key_masked || "";
      local.key_ref = remote.key_ref || local.key_ref || "";
      local.health_ref = remote.health_ref || local.health_ref || "";
      if (remote.health) local.health = remote.health;
    }
  }

  function providerHealthClass(provider) {
    const status = provider.health?.status || "";
    if (["ok", "failed", "cooldown", "half_open"].includes(status)) {
      return status.replace("_", "-");
    }
    return "unknown";
  }

  function providerHealthText(provider) {
    const status = provider.health?.status || "";
    if (status === "ok") return "健康";
    if (status === "failed") return "失效";
    if (status === "cooldown") return "冷却中";
    if (status === "half_open") return "探测中";
    return "未检测";
  }

  function providerHealthTitle(provider) {
    const health = provider.health || {};
    if (!health.last_seen) return "暂无运行时健康记录";
    const parts = [health.last_seen];
    if (health.consecutive_failures) parts.push(`连续失败 ${health.consecutive_failures} 次`);
    if (health.cooldown_until) parts.push(`冷却到 ${health.cooldown_until}`);
    if (health.last_error) parts.push(health.last_error);
    return parts.join("；");
  }

  function addLlmProvider() {
    form.llm_providers.push(newLlmProvider());
    selectedLlmProvider.value = form.llm_providers.length - 1;
    llmTest.value = null;
  }

  function removeLlmProvider(idx) {
    const provider = form.llm_providers[idx];
    if (!provider) return;
    const label = provider.name || provider.model || `端点 #${idx + 1}`;
    if (!confirm(`确认删除模型端点「${label}」？`)) return;
    form.llm_providers.splice(idx, 1);
    if (!form.llm_providers.length) {
      selectedLlmProvider.value = -1;
    } else if (selectedLlmProvider.value > idx) {
      selectedLlmProvider.value -= 1;
    } else if (selectedLlmProvider.value === idx) {
      selectedLlmProvider.value = Math.min(idx, form.llm_providers.length - 1);
    }
    llmTest.value = null;
  }

  function moveLlmProvider(idx, delta) {
    const next = idx + delta;
    if (next < 0 || next >= form.llm_providers.length) return;
    const [provider] = form.llm_providers.splice(idx, 1);
    form.llm_providers.splice(next, 0, provider);
    if (selectedLlmProvider.value === idx) selectedLlmProvider.value = next;
    else if (selectedLlmProvider.value === next) selectedLlmProvider.value = idx;
  }

  function buildLlmProvider(provider) {
    return {
      name: String(provider.name || "").trim(),
      base_url: String(provider.base_url || "").trim(),
      api_key: String(provider.api_key || "").trim(),
      key_ref: provider.key_ref || "",
      model: String(provider.model || "").trim(),
      protocol: normalizeLlmProtocol(provider.protocol),
      temperature: Number(provider.temperature ?? form.temperature ?? 0.3),
      weight: Math.max(1, Math.min(100, Number(provider.weight || 1))),
      enabled: provider.enabled !== false,
    };
  }

  function buildLlmProviders() {
    return form.llm_providers.map(buildLlmProvider);
  }

  function invalidateSingleKey() {
    form.key_ref = "";
    form.api_key_set = false;
    singleModels.value = [];
    singleModelsError.value = "";
    llmTest.value = null;
  }

  function invalidateProviderKey(provider) {
    if (!provider) return;
    provider.key_ref = "";
    provider.api_key_set = false;
    provider.api_key_masked = "";
    provider.health_ref = "";
    provider.health = {};
    provider.models = [];
    provider.modelsError = "";
    llmTest.value = null;
  }

  function validateLlmProviders() {
    if (llmMode.value !== "pool") {
      if (!String(form.base_url || "").trim() || !String(form.model || "").trim()
        || (!String(form.api_key || "").trim() && !form.key_ref)) {
        throw new Error("单端点配置缺少 base_url、api_key 或模型");
      }
      return;
    }
    if (!form.llm_providers.length) throw new Error("端点池至少需要一个端点");
    for (const [idx, provider] of buildLlmProviders().entries()) {
      if (!provider.name || !provider.base_url || !provider.model || (!provider.api_key && !provider.key_ref)) {
        throw new Error(`LLM 端点 #${idx + 1} 缺少名称、base_url、api_key 或模型`);
      }
    }
    if (!form.llm_providers.some((provider) => provider.enabled !== false)) {
      throw new Error("端点池至少需要启用一个端点");
    }
  }

  function resultText(item) {
    if (!item) return "";
    const parts = [];
    if (item.protocol) parts.push(item.protocol);
    if (item.model) parts.push(item.model);
    if (item.latency_ms) parts.push(`${item.latency_ms}ms`);
    if (item.status_code) parts.push(`HTTP ${item.status_code}`);
    if (item.ok && item.reply) parts.push(`reply: ${item.reply}`);
    if (item.ok && item.tool_calling) {
      const tc = {
        yes: "工具调用 ✓",
        no: "工具调用 ✗ 不支持原生 function calling（系统会自动用提示词模拟兜底；如仍异常可设 RIDDLE_TOOL_COMPAT=prompt）",
        unknown: "工具调用 ? 未检测到（若挖洞全程不调用工具，可设 RIDDLE_TOOL_COMPAT=prompt 强制模拟）",
      };
      parts.push(tc[item.tool_calling] || "");
    }
    if (!item.ok && item.error) parts.push(item.error);
    return parts.filter(Boolean).join(" · ");
  }

  async function copyLlmTest(item) {
    const text = item ? formatLlmTestCopy({ ok: item.ok, results: [item], error_copy: item.error_copy }) : formatLlmTestCopy(llmTest.value || {});
    const ok = await copyText(text);
    toast(ok ? "已复制 LLM 错误信息" : "复制失败，请手动选中");
  }

  function applyLlmHealthResults(results = []) {
    for (const item of results) {
      const provider = form.llm_providers.find((row) =>
        (row.name && item.name && row.name === item.name)
        || (row.base_url === item.base_url && row.model === item.model)
      );
      if (!provider) continue;
      provider.health = {
        status: item.ok ? "ok" : "failed",
        last_seen: new Date().toISOString(),
        last_error: item.ok ? "" : (item.error || "测试失败"),
      };
    }
  }

  async function refreshProviderHealth() {
    if (llmMode.value !== "pool" || !form.llm_providers.length) return;
    const res = await api.providerHealth();
    const byRef = new Map((res.providers || []).map((item) => [item.health_ref, item.health || {}]));
    suppressAutoSave.value = true;
    try {
      for (const provider of form.llm_providers) {
        if (provider.health_ref && byRef.has(provider.health_ref)) {
          provider.health = byRef.get(provider.health_ref);
        }
      }
    } finally {
      await nextTick();
      suppressAutoSave.value = false;
    }
  }

  // —— 端点池调度优化：主动健康检查 + 权重命中分布预览（与新建任务模型方案同步） ——
  const healthLoading = ref(false);
  const schedulePreview = ref(null);
  const scheduleLoading = ref(false);

  async function refreshHealthActive() {
    if (llmMode.value !== "pool" || !form.llm_providers.length) return;
    healthLoading.value = true;
    try {
      const res = await api.providerHealthCheck(
        form.llm_providers.map((p) => ({
          name: p.name,
          base_url: p.base_url,
          model: p.model,
          api_key: p.api_key,
          protocol: p.protocol,
        }))
      );
      const byName = new Map((res?.providers || []).map((item) => [item.name, item.health || {}]));
      suppressAutoSave.value = true;
      try {
        for (const provider of form.llm_providers) {
          const h = byName.get(provider.name);
          if (h) provider.health = { ...(provider.health || {}), ...h };
        }
      } finally {
        await nextTick();
        suppressAutoSave.value = false;
      }
    } catch (e) {
      // 主动检查失败不打断编辑，保留上次运行时健康数据
    } finally {
      healthLoading.value = false;
    }
  }

  async function refreshSchedule() {
    if (llmMode.value !== "pool" || !form.llm_providers.length) {
      schedulePreview.value = null;
      return;
    }
    scheduleLoading.value = true;
    try {
      const res = await api.poolSchedulePreview(
        form.llm_providers.map((p) => ({ name: p.name, weight: p.weight, enabled: p.enabled !== false }))
      );
      schedulePreview.value = res;
    } catch (e) {
      schedulePreview.value = null;
    } finally {
      scheduleLoading.value = false;
    }
  }

  watch(
    () => form.llm_providers.map((p) => `${p.name}|${p.weight}|${p.enabled !== false}`).join(","),
    () => refreshSchedule(),
    { immediate: true },
  );

  async function loadSingleModels() {
    singleModelsLoading.value = true;
    singleModelsError.value = "";
    try {
      const res = await api.listModels({
        base_url: form.base_url,
        api_key: form.api_key.trim(),
        key_ref: form.key_ref,
        model: form.model,
        protocol: form.protocol,
      });
      if (res?.ok && res.models?.length) {
        singleModels.value = res.models;
        if (!form.model || !singleModels.value.includes(form.model)) form.model = singleModels.value[0];
        toast(`已获取 ${res.models.length} 个模型`);
      } else {
        singleModels.value = [];
        singleModelsError.value = res?.error || "未获取到模型列表";
        toast("获取模型失败");
      }
    } catch (e) {
      singleModels.value = [];
      singleModelsError.value = String(e.message || e).replace(/^\d+\s*/, "");
      toast("获取模型失败");
    } finally {
      singleModelsLoading.value = false;
    }
  }

  async function loadProviderModels(idx) {
    const provider = form.llm_providers[idx];
    if (!provider) return;
    // 用 _uid 锚定：请求期间用户若主动换端点，结束时不抢回选中态
    const keepUid = provider._uid;
    const keepSelected = selectedLlmProvider.value;
    suppressAutoSave.value = true;
    provider.modelsLoading = true;
    provider.modelsError = "";
    try {
      const res = await api.listModels({
        base_url: provider.base_url,
        api_key: String(provider.api_key || "").trim(),
        protocol: provider.protocol,
        key_ref: provider.key_ref,
        model: provider.model,
      });
      if (res?.ok && res.models?.length) {
        provider.models = res.models;
        if (!provider.model || !provider.models.includes(provider.model)) provider.model = provider.models[0];
        toast(`已获取 ${res.models.length} 个模型`);
      } else {
        provider.models = [];
        provider.modelsError = res?.error || "未获取到模型列表";
        toast(`端点 #${idx + 1} 获取模型失败`);
      }
    } catch (e) {
      provider.models = [];
      provider.modelsError = String(e.message || e).replace(/^\d+\s*/, "");
      toast(`端点 #${idx + 1} 获取模型失败`);
    } finally {
      provider.modelsLoading = false;
      const nowUid = form.llm_providers[selectedLlmProvider.value]?._uid;
      // 仅当选中仍是发起查询的端点、或被副作用冲掉时，才按 uid 纠正索引
      if (nowUid === keepUid || selectedLlmProvider.value === keepSelected) {
        const found = form.llm_providers.findIndex((p) => p._uid === keepUid);
        if (found >= 0) selectedLlmProvider.value = found;
      }
      suppressAutoSave.value = false;
      scheduleAutoSave(); // 可能自动选中了模型
    }
  }

  async function testSingleLlm() {
    testingLlm.value = true;
    llmTest.value = null;
    try {
      const res = await api.testLLM({
        base_url: form.base_url,
        api_key: form.api_key.trim(),
        key_ref: form.key_ref,
        model: form.model,
        protocol: form.protocol,
        temperature: Number(form.temperature),
      });
      llmTest.value = res;
      toast(res.ok ? "LLM 测试通过" : "LLM 测试失败");
    } catch (e) {
      llmTest.value = { ok: false, results: [], error: String(e.message || e).replace(/^\d+\s*/, "") };
      toast("LLM 测试失败");
    } finally {
      testingLlm.value = false;
    }
  }

  async function testLlmProvider(idx) {
    const provider = form.llm_providers[idx];
    if (!provider) return;
    suppressAutoSave.value = true;
    provider.testing = true;
    llmTest.value = null;
    try {
      const payload = buildLlmProvider(provider);
      if (!payload.base_url || !payload.model || (!payload.api_key && !payload.key_ref)) {
        throw new Error(`LLM 端点 #${idx + 1} 配置不完整`);
      }
      const res = await api.testLLM({ providers: [payload] });
      llmTest.value = res;
      applyLlmHealthResults(res.results || []);
      toast(res.ok ? `端点 #${idx + 1} 测试通过` : `端点 #${idx + 1} 测试失败`);
    } catch (e) {
      llmTest.value = { ok: false, results: [], error: String(e.message || e).replace(/^\d+\s*/, "") };
      toast(`端点 #${idx + 1} 测试失败`);
    } finally {
      provider.testing = false;
      await nextTick();
      suppressAutoSave.value = false;
    }
  }

  return {
    llmMode,
    llmTest,
    selectedLlmProvider,
    selectedLlm,
    testingLlm,
    normalizeLlmProtocol,
    loadLlmProviders,
    mergeProvidersAfterSave,
    providerHealthClass,
    providerHealthText,
    providerHealthTitle,
    addLlmProvider,
    removeLlmProvider,
    moveLlmProvider,
    buildLlmProvider,
    buildLlmProviders,
    invalidateSingleKey,
    invalidateProviderKey,
    validateLlmProviders,
    resultText,
    copyLlmTest,
    applyLlmHealthResults,
    refreshProviderHealth,
    healthLoading,
    refreshHealthActive,
    schedulePreview,
    scheduleLoading,
    refreshSchedule,
    loadSingleModels,
    loadProviderModels,
    testSingleLlm,
    testLlmProvider,
  };
}
