// 目标凭据绑定（auth bindings）的共享逻辑：新建/编辑任务（CreateTaskModal 三步向导）
// 共用。返回同一个 authBindings ref 与同名函数，调用方的
// watch / v-model / loadAuthBindings 都作用在同一身份上。
import { ref, computed } from "vue";

export function emptyBinding() {
  return {
    target: "*", raw: "", username: "", password: "",
    cookie: "", authorization: "", login_url: "", note: "",
  };
}

const KIND_LABELS = { cookie: "Cookie", bearer: "Bearer", password: "账密" };
export function kindLabel(k) {
  return KIND_LABELS[k] || k;
}

// 行内实时类型识别（与后端 normalize_binding 的 kinds 口径一致，纯前端预览用）
export function bindingKinds(b) {
  const raw = b?.raw || "";
  const kinds = [];
  if ((b?.cookie || "").trim() || /Cookie\s*:/i.test(raw)) kinds.push("cookie");
  if ((b?.authorization || "").trim() || /Authorization\s*:/i.test(raw) || /Bearer\s+\S+/i.test(raw)) kinds.push("bearer");
  if (((b?.username || "").trim() && (b?.password || "").trim()) || /(密码|password|passwd|pwd)\s*[:=：]/i.test(raw)) kinds.push("password");
  return kinds;
}

function bindingKey(b) {
  return [
    (b.target || "*").trim() || "*",
    (b.username || "").trim(),
    (b.password || "").trim(),
    (b.cookie || "").trim(),
    (b.authorization || "").trim(),
  ].join("\u0001");
}

function isEmptyBinding(b) {
  return !(b.username || b.password || b.cookie || b.authorization || b.raw || (b.target && b.target.trim() && b.target.trim() !== "*"));
}

/**
 * @param {() => string} manualTargetsGetter 返回“手动目标清单”多行文本（各组件的 form.manual_targets）
 * @param {(v: string) => void} [manualTargetsSetter] 写回“手动目标清单”（批量导入时自动补目标用）
 */
export function useAuthBindings(manualTargetsGetter, manualTargetsSetter) {
  const authBindings = ref([emptyBinding()]);

  const manualTargetLines = computed(() =>
    String(manualTargetsGetter() || "").split("\n").map((s) => s.trim()).filter(Boolean)
  );

  // 取一行手动清单里的目标 token（行首第一个空白分隔段，忽略备注）
  function lineTarget(line) {
    return String(line).split(/\s+/)[0].trim();
  }

  const bindingOptions = computed(() => {
    const opts = [{ value: "*", label: "*（全部目标默认）" }];
    const seen = new Set(["*"]);
    for (const line of manualTargetLines.value) {
      if (!seen.has(line)) { seen.add(line); opts.push({ value: line, label: line }); }
    }
    for (const b of authBindings.value) {
      const t = (b.target || "").trim();
      if (t && !seen.has(t)) { seen.add(t); opts.push({ value: t, label: t }); }
    }
    return opts;
  });

  function addBinding() {
    authBindings.value.push(emptyBinding());
  }
  function removeBinding(i) {
    authBindings.value.splice(i, 1);
    if (!authBindings.value.length) authBindings.value.push(emptyBinding());
  }
  function clearBindings() {
    authBindings.value = [emptyBinding()];
  }
  function exportAuthBindings() {
    return authBindings.value
      .map((b) => ({
        target: (b.target || "*").trim() || "*",
        username: (b.username || "").trim(),
        password: (b.password || "").trim(),
        cookie: (b.cookie || "").trim(),
        authorization: (b.authorization || "").trim(),
        login_url: (b.login_url || "").trim(),
        raw: (b.raw || "").trim(),
        note: (b.note || "").trim(),
      }))
      .filter((b) => b.username || b.password || b.cookie || b.authorization || b.raw);
  }

  // 批量导入：把后端 /parse-auth-batch 返回的归一化绑定并入列表（去重，跳过空凭据），
  // 并把导入凭据里出现但手动清单缺失的目标自动补进清单。
  // 返回 { added, targetsAdded }。
  function importBindings(list) {
    const rows = (list || []).filter((b) => b && (b.username || b.password || b.cookie || b.authorization));
    if (!rows.length) return { added: 0, targetsAdded: 0 };
    const existing = new Set(authBindings.value.map(bindingKey));
    const added = [];
    for (const r of rows) {
      const nb = {
        target: (r.target || "*").trim() || "*",
        raw: "",
        username: (r.username || "").trim(),
        password: (r.password || "").trim(),
        cookie: (r.cookie || "").trim(),
        authorization: (r.authorization || "").trim(),
        login_url: (r.login_url || "").trim(),
        note: (r.note || "").trim(),
      };
      const key = bindingKey(nb);
      if (existing.has(key)) continue;
      existing.add(key);
      added.push(nb);
    }
    if (added.length) {
      if (authBindings.value.length === 1 && isEmptyBinding(authBindings.value[0])) {
        authBindings.value = added;
      } else {
        authBindings.value = [...authBindings.value, ...added];
      }
    }
    const targetsAdded = syncTargetsToManual(rows);
    return { added: added.length, targetsAdded };
  }

  // 把导入凭据里出现但手动清单缺失的目标追加进清单（保持清单与凭据目标一致）
  function syncTargetsToManual(rows) {
    if (!manualTargetsSetter) return 0;
    const manual = manualTargetLines.value.map(lineTarget).filter(Boolean);
    const missing = [];
    for (const r of rows) {
      const t = (r.target || "").trim();
      if (t && t !== "*" && !manual.includes(t)) {
        manual.push(t);
        missing.push(t);
      }
    }
    if (!missing.length) return 0;
    const cur = String(manualTargetsGetter() || "").trim();
    const add = [...new Set(missing)];
    manualTargetsSetter(cur ? cur + "\n" + add.join("\n") : add.join("\n"));
    return add.length;
  }

  // 批量导入预览列表的摘要（密码打码，仅展示）
  function bindingSummary(b) {
    const parts = [];
    if (b.target && b.target !== "*") parts.push(b.target);
    if (b.username) parts.push(`${b.username} / ${b.password ? "••••" : ""}`);
    if (b.cookie) parts.push(`Cookie ${(b.cookies && Object.keys(b.cookies).length) || 1} 项`);
    if (b.authorization) parts.push("Bearer");
    return parts.join(" · ") || "凭据";
  }

  return {
    authBindings,
    addBinding,
    removeBinding,
    clearBindings,
    importBindings,
    bindingSummary,
    bindingKinds,
    kindLabel,
    exportAuthBindings,
    bindingOptions,
  };
}
