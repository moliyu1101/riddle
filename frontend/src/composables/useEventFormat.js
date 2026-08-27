import { isLlmErrorEvent } from "../clipboard.js";

// 实时事件分类：活动流只展示里程碑；tool/thought 等细节静默缓冲，点击行再展开。
export const IMPORTANT_KINDS = new Set([
  "collector_phase",
  "finding_submitted", "finding_duplicate", "finding_invalid",
  "worker_start", "worker_finish", "worker_cancelled", "worker_auto_finish",
  "target_done", "target_requeued", "timeout", "auto_deepen", "salvage",
  "review_start", "review_done", "review_error", "review_deferred", "review_cancelled",
  "reproduce_start", "reproduce_done",
  "killsweep_start", "killsweep_done", "killsweep_error", "killsweep_dedup",
  "killsweep_invalid", "killsweep_cancelled", "killsweep_retry",
  "llm_error", "llm_soft_retry", "llm_interrupt", "worker_resume", "llm_provider_failed", "quota_stop", "reclaim", "recover", "workers_cancelled",
  "tool_exception",
  "auth_status",
  "escalate_start", "escalate_done", "escalate_skip", "escalate_cancelled", "escalate_error", "escalate_abandon",
  "worker_directive", "worker_directive_queued",
]);
export const NOISE_KINDS = new Set([
  "ping",
  "tool_http", "tool_shell", "tool_shell_blocked", "tool_arg_error",
  "tool_js_analyze", "tool_decode", "tool_waf_advice", "tool_fofa_lookup", "tool_session_set",
  "tool_asset_discovery", "tool_fingerprint",
  "tool_credential_brute", "tool_login_session", "tool_login_form_scan",
  "tool_http_batch", "tool_diff_response", "tool_timing_probe", "tool_crawl_links",
  "tool_sqli_probe", "tool_upload_probe", "tool_access_boundary",
  "tool_path_probe", "tool_injection_probe",
  "tool_capture_evidence",
  "tool_verify_known_vuln",
  "tool_update_cognition", "worker_reflect",
  "worker_thought", "intel_reported", "js_analyzer_enabled",
  "killsweep_fofa", "killsweep_http", "killsweep_shell",
  "escalate_http", "escalate_shell", "escalate_session",
  "llm_round_start",
  "refill", "cluster_cooldown_skip", "skip",
]);
export const LOG_INFO_IMPORTANT = new Set([
  "target_done", "target_requeued", "timeout", "auto_deepen", "salvage",
  "review_done", "review_deferred", "review_cancelled",
  "reclaim", "recover", "workers_cancelled", "quota_stop",
  "killsweep_done", "killsweep_dedup", "killsweep_error", "killsweep_cancelled", "killsweep_retry",
  "escalate_done", "escalate_skip", "escalate_cancelled",
]);
export const TRACE_KINDS = new Set([
  ...NOISE_KINDS,
  "worker_start", "worker_finish", "worker_cancelled", "worker_auto_finish",
  "worker_thought", "worker_directive", "worker_resume",
  "llm_round_start", "llm_error", "llm_soft_retry", "llm_interrupt",
  "finding_submitted", "finding_duplicate", "finding_invalid",
  "tool_exception", "auth_status", "finish_blocked",
]);
export const DETAIL_KINDS = new Set([
  "tool_http", "tool_shell", "tool_shell_blocked", "tool_arg_error",
  "tool_js_analyze", "tool_decode", "tool_waf_advice", "tool_fofa_lookup", "tool_session_set",
  "tool_asset_discovery", "tool_fingerprint",
  "tool_credential_brute", "tool_login_session", "tool_login_form_scan",
  "tool_http_batch", "tool_diff_response", "tool_timing_probe", "tool_crawl_links",
  "tool_sqli_probe", "tool_upload_probe", "tool_access_boundary",
  "tool_path_probe", "tool_injection_probe",
  "tool_capture_evidence",
  "tool_verify_known_vuln",
  "tool_update_cognition", "worker_reflect",
  "worker_thought", "worker_directive", "llm_round_start", "llm_error", "llm_soft_retry",
  "tool_exception", "finish_blocked", "auth_status",
]);

export const AGENT_ICON = { orchestrator: "◆", collector: "🛰", worker: "⚔", reviewer: "⚖", killsweep: "◇", escalation: "⬆" };
export const AGENT_LABEL = { orchestrator: "主控", collector: "搜集", worker: "挖掘", reviewer: "审核", killsweep: "通杀", escalation: "扩大危害" };

// 每条轨迹分配一个稳定唯一 id，作为渲染 key：既保证 TransitionGroup 只对真正新增
// 的那条做进入动画，也彻底避免「重复内容 → 重复 key → Vue diff 崩坏」导致的卡顿。
let _traceUid = 0;

export function nextTraceUid() {
  return ++_traceUid;
}

export function phaseLabel(phase) {
  return ({
    prefilter: "探活预筛",
    scoring: "评分归属",
    target_filter: "正在跑过滤器阶段",
    enrich: "补充情报",
    dispatch: "入队完成",
  }[phase] || phase || "");
}

export function parseEventTs(ts) {
  if (!ts) return null;
  // 后端时间统一是 UTC。带时区标识（Z/+/-）直接解析；
  // 万一是无时区的 naive 串（如 2026-06-27T02:29:00），按 UTC 补 Z，避免被当本地时区差 8 小时。
  const hasTz = /[zZ]$|[+-]\d{2}:?\d{2}$/.test(ts);
  const d = new Date(hasTz ? ts : `${ts}Z`);
  if (Number.isNaN(d.getTime())) return null;
  return d;
}

export function evTime(ts) {
  const d = parseEventTs(ts);
  if (!d) return "-";
  return d.toLocaleTimeString("zh-CN", { hour12: false });
}

export function eventRawTs(ev) {
  return ev?.ts || ev?.created_at || ev?.createdAt || ev?.timestamp || ev?.time || "";
}

export function streamEventStableKey(ev) {
  const text = ev?._text || ev?.message || ev?.kind || "";
  return [
    ev?.agent || "",
    ev?.kind || "",
    ev?.level || "",
    ev?.target_id || "",
    ev?.round || "",
    text,
    ev?.error || "",
  ].join("|");
}

// 去重键：落库 ts 与实时推送 ts 常有毫秒级差异（同一事件两个副本），
// 用「kind + 轮次 + 文案 + 秒级时间」而非精确 ts 归并，才能真正去掉重复行。
export function traceDedupKey(ev) {
  const parsed = parseEventTs(ev._displayTs || ev.ts);
  const sec = parsed ? Math.floor(parsed.getTime() / 1000) : 0;
  const text = ev._text || ev.message || ev.kind || "";
  return `${ev.kind || ""}|${ev.round || ""}|${text}|${sec}`;
}

export function evEpoch(ev) {
  const parsed = parseEventTs(ev._displayTs || ev.ts);
  return parsed ? parsed.getTime() : 0;
}

export function evClass(ev) {
  return `ev ${ev.level || "info"}`;
}

// kind → 语义类别：决定时间线节点的颜色与图标，让长轨迹一眼可扫。
const _EV_CAT = {
  finding_submitted: "hit",
  worker_thought: "thought",
  worker_directive: "directive", worker_directive_queued: "directive",
  worker_finish: "done", worker_auto_finish: "done", review_done: "done",
  reproduce_done: "done", escalate_done: "done", killsweep_done: "done",
  worker_cancelled: "muted", review_cancelled: "muted", escalate_cancelled: "muted",
  escalate_skip: "muted", escalate_abandon: "muted", finding_duplicate: "muted",
  duplicate_checked: "muted", killsweep_dedup: "muted", killsweep_invalid: "muted",
  finding_invalid: "warn", llm_soft_retry: "warn", llm_interrupt: "warn", review_deferred: "warn",
  llm_error: "error", llm_provider_failed: "error", tool_exception: "error",
  tool_arg_error: "error", tool_shell_blocked: "error", review_error: "error",
  killsweep_error: "error", escalate_error: "error",
  worker_start: "phase", worker_resume: "phase", llm_round_start: "phase",
  collector_phase: "phase", review_start: "phase", reproduce_start: "phase",
  escalate_start: "phase", killsweep_start: "phase", killsweep_retry: "phase",
  auth_status: "auth",
};
const _CAT_ICON = {
  hit: "◆", thought: "∘", directive: "▸", done: "✓", error: "✕",
  warn: "!", phase: "○", auth: "◈", action: "›", muted: "·", neutral: "·",
};

export function evCat(ev) {
  const k = ev?.kind || "";
  if (_EV_CAT[k]) return _EV_CAT[k];
  if (k.startsWith("tool_") || k.startsWith("escalate_")) return "action";
  return "neutral";
}

export function evIcon(cat) {
  return _CAT_ICON[cat] || "·";
}

// 稳定唯一 key：优先用入库时分配的 _uid（保证唯一且跨刷新稳定），
// 这样 TransitionGroup 只对真正新增的那条做进入动画，绝不会因重复内容撞 key。
export function evKey(ev) {
  if (ev?._uid != null) return `u${ev._uid}`;
  return `${ev?.ts || ""}|${ev?.kind || ""}|${ev?.round || ""}|${ev?._text || ev?.message || ""}`;
}

export function eventExpandKey(ev) {
  if (ev?._uid != null) return `u${ev._uid}`;
  return streamEventStableKey(ev);
}

export function canExpandEvent(ev) {
  return !!(ev?.target_id);
}

export function isImportantEvent(ev) {
  const kind = ev.kind || "";
  if (kind === "ping") return false;
  if (ev.level === "error" || ev.level === "warn") return true;
  if (NOISE_KINDS.has(kind)) return false;
  if (IMPORTANT_KINDS.has(kind)) return true;
  if (kind === "duplicate_checked") return !!ev.duplicate;
  if (ev.message && LOG_INFO_IMPORTANT.has(kind)) return true;
  if (ev.message && kind === "error") return true;
  return false;
}

// 英文枚举 → 中文（事件流展示用，避免用户看到 raw 值）
const _LLM_KIND_CN = {
  upstream: "上游服务异常", quota: "额度不足", auth: "密钥无效", blocked: "安全策略拦截",
  rate_limit: "被限流", invalid_request: "请求参数有误", timeout: "请求超时",
  network: "网络异常", unknown: "未知错误",
};
const _ENUM_TYPE_CN = { subdomain: "子域名", path: "路径", same_ip: "同 IP" };
const _WAF_CTX_CN = { generic: "通用", sqli: "SQL 注入", xss: "XSS", path: "路径", json: "JSON", header: "请求头" };
const _DECODE_MODE_CN = { auto: "自动", base64: "Base64", hex: "Hex", url: "URL", jwt: "JWT", hash: "哈希" };

// 把任意事件格式化为一句人话（worker 动作事件本身没有 message）。
// engineRef 用于 tool_fofa_lookup 的引擎名展示（依赖任务配置）。
export function useEventFormat(engineRef) {
  function fmtEvent(ev, full = false) {
    // 注意：不能优先返回 ev.message —— 后端落库时对无 message 的事件会把英文 kind 写进
    // message（如 worker_start），直接返回会显示英文。先走 switch 中文 case，default 再回退 message。
    // full 模式（展开细节用）不截断；主列表紧凑截断。
    const cap = (s, n) => String(s ?? "").slice(0, full ? 4000 : n);
    const d = ev;
    switch (ev.kind) {
      case "worker_start": return `开始挖掘 ${d.target || ""}${d.mode === "deepen" ? "（定向深挖）" : ""}`;
      case "collector_phase": return d.message || phaseLabel(d.phase) || "正在跑过滤器阶段";
      case "finding_submitted": return `🎯 发现漏洞 [${d.severity || ""}] ${d.title || ""}`;
      case "duplicate_checked": return d.duplicate ? `查重命中重复：${d.title || ""}` : null;
      case "finding_duplicate": return `重复漏洞已拦截：${d.title || ""}`;
      case "finding_invalid": return `漏洞提交格式有误，重新提交中`;
      case "worker_finish": {
        const verdictCn = ({ found: "已出洞", no_vuln: "未发现漏洞", error: "异常结束", cancelled: "已取消" })[d.verdict] || d.verdict || "";
        return `收尾：${verdictCn}`;
      }
      case "worker_auto_finish": {
        const verdictCn = ({ found: "已出洞", no_vuln: "未发现漏洞", error: "异常结束", cancelled: "已取消" })[d.verdict] || d.verdict || "";
        const summary = (d.summary || "").trim();
        const text = summary ? `${summary}（${verdictCn}）` : verdictCn;
        return cap(`自动收尾：${text}`, 140);
      }
      case "worker_cancelled": return `挖掘已取消：${d.target || ""}`;
      case "review_start": return `开始审核：${d.title || ""}`;
      case "review_done": {
        const verdictCn = ({ accepted: "采纳", ignored: "忽略", deepen: "深挖", rejected: "驳回", pending_review: "待审" })[d.verdict] || d.verdict || "";
        const confCn = ({ confirmed: "确认", likely: "疑似", uncertain: "不确定" })[d.confidence] || d.confidence || "";
        const score = d.score > 0 ? ` · 评分 ${d.score}` : "";
        return `审核完成：${verdictCn}${confCn ? ` · ${confCn}` : ""}${score}`;
      }
      case "review_error": return `审核异常：${cap(d.error, 120)}`;
      case "review_deferred": return `审核暂缓，稍后重试`;
      case "review_cancelled": return `审核已取消`;
      case "reproduce_start": return `复现验证：${d.title || ""}`;
      case "reproduce_done": return `复现${d.reproduced ? "成功" : "未证实"}：${d.title || ""}`;
      case "killsweep_start": return `通杀 Hunter 启动：${d.title || ""}`;
      case "killsweep_done": return `通杀分析完成：${d.product || ""} · ${d.is_killsweep ? "可通杀" : "不可通杀"}`;
      case "killsweep_error": return `通杀分析异常：${cap(d.error, 120)}`;
      case "killsweep_dedup": return `通杀分析去重：${d.product || ""}`;
      case "killsweep_invalid": return `通杀记录已标记无效：${d.product || ""}`;
      case "killsweep_retry": return `手动重启通杀分析：${d.product || d.title || ""}`;
      case "llm_error": {
        // 后端错误文案可能已带「LLM 调用失败：」前缀，去掉避免双重前缀
        const err = cap(d.error, 180).replace(/^LLM 调用失败[：:]\s*/, "");
        return `⚠ LLM 调用失败：${err}`;
      }
      case "llm_soft_retry": {
        // 注意：d.kind 是事件类型（恒为 llm_soft_retry），真正的失败类别在 failure_kind
        const kindCn = _LLM_KIND_CN[d.failure_kind || d.kind] || d.failure_kind || d.kind || "未知";
        return `LLM 调用失败，自动重试 ${d.attempt || "?"}/${d.max_attempts || "?"}（${kindCn}，等 ${d.wait_seconds || 0} 秒）：${cap(d.error, 180)}`;
      }
      case "llm_interrupt": {
        const saved = d.has_resume ? "，进度已保存可断点续挖" : "，进度未保存";
        return `LLM 中断${saved}：${cap(d.error, 180)}`;
      }
      case "worker_resume": return `断点续挖：恢复笔记 ${d.notes_len || 0} 字 / cookie ${(d.cookies || []).length} / 头 ${(d.headers || []).length}`;
      case "llm_provider_failed": {
        const kindCn = _LLM_KIND_CN[d.error_kind] || d.error_kind || "未知";
        return `LLM 端点失败：${d.model || ""} @ ${d.base_url || ""}（${kindCn}）${d.error ? ` · ${d.error}` : ""}`;
      }
      case "tool_exception": return `工具执行异常：${d.tool || ""} ${cap(d.error, 80)}`;
      case "tool_http": return `HTTP ${d.method || "GET"} ${d.url || ""}`;
      case "tool_shell": return `$ ${cap(d.command, 160)}`;
      case "tool_shell_blocked": return `已拦截命令：${cap(d.reason || d.command, 120)}`;
      case "tool_arg_error": return `工具参数有误：${d.tool || ""} ${cap(d.error, 80)}`;
      case "tool_js_analyze": return `JS 分析：${cap(d.url, 120)}`;
      case "tool_decode": return `解码：${_DECODE_MODE_CN[d.mode] || d.mode || "自动"}`;
      case "tool_waf_advice": return `WAF 建议：${_WAF_CTX_CN[d.context] || d.context || "通用"}`;
      case "tool_fofa_lookup": {
        const eng = ({
          fofa: "FOFA", quake: "360 Quake", hunter: "Hunter",
          zoomeye: "ZoomEye", shodan: "Shodan", censys: "Censys",
        })[engineRef.value?.engine] || engineRef.value?.engine || "测绘";
        return `${eng}：${cap(d.query, 100)}`;
      }
      case "tool_session_set": return `会话状态已更新`;
      case "tool_asset_discovery": return `资产发现：${cap(d.target || d.url, 120)}（${_ENUM_TYPE_CN[d.enum_type] || d.enum_type || "子域名"}）`;
      case "tool_fingerprint": return `指纹识别：${cap(d.url, 120)}`;
      case "tool_credential_brute": return `弱口令尝试：${cap(d.login_url, 120)}（${d.username || ""}）`;
      case "tool_login_session": return `登录态保持：${cap(d.login_url, 120)}（${d.username || ""}）`;
      case "tool_login_form_scan": return `登录入口侦察：${cap(d.url, 120)}`;
      case "tool_http_batch": return `批量请求：${cap(d.url, 100)}（${d.range || ""}）`;
      case "tool_diff_response": return `参数差异对比：${cap(d.url, 120)}`;
      case "tool_timing_probe": return `响应耗时测量：${cap(d.url, 120)}（±${d.samples || ""} 次）`;
      case "tool_crawl_links": return `链接抓取：${cap(d.url, 120)}`;
      case "tool_sqli_probe": return `SQL 注入探测：${cap(d.url, 100)}（${d.param_name || ""}）`;
      case "tool_upload_probe": return `上传接口探测：${cap(d.url, 120)}`;
      case "tool_path_probe": return `路径/备份探测：${cap(d.url, 120)}`;
      case "tool_injection_probe": return `注入探针：${cap(d.url, 100)}（${d.param_name || ""}）`;
      case "tool_access_boundary": return `权限边界测试：${cap(d.url, 120)}`;
      case "tool_capture_evidence": return `存证快照：${cap(d.url, 120)}`;
      case "tool_verify_known_vuln": return `已知漏洞实测：${cap(d.vuln_name, 60)} @ ${cap(d.url, 80)}`;
      case "tool_update_cognition": {
        const slotCn = ({ confirmed: "已确认", excluded: "已排除", leads: "线索", plan: "计划" })[d.slot] || d.slot || "";
        return `认知更新（${slotCn}）：${cap(d.text, 80)}`;
      }
      case "worker_reflect": return `🔄 周期复盘（第 ${d.round || "?"} 轮）`;
      case "worker_thought": return `💭 ${cap(d.text, 200)}`;
      case "worker_directive": return `🎛 执行人工指令：${cap(d.text, 160)}`;
      case "worker_directive_queued": return d.message || `人工指令已排队：${cap(d.text, 120)}`;
      case "llm_round_start": return `第 ${d.round || "?"} 轮 LLM 推理`;
      case "escalate_start": return `扩大危害启动：${d.title || ""}`;
      case "escalate_done": return `扩大危害完成：${d.title || ""} · ${d.severity || ""}`;
      case "escalate_skip": return d.message || `扩大危害未显著，已放弃`;
      case "escalate_cancelled": return d.message || `扩大危害已取消`;
      case "escalate_error": return `扩大危害异常：${cap(d.error, 120)}`;
      case "escalate_abandon": return `扩大危害已放弃：${cap(d.reason, 120)}`;
      case "escalate_http": return `扩大危害 HTTP ${cap(d.url, 120)}`;
      case "escalate_shell": return `扩大危害 $ ${cap(d.command, 120)}`;
      case "escalate_session": return `扩大危害会话更新（cookie ${d.has_cookies ? "有" : "无"} / 头 ${d.has_headers ? "有" : "无"}）`;
      case "coverage_reported": return `覆盖率上报：${d.route || ""}（${d.endpoints || 0} 个端点）`;
      case "blackboard_publish": {
        const confCn = ({ high: "高", medium: "中", low: "低" })[d.confidence] || "";
        return `黑板共享[${d.key || ""}]${confCn ? `（${confCn}可信）` : ""}：${cap(d.value, 140)}`;
      }
      case "blackboard_declare": return `黑板分工：${cap(d.direction, 120)}`;
      case "finding_needs_more_evidence": return `证据不足，打回补证：${d.title || ""}`;
      case "finding_out_of_scope": return `超出范围已拦截：${d.title || ""}`;
      case "finish_blocked": return `收尾被拦：${cap(d.reason, 120)}`;
      case "intel_reported": {
        const intelCn = ({ cred: "凭证", fingerprint: "打法", endpoint: "端点", profile: "画像", lesson: "经验" })[d.intel_kind] || d.intel_kind || "";
        return `情报上报：${intelCn}`;
      }
      case "js_analyzer_enabled": return `JS 分析已开启`;
      case "killsweep_fofa": return `通杀 FOFA：${cap(d.query, 100)}`;
      case "killsweep_http": return `通杀 HTTP：${cap(d.url, 120)}`;
      case "killsweep_shell": return `通杀 $ ${cap(d.command, 160)}`;
      case "provider_degrade_error": {
        const kindCn = _LLM_KIND_CN[d.failure_kind] || d.failure_kind || "未知";
        return `LLM 提供商降级（${kindCn}）：${cap(d.error, 120)}`;
      }
      case "provider_health_error": return `LLM 提供商健康异常：${cap(d.error, 120)}`;
      case "reproduce_conflict": return `复现冲突：${d.title || ""}（确定性信号 ${d.deterministic ?? "?"} vs LLM ${d.llm ?? "?"}）`;
      case "review_auto_accept_write": return `自动采纳（写操作）：${d.title || ""}`;
      case "review_auto_deepen": return `自动深挖：${d.title || ""}`;
      case "review_auto_ignore_bombing": return `自动忽略（轰炸类）：${d.title || ""}`;
      case "review_auto_ignore_weak_backdoor": return `自动忽略（弱后门）：${d.title || ""}`;
      case "tool_compat_switch": return `工具兼容切换：${cap(d.detail, 120)}`;
      case "target_done": return `目标处置完成`;
      case "target_requeued": return `目标重新入队`;
      case "timeout": return `目标超时`;
      case "auto_deepen": return `自动深挖`;
      case "salvage": return `抢救恢复`;
      case "quota_stop": return `额度耗尽，暂停`;
      case "reclaim": return `回收并发`;
      case "recover": return `恢复并发`;
      case "workers_cancelled": return `批量取消 worker`;
      case "killsweep_cancelled": return `通杀分析已取消`;
      case "refill": return `补充任务`;
      case "cluster_cooldown_skip": return `集群冷却跳过`;
      case "skip": return `跳过`;
      case "auth_status": {
        const kinds = (d.kinds || []).join(",") || "-";
        const st = d.status || "?";
        if (d.message) return d.message;
        if (st === "injected") return `凭据[${kinds}] 已注入`;
        if (st === "login_ok") return `凭据[${kinds}] 登录成功`;
        if (st === "login_fail") return `凭据[${kinds}] 登录失败：${cap(d.reason, 100)}`;
        return `凭据未使用：${cap(d.reason, 100)}`;
      }
      case "ping": return null;
      default: return ev.message || `${ev.kind || ""}`;
    }
  }

  function normalizeTimedEvent(ev, existingByKey = null) {
    const text = ev._text || fmtEvent(ev) || ev.message || ev.kind;
    if (!text) return null;
    const withText = { ...ev, _text: text };
    const raw = eventRawTs(withText);
    let displayTs = "";
    if (parseEventTs(raw)) {
      displayTs = raw;
    } else {
      const previous = existingByKey?.get(streamEventStableKey(withText));
      displayTs = previous?._displayTs || previous?.ts || new Date().toISOString();
    }
    return {
      ...withText,
      // Activity Stream 自己也需要稳定 uid。不能用 v-for 下标做 key：
      // 新事件插到顶部会让下标整体变化，展开状态会被误关。
      _uid: withText._uid ?? existingByKey?.get(streamEventStableKey(withText))?._uid ?? ++_traceUid,
      // 缺失/非法 ts 只在进入列表时固化一次。后续轮询复用 _displayTs，
      // 避免错误事件每次渲染都回退到当前时间，看起来像时间一直在增加。
      ts: raw || displayTs,
      _displayTs: displayTs,
    };
  }

  return {
    fmtEvent,
    normalizeTimedEvent,
    isImportantEvent,
    evCat,
    evIcon,
    evKey,
    eventExpandKey,
    canExpandEvent,
    evTime,
    evClass,
    parseEventTs,
    traceDedupKey,
    evEpoch,
    streamEventStableKey,
    eventRawTs,
    isLlmErrorEvent,
    nextTraceUid,
  };
}

// 事件 kind → 简短中文标签（用于展开细节的类型列 / 轨迹徽章，避免显示 raw 英文）
const _KIND_LABEL = {
  worker_start: "开始", worker_finish: "收尾", worker_cancelled: "取消", worker_auto_finish: "自动收尾",
  worker_thought: "思考", worker_directive: "指令", worker_directive_queued: "指令排队", worker_reflect: "复盘",
  worker_resume: "断点恢复", llm_round_start: "LLM 轮次", llm_error: "LLM 错误", llm_soft_retry: "LLM 重试",
  llm_interrupt: "LLM 中断", llm_provider_failed: "端点失败", provider_degrade_error: "提供商降级",
  provider_health_error: "提供商异常",
  finding_submitted: "漏洞提交", finding_duplicate: "重复拦截", finding_invalid: "格式错误",
  finding_needs_more_evidence: "证据不足", finding_out_of_scope: "超范围拦截",
  review_start: "审核", review_done: "审核完成", review_error: "审核异常", review_deferred: "审核暂缓",
  review_cancelled: "审核取消", review_auto_accept_write: "自动采纳", review_auto_deepen: "自动深挖",
  review_auto_ignore_bombing: "忽略轰炸", review_auto_ignore_weak_backdoor: "忽略弱后门",
  reproduce_start: "复现", reproduce_done: "复现完成", reproduce_conflict: "复现冲突",
  killsweep_start: "通杀", killsweep_done: "通杀完成", killsweep_error: "通杀异常", killsweep_dedup: "通杀去重",
  killsweep_invalid: "通杀无效", killsweep_cancelled: "通杀取消", killsweep_retry: "通杀重试",
  killsweep_fofa: "通杀测绘", killsweep_http: "通杀请求", killsweep_shell: "通杀命令",
  escalate_start: "扩大危害", escalate_done: "扩大完成", escalate_error: "扩大异常", escalate_skip: "扩大跳过",
  escalate_cancelled: "扩大取消", escalate_abandon: "扩大放弃", escalate_http: "扩大请求",
  escalate_shell: "扩大命令", escalate_session: "扩大会话",
  tool_exception: "工具异常", tool_arg_error: "参数错误", tool_compat_switch: "兼容切换",
  tool_http: "HTTP", tool_shell: "Shell", tool_shell_blocked: "Shell 拦截",
  tool_js_analyze: "JS 分析", tool_decode: "解码", tool_waf_advice: "WAF 建议", tool_fofa_lookup: "测绘查询",
  tool_session_set: "会话", tool_asset_discovery: "资产发现", tool_fingerprint: "指纹",
  tool_credential_brute: "弱口令", tool_login_session: "登录态", tool_login_form_scan: "登录侦察",
  tool_http_batch: "批量请求", tool_diff_response: "差异对比", tool_timing_probe: "耗时测量",
  tool_crawl_links: "链接抓取", tool_sqli_probe: "SQLi 探测", tool_upload_probe: "上传探测",
  tool_path_probe: "路径/备份", tool_injection_probe: "注入探针",
  tool_access_boundary: "权限边界", tool_capture_evidence: "存证快照", tool_verify_known_vuln: "已知漏洞",
  tool_update_cognition: "认知更新",
  auth_status: "凭据", finish_blocked: "收尾拦截", intel_reported: "情报上报",
  js_analyzer_enabled: "JS 分析", coverage_reported: "覆盖率",
  blackboard_publish: "黑板共享", blackboard_declare: "黑板分工",
  target_done: "目标完成", target_requeued: "目标重排", timeout: "目标超时", auto_deepen: "自动深挖",
  salvage: "抢救", quota_stop: "额度暂停", reclaim: "回收并发", recover: "恢复并发",
  workers_cancelled: "批量取消", refill: "补充任务", cluster_cooldown_skip: "冷却跳过", skip: "跳过",
  ping: "心跳",
};
export function kindLabel(kind) {
  const k = String(kind || "");
  return _KIND_LABEL[k] || (k.startsWith("tool_") ? k.slice(5) : k);
}
