// 展示辅助（等级/信度/步骤规范化）——多个列表组件与报告抽屉共用。
// 报告 Markdown 拼装已收敛到后端 app/report_export.py（/api/findings/{id}/export），
// 前端不再本地拼装，避免两份实现漂移。
export const CONF = { confirmed: "确认", likely: "疑似", uncertain: "不确定" };

// 复现步骤统一成 [{desc, poc, poc_http}]：兼容旧版纯字符串列表。
export function normalizeSteps(steps) {
  return (steps || [])
    .map((s) => {
      if (s && typeof s === "object") {
        const desc = String(s.desc ?? s.text ?? s.description ?? s.step ?? "").trim();
        const poc = String(s.poc ?? s.curl ?? s.command ?? "").trim();
        const pocHttp = String(s.poc_http ?? s.http ?? s.request ?? "").trim();
        return { desc, poc, poc_http: pocHttp };
      }
      return { desc: String(s ?? "").trim(), poc: "", poc_http: "" };
    })
    .filter((s) => s.desc);
}

export function effectiveSeverity(f) {
  // 与后端口径一致：用户编辑 > AI 终审 > worker 自评（此前缺最后一级，未审核显示 "-"）
  return f.review?.user_severity || f.review?.severity_final || f.severity_claimed || "-";
}

// 等级统一转中文展示，兼容数据源的英文枚举值（high/critical/medium/low）。
const SEV_CN = { "critical": "严重", "高": "高危", "high": "高危", "严重": "严重", "高危": "高危", "中": "中危", "medium": "中危", "中危": "中危", "低": "低危", "low": "低危", "低危": "低危" };
export function severityToCn(value) {
  const v = String(value || "").trim();
  return SEV_CN[v] || v || "-";
}

const IMPACT_SHORT = {
  L1: "信息面",
  L2: "认证越权",
  L3: "控制面",
  L4: "数据资金",
};

export function impactMeta(fe) {
  if (!fe || !fe.impact_level) return null;
  const level = fe.impact_level;
  const shortLabel = IMPACT_SHORT[level] || level;
  const allowed = fe.allowed !== false;
  const evidence = Array.isArray(fe.evidence) ? fe.evidence : [];
  const reasons = Array.isArray(fe.reasons) ? fe.reasons : [];
  const parts = [`${level} · ${fe.impact_label || shortLabel}`];
  parts.push(`机械凭据：${evidence.length ? evidence.join("、") : "无"}`);
  if (!allowed && reasons.length) parts.push(`闸门提示：${reasons.join("；")}`);
  return {
    level,
    shortLabel,
    allowed,
    evidence,
    evidenceText: evidence.length ? evidence.join("、") : "无",
    reasons,
    tooltip: parts.join("\n"),
  };
}
