// 融合层「任务验收目标」共享预设、格式转换与前端前置校验
export const GOAL_PRESETS = [
  {
    title: "未授权接口返回业务数据",
    kind: "existence",
    criteria: "匿名 HTTP 请求返回 200 且响应 JSON 含业务字段，可用 curl 复现",
    matchText: "未授权,unauthorized",
  },
  {
    title: "获取命令执行或代码执行权限",
    kind: "capability",
    criteria: "返回 HTTP 200 且命令输出包含 uid= 或可控回显，附带原始请求响应包",
    matchText: "rce,命令执行,代码执行",
  },
  {
    title: "越权读取敏感业务数据",
    kind: "capability",
    criteria: "替换对象 ID 后返回 status 200 且响应包含非本人敏感字段对比差异",
    matchText: "越权,idor,敏感",
  },
];

const CRITERIA_SIGNALS = [
  "200", "状态码", "status", "http", "响应", "返回", "字段", "读到", "读取",
  "curl", "命令输出", "命中", "登录成功", "uid=", "root:", "回显", "对比",
  "差异", "poc", "payload", "sha256", "content-length", "json", "token",
];

const PROCESS_ONLY = ["发现漏洞", "验证漏洞", "扫描目标", "排查目标", "测试接口", "尝试利用", "寻找入口", "分析站点"];

export function createEmptyGoal(index = 0) {
  return {
    id: `g${index + 1}`,
    title: "",
    kind: "existence",
    criteria: "",
    matchText: "",
  };
}

export function fromGoalPayload(goals) {
  return (goals || []).map((g, idx) => ({
    id: String(g.goal_key || g.id || `g${idx + 1}`),
    title: String(g.title || ""),
    kind: g.kind === "capability" ? "capability" : "existence",
    criteria: String(g.criteria || ""),
    matchText: Array.isArray(g.match) ? g.match.join(", ") : String(g.match || ""),
  }));
}

export function toGoalPayload(rows) {
  const seen = new Set();
  return (rows || []).map((r, idx) => {
    let gid = String(r.id || `g${idx + 1}`).trim() || `g${idx + 1}`;
    while (seen.has(gid)) gid = `${gid}_${idx + 1}`;
    seen.add(gid);
    return {
      id: gid,
      title: String(r.title || "").trim(),
      kind: r.kind === "capability" ? "capability" : "existence",
      criteria: String(r.criteria || "").trim(),
      match: String(r.matchText || "").split(/[,，\s]+/).map((s) => s.trim()).filter(Boolean),
    };
  });
}

export function validateGoalRows(rows) {
  for (let i = 0; i < (rows || []).length; i++) {
    const r = rows[i];
    const title = String(r.title || "").trim();
    const criteria = String(r.criteria || "").trim();
    const label = `第 ${i + 1} 条验收目标`;
    if (!title) return `${label}缺少标题`;
    if (PROCESS_ONLY.some((p) => title.startsWith(p))) {
      return `${label}写成了过程动作（${title}），请改为可核验的最终结果`;
    }
    if (criteria.length < 8) return `${label}的验收标准过短（至少 8 字）`;
    const lower = criteria.toLowerCase();
    if (!CRITERIA_SIGNALS.some((s) => lower.includes(s))) {
      return `${label}的验收标准缺少可核验信号（如 200 / 状态码 / 响应字段 / curl / uid=）`;
    }
  }
  return "";
}
