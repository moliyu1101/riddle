"""目标闸门：目标 + 可核验验收标准 + 收官判定 + 诚实终态。

机制说明：任务收官不再由模型自评「跑完了」决定，而是逐条核对目标是否 met。
只要还有 open/unmet 目标，终态一律记 ``incomplete``，并在列表/详情/报告三处
如实标注 ``x/y 目标达成``——不把超时、空转、覆盖度收尾粉饰成 done。

能力型目标（要求 RCE / 控制权 / 敏感数据等结果）只接受 high/critical 的
finding 作为证据，fact 与低危 finding 一律不够；存在型目标接受 fact 或任意 finding。
这是从「能力型目标被普通 fact 绕过」这类实战事故里长出来的硬约束。
"""
from __future__ import annotations

import re
from typing import Any

KIND_EXISTENCE = "existence"
KIND_CAPABILITY = "capability"
GOAL_KINDS = (KIND_EXISTENCE, KIND_CAPABILITY)

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4, "严重": 4, "高危": 3, "中危": 2, "低危": 1}

# 过程性措辞：只描述动作、没有可核验结果的目标一律拒绝
_PROCESS_ONLY = ("发现漏洞", "验证漏洞", "扫描目标", "排查目标", "测试接口", "尝试利用", "寻找入口", "分析站点")
# 能力型目标特征词
_CAPABILITY_HINTS = (
    "rce", "命令执行", "getshell", "webshell", "控制权", "接管", "提权",
    "敏感数据", "数据外带", "dump", "资金", "越权读取", "横向",
)
# 可核验信号：验收标准里必须至少命中一个，避免写出「确认安全性」这种无法判定的句子
_CRITERIA_SIGNALS = (
    "200", "状态码", "status", "http", "响应", "返回", "字段", "读到", "读取",
    "curl", "命令输出", "命中", "登录成功", "uid=", "root:", "回显", "对比",
    "差异", "poc", "payload", "sha256", "content-length", "json", "token",
)


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _blob(item: Any) -> str:
    """把 dict 或对象拍平成可检索文本。"""
    if isinstance(item, dict):
        parts: list[str] = []
        for k, v in item.items():
            if isinstance(v, (dict, list)):
                parts.append(_blob(v))
            else:
                parts.append(f"{k}={_text(v)}")
        return " ".join(parts).lower()
    out = []
    for name in ("title", "description", "vuln_type", "summary", "poc", "evidence", "affected_scope"):
        val = getattr(item, name, None)
        if val:
            out.append(_text(val))
    return " ".join(out).lower()


def _severity(finding: Any) -> str:
    val = finding.get("severity_claimed", "") if isinstance(finding, dict) else getattr(finding, "severity_claimed", "")
    if hasattr(val, "value"):
        val = val.value
    return _text(val).strip().lower()


def infer_kind(title: str, criteria: str, declared: str = "") -> str:
    """未显式声明时，按目标文本推断是存在型还是能力型。"""
    if declared in GOAL_KINDS:
        return declared
    blob = f"{title} {criteria}".lower()
    return KIND_CAPABILITY if any(h in blob for h in _CAPABILITY_HINTS) else KIND_EXISTENCE


def normalize_goal(raw: Any, index: int = 0) -> dict:
    """把外部输入收敛成统一结构，缺字段给默认值，不抛异常。"""
    raw = raw if isinstance(raw, dict) else {}
    title = _text(raw.get("title") or raw.get("name") or "").strip()
    criteria = _text(raw.get("criteria") or raw.get("acceptance") or "").strip()
    declared = _text(raw.get("kind") or "").strip().lower()
    return {
        "id": _text(raw.get("id") or f"g{index + 1}").strip() or f"g{index + 1}",
        "title": title,
        "criteria": criteria,
        "kind": infer_kind(title, criteria, declared),
        "match": [str(m).strip().lower() for m in (raw.get("match") or []) if str(m).strip()],
        "status": _text(raw.get("status") or "open").strip().lower(),
        "evidence_ref": _text(raw.get("evidence_ref") or ""),
    }


def validate_goals(goals: list[Any]) -> tuple[list[dict], list[str]]:
    """校验目标清单；返回 (规范化后的目标, 错误列表)。错误非空即整批拒绝写入。"""
    normalized = [normalize_goal(g, i) for i, g in enumerate(goals or [])]
    errors: list[str] = []
    if not normalized:
        return [], ["目标清单不能为空"]
    seen: set[str] = set()
    for g in normalized:
        gid = g["id"]
        if gid in seen:
            errors.append(f"目标 id 重复：{gid}")
        seen.add(gid)
        if not g["title"]:
            errors.append(f"{gid}: 目标标题不能为空")
        if any(g["title"].startswith(p) for p in _PROCESS_ONLY):
            errors.append(f"{gid}: 目标写成了过程动作（{g['title']}），必须写可核验的最终结果")
        if len(g["criteria"]) < 8:
            errors.append(f"{gid}: 验收标准过短，需写明可机械核验的信号")
        elif not any(s in g["criteria"].lower() for s in _CRITERIA_SIGNALS):
            errors.append(f"{gid}: 验收标准缺少可核验信号（状态码/响应字段/curl 输出/对比差异等）")
        if g["kind"] not in GOAL_KINDS:
            errors.append(f"{gid}: kind 必须是 {GOAL_KINDS}")
    return normalized, errors


def _evidence_match(goal: dict, item: Any) -> bool:
    if not goal["match"]:
        return True
    blob = _blob(item)
    return any(m in blob for m in goal["match"])


def goal_met(goal: dict, findings: list[Any], facts: list[Any] | None = None) -> tuple[bool, str]:
    """单条目标是否达成。返回 (是否达成, 判定说明)。"""
    if goal.get("status") == "met" and goal.get("evidence_ref"):
        return True, "已由人工/上游标记达成"
    matched_findings = [f for f in (findings or []) if _evidence_match(goal, f)]
    if goal["kind"] == KIND_CAPABILITY:
        strong = [f for f in matched_findings if _SEVERITY_ORDER.get(_severity(f), 0) >= 3]
        if strong:
            return True, "能力型目标命中 high/critical 实证漏洞"
        return False, "能力型目标只接受 high/critical 的 finding 证据，fact 与低危 finding 不足"
    if matched_findings:
        return True, "存在型目标命中 finding 证据"
    matched_facts = [f for f in (facts or []) if _evidence_match(goal, f)]
    if matched_facts:
        return True, "存在型目标命中 fact 证据"
    return False, "尚无命中该目标的证据"


def evaluate(goals: list[dict], findings: list[Any], facts: list[Any] | None = None) -> dict:
    """逐条判定并给出诚实终态。纯函数，不落库、不联网。"""
    met: list[dict] = []
    unmet: list[dict] = []
    for raw in goals or []:
        goal = normalize_goal(raw) if not isinstance(raw, dict) or "kind" not in raw else raw
        ok, reason = goal_met(goal, findings, facts)
        row = {**goal, "met": ok, "reason": reason}
        (met if ok else unmet).append(row)
    total = len(met) + len(unmet)
    state = "done" if total and not unmet else "incomplete"
    return {
        "total": total,
        "met_count": len(met),
        "unmet_count": len(unmet),
        "met": met,
        "unmet": unmet,
        "unmet_ids": [g["id"] for g in unmet],
        "terminal_state": state,
        "summary": f"{len(met)}/{total} 目标达成" if total else "未设置目标",
        # 收官闸门：还有未达成目标时拒绝落 done
        "goal_met": state == "done",
    }


def terminal_state(evaluation: dict, *, proposed: str = "done") -> str:
    """把上游想落的终态收敛成诚实终态。"""
    if evaluation.get("goal_met"):
        return proposed
    return "incomplete"


_CRITERIA_CODE = re.compile(r"\b(?:status|code)\s*[:=]?\s*(\d{3})\b", re.I)


def criteria_status_codes(goal: dict) -> list[str]:
    """从验收标准里抽出期望的 HTTP 状态码，供证据闸门交叉核对。"""
    return _CRITERIA_CODE.findall(goal.get("criteria", "") or "")
