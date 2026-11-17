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


async def evaluate_task_goals(session, task_ids: list[str]) -> dict[str, dict]:
    """批量评估多个任务的目标达成情况（仅对配置了目标的任务查询 Finding）。"""
    ids = [str(tid) for tid in (task_ids or []) if tid]
    if not ids:
        return {}
    from app.fusion.config import load_config
    if not load_config().goal_gate_enabled:
        return {}
    try:
        from sqlalchemy import select
        from app.db.models import Finding, FusionGoal

        goal_rows = (await session.execute(
            select(FusionGoal).where(FusionGoal.task_id.in_(ids)).order_by(FusionGoal.created_at)
        )).scalars().all()
        if not goal_rows:
            return {}
        by_task_goals: dict[str, list[dict]] = {}
        for r in goal_rows:
            by_task_goals.setdefault(r.task_id, []).append({
                "id": r.goal_key,
                "title": r.title,
                "criteria": r.criteria,
                "kind": r.kind,
                "match": r.match_terms or [],
                "status": r.status,
                "evidence_ref": r.evidence_ref,
            })
        configured_ids = list(by_task_goals.keys())
        finding_rows = (await session.execute(
            select(Finding).where(Finding.task_id.in_(configured_ids), Finding.status != "superseded")
        )).scalars().all()
        by_task_findings: dict[str, list[Any]] = {}
        for f in finding_rows:
            by_task_findings.setdefault(f.task_id, []).append(f)

        out: dict[str, dict] = {}
        for tid, goals in by_task_goals.items():
            ev = evaluate(goals, by_task_findings.get(tid, []))
            out[tid] = {
                "configured": True,
                "total": ev["total"],
                "met_count": ev["met_count"],
                "unmet_count": ev["unmet_count"],
                "summary": ev["summary"],
                "terminal_state": ev["terminal_state"],
                "goal_met": ev["goal_met"],
                "unmet_ids": ev["unmet_ids"],
            }
        return out
    except Exception:
        return {}


_SUGGEST_TEMPLATES: tuple[tuple[tuple[str, ...], dict], ...] = (
    (
        ("未授权", "unauthorized", "unauth", "接口"),
        {
            "title": "未授权接口返回业务数据",
            "kind": KIND_EXISTENCE,
            "criteria": "匿名 HTTP 请求返回 200 且响应 JSON/正文包含非公开业务字段，可用 curl 复现",
            "match": ["未授权", "unauthorized", "unauth"],
        },
    ),
    (
        ("越权", "idor", "水平", "垂直"),
        {
            "title": "越权读取非本人敏感业务数据",
            "kind": KIND_CAPABILITY,
            "criteria": "切换低权限/他人对象 ID 后返回 status 200 且响应对比差异包含非本人敏感字段",
            "match": ["越权", "idor"],
        },
    ),
    (
        ("sql", "sqli", "注入"),
        {
            "title": "确认 SQL 注入并取得数据库回显或布尔差异",
            "kind": KIND_CAPABILITY,
            "criteria": "注入 payload 后返回 HTTP 200/500 且响应对比含数据库报错、延迟或字段回显",
            "match": ["sql", "sqli", "注入"],
        },
    ),
    (
        ("rce", "命令执行", "代码执行", "反序列化"),
        {
            "title": "取得远程命令或代码执行回显权限",
            "kind": KIND_CAPABILITY,
            "criteria": "返回 HTTP 200 且命令输出包含 uid= / 主机特征回显，附带原始请求响应包",
            "match": ["rce", "命令执行", "代码执行", "反序列化"],
        },
    ),
    (
        ("文件上传", "upload"),
        {
            "title": "验证可执行或越权路径文件上传能力",
            "kind": KIND_CAPABILITY,
            "criteria": "上传接口返回 200 并给出可访问路径，后续 GET 返回期望内容或执行回显",
            "match": ["upload", "文件上传"],
        },
    ),
    (
        ("ssrf", "服务端请求"),
        {
            "title": "验证服务端请求伪造并取得响应或带外命中",
            "kind": KIND_CAPABILITY,
            "criteria": "触发 SSRF 请求后返回 HTTP 200 内部响应内容或 DNS/HTTP 带外回连命中日志",
            "match": ["ssrf"],
        },
    ),
    (
        ("文件读取", "路径穿越", "目录遍历", "lfi"),
        {
            "title": "验证任意文件读取并取得敏感配置或系统文件内容",
            "kind": KIND_CAPABILITY,
            "criteria": "请求穿越参数后返回 status 200 且响应包含 root: 或配置文件真实字段",
            "match": ["lfi", "文件读取", "路径穿越"],
        },
    ),
    (
        ("认证", "登录", "弱口令", "bypass", "接管"),
        {
            "title": "验证认证绕过或弱口令登录成功获取后台权限",
            "kind": KIND_CAPABILITY,
            "criteria": "携带绕过参数或凭证后返回 HTTP 200 登录成功态（token/Cookie）并可访问受保护接口",
            "match": ["auth", "bypass", "弱口令", "登录", "接管"],
        },
    ),
    (
        ("信息泄露", "敏感", "leak", "js", "api"),
        {
            "title": "敏感凭据或高价值内部接口响应外泄",
            "kind": KIND_EXISTENCE,
            "criteria": "HTTP 200 响应正文或 JS 源码返回真实 key/token/敏感用户信息，可用 curl 复现",
            "match": ["leak", "信息泄露", "敏感"],
        },
    ),
    (
        ("逻辑", "支付", "短信", "验证码", "logic"),
        {
            "title": "验证业务逻辑或验证码流程可稳定绕过",
            "kind": KIND_CAPABILITY,
            "criteria": "修改参数重放后返回 status 200 业务成功响应，附完整正常与异常对照请求包",
            "match": ["logic", "逻辑", "验证码"],
        },
    ),
    (
        ("xss",),
        {
            "title": "存储型或 DOM XSS 可控脚本payload写入并回显",
            "kind": KIND_EXISTENCE,
            "criteria": "提交测试 payload 后响应 HTTP 200 未转义原样回显或可执行触发",
            "match": ["xss"],
        },
    ),
)


def _extract_target_hints(targets: Any, limit: int = 3) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()
    for item in targets or []:
        raw = item if isinstance(item, str) else _text((item or {}).get("url") or (item or {}).get("host") or "")
        s = raw.strip()
        if not s:
            continue
        if "://" in s:
            s = s.split("://", 1)[1]
        s = s.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0].strip().lower()
        if s and s not in seen:
            seen.add(s)
            hosts.append(s)
            if len(hosts) >= limit:
                break
    return hosts


def suggest_goals(context: dict[str, Any] | None = None) -> list[dict]:
    """按任务漏洞类型、SRC 模式与目标特征智能拆解可核验的验收目标清单。"""
    ctx = context if isinstance(context, dict) else {}
    vuln_types = [str(v).strip() for v in (ctx.get("vuln_types") or []) if str(v).strip()]
    src_type = str(ctx.get("src_type") or "edusrc").strip().lower()
    name = str(ctx.get("name") or "").strip()
    fofa_query = str(ctx.get("fofa_query") or "").strip()
    signal_blob = " ".join([*vuln_types, name, fofa_query]).lower()

    picked: list[dict] = []
    seen_titles: set[str] = set()
    for keywords, tpl in _SUGGEST_TEMPLATES:
        if any(kw in signal_blob for kw in keywords):
            if tpl["title"] not in seen_titles:
                seen_titles.add(tpl["title"])
                picked.append({
                    "title": tpl["title"],
                    "kind": tpl["kind"],
                    "criteria": tpl["criteria"],
                    "match": list(tpl["match"]),
                })
        if len(picked) >= 5:
            break

    if not picked:
        if src_type == "enterprise":
            picked = [
                {
                    "title": "未授权或越权接口可稳定读取内部业务字段",
                    "kind": KIND_EXISTENCE,
                    "criteria": "匿名或低权限 HTTP 请求返回 200 且响应 JSON 含业务敏感字段，可用 curl 复现",
                    "match": ["未授权", "越权", "unauthorized", "idor"],
                },
                {
                    "title": "取得高危系统控制权或高价值数据库/管理后台访问能力",
                    "kind": KIND_CAPABILITY,
                    "criteria": "返回 status 200 并附带命令输出、后台会话 token 或脱敏数据样本对照差异",
                    "match": ["rce", "sql", "upload", "auth"],
                },
            ]
        else:
            picked = [
                {
                    "title": "公开入口或弱鉴权接口可返回真实业务敏感数据",
                    "kind": KIND_EXISTENCE,
                    "criteria": "匿名 HTTP 请求返回 200 且响应包含非公开学生/教务或业务字段，可用 curl 复现",
                    "match": ["未授权", "leak", "unauthorized"],
                },
                {
                    "title": "验证关键漏洞可稳定复现并具备可核验危害证据",
                    "kind": KIND_CAPABILITY,
                    "criteria": "返回 HTTP 200 实锤响应、请求包及复现步骤对照差异，拒绝仅版本号猜测",
                    "match": ["rce", "sql", "idor", "upload"],
                },
            ]

    hosts = _extract_target_hints(ctx.get("targets"))
    if hosts and picked:
        picked[0]["criteria"] = f'{picked[0]["criteria"]}（目标范围：{", ".join(hosts)}）'

    raw_goals = [{**g, "id": f"g{idx + 1}"} for idx, g in enumerate(picked)]
    normalized, errors = validate_goals(raw_goals)
    if errors:
        raise ValueError("；".join(errors))
    return normalized
