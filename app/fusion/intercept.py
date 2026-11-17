"""命令三层拦截（deny / judge / ask）+ 反注入窄视野裁判 + 人工审批台账。

设计边界（对应《差距补齐目的与方案》§3.4）：
- 第一层 deny：复用 ``app.tools.guard`` 自毁与任务禁止规则，命中即拒。
- 第二层 judge：针对上下文敏感命令（SQL 写删、sqlmap 高危参数、暴力破解等），
  构造只含 (tool, command, cwd, src_type) 的窄视野输入供裁剪裁判判定，绝不把长对话
  或目标响应体带进裁判视野；裁决输出走严格 JSON 解析，格式非法一律保守降级。
- 第三层 ask：针对监听端口/隧道等平台能力边界变更或待确认操作，写入在线审批队列；
  人工批准后放行同指纹命令，人工拒绝后在执行器层直接拦截。
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from app.tools.guard import (
    CommandBlocked,
    NeedsConfirm,
    check_command,
    check_rm_cwd,
    check_task_forbidden,
)

TIERS = ("allow", "deny", "judge", "ask")
MAX_ENTRIES = 500

_LOCK = threading.Lock()
_ENTRIES: list[dict[str, Any]] = []
_DECISIONS: dict[tuple[str, str], dict[str, str]] = {}

_JUDGE_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("sql_write_drop", re.compile(r"\b(?:drop|truncate)\s+table\b|\bdelete\s+from\b", re.I), "涉及 SQL 删改表语句，需结合目标与测试表上下文研判"),
    ("sqlmap_high_risk", re.compile(r"\bsqlmap\b[^\n]*(?:--os-shell|--os-pwn|--sql-shell|--risk\s*=?\s*3)", re.I), "sqlmap 高侵入参数，需研判是否仅作无害存在性验证"),
    ("bruteforce_tool", re.compile(r"\b(?:hydra|medusa|patator)\b", re.I), "在线暴力破解工具，需核对范围与口令字典规模"),
    ("http_delete_method", re.compile(r"\bcurl\b[^\n]*(?:-X|--request)\s+['\"]?DELETE\b", re.I), "HTTP DELETE 写删请求，需研判作用对象是否为临时测试数据"),
)

_ASK_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("listen_socket", re.compile(r"\b(?:nc|ncat|netcat)\b[^\n]*\s-[a-z]*l|\bsocat\b[^\n]*tcp-listen", re.I), "开启本地网络监听端口，属于平台能力边界变更，需人工审批"),
    ("tunnel_relay", re.compile(r"\bchisel\b\s+(?:server|client)|\bssh\b[^\n]*\s-[RLD]\s", re.I), "建立端口转发或隧道中继，需人工审批确认授权边界"),
)

_SAFE_TEST_MARKER = re.compile(r"(?:src_test_|_test\b|tmp_|/tmp/|sandbox|demo)", re.I)
_EXTREME_DANGER = re.compile(r"(?:--os-shell|--os-pwn|\b(?:drop|truncate)\s+table\b)", re.I)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cmd_sha(command: str) -> str:
    return hashlib.sha256((command or "").strip().encode("utf-8")).hexdigest()[:32]


def build_judge_context(
    tool: str,
    command: str,
    cwd: str = "",
    src_type: str = "edusrc",
) -> dict[str, str]:
    """构造反注入窄视野裁判上下文：绝不包含对话历史、网页响应体或外部提示。"""
    return {
        "tool": str(tool or "run_shell").strip()[:64],
        "command": str(command or "").strip()[:1000],
        "cwd": str(cwd or "").strip()[:260],
        "src_type": str(src_type or "edusrc").strip()[:32],
    }


def parse_judge_verdict(raw: str, *, fallback_action: str = "deny") -> dict[str, Any]:
    """严格解析裁判 JSON 返回（allow/deny/ask）；非 JSON 或未知动作一律保守降级。"""
    text = str(raw or "").strip()
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\s*|\s*```$", "", text, flags=re.S).strip()
    try:
        data = json.loads(text)
    except Exception:
        return {
            "action": fallback_action,
            "reason": f"裁判输出非合法 JSON，按保守策略降级为 {fallback_action}",
            "strict_parsed": False,
        }
    if not isinstance(data, dict):
        return {
            "action": fallback_action,
            "reason": f"裁判输出结构非 JSON 对象，降级为 {fallback_action}",
            "strict_parsed": False,
        }
    action = str(data.get("action") or "").strip().lower()
    if action not in ("allow", "deny", "ask"):
        return {
            "action": fallback_action,
            "reason": f"裁判输出非法动作 {action!r}，降级为 {fallback_action}",
            "strict_parsed": False,
        }
    return {
        "action": action,
        "reason": str(data.get("reason") or "模型裁判结论")[:300],
        "strict_parsed": True,
    }


def _default_judge(ctx: dict[str, str]) -> dict[str, Any]:
    cmd = ctx.get("command") or ""
    if _SAFE_TEST_MARKER.search(cmd) and not _EXTREME_DANGER.search(cmd):
        return {
            "action": "allow",
            "reason": "目标包含明确测试隔离标记且无破坏性执行参数，允许放行",
            "strict_parsed": True,
        }
    if _EXTREME_DANGER.search(cmd):
        return {
            "action": "deny",
            "reason": "命令含高破坏或系统接管特征，超出无害验证基线，予以拦截",
            "strict_parsed": True,
        }
    return {
        "action": "ask",
        "reason": "上下文敏感命令难以单独由静态模式判定无害性，转交人工审批队列",
        "strict_parsed": True,
    }


def _record_entry(
    *,
    task_id: str,
    command_sha: str,
    tool: str,
    command: str,
    cwd: str,
    src_type: str,
    tier: str,
    action: str,
    rule: str,
    reason: str,
    status: str,
) -> dict[str, Any]:
    with _LOCK:
        for row in reversed(_ENTRIES):
            if row["task_id"] == task_id and row["command_sha"] == command_sha and row["status"] == "pending":
                row["reason"] = reason
                row["tier"] = tier
                row["action"] = action
                return dict(row)
        entry = {
            "id": uuid.uuid4().hex[:16],
            "task_id": task_id,
            "command_sha": command_sha,
            "tool": tool,
            "command": command[:1000],
            "cwd": cwd[:260],
            "src_type": src_type,
            "tier": tier,
            "action": action,
            "rule": rule,
            "reason": reason[:400],
            "status": status,
            "decision_note": "",
            "created_at": _now_iso(),
            "decided_at": "",
        }
        _ENTRIES.append(entry)
        if len(_ENTRIES) > MAX_ENTRIES:
            del _ENTRIES[: len(_ENTRIES) - MAX_ENTRIES]
        return dict(entry)


def evaluate_command(
    command: str,
    *,
    tool: str = "run_shell",
    cwd: str = "",
    src_type: str = "edusrc",
    task_id: str = "",
    forbidden_ops: list[str] | None = None,
    llm_judge: Callable[[dict[str, str]], str] | None = None,
    record: bool = False,
) -> dict[str, Any]:
    """对单条工具命令执行三层闸门判定（deny → judge → ask）。"""
    cmd = str(command or "").strip()
    if not cmd:
        return {"tier": "allow", "action": "allow", "allowed": True, "rule": "", "reason": "空命令", "approval_status": ""}

    cmd_sha = _cmd_sha(cmd)
    tid = str(task_id or "").strip()
    with _LOCK:
        prior = _DECISIONS.get((tid, cmd_sha)) or _DECISIONS.get(("", cmd_sha))
    if prior:
        approved = prior["decision"] == "approved"
        return {
            "tier": "ask",
            "action": "allow" if approved else "deny",
            "allowed": approved,
            "rule": "manual_decision",
            "reason": prior.get("note") or ("人工已批准放行" if approved else "人工已拒绝执行"),
            "approval_status": prior["decision"],
            "command_sha": cmd_sha,
        }

    # 1) deny：先过既有硬规则 + 语义 rm
    needs_confirm_msg = ""
    try:
        check_task_forbidden(cmd, list(forbidden_ops or ()))
        check_command(cmd, enterprise=(src_type == "enterprise"))
        if cwd:
            check_rm_cwd(cmd, cwd)
    except CommandBlocked as exc:
        out = {
            "tier": "deny",
            "action": "deny",
            "allowed": False,
            "rule": "guard_blocked",
            "reason": str(exc),
            "approval_status": "blocked",
            "command_sha": cmd_sha,
        }
        if record:
            entry = _record_entry(
                task_id=tid, command_sha=cmd_sha, tool=tool, command=cmd, cwd=cwd,
                src_type=src_type, tier="deny", action="deny", rule="guard_blocked",
                reason=str(exc), status="denied",
            )
            out["entry_id"] = entry["id"]
        return out
    except NeedsConfirm as exc:
        needs_confirm_msg = str(exc)

    # 2) judge：上下文敏感命令（或 NeedsConfirm 预警）交窄视野裁判判定
    judge_rule = ""
    judge_reason = needs_confirm_msg
    for rname, pat, msg in _JUDGE_RULES:
        if pat.search(cmd):
            judge_rule = rname
            judge_reason = msg
            break
    if judge_rule or needs_confirm_msg:
        ctx = build_judge_context(tool, cmd, cwd=cwd, src_type=src_type)
        verdict = (
            parse_judge_verdict(llm_judge(ctx))
            if callable(llm_judge)
            else _default_judge(ctx)
        )
        act = verdict["action"]
        if act == "allow":
            return {
                "tier": "judge",
                "action": "allow",
                "allowed": True,
                "rule": judge_rule or "needs_confirm",
                "reason": verdict["reason"],
                "judge_context": ctx,
                "approval_status": "",
                "command_sha": cmd_sha,
            }
        if act == "deny":
            out = {
                "tier": "judge",
                "action": "deny",
                "allowed": False,
                "rule": judge_rule or "needs_confirm",
                "reason": verdict["reason"] or judge_reason,
                "judge_context": ctx,
                "approval_status": "denied",
                "command_sha": cmd_sha,
            }
            if record:
                entry = _record_entry(
                    task_id=tid, command_sha=cmd_sha, tool=tool, command=cmd, cwd=cwd,
                    src_type=src_type, tier="judge", action="deny", rule=out["rule"],
                    reason=out["reason"], status="denied",
                )
                out["entry_id"] = entry["id"]
            return out
        # act == "ask" → 进入第三层人工审批
        entry = _record_entry(
            task_id=tid, command_sha=cmd_sha, tool=tool, command=cmd, cwd=cwd,
            src_type=src_type, tier="judge", action="ask", rule=judge_rule or "needs_confirm",
            reason=verdict["reason"] or judge_reason, status="pending",
        ) if record else None
        return {
            "tier": "judge",
            "action": "ask",
            "allowed": False,
            "rule": judge_rule or "needs_confirm",
            "reason": verdict["reason"] or judge_reason,
            "judge_context": ctx,
            "approval_status": "pending",
            "command_sha": cmd_sha,
            **({"entry_id": entry["id"]} if entry else {}),
        }

    # 3) ask：监听/隧道类边界变更命令
    for rname, pat, msg in _ASK_RULES:
        if pat.search(cmd):
            entry = _record_entry(
                task_id=tid, command_sha=cmd_sha, tool=tool, command=cmd, cwd=cwd,
                src_type=src_type, tier="ask", action="ask", rule=rname,
                reason=msg, status="pending",
            ) if record else None
            return {
                "tier": "ask",
                "action": "ask",
                "allowed": False,
                "rule": rname,
                "reason": msg,
                "approval_status": "pending",
                "command_sha": cmd_sha,
                **({"entry_id": entry["id"]} if entry else {}),
            }

    return {
        "tier": "allow",
        "action": "allow",
        "allowed": True,
        "rule": "",
        "reason": "通过三层闸门检查",
        "approval_status": "",
        "command_sha": cmd_sha,
    }


def list_intercepts(*, task_id: str = "", status: str = "") -> list[dict[str, Any]]:
    tid = str(task_id or "").strip()
    st = str(status or "").strip().lower()
    with _LOCK:
        rows = list(reversed(_ENTRIES))
    out: list[dict[str, Any]] = []
    for r in rows:
        if tid and r["task_id"] != tid:
            continue
        if st and r["status"] != st:
            continue
        out.append(dict(r))
    return out


def decide_intercept(item_id: str, decision: str, note: str = "") -> dict[str, Any] | None:
    dec = str(decision or "").strip().lower()
    norm = "approved" if dec in ("approve", "approved", "allow") else "denied" if dec in ("deny", "denied", "reject") else ""
    if not norm:
        raise ValueError("decision 仅支持 approve / deny")
    clean_note = str(note or "").strip()[:300]
    with _LOCK:
        target: dict[str, Any] | None = None
        for r in _ENTRIES:
            if r["id"] == item_id:
                r["status"] = norm
                r["decision_note"] = clean_note
                r["decided_at"] = _now_iso()
                _DECISIONS[(r["task_id"], r["command_sha"])] = {
                    "decision": norm,
                    "note": clean_note,
                }
                target = dict(r)
                break
    return target


def clear_intercepts() -> None:
    with _LOCK:
        _ENTRIES.clear()
        _DECISIONS.clear()
