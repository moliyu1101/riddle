"""扩大危害 Hunter Agent：审核 accepted 一个洞后，顺着已确认的入口再往下打一层。

流程：
  收到一个已采纳的 Finding → 复用其入口/凭证 → 尝试越权写/遍历/改密/接管/RCE
  → 只有【危害等级实际提升】或【影响面数量级变化】才 submit_escalation，否则 abandon。

同步执行（内部 LLM/工具均阻塞），由 orchestrator 在线程池里调用。
任何异常都降级返回，不阻断主循环。设计上刻意克制：轮数少、只在显著升级时产出。
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from app.agents.history import compact_messages
from app.agents.prompts import escalate_system_prompt, is_enterprise_src
from app.config import worker_config
from app.llm.client import LLMClient
from app.tools.executor import ToolExecutor
from app.tools.schemas import ESCALATE_TOOL_SCHEMAS, SESSION_TOOL_SCHEMAS


def load_session_heritage(finding: dict, work_dir: str | None = None) -> dict:
    """读取前序 Worker 遗留的 session_heritage.json（登录态/笔记/认知卡）。"""
    if not isinstance(finding, dict):
        return {}
    direct = finding.get("session_heritage")
    if isinstance(direct, dict) and direct:
        return direct
    root = Path(work_dir or worker_config.work_root)
    candidates: list[str] = []
    for k in ("target_base_url", "target_url", "host"):
        val = str(finding.get(k) or "").strip()
        if val:
            candidates.append(val)
    turl = str(finding.get("target_url") or "").strip()
    if turl:
        try:
            p = urlparse(turl if "://" in turl else f"http://{turl}")
            if p.netloc:
                candidates.append(f"{p.scheme or 'https'}://{p.netloc}")
                candidates.append(p.netloc)
                if p.hostname:
                    candidates.append(p.hostname)
        except Exception:
            pass
    seen: set[str] = set()
    for raw in candidates:
        if raw in seen:
            continue
        seen.add(raw)
        safe_name = "".join(c if c.isalnum() else "_" for c in raw)[:60]
        if len(raw) > 60:
            digest = hashlib.sha1(raw.encode("utf-8")).hexdigest()[:10]
            safe_name = f"{safe_name}_{digest}"
        path = root / safe_name / "session_heritage.json"
        try:
            if path.exists():
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    return data
        except Exception:
            continue
    return {}

# 扩大危害阶段也开放会话保持：拿原洞凭证/新伪造凭证登录后固化登录态再深挖。
_ESCALATE_TOOLS = ESCALATE_TOOL_SCHEMAS + SESSION_TOOL_SCHEMAS

# 扩大危害只在已确认据点上做纵向升级，必须有限轮数：打不动就撤，不恋战。
# 10 轮：给"伪造凭证→登入→翻数据/找写操作"这类多步升级留足空间，又不至于无限恋战。
_MAX_ROUNDS = int(os.environ.get("ESCALATE_MAX_ROUNDS", "10"))


class EscalateResult:
    def __init__(self, data: dict):
        self.data = data

    def model_dump(self, mode: str = "json") -> dict:
        return self.data


class EscalateHunter:
    def __init__(
        self,
        finding: dict,
        llm: Optional[LLMClient] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
        src_type: str = "edusrc",
        cancel_event: Optional[threading.Event] = None,
        src_rules: str = "",
        guard_ops: Optional[list[str]] = None,
        work_dir: Optional[str] = None,
    ):
        self.finding = finding
        self.llm = llm or LLMClient()
        self.cancel_event = cancel_event or threading.Event()
        self.work_dir = work_dir
        self.executor = ToolExecutor(
            f"escalate_{finding.get('target_url', 'x')}", cancel_event=self.cancel_event,
            work_dir=work_dir, src_rules=src_rules or "", guard_ops=guard_ops,
        )
        self.on_event = on_event or (lambda kind, data: None)
        self._result: Optional[dict] = None
        self.src_type = src_type
        self._heritage: dict = {}

    def _emit(self, kind: str, **data: Any) -> None:
        self.on_event(kind, data)

    def _apply_heritage(self) -> dict:
        if self._heritage:
            return self._heritage
        heritage = load_session_heritage(self.finding, self.work_dir)
        if not heritage:
            return {}
        self._heritage = heritage
        try:
            self.executor.restore_resume_state(
                worker_notes=heritage.get("worker_notes") or "",
                cognition=heritage.get("cognition") or None,
                session_cookies=heritage.get("session_cookies") or None,
                session_headers=heritage.get("session_headers") or None,
            )
        except Exception:
            pass
        return heritage

    def _brief(self) -> str:
        f = self.finding
        unit_label = "企业/系统归属" if is_enterprise_src(self.src_type) else "归属"
        heritage = self._apply_heritage()
        heritage_lines: list[str] = []
        if heritage:
            cookies = heritage.get("session_cookies") or {}
            headers = heritage.get("session_headers") or {}
            notes = (heritage.get("worker_notes") or "").strip()
            cog = heritage.get("cognition") or {}
            if cookies or headers:
                heritage_lines.append(
                    f"- 已继承认证会话：Cookies {sorted(cookies.keys())}，Headers {sorted(headers.keys())}（http_request 会自动携带）"
                )
            if isinstance(cog, dict):
                if cog.get("confirmed"):
                    heritage_lines.append(f"- 前序已证实：{'；'.join(str(x) for x in cog['confirmed'][:6])}")
                if cog.get("excluded"):
                    heritage_lines.append(f"- 前序已排除（避坑）：{'；'.join(str(x) for x in cog['excluded'][:6])}")
                if cog.get("leads"):
                    heritage_lines.append(f"- 前序未穷尽线索：{'；'.join(str(x) for x in cog['leads'][:6])}")
                if cog.get("plan"):
                    heritage_lines.append(f"- 前序攻防思路：{str(cog['plan'])[:300]}")
            if notes:
                heritage_lines.append(f"- 前序工作笔记：\n{notes[:800]}")
        heritage_block = (
            "\n\n## 继承的前序 Worker 会话与认知资产\n" + "\n".join(heritage_lines)
            if heritage_lines
            else ""
        )
        return (
            f"# 已确认存在的漏洞（你的深挖起点）\n"
            f"- 标题：{f.get('title','')}\n"
            f"- 漏洞类型：{f.get('vuln_type','')}\n"
            f"- 当前等级：{f.get('severity','')}\n"
            f"- 目标 URL：{f.get('target_url','')}\n"
            f"- {unit_label}：{f.get('owner','')}\n"
            f"- 描述：{(f.get('description') or '')[:800]}\n"
            f"- 攻击链：{json.dumps(f.get('kill_chain') or [], ensure_ascii=False)[:600]}\n"
            f"- PoC：{(f.get('poc') or '')[:600]}\n"
            f"- 原始请求(片段)：{(f.get('raw_request') or '')[:600]}\n"
            f"- 原始响应(片段)：{(f.get('raw_response') or '')[:900]}"
            f"{heritage_block}\n\n"
            f"请在这个已确认据点上继续往下打，把危害做大。"
            f"打出任何原洞没证明、而你新证明出来的实锤危害（等级提升 / 影响面数量级 / 或在原洞基础上"
            f"实际拿到敏感数据·写操作·账号接管等新实质危害）就 submit_escalation；只有纯原地打转、"
            f"和原洞完全等价时才 abandon_escalation。"
        )

    def run(self) -> EscalateResult:
        self._apply_heritage()
        self._emit("escalate_start", title=self.finding.get("title", ""))
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": escalate_system_prompt(self.src_type)},
            {"role": "user", "content": self._brief()},
        ]
        rounds = 0
        while _MAX_ROUNDS <= 0 or rounds < _MAX_ROUNDS:
            if self.cancel_event.is_set():
                self.executor.cancel_running()
                return EscalateResult({"error": "扩大危害深挖已被取消"})
            rounds += 1
            try:
                send_messages = compact_messages(messages, rounds)
                msg = self.llm.chat(send_messages, tools=_ESCALATE_TOOLS, tool_choice="auto")
            except Exception as e:
                self._emit("escalate_error", error=str(e))
                return EscalateResult({"error": f"LLM 调用失败: {e}"})

            tool_calls = getattr(msg, "tool_calls", None)
            am: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if tool_calls:
                am["tool_calls"] = [
                    {"id": tc.id, "type": "function",
                     "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                    for tc in tool_calls
                ]
            messages.append(am)

            if not tool_calls:
                messages.append({"role": "user", "content": "请继续深挖，或调用 submit_escalation / abandon_escalation 收尾。"})
                continue

            for tc in tool_calls:
                if self.cancel_event.is_set():
                    self.executor.cancel_running()
                    return EscalateResult({"error": "扩大危害深挖已被取消"})
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError:
                    args = {}
                # 工具执行异常也要落一条 tool 响应：保证 assistant.tool_calls ↔ tool 配对完整，
                # 且异常不冒泡打断整个升级 agent（与 worker 一致的续跑健壮性）。
                try:
                    result = self._dispatch(tc.function.name, args)
                except Exception as e:
                    result = {"ok": False, "error": f"工具执行异常: {type(e).__name__}: {e}"}
                    self._emit("escalate_error", error=str(e))
                messages.append({"role": "tool", "tool_call_id": tc.id,
                                 "content": json.dumps(result, ensure_ascii=False),
                                 "_round": rounds, "_tool": tc.function.name})

            if self._result is not None:
                break

        if self._result is not None:
            return EscalateResult(self._result)
        # 到达轮数上限仍无结论：视作未能升级，安静放弃。
        return EscalateResult({"escalated": False, "reason": f"未在 {_MAX_ROUNDS} 轮内实现显著升级"})

    def _dispatch(self, name: str, args: dict) -> dict:
        if self.cancel_event.is_set():
            return {"ok": False, "cancelled": True, "error": "扩大危害深挖已被取消"}
        if name == "http_request":
            url = args.get("url")
            if not url:
                return {"ok": False, "error": "http_request 缺少 url"}
            self._emit("escalate_http", url=url)
            return self.executor.http_request(
                url=url, method=args.get("method", "GET"),
                headers=args.get("headers"), data=args.get("data"),
                json_body=args.get("json_body"), follow_redirects=args.get("follow_redirects", False),
                confirm_destructive=args.get("confirm_destructive", False),
                confirm_reason=args.get("confirm_reason") or "",
            )
        if name == "run_shell":
            command = args.get("command")
            if not command:
                return {"ok": False, "error": "run_shell 缺少 command"}
            self._emit("escalate_shell", command=str(args.get("command", ""))[:160])
            return self.executor.run_shell(
                command, timeout=args.get("timeout"),
                confirm_destructive=args.get("confirm_destructive", False),
                confirm_reason=args.get("confirm_reason") or "",
            )
        if name == "session_set":
            self._emit("escalate_session",
                       has_cookies=bool(args.get("cookies")), has_headers=bool(args.get("headers")))
            return self.executor.session_set(
                cookies=args.get("cookies"), headers=args.get("headers"),
                clear=bool(args.get("clear", False)),
            )
        if name == "submit_escalation":
            self._result = {
                "escalated": True,
                "vuln_type": args.get("vuln_type", ""),
                "title": args.get("title", ""),
                "severity": args.get("severity", ""),
                "description": args.get("description", ""),
                "kill_chain": args.get("kill_chain", []) if isinstance(args.get("kill_chain"), list) else [],
                "poc": args.get("poc", ""),
                "raw_request": args.get("raw_request", ""),
                "raw_response": args.get("raw_response", ""),
                "affected_scope": args.get("affected_scope", ""),
                "impact_count": int(args.get("impact_count", 0) or 0),
            }
            self._emit("escalate_done", title=self._result["title"], severity=self._result["severity"])
            return {"ok": True, "message": "已记录升级结论。"}
        if name == "abandon_escalation":
            self._result = {"escalated": False, "reason": args.get("reason", "")}
            self._emit("escalate_abandon", reason=str(args.get("reason", ""))[:200])
            return {"ok": True, "message": "已放弃本次升级。"}
        return {"ok": False, "error": f"未知工具: {name}"}
