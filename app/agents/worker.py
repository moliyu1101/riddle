"""Worker Agent：1:1 绑定一个目标，LLM + 工具真实挖洞。

流程（对应设计文档 §5.5）：
  只给一个裸 target → LLM 完全自主侦察+挖掘（function calling 循环）
  → 发现漏洞调 submit_finding → 挖完调 finish → 产出 WorkerResult。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from pydantic import ValidationError

from app.agents.history import compact_messages
from app.agents.prompts import is_enterprise_src, normalize_worker_prompt_version, worker_system_prompt
from app.agents.backdoor_proof import weak_backdoor_block_reason
from app.agents.edu_scope import edu_bombing_block_reason
from app.agents.exploit_chain import exploit_chain_block, weak_exploit_reason
from app.agents.write_proof import HARMLESS_PROTOCOL, weak_write_block_reason
from app.agents import auth_bootstrap
from app.agents.lessons import render_lessons_block
from app.config import worker_config
from app import dedup
from app.tools.evidence_capture import capture_snapshot, load_snapshot, save_snapshot
from app.llm.client import LLMClient, LLMError, llm_error_event_fields
from app.schemas import Finding, Verdict, WorkerResult
from app.tools.evidence_trail import latest_trail as _latest_evidence_trail
from app.tools.evidence_trail import load_trail as _load_evidence_trail
from app.tools.executor import ToolExecutor
from app.tools.schemas import (
    JS_ANALYZER_TOOL_SCHEMAS,
    SESSION_TOOL_SCHEMAS,
    TOOL_SCHEMAS,
)


_BROAD_NMAP_RE = re.compile(r"\bnmap\b[\s\S]*(?:-p\s*(?:-|1-10000|1-65535|0-65535)|--top-ports\s+\d{3,})", re.IGNORECASE)
_SLEEP_RE = re.compile(r"\bsleep\s+(\d+)", re.IGNORECASE)
_FOR_LIST_RE = re.compile(r"\bfor\s+\w+\s+in\s+([^;\n]+);", re.IGNORECASE)
_JS_INTENT_RE = re.compile(
    r"(?i)(?:审计|分析|提取|查看|深入|打|挖).{0,24}(?:js|javascript|前端|script|接口|密钥|secret|token)"
    r"|(?:^|[\s/\"'=])[\w./-]+\.js(?:[?#\"'\s>)]|$)|<script\b|id=[\"'](?:app|root)[\"']"
)
_WORKER_STATIC_PREFIX = (
    "下一条是目标/情报。只打当前目标；确认无攻击面才快速 finish。工具按信号开放，JS 线索再用 analyze_javascript。"
)

# LLM 调用失败时，worker 内软重试次数（清粘性后换端点/同端点再试），耗尽才整轮收尾回队。
_WORKER_LLM_SOFT_RETRIES = int(os.environ.get("WORKER_LLM_SOFT_RETRIES", "3"))
_WORKER_LLM_SOFT_RETRY_KINDS = {
    "rate_limit", "timeout", "network", "upstream", "provider_cooldown",
    "blocked", "unknown", "quota",
}

# 周期复盘循环：挖洞像人一样不能一路闷头打——每 REFLECT_EVERY 轮让 worker 停下来，
# 对照结构化认知卡复盘「证实了什么/排除了什么/走了哪些弯路/方向是否有效/下一步干嘛」，
# 并把复盘结果写回认知卡(update_cognition)，再决定继续或收敛。避免一路钻牛角尖、
# 或目标早已无望却空转到收尾。
REFLECT_EVERY = int(os.environ.get("WORKER_REFLECT_EVERY", "8"))
_REFLECT_PROMPT = (
    "# 复盘时刻（周期性停一停，像人一样想清楚再动手）\n"
    "你已经连续打了一段，先别急着发下一个请求。对照上面的认知卡做一次结构化复盘：\n"
    "① 已证实了什么（能否把所有证据串成一条受害链路）？\n"
    "② 这８轮走了哪些弯路、排除了哪些方向（写进 excluded，避免再踩）？\n"
    "③ 还有哪些活跃线索没验证（leads 里挑一个优先级最高的）？\n"
    "④ 当前方向还值得追吗：若只是枚举/网络/公开数据、换任何参数都拿不到实质，就收敛 finish(no_vuln)；\n"
    "   若还有一条明确线索，写下更新的下一步计划。\n"
    "请调用 update_cognition 把结论落盘（confirmed/excluded/leads/plan 四个槽都尽量更新），"
    "并用 update_notes 把本轮进度写进工作笔记（【已发现】/【已试失败】/【当前突破口】/【下一步】），"
    "然后带着最清晰的下一步继续调工具验证，或 finish。不要为了凑复盘而空转。"
)


def _shell_env_hint() -> str:
    """Windows 本地开发环境：run_shell 走 cmd.exe，提示 worker 改用 Windows 兼容命令。"""
    if os.name != "nt":
        return ""
    return (
        "\n\n# 当前 shell 环境（重要）\n"
        "run_shell 运行在 Windows cmd 上，不支持 Linux 命令。请用 Windows 兼容命令：\n"
        "- 列目录：dir / Get-ChildItem；读文件：type / Get-Content；文本搜索：findstr / Select-String\n"
        "- HTTP 请求：curl.exe -k -s（Windows 自带）；或 powershell 的 Invoke-WebRequest\n"
        "- 路径用 C:\\xxx 或 C:/xxx，不要用 /tmp/xxx、~、$HOME、/dev/null\n"
        "- 不要用 grep / ls / cat / openssl / timeout / rm -rf / for 循环（bash 语法）等 Linux 专属命令\n"
        "- 写临时文件建议放当前工作目录或 C:/temp\n"
    )


class Worker:
    def __init__(
        self,
        target: str,
        llm: Optional[LLMClient] = None,
        on_event: Optional[Callable[[str, dict], None]] = None,
        deepen_context: Optional[dict] = None,
        target_meta: Optional[dict] = None,
        duplicate_history: Optional[list[dict]] = None,
        cancel_event: Optional[threading.Event] = None,
        src_type: str = "edusrc",
        fofa_key: str = "",
        fofa_base_url: str = "",
        engine: str = "fofa",
        prompt_version: str | None = None,
        src_rules: str = "",
        guard_ops: Optional[list[str]] = None,
        pop_directive: Optional[Callable[[], Optional[str]]] = None,
        blackboard: Optional[Any] = None,
        worker_id: str = "",
    ):
        self.target = target
        self.llm = llm or LLMClient()
        self.cancel_event = cancel_event or threading.Event()
        self.src_type = src_type
        self._enterprise = is_enterprise_src(src_type)
        self.src_rules = src_rules or ""
        self.prompt_version = normalize_worker_prompt_version(prompt_version or worker_config.prompt_version)
        # 单站协作黑板：只在 site_ 来源任务中由编排层传入，普通任务为 None 完全降级。
        self.blackboard = blackboard
        self.worker_id = worker_id or ""
        self._blackboard_block_shown = False
        self.executor = ToolExecutor(
            target, cancel_event=self.cancel_event,
            enterprise=self._enterprise, fofa_key=fofa_key, fofa_base_url=fofa_base_url,
            engine=engine, src_rules=self.src_rules, guard_ops=guard_ops,
        )
        self.findings: list[Finding] = []
        self.on_event = on_event or (lambda kind, data: None)
        self._finished: Optional[dict] = None
        # 审核打回的定向深挖任务：{directive, vuln_type, original_title, original_summary}
        self.deepen_context = deepen_context or None
        # 人工 mid-run 指令：编排层按轮次弹出一条，注入下一轮 user 消息。
        self.pop_directive = pop_directive
        # 资产情报：候选归属学校/org/title，供 worker 核实并写进报告 owner
        self.target_meta = target_meta or {}
        # 同一 target 历史已提交漏洞摘要，用于 worker 提交前查重（superseded 不传入）
        self.duplicate_history = duplicate_history or []
        # JS 审计工具 schema 体积较大，默认只在目标/情报/响应出现 JS 信号后开放。
        self._js_tool_enabled = self._initial_js_tool_enabled()
        self._js_signal_seen = self._js_tool_enabled
        self._tool_counts: dict[str, int] = {}
        self._last_js_analysis_round = 0
        self._post_js_validation_count = 0
        # worker 主动上报的可复用情报（纯内存收集，由编排层 async 统一落全局情报库）
        self._reported_intel: list[dict] = []
        # 单站协作覆盖记录（API/入口/测试项摘要），由编排层写入事件流供后续 worker 复用。
        self._reported_coverage: list[dict] = []
        # 本轮已探测的 URL（http_request 实际发起的请求），LLM 中断时随断点保存，
        # 恢复后注入给 worker 避免重复探测同一批端点。
        self._probed_urls: set[str] = set()

    def _emit(self, kind: str, **data: Any) -> None:
        self.on_event(kind, data)

    def _initial_js_tool_enabled(self) -> bool:
        if worker_config.js_tool_always_on:
            return True
        meta = self.target_meta or {}
        if (meta.get("site_collab_route") or {}).get("js_first"):
            return True
        text = "\n".join([
            self.target,
            str(meta.get("title") or ""),
            str(meta.get("priority_reason") or ""),
            str((meta.get("playbook_route") or {}).get("route_id") or ""),
            " ".join((meta.get("playbook_route") or {}).get("tags") or []),
            str(meta.get("playbook_block") or ""),
            json.dumps(self.deepen_context or {}, ensure_ascii=False),
        ])
        low = text.lower()
        if _JS_INTENT_RE.search(text):
            return True
        return any(marker in low for marker in (
            "spa", "webpack", "vue", "react", "angular", "frontend", "front-end",
            "javascript", "script", "api_exposed", "secret", "前端",
        ))

    def _intel_block(self) -> str:
        m = self.target_meta or {}
        school = (m.get("school") or "").strip()
        org = (m.get("org") or "").strip()
        title = (m.get("title") or "").strip()
        source = (m.get("source") or "").strip()
        site = self._site_collab_block()
        priority_reason = (m.get("priority_reason") or "").strip()
        playbook = self._playbook_block()
        lessons = self._lessons_block()
        business = self._business_block()
        diff = self._diff_block()
        state_machine = self._state_machine_block()
        biz_test = self._biz_test_block()
        exploit = self._exploit_discipline_block()
        blackboard = self._blackboard_block()
        # 即使没有资产情报，只要有泄露凭证/情报库命中也要带出去（企业目标常无 school/org/title）。
        if not (school or org or title or source):
            return site + playbook + lessons + business + diff + state_machine + biz_test + exploit + blackboard + self._user_auth_block() + self._creds_block() + self._intel_lib_block()
        owner_label = "候选归属单位/系统" if is_enterprise_src(self.src_type) else "候选归属学校"
        prefix = [b.rstrip() for b in (site, playbook, lessons, business, diff, state_machine, biz_test, exploit, blackboard) if b.strip()]
        lines = prefix + ["# 资产情报（搜集阶段提供，需你核实）"]
        if school:
            lines.append(f"- {owner_label}：{school}")
        if org:
            lines.append(f"- 单位(org)：{org}")
        if title:
            lines.append(f"- 站点标题：{title}")
        if source == "killsweep":
            lines.append("- 来源：通杀验证目标（已由通杀 Hunter 找到同款系统并验证过 1 个点）")
            if priority_reason:
                lines.append(f"- 通杀上下文：{priority_reason}")
            lines.append("注意：你只负责把当前站点的实际漏洞证据打出来，不要围绕该产品继续做通杀扩散判断。")
        lines.append("提交漏洞时，请核实归属（域名/备案/证书CN/页脚版权/FOFA org/登录页品牌）后把最终归属写进 submit_finding 的 owner 字段。")
        return "\n".join(lines) + "\n\n" + self._user_auth_block() + self._creds_block() + self._intel_lib_block()

    def _user_auth_block(self) -> str:
        """用户在凭据区提供的 Cookie/账密（系统已尝试后的回执）。"""
        ctx = (self.target_meta or {}).get("user_auth") or (self.target_meta or {}).get("auth_context")
        attempt = (self.target_meta or {}).get("auth_attempt")
        if not ctx and not attempt:
            return ""
        return auth_bootstrap.user_auth_prompt_block(ctx, attempt)

    def _bootstrap_user_auth(self) -> None:
        """启动时确定性使用用户凭据：注入 Cookie/Bearer 或尝试账密登录，并 emit 反馈。"""
        ctx = (self.target_meta or {}).get("user_auth") or (self.target_meta or {}).get("auth_context")
        if not ctx:
            return
        result = auth_bootstrap.bootstrap_auth(self.executor, ctx, self.target)
        payload = result.as_event()
        self.target_meta["auth_attempt"] = payload
        self._emit(
            "auth_status",
            message=auth_bootstrap.format_auth_status_message(result),
            **payload,
        )

    def _autotag_injected_if_session(self) -> None:
        """session_set 成功 / 续挖恢复会话后，若已持有可用 cookie/header 凭据，自动标记为
        『已在当前会话注入』并上报看板（只暴露字段名，绝不落会话明文）。

        幂等：auth 已是更高的 login_ok 或本就在 injected 则不重复标记，避免看板闪变。
        供同目标断点续挖复用：后续轮次/续挖 worker 看到已注入会话，直接带登录态深入。
        """
        try:
            ex = self.executor
            cookies = dict(getattr(ex, "_session_cookies", {}) or {})
            headers = dict(getattr(ex, "_session_headers", {}) or {})
            if not cookies and not headers:
                return
            cur = (self.target_meta or {}).get("auth_attempt") or {}
            if cur.get("status") in ("injected", "login_ok"):
                return
            names = sorted(cookies.keys())
            hnames = sorted(headers.keys())
            payload = {
                "used": True,
                "matched": True,
                "status": "injected",
                "kinds": (["cookie"] if cookies else []) + (["bearer"] if headers else []),
                "matched_by": "自动捕获",
                "binding_target": self.target,
                "reason": "挖掘中 session_set 成功，已注入会话，后续请求自动携带",
                "cookie_names": names[:20],
                "header_names": hnames[:20],
            }
            self.target_meta["auth_attempt"] = payload
            self._emit(
                "auth_status",
                message="已注入会话（session_set 自动捕获），后续请求自动携带。",
                **payload,
            )
        except Exception:
            pass

    def _playbook_block(self) -> str:
        """目标打法路由：编排层生成的短路线块。"""
        return (self.target_meta or {}).get("playbook_block") or ""

    def _lessons_block(self) -> str:
        """经验知识引导：按目标的技术标签/玩路/标题/归属匹配共通打法与教训，命中才注入。"""
        m = self.target_meta or {}
        route = (m.get("playbook_route") or {}) or {}
        signals = [
            str(route.get("route_id") or ""),
            " ".join(route.get("tags") or []),
            str(route.get("label") or ""),
            str(m.get("title") or ""),
            str(m.get("priority_reason") or ""),
            str(m.get("school") or "") + " " + str(m.get("org") or ""),
            str(m.get("playbook_block") or ""),
        ]
        return render_lessons_block(signals)

    def _business_block(self) -> str:
        """业务上下文画像：编排层按站点标题/归属推断的业务类型与针对性测试重点。"""
        return (self.target_meta or {}).get("business_block") or ""

    def _diff_block(self) -> str:
        """差异化策略：大众洞规避 + 差异化重点，引导挖别人挖不到的洞。"""
        return (self.target_meta or {}).get("diff_block") or ""

    def _state_machine_block(self) -> str:
        """业务状态机引导：多步业务流绕过测试手法。"""
        return (self.target_meta or {}).get("state_machine_block") or ""

    def _biz_test_block(self) -> str:
        """业务逻辑测试模板：按业务类型给结构化可执行清单，逐条实测。"""
        return (self.target_meta or {}).get("biz_test_block") or ""

    def _exploit_discipline_block(self) -> str:
        """利用链纪律：发现漏洞后先深化利用再提交，别交半成品。"""
        return (
            "# 漏洞利用纪律（发现漏洞后）\n"
            "发现疑似漏洞后，先按类型深化利用再提交，别交半成品（只有 200/成功文案不算实锤）：\n"
            "- 未授权/越权：证明能读到/改到真实数据；抽 ID/手机号打其它接口；读升写；遍历量化规模\n"
            "- 信息泄露：证明泄露真实敏感数据；抽凭证打接口/登录；读配置抠密钥\n"
            "- SQL 注入：注出库名/表名/数据，别停在疑似\n"
            "- XSS：确认 payload 回显/存储执行；SSRF：确认服务器回连/时间差\n"
            "- 弱口令：确认能登录（Set-Cookie/后台数据）；上传：确认可访问/执行\n"
            "实锤标准：有真实数据/状态变化/回显。打不出实锤就 finish(deepen_lead) 写清缺哪一步。"
        )

    def _site_collab_block(self) -> str:
        """单站协作路线块：当前 worker 的分工和已有覆盖摘要。"""
        return (self.target_meta or {}).get("site_collab_block") or ""

    def _route_source(self) -> str:
        """当前 worker 所属单站协作路线（site_map/site_auth/site_fXX 等）。

        单站协作下 target_meta 会带 ln_route / site_collab_route 里的 source，
        传给黑板供前端按路线过滤情报；非单站任务返回空串。
        """
        meta = self.target_meta or {}
        for key in ("site_collab_route", "ln_route"):
            route = (meta.get(key) or {}).get("source") or ""
            if route:
                return str(route)[:40]
        return ""

    def _blackboard_block(self) -> str:
        """协作黑板实时态势：同站其它 worker 已探测/已覆盖/共享线索，避免重复路线。

        黑板为空或未启用（普通任务 blackboard=None）时返回空串。
        """
        bb = getattr(self, "blackboard", None)
        if bb is None:
            return ""
        try:
            text = bb.summary(worker_id=self.worker_id)
        except Exception:
            return ""
        if not text:
            return ""
        self._blackboard_block_shown = True
        return text + "\n\n"

    def _intel_lib_block(self) -> str:
        """全局情报库命中（编排层触发式检索后注入的现成文本块）。"""
        return (self.target_meta or {}).get("intel_block") or ""

    def _creds_block(self) -> str:
        """泄露凭证情报：搜集阶段查到的该域已泄露账号密码（已过滤打分）。"""
        creds = (self.target_meta or {}).get("leaked_creds") or []
        if not creds:
            return ""
        lines = [
            "# 泄露凭证情报（搜集阶段已过滤打分）",
            "以下账密按可用概率排序；它们只是深挖入场券，不是漏洞本身。",
        ]
        for c in creds[:12]:
            u = (c.get("username") or "")[:40]
            p = (c.get("password") or "")[:40]
            h = (c.get("host") or "")[:40]
            lines.append(f"- {u} : {p}  （泄露于 {h}）")
        lines.append("纪律：登录成功/CASTGC/session/个人中心本身不算洞；必须继续实证死规矩敏感数据、越权、敏感写操作、注入/上传 getshell 或具体业务系统危害。没实锤就写 deepen_lead；试 2-3 个高价值凭证失败就换攻击面；严禁改密。")
        return "\n".join(lines) + "\n\n"

    def _duplicate_block(self) -> str:
        if not self.duplicate_history:
            return ""
        lines = ["# 统一查重上下文（跨任务同 host / 通杀明细，勿重复提交）"]
        lines.append(f"后端完整查重池含 {len(self.duplicate_history)} 条；这里只列摘要。提交前必须调用 check_duplicate_finding。")
        lines.append("duplicate=true 才禁止提交同系统同洞；其它 endpoint/类型/证据链可继续。")
        for item in self.duplicate_history[:6]:
            reason = (item.get("dedup_reason") or "")[:80]
            lines.append(
                f"- 来源={item.get('source','history')}；[{item.get('vuln_type','')}] {item.get('title','')} "
                f"@ {item.get('target_url','')}（状态：{item.get('status','')}；原因：{reason or '已存在'}）"
            )
        if len(self.duplicate_history) > 6:
            lines.append(f"- 其余 {len(self.duplicate_history) - 6} 条仅在后台查重池中。")
        return "\n".join(lines) + "\n\n"

    def run(self) -> WorkerResult:
        # 用户凭据：在任何 LLM 轮次前强制尝试，结果写进 target_meta 供 prompt 与看板。
        try:
            self._bootstrap_user_auth()
        except Exception as e:
            self._emit("auth_status", used=True, matched=True, status="login_fail",
                       kinds=[], reason=f"凭据启动异常: {type(e).__name__}: {e}"[:300],
                       message=f"凭据启动异常: {e}")

        # 上一轮 LLM 中断留下的进度：笔记 + 会话态先恢复，再开挖
        self._restore_interrupt_progress()

        if self.deepen_context:
            user_content = self._intel_block() + self._duplicate_block() + self._deepen_brief()
            self._emit("worker_start", target=self.target, mode="deepen", prompt_version=self.prompt_version)
        else:
            user_content = (
                self._intel_block()
                + self._duplicate_block()
                + f"目标：{self.target}\n\n"
                + "只挖此目标；自主侦察取证，结束调用 finish。"
            )
            self._emit("worker_start", target=self.target, prompt_version=self.prompt_version)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": worker_system_prompt(self.src_type, self.prompt_version, src_rules=self.src_rules) + _shell_env_hint()},
            {"role": "user", "content": _WORKER_STATIC_PREFIX},
            {"role": "user", "content": user_content},
        ]

        rounds = 0
        no_tool_rounds = 0
        # auto 兼容模式下，检测到「哑模型」(全程零工具)时只自愈切一次提示词模拟，避免反复切
        tool_compat_selfheal_tried = False
        consecutive_failures = 0
        consecutive_blocked = 0
        consecutive_arg_errors = 0
        consecutive_network_failures = 0
        consecutive_llm_failures = 0
        # 按 src_type 取预算：企业模式给更大深挖空间（110/60），edu 走量沿用 90/45。
        max_rounds, soft_rounds = self._route_rounds(*worker_config.rounds_for(self.src_type))
        while rounds < max_rounds:
            if self.cancel_event.is_set():
                return self._cancelled_result(rounds)
            # 人工实时指令：在开新一轮 LLM 前注入，优先于自主打法。
            # 用 getattr：部分单测用 Worker.__new__ 绕过 __init__。
            directive = ""
            pop_directive = getattr(self, "pop_directive", None)
            if pop_directive:
                try:
                    directive = (pop_directive() or "").strip()
                except Exception:
                    directive = ""
            if directive:
                messages.append({
                    "role": "user",
                    "content": (
                        "# 人工实时指令（优先执行）\n"
                        f"{directive}\n\n"
                        "请按上述指令调整本轮打法，继续调用工具验证或 finish。"
                    ),
                })
                self._emit("worker_directive", round=rounds + 1, text=directive[:500])
            rounds += 1
            try:
                self._emit("llm_round_start", round=rounds)
                tools = list(TOOL_SCHEMAS)
                # 会话保持工具全模式开放：拿到泄露/用户凭证登录后固化登录态再深挖。
                tools += SESSION_TOOL_SCHEMAS
                if self._js_tool_enabled:
                    tools += JS_ANALYZER_TOOL_SCHEMAS
                send_messages = compact_messages(messages, rounds)
                # 每轮注入当前状态块（会话态 + 认知卡 + 工作笔记）——临时消息，不存入 messages 历史，
                # 避免累积膨胀；每轮新鲜生成，始终反映最新的 cookie/token/notes/认知卡。
                # 这是连续性的核心：即使旧历史被压缩成摘要，worker 仍能看到自己当前
                # 持有哪些登录态、认知卡里证实/排除了什么、还有哪些线索没验证，不会跨轮"失忆"。
                send_messages.append({"role": "user", "content": self.executor.session_status_block()})
                # 单站协作：每轮注入黑板实时态势，让 worker 看到同站其它 worker 的最新进展，
                # 主动错开已探测 URL / 已覆盖入口 / 已有人验证的线索，避免重复路线。
                bb_block = self._blackboard_block()
                if bb_block:
                    send_messages.append({"role": "user", "content": bb_block})
                # 周期复盘：每 REFLECT_EVERY 轮让 worker 停下来结构化复盘并写回认知卡，
                # 像人一样隔段时间退一步看全局，避免一路钻牛角尖或空转到收尾。
                if REFLECT_EVERY > 0 and rounds > 0 and rounds % REFLECT_EVERY == 0:
                    self._emit("worker_reflect", round=rounds)
                    send_messages.append({"role": "user", "content": _REFLECT_PROMPT})
                msg = self.llm.chat(send_messages, tools=tools, tool_choice="auto")
                consecutive_llm_failures = 0
            except Exception as e:
                fields = llm_error_event_fields(e)
                self._emit("llm_error", **fields)
                failure_kind = e.kind if isinstance(e, LLMError) else ""
                retry_after = e.retry_after if isinstance(e, LLMError) else 0
                if self._should_soft_retry_llm(e) and consecutive_llm_failures < _WORKER_LLM_SOFT_RETRIES:
                    consecutive_llm_failures += 1
                    clearer = getattr(self.llm, "clear_sticky_provider", None)
                    if callable(clearer):
                        clearer()
                    wait_s = min(2 ** (consecutive_llm_failures - 1), 8)
                    if retry_after:
                        wait_s = max(wait_s, min(int(retry_after), 30))
                    self._emit(
                        "llm_soft_retry",
                        round=rounds,
                        attempt=consecutive_llm_failures,
                        max_attempts=_WORKER_LLM_SOFT_RETRIES,
                        failure_kind=failure_kind or "unknown",
                        wait_seconds=wait_s,
                        error=str(e)[:240],
                        error_copy=fields.get("error_copy") or str(e),
                        detail=fields.get("detail") or "",
                        diagnostic=fields.get("diagnostic") or "",
                    )
                    # 不消耗轮次预算：基础设施抖动不应吃掉挖掘配额
                    rounds = max(0, rounds - 1)
                    if self.cancel_event.wait(wait_s):
                        return self._cancelled_result(rounds)
                    continue
                err_text = str(e)
                if not err_text.startswith("LLM"):
                    err_text = f"LLM 调用失败：{err_text}"
                return self._llm_interrupt_result(
                    rounds=rounds,
                    error=err_text,
                    failure_kind=failure_kind,
                    retry_after=retry_after,
                )
            if self.cancel_event.is_set():
                return self._cancelled_result(rounds)

            # 模型可能只回文本（思考），也可能带 tool_calls
            tool_calls = getattr(msg, "tool_calls", None)
            assistant_msg: dict[str, Any] = {"role": "assistant", "content": msg.content or ""}
            if tool_calls:
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                    }
                    for tc in tool_calls
                ]
            messages.append(assistant_msg)

            # 是否在本轮要插入 JS 工具提示。注意：若本轮带 tool_calls，这条 user 提示必须
            # 延迟到所有 tool 响应 append 之后再插入，否则会破坏 assistant(tool_calls) → tool
            # 的连续性，触发 400。
            js_hint_pending = False
            if msg.content:
                self._emit("worker_thought", round=rounds, text=msg.content[:2000])
                if self._maybe_enable_js_tool(msg.content, "模型明确提出 JS/前端分析意图"):
                    js_hint_pending = True
            js_hint_msg = {
                "role": "user",
                "content": "JS 工具已开放：analyze_javascript 只给线索，必须再用 http_request/run_shell 实证。",
            }
            if js_hint_pending and not tool_calls:
                messages.append(js_hint_msg)
                js_hint_pending = False

            if not tool_calls:
                no_tool_rounds += 1
                # auto 自愈：全程一个工具都没调过 + 是 auto 兼容模式 → 疑似「接受 tools 但不真正
                # 调工具」的哑模型。提前(第3轮)让 LLM 客户端把当前端点切成提示词模拟再给它机会，
                # 而不是空转到第6轮才放弃、还要用户手动设 RIDDLE_TOOL_COMPAT=prompt。
                # getattr 防御：单测里 self.llm 可能是 mock，没有该方法。
                if (not tool_compat_selfheal_tried
                        and no_tool_rounds >= 3
                        and sum(self._tool_counts.values()) == 0):
                    switch = getattr(self.llm, "force_prompt_tools_current", None)
                    if callable(switch) and switch():
                        tool_compat_selfheal_tried = True
                        no_tool_rounds = 0
                        self._emit("tool_compat_switch", round=rounds,
                                   detail="模型全程零工具，自动切提示词模拟工具调用重试")
                        messages.append({"role": "user", "content": "（已切换为提示词模拟工具调用）请按工具协议继续调用工具，或 finish。"})
                        continue
                if no_tool_rounds >= 6:
                    # 两种情况分开说清楚，别再堆黑话：
                    # ① 全程一个工具都没调过 → 是所选模型本身不会 function calling（哑模型）。
                    #    注意：真·报错「不支持 tools」的已被 LLM 层自动切提示词模拟兜底，走不到这里；
                    #    能走到这里说明模型没报错、返回正常，只是从不发起工具调用。
                    # ② 之前调过工具、但最近连续 6 轮又不调也不 finish → 模型在原地绕圈，空转收尾。
                    if sum(self._tool_counts.values()) == 0:
                        if tool_compat_selfheal_tried:
                            reason_msg = (
                                "没挖成：当前模型不会调用工具，已自动尝试提示词模拟仍无效。"
                                "请更换支持工具调用的模型(DeepSeek/GPT/Claude/通义/Kimi 等)。"
                            )
                        else:
                            reason_msg = (
                                "没挖成：当前模型不会调用工具(function calling)，连续 6 轮只回文字、不调工具，没法挖。"
                                "不是目标站问题，也不是报错，是模型能力不够。"
                                "解决：换个支持工具调用的模型(DeepSeek/GPT/Claude/通义/Kimi 等)，"
                                "或在服务端设 RIDDLE_TOOL_COMPAT=prompt 强制模拟。设置页「测试连接」可检测。"
                            )
                    else:
                        reason_msg = (
                            "自动收尾：模型连续 6 轮既不调工具也不结束(finish)，在原地绕圈，已收尾。"
                            "可重试或换更强的模型。"
                        )
                    self._auto_finish(reason_msg, "model_behavior")
                    break
                # 没有工具调用也没结束，提醒模型继续或收尾
                messages.append({"role": "user", "content": "继续调用工具验证，或 finish。"})
                continue
            no_tool_rounds = 0

            # 逐个执行工具调用。
            # 关键：OpenAI 协议要求 assistant.tool_calls 里【每一个】tool_call_id 都必须有
            # 对应的 tool 响应消息，否则下一轮请求会 400（insufficient tool messages）。
            # 因此用 answered 跟踪已响应的 id，无论循环怎么提前退出（收敛 break / 取消），
            # 循环结束后都补齐所有未响应的 tool_call，保证 messages 历史始终合法。
            answered: set[str] = set()
            cancelled_mid = False
            blocked_nudge_pending = False
            for tc in tool_calls:
                if self.cancel_event.is_set():
                    cancelled_mid = True
                    break
                name = tc.function.name
                try:
                    args = json.loads(tc.function.arguments or "{}")
                except json.JSONDecodeError as e:
                    args = {}
                    result = self._tool_arg_error(
                        name, "valid JSON arguments",
                        f"工具参数不是合法 JSON：{e}。请修正后只做一个高价值验证请求；无明确验证动作就 finish(no_vuln)。",
                    )
                    self._emit("tool_arg_error", round=rounds, tool=name, error=str(e))
                else:
                    try:
                        result = self._dispatch(name, args, rounds)
                    except Exception as e:
                        result = {
                            "ok": False,
                            "error": f"工具执行异常: {type(e).__name__}: {e}",
                            "guidance": "不要重复触发同一异常。请换成最小可验证请求；若无明确路径就 finish(no_vuln)。",
                        }
                        self._emit("tool_exception", round=rounds, tool=name, error=str(e))
                # 工具失败时注入针对性恢复提示，帮模型在同流里快速纠偏而非从头推理。
                hint = self._recovery_hint(name, result)
                if hint:
                    result.setdefault("guidance", hint)
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "content": json.dumps(result, ensure_ascii=False),
                    "_round": rounds,
                    "_tool": name,
                })
                answered.add(tc.id)

                # JS 分析命中业务状态机信号：追加针对性提示，引导实测步骤跳过/状态篡改。
                if (
                    name == "analyze_javascript"
                    and isinstance(result, dict)
                    and result.get("state_machines")
                ):
                    messages.append({
                        "role": "user",
                        "content": (
                            "JS 分析发现业务状态机/多步流信号（step/status/flowToken/向导组件）。"
                            "这是业务逻辑洞的高价值入口：按 state_machines 的 probes 用 http_request 实测"
                            "步骤跳过/状态篡改/令牌重放/并发竞态，别只停在信号层面。"
                        ),
                    })

                # 页面 HTML 自动识别出业务系统：追加业务逻辑测试提示（手动清单无静态画像时尤其关键）。
                if (
                    name == "http_request"
                    and isinstance(result, dict)
                    and result.get("business")
                ):
                    biz = result["business"]
                    messages.append({
                        "role": "user",
                        "content": (
                            f"页面识别为疑似业务系统：{biz.get('label')}（conf={biz.get('confidence')}，"
                            f"证据：{'/'.join(biz.get('evidence') or [])[:200]}）。"
                            "这是业务逻辑洞的高价值入口：按该业务的功能模块测越权/状态机跳变/"
                            "并发竞态/参数篡改（如选课抢课、审批流、支付订单、预约名额），"
                            "别只停在通用漏洞扫描。"
                        ),
                    })

                outcome = self._tool_outcome(result)
                if outcome == "ok":
                    consecutive_failures = 0
                    consecutive_blocked = 0
                    consecutive_arg_errors = 0
                    consecutive_network_failures = 0
                    continue

                consecutive_failures += 1
                consecutive_blocked = consecutive_blocked + 1 if outcome == "blocked" else 0
                consecutive_arg_errors = consecutive_arg_errors + 1 if outcome == "arg_error" else 0
                consecutive_network_failures = consecutive_network_failures + 1 if outcome in ("network", "timeout") else 0

                if consecutive_blocked >= 2:
                    # 被策略拦截的是“方向错”，不是目标无漏洞。以前这里直接 auto_finish，
                    # 会造成目标在 1-2 秒内被判 no_vuln/dead。现在只纠偏，不把目标判死。
                    blocked_nudge_pending = True
                    consecutive_failures = 0
                    consecutive_blocked = 0
                    continue
                if consecutive_arg_errors >= 3:
                    self._auto_finish(
                        "连续 3 次工具参数错误，模型未修正，本轮未得到可靠结论。",
                        "tool_argument",
                    )
                    break
                if consecutive_network_failures >= 3:
                    self._auto_finish("连续 3 次网络/超时失败，目标当前不可稳定验证，系统自动收敛。")
                    break
                if consecutive_failures >= 8:
                    self._auto_finish("连续 8 次工具失败且无新证据，系统自动收敛。")
                    break

            # 补齐所有未响应的 tool_call，保证消息历史合法（防 400）。
            for tc in tool_calls:
                if tc.id not in answered:
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": json.dumps(
                            {"ok": False, "error": "该工具调用未执行（本轮已收敛或被取消）。"},
                            ensure_ascii=False,
                        ),
                    })

            if cancelled_mid:
                return self._cancelled_result(rounds)

            # tool 响应已全部 append，此时再补上延迟的 JS 工具提示，保证顺序合法。
            if js_hint_pending:
                messages.append(js_hint_msg)

            if self._finished is not None:
                break

            if blocked_nudge_pending:
                messages.append({
                    "role": "user",
                    "content": (
                        "低价值动作已拦截。改做 JS/API/登录/上传/导出/Swagger/actuator 等明确入口的最小实证；别泛扫或打姊妹域。"
                    ),
                })

            # 早收敛提醒：尽早打断低价值空转，但只提醒，不硬杀复杂目标。
            if not self.findings and rounds in (12, 20, 30):
                messages.append({
                    "role": "user",
                    "content": (
                        f"收敛检查：{rounds} 轮无实锤。若仍是枚举/网络/公开数据，打最后一个明确验证或 finish(no_vuln)。"
                    ),
                })

            # 软引导：超过软阈值后，每轮催 worker 收尾，避免低价值空转（不硬杀）
            if rounds >= soft_rounds:
                remaining = max_rounds - rounds
                if remaining <= 5:
                    nudge = (
                        f"仅剩 {remaining} 轮：有洞 submit_finding 后 finish；无实锤立即 finish(no_vuln)。"
                    )
                else:
                    nudge = (
                        f"已 {rounds} 轮：聚焦实锤；别再穷举。无明确突破就 finish(no_vuln)。"
                    )
                messages.append({"role": "user", "content": nudge})

            # 周期落盘断点：硬杀/崩溃/重启也能从最近一次快照续挖，不丢已取证的进度。
            # 每轮都写（文件小、开销低），保证最坏情况下只损失一轮。
            self._write_resume_checkpoint(rounds)

        verdict = Verdict(self._finished["verdict"]) if self._finished else Verdict.error
        if self.findings and verdict == Verdict.no_vuln:
            verdict = Verdict.found  # 有漏洞却说 no_vuln，以实际为准
        # 正常结束（finish/自动收尾）时清掉检查点文件，避免下次从一个已跑完的目标
        # 误恢复旧进度；异常/被打断（error/cancelled）则保留，供硬杀后续挖兜底。
        if verdict in (Verdict.found.value, Verdict.no_vuln.value):
            try:
                path = self._resume_checkpoint_path()
                if path is not None and path.exists():
                    path.unlink(missing_ok=True)
            except Exception:
                pass
        return WorkerResult(
            target=self.target,
            verdict=verdict,
            findings=self.findings,
            summary=(self._finished or {}).get("summary", ""),
            rounds=rounds,
            error=(self._finished or {}).get("error") or (
                None if self._finished else f"达到最大轮数 {max_rounds} 未主动结束"
            ),
            failure_kind=(self._finished or {}).get("failure_kind", ""),
            deepen_lead=(self._finished or {}).get("deepen_lead", ""),
            reported_intel=self._reported_intel,
            reported_coverage=self._reported_coverage,
        )

    def _route_rounds(self, max_rounds: int, soft_rounds: int) -> tuple[int, int]:
        """按打法路线微调软收敛节奏。

        deep 路线（Actuator/Nacos/API docs/低代码等）更容易需要多步链路，延后软催收；
        static_low_value 才收紧硬上限，避免门户/官网长时间空转。
        """
        route = (self.target_meta or {}).get("playbook_route") or {}
        route_id = str(route.get("route_id") or "")
        intensity = str(route.get("intensity") or "")
        if intensity == "deep":
            soft_rounds = max(soft_rounds, min(max_rounds, 36 if not self._enterprise else 48))
        elif route_id == "static_low_value":
            soft_rounds = min(soft_rounds, 12)
            max_rounds = min(max_rounds, 30)
        elif intensity == "quick":
            soft_rounds = min(soft_rounds, 18)
        return max(1, max_rounds), max(1, min(soft_rounds, max_rounds))

    def _cancelled_result(self, rounds: int) -> WorkerResult:
        self._emit("worker_cancelled", target=self.target, round=rounds)
        return WorkerResult(
            target=self.target,
            verdict=Verdict.error,
            findings=self.findings,
            summary="任务已被 pause/stop 控制面取消，结果由 orchestrator 丢弃。",
            rounds=rounds,
            error="worker cancelled by task control",
            resume_context=self._build_resume_context(rounds),
        )

    @staticmethod
    def _should_soft_retry_llm(exc: BaseException) -> bool:
        """限流/超时/网络/冷却/策略拦截等：同轮内再试（池模式会换端点）。"""
        if isinstance(exc, LLMError):
            return exc.kind in _WORKER_LLM_SOFT_RETRY_KINDS or not exc.kind
        # 非 LLMError 的瞬时异常也给一次机会
        text = str(exc).lower()
        return any(k in text for k in ("timeout", "timed out", "connection", "network", "429", "rate"))

    def _resume_checkpoint_path(self):
        try:
            return self.executor.work_dir / "resume_checkpoint.json"
        except Exception:
            return None

    def _write_resume_checkpoint(self, rounds: int) -> None:
        """把断点快照周期落盘到目标专属文件，硬杀/崩溃/重启也能恢复。

        断点原本只在 worker「优雅返回」(llm_interrupt/cooldown/transient) 时才由
        orchestrator 写回 targets.deepen_context；容器重启或崩溃硬杀时这条路径可能
        走不完，目标只能拿老的 deepen_context 从 0 重扫（已发生的取证全部丢失）。
        这里每轮末尾主动把 resume 快照写盘，作为确定性兜底。任何失败静默忽略。
        """
        path = self._resume_checkpoint_path()
        if path is None:
            return
        resume = self._build_resume_context(rounds)
        if not resume:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".json.tmp")
            tmp.write_text(
                json.dumps(
                    {
                        "ts": time.time(),
                        "round": rounds,
                        "findings": len(self.findings),
                        "resume": resume,
                    },
                    ensure_ascii=False,
                ),
                encoding="utf-8",
            )
            os.replace(tmp, path)
        except Exception:
            pass

    def _load_resume_checkpoint(self) -> dict:
        """读取最近一次落盘的断点快照；不存在/损坏返回空 dict。"""
        path = self._resume_checkpoint_path()
        if path is None or not path.exists():
            return {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            resume = data.get("resume")
            if isinstance(resume, dict) and resume:
                self._emit(
                    "worker_resume",
                    source="checkpoint",
                    notes_len=len(str(resume.get("worker_notes") or "")),
                    cookies=sorted((resume.get("session_cookies") or {}).keys())[:20],
                    headers=sorted((resume.get("session_headers") or {}).keys())[:20],
                    probed_urls=len(resume.get("probed_urls") or []),
                    rounds_done=int(data.get("round") or 0),
                )
                return resume
        except Exception:
            return {}
        return {}

    def _recent_evidence_brief(self, max_items: int = 10) -> str:
        """从本地证据链取最近若干条工具动作，压缩成断点续挖可读的进度摘要。

        断点续挖的痛点：worker 依赖 LLM 主动调 update_notes 才有笔记，一旦中断时没记，
        恢复上下文只有 probed_urls，正在取证的漏洞（还没 submit）就丢了。而真实请求/响应
        早已随每次工具调用落盘（evidence_trail），此处把它们回灌进恢复指令，让续挖的
        worker 能看见自己上一轮在验证什么、拿到什么证据，接着干而不是从头泛扫。
        """
        try:
            trail = _load_evidence_trail(self.executor.work_dir)
        except Exception:
            return ""
        recent = [r for r in trail if r.get("kind") in ("http_request", "run_shell")][-max_items:]
        if not recent:
            return ""
        lines: list[str] = []
        for r in recent:
            url = (r.get("url") or "").strip()
            method = (r.get("method") or "").strip() or "GET"
            if r.get("kind") == "http_request":
                status = r.get("status")
                body = (r.get("body") or "").strip()
                snippet = body[:90].replace("\n", " ")
                lines.append(f"  · {method} {url} → HTTP {status}" + (f" | {snippet}" if snippet else ""))
            else:
                cmd = (r.get("notes") or "").replace("$ ", "", 1)
                out = (r.get("output") or "").strip()[:90].replace("\n", " ")
                lines.append(f"  · $ {cmd}" + (f" → {out}" if out else ""))
        return "\n".join(lines)

    def _restore_probed_from_trail(self) -> None:
        """从本目标证据链回灌已探测 URL，作为硬杀/重启后无中断上下文时的续挖兜底。

        证据链（evidence_trail.jsonl）里每次 http_request 都记录了真实请求的 URL，
        是比 LLM 笔记更可靠、永不丢失的进度来源。把它填进 _probed_urls，首轮
        _deepen_brief 就能看到上轮打过的点，避免从 0 泛扫。
        """
        if not hasattr(self, "_probed_urls"):
            self._probed_urls = set()
        try:
            trail = _load_evidence_trail(self.executor.work_dir)
        except Exception:
            return
        for r in trail:
            if r.get("kind") != "http_request":
                continue
            url = (r.get("url") or "").strip()
            if url:
                self._probed_urls.add(url)

    def _build_resume_context(self, rounds: int) -> dict:
        snap = self.executor.export_resume_state()
        notes = (snap.get("worker_notes") or "").strip()
        cookies = snap.get("session_cookies") or {}
        headers = snap.get("session_headers") or {}
        cognition = snap.get("cognition") or {}
        probed = sorted(getattr(self, "_probed_urls", set()) or set())[:120]
        has_progress = bool(notes or cognition or cookies or headers or self.findings or rounds >= 2)
        if not has_progress:
            return {}
        directive_bits = [
            "上一轮因 LLM 调用中断，请从已有进度继续，不要从头泛扫。",
        ]
        if getattr(self, "blackboard", None) is not None:
            directive_bits.append(
                "协作黑板仍在线：每轮会注入同站其它 worker 的最新共享情报，"
                "优先在黑板标注的未覆盖方向/新入口上继续，避免重复已探测路线。"
            )
        if notes:
            directive_bits.append(f"工作笔记：\n{notes[:1500]}")
        recent_evidence = self._recent_evidence_brief()
        if recent_evidence:
            directive_bits.append(
                "最近已执行的取证动作（继续验证这些点，别丢上一轮进度）：\n" + recent_evidence
            )
        if cognition:
            cog_lines = []
            for slot in ("confirmed", "excluded", "leads"):
                items = cognition.get(slot)
                if isinstance(items, list) and items:
                    cog_lines.append(f"  · {slot}：" + "；".join(str(x)[:200] for x in items[:6]))
            if cog_lines:
                directive_bits.append("已恢复认知卡：\n" + "\n".join(cog_lines))
        if cookies or headers:
            directive_bits.append(
                f"已恢复会话态（cookie {sorted(cookies.keys())}，鉴权头 {sorted(headers.keys())}），"
                "优先用现有登录态继续深挖。"
            )
        if self.findings:
            directive_bits.append(
                f"本轮已提交 {len(self.findings)} 个漏洞，继续挖其它入口或 finish。"
            )
        if probed:
            directive_bits.append(
                "已探测过的 URL（不要再重复请求，优先找新入口/深挖未验证点）：\n"
                + "\n".join(f"  · {u}" for u in probed[:60])
            )
        return {
            "directive": "\n".join(directive_bits)[:2000],
            "worker_notes": notes[:4000],
            "cognition": cognition,
            "session_cookies": cookies,
            "session_headers": headers,
            "probed_urls": probed,
            "shell_cwd": str(snap.get("shell_cwd") or ""),
            "shell_env": snap.get("shell_env") if isinstance(snap.get("shell_env"), dict) else {},
            "shell_history": snap.get("shell_history") if isinstance(snap.get("shell_history"), list) else [],
            "rounds_done": rounds,
            "source": "llm_interrupt",
            "original_summary": notes[:1000],
        }

    def _restore_interrupt_progress(self) -> None:
        # 首认领「已 submit 的暂存洞」：过去 submit 成功但因硬杀/崩溃未整轮落库的洞，
        # 永久在 findings_staged.jsonl 里。预填充 self.findings，保证即使在恢复后的
        # 续挖回合里 LLM 收尾判 no_vuln，这些洞也会随 _persist_worker_result 兜底落库，
        # 绝不因「提交过一次就丢」而静默遗漏。
        for _staged_f in self._load_staged_findings():
            try:
                _parsed = Finding(**_staged_f)
                self.findings.append(_parsed)
            except Exception:
                continue
        # 优先恢复「周期落盘检查点」：这是硬杀/崩溃/重启时最可靠的进度（可能比
        # deepen_context 更新），任何来源都先看它，文件里没有才回落 deepen_context。
        checkpoint = self._load_resume_checkpoint()
        ctx: dict = {}
        if checkpoint:
            ctx = dict(checkpoint)
            ctx["_from_checkpoint"] = True
            # 把检查点内容合并回 deepen_context，让首轮 _deepen_brief 走「断点续挖」
            # 分支并带上恢复的笔记/摘要；directive 优先用检查点自带，否则保留老的。
            _prev = dict(self.deepen_context or {})
            self.deepen_context = {
                "directive": str(
                    checkpoint.get("directive")
                    or _prev.get("directive")
                    or "从已恢复的笔记与取证进度继续，不要重新泛扫。"
                )[:2000],
                "original_title": _prev.get("original_title") or "LLM中断续挖",
                "original_summary": str(
                    checkpoint.get("original_summary")
                    or checkpoint.get("worker_notes")
                    or _prev.get("original_summary")
                    or ""
                )[:1000],
                "source": "llm_interrupt",
            }
        if not checkpoint:
            _ctx = self.deepen_context or {}
            if _ctx.get("source") != "llm_interrupt" and not (
                _ctx.get("worker_notes") or _ctx.get("session_cookies") or _ctx.get("session_headers")
            ):
                # 无中断上下文，仍是续挖场景：只要本目标证据链有真实取证动作，就回灌
                # 已探测 URL 并继续，让首轮 _deepen_brief 走断点分支、直接接上上轮进度，
                # 而不是从 0 泛扫。这是硬杀/重启后最关键的兜底。
                self._restore_probed_from_trail()
                if self._probed_urls:
                    self.deepen_context = {"source": "llm_interrupt"}
                    self._emit(
                        "worker_resume",
                        source="evidence_trail",
                        notes_len=0,
                        cookies=[],
                        headers=[],
                        probed_urls=len(self._probed_urls),
                        shell_cwd="",
                        rounds_done=0,
                    )
                return
            ctx = dict(_ctx)
        notes = str(ctx.get("worker_notes") or "")
        cookies = ctx.get("session_cookies") if isinstance(ctx.get("session_cookies"), dict) else {}
        headers = ctx.get("session_headers") if isinstance(ctx.get("session_headers"), dict) else {}
        cognition = ctx.get("cognition") if isinstance(ctx.get("cognition"), dict) else {}
        probed = ctx.get("probed_urls") if isinstance(ctx.get("probed_urls"), list) else []
        self.executor.restore_resume_state(
            worker_notes=notes,
            cognition=cognition,
            session_cookies=cookies,
            session_headers=headers,
            shell_cwd=str(ctx.get("shell_cwd") or ""),
            shell_env=ctx.get("shell_env") if isinstance(ctx.get("shell_env"), dict) else None,
            shell_history=ctx.get("shell_history") if isinstance(ctx.get("shell_history"), list) else None,
        )
        if not hasattr(self, "_probed_urls"):
            self._probed_urls = set()
        for u in probed:
            if isinstance(u, str) and u.strip():
                self._probed_urls.add(u.strip())
        # 续挖恢复成功后若已携带会话凭据，同样自动标记「已注入」（供看板显示 + 同目标复用）
        self._autotag_injected_if_session()
        self._emit(
            "worker_resume",
            notes_len=len(notes),
            cookies=sorted(cookies.keys())[:20],
            headers=sorted(headers.keys())[:20],
            probed_urls=len(self._probed_urls),
            shell_cwd=str(ctx.get("shell_cwd") or ""),
            rounds_done=int(ctx.get("rounds_done") or 0),
        )

    def _llm_interrupt_result(
        self,
        *,
        rounds: int,
        error: str,
        failure_kind: str,
        retry_after: int,
    ) -> WorkerResult:
        resume = self._build_resume_context(rounds)
        self._emit(
            "llm_interrupt",
            round=rounds,
            failure_kind=failure_kind or "unknown",
            has_resume=bool(resume),
            findings=len(self.findings),
            error=error[:240],
        )
        return WorkerResult(
            target=self.target,
            verdict=Verdict.found if self.findings else Verdict.error,
            findings=self.findings,
            summary=(
                "LLM 调用失败，已保存进度供回队续挖，此前发现的漏洞保留待提交。"
            ) if resume else "",
            rounds=rounds,
            error=error,
            failure_kind=failure_kind,
            retry_after_seconds=int(retry_after or 0),
            resume_context=resume,
        )

    def _deepen_brief(self) -> str:
        ctx = self.deepen_context or {}
        directive = ctx.get("directive", "").strip()
        original = ctx.get("original_title", "") or ctx.get("vuln_type", "")
        summary = (ctx.get("original_summary", "") or "").strip()
        # 断点恢复最可靠的进度来源是本目标证据链（evidence_trail.jsonl）：每次真实请求/响应
        # 都在工具调用那一刻落盘，与 LLM 笔记完全解耦。即便没有 deepen_context 笔记/checkpoint，
        # 续挖 worker 也应看到上一轮实际取证的证据，直接接着打，而不是从 0 泛扫。
        recent_evidence = ""
        try:
            recent_evidence = self._recent_evidence_brief()
        except Exception:
            recent_evidence = ""
        if ctx.get("source") == "llm_interrupt":
            parts = [
                f"目标：{self.target}",
                "",
                "⚡ 这是一次【断点续挖】：上一轮 LLM 中断，会话态与工作笔记已恢复。",
            ]
            if summary:
                parts.append(f"已有进度摘要：{summary[:800]}")
            # 恢复的工作笔记直接展示给续挖 worker，这是上一轮 LLM 主动记下的关键进度
            _notes = ""
            try:
                _notes = str(getattr(self.executor, "_worker_notes", "") or "")
            except Exception:
                _notes = ""
            if _notes:
                parts.append(f"上一轮工作笔记：\n{_notes[:1500]}")
            if recent_evidence:
                parts.append(
                    "上一轮已落盘的真实取证动作（继续验证这些点，别丢进度）：\n" + recent_evidence
                )
            if getattr(self, "_probed_urls", None):
                parts.append(
                    "已探测过的 URL（不要再重复请求，优先找新入口/深挖未验证点）：\n"
                    + "\n".join(f"  · {u}" for u in sorted(self._probed_urls)[:80])
                )
            parts += [
                "",
                f"👉 继续任务：{directive or '从已有笔记与登录态接着打，不要重新泛扫。'}",
                "",
                "要求：直接接上进度验证/深挖；打穿就 submit_finding；确认无增量就 finish。",
            ]
            return "\n".join(parts)
        parts = [
            f"目标：{self.target}",
            "",
            "⚡ 这是一次【定向深挖任务】，不是普通自由挖掘。",
            f"上一轮在此目标发现了线索：{original}",
        ]
        if summary:
            parts.append(f"原始线索摘要：{summary[:800]}")
        parts += [
            "",
            "审核判定：线索真实有价值，但利用链没打穿，所以打回让你专门攻这一个点。",
            f"👉 你这一轮的唯一任务：{directive}",
            "",
            "要求：",
            "1. 直奔主题，优先把上面这条利用链打穿，不要重新从头泛泛侦察。",
            "2. 打穿了（取到真实数据/造成实锤危害）就用 submit_finding 提交完整利用链 + 原始请求响应证据。",
            "3. 反复尝试确实打不穿、证明只是理论可能，就 finish(verdict=no_vuln) 并说明卡在哪，绝不交半成品。",
        ]
        return "\n".join(parts)

    def _dispatch(self, name: str, args: dict, rnd: int) -> dict:
        if name == "http_request":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "http_request", "url",
                    "必须传完整 URL。不要因为工具参数缺失中断任务；修正参数后只做一次高价值请求，"
                    "若没有明确攻击面就 finish(verdict=no_vuln)。",
                )
            self._emit("tool_http", round=rnd, url=url, method=args.get("method", "GET"))
            self._probed_urls.add(url)
            bb = getattr(self, "blackboard", None)
            if bb is not None:
                try:
                    bb.note_probed(url, worker_id=self.worker_id, source=self._route_source())
                except Exception:
                    pass
            self._maybe_enable_js_tool(url, "worker 主动请求 JS 资源")
            result = self.executor.http_request(
                url=url,
                method=args.get("method", "GET"),
                headers=args.get("headers"),
                data=args.get("data"),
                json_body=args.get("json_body"),
                follow_redirects=args.get("follow_redirects", False),
                confirm_destructive=args.get("confirm_destructive", False),
                confirm_reason=args.get("confirm_reason") or "",
            )
            if not self._js_tool_enabled and isinstance(result, dict):
                headers = result.get("response_headers") if isinstance(result.get("response_headers"), dict) else {}
                probe_text = "\n".join([
                    url,
                    str(result.get("url") or ""),
                    str(headers.get("content-type") or headers.get("Content-Type") or ""),
                    str(result.get("body") or "")[:1400],
                ])
                if self._maybe_enable_js_tool(probe_text, "HTTP 响应出现 JS/SPA/前端接口信号"):
                    result["guidance"] = (
                        (result.get("guidance") or "")
                        + " 检测到 JS/SPA/前端接口信号；下一轮可使用 analyze_javascript 提取接口和密钥线索。"
                    ).strip()
            # 业务类型自动识别：页面 HTML 命中业务系统时，动态注入业务逻辑测试引导。
            if isinstance(result, dict) and result.get("business"):
                biz = result["business"]
                result["guidance"] = (
                    (result.get("guidance") or "")
                    + f" 页面识别为疑似业务系统：{biz.get('label')}（conf={biz.get('confidence')}）。"
                    "按业务逻辑测：越权/状态机跳变/并发竞态/参数篡改，别停在通用漏洞扫描。"
                ).strip()
            # WAF 自动绕过感知：http_request 内置自动绕过，命中时输出事件流并给引导。
            if isinstance(result, dict) and result.get("waf"):
                waf = result["waf"]
                if waf.get("bypassed"):
                    self._emit(
                        "tool_waf_auto",
                        round=rnd,
                        url=url,
                        waf_type=waf.get("type", ""),
                        technique=waf.get("technique", ""),
                        original_status=waf.get("original_status"),
                        bypassed=True,
                    )
                    result["guidance"] = (
                        (result.get("guidance") or "")
                        + f" 已自动绕过 WAF（{waf.get('type')}，用 {waf.get('technique')}），"
                        f"原响应 HTTP {waf.get('original_status')} 被拦截；这是绕过后的真实响应，继续按业务逻辑验证危害。"
                    ).strip()
                else:
                    self._emit(
                        "tool_waf_auto",
                        round=rnd,
                        url=url,
                        waf_type=waf.get("type", ""),
                        original_status=result.get("status_code"),
                        bypassed=False,
                    )
                    result["guidance"] = (
                        (result.get("guidance") or "")
                        + f" 检测到 WAF（{waf.get('type')}）拦截，自动绕过未成功（已试 {len(waf.get('tried') or [])} 种变体）。"
                        "仅对已有明确可控点的验证链用 suggest_waf_bypass 取候选变形复测；别泛试 payload。"
                    ).strip()
            return result

        if name == "analyze_javascript":
            self._mark_tool_used(name, rnd)
            if not self._js_tool_enabled:
                return {
                    "ok": False,
                    "blocked": True,
                    "error": "JS 分析工具尚未开放：只有明确进入 JS/前端接口/密钥审计方向后才能调用。",
                    "guidance": "如果你确实要审计 JS，请先说明具体 JS 方向和原因；否则继续常规攻击面验证。",
                }
            url = (args.get("url") or "").strip()
            text = args.get("text") or ""
            self._emit("tool_js_analyze", round=rnd, url=url[:200], has_text=bool(text))
            return self.executor.analyze_javascript(
                url=url,
                text=text,
                max_depth=args.get("max_depth", 2),
                max_assets=args.get("max_assets", 80),
            )

        if name == "run_shell":
            self._mark_tool_used(name, rnd)
            command = (args.get("command") or args.get("cmd") or args.get("shell") or "").strip()
            if not command:
                return self._tool_arg_error(
                    "run_shell", "command",
                    "必须传要执行的命令字符串。不要重复空调用；若已经没有明确验证动作就 finish(verdict=no_vuln)。",
                )
            low_value = self._low_value_shell_reason(command, rnd)
            if low_value:
                self._emit("tool_shell_blocked", round=rnd, command=command[:200], reason=low_value)
                return {
                    "ok": False,
                    "blocked": True,
                    "error": low_value,
                    "guidance": (
                        "该动作会高概率造成低价值空转。请改为一个具体、可证明危害的最小验证请求；"
                        "如果没有这样的请求，立即调用 finish(verdict=no_vuln)。"
                    ),
                }
            self._emit("tool_shell", round=rnd, command=command[:200])
            return self.executor.run_shell(
                command,
                timeout=args.get("timeout"),
                confirm_destructive=args.get("confirm_destructive", False),
                confirm_reason=args.get("confirm_reason") or "",
            )

        if name == "decode_transform":
            self._mark_tool_used(name, rnd)
            value = args.get("value") or ""
            self._emit("tool_decode", round=rnd, mode=args.get("mode", "auto"), value_len=len(str(value)))
            return self.executor.decode_transform(value=value, mode=args.get("mode", "auto"))

        if name == "suggest_waf_bypass":
            self._mark_tool_used(name, rnd)
            payload = args.get("payload") or ""
            if not payload:
                return self._tool_arg_error(
                    "suggest_waf_bypass", "payload",
                    "必须传被 WAF 拦截的最小 payload 或可控参数值；不要空调用。",
                )
            self._emit("tool_waf_advice", round=rnd, context=args.get("context", "generic"), payload_len=len(str(payload)))
            return self.executor.suggest_waf_bypass(
                payload=payload,
                status_code=args.get("status_code"),
                response_headers=args.get("response_headers"),
                response_body=args.get("response_body", ""),
                context=args.get("context", "generic"),
            )

        if name == "fofa_lookup":
            self._mark_tool_used(name, rnd)
            query = (args.get("query") or "").strip()
            if not query:
                return self._tool_arg_error(
                    "fofa_lookup", "query",
                    '必须传 FOFA 语法（如 ip="1.2.3.4"）；无明确测绘需求就别空调用。',
                )
            self._emit("tool_fofa_lookup", round=rnd, query=query[:120])
            return self.executor.fofa_lookup(query=query, size=args.get("size", 10))

        if name == "asset_discovery":
            self._mark_tool_used(name, rnd)
            target = (args.get("target") or "").strip()
            enum_type = (args.get("enum_type") or "subdomain").strip().lower()
            if not target:
                return self._tool_arg_error(
                    "asset_discovery", "target",
                    "必须传目标域名或 URL；无明确侦察需求就别空调用。",
                )
            if enum_type not in ("subdomain", "path", "same_ip"):
                enum_type = "subdomain"
            self._emit("tool_asset_discovery", round=rnd, target=target[:200], enum_type=enum_type)
            return self.executor.asset_discovery(
                target=target,
                enum_type=enum_type,
                max_results=args.get("max_results", 20),
            )

        if name == "fingerprint":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            headers = args.get("headers")
            body = args.get("body") or ""
            title = args.get("title") or ""
            if not url and not headers and not body:
                return self._tool_arg_error(
                    "fingerprint", "url",
                    "必须传 URL 或已拿到的响应头/body；无明确目标就别空调用。",
                )
            self._emit("tool_fingerprint", round=rnd, url=url[:200], has_headers=bool(headers), body_len=len(str(body)))
            return self.executor.fingerprint(url=url, headers=headers, body=body, title=title)

        if name == "credential_brute":
            self._mark_tool_used(name, rnd)
            login_url = (args.get("login_url") or "").strip()
            username = (args.get("username") or "").strip()
            if not login_url or not username:
                return self._tool_arg_error(
                    "credential_brute", "login_url/username",
                    "必须传登录 URL 和要验证的用户名；无明确目标就别空调用。",
                )
            self._emit("tool_credential_brute", round=rnd, login_url=login_url[:200], username=username[:60])
            return self.executor.credential_brute(
                login_url=login_url,
                username=username,
                usernames=args.get("usernames"),
                passwords=args.get("passwords"),
                use_builtin_dict=args.get("use_builtin_dict", True),
                max_attempts=args.get("max_attempts", 20),
                edu_mode=args.get("edu_mode", False),
            )

        if name == "login_session":
            self._mark_tool_used(name, rnd)
            login_url = (args.get("login_url") or "").strip()
            username = (args.get("username") or "").strip()
            password = (args.get("password") or "").strip()
            if not login_url or not username or not password:
                return self._tool_arg_error(
                    "login_session", "login_url/username/password",
                    "必须传登录 URL、账号、密码；无明确目标就别空调用。",
                )
            self._emit("tool_login_session", round=rnd, login_url=login_url[:200], username=username[:60])
            return self.executor.login_session(login_url=login_url, username=username, password=password)

        if name == "login_form_scan":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "login_form_scan", "url",
                    "必须传目标 URL；无明确目标就别空调用。",
                )
            self._emit("tool_login_form_scan", round=rnd, url=url[:200])
            return self.executor.login_form_scan(url=url, max_paths=args.get("max_paths", 8))

        if name == "http_batch":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "http_batch", "url",
                    "必须传带 {p} 占位的 url（或配 param_name）；遍历位没写就不知道扫什么。",
                )
            self._emit("tool_http_batch", round=rnd, url=url[:200],
                       range=f"{args.get('start',1)}-{args.get('end',10)}")
            return self.executor.http_batch(
                url=url, param_name=args.get("param_name", ""),
                start=args.get("start", 1), end=args.get("end", 10), step=args.get("step", 1),
                method=args.get("method", "GET"), data_template=args.get("data_template", ""),
                delay=args.get("delay", 0.15), max_items=args.get("max_items", 40),
                interest_contains=args.get("interest_contains"),
            )

        if name == "diff_response":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "diff_response", "url",
                    "必须传 URL；用来对两组参数做差异对比。",
                )
            self._emit("tool_diff_response", round=rnd, url=url[:200])
            return self.executor.diff_response(
                url=url, params_a=args.get("params_a"), params_b=args.get("params_b"),
                method=args.get("method", "GET"),
            )

        if name == "timing_probe":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "timing_probe", "url",
                    "必须传要测时的 URL；无明确目标就别空调用。",
                )
            self._emit("tool_timing_probe", round=rnd, url=url[:200], samples=args.get("samples", 5))
            return self.executor.timing_probe(
                url=url, method=args.get("method", "GET"), data=args.get("data", ""),
                samples=args.get("samples", 5),
            )

        if name == "crawl_links":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "crawl_links", "url",
                    "必须传起始页 URL；无明确目标就别空调用。",
                )
            self._emit("tool_crawl_links", round=rnd, url=url[:200])
            return self.executor.crawl_links(
                url=url, max_pages=args.get("max_pages", 5), max_links=args.get("max_links", 60),
                same_host_only=args.get("same_host_only", True),
            )

        if name == "sqli_probe":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            param_name = (args.get("param_name") or "").strip()
            if not url or not param_name:
                return self._tool_arg_error(
                    "sqli_probe", "url/param_name",
                    "必须传目标 url 和要探测的参数名 param_name；无明确目标就别空调用。",
                )
            self._emit("tool_sqli_probe", round=rnd, url=url[:200], param_name=param_name[:60])
            return self.executor.sqli_probe(
                url=url, param_name=param_name, method=args.get("method", "GET"),
                probe_types=args.get("probe_types"),
            )

        if name == "upload_probe":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "upload_probe", "url",
                    "必须传上传接口 URL；无明确目标就别空调用。",
                )
            self._emit("tool_upload_probe", round=rnd, url=url[:200])
            return self.executor.upload_probe(
                url=url, file_field=args.get("file_field", "file"),
                filename=args.get("filename", "test.txt"),
                content_type=args.get("content_type", "text/plain"),
            )

        if name == "path_probe":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "path_probe", "url",
                    "必须传目标 URL；无明确目标就别空调用。",
                )
            self._emit("tool_path_probe", round=rnd, url=url[:200])
            return self.executor.path_probe(
                url=url,
                max_paths=args.get("max_paths", 40),
                include_backup=args.get("include_backup", True),
            )

        if name == "injection_probe":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            param_name = (args.get("param_name") or "").strip()
            if not url or not param_name:
                return self._tool_arg_error(
                    "injection_probe", "url/param_name",
                    "必须传目标 url 和要探测的参数名 param_name；无明确目标就别空调用。",
                )
            self._emit("tool_injection_probe", round=rnd, url=url[:200], param_name=param_name[:60])
            return self.executor.injection_probe(
                url=url, param_name=param_name, method=args.get("method", "GET"),
                probe_types=args.get("probe_types"),
            )

        if name == "access_boundary":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "access_boundary", "url",
                    "必须传要测权限边界的接口 URL；无明确目标就别空调用。",
                )
            self._emit("tool_access_boundary", round=rnd, url=url[:200])
            return self.executor.access_boundary(
                url=url, method=args.get("method", "GET"), data=args.get("data", ""),
            )

        if name == "capture_evidence":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            if not url:
                return self._tool_arg_error(
                    "capture_evidence", "url",
                    "必须传要存证的页面 URL（含 PoC 参数）；无明确目标就别空调用。",
                )
            self._emit("tool_capture_evidence", round=rnd, url=url[:200])
            return self.executor.capture_evidence(
                url=url, method=args.get("method", "GET"), data=args.get("data", ""),
            )

        if name == "verify_known_vuln":
            self._mark_tool_used(name, rnd)
            url = (args.get("url") or "").strip()
            vuln_name = (args.get("vuln_name") or "").strip()
            if not url or not vuln_name:
                return self._tool_arg_error(
                    "verify_known_vuln", "url/vuln_name",
                    "必须传目标 url 和要实测的漏洞名 vuln_name（取自 fingerprint 的 known_vulns.name）；无命中漏洞就别空调用。",
                )
            self._emit("tool_verify_known_vuln", round=rnd, url=url[:200], vuln_name=vuln_name[:80])
            return self.executor.verify_known_vuln(url=url, vuln_name=vuln_name)

        if name == "session_set":
            self._mark_tool_used(name, rnd)
            self._emit("tool_session_set", round=rnd,
                       has_cookies=bool(args.get("cookies")), has_headers=bool(args.get("headers")))
            result = self.executor.session_set(
                cookies=args.get("cookies"),
                headers=args.get("headers"),
                clear=bool(args.get("clear", False)),
            )
            # 登记成功后若已持有可用 cookie/header 凭据，自动标记为「已注入会话」，
            # 前端看板即显示「凭据·已注入」，供同目标断点续挖复用（不落明文）。
            if result.get("ok") and (result.get("active_cookies") or result.get("active_headers")):
                self._autotag_injected_if_session()
            return result

        if name == "update_notes":
            self._mark_tool_used(name, rnd)
            return self.executor.update_notes(notes=args.get("notes", ""))

        if name == "update_cognition":
            self._mark_tool_used(name, rnd)
            slot = (args.get("slot") or "").strip()
            text = (args.get("text") or "").strip()
            if not slot or not text:
                return self._tool_arg_error(
                    "update_cognition", "slot/text",
                    "必须传认知槽位(slot)和内容(text)；slot ∈ confirmed/excluded/leads/plan。",
                )
            self._emit("tool_update_cognition", round=rnd, slot=slot, text=text[:2000])
            return self.executor.update_cognition(slot=slot, text=text)

        if name == "blackboard_publish":
            self._mark_tool_used(name, rnd)
            return self._blackboard_publish(args, rnd)

        if name == "blackboard_query":
            self._mark_tool_used(name, rnd)
            return self._blackboard_query(args)

        if name == "blackboard_declare":
            self._mark_tool_used(name, rnd)
            return self._blackboard_declare(args, rnd)

        if name == "report_intel":
            self._mark_tool_used(name, rnd)
            return self._report_intel(args)

        if name == "report_coverage":
            self._mark_tool_used(name, rnd)
            return self._report_coverage(args)

        if name == "submit_finding":
            self._mark_tool_used(name, rnd)
            return self._submit_finding(args)

        if name == "check_duplicate_finding":
            self._mark_tool_used(name, rnd)
            return self._check_duplicate(args)

        if name == "finish":
            premature = self._premature_finish_reason(args, rnd)
            if premature:
                self._emit("finish_blocked", round=rnd, reason=premature[:300])
                return {
                    "ok": False,
                    "kind": "premature_finish",
                    "error": premature,
                    "guidance": (
                        "继续补齐入口覆盖：读完 JS/API 线索，挑高价值接口做最小实证；"
                        "只有真不可达/纯静态/无交互，或线索已验证打不穿，才 finish(no_vuln)。"
                    ),
                }
            self._finished = {
                "verdict": args.get("verdict", "no_vuln"),
                "summary": args.get("summary", ""),
                "deepen_lead": (args.get("deepen_lead") or "").strip(),
            }
            self._report_provider_success()
            self._emit("worker_finish", verdict=self._finished["verdict"],
                       summary=self._finished["summary"][:300],
                       deepen_lead=self._finished["deepen_lead"][:300])
            return {"ok": True, "message": "已记录结束。"}

        return {"ok": False, "error": f"未知工具: {name}"}

    def _mark_tool_used(self, name: str, rnd: int) -> None:
        self._tool_counts[name] = self._tool_counts.get(name, 0) + 1
        if name == "analyze_javascript":
            self._last_js_analysis_round = rnd
            self._post_js_validation_count = 0
        elif name in {"http_request", "run_shell"} and self._last_js_analysis_round:
            self._post_js_validation_count += 1

    def _premature_finish_reason(self, args: dict, rnd: int) -> str:
        if (args.get("verdict") or "no_vuln") != "no_vuln" or self.findings:
            return ""
        if self.deepen_context:
            return ""
        if self._js_signal_seen and not self._tool_counts.get("analyze_javascript"):
            return (
                f"过早结束：已出现 JS/API/前端接口信号，但第 {rnd} 轮仍未调用 analyze_javascript。"
                "先抓取/审计关联 JS，提取接口、路由、secret/token/sign，再决定是否无洞。"
            )
        if self._last_js_analysis_round and self._post_js_validation_count == 0:
            return (
                "过早结束：已经分析 JS，但还没有对 JS 提取出的高价值接口/链路做 http_request/run_shell 实证。"
                "至少挑登录/找回/导出/用户/管理/上传/配置等高价值端点验证一次。"
            )
        tool_actions = sum(self._tool_counts.values())
        if (rnd < 12 or tool_actions < 8) and not self._quick_no_vuln_allowed(args):
            return (
                f"过早结束：仅 {rnd} 轮、{tool_actions} 次工具动作，不足以确认有攻击面的站点无洞。"
                "除非已明确证明目标不可达，或纯静态且无登录/表单/API/JS/可控参数，否则继续覆盖首页、登录/API/JS/高价值端点。"
            )
        return ""

    @staticmethod
    def _quick_no_vuln_allowed(args: dict) -> bool:
        text = "\n".join([
            str(args.get("summary") or ""),
            str(args.get("deepen_lead") or ""),
        ]).lower()
        unreachable = (
            "不可达", "连不上", "连接失败", "拒连", "超时", "timeout",
            "connection refused", "could not resolve", "dns", "下线",
        )
        static_or_empty = (
            "纯静态", "静态页", "空壳", "无交互", "无攻击面",
        )
        no_surface = (
            "无登录", "无表单", "无api", "无 api", "无js", "无 js",
            "无可控参数", "没有登录", "没有表单", "没有api", "没有 api",
        )
        return any(x in text for x in unreachable) or (
            any(x in text for x in static_or_empty) and any(x in text for x in no_surface)
        )

    def _maybe_enable_js_tool(self, text: str, reason: str) -> bool:
        if self._js_tool_enabled:
            return False
        if not _JS_INTENT_RE.search(text or ""):
            return False
        self._js_tool_enabled = True
        self._js_signal_seen = True
        self._emit("js_analyzer_enabled", reason=reason)
        return True

    @staticmethod
    def _tool_arg_error(tool: str, missing: str, guidance: str) -> dict:
        return {
            "ok": False,
            "kind": "arg_error",
            "error": f"{tool} 工具参数缺失：{missing}",
            "guidance": guidance,
        }

    def _recovery_hint(self, tool: str, result: dict) -> str:
        """工具失败时返回针对性恢复提示，帮模型在同流里快速纠偏而非从头推理。

        只在 result 不含 guidance 时才会被采用（调用方用 setdefault）。
        针对 http_request 的各类状态码、run_shell 的各类失败、以及通用错误分别给提示。
        """
        if result.get("ok") is True or result.get("guidance"):
            return ""
        if tool == "http_request":
            sc = result.get("status_code")
            err = str(result.get("error", ""))
            if sc == 401:
                return "401 未授权：需要登录态。若已 session_set 过，可能 session 过期了——重新登录或换凭证；若本就是测未授权，401 说明接口有鉴权，换个不需要登录的入口或测越权。"
            if sc == 403:
                return "403 禁止：常见原因——路径不对(试目录爆破/换路径)、需要特定角色/IP、WAF 拦截(看响应体有无 WAF 特征，用 suggest_waf_bypass)、或缺少 CSRF token。换路径或换攻击面，别死磕同一个 403。"
            if sc == 404:
                return "404 不存在：路径不对。从 JS/首页/接口文档里重新找正确路径，或试常见变体(/api/v1/、/api/v2/、大小写、尾斜杠)。"
            if sc in (500, 502, 503):
                return f"{sc} 服务端错误：可能是 payload 触发了异常(注入/RCE 线索)或服务临时不可用。保留这个请求作为证据，换参数复现确认；若多次稳定 500 可作为注入/异常漏洞线索。"
            if sc == 302:
                loc = (result.get("response_headers", {}) or {}).get("Location", "")
                return f"302 跳转到 {loc[:120]}：若是跳登录页说明需要登录态；若是跳 ticket/SSO 链，设 follow_redirects=true 跟完整个登录链。"
            if "timed out" in err.lower() or "timeout" in err.lower():
                return "请求超时：目标可能慢或不可达。换更小范围的请求、加大 timeout、或确认目标是否在线；连续超时就 finish。"
            if "connection" in err.lower() or "refused" in err.lower() or "unreachable" in err.lower():
                return "连接失败：目标可能下线/防火墙拦截/端口未开放。确认目标可达性(换个端口/协议)；不可达就 finish(no_vuln)。"
        if tool == "run_shell":
            rc = result.get("return_code")
            if rc and rc != 0:
                return f"命令退出码 {rc}：检查命令语法/参数/路径是否正确。换最小命令验证环境，别重复跑同一条失败的命令。"
            if result.get("timed_out"):
                return "命令超时：可能命令本身耗时(如 nmap 全端口)或挂起。换更小范围或加 timeout 参数；别重复跑超时命令。"
            if result.get("blocked"):
                return ""  # blocked 已有自己的 guidance
        if "参数" in str(result.get("error", "")) or "JSON" in str(result.get("error", "")):
            return "参数格式错误：检查工具参数是否合法 JSON、必填字段是否齐全。对照工具 schema 修正后重试一次。"
        return ""

    def _auto_finish(self, reason: str, failure_kind: str = "") -> None:
        if failure_kind:
            self._finished = {
                "verdict": "error",
                "summary": reason,
                "error": reason,
                "failure_kind": failure_kind,
            }
            self._report_provider_failure(reason, failure_kind)
            self._emit(
                "worker_auto_finish",
                verdict="error",
                failure_kind=failure_kind,
                summary=reason[:300],
                error=reason[:500],
                error_copy=reason,
            )
            return
        verdict = "found" if self.findings else "no_vuln"
        self._finished = {"verdict": verdict, "summary": reason}
        self._emit("worker_auto_finish", verdict=verdict, summary=reason[:300])

    def _report_provider_failure(self, reason: str, failure_kind: str) -> None:
        if failure_kind not in {"model_behavior", "tool_argument"}:
            return
        reporter = getattr(self.llm, "report_current_provider_failure", None)
        if not reporter:
            return
        try:
            reporter(reason, kind=failure_kind)
        except Exception as exc:
            self._emit("provider_degrade_error", error=str(exc), failure_kind=failure_kind)

    def _report_provider_success(self) -> None:
        reporter = getattr(self.llm, "report_current_provider_success", None)
        if not reporter:
            return
        try:
            reporter()
        except Exception as exc:
            self._emit("provider_health_error", error=str(exc))

    @staticmethod
    def _tool_outcome(result: dict) -> str:
        if result.get("ok") is True:
            return "ok"
        if result.get("kind") == "needs_more_evidence":
            return "ok"
        if result.get("blocked"):
            return "blocked"
        if result.get("kind") == "arg_error" or "工具参数缺失" in str(result.get("error", "")):
            return "arg_error"
        if result.get("timed_out"):
            return "timeout"
        if result.get("cancelled"):
            return "timeout"
        text = (str(result.get("error", "")) + "\n" + str(result.get("output", ""))).lower()
        if any(marker in text for marker in ("timed out", "timeout", "超时")):
            return "timeout"
        if any(marker in text for marker in (
            "connection refused", "connection reset", "connection timed out",
            "network is unreachable", "no route to host", "name or service not known",
            "temporary failure", "http 请求异常",
        )):
            return "network"
        return "error"

    def _low_value_shell_reason(self, command: str, rnd: int) -> str:
        cmd = command.strip()
        lower = cmd.lower()
        target_host = urlparse(self.target if "://" in self.target else f"http://{self.target}").netloc.lower()

        sleep_values = [int(m.group(1)) for m in _SLEEP_RE.finditer(lower)]
        if sleep_values and max(sleep_values) >= 30:
            return "禁止长 sleep/等待式探测：这会占住 worker 且不产生漏洞证据。"

        if _BROAD_NMAP_RE.search(lower):
            return "禁止宽端口 nmap 扫描：请只验证当前 Web 服务相关端口或直接收尾。"

        if "nuclei" in lower and " -t " not in lower and " -tags " not in lower and " -id " not in lower:
            return "禁止无模板/无 tag 的 nuclei 泛扫：先用接口/JS/逻辑分析形成假设，再用具体模板或最小请求验证。"

        if "sqlmap" in lower and not any(marker in lower for marker in ("?", "--data", " -r ", "--cookie", "--headers")):
            return "禁止无具体参数/请求包的 sqlmap 泛扫：必须先定位可控参数或原始请求，再做针对性注入验证。"

        if re.search(r"\b(ffuf|gobuster|dirsearch|feroxbuster)\b", lower):
            if not any(marker in lower for marker in ("api", "swagger", "actuator", "druid", "nacos", "upload", "login")):
                return "禁止泛目录爆破：优先测试已发现的接口、登录/改密/上传/越权逻辑；目录扫描只能针对高价值路径簇。"

        if "socket.socket" in lower and rnd >= 6:
            return "禁止在中后期用 raw socket 死磕协议异常：网络/协议不可达应收敛为 no_vuln。"

        if "/dev/tcp/" in lower and "for port in" in lower and rnd >= 8:
            return "禁止中后期用 /dev/tcp 循环探端口：这属于低价值端口枚举，应聚焦当前 Web 入口。"

        if "curl" in lower and "for " in lower:
            match = _FOR_LIST_RE.search(cmd)
            if match:
                items = [x for x in re.split(r"\s+", match.group(1).strip()) if x]
                if len(items) > 10 and rnd >= 8:
                    # 同一接口的方法/参数变体枚举（如 docfileinfo/download、getFile、readFile…
                    # 共享相同路径前缀）是对已发现功能接口的针对性验证，不算泛目录扫描，豁免；
                    # 只有前缀各异的泛路径猜测才拦。
                    stripped = [re.sub(r"[?#].*$", "", it) for it in items]
                    if len(stripped) >= 2 and len(os.path.commonprefix(stripped)) >= 8:
                        return ""
                    return "禁止中后期大列表路径/子域枚举：请聚焦已确认入口，或无洞收尾。"

        url_hosts = re.findall(r"https?://([^/\\s\"']+)", lower)
        if rnd >= 6 and target_host:
            # 目标常带端口（如 admin-api.hzcu.edu.cn:8082），netloc 直接比会把同域误判成姊妹域；
            # 归一化去掉端口，且当前域及其子域都不算偏离，仅拦真正无关的 .edu.cn 请求。
            target_domain = target_host.split(":")[0]
            for h in url_hosts:
                host_domain = h.split(":")[0]
                if (
                    host_domain.endswith(".edu.cn")
                    and host_domain != target_domain
                    and not host_domain.endswith("." + target_domain)
                ):
                    return "禁止中后期偏离当前目标请求姊妹域：本 worker 只负责当前 target。"

        # 只拦明确的多子域批量枚举（for sub in / for host in / for d in…），
        # 不拦普通小循环（如密码/参数列表），避免把对当前目标的登录爆破误判成姊妹域扫描。
        sibling_markers = ("for sub in", "for host in", "for domain in", "for d in")
        if rnd >= 10 and any(marker in lower for marker in sibling_markers) and "curl" in lower and "for " in lower:
            return "禁止偏离当前目标批量探测姊妹域：本 worker 只负责当前目标。"

        return ""

    def _candidate_pool(self) -> list[dict]:
        pool = list(self.duplicate_history)
        for f in self.findings:
            pool.append(f.model_dump(mode="json"))
        return pool

    def _dup_matches(self, candidate: dict) -> tuple[bool, list[dict]]:
        return dedup.is_duplicate(candidate, self._candidate_pool(), target_ref=self.target)

    def _check_duplicate(self, args: dict) -> dict:
        duplicate, matches = self._dup_matches(args)
        self._emit("duplicate_checked", duplicate=duplicate, matches=len(matches),
                   title=(args.get("title") or "")[:120])
        return {
            "ok": True,
            "duplicate": duplicate,
            "matches": matches,
            "guidance": (
                "这是重复/已驳回/通杀库已覆盖的漏洞，不要 submit_finding；继续挖其它入口或 finish。"
                if duplicate else
                "未发现明显重复；若已取得真实证据，可继续 submit_finding。"
            ),
        }

    def _blackboard_publish(self, args: dict, rnd: int = 0) -> dict:
        """发布情报到协作黑板（仅单站协作启用，普通任务降级提示）。"""
        bb = getattr(self, "blackboard", None)
        if bb is None:
            return {"ok": False, "error": "当前任务未启用协作黑板（非单站协作），无需发布。"}
        key = (args.get("key") or "").strip()
        value = (args.get("value") or "").strip()
        if not key or not value:
            return self._tool_arg_error(
                "blackboard_publish", "key/value",
                "必须传 key（分类）和 value（情报内容）；不要空调用。",
            )
        result = bb.publish(
            key=key, value=value,
            worker_id=self.worker_id,
            confidence=args.get("confidence", "medium"),
            source=self._route_source(),
        )
        if result.get("ok"):
            self._emit("blackboard_publish", round=rnd, key=key, value=value[:200], confidence=args.get("confidence", "medium"))
        return result

    def _blackboard_query(self, args: dict) -> dict:
        """查询协作黑板（仅单站协作启用）。"""
        bb = getattr(self, "blackboard", None)
        if bb is None:
            return {"ok": False, "error": "当前任务未启用协作黑板（非单站协作）。"}
        return bb.query(key=args.get("key"))

    def _blackboard_declare(self, args: dict, rnd: int = 0) -> dict:
        """声明当前方向（软分工，仅单站协作启用）。"""
        bb = getattr(self, "blackboard", None)
        if bb is None:
            return {"ok": False, "error": "当前任务未启用协作黑板（非单站协作）。"}
        direction = (args.get("direction") or "").strip()
        if not direction:
            return self._tool_arg_error(
                "blackboard_declare", "direction",
                "必须传 direction（当前方向）；不要空调用。",
            )
        result = bb.declare(direction=direction, worker_id=self.worker_id)
        if result.get("ok"):
            self._emit("blackboard_declare", round=rnd, direction=direction[:120])
        return result

    def _report_intel(self, args: dict) -> dict:
        """worker 主动上报可复用情报（纯内存收集，编排层 async 统一落全局情报库）。

        kind: cred / endpoint / profile（fingerprint 由系统自动识别，不让 worker 报）
        - cred:     {username, password}  —— 仅上报【验证过能登录】的凭证
        - endpoint: {path, vuln_type}     —— 验证有效的未授权/敏感端点
        - profile:  {key, value}          —— 技术栈/WAF/突破口等画像
        纯本地、无网络、无 DB、不阻塞。最多收集 20 条防滥用。
        """
        kind = (args.get("kind") or "").strip().lower()
        if kind not in ("cred", "endpoint", "profile"):
            return {"ok": False, "error": "kind 必须是 cred/endpoint/profile 之一。"}
        payload = args.get("payload")
        if not isinstance(payload, dict) or not payload:
            return {"ok": False, "error": "payload 必须是非空对象，按 kind 提供对应字段。"}
        if len(self._reported_intel) >= 20:
            return {"ok": True, "message": "本轮情报已上报足够，无需再报。"}
        def _safe_text(value: Any, limit: int) -> str:
            if isinstance(value, (dict, list)):
                try:
                    text = json.dumps(value, ensure_ascii=False)
                except Exception:
                    text = str(value)
            else:
                text = str(value or "")
            return text[:limit]

        item = {
            "kind": kind,
            "payload": {str(k)[:50]: _safe_text(v, 300) for k, v in payload.items() if v not in (None, "")},
            "summary": _safe_text(args.get("summary"), 300),
            "confidence": "verified" if args.get("verified") else "likely",
        }
        if not item["payload"]:
            return {"ok": False, "error": "payload 内容为空。"}
        self._reported_intel.append(item)
        self._emit("intel_reported", intel_kind=kind)
        return {"ok": True, "message": "情报已记录，将沉淀到全局情报库供后续 worker 复用。继续挖洞或 finish。"}

    def _report_coverage(self, args: dict) -> dict:
        """单站协作覆盖记录：记录已验证 API/入口，供后续 worker 复用。"""
        if len(self._reported_coverage) >= 12:
            return {"ok": True, "message": "本轮覆盖记录已足够，收尾时汇总即可。"}

        def _safe_text(value: Any, limit: int) -> str:
            if isinstance(value, (dict, list)):
                try:
                    text = json.dumps(value, ensure_ascii=False)
                except Exception:
                    text = str(value)
            else:
                text = str(value or "")
            return text[:limit]

        route = (args.get("route") or "").strip()
        if not route:
            route = str((self.target_meta.get("site_collab_route") or {}).get("source") or "")
        summary = _safe_text(args.get("summary"), 400).strip()
        if not summary:
            return {"ok": False, "error": "summary 不能为空：请概括已覆盖的 API/入口和结论。"}
        endpoints_in = args.get("endpoints") or []
        endpoints: list[dict] = []
        if isinstance(endpoints_in, list):
            for item in endpoints_in[:20]:
                if not isinstance(item, dict):
                    continue
                endpoints.append({
                    "method": _safe_text(item.get("method") or "GET", 12).upper(),
                    "path": _safe_text(item.get("path") or item.get("url"), 220),
                    "status": _safe_text(item.get("status"), 40),
                    "checks": _safe_text(item.get("checks"), 120),
                    "result": _safe_text(item.get("result") or item.get("note"), 180),
                })
        record = {
            "route": route or "site",
            "summary": summary,
            "endpoints": endpoints,
            "remaining": _safe_text(args.get("remaining"), 400),
        }
        self._reported_coverage.append(record)
        bb = getattr(self, "blackboard", None)
        if bb is not None:
            try:
                bb.add_coverage(record, worker_id=self.worker_id, source=self._route_source())
            except Exception:
                pass
        self._emit("coverage_reported", route=record["route"], summary=summary[:180], endpoints=len(endpoints))
        return {"ok": True, "message": "覆盖记录已记下，后续同站 worker 会看到摘要。继续补盲区或 finish。"}

    def _submit_finding(self, args: dict) -> dict:
        """Pydantic 兜底校验（双保险），失败返回错误让模型修正。"""
        try:
            finding = Finding(**args)
        except ValidationError as e:
            self._emit("finding_invalid", errors=str(e))
            return {"ok": False, "error": f"Finding 校验失败，请修正后重新提交: {e}"}

        if not self._enterprise:
            bomb_block = edu_bombing_block_reason(finding)
            if bomb_block:
                self._emit("finding_out_of_scope", title=finding.title, reason=bomb_block[:200])
                return {
                    "ok": False,
                    "kind": "out_of_scope",
                    "submitted": False,
                    "error": bomb_block,
                }

        backdoor_block = weak_backdoor_block_reason(finding)
        if backdoor_block:
            self._emit("finding_out_of_scope", title=finding.title, reason=backdoor_block[:200])
            return {
                "ok": False,
                "kind": "out_of_scope",
                "submitted": False,
                "error": backdoor_block,
            }

        evidence_block = self._weak_write_evidence_reason(finding)
        if evidence_block:
            self._emit("finding_needs_more_evidence", title=finding.title, reason=evidence_block[:200])
            return {
                "ok": False,
                "kind": "needs_more_evidence",
                "submitted": False,
                "error": evidence_block,
                "guidance": (
                    "不要把这条半成品提交给 reviewer。" + HARMLESS_PROTOCOL
                ),
            }

        exploit_block = weak_exploit_reason(finding)
        if exploit_block:
            self._emit("finding_needs_more_evidence", title=finding.title, reason=exploit_block[:200])
            return {
                "ok": False,
                "kind": "needs_more_evidence",
                "submitted": False,
                "error": exploit_block,
                "guidance": (
                    "按深化路线继续用 http_request/run_shell 实证，把危害打实再提交；"
                    "确实打不出实锤就 finish(deepen_lead) 写清缺哪一步。"
                ),
            }

        duplicate, matches = self._dup_matches(finding.model_dump(mode="json"))
        if duplicate:
            self._emit("finding_duplicate", title=finding.title, matches=len(matches))
            return {
                "ok": False,
                "duplicate": True,
                "matches": matches,
                "error": "该漏洞命中统一查重库（历史提交/已驳回/通杀明细），已拦截。不要再次提交同一漏洞，继续挖其它点或 finish。",
            }

        self._backfill_finding_fields(finding)
        self._auto_capture_evidence(finding)
        self.findings.append(finding)
        # 同步落盘暂存（findings_staged.jsonl）：与 evidence_trail 并列，进程被硬杀
        # （kill -9/容器重启/崩溃）时，本已 submit 成功的洞判定仍在盘上，可被断点续挖
        # 认领，绝不因「_emit 异步落库未 commit」而静默丢弃。
        self._stash_finding(finding)
        # 携带完整 finding 供 orchestrator 实时落库（进程被打断时不丢洞）。
        self._emit(
            "finding_submitted",
            title=finding.title,
            severity=finding.severity_claimed.value,
            vuln_type=finding.vuln_type,
            finding=finding.model_dump(mode="json"),
        )
        return {"ok": True, "message": f"已收录漏洞「{finding.title}」（{finding.severity_claimed.value}）。可继续挖其它漏洞或调用 finish。"}

    def _stash_finding(self, finding: "Finding") -> None:
        """把 submit 成功的洞同步追加到 work_dir/findings_staged.jsonl。

        与证据链并列的本地暂存，仅用于硬杀/崩溃时的兜底认领；任何失败静默忽略，
        绝不影响 submit 主流程。正常整轮落库成功后，由兜底清理。
        """
        try:
            path = self._staged_findings_path()
            if path is None:
                return
            record = {
                "kind": "finding_staged",
                "ts": time.time(),
                "title": finding.title or "",
                "severity": getattr(finding.severity_claimed, "value", "") or "",
                "vuln_type": finding.vuln_type or "",
                "target_url": finding.target_url or "",
                "owner": finding.owner or "",
                "dedup_key": getattr(finding, "dedup_key", "") or "",
                "finding": finding.model_dump(mode="json"),
            }
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record, ensure_ascii=False) + "\n")
        except Exception:
            pass

    def _staged_findings_path(self):
        try:
            wd = self.executor.work_dir
            if wd is None:
                return None
            return Path(wd) / "findings_staged.jsonl"
        except Exception:
            return None

    def _load_staged_findings(self) -> list[dict]:
        """读取本目标暂存的已 submit 洞（幂等认领用）。不存在/失败返回空。"""
        try:
            path = self._staged_findings_path()
            if path is None or not path.exists():
                return []
            out: list[dict] = []
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                    if rec.get("finding"):
                        out.append(rec["finding"])
                except Exception:
                    continue
            return out
        except Exception:
            return []

    def _backfill_finding_fields(self, finding: Finding) -> None:
        """从本地证据链确定性补齐 LLM 可能漏写的大字段（raw_request/raw_response/poc_http）。

        目的：submit_finding 是单次 LLM 调用，若要求它把完整请求包/响应包都塞进一个大 JSON，
        在慢中转上极易超时（后端 120s 硬截断）。真实请求/响应早已随每次工具调用落盘
        （evidence_trail），此处优先让 LLM 只提交判词+小字段，大字段由确定性命中目标 URL
        的证据链回填——提交载荷更小、不依赖 LLM 复制大文本，超时概率显著下降。
        纯增强：补齐失败不阻塞提交。
        """
        try:
            if not finding.target_url:
                return
            url = (finding.target_url or "").strip()
            rec = _latest_evidence_trail(self.executor.work_dir)
            if not rec or rec.get("kind") != "http_request":
                return
            # 只回填与目标 URL 同源/同路径的证据（避免串到别的目标）
            rec_url = (rec.get("url") or "").strip()
            if not rec_url or rec_url.split("://")[-1] != url.split("://")[-1]:
                return
            if not finding.raw_request:
                finding.raw_request = rec.get("request") or ""
            if not finding.poc_http:
                finding.poc_http = rec.get("request") or ""
            if not finding.raw_response:
                status = rec.get("status") or ""
                headers = rec.get("response_headers") or ""
                body = rec.get("body") or ""
                finding.raw_response = f"HTTP/1.1 {status}\n{headers}\n\n{body[:8000]}"
        except Exception:
            pass

    def _auto_capture_evidence(self, finding: Finding) -> None:
        """自动存证快照：提交时抓取目标页面 HTTP 快照写入 evidence.snapshot。

        优先用挖掘时 capture_evidence 存下的 snapshot_ref；否则自动抓取
        target_url。失败不阻塞提交（存证是增强不是必需）。
        """
        try:
            ev = finding.evidence.model_dump() if finding.evidence else {}
            ref = (ev.get("snapshot_ref") or "").strip()
            if ref:
                snap = load_snapshot(self.executor.work_dir, ref)
                if snap:
                    finding.evidence.snapshot = snap
                    return
            url = (finding.target_url or "").strip()
            if not url:
                return
            snap = capture_snapshot(self.executor, url)
            if not snap or not snap.get("ok"):
                return
            saved_ref = save_snapshot(self.executor.work_dir, snap)
            finding.evidence.snapshot = snap
            finding.evidence.snapshot_ref = saved_ref
        except Exception:
            # 存证失败绝不阻塞漏洞提交
            pass

    def _weak_write_evidence_reason(self, finding: Finding) -> str:
        """拦截 EduSRC 最常见半成品：写接口返回成功但影响 0 行。

        无害证法（哨兵闭环 / 鉴权对照 / 幂等回写 / 旁路回读）放行；
        只拦「成功文案 + 零影响」且没有任何无害证据的半成品。
        """
        if self._enterprise:
            return ""
        return weak_write_block_reason(finding)
