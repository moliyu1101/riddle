"""orchestrator 共享常量与模块级函数（拆分自单体文件，行为不变）。"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import os
import threading
import traceback
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlunparse

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app import dedup
from app.blackboard import Blackboard
from app.tools import escalation_guard
from app.agents import collector
from app.agents import intel as intel_lib
from app.agents import playbook_router
from app.agents import prefilter
from app.agents import site_collab
from app.agents import target_cluster
from app.agents.business_profiler import profile_business, render_business_block
from app.agents.biz_test_template import render_biz_test_block
from app.agents.diff_score import diff_strategy_block
from app.agents.state_machine import render_state_machine_block
from app.agents.throttle import compute_effective_cap, same_org_ratio
from app.agents.deepen import deepen_cap_for  # 任务级深挖上限（人工+AI+lead 合计，防死循环）
from app.agents.prompts import is_enterprise_src, should_escalate
from app.agents.reviewer import Reviewer
from app.agents.worker import Worker
from app.agent_runtime import (
    AGENT_EXECUTOR, COLLECTOR_IO_EXECUTOR, WORKER_MAX_CONCURRENCY,
    QUEUE_LIVENESS_BATCH_SIZE, QUEUE_LIVENESS_CONCURRENCY,
    agent_semaphore, shutdown_agent_executor,
)
from app.db.models import CST, Finding, Killsweep, Review, Target, Task, TaskEvent
from app.db.session import SessionLocal
from app.events import bus
from app.maintenance.cleanup import TRACE_FINE_KINDS, prune_target_traces
from app.llm.client import LLMClient
from app.settings_service import (
    llm_client_for_task,
    resolve_engine_config,
    resolve_engine_name,
    resolve_llm_runtime_mode,
    resolve_worker_prompt_version,
)
from app.schemas import Finding as FindingSchema
from app.schemas import Verdict


__all__ = [
    "logger",
    "_now_iso",
    "_SEVERITY_RANK",
    "_ESCALATE_TOPTIER_KEYWORDS",
    "_ESCALATE_IMPACT_THRESHOLD",
    "_escalation_is_significant",
    "LOOP_INTERVAL",
    "LOW_WATERMARK",
    "MAX_RETRY",
    "_WORKER_TRACE_KINDS",
    "_TRACE_TEXT_KEYS",
    "_TRACE_LONG_KEYS",
    "WORKER_WALL_TIMEOUT",
    "WORKER_IDLE_TIMEOUT",
    "WORKER_MAX_WALL_TIMEOUT",
    "WORKER_WAIT_POLL_INTERVAL",
    "WORKER_SEM_ACQUIRE_TIMEOUT",
    "AGENT_SEM_ACQUIRE_TIMEOUT",
    "REVIEW_WALL_TIMEOUT",
    "KILLSWEEP_WALL_TIMEOUT",
    "ESCALATE_WALL_TIMEOUT",
    "WORKER_CLEANUP_TIMEOUT",
    "REVIEW_RETRY_BACKOFF",
    "REVIEW_MAX_ATTEMPTS",
    "TRACE_FLUSH_BATCH",
    "TRACE_FLUSH_INTERVAL",
    "TARGET_HEARTBEAT_INTERVAL",
    "KILLSWEEP_DEDUP_SCAN_LIMIT",
    "KILLSWEEP_REPLAY_ENQUEUE_LIMIT",
    "_KILLSWEEP_STAGE_MAP",
    "_KILLSWEEP_STAGE_LABEL",
    "_KILLSWEEP_STAGE_PCT",
    "MAX_TRANSIENT_LLM_REQUEUE",
    "FOFA_AUTH_FAIL_PAUSE_THRESHOLD",
    "STALE_NO_WORKER_GRACE",
    "QUEUE_LIVENESS_TIMEOUT",
    "QUEUE_LIVENESS_CACHE_TTL",
    "QUEUE_LOW_SUCCESS_SKIP",
    "QUEUE_LOW_SUCCESS_SCORE_THRESHOLD",
    "QUEUE_TRANSIENT_PREFILTER_COOLDOWN",
    "QUEUE_DISPATCH_CANDIDATE_LIMIT",
    "_LOW_SUCCESS_SCORE_MARKERS",
    "_TRANSIENT_UNREACHABLE_REASONS",
    "_NO_VULN_RETRY_PRIORITY_MARKERS",
    "_USABLE_LEAKED_CRED_STATUS",
    "_WORKER_DEEPEN_NEGATIVE_MARKERS",
    "_WORKER_DEEPEN_ACTIONABLE_MARKERS",
    "_WORKER_DEEPEN_ACTION_MARKERS",
    "_now",
    "_worker_timeout_reason",
    "_has_usable_leaked_cred",
    "_is_actionable_worker_deepen_lead",
    "_consume_task_exception",
    "_log_bg_task_exc",
    "_bracket_ipv6_host",
    "_with_scheme",
    "_swap_url_scheme",
    "_probe_urls",
    "_probe_target_liveness",
    "_llm_for_task",
]


logger = logging.getLogger("riddle.orchestrator")

def _now_iso() -> str:
    """当前时刻的 CST ISO 字符串（带 +08:00 偏移），供实时事件统一携带时区。"""
    return datetime.now(CST).isoformat()

_SEVERITY_RANK = {"低危": 1, "中危": 2, "高危": 3, "严重": 4}

_ESCALATE_TOPTIER_KEYWORDS = (
    "接管", "密码重置", "改密", "rce", "命令执行", "getshell", "get shell",
    "提权", "权限提升", "任意文件写", "任意文件上传", "任意用户", "全部",
)

_ESCALATE_IMPACT_THRESHOLD = int(os.environ.get("ESCALATE_IMPACT_THRESHOLD", "100"))

def _escalation_is_significant(orig_severity: str, res: dict) -> bool:
    """判定扩大危害结果是否『显著』——不显著则丢弃，不产出新 finding。

    满足任一即算显著：
      1. 等级实际跳变（新等级 > 原等级）；
      2. 定性质变（升级后类型/标题命中顶格危害关键词，如 接管/RCE）；
      3. 影响面数量级（impact_count ≥ 阈值）。
    """
    if not res or not res.get("escalated"):
        return False
    new_sev = res.get("severity") or ""
    if _SEVERITY_RANK.get(new_sev, 0) > _SEVERITY_RANK.get(orig_severity, 0):
        return True
    blob = f"{res.get('vuln_type','')} {res.get('title','')}".lower()
    if any(k in blob for k in _ESCALATE_TOPTIER_KEYWORDS):
        return True
    if int(res.get("impact_count", 0) or 0) >= _ESCALATE_IMPACT_THRESHOLD:
        return True
    return False

LOOP_INTERVAL = 3.0

LOW_WATERMARK = 5

MAX_RETRY = 1  # 单 target 最多再挖 1 次

_WORKER_TRACE_KINDS = frozenset({
    "worker_start", "worker_finish", "worker_cancelled", "worker_auto_finish",
    "worker_thought", "worker_directive", "worker_resume",
    "tool_http", "tool_shell", "tool_shell_blocked", "tool_arg_error",
    "tool_exception", "tool_js_analyze", "tool_decode", "tool_waf_advice",
    "tool_fofa_lookup", "tool_asset_discovery", "tool_fingerprint", "tool_session_set",
    "tool_credential_brute", "tool_login_session", "tool_login_form_scan",
    "tool_http_batch", "tool_diff_response", "tool_timing_probe", "tool_crawl_links",
    "tool_sqli_probe", "tool_upload_probe", "tool_access_boundary",
    "tool_path_probe", "tool_injection_probe",
    "tool_capture_evidence",
    "tool_update_cognition", "worker_reflect", "tool_verify_known_vuln",
    "blackboard_publish", "blackboard_declare",
    "llm_round_start", "llm_error", "llm_soft_retry", "llm_interrupt",
    "finding_submitted", "finding_duplicate", "finding_invalid",
    "auth_status", "finish_blocked",
})

_TRACE_TEXT_KEYS = ("text", "command", "url", "error", "message", "reason", "query", "summary")

_TRACE_LONG_KEYS = ("error_copy", "diagnostic", "detail")

WORKER_WALL_TIMEOUT = float(os.environ.get("WORKER_WALL_TIMEOUT", "1800"))

WORKER_IDLE_TIMEOUT = float(os.environ.get("WORKER_IDLE_TIMEOUT", str(WORKER_WALL_TIMEOUT)))

WORKER_MAX_WALL_TIMEOUT = float(os.environ.get("WORKER_MAX_WALL_TIMEOUT", str(max(WORKER_WALL_TIMEOUT * 4, WORKER_WALL_TIMEOUT))))

WORKER_WAIT_POLL_INTERVAL = float(os.environ.get("WORKER_WAIT_POLL_INTERVAL", "10"))

WORKER_SEM_ACQUIRE_TIMEOUT = float(os.environ.get("WORKER_SEM_ACQUIRE_TIMEOUT", "120"))
# review/killsweep/escalation 共用：并发位 acquire 超时（worker 侧「并发位永久
# 丢失」事故的同类防护——一个 wedge 死线程此前可永久吃掉小配额的全部并发位）。
AGENT_SEM_ACQUIRE_TIMEOUT = float(os.environ.get("AGENT_SEM_ACQUIRE_TIMEOUT", "180"))

REVIEW_WALL_TIMEOUT = float(os.environ.get("REVIEW_WALL_TIMEOUT", "600"))

KILLSWEEP_WALL_TIMEOUT = float(os.environ.get("KILLSWEEP_WALL_TIMEOUT", "3600"))

ESCALATE_WALL_TIMEOUT = float(os.environ.get("ESCALATE_WALL_TIMEOUT", "900"))

WORKER_CLEANUP_TIMEOUT = float(os.environ.get("WORKER_CLEANUP_TIMEOUT", "15"))

REVIEW_RETRY_BACKOFF = float(os.environ.get("REVIEW_RETRY_BACKOFF", "300"))

REVIEW_MAX_ATTEMPTS = int(os.environ.get("REVIEW_MAX_ATTEMPTS", "5"))

TRACE_FLUSH_BATCH = int(os.environ.get("TRACE_FLUSH_BATCH", "50"))

TRACE_FLUSH_INTERVAL = float(os.environ.get("TRACE_FLUSH_INTERVAL", "3"))

TARGET_HEARTBEAT_INTERVAL = float(os.environ.get("TARGET_HEARTBEAT_INTERVAL", "30"))

KILLSWEEP_DEDUP_SCAN_LIMIT = int(os.environ.get("KILLSWEEP_DEDUP_SCAN_LIMIT", "200"))

KILLSWEEP_REPLAY_ENQUEUE_LIMIT = int(os.environ.get("KILLSWEEP_REPLAY_ENQUEUE_LIMIT", "50"))

_KILLSWEEP_STAGE_MAP = {
    "killsweep_start": "start",
    "killsweep_fofa": "fofa",
    "killsweep_http": "verify",
    "killsweep_shell": "verify",
}

_KILLSWEEP_STAGE_LABEL = {
    "start": "认指纹 / 圈定同款",
    "fofa": "FOFA 测绘统计",
    "verify": "实打验证同款站",
    "done": "分析完成",
}

_KILLSWEEP_STAGE_PCT = {
    "start": 15,
    "fofa": 55,
    "verify": 80,
    "done": 100,
}

MAX_TRANSIENT_LLM_REQUEUE = int(os.environ.get("MAX_TRANSIENT_LLM_REQUEUE", "5"))

FOFA_AUTH_FAIL_PAUSE_THRESHOLD = int(os.environ.get("FOFA_AUTH_FAIL_PAUSE_THRESHOLD", "3"))

STALE_NO_WORKER_GRACE = float(os.environ.get("STALE_NO_WORKER_GRACE", "150"))

QUEUE_LIVENESS_TIMEOUT = float(os.environ.get("QUEUE_LIVENESS_TIMEOUT", "6"))

QUEUE_LIVENESS_CACHE_TTL = float(os.environ.get("QUEUE_LIVENESS_CACHE_TTL", "300"))

QUEUE_LOW_SUCCESS_SKIP = os.environ.get("QUEUE_LOW_SUCCESS_SKIP", "1").lower() not in {"0", "false", "no"}

QUEUE_LOW_SUCCESS_SCORE_THRESHOLD = float(os.environ.get("QUEUE_LOW_SUCCESS_SCORE_THRESHOLD", "-3.5"))

QUEUE_TRANSIENT_PREFILTER_COOLDOWN = float(os.environ.get("QUEUE_TRANSIENT_PREFILTER_COOLDOWN", "900"))

QUEUE_DISPATCH_CANDIDATE_LIMIT = max(30, int(os.environ.get("QUEUE_DISPATCH_CANDIDATE_LIMIT", "120")))

_LOW_SUCCESS_SCORE_MARKERS = (
    "pure_frontend", "pure_marketing_site", "static_assets", "data_display_platform",
    "public_generic_service", "纯前端", "静态", "官网", "门户", "营销展示",
)

_TRANSIENT_UNREACHABLE_REASONS = ("服务异常",)

_NO_VULN_RETRY_PRIORITY_MARKERS = (
    "killchain:",
    "暴露端点:",
)

_USABLE_LEAKED_CRED_STATUS = {
    "usable", "valid", "verified", "login_success", "success", "authenticated", "ok"
}

_WORKER_DEEPEN_NEGATIVE_MARKERS = (
    "无。", "无攻击面", "无有效攻击面", "无入口", "无有效入口", "无可深入", "无可利用",
    "凭证均无效", "泄露凭证均无效", "所有凭证", "均失败", "登录失败", "默认密码登录失败",
    "需要有效凭证", "需有效凭证", "需先获取", "后续若获得", "若未来获得", "未来获得",
    "社会工程", "联系厂家", "无法继续", "无法突破", "打不穿", "已证明不通", "已失效",
    "均需认证", "均需鉴权", "需认证", "需鉴权", "无下游", "无其他攻击面",
)

_WORKER_DEEPEN_ACTIONABLE_MARKERS = (
    "拿到", "已拿到", "登录成功", "可用凭据", "可用凭证", "有效凭据", "有效凭证",
    "token", "jwt", "session", "cookie", "secret", "ak/sk", "accesskey", "签名",
    "未授权", "越权", "idor", "接口", "api", "参数", "对象 id", "对象ID", "user_id",
    "tenant", "导出", "上传", "下载", "写操作", "重置", "验证码", "绕过",
)

_WORKER_DEEPEN_ACTION_MARKERS = (
    "调用", "调 ", "访问", "验证", "证明", "上传", "执行", "解析", "读取", "导出",
    "枚举", "伪造", "重放", "替换", "越权读取", "越权修改",
)

def _now() -> datetime:
    return datetime.now(timezone.utc)

def _worker_timeout_reason(started_at: float, last_activity_at: float, now: float) -> str:
    """返回 worker 应被回收的原因；空字符串表示继续等。

    - idle：长时间没有任何 worker 事件，通常是 LLM/工具卡死；
    - max_wall：即使一直活跃也不能无限占用线程池。
    """
    if WORKER_MAX_WALL_TIMEOUT > 0 and now - started_at >= WORKER_MAX_WALL_TIMEOUT:
        return f"worker 达到最大墙钟上限(>{int(WORKER_MAX_WALL_TIMEOUT)}s)，强制回收"
    if WORKER_IDLE_TIMEOUT > 0 and now - last_activity_at >= WORKER_IDLE_TIMEOUT:
        return f"worker 空闲超时(>{int(WORKER_IDLE_TIMEOUT)}s 无新动作)，强制回收"
    return ""

def _has_usable_leaked_cred(creds: list | None) -> bool:
    """是否存在已验证可用的泄露凭据。

    搜集阶段的 leaked_creds 只是按质量打分筛选，不能代表真的可登录。
    no_vuln 后只有显式带成功/可用标记的凭据才值得自动回队深挖。
    """
    for cred in creds or []:
        if not isinstance(cred, dict):
            continue
        if any(cred.get(k) is True for k in (
            "usable", "valid", "verified", "login_success", "authenticated"
        )):
            return True
        status = str(cred.get("status") or cred.get("result") or cred.get("login_status") or "").strip().lower()
        if status in _USABLE_LEAKED_CRED_STATUS:
            return True
    return False

def _is_actionable_worker_deepen_lead(lead: str) -> bool:
    """worker finish(no_vuln) 时给出的 deepen_lead 是否真值得自动回火。

    deepen_lead 是模型自由文本，实际运行里会出现“无”“未来有凭证再测”这类空线索。
    这类不应再派 worker；只有已经拿到某个据点，且下一步能落到具体接口/参数/凭据/状态
    验证时，才值得自动深挖。
    """
    text = (lead or "").strip()
    if len(text) < 8:
        return False
    compact = text.lower()
    if any(marker.lower() in compact for marker in _WORKER_DEEPEN_NEGATIVE_MARKERS):
        return False
    has_actionable_marker = any(marker.lower() in compact for marker in _WORKER_DEEPEN_ACTIONABLE_MARKERS)
    has_concrete_endpoint = "/" in text or "?" in text or "=" in text
    has_concrete_action = any(marker.lower() in compact for marker in _WORKER_DEEPEN_ACTION_MARKERS)
    return has_actionable_marker and (has_concrete_endpoint or has_concrete_action)

def _consume_task_exception(task: asyncio.Future) -> None:
    """读取后台 future 异常，避免未观测异常和引用链长期滞留。"""
    try:
        task.exception()
    except (asyncio.CancelledError, Exception):
        pass

def _log_bg_task_exc(task: asyncio.Future, label: str) -> None:
    """后台 fire-and-forget 任务的异常回调：记录留痕而非静默吞掉。
    专治「实时落库/推送悄悄失败 → 真洞丢失且无从追查」。"""
    try:
        exc = task.exception()
    except asyncio.CancelledError:
        return
    except Exception:
        return
    if exc is not None:
        logger.error("background task %s failed: %r", label, exc,
                     exc_info=(type(exc), exc, exc.__traceback__))

def _bracket_ipv6_host(host: str) -> str:
    """裸 IPv6 加方括号，避免拼进 URL 后被 urlparse/httpx 误当 host:port。

    形如 `250:4809:3:fcfc:feff:febc:b092` 的裸 IPv6，直接拼 `http://<ip>` 会让
    解析器把最后一段当端口 → `ValueError: Port could not be cast to integer`。
    """
    from app.urlnorm import bracket_ipv6_host
    return bracket_ipv6_host(host)

def _with_scheme(url_or_host: str) -> str:
    s = (url_or_host or "").strip()
    if not s:
        return ""
    if "://" in s:
        return s
    from app.urlnorm import ensure_scheme
    return ensure_scheme(s)

def _swap_url_scheme(url: str) -> str:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            return ""
        alt = "https" if p.scheme == "http" else "http"
        return urlunparse((alt, p.netloc, p.path or "/", "", p.query, ""))
    except Exception:
        return ""

def _probe_urls(url: str, host: str) -> list[str]:
    """生成派发前探活 URL：优先原 URL，再试同 host 的另一种 http/https。"""
    primary = _with_scheme(url or host)
    urls: list[str] = []
    for candidate in (primary, _swap_url_scheme(primary), _with_scheme(host)):
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls

def _probe_target_liveness(url: str, host: str, timeout: float) -> dict:
    """同步派发前预筛，给 run_in_executor 调用。

    - 任意可访问 HTTP 响应都算 alive；
    - prefilter 判定的 CDN/静态/5xx 等返回 skip=True，不交给 worker 消耗 token；
    - http/https 都不通才 alive=False。
    """
    urls = _probe_urls(url, host)
    skipped: list[dict] = []
    for probe_url in urls:
        skip, reason, info = prefilter.should_skip_ex(host, probe_url, timeout=timeout)
        if not skip:
            return {
                "alive": True,
                "url": probe_url,
                "status": info.get("status", 0),
                "skip": False,
            }
        skipped.append({"reason": reason, "url": probe_url, "status": info.get("status", 0)})

    for item in skipped:
        reason = item.get("reason") or ""
        if reason and reason != "死链/连接超时/无响应":
            return {
                "alive": True,
                "url": item.get("url") or (urls[0] if urls else url or host),
                "status": item.get("status", 0),
                "skip": True,
                "reason": reason,
            }
    return {
        "alive": False,
        "url": urls[0] if urls else (url or host),
        "status": 0,
        "skip": False,
        "reason": "派发前探活失败：死链/连接超时/无响应",
    }

def _llm_for_task(task: Task, on_provider_failure=None, on_provider_selected=None) -> LLMClient:
    return llm_client_for_task(
        task,
        on_provider_failure=on_provider_failure,
        on_provider_selected=on_provider_selected,
    )
