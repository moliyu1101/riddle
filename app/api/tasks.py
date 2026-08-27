"""任务相关 API：创建 / 列表 / 详情 / 启停。"""
from __future__ import annotations


from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import case, delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dto import (
    CreateTaskRequest,
    DirectiveRequest,
    ParseAuthBatchRequest,
    ParseAuthBatchResponse,
    ParseForbiddenOpsRequest,
    ParseForbiddenOpsResponse,
    ParseTargetsRequest,
    ParseTargetsResponse,
    ParseQueryRequest,
    ParseQueryResponse,
    TaskModelsProbeRequest,
    TaskResponse,
    TaskStats,
    UpdateTaskRequest,
)
from app.agents import site_collab
from app.agents.auth_bootstrap import preview_auth_batch
from app.agents.manual_targets import clean_manual_target_lines, preview_manual_targets
from app.agents.query_analyzer import analyze_query
from app.agents.prompts import normalize_src_type
from app.tools.guard import _FORBIDDEN_OP_DEFS, forbidden_ops_labels, parse_forbidden_ops
from app.db.models import Finding, Killsweep, ReportVersion, Review, Target, Task, TaskEvent, to_cst, to_cst_iso
from app.db.session import get_session
from app.llm.usage import usage_snapshot
from app.orchestrator import manager
from app.security import resolve_role, token_from_headers
from app.settings_service import (
    _clean_llm_providers,
    _llm_identity,
    _normalize_model_list,
    _preserve_provider_keys,
    _public_llm_provider,
    is_masked_secret,
    list_available_models,
    normalize_llm_protocol,
    resolve_engine_config,
    resolve_llm_config,
    resolve_llm_providers,
    resolve_llm_runtime_mode,
    resolve_worker_prompt_version,
    secret_ref,
)
from app.agents.deepen import clamp_deepen_cap

router = APIRouter(prefix="/api/tasks", tags=["tasks"])

# 任务级 worker 并发上限（与设置页 max=32、全局 WORKER_MAX_CONCURRENCY 对齐）。
_TASK_CONCURRENCY_MAX = 32


def _clamp_task_concurrency(value: int | None, default: int = 3) -> int:
    try:
        n = int(value) if value is not None else default
    except (TypeError, ValueError):
        n = default
    return max(1, min(n, _TASK_CONCURRENCY_MAX))


# Activity Stream 历史回放：过滤高频低价值事件（与前端 BoardView 规则对齐）。
_STREAM_NOISE_KINDS = frozenset({"refill", "cluster_cooldown_skip", "skip", "ping"})
_STREAM_IMPORTANT_KINDS = frozenset({
    "collector_phase",
    # worker 生命周期里程碑：与前端 BoardView 的 IMPORTANT_KINDS 对齐。这些是清理后仍
    # 保留的摘要事件（见 maintenance.cleanup.TRACE_SUMMARY_KINDS），刷新走 board 历史
    # 回放时必须返回，否则「开始挖掘/收尾/发现漏洞」等记录会在刷新后凭空消失。
    "worker_start", "worker_finish", "worker_cancelled", "worker_auto_finish",
    "finding_submitted", "finding_duplicate", "finding_invalid",
    "target_done", "target_requeued", "timeout", "auto_deepen", "salvage",
    "coverage_reported", "site_followups_spawned",
    "review_start", "review_done", "review_error", "review_deferred", "review_cancelled",
    "reproduce_start", "reproduce_done",
    "killsweep_start", "killsweep_done", "killsweep_dedup", "killsweep_error",
    "killsweep_invalid", "killsweep_cancelled", "killsweep_retry",
    "reclaim", "recover", "workers_cancelled", "quota_stop",
    "llm_error", "llm_soft_retry", "llm_interrupt", "worker_resume", "llm_provider_failed",
    "tool_exception",
    "auth_status",
    "escalate_start", "escalate_done", "escalate_skip", "escalate_cancelled",
    "escalate_error", "escalate_abandon",
    "worker_directive_queued", "worker_directive",
})
# Verbose / Worker Trace：细粒度事件（默认活动流不回放，verbose 或 trace API 才返回）。
_STREAM_TRACE_KINDS = frozenset({
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
    "llm_round_start", "llm_error", "llm_soft_retry", "llm_interrupt",
    "finding_submitted", "finding_duplicate", "finding_invalid",
    "auth_status", "finish_blocked",
    "escalate_http", "escalate_shell", "escalate_session", "escalate_error", "escalate_abandon",
})


def _stream_event_visible(kind: str, level: str, *, verbose: bool = False) -> bool:
    if kind in _STREAM_NOISE_KINDS:
        return False
    if level in ("warn", "error"):
        return True
    if kind in _STREAM_IMPORTANT_KINDS or kind == "error":
        return True
    if verbose and kind in _STREAM_TRACE_KINDS:
        return True
    return False


def _is_observer(request: Request | None) -> bool:
    return bool(request and resolve_role(token_from_headers(request.headers)) == "observer")


def _observer_model_config() -> dict:
    return {"base_url": "", "model": "hidden", "api_key_set": False}


def _observer_fofa_config() -> dict:
    return {
        "max_pages": 0, "page_size": 0, "intent_mode": "",
        "key_set": False, "current_query": "", "cursor": 0,
        "collector_phase": "", "collector_phase_text": "",
    }


def _model_inherits_global(cfg: dict) -> bool:
    if cfg.get("inherit_global") is not None:
        return bool(cfg.get("inherit_global"))
    if cfg.get("providers"):
        return False
    return not any(
        str(cfg.get(key) or "").strip()
        for key in ("api_key", "providers_json", "base_url", "model", "protocol")
    )


def _mask_label(label: str) -> str:
    """观摩展示用：单个域名 label 保留少量轮廓，其余打 *。"""
    label = (label or "").strip()
    if not label:
        return ""
    if len(label) <= 2:
        return label[:1] + "*"
    if len(label) <= 4:
        return label[:1] + ("*" * (len(label) - 1))
    return label[:1] + ("*" * (len(label) - 2)) + label[-1:]


def _observer_host(host: str) -> str:
    """观摩模式域名/IP 部分打码，保留后缀结构但隐藏关键资产名。"""
    s = (host or "").strip().lower()
    if not s:
        return ""
    port = ""
    from app.urlnorm import is_bare_ipv6
    # 裸 IPv6(多冒号)不能 rsplit(':',1)——会把末段 hextet 误当端口剥掉。
    if ":" in s and not s.startswith("[") and not is_bare_ipv6(s):
        h, maybe_port = s.rsplit(":", 1)
        if maybe_port.isdigit():
            s, port = h, f":{maybe_port}"
    parts = s.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return ".".join(parts[:2] + ["*", "*"]) + port
    if len(parts) <= 1:
        return _mask_label(s) + port
    # 保留公共后缀，业务/学校/子域 label 全部局部打码，例如 xb.ymun.edu.cn -> x*.y***.edu.cn
    keep_suffix = 2 if parts[-2:] in (["edu", "cn"], ["com", "cn"], ["net", "cn"], ["org", "cn"], ["gov", "cn"]) else 1
    masked = [_mask_label(p) for p in parts[:-keep_suffix]] + parts[-keep_suffix:]
    return ".".join(masked) + port


def _observer_url(url: str, host: str = "") -> str:
    """观摩模式只展示 host 级目标，不展示 path/query。"""
    if host:
        return _observer_host(host)
    s = (url or "").strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    return _observer_host(s.split("/", 1)[0])


def _observer_text(text: str) -> str:
    """观摩模式隐藏站点标题、单位名等可直接识别目标的文本。"""
    return "" if (text or "").strip() else ""


def _observer_task_name(name: str, task_id: str = "") -> str:
    """观摩模式任务名可能含目标关键词，统一替换为匿名编号。"""
    suffix = (task_id or "")[:8] or "unknown"
    return f"任务 {suffix}"


def _observer_ip(ip: str) -> str:
    """观摩模式 IP 只保留前两段。"""
    parts = (ip or "").strip().split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return f"{parts[0]}.{parts[1]}.*.*"
    return ""


def _public_model_config(task: Task) -> dict:
    cfg = resolve_llm_config(task)
    raw_cfg = dict(task.model_config_json or {})
    inherit = _model_inherits_global(raw_cfg)
    task_providers = _clean_llm_providers(
        raw_cfg.get("providers") or raw_cfg.get("providers_json") or []
    )
    return {
        "base_url": cfg.base_url,
        "model": cfg.model,
        "models": _normalize_model_list(raw_cfg.get("models") or []),
        "protocol": cfg.protocol,
        "api_key_set": bool(cfg.api_key),
        "key_ref": secret_ref(cfg.api_key),
        "provider_count": len(resolve_llm_providers(task)),
        "providers": [_public_llm_provider(item) for item in task_providers],
        "mode": resolve_llm_runtime_mode(task),
        "prompt_version": resolve_worker_prompt_version(task),
        "inherit_global": inherit,
    }


def _public_fofa_config(task: Task) -> dict:
    cfg = dict(task.fofa_config or {})
    eff = resolve_engine_config(task)
    return {
        "engine": eff.get("engine", "fofa"),
        "base_url": eff["base_url"],
        "max_pages": eff["max_pages"],
        "page_size": eff["page_size"],
        "intent_mode": eff["intent_mode"],
        "key_set": bool(eff["key"]),
        "skip_site_recon": bool(cfg.get("skip_site_recon")),
        "current_query": cfg.get("current_query", ""),
        "cursor": cfg.get("cursor", 0),
        "collector_phase": cfg.get("collector_phase", ""),
        "collector_phase_text": cfg.get("collector_phase_text", ""),
        "last_target_filter_total": cfg.get("last_target_filter_total", 0),
        "last_target_filter_evaluated": cfg.get("last_target_filter_evaluated", 0),
        "last_skipped_filter": cfg.get("last_skipped_filter", 0),
        "leak_roots_total": cfg.get("leak_roots_total", 0),
        "leak_roots_done": cfg.get("leak_roots_done", 0),
        "leak_hits": cfg.get("leak_hits", 0),
        "leak_targets": cfg.get("leak_targets", 0),
    }


def _dump_auth_bindings(items) -> list[dict]:
    """把创建/更新请求里的凭据绑定规范成可落库的 list[dict]（保留原文便于回显编辑）。"""
    out: list[dict] = []
    for item in items or []:
        d = item.model_dump() if hasattr(item, "model_dump") else dict(item or {})
        target = str(d.get("target") or "*").strip() or "*"
        row = {
            "target": target,
            "username": str(d.get("username") or "").strip(),
            "password": str(d.get("password") or "").strip(),
            "cookie": str(d.get("cookie") or "").strip(),
            "authorization": str(d.get("authorization") or "").strip(),
            "login_url": str(d.get("login_url") or "").strip(),
            "raw": str(d.get("raw") or "").strip(),
            "note": str(d.get("note") or "").strip(),
        }
        if not any(row[k] for k in ("username", "password", "cookie", "authorization", "raw")):
            continue
        out.append(row)
    return out


def _public_auth_bindings(task: Task, observer: bool = False) -> list[dict]:
    if observer:
        return []
    rows = task.auth_bindings or []
    if not isinstance(rows, list):
        return []
    return [dict(x) for x in rows if isinstance(x, dict)]


def _task_progress(counts: dict[str, int]) -> int:
    """由目标状态分布推导任务进度：已落定(done/dead/skipped)占当前目标池比例。"""
    total = sum(counts.values())
    if total <= 0:
        return 0
    settled = counts.get("done", 0) + counts.get("dead", 0) + counts.get("skipped", 0)
    return max(1, min(99, round(100 * settled / total)))


def _stats_int(stats, name: str) -> int:
    """安全提取 TaskStats 数值字段（测试中 stats 可能为 Mock，逐字段容错）。"""
    try:
        return int(getattr(stats, name, 0) or 0)
    except (TypeError, ValueError):
        return 0


def _stats_counts(stats) -> dict[str, int]:
    return {
        "queued": _stats_int(stats, "queued"),
        "scanning": _stats_int(stats, "scanning"),
        "done": _stats_int(stats, "done"),
        "dead": _stats_int(stats, "dead"),
        "skipped": _stats_int(stats, "skipped"),
    }


# 搜集器终态/待命阶段：到这些阶段说明目标入队已结束，进度应切回「处置进度」。
# 24×7 自动补队列下搜集器常驻待命（idle），但主进度环必须展示处置口径，
# 否则手动清单任务会在入队完成后永久停在无意义的「25% 搜集进度」。
_COLLECT_DONE_PHASES = frozenset({"dispatch", "idle", "exhausted", "fofa_error"})
_PHASE_LABELS = {
    "prefilter": "探活预筛",
    "scoring": "评分归属",
    "target_filter": "正在跑过滤器阶段",
    "enrich": "补充情报",
    "dispatch": "入队完成",
}
_PHASE_PCT = {"prefilter": 18, "scoring": 38, "target_filter": 62, "enrich": 78, "dispatch": 100}


# Worker 活态阶段分类：依据 action 文本与发现数推导，供看板单元卡展示阶段徽章。
# 顺序即优先级：命中「已发现」则优先展示战果，其余按动作特征归类。
def _worker_phase(w: dict) -> str:
    action = str(w.get("action") or "")
    if int(w.get("findings") or 0) > 0 or action.startswith("🎯"):
        return "found"
    if "收尾" in action or "自动收敛" in action:
        return "finishing"
    if "HTTP" in action or action.startswith("$") or "拦截" in action or "查重" in action:
        return "verify"
    if "💭" in action or "LLM 思考" in action or "思考中" in action:
        return "thinking"
    if "凭据" in action or "认证" in action or "登录" in action or "弱口令" in action:
        return "auth"
    if "启动" in action or "初始化" in action:
        return "booting"
    return "recon"


def _worker_progress(w: dict) -> int:
    """0-100 粗略进度：以轮次推进侦察，发现漏洞后按战果抬升。"""
    r = int(w.get("round") or 0)
    f = int(w.get("findings") or 0)
    if f > 0:
        return min(100, 55 + f * 12)
    return min(50, r * 6)


def _progress_view(task_status: str, stats, fofa_config: dict) -> dict:
    """统一进度视图（前后端单一事实来源）。

    kind=collect 表示目标搜集期（进度环走阶段推进），kind=dispose 表示处置期
    （已落定目标 done/dead/skipped 占目标池比例）。前端原样渲染，不再自行推导。
    """
    counts = _stats_counts(stats)
    total = sum(counts.values())
    settled = counts["done"] + counts["dead"] + counts["skipped"]
    cfg = fofa_config or {}
    phase = str(cfg.get("collector_phase") or "")

    if task_status != "running":
        collecting = False
    elif phase:
        collecting = phase not in _COLLECT_DONE_PHASES
    else:
        collecting = total == 0

    if collecting:
        phase_pct = _PHASE_PCT.get(phase, 25)
        f_total = int(cfg.get("last_target_filter_total") or 0)
        f_done = int(cfg.get("last_target_filter_evaluated") or 0)
        if phase == "enrich" and f_total > 0:
            phase_pct = max(72, min(88, round(100 * f_done / f_total)))
        pct = phase_pct or 8
        meta = f"过滤器 {f_done}/{f_total}" if f_total > 0 else (phase or "初始化中")
    else:
        phase_pct = 100
        pct = round(100 * settled / total) if total > 0 else 0
        meta = ""

    label = str(cfg.get("collector_phase_text") or "") or _PHASE_LABELS.get(phase, "")
    return {
        "pct": pct,
        "kind": "collect" if collecting else "dispose",
        "phase": phase,
        "phase_label": label,
        "phase_pct": phase_pct,
        "meta": meta,
    }


def _timeline_buckets(items: list, bucket: str, limit: int) -> list[dict]:
    """把 [(bucket_key, [findings, accepted]), ...] 补零展成连续桶序列（最近 limit 个）。"""
    if not items:
        return []
    by_key = {str(k): (int(v[0] or 0), int(v[1] or 0)) for k, v in items}
    keys = sorted(by_key)
    if bucket == "hour":
        # 'YYYY-MM-DD HH' 逐小时推进
        from datetime import datetime, timedelta
        fmt = "%Y-%m-%d %H"
        start = datetime.strptime(keys[0], fmt)
        end = datetime.strptime(keys[-1], fmt)
        span = []
        cur = start
        while cur <= end:
            span.append(cur.strftime(fmt))
            cur += timedelta(hours=1)
    else:
        from datetime import date, timedelta
        start = date.fromisoformat(keys[0])
        end = date.fromisoformat(keys[-1])
        span = []
        cur = start
        while cur <= end:
            span.append(cur.isoformat())
            cur += timedelta(days=1)
    span = span[-limit:] if limit > 0 else span
    return [
        {"ts": k, "findings": by_key.get(k, (0, 0))[0], "accepted": by_key.get(k, (0, 0))[1]}
        for k in span
    ]


def _task_to_dto(t: Task, stats: TaskStats | None = None,
                 pending_user_review: int = 0, observer: bool = False,
                 total_targets: int = 0, total_vulns: int = 0, progress: int = 0) -> TaskResponse:
    model_config = _public_model_config(t)
    if observer:
        model_config = _observer_model_config()
    return TaskResponse(
        id=t.id, name=_observer_task_name(t.name, t.id) if observer else t.name, status=t.status, src_type=t.src_type,
        vuln_types=t.vuln_types or [], target_source=t.target_source,
        engine=t.engine or "", fofa_query="" if observer else t.fofa_query, concurrency=t.concurrency,
        deepen_cap=clamp_deepen_cap(getattr(t, "deepen_cap", None)),
        src_rules="" if observer else (t.src_rules or ""),
        manual_targets=[] if observer else (t.manual_targets or []),
        auth_bindings=_public_auth_bindings(t, observer=observer),
        model_config_data=model_config,
        fofa_config=_observer_fofa_config() if observer else _public_fofa_config(t),
        engine_config={} if observer else {"engine": t.engine or ""},
        llm_usage={} if observer else usage_snapshot(t.id, model_config.get("model", "")),
        created_at=to_cst_iso(t.created_at), updated_at=to_cst_iso(t.updated_at),
        stats=stats, pending_user_review=pending_user_review,
        total_targets=total_targets, total_vulns=total_vulns, progress=progress,
    )


async def _compute_stats(session: AsyncSession, task_id: str) -> TaskStats:
    stats = TaskStats()
    rows = await session.execute(
        select(Target.status, func.count()).where(Target.task_id == task_id).group_by(Target.status)
    )
    for status, cnt in rows.all():
        if status == "queued":
            stats.queued += cnt
        elif status in ("assigned", "scanning"):
            stats.scanning += cnt
        elif status == "done":
            stats.done += cnt
        elif status == "dead":
            stats.dead += cnt
        elif status == "skipped":
            stats.skipped += cnt

    # findings 两项计数合并为一次扫表（conditional aggregation）：
    # findings_total 排除 superseded（被打回深挖让位的旧线索，不算真实漏洞）。
    frow = (await session.execute(
        select(
            func.count(case((Finding.status != "superseded", 1))),
            func.count(case((Finding.status == "pending_review", 1))),
        ).where(Finding.task_id == task_id)
    )).one()
    stats.findings_total = frow[0] or 0
    stats.pending_review = frow[1] or 0

    # reviews 一次 GROUP BY 同时算出 verdict 维度计数（accepted/ignored/deepen）
    # 与用户复审维度计数（review_pending/submit_ready/rejected），避免两次扫表。
    ur_rows = await session.execute(
        select(Review.verdict, Review.user_status, Review.submitted, func.count())
        .where(Review.task_id == task_id)
        .group_by(Review.verdict, Review.user_status, Review.submitted)
    )
    for verdict, user_status, submitted, cnt in ur_rows.all():
        if verdict == "accepted":
            stats.accepted += cnt
        elif verdict == "ignored":
            stats.ignored += cnt
        elif verdict == "deepen":
            stats.deepen += cnt
        if verdict == "accepted" and user_status == "pending":
            stats.review_pending += cnt
        if user_status == "passed" and not submitted:
            stats.submit_ready += cnt
        elif user_status == "rejected":
            stats.rejected += cnt
    stats.killsweep = (await session.execute(
        select(func.count()).select_from(Killsweep).where(
            Killsweep.task_id == task_id, Killsweep.status != "invalid")
    )).scalar() or 0
    # AI 未采纳归档：与 /archived 接口筛选完全一致，保证徽标数字 == 列表条数（不用点开即预加载）
    stats.archived = (await session.execute(
        select(func.count()).select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(
            Finding.task_id == task_id,
            Review.verdict.in_(["ignored", "deepen"]),
            Review.user_status == "pending",
            Finding.status != "superseded",
        )
    )).scalar() or 0
    stats.archived_write = (await session.execute(
        select(func.count()).select_from(Finding)
        .join(Review, Review.finding_id == Finding.id)
        .where(
            Finding.task_id == task_id,
            Review.verdict.in_(["ignored", "deepen"]),
            Review.user_status == "pending",
            Finding.status != "superseded",
            or_(
                Finding.title.ilike("%删除%"),
                Finding.title.ilike("%修改%"),
                Finding.title.ilike("%更新%"),
                Finding.title.ilike("%delete%"),
                Finding.title.ilike("%update%"),
                Finding.target_url.ilike("%delete%"),
                Finding.target_url.ilike("%update%"),
                Finding.target_url.ilike("%/save%"),
                Finding.target_url.ilike("%remove%"),
            ),
        )
    )).scalar() or 0
    return stats


@router.post("", response_model=TaskResponse)
async def create_task(req: CreateTaskRequest, session: AsyncSession = Depends(get_session)):
    if req.target_source not in {"fofa", "manual", "both", "site"}:
        raise HTTPException(400, "target_source 必须是 fofa/manual/both/site")
    engine_name = req.engine or ""
    # 引擎配置：合并 engine_config 和向后兼容的 fofa_config
    fofa_cfg = req.fofa_config.model_dump(exclude_defaults=True) if req.fofa_config else {}
    eng_cfg = req.engine_config.model_dump(exclude_defaults=True) if req.engine_config else {}
    if engine_name and engine_name != "fofa" and eng_cfg.get("key"):
        fofa_cfg["key"] = eng_cfg["key"]
    if eng_cfg.get("base_url"):
        fofa_cfg["base_url"] = eng_cfg["base_url"]
    inherit_global = req.model_config_data.inherit_global
    raw_providers = list(req.model_config_data.providers or [])
    has_providers = bool(raw_providers)
    if inherit_global is None:
        inherit_global = not bool(
            (req.model_config_data.model_fields_set
             & {"base_url", "api_key", "model", "protocol", "providers"})
            or has_providers
        )
    if inherit_global:
        model_config = req.model_config_data.model_dump(exclude_defaults=True)
        model_config = {k: v for k, v in model_config.items() if k == "prompt_version"}
        model_config["inherit_global"] = True
    elif has_providers:
        cleaned = _clean_llm_providers(raw_providers)
        if not cleaned:
            raise HTTPException(400, "端点池至少需要一个配置完整且已启用的 LLM 端点")
        if not any(item.get("enabled", True) for item in cleaned):
            raise HTTPException(400, "端点池至少需要启用一个端点")
        model_config = {
            "inherit_global": False,
            "providers": cleaned,
        }
        if req.model_config_data.prompt_version:
            model_config["prompt_version"] = req.model_config_data.prompt_version
    else:
        model_config = req.model_config_data.model_dump(
            exclude={"inherit_global", "providers"},
            exclude_unset=True,
        )
        model_config.pop("providers", None)
        model_config["inherit_global"] = False
    task = Task(
        name=req.name, src_type=normalize_src_type(req.src_type), vuln_types=req.vuln_types,
        src_rules=req.src_rules, target_source=req.target_source,
        engine=engine_name, fofa_query=req.fofa_query,
        manual_targets=clean_manual_target_lines(req.manual_targets or []),
        auth_bindings=_dump_auth_bindings(req.auth_bindings),
        model_config_json=model_config,
        fofa_config=fofa_cfg, concurrency=_clamp_task_concurrency(req.concurrency),
        deepen_cap=clamp_deepen_cap(req.deepen_cap),
        status="created",
    )
    session.add(task)
    await session.commit()
    await session.refresh(task)
    return _task_to_dto(task)


@router.post("/parse-targets", response_model=ParseTargetsResponse)
async def parse_targets(req: ParseTargetsRequest):
    """手动目标清单实时解析预览（不落库），供新建/编辑任务前端即时反馈。"""
    return preview_manual_targets(req.text)


@router.post("/parse-query", response_model=ParseQueryResponse)
async def parse_query(req: ParseQueryRequest):
    """查询条件实时解析（不落库）：语法校验 + 关键词提取 + 问题提示，供前端即时反馈。"""
    return analyze_query(req.engine, req.query, req.src_type, req.intent_mode)


@router.post("/parse-auth-batch", response_model=ParseAuthBatchResponse)
async def parse_auth_batch(req: ParseAuthBatchRequest):
    """批量登录凭据解析预览（不落库）：拆行 + 归一化 + 类型统计 + 忽略行，供前端批量导入即时反馈。"""
    return preview_auth_batch(req.text)


@router.post("/parse-forbidden-ops", response_model=ParseForbiddenOpsResponse)
async def parse_forbidden_ops_endpoint(req: ParseForbiddenOpsRequest):
    """任务规则禁止操作实时解析（不落库）：命中「禁止前缀+操作关键词」的操作类别，
    执行层将硬拦截。供前端规则区即时展示硬约束生效情况。"""
    ops = parse_forbidden_ops(req.text)
    label_map = {op["id"]: op["label"] for op in _FORBIDDEN_OP_DEFS}
    return ParseForbiddenOpsResponse(
        forbidden=[{"id": op, "label": label_map.get(op, op)} for op in ops],
        count=len(ops),
        labels=forbidden_ops_labels(ops),
    )


@router.post("/{task_id}/models")
async def probe_task_models(
    task_id: str,
    body: TaskModelsProbeRequest,
    session: AsyncSession = Depends(get_session),
):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    config = resolve_llm_config(task)
    base_url = str(body.base_url or config.base_url or "").strip()
    protocol = normalize_llm_protocol(body.protocol or config.protocol)
    api_key = str(body.api_key or "").strip()
    if is_masked_secret(api_key):
        api_key = ""
    key_ref = str(body.key_ref or "").strip()
    if not api_key:
        # 端点池：按 key_ref + 身份匹配「任意」任务级端点，不能只认 resolve_llm_config 的第一个
        raw_cfg = dict(task.model_config_json or {})
        task_providers = _clean_llm_providers(
            raw_cfg.get("providers") or raw_cfg.get("providers_json") or []
        )
        want = _llm_identity(base_url, protocol)
        for item in task_providers:
            candidate = str(item.get("api_key") or "").strip()
            if not candidate:
                continue
            if _llm_identity(item.get("base_url"), item.get("protocol")) != want:
                continue
            if key_ref and secret_ref(candidate) != key_ref:
                continue
            api_key = candidate
            break
        if not api_key:
            same_identity = want == _llm_identity(config.base_url, config.protocol)
            same_ref = bool(key_ref and key_ref == secret_ref(config.api_key))
            if same_identity and (not key_ref or same_ref) and config.api_key:
                api_key = config.api_key
        if not api_key:
            # 再兜底系统配置里的同身份密钥（任务端点可能与系统池共用）
            return await list_available_models(
                base_url=base_url,
                api_key="",
                protocol=protocol,
                key_ref=key_ref or None,
            )
    return await list_available_models(
        base_url=base_url,
        api_key=api_key,
        protocol=protocol,
    )


@router.get("", response_model=list[TaskResponse])
async def list_tasks(request: Request, session: AsyncSession = Depends(get_session)):
    rows = await session.execute(select(Task).order_by(Task.created_at.desc()))
    tasks = rows.scalars().all()
    # 一条聚合查询拿到所有任务的「待人工复审」数（AI accepted 且用户 pending），避免 N+1。
    pending_map: dict[str, int] = {}
    pr_rows = await session.execute(
        select(Review.task_id, func.count())
        .where(Review.verdict == "accepted", Review.user_status == "pending")
        .group_by(Review.task_id)
    )
    for tid, cnt in pr_rows.all():
        pending_map[tid] = cnt

    # 漏洞数（排除 superseded）与目标状态分布：各一条聚合查询，避免 N+1。
    vuln_map: dict[str, int] = {}
    v_rows = await session.execute(
        select(Finding.task_id, func.count())
        .where(Finding.status != "superseded")
        .group_by(Finding.task_id)
    )
    for tid, cnt in v_rows.all():
        vuln_map[tid] = cnt

    tcount_map: dict[str, dict[str, int]] = {}
    t_rows = await session.execute(
        select(Target.task_id, Target.status, func.count())
        .group_by(Target.task_id, Target.status)
    )
    for tid, status, cnt in t_rows.all():
        tcount_map.setdefault(tid, {})[status] = cnt

    observer = _is_observer(request)
    return [
        _task_to_dto(
            t,
            pending_user_review=pending_map.get(t.id, 0),
            total_targets=sum(tcount_map.get(t.id, {}).values()),
            total_vulns=vuln_map.get(t.id, 0),
            progress=_task_progress(tcount_map.get(t.id, {})),
            observer=observer,
        )
        for t in tasks
    ]


@router.get("/hard-targets")
async def global_hard_targets(
    request: Request,
    status: str = Query("all", pattern="^(all|dead|skipped)$"),
    q: str | None = Query(None),
    limit: int = Query(100, ge=1),
    offset: int = Query(0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """全局硬骨头库：跨任务聚合 dead/skipped 目标，便于回捞和复盘。

    搜索 q 下推到 SQL（LIKE），避免「先取 limit 条再内存过滤」导致只能搜到最新 N 条的问题。
    """
    statuses = ["dead", "skipped"] if status == "all" else [status]
    safe_limit = max(1, min(int(limit or 100), 100))
    safe_offset = max(0, int(offset or 0))
    observer = _is_observer(request)
    stmt = (
        select(Target, Task.name)
        .join(Task, Task.id == Target.task_id)
        .where(Target.status.in_(statuses))
    )
    needle = (q or "").strip()
    if needle:
        like = f"%{needle}%"
        stmt = stmt.where(or_(
            Target.host.ilike(like),
            Target.url.ilike(like),
            *([] if observer else [
                Target.org.ilike(like),
                Target.school.ilike(like),
                Target.title.ilike(like),
                Target.dead_reason.ilike(like),
                Target.last_error.ilike(like),
                Target.priority_reason.ilike(like),
                Task.name.ilike(like),
            ]),
        ))
    total = (await session.execute(
        select(func.count()).select_from(stmt.subquery())
    )).scalar() or 0
    stmt = (
        stmt.order_by(Target.updated_at.desc(), Target.priority_score.desc())
        .offset(safe_offset)
        .limit(safe_limit)
    )
    rows = (await session.execute(stmt)).all()
    out = []
    for t, task_name in rows:
        out.append({
            "id": t.id,
            "task_id": t.task_id,
            "task_name": _observer_task_name(task_name, t.task_id) if observer else task_name,
            "url": _observer_url(t.url, t.host) if observer else t.url,
            "host": _observer_host(t.host) if observer else t.host,
            "ip": _observer_ip(t.ip) if observer else t.ip,
            "org": _observer_text(t.org) if observer else t.org,
            "school": _observer_text(t.school) if observer else t.school,
            "title": _observer_text(t.title) if observer else t.title,
            "source": "" if observer else t.source,
            "status": t.status,
            "verdict": t.verdict,
            "retry_count": t.retry_count,
            "priority_score": t.priority_score,
            "priority_reason": "" if observer else t.priority_reason,
            "dead_reason": "" if observer else t.dead_reason,
            "last_error": "" if observer else t.last_error,
            "created_at": to_cst_iso(t.created_at),
            "updated_at": to_cst_iso(t.updated_at),
        })
    return {
        "items": out,
        "total": total,
        "limit": safe_limit,
        "offset": safe_offset,
        "has_more": safe_offset + len(out) < total,
    }


@router.get("/hard-targets/stats")
async def hard_targets_stats(session: AsyncSession = Depends(get_session)):
    """全局硬骨头库总览：总数、硬骨头(dead)、已跳过(skipped) 分布。"""
    rows = (await session.execute(
        select(Target.status, func.count())
        .where(Target.status.in_(["dead", "skipped"]))
        .group_by(Target.status)
    )).all()
    counts = {status: cnt for status, cnt in rows}
    total = sum(counts.values())
    return {
        "total": total,
        "dead": counts.get("dead", 0),
        "skipped": counts.get("skipped", 0),
    }


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(task_id: str, request: Request, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    stats = await _compute_stats(session, task_id)
    counts = _stats_counts(stats)
    return _task_to_dto(
        task, stats,
        total_targets=sum(counts.values()),
        total_vulns=_stats_int(stats, "findings_total"),
        progress=_task_progress(counts),
        observer=_is_observer(request),
    )


@router.patch("/{task_id}", response_model=TaskResponse)
async def update_task(task_id: str, req: UpdateTaskRequest, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    if req.name is not None:
        task.name = req.name.strip() or task.name
    if req.src_type is not None:
        task.src_type = normalize_src_type(req.src_type)
    if req.vuln_types is not None:
        task.vuln_types = [v.strip() for v in req.vuln_types if str(v).strip()]
    if req.src_rules is not None:
        task.src_rules = req.src_rules
    if req.target_source is not None:
        if req.target_source not in {"fofa", "manual", "both", "site"}:
            raise HTTPException(400, "target_source 必须是 fofa/manual/both/site")
        task.target_source = req.target_source
    if req.engine is not None:
        task.engine = req.engine
    if req.manual_targets is not None:
        task.manual_targets = clean_manual_target_lines(req.manual_targets)
    if req.auth_bindings is not None:
        task.auth_bindings = _dump_auth_bindings(req.auth_bindings)
    if req.concurrency is not None:
        task.concurrency = _clamp_task_concurrency(req.concurrency)
    if req.deepen_cap is not None:
        task.deepen_cap = clamp_deepen_cap(req.deepen_cap)

    old_query = task.fofa_query or ""
    if req.fofa_query is not None:
        task.fofa_query = req.fofa_query
        # 改语法后清 exhausted，允许重新翻页（即使本次未带 fofa_config patch）
        if req.fofa_query != old_query:
            fc = dict(task.fofa_config or {})
            fc.pop("current_query", None)
            fc["cursor"] = 0
            fc["history"] = []
            fc.pop("empty_streak", None)
            fc.pop("empty_query_streak", None)
            fc.pop("fofa_exhausted", None)
            task.fofa_config = fc

    if req.model_config_data is not None:
        patch = req.model_config_data.model_dump(exclude_unset=True)
        cfg = dict(task.model_config_json or {})
        current_runtime = resolve_llm_config(task)
        current_identity = _llm_identity(
            current_runtime.base_url, current_runtime.protocol
        )
        prompt_version = cfg.get("prompt_version")
        if "prompt_version" in patch and patch.get("prompt_version") is not None:
            prompt_version = str(patch["prompt_version"]).strip()

        wants_single = (
            patch.get("inherit_global") is False
            or any(k in patch for k in ("base_url", "api_key", "model", "protocol"))
        ) and not ("providers" in patch and patch.get("providers") is not None)

        if patch.get("inherit_global") is True:
            cfg = {"inherit_global": True}
            if prompt_version:
                cfg["prompt_version"] = prompt_version
        elif "providers" in patch and patch.get("providers") is not None:
            old_providers = _clean_llm_providers(
                cfg.get("providers") or cfg.get("providers_json") or []
            )
            preserved = _preserve_provider_keys(patch.get("providers") or [], old_providers)
            cleaned = _clean_llm_providers(preserved)
            if not cleaned:
                raise HTTPException(400, "端点池至少需要一个配置完整且已启用的 LLM 端点")
            if not any(item.get("enabled", True) for item in cleaned):
                raise HTTPException(400, "端点池至少需要启用一个端点")
            cfg = {
                "inherit_global": False,
                "providers": cleaned,
            }
            if prompt_version:
                cfg["prompt_version"] = prompt_version
        elif wants_single:
            # 单端点覆盖：清掉任务级端点池，写入 base_url/model/key
            cfg.pop("providers", None)
            cfg.pop("providers_json", None)
            cfg["inherit_global"] = False
            next_identity = _llm_identity(
                patch.get("base_url")
                if patch.get("base_url") is not None
                else cfg.get("base_url") or current_runtime.base_url,
                patch.get("protocol")
                if patch.get("protocol") is not None
                else cfg.get("protocol") or current_runtime.protocol,
            )
            supplied_key = str(patch.get("api_key") or "").strip()
            has_new_key = bool(supplied_key and not is_masked_secret(supplied_key))
            if current_identity != next_identity and not has_new_key:
                cfg.pop("api_key", None)
            for key in ("base_url", "model", "protocol"):
                if key in patch and patch[key] is not None:
                    value = str(patch[key]).strip()
                    cfg[key] = normalize_llm_protocol(value) if key == "protocol" else value
            if "models" in patch and patch["models"] is not None:
                cfg["models"] = _normalize_model_list(patch["models"])
            if has_new_key:
                cfg["api_key"] = supplied_key
            if prompt_version:
                cfg["prompt_version"] = prompt_version
        else:
            # 仅改 prompt_version 等非模式字段，保留原 inherit/providers/single
            if "prompt_version" in patch:
                if prompt_version:
                    cfg["prompt_version"] = prompt_version
                else:
                    cfg.pop("prompt_version", None)
        task.model_config_json = cfg

    if req.engine_config is not None:
        ec_patch = req.engine_config.model_dump(exclude_unset=True)
        ec_cfg = dict(task.fofa_config or {})
        if "key" in ec_patch and str(ec_patch.get("key") or "").strip():
            ec_cfg["key"] = str(ec_patch["key"]).strip()
        if "base_url" in ec_patch and ec_patch["base_url"] is not None:
            ec_cfg["base_url"] = ec_patch["base_url"]
        task.fofa_config = ec_cfg

    if req.fofa_config is not None:
        patch = req.fofa_config.model_dump(exclude_unset=True)
        cfg = dict(task.fofa_config or {})
        if "key" in patch and str(patch.get("key") or "").strip():
            cfg["key"] = str(patch["key"]).strip()
        if "base_url" in patch and patch["base_url"] is not None:
            cfg["base_url"] = str(patch["base_url"]).strip()
        if "max_pages" in patch and patch["max_pages"] is not None:
            cfg["max_pages"] = max(1, min(int(patch["max_pages"]), 200))
        if "page_size" in patch and patch["page_size"] is not None:
            cfg["page_size"] = max(1, min(int(patch["page_size"]), 1000))
        if "intent_mode" in patch and patch["intent_mode"] is not None:
            intent_mode = str(patch["intent_mode"]).strip()
            if intent_mode not in {"", "syntax", "intent"}:
                raise HTTPException(400, "intent_mode 必须是空/syntax/intent")
            cfg["intent_mode"] = intent_mode
        if req.fofa_query is not None and req.fofa_query != old_query:
            # 与上方 fofa_query 变更清理保持一致（可能已被清过，幂等）
            cfg.pop("current_query", None)
            cfg["cursor"] = 0
            cfg["history"] = []
            cfg.pop("empty_streak", None)
            cfg.pop("empty_query_streak", None)
            cfg.pop("fofa_exhausted", None)
        task.fofa_config = cfg

    await session.commit()
    await session.refresh(task)
    stats = await _compute_stats(session, task_id)
    counts = _stats_counts(stats)
    return _task_to_dto(
        task, stats,
        total_targets=sum(counts.values()),
        total_vulns=_stats_int(stats, "findings_total"),
        progress=_task_progress(counts),
    )


@router.delete("/{task_id}", status_code=204)
async def delete_task(task_id: str, session: AsyncSession = Depends(get_session)):
    """删除任务及其关联数据（目标 / 漏洞 / 审核 / 通杀 / 事件）。

    - 先停掉运行时（终止后台 worker/collector），避免删除过程中仍有写入产生脏数据。
    - 过审漏洞（Review.user_status == "passed" 且非 superseded）孤立化保留：
      置空 task_id/target_id 外键，脱离级联删除，任务删除后仍可在漏洞档案库查看报告。
    - 全局情报库（Intel）为跨任务共享知识，不随任务删除。
    """
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    # 1) 先彻底停掉该任务的运行时，确保没有后台协程再往这些表写数据。
    await manager.stop(task_id)

    # 2) 过审漏洞孤立化：置空外键，脱离级联删除（任务删除后仍保留在漏洞档案库）。
    passed_ids = (await session.execute(
        select(Finding.id)
        .join(Review, Review.finding_id == Finding.id)
        .where(Finding.task_id == task_id, Review.user_status == "passed",
               Finding.status != "superseded")
    )).scalars().all()
    passed_set = set(passed_ids)
    if passed_set:
        await session.execute(
            update(Finding).where(Finding.id.in_(passed_set)).values(task_id=None, target_id=None)
        )
        await session.execute(
            update(Review).where(Review.finding_id.in_(passed_set)).values(task_id=None)
        )

    # 3) 删除该任务下其余关联（过审项已置空外键，不会被误删）。
    all_ids = (await session.execute(
        select(Finding.id).where(Finding.task_id == task_id)
    )).scalars().all()
    delete_ids = [fid for fid in all_ids if fid not in passed_set]
    if delete_ids:
        await session.execute(delete(ReportVersion).where(ReportVersion.finding_id.in_(delete_ids)))
    await session.execute(delete(Review).where(Review.task_id == task_id))
    await session.execute(delete(Finding).where(Finding.task_id == task_id))
    await session.execute(delete(Killsweep).where(Killsweep.task_id == task_id))
    await session.execute(delete(TaskEvent).where(TaskEvent.task_id == task_id))
    await session.execute(delete(Target).where(Target.task_id == task_id))

    # 4) 删除任务本体。
    await session.execute(delete(Task).where(Task.id == task_id))
    await session.commit()
    return None


async def _compute_site_collab(session: AsyncSession, task_id: str) -> dict | None:
    """单站协作态势：把该任务的 site 路线按三阶段聚合，供前端「协作态势」面板渲染。
    每条路线带上它名下已产出的 finding 数（未 superseded），让流水线能体现各路线战果。"""
    # 每个 site target 的 finding 计数（排除被顶替的旧洞）
    fc_rows = (await session.execute(
        select(Finding.target_id, func.count())
        .where(Finding.task_id == task_id, Finding.status != "superseded")
        .group_by(Finding.target_id)
    )).all()
    fc = {tid: n for tid, n in fc_rows}

    rows = (await session.execute(
        select(Target.id, Target.source, Target.status, Target.verdict,
               Target.priority_reason, Target.deepen_count)
        .where(Target.task_id == task_id)
    )).all()
    payload = [{
        "source": r.source, "status": r.status, "verdict": r.verdict,
        "priority_reason": r.priority_reason, "deepen_count": r.deepen_count,
        "findings": fc.get(r.id, 0),
    } for r in rows]
    return site_collab.build_collab_overview(payload)


@router.get("/{task_id}/board")
async def task_board(
    task_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    verbose: bool = Query(False),
):
    """实时看板快照：在跑 worker 活态 + 目标进度 + 最近事件（用于刷新后恢复）。"""
    from app.db.models import TaskEvent
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    runner = manager.get_runner(task_id)
    observer = _is_observer(request)
    live = runner.live_workers() if runner else []
    live_escalations = runner.live_escalations() if runner else []
    if observer:
        safe_live = []
        for w in live:
            raw_action = str(w.get("action") or "")
            if "HTTP" in raw_action or "$" in raw_action or "发现" in raw_action or "漏洞" in raw_action:
                action = "正在验证目标"
            elif "思考" in raw_action or "💭" in raw_action:
                action = "正在分析目标"
            else:
                action = raw_action[:40] or "运行中"
            safe_live.append({
                "worker_id": w.get("worker_id", ""),
                "target": _observer_url(w.get("target", "")),
                "status": w.get("status", ""),
                "action": action,
                "score": w.get("score", 0),
                "score_reason": "",
                "mode": w.get("mode", ""),
                "phase": _worker_phase(w),
                "progress": _worker_progress(w),
            })
        live = safe_live
        live_escalations = [{
            "finding_id": e.get("finding_id", ""),
            "title": "hidden",
            "severity": e.get("severity", ""),
            "action": "扩大危害进行中",
            "started_at": e.get("started_at", ""),
        } for e in live_escalations]
    else:
        live = [dict(w, phase=_worker_phase(w), progress=_worker_progress(w)) for w in live]

    stats = await _compute_stats(session, task_id)
    # 漏洞类型分布（排除 superseded 旧线索），供任务大屏「漏洞类型分布」可视化。
    vuln_rows = (await session.execute(
        select(Finding.vuln_type, func.count())
        .where(Finding.task_id == task_id, Finding.status != "superseded")
        .group_by(Finding.vuln_type)
        .order_by(func.count().desc())
        .limit(8)
    )).all()
    vuln_dist = [{"type": (vt or "其他").strip() or "其他", "count": c} for vt, c in vuln_rows]
    concurrency = _clamp_task_concurrency(task.concurrency)
    worker_summary = {
        "running": len(live),
        "escalating": len(live_escalations),
        "idle": max(0, concurrency - len(live)),
    }
    # 智能节流状态（队列水位/LLM 健康度/同机构扎堆），观察者只给摘要不泄露细节。
    throttle = {}
    if runner:
        ts = runner._throttle_state or {}
        throttle = {
            "cap": ts.get("cap", concurrency),
            "base_cap": ts.get("base_cap", concurrency),
            "reasons": ts.get("reasons", []) if not observer else [],
            "queued": ts.get("queued", 0),
            "same_org_ratio": ts.get("same_org_ratio", 0.0),
            "llm_under_cooldown": ts.get("llm_under_cooldown", False),
            "provider_cooldowns": ts.get("provider_cooldowns", 0),
        }
    tab_summary = {
        "review": stats.review_pending,
        "submit": stats.submit_ready,
        "killsweep": stats.killsweep,
        "rejected": stats.rejected,
        "archived": stats.archived,
        "archived_write": stats.archived_write,
    }

    # 最近重要事件（倒序，给前端做历史回放；多取一些再过滤噪音）
    fetch_limit = 500 if verbose else 200
    event_cap = 120 if verbose else 60
    ev_rows = (await session.execute(
        select(TaskEvent).where(TaskEvent.task_id == task_id)
        .order_by(TaskEvent.id.desc()).limit(fetch_limit)
    )).scalars().all()
    events = []
    for e in ev_rows:
        if not _stream_event_visible(e.kind or "", e.level or "info", verbose=verbose):
            continue
        payload = e.payload or {}
        events.append({
            "agent": e.agent, "kind": e.kind, "level": e.level,
            "message": "" if observer else e.message,
            "ts": to_cst_iso(e.ts),
            "target_id": "" if observer else (payload.get("target_id") or ""),
            **({} if observer else {k: payload.get(k) for k in (
                "url", "method", "command", "text", "title", "verdict", "round", "tool", "error",
                "target", "mode", "prompt_version",
            ) if k in payload}),
        })
        if len(events) >= event_cap:
            break

    # 单站协作态势（仅 site 任务）：三阶段路线流水线，不含敏感数据，观察者也可看。
    site_overview = None
    if task.target_source == "site":
        site_overview = await _compute_site_collab(session, task_id)
        if runner is not None and site_overview is not None:
            bb = getattr(runner, "_blackboard", None)
            if bb is not None:
                snap = bb.snapshot()
                if observer:
                    # 观察者脱敏：只给分工与数量，不给具体 URL/情报内容。
                    site_overview["blackboard"] = {
                        "directions": snap.get("directions") or {},
                        "counts": {
                            "probed": len(snap.get("probed") or []),
                            "coverage": len(snap.get("coverage") or []),
                            "leads": len(snap.get("leads") or []),
                            "excluded": len(snap.get("excluded") or []),
                        },
                    }
                else:
                    site_overview["blackboard"] = snap

    fofa_cfg = _observer_fofa_config() if observer else _public_fofa_config(task)
    return {
        "task_status": task.status,
        "live_workers": live,
        "live_escalations": live_escalations,
        "stats": stats.model_dump(),
        "vuln_dist": vuln_dist,
        "progress": _progress_view(task.status, stats, fofa_cfg),
        "concurrency": concurrency,
        "worker_summary": worker_summary,
        "throttle": throttle,
        "tab_summary": tab_summary,
        "fofa_config": fofa_cfg,
        "model_config_data": _observer_model_config() if observer else _public_model_config(task),
        "llm_usage": {} if observer else usage_snapshot(task.id, resolve_llm_config(task).model),
        "events": events,
        "site_collab": site_overview,
    }


@router.get("/{task_id}/timeline")
async def task_timeline(
    task_id: str,
    bucket: str = Query("day", pattern="^(day|hour)$"),
    limit: int = Query(14, ge=1, le=90),
    session: AsyncSession = Depends(get_session),
):
    """作战时间线：按天/小时分桶的新增发现与过审数（前端指挥横幅的作战曲线）。

    created_at 落库为 UTC，这里按东八区分桶，与站内 to_cst_iso 展示口径一致。
    accepted 计数与漏洞库口径一致：Review.verdict=accepted，排除 superseded 旧线索。
    桶间空档补零保证曲线连续；limit 取最近 N 个桶。
    """
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")

    rows = (await session.execute(
        select(Finding.created_at, Review.verdict)
        .select_from(Finding)
        .outerjoin(Review, Review.finding_id == Finding.id)
        .where(Finding.task_id == task_id, Finding.status != "superseded")
    )).all()

    def bucket_key(dt) -> str:
        local = to_cst(dt)
        return local.strftime("%Y-%m-%d %H") if bucket == "hour" else local.strftime("%Y-%m-%d")

    agg: dict[str, list[int]] = {}
    for created_at, verdict in rows:
        if created_at is None:
            continue
        k = bucket_key(created_at)
        cell = agg.setdefault(k, [0, 0])
        cell[0] += 1
        if verdict == "accepted":
            cell[1] += 1
    buckets = _timeline_buckets(sorted(agg.items()), bucket, limit)
    return {
        "bucket": bucket,
        "buckets": buckets,
        "total_findings": sum(b["findings"] for b in buckets),
        "total_accepted": sum(b["accepted"] for b in buckets),
    }


@router.post("/{task_id}/targets/{target_id}/skip")
async def skip_target(task_id: str, target_id: str):
    """人工从看板删除某个目标：取消其正在进行的挖掘（若有）并标记跳过，使其不再被派发、
    回队或被 collector 重新收集。仅影响【本任务】的目标列表，不影响其它任务与已挖到的漏洞。"""
    res = await manager.skip_target(task_id, target_id)
    if not res.get("ok"):
        raise HTTPException(404, res.get("error") or "无法删除该目标")
    return res


@router.post("/{task_id}/targets/{target_id}/directive")
async def inject_target_directive(task_id: str, target_id: str, body: DirectiveRequest):
    """向运行中的 worker 注入人工实时指令；下一轮 LLM 调用前生效。"""
    res = manager.inject_directive(task_id, target_id, body.directive)
    if not res.get("ok"):
        raise HTTPException(400, res.get("error") or "无法注入指令")
    return res


@router.get("/{task_id}/targets/{target_id}/trace")
async def target_trace(
    task_id: str,
    target_id: str,
    request: Request,
    session: AsyncSession = Depends(get_session),
    limit: int = Query(200, ge=1, le=500),
):
    """单个目标的 worker 执行轨迹（落库的细粒度事件，刷新后可回看）。"""
    if _is_observer(request):
        raise HTTPException(403, "观摩令牌不允许查看执行轨迹")
    tgt = await session.get(Target, target_id)
    if not tgt or tgt.task_id != task_id:
        raise HTTPException(404, "目标不存在或不属于该任务")
    rows = (await session.execute(
        select(TaskEvent)
        .where(TaskEvent.task_id == task_id, TaskEvent.agent == "worker")
        .order_by(TaskEvent.id.desc())
        .limit(min(limit * 3, 1500))
    )).scalars().all()
    events = []
    for e in rows:
        payload = e.payload or {}
        if payload.get("target_id") != target_id:
            continue
        events.append({
            "agent": e.agent,
            "kind": e.kind,
            "level": e.level,
            "message": e.message,
            "ts": to_cst_iso(e.ts),
            "target_id": target_id,
            **{k: payload.get(k) for k in (
                "url", "method", "command", "text", "title", "verdict", "round", "tool", "error",
                "target", "mode", "prompt_version",
            ) if k in payload},
        })
        if len(events) >= limit:
            break
    events.reverse()  # 时间正序，便于 round-by-round 阅读
    return {
        "target_id": target_id,
        "host": tgt.host or "",
        "url": tgt.url or "",
        "status": tgt.status,
        "events": events,
    }


@router.post("/{task_id}/escalations/{finding_id}/cancel")
async def cancel_escalation(task_id: str, finding_id: str):
    """取消单个正在进行的扩大危害任务。"""
    res = manager.cancel_escalation(task_id, finding_id)
    if not res.get("ok"):
        raise HTTPException(404, res.get("error") or "无法取消扩大危害")
    return res


@router.get("/{task_id}/targets")
async def list_targets(task_id: str, request: Request, status: str | None = None, limit: int = 200,
                       session: AsyncSession = Depends(get_session)):
    """目标库查询。status 过滤：
       不传=全部 / queued+assigned+scanning=在挖 / dead=硬骨头库 / skipped=低分跳过 / done=已完成。"""
    q = select(Target).where(Target.task_id == task_id)
    if status == "alive":
        q = q.where(Target.status.in_(["queued", "assigned", "scanning"]))
    elif status:
        q = q.where(Target.status == status)
    q = q.order_by(Target.priority_score.desc(), Target.created_at.desc()).limit(min(limit, 1000))
    rows = (await session.execute(q)).scalars().all()
    observer = _is_observer(request)
    return [{
        "id": t.id, "url": _observer_url(t.url, t.host) if observer else t.url,
        "host": _observer_host(t.host) if observer else t.host,
        "ip": _observer_ip(t.ip) if observer else t.ip,
        "org": _observer_text(t.org) if observer else t.org,
        "school": _observer_text(t.school) if observer else t.school,
        "title": _observer_text(t.title) if observer else t.title,
        "status": t.status, "verdict": t.verdict,
        "is_edu": t.is_edu, "priority_score": t.priority_score,
        "priority_reason": "" if observer else t.priority_reason, "retry_count": t.retry_count,
        "deepen_count": t.deepen_count, "dead_reason": "" if observer else t.dead_reason,
        "last_error": "" if observer else t.last_error,
        "created_at": to_cst_iso(t.created_at),
    } for t in rows]

@router.post("/{task_id}/start", response_model=TaskResponse)
async def start_task(task_id: str, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    task.status = "running"
    # 重启即清空 FOFA 账号失败计数与错误标记：用户通常已换/续了 key，
    # 否则旧计数 ≥ 阈值会导致刚启动又被自动暂停。
    if task.fofa_config and (task.fofa_config.get("fofa_auth_fail_count") or task.fofa_config.get("daily_limit_count")):
        fc = dict(task.fofa_config)
        fc["fofa_auth_fail_count"] = 0
        fc["daily_limit_count"] = 0
        fc.pop("daily_limit_until", None)
        fc.pop("daily_limit_exhausted", None)
        fc.pop("last_fofa_error", None)
        task.fofa_config = fc
    await session.commit()
    await manager.ensure_running(task_id)
    await session.refresh(task)
    return _task_to_dto(task)


@router.post("/{task_id}/pause", response_model=TaskResponse)
async def pause_task(task_id: str, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    task.status = "paused"
    await session.commit()
    await manager.pause(task_id)
    await session.refresh(task)
    return _task_to_dto(task)


@router.post("/{task_id}/stop", response_model=TaskResponse)
async def stop_task(task_id: str, session: AsyncSession = Depends(get_session)):
    task = await session.get(Task, task_id)
    if not task:
        raise HTTPException(404, "任务不存在")
    task.status = "stopped"
    await session.commit()
    await manager.stop(task_id)
    await session.refresh(task)
    return _task_to_dto(task)
