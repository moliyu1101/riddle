"""独立多轮对话模块 API：按 Agent 角色分组、多轮活动流水、@实体引用、附件分析、旁路提问（/btw）与只读工具协同。"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import and_, delete, desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    ChatActivity,
    ChatConversation,
    Finding,
    Intel,
    Review,
    Target,
    Task,
    to_cst_iso,
)
from app.db.session import DB_PATH, SessionLocal, get_session
from app.llm.client import LLMClient, LLMError
from app.llm.usage import clear_usage, usage_snapshot
from app.settings_service import (
    public_settings_view,
    refresh_cache,
    resolve_llm_providers,
    resolve_llm_runtime_mode,
)

logger = logging.getLogger("riddle.chat")

router = APIRouter(prefix="/api/chat", tags=["chat"])

# ── 运行态并发与取消管理 ──────────────────────────────────────
_CHAT_STATE_LOCK = threading.Lock()
_CHAT_BUSY: set[str] = set()
_CHAT_CANCEL_EVENTS: dict[str, threading.Event] = {}
_CHAT_TASKS: dict[str, asyncio.Task] = {}

_MAX_TITLE_LEN = 120
_MAX_BATCH_DELETE = 100
_MAX_UPLOAD_BYTES = 10 * 1024 * 1024  # 10 MB
_MAX_TOOL_ROUNDS = 6
_CHAT_UPLOADS_ROOT = Path(DB_PATH).resolve().parent / "chat_uploads"

# ── 内置对话 Agent 角色定义 ───────────────────────────────────
CHAT_AGENTS: list[dict[str, str]] = [
    {
        "key": "assistant",
        "name": "通用安全助手",
        "description": "检索平台漏洞、任务、目标与情报，解答安全技术问题并协助日常研判。",
        "system_prompt": (
            "你是知蠹 Riddle 平台的通用安全智能助手。你可以结合用户提问、@引用的平台实体上下文以及只读查询工具，"
            "帮助安全工程师检索漏洞、分析任务进展、排查配置与解读安全日志。\n"
            "原则：回答结构清晰、准确务实；优先使用提供的只读工具核实平台数据，不编造不存在的记录；"
            "仅在授权测试与防守分析范围内提供建议。"
        ),
    },
    {
        "key": "analyst",
        "name": "漏洞分析与复审专家",
        "description": "深度研判漏洞真实性、核定危害等级、润色 SRC 报告与给出修复建议。",
        "system_prompt": (
            "你是资深漏洞复审与安全研究专家，熟悉 EduSRC 与企业 SRC 审核口径。\n"
            "你需要帮助用户核查漏洞成因、校验 PoC 证据链充分性、评估危害定级（严重/高危/中危/低危）、"
            "润色漏洞标题与复现步骤，并给出可落地的修复建议。如需核对某条漏洞，请先调用只读工具读取完整记录。"
        ),
    },
    {
        "key": "recon",
        "name": "测绘与资产侦察专家",
        "description": "编写与优化 FOFA/Quake/Hunter/ZoomEye/Shodan/Censys 测绘语法，梳理资产暴露面。",
        "system_prompt": (
            "你是空间测绘与攻击面侦察专家，精通 FOFA、360 Quake、奇安信 Hunter、ZoomEye、Shodan、Censys 的查询语法与指纹提炼。\n"
            "帮助用户根据产品组件或漏洞特征构造精准的测绘语法、过滤无效资产、收敛授权范围，并结合平台目标与情报给出侦察思路。"
        ),
    },
    {
        "key": "code_audit",
        "name": "代码审计专家",
        "description": "审查上传的源码、配置或请求报文，追踪污点流并给出安全修复代码。",
        "system_prompt": (
            "你是资深代码安全审计专家，擅长 Java、Python、Go、PHP、Node.js/TypeScript 与前端安全审计。\n"
            "请结合用户粘贴或上传的源码/配置文件，系统梳理鉴权控制、输入校验、SQL/模板/命令注入、SSRF、反序列化与越权风险，"
            "指出具体行号或函数位置，并给出最小改动的安全修复补丁。"
        ),
    },
    {
        "key": "ops",
        "name": "任务调度与运维顾问",
        "description": "分析挖掘任务运行状态、硬骨头目标、情报沉淀与并发/护栏调优策略。",
        "system_prompt": (
            "你是知蠹 Riddle 平台任务调度与运维顾问。擅长查看各挖掘任务状态、并发配置、硬骨头目标原因与全局情报复用情况，"
            "为用户提供任务编排、测绘翻页、模型池路由与护栏策略优化建议。"
        ),
    },
]
_CHAT_AGENTS_MAP = {item["key"]: item for item in CHAT_AGENTS}

# ── 只读工具声明（供对话 Agent 按需调用）─────────────────────
CHAT_TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "search_riddle_findings",
            "description": "在知蠹 Riddle 漏洞库中按关键字检索已落盘漏洞（标题、类型、目标 URL、归属）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "检索关键字，留空返回最新漏洞"},
                    "limit": {"type": "integer", "description": "返回条数上限（1-20），默认 10"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "get_riddle_finding",
            "description": "按漏洞 ID 读取单条漏洞的完整详情、PoC 摘要与审核结论。",
            "parameters": {
                "type": "object",
                "properties": {
                    "finding_id": {"type": "string", "description": "漏洞 ID"},
                },
                "required": ["finding_id"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_riddle_tasks",
            "description": "列出知蠹 Riddle 的挖掘任务概览（状态、测绘引擎、查询语法、并发与 SRC 模式）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "status": {"type": "string", "description": "按状态过滤（running/paused/stopped/created），留空返回全部"},
                    "limit": {"type": "integer", "description": "返回条数上限（1-20），默认 10"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_riddle_targets",
            "description": "检索平台资产目标（URL、Host、标题、高校归属、扫描状态与失败原因）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "域名、标题或学校关键字"},
                    "task_id": {"type": "string", "description": "可选，限定所属任务 ID"},
                    "limit": {"type": "integer", "description": "返回条数上限（1-20），默认 10"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_riddle_intel",
            "description": "检索全局情报库（指纹打法、有效端点、目标画像、验证凭证摘要）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "匹配键或摘要关键字"},
                    "kind": {"type": "string", "description": "可选：fingerprint / endpoint / profile / cred"},
                    "limit": {"type": "integer", "description": "返回条数上限（1-20），默认 10"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_chat_attachment",
            "description": "读取当前会话中用户已上传附件的文本内容（最多读取前 16KB）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "filename": {"type": "string", "description": "附件文件名或相对路径"},
                },
                "required": ["filename"],
            },
        },
    },
]

# ── Pydantic 请求模型 ─────────────────────────────────────────
class ConversationCreateRequest(BaseModel):
    agent_key: str = "assistant"
    title: str = ""
    model_override: str = ""


class ConversationPatchRequest(BaseModel):
    title: str | None = None
    pinned: bool | None = None
    model_override: str | None = None


class BatchDeleteRequest(BaseModel):
    ids: list[str] = Field(default_factory=list)


class ChatAttachmentItem(BaseModel):
    name: str
    path: str
    size: int = 0
    content_type: str = ""


class SendMessageRequest(BaseModel):
    message: str = ""
    attachments: list[ChatAttachmentItem] = Field(default_factory=list)


class SideQuestionRequest(BaseModel):
    question: str = ""


# ── 工具与 DTO 辅助函数 ───────────────────────────────────────
def _is_busy(conv_id: str) -> bool:
    with _CHAT_STATE_LOCK:
        return conv_id in _CHAT_BUSY


def _cancel_conversation(conv_id: str) -> bool:
    with _CHAT_STATE_LOCK:
        ev = _CHAT_CANCEL_EVENTS.get(conv_id)
        if ev is not None:
            ev.set()
            return True
    return False


def _sanitize_filename(name: str) -> str:
    base = os.path.basename((name or "upload.txt").replace("\\", "/")).strip()
    cleaned = re.sub(r"[^A-Za-z0-9._\-\u4e00-\u9fff]+", "_", base).strip("._")
    if not cleaned:
        cleaned = "upload.txt"
    return cleaned[:100]


def _conv_upload_dir(conv_id: str) -> Path:
    safe_id = re.sub(r"[^A-Za-z0-9_-]", "", conv_id)
    return _CHAT_UPLOADS_ROOT / safe_id


def _safe_read_attachment(conv_id: str, rel_or_name: str, max_chars: int = 16000) -> str:
    base_dir = _conv_upload_dir(conv_id).resolve()
    if not base_dir.exists():
        return "当前会话暂无已上传附件。"
    candidate_name = os.path.basename((rel_or_name or "").replace("\\", "/"))
    if not candidate_name:
        return "附件文件名不能为空。"
    target = (base_dir / candidate_name).resolve()
    try:
        target.relative_to(base_dir)
    except ValueError:
        return "非法附件路径。"
    if not target.is_file():
        # 按原文件名后缀模糊匹配（上传时可能带短前缀）
        matches = [p for p in base_dir.iterdir() if p.is_file() and p.name.endswith(candidate_name)]
        if not matches:
            return f"未找到附件：{candidate_name}"
        target = matches[0]
    raw = target.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("gb18030", errors="replace")
    if len(text) > max_chars:
        return text[:max_chars] + f"\n\n...[已截断，总字符数 {len(text)}]"
    return text


def _activity_dto(a: ChatActivity, *, include_detail: bool = True) -> dict[str, Any]:
    detail_text = a.detail or ""
    has_detail = bool(detail_text)
    if not include_detail and len(detail_text) > 1200:
        detail_preview = detail_text[:1200] + "\n...[展开查看完整内容]"
    else:
        detail_preview = detail_text
    return {
        "id": a.id,
        "conversation_id": a.conversation_id,
        "kind": a.kind,
        "text": a.text or "",
        "detail": detail_preview,
        "has_more_detail": has_detail and not include_detail and len(detail_text) > 1200,
        "tool_name": a.tool_name or "",
        "attachments": a.attachments or [],
        "meta": a.meta or {},
        "input_tokens": int(a.input_tokens or 0),
        "output_tokens": int(a.output_tokens or 0),
        "created_at": to_cst_iso(a.created_at),
    }


def _conv_dto(
    c: ChatConversation,
    *,
    running: bool = False,
    message_count: int = 0,
    input_tokens: int = 0,
    output_tokens: int = 0,
    last_preview: str = "",
) -> dict[str, Any]:
    agent_info = _CHAT_AGENTS_MAP.get(c.agent_key) or CHAT_AGENTS[0]
    return {
        "id": c.id,
        "agent_key": c.agent_key,
        "agent_name": agent_info["name"],
        "title": c.title or "新对话",
        "model_override": c.model_override or "",
        "pinned": bool(c.pinned),
        "pinned_at": to_cst_iso(c.pinned_at),
        "running": running,
        "message_count": message_count,
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "last_preview": last_preview,
        "created_at": to_cst_iso(c.created_at),
        "updated_at": to_cst_iso(c.updated_at),
    }


def _available_model_options() -> list[dict[str, str]]:
    """收集当前全局设置中可用模型选项（供对话模型覆盖下拉框）。"""
    pub = public_settings_view()
    llm_pub = pub.get("llm") or {}
    seen: set[str] = set()
    options: list[dict[str, str]] = []

    def _add(model_name: str, label: str = ""):
        m = str(model_name or "").strip()
        if not m or m in seen:
            return
        seen.add(m)
        options.append({"model": m, "label": label or m})

    if llm_pub.get("api_key_set"):
        _add(llm_pub.get("model", ""), f"{llm_pub.get('model', '')} (默认)")
        for m in llm_pub.get("models") or []:
            _add(m)
    for p in llm_pub.get("providers") or []:
        if p.get("enabled", True) and p.get("api_key_set"):
            pname = str(p.get("name") or "").strip()
            m = str(p.get("model") or "").strip()
            _add(m, f"{m} · {pname}" if pname else m)
    return options


def _build_chat_llm_client(model_override: str = "", usage_key: str | None = None) -> LLMClient | None:
    providers = resolve_llm_providers(None)
    if not providers:
        return None
    chosen = [dict(p) for p in providers]
    override = (model_override or "").strip()
    if override:
        exact = [p for p in chosen if str(p.get("model") or "").strip() == override]
        rest = [p for p in chosen if str(p.get("model") or "").strip() != override]
        if exact:
            chosen = exact + rest
        else:
            # 将首选端点模型替换为覆盖模型（同端点多模型）
            first = dict(chosen[0])
            first["model"] = override
            chosen = [first] + chosen
    pool_mode = resolve_llm_runtime_mode(None) == "pool" or len(chosen) > 1
    try:
        return LLMClient(providers=chosen, pool_mode=pool_mode, usage_key=usage_key)
    except Exception as exc:
        logger.warning("build chat llm client failed: %s", exc)
        return None


# ── @ 实体引用解析 ────────────────────────────────────────────
_MENTION_RE = re.compile(r"@\[(漏洞|任务|目标|情报)#([A-Za-z0-9_-]+)(?: ([^\]\r\n]*))?\]")
_MENTION_KIND_MAP = {
    "漏洞": "finding",
    "任务": "task",
    "目标": "target",
    "情报": "intel",
}


async def _resolve_mentions_context(session: AsyncSession, text: str) -> tuple[str, list[dict[str, str]]]:
    matches = list(_MENTION_RE.finditer(text or ""))
    if not matches:
        return "", []
    seen: set[tuple[str, str]] = set()
    resolved_meta: list[dict[str, str]] = []
    blocks: list[str] = []

    for m in matches[:10]:
        cn_kind, raw_id, label = m.group(1), m.group(2), (m.group(3) or "").strip()
        kind = _MENTION_KIND_MAP.get(cn_kind, "")
        if not kind or (kind, raw_id) in seen:
            continue
        seen.add((kind, raw_id))

        if kind == "finding":
            f = await session.get(Finding, raw_id)
            if f:
                r = (await session.execute(select(Review).where(Review.finding_id == f.id))).scalar_one_or_none()
                sev = (r.user_severity or r.severity_final) if r else f.severity_claimed
                blocks.append(
                    f"[引用漏洞 #{f.id}]\n"
                    f"- 标题: {f.title}\n- 类型: {f.vuln_type}\n- 等级: {sev}\n- 目标: {f.target_url}\n"
                    f"- 归属: {f.owner}\n- 描述: {(f.description or '')[:600]}\n"
                    f"- PoC 摘要: {(f.poc or '')[:600]}"
                )
                resolved_meta.append({"kind": "finding", "id": f.id, "label": f.title[:60]})
        elif kind == "task":
            t = await session.get(Task, raw_id)
            if t:
                blocks.append(
                    f"[引用任务 #{t.id}]\n"
                    f"- 名称: {t.name}\n- 状态: {t.status}\n- 模式: {t.src_type}\n- 引擎: {t.engine or 'fofa'}\n"
                    f"- 测绘语法: {t.fofa_query or '(无)'}\n- 并发: {t.concurrency}"
                )
                resolved_meta.append({"kind": "task", "id": t.id, "label": t.name[:60]})
        elif kind == "target":
            tg = await session.get(Target, raw_id)
            if tg:
                blocks.append(
                    f"[引用目标 #{tg.id}]\n"
                    f"- URL: {tg.url}\n- Host: {tg.host}\n- 标题: {tg.title}\n- 归属学校: {tg.school or tg.org}\n"
                    f"- 状态: {tg.status} ({tg.verdict})\n- 备注/死因: {tg.dead_reason or tg.last_error or '-'}"
                )
                resolved_meta.append({"kind": "target", "id": tg.id, "label": (tg.host or tg.url)[:60]})
        elif kind == "intel":
            it = await session.get(Intel, raw_id)
            if it:
                blocks.append(
                    f"[引用情报 #{it.id}]\n"
                    f"- 分类: {it.kind}\n- 匹配键: {it.match_key}\n- 可信度: {it.confidence}\n"
                    f"- 摘要: {it.summary}\n- 命中次数: {it.hit_count}"
                )
                resolved_meta.append({"kind": "intel", "id": it.id, "label": (it.summary or it.match_key)[:60]})
        else:
            if label:
                resolved_meta.append({"kind": kind, "id": raw_id, "label": label})

    if not blocks:
        return "", resolved_meta
    return "【用户 @引用的平台实体上下文】\n" + "\n\n".join(blocks), resolved_meta


# ── 只读工具执行器 ────────────────────────────────────────────
async def _execute_chat_tool(conv_id: str, tool_name: str, args: dict[str, Any]) -> str:
    limit = max(1, min(int(args.get("limit") or 10), 20))
    query = str(args.get("query") or "").strip()

    if tool_name == "read_chat_attachment":
        return _safe_read_attachment(conv_id, str(args.get("filename") or ""))

    async with SessionLocal() as session:
        if tool_name == "search_riddle_findings":
            stmt = (
                select(Finding, Review)
                .outerjoin(Review, Review.finding_id == Finding.id)
                .where(Finding.status != "superseded")
            )
            if query:
                like = f"%{query}%"
                stmt = stmt.where(
                    or_(
                        Finding.title.ilike(like),
                        Finding.vuln_type.ilike(like),
                        Finding.target_url.ilike(like),
                        Finding.owner.ilike(like),
                    )
                )
            rows = (await session.execute(stmt.order_by(desc(Finding.created_at)).limit(limit))).all()
            if not rows:
                return "未检索到匹配的漏洞记录。"
            out = []
            for f, r in rows:
                sev = (r.user_severity or r.severity_final) if r else f.severity_claimed
                ustatus = r.user_status if r else f.status
                out.append({
                    "id": f.id,
                    "title": f.title,
                    "vuln_type": f.vuln_type,
                    "severity": sev,
                    "status": ustatus,
                    "target_url": f.target_url,
                    "owner": f.owner,
                })
            return json.dumps(out, ensure_ascii=False, indent=2)

        if tool_name == "get_riddle_finding":
            fid = str(args.get("finding_id") or "").strip()
            f = await session.get(Finding, fid)
            if not f:
                return f"未找到 ID 为 {fid} 的漏洞记录。"
            r = (await session.execute(select(Review).where(Review.finding_id == f.id))).scalar_one_or_none()
            data = {
                "id": f.id,
                "task_id": f.task_id,
                "title": f.title,
                "vuln_type": f.vuln_type,
                "severity": (r.user_severity or r.severity_final) if r else f.severity_claimed,
                "target_url": f.target_url,
                "owner": f.owner,
                "description": (f.description or "")[:1500],
                "poc": (f.poc or "")[:1500],
                "review": {
                    "verdict": r.verdict,
                    "confidence": r.confidence,
                    "score": r.score,
                    "user_status": r.user_status,
                    "submitted": r.submitted,
                    "notes": r.reviewer_notes[:500],
                } if r else None,
            }
            return json.dumps(data, ensure_ascii=False, indent=2)

        if tool_name == "list_riddle_tasks":
            status_filter = str(args.get("status") or "").strip()
            stmt = select(Task)
            if status_filter and status_filter != "all":
                stmt = stmt.where(Task.status == status_filter)
            rows = (await session.execute(stmt.order_by(desc(Task.updated_at)).limit(limit))).scalars().all()
            if not rows:
                return "当前暂无符合条件的挖掘任务。"
            return json.dumps(
                [
                    {
                        "id": t.id,
                        "name": t.name,
                        "status": t.status,
                        "src_type": t.src_type,
                        "engine": t.engine or "fofa",
                        "fofa_query": t.fofa_query,
                        "concurrency": t.concurrency,
                        "updated_at": to_cst_iso(t.updated_at),
                    }
                    for t in rows
                ],
                ensure_ascii=False,
                indent=2,
            )

        if tool_name == "search_riddle_targets":
            stmt = select(Target)
            tid = str(args.get("task_id") or "").strip()
            if tid:
                stmt = stmt.where(Target.task_id == tid)
            if query:
                like = f"%{query}%"
                stmt = stmt.where(
                    or_(
                        Target.url.ilike(like),
                        Target.host.ilike(like),
                        Target.title.ilike(like),
                        Target.school.ilike(like),
                    )
                )
            rows = (await session.execute(stmt.order_by(desc(Target.priority_score)).limit(limit))).scalars().all()
            if not rows:
                return "未检索到匹配的目标资产。"
            return json.dumps(
                [
                    {
                        "id": tg.id,
                        "task_id": tg.task_id,
                        "url": tg.url,
                        "host": tg.host,
                        "title": tg.title,
                        "school": tg.school,
                        "status": tg.status,
                        "verdict": tg.verdict,
                        "dead_reason": tg.dead_reason,
                    }
                    for tg in rows
                ],
                ensure_ascii=False,
                indent=2,
            )

        if tool_name == "search_riddle_intel":
            stmt = select(Intel)
            kind = str(args.get("kind") or "").strip()
            if kind:
                stmt = stmt.where(Intel.kind == kind)
            if query:
                like = f"%{query}%"
                stmt = stmt.where(or_(Intel.match_key.ilike(like), Intel.summary.ilike(like)))
            rows = (await session.execute(stmt.order_by(desc(Intel.hit_count), desc(Intel.last_seen)).limit(limit))).scalars().all()
            if not rows:
                return "未检索到匹配的全局情报。"
            return json.dumps(
                [
                    {
                        "id": it.id,
                        "kind": it.kind,
                        "match_key": it.match_key,
                        "summary": it.summary,
                        "confidence": it.confidence,
                        "hit_count": it.hit_count,
                    }
                    for it in rows
                ],
                ensure_ascii=False,
                indent=2,
            )

    return f"未知工具：{tool_name}"


# ── 构建历史对话消息窗口 ──────────────────────────────────────
async def _load_conversation_history_messages(
    session: AsyncSession,
    conv: ChatConversation,
    *,
    max_turns: int = 24,
) -> list[dict[str, Any]]:
    agent_info = _CHAT_AGENTS_MAP.get(conv.agent_key) or CHAT_AGENTS[0]
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": agent_info["system_prompt"]},
    ]
    rows = (
        await session.execute(
            select(ChatActivity)
            .where(
                ChatActivity.conversation_id == conv.id,
                ChatActivity.kind.in_(("user", "assistant")),
            )
            .order_by(desc(ChatActivity.id))
            .limit(max_turns * 2)
        )
    ).scalars().all()
    rows.reverse()
    for row in rows:
        content = (row.text or "").strip()
        if not content:
            continue
        messages.append({"role": "user" if row.kind == "user" else "assistant", "content": content})
    return messages


async def _append_activity(
    conv_id: str,
    kind: str,
    *,
    text: str = "",
    detail: str = "",
    tool_name: str = "",
    attachments: list[dict[str, Any]] | None = None,
    meta: dict[str, Any] | None = None,
    input_tokens: int = 0,
    output_tokens: int = 0,
) -> ChatActivity:
    async with SessionLocal() as session:
        act = ChatActivity(
            conversation_id=conv_id,
            kind=kind,
            text=text,
            detail=detail,
            tool_name=tool_name,
            attachments=attachments or [],
            meta=meta or {},
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        session.add(act)
        conv = await session.get(ChatConversation, conv_id)
        if conv is not None:
            conv.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(act)
        return act


async def _run_conversation_turn(
    conv_id: str,
    agent_messages: list[dict[str, Any]],
    model_override: str,
    cancel_event: threading.Event,
) -> None:
    started = time.perf_counter()
    usage_key = f"chat-{conv_id}-{uuid.uuid4().hex[:8]}"
    used_model = model_override or ""
    try:
        llm = _build_chat_llm_client(model_override=model_override, usage_key=usage_key)
        if llm is None:
            await _append_activity(
                conv_id,
                "error",
                text="尚未配置可用的大模型 API Key，请先前往「模型与多角色路由」或「系统设置」完成配置。",
            )
            return

        messages = list(agent_messages)
        final_text = ""

        for round_idx in range(_MAX_TOOL_ROUNDS):
            if cancel_event.is_set():
                await _append_activity(conv_id, "stopped", text="已手动停止当前生成。")
                return

            last_round = round_idx == _MAX_TOOL_ROUNDS - 1
            call_messages = messages
            if last_round:
                call_messages = messages + [{
                    "role": "user",
                    "content": "请基于以上已检索的信息直接给出完整结论，不要再发起新的工具调用。",
                }]

            msg = await asyncio.to_thread(
                llm.chat,
                call_messages,
                CHAT_TOOLS,
                "none" if last_round else "auto",
                0.3,
            )

            if cancel_event.is_set():
                await _append_activity(conv_id, "stopped", text="已手动停止当前生成。")
                return

            reasoning = str(getattr(msg, "reasoning_content", "") or "").strip()
            if reasoning:
                await _append_activity(
                    conv_id,
                    "thinking",
                    text="推理思考过程",
                    detail=reasoning,
                )

            tool_calls = getattr(msg, "tool_calls", None) or []
            content = str(getattr(msg, "content", "") or "").strip()

            if tool_calls and not last_round:
                if content:
                    await _append_activity(conv_id, "thinking", text=content)

                assistant_msg: dict[str, Any] = {
                    "role": "assistant",
                    "content": content,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {"name": tc.function.name, "arguments": tc.function.arguments},
                        }
                        for tc in tool_calls
                    ],
                }
                messages.append(assistant_msg)

                for tc in tool_calls:
                    if cancel_event.is_set():
                        await _append_activity(conv_id, "stopped", text="已手动停止当前生成。")
                        return
                    t_name = tc.function.name
                    raw_args = tc.function.arguments or "{}"
                    try:
                        parsed_args = json.loads(raw_args) if isinstance(raw_args, str) else dict(raw_args)
                    except Exception:
                        parsed_args = {}

                    await _append_activity(
                        conv_id,
                        "tool_use",
                        text=f"调用工具 `{t_name}`",
                        detail=json.dumps(parsed_args, ensure_ascii=False, indent=2),
                        tool_name=t_name,
                    )

                    t0 = time.perf_counter()
                    try:
                        tool_output = await _execute_chat_tool(conv_id, t_name, parsed_args)
                    except Exception as exc:
                        tool_output = f"工具执行失败：{exc}"
                    dur_ms = int((time.perf_counter() - t0) * 1000)

                    await _append_activity(
                        conv_id,
                        "tool_result",
                        text=f"`{t_name}` 返回结果（{dur_ms}ms）",
                        detail=tool_output,
                        tool_name=t_name,
                        meta={"duration_ms": dur_ms},
                    )
                    messages.append({
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "content": tool_output[:12000],
                    })
                continue

            final_text = content or "（模型未返回正文内容）"
            await _append_activity(conv_id, "assistant", text=final_text)
            break

        snap = usage_snapshot(usage_key)
        used_model = str(snap.get("model") or used_model or "")
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        await _append_activity(
            conv_id,
            "result",
            text=f"本轮完成 · {elapsed_ms}ms",
            meta={"elapsed_ms": elapsed_ms, "model": used_model},
            input_tokens=int(snap.get("prompt_tokens") or 0),
            output_tokens=int(snap.get("completion_tokens") or 0),
        )
    except (LLMError, RuntimeError) as exc:
        await _append_activity(conv_id, "error", text=f"模型请求失败：{exc}")
    except asyncio.CancelledError:
        await _append_activity(conv_id, "stopped", text="对话任务已取消。")
    except Exception as exc:
        logger.exception("chat turn failed for conv=%s", conv_id)
        await _append_activity(conv_id, "error", text=f"对话执行异常：{exc}")
    finally:
        clear_usage(usage_key)
        with _CHAT_STATE_LOCK:
            _CHAT_BUSY.discard(conv_id)
            _CHAT_CANCEL_EVENTS.pop(conv_id, None)
            _CHAT_TASKS.pop(conv_id, None)


# ── API 路由 ──────────────────────────────────────────────────
@router.get("/agents")
async def list_chat_agents(session: AsyncSession = Depends(get_session)):
    """返回可用的对话 Agent 角色与模型选项。"""
    await refresh_cache(session)
    models = _available_model_options()
    return {
        "agents": [
            {"key": a["key"], "name": a["name"], "description": a["description"]}
            for a in CHAT_AGENTS
        ],
        "models": models,
        "llm_ready": bool(resolve_llm_providers(None)),
    }


@router.get("/mentions")
async def search_chat_mentions(
    kind: str = Query("", description="finding / task / target / intel / 留空全量"),
    q: str = Query("", description="搜索关键字"),
    limit: int = Query(15, ge=1, le=30),
    session: AsyncSession = Depends(get_session),
):
    """支持在对话框中输入 @ 实时检索平台漏洞、任务、目标与情报。"""
    needle = (q or "").strip()
    like = f"%{needle}%"
    items: list[dict[str, str]] = []
    kinds = [kind] if kind in {"finding", "task", "target", "intel"} else ["finding", "task", "target", "intel"]
    per_kind = limit if len(kinds) == 1 else max(4, limit // len(kinds) + 1)

    if "finding" in kinds:
        stmt = select(Finding).where(Finding.status != "superseded")
        if needle:
            stmt = stmt.where(or_(Finding.title.ilike(like), Finding.vuln_type.ilike(like), Finding.target_url.ilike(like)))
        rows = (await session.execute(stmt.order_by(desc(Finding.created_at)).limit(per_kind))).scalars().all()
        for f in rows:
            items.append({
                "kind": "finding",
                "id": f.id,
                "label": f.title[:80],
                "description": f"{f.vuln_type} · {f.target_url}",
            })

    if "task" in kinds:
        stmt = select(Task)
        if needle:
            stmt = stmt.where(or_(Task.name.ilike(like), Task.fofa_query.ilike(like)))
        rows = (await session.execute(stmt.order_by(desc(Task.updated_at)).limit(per_kind))).scalars().all()
        for t in rows:
            items.append({
                "kind": "task",
                "id": t.id,
                "label": t.name[:80],
                "description": f"{t.status} · {t.engine or 'fofa'} · {t.fofa_query[:60]}",
            })

    if "target" in kinds:
        stmt = select(Target)
        if needle:
            stmt = stmt.where(or_(Target.host.ilike(like), Target.url.ilike(like), Target.title.ilike(like), Target.school.ilike(like)))
        rows = (await session.execute(stmt.order_by(desc(Target.priority_score)).limit(per_kind))).scalars().all()
        for tg in rows:
            items.append({
                "kind": "target",
                "id": tg.id,
                "label": (tg.host or tg.url)[:80],
                "description": f"{tg.school or tg.title or tg.url} ({tg.status})",
            })

    if "intel" in kinds:
        stmt = select(Intel)
        if needle:
            stmt = stmt.where(or_(Intel.match_key.ilike(like), Intel.summary.ilike(like)))
        rows = (await session.execute(stmt.order_by(desc(Intel.hit_count)).limit(per_kind))).scalars().all()
        for it in rows:
            items.append({
                "kind": "intel",
                "id": it.id,
                "label": (it.summary or it.match_key)[:80],
                "description": f"{it.kind} · {it.match_key} · 命中 {it.hit_count}",
            })

    return {"items": items[:limit]}


@router.get("/conversations")
async def list_conversations(session: AsyncSession = Depends(get_session)):
    """列出全部对话会话（置顶优先，其后按最近活跃时间倒序）。"""
    rows = (
        await session.execute(
            select(ChatConversation).order_by(
                desc(ChatConversation.pinned),
                desc(ChatConversation.pinned_at),
                desc(ChatConversation.updated_at),
            )
        )
    ).scalars().all()
    if not rows:
        return {"conversations": []}

    conv_ids = [c.id for c in rows]
    stats_rows = (
        await session.execute(
            select(
                ChatActivity.conversation_id,
                func.count(ChatActivity.id),
                func.coalesce(func.sum(ChatActivity.input_tokens), 0),
                func.coalesce(func.sum(ChatActivity.output_tokens), 0),
            )
            .where(ChatActivity.conversation_id.in_(conv_ids))
            .group_by(ChatActivity.conversation_id)
        )
    ).all()
    stats_map = {
        cid: (int(cnt or 0), int(inp or 0), int(outp or 0))
        for cid, cnt, inp, outp in stats_rows
    }

    items = []
    for c in rows:
        cnt, inp, outp = stats_map.get(c.id, (0, 0, 0))
        items.append(
            _conv_dto(
                c,
                running=_is_busy(c.id),
                message_count=cnt,
                input_tokens=inp,
                output_tokens=outp,
            )
        )
    return {"conversations": items}


@router.post("/conversations")
async def create_conversation(
    req: ConversationCreateRequest,
    session: AsyncSession = Depends(get_session),
):
    agent_key = (req.agent_key or "assistant").strip()
    if agent_key not in _CHAT_AGENTS_MAP:
        raise HTTPException(status_code=400, detail=f"未知对话角色：{agent_key}")
    title = (req.title or "").strip() or "新对话"
    if len(title) > _MAX_TITLE_LEN:
        raise HTTPException(status_code=400, detail=f"标题最多 {_MAX_TITLE_LEN} 个字符")
    conv = ChatConversation(
        agent_key=agent_key,
        title=title,
        model_override=(req.model_override or "").strip()[:200],
    )
    session.add(conv)
    await session.commit()
    await session.refresh(conv)
    return _conv_dto(conv, running=False)


@router.patch("/conversations/{conv_id}")
async def update_conversation(
    conv_id: str,
    req: ConversationPatchRequest,
    session: AsyncSession = Depends(get_session),
):
    conv = await session.get(ChatConversation, conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")
    if req.title is None and req.pinned is None and req.model_override is None:
        raise HTTPException(status_code=400, detail="请至少提供一项待更新字段")
    if req.title is not None:
        title = req.title.strip()
        if not title:
            raise HTTPException(status_code=400, detail="标题不能为空")
        if len(title) > _MAX_TITLE_LEN:
            raise HTTPException(status_code=400, detail=f"标题最多 {_MAX_TITLE_LEN} 个字符")
        conv.title = title
    if req.pinned is not None:
        conv.pinned = bool(req.pinned)
        conv.pinned_at = datetime.now(timezone.utc) if conv.pinned else None
    if req.model_override is not None:
        conv.model_override = req.model_override.strip()[:200]
    conv.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(conv)
    return _conv_dto(conv, running=_is_busy(conv.id))


@router.delete("/conversations/{conv_id}")
async def delete_conversation(
    conv_id: str,
    session: AsyncSession = Depends(get_session),
):
    conv = await session.get(ChatConversation, conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")
    _cancel_conversation(conv_id)
    await session.delete(conv)
    await session.commit()
    shutil.rmtree(_conv_upload_dir(conv_id), ignore_errors=True)
    return {"ok": True, "deleted": conv_id}


@router.post("/conversations/batch-delete")
async def batch_delete_conversations(
    req: BatchDeleteRequest,
    session: AsyncSession = Depends(get_session),
):
    unique_ids: list[str] = []
    seen: set[str] = set()
    for cid in req.ids:
        clean = str(cid or "").strip()
        if clean and clean not in seen:
            seen.add(clean)
            unique_ids.append(clean)
    if not unique_ids or len(unique_ids) > _MAX_BATCH_DELETE:
        raise HTTPException(status_code=400, detail=f"ids 数量必须为 1-{_MAX_BATCH_DELETE}")

    existing_ids = set(
        (
            await session.execute(
                select(ChatConversation.id).where(ChatConversation.id.in_(unique_ids))
            )
        ).scalars().all()
    )
    for cid in existing_ids:
        _cancel_conversation(cid)

    if existing_ids:
        await session.execute(
            delete(ChatActivity).where(ChatActivity.conversation_id.in_(existing_ids))
        )
        await session.execute(
            delete(ChatConversation).where(ChatConversation.id.in_(existing_ids))
        )
        await session.commit()
        for cid in existing_ids:
            shutil.rmtree(_conv_upload_dir(cid), ignore_errors=True)

    return {
        "items": [
            {"id": cid, "ok": cid in existing_ids, "error": "" if cid in existing_ids else "对话不存在"}
            for cid in unique_ids
        ]
    }


@router.get("/conversations/{conv_id}/messages")
async def list_conversation_messages(
    conv_id: str,
    since: int | None = Query(None, ge=0),
    before: int | None = Query(None, ge=1),
    limit: int = Query(200, ge=1, le=500),
    session: AsyncSession = Depends(get_session),
):
    """支持增量拉取（?since=cursor）与向上翻页（?before=id）。"""
    conv = await session.get(ChatConversation, conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")

    tok_row = (
        await session.execute(
            select(
                func.coalesce(func.sum(ChatActivity.input_tokens), 0),
                func.coalesce(func.sum(ChatActivity.output_tokens), 0),
            ).where(ChatActivity.conversation_id == conv_id)
        )
    ).one()
    token_usage = {"input_tokens": int(tok_row[0] or 0), "output_tokens": int(tok_row[1] or 0)}
    running = _is_busy(conv_id)

    if since is not None:
        rows = (
            await session.execute(
                select(ChatActivity)
                .where(and_(ChatActivity.conversation_id == conv_id, ChatActivity.id > since))
                .order_by(ChatActivity.id.asc())
                .limit(max(limit, 500))
            )
        ).scalars().all()
        cursor = rows[-1].id if rows else since
        return {
            "items": [_activity_dto(a, include_detail=False) for a in rows],
            "cursor": cursor,
            "running": running,
            "has_more": False,
            "token_usage": token_usage,
        }

    stmt = select(ChatActivity).where(ChatActivity.conversation_id == conv_id)
    if before is not None:
        stmt = stmt.where(ChatActivity.id < before)
    rows = (await session.execute(stmt.order_by(ChatActivity.id.desc()).limit(limit + 1))).scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    rows.reverse()
    cursor = rows[-1].id if rows else (before or 0)
    return {
        "items": [_activity_dto(a, include_detail=False) for a in rows],
        "cursor": cursor,
        "running": running,
        "has_more": has_more,
        "token_usage": token_usage,
    }


@router.get("/conversations/{conv_id}/messages/{seq}/detail")
async def get_message_detail(
    conv_id: str,
    seq: int,
    session: AsyncSession = Depends(get_session),
):
    act = (
        await session.execute(
            select(ChatActivity).where(
                and_(ChatActivity.conversation_id == conv_id, ChatActivity.id == seq)
            )
        )
    ).scalar_one_or_none()
    if not act:
        raise HTTPException(status_code=404, detail="消息步骤不存在")
    return {"detail": act.detail or ""}


@router.post("/conversations/{conv_id}/uploads")
async def upload_chat_file(
    conv_id: str,
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
):
    conv = await session.get(ChatConversation, conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")
    raw = await file.read(_MAX_UPLOAD_BYTES + 1)
    if len(raw) > _MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="单个附件大小不能超过 10MB")

    safe_name = _sanitize_filename(file.filename or "upload.txt")
    stored_name = f"{uuid.uuid4().hex[:8]}_{safe_name}"
    target_dir = _conv_upload_dir(conv_id)
    target_dir.mkdir(parents=True, exist_ok=True)
    target_path = target_dir / stored_name
    target_path.write_bytes(raw)
    return {
        "name": safe_name,
        "path": stored_name,
        "size": len(raw),
        "content_type": file.content_type or "application/octet-stream",
    }


@router.post("/conversations/{conv_id}/messages")
async def send_conversation_message(
    conv_id: str,
    req: SendMessageRequest,
    session: AsyncSession = Depends(get_session),
):
    await refresh_cache(session)
    conv = await session.get(ChatConversation, conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")

    msg_text = (req.message or "").strip()
    attachments = [a.model_dump() for a in (req.attachments or [])]
    if not msg_text and not attachments:
        raise HTTPException(status_code=400, detail="消息内容不能为空")

    if not resolve_llm_providers(None):
        raise HTTPException(
            status_code=503,
            detail="尚未配置大模型 API Key，请先在「模型与多角色路由」或「系统设置」中配置后再发起对话",
        )

    with _CHAT_STATE_LOCK:
        if conv_id in _CHAT_BUSY:
            raise HTTPException(status_code=409, detail="当前对话正在生成中，请等待完成或先点击停止")
        _CHAT_BUSY.add(conv_id)
        cancel_event = threading.Event()
        _CHAT_CANCEL_EVENTS[conv_id] = cancel_event

    try:
        mentions_ctx, resolved_mentions = await _resolve_mentions_context(session, msg_text)

        # 自动使用首条消息更新默认标题
        if conv.title == "新对话":
            auto_title = re.sub(r"\s+", " ", msg_text).strip() or (attachments[0]["name"] if attachments else "新对话")
            conv.title = auto_title[:42]

        user_activity = ChatActivity(
            conversation_id=conv_id,
            kind="user",
            text=msg_text or f"（上传了 {len(attachments)} 个附件）",
            attachments=attachments,
            meta={"mentions": resolved_mentions} if resolved_mentions else {},
        )
        session.add(user_activity)
        conv.updated_at = datetime.now(timezone.utc)
        await session.commit()
        await session.refresh(user_activity)

        history_messages = await _load_conversation_history_messages(session, conv)
        # 为最后一条 user 消息追加 @引用实体与附件可读提示（不污染落盘的用户原文）
        extra_blocks: list[str] = []
        if mentions_ctx:
            extra_blocks.append(mentions_ctx)
        if attachments:
            att_lines = ["【本轮上传附件】"]
            for a in attachments:
                att_lines.append(f"- {a['name']} (stored: {a['path']}, {a.get('size', 0)} bytes)")
                # 小文本文件直接内联前 4000 字，避免多余工具往返
                if int(a.get("size") or 0) <= 64 * 1024:
                    preview_txt = _safe_read_attachment(conv_id, a["path"], max_chars=4000)
                    att_lines.append(f"```text\n{preview_txt}\n```")
            extra_blocks.append("\n".join(att_lines))

        if extra_blocks and history_messages and history_messages[-1]["role"] == "user":
            history_messages[-1]["content"] = (
                history_messages[-1]["content"] + "\n\n" + "\n\n".join(extra_blocks)
            )

        bg_task = asyncio.create_task(
            _run_conversation_turn(conv_id, history_messages, conv.model_override or "", cancel_event)
        )
        with _CHAT_STATE_LOCK:
            _CHAT_TASKS[conv_id] = bg_task

        return {
            "ok": True,
            "running": True,
            "user_activity": _activity_dto(user_activity),
            "conversation": _conv_dto(conv, running=True),
        }
    except Exception:
        with _CHAT_STATE_LOCK:
            _CHAT_BUSY.discard(conv_id)
            _CHAT_CANCEL_EVENTS.pop(conv_id, None)
        raise


@router.post("/conversations/{conv_id}/stop")
async def stop_conversation(
    conv_id: str,
    session: AsyncSession = Depends(get_session),
):
    conv = await session.get(ChatConversation, conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")
    stopped = _cancel_conversation(conv_id)
    return {"ok": True, "status": "stopping" if stopped else "idle"}


@router.post("/conversations/{conv_id}/side-question")
async def ask_side_question(
    conv_id: str,
    req: SideQuestionRequest,
    session: AsyncSession = Depends(get_session),
):
    """旁路提问（/btw）：读取当前会话最近上下文并单轮快答，不打断主对话、不污染主记录。"""
    await refresh_cache(session)
    conv = await session.get(ChatConversation, conv_id)
    if not conv:
        raise HTTPException(status_code=404, detail="对话不存在")
    question = (req.question or "").strip()
    if not question:
        raise HTTPException(status_code=400, detail="旁路提问内容不能为空")

    usage_key = f"sideq-{conv_id}-{uuid.uuid4().hex[:8]}"
    llm = _build_chat_llm_client(model_override=conv.model_override or "", usage_key=usage_key)
    if llm is None:
        raise HTTPException(status_code=503, detail="尚未配置大模型 API Key")

    recent = (
        await session.execute(
            select(ChatActivity)
            .where(
                ChatActivity.conversation_id == conv_id,
                ChatActivity.kind.in_(("user", "assistant")),
            )
            .order_by(desc(ChatActivity.id))
            .limit(10)
        )
    ).scalars().all()
    recent.reverse()

    ctx_lines = [
        f"{'用户' if r.kind == 'user' else '助手'}：{(r.text or '')[:800]}"
        for r in recent
        if (r.text or "").strip()
    ]
    system_prompt = (
        "你是知蠹 Riddle 旁路快答助手（/btw 模式）。"
        "请结合下方主对话摘要直接、简明地回答用户的旁路问题。"
        "注意：旁路提问不能调用任何工具，也不会写入主会话历史。"
    )
    user_content = question
    if ctx_lines:
        user_content = "【当前主对话最近上下文】\n" + "\n\n".join(ctx_lines) + "\n\n【旁路问题】\n" + question

    started = time.perf_counter()
    try:
        msg = await asyncio.to_thread(
            llm.chat,
            [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            None,
            None,
            0.3,
        )
        answer = str(getattr(msg, "content", "") or "").strip() or "（模型未返回回答）"
        snap = usage_snapshot(usage_key)
        return {
            "ok": True,
            "answer": answer,
            "model": str(snap.get("model") or conv.model_override or ""),
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "input_tokens": int(snap.get("prompt_tokens") or 0),
            "output_tokens": int(snap.get("completion_tokens") or 0),
        }
    except (LLMError, RuntimeError) as exc:
        raise HTTPException(status_code=502, detail=f"旁路提问失败：{exc}") from exc
    finally:
        clear_usage(usage_key)
