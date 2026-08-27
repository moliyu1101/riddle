"""全局系统配置 API。"""
from __future__ import annotations

import asyncio
import functools
import re
import time

import httpx
from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dto import SettingsUpdateRequest
from app.config import LLMConfig
from app.db.models import Task
from app.db.session import get_session
from app.engines.base import get_engine
from app.llm.client import _is_kimi_coding_endpoint, _resolve_user_agent, llm_request_url
from app.llm.presets import (
    LLM_PROVIDER_PRESETS,
    pool_schedule_preview,
    recommend_temperature,
)
from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url
from app.workdir_cleanup import cleanup_workdir, get_workdir_stats
from app.ui_prefs import (
    MAX_WALLPAPER_BYTES,
    current_wallpaper,
    delete_wallpaper,
    save_wallpaper_bytes,
)
from app.settings_service import (
    _clean_llm_providers,
    _llm_identity,
    _preserve_provider_keys,
    effective_settings,
    export_settings,
    is_masked_secret,
    list_available_models,
    normalize_llm_mode,
    normalize_llm_protocol,
    public_settings_view,
    refresh_cache,
    resolve_engine_base_url,
    resolve_engine_key,
    resolve_llm_config,
    resolve_llm_key_for_identity,
    resolve_llm_key_ref,
    resolve_llm_providers,
    secret_ref,
    update_settings,
)

router = APIRouter(prefix="/api/settings", tags=["settings"])


@router.get("")
async def get_settings(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    return public_settings_view()


class ModelsProbeRequest(BaseModel):
    base_url: str | None = None
    api_key: str | None = None
    protocol: str | None = None
    key_ref: str | None = None
    model: str | None = None


@router.post("/models")
async def probe_models(
    body: ModelsProbeRequest,
    session: AsyncSession = Depends(get_session),
):
    """拉取模型商可用模型列表，供前端下拉选择。base_url/api_key 留空用有效配置。
    注意：api_key 为脱敏占位（如 ••••••••）时视为未传，回退到服务端已存的真实 key。"""
    await refresh_cache(session)
    key = (body.api_key or "").strip()
    if key and is_masked_secret(key):
        key = ""  # 前端回显的脱敏占位，丢弃
    return await list_available_models(
        base_url=body.base_url,
        api_key=key or None,
        protocol=body.protocol,
        key_ref=body.key_ref,
        model=body.model,
    )


@router.get("/llm-presets")
async def llm_provider_presets():
    """模型商预设列表，供连接向导一键填充 base_url/协议/推荐模型。"""
    return {"presets": LLM_PROVIDER_PRESETS}


class TemperatureRecommendRequest(BaseModel):
    model: str = ""
    role: str = "hunt"


@router.post("/temperature-recommend")
async def temperature_recommend_endpoint(body: TemperatureRecommendRequest):
    """按模型类型 + 任务角色推荐 temperature，供前端一键应用。"""
    return recommend_temperature(body.model, body.role)


class PoolSchedulePreviewRequest(BaseModel):
    providers: list[dict] = []


@router.post("/pool-schedule-preview")
async def pool_schedule_preview_endpoint(body: PoolSchedulePreviewRequest):
    """端点池调度预览：按权重计算命中分布 + 调度策略说明。"""
    return pool_schedule_preview(body.providers)


class ProviderHealthCheckRequest(BaseModel):
    providers: list[dict] = []


@router.post("/provider-health-check")
async def provider_health_check(body: ProviderHealthCheckRequest):
    """按端点配置实时查询运行时健康状态（无历史记录返回 unknown，不落库不探测）。"""
    from app.llm.health import provider_ref, snapshot

    snap = snapshot()
    out = []
    for p in body.providers or []:
        ref = provider_ref(
            str(p.get("base_url") or ""),
            str(p.get("model") or ""),
            str(p.get("api_key") or ""),
            str(p.get("protocol") or "auto"),
        )
        health = snap.get(ref) or {}
        out.append({
            "name": str(p.get("name") or "").strip() or "未命名",
            "health_ref": ref,
            "health": {
                "status": health.get("status", "unknown"),
                "last_seen": health.get("last_seen", ""),
                "consecutive_failures": health.get("consecutive_failures", 0),
                "cooldown_until": health.get("cooldown_until", ""),
                "last_error": health.get("last_error", ""),
            },
        })
    return {"providers": out}


@router.get("/provider-health")
async def get_provider_health(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    llm = public_settings_view()["llm"]
    return {
        "mode": llm.get("mode", "single"),
        "single": {
            "health_ref": llm.get("health_ref", ""),
            "health": llm.get("health", {}),
        },
        "providers": [
            {
                "name": item.get("name", ""),
                "base_url": item.get("base_url", ""),
                "model": item.get("model", ""),
                "protocol": item.get("protocol", "auto"),
                "health_ref": item.get("health_ref", ""),
                "health": item.get("health", {}),
            }
            for item in llm.get("providers", [])
        ],
    }


@router.get("/health-overview")
async def health_overview(session: AsyncSession = Depends(get_session)):
    """全局健康总览：LLM / 测绘引擎 / 磁盘，供设置侧栏与概览展示。"""
    await refresh_cache(session)
    view = public_settings_view()
    llm = view["llm"]
    providers = llm.get("providers", [])
    enabled = [p for p in providers if p.get("enabled", True)]
    degraded = any(
        (p.get("health") or {}).get("status") in ("failed", "cooldown")
        for p in enabled
    )
    engines_view = view["engines"] or {}
    engine_items = []
    for meta in view.get("available_engines", []):
        name = meta["name"]
        cfg = engines_view.get(name, {})
        engine_items.append({
            "name": name,
            "display_name": meta.get("display_name", name),
            "key_set": bool(cfg.get("key_set")),
        })
    loop = asyncio.get_running_loop()
    disk = await loop.run_in_executor(None, get_workdir_stats)
    return {
        "updated_at": view.get("updated_at"),
        "llm": {
            "mode": llm.get("mode", "single"),
            "provider_count": len(providers),
            "enabled_count": len(enabled),
            "healthy": len(enabled) > 0 and not degraded,
            "degraded": degraded,
        },
        "engines": {
            "total": len(engine_items),
            "configured": sum(1 for item in engine_items if item["key_set"]),
            "default": view.get("defaults", {}).get("engine", "fofa"),
            "items": engine_items,
        },
        "disk": {
            "work_size_human": disk.get("total_size_human", "0 B"),
            "work_dirs": disk.get("total_dirs", 0),
            "auto_cleanup": bool(disk.get("auto_cleanup_enabled")),
        },
    }


class LLMTestRequest(BaseModel):
    base_url: str | None = None
    api_key: str | None = None
    key_ref: str | None = None
    model: str | None = None
    protocol: str | None = None
    temperature: float | None = None
    providers: list[dict] | None = None
    task_id: str | None = None  # 编辑任务时传入，解析任务级 API Key


_TEST_SECRET_RE = re.compile(
    r"(?:\bsk-[A-Za-z0-9_-]{8,}\b|\bBearer\s+[A-Za-z0-9._~+/=-]{8,})",
    re.IGNORECASE,
)


_NAMED_SECRET_RE = re.compile(
    r"((?:api[_-]?key|x-api-key|token|secret|password|passwd|pwd)"
    r"\s*[\"']?\s*[:=]\s*[\"']?)[^\s,;\"']+",
    re.IGNORECASE,
)


def _safe_error(value: object, *secrets: str, limit: int = 500) -> str:
    text = " ".join(str(value or "").split())
    for secret in secrets:
        if secret:
            text = text.replace(str(secret), "<masked>")
    text = _NAMED_SECRET_RE.sub(r"\1<masked>", text)
    return _TEST_SECRET_RE.sub("<masked>", text)[:limit]


def _llm_test_error_copy(result: dict) -> str:
    lines = [
        f"ok={result.get('ok')}",
        f"name={result.get('name') or '-'}",
        f"model={result.get('model') or '-'}",
        f"base_url={result.get('base_url') or '-'}",
        f"protocol={result.get('protocol') or '-'}",
        f"status_code={result.get('status_code') or 0}",
        f"latency_ms={result.get('latency_ms') or 0}",
        f"tool_calling={result.get('tool_calling') or '-'}",
    ]
    if result.get("error"):
        lines.append(f"error={result['error']}")
    if result.get("reply"):
        lines.append(f"reply={result['reply']}")
    return "\n".join(lines)


_MODEL_NOT_FOUND_HINTS = (
    "model_not_found",
    "model not found",
    "no available channel",
    "model does not exist",
    "model not exist",
    "no such model",
    "unknown model",
    "模型不存在",
    "找不到模型",
    "无可用模型",
)


def _is_model_not_found(text: str) -> bool:
    """判断测试连接错误是否为「模型不存在/无可用渠道」，用于触发可用模型自动探测。"""
    lowered = (text or "").lower()
    return any(h in lowered for h in _MODEL_NOT_FOUND_HINTS)


def _test_configs(body: LLMTestRequest) -> list[tuple[str, LLMConfig]]:
    eff = effective_settings()["llm"]
    old_providers = _clean_llm_providers(eff.get("providers") or [])
    if body.providers is not None:
        items = _clean_llm_providers(_preserve_provider_keys(body.providers, old_providers))
        return [
            (
                str(item.get("name") or f"llm-{index + 1}"),
                LLMConfig(
                    base_url=item["base_url"],
                    api_key=item["api_key"],
                    model=item["model"],
                    protocol=item["protocol"],
                    temperature=float(item["temperature"]),
                    weight=int(item["weight"]),
                    enabled=bool(item["enabled"]),
                ),
            )
            for index, item in enumerate(items)
            if item.get("enabled", True)
        ]

    explicit_single = any((body.base_url, body.api_key, body.key_ref, body.model, body.protocol))
    if explicit_single:
        base_url = body.base_url or eff.get("base_url") or ""
        model = body.model or eff.get("model") or ""
        protocol = normalize_llm_protocol(body.protocol or eff.get("protocol"))
        api_key = str(body.api_key or "").strip()
        if not api_key or is_masked_secret(api_key):
            api_key = resolve_llm_key_ref(
                body.key_ref, base_url, model, protocol
            ) or resolve_llm_key_for_identity(base_url, model, protocol)
        return [("single", LLMConfig(
            base_url=base_url,
            api_key=api_key,
            model=model,
            protocol=protocol,
            temperature=float(body.temperature if body.temperature is not None else eff.get("temperature") or 0.3),
        ))]

    return [
        (f"llm-{index + 1}", config)
        for index, config in enumerate(resolve_llm_providers())
    ]


async def _probe_tool_calling(url: str, headers: dict, model: str, protocol: str) -> str:
    """探测模型是否支持 function/tool calling，返回 'yes' / 'no' / 'unknown'。

    仅由「测试连接」按钮触发，绝不进入挖洞主循环，不影响 worker/collector 的行为与预算。
    保守判定：真返回 tool_call 才判 'yes'；错误信息明确提到 tool/function 才判 'no'；
    其它一律 'unknown'（不下死结论，避免把正常模型误判成不支持）。
    """
    import httpx

    if protocol == "anthropic_messages":
        payload = {
            "model": model,
            "max_tokens": 64,
            "messages": [{"role": "user", "content": "Call the report_ready tool with status=ok."}],
            "tools": [{
                "name": "report_ready",
                "description": "Report readiness. You must call this tool.",
                "input_schema": {"type": "object", "properties": {"status": {"type": "string"}}, "required": ["status"]},
            }],
        }
    else:
        payload = {
            "model": model,
            # Kimi Code 端点（k3 思考模型）只接受 temperature=1
            "temperature": 1 if _is_kimi_coding_endpoint(url) else 0,
            "max_tokens": 64,
            "messages": [
                {"role": "system", "content": "You must use the provided tool to answer."},
                {"role": "user", "content": "Call the report_ready tool with status=ok."},
            ],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "report_ready",
                    "description": "Report readiness. You must call this function.",
                    "parameters": {"type": "object", "properties": {"status": {"type": "string"}}, "required": ["status"]},
                },
            }],
            "tool_choice": "auto",
        }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(url, headers=headers, json=payload)
            if resp.status_code == 400 and "max_tokens" in resp.text.lower():
                payload.pop("max_tokens", None)
                resp = await client.post(url, headers=headers, json=payload)
        if resp.status_code >= 400:
            low = resp.text.lower()
            if any(k in low for k in ("tool", "function")):
                return "no"
            return "unknown"
        data = resp.json()
        if protocol == "anthropic_messages":
            has = any(
                isinstance(b, dict) and b.get("type") == "tool_use"
                for b in (data.get("content") or [])
            )
        else:
            msg = ((data.get("choices") or [{}])[0].get("message") or {})
            has = bool(msg.get("tool_calls"))
        return "yes" if has else "unknown"
    except Exception:
        return "unknown"


async def _test_llm_one(name: str, provider: LLMConfig) -> dict:
    import httpx

    protocol = normalize_llm_protocol(provider.protocol)
    if protocol == "auto":
        lowered = provider.base_url.lower()
        protocol = "anthropic_messages" if "anthropic" in lowered or "/messages" in lowered else "openai_chat"
    url = llm_request_url(provider.base_url, protocol)
    result = {
        "name": name,
        "ok": False,
        "base_url": provider.base_url,
        "model": provider.model,
        "protocol": protocol,
        "status_code": 0,
        "latency_ms": 0,
        "error": "",
        # tool-calling 能力：unknown/yes/no。知蠹 Riddle 全流程依赖 function calling，
        # 这里在连通性 OK 后额外探一次，让配置期就能发现「模型不支持工具调用」。
        "tool_calling": "unknown",
    }
    if not provider.api_key:
        result["error"] = "未配置 API Key"
        result["error_copy"] = _llm_test_error_copy(result)
        return result
    try:
        assert_safe_outbound_url(url)
    except SsrfBlocked as exc:
        result["error"] = f"base_url 不被允许：{exc}"
        result["error_copy"] = _llm_test_error_copy(result)
        return result

    headers = {
        "Authorization": f"Bearer {provider.api_key}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": _resolve_user_agent(provider.model, provider.base_url),
    }
    payload = {
        "model": provider.model,
        "messages": [{"role": "user", "content": "Reply with exactly: ok"}],
        # Kimi Code 端点（k3 思考模型）只接受 temperature=1
        "temperature": 1 if _is_kimi_coding_endpoint(provider.base_url) else 0,
        "max_tokens": 8,
    }
    if protocol == "anthropic_messages":
        headers.update({
            "x-api-key": provider.api_key,
            "anthropic-version": "2023-06-01",
        })

    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(url, headers=headers, json=payload)
            if response.status_code == 400 and "max_tokens" in response.text.lower():
                payload.pop("max_tokens", None)
                response = await client.post(url, headers=headers, json=payload)
        result["latency_ms"] = int((time.perf_counter() - started) * 1000)
        result["status_code"] = response.status_code
        if response.status_code >= 400:
            raw = _safe_error(
                f"HTTP {response.status_code}: {response.text[:2000]}",
                provider.api_key,
                limit=2000,
            )
            result["error"] = raw[:500]
            result["error_copy"] = _llm_test_error_copy({**result, "error": raw})
            # 模型不存在/无可用渠道时，自动拉取网关可用模型列表，前端据此提示或一键回填。
            if _is_model_not_found(raw):
                probe = await list_available_models(
                    base_url=provider.base_url,
                    api_key=provider.api_key,
                    protocol=provider.protocol,
                    model=provider.model,
                )
                if probe.get("ok") and probe.get("models"):
                    result["available_models"] = probe["models"]
            # 连接测试是管理员手动探测，只返回结果、不写生产熔断器（避免污染在跑 worker 的端点健康）。
            return result
        data = response.json()
        if protocol == "anthropic_messages":
            reply = "".join(
                str(block.get("text") or "")
                for block in data.get("content") or []
                if isinstance(block, dict) and block.get("type") == "text"
            )
        else:
            choice = (data.get("choices") or [{}])[0]
            reply = str((choice.get("message") or {}).get("content") or choice.get("text") or "")
        result.update(ok=True, reply=reply[:80])
        # 连通性 OK 后再探一次工具调用能力（额外一次小请求，仅测试按钮触发，不碰挖洞）。
        result["tool_calling"] = await _probe_tool_calling(url, headers, provider.model, protocol)
        result["error_copy"] = _llm_test_error_copy(result)
        # 测试成功不清生产熔断器（否则会抹掉真实 cooldown，让 worker 立即冲击刚被限流的端点）。
        return result
    except Exception as exc:
        result["latency_ms"] = int((time.perf_counter() - started) * 1000)
        raw = _safe_error(exc, provider.api_key, limit=2000)
        result["error"] = raw[:500]
        result["error_copy"] = _llm_test_error_copy({**result, "error": raw})
        # 同上：手动测试失败不累加生产熔断计数。
        return result


@router.post("/test-llm")
async def test_llm(body: LLMTestRequest, session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    if body.task_id:
        # 编辑任务时测试连接：解析任务级 API Key（任务自带 key 不在全局密钥池里）
        task = await session.get(Task, body.task_id)
        if task is None:
            raise HTTPException(status_code=404, detail="任务不存在")
        config = resolve_llm_config(task)
        base_url = str(body.base_url or config.base_url or "").strip()
        protocol = normalize_llm_protocol(body.protocol or config.protocol)
        api_key = str(body.api_key or "").strip()
        if is_masked_secret(api_key):
            api_key = ""
        key_ref = str(body.key_ref or "").strip()
        if not api_key:
            want = _llm_identity(base_url, protocol)
            raw_cfg = dict(task.model_config_json or {})
            task_providers = _clean_llm_providers(
                raw_cfg.get("providers") or raw_cfg.get("providers_json") or []
            )
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
        body.base_url = base_url
        body.protocol = protocol
        body.api_key = api_key
        body.key_ref = ""
    providers = _test_configs(body)
    if not providers:
        return {"ok": False, "results": [], "error": "未配置可用 LLM 端点", "error_copy": "ok=false\nerror=未配置可用 LLM 端点"}
    results = [await _test_llm_one(name, provider) for name, provider in providers]
    copy_parts = [item.get("error_copy") or _llm_test_error_copy(item) for item in results]
    return {
        "ok": all(item["ok"] for item in results),
        "results": results,
        "error_copy": "\n\n".join(copy_parts),
    }


class EngineTestRequest(BaseModel):
    engine: str
    key: str | None = None
    base_url: str | None = None


# 认证/账号类错误关键词（跨引擎通用），用于把连接测试结果归类为 auth
_ENGINE_AUTH_MARKERS = (
    "key", "token", "认证", "鉴权", "账号", "密码", "权限", "credential",
    "unauthorized", "forbidden", "invalid", "expired", "quota", "配额",
    "401", "403", "auth", "login", "sign in",
)


def _engine_error_type(err: Exception) -> str:
    text = str(err or "").lower()
    if any(m in text for m in _ENGINE_AUTH_MARKERS):
        return "auth"
    if isinstance(err, httpx.HTTPError) or "timeout" in text or "connect" in text or "连接" in text:
        return "network"
    return "other"


@router.post("/test-engine")
async def test_engine(body: EngineTestRequest, session: AsyncSession = Depends(get_session)):
    """测试测绘引擎连接与认证。key/base_url 留空用已保存配置。"""
    await refresh_cache(session)
    engine = get_engine(body.engine)
    if engine is None:
        raise HTTPException(status_code=404, detail=f"未知引擎: {body.engine}")
    key = (body.key or "").strip()
    if key and is_masked_secret(key):
        key = ""
    if not key:
        key = resolve_engine_key(body.engine)
    if not key:
        return {"ok": False, "engine": body.engine, "error": "未配置 API Key", "error_type": "auth"}
    base_url = (body.base_url or "").strip() or resolve_engine_base_url(body.engine)
    result = {"ok": False, "engine": body.engine, "latency_ms": 0, "size": 0, "error": "", "error_type": "other"}
    try:
        ok = await engine.test_connection(key, base_url=base_url)
        result.update(ok)
    except Exception as exc:
        raw = str(exc)[:400]
        result["error"] = raw
        result["error_type"] = _engine_error_type(exc)
    return result


@router.put("")
async def put_settings(
    body: SettingsUpdateRequest,
    session: AsyncSession = Depends(get_session),
):
    payload = body.model_dump(exclude_unset=True)
    llm_update = payload.get("llm") or {}
    if llm_update:
        current_llm = effective_settings()["llm"]
        mode = normalize_llm_mode(llm_update.get("mode", current_llm.get("mode")))
        if mode == "pool":
            old_providers = _clean_llm_providers(current_llm.get("providers") or [])
            incoming = llm_update.get("providers", current_llm.get("providers") or [])
            providers = _clean_llm_providers(
                _preserve_provider_keys(incoming, old_providers)
            )
            if not any(item.get("enabled", True) for item in providers):
                raise HTTPException(
                    status_code=400,
                    detail="端点池模式至少需要一个配置完整且已启用的 LLM 端点",
                )
    return await update_settings(session, payload)


@router.get("/export")
async def export_settings_api(session: AsyncSession = Depends(get_session)):
    """导出完整配置（含密钥明文），供备份/迁移。仅管理员主动调用。"""
    await refresh_cache(session)
    return export_settings()


class SettingsImportRequest(BaseModel):
    llm: dict | None = None
    fofa: dict | None = None
    engines: dict | None = None
    defaults: dict | None = None
    ui: dict | None = None
    auth: dict | None = None


@router.post("/import")
async def import_settings_api(
    body: SettingsImportRequest,
    session: AsyncSession = Depends(get_session),
):
    """从导出的 JSON 导入配置。密钥留空不覆盖现有值。"""
    payload = body.model_dump(exclude_unset=True)
    if not payload:
        raise HTTPException(status_code=400, detail="导入内容为空")
    return await update_settings(session, payload)


# ===== 工作目录管理 =====


@router.get("/workdir/stats")
async def workdir_stats():
    """获取工作目录磁盘占用统计。"""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, get_workdir_stats)


@router.post("/workdir/cleanup")
async def workdir_cleanup(
    retention_days: int | None = Query(default=None, ge=0, le=365, description="保留天数，留空用配置默认值，0=不清理"),
    dry_run: bool = Query(default=True, description="默认只模拟；要真删必须 dry_run=false"),
):
    """手动触发工作目录清理。

    按目录内文件活动时间判断：超过 retention_days 天且最近 30 分钟无写入才删。
    受保护目录（node_modules/browser_profile 等）和符号链接不会被删除。
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, functools.partial(cleanup_workdir, retention_days=retention_days, dry_run=dry_run)
    )


@router.get("/ui/wallpaper")
async def get_ui_wallpaper():
    path = current_wallpaper()
    if path is None:
        raise HTTPException(status_code=404, detail="未设置背景图")
    mime = {
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".png": "image/png",
        ".gif": "image/gif",
        ".webp": "image/webp",
    }.get(path.suffix.lower(), "image/jpeg")
    return FileResponse(
        path,
        media_type=mime,
        headers={"Cache-Control": "private, max-age=3600"},
    )


@router.post("/ui/wallpaper")
async def upload_ui_wallpaper(
    file: UploadFile = File(...),
    session: AsyncSession = Depends(get_session),
):
    data = await file.read()
    if len(data) > MAX_WALLPAPER_BYTES:
        raise HTTPException(status_code=400, detail="图片超过 3MB")
    try:
        save_wallpaper_bytes(data)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await update_settings(session, {"ui": {"wallpaperKind": "file", "wallpaperUrl": "", "saved": True}})
    return public_settings_view()


@router.delete("/ui/wallpaper")
async def remove_ui_wallpaper(session: AsyncSession = Depends(get_session)):
    delete_wallpaper()
    await update_settings(session, {"ui": {"wallpaperKind": "none", "wallpaperUrl": "", "saved": True}})
    return public_settings_view()
