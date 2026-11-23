"""告警通知配置与测试 API（/api/notify/*）。"""
from __future__ import annotations

import asyncio
from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app import notify
from app.db.session import get_session
from app.settings_service import effective_settings, refresh_cache, update_settings

router = APIRouter(prefix="/api/notify", tags=["notify"])


class NotifyConfigUpdate(BaseModel):
    enabled: bool | None = None
    channel: str | None = None
    webhook_url: str | None = None
    clear_webhook_url: bool = False
    telegram_bot_token: str | None = None
    clear_telegram_bot_token: bool = False
    telegram_chat_id: str | None = None
    console_base_url: str | None = None
    min_severity: str | None = None
    on_finding_accepted: bool | None = None
    on_intercept_pending: bool | None = None
    on_task_done: bool | None = None


@router.get("/config")
async def get_notify_config(session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    return {"config": notify.public_notify_config(), "channels": list(notify.CHANNELS)}


@router.put("/config")
async def put_notify_config(body: NotifyConfigUpdate, session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    merged = notify.merge_notify_patch(body.model_dump(exclude_unset=True))
    defaults = dict(effective_settings().get("defaults") or {})
    defaults["notify"] = merged
    await update_settings(session, {"defaults": defaults})
    return {"ok": True, "config": notify.public_notify_config()}


@router.post("/test")
async def test_notify(body: NotifyConfigUpdate | None = None, session: AsyncSession = Depends(get_session)):
    await refresh_cache(session)
    cfg = notify.merge_notify_patch(body.model_dump(exclude_unset=True)) if body else notify.raw_notify_config()
    result = await asyncio.to_thread(
        notify.send_notification_sync,
        "测试告警连通性",
        [
            "通道状态：连通性验证消息",
            f"触发最低等级：{cfg.get('min_severity', '高危')}",
            "若收到此卡片，表示知蠹 Riddle 7×24 实时推送已就绪。",
        ],
        event_type="test",
        link_path="/dashboard",
        cfg_override=cfg,
        force=True,
    )
    return result


@router.get("/history")
async def notify_history(limit: int = 30):
    return {"items": notify.list_delivery_history(limit=limit)}
