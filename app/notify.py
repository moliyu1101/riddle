"""实时告警通知引擎：支持飞书 / 钉钉 / 企业微信 / Telegram / 通用 Webhook。

配置持久化在 ``SystemSettings.defaults["notify"]``（复用单行配置表，免迁移），
通过 ``settings_service.effective_settings()`` 热读取；所有出网 Webhook URL 强制经过
``assert_safe_outbound_url`` SSRF 校验，防止误配或诱导探测内网。
"""
from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from app.tools.netguard import SsrfBlocked, assert_safe_outbound_url

logger = logging.getLogger("riddle.notify")

CHANNELS = ("feishu", "dingtalk", "wecom", "telegram", "webhook")
SEV_RANK = {"低危": 1, "low": 1, "中危": 2, "medium": 2, "高危": 3, "high": 3, "严重": 4, "critical": 4}
_HISTORY_MAX = 50
_LOCK = threading.Lock()
_HISTORY: list[dict[str, Any]] = []


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _mask_url(url: str) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""
    if len(raw) <= 28:
        return raw[:8] + "••••"
    return f"{raw[:24]}••••{raw[-6:]}"


def _mask_secret(val: str) -> str:
    raw = (val or "").strip()
    if not raw:
        return ""
    if len(raw) <= 8:
        return "••••••••"
    return f"{raw[:4]}••••{raw[-4:]}"


def _default_config() -> dict[str, Any]:
    return {
        "enabled": False,
        "channel": "feishu",
        "webhook_url": "",
        "telegram_bot_token": "",
        "telegram_chat_id": "",
        "console_base_url": "",
        "min_severity": "高危",
        "on_finding_accepted": True,
        "on_intercept_pending": True,
        "on_task_done": True,
    }


def raw_notify_config() -> dict[str, Any]:
    """读取生效的完整通知配置（含真实密钥，仅服务端发送时使用）。"""
    base = _default_config()
    try:
        from app.settings_service import effective_settings

        saved = (effective_settings().get("defaults") or {}).get("notify") or {}
        if isinstance(saved, dict):
            base.update({k: saved[k] for k in base if k in saved})
    except Exception:
        pass
    return base


def public_notify_config() -> dict[str, Any]:
    """返回脱敏后的通知配置供前端展示。"""
    cfg = raw_notify_config()
    return {
        "enabled": bool(cfg.get("enabled")),
        "channel": str(cfg.get("channel") or "feishu"),
        "webhook_url": _mask_url(str(cfg.get("webhook_url") or "")),
        "webhook_url_set": bool(str(cfg.get("webhook_url") or "").strip()),
        "telegram_bot_token": _mask_secret(str(cfg.get("telegram_bot_token") or "")),
        "telegram_bot_token_set": bool(str(cfg.get("telegram_bot_token") or "").strip()),
        "telegram_chat_id": str(cfg.get("telegram_chat_id") or ""),
        "console_base_url": str(cfg.get("console_base_url") or ""),
        "min_severity": str(cfg.get("min_severity") or "高危"),
        "on_finding_accepted": bool(cfg.get("on_finding_accepted", True)),
        "on_intercept_pending": bool(cfg.get("on_intercept_pending", True)),
        "on_task_done": bool(cfg.get("on_task_done", True)),
    }


def merge_notify_patch(incoming: dict[str, Any]) -> dict[str, Any]:
    """合并前端提交的通知配置，空串或脱敏占位保留原密钥。"""
    cur = raw_notify_config()
    out = dict(cur)
    if "enabled" in incoming:
        out["enabled"] = bool(incoming["enabled"])
    if "channel" in incoming and str(incoming["channel"]).strip() in CHANNELS:
        out["channel"] = str(incoming["channel"]).strip()
    if "webhook_url" in incoming:
        val = str(incoming["webhook_url"] or "").strip()
        if val and "••••" not in val:
            out["webhook_url"] = val
        elif incoming.get("clear_webhook_url"):
            out["webhook_url"] = ""
    if "telegram_bot_token" in incoming:
        val = str(incoming["telegram_bot_token"] or "").strip()
        if val and "••••" not in val:
            out["telegram_bot_token"] = val
        elif incoming.get("clear_telegram_bot_token"):
            out["telegram_bot_token"] = ""
    if "telegram_chat_id" in incoming:
        out["telegram_chat_id"] = str(incoming["telegram_chat_id"] or "").strip()
    if "console_base_url" in incoming:
        out["console_base_url"] = str(incoming["console_base_url"] or "").strip().rstrip("/")
    if "min_severity" in incoming and str(incoming["min_severity"]).strip() in SEV_RANK:
        out["min_severity"] = str(incoming["min_severity"]).strip()
    for flag in ("on_finding_accepted", "on_intercept_pending", "on_task_done"):
        if flag in incoming:
            out[flag] = bool(incoming[flag])
    return out


def severity_meets_threshold(severity: str, min_severity: str) -> bool:
    cur = SEV_RANK.get((severity or "").strip().lower(), SEV_RANK.get((severity or "").strip(), 2))
    floor = SEV_RANK.get((min_severity or "高危").strip().lower(), SEV_RANK.get((min_severity or "高危").strip(), 3))
    return cur >= floor


def build_channel_request(
    channel: str,
    title: str,
    lines: list[str],
    *,
    webhook_url: str = "",
    telegram_bot_token: str = "",
    telegram_chat_id: str = "",
    event_type: str = "alert",
    link_url: str = "",
) -> tuple[str, dict[str, Any]]:
    """按目标渠道构造 (url, json_body)。"""
    body_lines = [line for line in lines if line]
    if link_url:
        body_lines.append(f"控制台直达：{link_url}")
    text = f"【知蠹 Riddle】{title}\n" + "\n".join(body_lines)

    ch = (channel or "feishu").strip().lower()
    if ch == "feishu":
        return webhook_url, {
            "msg_type": "interactive",
            "card": {
                "header": {"title": {"tag": "plain_text", "content": f"知蠹 Riddle · {title}"}, "template": "blue"},
                "elements": [{"tag": "markdown", "content": "\n".join(body_lines)}],
            },
        }
    if ch == "dingtalk":
        return webhook_url, {
            "msg_type": "markdown",
            "msgtype": "markdown",
            "markdown": {"title": f"知蠹 Riddle · {title}", "text": f"### 知蠹 Riddle · {title}\n\n" + "\n\n".join(body_lines)},
        }
    if ch == "wecom":
        return webhook_url, {
            "msgtype": "markdown",
            "markdown": {"content": f"### 知蠹 Riddle · {title}\n" + "\n".join(body_lines)},
        }
    if ch == "telegram":
        url = f"https://api.telegram.org/bot{telegram_bot_token}/sendMessage"
        return url, {"chat_id": telegram_chat_id, "text": text, "disable_web_page_preview": True}
    return webhook_url, {
        "source": "riddle",
        "event": event_type,
        "title": title,
        "lines": body_lines,
        "link_url": link_url,
        "ts": _now_iso(),
    }


def _record_delivery(entry: dict[str, Any]) -> None:
    with _LOCK:
        _HISTORY.insert(0, entry)
        del _HISTORY[_HISTORY_MAX:]


def list_delivery_history(limit: int = 30) -> list[dict[str, Any]]:
    with _LOCK:
        return list(_HISTORY[: max(1, min(limit, _HISTORY_MAX))])


def send_notification_sync(
    title: str,
    lines: list[str],
    *,
    event_type: str = "alert",
    link_path: str = "",
    cfg_override: dict[str, Any] | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """同步发送一条告警通知并记录投递历史（含 SSRF 校验，绝不抛出未捕获异常）。"""
    cfg = dict(cfg_override) if cfg_override is not None else raw_notify_config()
    if not force and not cfg.get("enabled"):
        return {"ok": False, "skipped": True, "reason": "通知开关未启用"}

    channel = str(cfg.get("channel") or "feishu")
    webhook_url = str(cfg.get("webhook_url") or "").strip()
    tg_token = str(cfg.get("telegram_bot_token") or "").strip()
    tg_chat = str(cfg.get("telegram_chat_id") or "").strip()

    if channel == "telegram":
        if not tg_token or not tg_chat:
            return {"ok": False, "error": "Telegram 渠道需要配置 Bot Token 与 Chat ID"}
    elif not webhook_url:
        return {"ok": False, "error": "未配置 Webhook URL"}

    base_url = str(cfg.get("console_base_url") or "").strip().rstrip("/")
    link_url = f"{base_url}{link_path}" if (base_url and link_path) else ""
    url, payload = build_channel_request(
        channel,
        title,
        lines,
        webhook_url=webhook_url,
        telegram_bot_token=tg_token,
        telegram_chat_id=tg_chat,
        event_type=event_type,
        link_url=link_url,
    )

    allow_private = os.environ.get("RIDDLE_NOTIFY_ALLOW_PRIVATE", "").strip() in ("1", "true", "True")
    try:
        assert_safe_outbound_url(url, allow_private=allow_private)
    except SsrfBlocked as exc:
        err = f"Webhook URL 被出网安全策略拦截：{exc}"
        entry = {"ts": _now_iso(), "channel": channel, "event": event_type, "title": title, "ok": False, "error": err}
        _record_delivery(entry)
        return entry

    started = time.perf_counter()
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
        latency_ms = int((time.perf_counter() - started) * 1000)
        ok = 200 <= resp.status_code < 300
        err = "" if ok else f"HTTP {resp.status_code}: {resp.text[:200]}"
        entry = {
            "ts": _now_iso(),
            "channel": channel,
            "event": event_type,
            "title": title,
            "ok": ok,
            "status_code": resp.status_code,
            "latency_ms": latency_ms,
            "error": err,
        }
    except Exception as exc:  # noqa: BLE001
        entry = {
            "ts": _now_iso(),
            "channel": channel,
            "event": event_type,
            "title": title,
            "ok": False,
            "status_code": 0,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "error": str(exc)[:240],
        }
    _record_delivery(entry)
    return entry


def fire_notification_async(
    title: str,
    lines: list[str],
    *,
    event_type: str = "alert",
    link_path: str = "",
) -> None:
    """后台线程异步投递，确保不阻塞编排器或执行器主流程。"""
    cfg = raw_notify_config()
    if not cfg.get("enabled"):
        return
    if event_type == "finding_accepted" and not cfg.get("on_finding_accepted", True):
        return
    if event_type == "intercept_pending" and not cfg.get("on_intercept_pending", True):
        return
    if event_type == "task_done" and not cfg.get("on_task_done", True):
        return

    def _run() -> None:
        try:
            send_notification_sync(title, lines, event_type=event_type, link_path=link_path, cfg_override=cfg)
        except Exception:  # noqa: BLE001
            logger.debug("async notify failed", exc_info=True)

    threading.Thread(target=_run, daemon=True, name="riddle-notify").start()
