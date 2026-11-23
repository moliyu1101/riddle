"""新增核心能力回归测试：实时告警通知引擎、融合层自动闭环联动、浏览器 XHR/Fetch 网络捕获。"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app import notify
from app.db.models import Base, Finding, FusionGoal, FusionTraffic, Task
from app.fusion import auto_sync, traffic_ledger
from app.tools.browser_actions import BrowserSession


def test_notify_channel_payloads_and_thresholds():
    url, body = notify.build_channel_request(
        "feishu",
        "发现高危漏洞",
        ["标题：SQL 注入"],
        webhook_url="https://open.feishu.cn/open-apis/bot/v2/hook/abc",
        link_url="http://console.example.com/function/findings/detail?id=f1",
    )
    assert url.startswith("https://open.feishu.cn/")
    assert body["msg_type"] == "interactive"
    assert "SQL 注入" in body["card"]["elements"][0]["content"]

    _, dt = notify.build_channel_request("dingtalk", "测试", ["line1"], webhook_url="https://oapi.dingtalk.com/robot/send")
    assert dt["msgtype"] == "markdown"

    _, wc = notify.build_channel_request("wecom", "测试", ["line1"], webhook_url="https://qyapi.weixin.qq.com/cgi-bin/webhook/send")
    assert wc["msgtype"] == "markdown"

    tg_url, tg_body = notify.build_channel_request(
        "telegram", "测试", ["line1"], telegram_bot_token="123:TOKEN", telegram_chat_id="-1009"
    )
    assert "api.telegram.org/bot123:TOKEN/sendMessage" in tg_url
    assert tg_body["chat_id"] == "-1009"

    assert notify.severity_meets_threshold("严重", "高危") is True
    assert notify.severity_meets_threshold("高危", "高危") is True
    assert notify.severity_meets_threshold("中危", "高危") is False
    assert notify.severity_meets_threshold("medium", "中危") is True


def test_notify_ssrf_blocks_private_webhook():
    res = notify.send_notification_sync(
        "SSRF 测试",
        ["不应允许请求本机地址"],
        cfg_override={
            "enabled": True,
            "channel": "webhook",
            "webhook_url": "http://127.0.0.1:18800/health",
        },
        force=True,
    )
    assert res["ok"] is False
    assert "拦截" in res["error"]


def test_browser_session_captures_only_in_scope_apis():
    fake_exec = SimpleNamespace(target="https://portal.demo.edu.cn/login")
    bs = BrowserSession(fake_exec)

    # 静态图片忽略
    assert bs.record_api_response(
        method="GET",
        url="https://portal.demo.edu.cn/static/logo.png",
        status=200,
        resource_type="image",
        content_type="image/png",
    ) is False

    # 跨站外域忽略
    assert bs.record_api_response(
        method="GET",
        url="https://analytics.thirdparty.com/api/ping",
        status=200,
        resource_type="xhr",
        content_type="application/json",
    ) is False

    # 同域 XHR 捕获
    assert bs.record_api_response(
        method="POST",
        url="https://portal.demo.edu.cn/api/v1/user/profile?ts=1",
        status=200,
        resource_type="xhr",
        content_type="application/json; charset=utf-8",
        auth_headers=["Authorization"],
    ) is True

    # 同路径再次命中应去重并累加 hits
    assert bs.record_api_response(
        method="POST",
        url="https://portal.demo.edu.cn/api/v1/user/profile?ts=2",
        status=200,
        resource_type="fetch",
        content_type="application/json",
    ) is False

    apis = bs.get_captured_apis()
    assert len(apis) == 1
    assert apis[0]["hits"] == 2
    assert apis[0]["auth_headers"] == ["Authorization"]


@pytest.mark.asyncio
async def test_fusion_auto_sync_binds_traffic_and_evaluates_goals(tmp_path):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

    # 写入测试 fusion_traffic.jsonl
    jsonl = tmp_path / traffic_ledger.JSONL_NAME
    jsonl.write_text(
        "\n".join([
            json.dumps({
                "method": "GET",
                "url": "https://portal.demo.edu.cn/api/admin/users",
                "status_code": 200,
                "request_head": "GET /api/admin/users HTTP/1.1",
                "response_head": "HTTP/1.1 200 OK",
                "body": '{"users": ["admin"]}',
                "role": "proof",
            }),
            json.dumps({
                "method": "GET",
                "url": "https://unrelated.other.org/index",
                "status_code": 200,
                "request_head": "GET /index HTTP/1.1",
                "response_head": "HTTP/1.1 200 OK",
                "body": "ok",
                "role": "baseline",
            }),
        ]),
        encoding="utf-8",
    )

    async with Session() as session:
        t = Task(id="t-sync-1", name="同步测试任务", src_type="edusrc", target_source="manual")
        f = Finding(
            id="f-sync-1",
            task_id="t-sync-1",
            target_id="tg-1",
            vuln_type="未授权访问",
            title="后台用户列表未授权访问",
            severity_claimed="高危",
            target_url="https://portal.demo.edu.cn/api/admin/users",
            poc="curl https://portal.demo.edu.cn/api/admin/users",
            raw_request="GET /api/admin/users HTTP/1.1",
            raw_response="HTTP/1.1 200 OK",
        )
        g = FusionGoal(
            task_id="t-sync-1",
            goal_key="g1",
            title="发现未授权高危洞",
            criteria="命中未授权访问漏洞",
            kind="finding",
            match_terms=["未授权"],
            status="pending",
        )
        session.add_all([t, f, g])
        await session.commit()

        res = await auto_sync.on_finding_reviewed(
            session,
            "t-sync-1",
            "f-sync-1",
            "https://portal.demo.edu.cn/api/admin/users",
            work_dir=str(tmp_path),
        )
        await session.commit()

        assert res["traffic"]["imported"] == 1
        assert res["traffic"]["bound"] == 1

        bound_rows = (
            await session.execute(select(FusionTraffic).where(FusionTraffic.finding_id == "f-sync-1"))
        ).scalars().all()
        assert len(bound_rows) == 1
        assert "portal.demo.edu.cn" in bound_rows[0].url

        goal_row = (
            await session.execute(select(FusionGoal).where(FusionGoal.task_id == "t-sync-1"))
        ).scalar_one()
        assert goal_row.status == "met"
        assert goal_row.evidence_ref == "f-sync-1"

    await engine.dispose()
