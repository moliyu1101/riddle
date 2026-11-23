"""漏洞库一键通杀落盘新任务 API 回归测试。"""
from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api.vulns import (
    KillsweepTaskCreateRequest,
    create_killsweep_task,
    killsweep_preview,
)
from app.db.models import Base, Finding, Killsweep, Review, SystemSettings, Target, Task, TaskEvent
from app.orchestrator import manager


async def _make_session() -> tuple[AsyncSession, object]:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    session_factory = async_sessionmaker(engine, expire_on_commit=False)
    return session_factory(), engine


async def _seed_finding(
    session: AsyncSession,
    *,
    with_killsweep: bool = True,
    fofa_key: str = "",
) -> tuple[Task, Finding]:
    origin_task = Task(
        name="高校资产巡检",
        src_type="edusrc",
        engine="fofa",
        fofa_query='title="门户" && domain="edu.cn"',
        guard_ops=["db_dump", "db_delete", "dos"],
        status="running",
    )
    session.add(origin_task)
    await session.flush()

    target = Target(
        task_id=origin_task.id,
        url="https://demo.edu.cn/jeecg-boot/sys/user",
        host="demo.edu.cn",
        title="教务门户",
        status="done",
    )
    session.add(target)
    await session.flush()

    finding = Finding(
        task_id=origin_task.id,
        target_id=target.id,
        vuln_type="未授权访问",
        title="JeecgBoot 接口未授权访问漏洞",
        severity_claimed="高危",
        target_url="https://demo.edu.cn/jeecg-boot/sys/user",
        owner="测试高校",
        description="特定接口缺少鉴权校验，可未授权读取配置。",
        poc="GET /jeecg-boot/sys/user HTTP/1.1",
        status="reviewed",
    )
    session.add(finding)
    await session.flush()

    review = Review(
        finding_id=finding.id,
        task_id=origin_task.id,
        verdict="accepted",
        confidence="confirmed",
        severity_final="高危",
        score=88.0,
        user_status="passed",
        user_severity="高危",
    )
    session.add(review)

    if with_killsweep:
        ks = Killsweep(
            task_id=origin_task.id,
            origin_finding_id=finding.id,
            product_key="jeecg-boot",
            product_name="JeecgBoot",
            vuln_type="未授权访问",
            vuln_summary="JeecgBoot 接口未授权访问",
            fofa_query='body="jeecg-boot" && domain="edu.cn"',
            fingerprint='body="jeecg-boot"',
            asset_count=120,
            edu_count=18,
            is_killsweep=True,
            verified=True,
            status="done",
        )
        session.add(ks)

    settings_row = SystemSettings(
        id="global",
        engines={"fofa": {"key": fofa_key}} if fofa_key else {},
        fofa={"key": fofa_key, "max_pages": 15, "page_size": 80},
        defaults={"engine": "fofa", "concurrency": 4, "deepen_cap": 2},
    )
    session.add(settings_row)
    await session.commit()
    return origin_task, finding


@pytest.mark.asyncio
async def test_killsweep_preview_prefers_existing_query_and_reports_engine_keys(monkeypatch):
    for var in ("FOFA_KEY", "FOFA_KEY_BACKUP", "FOFA_KEY_BACKUP2", "QUAKE_KEY", "HUNTER_KEY", "ZOOMEYE_KEY", "SHODAN_KEY", "CENSYS_KEY"):
        monkeypatch.delenv(var, raising=False)

    session, engine = await _make_session()
    try:
        _, finding = await _seed_finding(session, with_killsweep=True, fofa_key="test-fofa-key-123")
        preview = await killsweep_preview(finding.id, session=session)

        assert preview["finding"]["id"] == finding.id
        assert preview["query_source"] == "killsweep"
        assert preview["suggested_query"] == 'body="jeecg-boot" && domain="edu.cn"'
        assert preview["suggested_name"].startswith("[通杀] JeecgBoot")
        assert preview["default_engine"] == "fofa"
        assert preview["has_configured_engine"] is True
        engine_map = {e["name"]: e for e in preview["engines"]}
        assert engine_map["fofa"]["key_set"] is True
        assert engine_map["quake"]["key_set"] is False
        assert len(engine_map) >= 6
    finally:
        await session.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_killsweep_preview_fallback_query_and_404(monkeypatch):
    for var in ("FOFA_KEY", "FOFA_KEY_BACKUP", "FOFA_KEY_BACKUP2"):
        monkeypatch.delenv(var, raising=False)

    session, engine = await _make_session()
    try:
        _, finding = await _seed_finding(session, with_killsweep=False, fofa_key="")
        preview = await killsweep_preview(finding.id, session=session)
        assert preview["query_source"] == "suggested"
        assert 'domain="edu.cn"' in preview["suggested_query"]
        assert preview["has_configured_engine"] is False

        with pytest.raises(HTTPException) as exc:
            await killsweep_preview("nonexistent-id", session=session)
        assert exc.value.status_code == 404
    finally:
        await session.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_create_killsweep_task_rejects_unconfigured_engine(monkeypatch):
    for var in ("FOFA_KEY", "FOFA_KEY_BACKUP", "FOFA_KEY_BACKUP2", "QUAKE_KEY"):
        monkeypatch.delenv(var, raising=False)

    session, engine = await _make_session()
    try:
        _, finding = await _seed_finding(session, with_killsweep=True, fofa_key="")
        with pytest.raises(HTTPException) as exc:
            await create_killsweep_task(
                finding.id,
                KillsweepTaskCreateRequest(engine="fofa", query='body="jeecg-boot"'),
                session=session,
            )
        assert exc.value.status_code == 400
        assert "API Key" in exc.value.detail

        with pytest.raises(HTTPException) as exc_unknown:
            await create_killsweep_task(
                finding.id,
                KillsweepTaskCreateRequest(engine="unknown_engine", query='title="x"'),
                session=session,
            )
        assert exc_unknown.value.status_code == 400
    finally:
        await session.close()
        await engine.dispose()


@pytest.mark.asyncio
async def test_create_killsweep_task_persists_and_starts(monkeypatch):
    for var in ("FOFA_KEY", "FOFA_KEY_BACKUP", "FOFA_KEY_BACKUP2"):
        monkeypatch.delenv(var, raising=False)

    ensure_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(manager, "ensure_running", ensure_mock)

    session, engine = await _make_session()
    try:
        origin_task, finding = await _seed_finding(session, with_killsweep=True, fofa_key="valid-fofa-key")

        # 1) Create and start immediately
        res = await create_killsweep_task(
            finding.id,
            KillsweepTaskCreateRequest(
                engine="fofa",
                query='body="jeecg-boot" && domain="edu.cn"',
                name="[通杀] JeecgBoot 专项",
                src_type="edusrc",
                concurrency=5,
                max_pages=10,
                page_size=50,
                extra_src_rules="仅做无害只读验证",
                start_immediately=True,
            ),
            session=session,
        )
        assert res["ok"] is True
        assert res["started"] is True
        new_task_id = res["task"]["id"]
        assert new_task_id != origin_task.id
        ensure_mock.assert_awaited_once_with(new_task_id)

        persisted = await session.get(Task, new_task_id)
        assert persisted is not None
        assert persisted.status == "running"
        assert persisted.target_source == "fofa"
        assert persisted.engine == "fofa"
        assert persisted.fofa_query == 'body="jeecg-boot" && domain="edu.cn"'
        assert persisted.vuln_types == ["未授权访问"]
        assert persisted.concurrency == 5
        assert persisted.guard_ops == ["db_dump", "db_delete", "dos"]
        assert persisted.fofa_config["killsweep_mode"] is True
        assert persisted.fofa_config["origin_finding_id"] == finding.id
        assert "【漏洞库一键通杀上下文】" in persisted.src_rules
        assert "仅做无害只读验证" in persisted.src_rules

        events = (
            await session.execute(select(TaskEvent).where(TaskEvent.task_id == new_task_id))
        ).scalars().all()
        assert len(events) == 1
        assert events[0].kind == "killsweep_task_created"

        # 2) Create without auto-start
        ensure_mock.reset_mock()
        res_created = await create_killsweep_task(
            finding.id,
            KillsweepTaskCreateRequest(
                engine="fofa",
                query='body="jeecg-boot"',
                start_immediately=False,
            ),
            session=session,
        )
        assert res_created["started"] is False
        assert res_created["task"]["status"] == "created"
        ensure_mock.assert_not_awaited()
    finally:
        await session.close()
        await engine.dispose()
