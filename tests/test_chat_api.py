"""智能对话模块 API 回归测试（会话管理、置顶重命名、批量删除、@实体引用、多轮工具协同、旁路提问）。"""
from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.api import chat as chat_api
from app.db.models import Base, ChatActivity, Finding, Intel, Review, SystemSettings, Target, Task


async def _make_db(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(chat_api, "SessionLocal", factory)
    return factory, engine


async def _seed_entities(session: AsyncSession) -> tuple[Task, Target, Finding, Intel]:
    task = Task(
        name="高校统一认证巡检",
        src_type="edusrc",
        engine="fofa",
        fofa_query='title="统一身份认证" && domain="edu.cn"',
        status="running",
    )
    session.add(task)
    await session.flush()

    target = Target(
        task_id=task.id,
        url="https://auth.demo.edu.cn/login",
        host="auth.demo.edu.cn",
        title="统一身份认证",
        school="测试大学",
        status="done",
    )
    session.add(target)
    await session.flush()

    finding = Finding(
        task_id=task.id,
        target_id=target.id,
        vuln_type="未授权访问",
        title="统一身份认证管理接口未授权访问",
        severity_claimed="高危",
        target_url="https://auth.demo.edu.cn/api/admin/users",
        owner="测试大学",
        description="管理员列表接口缺少鉴权拦截",
        poc="GET /api/admin/users HTTP/1.1",
        status="reviewed",
    )
    session.add(finding)
    await session.flush()

    session.add(
        Review(
            finding_id=finding.id,
            task_id=task.id,
            verdict="accepted",
            confidence="confirmed",
            severity_final="高危",
            score=90.0,
            user_status="passed",
        )
    )

    intel = Intel(
        kind="endpoint",
        match_key="unified-auth",
        dedup_hash="abc123",
        summary="/api/admin/users 未授权暴露",
        confidence="verified",
        hit_count=5,
    )
    session.add(intel)

    session.add(
        SystemSettings(
            id="global",
            llm={"base_url": "https://api.example.com/v1", "api_key": "sk-test-chat-key", "model": "deepseek-chat"},
        )
    )
    await session.commit()
    return task, target, finding, intel


@pytest.mark.asyncio
async def test_chat_conversations_crud_pin_and_batch_delete(monkeypatch):
    factory, engine = await _make_db(monkeypatch)
    async with factory() as session:
        await _seed_entities(session)
        agents_res = await chat_api.list_chat_agents(session=session)
        assert len(agents_res["agents"]) >= 5
        assert agents_res["llm_ready"] is True

        c1 = await chat_api.create_conversation(
            chat_api.ConversationCreateRequest(agent_key="assistant", title="第一条对话"),
            session=session,
        )
        c2 = await chat_api.create_conversation(
            chat_api.ConversationCreateRequest(agent_key="recon", title="测绘语法讨论"),
            session=session,
        )

        # Pin c1 and rename + model override
        updated = await chat_api.update_conversation(
            c1["id"],
            chat_api.ConversationPatchRequest(title="已重命名对话", pinned=True, model_override="deepseek-reasoner"),
            session=session,
        )
        assert updated["title"] == "已重命名对话"
        assert updated["pinned"] is True
        assert updated["model_override"] == "deepseek-reasoner"

        listed = await chat_api.list_conversations(session=session)
        assert listed["conversations"][0]["id"] == c1["id"]

        # Batch delete c1, c2 and one missing id
        batch = await chat_api.batch_delete_conversations(
            chat_api.BatchDeleteRequest(ids=[c1["id"], c2["id"], "missing-conv"]),
            session=session,
        )
        by_id = {x["id"]: x for x in batch["items"]}
        assert by_id[c1["id"]]["ok"] is True
        assert by_id[c2["id"]]["ok"] is True
        assert by_id["missing-conv"]["ok"] is False

        listed_after = await chat_api.list_conversations(session=session)
        assert listed_after["conversations"] == []
    await engine.dispose()


@pytest.mark.asyncio
async def test_chat_mentions_search_and_resolution(monkeypatch):
    factory, engine = await _make_db(monkeypatch)
    async with factory() as session:
        task, target, finding, intel = await _seed_entities(session)

        res_all = await chat_api.search_chat_mentions(kind="", q="", limit=15, session=session)
        kinds_found = {item["kind"] for item in res_all["items"]}
        assert {"finding", "task", "target", "intel"} <= kinds_found

        res_finding = await chat_api.search_chat_mentions(kind="finding", q="未授权", limit=10, session=session)
        assert len(res_finding["items"]) == 1
        assert res_finding["items"][0]["id"] == finding.id

        prompt = f"请帮我复核 @[漏洞#{finding.id} 统一身份认证] 以及 @[任务#{task.id} 巡检] 和 @[情报#{intel.id} 端点]"
        ctx, resolved = await chat_api._resolve_mentions_context(session, prompt)
        assert len(resolved) == 3
        assert "统一身份认证管理接口未授权访问" in ctx
        assert "高校统一认证巡检" in ctx
        assert "/api/admin/users 未授权暴露" in ctx
    await engine.dispose()


@pytest.mark.asyncio
async def test_chat_send_message_with_tool_roundtrip_and_side_question(monkeypatch, tmp_path):
    factory, engine = await _make_db(monkeypatch)
    monkeypatch.setattr(chat_api, "_CHAT_UPLOADS_ROOT", tmp_path / "chat_uploads")

    class _FakeLLM:
        def __init__(self):
            self.calls = 0

        def chat(self, messages, tools=None, tool_choice=None, temperature=0.3):
            self.calls += 1
            # Side-question mode passes tools=None
            if tools is None:
                return SimpleNamespace(content="旁路快答：核心风险为未授权访问。", tool_calls=None, reasoning_content="")
            if self.calls == 1:
                tc = SimpleNamespace(
                    id="call_1",
                    function=SimpleNamespace(name="search_riddle_findings", arguments='{"query":"未授权","limit":5}'),
                )
                return SimpleNamespace(content="先检索漏洞库确认记录。", tool_calls=[tc], reasoning_content="检查漏洞列表")
            return SimpleNamespace(
                content="已检索到 1 条高危未授权访问漏洞，建议优先核验并提交 SRC。",
                tool_calls=None,
                reasoning_content="",
            )

    fake_llm = _FakeLLM()
    monkeypatch.setattr(chat_api, "_build_chat_llm_client", lambda model_override="", usage_key=None: fake_llm)

    async with factory() as session:
        _, _, finding, _ = await _seed_entities(session)
        conv = await chat_api.create_conversation(
            chat_api.ConversationCreateRequest(agent_key="analyst"),
            session=session,
        )

        # Send message -> triggers background tool call + final assistant answer
        sent = await chat_api.send_conversation_message(
            conv["id"],
            chat_api.SendMessageRequest(message=f"分析一下 @[漏洞#{finding.id} 未授权]"),
            session=session,
        )
        assert sent["ok"] is True
        assert sent["conversation"]["title"] != "新对话"

        # Wait for background turn task to complete
        bg = chat_api._CHAT_TASKS.get(conv["id"])
        if bg is not None:
            await asyncio.wait_for(bg, timeout=5.0)

        msgs = await chat_api.list_conversation_messages(conv["id"], since=None, before=None, limit=50, session=session)
        kinds = [m["kind"] for m in msgs["items"]]
        assert "user" in kinds
        assert "tool_use" in kinds
        assert "tool_result" in kinds
        assert "assistant" in kinds
        assert "result" in kinds
        assert msgs["running"] is False

        # Incremental poll after latest cursor returns empty
        inc = await chat_api.list_conversation_messages(conv["id"], since=msgs["cursor"], before=None, limit=50, session=session)
        assert inc["items"] == []

        # Lazy step detail lookup
        tool_res_item = next(m for m in msgs["items"] if m["kind"] == "tool_result")
        detail = await chat_api.get_message_detail(conv["id"], tool_res_item["id"], session=session)
        assert "统一身份认证管理接口未授权访问" in detail["detail"]

        # Side question (/btw) should answer WITHOUT adding any ChatActivity rows
        before_count = len(msgs["items"])
        sq = await chat_api.ask_side_question(
            conv["id"],
            chat_api.SideQuestionRequest(question="一句话总结核心风险"),
            session=session,
        )
        assert sq["ok"] is True
        assert "旁路快答" in sq["answer"]

        msgs_after = await chat_api.list_conversation_messages(conv["id"], since=None, before=None, limit=50, session=session)
        assert len(msgs_after["items"]) == before_count

        # Path traversal guard on attachment reader
        assert "非法" in chat_api._safe_read_attachment(conv["id"], "../../etc/passwd") or "暂无" in chat_api._safe_read_attachment(conv["id"], "../../etc/passwd")
    await engine.dispose()


@pytest.mark.asyncio
async def test_chat_rejects_unknown_agent_and_empty_message(monkeypatch):
    factory, engine = await _make_db(monkeypatch)
    async with factory() as session:
        with pytest.raises(HTTPException) as exc:
            await chat_api.create_conversation(
                chat_api.ConversationCreateRequest(agent_key="nonexistent_role"),
                session=session,
            )
        assert exc.value.status_code == 400

        c = await chat_api.create_conversation(chat_api.ConversationCreateRequest(agent_key="assistant"), session=session)
        with pytest.raises(HTTPException) as exc_empty:
            await chat_api.send_conversation_message(c["id"], chat_api.SendMessageRequest(message="   "), session=session)
        assert exc_empty.value.status_code == 400
    await engine.dispose()
