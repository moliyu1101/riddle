"""双图全局资产真值库与自动化资产收集引擎回归测试。"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.api import assets as assets_api
from app.assets import ai_collector
from app.assets import collector_service as svc
from app.db.models import AssetCompany, Base, Finding, FusionGoal, GlobalAsset, SystemSettings, Target, Task
from app.orchestrator import manager


async def _make_db(monkeypatch):
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(svc, "SessionLocal", factory)
    monkeypatch.setattr(ai_collector, "SessionLocal", factory)
    return factory, engine


@pytest.mark.asyncio
async def test_global_asset_upsert_explicit_invariant_and_dsl_filter(monkeypatch):
    factory, engine = await _make_db(monkeypatch)
    async with factory() as session:
        # 1) Create two companies with overlapping domain scope
        c_explicit = (
            await assets_api.create_company(
                assets_api.CompanyCreateRequest(name="显式主体", scope_rules=[]),
                session=session,
            )
        )["company"]
        # Import asset explicitly bound to c_explicit
        imp = await assets_api.manual_import_assets(
            assets_api.ManualAssetImportRequest(
                seeds_text="https://portal.alpha.edu.cn:8443/api/login\n202.120.1.10",
                company_id=c_explicit["id"],
            ),
            session=session,
        )
        assert imp["total_inserted"] >= 4

        # Create another company whose scope matches alpha.edu.cn & 202.120.1.0/24
        c_scope = await assets_api.create_company(
            assets_api.CompanyCreateRequest(
                name="范围认领主体",
                scope_rules=[
                    assets_api.CompanyScopeRuleIn(kind="domain", value="alpha.edu.cn"),
                    assets_api.CompanyScopeRuleIn(kind="cidr", value="202.120.1.0/24"),
                ],
            ),
            session=session,
        )
        # Explicit ownership must NEVER be overwritten by scope claiming!
        assert c_scope["claimed_assets"] == 0

        # Import an unbound asset -> automatically claimed by c_scope!
        await assets_api.manual_import_assets(
            assets_api.ManualAssetImportRequest(seeds_text="https://oa.alpha.edu.cn/index"),
            session=session,
        )
        oa_rows = await assets_api.list_global_assets(
            asset_type="subdomain", company_id=None, q="host:oa.alpha", limit=100, offset=0, session=session
        )
        assert oa_rows["total"] == 1
        assert oa_rows["items"][0]["company_name"] == "范围认领主体"

        # Test upsert merges technologies & status_code cleanly
        await svc.upsert_global_asset(
            session,
            asset_type="service",
            dedup_key="https://portal.alpha.edu.cn:8443",
            value="https://portal.alpha.edu.cn:8443",
            host="portal.alpha.edu.cn",
            port=8443,
            status_code=200,
            technologies=["Nginx", "Spring/Java"],
        )
        await session.commit()

        dsl_hit = await assets_api.list_global_assets(
            asset_type="service",
            company_id=None,
            q="port:8443 status:200 tech:nginx domain:alpha.edu.cn",
            limit=100,
            offset=0,
            session=session,
        )
        assert dsl_hit["total"] == 1
        assert "Nginx" in dsl_hit["items"][0]["technologies"]
    await engine.dispose()


@pytest.mark.asyncio
async def test_sync_from_tasks_and_dual_graph_with_lineage(monkeypatch):
    factory, engine = await _make_db(monkeypatch)
    async with factory() as session:
        t = Task(name="双图测试任务", src_type="edusrc", status="running")
        session.add(t)
        await session.flush()

        tg = Target(
            task_id=t.id,
            url="https://jw.beta.edu.cn/admin/index",
            host="jw.beta.edu.cn",
            ip="10.20.30.40",
            title="教务管理系统",
            status="done",
        )
        session.add(tg)
        await session.flush()

        session.add(
            FusionGoal(
                task_id=t.id,
                goal_key="g1",
                title="教务管理系统未授权访问验证",
                criteria="拿到受保护数据响应",
                kind="capability",
            )
        )
        session.add(
            Finding(
                task_id=t.id,
                target_id=tg.id,
                vuln_type="未授权访问",
                title="教务管理系统未授权访问",
                severity_claimed="高危",
                target_url="https://jw.beta.edu.cn/admin/index",
                steps=[{"desc": "直接请求 /admin/index 返回 200 管理面板"}],
                status="reviewed",
            )
        )
        await session.commit()

        synced = await assets_api.sync_from_tasks(assets_api.SyncFromTasksRequest(task_id=t.id), session=session)
        assert synced["synced"]["processed"] == 1
        assert synced["synced"]["root_domain"] == 1
        assert synced["synced"]["subdomain"] == 1

        graph = await assets_api.get_dual_graph(task_id=t.id, company_id=None, limit=200, session=session)
        assert graph["coverage"]["asset_nodes"] >= 4
        assert graph["coverage"]["exploration_nodes"] >= 2
        assert graph["coverage"]["anchored_assets"] >= 1
        edge_kinds = {e["kind"] for e in graph["edges"]}
        assert "anchors" in edge_kinds
        assert "proves" in edge_kinds

        finding_node = next(n for n in graph["nodes"] if n["kind"] == "finding")
        lin = await assets_api.get_dual_graph_lineage(
            node_id=finding_node["id"],
            task_id=t.id,
            company_id=None,
            direction="both",
            session=session,
        )
        assert len(lin["lineage"]) >= 2
    await engine.dispose()


@pytest.mark.asyncio
async def test_auto_collect_job_pipeline_and_convert_to_task(monkeypatch):
    factory, engine = await _make_db(monkeypatch)

    monkeypatch.setattr(svc, "_fetch_crtsh_subdomains", AsyncMock(return_value=["vpn.gamma.edu.cn", "oa.gamma.edu.cn"]))
    monkeypatch.setattr(
        svc,
        "_resolve_dns_batch",
        AsyncMock(return_value={"vpn.gamma.edu.cn": ["198.51.100.10"], "oa.gamma.edu.cn": ["198.51.100.11"]}),
    )

    async def _fake_probe(client, url_candidate):
        if "oa.gamma.edu.cn" in url_candidate and url_candidate.startswith("https://"):
            return {
                "url": "https://oa.gamma.edu.cn",
                "status_code": 200,
                "title": "OA 协同办公系统",
                "technologies": ["Nginx", "JeecgBoot"],
                "endpoints": ["https://oa.gamma.edu.cn/jeecg-boot/sys/login"],
            }
        return None

    monkeypatch.setattr(svc, "_probe_http_host", _fake_probe)
    ensure_mock = AsyncMock(return_value=None)
    monkeypatch.setattr(manager, "ensure_running", ensure_mock)

    async with factory() as session:
        started = await assets_api.start_collect_job(
            assets_api.CollectJobCreateRequest(
                name="Gamma 高校自动收集",
                seeds_text="gamma.edu.cn",
                sources=["crtsh", "dns", "http_probe"],
            ),
            session=session,
        )
        job_id = started["job"]["id"]
        bg = svc._COLLECT_TASKS.get(job_id)
        if bg is not None:
            await asyncio.wait_for(bg, timeout=5.0)

        job_done = await assets_api.get_collect_job(job_id, session=session)
        assert job_done["status"] == "done"
        assert job_done["stats"]["root_domain"] >= 1
        assert job_done["stats"]["subdomain"] >= 2
        assert job_done["stats"]["ip"] >= 2
        assert job_done["stats"]["service"] >= 1
        assert job_done["stats"]["app"] >= 1
        assert job_done["stats"]["endpoint"] >= 1

        # Convert collected service assets directly into a Riddle scanning Task
        services = await assets_api.list_global_assets(
            asset_type="service", company_id=None, q="", limit=100, offset=0, session=session
        )
        assert services["total"] >= 1
        res_task = await assets_api.create_task_from_assets(
            assets_api.AssetsToTaskRequest(
                asset_ids=[s["id"] for s in services["items"]],
                name="Gamma 收集资产挖掘",
                start_immediately=True,
            ),
            session=session,
        )
        assert res_task["ok"] is True
        assert res_task["target_count"] >= 1
        ensure_mock.assert_awaited_once_with(res_task["task"]["id"])

        persisted = (await session.execute(select(GlobalAsset))).scalars().all()
        assert len(persisted) >= 6
    await engine.dispose()


@pytest.mark.asyncio
async def test_ai_natural_language_plan_and_autonomous_collection(monkeypatch):
    from types import SimpleNamespace

    factory, engine = await _make_db(monkeypatch)
    monkeypatch.setattr(svc, "_fetch_crtsh_subdomains", AsyncMock(return_value=["portal.delta.edu.cn", "jw.delta.edu.cn"]))
    monkeypatch.setattr(
        svc,
        "_resolve_dns_batch",
        AsyncMock(return_value={"portal.delta.edu.cn": ["203.0.113.10"], "jw.delta.edu.cn": ["203.0.113.11"]}),
    )

    async def _fake_probe(client, url_candidate):
        if "jw.delta.edu.cn" in url_candidate and url_candidate.startswith("https://"):
            return {
                "url": "https://jw.delta.edu.cn",
                "status_code": 200,
                "title": "教务系统登录入口",
                "technologies": ["Nginx", "Spring/Java"],
                "endpoints": ["https://jw.delta.edu.cn/login"],
            }
        return None

    monkeypatch.setattr(svc, "_probe_http_host", _fake_probe)

    class _FakeCollectLLM:
        def __init__(self):
            self.step = 0

        def chat(self, messages, tools=None, tool_choice=None, temperature=0.25):
            # Planning call has tools=None
            if tools is None:
                return SimpleNamespace(
                    content=(
                        '```json\n'
                        '{"task_name":"Delta高校资产收集","summary":"围绕 delta.edu.cn 开展被动子域、DNS与HTTP指纹收集",'
                        '"company_name":"Delta 大学","scope_rules":[{"kind":"domain","value":"delta.edu.cn"}],'
                        '"seeds":["delta.edu.cn"],"recommended_engine":"","queries":[],'
                        '"steps":["建立Delta大学主体","crt.sh收集子域","DNS与HTTP探活"],"reasoning":"优先被动收敛范围"}\n'
                        '```'
                    ),
                    tool_calls=None,
                    reasoning_content="分析目标高校根域名并制定安全收集计划",
                )

            self.step += 1
            if self.step == 1:
                return SimpleNamespace(
                    content="先建立主体 Delta 大学，并查询 delta.edu.cn 的证书透明度子域名。",
                    reasoning_content="先建主体再收集子域",
                    tool_calls=[
                        SimpleNamespace(
                            id="tc1",
                            function=SimpleNamespace(
                                name="ensure_asset_company",
                                arguments='{"name":"Delta 大学","scope_rules":[{"kind":"domain","value":"delta.edu.cn"}]}',
                            ),
                        ),
                        SimpleNamespace(
                            id="tc2",
                            function=SimpleNamespace(
                                name="query_crtsh_subdomains",
                                arguments='{"root_domain":"delta.edu.cn"}',
                            ),
                        ),
                    ],
                )
            if self.step == 2:
                return SimpleNamespace(
                    content="已发现 2 个子域，接下来并发解析 DNS 并对主机做轻量 HTTP 存活指纹探测。",
                    reasoning_content="补全 IP 与存活指纹",
                    tool_calls=[
                        SimpleNamespace(
                            id="tc3",
                            function=SimpleNamespace(
                                name="resolve_dns_hosts",
                                arguments='{"hosts":["portal.delta.edu.cn","jw.delta.edu.cn"]}',
                            ),
                        ),
                        SimpleNamespace(
                            id="tc4",
                            function=SimpleNamespace(
                                name="probe_http_services",
                                arguments='{"targets":["jw.delta.edu.cn"]}',
                            ),
                        ),
                    ],
                )
            return SimpleNamespace(
                content="## AI 资产摸排总结\n\n- 已自动创建主体 **Delta 大学**\n- 发现高价值入口：`https://jw.delta.edu.cn`（教务系统登录入口）",
                reasoning_content="",
                tool_calls=None,
            )

    fake_llm = _FakeCollectLLM()
    monkeypatch.setattr(ai_collector, "_build_llm", lambda usage_key=None: fake_llm)

    async with factory() as session:
        session.add(
            SystemSettings(
                id="global",
                llm={"base_url": "https://api.example.com/v1", "api_key": "sk-test-ai-collect", "model": "deepseek-chat"},
            )
        )
        await session.commit()

        # 1) Test natural language plan preview
        plan_res = await assets_api.preview_ai_collect_plan(
            assets_api.AICollectPlanRequest(prompt="帮我收集 Delta 大学 delta.edu.cn 的教务与门户资产"),
            session=session,
        )
        assert plan_res["ok"] is True
        assert plan_res["plan"]["company_name"] == "Delta 大学"
        assert "delta.edu.cn" in plan_res["plan"]["seeds"]

        # 2) Launch autonomous AI collection job
        started = await assets_api.start_ai_collect_job(
            assets_api.AICollectJobCreateRequest(
                prompt="帮我收集 Delta 大学 delta.edu.cn 的教务与门户资产，并识别存活指纹",
                max_rounds=6,
            ),
            session=session,
        )
        job_id = started["job"]["id"]
        bg = svc._COLLECT_TASKS.get(job_id)
        if bg is not None:
            await asyncio.wait_for(bg, timeout=5.0)

        done_job = await assets_api.get_collect_job(job_id, session=session)
        assert done_job["mode"] == "ai"
        assert done_job["status"] == "done"
        assert done_job["company_name"] == "Delta 大学"
        assert "教务系统登录入口" in done_job["ai_summary"]
        trace_kinds = {t["kind"] for t in done_job["ai_trace"]}
        assert {"thinking", "tool_use", "tool_result", "summary"} <= trace_kinds
        assert done_job["stats"]["root_domain"] >= 1
        assert done_job["stats"]["subdomain"] >= 2
        assert done_job["stats"]["ip"] >= 2
        assert done_job["stats"]["service"] >= 1

        comps = (await session.execute(select(AssetCompany))).scalars().all()
        assert any(c.name == "Delta 大学" for c in comps)
    await engine.dispose()
