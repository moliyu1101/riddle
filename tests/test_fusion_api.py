"""融合层 API 冒烟：验证 router 挂载、请求模型与序列化。

刻意不启动 app.main 的 lifespan（watchdog 会注册 signal，非主线程会报错），
只把 fusion.router 挂到一个最小 FastAPI 实例上，测不依赖数据库的端点。
"""
from __future__ import annotations

from dataclasses import replace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import fusion
from app.fusion.config import FusionConfig


def _client() -> TestClient:
    app = FastAPI()
    app.include_router(fusion.router)
    # 不进入 with：避免触发 lifespan（本 router 自身没有启动钩子）
    return TestClient(app, raise_server_exceptions=False)


def test_evidence_check_endpoint():
    r = _client().post("/api/fusion/evidence/check", json={"finding": {
        "severity_claimed": "critical",
        "title": "远程命令执行",
        "vuln_type": "rce",
        "poc": "curl http://target/run?cmd=id",
        "raw_response": "HTTP/1.1 200 OK uid=0(root)",
    }})
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is True
    assert body["impact_level"] == "L3"


def test_evidence_check_batch_endpoint():
    r = _client().post("/api/fusion/evidence/check", json={"finding": [
        {"severity_claimed": "critical", "title": "疑似风险", "vuln_type": "rce"},
        {"severity_claimed": "low", "title": "指纹暴露"},
    ]})
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 2
    assert body["blocked"] >= 1


def test_scope_check_endpoint():
    r = _client().post("/api/fusion/scope/check", json={
        "target": "169.254.169.254",
        "scope": {"roots": ["example.edu.cn"]},
    })
    assert r.status_code == 200
    body = r.json()
    assert body["allowed"] is False
    assert body["classification"] == "infra"


def test_skill_index_endpoint():
    r = _client().get("/api/fusion/skill-index")
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert "可用方法论速查" in body["block"]


def test_intel_match_endpoint_is_wired():
    # 该端点走 DB，未初始化时允许报错，但路由必须存在（不是 404）
    r = _client().post("/api/fusion/intel/match", json={"technologies": []})
    assert r.status_code != 404


# ---- 第二轮：配置 / 双图 / 流量 / 公文报告 -------------------------------

def test_get_config_endpoint_exposes_safe_subset():
    r = _client().get("/api/fusion/config")
    assert r.status_code == 200
    body = r.json()
    assert set(("config", "overlay", "source")).issubset(body)
    assert "traffic_enabled" in body["config"]
    assert "graphs_enabled" in body["config"]
    assert "report_enabled" in body["config"]
    assert "nvd_api_key" not in body["config"]
    assert body["source"] in ("db", "env")


def test_put_config_rejects_non_whitelisted_patch():
    # 白名单收敛发生在使用 DB 之前，空 patch 必须明确 400 而不是静默成功
    r = _client().put("/api/fusion/config", json={"config": {"nvd_api_key": "x", "bogus": 1}})
    assert r.status_code == 400


def test_traffic_discover_endpoint():
    r = _client().get("/api/fusion/traffic/discover")
    assert r.status_code == 200
    assert isinstance(r.json()["dirs"], list)


def test_graphs_switch_returns_409_before_any_write():
    with patch.object(fusion.config, "load_config", return_value=replace(FusionConfig(), graphs_enabled=False)):
        r = _client().post("/api/fusion/graphs/T1/rebuild")
    assert r.status_code == 409
    assert "graphs" in r.json()["detail"]


def test_report_switch_returns_409_on_both_endpoints():
    with patch.object(fusion.config, "load_config", return_value=replace(FusionConfig(), report_enabled=False)):
        assert _client().get("/api/fusion/report/model/F1").status_code == 409
        assert _client().get("/api/fusion/report/docx/F1").status_code == 409


def test_second_round_routes_are_registered():
    # 查 OpenAPI 路径表：新版 FastAPI 的 app.routes 里是嵌套 router，且走 DB 的
    # 端点在空库里返回 404「任务不存在」是合法业务响应，用 HTTP 状态码判断会误判。
    app = FastAPI()
    app.include_router(fusion.router)
    registered = app.openapi()["paths"]
    expected = [
        ("GET", "/api/fusion/config"), ("PUT", "/api/fusion/config"),
        ("POST", "/api/fusion/graphs/{task_id}/rebuild"),
        ("GET", "/api/fusion/graphs/{task_id}"),
        ("GET", "/api/fusion/graphs/{task_id}/lineage"),
        ("GET", "/api/fusion/traffic/discover"),
        ("POST", "/api/fusion/traffic/import"),
        ("GET", "/api/fusion/traffic/{task_id}"),
        ("POST", "/api/fusion/traffic/bind"),
        ("GET", "/api/fusion/report/model/{finding_id}"),
        ("GET", "/api/fusion/report/docx/{finding_id}"),
    ]
    for method, path in expected:
        assert method.lower() in registered.get(path, {}), f"{method} {path} 未挂载"
