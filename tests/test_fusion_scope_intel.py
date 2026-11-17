"""融合层：范围守卫 / 情报时间流 / 角色路由 单元测试（离线，不发网络请求）。"""
from __future__ import annotations

from app.fusion import config, role_router, scope_guard, vulnintel


def test_normalize_host_handles_url_port_and_path():
    assert scope_guard.normalize_host("https://API.Example.EDU.CN:8443/path?q=1") == "api.example.edu.cn"
    assert scope_guard.normalize_host("10.0.0.1:8080") == "10.0.0.1"
    assert scope_guard.normalize_host("") == ""


def test_root_domain_generic_multi_part_suffix():
    assert scope_guard.root_domain("a.example.edu.cn") == "example.edu.cn"
    assert scope_guard.root_domain("b.other.com") == "other.com"


def test_infra_and_private_addresses_are_blocked():
    for host in ("169.254.169.254", "localhost", "127.0.0.1", "10.0.0.5", "192.168.1.7"):
        assert scope_guard.classify(host) == scope_guard.INFRA, host
        assert scope_guard.check_writeback(host, {"roots": ["10.0.0.5"]})["allowed"] is False


def test_own_source_foreign_classification():
    scope = scope_guard.normalize_scope({
        "roots": ["https://example.edu.cn"],
        "sources": ["partner.example.net"],
        "cidrs": ["93.184.216.0/24"],
    })
    assert scope_guard.check_writeback("api.example.edu.cn", scope)["classification"] == scope_guard.OWN
    assert scope_guard.check_writeback("93.184.216.34", scope)["allowed"] is True
    src = scope_guard.check_writeback("partner.example.net", scope)
    assert src["classification"] == scope_guard.SOURCE
    assert src["allowed"] is False
    foreign = scope_guard.check_writeback("unrelated.example.org", scope)
    assert foreign["classification"] == scope_guard.FOREIGN
    assert foreign["allowed"] is False


def test_parse_nvd_extracts_cvss_and_products():
    payload = {"vulnerabilities": [{"cve": {
        "id": "CVE-2026-0001",
        "descriptions": [{"lang": "en", "value": "A remote code execution issue"}],
        "published": "2026-11-16T00:00:00.000",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
        "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:vendor:some_product:1.0:*:*:*:*:*:*:*"}]}]}],
    }}]}
    rows = vulnintel.parse_nvd(payload)
    assert len(rows) == 1
    assert rows[0]["cve_id"] == "CVE-2026-0001"
    assert rows[0]["cvss"] == 9.8
    assert "some product" in rows[0]["products"]


def test_parse_kev_and_dedup_merges_flags():
    kev = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "dateAdded": "2026-11-16",
                                 "vendorProject": "vendor", "product": "some_product",
                                 "vulnerabilityName": "Known exploited"}]}
    nvd = {"vulnerabilities": [{"cve": {"id": "CVE-2026-0001", "descriptions": [], "metrics": {}}}]}
    merged = vulnintel.dedup_entries(vulnintel.parse_nvd(nvd) + vulnintel.parse_kev(kev))
    assert len(merged) == 1
    assert merged[0]["kev"] is True
    assert "some_product" in merged[0]["products"]


def test_fastlane_and_intel_rows():
    cfg = config.FusionConfig(intel_fastlane_cvss=9.0)
    entries = [
        {"cve_id": "CVE-A", "cvss": 9.8, "kev": False, "products": ["some_product"], "summary": "high", "published": ""},
        {"cve_id": "CVE-B", "cvss": 4.2, "kev": False, "products": [], "summary": "low", "published": ""},
        {"cve_id": "CVE-C", "cvss": 0.0, "kev": True, "products": [], "summary": "kev", "published": ""},
    ]
    fast = vulnintel.fastlane(entries, cfg)
    assert {e["cve_id"] for e in fast} == {"CVE-A", "CVE-C"}
    rows = vulnintel.build_intel_rows(entries)
    assert len(rows) == 3
    assert all(r["kind"] == vulnintel.INTEL_KIND for r in rows)
    assert len({r["dedup_hash"] for r in rows}) == 3


def test_match_fingerprint_returns_hints():
    entries = [{"cve_id": "CVE-A", "cvss": 9.8, "kev": True,
                "products": ["some_product"], "summary": "rce"}]
    hints = vulnintel.match_fingerprint(entries, ["some_product 1.0", "nginx"])
    assert len(hints) == 1
    assert hints[0]["cve_id"] == "CVE-A"
    assert vulnintel.match_fingerprint(entries, ["unrelated"]) == []


def test_sync_uses_injected_fetcher_and_never_hits_network():
    def fake(url, params, headers):
        if "nvd" in url:
            return {"vulnerabilities": [{"cve": {
                "id": "CVE-2026-7777",
                "descriptions": [{"lang": "en", "value": "test"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.9}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:v:some_product:1.0:*:*:*:*:*:*:*"}]}]}],
            }}]}
        return {"vulnerabilities": []}

    result = vulnintel.sync(fetcher=fake, cfg=config.FusionConfig(intel_sync_enabled=True))
    assert result["ok"] is True
    assert result["entry_count"] == 1
    assert result["fastlane_count"] == 1
    assert result["errors"] == []
    assert result["rows"][0]["confidence"] == "likely"


def test_sync_disabled_returns_explicit_error():
    result = vulnintel.sync(fetcher=lambda *a: {}, cfg=config.FusionConfig(intel_sync_enabled=False))
    assert result["ok"] is False
    assert result["entries"] == []


def test_config_defaults_keep_hard_gates_off(monkeypatch):
    for key in ("FUSION_EVIDENCE_GATE_HARD", "FUSION_SCOPE_GUARD_HARD", "FUSION_GOAL_GATE"):
        monkeypatch.delenv(key, raising=False)
    cfg = config.load_config()
    assert cfg.evidence_gate_hard is False
    assert cfg.scope_guard_hard is False
    assert cfg.goal_gate_enabled is True
    public = config.public_config()
    assert "nvd_api_key" not in public
    assert "nvd_api_key_configured" in public


def test_role_model_and_routing_table(monkeypatch):
    monkeypatch.setenv("FUSION_ROLE_MODEL_PLANNER", "strong-model")
    assert role_router.resolve_role_model("planner", fallback="default") == "strong-model"
    assert role_router.resolve_role_model("worker", fallback="default") == "default"
    table = role_router.role_routing_table("base-model")
    assert {r["role"] for r in table} == set(config.ROLES)
    assert all("hint" in r for r in table)


def test_skill_index_block_is_bounded_and_informative():
    block = role_router.skill_index_block()
    assert "可用方法论速查" in block
    assert len(block) <= 1400
    assert role_router.skill_index_block([]) == ""


def test_fusion_worker_block_contains_disciplines():
    block = role_router.fusion_worker_block()
    assert "证据与影响纪律" in block
    assert "L1" in block and "L4" in block
