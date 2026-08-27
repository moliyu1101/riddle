"""阶段一侦察能力补强测试：资产发现 + 指纹识别与已知漏洞匹配。

只测纯逻辑（目标归一化/根域/路径分类/组件识别/版本提取/已知漏洞匹配），
不依赖网络；fingerprint 用直接传 headers/body 的离线路径。
"""
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.recon import (  # noqa: E402
    _classify_path,
    _detect_components,
    _extract_versions,
    _match_known_vulns,
    _normalize_target,
    _root_domain,
    asset_discovery,
    fingerprint,
)


class NormalizeTargetTest(unittest.TestCase):
    def test_bare_domain(self):
        n = _normalize_target("example.com")
        self.assertEqual(n["host"], "example.com")
        self.assertEqual(n["base"], "http://example.com")

    def test_full_url_with_port(self):
        n = _normalize_target("https://jwxt.example.edu.cn:8443/x")
        self.assertEqual(n["host"], "jwxt.example.edu.cn")
        self.assertEqual(n["port"], 8443)
        self.assertEqual(n["base"], "https://jwxt.example.edu.cn:8443")

    def test_invalid(self):
        self.assertIsNone(_normalize_target(""))
        self.assertIsNone(_normalize_target("   "))


class RootDomainTest(unittest.TestCase):
    def test_edu_cn_three_labels(self):
        self.assertEqual(_root_domain("jwxt.xxx.edu.cn"), "xxx.edu.cn")

    def test_normal_two_labels(self):
        self.assertEqual(_root_domain("www.example.com"), "example.com")

    def test_already_root(self):
        self.assertEqual(_root_domain("example.com"), "example.com")


class ClassifyPathTest(unittest.TestCase):
    def test_git_source_leak(self):
        item = _classify_path("/.git/config", 200, "", "ref: refs/heads/master")
        self.assertEqual(item["value"], "source")
        self.assertEqual(item["status"], 200)

    def test_env_config(self):
        item = _classify_path("/.env", 200, "", "DB_PASSWORD=xxx")
        self.assertEqual(item["value"], "config")

    def test_actuator_monitor(self):
        item = _classify_path("/actuator/env", 200, "", '{"propertySources":[]}')
        self.assertEqual(item["value"], "monitor")

    def test_swagger_api_doc(self):
        item = _classify_path("/swagger-ui.html", 200, "Swagger UI", "")
        self.assertEqual(item["value"], "api_doc")

    def test_upload(self):
        item = _classify_path("/upload", 200, "", "upload")
        self.assertEqual(item["value"], "upload")


class DetectComponentsTest(unittest.TestCase):
    def test_nginx_and_php(self):
        comps = _detect_components(
            {"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
            "<html>welcome</html>",
        )
        names = {c["name"] for c in comps}
        self.assertIn("nginx", names)
        self.assertIn("php", names)

    def test_thinkphp_body(self):
        comps = _detect_components({}, "<html>ThinkPHP V5.0</html>")
        names = {c["name"] for c in comps}
        self.assertIn("thinkphp", names)

    def test_ruoyi_body(self):
        comps = _detect_components({}, "<html>若依管理系统</html>")
        names = {c["name"] for c in comps}
        self.assertIn("ruoyi", names)

    def test_empty(self):
        self.assertEqual(_detect_components({}, ""), [])


class ExtractVersionsTest(unittest.TestCase):
    def test_server_version(self):
        vers = _extract_versions({"Server": "nginx/1.18.0"}, "")
        self.assertIn("nginx/1.18.0", {f"{v['component']}/{v['version']}" for v in vers})

    def test_php_version(self):
        vers = _extract_versions({"X-Powered-By": "PHP/7.4.3"}, "")
        self.assertIn("php/7.4.3", {f"{v['component']}/{v['version']}" for v in vers})


class MatchKnownVulnsTest(unittest.TestCase):
    def test_thinkphp_matches(self):
        vulns = _match_known_vulns(
            [{"name": "thinkphp", "category": "framework", "evidence": "x"}],
            [],
        )
        self.assertTrue(any(v["name"].startswith("ThinkPHP") for v in vulns))
        self.assertEqual(vulns[0]["cve"], "CVE-2018-1002015")

    def test_intel_fingerprint_matches(self):
        # intel 指纹标识也能命中（如编排层 detect_fingerprints 的产物）
        vulns = _match_known_vulns([], ["framework_springboot"])
        self.assertTrue(any("Actuator" in v["name"] for v in vulns))

    def test_no_match(self):
        self.assertEqual(_match_known_vulns([{"name": "unknown", "category": "x", "evidence": ""}], []), [])


class FingerprintOfflineTest(unittest.TestCase):
    def test_offline_fingerprint(self):
        res = fingerprint(
            headers={"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4.3"},
            body="<html><title>XX大学教务管理系统</title>ThinkPHP V5.0</html>",
            title="XX大学教务管理系统",
        )
        self.assertTrue(res["ok"])
        names = {c["name"] for c in res["components"]}
        self.assertIn("nginx", names)
        self.assertIn("thinkphp", names)
        self.assertTrue(any(v["name"].startswith("ThinkPHP") for v in res["known_vulns"]))

    def test_offline_waf(self):
        res = fingerprint(
            headers={"Server": "nginx", "X-Powered-By": "PHP/7.4.3"},
            body="<html>cloudflare ray id: 123</html>",
        )
        self.assertTrue(res["ok"])
        self.assertTrue(res["waf"]["detected"])

    def test_empty_returns_ok(self):
        res = fingerprint(headers={}, body="")
        self.assertTrue(res["ok"])
        self.assertEqual(res["components"], [])


class AssetDiscoveryArgTest(unittest.TestCase):
    def test_bad_target(self):
        res = asset_discovery("", "subdomain")
        self.assertFalse(res["ok"])
        self.assertEqual(res["kind"], "arg_error")

    def test_bad_enum_type_falls_back(self):
        # 非法 enum_type 回退 subdomain；无引擎 key 时走 DNS 回退，仍返回 ok
        res = asset_discovery("example.invalid", "bogus", api_key="", max_results=5)
        self.assertTrue(res["ok"])
        self.assertEqual(res["enum_type"], "subdomain")


if __name__ == "__main__":
    unittest.main()
