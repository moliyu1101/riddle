"""指纹实测验证链测试：结构化探针 / 验证计划渲染 / 探针请求构造 / 证据判定 / executor 接线。

覆盖 verify_chain 纯逻辑（探针命中判定、vrify_plan 生成、证据聚合）与 executor.verify_known_vuln
的参数校验、无探针回落、以及 recon.fingerprint 命中已知漏洞后附带 verify_plan 的接线。
"""
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.tools.verify_chain import (  # noqa: E402
    build_probe_request,
    get_verify_actions,
    has_structured_probes,
    mark_action_result,
    render_verify_plan,
    summarize_evidence,
    _MAX_PROBES,
    _PROBES,
)
from app.tools.recon import _match_known_vulns, _detect_components  # noqa: E402
from app.tools.executor import ToolExecutor  # noqa: E402


class RegistryTest(unittest.TestCase):
    def test_nacos_has_probes(self):
        acts = get_verify_actions("Nacos 认证绕过")
        self.assertTrue(acts)
        self.assertTrue(any("users" in a["path"] for a in acts))
        self.assertLessEqual(len(acts), _MAX_PROBES)

    def test_fuzzy_match(self):
        self.assertTrue(get_verify_actions("我的站点有 Nacos 认证绕过"))  # 宽松包含
        self.assertTrue(has_structured_probes("Spring Boot Actuator 未授权访问"))

    def test_unknown_vuln_no_probes(self):
        self.assertIsNone(get_verify_actions("MySQL 弱口令"))
        self.assertFalse(has_structured_probes("MySQL 弱口令"))

    def test_probes_are_readonly_get(self):
        for name, acts in [
            ("Nacos 认证绕过", None), ("Grafana 任意文件读取", None),
        ]:
            for a in get_verify_actions(name) or []:
                self.assertEqual(a["method"].upper(), "GET")
                self.assertNotIn("body", a)


class PlanRenderTest(unittest.TestCase):
    def test_empty_returns_empty(self):
        self.assertEqual(render_verify_plan([]), "")
        self.assertEqual(render_verify_plan(None), "")

    def test_poc_vuln_renders_probes(self):
        block = render_verify_plan([
            {"name": "Nacos 认证绕过", "risk": "高危", "cve": "CVE-2021-29441"},
        ])
        self.assertIn("指纹已知漏洞实测链", block)
        self.assertIn("verify_known_vuln", block)
        self.assertIn("/nacos/v1/auth/users", block)
        self.assertIn("高危", block)
        # 强调只读 + 不臆断
        self.assertIn("只读探测", block)

    def test_vuln_without_probes_falls_back_to_verify_text(self):
        block = render_verify_plan([
            {"name": "Log4j2 JNDI 注入 RCE", "risk": "严重", "verify": "${jndi:ldap...}回连验证"},
        ])
        self.assertIn("无内置探针", block)
        self.assertNotIn("verify_known_vuln(url=\"Log4j2", block)

    def test_multiple_vulns_each_listed(self):
        block = render_verify_plan([
            {"name": "Nacos 认证绕过", "risk": "高危"},
            {"name": "Apache Shiro 反序列化（Shiro-550）", "risk": "高危"},
        ])
        self.assertIn("Nacos 认证绕过", block)
        self.assertIn("rememberMe", block)


class ProbeRequestTest(unittest.TestCase):
    def test_join_base_and_path(self):
        req = build_probe_request("https://jwgl.example.edu.cn:8443", {
            "method": "GET", "path": "/nacos/v1/auth/users?pageNo=1",
        })
        self.assertEqual(req["method"], "GET")
        self.assertEqual(req["url"], "https://jwgl.example.edu.cn:8443/nacos/v1/auth/users?pageNo=1")

    def test_path_adds_leading_slash(self):
        req = build_probe_request("http://h", {"path": "nacos", "method": "get"})
        self.assertEqual(req["url"], "http://h/nacos")
        self.assertEqual(req["method"], "GET")


class EvidenceTest(unittest.TestCase):
    def test_hit_from_body(self):
        r = mark_action_result(
            {"label": "l", "path": "/p", "expect": ["username", "password"]},
            200, '{"username":"admin","password":"x"}', {},
        )
        self.assertTrue(r["hit"])
        self.assertTrue(r["signal"])
        self.assertIn("username", r["snippet"])

    def test_hit_from_headers(self):
        r = mark_action_result(
            {"label": "l", "path": "/", "expect": ["rememberMe=deleteMe"]},
            200, "", {"Set-Cookie": "JSESSIONID=ab; rememberMe=deleteMe"},
        )
        self.assertTrue(r["hit"])

    def test_status_bad_so_not_hit(self):
        # 特征在但状态 404，不算实锤命中
        r = mark_action_result({"label": "l", "path": "/p", "expect": ["username"]}, 404, "username x", {})
        self.assertFalse(r["hit"])

    def test_no_signal_no_hit(self):
        r = mark_action_result({"label": "l", "path": "/p", "expect": ["password"]}, 200, "just a page", {})
        self.assertFalse(r["hit"])
        self.assertTrue(r["signal"] is False)


class SummaryTest(unittest.TestCase):
    def test_likely_when_any_hit(self):
        s = summarize_evidence([
            {"hit": True, "label": "a", "status": 200},
            {"hit": False, "label": "b", "status": 200},
        ])
        self.assertEqual(s["verdict"], "likely")
        self.assertIn("1/2", s["summary"])

    def test_endpoint_exposed_when_reachable_no_hit(self):
        s = summarize_evidence([
            {"hit": False, "label": "a", "status": 200},
            {"hit": False, "label": "b", "status": 404},
        ])
        self.assertEqual(s["verdict"], "endpoint_exposed")
        self.assertIn("可达", s["summary"])

    def test_negative_when_nothing_reachable(self):
        s = summarize_evidence([
            {"hit": False, "label": "a", "status": 404},
            {"hit": False, "label": "b", "status": 403},
        ])
        self.assertEqual(s["verdict"], "negative")


class ReconIntegrationTest(unittest.TestCase):
    def test_match_nacos_then_plan_has_probe(self):
        vulns = _match_known_vulns(
            [{"name": "nacos", "category": "system", "evidence": "body"}],
            ["mw_nacos"],
        )
        self.assertTrue(any("Nacos 认证绕过" == v["name"] for v in vulns))
        block = render_verify_plan(vulns)
        self.assertIn("/nacos/v1/auth/users", block)

    def test_order_limited(self):
        # 构造大量组件命中，验证长度受限
        vulns = _match_known_vulns([
            {"name": "nacos", "category": "s", "evidence": "x"},
        ], ["mw_nacos", "mw_druid", "api_swagger", "mw_grafana"])
        self.assertLessEqual(len(vulns), 8)


class ExecutorTest(unittest.TestCase):
    def _fake(self, resp):
        fake = MagicMock()
        fake._forbidden_ops = []
        fake.http_request = MagicMock(return_value=resp)
        return fake

    def test_arg_error_missing(self):
        fake = self._fake({})
        res = ToolExecutor.verify_known_vuln(fake, url="https://h", vuln_name="")
        self.assertFalse(res["ok"])
        self.assertEqual(res.get("kind"), "arg_error")

    def test_no_probe_name(self):
        fake = self._fake({})
        res = ToolExecutor.verify_known_vuln(fake, url="https://h", vuln_name="Log4j2 JNDI 注入 RCE")
        self.assertFalse(res["ok"])
        self.assertEqual(res.get("kind"), "no_probe")

    def test_hit_propagates_likely(self):
        fake = self._fake({
            "ok": True, "status_code": 200,
            "body": '{"username":"admin","password":"p","accessToken":"t"}',
            "response_headers": {},
        })
        res = ToolExecutor.verify_known_vuln(fake, url="http://h", vuln_name="Nacos 认证绕过")
        self.assertTrue(res["ok"])
        self.assertEqual(res["verdict"], "likely")
        self.assertTrue(any(p["hit"] for p in res["probes"]))
        self.assertEqual(len(res["probes"]), res["probes_count"])

    def test_network_error_no_crash(self):
        fake = self._fake({"ok": False, "error": "timeout"})
        res = ToolExecutor.verify_known_vuln(fake, url="http://h", vuln_name="Nacos 认证绕过")
        self.assertTrue(res["ok"])  # 探针级失败不崩，聚合返回
        self.assertEqual(res["verdict"], "negative")


class ExpandedProbeRegistryTest(unittest.TestCase):
    """阶段八新增探针：Kibana/Coremail/致远/泛微/通达/WordPress/深信服/WebVPN/ES/Solr/Zabbix。"""

    NEW_VULN_NAMES = [
        "Kibana 远程代码执行",
        "Coremail 配置信息泄露",
        "致远 A8 任意文件上传/未授权",
        "泛微 e-cology SQL 注入/文件上传",
        "通达 OA 任意文件上传/包含",
        "WordPress 插件/主题已知漏洞",
        "深信服 SSL VPN 未授权访问",
        "WebVPN 未授权/信息泄露",
        "Elasticsearch 未授权访问",
        "Apache Solr 远程代码执行",
        "Zabbix 未授权访问",
    ]

    def test_all_new_vulns_have_probes(self):
        for name in self.NEW_VULN_NAMES:
            self.assertTrue(get_verify_actions(name), f"{name} 应有结构化探针")
            self.assertTrue(has_structured_probes(name), f"{name} has_structured_probes 应为 True")

    def test_all_new_probes_are_readonly_get(self):
        for name in self.NEW_VULN_NAMES:
            for a in get_verify_actions(name) or []:
                self.assertEqual(a["method"].upper(), "GET", f"{name} 探针应为 GET")
                self.assertNotIn("body", a, f"{name} 探针不应有 body")

    def test_probe_count_le_max(self):
        for name in self.NEW_VULN_NAMES:
            acts = get_verify_actions(name)
            self.assertLessEqual(len(acts), _MAX_PROBES, f"{name} 探针数超限")

    def test_probe_has_expect(self):
        for name in self.NEW_VULN_NAMES:
            for a in get_verify_actions(name) or []:
                self.assertTrue(a.get("expect"), f"{name} 探针 {a.get('label')} 缺 expect")
                self.assertTrue(a.get("path"), f"{name} 探针 {a.get('label')} 缺 path")

    def test_probe_registry_total(self):
        self.assertGreaterEqual(len(_PROBES), 23)

    def test_fuzzy_match_new(self):
        self.assertTrue(get_verify_actions("我的 Kibana 远程代码执行"))
        self.assertTrue(get_verify_actions("Elasticsearch 未授权"))

    def test_unknown_still_no_probe(self):
        self.assertIsNone(get_verify_actions("Tomcat Ghostcat"))
        self.assertIsNone(get_verify_actions("Log4j2 JNDI 注入 RCE"))


class NewComponentDetectionTest(unittest.TestCase):
    """新增组件标识符能被 _detect_components 正确识别。"""

    def test_elasticsearch_from_body(self):
        comps = _detect_components({}, '{"cluster_name":"es","version":{},"tagline":"You Know, for Search"}')
        names = [c["name"] for c in comps]
        self.assertIn("elasticsearch", names)

    def test_solr_from_body(self):
        comps = _detect_components({}, '<html><title>Solr Admin</title></html>')
        names = [c["name"] for c in comps]
        self.assertIn("solr", names)

    def test_zabbix_from_body(self):
        comps = _detect_components({}, '<html><title>Zabbix</title></html>')
        names = [c["name"] for c in comps]
        self.assertIn("zabbix", names)


class NewKnownVulnsMatchTest(unittest.TestCase):
    """新增漏洞条目能被 _match_known_vulns 正确匹配并生成 verify_plan。"""

    def test_es_matches_and_has_probes(self):
        vulns = _match_known_vulns(
            [{"name": "elasticsearch", "category": "db", "evidence": "body"}],
            ["db_elasticsearch"],
        )
        matched = [v for v in vulns if "Elasticsearch" in v["name"]]
        self.assertEqual(len(matched), 1)
        block = render_verify_plan(matched)
        self.assertIn("verify_known_vuln", block)
        self.assertIn("_cat/indices", block)

    def test_solr_matches_and_has_probes(self):
        vulns = _match_known_vulns(
            [{"name": "solr", "category": "system", "evidence": "body"}],
            ["mw_solr"],
        )
        matched = [v for v in vulns if "Solr" in v["name"]]
        self.assertEqual(len(matched), 1)
        block = render_verify_plan(matched)
        self.assertIn("/solr/admin/", block)

    def test_zabbix_matches_and_has_probes(self):
        vulns = _match_known_vulns(
            [{"name": "zabbix", "category": "system", "evidence": "body"}],
            ["mw_zabbix"],
        )
        matched = [v for v in vulns if "Zabbix" in v["name"]]
        self.assertEqual(len(matched), 1)
        block = render_verify_plan(matched)
        self.assertIn("/api_jsonrpc.php", block)

    def test_wordpress_matches_and_has_probes(self):
        vulns = _match_known_vulns(
            [{"name": "wordpress", "category": "cms", "evidence": "body"}],
            ["cms_wordpress"],
        )
        matched = [v for v in vulns if "WordPress" in v["name"]]
        self.assertEqual(len(matched), 1)
        block = render_verify_plan(matched)
        self.assertIn("wp-json", block)


class NewProbeRequestTest(unittest.TestCase):
    """新增探针的 URL 拼接正确。"""

    def test_es_root_probe(self):
        req = build_probe_request("http://es:9200", {"method": "GET", "path": "/"})
        self.assertEqual(req["url"], "http://es:9200/")

    def test_solr_admin_probe(self):
        req = build_probe_request("http://solr:8983", {"method": "GET", "path": "/solr/admin/"})
        self.assertEqual(req["url"], "http://solr:8983/solr/admin/")

    def test_es_cat_indices_with_query(self):
        acts = get_verify_actions("Elasticsearch 未授权访问")
        cat_act = next(a for a in acts if "_cat/indices" in a["path"])
        req = build_probe_request("http://es:9200", cat_act)
        self.assertIn("_cat/indices", req["url"])


class NewProbeEvidenceTest(unittest.TestCase):
    """新增探针的命中判定。"""

    def test_es_cluster_hit(self):
        body = '{"cluster_name":"my-cluster","version":{"number":"7.10.0","lucene_version":"8.7.0"},"tagline":"You Know, for Search"}'
        r = mark_action_result(
            {"label": "集群信息", "path": "/", "expect": ["cluster_name", "version", "tagline"]},
            200, body, {},
        )
        self.assertTrue(r["hit"])
        self.assertIn("cluster_name", r["snippet"])

    def test_solr_admin_hit(self):
        body = '<html><head><title>Solr Admin</title></head><body>solr-admin dashboard</body></html>'
        r = mark_action_result(
            {"label": "Solr 管理页", "path": "/solr/admin/", "expect": ["solr", "solr-admin", "dashboard"]},
            200, body, {},
        )
        self.assertTrue(r["hit"])

    def test_wordpress_users_hit(self):
        body = '[{"id":1,"name":"admin","slug":"admin","avatar_urls":{}}]'
        r = mark_action_result(
            {"label": "用户枚举", "path": "/wp-json/wp/v2/users", "expect": ["id", "name", "slug", "avatar_urls"]},
            200, body, {},
        )
        self.assertTrue(r["hit"])

    def test_kibana_status_hit(self):
        body = '{"name":"kibana","version":{"number":"7.10.0"},"kbn":{"version":"7.10.0"},"cluster_uuid":"abc"}'
        r = mark_action_result(
            {"label": "版本状态", "path": "/api/status", "expect": ["version", "kbn", "cluster_uuid"]},
            200, body, {},
        )
        self.assertTrue(r["hit"])

    def test_es_negative(self):
        r = mark_action_result(
            {"label": "集群信息", "path": "/", "expect": ["cluster_name", "tagline"]},
            404, "Not Found", {},
        )
        self.assertFalse(r["hit"])


if __name__ == "__main__":
    unittest.main()