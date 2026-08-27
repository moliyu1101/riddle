"""查询条件解析分析单测。"""
from __future__ import annotations

from app.agents.query_analyzer import analyze_query


def test_analyze_fofa_domain_and_title():
    r = analyze_query("fofa", 'title="统一身份认证" && domain=".edu.cn"', "edusrc")
    assert r["looks_like_syntax"] is True
    assert r["token_count"] == 2
    assert r["fields"] == ["title", "domain"]
    assert r["keywords"]["domain"] == ["edu.cn"]       # 前导点被去掉
    assert r["keywords"]["title"] == ["统一身份认证"]
    assert "按域名 edu.cn + 标题 统一身份认证 搜索" in r["summary"]
    assert r["issues"] == []


def test_analyze_unknown_field_warns():
    r = analyze_query("fofa", 'foo="bar" && title="x"', "edusrc")
    assert any("foo" in i and "不是 fofa 的官方字段" in i for i in r["issues"])


def test_analyze_balance_issues():
    r = analyze_query("fofa", 'title="x" && (domain="a.edu.cn"', "edusrc")
    assert any("括号不匹配" in i for i in r["issues"])
    r2 = analyze_query("fofa", 'title="x', "edusrc")
    assert any("双引号未闭合" in i for i in r2["issues"])


def test_analyze_intent_mode():
    r = analyze_query("fofa", "找全国高校的统一身份认证系统", "edusrc", intent_mode="intent")
    assert r["looks_like_syntax"] is False
    assert "意图模式" in r["summary"]


def test_analyze_empty_and_plain_text():
    assert analyze_query("fofa", "", "edusrc")["token_count"] == 0
    r = analyze_query("fofa", "随便一句话不是语法", "edusrc")
    assert r["looks_like_syntax"] is False
    assert "自然语言意图" in r["summary"]


def test_analyze_engine_specific_fields():
    r = analyze_query("hunter", 'web.title="OA" && domain.suffix="edu.cn"', "edusrc")
    assert r["token_count"] == 2
    assert r["keywords"]["domain"] == ["edu.cn"]
    assert r["issues"] == []


def test_analyze_org_and_port():
    r = analyze_query("fofa", 'org="示例集团" && port="8080"', "enterprise")
    assert r["keywords"]["org"] == ["示例集团"]
    assert r["keywords"]["port"] == ["8080"]


def test_analyze_colon_syntax_quake():
    r = analyze_query("quake", 'title:"登录" AND domain:"edu.cn"', "edusrc")
    assert r["looks_like_syntax"] is True
    assert r["token_count"] == 2
    assert r["keywords"]["domain"] == ["edu.cn"]
    assert r["keywords"]["title"] == ["登录"]
    assert r["syntax_mismatch"] == ""
    assert r["issues"] == []


def test_analyze_colon_syntax_censys():
    r = analyze_query("censys", 'host.services.http.response.html_title:"Login" and host.dns.names: edu.cn', "edusrc")
    assert r["looks_like_syntax"] is True
    assert r["token_count"] == 2
    assert r["keywords"]["title"] == ["Login"]
    assert r["keywords"]["domain"] == ["edu.cn"]


def test_analyze_http_url_not_misparsed():
    # http:// 里的冒号不能被当成字段条件
    r = analyze_query("fofa", "https://example.edu.cn 的登录页", "edusrc")
    assert r["looks_like_syntax"] is False


def test_analyze_syntax_mismatch_fofa_query_on_quake():
    r = analyze_query("quake", 'title="登录" && domain="edu.cn"', "edusrc")
    assert r["syntax_mismatch"] != ""
    assert any("冒号" in i for i in r["issues"])


def test_analyze_syntax_mismatch_colon_query_on_fofa():
    r = analyze_query("fofa", 'title:"登录" AND domain:"edu.cn"', "edusrc")
    assert r["syntax_mismatch"] != ""
    assert any("等号" in i for i in r["issues"])


def test_analyze_mixed_style_warns():
    r = analyze_query("quake", 'title="登录" AND domain:"edu.cn"', "edusrc")
    assert r["token_count"] == 2
    assert any("混用" in i for i in r["issues"])


def test_analyze_field_sheet_and_engine_hint():
    r = analyze_query("fofa", "", "edusrc")
    assert r["engine_hint"] != ""
    assert any(f["field"] == "title" for f in r["field_sheet"])
    rq = analyze_query("quake", "", "edusrc")
    assert any(f["field"] == "service.name" for f in rq["field_sheet"])


def test_analyze_tokens_detail():
    r = analyze_query("fofa", 'title="登录" && domain="edu.cn"', "edusrc")
    assert r["tokens_detail"][0]["field"] == "title"
    assert r["tokens_detail"][0]["op"] == "="
    assert r["tokens_detail"][1]["value"] == "edu.cn"
