"""批量登录凭据解析：parse_auth_batch / preview_auth_batch 的格式覆盖与边界。"""
from __future__ import annotations

from app.agents.auth_bootstrap import (
    _parse_auth_line,
    parse_auth_batch,
    preview_auth_batch,
)


def _kinds(bindings):
    return [sorted(b.get("kinds") or []) for b in bindings]


def test_user_pass_colon():
    out = parse_auth_batch("admin:admin123\nroot:toor")
    assert len(out) == 2
    assert out[0]["username"] == "admin"
    assert out[0]["password"] == "admin123"
    assert out[0]["target"] == "*"
    assert out[1]["username"] == "root"


def test_user_pass_slash_comma_space():
    out = parse_auth_batch("a/b\nc,d\ne f")
    assert len(out) == 3
    assert [(b["username"], b["password"]) for b in out] == [
        ("a", "b"), ("c", "d"), ("e", "f"),
    ]


def test_password_with_colon_joins():
    out = parse_auth_batch("admin:pass:word:1")
    assert len(out) == 1
    assert out[0]["username"] == "admin"
    assert out[0]["password"] == "pass:word:1"


def test_target_formats():
    out = parse_auth_batch(
        "example.com|admin|admin123\n"
        "admin:admin123@example.com\n"
        "https://a.edu.cn admin admin123\n"
        "admin:admin123@https://b.edu.cn"
    )
    assert len(out) == 4
    targets = [b["target"] for b in out]
    assert targets[0] == "example.com"
    assert targets[1] == "example.com"
    assert targets[2] == "https://a.edu.cn"
    assert targets[3] == "https://b.edu.cn"
    assert all(b["username"] == "admin" for b in out)


def test_cookie_header():
    out = parse_auth_batch("Cookie: JSESSIONID=abc; other=1")
    assert len(out) == 1
    assert "cookie" in out[0]["kinds"]
    assert out[0]["cookies"]["JSESSIONID"] == "abc"


def test_bare_cookie_string():
    out = parse_auth_batch("JSESSIONID=abc; other=1")
    assert len(out) == 1
    assert "cookie" in out[0]["kinds"]
    assert out[0]["cookies"]["JSESSIONID"] == "abc"


def test_authorization_bearer():
    out = parse_auth_batch("Authorization: Bearer eyJtoken")
    assert len(out) == 1
    assert "bearer" in out[0]["kinds"]
    assert out[0]["headers"]["Authorization"] == "Bearer eyJtoken"


def test_bare_bearer():
    out = parse_auth_batch("Bearer eyJtoken")
    assert len(out) == 1
    assert "bearer" in out[0]["kinds"]


def test_chinese_user_pass():
    out = parse_auth_batch("账号: test 密码: Test@123")
    assert len(out) == 1
    assert out[0]["username"] == "test"
    assert out[0]["password"] == "Test@123"
    assert "password" in out[0]["kinds"]


def test_comments_and_empty_ignored():
    out = parse_auth_batch(
        "# 注释\n"
        "// 注释2\n"
        "; 注释3\n"
        "\n"
        "   \n"
        "admin:admin123"
    )
    assert len(out) == 1
    assert out[0]["username"] == "admin"


def test_url_only_ignored():
    assert parse_auth_batch("https://example.com\nhttp://a.edu.cn/path") == []


def test_host_port_not_misparsed():
    assert parse_auth_batch("example.com:8080\nlocalhost:3000") == []


def test_http_request_line_ignored():
    out = parse_auth_batch("POST /login HTTP/1.1\nadmin:admin123")
    assert len(out) == 1
    assert out[0]["username"] == "admin"


def test_preview_stats():
    res = preview_auth_batch(
        "admin:admin123\n"
        "Cookie: a=1\n"
        "Bearer xyz\n"
        "not a credential line\n"
        "# comment\n"
    )
    assert res["total_lines"] == 4
    assert res["parsed"] == 3
    assert res["ignored_total"] == 1
    assert res["ignored"] == ["not a credential line"]
    assert res["by_kind"] == {"password": 1, "cookie": 1, "bearer": 1}
    assert len(res["bindings"]) == 3


def test_preview_empty():
    res = preview_auth_batch("")
    assert res["total_lines"] == 0
    assert res["parsed"] == 0
    assert res["ignored_total"] == 0
    assert res["bindings"] == []


def test_parse_auth_line_helpers():
    assert _parse_auth_line("admin:admin123") == {"target": "", "username": "admin", "password": "admin123"}
    assert _parse_auth_line("Cookie: a=1") == {"raw": "Cookie: a=1"}
    assert _parse_auth_line("随便一句话") is None
