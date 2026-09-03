"""测试：worker 挖掘中 session_set 成功后自动标记『已注入会话』并 emit auth_status。"""
import pytest
from unittest import mock

from app.agents.worker import Worker
from app.tools.executor import ToolExecutor


def _make_worker(emits=None):
    emits = emits if emits is not None else []
    w = object.__new__(Worker)
    w.executor = object.__new__(ToolExecutor)
    w.executor._session_cookies = {}
    w.executor._session_headers = {}
    w.target = "https://t.example.com/"
    w.target_meta = {}
    w.emits = emits
    w._emit = lambda kind, **kw: emits.append((kind, kw))
    return w


def test_session_set_success_marks_injected_and_emits_auth_status():
    w = _make_worker()
    # 直接调用辅助方法：先给 executor 灌一个 cookie
    w.executor._session_cookies["JSESSIONID"] = "abc"
    w._autotag_injected_if_session()

    auth_events = [e for e in w.emits if e[0] == "auth_status"]
    assert auth_events, "应 emit 一次 auth_status"
    data = auth_events[-1][1]
    assert data["status"] == "injected"
    assert data["cookie_names"] == ["JSESSIONID"]
    assert "value" not in str(data), "不应落 cookie 明文"
    # target_meta 已更新，供续挖复用
    assert (w.target_meta.get("auth_attempt") or {}).get("status") == "injected"


def test_session_set_empty_does_not_mark():
    w = _make_worker()
    w._autotag_injected_if_session()  # 无任何会话
    assert not [e for e in w.emits if e[0] == "auth_status"]


def test_already_login_ok_not_downgraded():
    w = _make_worker()
    w.executor._session_cookies["SID"] = "s"
    w.target_meta["auth_attempt"] = {"status": "login_ok"}
    w._autotag_injected_if_session()
    assert (w.target_meta["auth_attempt"]["status"]) == "login_ok"
    # 不重复 emit injected
    assert not [e for e in w.emits if e[0] == "auth_status" and (e[1] or {}).get("status") == "injected"]