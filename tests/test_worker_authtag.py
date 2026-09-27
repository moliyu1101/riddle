"""测试：worker 挖掘中 session_set 成功后自动标记『已注入会话』并 emit auth_status。"""
import pytest
from unittest import mock

from app.agents.worker import Worker
from app.tools.executor import ToolExecutor


def _make_worker(emits=None, explicit=None):
    emits = emits if emits is not None else []
    w = object.__new__(Worker)
    w.executor = object.__new__(ToolExecutor)
    w.executor._session_cookies = {}
    w.executor._session_headers = {}
    w.executor._explicit_session_keys = set(explicit or ())
    w.target = "https://t.example.com/"
    w.target_meta = {}
    w.emits = emits
    w._emit = lambda kind, **kw: emits.append((kind, kw))
    return w


def test_session_set_success_marks_injected_and_emits_auth_status():
    w = _make_worker(explicit={"c:JSESSIONID"})
    # 直接调用辅助方法：先给 executor 灌一个「显式登记」的 cookie
    w.executor._session_cookies["JSESSIONID"] = "abc"
    w._autotag_injected_if_session()

    auth_events = [e for e in w.emits if e[0] == "auth_status"]
    assert auth_events, "应 emit 一次 auth_status"
    data = auth_events[-1][1]
    assert data["status"] == "registered", "session_set 后只标已登记未验证，结论由 LLM 上报"
    assert data["cookie_names"] == ["JSESSIONID"]
    assert "value" not in str(data), "不应落 cookie 明文"
    # target_meta 已更新，供续挖复用
    assert (w.target_meta.get("auth_attempt") or {}).get("status") == "registered"


def test_passive_site_cookie_not_marked():
    """被动吸收的站点普通 cookie（如设备会话 TWFID）不标注「凭据注入」——乱注入修复。"""
    w = _make_worker()
    w.executor._session_cookies["TWFID"] = "site-session-cookie"   # 被动吸收，无显式登记
    w._autotag_injected_if_session()
    assert not [e for e in w.emits if e[0] == "auth_status"], "被动 cookie 不应触发凭据注入标记"


def test_resume_marks_with_source_label():
    """断点恢复的历史会话保留标记，但 reason 标注来源。"""
    w = _make_worker()
    w.executor._session_cookies["TWFID"] = "restored"
    w._autotag_injected_if_session(from_resume=True)
    events = [e for e in w.emits if e[0] == "auth_status"]
    assert events and events[-1][1]["status"] == "registered"
    assert "恢复" in events[-1][1]["reason"]


def test_session_set_empty_does_not_mark():
    w = _make_worker()
    w._autotag_injected_if_session()  # 无任何会话
    assert not [e for e in w.emits if e[0] == "auth_status"]


def test_already_login_ok_not_downgraded():
    w = _make_worker(explicit={"c:SID"})
    w.executor._session_cookies["SID"] = "s"
    w.target_meta["auth_attempt"] = {"status": "login_ok"}
    w._autotag_injected_if_session()
    assert (w.target_meta["auth_attempt"]["status"]) == "login_ok"
    # 不重复 emit injected
    assert not [e for e in w.emits if e[0] == "auth_status" and (e[1] or {}).get("status") == "injected"]