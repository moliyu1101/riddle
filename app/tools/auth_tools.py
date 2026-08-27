"""凭证爆破与登录态自动化（阶段三）：弱口令验证 + 登录态保持 + 登录表单侦察。

背景：登录后深挖（越权/敏感数据/写操作）是差异化来源，但此前登录依赖用户手填
Cookie/账密，Worker 拿到登录入口后缺少「系统化弱口令验证 + 登录态自动化」工具。

本模块提供三个工具（纯规则确定性实现，可单测）：
1. credential_brute  弱口令验证：内置分层字典 + 登录表单识别 + 成功判定 + 限速限量
2. login_session     登录态自动化：自动登录并保持会话，后续 http_request 自动携带
3. login_form_scan   登录入口/表单侦察：探测登录路径、识别字段、检测验证码、给构造建议

安全约束：
- 内置小字典 + 默认限量（max_attempts=20）+ 限速（delay），检测验证码/锁定即停，防 DoS。
- 走任务禁止操作硬拦（任务规则禁止爆破则整体拦截）。
- 只对授权目标做无害验证；登录成功本身不是洞，深挖才算。
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from app.agents.auth_bootstrap import _extract_login_form, _judge_login_success

# ============ 内置数据 ============
# 通用弱口令（政企/系统默认口令高频）
_GENERIC_WEAK_PASSWORDS: tuple[str, ...] = (
    "admin", "admin123", "admin888", "admin@123", "Admin@123", "admin123456",
    "123456", "12345678", "123456789", "1234567890", "123123", "123qwe",
    "abc123", "qwe123", "1q2w3e4r", "1qaz2wsx", "000000", "111111", "666666",
    "888888", "999999", "password", "password123", "Passw0rd", "P@ssw0rd",
    "root", "root123", "test", "test123", "guest", "guest123", "user",
    "user123", "admin1", "admin1234", "Aa123456", "a123456", "123456a",
    "admin2023", "admin2024", "123456789a",
)

# 教育场景弱口令（学号/工号常见弱口令，不含个人信息推导）
_EDU_WEAK_PASSWORDS: tuple[str, ...] = (
    "123456", "12345678", "123456789", "1234567890", "000000", "111111",
    "666666", "888888", "123123", "abc123", "123qwe", "1q2w3e4r",
    "Aa123456", "a123456", "123456a", "password", "123456789a",
)

# 常见登录路径（登录入口发现用）
_LOGIN_PATHS: tuple[str, ...] = (
    "/login", "/user/login", "/admin/login", "/account/login", "/signin",
    "/login.jsp", "/admin", "/system/login", "/api/login", "/api/user/login",
    "/api/auth/login", "/cas/login", "/sso/login", "/portal/login",
    "/index/login", "/login/index", "/auth/login",
)

# 验证码/锁定特征（命中即停止爆破）
_CAPTCHA_MARKERS = (
    "验证码", "图形验证", "滑动验证", "captcha", "verification code",
    "太多次", "尝试次数过多", "锁定", "locked", "too many", "account locked",
)

# ============ 工具函数 ============
def _strip(s: Any) -> str:
    return str(s or "").strip()


def _origin_of(url: str) -> str:
    from app.urlnorm import ensure_scheme, safe_urlparse
    u = ensure_scheme(_strip(url))
    p = safe_urlparse(u)
    return f"{p.scheme or 'http'}://{p.netloc}" if p.netloc else u


def _identify_form_fields(fields: dict[str, str]) -> dict[str, list[str]]:
    """从表单字段里识别用户名/密码/验证码字段名。"""
    user_keys = [k for k in fields if re.search(r"(?i)user|account|login|email|name", k)]
    pass_keys = [k for k in fields if re.search(r"(?i)pass|pwd", k)]
    captcha_keys = [k for k in fields if re.search(r"(?i)captcha|verify|code|验证码", k)]
    return {"user": user_keys, "pass": pass_keys, "captcha": captcha_keys}


def _has_captcha(body: str, fields: dict[str, str]) -> tuple[bool, str]:
    """检测登录页/表单是否含验证码，返回 (是否, 依据)。"""
    low = (body or "").lower()
    for m in _CAPTCHA_MARKERS:
        if m.lower() in low:
            return True, f"页面含 `{m}`"
    if fields:
        ident = _identify_form_fields(fields)
        if ident["captcha"]:
            return True, f"表单含验证码字段 {ident['captcha']}"
    return False, ""


def _build_password_list(
    username: str,
    passwords: Optional[list[str]],
    use_builtin: bool,
    edu_mode: bool,
) -> list[str]:
    """组装密码候选：用户指定 + 内置字典 + 基于用户名的变体（去重保序）。"""
    out: list[str] = []
    seen: set[str] = set()
    for p in (passwords or []):
        p = _strip(p)
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    if use_builtin:
        base = _EDU_WEAK_PASSWORDS if edu_mode else _GENERIC_WEAK_PASSWORDS
        for p in base:
            if p not in seen:
                seen.add(p)
                out.append(p)
    # 基于用户名的变体
    u = _strip(username)
    if u:
        for p in (u, f"{u}123", f"{u}123456", f"{u}@123", f"{u}888", f"{u}2023", f"{u}2024"):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _try_login_once(
    executor: Any,
    login_url: str,
    username: str,
    password: str,
    form: Optional[dict[str, Any]],
    origin: str,
) -> dict[str, Any]:
    """单次登录尝试。成功保留会话；失败清空会话防累积串号。"""
    executor.session_set(clear=True)
    try:
        if form:
            data = dict(form.get("fields") or {})
            ident = _identify_form_fields(data)
            user_key = ident["user"][0] if ident["user"] else "username"
            pass_key = ident["pass"][0] if ident["pass"] else "password"
            data[user_key] = username
            data[pass_key] = password
            body_enc = "&".join(f"{_q(k)}={_q(v)}" for k, v in data.items())
            post = executor.http_request(
                form.get("action") or login_url,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=body_enc,
                follow_redirects=True,
                timeout=20,
            )
        else:
            post = executor.http_request(
                login_url,
                method="POST",
                json_body={
                    "username": username, "password": password,
                    "userName": username, "account": username,
                },
                follow_redirects=True,
                timeout=20,
            )
        verdict = _judge_login_success(executor, post, origin)
        if verdict.get("ok"):
            return {"ok": True, "reason": verdict.get("reason", "")}
        return {"ok": False, "reason": verdict.get("reason", "")}
    except Exception as e:
        return {"ok": False, "reason": f"请求异常: {type(e).__name__}: {e}"}


def _q(s: str) -> str:
    from urllib.parse import quote_plus
    return quote_plus(str(s), safe="")


# ============ 工具 1：凭证爆破（弱口令验证） ============
def credential_brute(
    executor: Any,
    login_url: str = "",
    username: str = "",
    usernames: Optional[list[str]] = None,
    passwords: Optional[list[str]] = None,
    use_builtin_dict: bool = True,
    max_attempts: int = 20,
    delay: float = 0.5,
    edu_mode: bool = False,
) -> dict[str, Any]:
    """弱口令验证：内置分层字典 + 表单识别 + 成功判定 + 限速限量。

    只对授权目标做无害验证；检测验证码/锁定即停止；默认限量防 DoS。
    """
    url = _strip(login_url)
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "必须传 login_url。"}
    user_list = [u for u in (_strip(x) for x in (usernames or [])) if u]
    if username and username not in user_list:
        user_list.insert(0, username)
    if not user_list:
        user_list = ["admin"]
    origin = _origin_of(url)

    # 打开登录页识别表单（失败则走 JSON 登录）
    form = None
    try:
        get_r = executor.http_request(url, method="GET", follow_redirects=True, timeout=15)
        body = get_r.get("body") or get_r.get("response_body") or ""
        if isinstance(body, bytes):
            body = body.decode("utf-8", "ignore")
        form = _extract_login_form(body, url)
        has_cap, cap_ev = _has_captcha(body, form.get("fields") if form else None)
        if has_cap:
            return {
                "ok": False, "stopped": True,
                "error": f"登录页含验证码/锁定机制（{cap_ev}），停止爆破。可人工过验证码后提供 Cookie，或用 login_form_scan 看绕过思路。",
            }
    except Exception:
        pass

    # 组装候选：用户名 × 密码（限量）
    candidates: list[tuple[str, str]] = []
    for u in user_list:
        for p in _build_password_list(u, passwords, use_builtin_dict, edu_mode):
            candidates.append((u, p))
    candidates = candidates[: max(1, min(int(max_attempts), 40))]

    found: list[dict[str, str]] = []
    stopped_reason = ""
    session_snap = executor.snapshot_session()
    for i, (u, p) in enumerate(candidates):
        if i > 0 and delay > 0:
            time.sleep(min(delay, 1.0))
        r = _try_login_once(executor, url, u, p, form, origin)
        if r.get("ok"):
            found.append({"username": u, "password": p})
            break  # 命中即停，保留会话
        reason = r.get("reason", "")
        if re.search(r"(?i)验证码|captcha|锁定|locked|too many", reason):
            stopped_reason = f"触发验证码/锁定机制：{reason}"
            break

    if found:
        return {
            "ok": True,
            "found": found,
            "attempts": len(candidates),
            "session_kept": True,
            "guidance": (
                f"弱口令命中 {found[0]['username']}，会话已保持，后续 http_request 自动携带登录态。"
                "登录成功本身不是洞：继续深挖越权/敏感数据/写操作才算。"
            ),
        }
    executor.restore_session(session_snap)
    return {
        "ok": True,
        "found": [],
        "attempts": len(candidates),
        "stopped_reason": stopped_reason or "全部尝试未命中",
        "session_restored": True,
        "guidance": (
            "未命中弱口令，原会话已恢复。不要无限制爆破：换登录入口/查泄露凭证/测未授权面，"
            "或确认是否需验证码后人工提供 Cookie。"
        ),
    }


# ============ 工具 2：登录态自动化 ============
def login_session(
    executor: Any,
    login_url: str = "",
    username: str = "",
    password: str = "",
) -> dict[str, Any]:
    """登录态自动化：自动登录并保持会话，后续 http_request 自动携带。"""
    url = _strip(login_url)
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "必须传 login_url。"}
    if not (_strip(username) and _strip(password)):
        return {"ok": False, "kind": "arg_error", "error": "必须传 username 和 password。"}
    from app.agents.auth_bootstrap import try_user_login

    session_snap = executor.snapshot_session()
    res = try_user_login(executor, url, _strip(username), _strip(password))
    if res.get("ok"):
        cookies = sorted(getattr(executor, "_session_cookies", {}).keys())
        return {
            "ok": True,
            "status": "login_ok",
            "reason": res.get("reason", ""),
            "session_cookies": cookies,
            "guidance": (
                "登录成功，会话已保持。登录成功本身不是洞：继续深挖越权/敏感数据/写操作，"
                "把登录态当入场券。"
            ),
        }
    executor.restore_session(session_snap)
    return {
        "ok": False,
        "status": "login_fail",
        "reason": res.get("reason") or res.get("error") or "登录失败",
        "session_restored": True,
        "guidance": "登录未成功，原会话已恢复：换登录入口/查泄露凭证/测未授权面，勿反复空撞同一接口。",
    }


# ============ 工具 3：登录入口/表单侦察 ============
def login_form_scan(
    executor: Any,
    url: str = "",
    max_paths: int = 8,
) -> dict[str, Any]:
    """登录入口/表单侦察：探测常见登录路径，识别表单字段/验证码，给构造建议。"""
    base = _strip(url)
    if not base:
        return {"ok": False, "kind": "arg_error", "error": "必须传目标 URL。"}
    origin = _origin_of(base)
    found_paths: list[dict[str, Any]] = []
    seen: set[str] = set()

    candidates = [base] + [urljoin(origin + "/", p.lstrip("/")) for p in _LOGIN_PATHS]
    for page_url in candidates[: max(1, min(int(max_paths), 12))]:
        if page_url in seen:
            continue
        seen.add(page_url)
        try:
            r = executor.http_request(page_url, method="GET", follow_redirects=True, timeout=12)
            if not r.get("ok"):
                continue
            status = int(r.get("status_code") or 0)
            body = r.get("body") or r.get("response_body") or ""
            if isinstance(body, bytes):
                body = body.decode("utf-8", "ignore")
            low = body.lower()
            has_login_form = bool(_extract_login_form(body, page_url))
            loginish = bool(re.search(r"(?i)登录|login|signin|用户名|密码|password", low))
            if status in (200, 302, 301) and (has_login_form or loginish):
                form = _extract_login_form(body, page_url)
                fields = list((form.get("fields") or {}).keys()) if form else []
                has_cap, cap_ev = _has_captcha(body, form.get("fields") if form else None)
                found_paths.append({
                    "url": page_url,
                    "status": status,
                    "has_form": bool(form),
                    "fields": fields[:12],
                    "has_captcha": has_cap,
                    "captcha_evidence": cap_ev,
                })
        except Exception:
            continue

    if not found_paths:
        return {
            "ok": True,
            "found": [],
            "guidance": "未发现明显登录入口。可能走 SSO/CAS 单点、或登录在 JS 里动态加载；用 http_request 看首页/JS 里的登录接口。",
        }

    best = found_paths[0]
    suggested = ""
    if best.get("has_form"):
        suggested = "username=<账号>&password=<密码>"
    return {
        "ok": True,
        "found": found_paths,
        "suggested_payload": suggested,
        "guidance": (
            "登录入口已定位。若 has_captcha=False 且 has_form=True，可直接用 credential_brute 做弱口令验证"
            "（限量限速）；有验证码则人工过验证码后提供 Cookie 用 session_set 登记。"
        ),
    }
