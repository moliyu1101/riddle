"""浏览器自动化：让 worker 用真实浏览器执行 JS 渲染页 / 登录后页面的交互操作。

相比 capture_evidence 的"打开即截图"，browser_action 提供完整交互能力：
- open      : 打开 URL，等 JS 渲染，提取页面结构（标题/可见文本/链接/表单/输入框/按钮）
- click     : 点击元素（CSS 选择器或可见文本）
- fill      : 填写输入框
- submit    : 提交表单（按回车或点击按钮）
- extract   : 提取当前页结构
- screenshot: 截图当前页
- wait      : 等待指定毫秒
- close     : 关闭浏览器释放资源

会话与安全：
- 浏览器 context 自动注入 executor 的 _session_cookies / _session_headers
- 浏览器产生的 cookie 同步回 executor._session_cookies（登录态与 http_request 互通）
- 惰性初始化 + idle 超时自动关闭，worker 中断/重启不泄漏浏览器进程
- 域边界：只允许访问目标域及其子域，防止 worker 用浏览器打其它目标
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

# 页面结构提取上限，避免撑爆工具返回载荷。
_MAX_VISIBLE_TEXT = 2500
_MAX_ARIA_SNAPSHOT = 4000
_MAX_LINKS = 40
_MAX_INPUTS = 20
_MAX_BUTTONS = 20
_MAX_FORMS = 10
# 浏览器 idle 超时（秒）：超过则自动关闭释放资源。
_BROWSER_IDLE_TIMEOUT = 120.0
# 单次操作默认超时（秒）。
_DEFAULT_TIMEOUT = 20


def _target_host(target: str) -> str:
    """从 executor.target 提取 host（支持 域名 / URL 两种写法）。"""
    t = (target or "").strip()
    if not t:
        return ""
    if "://" not in t:
        t = "http://" + t
    try:
        return (urlparse(t).hostname or "").strip().lower()
    except Exception:
        return ""


def _url_allowed(url: str, target_host: str) -> bool:
    """域边界校验：只允许访问目标域及其子域（http/https）。"""
    if not url:
        return False
    try:
        u = urlparse(url)
    except Exception:
        return False
    if u.scheme not in ("http", "https"):
        return False
    host = (u.hostname or "").strip().lower()
    if not host:
        return False
    if not target_host:
        return True  # 无目标 host 时不强制限制（本地/测试场景）
    return host == target_host or host.endswith("." + target_host)


def _extract_page(page: Any, max_text: int = _MAX_VISIBLE_TEXT) -> dict[str, Any]:
    """提取当前页面结构：标题/URL/状态/ARIA树/可见文本/链接/表单/输入框/按钮。"""
    out: dict[str, Any] = {}
    try:
        out["url"] = page.url
    except Exception:
        out["url"] = ""
    try:
        out["title"] = (page.title() or "").strip()[:200]
    except Exception:
        out["title"] = ""
    try:
        out["status"] = page.evaluate(
            "() => (performance.getEntriesByType('navigation')[0] || {}).responseStatus || 0"
        ) or 0
    except Exception:
        out["status"] = 0
    # ARIA 可访问性快照：结构化语义树（heading/link/button/input/form 等），
    # 比 innerText 更能让 LLM 理解可交互结构与表单控件（参考 playwright-browser-mcp 规则）。
    try:
        aria = page.aria_snapshot()
        out["aria_snapshot"] = (aria or "").strip()[:_MAX_ARIA_SNAPSHOT]
    except Exception:
        out["aria_snapshot"] = ""
    try:
        text = page.evaluate("() => document.body ? document.body.innerText : ''") or ""
        out["visible_text"] = " ".join(text.split())[:max_text]
    except Exception:
        out["visible_text"] = ""
    try:
        links = page.evaluate(
            "() => Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
        ) or []
        seen: list[str] = []
        for lnk in links:
            if lnk and lnk not in seen:
                seen.append(lnk)
        out["links"] = seen[:_MAX_LINKS]
    except Exception:
        out["links"] = []
    try:
        out["forms"] = (page.evaluate(
            "() => Array.from(document.querySelectorAll('form')).map(f => ({action: f.action, method: f.method}))"
        ) or [])[:_MAX_FORMS]
    except Exception:
        out["forms"] = []
    try:
        out["inputs"] = (page.evaluate(
            "() => Array.from(document.querySelectorAll('input')).map(i => "
            "({name: i.name, type: i.type, id: i.id, placeholder: i.placeholder}))"
        ) or [])[:_MAX_INPUTS]
    except Exception:
        out["inputs"] = []
    try:
        out["buttons"] = (page.evaluate(
            "() => Array.from(document.querySelectorAll('button, input[type=submit], input[type=button]'))"
            ".map(b => (b.innerText || b.value || b.name || '').trim()).filter(Boolean)"
        ) or [])[:_MAX_BUTTONS]
    except Exception:
        out["buttons"] = []
    return out


def _sync_cookies(executor: Any, context: Any) -> int:
    """把浏览器产生的 cookie 同步回 executor 会话 jar（登录态互通）。"""
    try:
        cookies = context.cookies()
    except Exception:
        return 0
    n = 0
    for c in cookies:
        name = c.get("name")
        value = c.get("value")
        if name:
            try:
                executor._put_cookie(str(name), str(value), [])
                n += 1
            except Exception:
                pass
    return n


def _click(page: Any, selector: str = "", text: str = "", timeout: int = _DEFAULT_TIMEOUT) -> None:
    """点击元素：优先 CSS 选择器，其次可见文本。"""
    ms = int(timeout or _DEFAULT_TIMEOUT) * 1000
    if selector:
        loc = page.locator(selector).first
        loc.wait_for(state="visible", timeout=ms)
        loc.click()
        return
    if text:
        loc = page.get_by_text(text, exact=False).first
        loc.wait_for(state="visible", timeout=ms)
        loc.click()
        return
    raise ValueError("click 需要 selector 或 text 至少一个。")


def _fill(page: Any, selector: str, value: str, timeout: int = _DEFAULT_TIMEOUT) -> None:
    if not selector:
        raise ValueError("fill 需要 selector。")
    ms = int(timeout or _DEFAULT_TIMEOUT) * 1000
    loc = page.locator(selector).first
    loc.wait_for(state="visible", timeout=ms)
    loc.fill(str(value or ""))


class BrowserSession:
    """惰性初始化的 Playwright 浏览器会话，跨多次 browser_action 复用。"""

    def __init__(self, executor: Any):
        self._executor = executor
        self._browser: Any = None
        self._context: Any = None
        self._page: Any = None
        self._last_used = 0.0

    def _ensure(self) -> Any:
        """获取或创建浏览器 + context + page（注入会话 cookie/头）。"""
        now = time.time()
        if self._browser is not None:
            self._last_used = now
            return self._page
        from playwright.sync_api import sync_playwright
        p = sync_playwright().start()
        browser = p.chromium.launch(
            headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
        )
        context = browser.new_context(viewport={"width": 1366, "height": 900})
        # 注入已维持的会话 cookie（针对目标域，保证实际访问时生效）。
        cookies = getattr(self._executor, "_session_cookies", None) or {}
        host = _target_host(getattr(self._executor, "target", "") or "")
        if cookies and host:
            try:
                context.add_cookies(
                    [{"name": k, "value": str(v), "url": f"http://{host}"} for k, v in cookies.items()]
                )
            except Exception:
                pass
        page = context.new_page()
        self._p = p
        self._browser = browser
        self._context = context
        self._page = page
        self._last_used = now
        return page

    def is_idle(self) -> bool:
        if self._browser is None:
            return False
        return (time.time() - self._last_used) > _BROWSER_IDLE_TIMEOUT

    def inject_cookies(self) -> int:
        """把 executor 会话 cookie 同步到浏览器 context（幂等，浏览器已存在时也生效）。

        浏览器会话跨调用保持，session_set 新增的 cookie 也要能注入到已打开的 context。
        """
        if self._context is None:
            return 0
        cookies = getattr(self._executor, "_session_cookies", None) or {}
        host = _target_host(getattr(self._executor, "target", "") or "")
        if not cookies or not host:
            return 0
        try:
            self._context.add_cookies(
                [{"name": k, "value": str(v), "url": f"http://{host}"} for k, v in cookies.items()]
            )
            return len(cookies)
        except Exception:
            return 0

    def close(self) -> None:
        try:
            if self._browser is not None:
                self._browser.close()
        except Exception:
            pass
        try:
            if getattr(self, "_p", None) is not None:
                self._p.stop()
        except Exception:
            pass
        self._browser = None
        self._context = None
        self._page = None
        self._last_used = 0.0


def browser_action(
    executor: Any,
    action: str = "",
    url: str = "",
    selector: str = "",
    text: str = "",
    value: str = "",
    wait_ms: int = 0,
    timeout: int = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """browser_action 工具实现：分发到具体浏览器操作。"""
    action = (action or "").strip().lower()
    if action not in ("open", "click", "fill", "submit", "extract", "screenshot", "wait", "close"):
        return {
            "ok": False,
            "kind": "arg_error",
            "error": f"未知 action: {action}。可选 open/click/fill/submit/extract/screenshot/wait/close。",
        }
    target_host = _target_host(getattr(executor, "target", "") or "")
    if url and not _url_allowed(url, target_host):
        return {
            "ok": False,
            "blocked": True,
            "error": f"目标域边界拦截：{url} 不在目标域（{target_host or '未指定'}）及其子域内。浏览器只允许访问目标域。",
        }
    session: BrowserSession = getattr(executor, "_browser_session", None)
    if session is None:
        session = BrowserSession(executor)
        executor._browser_session = session
    if session.is_idle():
        session.close()
    try:
        page = session._ensure()
    except Exception as e:
        return {"ok": False, "error": f"浏览器启动失败: {type(e).__name__}: {e}"}
    session.inject_cookies()  # 每次操作前同步 executor 会话 cookie（含 session_set 新增的）

    try:
        if action == "open":
            if not url:
                return {"ok": False, "kind": "arg_error", "error": "open 需要 url。"}
            page.goto(url, timeout=int(timeout or _DEFAULT_TIMEOUT) * 1000, wait_until="domcontentloaded")
            page.wait_for_timeout(1200)  # 等 JS 渲染 / 懒加载
            page.wait_for_load_state("networkidle", timeout=5000)
        elif action == "click":
            _click(page, selector=selector, text=text, timeout=timeout)
            page.wait_for_timeout(800)
        elif action == "fill":
            _fill(page, selector, value, timeout=timeout)
        elif action == "submit":
            if selector:
                _click(page, selector=selector, timeout=timeout)
            else:
                page.locator("form").first.press("Enter")
            page.wait_for_timeout(1200)
        elif action == "wait":
            page.wait_for_timeout(int(wait_ms or 0))
        elif action == "screenshot":
            base = Path(executor.work_dir) / "evidence" / "screenshots"
            base.mkdir(parents=True, exist_ok=True)
            ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
            name = f"browser_{ts}_{abs(hash(page.url)) % 10000}.png"
            path = base / name
            page.screenshot(path=str(path), full_page=False)
            n_cookies = _sync_cookies(executor, session._context)
            return {
                "ok": True,
                "action": action,
                "url": page.url,
                "ref": f"evidence/screenshots/{name}",
                "path": str(path),
                "cookies_synced": n_cookies,
                "elapsed": round(time.time() - session._last_used, 2),
                "guidance": "截图已保存，可用 capture_evidence 或报告引用该 ref。",
            }
        elif action == "close":
            session.close()
            return {"ok": True, "action": action, "message": "浏览器已关闭，资源已释放。"}

        n_cookies = _sync_cookies(executor, session._context)
        page_info = _extract_page(page)
        summary_lines = [
            f"浏览器 {action} 完成 @ {page_info.get('url') or '-'}",
            f"标题: {page_info.get('title') or '-'} | HTTP {page_info.get('status') or '-'}",
        ]
        if page_info.get("aria_snapshot"):
            summary_lines.append(f"ARIA 结构树: {page_info['aria_snapshot'][:600]}")
        if page_info.get("visible_text"):
            summary_lines.append(f"可见文本: {page_info['visible_text'][:400]}")
        if page_info.get("links"):
            summary_lines.append(f"链接({len(page_info['links'])}): " + "; ".join(page_info["links"][:8]))
        if page_info.get("inputs"):
            summary_lines.append(
                f"输入框({len(page_info['inputs'])}): "
                + "; ".join(f"{i.get('name') or i.get('id') or i.get('placeholder') or '?'}[{i.get('type') or 'text'}]" for i in page_info["inputs"][:8])
            )
        if page_info.get("buttons"):
            summary_lines.append(f"按钮: " + "; ".join(page_info["buttons"][:8]))
        if page_info.get("forms"):
            summary_lines.append(
                f"表单({len(page_info['forms'])}): "
                + "; ".join(f"{f.get('method') or 'GET'}→{f.get('action') or '-'}" for f in page_info["forms"][:5])
            )
        if n_cookies:
            summary_lines.append(f"已同步 {n_cookies} 个浏览器 cookie 到会话（后续 http_request 自动携带）。")
        return {
            "ok": True,
            "action": action,
            "url": page_info.get("url") or "",
            "title": page_info.get("title") or "",
            "status": page_info.get("status") or 0,
            "aria_snapshot": page_info.get("aria_snapshot") or "",
            "visible_text": page_info.get("visible_text") or "",
            "links": page_info.get("links") or [],
            "inputs": page_info.get("inputs") or [],
            "buttons": page_info.get("buttons") or [],
            "forms": page_info.get("forms") or [],
            "cookies_synced": n_cookies,
            "summary": "\n".join(summary_lines),
            "guidance": (
                "浏览器会话已保持（后续 browser_action 复用同一页面）。"
                "ARIA 结构树可读可交互元素（链接/按钮/输入框/表单），"
                "登录/交互产生的 cookie 已同步到会话，后续 http_request 自动携带。"
                "继续按业务逻辑验证，或截图取证后 submit_finding。"
            ),
        }
    except Exception as e:
        return {"ok": False, "error": f"browser_action({action}) 失败: {type(e).__name__}: {e}"}
