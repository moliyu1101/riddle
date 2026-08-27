"""攻击面扩展与参数可控性探测工具（纯规则、复用 executor.http_request，限量限速防 DoS）。

worker「像人一样思考」的自动化助力：批量遍历不再手写几十次单发、响应对比不再靠肉眼、
耗时测量不再靠感觉。全部只读/有限度，天然受任务禁止操作硬拦约束。

- http_batch   : 对占位变量做批量遍历，汇总命中与差异样本（IDOR/越权枚举）
- diff_response: 同一请求两组参数做前后对比，判定"参数是否可控/有注入信号"
- timing_probe : 对同一请求稳定测量耗时统计，辅助时间盲注/时序侧信道
- crawl_links  : 从页面/表单/JS 提取链接与入口，扩展攻击面
"""
from __future__ import annotations

import re
import statistics
import time
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

# 遍历/爬取硬上限，防异常站点拖垮 worker 与目标。
_BATCH_MAX_ITEMS = 60
_BATCH_MAX_DELAY = 0.5
_CRAWL_MAX_PAGES = 10
_CRAWL_MAX_LINKS = 80
_TIMING_SAMPLES_RANGE = (3, 7)
_TIMING_MAX_TIMEOUT = 20

_LINK_RE = re.compile(r"""(?:href|src|action|data-url|formaction)\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_SKIP_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2",
             ".ttf", ".eot", ".pdf", ".zip", ".mp4", ".webp", ".map")


def _fill(template: str, value: str) -> str:
    """把模板里的 {p} 占位符替换成 value；无占位符则原样返回。"""
    if "{p}" in template:
        return template.replace("{p}", value)
    return template


def _status_len(resp: dict) -> tuple[int, int]:
    try:
        return int(resp.get("status_code") or 0), int(resp.get("body_len") or 0)
    except Exception:
        return 0, 0


def _is_interesting(body: str, keywords: list[str]) -> bool:
    if not keywords:
        return False
    low = (body or "").lower()
    return any(k and k.lower() in low for k in keywords)


def http_batch(
    executor: Any,
    url: str = "",
    param_name: str = "",
    start: int = 1,
    end: int = 10,
    step: int = 1,
    method: str = "GET",
    data_template: str = "",
    headers: Optional[dict] = None,
    delay: float = 0.15,
    max_items: int = 40,
    interest_contains: Optional[list[str]] = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """批量遍历 {p} 占位符（或 param_name 参数）的整数区间，返回命中与差异样本。

    用于 IDOR/越权/对象穿透类枚举：把 URL 或 POST body 里会被遍历的位置写成 {p}
    （或给 param_name 自动替换 url 里的 param_name=xxx），程序遍历 start..end，
    汇总各状态码计数、与基线差异明显的样本、命中兴趣关键词的样本。
    只读为主，POST 也仅做无害验证请求；限量 + 限速，绝不穷举海量。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空，且遍历位用 {p} 占位或 param_name。"}
    if not param_name and "{p}" not in url and "{p}" not in (data_template or ""):
        return {"ok": False, "kind": "arg_error",
                "error": "未指定遍历位：请在 url 或 data_template 中用 {p} 占位，或传 param_name 自动替换。"}
    m_items = max(1, min(int(max_items or 40), _BATCH_MAX_ITEMS))
    m_delay = max(0.0, min(float(delay or 0.15), _BATCH_MAX_DELAY))
    m_start, m_end = int(start), int(end)
    if m_start > m_end:
        m_start, m_end = m_end, m_start
    total = abs(m_end - m_start) // max(1, int(step or 1)) + 1
    if total > m_items:
        m_end = m_start + (m_items - 1) * max(1, int(step or 1))

    keyword_list = list(interest_contains or [])
    results: list[dict] = []
    status_counts: dict[int, int] = {}
    diffs: list[dict] = []
    baseline: Optional[tuple[int, int]] = None
    interesting: list[dict] = []

    for i in range(m_start, m_end + 1, max(1, int(step or 1))):
        value = str(i)
        request_url = url
        payload = data_template
        if param_name:
            # 替换 url 里的 param_name=值
            request_url = re.sub(rf"([?&]{re.escape(param_name)}=)[^&\s]*", rf"\g<1>{value}", request_url)
            # payload 里的变量位统一走 {p} 占位（见 _fill），此处不动 param_name 以免误伤 JSON 结构
        request_url = _fill(request_url, value)
        payload = _fill(payload, value)
        try:
            resp = executor.http_request(
                request_url, method=method, headers=dict(headers or {}),
                data=payload or None, timeout=int(timeout or 15),
            )
        except Exception as e:
            results.append({"i": i, "ok": False, "error": str(e)})
            status_counts[0] = status_counts.get(0, 0) + 1
            continue
        st, ln = _status_len(resp)
        status_counts[st] = status_counts.get(st, 0) + 1
        body = resp.get("body") or ""
        entry = {
            "i": i, "value": value, "status": st, "body_len": ln,
            "url": resp.get("url") or request_url,
        }
        results.append(entry)
        if baseline is None:
            baseline = (st, ln)
            entry["baseline"] = True
            continue
        bs, bl = baseline
        len_gap = abs(ln - bl)
        len_ratio = (len_gap / bl) if bl else 0
        is_diff = st != bs or len_gap > 200 or len_ratio > 0.3
        if is_diff:
            diffs.append({**entry, "note": f"vs基线(status {bs}/len {bl})"})
        if _is_interesting(body, keyword_list):
            interesting.append({**entry, "matched_keywords": [k for k in keyword_list if k in body.lower()][:5]})
        if len(diffs) >= 12:
            break
        if m_delay > 0:
            time.sleep(m_delay)

    return {
        "ok": True,
        "scanned": min(total, m_items),
        "range": [m_start, m_end, max(1, int(step or 1))],
        "status_counts": status_counts,
        "baseline": baseline,
        "diff_samples": diffs,
        "interesting_samples": interesting[:8],
        "guidance": (
            "看 diff_samples/interesting_samples：状态或长度突变的项可能就是越权/对象穿透的信号。"
            "挑 1 个差异最大或命中最敏感的用 http_request 单独复现取证，再 submit_finding；不要扫更大范围。"
        ),
    }


def diff_response(
    executor: Any,
    url: str = "",
    params_a: Optional[dict] = None,
    params_b: Optional[dict] = None,
    method: str = "GET",
    headers: Optional[dict] = None,
    timeout: int = 15,
) -> dict[str, Any]:
    """对同一 URL 用两组参数各发一次，对比状态码/长度/关键字段/耗时。

    判定"参数是否真正可控、是否有注入/越权信号"：若改动一个参数导致响应显著变化
    （状态码变、长度突变、错误文案/数据范围变），说明该参数被后端消费，值得深挖；
    若两组几乎一样，说明参数可能被忽略，不必停留。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空。"}
    pa = dict(params_a or {})
    pb = dict(params_b or {})

    def send(p: dict) -> dict | None:
        try:
            q = "&".join(f"{k}={v}" for k, v in p.items())
            target = url + ("&" if "?" in url else "?") + q if p else url
            return executor.http_request(target, method=method, headers=dict(headers or {}),
                                         timeout=int(timeout or 15))
        except Exception as e:
            return {"ok": False, "error": str(e)}

    ra = send(pa)
    rb = send(pb)
    if not ra or not rb or not ra.get("ok") or not rb.get("ok"):
        return {"ok": False, "error": f"请求失败 a={str(ra)[:200]} b={str(rb)[:200]}"}
    st_a, ln_a = _status_len(ra)
    st_b, ln_b = _status_len(rb)
    body_a, body_b = ra.get("body") or "", rb.get("body") or ""
    ta = ra.get("elapsed_ms") or 0
    tb = rb.get("elapsed_ms") or 0
    len_gap = abs(ln_b - ln_a)
    diff = {
        "status": {"a": st_a, "b": st_b, "changed": st_a != st_b},
        "body_len": {"a": ln_a, "b": ln_b, "delta": ln_b - ln_a},
        "sig_attr": bool(st_a != st_b or len_gap > 150 or (ln_a and len_gap / ln_a > 0.25)),
        "elapsed_ms": {"a": ta, "b": tb},
    }
    return {
        "ok": True,
        "url": url,
        "params_a": pa, "params_b": pb,
        "diff": diff,
        "guidance": (
            "参数 BA 差异显著 → 该参数被后端消费：追缺失的鉴权(越权)或注入信号。"
            "差异微弱 → 参数可能被忽略，跳过或换注入点，别停留。"
        ),
    }


def timing_probe(
    executor: Any,
    url: str = "",
    method: str = "GET",
    data: str = "",
    headers: Optional[dict] = None,
    samples: int = 5,
    timeout: int = 15,
) -> dict[str, Any]:
    """对同一请求采样多次测量耗时，给出 min/avg/p50/max/std。

    辅助时间盲注/时序侧信道：先测基线耗时，再换注入 payload（如 sleep 表达式）测再次时序，
    对比两者耗时是否系统性拉大，即可判定是否有时序反馈。只读、有限次采样，不会长时间悬挂。
    """
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空。"}
    n = max(_TIMING_SAMPLES_RANGE[0], min(int(samples or 5), _TIMING_SAMPLES_RANGE[1]))
    to = max(5, min(int(timeout or 15), _TIMING_MAX_TIMEOUT))
    timings: list[float] = []
    last = None
    for _ in range(n):
        try:
            t0 = time.perf_counter()
            last = executor.http_request(url, method=method, headers=dict(headers or {}),
                                         data=data or None, timeout=to)
            timings.append((time.perf_counter() - t0) * 1000)
        except Exception:
            pass
    if not timings:
        return {"ok": False, "error": "所有采样都失败，无法测时。"}
    timings.sort()
    st = last.get("status_code") if last else 0
    return {
        "ok": True,
        "url": url,
        "samples": len(timings),
        "status": st,
        "min_ms": round(timings[0], 2),
        "p50_ms": round(statistics.median(timings), 2),
        "max_ms": round(timings[-1], 2),
        "avg_ms": round(sum(timings) / len(timings), 2),
        "std_ms": round(statistics.pstdev(timings), 2) if len(timings) > 1 else 0.0,
        "guidance": (
            "此为基线耗时。若构造时间盲注 payload 后再测，耗时系统性拉大（p50 明显变大）才有时序反馈；"
            "不显著变大就不是时间盲注，别据此乱报洞。"
        ),
    }


def crawl_links(
    executor: Any,
    url: str = "",
    max_pages: int = 5,
    max_links: int = 60,
    same_host_only: bool = True,
    timeout: int = 10,
) -> dict[str, Any]:
    """从起始页抓取内链/表单/资源 URL，扩展攻击面（只 GET，深度 1，限量限速）。"""
    url = (url or "").strip()
    if not url:
        return {"ok": False, "kind": "arg_error", "error": "url 不能为空。"}
    if not url.lower().startswith("http"):
        url = "http://" + url
    mp = max(1, min(int(max_pages or 5), _CRAWL_MAX_PAGES))
    ml = max(1, min(int(max_links or 60), _CRAWL_MAX_LINKS))
    base_netloc = urlparse(url).netloc.lower()
    seen: set[str] = set()
    pages_seen = 0
    queue = [url]
    while queue and pages_seen < mp and len(seen) < ml:
        cur = queue.pop(0)
        if cur in seen:
            continue
        seen.add(cur)
        pages_seen += 1
        try:
            resp = executor.http_request(cur, method="GET", timeout=int(timeout or 10))
        except Exception:
            continue
        if not resp.get("ok"):
            continue
        body = resp.get("body") or ""
        ct = (resp.get("response_headers") or {}).get("content-type", "")
        if "html" not in ct.lower() and "<a " not in body[:4000].lower():
            continue
        for m in _LINK_RE.finditer(body):
            if len(seen) >= ml:
                break
            raw = m.group(1).strip()
            if not raw or raw.startswith(("javascript:", "mailto:", "tel:", "#")):
                continue
            low = raw.lower()
            if any(low.endswith(e) for e in _SKIP_EXT):
                continue
            full = urljoin(cur, raw)
            try:
                fnet = urlparse(full).netloc.lower()
            except Exception:
                continue
            if same_host_only and fnet and fnet != base_netloc:
                continue
            if full not in seen:
                seen.add(full)
                queue.append(full)
    # 按路径类型归纳（只读接口 / 普通页 / 源内资源）
    links = sorted(seen)
    api_like = [u for u in links if re.search(r"/api/|/rest/|/ajax/|/action/|\.json|\.do\b|graphql", u, re.I)]
    return {
        "ok": True,
        "start": url,
        "page_count": pages_seen,
        "link_count": len(links),
        "links": links[:ml],
        "api_like": api_like[:15],
        "guidance": (
            "api_like 列表优先：只读接口往往是未授权/越权高发区。挑 1~2 个高价值接口用 http_request 验证"
            "是否未鉴权返回真实数据；普通页链接用于标记未测入口，不要全量都打。"
        ),
    }