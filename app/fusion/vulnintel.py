"""漏洞情报时间流：把「按组件查静态表」升级成「按时间流 + 指纹反查」。

Riddle 现有 ``app/tools/recon.py`` 是约 20 条硬编码指纹→CVE 表，不会随时间更新。
本模块实现可插拔的同步骨架：

  NVD 2.0 全量/增量 + CISA KEV 在野利用 → 归一化为统一条目 →
  近期高危快通道（CVSS ≥ 阈值 或 KEV）→ 资产指纹反向匹配产出 hint →
  复用现有 ``Intel`` 表（kind=cve_feed）持久化，天然带去重与命中计数。

设计约束：
  * **不在 import / 启动阶段联网**；只有显式调用 ``sync()`` 或 API 手动触发才发请求；
  * ``fetcher`` 可注入，单元测试完全离线；
  * 数据源 URL 是公开标准端点，不含任何具体厂商/品牌示例。
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any, Callable

from app.fusion.config import load_config

INTEL_KIND = "cve_feed"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

Fetcher = Callable[[str, dict, dict], dict]

_TOKEN_SPLIT = re.compile(r"[^a-z0-9\u4e00-\u9fff]+")


def _tokens(value: Any) -> set[str]:
    return {t for t in _TOKEN_SPLIT.split(str(value or "").lower()) if len(t) >= 2}


def _cvss_of(metrics: Any) -> float:
    """从 NVD metrics 里取最高 CVSS，兼容 v2/v3.0/v3.1/v4.0 各种键名。"""
    best = 0.0
    for group in (metrics or {}).values() if isinstance(metrics, dict) else []:
        if not isinstance(group, list):
            continue
        for entry in group:
            if not isinstance(entry, dict):
                continue
            data = entry.get("cvssData") or entry
            for key in ("baseScore", "score"):
                try:
                    best = max(best, float(data.get(key) or 0))
                except (TypeError, ValueError):
                    continue
    return best


def parse_nvd(payload: dict) -> list[dict]:
    """解析 NVD 2.0 响应；结构异常时容错返回空列表，绝不抛到调用方。"""
    out: list[dict] = []
    for item in (payload or {}).get("vulnerabilities") or []:
        cve = (item or {}).get("cve") or {}
        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            continue
        desc = ""
        for d in cve.get("descriptions") or []:
            if isinstance(d, dict) and str(d.get("lang", "")).startswith("en"):
                desc = str(d.get("value") or "")
                break
        products: set[str] = set()
        for cfg in ((cve.get("configurations") or [{}])[0].get("nodes") or []) if cve.get("configurations") else []:
            for match in (cfg or {}).get("cpeMatch") or []:
                criteria = str((match or {}).get("criteria") or "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    products.add(parts[4].replace("_", " "))
        out.append({
            "cve_id": cve_id,
            "summary": desc[:400],
            "cvss": _cvss_of(cve.get("metrics")),
            "published": str(cve.get("published") or ""),
            "modified": str(cve.get("lastModified") or ""),
            "products": sorted(products)[:12],
            "kev": False,
        })
    return out


def parse_kev(payload: dict) -> list[dict]:
    """解析 CISA KEV 清单，标记在野利用条目。"""
    out: list[dict] = []
    for row in (payload or {}).get("vulnerabilities") or []:
        cve_id = str((row or {}).get("cveID") or "").strip()
        if not cve_id:
            continue
        out.append({
            "cve_id": cve_id,
            "summary": str(row.get("vulnerabilityName") or "")[:400],
            "cvss": 0.0,
            "published": str(row.get("dateAdded") or ""),
            "modified": "",
            "products": [str(row.get("vendorProject") or ""), str(row.get("product") or "")],
            "kev": True,
        })
    return out


def dedup_entries(entries: list[dict]) -> list[dict]:
    """按 CVE id 合并；KEV 命中优先，分数取高者，产品集合取并集。"""
    merged: dict[str, dict] = {}
    for e in entries or []:
        cid = e.get("cve_id")
        if not cid:
            continue
        if cid not in merged:
            merged[cid] = {**e, "products": list(e.get("products") or [])}
            continue
        cur = merged[cid]
        cur["kev"] = bool(cur.get("kev")) or bool(e.get("kev"))
        cur["cvss"] = max(float(cur.get("cvss") or 0), float(e.get("cvss") or 0))
        cur["products"] = sorted(set(cur["products"]) | set(e.get("products") or []))[:16]
        if not cur.get("summary"):
            cur["summary"] = e.get("summary", "")
    return list(merged.values())


def fastlane(entries: list[dict], cfg=None) -> list[dict]:
    """近期高危快通道：CVSS ≥ 阈值或 KEV 在野利用。"""
    cfg = cfg or load_config()
    return [e for e in entries if e.get("kev") or float(e.get("cvss") or 0) >= cfg.intel_fastlane_cvss]


def build_intel_rows(entries: list[dict]) -> list[dict]:
    """转成可直接写入 ``Intel`` 表的行；match_key 用产品 token 供指纹反查。"""
    rows: list[dict] = []
    for e in entries or []:
        cid = e.get("cve_id")
        if not cid:
            continue
        products = [p for p in (e.get("products") or []) if p]
        match_key = products[0].lower() if products else "global"
        rows.append({
            "kind": INTEL_KIND,
            "match_key": match_key[:255],
            "dedup_hash": hashlib.sha1(cid.encode("utf-8")).hexdigest(),
            "payload": {
                "cve_id": cid,
                "cvss": float(e.get("cvss") or 0),
                "published": e.get("published", ""),
                "kev": bool(e.get("kev")),
                "products": products,
            },
            "summary": f"{cid} CVSS {float(e.get('cvss') or 0):.1f}｜{e.get('summary', '')[:160]}",
            "confidence": "verified" if e.get("kev") else "likely",
        })
    return rows


def match_fingerprint(entries: list[dict], technologies: list[Any]) -> list[dict]:
    """资产指纹 → CVE 反向匹配，产出可注入 prompt 的 hint。"""
    tech_tokens: set[str] = set()
    for t in technologies or []:
        tech_tokens |= _tokens(t)
    hints: list[dict] = []
    for e in entries or []:
        prod_tokens: set[str] = set()
        for p in e.get("products") or []:
            prod_tokens |= _tokens(p)
        hit = sorted(tech_tokens & prod_tokens)
        if not hit:
            continue
        hints.append({
            "cve_id": e.get("cve_id"),
            "cvss": float(e.get("cvss") or 0),
            "kev": bool(e.get("kev")),
            "matched": hit[:5],
            "summary": e.get("summary", "")[:200],
        })
    return hints[:20]


def default_fetcher(url: str, params: dict, headers: dict) -> dict:
    """默认同步抓取；只在显式调用时使用，带硬超时。"""
    import httpx
    from app.fusion.config import load_config
    with httpx.Client(timeout=load_config().intel_timeout, follow_redirects=True) as client:
        resp = client.get(url, params=params, headers=headers)
        resp.raise_for_status()
        return resp.json()


def _iso_days_ago(days: int) -> str:
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")


def sync(fetcher: Fetcher | None = None, cfg=None, *, include_kev: bool = True) -> dict:
    """执行一次时间流同步。返回归一化条目、快通道、可入库行；由 API 负责落库。"""
    cfg = cfg or load_config()
    if not cfg.intel_sync_enabled:
        return {"ok": False, "error": "情报同步未启用（FUSION_INTEL_SYNC）", "entries": []}
    fetch = fetcher or default_fetcher
    headers = {"User-Agent": "riddle-fusion/1.0"}
    if cfg.nvd_api_key:
        headers["apiKey"] = cfg.nvd_api_key
    entries: list[dict] = []
    errors: list[str] = []
    try:
        nvd = fetch(NVD_URL, {
            "pubStartDate": _iso_days_ago(cfg.intel_lookback_days),
            "resultsPerPage": 500,
        }, headers)
        entries.extend(parse_nvd(nvd))
    except Exception as exc:
        errors.append(f"NVD 同步失败: {type(exc).__name__}: {exc}")
    if include_kev:
        try:
            kev = fetch(KEV_URL, {}, headers)
            entries.extend(parse_kev(kev))
        except Exception as exc:
            errors.append(f"KEV 同步失败: {type(exc).__name__}: {exc}")
    merged = dedup_entries(entries)
    return {
        "ok": not errors or bool(merged),
        "source_count": len(entries),
        "entry_count": len(merged),
        "fastlane_count": len(fastlane(merged, cfg)),
        "entries": merged[:200],
        "fastlane": fastlane(merged, cfg)[:50],
        "rows": build_intel_rows(merged)[:200],
        "errors": errors,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }
