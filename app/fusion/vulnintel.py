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

import asyncio
import hashlib
import logging
import re
import time
from datetime import datetime, timezone
from typing import Any, Callable

from app.fusion.config import load_config

logger = logging.getLogger("riddle.fusion.intel")

INTEL_KIND = "cve_feed"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

Fetcher = Callable[[str, dict, dict], dict]

_TOKEN_SPLIT = re.compile(r"[^a-z0-9\u4e00-\u9fff]+")
_VERSION_EXTRACT = re.compile(r"(?:[/:\s@]|^)v?(\d+\.\d+(?:\.\d+){0,2})\b", re.I)
_RANGE_OP_RE = re.compile(r"(<=|>=|==|=|<|>)\s*v?(\d+(?:\.\d+){0,3})")


def _tokens(value: Any) -> set[str]:
    return {t for t in _TOKEN_SPLIT.split(str(value or "").lower()) if len(t) >= 2}


def extract_tech_version(tech: Any) -> tuple[str, str]:
    """从组件指纹字符串提取 `(组件名文本, 版本号)`；无版本号时版本号为空串。"""
    text = str(tech or "").strip()
    if not text:
        return "", ""
    m = _VERSION_EXTRACT.search(text)
    if not m:
        return text, ""
    ver = m.group(1)
    product = (text[:m.start()] + " " + text[m.end():]).strip(" /:@-_")
    return (product or text), ver


def _ver_tuple(version: str) -> tuple[int, ...]:
    nums = [int(n) for n in re.findall(r"\d+", str(version or ""))[:4]]
    return tuple(nums)


def compare_versions(v1: str, v2: str) -> int:
    """语义/点分数字版本比较：v1<v2 返回 -1，相等 0，v1>v2 返回 1。"""
    t1 = list(_ver_tuple(v1))
    t2 = list(_ver_tuple(v2))
    if not t1 or not t2:
        return 0
    width = max(len(t1), len(t2))
    t1.extend([0] * (width - len(t1)))
    t2.extend([0] * (width - len(t2)))
    if t1 < t2:
        return -1
    if t1 > t2:
        return 1
    return 0


def _parse_range_item(item: Any) -> dict[str, str] | None:
    if isinstance(item, dict):
        parsed: dict[str, str] = {}
        mapping = (
            ("start_including", ("start_including", "versionStartIncluding")),
            ("start_excluding", ("start_excluding", "versionStartExcluding")),
            ("end_including", ("end_including", "versionEndIncluding")),
            ("end_excluding", ("end_excluding", "versionEndExcluding")),
            ("exact", ("exact", "version")),
        )
        for dst, keys in mapping:
            for k in keys:
                val = str(item.get(k) or "").strip()
                if val and _ver_tuple(val):
                    parsed[dst] = val
                    break
        return parsed or None
    if isinstance(item, str):
        parsed = {}
        for op, ver in _RANGE_OP_RE.findall(item):
            if op == ">=":
                parsed["start_including"] = ver
            elif op == ">":
                parsed["start_excluding"] = ver
            elif op == "<=":
                parsed["end_including"] = ver
            elif op == "<":
                parsed["end_excluding"] = ver
            elif op in ("=", "=="):
                parsed["exact"] = ver
        return parsed or None
    return None


def evaluate_version_range(version: str, ranges: list[Any] | None) -> str:
    """判断组件版本是否落入 CVE 受影响区间，返回 ``affected`` / ``unaffected`` / ``unknown``。"""
    ver = str(version or "").strip()
    if not ver or not _ver_tuple(ver) or not ranges:
        return "unknown"
    valid_ranges = [r for r in (_parse_range_item(x) for x in ranges) if r]
    if not valid_ranges:
        return "unknown"
    for r in valid_ranges:
        ok = True
        if "exact" in r and compare_versions(ver, r["exact"]) != 0:
            ok = False
        if ok and "start_including" in r and compare_versions(ver, r["start_including"]) < 0:
            ok = False
        if ok and "start_excluding" in r and compare_versions(ver, r["start_excluding"]) <= 0:
            ok = False
        if ok and "end_including" in r and compare_versions(ver, r["end_including"]) > 0:
            ok = False
        if ok and "end_excluding" in r and compare_versions(ver, r["end_excluding"]) >= 0:
            ok = False
        if ok:
            return "affected"
    return "unaffected"


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
        version_ranges: list[dict[str, str]] = []
        for cfg in ((cve.get("configurations") or [{}])[0].get("nodes") or []) if cve.get("configurations") else []:
            for match in (cfg or {}).get("cpeMatch") or []:
                mobj = match or {}
                criteria = str(mobj.get("criteria") or "")
                parts = criteria.split(":")
                if len(parts) > 4:
                    products.add(parts[4].replace("_", " "))
                vr: dict[str, str] = {}
                for dst, src in (
                    ("start_including", "versionStartIncluding"),
                    ("start_excluding", "versionStartExcluding"),
                    ("end_including", "versionEndIncluding"),
                    ("end_excluding", "versionEndExcluding"),
                ):
                    v = str(mobj.get(src) or "").strip()
                    if v and _ver_tuple(v):
                        vr[dst] = v
                if not vr and len(parts) > 5 and parts[5] not in ("*", "-", "") and _ver_tuple(parts[5]):
                    vr["exact"] = parts[5]
                if vr and vr not in version_ranges:
                    version_ranges.append(vr)
        out.append({
            "cve_id": cve_id,
            "summary": desc[:400],
            "cvss": _cvss_of(cve.get("metrics")),
            "published": str(cve.get("published") or ""),
            "modified": str(cve.get("lastModified") or ""),
            "products": sorted(products)[:12],
            "version_ranges": version_ranges[:16],
            "kev": False,
        })
    return out


def parse_ghsa(payload: dict | list) -> list[dict]:
    """解析 GitHub Security Advisories 响应，提取组件名与受影响版本表达式。"""
    items = payload if isinstance(payload, list) else (payload or {}).get("advisories") or []
    out: list[dict] = []
    for adv in items:
        if not isinstance(adv, dict):
            continue
        cid = str(adv.get("cve_id") or adv.get("ghsa_id") or "").strip()
        if not cid:
            continue
        products: set[str] = set()
        version_ranges: list[str] = []
        for v in adv.get("vulnerabilities") or []:
            if not isinstance(v, dict):
                continue
            pkg = (v.get("package") or {}).get("name") or ""
            if pkg:
                products.add(str(pkg).strip().lower())
            rng = str(v.get("vulnerable_version_range") or "").strip()
            if rng and rng not in version_ranges:
                version_ranges.append(rng)
        cvss_raw = (adv.get("cvss") or {}).get("score") if isinstance(adv.get("cvss"), dict) else adv.get("cvss_score")
        try:
            cvss = float(cvss_raw or 0.0)
        except (TypeError, ValueError):
            cvss = 0.0
        out.append({
            "cve_id": cid,
            "summary": str(adv.get("summary") or adv.get("description") or "")[:400],
            "cvss": cvss,
            "published": str(adv.get("published_at") or ""),
            "modified": str(adv.get("updated_at") or ""),
            "products": sorted(products)[:12],
            "version_ranges": version_ranges[:16],
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
            "version_ranges": [],
            "kev": True,
        })
    return out


def dedup_entries(entries: list[dict]) -> list[dict]:
    """按 CVE id 合并；KEV 命中优先，分数取高者，产品与版本区间取并集。"""
    merged: dict[str, dict] = {}
    for e in entries or []:
        cid = e.get("cve_id")
        if not cid:
            continue
        if cid not in merged:
            merged[cid] = {
                **e,
                "products": list(e.get("products") or []),
                "version_ranges": list(e.get("version_ranges") or []),
            }
            continue
        cur = merged[cid]
        cur["kev"] = bool(cur.get("kev")) or bool(e.get("kev"))
        cur["cvss"] = max(float(cur.get("cvss") or 0), float(e.get("cvss") or 0))
        cur["products"] = sorted(set(cur["products"]) | set(e.get("products") or []))[:16]
        existing_ranges = list(cur.get("version_ranges") or [])
        for r in e.get("version_ranges") or []:
            if r not in existing_ranges:
                existing_ranges.append(r)
        cur["version_ranges"] = existing_ranges[:16]
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
                "version_ranges": list(e.get("version_ranges") or [])[:16],
            },
            "summary": f"{cid} CVSS {float(e.get('cvss') or 0):.1f}｜{e.get('summary', '')[:160]}",
            "confidence": "verified" if e.get("kev") else "likely",
        })
    return rows


def match_fingerprint(
    entries: list[dict],
    technologies: list[Any],
    *,
    include_unaffected: bool = False,
) -> list[dict]:
    """资产指纹 → CVE 反向匹配（支持版本区间三态过滤），产出可注入 prompt 的 hint。"""
    tech_tokens: set[str] = set()
    tech_versions: list[tuple[set[str], str]] = []
    for t in technologies or []:
        prod_part, ver = extract_tech_version(t)
        toks = _tokens(prod_part or t) | _tokens(t)
        tech_tokens |= toks
        tech_versions.append((toks, ver))
    hints: list[dict] = []
    for e in entries or []:
        prod_tokens: set[str] = set()
        for p in e.get("products") or []:
            prod_tokens |= _tokens(p)
        hit = sorted(tech_tokens & prod_tokens)
        if not hit:
            continue
        detected_ver = ""
        for toks, ver in tech_versions:
            if ver and (toks & prod_tokens):
                detected_ver = ver
                break
        vir = evaluate_version_range(detected_ver, e.get("version_ranges") or [])
        if vir == "unaffected" and not include_unaffected:
            continue
        hints.append({
            "cve_id": e.get("cve_id"),
            "cvss": float(e.get("cvss") or 0),
            "kev": bool(e.get("kev")),
            "matched": hit[:5],
            "detected_version": detected_ver,
            "version_in_range": vir,
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


async def sync_and_store(
    session,
    *,
    fetcher: Fetcher | None = None,
    cfg=None,
    include_kev: bool = True,
) -> dict:
    """执行时间流同步并按 dedup_hash 幂等写入 Intel 表。API 与后台定时共用的单一实现。"""
    from sqlalchemy import select
    from app.db.models import Intel

    result = await asyncio.to_thread(sync, fetcher=fetcher, cfg=cfg, include_kev=include_kev)
    rows = result.get("rows") or []
    if not rows:
        return {**result, "stored": 0}
    stored = 0
    for row in rows:
        existing = (await session.execute(
            select(Intel).where(Intel.kind == INTEL_KIND, Intel.dedup_hash == row["dedup_hash"])
        )).scalar_one_or_none()
        if existing:
            existing.payload = row["payload"]
            existing.summary = row["summary"]
            existing.match_key = row["match_key"]
            existing.hit_count = (existing.hit_count or 1) + 1
        else:
            session.add(Intel(**row))
        stored += 1
    await session.commit()
    return {**result, "stored": stored}


async def _latest_feed_epoch(session) -> float:
    from sqlalchemy import func, select
    from app.db.models import Intel

    last_seen = (await session.execute(
        select(func.max(Intel.last_seen)).where(Intel.kind == INTEL_KIND)
    )).scalar_one_or_none()
    if last_seen is None:
        return 0.0
    if last_seen.tzinfo is None:
        last_seen = last_seen.replace(tzinfo=timezone.utc)
    return last_seen.timestamp()


async def run_periodic_intel_sync(
    *,
    session_factory=None,
    fetcher: Fetcher | None = None,
    poll_seconds: float = 60.0,
) -> None:
    """后台定时情报同步：默认 interval=0 关闭；在配置开启时按周期拉取 NVD/KEV。"""
    if session_factory is None:
        from app.db.session import SessionLocal
        factory = SessionLocal
    else:
        factory = session_factory
    last_sync_at: float | None = None
    while True:
        try:
            cfg = load_config()
            interval_hours = int(getattr(cfg, "intel_sync_interval_hours", 0) or 0)
            if cfg.intel_sync_enabled and interval_hours > 0:
                interval_sec = interval_hours * 3600
                if last_sync_at is None:
                    try:
                        async with factory() as session:
                            last_sync_at = await _latest_feed_epoch(session)
                    except Exception:
                        last_sync_at = 0.0
                now = time.time()
                if now - last_sync_at >= interval_sec:
                    last_sync_at = now
                    async with factory() as session:
                        res = await sync_and_store(session, fetcher=fetcher, cfg=cfg)
                    logger.info(
                        "情报自动同步完成: ok=%s entries=%s stored=%s errors=%s",
                        res.get("ok"), res.get("entry_count", 0), res.get("stored", 0), res.get("errors") or [],
                    )
            await asyncio.sleep(max(0.05, float(poll_seconds)))
        except asyncio.CancelledError:
            logger.info("情报自动同步已停止")
            break
        except Exception:
            logger.exception("情报自动同步异常")
            await asyncio.sleep(max(0.05, float(poll_seconds)))
