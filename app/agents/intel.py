"""全局情报库（跨任务共享）：写入 + 触发式检索 + 轻量指纹识别。

设计要点（对应用户决策）：
- 全局跨任务共享（决策一）。
- 四类：cred / fingerprint / endpoint / profile（决策二 A/B/C/F）。
- 触发式检索（决策三）：不主动全量注入，按当前目标的 root域/系统指纹命中才给。
- 不冗余：结构化字段 + 强去重(dedup_hash) + 命中计数 + 质量门槛 + 限量注入。

安全（吸取 js_analyzer 教训）：
- 指纹识别纯字符串 `in` 匹配，无正则、无回溯、无网络、纯内存。
- 写入/检索全 try/except 降级，绝不阻断 worker 主流程。
- 注入有硬字数上限、每类有数量上限。
"""
from __future__ import annotations

import hashlib
import os
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agents.intel_curator import assess_intel
from app.db.models import Intel

# ============ 轻量指纹关键词表（纯字符串匹配，无正则） ============
# 命中规则：把 title/server/body 片段/host 拼成一个小写大串，逐个 in 判断。
# value 是归一化的「系统指纹标识」，作为 fingerprint/endpoint 类情报的 match_key。
# 只放高频、好识别、有复用价值的系统，宁缺毋滥（不冗余）。
_FINGERPRINT_KEYWORDS: list[tuple[tuple[str, ...], str]] = [
    # 统一身份认证 / SSO
    (("统一身份认证", "统一认证", "cas/login", "/cas/", "single sign"), "sso_cas"),
    # 邮件系统
    (("coremail", "/coremail/",), "mail_coremail"),
    (("exchange", "owa/auth", "/owa/"), "mail_exchange"),
    # 常见国产框架/CMS
    (("若依", "ruoyi", "ry-", "若依管理"), "framework_ruoyi"),
    (("thinkphp", "think_template", "x-powered-by: thinkphp"), "framework_thinkphp"),
    (("fastadmin",), "framework_fastadmin"),
    (("springboot", "whitelabel error page", "/actuator"), "framework_springboot"),
    (("jeecg", "jeecg-boot", "jeecgboot"), "framework_jeecg"),
    (("seeyon", "致远", "/seeyon/"), "oa_seeyon"),
    (("泛微", "weaver", "/weaver/", "ecology"), "oa_weaver"),
    (("通达", "tongda", "/ispirit/"), "oa_tongda"),
    # 教务/校园业务系统
    (("强智", "jwgl", "教务系统", "academic"), "edu_jwgl"),
    (("正方", "zfsoft", "/jwglxt/"), "edu_zhengfang"),
    (("迎新", "yxxt", "新生报到"), "edu_freshman"),
    # VPN / 网关
    (("sslvpn", "/+cscoe+/", "anyconnect"), "vpn_cisco"),
    (("sangfor", "深信服", "/por/login"), "vpn_sangfor"),
    (("webvpn",), "vpn_webvpn"),
    # 数据库/中间件管理
    (("phpmyadmin",), "db_phpmyadmin"),
    (("druid", "/druid/index"), "mw_druid"),
    (("swagger-ui", "swagger-ui.html", "/v2/api-docs"), "api_swagger"),
    (("nacos", "/nacos/"), "mw_nacos"),
    (("grafana",), "mw_grafana"),
    (("kibana",), "mw_kibana"),
    (("xxl-job", "xxl_job"), "mw_xxl_job"),
    (("minio", "x-amz-request-id"), "mw_minio"),
    # 组件 / 开发与企业套件
    (("rememberme=", "shiro"), "comp_shiro"),
    (("fastjson", "com.alibaba.fastjson"), "comp_fastjson"),
    (("jenkins", "x-jenkins"), "devops_jenkins"),
    (("gitlab", "_gitlab_session"), "devops_gitlab"),
    (("wordpress", "wp-content", "wp-login"), "cms_wordpress"),
    (("dedecms", "dedeajax"), "cms_dedecms"),
    (("discuz", "discuz_"), "cms_discuz"),
    (("eyou", "亿邮"), "mail_eyou"),
    (("landray", "蓝凌", "/ekp/"), "oa_landray"),
    (("kingdee", "金蝶", "/k3cloud/"), "erp_kingdee"),
    (("yonyou", "用友", "/nccloud/", "/u8cloud/"), "erp_yonyou"),
]

# 注入上限（防 prompt 膨胀 / 不冗余）
_MAX_PER_KIND = int(os.environ.get("INTEL_MAX_PER_KIND", "4"))
_MAX_INJECT_CHARS = int(os.environ.get("INTEL_MAX_INJECT_CHARS", "1800"))
# 内容字段写入前的硬截断（防异常超长）
_MAX_FIELD = 300


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _clip(s, n: int = _MAX_FIELD) -> str:
    if not isinstance(s, str):
        s = str(s or "")
    return s[:n]


def _clip_payload_value(v, n: int = _MAX_FIELD):
    if isinstance(v, (bool, int, float)):
        return v
    return _clip(v, n)


def detect_fingerprints(*parts: str) -> list[str]:
    """从 title/server/body/host 等文本里识别系统指纹（纯字符串匹配，无正则）。

    返回去重后的指纹标识列表（可能多个）。无匹配返回空。
    """
    blob = " ".join(p for p in parts if p).lower()
    if not blob:
        return []
    # 限制扫描长度，防异常超长 body（纯 in 匹配本就线性，这里再加一道保险）。
    blob = blob[:20000]
    hits: list[str] = []
    for keywords, fp in _FINGERPRINT_KEYWORDS:
        for kw in keywords:
            if kw in blob:
                hits.append(fp)
                break
    # 去重保序
    seen = set()
    out = []
    for h in hits:
        if h not in seen:
            seen.add(h)
            out.append(h)
    return out


def _dedup_hash(kind: str, match_key: str, payload: dict) -> str:
    """内容指纹：同类+同检索键下，内容相同的视为一条（去重）。"""
    if kind == "cred":
        sig = f"{payload.get('username', '')}|{payload.get('password', '')}"
    elif kind == "endpoint":
        sig = f"{payload.get('path', '')}|{payload.get('vuln_type', '')}"
    elif kind == "fingerprint":
        sig = f"{payload.get('tactic', '')}"
    elif kind == "lesson":
        sig = f"{payload.get('lesson_type', '')}|{payload.get('vuln_type', '')}"
    else:  # profile
        sig = f"{payload.get('key', '')}|{payload.get('value', '')}"
    raw = f"{kind}|{match_key}|{sig}".lower()
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()


async def record_intel(
    session: AsyncSession,
    kind: str,
    match_key: str,
    payload: dict,
    summary: str = "",
    source_host: str = "",
    source_task_id: str = "",
    confidence: str = "likely",
) -> bool:
    """写入一条情报（去重 + 计数）。已存在则 +hit_count 并更新 last_seen/confidence。

    返回是否成功（失败降级返回 False，绝不抛异常）。
    """
    try:
        kind = (kind or "").strip().lower()
        match_key = _clip((match_key or "").strip().lower(), 255)
        if kind not in ("cred", "fingerprint", "endpoint", "profile", "lesson") or not match_key:
            return False
        if not isinstance(payload, dict) or not payload:
            return False
        # 内容字段硬截断（保留 bool/int/float 供效用与来源标记）
        payload = {k: _clip_payload_value(v) for k, v in payload.items() if v not in (None, "")}
        if not payload:
            return False
        assessment = assess_intel(kind, match_key, payload, summary, confidence)
        if not assessment.ok:
            return False
        payload = assessment.payload
        dh = _dedup_hash(kind, match_key, payload)

        existing = (await session.execute(
            select(Intel).where(
                Intel.kind == kind, Intel.match_key == match_key, Intel.dedup_hash == dh
            )
        )).scalar_one_or_none()

        if existing:
            existing.hit_count = (existing.hit_count or 1) + 1
            existing.last_seen = _now()
            # verified 优先级高于 likely：一旦验证过就升级，不回退。
            if confidence == "verified":
                existing.confidence = "verified"
            if payload.get("human_verified"):
                old_pl = existing.payload if isinstance(existing.payload, dict) else {}
                merged = dict(payload)
                for stat_k in ("injected_count", "converted_count", "rejected_count"):
                    if stat_k in old_pl and stat_k not in merged:
                        merged[stat_k] = old_pl[stat_k]
                existing.payload = merged
                if summary:
                    existing.summary = _clip(summary, 500)
            return True

        session.add(Intel(
            kind=kind, match_key=match_key, dedup_hash=dh,
            payload=payload, summary=_clip(summary, 500),
            source_host=_clip(source_host, 255), source_task_id=_clip(source_task_id, 32),
            confidence="verified" if confidence == "verified" else "likely",
        ))
        return True
    except Exception:
        return False


def intel_utility_score(row: Any) -> float:
    """计算情报效用分：综合验证状态、贝叶斯注入转化率、人工核准与误报驳回惩罚。"""
    if isinstance(row, dict):
        pl = row.get("payload") or {}
        conf = str(row.get("confidence") or "likely")
        hits = int(row.get("hit_count") or 1)
    else:
        pl = getattr(row, "payload", None) or {}
        conf = str(getattr(row, "confidence", None) or "likely")
        hits = int(getattr(row, "hit_count", None) or 1)
    if not isinstance(pl, dict):
        pl = {}
    injected = max(0, int(pl.get("injected_count") or 0))
    converted = max(0, int(pl.get("converted_count") or 0))
    rejected = max(0, int(pl.get("rejected_count") or 0))
    # 人工核准避坑警示保持高优先级地板，防止避坑提醒被低分沉底
    if pl.get("lesson_type") == "pitfall" and pl.get("human_rejected"):
        return round(4.5 + min(max(1, hits), 10) * 0.1, 4)
    ctr_score = ((converted + 1.0) / (injected + 2.0)) * 3.0
    score = ctr_score
    if conf == "verified":
        score += 1.5
    if pl.get("human_verified"):
        score += 1.5
    score += min(float(max(1, hits)) * 0.2, 2.0)
    score -= float(rejected) * 1.2
    return round(score, 4)


def _rank_intel_rows(rows: list[Intel], limit: int) -> list[Intel]:
    """按效用分降序重排候选情报，同分时保持 SQL 原先按 confidence/hit_count/last_seen 的顺序。"""
    if not rows:
        return []
    ranked = sorted(
        rows,
        key=lambda r: (intel_utility_score(r), int(getattr(r, "hit_count", 1) or 1)),
        reverse=True,
    )
    return ranked[:limit]


async def lookup_intel(
    session: AsyncSession,
    root: str,
    fingerprints: list[str] | None = None,
    *,
    fallback_keys: list[str] | None = None,
) -> dict[str, list[Intel]]:
    """触发式检索：按 root域 + 系统指纹（及业务画像/漏洞类降级键）命中相关情报。

    返回 {cred:[], fingerprint:[], endpoint:[], profile:[], lesson:[]}，按效用分与 hit_count 排序、限量，
    并为实际注入给 Worker 的动作类情报累加 injected_count。任何失败降级返回空 dict。
    """
    out: dict[str, list[Intel]] = {"cred": [], "fingerprint": [], "endpoint": [], "profile": [], "lesson": []}
    try:
        root = (root or "").strip().lower()
        fps: list[str] = []
        seen_fp: set[str] = set()
        for raw_k in [*(fingerprints or []), *(fallback_keys or [])]:
            k = str(raw_k or "").strip().lower()
            if k and k not in seen_fp:
                seen_fp.add(k)
                fps.append(k)

        candidate_limit = max(_MAX_PER_KIND * 4, _MAX_PER_KIND)

        # cred / profile 按 root 域命中
        if root:
            for kind in ("cred", "profile"):
                rows = (await session.execute(
                    select(Intel).where(Intel.kind == kind, Intel.match_key == root)
                    .order_by(Intel.confidence.desc(), Intel.hit_count.desc(), Intel.last_seen.desc())
                    .limit(candidate_limit)
                )).scalars().all()
                out[kind] = _rank_intel_rows(list(rows), _MAX_PER_KIND)

        # fingerprint / endpoint / lesson 按系统指纹及三级降级键命中
        if fps:
            for kind in ("fingerprint", "endpoint", "lesson"):
                rows = (await session.execute(
                    select(Intel).where(Intel.kind == kind, Intel.match_key.in_(fps))
                    .order_by(Intel.confidence.desc(), Intel.hit_count.desc(), Intel.last_seen.desc())
                    .limit(candidate_limit)
                )).scalars().all()
                out[kind] = _rank_intel_rows(list(rows), _MAX_PER_KIND)

        # 记录动作类情报的实际注入次数（重新赋新 dict 以触发 SQLAlchemy JSON 脏追踪）
        for kind in ("cred", "fingerprint", "endpoint", "lesson"):
            for row in out[kind]:
                pl = dict(row.payload or {})
                pl["injected_count"] = int(pl.get("injected_count") or 0) + 1
                row.payload = pl
        return out
    except Exception:
        return out


async def record_intel_conversion(
    session: AsyncSession,
    root: str,
    fingerprints: list[str] | None = None,
    *,
    fallback_keys: list[str] | None = None,
) -> int:
    """目标确认出洞后，为命中该目标且已注入过的活跃情报累加 converted_count。"""
    updated = 0
    try:
        root_key = (root or "").strip().lower()
        fps: list[str] = []
        seen_fp: set[str] = set()
        for raw_k in [*(fingerprints or []), *(fallback_keys or [])]:
            k = str(raw_k or "").strip().lower()
            if k and k not in seen_fp:
                seen_fp.add(k)
                fps.append(k)

        candidates: list[Intel] = []
        if root_key:
            rows = (await session.execute(
                select(Intel).where(Intel.kind == "cred", Intel.match_key == root_key)
            )).scalars().all()
            candidates.extend(rows)
        if fps:
            rows = (await session.execute(
                select(Intel).where(
                    Intel.kind.in_(("fingerprint", "endpoint", "lesson")),
                    Intel.match_key.in_(fps),
                )
            )).scalars().all()
            candidates.extend(rows)

        seen_ids: set[str] = set()
        for row in candidates:
            rid = getattr(row, "id", "") or ""
            if rid and rid in seen_ids:
                continue
            if rid:
                seen_ids.add(rid)
            pl = dict(row.payload or {})
            inj = int(pl.get("injected_count") or 0)
            if inj <= 0:
                continue
            conv = int(pl.get("converted_count") or 0)
            if conv < inj:
                pl["converted_count"] = conv + 1
                row.payload = pl
                updated += 1
        return updated
    except Exception:
        return updated


async def lookup_cve_hints(session: AsyncSession, technologies: list[str]) -> str:
    """按当前目标识别出的指纹/技术栈反查近期 CVE 时间流，生成紧凑提示块。"""
    techs = [str(t).strip() for t in (technologies or []) if str(t or "").strip()]
    if not techs:
        return ""
    try:
        from app.fusion import vulnintel

        rows = (await session.execute(
            select(Intel)
            .where(Intel.kind == vulnintel.INTEL_KIND)
            .order_by(Intel.last_seen.desc())
            .limit(300)
        )).scalars().all()
        if not rows:
            return ""
        entries = [{
            "cve_id": (r.payload or {}).get("cve_id", ""),
            "cvss": (r.payload or {}).get("cvss", 0),
            "kev": (r.payload or {}).get("kev", False),
            "products": list((r.payload or {}).get("products") or []) + ([r.match_key] if r.match_key else []),
            "version_ranges": list((r.payload or {}).get("version_ranges") or []),
            "summary": r.summary or "",
        } for r in rows]
        hints = vulnintel.match_fingerprint(entries, techs)
        if not hints:
            return ""
        lines = ["## 近期关联 CVE 情报提示（融合时间流匹配）"]
        for h in hints[:4]:
            kev_tag = " [KEV]" if h.get("kev") else ""
            ver_tag = f" ({h.get('version_in_range')})" if h.get("version_in_range") else ""
            lines.append(
                f"- {h.get('cve_id')} CVSS {float(h.get('cvss') or 0):.1f}{kev_tag}{ver_tag}｜命中 {', '.join(h.get('matched') or [])}｜{h.get('summary', '')[:120]}"
            )
        return "\n".join(lines)
    except Exception:
        return ""


def render_intel_block(intel: dict[str, list[Intel]], cve_block: str = "") -> str:
    """把检索到的情报渲染成注入 worker 的 prompt 块（限量、去重、不冗余）。

    完全没命中则返回空串（绝大多数新目标的常态，零开销）。
    """
    cred = intel.get("cred") or []
    fp = intel.get("fingerprint") or []
    ep = intel.get("endpoint") or []
    profile = intel.get("profile") or []
    lesson = intel.get("lesson") or []
    cve_text = (cve_block or "").strip()
    if not (cred or fp or ep or profile or lesson or cve_text):
        return ""

    lines = ["# 情报库命中（其它 worker 沉淀的可复用情报，按可信度排序）"]

    if lesson:
        lines.append("\n## 同类系统历史经验（审核反馈沉淀）")
        for it in lesson:
            p = it.payload or {}
            tag = "✓人工核准" if p.get("human_verified") else ("✓出洞" if it.confidence == "verified" else "·疑似")
            kind_tag = "有效打法" if p.get("lesson_type") == "poc" else "易踩坑"
            lines.append(f"- [{tag}]{kind_tag} [{p.get('vuln_type','')}] {it.summary}".rstrip())

    if fp:
        lines.append("\n## 同类系统打法（历史出洞验证）")
        for it in fp:
            tag = "✓验证" if it.confidence == "verified" else "·疑似"
            lines.append(f"- [{tag}] {it.summary or it.payload.get('tactic', '')}")

    if ep:
        lines.append("\n## 同类系统有效端点")
        for it in ep:
            p = it.payload or {}
            lines.append(f"- {p.get('path', '')}  {('('+p.get('vuln_type', '')+')') if p.get('vuln_type') else ''} {it.summary}".rstrip())

    if cred:
        lines.append("\n## 本域历史有效凭证（验证过可登录，可直接撞库）")
        for it in cred:
            p = it.payload or {}
            tag = "✓验证" if it.confidence == "verified" else "·疑似"
            lines.append(f"- [{tag}] {p.get('username', '')} : {p.get('password', '')}  {it.summary}".rstrip())

    if profile:
        lines.append("\n## 本域画像（技术栈/WAF/突破口）")
        for it in profile:
            p = it.payload or {}
            lines.append(f"- {p.get('key', '')}: {p.get('value', '')}")

    if cve_text:
        lines.append("\n" + cve_text)

    lines.append("\n注意：情报仅供参考、可能已失效；它只是其中一个攻击面，别因此忽略其它洞，也别盲目照搬。")
    block = "\n".join(lines)
    # 硬字数上限，防膨胀。
    if len(block) > _MAX_INJECT_CHARS:
        block = block[:_MAX_INJECT_CHARS] + "\n…(情报过多已截断)"
    return block + "\n\n"


# ============ 审核反馈闭环：把初审结论沉淀为可复用打法/易踩坑经验 ============
# 只对「证据质量」类驳回提炼负向经验；范围/重复/公开类与此无关，提炼无意义还制造噪音。
_PITFALL_REASON_MARKERS = (
    "半成品", "证据不足", "未打穿", "未证明", "未生效", "无实质", "无法复现",
    "自评不足", "没实锤", "缺证据", "无法确认危害",
)


def _host_of(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return (urlparse(url or "").netloc or "").lower()
    except Exception:
        return ""


def _norm_key_token(value: str, limit: int = 40) -> str:
    import re
    clean = re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "_", str(value or "").strip().lower()).strip("_")
    return clean[:limit]


def resolve_lesson_keys(f: dict) -> list[str]:
    """三级检索键解析：系统指纹 → 业务画像(biz_*) → 漏洞类型(vuln_*)。"""
    url = _clip((f.get("target_url") or ""), 255)
    title = _clip((f.get("title") or ""), 120)
    owner = _clip((f.get("owner") or ""), 120)
    desc = _clip((f.get("description") or ""), 400)
    raw_resp = _clip((f.get("raw_response") or ""), 800)
    poc = _clip((f.get("poc") or ""), 300)
    fps = detect_fingerprints(_host_of(url), title, owner, desc, raw_resp, poc)
    if fps:
        return [ _clip(fps[0], 64) ]
    keys: list[str] = []
    biz_id = _norm_key_token(f.get("biz_id") or "")
    if biz_id:
        keys.append(f"biz_{biz_id}")
    vtype = str(f.get("vuln_type") or "").strip()
    if vtype and vtype not in ("其他", "unknown", "other"):
        vtok = _norm_key_token(vtype)
        if vtok:
            keys.append(f"vuln_{vtok}")
    return keys


def distill_review_lesson(
    f: dict,
    review: dict,
    *,
    allow_fallback: bool = False,
) -> dict | None:
    """从一条初审结论提炼可回流的 lesson 情报（纯函数，可单测）。

    输入 f=Finding 关键字段 dict，review=审核结果 dict（verdict/severity_final/ignore_reasons...）。
    allow_fallback=True 时启用「指纹 → 业务画像 → 漏洞类型」三级兜底键，打破固定指纹限制。
    只产出两类：
      - accepted → 正向「有效打法」PoC 模板（confidence=verified）
      - ignored 且驳回原因是证据质量 → 负向「易踩坑」注意（confidence=likely）
    """
    try:
        verdict = (review.get("verdict") or "").strip()
        if verdict == "deepen":
            return None
        vuln_type = _clip((f.get("vuln_type") or "其他"), 30)
        title = _clip((f.get("title") or ""), 100)
        url = _clip((f.get("target_url") or ""), 255)
        if allow_fallback:
            keys = resolve_lesson_keys(f)
            if not keys:
                return None
            match_key = _clip(keys[0], 64)
        else:
            fps = detect_fingerprints(_host_of(url), title, f.get("owner") or "")
            if not fps:
                return None
            match_key = _clip(fps[0], 64)

        if verdict == "accepted":
            repro = _clip((f.get("poc") or "") or (f.get("raw_request") or ""), 300)
            payload = {"lesson_type": "poc", "vuln_type": vuln_type,
                       "title": title or vuln_type, "repro": repro}
            summary = f"已出洞打法 [{vuln_type}] {title}".strip()
            return {"kind": "lesson", "match_key": match_key, "payload": payload,
                    "summary": summary, "confidence": "verified"}

        if verdict == "ignored":
            reasons = review.get("ignore_reasons") or []
            reason = "；".join(str(r) for r in reasons if r)
            if not any(m in reason for m in _PITFALL_REASON_MARKERS):
                return None
            payload = {"lesson_type": "pitfall", "vuln_type": vuln_type, "reason": _clip(reason, 200)}
            summary = f"易踩坑 [{vuln_type}] 这类通常被判半成品/证据不足，别浪费轮次".strip()
            return {"kind": "lesson", "match_key": match_key, "payload": payload,
                    "summary": summary, "confidence": "likely"}
    except Exception:
        return None
    return None


async def emit_review_lessons(
    session: AsyncSession,
    finding: dict,
    review: dict,
    *,
    allow_fallback: bool = False,
) -> None:
    """审核落库后调用：把初审结论沉淀进情报库（失败降级不抛异常）。"""
    item = distill_review_lesson(finding, review, allow_fallback=allow_fallback)
    if not item:
        return
    await record_intel(
        session, item["kind"], item["match_key"],
        payload=item["payload"], summary=item["summary"],
        source_host=_host_of(finding.get("target_url") or ""),
        confidence=item["confidence"],
    )


async def apply_human_review_feedback(
    session: AsyncSession,
    finding: Any,
    review: Any,
    *,
    user_status: str,
    user_notes: str = "",
    user_edits: dict | None = None,
) -> dict:
    """人工复审强反馈闭环：passed 沉淀精修经验与端点，rejected 记为避坑指南并降权误报打法。"""
    if user_status not in ("passed", "rejected") or finding is None:
        return {"recorded": "", "downgraded": 0}
    try:
        edits = user_edits if isinstance(user_edits, dict) else {}
        ev = getattr(finding, "evidence", None) if not isinstance(finding, dict) else finding.get("evidence")
        biz_id = (ev or {}).get("biz_id", "") if isinstance(ev, dict) else ""
        get_f = (lambda k, d="": finding.get(k, d)) if isinstance(finding, dict) else (lambda k, d="": getattr(finding, k, d))
        title = _clip(edits.get("title") or get_f("title", ""), 100)
        vuln_type = _clip(get_f("vuln_type", "") or "其他", 30)
        target_url = _clip(get_f("target_url", ""), 255)
        poc = _clip(edits.get("poc") or get_f("poc", "") or get_f("raw_request", ""), 300)
        eff = {
            "vuln_type": vuln_type,
            "title": title,
            "target_url": target_url,
            "owner": get_f("owner", ""),
            "description": edits.get("description") or get_f("description", ""),
            "poc": poc,
            "raw_response": get_f("raw_response", ""),
            "biz_id": biz_id,
        }
        keys = resolve_lesson_keys(eff) or [f"vuln_{_norm_key_token(vuln_type) or 'general'}"]
        match_key = _clip(keys[0], 64)
        host = _host_of(target_url)

        if user_status == "passed":
            await record_intel(
                session,
                "lesson",
                match_key,
                payload={
                    "lesson_type": "poc",
                    "vuln_type": vuln_type,
                    "title": title or vuln_type,
                    "repro": poc or title or "已人工审核通过，保留有效验证步骤",
                    "human_verified": True,
                },
                summary=f"人工核准打法 [{vuln_type}] {title}".strip(),
                source_host=host,
                confidence="verified",
            )
            from urllib.parse import urlparse
            path = (urlparse(target_url).path or "") if target_url else ""
            if path and path != "/":
                await record_intel(
                    session,
                    "endpoint",
                    match_key,
                    payload={"path": path, "vuln_type": vuln_type, "human_verified": True},
                    summary=f"人工复审通过端点（来自 {host}）",
                    source_host=host,
                    confidence="verified",
                )
            return {"recorded": "passed", "match_key": match_key, "downgraded": 0}

        # user_status == "rejected"
        rev_notes = (
            getattr(review, "reviewer_notes", "") if review and not isinstance(review, dict) else (review or {}).get("reviewer_notes", "")
        )
        reason = _clip(
            (user_notes or "").strip() or (rev_notes or "").strip() or "人工复审判定无效或证据不足",
            200,
        )
        await record_intel(
            session,
            "lesson",
            match_key,
            payload={
                "lesson_type": "pitfall",
                "vuln_type": vuln_type,
                "reason": reason,
                "human_rejected": True,
            },
            summary=f"人工驳回避坑 [{vuln_type}] {reason[:90]}".strip(),
            source_host=host,
            confidence="verified",
        )
        downgraded = 0
        rows = (await session.execute(
            select(Intel).where(Intel.kind == "lesson", Intel.match_key == match_key)
        )).scalars().all()
        for row in rows:
            pl = dict(row.payload or {})
            if pl.get("lesson_type") == "poc" and (pl.get("vuln_type") == vuln_type or title and pl.get("title") == title):
                pl["rejected_count"] = int(pl.get("rejected_count") or 0) + 1
                row.payload = pl
                if row.confidence != "likely" and not pl.get("human_verified"):
                    row.confidence = "likely"
                downgraded += 1
        return {"recorded": "rejected", "match_key": match_key, "downgraded": downgraded}
    except Exception:
        return {"recorded": "", "downgraded": 0}
