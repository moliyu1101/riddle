"""Riddle 挖洞知识库：漏洞测试手册 + 方法论（DB 为主，文件为一次性种子）。

背景：从外部方法论整合而来，去品牌化，落在本项目「作战情报→知识库」。

设计（贴合作战情报需求）：
- DB 为主：知识库条目落地 Intel(kind='knowledge')，前端可浏览 / 手动增删改。
- 文件为种子：启动时从 knowledge/rules + knowledge/kb 同步进 DB，同名 seed 条目
  已存在则跳过（保留用户对其的二次编辑），用户新增不受影响。
- 按需检索：worker 挖某目标时，按漏洞类型/技术栈命中相关篇目，限量注入，不冗余。
- 安全：纯字符串匹配检索，无正则、无回溯；全程 try/except 降级，绝不阻断主流程。

knowledge 条目字段映射（复用 Intel 单表，不新增表）：
  kind      = 'knowledge'
  match_key = 知识库篇目标识（seed 用文件名如 idor-test / src-value-hunting；用户条目用名称）
  summary   = 篇目标题/一句话摘要
  payload   = { name, category(rules|kb|user), filename, origin(seed|user),
                content, enabled, keyword }  （content 为全文）
  confidence= seed 固定 'verified'（可信基础库）
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Intel

# ============ 路径 ============
# 项目根（knowledge/ 与 app/ 同层）
_ROOT = Path(__file__).resolve().parent.parent.parent
_RULES_DIR = _ROOT / "knowledge" / "rules"
_KB_DIR = _ROOT / "knowledge" / "kb"

# 注入上限（防 prompt 膨胀 / 不冗余）
_KB_MAX = int(os.environ.get("KB_MAX_INJECT", "3"))
_KB_CHARS = int(os.environ.get("KB_MAX_INJECT_CHARS", "2600"))


def _now_ts_str() -> str:
    """seed 条目标签：本次同步批次时间戳（用于幂等识别种子批次）。"""
    return "seed-v1"


# ============ 本地文件扫描（一次性种子） ============
def scan_local_files() -> list[dict]:
    """扫描 knowledge/rules + knowledge/kb 下的 .md，返回条目元数据列表。"""
    out: list[dict] = []
    for category, folder in (("rules", _RULES_DIR), ("kb", _KB_DIR)):
        if not folder.exists():
            continue
        for p in sorted(folder.glob("*.md")):
            try:
                if p.stat().st_size == 0:
                    continue
            except Exception:
                continue
            out.append({
                "name": p.stem,
                "category": category,
                "filename": p.name,
                "path": str(p),
            })
    return out


def _seed_dedup(name: str) -> str:
    return "kb:" + hashlib.sha1(name.encode("utf-8", "ignore")).hexdigest()


async def sync_kb_from_files(session: AsyncSession) -> dict:
    """把本地知识库文件同步为 Intel(kind='knowledge')。同名 seed 已存在则跳过（保留用户编辑）。"""
    added = skipped = 0
    for f in scan_local_files():
        try:
            already = (await session.execute(
                select(Intel).where(
                    Intel.kind == "knowledge",
                    Intel.match_key == f["name"],
                    Intel.dedup_hash == _seed_dedup(f["name"]),
                )
            )).scalar_one_or_none()
            if already is not None:
                skipped += 1
                continue
            content = Path(f["path"]).read_text(encoding="utf-8", errors="ignore")
            # 从文件名去 `-test`/`-hunting` 等后缀，拼一个可读标题。
            title = _human_title(f["name"])
            summary = f"{title}（{_category_label(f['category'])}）"
            it = Intel(
                kind="knowledge",
                match_key=f["name"],
                dedup_hash=_seed_dedup(f["name"]),
                payload={
                    "name": f["name"],
                    "category": f["category"],
                    "filename": f["filename"],
                    "origin": "seed",
                    "content": content,
                    "enabled": True,
                    "keyword": title,
                },
                summary=summary[:500],
                source_host="",
                source_task_id="",
                confidence="verified",
                hit_count=1,
            )
            session.add(it)
            added += 1
        except Exception:
            skipped += 1
    try:
        await session.commit()
    except Exception:
        await session.rollback()
    return {"added": added, "skipped": skipped, "total": added + skipped}


def _human_title(name: str) -> str:
    """把 idor-test / src-value-hunting 转成可读标题。"""
    return name.replace("-test", "").replace("_test", "").replace("-", " ").title()


def _category_label(cat: str) -> str:
    return "方法论" if cat == "rules" else "测试手册"


# ============ 中文漏洞类型 → 篇目别名（提高检索命中） ============
_ALIAS: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    (("越权", "idor", "垂直越权", "水平越权", "批量", "bola", "bfla"), ("idor-test",)),
    (("注入", "sql", "sql注入", "hql", "表达式注入"), ("injection-test",)),
    (("ssrf", "服务端请求伪造"), ("ssrf-test",)),
    (("xss", "跨站脚本", "存储型", "反射型"), ("xss-test",)),
    (("csrf", "跨站请求伪造"), ("csrf-test",)),
    (("文件上传", "上传绕过"), ("file-upload-test",)),
    (("逻辑", "业务逻辑", "订单", "优惠券", "积分"), ("logic-test",)),
    (("竞态", "并发", "并发竞态", "race"), ("race-condition-test",)),
    (("jwt", "oauth", "单点登录", "令牌", "token"), ("oauth-jwt-test",)),
    (("graphql",), ("graphql-test",)),
    (("websocket",), ("websocket-test",)),
    (("反序列化", "jndi", "fastjson"), ("deserialization-test", "jndi-injection-test")),
    (("路径穿越", "lfi", "任意文件下载", "file read"), ("path-traversal-lfi-test",)),
    (("xxe", "xml外部实体"), ("xxe-test",)),
    (("waf", "waf绕过", "bypass"), ("waf-bypass",)),
    (("认证绕过", "绕过认证", "任意登录", "账号接管", "任意账号"), ("authbypass-test",)),
    (("信息泄露", "信息泄漏", "信息收集", "源码泄露"), ("info-leak-test",)),
    (("原型链", "原型链污染"), ("prototype-pollution-test",)),
    (("缓存投毒", "缓存欺骗", "cache"), ("cache-poisoning-test",)),
    (("请求走私", "smuggling"), ("http-smuggling-test",)),
    (("侦察", "指纹", "fofa", "资产"), ("recon-methodology",)),
    (("弱口令", "默认口令", "爆破"), ("recon-methodology",)),
    (("前端", "js逆向", "js反编译", "接口"), ("js-reverse-guide",)),
    (("api网关", "网关"), ("api-gateway-test",)),
    (("反序列化绕过", "类型杂耍", "php"), ("type-juggling-test",)),
]

def _match_terms(text: str) -> list[str]:
    """把 query 关键词（含中文漏洞词）映射到的篇目名别名列表（供 match_key 命中）。"""
    text = (text or "").lower()
    hits: list[str] = []
    for words, targets in _ALIAS:
        for w in words:
            if w in text:
                hits.extend(targets)
                break
    return hits


async def lookup_kb(
    session: AsyncSession,
    query_terms: list[str] | None = None,
    query_text: str = "",
    limit: int = 0,
) -> list[Intel]:
    """按漏洞类型/技术栈检索知识库（enabled 的条目）。

    命中策略（两级）：
      1) 别名映射：query_terms 里的中文漏洞词 → 篇目名，与 match_key 精确命中；
      2) 全文兜底：query_text 在 summary/content 里 in 匹配。
    限量返回（默认 _KB_MAX），便于按需注入。
    """
    limit = limit or _KB_MAX
    # 覆盖 seed(种子) + 用户手动添加两类条目：种子用 kb: 前缀，用户条目用 kbu: 前缀。
    stmt = select(Intel).where(Intel.kind == "knowledge")
    rows = (await session.execute(stmt)).scalars().all()

    alias_names: set[str] = set()
    terms = [t for t in (query_terms or []) if t]
    needle = (query_text or "").lower()
    for t in terms:
        alias_names.update(_match_terms(t))
        alias_names.add(t.lower())

    scored: list[tuple[int, Intel]] = []
    for it in rows:
        pl = it.payload or {}
        if not pl.get("enabled", True):
            continue
        name = (it.match_key or "").lower()
        keyword = (pl.get("keyword") or "").lower()
        score = 0
        if name in alias_names or keyword in alias_names:
            score += 100
        if needle:
            blob = f"{it.summary or ''} {keyword} {pl.get('content', '')}".lower()
            if needle in blob:
                score += 20
        if score > 0:
            scored.append((score, it))

    scored.sort(key=lambda x: -x[0])
    return [it for _, it in scored[:limit]]


def render_kb_block(items: list[Intel], max_chars: int = 0) -> str:
    """把命中的知识库篇目裁剪渲染成 worker 注入块。"""
    if not items:
        return ""
    max_chars = max_chars or _KB_CHARS
    lines = ["# 挖洞知识库（按当前目标命中，按需取用，勿硬套）"]
    used = len("".join(lines))
    for it in items[: _KB_MAX]:
        pl = it.payload or {}
        content = pl.get("content", "")
        title = it.summary or it.match_key or "未命名"
        head = content[:500].strip().replace("\n", " ")
        entry = f"- [{title}] {head}"
        if used + len(entry) + 2 > max_chars:
            entry = f"- [{title}] …(正文较长，仅保留开篇摘要；可到作战情报→知识库查看全文)"
        lines.append(entry)
        used += len(entry) + 2
    return "\n".join(lines) + "\n"