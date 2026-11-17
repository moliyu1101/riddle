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
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Finding, Intel, Review, to_cst_iso

# ============ 路径 ============
# 项目根（knowledge/ 与 app/ 同层）
_ROOT = Path(__file__).resolve().parent.parent.parent
_RULES_DIR = _ROOT / "knowledge" / "rules"
_KB_DIR = _ROOT / "knowledge" / "kb"

# 文档交叉引用：`xxx-test.md` 一类（含中文文件名），用于解析文档间跳转关系。
_REF_RE = re.compile(r"[A-Za-z0-9_\-\u4e00-\u9fff]+\.md")

# 注入上限（防 prompt 膨胀 / 不冗余）
_KB_MAX = int(os.environ.get("KB_MAX_INJECT", "3"))
_KB_CHARS = int(os.environ.get("KB_MAX_INJECT_CHARS", "2600"))
# 方法论（category=rules）随任务常驻注入，独立于手册名额，最多 _METHOD_MAX 篇
_METHOD_MAX = int(os.environ.get("KB_METHOD_MAX", "2"))

# ============ 方法论（rules）触发词 → 篇目名 ============
# 与手册（kb）的「漏洞类型映射」解耦：方法论承载锁面/范围/价值排序/迭代等
# 工作流指引，只要任务命中任一触发词即优先注入，不占 _KB_MAX 手册名额。
_METHOD_ALIAS: list[tuple[tuple[str, ...], str]] = [
    (("锁面", "自由跳", "范围", "扩面", "资产", "续挖", "侦察", "流程", "协作", "站点", "seed", "挖掘"), "dig-scope-workflow"),
    (("价值", "高危", "优先级", "排序", "类型", "矩阵", "四件套", "力气", "优先"), "src-value-hunting"),
    (("迭代", "能力", "换站", "短表", "复盘", "经验", "收口", "拟进"), "hunt-iter"),
    (("报告", "提交", "复现", "格式", "定级", "验收", "编写", "poc"), "vuln-report-format"),
    (("能力", "增强", "方法论", "打穿", "深度", "boost"), "skill-as-boost"),
    (("白盒", "黑盒", "代码审计", "授权研究", "渗透测试", "审计"), "researcher-blackbox-whitebox"),
    (("cors", "跨域"), "cors-vuln-report-priority"),
    (("桌面", "任务夹", "目录"), "desktop-task-folder"),
    (("浏览器", "playwright", "mcp", "自动化"), "playwright-browser-mcp"),
    (("授权研究", "安全研究", "研究语境", "渗透测试授权"), "security-research-context"),
    (("道德", "伦理", "过度", "造作"), "anti-over-moralization"),
]


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


def _parse_refs(content: str, known: set[str]) -> list[str]:
    """解析文档里的 `.md` 交叉引用，只保留知识库中真实存在的篇目名。

    源知识库文档互相跳转（如「见 authbypass-test.md §18」），直接搬移后这些引用
    对 worker 只是无意义字符串。这里把引用解析成可用的关联篇目列表（related），
    供注入提示与 kb_lookup 查询使用；指向不存在文件的引用（xxx.md/hashlib.md 等）自动过滤。
    """
    out: list[str] = []
    seen: set[str] = set()
    for m in _REF_RE.finditer(content or ""):
        name = m.group(0)[:-3]  # 去掉 .md 后缀
        if name in known and name not in seen:
            seen.add(name)
            out.append(name)
    return out


async def sync_kb_from_files(session: AsyncSession) -> dict:
    """把本地知识库文件同步为 Intel(kind='knowledge')。同名 seed 已存在则跳过（保留用户编辑）。"""
    added = skipped = updated = 0
    files = scan_local_files()
    known = {f["name"] for f in files}
    for f in files:
        try:
            already = (await session.execute(
                select(Intel).where(
                    Intel.kind == "knowledge",
                    Intel.match_key == f["name"],
                    Intel.dedup_hash == _seed_dedup(f["name"]),
                )
            )).scalar_one_or_none()
            if already is not None:
                # 旧 seed 条目可能缺 related（关联解析是后加的）：补上，不覆盖用户其它编辑。
                # 注意：必须用 dict() 拷贝新对象——直接复用 payload 原 dict 再赋回，
                # SQLAlchemy 按对象身份判断未变化，session.add 后变更会静默丢失。
                pl = dict(already.payload or {})
                if not pl.get("related"):
                    content = Path(f["path"]).read_text(encoding="utf-8", errors="ignore")
                    pl["related"] = _parse_refs(content, known)
                    already.payload = pl
                    session.add(already)
                    updated += 1
                skipped += 1
                continue
            content = Path(f["path"]).read_text(encoding="utf-8", errors="ignore")
            # 从文件名去 `-test`/`-hunting` 等后缀，拼一个可读标题。
            title = _human_title(f["name"])
            summary = f"{title}（{_category_label(f['category'])}）"
            # 解析文档间交叉引用（只保留真实存在的篇目），供注入提示与 kb_lookup 跳转。
            related = _parse_refs(content, known)
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
                    "related": related,
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
    return {"added": added, "skipped": skipped, "updated": updated, "total": added + skipped}


def _human_title(name: str) -> str:
    """把 idor-test / src-value-hunting 转成可读标题。"""
    return name.replace("-test", "").replace("_test", "").replace("-", " ").title()


def _category_label(cat: str) -> str:
    return "方法论" if cat == "rules" else "测试手册"


# ============ 中文漏洞类型 → 篇目别名（提高检索命中） ============
# 同时覆盖 orchestrator 传入的英文漏洞类型（vuln_types 如 weak_password/rce/info_leak）
_ALIAS: list[tuple[tuple[str, ...], tuple[str, ...]]] = [
    (("越权", "idor", "垂直越权", "水平越权", "批量", "bola", "bfla", "privilege_escalation", "提权"), ("idor-test",)),
    (("注入", "sql", "sql注入", "hql", "表达式注入", "rce", "命令执行", "远程代码执行", "命令注入", "ssti", "模板注入", "模板引擎"), ("injection-test",)),
    (("ssrf", "服务端请求伪造"), ("ssrf-test",)),
    (("xss", "跨站脚本", "存储型", "反射型"), ("xss-test",)),
    (("csrf", "跨站请求伪造"), ("csrf-test",)),
    (("文件上传", "上传绕过", "file_upload"), ("file-upload-test",)),
    (("逻辑", "业务逻辑", "订单", "优惠券", "积分", "logic_flaw", "逻辑漏洞"), ("logic-test",)),
    (("竞态", "并发", "并发竞态", "race"), ("race-condition-test",)),
    (("jwt", "oauth", "单点登录", "令牌", "token"), ("oauth-jwt-test",)),
    (("graphql",), ("graphql-test",)),
    (("websocket",), ("websocket-test",)),
    (("反序列化", "jndi", "fastjson"), ("deserialization-test", "jndi-injection-test")),
    (("路径穿越", "lfi", "任意文件下载", "任意文件读取", "文件读取", "file read", "file_read"), ("path-traversal-lfi-test",)),
    (("xxe", "xml外部实体"), ("xxe-test",)),
    (("waf", "waf绕过", "bypass", "captcha_bypass", "验证码绕过", "captcha"), ("waf-bypass",)),
    (("认证绕过", "绕过认证", "任意登录", "账号接管", "任意账号", "unauthorized_access", "未授权", "未授权访问"), ("authbypass-test",)),
    (("信息泄露", "信息泄漏", "信息收集", "源码泄露", "info_leak", "backdoor_compromised", "后门", "被攻陷", "webshell"), ("info-leak-test",)),
    (("原型链", "原型链污染"), ("prototype-pollution-test",)),
    (("缓存投毒", "缓存欺骗", "cache"), ("cache-poisoning-test",)),
    (("请求走私", "smuggling"), ("http-smuggling-test",)),
    (("侦察", "指纹", "fofa", "资产"), ("recon-methodology",)),
    (("弱口令", "默认口令", "爆破", "弱密码", "weak_password"), ("recon-methodology",)),
    (("前端", "js逆向", "js反编译", "接口"), ("js-reverse-guide",)),
    (("api网关", "网关"), ("api-gateway-test",)),
    (("反序列化绕过", "类型杂耍", "php"), ("type-juggling-test",)),
    (("开放重定向", "任意跳转", "open_redirect"), ("open-redirect-test",)),
    # 补充映射：覆盖其余测试手册（含「几乎不交」降级类，让 worker 知道默认不收）
    (("401", "403", "接口鉴权", "权限绕过", "未授权接口"), ("401-403-bypass",)),
    (("短表", "手法索引", "打穿短表", "索引"), ("打穿短表",)),
    (("工具真执行", "对话口", "工具执行", "会跑命令"), ("agent-tool-exec-test",)),
    (("云ide", "codex", "编程平台", "ai编程", "编程台", "rce链"), ("cloud-ide-codex-rce-chain",)),
    (("点击劫持", "clickjacking", "覆盖攻击"), ("clickjacking-test",)),
    (("csp", "内容安全策略", "策略绕过"), ("csp-bypass-test",)),
    (("csv", "公式注入", "电子表格注入"), ("csv-formula-injection-test",)),
    (("悬空标记", "dangling", "悬空"), ("dangling-markup-test",)),
    (("依赖混淆", "供应链", "内部包名"), ("dependency-confusion-test",)),
    (("dns重绑定", "重绑定", "dns rebinding"), ("dns-rebinding-test",)),
    (("el注入", "表达式语言", "expression language"), ("el-injection-test",)),
    (("邮件头", "邮件注入", "邮件头注入"), ("email-header-injection-test",)),
    (("ghost bits", "幽灵位", "cast攻击", "类型转换攻击"), ("ghost-bits-cast-test",)),
    (("参数污染", "hpp", "参数覆盖"), ("hpp-test",)),
    (("host头", "主机头", "毒重置信", "重置信", "host header"), ("http-host-header-test",)),
    (("http2", "h2走私", "http/2"), ("http2-attacks-test",)),
    (("scm", "源码管理", "git泄露", "代码仓库", "不安全scm"), ("insecure-scm-test",)),
    (("llm", "ai安全", "越狱", "提示注入", "prompt injection"), ("llm-security-test",)),
    (("子域接管", "子域名接管", "域名接管", "subdomain"), ("subdomain-takeover-test",)),
    (("xslt", "xslt注入"), ("xslt-injection-test",)),
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


def _match_methods(text: str) -> list[str]:
    """映射到方法论（category=rules）篇目名：命中触发词即算。"""
    text = (text or "").lower()
    out: list[str] = []
    for words, target in _METHOD_ALIAS:
        for w in words:
            if w in text:
                out.append(target)
                break
    return out


# 知识库条目缓存：worker 每次派发都会调 lookup_kb，全表拉取是重复 IO；
# 条目只在启动同步/手动编辑时变化（低频），TTL 60s + 写操作主动失效。
_KB_CACHE: dict[str, Any] = {"rows": None, "expires": 0.0}
_KB_CACHE_TTL = 60.0


async def _load_kb_rows(session: AsyncSession) -> list:
    now = time.monotonic()
    if _KB_CACHE["rows"] is not None and now < _KB_CACHE["expires"]:
        return _KB_CACHE["rows"]
    stmt = select(Intel).where(Intel.kind == "knowledge")
    rows = (await session.execute(stmt)).scalars().all()
    _KB_CACHE["rows"] = rows
    _KB_CACHE["expires"] = now + _KB_CACHE_TTL
    return rows


def clear_kb_cache() -> None:
    """知识库条目增删改后调用，让 lookup_kb 下次拉取最新。"""
    _KB_CACHE["rows"] = None
    _KB_CACHE["expires"] = 0.0


async def refresh_kb_cache(session: AsyncSession) -> list:
    """清除并立即重新预热 DB 知识库缓存，供同步工具 kb_lookup 与 skill_index 读取最新内容。"""
    clear_kb_cache()
    try:
        return await _load_kb_rows(session)
    except Exception:
        return []


def cached_db_kb_entries() -> list[dict]:
    """线程安全读取最近一次缓存的 DB 知识库条目（含用户新增与编辑覆盖）。"""
    rows = _KB_CACHE.get("rows")
    if not rows:
        return []
    snapshot = list(rows)
    out: list[dict] = []
    for it in snapshot:
        try:
            pl = dict(getattr(it, "payload", None) or {})
            name = str(getattr(it, "match_key", "") or pl.get("name") or "").strip()
            content = str(pl.get("content") or "")
            if not name:
                continue
            out.append({
                "name": name,
                "category": str(pl.get("category") or "user"),
                "origin": str(pl.get("origin") or "user"),
                "title": str(pl.get("name") or _human_title(name)),
                "keyword": str(pl.get("keyword") or name),
                "content": content,
                "enabled": bool(pl.get("enabled", True)),
                "related": list(pl.get("related") or []),
            })
        except Exception:
            continue
    return out


async def lookup_kb(
    session: AsyncSession,
    query_terms: list[str] | None = None,
    query_text: str = "",
    limit: int = 0,
) -> list[Intel]:
    """按漏洞类型/技术栈检索知识库（enabled 的条目）。

    命中策略（三级）：
      1) 方法论优先：query_terms + query_text 命中触发词的 rules 篇目，优先注入（占 _METHOD_MAX 名额）；
      2) 别名映射：query_terms 里的中文漏洞词 → 手册篇目名，与 match_key 精确命中；
      3) 全文兜底：query_text 在 summary/content 里 in 匹配。
    限量返回，手册不占方法论名额。
    """
    limit = limit or _KB_MAX
    rows = await _load_kb_rows(session)
    by_name = {it.match_key: it for it in rows}

    alias_names: set[str] = set()
    terms = [t for t in (query_terms or []) if t]
    method_names: list[str] = []
    needle = (query_text or "").lower()
    for t in terms:
        alias_names.update(_match_terms(t))
        alias_names.add(t.lower())
        method_names.extend(_match_methods(t))
    # query_text 也参与方法论命中（目标标题/org 里的范围/优先级等词）
    method_names.extend(_match_methods(needle))

    # 方法论：命中多篇时保持声明顺序（稳定、可预期）
    method_items: list[Intel] = []
    seen_method: set[str] = set()
    for m in method_names:
        if m in seen_method:
            continue
        seen_method.add(m)
        it = by_name.get(m)
        if it is not None and (it.payload or {}).get("enabled", True):
            method_items.append(it)
    method_items = method_items[:_METHOD_MAX]

    scored: list[tuple[int, Intel]] = []
    for it in rows:
        pl = it.payload or {}
        if not pl.get("enabled", True):
            continue
        if pl.get("category") == "rules":
            # 方法论已在上面单独优先处理，这里不重复占手册名额
            continue
        name = (it.match_key or "").lower()
        keyword = (pl.get("keyword") or "").lower()
        kw_tokens = {tok for tok in re.split(r"[\s,|]+", keyword) if tok}
        score = 0
        if name in alias_names or keyword in alias_names:
            score += 100
        elif kw_tokens & alias_names:
            score += 80
        elif any(t.lower() in keyword for t in terms if len(t.strip()) >= 2):
            score += 60
        if needle:
            blob = f"{it.summary or ''} {keyword} {pl.get('content', '')}".lower()
            if needle in blob:
                score += 20
        if score > 0:
            scored.append((score, it))

    scored.sort(key=lambda x: -x[0])
    items = scored[:limit]
    # 方法论置顶：作为工作流指引优先给 worker 看到
    return method_items + [it for _, it in items]


def render_kb_block(items: list[Intel], max_chars: int = 0) -> str:
    """把命中的知识库篇目裁剪渲染成 worker 注入块。

    方法论（category=rules）与测试手册（kb）分开渲染：方法论只留简短指引头部，
    手册保留正文摘要；指令总长仍受 max_chars 约束（避免长方法论挤掉按类型命中的手册）。
    """
    if not items:
        return ""
    max_chars = max_chars or _KB_CHARS
    method_items = [it for it in items if (it.payload or {}).get("category") == "rules"]
    manual_items = [it for it in items if (it.payload or {}).get("category") != "rules"]

    out: list[str] = []
    used = 0

    def _push_line(line: str) -> None:
        """追加一行，超预算时用截断占位替换该行正文只留标题。"""
        nonlocal used
        rest = max_chars - used
        if rest <= 0:
            return
        if len(line) + 2 > rest:
            # 塞不下：退化为只保留「标题 + 占位」，仍尽量给出可读指引
            idx = line.find("]")
            if idx > 0:
                line = line[: idx + 1] + " …(正文过长，仅保留此指引；详见作战情报→知识库)"
        out.append(line)
        used += len(line) + 2

    # 方法论：只取开篇要点，不整篇灌（dig-scope 等动辄上万字）。
    if method_items:
        _push_line("# 挖洞工作流方法论（命中随任务注入，按需遵循）")
        for it in method_items[:_METHOD_MAX]:
            pl = it.payload or {}
            content = pl.get("content", "")
            title = it.summary or it.match_key or "未命名"
            head = content[:300].strip().replace("\n", " ") or content[:180]
            _push_line(f"- [{title}] {head}")

    # 手册：正文摘要。
    if manual_items:
        _push_line("# 挖洞知识库（按当前目标命中，按需取用）")
        for it in manual_items[:_KB_MAX]:
            pl = it.payload or {}
            content = pl.get("content", "")
            title = it.summary or it.match_key or "未命名"
            head = content[:500].strip().replace("\n", " ")
            _push_line(f"- [{title}] {head}")
            # 关联篇目：文档内交叉引用的其他知识库篇目，worker 可用 kb_lookup 查全文跳转。
            related = pl.get("related") or []
            if related:
                _push_line(f"    关联篇目: {'、'.join(related)}（kb_lookup 可查全文）")

    return "\n".join(out) + "\n"


def lookup_kb_file(query: str, max_chars: int = 4000) -> dict:
    """按篇目名/关键词查知识库全文（合并 DB 动态知识库缓存与本地 knowledge 目录）。

    知识库文档互相引用（如「见 authbypass-test.md §18」），worker 看到跳转指引时
    用本函数查对应篇目全文。精确命中篇目名返回全文；否则按关键词返回候选列表。
    DB 中的用户新增（origin='user'/'distilled'）与已编辑种子条目优先级高于磁盘文件。
    """
    query = (query or "").strip().lower()
    if not query:
        return {"ok": False, "error": "query 不能为空"}
    if query.endswith(".md"):
        query = query[:-3]

    entries_by_name: dict[str, dict] = {}
    for category, folder in (("rules", _RULES_DIR), ("kb", _KB_DIR)):
        if not folder.exists():
            continue
        for p in sorted(folder.glob("*.md")):
            entries_by_name[p.stem] = {
                "name": p.stem,
                "category": category,
                "origin": "seed",
                "title": _human_title(p.stem),
                "keyword": _human_title(p.stem),
                "path": p,
                "content": None,
                "enabled": True,
                "related": None,
            }

    for db_row in cached_db_kb_entries():
        name = db_row["name"]
        if not db_row.get("enabled", True):
            entries_by_name.pop(name, None)
            continue
        entries_by_name[name] = {**db_row, "path": None}

    entries = list(entries_by_name.values())
    known = {e["name"] for e in entries}

    def _get_content(entry: dict) -> str:
        if entry.get("content") is not None:
            return entry["content"]
        p = entry.get("path")
        if p is not None:
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                entry["content"] = content
                return content
            except Exception:
                return ""
        return ""

    def _read(entry: dict) -> dict:
        content = _get_content(entry)
        rel = entry.get("related")
        if not rel:
            rel = _parse_refs(content, known)
        return {
            "ok": True,
            "query": query,
            "name": entry["name"],
            "category": entry["category"],
            "origin": entry.get("origin", "seed"),
            "title": entry.get("title") or _human_title(entry["name"]),
            "related": rel,
            "content": content[:max_chars],
            "truncated": len(content) > max_chars,
        }

    exact = [
        e for e in entries
        if e["name"].lower() == query
        or str(e.get("keyword") or "").lower() == query
        or str(e.get("title") or "").lower() == query
    ]
    if exact:
        return _read(exact[0])
    partial = [
        e for e in entries
        if query in e["name"].lower()
        or query in str(e.get("keyword") or "").lower()
        or query in str(e.get("title") or "").lower()
    ]
    if partial:
        out = _read(partial[0])
        out["matches"] = [
            {"name": e["name"], "category": e["category"], "title": e.get("title") or _human_title(e["name"])}
            for e in partial
        ]
        return out
    hits: list[dict] = []
    parts = _kw_parts(query)
    need = min(2, len(parts))  # 中文 2 字窗口至少命中 2 个，避免单窗口误命中
    for entry in entries:
        content = _get_content(entry)
        low = f"{entry.get('title', '')} {entry.get('keyword', '')} {content}".lower()
        if sum(1 for p in parts if p in low) >= need:
            hits.append({"name": entry["name"], "category": entry["category"], "title": entry.get("title") or _human_title(entry["name"])})
    if hits:
        return {
            "ok": True,
            "query": query,
            "matches": hits[:10],
            "content": "",
            "summary": f"关键词命中 {len(hits)} 篇，用篇目名精确查询可读全文",
        }
    return {"ok": False, "error": f"知识库无匹配篇目: {query}", "matches": []}


def _kw_parts(query: str) -> list[str]:
    """把查询拆成匹配片段：纯英文按原词；含中文按 2 字滑动窗口（「滑块验证码」→滑块/块验/验证/证码）。

    中文短语常被文档拆开表述（如「滑块」与「验证码」分处两处），整串 in 匹配会漏；
    2 字窗口任一命中即算，作为关键词兜底足够（返回候选列表由调用方取舍）。
    """
    if re.search(r"[\u4e00-\u9fff]", query):
        parts = [query[i : i + 2] for i in range(len(query) - 1)]
        return parts or [query]
    return [query]


# ============ 实战漏洞自动蒸馏为可复用知识库 ============

_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^((?:cookie|authorization|x-api-key|x-auth-token|token)\s*:\s*).+$"
)
_IP_MASK_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b")


def _sanitize_play_text(text: str, *, netloc: str = "", host: str = "") -> str:
    """将请求/PoC 中的目标域名、IP 与认证头脱敏，保留攻击路径、参数与判定逻辑。"""
    s = (text or "").strip()
    if not s:
        return ""
    if netloc:
        s = re.sub(re.escape(netloc), "<TARGET_HOST>", s, flags=re.IGNORECASE)
    if host and "." in host:
        s = re.sub(re.escape(host), "<TARGET_HOST>", s, flags=re.IGNORECASE)
    s = _IP_MASK_RE.sub("<TARGET_IP>", s)
    s = _SENSITIVE_HEADER_RE.sub(r"\1<REDACTED>", s)
    return s


def synthesize_kb_from_finding(finding: Any, review: Any = None) -> dict:
    """将已验证/过审的高价值 Finding（结合人工编辑与复审备注）脱敏蒸馏为结构化知识库篇目。"""
    get_f = (lambda k, d="": finding.get(k, d)) if isinstance(finding, dict) else (lambda k, d="": getattr(finding, k, d))
    edits: dict = {}
    rev_notes = ""
    user_notes = ""
    user_sev = ""
    rev_sev = ""
    if review is not None:
        raw_edits = review.get("user_edits") if isinstance(review, dict) else getattr(review, "user_edits", None)
        if isinstance(raw_edits, dict):
            edits = raw_edits
        rev_notes = str((review.get("reviewer_notes") if isinstance(review, dict) else getattr(review, "reviewer_notes", "")) or "")
        user_notes = str((review.get("user_notes") if isinstance(review, dict) else getattr(review, "user_notes", "")) or "")
        user_sev = str((review.get("user_severity") if isinstance(review, dict) else getattr(review, "user_severity", "")) or "")
        rev_sev = str((review.get("severity_final") if isinstance(review, dict) else getattr(review, "severity_final", "")) or "")

    vuln_type = str(edits.get("vuln_type") or get_f("vuln_type", "") or "综合漏洞").strip()[:80]
    raw_title = str(edits.get("title") or get_f("title", "") or vuln_type).strip()
    target_url = str(get_f("target_url", "") or "").strip()
    owner = str(get_f("owner", "") or "").strip()
    severity = (user_sev or rev_sev or str(get_f("severity_claimed", "") or "high")).strip()
    description = str(edits.get("description") or get_f("description", "") or "").strip()
    poc = str(edits.get("poc") or get_f("poc", "") or get_f("poc_http", "") or get_f("raw_request", "") or "").strip()
    raw_resp = str(edits.get("raw_response") or get_f("raw_response", "") or "").strip()

    ev = get_f("evidence", None)
    ev_dict = ev if isinstance(ev, dict) else {}
    biz_id = str(ev_dict.get("biz_id") or "").strip()
    kill_chain = get_f("kill_chain", None) or ev_dict.get("kill_chain") or []
    steps = edits.get("steps") or get_f("steps", None) or ev_dict.get("steps") or []

    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}") if target_url else None
    netloc = (parsed.netloc if parsed else "").strip()
    host = (parsed.hostname if parsed else "").strip()
    url_path = (parsed.path if parsed else "") or "/"

    from app.agents.intel import detect_fingerprints

    fps = detect_fingerprints(target_url, raw_title, owner, description, poc, raw_resp)
    anchor_tok = ""
    if fps:
        anchor_tok = fps[0].removeprefix("fp_")
    elif biz_id:
        anchor_tok = biz_id
    else:
        ascii_slug = re.sub(r"[^a-z0-9]+", "-", vuln_type.lower()).strip("-")
        if ascii_slug:
            anchor_tok = ascii_slug[:24]
        else:
            mapped = sorted(_match_terms(vuln_type))
            anchor_tok = mapped[0] if mapped else "play"

    clean_title = _sanitize_play_text(raw_title, netloc=netloc, host=host) or vuln_type
    clean_desc = _sanitize_play_text(description, netloc=netloc, host=host)
    clean_poc = _sanitize_play_text(poc, netloc=netloc, host=host)[:1200]
    clean_resp = _sanitize_play_text(raw_resp, netloc=netloc, host=host)[:500]
    clean_notes = _sanitize_play_text(
        "；".join(p for p in [user_notes.strip(), rev_notes.strip()] if p),
        netloc=netloc, host=host,
    )

    sig_seed = f"{vuln_type.lower()}|{url_path.lower()}|{clean_title.lower()}"
    short_hash = hashlib.sha1(sig_seed.encode("utf-8", errors="ignore")).hexdigest()[:8]
    safe_anchor = re.sub(r"[^a-z0-9_-]+", "-", anchor_tok.lower()).strip("-") or "play"
    match_key = f"distilled-{safe_anchor[:24]}-{short_hash}"

    play_name = f"[实战蒸馏] {vuln_type}：{clean_title[:56]}".strip("： ")
    kw_parts: list[str] = [vuln_type, clean_title[:40], match_key]
    for fp in fps:
        kw_parts.append(fp)
        kw_parts.append(fp.removeprefix("fp_"))
    if biz_id:
        kw_parts.append(biz_id)
    if url_path and url_path != "/":
        kw_parts.append(url_path)
    kw_parts.extend(sorted(_match_terms(vuln_type)))
    dedup_kw: list[str] = []
    seen_kw: set[str] = set()
    for p in kw_parts:
        s = str(p or "").strip()
        if s and s.lower() not in seen_kw:
            seen_kw.add(s.lower())
            dedup_kw.append(s)
    keyword = " ".join(dedup_kw)[:240]

    chain_lines: list[str] = []
    if isinstance(kill_chain, list):
        for idx, step in enumerate(kill_chain[:10], 1):
            if isinstance(step, dict):
                m = str(step.get("method") or step.get("step") or "").strip()
                d = _sanitize_play_text(str(step.get("detail") or step.get("desc") or ""), netloc=netloc, host=host)
                txt = f"{m}: {d}".strip(": ")
            else:
                txt = _sanitize_play_text(str(step), netloc=netloc, host=host)
            if txt:
                chain_lines.append(f"{idx}. {txt}")
    if not chain_lines and isinstance(steps, list):
        for idx, st in enumerate(steps[:10], 1):
            txt = _sanitize_play_text(
                st.get("detail") or st.get("action") or str(st) if isinstance(st, dict) else str(st),
                netloc=netloc, host=host,
            )
            if txt:
                chain_lines.append(f"{idx}. {txt}")
    if not chain_lines and clean_desc:
        chain_lines.append(f"1. {clean_desc[:400]}")

    fp_desc = ", ".join(fps) if fps else "通用 Web / 业务逻辑面"
    lines = [
        f"# {play_name}",
        "",
        "## 适用场景与指纹特征",
        f"- 漏洞类型：{vuln_type}",
        f"- 典型等级：{severity}",
        f"- 指纹特征：{fp_desc}",
        f"- 目标路径模式：`{url_path}`",
    ]
    if biz_id:
        lines.append(f"- 业务场景：`{biz_id}`")
    if clean_desc:
        lines.extend(["", f"> 概述：{clean_desc[:400]}"])

    lines.extend(["", "## 攻击路径与关键步骤"])
    lines.extend(chain_lines or ["1. 探测目标关键接口与参数，确认未授权/越权或注入点。"])

    lines.extend(["", "## 验证载荷参考（已脱敏）"])
    if clean_poc:
        lines.extend(["```http", clean_poc, "```"])
    else:
        lines.append(f"- 请求路径：`{url_path}`（按同型接口参数构造安全只读验证探针）")

    lines.extend(["", "## 复现判定与避坑要点"])
    if clean_notes:
        lines.append(f"- 复审核准要点：{clean_notes[:350]}")
    if clean_resp:
        lines.extend(["- 典型有效响应特征：", f"  `{clean_resp[:300]}`"])
    elif not clean_notes:
        lines.append("- 复现时需核实实际返回业务数据/权限越界证据，禁止仅凭 HTTP 状态码下结论。")

    content = "\n".join(lines)
    known = {e["name"] for e in scan_local_files()}
    related = _parse_refs(content, known)
    for m_name in sorted(_match_terms(vuln_type)):
        if m_name in known and m_name not in related:
            related.append(m_name)

    return {
        "name": play_name,
        "keyword": keyword,
        "match_key": match_key,
        "category": "user",
        "origin": "distilled",
        "vuln_type": vuln_type,
        "severity": severity,
        "source_host": host or netloc,
        "summary": f"{vuln_type}（{severity}）实战蒸馏：{clean_title[:80]}",
        "content": content,
        "related": related[:8],
    }


async def distill_finding_to_kb(
    session: AsyncSession,
    finding_id: str,
    *,
    commit: bool = True,
) -> dict:
    """将指定 Finding（及关联 Review）蒸馏并幂等写入知识库，返回前端可用字典。"""
    finding = await session.get(Finding, finding_id)
    if finding is None:
        raise ValueError(f"finding_not_found:{finding_id}")

    review = (await session.execute(
        select(Review).where(Review.finding_id == finding_id)
    )).scalar_one_or_none()

    synth = synthesize_kb_from_finding(finding, review)
    match_key = synth["match_key"]
    dedup_hash = "kbd:" + hashlib.sha1(match_key.encode("utf-8", errors="ignore")).hexdigest()[:16]
    payload = {
        "category": "user",
        "origin": "distilled",
        "name": synth["name"],
        "keyword": synth["keyword"],
        "content": synth["content"],
        "enabled": True,
        "related": synth["related"],
        "source_finding_id": finding.id,
        "vuln_type": synth["vuln_type"],
        "severity": synth["severity"],
    }
    now = datetime.now(timezone.utc)

    existing = (await session.execute(
        select(Intel).where(Intel.kind == "knowledge", Intel.match_key == match_key)
    )).scalar_one_or_none()

    if existing is not None:
        existing.payload = payload
        existing.summary = synth["summary"][:500]
        existing.source_host = (synth["source_host"] or existing.source_host or "")[:255]
        existing.source_task_id = (finding.task_id or existing.source_task_id or "")[:32]
        existing.confidence = "verified"
        existing.hit_count = (existing.hit_count or 1) + 1
        existing.last_seen = now
        it = existing
    else:
        it = Intel(
            kind="knowledge",
            match_key=match_key,
            dedup_hash=dedup_hash,
            payload=payload,
            summary=synth["summary"][:500],
            source_host=synth["source_host"][:255],
            source_task_id=(finding.task_id or "")[:32],
            confidence="verified",
            hit_count=1,
            first_seen=now,
            last_seen=now,
        )
        session.add(it)

    await session.flush()
    if commit:
        await session.commit()
        await refresh_kb_cache(session)

    pl = it.payload or {}
    return {
        "id": it.id,
        "match_key": it.match_key or "",
        "category": pl.get("category", "user"),
        "origin": pl.get("origin", "distilled"),
        "name": pl.get("name", ""),
        "keyword": pl.get("keyword", ""),
        "summary": it.summary or "",
        "enabled": bool(pl.get("enabled", True)),
        "hit_count": it.hit_count or 1,
        "related": pl.get("related", []),
        "content": pl.get("content", ""),
        "created_at": to_cst_iso(it.first_seen),
        "updated_at": to_cst_iso(it.last_seen),
    }