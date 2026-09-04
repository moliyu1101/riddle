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
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Intel

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
    # 覆盖 seed(种子) + 用户手动添加两类条目：种子用 kb: 前缀，用户条目用 kbu: 前缀。
    stmt = select(Intel).where(Intel.kind == "knowledge")
    rows = (await session.execute(stmt)).scalars().all()
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
    """按篇目名/关键词查知识库全文（读 knowledge 目录文件，同步、无 DB 依赖）。

    知识库文档互相引用（如「见 authbypass-test.md §18」），worker 看到跳转指引时
    用本函数查对应篇目全文。精确命中篇目名返回全文；否则按关键词返回候选列表。
    """
    query = (query or "").strip().lower()
    if not query:
        return {"ok": False, "error": "query 不能为空"}
    if query.endswith(".md"):
        query = query[:-3]
    files: list[tuple[str, str, Path]] = []
    for category, folder in (("rules", _RULES_DIR), ("kb", _KB_DIR)):
        if not folder.exists():
            continue
        for p in sorted(folder.glob("*.md")):
            files.append((p.stem, category, p))
    known = {f[0] for f in files}

    def _read(name: str, category: str, path: Path) -> dict:
        content = path.read_text(encoding="utf-8", errors="ignore")
        return {
            "ok": True,
            "query": query,
            "name": name,
            "category": category,
            "title": _human_title(name),
            "related": _parse_refs(content, known),
            "content": content[:max_chars],
            "truncated": len(content) > max_chars,
        }

    exact = [f for f in files if f[0].lower() == query]
    if exact:
        return _read(*exact[0])
    partial = [f for f in files if query in f[0].lower()]
    if partial:
        out = _read(*partial[0])
        out["matches"] = [
            {"name": f[0], "category": f[1], "title": _human_title(f[0])} for f in partial
        ]
        return out
    hits: list[dict] = []
    parts = _kw_parts(query)
    need = min(2, len(parts))  # 中文 2 字窗口至少命中 2 个，避免单窗口误命中
    for name, category, path in files:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        low = content.lower()
        if sum(1 for p in parts if p in low) >= need:
            hits.append({"name": name, "category": category, "title": _human_title(name)})
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