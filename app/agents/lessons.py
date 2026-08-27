"""经验知识引导：把跨业务/跨技术栈的通用打法与已知教训，按目标信号匹配后注入 Worker。

区别于 playbook（目标级打法路由）、biz_test_template（业务测试清单）、exploit_chain（漏洞利用链），
本模块是「过来人踩过的坑 + 通用高效打法」，用目标的技术栈标签/玩路/标题/归属做关键词匹配，
只在命中时注入，避免无意义刷屏。纯规则、可单测、零外部依赖。
"""
from __future__ import annotations

import re
from typing import Iterable

# 每条约 {id, title, when: 命中关键词列表, text}。
# when 按小写匹配 signals 里的任意词；all_when=True 时需全部命中。
_LESSONS: list[dict] = [
    {
        "id": "post_login_idor",
        "title": "登录后的首选：横向越权",
        "when": ["login", "后台", "管理", "user", "dashboard", "session", "登录"],
        "text": (
            "很多系统登录后默认不做对象级鉴权：拿到一个已登录会话后，优先测横向越权——"
            "换查询参数里的 id/手机号/工号/编号访问他人数据（详情/订单/成绩/资料），"
            "再看能否从『读』升到『写』（save/update/delete/reset）。这是 EDU 站最常出、也最好中审的洞。"
        ),
    },
    {
        "id": "api_docs",
        "title": "API 文档即攻击面",
        "when": ["swagger", "api-docs", "openapi", "spring", "flask", "django", "接口"],
        "text": (
            "Spring/Flask/Django 类系统常带 /v2/api-docs、/swagger-ui.html、/api-docs 等接口文档且未关鉴权。"
            "先探这些路径：拿到完整接口清单和无鉴权接口，往往直接就是未授权访问/信息泄露的起点；"
            "若文档被拦，先从 JS/网页里挖接口再打。"
        ),
    },
    {
        "id": "upload_chain",
        "title": "文件上传别只看回显",
        "when": ["upload", "上传", "附件", "头像", "file", "文件"],
        "text": (
            "测文件上传补全链路：②扩展名白名单绕过（截断/大小写/双扩展/换 MIME）；"
            "①上传成功后立刻用返回 URL 直接 GET 访问，确认文件是否真实落库并可访问；"
            "③能否访问到其他用户上传的文件（越权读）。只传上去不算数，能访问/能执行才算实锤。"
        ),
    },
    {
        "id": "state_flow",
        "title": "多步业务流测跳转/伪造",
        "when": ["支付", "缴费", "审批", "订单", "预约", "报名", "选课", "流程", "多步", "step"],
        "text": (
            "缴费/审批/预约/报名这类多步流程，重点测：①跳过步骤直接调最终落地接口（未完成前置也能提交）；"
            "②伪造/篡改流程 token 或步骤号；③先付后拦截/改金额再提交；④并发抢名额/重复提交。"
            "这类业务逻辑洞属于差异化加分项，比通用 SQLi 更容易被审出价值。"
        ),
    },
    {
        "id": "spa_api",
        "title": "SPA 后端接口多未授权",
        "when": ["spa", "vue", "react", "webpack", "前端", "javascript", "api_exposed"],
        "text": (
            "Vue/React 单页应用：前端打包里往往带完整后端 API 路径和参数说明，且很多接口后端没做鉴权。"
            "用 analyze_javascript 从 JS/页面挖出接口清单后，逐条用 http_request 直接打，"
            "重点找 list/get/info/export/download 这类只读接口是否未鉴权返回真实数据。"
        ),
    },
    {
        "id": "error_leak",
        "title": "报错信息即泄露",
        "when": ["报错", "exception", "错误", "traceback", "sql error"],
        "text": (
            "故意传非法参数（超长/类型错/特殊字符）触发异常，观察响应是否回显 SQL 语句、Java/Python 堆栈、"
            "绝对路径、数据库类型或连接串。能复现任意参数触发回显即信息泄露实锤；"
            "别停留在『页面报错』，要抓到具体的敏感字段才算数。"
        ),
    },
    {
        "id": "json_api",
        "title": "JSON 接口优先测参数篡改",
        "when": ["json", "rest", "api", "接口", "ajax", "graphql"],
        "text": (
            "JSON/REST 接口：优先测①布尔/枚举参数篡改（isAdmin/payStatus/done 翻成 1 或已结算）；"
            "②数值参数篡改（金额/数量/余额改大改小）；③并发竞态（同一请求打多次看是否重复入账/重复发放）。"
            "这些直接命中业务逻辑/越权，差异化分高。"
        ),
    },
    {
        "id": "captcha_weakpwd",
        "title": "无验证码登录测弱口令",
        "when": ["login", "弱口令", "登录", "账号密码", "auth", "认证", "无验证码"],
        "text": (
            "登录页没有验证码/锁定机制时，可用 credential_brute 做限量弱口令验证（内置小字典，限量限速，不会锁号）。"
            "登录成功本身不是洞——要拿登录态继续深挖越权/敏感数据/写操作才算。有验证码时别硬爆，改用已验证凭证固化登录态。"
        ),
    },
    {
        "id": "git_backup",
        "title": "源码/备份泄露要尝",
        "when": ["备份", "源码", ".git", "backup", "备份文件", "源码泄露", "www.zip"],
        "text": (
            "顺手探 .git/config、.env、application.yml、www.zip、bak.sql 等敏感文件："
            "命中即源码/配置/数据库备份泄露，从泄露内容往往能抠出数据库口令、AK/SK、后台账号，"
            "再回打登录/管理接口就是一条完整链。只读到文件内容并附关键片段即实锤。"
        ),
    },
    {
        "id": "export_download",
        "title": "导出/下载接口常越权",
        "when": ["export", "download", "导出", "下载", "report", "打印"],
        "text": (
            "导出/下载/打印类接口是越权高发区：改 id/编号参数可导别人数据，或用文件下载接口路径穿越读任意文件。"
            "测导出时先拿真实数据范围，能导出含他人手机号/学号/身份证的完整台账即实锤，附脱敏或最小字段举证。"
            "注意：不要导出全量海量数据进行脱库，药按 EduSRC 最小举证原则只取证明危害的小样本。"
        ),
    },
]


def _norm(text: str) -> str:
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", " ", str(text or "").lower())


def match_lessons(signals: Iterable[str], limit: int = 3) -> list[dict]:
    """给定目标信号（路由/标签/标题/归属/备注的字符串），返回命中的经验条目。

    命中判定：条目的 when 关键词里，若出现「可由人工标注的强词」(when_all 标记)则要求全中，
    否则任一关键词出现在 signals 拼接文本里即命中。返回按 id 稳定排序，避免随机性。
    """
    joined = _norm(" ".join(s for s in signals if s))
    if not joined:
        return []
    hits: list[dict] = []
    for lesson in _LESSONS:
        when = [k for k in lesson["when"] if k]
        if not when:
            continue
        matched = [k for k in when if _norm(k) in joined]
        if matched:
            hits.append({**lesson, "matched": [k for k in when if _norm(k) in joined]})
    hits.sort(key=lambda x: x["id"])
    return hits[:limit]


def render_lessons_block(signals: Iterable[str], limit: int = 3) -> str:
    """渲染经验引导块；无命中返回空串，不注入任何文本。"""
    hits = match_lessons(signals, limit=limit)
    if not hits:
        return ""
    lines = ["# 经验引导（同类站点常见高效打法，按需参考，不强制逐条执行）"]
    for i, h in enumerate(hits, 1):
        lines.append(f"{i}. 【{h['title']}】{h['text']}")
    return "\n".join(lines) + "\n\n"