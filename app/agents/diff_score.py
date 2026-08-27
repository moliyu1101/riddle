"""差异化评分：识别“大众洞”并给 Finding 打差异化分，引导挖别人挖不到的洞。

背景：同类自动化工具泛滥，通用 SQLi/XSS/SSRF、已知框架 CVE、知名系统
（正方/金智/泛微/若依…）上的常规洞被反复提交，先到先得、后到全重复。
本模块从「类型 + 目标 + 证据」三个维度给 Finding 打 0-100 差异化分，
并产出两段可注入的短上下文：
- diff_strategy_block：目标级差异化策略，注入 Worker，引导优先业务逻辑/越权/状态机；
- review_diff_note：Finding 级差异化参考，注入 Reviewer，作为验收口径参考。

- 不替代 reviewer 的证据审查；只回答“这个洞是不是别人也一挖一大把”。
- 纯规则确定性实现，可单测；不依赖 LLM。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DiffScore:
    score: float
    tier: str                 # rare / differentiated / normal / common
    label: str                # 中文档位
    reasons: tuple[str, ...]  # 加分/减分理由
    common_hits: tuple[str, ...]  # 命中的大众洞特征
    suggestions: tuple[str, ...]  # 深挖建议

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 1),
            "tier": self.tier,
            "label": self.label,
            "reasons": list(self.reasons),
            "common_hits": list(self.common_hits),
            "suggestions": list(self.suggestions),
        }


# ---- 大众洞类型：扫描器/同类工具一挖一大把，差异化低 ----
# (关键词, 扣分, 标签)。关键词在 vuln_type/title/description 全文中匹配。
_COMMON_PATTERNS: tuple[tuple[str, float, str], ...] = (
    ("reflected_xss", 30, "反射型XSS"),
    ("反射型xss", 30, "反射型XSS"),
    ("反射xss", 30, "反射型XSS"),
    ("self-xss", 35, "Self-XSS"),
    ("self xss", 35, "Self-XSS"),
    ("stored_xss", 18, "存储型XSS"),
    ("存储型xss", 18, "存储型XSS"),
    ("xss", 22, "XSS"),
    ("sql_injection", 25, "SQL注入"),
    ("sql注入", 25, "SQL注入"),
    ("sqli", 25, "SQL注入"),
    ("command_injection", 12, "命令注入"),
    ("命令注入", 12, "命令注入"),
    ("open_redirect", 25, "开放重定向"),
    ("开放重定向", 25, "开放重定向"),
    ("directory_listing", 20, "目录列举"),
    ("目录列举", 20, "目录列举"),
    ("weak_password", 20, "弱口令"),
    ("弱口令", 20, "弱口令"),
    ("default_password", 20, "默认口令"),
    ("默认口令", 20, "默认口令"),
    ("captcha_bypass", 15, "验证码绕过"),
    ("验证码绕过", 15, "验证码绕过"),
    ("图形验证码", 18, "图形验证码回显"),
    ("算术验证码", 18, "算术验证码回显"),
    ("username_enum", 18, "用户名枚举"),
    ("用户名枚举", 18, "用户名枚举"),
    ("phpinfo", 30, "phpinfo泄露"),
    ("信息泄露", 12, "泛化信息泄露"),
    ("information_disclosure", 12, "泛化信息泄露"),
    ("info_leak", 12, "泛化信息泄露"),
    ("敏感信息泄露", 8, "敏感信息泄露"),
    ("sensitive_data_exposure", 8, "敏感信息泄露"),
    ("cve-", 20, "已知CVE"),
    ("nuclei", 20, "扫描器模板命中"),
    ("struts2", 18, "Struts2框架洞"),
    ("log4j", 18, "Log4j洞"),
    ("fastjson", 15, "Fastjson反序列化"),
    ("shiro", 12, "Shiro框架洞"),
    ("springboot", 8, "SpringBoot组件洞"),
    ("spring boot", 8, "SpringBoot组件洞"),
    ("nacos", 10, "Nacos组件洞"),
    ("druid", 10, "Druid组件洞"),
    ("swagger", 10, "Swagger文档暴露"),
    ("actuator", 10, "Actuator暴露"),
)

# ---- 差异化类型：业务逻辑/越权/状态机，通用工具难挖到 ----
_DIFF_PATTERNS: tuple[tuple[str, float, str], ...] = (
    ("idor", 25, "对象级越权IDOR"),
    ("越权", 22, "越权"),
    ("bfla", 25, "功能级越权BFLA"),
    ("business_logic", 30, "业务逻辑缺陷"),
    ("业务逻辑", 30, "业务逻辑缺陷"),
    ("logic_flaw", 30, "业务逻辑缺陷"),
    ("逻辑漏洞", 28, "业务逻辑缺陷"),
    ("auth_bypass", 20, "认证绕过"),
    ("认证绕过", 20, "认证绕过"),
    ("privilege_escalation", 25, "提权"),
    ("提权", 25, "提权"),
    ("account_takeover", 25, "账号接管"),
    ("账号接管", 25, "账号接管"),
    ("任意用户", 22, "任意用户接管"),
    ("unauthorized_access", 14, "未授权访问"),
    ("未授权", 12, "未授权访问"),
    ("payment", 30, "支付逻辑"),
    ("支付", 28, "支付逻辑"),
    ("金额", 26, "金额篡改"),
    ("workflow", 30, "审批流绕过"),
    ("审批", 24, "审批流绕过"),
    ("state_machine", 30, "状态机绕过"),
    ("状态机", 30, "状态机绕过"),
    ("race_condition", 25, "并发/竞态"),
    ("并发", 22, "并发/竞态"),
    ("竞态", 25, "并发/竞态"),
    ("jwt", 10, "JWT伪造"),
    ("jwt_forgery", 15, "JWT伪造"),
    ("sms_otp", 18, "短信OTP绕过"),
    ("短信otp", 18, "短信OTP绕过"),
    ("password_reset", 20, "密码重置缺陷"),
    ("密码重置", 20, "密码重置缺陷"),
    ("改密", 18, "改密缺陷"),
    ("email_verification", 20, "邮箱验证绕过"),
    ("验证码回显", 14, "验证码回显"),
    ("ssti", 5, "SSTI模板注入"),
    ("xxe", 5, "XXE"),
    ("deserialization", 5, "反序列化"),
    ("反序列化", 5, "反序列化"),
    ("ssrf", 5, "SSRF"),
)

# ---- 知名系统：被所有人反复挖，常规洞重复率极高 ----
_WELL_KNOWN_SYSTEMS: tuple[tuple[str, str], ...] = (
    ("正方", "正方教务"),
    ("zfsoft", "正方教务"),
    ("金智", "金智教育"),
    ("wisedu", "金智教育"),
    ("泛微", "泛微OA"),
    ("weaver", "泛微OA"),
    ("e-cology", "泛微E-cology"),
    ("致远", "致远OA"),
    ("seeyon", "致远OA"),
    ("用友", "用友"),
    ("yonyou", "用友"),
    ("金蝶", "金蝶"),
    ("kingdee", "金蝶"),
    ("蓝凌", "蓝凌OA"),
    ("landray", "蓝凌OA"),
    ("通达", "通达OA"),
    ("tongda", "通达OA"),
    ("万户", "万户OA"),
    ("大汉", "大汉CMS"),
    ("帆软", "帆软报表"),
    ("fanruan", "帆软报表"),
    ("finereport", "帆软报表"),
    ("若依", "若依RuoYi"),
    ("ruoyi", "若依RuoYi"),
    ("微擎", "微擎"),
    ("织梦", "织梦CMS"),
    ("dedecms", "织梦CMS"),
    ("帝国cms", "帝国CMS"),
    ("empirecms", "帝国CMS"),
    ("统一身份", "统一身份认证"),
    ("cas认证", "统一身份认证"),
    ("sso", "统一身份认证"),
)

# ---- 证据强弱信号 ----
_STRONG_EVIDENCE_MARKERS: tuple[str, ...] = (
    "身份证", "密码哈希", "密码hash", "明文口令", "md5", "sha256", "bcrypt",
    "sessiontoken", "session token", "accesskey", "access key", "secretkey",
    "私钥", "数据库密码", "db密码", "getshell", "webshell", "上传成功",
    "登录成功", "新密码登录", "状态已变化", "真实数据", "批量导出", "越权读取",
    "接管", "管理员权限", "后台权限", "命令执行", "命令回显", "uid=", "root:",
)
_WEAK_EVIDENCE_MARKERS: tuple[str, ...] = (
    "仅200", "空响应", "无回显", "无输出", "理论风险", "疑似", "可能存在",
    "扫描器结果", "接口存在", "配置不当", "未验证", "无实锤", "仅报错",
    "报错特征", "无实际影响", "只返回", "200/空",
)

# 差异化档位
_TIER_RULES: tuple[tuple[float, str, str], ...] = (
    (75.0, "rare", "稀有"),
    (60.0, "differentiated", "差异化"),
    (40.0, "normal", "普通"),
    (0.0, "common", "大众洞"),
)


def _tier_of(score: float) -> tuple[str, str]:
    for threshold, tier, label in _TIER_RULES:
        if score >= threshold:
            return tier, label
    return "common", "大众洞"


def _match(text: str, patterns: tuple[tuple[str, float, str], ...]) -> tuple[list[tuple[str, float]], set[str]]:
    hits: list[tuple[str, float]] = []
    labels: set[str] = set()
    for kw, delta, label in patterns:
        if kw in text:
            hits.append((kw, delta))
            labels.add(label)
    return hits, labels


def score_differentiation(
    *,
    vuln_type: str = "",
    title: str = "",
    description: str = "",
    target_url: str = "",
    owner: str = "",
    affected_scope: str = "",
    raw_response: str = "",
) -> DiffScore:
    """给一个 Finding 打差异化分（0-100，越高越差异化）。

    只依赖 Finding 自身字段，纯规则、确定性、可单测。
    """
    combined = " ".join([
        vuln_type or "", title or "", description or "",
        target_url or "", owner or "", affected_scope or "",
    ]).lower()
    evidence_text = (raw_response or "").lower()

    score = 50.0
    reasons: list[str] = []
    common_hits: list[str] = []
    suggestions: list[str] = []

    # 1) 类型维度：大众洞扣分
    common, common_labels = _match(combined, _COMMON_PATTERNS)
    if common:
        # 取最高扣分（同类型只扣一次）
        top = max(d for _, d in common)
        score -= top
        common_hits.extend(sorted(common_labels))
        reasons.append(f"大众洞类型：{'/'.join(sorted(common_labels))}（-{top:.0f}）")
        suggestions.append(
            "通用注入/XSS/重定向类大众洞已被同类工具反复提交；不要作为最终成果，"
            "沿业务链路继续深挖越权/状态机/业务逻辑。"
        )

    # 2) 类型维度：差异化类型加分
    diff, diff_labels = _match(combined, _DIFF_PATTERNS)
    if diff:
        top = max(d for _, d in diff)
        score += top
        reasons.append(f"差异化类型：{'/'.join(sorted(diff_labels))}（+{top:.0f}）")

    # 3) 目标维度：知名系统扣分
    for kw, label in _WELL_KNOWN_SYSTEMS:
        if kw in combined:
            score -= 15
            common_hits.append(label)
            reasons.append(f"知名系统：{label}（-15，人人都在挖）")
            suggestions.append(
                f"目标疑似 {label}，同类工具已大量提交；常规洞重复率高，"
                "必须打出该业务特有的越权/逻辑/状态机洞或独特利用链。"
            )
            break  # 只扣一次

    # 4) 证据维度
    strong = [m for m in _STRONG_EVIDENCE_MARKERS if m in combined or m in evidence_text]
    weak = [m for m in _WEAK_EVIDENCE_MARKERS if m in combined or m in evidence_text]
    if strong:
        score += 8
        reasons.append(f"强证据信号：{'/'.join(strong[:3])}（+8）")
    if weak:
        score -= 12
        reasons.append(f"弱证据信号：{'/'.join(weak[:3])}（-12，验收从严）")
        suggestions.append("证据偏弱（仅报错/空响应/理论风险），需补真实数据或状态变化实锤。")

    score = max(0.0, min(100.0, score))
    tier, label = _tier_of(score)
    return DiffScore(
        score=round(score, 1),
        tier=tier,
        label=label,
        reasons=tuple(reasons),
        common_hits=tuple(dict.fromkeys(common_hits)),
        suggestions=tuple(dict.fromkeys(suggestions)),
    )


def diff_strategy_block(
    *,
    business_id: str = "",
    business_label: str = "",
    playbook_route_id: str = "",
) -> str:
    """目标级差异化策略块，注入 Worker：大众洞规避 + 差异化重点。"""
    lines = ["# 差异化策略（大众洞规避）"]
    lines.append(
        "同类自动化工具泛滥，通用 SQLi/XSS/SSRF、已知框架 CVE、知名系统上的常规洞"
        "已被反复提交、重复率极高。差异化重点：优先业务逻辑/越权/状态机类漏洞"
        "（IDOR、水平/垂直越权、审批/支付/选课状态机绕过、账号接管、短信 OTP 绕过）。"
    )
    if business_id:
        lines.append(f"- 本目标业务：{business_label or business_id}，优先按该业务特有流程找逻辑洞。")
    if playbook_route_id in ("upload_business_idor", "api_authorization", "directed_deepen"):
        lines.append("- 当前路线偏业务/授权，重点验证对象级与功能级越权，别停在接口暴露。")
    lines.append(
        "- 若只发现通用注入/XSS 类大众洞：不要作为最终成果提交，继续沿业务链路深挖；"
        "确实打不出差异化成果再提交，并在描述里写明为何这条链路别人挖不到。"
    )
    return "\n".join(lines) + "\n\n"


def review_diff_note(ds: DiffScore) -> str:
    """Finding 级差异化参考，注入 Reviewer：验收口径参考，不替代证据审查。"""
    lines = ["# 差异化参考（验收口径参考，不替代证据审查）"]
    lines.append(f"该 Finding 差异化分 {ds.score:.0f}/100（{ds.label}）。")
    if ds.common_hits:
        lines.append("大众洞特征：" + "、".join(ds.common_hits[:6]) + "。")
    if ds.tier == "common":
        lines.append(
            "同类工具已大量提交此类洞，验收从严：证据必须实锤（真实数据/状态变化/可用凭证），"
            "否则 deepen 或 ignored，避免重复提交。"
        )
    elif ds.tier == "rare":
        lines.append("类型/链路较稀缺，证据充分即可正常 accepted，别因类型陌生误杀。")
    elif ds.tier == "differentiated":
        lines.append("差异化较好，证据实锤即可 accepted。")
    if ds.suggestions:
        lines.append("深挖建议：" + " ".join(ds.suggestions[:2]))
    return "\n".join(lines) + "\n\n"
