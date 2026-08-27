"""业务状态机引导：多步业务流的绕过测试手法，业务逻辑洞的差异化来源。

背景：业务逻辑漏洞（越权/状态机/并发/审批流/金额篡改）需要先理解业务才能挖，
是通用扫描器挖不到的差异化来源。业务画像（business_profiler）告诉 worker
「测什么业务」，本模块告诉 worker「多步业务流怎么测」——步骤跳过、状态篡改、
令牌重放、并发竞态、审批绕过等具体手法。

- 纯规则确定性实现，可单测；不依赖 LLM。
- 输出短块注入 Worker prompt，按命中的业务类型/关键词裁剪，避免冗余。
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class _FlowPattern:
    flow_id: str
    label: str
    keywords: tuple[str, ...]      # 标题/描述/URL 命中关键词
    biz_ids: tuple[str, ...]       # 相关业务类型（business_profiler 的 biz_id）
    techniques: tuple[str, ...]    # 具体绕过测试手法


_FLOW_PATTERNS: tuple[_FlowPattern, ...] = (
    _FlowPattern(
        "multi_step_wizard", "多步表单/向导",
        ("报名", "申请", "注册", "开户", "预约", "下单", "填报", "提交申请", "wizard", "step", "多步", "流程"),
        ("jwc", "xsc", "rs", "oa", "pay", "book", "reg"),
        (
            "步骤跳过：直接请求第 N 步接口，看是否校验前置步骤完成（无 step token / 完成标记校验）",
            "步骤数据篡改：第 1 步提交 A，第 2 步把 A 改成 B，看后端是否信任前端状态而非重算",
            "步骤令牌缺失/复用：删除或复用前一步返回的 token/stepId，看是否仍放行",
        ),
    ),
    _FlowPattern(
        "approval_chain", "审批流",
        ("审批", "审核", "流程", "待办", "会签", "签批", "approval", "approve", "workflow", "wf"),
        ("oa", "hr", "pay", "xsc", "rs"),
        (
            "自审自批：用申请人身份调用审批通过接口，看是否校验审批人身份/权限",
            "跳过审批人：直接调用最终审批接口，看是否校验中间审批节点已完成",
            "审批状态篡改：把状态参数从待审批改成已通过/已驳回，看后端是否校验状态机迁移合法性",
        ),
    ),
    _FlowPattern(
        "payment_order", "支付/订单",
        ("支付", "订单", "下单", "退款", "金额", "优惠", "购物车", "结算", "pay", "order", "price", "amount", "refund"),
        ("pay", "mall", "canteen", "book"),
        (
            "金额/数量篡改：改价格、数量为负、优惠叠加，看后端是否重新计算而非信任前端",
            "支付状态跳变：把状态从未支付改成已支付/已发货，看后端是否校验支付回调",
            "并发下单/重复退款：同一订单并发提交，看是否绕过数量/库存/退款限制",
        ),
    ),
    _FlowPattern(
        "registration_activation", "注册/激活",
        ("注册", "激活", "验证码", "邮箱验证", "手机验证", "signup", "register", "activate", "activation", "captcha"),
        ("reg", "xsc", "jwc"),
        (
            "跳过验证步骤：直接请求激活/注册完成接口，看是否校验验证码/邮箱/手机已验证",
            "验证码重放/爆破：同一验证码多次使用、验证码可枚举",
            "激活状态篡改：把激活状态参数改成已激活，看后端是否校验",
        ),
    ),
    _FlowPattern(
        "booking_selection", "预约/选课/抢购",
        ("选课", "抢课", "预约", "报名", "抢购", "名额", "座位", "订座", "book", "select", "enroll", "grab"),
        ("jwc", "book", "mall", "canteen"),
        (
            "并发提交：同一资源并发提交，看是否绕过数量/名额限制（抢课/抢单/重复领取）",
            "名额绕过：退课再选、跨学期/跨场次越权选课、修改名额参数",
            "跨用户越权：替换 userId/studentId 操作他人预约/选课",
        ),
    ),
    _FlowPattern(
        "password_reset", "密码重置",
        ("密码重置", "找回密码", "改密", "忘记密码", "reset password", "forgot password", "change password"),
        ("reg", "jwc", "xsc", "oa"),
        (
            "步骤绕过：直接请求重置完成接口，看是否校验验证码/旧密码/邮箱验证",
            "token 复用/枚举：重置 token 可复用、可枚举、不失效",
            "用户枚举：重置接口对存在/不存在用户返回差异",
        ),
    ),
    _FlowPattern(
        "quota_credit", "积分/余额/优惠券",
        ("积分", "余额", "优惠券", "红包", "充值", "兑换", "point", "balance", "coupon", "credit", "recharge"),
        ("pay", "mall", "canteen", "xsc"),
        (
            "金额篡改：充值/兑换金额参数篡改、负数、精度溢出",
            "重复领取：同一优惠券/红包/积分并发重复领取",
            "越权使用：替换 userId 使用他人积分/余额/优惠券",
        ),
    ),
)


def detect_flow_patterns(
    *,
    business_id: str = "",
    title: str = "",
    description: str = "",
    url: str = "",
    priority_reason: str = "",
) -> list[_FlowPattern]:
    """按业务类型 + 目标信息命中相关状态机模式（按命中强度排序）。"""
    combined = " ".join([title or "", description or "", url or "", priority_reason or ""]).lower()
    scored: list[tuple[int, _FlowPattern]] = []
    for pat in _FLOW_PATTERNS:
        score = 0
        if business_id and business_id in pat.biz_ids:
            score += 2
        score += sum(1 for kw in pat.keywords if kw.lower() in combined)
        if score > 0:
            scored.append((score, pat))
    scored.sort(key=lambda x: x[0], reverse=True)
    return [pat for _, pat in scored]


def render_state_machine_block(
    *,
    business_id: str = "",
    title: str = "",
    description: str = "",
    url: str = "",
    priority_reason: str = "",
    max_patterns: int = 3,
) -> str:
    """渲染业务状态机引导块，注入 Worker。无命中返回空串。"""
    pats = detect_flow_patterns(
        business_id=business_id, title=title, description=description,
        url=url, priority_reason=priority_reason,
    )
    if not pats:
        return ""
    lines = ["# 业务状态机引导（多步业务流测试，业务逻辑洞是差异化核心）"]
    lines.append(
        "若目标存在多步业务流（向导/审批/支付/预约/注册激活等），不要只测单接口，"
        "按状态机视角测步骤间信任边界："
    )
    for pat in pats[:max_patterns]:
        lines.append(f"- {pat.label}：")
        for t in pat.techniques:
            lines.append(f"  - {t}")
    lines.append("纪律：只做无害验证（自建测试数据/哨兵），禁止破坏真实数据、禁止改密/删数据。")
    return "\n".join(lines) + "\n\n"
