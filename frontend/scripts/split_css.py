# -*- coding: utf-8 -*-
"""按分区把 style.css 拆成 6 个模块文件，保持级联顺序与注释。"""
import io
import os

SRC = r"c:\Users\田心渝\Desktop\tmp\src-hunter\frontend\src\style.css"
OUT_DIR = r"c:\Users\田心渝\Desktop\tmp\src-hunter\frontend\src\styles"

with io.open(SRC, "r", encoding="utf-8-sig") as f:
    lines = f.read().split("\n")

# 1-based 行号区间（含首尾），均为空行边界
sections = [
    ("base.css", 1, 228, "设计令牌 / 重置 / 滚动条 / 字阶 / 表单控件"),
    ("layout.css", 230, 1047, "顶栏 / 底部导航 / 加载 / 任务列表 / 表单 / 新建任务"),
    ("settings.css", 1049, 1906, "系统配置页 / 工作目录管理"),
    ("board.css", 1908, 3034, "任务指挥台 / 看板 / 事件流 / 抽屉 / 报告"),
    ("responsive.css", 3036, 3654, "手机端 / 无障碍减弱动效"),
    ("intel.css", 3656, 3950, "情报库 / 漏洞库 / 运行日志 / 署名"),
]

os.makedirs(OUT_DIR, exist_ok=True)

for name, start, end, desc in sections:
    body = lines[start - 1:end]
    # 去掉首尾多余空行
    while body and body[0].strip() == "":
        body.pop(0)
    while body and body[-1].strip() == "":
        body.pop()
    header = (
        "/* ============================================================\n"
        "   知蠹 Riddle — 作战终端 / 样式模块\n"
        f"   模块：{name} — {desc}\n"
        "   由 style.css 按分区拆分而来，级联顺序与语义不变。\n"
        "   ============================================================ */\n"
    )
    content = header + "\n" + "\n".join(body) + "\n"
    with io.open(os.path.join(OUT_DIR, name), "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    print(f"{name}: {len(body)} 行 -> {os.path.join(OUT_DIR, name)}")

print("拆分完成")
