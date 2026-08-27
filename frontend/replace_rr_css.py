# -*- coding: utf-8 -*-
import io

p = r"c:\Users\田心渝\Desktop\tmp\src-hunter\frontend\src\styles\board.css"
with io.open(p, encoding="utf-8") as f:
    lines = f.readlines()

new_block = """/* ---------- 结果行（OPS LOG 视觉语言 v2）：左侧等级色条 + 微渐变卡片 ---------- */
.result-row {
  position: relative;
  display: flex; align-items: center; gap: 14px; padding: 13px 14px 13px 16px;
  background:
    linear-gradient(180deg, color-mix(in oklch, var(--surface) 88%, var(--bg)), var(--bg));
  border: 1px solid var(--border-soft); border-radius: 14px;
  margin-bottom: 10px; cursor: pointer; overflow: hidden;
  transition: border-color .15s, background-color .15s, transform .15s ease, box-shadow .15s ease;
}
.result-row::before {
  content: ""; position: absolute; left: 0; top: 10px; bottom: 10px; width: 3px;
  border-radius: 0 3px 3px 0; background: var(--border);
}
/* 等级色条：严重红 / 高危琥珀 / 中危青 / 低危灰（与 sev-pill 语义一致） */
.result-row.rr-critical::before { background: var(--danger); box-shadow: 0 0 10px color-mix(in srgb, var(--danger) 60%, transparent); }
.result-row.rr-high::before     { background: var(--warn);   box-shadow: 0 0 10px color-mix(in srgb, var(--warn) 60%, transparent); }
.result-row.rr-medium::before   { background: var(--info);   box-shadow: 0 0 10px color-mix(in srgb, var(--info) 60%, transparent); }
.result-row.rr-low::before      { background: var(--faint); }
.result-row:hover { border-color: var(--border); background: var(--surface); transform: translateY(-1px); box-shadow: 0 6px 22px -8px color-mix(in srgb, var(--accent) 45%, transparent); }
.result-row.submitted { opacity: .5; }
.result-row.rejected { opacity: .62; }
.result-row.rejected:hover { opacity: 1; }
/* AI 未采纳归档：默认淡出弱化存在感，悬浮时恢复，暗示「沉淀区、需要时才翻」 */
.result-row.archived { opacity: .68; }
.result-row.archived:hover { opacity: 1; }
.result-row.archived.write-op { opacity: 1; border-color: color-mix(in srgb, var(--warn) 45%, var(--border)); }
.write-flag {
  display: inline-block; font-size: 10px; font-style: normal; font-weight: 700;
  margin-left: 6px; padding: 2px 6px; border-radius: 6px;
  background: var(--warn-bg); color: var(--warn); line-height: 1.2;
}
.write-hint { color: var(--warn) !important; }
.arch-tag.write { background: var(--warn-bg); color: var(--warn); }
.rr-side { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex: none; }
/* 归档原因标：ignored=疑似误杀用告警色，deepen=深挖未升级用中性信息色 */
.arch-tag {
  display: inline-block; font-size: 10.5px; font-weight: 700; line-height: 1;
  padding: 3px 7px; border-radius: 6px; margin-right: 6px; vertical-align: 1px;
}
.arch-tag.ignored { background: var(--warn-bg); color: var(--warn); }
.arch-tag.deepen { background: var(--info-bg); color: var(--info); }
.rr-note { color: var(--danger); margin-top: 3px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.review-bar .rb-hint { font-size: 12.5px; color: var(--muted); }
.rr-main { flex: 1; min-width: 0; }
.rr-title { font-weight: 650; font-size: 14px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; letter-spacing: -.01em; }
.score {
  min-width: 42px; text-align: center; color: var(--ink);
  background: var(--surface); border: 1px solid var(--border-soft); border-radius: 9px;
  padding: 6px 8px; font-family: "IBM Plex Mono", monospace; font-size: 13px; font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.tag-done { font-size: 10.5px; background: var(--ok-bg); color: var(--ok); border-radius: 6px; padding: 2px 8px; margin-left: 8px; font-weight: 600; }
.tag-fail { font-size: 10.5px; background: var(--danger-bg); color: var(--danger); border-radius: 6px; padding: 2px 8px; margin-left: 8px; font-weight: 600; }
.tag-run { font-size: 10.5px; background: var(--info-bg); color: var(--info); border-radius: 6px; padding: 2px 8px; margin-left: 8px; font-weight: 600; }
.tag-miss { font-size: 10.5px; background: var(--surface-2); color: var(--muted); border-radius: 6px; padding: 2px 8px; margin-left: 8px; font-weight: 600; border: 1px solid var(--border); }
"""

lines[1300:1344] = [new_block]
with io.open(p, "w", encoding="utf-8", newline="") as f:
    f.writelines(lines)
print("替换完成，新块行数:", len(new_block.splitlines()))
