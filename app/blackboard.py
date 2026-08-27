"""任务级黑板：单站协作下多 Worker 实时共享信息，避免重复路线。

黑板只做「镜子」不做「锁」：只共享信息，不限制任何 worker 发请求，
多 worker 并行能力完全保留，靠共享情报让 LLM 自主错开方向。

只会在单站协作任务（site_ 来源）中创建并传给 Worker；普通任务完全不感知。
"""
from __future__ import annotations

import threading
from collections import deque
from datetime import datetime
from typing import Any, Optional


def _now_iso() -> str:
    return datetime.now().astimezone().strftime("%H:%M:%S")


class Blackboard:
    """任务级共享黑板（线程安全，worker 跑在线程池里并发读写）。"""

    MAX_PROBED = 200       # 已探测 URL 上限
    MAX_COVERAGE = 60      # 覆盖记录上限
    MAX_LEADS = 40         # 线索上限
    MAX_EXCLUDED = 40      # 排除记录上限
    MAX_EVENTS = 60        # 事件环形缓冲

    def __init__(self, task_id: str):
        self.task_id = task_id
        self._lock = threading.RLock()
        # url -> {worker_id, ts}：已探测 URL，避免重复请求
        self._probed: dict[str, dict] = {}
        # 覆盖记录：测过的入口/参数/结论
        self._coverage: list[dict] = []
        # 线索：强线索（未打穿但值得追）
        self._leads: list[dict] = []
        # 排除：验证过打不穿的点
        self._excluded: list[dict] = []
        # worker_id -> 当前方向（软分工，不排他）
        self._directions: dict[str, str] = {}
        # 通用情报：key -> 条目列表
        self._entries: dict[str, list[dict]] = {}
        # 最近动作（环形缓冲，供事件流/前端）
        self._events: deque = deque(maxlen=self.MAX_EVENTS)

    # ---------- 通用发布/查询 ----------

    def publish(self, key: str, value: str, worker_id: str = "",
                confidence: str = "medium", source: str = "") -> dict:
        """发布一条共享情报到黑板，供其它 worker 实时可见。

        source: 发布者所属路线（site_map/site_auth 等），供前端按路线过滤黑板。
        """
        key = (key or "").strip()[:40]
        value = (value or "").strip()
        if not key or not value:
            return {"ok": False, "error": "key 和 value 都不能为空。"}
        if confidence not in ("high", "medium", "low"):
            confidence = "medium"
        entry = {
            "key": key,
            "value": value[:600],
            "worker_id": worker_id,
            "source": (source or "").strip()[:40],
            "confidence": confidence,
            "ts": _now_iso(),
        }
        with self._lock:
            self._entries.setdefault(key, []).append(entry)
            self._events.append(("publish", entry))
        return {"ok": True, "key": key, "message": f"已发布到黑板 key={key}，其它 worker 可见。"}

    def query(self, key: Optional[str] = None) -> dict:
        """查询黑板信息；key 留空返回全部键名与数量。"""
        with self._lock:
            if key:
                key = (key or "").strip()[:40]
                entries = list(self._entries.get(key, [])[-10:])
                return {"ok": True, "key": key, "entries": entries}
            return {
                "ok": True,
                "keys": {k: len(v) for k, v in self._entries.items()},
                "probed": len(self._probed),
                "coverage": len(self._coverage),
                "leads": len(self._leads),
                "excluded": len(self._excluded),
                "directions": dict(self._directions),
            }

    def declare(self, direction: str, worker_id: str = "") -> dict:
        """软分工：声明当前 worker 正在攻的方向（不排他，仅共享）。"""
        direction = (direction or "").strip()[:120]
        if not direction:
            return {"ok": False, "error": "direction 不能为空。"}
        with self._lock:
            self._directions[worker_id] = direction
            self._events.append(("declare", {"worker_id": worker_id, "direction": direction}))
        return {"ok": True, "message": "方向已声明，其它 worker 会看到并尽量错开。"}

    # ---------- 自动采集（worker 内部调用，不走 LLM 工具） ----------

    def note_probed(self, url: str, worker_id: str = "", source: str = "") -> None:
        """记录已探测 URL（http_request 命中后自动调用）。"""
        url = (url or "").strip()
        if not url:
            return
        with self._lock:
            if url in self._probed:
                return
            self._probed[url] = {"worker_id": worker_id, "source": (source or "").strip()[:40], "ts": _now_iso()}
            if len(self._probed) > self.MAX_PROBED:
                # 淘汰最旧的一条
                oldest = next(iter(self._probed))
                self._probed.pop(oldest, None)

    def add_coverage(self, record: dict, worker_id: str = "", source: str = "") -> None:
        """记录覆盖上报（report_coverage 命中后自动同步）。"""
        if not isinstance(record, dict) or not record:
            return
        with self._lock:
            self._coverage.append({
                "worker_id": worker_id,
                "source": (source or record.get("route") or "").strip()[:40],
                "ts": _now_iso(),
                **record,
            })
            if len(self._coverage) > self.MAX_COVERAGE:
                self._coverage.pop(0)

    def add_lead(self, text: str, worker_id: str = "", confidence: str = "medium", source: str = "") -> None:
        """记录强线索。"""
        text = (text or "").strip()[:400]
        if not text:
            return
        with self._lock:
            self._leads.append({
                "worker_id": worker_id,
                "source": (source or "").strip()[:40],
                "confidence": confidence if confidence in ("high", "medium", "low") else "medium",
                "text": text,
                "ts": _now_iso(),
            })
            if len(self._leads) > self.MAX_LEADS:
                self._leads.pop(0)

    def add_excluded(self, text: str, worker_id: str = "", source: str = "") -> None:
        """记录已排除（验证打不穿）的点。"""
        text = (text or "").strip()[:300]
        if not text:
            return
        with self._lock:
            self._excluded.append({
                "worker_id": worker_id,
                "source": (source or "").strip()[:40],
                "text": text,
                "ts": _now_iso(),
            })
            if len(self._excluded) > self.MAX_EXCLUDED:
                self._excluded.pop(0)

    # ---------- 快照 / 摘要 ----------

    def snapshot(self) -> dict:
        """完整快照（供前端协作面板拉取）。"""
        with self._lock:
            return {
                "task_id": self.task_id,
                "directions": dict(self._directions),
                "probed": [
                    {"url": u, "worker_id": p.get("worker_id", ""), "source": p.get("source", ""), "ts": p.get("ts", "")}
                    for u, p in list(self._probed.items())[-80:]
                ],
                "coverage": list(self._coverage)[-30:],
                "leads": list(self._leads)[-20:],
                "excluded": list(self._excluded)[-20:],
                "entries": {k: v[-10:] for k, v in self._entries.items()},
                "events": list(self._events)[-30:],
            }

    def summary(self, worker_id: str = "", limit: int = 900) -> str:
        """渲染成注入 prompt 的协作态势文本；黑板为空返回空串。"""
        with self._lock:
            directions = dict(self._directions)
            probed = list(self._probed.keys())
            coverage = list(self._coverage)
            leads = list(self._leads)
            excluded = list(self._excluded)
            entries = {k: v[-5:] for k, v in self._entries.items()}
        if not (directions or probed or coverage or leads or excluded or entries):
            return ""
        lines = ["# 协作黑板（实时共享：其它 worker 也在打同一站点，动手前先看，避免重复路线）"]
        if directions:
            lines.append("## 当前分工")
            for wid, d in list(directions.items())[:8]:
                mark = "（你）" if wid and wid == worker_id else ""
                lines.append(f"- {wid or '?'}{mark}：{d[:80]}")
        if probed:
            lines.append(f"## 已探测 URL（{len(probed)} 个，别再重复请求，优先找新入口）")
            lines.extend(f"- {u[:160]}" for u in probed[-20:])
        if coverage:
            lines.append(f"## 已覆盖入口（{len(coverage)} 条，测过就不要再测）")
            for c in coverage[-8:]:
                endpoints = c.get("endpoints") or []
                ep = endpoints[0] if endpoints else {}
                path = (ep.get("path") or ep.get("url") or "")[:120]
                method = (ep.get("method") or "GET").upper()
                result = (ep.get("result") or c.get("summary") or "")[:80]
                lines.append(f"- {method} {path} → {result}")
        if leads:
            lines.append("## 共享线索（未打穿但值得追，别重复验证）")
            for lead in leads[-6:]:
                conf = {"high": "高", "medium": "中", "low": "低"}.get(lead.get("confidence"), "中")
                lines.append(f"- [{conf}] {lead.get('text', '')[:160]}")
        if excluded:
            lines.append("## 已排除（验证打不穿，别浪费时间）")
            for ex in excluded[-5:]:
                lines.append(f"- {ex.get('text', '')[:120]}")
        if entries:
            lines.append("## 共享情报")
            for k, items in list(entries.items())[:6]:
                for it in items[-2:]:
                    lines.append(f"- [{k}] {it.get('value', '')[:140]}")
        text = "\n".join(lines)
        return text[:limit] + ("\n…（黑板内容较多，已截断）" if len(text) > limit else "")
