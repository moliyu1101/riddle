"""证据沉淀链：把 worker 每次工具调用的真实请求/响应/输出增量落盘。

背景：submit_finding 是漏洞数据的唯一出口，但它是单次 LLM 调用返回超大 JSON。
一旦慢中转（后端 120s 硬截断）超时，finding 数据就随 LLM 失败一起丢失——
因为真正的证据（http_request 的请求/响应、run_shell 的输出）只存在于 worker
内存，从未落盘。

本模块让证据在【产生的那一刻】就增量落到 work_dir/evidence_trail.jsonl，
与 LLM 完全解耦。即使后面所有 LLM 调用都失败，已发生的攻击与取证永远在盘上，
可由确定性代码重建 Finding，不再依赖单次大响应。

- append_trail     : 一次工具调用后追加一条证据（线程安全）
- load_trail       : 读取整条证据链（按时间序）
- latest_trail     : 最近一条
- reset_trail      : 清空（仅测试用）
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Optional

_TRAIL_NAME = "evidence_trail.jsonl"
_lock = threading.RLock()

# 单条记录字段体积上限：正文/输出过大就截断标注（与 executor._truncate 一致思路），
# 避免几百条大响应把 work_dir 撑爆。原始 body 上限由 executor 的 _HTTP_MAX_BYTES 控制。
_BODY_LIMIT = 200 * 1024
_HEADER_LIMIT = 64 * 1024
_TRAIL_MAX_RECORDS = 2000   # 每目标最多保留 2000 条，防长期任务无限膨胀


def _trail_path(work_dir: Any) -> Path:
    return Path(work_dir) / _TRAIL_NAME


def _clip(text: str, limit: int) -> str:
    text = text or ""
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    return f"{head}\n\n...[取证超长已裁剪]...\n\n{tail}"


def append_trail(
    work_dir: Any,
    *,
    kind: str,
    target: str = "",
    tool: str = "",
    url: str = "",
    method: str = "",
    request: Optional[str] = None,
    response_headers: Optional[dict] = None,
    body: Optional[str] = None,
    status: Optional[int] = None,
    output: Optional[str] = None,
    notes: Optional[str] = None,
    extra: Optional[dict] = None,
) -> None:
    """追加一条低风险证据记录。任何失败都静默忽略，绝不阻断挖掘主流程。"""
    try:
        path = _trail_path(work_dir)
        with _lock:
            path.parent.mkdir(parents=True, exist_ok=True)
            rec = {
                "ts": time.time(),
                "kind": kind,
                "target": (target or "")[:200],
                "tool": (tool or "")[:60],
                "url": (url or "")[:500],
                "method": (method or "")[:12],
                "status": status,
                "request": _clip(request or "", _BODY_LIMIT),
                "body": _clip(body or "", _BODY_LIMIT),
                "output": _clip(output or "", _BODY_LIMIT),
                "notes": (notes or "")[:2000],
                "response_headers": _clip(json.dumps(response_headers or {}, ensure_ascii=False), _HEADER_LIMIT),
            }
            if extra:
                for k, v in extra.items():
                    try:
                        rec[k] = _clip(str(v), _BODY_LIMIT)
                    except Exception:
                        pass
            with path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            _trim(path)
    except Exception:
        pass


def _trim(path: Path) -> None:
    """超出条数上限时，截断到只保留最近 _TRAIL_MAX_RECORDS 条（保留文件尾）。"""
    try:
        size = path.stat().st_size
        if size < 4 * 1024 * 1024:
            return  # 未超 4MB 不频繁扫描
        with _lock:
            lines = path.read_text(encoding="utf-8").splitlines()
            if len(lines) > _TRAIL_MAX_RECORDS:
                path.write_text("\n".join(lines[-_TRAIL_MAX_RECORDS:]) + "\n", encoding="utf-8")
    except Exception:
        pass


def load_trail(work_dir: Any) -> list[dict[str, Any]]:
    """按时间序读取整条证据链。失败返回空列表。"""
    try:
        path = _trail_path(work_dir)
        if not path.exists():
            return []
        out: list[dict[str, Any]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                if isinstance(rec, dict):
                    # 兼容旧字段名解析失败
                    out.append(rec)
            except Exception:
                continue
        return out
    except Exception:
        return []


def latest_trail(work_dir: Any) -> Optional[dict[str, Any]]:
    try:
        trail = load_trail(work_dir)
        return trail[-1] if trail else None
    except Exception:
        return None