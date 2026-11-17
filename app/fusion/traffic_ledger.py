"""请求级流量留痕 + finding 四类证据绑定 + sha256 版本化。

边界说明：这是**留痕层**，不是 MITM 代理层。Riddle 的 http_request 已经把
请求/响应落进 evidence_trail，本模块在它的同一个钩子上再写一份结构化 JSONL，
并把记录关联到具体 finding（baseline / proof / verification / supporting），
让报告能引用「哪一次真实请求证明了这个结论」。

之所以不引入真正的 MITM 代理：那需要 CA 签发、独立监听端口、改所有出网路径，
会直接冲击 netguard / pinned IP / 会话保持这几条现有红线。留痕层零侵入、
默认关闭（FUSION_TRAFFIC=1 或融合页开关），启用后只追加一个本地文件，不改发包行为。
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

ROLES = ("baseline", "proof", "verification", "supporting")
JSONL_NAME = "fusion_traffic.jsonl"
_MAX_HEAD_CHARS = 4000
_MAX_IMPORT_ROWS = 2000


def _text(value: Any) -> str:
    return "" if value is None else str(value)


def _head(value: Any) -> str:
    return _text(value)[:_MAX_HEAD_CHARS]


def exchange_hash(row: dict) -> str:
    """请求+响应的内容指纹；同一请求重复执行也能区分不同响应。"""
    raw = "|".join(_text(row.get(k, "")) for k in ("method", "url", "request_head", "status_code", "response_head", "body"))
    return hashlib.sha256(raw.encode("utf-8", "ignore")).hexdigest()


def encode_exchange(result: dict, url: str, method: str, target: str = "") -> dict:
    """把 http_request 的返回值收敛成一条留痕记录（不落盘）。"""
    row = {
        "method": _text(result.get("final_method") or method or "GET").upper()[:10],
        "url": _text(result.get("url") or url)[:1000],
        "status_code": int(result.get("status_code") or 0),
        "request_head": _head(result.get("raw_request") or result.get("request") or ""),
        "response_head": _head(result.get("raw_response") or result.get("response_headers") or ""),
        "body": _head(result.get("body") or ""),
        "target": _text(target)[:255],
        "notes": _head(result.get("error") or ""),
        "ok": bool(result.get("ok")),
    }
    row["body_sha256"] = exchange_hash(row)
    return row


def append_jsonl(work_dir: str | Path, row: dict) -> bool:
    """同步追加一条留痕；任何 IO 异常都由调用方吞掉，绝不影响主请求。"""
    try:
        path = Path(work_dir) / JSONL_NAME
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        return True
    except OSError:
        return False


def capture_sync(work_dir: str | Path, result: dict, url: str, method: str, target: str = "") -> bool:
    """executor 钩子入口：编码 + 落盘，永不抛异常。"""
    try:
        return append_jsonl(work_dir, encode_exchange(result, url, method, target))
    except Exception:
        return False


def read_jsonl(work_dir: str | Path, limit: int = _MAX_IMPORT_ROWS) -> list[dict]:
    """读取留痕文件；损坏行跳过，按时间顺序返回。"""
    path = Path(work_dir) / JSONL_NAME
    if not path.exists():
        return []
    rows: list[dict] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if len(rows) >= limit:
                    break
                try:
                    item = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if isinstance(item, dict):
                    rows.append(item)
    except OSError:
        return []
    return rows


def classify_role(row: dict, *, has_finding: bool = False) -> str:
    """按记录特征推断证据用途；只做默认归类，最终以人工绑定为准。"""
    if not row.get("ok"):
        return "supporting"
    status = int(row.get("status_code") or 0)
    if has_finding and 200 <= status < 300:
        return "verification"
    if status in (401, 403):
        return "baseline"
    if 200 <= status < 300:
        return "proof"
    return "supporting"


def build_db_rows(rows: list[dict], task_id: str) -> list[dict]:
    """转成可直接写入 FusionTraffic 表的行（去重键为 body_sha256 + url）。"""
    out: list[dict] = []
    seen: set[str] = set()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        sha = str(row.get("body_sha256") or "") or exchange_hash(row)
        key = f"{sha}:{_text(row.get('url', ''))[:200]}"
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "task_id": task_id,
            "role": classify_role(row),
            "method": _text(row.get("method") or "GET")[:10],
            "url": _text(row.get("url") or "")[:1000],
            "status_code": int(row.get("status_code") or 0),
            "request_head": _head(row.get("request_head") or ""),
            "response_head": _head(row.get("response_head") or ""),
            "body_sha256": sha,
            "notes": _head(row.get("notes") or _text(row.get("target") or "")),
        })
    return out[:_MAX_IMPORT_ROWS]


def bindings_for_finding(bindings: list[dict], finding_id: str) -> dict[str, list[dict]]:
    """按四类证据角色分组，供报告引用。"""
    out: dict[str, list[dict]] = {r: [] for r in ROLES}
    for b in bindings or []:
        if str(b.get("finding_id") or "") != finding_id:
            continue
        role = str(b.get("role") or "supporting")
        out.setdefault(role, []).append(b)
    return out
