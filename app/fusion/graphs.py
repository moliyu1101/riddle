"""双图架构：资产图 × 探索图 + 血缘回溯 + 覆盖度。

旁路镜像，不替换 Riddle 现有的 Task/Target/Finding 状态机：从主表增量构建
两张只读图，让「这个结论是怎么推出来的」和「哪些资产还没测」成为可查询对象。

  资产图（跨任务可共享）: root_domain / subdomain / ip / service / app / endpoint
  探索图（每任务一份）  : goal / intent / fact / finding / hint
  边                    : spawns / derived_from / yields / proves / covers / anchors

移植的是机制，不含任何外部项目源码；节点 id 由本模块确定性生成，重建幂等。
"""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlsplit

from app.fusion import scope_guard

ASSET_KINDS = ("root_domain", "subdomain", "ip", "service", "app", "endpoint")
EXPLORATION_KINDS = ("goal", "intent", "fact", "finding", "hint")
EDGE_KINDS = ("spawns", "derived_from", "yields", "proves", "covers", "anchors")


def node_id(*parts: Any) -> str:
    raw = "|".join(str(p or "") for p in parts)
    return hashlib.sha1(raw.encode("utf-8", "ignore")).hexdigest()[:24]


def _label(value: Any, limit: int = 160) -> str:
    return str(value or "").strip()[:limit]


def asset_nodes(targets: list[Any]) -> tuple[list[dict], list[dict]]:
    """从 Target 列表构建资产图节点与 anchors 边。"""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add(kind: str, key: str, label: str, payload: dict | None = None) -> str:
        nid = node_id("asset", kind, key)
        nodes.setdefault(nid, {
            "id": nid, "graph": "asset", "kind": kind,
            "label": _label(label) or key, "ref_id": _label(key, 64),
            "payload": payload or {},
        })
        return nid

    for t in targets or []:
        url = t.get("url") if isinstance(t, dict) else getattr(t, "url", "")
        host = t.get("host") if isinstance(t, dict) else getattr(t, "host", "") or scope_guard.normalize_host(url)
        ip = t.get("ip") if isinstance(t, dict) else getattr(t, "ip", "") or ""
        title = t.get("title") if isinstance(t, dict) else getattr(t, "title", "") or ""
        ref = t.get("id") if isinstance(t, dict) else getattr(t, "id", "") or ""
        host = scope_guard.normalize_host(host) or scope_guard.normalize_host(url)
        if not host:
            continue
        root = scope_guard.root_domain(host)
        rid = add("root_domain", root, root)
        hid = add("subdomain", host, host)
        edges.append({"kind": "anchors", "src": hid, "dst": rid})
        if ip:
            ipid = add("ip", ip, ip)
            edges.append({"kind": "anchors", "src": hid, "dst": ipid})
        if url:
            try:
                parsed = urlsplit(url if "://" in url else f"http://{url}")
                path = parsed.path or "/"
            except ValueError:
                path = "/"
            eid = add("endpoint", f"{host}{path}", f"{host}{path}")
            edges.append({"kind": "anchors", "src": eid, "dst": hid})
            if title:
                aid = add("app", f"{host}:{title}", title)
                edges.append({"kind": "anchors", "src": eid, "dst": aid})
    return list(nodes.values()), edges


def exploration_nodes(
    goals: list[Any],
    findings: list[Any],
    events: list[Any] | None = None,
) -> tuple[list[dict], list[dict], dict[str, str]]:
    """从目标 / 漏洞 / 事件构建探索图；返回 (节点, 边, goal_id→node_id 映射)。"""
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    goal_map: dict[str, str] = {}

    def add(kind: str, key: str, label: str, ref_id: str = "", payload: dict | None = None) -> str:
        nid = node_id("exploration", kind, key)
        nodes.setdefault(nid, {
            "id": nid, "graph": "exploration", "kind": kind,
            "label": _label(label) or key, "ref_id": ref_id or _label(key, 64),
            "payload": payload or {},
        })
        return nid

    for g in goals or []:
        gid = str(g.get("id") or g.get("goal_key") or "") if isinstance(g, dict) else str(getattr(g, "goal_key", "") or "")
        title = g.get("title") if isinstance(g, dict) else getattr(g, "title", "")
        criteria = g.get("criteria") if isinstance(g, dict) else getattr(g, "criteria", "")
        gnode = add("goal", gid, title, gid, {"criteria": criteria})
        if gid:
            goal_map[gid] = gnode

    for e in (events or [])[:200]:
        kind = str(e.get("kind") or "") if isinstance(e, dict) else str(getattr(e, "kind", "") or "")
        msg = e.get("message") if isinstance(e, dict) else getattr(e, "message", "")
        if not kind:
            continue
        hint = add("hint", f"{kind}:{_label(msg, 40)}", msg or kind)
        if "finding" in kind:
            edges.append({"kind": "derived_from", "src": hint, "dst": hint})

    for f in findings or []:
        fid = str(f.get("id") or "") if isinstance(f, dict) else str(getattr(f, "id", "") or "")
        title = f.get("title") if isinstance(f, dict) else getattr(f, "title", "")
        sev = f.get("severity_claimed") if isinstance(f, dict) else getattr(f, "severity_claimed", "")
        fnode = add("finding", fid or title, title, fid, {"severity": str(sev)})
        # finding 证明目标：按标题/类型粗匹配，命中则连 proves 边
        for gid, gnode in goal_map.items():
            goal_node = nodes.get(gnode) or {}
            terms = [t for t in str(goal_node.get("label") or "").replace("，", " ").split() if len(t) >= 2]
            if terms and any(t in str(title) for t in terms):
                edges.append({"kind": "proves", "src": fnode, "dst": gnode})
        # 复现步骤 → fact 节点 → yields → finding
        steps = f.get("steps") if isinstance(f, dict) else getattr(f, "steps", []) or []
        for i, st in enumerate(steps[:12]):
            desc = st.get("desc") if isinstance(st, dict) else (getattr(st, "desc", "") if not isinstance(st, str) else st)
            if not desc:
                continue
            fact = add("fact", f"{fid}:step{i}", desc)
            edges.append({"kind": "yields", "src": fact, "dst": fnode})
    return list(nodes.values()), edges, goal_map


def lineage(
    nodes: list[dict],
    edges: list[dict],
    start: str,
    max_depth: int = 8,
    direction: str = "backward",
) -> list[dict]:
    """血缘遍历（BFS，防环），按边方向取三种视角。

    边的语义统一是「src 产生/指向 dst」：探索图 ``fact -yields-> finding``，
    资产图 ``endpoint -anchors-> subdomain -anchors-> root_domain``。因此：

    * ``backward``：沿指向当前节点的边回溯来源（finding → fact → goal）
    * ``forward``：沿从当前节点出发的边追下去（endpoint → subdomain → root）
    * ``both``：双向邻域，给前端点任意节点时展示完整血缘

    默认值保持 backward 不变，既有调用方无需改动。
    """
    if direction not in ("backward", "forward", "both"):
        direction = "backward"
    by_id = {n["id"]: n for n in nodes or []}
    if start not in by_id:
        return []
    seen = {start}
    queue: list[tuple[str, int]] = [(start, 0)]
    chain: list[dict] = []
    while queue:
        cur, depth = queue.pop(0)
        node = by_id.get(cur)
        if not node:
            continue
        chain.append({**node, "depth": depth})
        if depth >= max_depth:
            continue
        for e in edges or []:
            candidates: list[str] = []
            if direction in ("backward", "both") and e.get("dst") == cur:
                candidates.append(str(e.get("src") or ""))
            if direction in ("forward", "both") and e.get("src") == cur:
                candidates.append(str(e.get("dst") or ""))
            for nxt in candidates:
                if nxt and nxt in by_id and nxt not in seen:
                    seen.add(nxt)
                    queue.append((nxt, depth + 1))
    return chain


def coverage(nodes: list[dict], edges: list[dict]) -> dict:
    """资产覆盖度：被 covers 边命中的资产节点 / 全部资产节点。"""
    asset_ids = [n["id"] for n in nodes or [] if n.get("graph") == "asset"]
    covered = {e.get("dst") for e in edges or [] if e.get("kind") == "covers"}
    hit = sum(1 for nid in asset_ids if nid in covered)
    by_kind: dict[str, int] = {}
    for n in nodes or []:
        if n.get("graph") == "asset":
            by_kind[n.get("kind", "")] = by_kind.get(n.get("kind", ""), 0) + 1
    return {
        "asset_nodes": len(asset_ids),
        "covered": hit,
        "ratio": round(hit / len(asset_ids), 4) if asset_ids else 0.0,
        "by_kind": by_kind,
    }
