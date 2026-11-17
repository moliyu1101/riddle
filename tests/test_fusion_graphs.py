"""双图架构回归：资产图 / 探索图构建、血缘回溯、覆盖度统计。

图是旁路镜像，纯函数无 IO；节点 id 由内容确定性生成，重建必须幂等。
"""
from __future__ import annotations

from app.fusion import graphs


def _targets():
    return [
        {"id": "t1", "url": "https://a.example.edu.cn/admin?id=1",
         "host": "a.example.edu.cn", "ip": "93.184.216.34", "title": "管理后台"},
        {"id": "t2", "url": "https://b.example.edu.cn/api/v1",
         "host": "b.example.edu.cn", "ip": "", "title": ""},
    ]


def test_asset_nodes_kinds_and_multipart_suffix():
    nodes, edges = graphs.asset_nodes(_targets())
    kinds = {n["kind"] for n in nodes}
    assert {"root_domain", "subdomain", "ip", "app", "endpoint"}.issubset(kinds)
    assert all(n["graph"] == "asset" for n in nodes)
    labels = {n["label"] for n in nodes}
    # edu.cn 是多段公共后缀，根域必须保留三段而不是错误收敛成 edu.cn
    assert "example.edu.cn" in labels
    assert "a.example.edu.cn" in labels
    assert "a.example.edu.cn/admin" in labels
    assert all(e["kind"] == "anchors" for e in edges)
    assert len(edges) == 6  # t1: host/ip/endpoint/app；t2: host/endpoint


def test_asset_nodes_are_deterministic_and_deduped():
    first, first_edges = graphs.asset_nodes(_targets())
    again, again_edges = graphs.asset_nodes(_targets() + [_targets()[0]])
    assert {n["id"] for n in first} == {n["id"] for n in again}  # 节点按 id 去重，重建幂等
    assert len(again_edges) == len(first_edges) + 4  # 重复目标只多 4 条 anchors 边
    assert graphs.node_id("asset", "subdomain", "a.example.edu.cn") == \
           next(n["id"] for n in first if n["label"] == "a.example.edu.cn")


def test_asset_nodes_ignores_empty_targets_and_bad_urls():
    nodes, edges = graphs.asset_nodes([{}, {"url": "not a url", "host": ""}])
    assert nodes == [] or all(n["graph"] == "asset" for n in nodes)
    assert isinstance(edges, list)
    assert graphs.asset_nodes([]) == ([], [])


def test_exploration_nodes_proves_and_yields():
    goals = [{"id": "g1", "title": "证明 SQL 注入 可读取数据", "criteria": "HTTP/1.1 200 OK 响应字段"}]
    findings = [{
        "id": "f1", "title": "SQL 注入漏洞", "severity_claimed": "high",
        "steps": [{"desc": "构造 payload"}, "访问并对比响应"],
    }]
    events = [{"kind": "finding_submitted", "message": "提交漏洞"}]
    nodes, edges, goal_map = graphs.exploration_nodes(goals, findings, events)
    assert all(n["graph"] == "exploration" for n in nodes)
    assert "g1" in goal_map and set(goal_map.values()).issubset({n["id"] for n in nodes})
    assert {"goal", "fact", "finding", "hint"}.issubset({n["kind"] for n in nodes})
    assert any(e["kind"] == "proves" for e in edges), "标题命中目标词应连 proves 边"
    assert sum(1 for e in edges if e["kind"] == "yields") == 2
    assert any(n["kind"] == "fact" and n["label"] == "访问并对比响应" for n in nodes)


def test_exploration_nodes_handles_empty_and_string_steps():
    nodes, edges, mapping = graphs.exploration_nodes([], [], [])
    assert nodes == [] and edges == [] and mapping == {}
    nodes, edges, _ = graphs.exploration_nodes(
        [{"id": "g", "title": "目标", "criteria": "状态码 200"}],
        [{"id": "f", "title": "漏洞", "steps": "字符串步骤"}],
    )
    # steps 是字符串时按字符迭代，但每个字符仍会生成 fact 节点，不应抛异常
    assert any(n["kind"] == "finding" for n in nodes)
    assert all(e["kind"] in graphs.EDGE_KINDS for e in edges)


def test_lineage_backtracks_and_is_cycle_safe():
    nodes = [
        {"id": "A", "graph": "asset", "kind": "root_domain", "label": "根域"},
        {"id": "B", "graph": "asset", "kind": "subdomain", "label": "子域"},
        {"id": "C", "graph": "asset", "kind": "endpoint", "label": "端点"},
        {"id": "D", "graph": "exploration", "kind": "finding", "label": "结论"},
    ]
    edges = [
        {"kind": "anchors", "src": "B", "dst": "A"},
        {"kind": "anchors", "src": "C", "dst": "B"},
        {"kind": "derived_from", "src": "C", "dst": "D"},
        {"kind": "derived_from", "src": "C", "dst": "C"},  # 自环
        {"kind": "derived_from", "src": "D", "dst": "C"},  # 成环
    ]
    # 默认 backward：沿「指向当前节点」的边回溯来源；自环/成环不得重复入链
    backward = graphs.lineage(nodes, edges, "D")
    assert [c["id"] for c in backward] == ["D", "C"]
    assert [c["depth"] for c in backward] == [0, 1]
    # forward：沿「从当前节点出发」的边追下去，可覆盖整张图且不重复
    forward = graphs.lineage(nodes, edges, "C", direction="forward")
    assert forward[0]["id"] == "C"
    assert {c["id"] for c in forward} == {"A", "B", "C", "D"}
    assert len({c["id"] for c in forward}) == len(forward)
    # both：任意起点都能看到完整血缘邻域
    assert {c["id"] for c in graphs.lineage(nodes, edges, "A", direction="both")} == {"A", "B", "C", "D"}
    assert graphs.lineage(nodes, edges, "missing") == []
    assert len(graphs.lineage(nodes, edges, "D", max_depth=1)) == 2
    assert graphs.lineage(nodes, edges, "D", direction="nonsense") == backward


def test_coverage_counts_covers_edges():
    nodes = [
        {"id": "A", "graph": "asset", "kind": "root_domain"},
        {"id": "B", "graph": "asset", "kind": "endpoint"},
        {"id": "X", "graph": "exploration", "kind": "finding"},
    ]
    edges = [{"kind": "covers", "src": "coverage", "dst": "B"}]
    out = graphs.coverage(nodes, edges)
    assert out["asset_nodes"] == 2
    assert out["covered"] == 1
    assert out["ratio"] == 0.5
    assert out["by_kind"] == {"root_domain": 1, "endpoint": 1}
    assert graphs.coverage([], [])["ratio"] == 0.0
