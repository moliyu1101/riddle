"""公文级 Word 报告回归：报告模型、OOXML 合法性、转义与零新增依赖。

不引入 python-docx，直接按 OOXML 包结构校验，确保下载的文件能被 Word/WPS 打开。
"""
from __future__ import annotations

import io
import zipfile
from xml.etree import ElementTree as ET

from app.fusion import docx_report, traffic_ledger


def _finding(**overrides):
    base = {
        "id": "F1", "title": "SQL 注入导致数据泄露", "vuln_type": "sqli",
        "severity_claimed": "high", "target_url": "https://a.example.edu.cn/admin?id=1",
        "owner": "某归属单位", "description": "参数未过滤，可拼接查询。",
        "affected_scope": "管理后台查询接口", "poc": "curl -s 'https://a.example.edu.cn/admin?id=1'",
        "poc_http": "GET /admin?id=1 HTTP/1.1\r\nHost: a.example.edu.cn",
        "steps": [{"desc": "构造 payload", "poc": "id=1' OR 1=1--"}],
        "evidence": {"status_code": 200, "matched": True},
        "raw_response": "HTTP/1.1 200 OK",
    }
    base.update(overrides)
    return base


def test_build_report_model_defaults_and_groups():
    model = docx_report.build_report_model({"title": "标题"})
    assert model["title"] == "标题"
    assert model["subtitle"] == "安全测试报告"
    assert model["org"] == "—"
    assert model["impact_level"].startswith("L")
    assert model["review"]["verdict"] == "待复审"
    assert set(model["traffic"]) == set(traffic_ledger.ROLES)
    assert all(v == [] for v in model["traffic"].values())
    assert len(model["roadmap"]) == 4
    assert model["goals"] == {}


def test_build_report_model_consumes_finding_review_and_traffic():
    traffic = [
        {"role": "baseline", "method": "GET", "url": "u1", "status_code": 403, "body_sha256": "a" * 64},
        {"role": "proof", "method": "POST", "url": "u2", "status_code": 200, "body_sha256": "b" * 64,
         "request_head": "POST /admin HTTP/1.1"},
        {"role": "verification", "method": "GET", "url": "u3", "status_code": 200},
        {"role": "supporting", "method": "GET", "url": "u4", "status_code": 500},
    ]
    model = docx_report.build_report_model(
        _finding(),
        review={"verdict": "accepted", "severity_final": "high", "reviewer_notes": "已复现", "reproduced": True},
        goals_eval={"summary": "1/1 目标达成", "met": [{"title": "目标", "criteria": "状态码 200"}],
                    "unmet": [{"title": "待补", "reason": "缺证据"}]},
        traffic=traffic,
        meta={"org": "测试单位", "date": "2026-11-17"},
    )
    assert model["org"] == "测试单位" and model["date"] == "2026-11-17"
    assert model["target_url"].endswith("id=1")
    assert model["review"]["reproduced"] is True
    assert model["goals"]["summary"] == "1/1 目标达成"
    assert len(model["traffic"]["proof"]) == 1
    assert all(len(model["traffic"][r]) == 1 for r in traffic_ledger.ROLES)
    assert model["severity_color"] == docx_report._SEVERITY_COLOR["high"]
    assert len(model["steps"]) == 1 and model["steps"][0]["desc"] == "构造 payload"


def test_render_document_xml_is_well_formed_and_has_all_sections():
    model = docx_report.build_report_model(_finding(), traffic=[
        {"role": "proof", "method": "GET", "url": "https://a.example.edu.cn/x",
         "status_code": 200, "body_sha256": "a" * 64, "request_head": "GET /x HTTP/1.1"},
    ])
    xml = docx_report.render_document_xml(model)
    root = ET.fromstring(xml)  # 不合法会直接抛
    text = "".join(root.itertext())
    for section in ("目录", "一、执行摘要", "二、目标达成情况", "三、漏洞详情",
                    "四、复现步骤与 PoC", "五、流量证据链", "六、复测记录",
                    "七、修复路线图", "八、附录"):
        assert section in text, section
    assert "SQL 注入导致数据泄露" in text
    assert "GET /x HTTP/1.1" in text
    assert 'w:instr="TOC \\o &quot;1-2&quot; \\h \\z \\u"' in xml
    assert 'r:id="rIdH1"' in xml and 'r:id="rIdF1"' in xml


def test_docx_package_parts_relationships_and_content_types():
    data = docx_report.build_public_docx_bytes(docx_report.build_report_model(_finding()))
    assert data[:2] == b"PK"
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = set(zf.namelist())
        required = {
            "[Content_Types].xml", "_rels/.rels", "word/_rels/document.xml.rels",
            "word/document.xml", "word/styles.xml", "word/numbering.xml",
            "word/header1.xml", "word/footer1.xml", "docProps/core.xml", "docProps/app.xml",
        }
        assert required.issubset(names)
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                ET.fromstring(zf.read(name))  # 任一部件不合法都会直接抛
        doc_rels = ET.fromstring(zf.read("word/_rels/document.xml.rels"))
        ids = {el.get("Id") for el in doc_rels}
        assert {"rIdS1", "rIdN1", "rIdH1", "rIdF1"}.issubset(ids)
        targets = {el.get("Target") for el in doc_rels}
        assert all(f"word/{t}" in names for t in targets)
        ct = ET.fromstring(zf.read("[Content_Types].xml"))
        overrides = {el.get("PartName") for el in ct}
        assert "/word/document.xml" in overrides and "/word/header1.xml" in overrides
        doc = zf.read("word/document.xml").decode("utf-8")
        assert "五、流量证据链" in doc


def test_docx_escapes_special_characters_and_has_no_brand_hardcoding():
    model = docx_report.build_report_model(_finding(title='SQL <注入> & "引号" \'单引号\''))
    xml = docx_report.render_document_xml(model)
    ET.fromstring(xml)  # 特殊字符必须被转义，否则这里会抛
    assert "&lt;注入&gt;" in xml
    data = docx_report.build_public_docx_bytes(model)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        doc = zf.read("word/document.xml").decode("utf-8")
        for brand in ("工商银行", "阿里巴巴", "腾讯"):
            assert brand not in doc, "报告模板不得硬编码具体品牌示例"


def test_docx_header_footer_and_core_props_escape_content():
    model = docx_report.build_report_model(_finding(), meta={"classification": "内部 <资料> & 限授权"})
    data = docx_report.build_public_docx_bytes(model)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for name in ("word/header1.xml", "word/footer1.xml", "docProps/core.xml"):
            ET.fromstring(zf.read(name))
        assert "&lt;资料&gt;" in zf.read("word/header1.xml").decode("utf-8")
        assert "SQL 注入导致数据泄露" in zf.read("docProps/core.xml").decode("utf-8")
