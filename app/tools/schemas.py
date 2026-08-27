"""工具的 function calling schema 定义。

submit_finding 的参数 schema 直接对应 Finding 结构，强制 LLM 结构化输出
（用户决策：工具参数 schema 为主 + Pydantic 兜底校验）。
"""
from __future__ import annotations

TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "发一个 HTTP 请求并返回完整的请求包，以及状态码、响应头和响应体。挖洞取证的首选工具。会自动携带并吸收 Cookie（含整条重定向链每一跳的 Set-Cookie），登录后深挖无需每次手拼凭证。【登录/CAS/SSO 场景】务必把 follow_redirects 设为 true：一次 POST 账号密码即可自动走完 302 连环跳（lt→CASTGC→ST ticket→JSESSIONID），返回里的 redirect_chain/final_url 可看清跳到哪、是否登录成功；别再手动一跳跳拼 ticket。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "完整 URL"},
                    "method": {"type": "string", "description": "HTTP 方法", "default": "GET"},
                    "headers": {"type": "object", "description": "请求头键值对", "additionalProperties": {"type": "string"}},
                    "data": {"type": "string", "description": "请求体原始字符串（如表单 a=1&b=2）"},
                    "json_body": {"type": "object", "description": "JSON 请求体（与 data 二选一）"},
                    "follow_redirects": {"type": "boolean", "default": False, "description": "是否自动跟随 302/301 跳转。登录/CAS/SSO 走通登录链必须设 true（自动带齐每跳 Cookie）。仅想看单跳 302 目标时才用 false。"},
                    "confirm_destructive": {"type": "boolean", "default": False, "description": "疑似删库/清缓存/覆盖文件时会先暂停让你反思。确认无害后再设 true。"},
                    "confirm_reason": {"type": "string", "description": "确认时必填：为何无害（SRC_TEST_/ROLLBACK/只证明接口存在）。"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "在工作目录执行 shell 命令并返回输出。可用 curl/nuclei/sqlmap/nmap/httpx/whatweb 或自写脚本。扫描器仅在已有明确入口/参数/模板时辅助，禁止泛扫。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "要执行的完整命令"},
                    "timeout": {"type": "integer", "description": "超时秒数，默认 120"},
                    "confirm_destructive": {"type": "boolean", "default": False, "description": "疑似删库/清缓存/覆盖文件时会先暂停让你反思。确认无害后再设 true。"},
                    "confirm_reason": {"type": "string", "description": "确认时必填：为何无害（SRC_TEST_/ROLLBACK/只证明接口存在）。"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_transform",
            "description": "纯本地解析编码/凭证：解码 base64/hex/url、解析 JWT(看 alg/payload 给攻击建议)、识别哈希、计算 md5/sha1/sha256。遇到看不懂的 token/参数/响应值先用它看清结构。零副作用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "value": {"type": "string", "description": "要解析的字符串（token/编码串/凭证/响应字段值）"},
                    "mode": {
                        "type": "string",
                        "enum": ["auto", "base64", "hex", "url", "jwt", "hash"],
                        "description": "auto=自动尝试所有；指定则只做该种；hash=计算哈希并识别输入像哪种哈希。默认 auto。",
                        "default": "auto",
                    },
                },
                "required": ["value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "suggest_waf_bypass",
            "description": "纯本地 WAF 辅助：具体验证请求被 403/406/429/拦截页阻断时，据状态码/响应头/体和 payload 判断 WAF 指纹并给少量候选变形。不代表已绕过，必须再用 http_request 做 baseline vs variant 实证。",
            "parameters": {
                "type": "object",
                "properties": {
                    "payload": {"type": "string", "description": "被拦截的最小 payload 或可控参数值"},
                    "status_code": {"type": "integer", "description": "被拦截响应的 HTTP 状态码，如 403/406/429"},
                    "response_headers": {"type": "object", "description": "被拦截响应头", "additionalProperties": {"type": "string"}},
                    "response_body": {"type": "string", "description": "被拦截响应体片段"},
                    "context": {
                        "type": "string",
                        "enum": ["generic", "sqli", "xss", "path", "json", "api", "header"],
                        "description": "当前验证场景，用于排序候选变形",
                        "default": "generic",
                    },
                },
                "required": ["payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fofa_lookup",
            "description": "只读资产测绘（走任务所选引擎 FOFA/Quake/Hunter/…，统一用 FOFA 语法书写、自动翻译）：①确认目标归属(org/备案/证书)把 owner 填准；②查同 IP/同域开放的端口服务找隐藏攻击面。只测绘不碰目标。拿裸 IP/确认不了归属时尤其有用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": 'FOFA 语法（非 FOFA 引擎自动翻译），如 ip="1.2.3.4" / host="example.com" / domain="x.com"'},
                    "size": {"type": "integer", "description": "返回样本数，默认 10，最大 30", "default": 10},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "asset_discovery",
            "description": "主动侦察攻击面（只读）：①subdomain=用测绘引擎/内置字典枚举子域；②path=探测高价值敏感路径（后台/上传/导出/配置/备份/源码/API文档）；③same_ip=解析目标IP后用测绘引擎/TCP探测找同IP其它资产。解决手动清单只给根域时攻击面不足。只读GET+短超时+小规模，不碰数据。",
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "目标域名或 URL，如 example.com 或 https://example.com"},
                    "enum_type": {"type": "string", "enum": ["subdomain", "path", "same_ip"], "description": "枚举类型，默认 subdomain"},
                    "max_results": {"type": "integer", "description": "返回结果上限，默认 20，最大 40"},
                },
                "required": ["target", "enum_type"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "fingerprint",
            "description": "识别目标系统/中间件/框架/WAF/组件版本并匹配内置已知漏洞表（CVE/PoC思路）。传 URL 自动只读抓取，或直接传已拿到的响应头/body/title。纯本地匹配，只给验证思路不自动打；命中后按 verify 用 http_request 实证。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL（自动发 GET 抓响应头/body）"},
                    "headers": {"type": "object", "description": "已拿到的响应头（与 url 二选一）", "additionalProperties": {"type": "string"}},
                    "body": {"type": "string", "description": "已拿到的响应体片段"},
                    "title": {"type": "string", "description": "页面标题"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "verify_known_vuln",
            "description": "指纹实测验证链：对 fingerprint 命中的已知漏洞逐条发只读 GET 探针，判定特征是否命中（如 Nacos 未授权列用户、Swagger 空访问、Actuator 泄露、Shiro rememberMe、Grafana 读 passwd 等）。只读探测不碰数据；命中只代表组件/端点暴露，需按实际危害确认后再提交。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL（与 fingerprint 同一目标）"},
                    "vuln_name": {"type": "string", "description": "要实测的已知漏洞名（取 fingerprint 返回 known_vulns 里的 name）"},
                },
                "required": ["url", "vuln_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "credential_brute",
            "description": "弱口令验证（限量限速）：内置分层字典（通用/教育）+ 自动识别登录表单 + 登录成功判定。命中即停并保持会话；检测验证码/锁定即停止；默认最多 20 次防 DoS。只对授权目标做无害验证，登录成功本身不是洞。",
            "parameters": {
                "type": "object",
                "properties": {
                    "login_url": {"type": "string", "description": "登录页 URL（会自动识别表单字段）"},
                    "username": {"type": "string", "description": "要验证的用户名（如 admin/学号/工号）"},
                    "usernames": {"type": "array", "items": {"type": "string"}, "description": "多个用户名（与 username 二选一）"},
                    "passwords": {"type": "array", "items": {"type": "string"}, "description": "自定义密码候选（可选，默认用内置字典）"},
                    "use_builtin_dict": {"type": "boolean", "default": True, "description": "是否使用内置弱口令字典"},
                    "max_attempts": {"type": "integer", "description": "最多尝试次数，默认 20，最大 40"},
                    "edu_mode": {"type": "boolean", "default": False, "description": "教育场景：用教育弱口令字典"},
                },
                "required": ["login_url", "username"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "login_session",
            "description": "登录态自动化：用账密自动登录并保持会话，后续 http_request 自动携带 Cookie。登录成功本身不是洞，登录后深挖越权/敏感数据/写操作才算。",
            "parameters": {
                "type": "object",
                "properties": {
                    "login_url": {"type": "string", "description": "登录页或登录 API URL"},
                    "username": {"type": "string", "description": "账号"},
                    "password": {"type": "string", "description": "密码"},
                },
                "required": ["login_url", "username", "password"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "login_form_scan",
            "description": "登录入口/表单侦察：探测常见登录路径，识别表单字段与验证码，给登录构造建议。定位登录入口后：无验证码可直接 credential_brute 弱口令验证；有验证码则人工过验证码后提供 Cookie。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL（根域或任意页面）"},
                    "max_paths": {"type": "integer", "description": "最多探测登录路径数，默认 8"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "check_duplicate_finding",
            "description": "提交漏洞前查重：用类型/标题/URL 对比全局同系统历史漏洞。只拦同系统同洞；duplicate=true 时不要再 submit，同系统其它 endpoint/类型/证据链可继续挖。",
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型，如 idor/unauthorized_access/sql_injection"},
                    "title": {"type": "string", "description": "准备提交的漏洞标题"},
                    "target_url": {"type": "string", "description": "漏洞所在URL"},
                    "description": {"type": "string", "description": "简要描述，用于辅助模糊查重"},
                },
                "required": ["vuln_type", "title", "target_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_finding",
            "description": (
                "提交一个确认的漏洞。提交前必须先用 http_request/run_shell 取得真实证据"
                "（原始请求/响应包）。提交前必须如实填写 self_check 自检。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "漏洞类型，如 sql_injection/rce/captcha_bypass/idor/unauthorized_access/file_upload"},
                    "title": {"type": "string", "description": "[目标]-[模块]-[简述]"},
                    "severity_claimed": {"type": "string", "enum": ["严重", "高危", "中危", "低危"]},
                    "target_url": {"type": "string"},
                    "owner": {"type": "string", "description": "归属单位/业务系统 + 确认依据。EduSRC 写学校/教育机构；企业模式写企业/集团/系统，如「XX集团 CRM（依据：证书CN+页面版权）」；核实不了填「待确认（原因…）」"},
                    "description": {"type": "string", "description": "漏洞类型、触发条件、影响范围"},
                    "steps": {"type": "array", "items": {"type": "string"}, "description": "逐条复现步骤"},
                    "poc": {"type": "string", "description": "可执行 PoC，curl 命令或 payload"},
                    "raw_request": {"type": "string", "description": "原始请求包"},
                    "raw_response": {"type": "string", "description": "原始响应包，含证明漏洞的关键差异"},
                    "evidence": {
                        "type": "object",
                        "properties": {
                            "extracted_data_sample": {"type": "string"},
                            "tool_output": {"type": "string"},
                            "notes": {"type": "string"},
                        },
                    },
                    "affected_scope": {"type": "string", "description": "影响面"},
                    "kill_chain": {
                        "type": "array",
                        "description": "攻击链路：按时间顺序记录你怎么一步步打下来的（侦察→定位→利用→取证），让人一眼看懂这洞的拿下方法",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": {"type": "string", "description": "这一步的方法/动作，如『审计前端JS』『提取API端点』『构造越权请求』『取出数据取证』"},
                                "detail": {"type": "string", "description": "这步具体做了什么、发现或得到了什么"},
                            },
                            "required": ["method"],
                        },
                    },
                    "self_check": {
                        "type": "object",
                        "description": "对照当前 SRC 模式忽略清单的自检",
                        "properties": {
                            "is_reflected_xss": {"type": "boolean"},
                            "needs_admin_login": {"type": "boolean"},
                            "needs_mitm": {"type": "boolean"},
                            "is_pure_info_leak": {"type": "boolean"},
                            "scanner_only_no_poc": {"type": "boolean"},
                            "is_public_interface": {"type": "boolean", "description": "该接口是否本就是面向公众的公开接口"},
                            "info_leak_hits_strict_list": {"type": "boolean", "description": "若信息泄露类：是否命中身份证照片/大头照/身份证号/密码哈希死规矩"},
                        },
                        "required": ["is_reflected_xss", "needs_admin_login", "needs_mitm", "is_pure_info_leak", "scanner_only_no_poc"],
                    },
                },
                "required": ["vuln_type", "title", "severity_claimed", "target_url", "description", "steps", "poc", "kill_chain", "self_check"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_intel",
            "description": "把可复用情报沉淀到全局情报库供后续 worker 复用。只报真验证有效的高价值情报：①cred=验证过能登录的账密；②endpoint=验证有效的未授权/敏感端点；③profile=技术栈/WAF/突破口画像。出洞或撞库成功后顺手报一条。维护器会拦截垃圾(未验证凭证/公开静态浅路径/占位画像/含失败结论)，别报这些。",
            "parameters": {
                "type": "object",
                "properties": {
                    "kind": {"type": "string", "enum": ["cred", "endpoint", "profile"], "description": "情报类型"},
                    "payload": {
                        "type": "object",
                        "description": "按 kind 填：cred={username,password}；endpoint={path,vuln_type}；profile={key,value}",
                        "additionalProperties": {"type": "string"},
                    },
                    "summary": {"type": "string", "description": "一句话说明（可选），如『后台弱口令可登』"},
                    "verified": {"type": "boolean", "description": "是否亲自验证有效（true 会标记为高可信）", "default": False},
                },
                "required": ["kind", "payload"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_coverage",
            "description": "单站协作覆盖记录：把本路线已经盘点/验证过的 API、参数、测试类型和结论记下来，供后续 worker 避免重复并补盲区。没出洞也要在收尾前报告覆盖面。",
            "parameters": {
                "type": "object",
                "properties": {
                    "route": {"type": "string", "description": "当前路线名，如 site_map/site_js/site_auth，可留空由系统补"},
                    "summary": {"type": "string", "description": "一句话总结本轮覆盖面和主要结论"},
                    "endpoints": {
                        "type": "array",
                        "description": "已测试的接口/入口样例，控制在 20 条内，按价值排序",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": {"type": "string", "description": "GET/POST/PUT/DELETE 等"},
                                "path": {"type": "string", "description": "路径或完整 URL"},
                                "status": {"type": "string", "description": "状态码或结果状态，如 200/403/需登录/timeout"},
                                "checks": {"type": "string", "description": "测过的点：未授权/越权/注入/上传/配置泄露等"},
                                "result": {"type": "string", "description": "结论：公开正常/需登录/无差异/存在强线索/已提交漏洞等"},
                            },
                        },
                    },
                    "remaining": {"type": "string", "description": "尚未覆盖但值得后续路线继续的入口/参数/假设"},
                },
                "required": ["summary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "finish",
            "description": "结束对当前目标的挖掘。所有该挖的都挖完了，或确认无漏洞时调用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["found", "no_vuln"], "description": "found=至少提交过一个漏洞；no_vuln=确认无漏洞"},
                    "summary": {"type": "string", "description": "本次挖掘总结：测了哪些面、为什么是这个结论"},
                    "deepen_lead": {
                        "type": "string",
                        "description": (
                            "可选。仅在你已经突破了某个入口（拿到凭证/token/登录态/可控参数/敏感接口）"
                            "但本轮没把它打穿成完整漏洞时填写：用一句话给出下一轮该如何顺着这个据点深挖的"
                            "具体方向（如：用拿到的 token 调 /api/admin/users 验证越权；用泄露的 ak/sk 调 OSS 列桶）。"
                            "没有可深挖的明确线索就留空。这会触发系统自动再派一轮定向深挖。"
                        ),
                    },
                },
                "required": ["verdict", "summary"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_batch",
            "description": "批量遍历（IDOR/越权/对象穿透枚举）：URL 或 POST body 里用 {p} 占位（或给 param_name 自动替换 url 里的 param_name=xxx），程序遍历整数区间(start..end)并发请求，汇总各状态码计数、与基线(status/长度)差异明显的样本、命中兴趣关键词的样本。限量(max_items≤60)限速(delay≤0.5s)防 DoS，只做无害验证；扫完挑差异最大的单点用 http_request 复现取证并 submit_finding，不要继续扩大范围。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "带 {p} 占位的请求 URL（如 https://x/api/user/{p}），或普通 URL 配合 param_name"},
                    "param_name": {"type": "string", "description": "若不用 {p} 占位，填要在 url 里遍历的参数名（自动替换 param_name=值）"},
                    "start": {"type": "integer", "description": "遍历起始，默认 1"},
                    "end": {"type": "integer", "description": "遍历结束，默认 10"},
                    "step": {"type": "integer", "description": "步长，默认 1"},
                    "method": {"type": "string", "description": "GET 或 POST"},
                    "data_template": {"type": "string", "description": "POST body，可用 {p} 占位"},
                    "delay": {"type": "number", "description": "请求间隔秒，默认 0.15，最大 0.5"},
                    "max_items": {"type": "integer", "description": "最多请求数，默认 40，最大 60"},
                    "interest_contains": {"type": "array", "items": {"type": "string"}, "description": "兴趣关键词，body 命中即高亮（如 手机号/成绩/学号）"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "diff_response",
            "description": "响应差异对比：对同一 URL 用两组不同参数(params_a/params_b)各发一次，对比状态码/响应长度/耗时，判定参数是否被后端真正消费（改动参数导致响应显著变化=参数可控，值得挖越权或注入；几乎无变化=参数被忽略，跳过）。判断注入/越权/参数篡改信号前先用它做一次确定性对比，别靠肉眼猜。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "请求 URL"},
                    "params_a": {"type": "object", "description": "基线参数集，如 {\"id\":\"1\"}", "additionalProperties": {"type": "string"}},
                    "params_b": {"type": "object", "description": "对照组参数集，如 {\"id\":\"999\"}", "additionalProperties": {"type": "string"}},
                    "method": {"type": "string", "description": "GET 或 POST"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "timing_probe",
            "description": "时序测量：对同一请求采样多次给出 min/p50/max/avg/std 耗时统计。先测基线耗时，再换时间盲注 payload 测次，对比 p50 是否系统性拉大判定有无时序反馈。纯只读、有限次采样(3~7次)、不会长时间悬挂。用于验证时间盲注/时序侧信道，避免手估算耗时误判。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "要测时的 URL"},
                    "method": {"type": "string", "description": "GET 或 POST"},
                    "data": {"type": "string", "description": "POST body"},
                    "samples": {"type": "integer", "description": "采样次数，默认 5，范围 3~7"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "crawl_links",
            "description": "攻击面链接抓取：从起始页(pages)，只发起只读 GET，提取内链/表单 action/src，保留同主机 URL 并筛出 api/rest/ajax/action 等 API 风格链接。用于从站点抓取未测入口和隐藏接口，弥补 analyze_javascript 只覆盖 JS、不覆盖普通 HTML 多页的盲区。限量(max_pages≤10/max_links≤80)防 DoS；抓完挑 1~2 个高价值接口实测，别全量打。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "起始页 URL"},
                    "max_pages": {"type": "integer", "description": "最多抓取页数，默认 5，最大 10"},
                    "max_links": {"type": "integer", "description": "最多保留链接数，默认 60，最大 80"},
                    "same_host_only": {"type": "boolean", "description": "是否只留同主机链接，默认 true"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "sqli_probe",
            "description": "SQL 注入探测：对指定参数(param_name)做报错型/布尔型/时间型三类无害探测。报错型注入单引号/双引号/闭合变体检测数据库报错特征(MySQL/Oracle/MSSQL/PG)；布尔型 1=1 与 1=2 对照响应长度差异；时间型 SLEEP(2) 与基线耗时对比。全部只读/无害、限量(≤8 请求)限速防 DoS。命中只是信号，必须用 http_request 复现取证确认实际危害后再 submit_finding，不要凭「参数可控」提交。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "要探测的请求 URL（含目标参数）"},
                    "param_name": {"type": "string", "description": "要探测的参数名（自动替换 url 里的 param_name=值）"},
                    "method": {"type": "string", "description": "GET 或 POST，默认 GET"},
                    "probe_types": {"type": "array", "items": {"type": "string"}, "description": "探测类型：error/bool/time，默认全部"},
                },
                "required": ["url", "param_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "path_probe",
            "description": "路径字典爆破 + 备份/源码泄露探测：对目标批量 GET 探测常见管理/接口路径（admin/upload/api/actuator/swagger 等）和备份/源码泄露路径（.git/.svn/.DS_Store/www.zip/.env/备份文件等）。全部只读 GET、限量限速防 DoS。命中只是信号，必须用 http_request 复现取证确认实际危害后再 submit_finding，不要凭「路径存在」提交。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "目标 URL（根域或任意页面，自动取 origin 作为探测基址）"},
                    "max_paths": {"type": "integer", "description": "最多探测路径数，默认 40，最大 80"},
                    "include_backup": {"type": "boolean", "description": "是否包含备份/源码泄露路径（.git/.svn/.DS_Store/www.zip/.env 等），默认 true"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "injection_probe",
            "description": "CORS/SSRF/命令注入/SSTI/XXE 五类注入探针：对指定参数(param_name)做无害探测。CORS 带任意 Origin 检测 Access-Control-Allow-Origin 反射；SSRF 注入内部/云元数据地址检测响应特征；命令注入注入分隔符+回显标记检测回显；SSTI 注入 {{7*7}} 等检测 49 求值；XXE 构造含外部实体的 XML 检测解析特征。全部只读/无害、限量(≤12 请求)限速防 DoS。命中只是信号，必须用 http_request 复现取证确认实际危害后再 submit_finding。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "要探测的请求 URL（含目标参数）"},
                    "param_name": {"type": "string", "description": "要探测的参数名（自动替换 url 里的 param_name=值）"},
                    "method": {"type": "string", "description": "GET 或 POST，默认 GET"},
                    "probe_types": {"type": "array", "items": {"type": "string"}, "description": "探测类型：cors/ssrf/cmdi/ssti/xxe，默认全部"},
                },
                "required": ["url", "param_name"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "upload_probe",
            "description": "上传接口无害探测：对疑似上传接口只传纯文本占位文件(test.txt)，验证接口是否存在、是否校验文件类型/大小。绝不传可执行文件(.php/.jsp/.asp 等，硬拦)。命中「上传成功/返回路径/大小限制」只是接口信号，不代表可传恶意文件，需按实际业务危害确认后再提交。限量(≤2 次)防 DoS。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "上传接口 URL"},
                    "file_field": {"type": "string", "description": "文件字段名，默认 file"},
                    "filename": {"type": "string", "description": "占位文件名，默认 test.txt（禁止可执行扩展名）"},
                    "content_type": {"type": "string", "description": "文件 Content-Type，默认 text/plain"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "access_boundary",
            "description": "权限边界测试：对接口分别用「无认证」和「当前会话」各发一次，对比状态码/响应长度/内容，判定未授权访问或越权信号。无认证也能 2xx 拿到内容=疑似未授权；无认证与登录态响应高度一致=疑似鉴权缺失；无认证被拒(401/403/302)=鉴权生效可继续测越权。只读 GET 为主，POST 仅无害验证。命中只是信号，需复现取证确认实际可访问的敏感数据后再 submit_finding。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "要测权限边界的接口 URL"},
                    "method": {"type": "string", "description": "GET 或 POST，默认 GET"},
                    "data": {"type": "string", "description": "POST body（可选）"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "capture_evidence",
            "description": "存证快照：对确认漏洞的页面 URL 抓取结构化 HTTP 快照（状态码/响应头/正文片段/标题/可见文本/耗时）作为存证，保存到工作目录并返回 evidence_ref。只读为主，走当前会话。命中漏洞后、submit_finding 前调用，把返回的 evidence_ref 通过 submit_finding 的 evidence.snapshot_ref 带上，提交时会自动合并进报告证据链。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "要存证的页面 URL（含 PoC 参数）"},
                    "method": {"type": "string", "description": "GET 或 POST，默认 GET"},
                    "data": {"type": "string", "description": "POST body（可选）"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "blackboard_publish",
            "description": "发布一条情报到协作黑板，供同站其它 worker 实时共享。适合发布：已探测/已覆盖的入口与结论、发现的强线索、验证过打不穿的点。动手前先 blackboard_query 看别人是否已测过；测完把结论发布出来避免别人重复。只读无副作用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "情报分类键，如 probed/coverage/lead/excluded/cred/endpoint 或自定义"},
                    "value": {"type": "string", "description": "情报内容：入口+结论/线索描述/排除说明，一句话讲清"},
                    "confidence": {"type": "string", "enum": ["high", "medium", "low"], "default": "medium", "description": "可信度：验证过=high，疑似=medium，猜测=low"},
                },
                "required": ["key", "value"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "blackboard_query",
            "description": "查询协作黑板：看同站其它 worker 已探测哪些 URL、已覆盖哪些入口、共享了哪些线索/排除。key 留空返回概览（各分类数量+当前分工），指定 key 返回该分类明细。动手前先查，避免重复路线；查到别人已测过就换方向。",
            "parameters": {
                "type": "object",
                "properties": {
                    "key": {"type": "string", "description": "要查的分类键（probed/coverage/lead/excluded 或自定义），留空查概览"},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "blackboard_declare",
            "description": "声明当前 worker 正在攻的方向（软分工，不排他）：让同站其它 worker 看到你在做什么，尽量错开不撞车。开局或换方向时调用一次即可。",
            "parameters": {
                "type": "object",
                "properties": {
                    "direction": {"type": "string", "description": "一句话说明当前方向，如『测认证越权』『审计前端 JS 密钥』"},
                },
                "required": ["direction"],
            },
        },
    },
]


JS_ANALYZER_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "analyze_javascript",
            "description": "审计前端 JS/接口/硬编码密钥/路由。SPA、登录页、接口藏前端、常规入口不足时优先用。传入口 URL 自动抓 HTML 和关联 JS 提取接口清单和攻击链，或传 JS 文本离线分析。只是线索地图，必须继续用 http_request/run_shell 实证。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string", "description": "入口 URL 或 JS URL。传 URL 时会递归抓取关联 JS。"},
                    "text": {"type": "string", "description": "已拿到的 JS/HTML 文本；与 url 二选一。"},
                    "max_depth": {"type": "integer", "description": "递归抓取 JS 深度，默认 2，最大 4。"},
                    "max_assets": {"type": "integer", "description": "最多抓取资产数，默认 80，最大 150。"},
                },
            },
        },
    }
]


SESSION_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "session_set",
            "description": "登记已拿到的登录态(cookie 或鉴权头如 Authorization: Bearer xxx)，登记后所有 http_request 自动携带、且自动吸收响应 Set-Cookie。用泄露/用户凭证登录成功后，务必先用它固化登录态，再带着登录态深挖受限接口、后台功能、枚举越权对象——只登录成功不算洞。",
            "parameters": {
                "type": "object",
                "properties": {
                    "cookies": {
                        "type": "object",
                        "description": "要维持的 cookie 键值对，如 {\"JSESSIONID\":\"xxx\"}",
                        "additionalProperties": {"type": "string"},
                    },
                    "headers": {
                        "type": "object",
                        "description": "要维持的鉴权头，如 {\"Authorization\":\"Bearer xxx\"}",
                        "additionalProperties": {"type": "string"},
                    },
                    "clear": {"type": "boolean", "description": "true=清空当前会话态后再设置（换账号时用）", "default": False},
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_notes",
            "description": "更新你的工作笔记（跨轮持久，不会被历史压缩丢掉，每轮自动注入给你）。发现关键信息就立刻记：已确认的端点/凭据/token/cookie、已试过但失败的方向、当前突破口、下一步计划。这是你跨轮'记得自己干了什么'的关键——不记就会重复扫同一条路。",
            "parameters": {
                "type": "object",
                "properties": {
                    "notes": {"type": "string", "description": "工作笔记内容。建议分块写：【已发现】端点/凭据/token/cookie；【已试失败】方向+原因；【当前突破口】；【下一步】计划。控制在 1500 字内。"},
                },
                "required": ["notes"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "update_cognition",
            "description": "维护你的结构化认知卡（像人一样记忆的关键：跨轮持久、每轮自动注入）。用固定槽位把思考过程落盘：【confirmed】已实证证实的事实/危害；【excluded】已排除的攻击方向+原因（避免重复踩坑）；【leads】未落定的活跃线索；【plan】当前打法/下一步计划。验证了实锤、否决了方向、冒出新线索、定了下一步时立刻写，历史压缩后你仍记得自己学到什么、还要干嘛。",
            "parameters": {
                "type": "object",
                "properties": {
                    "slot": {"type": "string", "enum": ["confirmed", "excluded", "leads", "plan"], "description": "认知槽位"},
                    "text": {"type": "string", "description": "要写入的内容：confirmed/excluded/leads 追加（去重，保留最新若干条），plan 覆盖当前计划。"},
                },
                "required": ["slot", "text"],
            },
        },
    },
]


REVIEWER_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "submit_review",
            "description": "提交对当前 Finding 的审核结论。",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["accepted", "ignored", "deepen"], "description": "accepted=进最终列表 / ignored=丢弃 / deepen=线索有价值但利用没打穿，打回让 worker 定向深挖"},
                    "confidence": {"type": "string", "enum": ["confirmed", "likely", "uncertain"], "description": "信度分档"},
                    "severity_final": {"type": "string", "enum": ["严重", "高危", "中危", "低危"], "description": "最终等级，accepted 时必填"},
                    "score": {"type": "number", "description": "0-10 评分，必须落在等级对应区间"},
                    "in_scope": {"type": "boolean", "description": "是否在当前任务 SRC 范围内"},
                    "is_duplicate": {"type": "boolean", "default": False},
                    "ignore_reasons": {"type": "array", "items": {"type": "string"}, "description": "忽略理由，ignored 时必填"},
                    "downgrade_reasons": {"type": "array", "items": {"type": "string"}, "description": "降级理由"},
                    "deepen_directive": {"type": "string", "description": "深挖指令，verdict=deepen 时必填：具体告诉 worker 这一轮要把什么利用链打穿（如：用泄露的 secret 伪造签名调通 /api/order 取出他人订单数据）"},
                    "reviewer_notes": {"type": "string", "description": "判断依据"},
                },
                "required": ["verdict", "confidence", "score", "in_scope", "reviewer_notes"],
            },
        },
    },
]


KILLSWEEP_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "fofa_search",
            "description": "用 FOFA 语法圈定同款系统并统计规模（走任务所选测绘引擎，非 FOFA 自动翻译）。返回命中总量(size)和样本资产列表（host/title/org）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "FOFA 查询语法，如 title=\"XX系统\" || body=\"特征字符串\""},
                    "edu_only": {"type": "boolean", "description": "是否只统计教育行业(自动叠加 .edu.cn/教育 org 限定)，默认 false 即全网", "default": False},
                },
                "required": ["query"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "对某个同款站点发请求，验证它是否同样存在该漏洞（实证通杀）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "data": {"type": "string"},
                    "json_body": {"type": "object"},
                    "follow_redirects": {"type": "boolean", "default": False, "description": "登录/CAS/SSO 走登录链必须设 true（自动带齐每跳 Cookie）。"},
                    "confirm_destructive": {"type": "boolean", "default": False, "description": "疑似破坏性操作会先暂停反思。确认无害后再设 true。"},
                    "confirm_reason": {"type": "string", "description": "确认时必填：为何无害。"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "执行 shell 命令（curl 等）辅助验证同款站点。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                    "confirm_destructive": {"type": "boolean", "default": False, "description": "疑似破坏性操作会先暂停反思。确认无害后再设 true。"},
                    "confirm_reason": {"type": "string", "description": "确认时必填：为何无害。"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_killsweep",
            "description": "提交通杀分析结论。无论是否可通杀都要调用一次。",
            "parameters": {
                "type": "object",
                "properties": {
                    "is_generic_product": {"type": "boolean", "description": "该系统是否为有指纹特征的通用产品/框架（而非单位自研一次性系统）"},
                    "product_name": {"type": "string", "description": "通用产品/框架名称，如『XX教务系统』『RuoYi框架』；自研系统填『自研/无通用指纹』"},
                    "is_killsweep": {"type": "boolean", "description": "该漏洞是否为这套系统的通用缺陷、可一打一片（代码层缺陷=可通杀；单位个例配置=不可）"},
                    "confidence": {"type": "string", "enum": ["confirmed", "likely", "uncertain"], "description": "通杀判定信度：打了同款站点实证成功=confirmed"},
                    "fofa_query": {"type": "string", "description": "圈定同款系统的最优 FOFA 语法"},
                    "fingerprint": {"type": "string", "description": "指纹依据：用了哪些 title/body/server/favicon 特征"},
                    "asset_count": {"type": "integer", "description": "全网同款资产规模(FOFA size)"},
                    "edu_count": {"type": "integer", "description": "教育行业同款规模"},
                    "verified_url": {"type": "string", "description": "代表性的一个已验证同款站点 URL；实打成功的每个站点都要列进 affected_table 并标 status=verified，这里填其中一个即可"},
                    "verified": {"type": "boolean", "description": "是否至少打通 1 个同款站点并实证同样中招（打通多个时也为 true）"},
                    "affected_table": {
                        "type": "array",
                        "description": "通杀影响明细表：每行是一个学校/单位与对应通杀洞，后端会写入查重库，避免后续重复报同一通杀洞。",
                        "items": {
                            "type": "object",
                            "properties": {
                                "school": {"type": "string", "description": "学校/单位名称；从 org/title/域名推断，未知填待确认"},
                                "url": {"type": "string", "description": "同款系统 URL/host"},
                                "host": {"type": "string", "description": "归一化 host，可不填，后端会补"},
                                "title": {"type": "string", "description": "站点标题"},
                                "vuln_title": {"type": "string", "description": "该学校对应的通杀漏洞标题"},
                                "status": {"type": "string", "enum": ["verified", "candidate"], "description": "verified=已实打复现成功的同款站点（可有多个）；candidate=FOFA圈定同款候选"},
                                "evidence": {"type": "string", "description": "证据/依据，如 FOFA命中、标题特征、验证响应摘要"},
                            },
                            "required": ["school", "url", "vuln_title", "status"],
                        },
                    },
                    "notes": {"type": "string", "description": "结论与批量利用建议；不可通杀时说明原因"},
                },
                "required": ["is_generic_product", "is_killsweep", "confidence", "notes"],
            },
        },
    },
]


ESCALATE_TOOL_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "http_request",
            "description": "顺着已确认的入口继续发包，尝试把危害做大（越权写、遍历、改密、接管、命令执行等）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "default": "GET"},
                    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                    "data": {"type": "string"},
                    "json_body": {"type": "object"},
                    "follow_redirects": {"type": "boolean", "default": False, "description": "登录/CAS/SSO 走登录链必须设 true（自动带齐每跳 Cookie）。"},
                    "confirm_destructive": {"type": "boolean", "default": False, "description": "疑似破坏性操作会先暂停反思。确认无害后再设 true。"},
                    "confirm_reason": {"type": "string", "description": "确认时必填：为何无害。"},
                },
                "required": ["url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_shell",
            "description": "执行 shell 命令（curl 等）辅助升级利用。",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                    "confirm_destructive": {"type": "boolean", "default": False, "description": "疑似破坏性操作会先暂停反思。确认无害后再设 true。"},
                    "confirm_reason": {"type": "string", "description": "确认时必填：为何无害。"},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_escalation",
            "description": (
                "仅当你已把原漏洞【实锤升级】——危害等级实际提升，或影响面出现数量级变化（如单点→批量接管/遍历）"
                "——时调用一次，交出升级后的完整证据链。没打穿、原地打转、危害没变，请改调 abandon_escalation。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "vuln_type": {"type": "string", "description": "升级后的漏洞类型，如『任意用户密码重置+账号接管』"},
                    "title": {"type": "string", "description": "升级后的漏洞标题（含归属单位/系统 + 升级后的危害）"},
                    "severity": {"type": "string", "enum": ["严重", "高危", "中危", "低危"], "description": "升级后的最终等级"},
                    "description": {"type": "string", "description": "升级利用链描述：从原入口如何一步步做大危害"},
                    "kill_chain": {
                        "type": "array",
                        "description": "升级攻击链路，逐步：[{method, detail}]",
                        "items": {
                            "type": "object",
                            "properties": {
                                "method": {"type": "string"},
                                "detail": {"type": "string"},
                            },
                        },
                    },
                    "poc": {"type": "string", "description": "完整可复现 PoC（含关键 curl/请求）"},
                    "raw_request": {"type": "string", "description": "关键升级步骤的原始请求"},
                    "raw_response": {"type": "string", "description": "证明升级成功的原始响应（真实成功证据）"},
                    "affected_scope": {"type": "string", "description": "量化影响面，如『2230 名教师+全部学生可被接管』"},
                    "impact_count": {"type": "integer", "description": "可量化的受影响对象数量（遍历/接管规模），无则填 0"},
                },
                "required": ["vuln_type", "title", "severity", "description", "poc", "raw_response"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "abandon_escalation",
            "description": "本次深挖没能显著升级危害（等级没提升、影响面没质变），放弃并说明原因。",
            "parameters": {
                "type": "object",
                "properties": {
                    "reason": {"type": "string", "description": "为什么放弃：试了哪些方向、卡在哪、为何危害没变大"},
                },
                "required": ["reason"],
            },
        },
    },
]


COLLECTOR_QUERY_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "gen_query",
            "description": "产出一条 FOFA 搜索语法，用于本轮目标搜集。",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "可直接调用的 FOFA 查询语法字符串"},
                    "reason": {"type": "string", "description": "一句话说明本轮覆盖的角度"},
                },
                "required": ["query"],
            },
        },
    },
]


COLLECTOR_EDU_SCHEMAS = [
    {
        "type": "function",
        "function": {
            "name": "judge_edu",
            "description": "批量判定资产是否属于中国教育行业（EduSRC 范围）。",
            "parameters": {
                "type": "object",
                "properties": {
                    "results": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
	                                "index": {"type": "integer", "description": "对应输入资产的序号"},
	                                "is_edu": {"type": "boolean"},
	                                "school": {"type": "string", "description": "归属学校/教育机构全称，推断不出可空"},
	                            },
                            "required": ["index", "is_edu"],
                        },
                    },
                },
                "required": ["results"],
            },
        },
    },
]


def _compact_descriptions(value, limit: int = 72, _depth: int = 0):
    """压缩 function schema 里的自然语言描述，保留字段/required/enum 不变。

    OpenAI 兼容 function schema 会随每轮请求一起发送；长 description 是稳定但昂贵的
    prompt。系统提示已覆盖规则细节，这里只保留最短可辨识说明。
    """
    if isinstance(value, list):
        return [_compact_descriptions(item, limit, _depth + 1) for item in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for key, item in value.items():
        if key == "description" and isinstance(item, str):
            if _depth > 2:
                continue
            text = " ".join(item.split())
            out[key] = text[:limit]
        else:
            out[key] = _compact_descriptions(item, limit, _depth + 1)
    return out


TOOL_SCHEMAS = _compact_descriptions(TOOL_SCHEMAS)
JS_ANALYZER_TOOL_SCHEMAS = _compact_descriptions(JS_ANALYZER_TOOL_SCHEMAS)
SESSION_TOOL_SCHEMAS = _compact_descriptions(SESSION_TOOL_SCHEMAS)
# 向后兼容别名（历史命名，全模式已可用）。
REVIEWER_TOOL_SCHEMAS = _compact_descriptions(REVIEWER_TOOL_SCHEMAS)
KILLSWEEP_TOOL_SCHEMAS = _compact_descriptions(KILLSWEEP_TOOL_SCHEMAS)
ESCALATE_TOOL_SCHEMAS = _compact_descriptions(ESCALATE_TOOL_SCHEMAS)
COLLECTOR_QUERY_SCHEMAS = _compact_descriptions(COLLECTOR_QUERY_SCHEMAS)
COLLECTOR_EDU_SCHEMAS = _compact_descriptions(COLLECTOR_EDU_SCHEMAS)
