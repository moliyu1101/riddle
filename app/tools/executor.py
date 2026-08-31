"""工具执行器：worker 真实挖洞的底层能力。

提供给 LLM 通过 function calling 调用：
- run_shell: 受控执行任意命令（带超时、输出截断、自毁防护、工作目录隔离）
- http_request: 发原始 HTTP 请求，返回完整请求包+响应包（取证用）
"""
from __future__ import annotations

import json
import os
import re
import selectors
import signal
import subprocess
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Optional

import httpx

from app.agents.business_profiler import profile_business, render_business_block
from app.agents.prefilter import capped_resolution
from app.config import worker_config
from app.memory import drop_file_cache, drop_tree_cache, trim_process_memory
from app.tools.decoder import decode_transform as _decode_transform
from app.tools.guard import (
    CommandBlocked,
    NeedsConfirm,
    check_command,
    check_http_request,
    check_task_forbidden,
    normalize_guard_ops,
    parse_forbidden_ops,
)
from app.tools.js_analyzer import analyze_javascript as analyze_js_text
from app.tools.js_analyzer import analyze_url as analyze_js_url
from app.tools.auth_tools import credential_brute as _credential_brute
from app.tools.auth_tools import login_form_scan as _login_form_scan
from app.tools.auth_tools import login_session as _login_session
from app.tools.attack_tools import crawl_links as _crawl_links
from app.tools.attack_tools import diff_response as _diff_response
from app.tools.attack_tools import http_batch as _http_batch
from app.tools.attack_tools import timing_probe as _timing_probe
from app.tools.evidence_capture import capture_evidence as _capture_evidence_tool
from app.tools.evidence_trail import append_trail as _append_evidence_trail
from app.tools.probe_tools import access_boundary as _access_boundary
from app.tools.probe_tools import injection_probe as _injection_probe
from app.tools.probe_tools import sqli_probe as _sqli_probe
from app.tools.probe_tools import upload_probe as _upload_probe
from app.tools.recon import asset_discovery as _asset_discovery
from app.tools.recon import fingerprint as _fingerprint
from app.tools.recon import _normalize_target as _norm_target
from app.tools.verify_chain import (
    _SIGNAL_SNIPPET,
    build_probe_request as _build_probe_request,
    get_verify_actions as _get_verify_actions,
    mark_action_result as _mark_action_result,
    summarize_evidence as _summarize_evidence,
)
from app.tools.waf_advisor import (
    _detect_waf as _waf_detect,
    _header_variants as _waf_header_variants,
    _normalize_headers as _waf_norm_headers,
    suggest_waf_bypass as _suggest_waf_bypass,
)

# 只读测绘查询硬上限：worker 用它确认归属/探攻击面，不是全量测绘，给小额度即可。
_FOFA_LOOKUP_MAX_SIZE = 30
# 企业 session cookie jar 上限，防异常站点塞爆内存。
_SESSION_MAX_COOKIES = 50
_SESSION_MAX_HEADERS = 30

# 单目标工作目录落地日志体积上限（字节）。24x7 防撞盘：超限后停止写新日志文件，
# 仍把截断输出回传给 LLM，不影响挖掘，只是不再落地完整证据。
_WORKDIR_MAX_BYTES = int(os.environ.get("WORKER_WORKDIR_MAX_BYTES", str(50 * 1024 * 1024)))
# 每写这么多次日志做一次真实全目录体积校准（捕获 shell 子进程 curl -o/wget/重定向直落的顶层文件；
# _dir_size 用非递归 glob，只数顶层文件，git clone 落的子目录树不在统计内）。
_WORKDIR_RESCAN_EVERY = 32
_SHELL_CAPTURE_MAX_BYTES = int(os.environ.get("WORKER_SHELL_CAPTURE_MAX_BYTES", str(512 * 1024)))
# HTTP 响应体读取上限（字节）：超限截断并标注，保护内存。与 _SHELL_CAPTURE_MAX_BYTES 同思路。
_HTTP_MAX_BYTES = int(os.environ.get("WORKER_HTTP_MAX_BYTES", str(2 * 1024 * 1024)))
# http_request 自动 WAF 绕过：检测到 WAF 拦截时自动重试无害变体（头/URL 编码/body 编码），
# 最多 3 次；绕过成功返回结果并标记 waf.bypassed。默认开启，可设 RIDDLE_AUTO_WAF_BYPASS=0 关闭。
_AUTO_WAF_BYPASS = os.environ.get("RIDDLE_AUTO_WAF_BYPASS", "1").strip().lower() not in ("0", "false", "no", "off")
# 自动绕过单次最多尝试的变体数，控制请求量。
_AUTO_WAF_MAX_TRIES = int(os.environ.get("RIDDLE_AUTO_WAF_MAX_TRIES", "3"))

# path_probe 内置字典：常见管理/接口路径 + 备份/源码泄露路径（SRC 高频）。
_PATH_DICT = [
    "admin", "login", "api", "upload", "uploads", "static", "assets", "swagger",
    "swagger-ui", "swagger-ui.html", "v3/api-docs", "v2/api-docs", "actuator",
    "actuator/health", "actuator/env", "console", "manage", "manager", "config",
    "backup", "test", "phpmyadmin", "adminer", "robots.txt", "sitemap.xml",
    ".well-known/security.txt", "druid", "druid/index.html", "nacos", "eureka",
    "graphql", "graphiql", "doc", "docs", "api-docs", "user", "users",
    "admin/login", "system", "index.php", "index.jsp", "web.config", "crossdomain.xml",
]
_BACKUP_PATH_DICT = [
    ".git/config", ".git/HEAD", ".git/index", ".svn/entries", ".svn/wc.db",
    ".DS_Store", "www.zip", "web.zip", "backup.zip", "site.zip", "code.zip",
    "src.zip", "wwwroot.zip", "html.zip", "web.rar", "www.rar", "backup.rar",
    "index.php.bak", "index.php~", "config.php.bak", "config.php~", ".env",
    ".env.bak", ".env.local", ".htaccess", ".gitignore", "WEB-INF/web.xml",
    "WEB-INF/classes/application.properties", "application.yml", "application.properties",
    "database.sql", "db.sql", "dump.sql", "backup.sql", "data.sql",
]
# 备份/源码泄露路径命中特征：body 含这些关键词才算真泄露（避免框架 404 页误报）。
_BACKUP_HIT_MARKERS = (
    "[core]", "repositoryformatversion", "ref:", "packed-refs", "svn:",
    "application.properties", "spring.datasource", "DB_PASSWORD", "APP_KEY",
    "CREATE TABLE", "INSERT INTO", "mysql", "password=", "secret=", "token=",
    "api_key", "apikey", "access_key", "BEGIN RSA", "BEGIN PRIVATE",
)
_REFLECT_GUIDANCE = (
    "本次未执行。请先反思：会不会删库、清缓存、覆盖已有文件导致改不回？"
    "能改成 SRC_TEST_ 哨兵、ROLLBACK、或只证明接口存在就不要做破坏。"
    "若确认是无害验证，再次调用并设 confirm_destructive=true，confirm_reason 写明原因。"
)


def _confirm_pause(exc: NeedsConfirm) -> dict[str, Any]:
    return {
        "ok": False,
        "needs_confirm": True,
        "error": f"疑似不可逆操作，先停一下：{exc.reason}",
        "guidance": _REFLECT_GUIDANCE,
    }


def _truncate(text: str, limit: Optional[int] = None) -> str:
    if limit is None:
        limit = worker_config.output_truncate
        if worker_config.llm_tool_output_truncate > 0:
            limit = min(limit, worker_config.llm_tool_output_truncate)
    else:
        limit = int(limit)
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    return f"{head}\n\n...[输出过长已截断，完整内容已写入工作目录文件]...\n\n{tail}"


def _normalize_headers(headers: Any) -> dict[str, str]:
    """把 LLM 可能乱传的 headers 统一成 {str: str}，容错非 dict 形态，绝不抛异常。

    支持：
      - dict            → 原样（值转字符串）
      - list["K: V"]    → 逐行按第一个冒号切分
      - "K: V\\nK2: V2"  → 按行切分
      - None / 其它      → {}
    """
    if not headers:
        return {}
    if isinstance(headers, dict):
        return {str(k): str(v) for k, v in headers.items()}
    lines: list[str] = []
    if isinstance(headers, str):
        lines = headers.splitlines()
    elif isinstance(headers, (list, tuple)):
        for item in headers:
            if isinstance(item, dict):
                # list[{"name":..,"value":..}] 或 list[{"K":"V"}]
                if "name" in item and "value" in item:
                    lines.append(f"{item['name']}: {item['value']}")
                else:
                    lines.extend(f"{k}: {v}" for k, v in item.items())
            else:
                lines.append(str(item))
    else:
        return {}
    out: dict[str, str] = {}
    for line in lines:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def _merge_forbidden_ops(src_rules: str, guard_ops: Optional[list[str]]) -> list[str]:
    """合并任务级拦截：额外规则文本解析出的禁止操作 + 界面勾选的八大类，保序去重。

    勾了什么拦什么；未勾选的类别一律放行，避免全局硬拦导致合法漏洞验证被挡、洞被忽略。
    """
    merged: list[str] = []
    for op in [*parse_forbidden_ops(src_rules), *normalize_guard_ops(guard_ops)]:
        if op not in merged:
            merged.append(op)
    return merged


class ToolExecutor:
    def __init__(
        self,
        target: str,
        work_dir: Optional[str] = None,
        cancel_event: Optional[threading.Event] = None,
        enterprise: bool = False,
        fofa_key: str = "",
        fofa_base_url: str = "",
        engine: str = "fofa",
        src_rules: str = "",
        guard_ops: Optional[list[str]] = None,
    ):
        self.target = target
        self.cancel_event = cancel_event or threading.Event()
        # 企业模式：对目标生产环境的破坏性命令做额外硬拦截。
        self.enterprise = enterprise
        # 任务级禁止操作：任务界面勾选的八大类拦截 + 额外规则文本解析的禁止操作，合并生效（保序去重）。
        # 勾了什么拦什么；未勾选的类别一律放行，避免全局硬拦导致合法漏洞验证被挡、洞被忽略。
        self._forbidden_ops = _merge_forbidden_ops(src_rules, guard_ops)
        # 资产测绘引擎：fofa_lookup 走任务选定的引擎（FOFA / Quake / Hunter / …），
        # key/base_url 由编排层按 resolve_engine_config 注入；base_url 空则用引擎默认端点。
        self.engine = engine or "fofa"
        self.fofa_key = fofa_key or ""
        self.fofa_base_url = (fofa_base_url or "").rstrip("/")
        # 每个目标独立工作目录
        safe_name = "".join(c if c.isalnum() else "_" for c in target)[:60]
        self.work_dir = Path(work_dir or worker_config.work_root) / safe_name
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self._log_seq = 0
        self._active_procs: set[subprocess.Popen] = set()
        # 会话态：worker 登录/拿到 token 后自动携带到后续 http_request，
        # 解决"明明登进去了，深挖请求却忘带凭证导致越权失败"的断链问题。
        # 每个 target 独立 executor 实例、session jar 相互隔离，不会串号。
        # 全模式启用（edu 用泄露凭证/用户凭证登录后同样必须带登录态深入）。
        self._session_cookies: dict[str, str] = {}
        self._session_headers: dict[str, str] = {}
        # 工作笔记：worker 用 update_notes 工具维护，每轮注入回 messages，
        # 解决"历史压缩后忘了自己发现过什么"的连续性断裂问题。
        self._worker_notes: str = ""
        # 结构化认知卡：让 worker 显式维护「已证实/已排除/活跃线索/当前计划」四个槽位，
        # 每轮随 session_status_block 注入，是「像人一样记忆」的核心：不重复踩同一坑、
        # 记住未验证的线索、清晰知道下一步要干嘛。由 update_cognition 工具写入。
        self._cognition: dict[str, list[str] | str] = {
            "confirmed": [],  # 已实证确认的事实/危害（端点/数据/凭据…）
            "excluded": [],   # 已排除的攻击方向 + 原因（避免反复尝试已证明失败的路）
            "leads": [],      # 未落定的活跃线索（待下一步验证）
            "plan": "",       # 当前打法/下一步计划（自由文本）
        }
        # HTTP 会话复用：持久 httpx.Client（惰性创建），避免同 host 大量请求每次重做 TCP+TLS 握手。
        self._client: Optional[httpx.Client] = None
        # 工作目录体积：增量估算 + 周期性全目录校准（见 _write_log），避免每次写日志都全目录扫描。
        self._workdir_bytes: int = self._dir_size()
        self._writes_since_scan: int = 0
        self._over_cap: bool = False   # 一旦确认超上限即置位：work_dir 只增不删，此后直接短路不再全扫
        # 业务类型自动识别缓存（host 级）：同一目标只识别一次，避免重复分析页面。
        self._business_cache: dict[str, dict[str, Any] | None] = {}
        # run_shell 终端化状态：工作目录/环境变量跨命令持久化 + 命令历史去重。
        # 让 worker 的 shell 更像真实终端（cd 后下一条命令保持目录），
        # 历史随断点保存，LLM 中断恢复后不重复执行同一批命令。
        self._shell_cwd: Path = self.work_dir
        self._shell_env: dict[str, str] = {}
        self._shell_history: list[str] = []

    def cancel_running(self) -> None:
        """协作取消：置取消信号 + 杀子进程。仅用于控制面真取消（pause/stop/超时）。

        注意：会 set cancel_event，worker 据此判定"被取消、结果丢弃"。所以
        【正常完成后的清理】绝不能调这个（否则正常结果会被误判成取消而丢弃，
        历史事故根因：每个 worker 完成都被丢弃、findings/done 永远为 0）。
        正常完成清理请用 kill_processes()。
        """
        self.cancel_event.set()
        self.kill_processes()

    def kill_processes(self) -> None:
        """只杀掉当前 executor 启动的所有子进程组，不触碰 cancel_event。

        用于 worker 正常完成后的资源清理（杀残留子进程），不污染取消信号。
        """
        for proc in list(self._active_procs):
            self._kill_process_group(proc)
        self.close_http_client()
        drop_tree_cache(self.work_dir, cap=80)
        trim_process_memory()

    # ---- run_shell ----
    def _apply_shell_state(self, command: str) -> tuple[str, str]:
        """解析 cd/export/set 前缀命令，更新持久化 shell 状态。

        返回 (剩余命令, 状态提示)。纯 cd / 纯 export 返回空命令（不实际执行），
        `cd /x && cmd` 这类则更新状态后执行剩余部分。
        """
        cmd = command.strip()
        hint = ""
        m = re.match(r"^cd\s+(.+)$", cmd)
        if m:
            target = m.group(1).strip().strip('"').strip("'")
            rest = ""
            if "&&" in target:
                target, rest = target.split("&&", 1)
                target = target.strip()
            new_cwd = Path(target)
            if not new_cwd.is_absolute():
                new_cwd = self._shell_cwd / new_cwd
            try:
                new_cwd = new_cwd.resolve()
                if new_cwd.exists() and new_cwd.is_dir():
                    self._shell_cwd = new_cwd
                    hint = f"[cwd] {self._shell_cwd}"
                else:
                    hint = f"[cwd] 目录不存在，保持 {self._shell_cwd}"
            except Exception:
                hint = f"[cwd] 无法解析 {target}，保持 {self._shell_cwd}"
            return rest.strip(), hint
        m = re.match(r"^(?:export|set)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$", cmd)
        if m:
            key, val = m.group(1), m.group(2).strip().strip('"').strip("'")
            self._shell_env[key] = val
            return "", f"[env] {key}={val}"
        return cmd, hint

    @staticmethod
    def _summarize_output(text: str, max_lines: int = 30) -> str:
        """大输出自动摘要：提取含关键信号的行，信息密度高于直接截断。"""
        lines = text.splitlines()
        keep: list[str] = []
        for ln in lines:
            low = ln.lower()
            if any(
                k in low
                for k in (
                    "error", "fatal", "exception", "denied", "forbidden",
                    "200", "403", "404", "500", "found", "success", "fail",
                    "token", "password", "secret", "flag", "admin", "upload",
                )
            ):
                keep.append(ln)
                if len(keep) >= max_lines:
                    break
        return "\n".join(keep)

    def run_shell(
        self,
        command: str,
        timeout: Optional[int] = None,
        confirm_destructive: Any = False,
        confirm_reason: str = "",
    ) -> dict[str, Any]:
        try:
            timeout = int(timeout) if timeout else worker_config.shell_timeout
        except (TypeError, ValueError):
            timeout = worker_config.shell_timeout
        # 硬上限 + 下限：防 LLM 传超大/非法 timeout 长期占用 worker 槽位（DoS）。
        timeout = max(1, min(timeout, worker_config.shell_timeout_max))
        try:
            # 任务级禁止操作优先硬拦（用户明确禁止，不弹确认）；再走原有自毁/破坏性防护。
            check_task_forbidden(command, self._forbidden_ops)
            check_command(
                command,
                enterprise=self.enterprise,
                confirm_destructive=confirm_destructive,
                confirm_reason=confirm_reason,
            )
        except NeedsConfirm as e:
            return _confirm_pause(e)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}

        # 终端化：解析 cd/export/set 前缀，更新持久化 shell 状态；纯状态命令不实际执行。
        command, state_hint = self._apply_shell_state(command)
        if not command:
            return {"ok": True, "return_code": 0, "elapsed_sec": 0.0,
                    "output": state_hint or "（shell 状态已更新）", "output_file": ""}

        # 命令历史去重：重复执行时提示，避免 worker 反复跑同一命令。
        self._shell_history.append(command)
        repeat = self._shell_history.count(command)

        start = time.time()
        proc: subprocess.Popen | None = None
        timed_out = False
        cancelled = False
        omitted_bytes = 0
        chunks: list[bytes] = []
        try:
            shell_env = dict(os.environ)
            shell_env.update(self._shell_env)
            proc = subprocess.Popen(
                command,
                shell=True,
                cwd=str(self._shell_cwd),
                env=shell_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                start_new_session=True,  # 独立进程组，便于超时整组 kill
            )
            self._active_procs.add(proc)
            deadline = start + timeout

            # 用线程读 stdout（read1 跨平台支持管道），避免 selectors 在 Windows 上
            # 只认 socket 不认管道导致 WinError 10038 使 run_shell 完全不可用。
            def _reader() -> None:
                nonlocal omitted_bytes
                assert proc is not None and proc.stdout is not None
                while True:
                    data = proc.stdout.read1(8192)
                    if not data:
                        break
                    room = max(0, _SHELL_CAPTURE_MAX_BYTES - sum(len(c) for c in chunks))
                    if room:
                        chunks.append(data[:room])
                    if len(data) > room:
                        omitted_bytes += len(data) - room

            reader = threading.Thread(target=_reader, daemon=True)
            reader.start()
            while True:
                if self.cancel_event.is_set():
                    cancelled = True
                    self._kill_process_group(proc)
                elif time.time() >= deadline:
                    timed_out = True
                    self._kill_process_group(proc)
                rc = proc.poll()
                if rc is not None:
                    break
                time.sleep(0.05)
            reader.join(timeout=3)
            rc = proc.wait(timeout=3)
            cancelled = cancelled or self.cancel_event.is_set()
        except Exception as e:
            return {"ok": False, "error": f"命令执行异常: {e}"}
        finally:
            if proc is not None:
                self._active_procs.discard(proc)
                if proc.poll() is None:
                    self._kill_process_group(proc)
                    try:
                        proc.wait(timeout=3)
                    except Exception:
                        pass

        elapsed = round(time.time() - start, 2)
        full_out = b"".join(chunks).decode("utf-8", "replace")
        if omitted_bytes:
            full_out += f"\n\n...[输出超过 {_SHELL_CAPTURE_MAX_BYTES} 字节，已丢弃约 {omitted_bytes} 字节以保护内存]..."
        # 完整输出落地，避免截断丢证据（带体积上限，防 24x7 撞盘）
        log_file = self._write_log(f"$ {command}\n\n{full_out}")

        output = _truncate(full_out)
        # 大输出自动摘要：超限时提取关键信号行，信息密度高于纯截断。
        if len(full_out) > (worker_config.llm_tool_output_truncate or worker_config.output_truncate):
            digest = self._summarize_output(full_out)
            if digest:
                output += f"\n\n[关键行摘要]\n{digest}"
        # 命令历史去重提示：同一命令反复执行时提醒，引导 worker 换思路。
        if repeat > 1:
            output += f"\n\n[提示] 该命令此前已执行过 {repeat} 次，如无新意图请避免重复执行。"
        # Windows 本地开发：cmd 不认 Linux 命令时附加环境提示，引导 worker 换命令而不是反复重试。
        if os.name == "nt" and rc != 0 and not timed_out and not cancelled:
            low = output.lower()
            if any(m in low for m in ("is not recognized", "was unexpected", "invalid syntax")):
                output += (
                    "\n\n[环境提示] 当前是 Windows cmd，不支持 grep/ls/cat/openssl/timeout/for 循环等 Linux 命令。"
                    "请改用 dir / type / findstr / curl.exe 或 powershell（Select-String、Get-ChildItem、Invoke-WebRequest），"
                    "路径用 C:\\xxx 或 C:/xxx，别用 /tmp/xxx。"
                )

        # 命令输出证据落盘：与 LLM 解耦，提交失败时仍可从盘上重建（见 evidence_trail）。
        _append_evidence_trail(
            self.work_dir,
            kind="run_shell",
            target=self.target,
            tool="run_shell",
            output=full_out,
            status=rc,
            notes=f"$ {command}",
        )
        return {
            "ok": rc == 0 and not timed_out and not cancelled,
            "return_code": rc,
            "timed_out": timed_out,
            "cancelled": cancelled,
            "elapsed_sec": elapsed,
            "output": output,
            "output_file": str(log_file) if log_file else "",
        }

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _dir_size(self) -> int:
        try:
            return sum(f.stat().st_size for f in self.work_dir.glob("*") if f.is_file())
        except Exception:
            return 0

    def _write_log(self, content: str) -> Optional[Path]:
        """落地日志文件；工作目录超体积上限则跳过（返回 None），不再写盘。

        体积用增量计数 self._workdir_bytes 估算，避免每次写日志都全目录扫描（聚合 O(files²)）；
        每 _WORKDIR_RESCAN_EVERY 次写入做一次真实全目录扫描校准——因为 run_shell 的子进程
        （curl -o / wget / 输出重定向等直落顶层文件）会绕过本函数，纯计数器会漏统计、弱化
        _WORKDIR_MAX_BYTES 的防撞盘保护。估算值一旦达上限即置 _over_cap 终态、停止写盘且不再全扫。
        """
        # 超上限是终态（work_dir 只增不删）：直接短路，绝不再触发全目录扫描。
        if self._over_cap:
            return None
        data = content.encode("utf-8")
        # 仅按“写入次数”周期性校准，不再因“已达上限”而每次全扫（否则撞盘后退化成每写必扫）。
        if self._writes_since_scan >= _WORKDIR_RESCAN_EVERY:
            self._workdir_bytes = self._dir_size()
            self._writes_since_scan = 0
        if self._workdir_bytes >= _WORKDIR_MAX_BYTES:
            self._over_cap = True
            return None
        self._log_seq += 1
        log_file = self.work_dir / f"shell_{self._log_seq}.log"
        try:
            log_file.write_bytes(data)  # 与 write_text(encoding="utf-8") 字节数一致，便于精确计数
            drop_file_cache(log_file)
        except Exception:
            return None
        self._workdir_bytes += len(data)
        self._writes_since_scan += 1
        return log_file

    def _get_http_client(self) -> httpx.Client:
        """惰性复用的持久 HTTP client（连接池），避免同 host 大量请求重复 TCP+TLS 握手。

        per-request 的 timeout/follow_redirects 在 build_request/send 时逐次覆盖；cookie 每次
        请求前清空再从 self._session_cookies 重灌，保证会话态唯一真值来源、jar 不跨 host 累积。
        """
        if self._client is None or self._client.is_closed:
            self._client = httpx.Client(
                verify=False,
                timeout=20,
                follow_redirects=False,
                limits=httpx.Limits(
                    max_keepalive_connections=8, max_connections=32, keepalive_expiry=30.0
                ),
            )
        return self._client

    def close_http_client(self) -> None:
        # 经 kill_processes 调用。正常完成时无 in-flight 请求；取消路径（cancel_running →
        # kill_processes）下 worker 线程可能正在 send/iter，此时 close 会让该请求抛异常并被
        # http_request 的 except 兜成 {ok:false}——这正是取消语义（放弃在途请求），有意为之。
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    # ---- http_request ----
    def http_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[dict[str, str]] = None,
        data: Optional[str] = None,
        json_body: Optional[Any] = None,
        follow_redirects: bool = False,
        timeout: int = 20,
        confirm_destructive: Any = False,
        confirm_reason: str = "",
    ) -> dict[str, Any]:
        # LLM 可能把 headers 传成非 dict 形态（list["K: V"] / "K: V\nK2: V2" / None），
        # 直接喂给 dict()/httpx 会抛 "dictionary update sequence element..." 崩掉整个 agent。
        # 这里统一规范化成 dict，容错所有 agent 的 http_request 调用。
        headers = _normalize_headers(headers)
        try:
            # 任务级禁止操作优先硬拦（用户明确禁止，不弹确认）；再走原有自毁/破坏性防护。
            check_task_forbidden(
                "\n".join([method or "", url or "", data or "", str(json_body) if json_body is not None else ""]),
                self._forbidden_ops,
            )
            check_http_request(
                method, url, data=data, json_body=json_body,
                confirm_destructive=confirm_destructive,
                confirm_reason=confirm_reason,
            )
        except NeedsConfirm as e:
            return {**_confirm_pause(e), "url": url}
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e), "url": url}
        result = self._http_request_once(url, method, headers, data, json_body, follow_redirects, timeout)
        # 自动 WAF 绕过：仅当本次响应确实被 WAF/拦截页阻断时，用无害变体自动重试有限次。
        if result.get("ok") and _AUTO_WAF_BYPASS:
            result = self._maybe_auto_waf_bypass(result, url, method, headers, data, json_body, follow_redirects, timeout)
        # 真实请求/响应证据落盘：与 LLM 解耦，即使后续 submit_finding 被慢中转超时丢弃，
        # 已发生的攻击与取证仍在盘上，可确定性重建 Finding（见 worker 的证据恢复逻辑）。
        _append_evidence_trail(
            self.work_dir,
            kind="http_request",
            target=self.target,
            tool="http_request",
            url=result.get("url") or url,
            method=result.get("final_method") or method,
            request=result.get("request") or (result.get("raw_request") or ""),
            status=result.get("status_code"),
            body=result.get("body") or "",
            response_headers=result.get("response_headers") or {},
            notes=result.get("error") if not result.get("ok") else "",
        )
        return result

    def _http_request_once(
        self,
        url: str,
        method: str,
        headers: Optional[dict[str, str]],
        data: Optional[str],
        json_body: Optional[Any],
        follow_redirects: bool,
        timeout: int,
    ) -> dict[str, Any]:
        """发送一次 HTTP 请求并构造完整结果（不含自动 WAF 绕过）。"""
        # 会话保持：把已维持的 cookie/header 合并进本次请求（用户传的同名键优先）。
        merged_headers, session_applied = self._apply_session(headers)

        req: httpx.Request | None = None
        try:
            # 用持久 cookie jar 的 Client：跟随重定向时 httpx 会自动把每一跳 Set-Cookie
            # 存进 jar 并在后续跳转/同域请求里带上——这是走通 CAS/SSO 这类
            # 「302 连环跳 + 每跳发新 Cookie（lt→CASTGC→ST ticket→JSESSIONID）」登录链的关键。
            # 之前每次新建无 jar 的 Client + 只读最终 resp.cookies，会丢掉中间跳的 CASTGC/跨域
            # JSESSIONID，导致「明明账号对却始终登不进、没法进系统深挖」。
            # 持久复用的 client（连接池）；timeout/follow_redirects 逐请求覆盖。
            client = self._get_http_client()
            # 每次请求前清空 jar 并仅灌入当前维持的 session cookie，保持与“每次新建 Client”
            # 完全一致的会话语义，避免持久 jar 跨请求/跨 host 累积串号。
            try:
                client.cookies.clear()
            except Exception:
                pass
            for _ck, _cv in self._session_cookies.items():
                try:
                    client.cookies.set(_ck, _cv)
                except Exception:
                    pass
            req = client.build_request(
                method.upper(), url, headers=merged_headers, content=data, json=json_body,
                timeout=timeout,
            )
            with capped_resolution():
                resp = client.send(req, stream=True, follow_redirects=follow_redirects)
            body, truncated = self._read_limited_response(resp)
            # 吸收整条重定向链（resp.history 里每个中间 302 + 最终响应）的 Set-Cookie，
            # 而不是只读最终 resp.cookies；再兜底吸收 client.cookies jar 里的全部。
            session_updated = self._absorb_redirect_chain(resp, client)
        except Exception as e:
            return {"ok": False, "error": f"HTTP 请求异常: {e}", "url": url}

        # 原始请求行（取证/格式参考）。响应报文不再单独回传：状态码 + response_headers +
        # body 已结构化提供，raw_response 会与它们 100% 重复，是当轮就纯冗余的双份大文本。
        # 模型 submit_finding 时按 prompt 规范从 body 自行裁剪取证，不依赖这份 raw_response。
        raw_req = self._raw_request(req, data, json_body)

        result = {
            "ok": True,
            "status_code": resp.status_code,
            "url": str(resp.url),
            "response_headers": dict(resp.headers),
            "body": _truncate(body),
            "body_len": len(body),
            "body_truncated": truncated,
            "raw_request": _truncate(raw_req, 1536),
        }
        # 响应自动分析：JSON 字段/敏感信息/技术栈，帮 worker 单轮拿到更多线索。
        analysis = self._analyze_http_response(body, dict(resp.headers))
        if analysis:
            result["analysis"] = analysis
        # 跟随重定向时给出跳转链摘要，方便 agent 看清 CAS/SSO 登录流程走到哪、最终落在哪。
        try:
            hist = list(getattr(resp, "history", []) or [])
            if hist:
                chain = [f"{h.status_code} {h.request.method} {str(h.url)}" for h in hist]
                chain.append(f"{resp.status_code} {resp.request.method} {str(resp.url)}")
                result["redirect_chain"] = chain[:12]
                result["final_url"] = str(resp.url)
        except Exception:
            pass
        if session_applied:
            result["session_applied"] = session_applied
        if session_updated:
            result["session_cookies_updated"] = session_updated
        # 业务类型自动识别：HTML 响应时用页面标题/meta/可见文本识别业务系统，
        # 动态注入业务逻辑测试引导（手动清单只给 URL 时编排层静态画像常缺失）。
        try:
            ct = (resp.headers.get("content-type") or "").lower()
            head = body[:2000].lower()
            if body and ("text/html" in ct or "<html" in head or "<!doctype html" in head):
                biz = self._detect_business_from_html(str(resp.url), body)
                if biz:
                    result["business"] = biz
        except Exception:
            pass
        return result

    @staticmethod
    def _is_waf_blocked(status: int, headers: dict[str, Any], body: str) -> bool:
        """判断响应是否被 WAF/拦截页阻断。

        具体 WAF 指纹（cloudflare/modsecurity 等）直接判定；generic 需要响应体命中
        至少 2 个拦截关键词才算，避免把普通 403（如仅含 "Forbidden"）误判成 WAF 而自动重试。
        """
        sig, _ = _waf_detect(int(status or 0), _waf_norm_headers(headers or {}), body or "")
        if sig.name == "none":
            return False
        if sig.name == "generic":
            low = (body or "").lower()
            hits = [k for k in sig.body_keywords if k in low]
            return len(hits) >= 2
        return True

    def _waf_bypass_variants(
        self,
        url: str,
        method: str,
        headers: Optional[dict[str, str]],
        data: Optional[str],
        json_body: Optional[Any],
    ) -> list[dict[str, Any]]:
        """生成无害的 WAF 绕过候选：头变体（UA/客户端 IP）+ URL query 编码 + form body 编码。

        只做编码/头层面的无害变形，不做任何破坏性操作。
        """
        variants: list[dict[str, Any]] = []
        base_headers = dict(headers or {})
        for hv in _waf_header_variants(("header", "ua")):
            merged = dict(base_headers)
            merged.update(hv)
            variants.append({"headers": merged, "technique": f"header:{next(iter(hv))}"})
        if "?" in url:
            encoded = self._url_encode_query(url)
            if encoded and encoded != url:
                variants.append({"url": encoded, "technique": "url_encode_query"})
        if isinstance(data, str) and "=" in data:
            encoded = self._url_encode_form(data)
            if encoded and encoded != data:
                variants.append({"data": encoded, "technique": "body_url_encode"})
        return variants

    @staticmethod
    def _url_encode_query(url: str) -> str:
        """对 URL query 参数值做 URL 编码（保留键名与分隔符），失败原样返回。"""
        try:
            parts = urllib.parse.urlsplit(url)
            if not parts.query:
                return url
            params = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
            encoded = urllib.parse.urlencode(params, doseq=True)
            return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, encoded, parts.fragment))
        except Exception:
            return url

    @staticmethod
    def _url_encode_form(data: str) -> str:
        """对 application/x-www-form-urlencoded 的键值做 URL 编码，失败原样返回。"""
        try:
            params = urllib.parse.parse_qsl(data, keep_blank_values=True)
            return urllib.parse.urlencode(params, doseq=True)
        except Exception:
            return data

    def _maybe_auto_waf_bypass(
        self,
        result: dict[str, Any],
        url: str,
        method: str,
        headers: Optional[dict[str, str]],
        data: Optional[str],
        json_body: Optional[Any],
        follow_redirects: bool,
        timeout: int,
    ) -> dict[str, Any]:
        """检测到 WAF 拦截时自动重试无害变体；绕过成功返回绕过结果并标记 waf.bypassed。"""
        status = result.get("status_code", 0)
        resp_headers = result.get("response_headers") or {}
        body = result.get("body") or ""
        if not self._is_waf_blocked(status, resp_headers, body):
            return result
        sig, evidence = _waf_detect(int(status or 0), _waf_norm_headers(resp_headers), body)
        waf_info: dict[str, Any] = {
            "detected": True,
            "type": sig.name,
            "evidence": evidence,
            "bypassed": False,
        }
        variants = self._waf_bypass_variants(url, method, headers, data, json_body)
        if variants:
            original_status = status
            original_body = body
            tried: list[str] = []
            for v in variants[:_AUTO_WAF_MAX_TRIES]:
                tried.append(v.get("technique", ""))
                v_result = self._http_request_once(
                    v.get("url", url),
                    method,
                    v.get("headers", headers),
                    v.get("data", data),
                    v.get("json_body", json_body),
                    follow_redirects,
                    timeout,
                )
                if not v_result.get("ok"):
                    continue
                v_status = v_result.get("status_code", 0)
                v_headers = v_result.get("response_headers") or {}
                v_body = v_result.get("body") or ""
                if self._is_waf_blocked(v_status, v_headers, v_body):
                    continue
                # 状态码或响应体有明显差异才算真正绕过（不是同一拦截页换皮）。
                if v_status != original_status or abs(len(v_body) - len(original_body)) > 50:
                    waf_info["bypassed"] = True
                    waf_info["technique"] = v.get("technique", "")
                    waf_info["original_status"] = original_status
                    waf_info["original_body"] = _truncate(original_body, 500)
                    v_result["waf"] = waf_info
                    return v_result
            waf_info["tried"] = tried
        result["waf"] = waf_info
        return result

    # ---- 会话状态管理（全模式）----
    def _apply_session(self, headers: Optional[dict[str, str]]) -> tuple[dict[str, str], list[str]]:
        """把维持的 session cookie/header 合并进请求头。返回 (合并后headers, 应用了哪些)。

        合并规则：用户本次显式传入的头优先（不被 session 覆盖），保证可手动覆写。
        会话为空时原样返回、零开销；全模式启用。
        """
        if not self._session_cookies and not self._session_headers:
            return (dict(headers) if headers else {}), []
        try:
            merged: dict[str, str] = {}
            applied: list[str] = []
            for k, v in self._session_headers.items():
                merged[k] = v
            if self._session_cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
                merged["Cookie"] = cookie_str
                applied.append(f"Cookie({len(self._session_cookies)})")
            if self._session_headers:
                applied.append(f"headers({len(self._session_headers)})")
            # 用户本次传入的头覆盖 session（显式优先）。
            if headers:
                for k, v in headers.items():
                    merged[k] = v
            return merged, applied
        except Exception:
            return (dict(headers) if headers else {}), []

    def _put_cookie(self, name: str, value: str, updated: list[str]) -> None:
        if name in self._session_cookies:
            self._session_cookies[name] = value
            if name not in updated:
                updated.append(name)
        elif len(self._session_cookies) < _SESSION_MAX_COOKIES:
            self._session_cookies[name] = value
            if name not in updated:
                updated.append(name)

    def _absorb_set_cookie(self, resp: httpx.Response) -> list[str]:
        """从单个响应吸收 Set-Cookie 进 session jar（带数量上限防爆内存）。"""
        try:
            updated: list[str] = []
            for name, value in resp.cookies.items():
                self._put_cookie(name, value, updated)
            return updated
        except Exception:
            return []

    def _absorb_redirect_chain(self, resp: httpx.Response, client: "httpx.Client") -> list[str]:
        """吸收整条重定向链上每一跳的 Set-Cookie（CAS/SSO 登录链的关键）。

        httpx 跟随重定向时，中间的每个 302 响应都在 resp.history 里。CAS 登录的
        CASTGC / 跨域 JSESSIONID 往往就发在这些中间跳上；只读最终 resp.cookies 会漏。
        再用 client.cookies jar 兜底（httpx 已把整条链的 cookie 归并进 jar）。
        """
        updated: list[str] = []
        try:
            for hist in list(getattr(resp, "history", []) or []):
                try:
                    for name, value in hist.cookies.items():
                        self._put_cookie(name, value, updated)
                except Exception:
                    pass
            for name, value in resp.cookies.items():
                self._put_cookie(name, value, updated)
            # 兜底：client jar 里可能还有 history/resp.cookies 没暴露出来的（不同域）。
            try:
                for ck in client.cookies.jar:
                    if ck.name and ck.value:
                        self._put_cookie(ck.name, ck.value, updated)
            except Exception:
                pass
        except Exception:
            pass
        return updated

    def session_set(
        self,
        cookies: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
        clear: bool = False,
    ) -> dict[str, Any]:
        """worker 显式设置/查看会话态：手动登记拿到的 token/cookie，后续自动携带。全模式可用。"""
        try:
            if clear:
                self._session_cookies.clear()
                self._session_headers.clear()
            if isinstance(cookies, dict):
                for k, v in cookies.items():
                    if not isinstance(k, str):
                        continue
                    if k in self._session_cookies or len(self._session_cookies) < _SESSION_MAX_COOKIES:
                        self._session_cookies[k] = str(v)[:4096]
            if isinstance(headers, dict):
                for k, v in headers.items():
                    if not isinstance(k, str):
                        continue
                    if k in self._session_headers or len(self._session_headers) < _SESSION_MAX_HEADERS:
                        self._session_headers[k] = str(v)[:4096]
            return {
                "ok": True,
                "active_cookies": sorted(self._session_cookies.keys()),
                "active_headers": sorted(self._session_headers.keys()),
                "guidance": "已更新会话态，后续 http_request 会自动携带；继续以此据点深挖受限接口。",
            }
        except Exception as e:
            return {"ok": False, "error": f"session_set 异常: {type(e).__name__}: {e}"}

    def snapshot_session(self) -> dict[str, dict[str, str]]:
        """深拷贝当前会话状态（cookies + headers），供操作后恢复用。"""
        return {
            "cookies": dict(self._session_cookies or {}),
            "headers": dict(self._session_headers or {}),
        }

    def restore_session(self, snap: dict[str, dict[str, str]]) -> None:
        """从快照恢复会话状态（深拷贝写回）。失败静默不抛异常。"""
        try:
            self._session_cookies = dict(snap.get("cookies") or {})
            self._session_headers = dict(snap.get("headers") or {})
        except Exception:
            pass

    # ---- 工作笔记（跨轮持久记忆）----
    def update_notes(self, notes: str = "") -> dict[str, Any]:
        """worker 更新工作笔记。笔记每轮注入回 messages，不受历史压缩影响。"""
        self._worker_notes = (notes or "").strip()[:4000]
        return {"ok": True, "notes_len": len(self._worker_notes)}

    # ---- 结构化认知卡（跨轮持久、结构化工作记忆）----
    _COGNITION_SLOTS = ("confirmed", "excluded", "leads")
    _COGNITION_LIMITS = {"confirmed": 12, "excluded": 12, "leads": 10, "plan": 2000}

    def update_cognition(self, slot: str = "", text: str = "") -> dict[str, Any]:
        """向认知卡的一个槽位写入/更新内容。

        槽位语义（把思考过程结构化，避免重复踩坑/遗忘线索）：
          - confirmed：已实证确认的事实/危害（端点、能读到的数据、拿到的凭据）
          - excluded ：已排除的攻击方向 + 原因（不重复尝试已证明失败的路）
          - leads    ：未落定的活跃线索（待下一步验证的可能性）
          - plan     ：当前打法/下一步计划（自由文本，直接覆盖）
        slot 为列表槽时追加（去重）；plan 为覆盖。限量防膨胀。
        """
        slot = (slot or "").strip().lower()
        text = (text or "").strip()[:4000]
        if slot not in self._cognition:
            return {"ok": False, "kind": "arg_error", "error": f"认知槽位必须是 {list(self._COGNITION_SLOTS)} 或 plan。"}
        if not text:
            return {"ok": False, "kind": "arg_error", "error": "text 不能为空。"}
        if slot in self._COGNITION_SLOTS:
            items = self._cognition[slot]
            assert isinstance(items, list)
            if text not in items:
                items.append(text)
            limit = self._COGNITION_LIMITS[slot]
            if len(items) > limit:
                del items[: len(items) - limit]  # 保留最新
        else:
            self._cognition[slot] = text[: self._COGNITION_LIMITS["plan"]]
        return {"ok": True, "slot": slot, "counts": {s: len(v) if isinstance(v, list) else 0 for s, v in self._cognition.items() if s != "plan"}, "plan": str(self._cognition.get("plan"))[:80]}

    def session_status_block(self) -> str:
        """生成会话态 + 结构化认知卡 + 工作笔记摘要块，供 worker 每轮注入 messages。

        这是「像人一样记忆」的核心：历史被压缩成摘要后，worker 仍能『看到』自己
        持有哪些登录态、已证实什么、已排除什么、还有哪些线索没验证、下一步干嘛，
        不会重复扫同一条路、也不会忘了半途的线索。
        """
        lines = ["# 当前状态（跨轮持久，每轮自动注入）"]
        # 会话态
        cookies = sorted(self._session_cookies.keys()) if self._session_cookies else []
        headers = sorted(self._session_headers.keys()) if self._session_headers else []
        if cookies or headers:
            lines.append(f"- 会话态：持有 cookie {cookies}，鉴权头 {headers}（http_request 自动携带）")
        else:
            lines.append("- 会话态：暂无登录态（拿到凭证后用 session_set 登记）")
        # 结构化认知卡
        cog = self._cognition
        lines.append("- 认知卡（用 update_cognition 维护）：")
        if cog.get("confirmed"):
            lines.append("  · 已证实：" + "；".join(cog["confirmed"]))
        else:
            lines.append("  · 已证实：（无，发现实锤先 Update_cognition 收集，别光在脑子里）")
        if cog.get("excluded"):
            lines.append("  · 已排除：" + "；".join(cog["excluded"]))
        if cog.get("leads"):
            lines.append("  · 活跃线索：" + "；".join(cog["leads"]))
        if cog.get("plan"):
            lines.append("  · 当前计划：" + str(cog.get("plan")))
        else:
            lines.append("  · 当前计划：（暂无，明确下一步后用 update_cognition(plan=…) 写下，才能节奏不乱）")
        # 工作笔记
        if self._worker_notes:
            lines.append("- 工作笔记：")
            lines.append(self._worker_notes)
        return "\n".join(lines) + "\n\n"

    def export_resume_state(self) -> dict[str, Any]:
        """导出可跨 worker 续挖的进度快照（认知卡 + 笔记 + 会话态 + shell 状态）。"""
        return {
            "worker_notes": self._worker_notes or "",
            "cognition": {k: (list(v) if isinstance(v, list) else str(v)) for k, v in self._cognition.items()},
            "session_cookies": dict(self._session_cookies or {}),
            "session_headers": dict(self._session_headers or {}),
            "shell_cwd": str(self._shell_cwd),
            "shell_env": dict(self._shell_env or {}),
            "shell_history": list(self._shell_history[-50:]),
        }

    def restore_resume_state(
        self,
        *,
        worker_notes: str = "",
        cognition: dict | None = None,
        session_cookies: dict | None = None,
        session_headers: dict | None = None,
        shell_cwd: str = "",
        shell_env: dict | None = None,
        shell_history: list | None = None,
    ) -> None:
        """从上一轮 LLM 中断快照恢复认知卡、笔记、会话态与 shell 状态。"""
        if worker_notes:
            self._worker_notes = str(worker_notes).strip()[:4000]
        if isinstance(cognition, dict):
            for slot, val in cognition.items():
                if slot in self._COGNITION_SLOTS and isinstance(val, list):
                    self._cognition[slot] = [str(x)[:4000] for x in val][: self._COGNITION_LIMITS[slot]]
                elif slot == "plan" and isinstance(val, str):
                    self._cognition[slot] = val[: self._COGNITION_LIMITS["plan"]]
        cookies = session_cookies if isinstance(session_cookies, dict) else {}
        headers = session_headers if isinstance(session_headers, dict) else {}
        if cookies or headers:
            self.session_set(cookies=cookies or None, headers=headers or None)
        if shell_cwd:
            try:
                p = Path(shell_cwd)
                if p.exists() and p.is_dir():
                    self._shell_cwd = p
            except Exception:
                pass
        if isinstance(shell_env, dict):
            self._shell_env = {str(k): str(v) for k, v in shell_env.items()}
        if isinstance(shell_history, list):
            self._shell_history = [str(x) for x in shell_history if isinstance(x, str)][-50:]

    # ---- decode_transform ----
    def decode_transform(self, value: str = "", mode: str = "auto") -> dict[str, Any]:
        """编码/解码/哈希分析（纯内存，无外部副作用）。详见 tools/decoder.py。"""
        return _decode_transform(value, mode)

    # ---- fofa_lookup（只读资产测绘，确认归属 + 探攻击面）----
    def fofa_lookup(self, query: str = "", size: int = 10) -> dict[str, Any]:
        """对任务选定的测绘引擎发一次只读查询，返回命中规模和样本
        （host/ip/port/title/domain/org）。

        用途：① 确认目标归属（org/备案/证书）填准 owner；② 看同 IP/同域还开了
        哪些端口/服务，发现隐藏攻击面。查询统一按 FOFA 语法书写，非 FOFA 引擎
        （Quake / Hunter / …）在请求前自动翻译。只读查询，不对目标产生任何请求。
        """
        from app.engines.sync import engine_display_name, engine_search_sync, result_rows_to_dicts

        engine_name = self.engine or "fofa"
        disp = engine_display_name(engine_name)
        if not self.fofa_key:
            return {"ok": False, "error": f"未配置 {disp} key，无法查询。",
                    "guidance": "跳过测绘，直接用 http_request 验证归属（看证书/页脚/备案）。"}
        q = (query or "").strip()
        if not q:
            return {"ok": False, "kind": "arg_error", "error": "query 不能为空",
                    "guidance": f'传 {disp} 查询语法，如 ip="1.2.3.4" 或 host="example.com"。'}
        safe_size = max(1, min(int(size or 10), _FOFA_LOOKUP_MAX_SIZE))
        try:
            res = engine_search_sync(
                engine_name, self.fofa_key, q,
                page=1, page_size=safe_size, base_url=self.fofa_base_url or None,
            )
        except Exception as e:
            return {"ok": False, "error": f"{disp} 调用失败: {type(e).__name__}: {e}"[:300],
                    "guidance": f"{disp} 不可用，改用 http_request 直接验证归属。"}

        sample = []
        for r in result_rows_to_dicts(res, limit=safe_size):
            sample.append({
                "host": r.get("host", ""),
                "ip": r.get("ip", ""),
                "port": r.get("port", ""),
                "title": (r.get("title", "") or "")[:120],
                "domain": r.get("domain", ""),
                "org": r.get("org", ""),
                "protocol": r.get("protocol", ""),
            })
        return {
            "ok": True,
            "query": q,
            "engine": engine_name,
            "size": res.size,
            "sample": sample,
            "guidance": "据此核实 owner 归属、发现同 IP/同域其它端口与服务；测绘只读，验证仍需 http_request 实证。",
        }

    # ---- asset_discovery（主动侦察攻击面：子域 / 路径 / 同 IP）----
    def asset_discovery(
        self,
        target: str = "",
        enum_type: str = "subdomain",
        max_results: int = 20,
    ) -> dict[str, Any]:
        """主动侦察攻击面（只读）。复用任务选定的测绘引擎；无 key 时内置字典/TCP 回退。"""
        try:
            check_task_forbidden(target or "", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _asset_discovery(
                target,
                enum_type,
                engine=self.engine or "fofa",
                api_key=self.fofa_key or "",
                base_url=self.fofa_base_url or "",
                client=self._get_http_client(),
                max_results=max_results,
            )
        except Exception as e:
            return {"ok": False, "error": f"asset_discovery 异常: {type(e).__name__}: {e}"}

    # ---- fingerprint（系统/中间件/框架/WAF/版本识别 + 已知漏洞匹配）----
    def fingerprint(
        self,
        url: str = "",
        headers: Optional[dict[str, Any]] = None,
        body: str = "",
        title: str = "",
    ) -> dict[str, Any]:
        """识别目标指纹并匹配内置已知漏洞表（只给验证思路，不自动打）。"""
        try:
            check_task_forbidden("\n".join([url or "", title or ""]), self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _fingerprint(
                url=url,
                headers=headers,
                body=body,
                title=title,
                client=self._get_http_client(),
            )
        except Exception as e:
            return {"ok": False, "error": f"fingerprint 异常: {type(e).__name__}: {e}"}

    # ---- 指纹实测验证链（按内置只读探针实测已知漏洞，不碰数据）----
    def verify_known_vuln(
        self,
        url: str = "",
        vuln_name: str = "",
    ) -> dict[str, Any]:
        """对指纹命中的已知漏洞做只读探针实测：逐条发 GET，判定特征命中。
        命中只代表组件/端点暴露，是否构成可交漏洞由 worker 按实际危害判断。
        """
        try:
            check_task_forbidden(f"GET {url or ''} {vuln_name or ''}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        if not vuln_name or not url:
            return {"ok": False, "kind": "arg_error",
                    "error": "需同时传目标 url 和要实测的已知漏洞 vuln_name（来自 fingerprint 的 known_vulns）。"}
        norm = _norm_target(url)
        if not norm:
            return {"ok": False, "kind": "arg_error", "error": f"目标无法解析: {url}"}
        base = norm["base"]
        actions = _get_verify_actions(vuln_name)
        if not actions:
            return {"ok": False, "kind": "no_probe",
                    "error": f"「{vuln_name}」无内置结构化探针（需端口/特殊协议/危险载荷），"
                             "请按 fingerprint 返回的 verify 思路用 http_request 自行实证。"}
        results: list[dict[str, Any]] = []
        try:
            for a in actions:
                probe = _build_probe_request(base, a)
                resp = self.http_request(
                    probe["url"], method=probe["method"], timeout=12, follow_redirects=True
                )
                if not resp.get("ok"):
                    results.append({
                        "label": a.get("label") or a.get("path", ""),
                        "method": probe["method"], "path": a.get("path", ""),
                        "status": 0, "signal": False, "hit": False,
                        "snippet": (resp.get("error") or "")[:_SIGNAL_SNIPPET],
                    })
                    continue
                results.append(
                    _mark_action_result(
                        a, resp.get("status_code") or 0,
                        resp.get("body") or "", resp.get("response_headers") or {}
                    )
                )
        except Exception as e:
            return {"ok": False, "error": f"verify_known_vuln 异常: {type(e).__name__}: {e}"}
        verdict = _summarize_evidence(results)
        return {
            "ok": True,
            "vuln_name": vuln_name,
            "base_url": base,
            "probes_count": len(results),
            "probes": results,
            "verdict": verdict.get("verdict", "unknown"),
            "summary": verdict.get("summary", ""),
            "guidance": (
                "探针只读探测，命中只代表该组件/端点暴露且版本疑似受影响。"
                "构成可交漏洞需按风险确认实际危害（如确实读到配置/数据/未授权操作），"
                "实证成功 + 有危害才 submit_finding；纯端点可达无特征不算洞。"
            ),
        }

    # ---- 凭证爆破与登录态自动化（阶段三）----
    def credential_brute(
        self,
        login_url: str = "",
        username: str = "",
        usernames: Optional[list[str]] = None,
        passwords: Optional[list[str]] = None,
        use_builtin_dict: bool = True,
        max_attempts: int = 20,
        edu_mode: bool = False,
    ) -> dict[str, Any]:
        """弱口令验证（限量限速）：内置字典 + 表单识别 + 成功判定。"""
        try:
            check_task_forbidden(
                "\n".join([login_url or "", username or "", " ".join(usernames or [])]),
                self._forbidden_ops,
            )
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _credential_brute(
                self,
                login_url=login_url,
                username=username,
                usernames=usernames,
                passwords=passwords,
                use_builtin_dict=use_builtin_dict,
                max_attempts=max_attempts,
                edu_mode=edu_mode,
            )
        except Exception as e:
            return {"ok": False, "error": f"credential_brute 异常: {type(e).__name__}: {e}"}

    def login_session(
        self,
        login_url: str = "",
        username: str = "",
        password: str = "",
    ) -> dict[str, Any]:
        """登录态自动化：自动登录并保持会话。"""
        try:
            check_task_forbidden("\n".join([login_url or "", username or ""]), self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _login_session(self, login_url=login_url, username=username, password=password)
        except Exception as e:
            return {"ok": False, "error": f"login_session 异常: {type(e).__name__}: {e}"}

    def login_form_scan(
        self,
        url: str = "",
        max_paths: int = 8,
    ) -> dict[str, Any]:
        """登录入口/表单侦察：探测登录路径、识别字段与验证码。"""
        try:
            check_task_forbidden(url or "", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _login_form_scan(self, url=url, max_paths=max_paths)
        except Exception as e:
            return {"ok": False, "error": f"login_form_scan 异常: {type(e).__name__}: {e}"}

    # ---- 攻击面扩展 / 参数可控性探测（纯规则，限量限速防 DoS）----
    def http_batch(
        self,
        url: str = "",
        param_name: str = "",
        start: int = 1,
        end: int = 10,
        step: int = 1,
        method: str = "GET",
        data_template: str = "",
        delay: float = 0.15,
        max_items: int = 40,
        interest_contains: Optional[list[str]] = None,
        timeout: int = 15,
    ) -> dict[str, Any]:
        """批量遍历 IDOR/越权枚举（限量限速）。"""
        try:
            check_task_forbidden(f"{method} {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _http_batch(
                self, url=url, param_name=param_name, start=start, end=end, step=step,
                method=method, data_template=data_template, delay=delay, max_items=max_items,
                interest_contains=interest_contains, timeout=timeout,
            )
        except Exception as e:
            return {"ok": False, "error": f"http_batch 异常: {type(e).__name__}: {e}"}

    def diff_response(
        self,
        url: str = "",
        params_a: Optional[dict] = None,
        params_b: Optional[dict] = None,
        method: str = "GET",
        timeout: int = 15,
    ) -> dict[str, Any]:
        """同一请求两组参数做响应差异对比，判定参数可控性。"""
        try:
            check_task_forbidden(f"{method} {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _diff_response(self, url=url, params_a=params_a, params_b=params_b,
                                  method=method, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"diff_response 异常: {type(e).__name__}: {e}"}

    def timing_probe(
        self,
        url: str = "",
        method: str = "GET",
        data: str = "",
        samples: int = 5,
        timeout: int = 15,
    ) -> dict[str, Any]:
        """时序测量，辅助时间盲注/时序侧信道判定。"""
        try:
            check_task_forbidden(f"{method} {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _timing_probe(self, url=url, method=method, data=data or None,
                                 samples=samples, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"timing_probe 异常: {type(e).__name__}: {e}"}

    def crawl_links(
        self,
        url: str = "",
        max_pages: int = 5,
        max_links: int = 60,
        same_host_only: bool = True,
        timeout: int = 10,
    ) -> dict[str, Any]:
        """攻击面链接抓取（只读 GET，限量限速）。"""
        try:
            check_task_forbidden(f"GET {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _crawl_links(self, url=url, max_pages=max_pages, max_links=max_links,
                                same_host_only=same_host_only, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"crawl_links 异常: {type(e).__name__}: {e}"}

    # ---- 专项漏洞探测（纯规则，只读/无害，限量限速防 DoS）----
    def sqli_probe(
        self,
        url: str = "",
        param_name: str = "",
        method: str = "GET",
        probe_types: Optional[list[str]] = None,
        timeout: int = 12,
    ) -> dict[str, Any]:
        """SQL 注入探测（报错/布尔/时间三类，只读无害）。"""
        try:
            check_task_forbidden(f"{method} {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _sqli_probe(self, url=url, param_name=param_name, method=method,
                               probe_types=probe_types, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"sqli_probe 异常: {type(e).__name__}: {e}"}

    def upload_probe(
        self,
        url: str = "",
        file_field: str = "file",
        filename: str = "test.txt",
        content_type: str = "text/plain",
        timeout: int = 15,
    ) -> dict[str, Any]:
        """上传接口无害探测（只传纯文本占位，不落可执行文件）。"""
        try:
            check_task_forbidden(f"POST {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _upload_probe(self, url=url, file_field=file_field, filename=filename,
                                 content_type=content_type, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"upload_probe 异常: {type(e).__name__}: {e}"}

    def path_probe(
        self,
        url: str = "",
        max_paths: int = 40,
        include_backup: bool = True,
        timeout: int = 10,
    ) -> dict[str, Any]:
        """路径字典爆破 + 备份/源码泄露探测（批量只读 GET，限量限速防 DoS）。"""
        if not url:
            return {"ok": False, "kind": "arg_error", "error": "url 不能为空",
                    "guidance": "传目标 URL，如 https://example.com"}
        try:
            base = str(url).strip()
            if not base.startswith(("http://", "https://")):
                base = "https://" + base
            parsed = urllib.parse.urlsplit(base)
            origin = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            return {"ok": False, "error": f"URL 解析失败: {url}"}
        try:
            check_task_forbidden(f"GET {origin}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}

        safe_max = max(1, min(int(max_paths or 40), 80))
        # 常规路径占前 60%，备份/源码泄露路径占后 40%：保证默认预算内两类都覆盖，
        # 否则 _PATH_DICT 有 43 条、默认 max_paths=40 时备份路径永远探测不到。
        reg_budget = max(1, int(safe_max * 0.6))
        paths = list(_PATH_DICT)[:reg_budget]
        if include_backup:
            paths += _BACKUP_PATH_DICT[: max(0, safe_max - reg_budget)]

        hits: list[dict[str, Any]] = []
        probed = 0
        for p in paths:
            if self.cancel_event.is_set():
                break
            target = f"{origin}/{p}"
            probed += 1
            try:
                res = self.http_request(url=target, method="GET", timeout=timeout)
            except Exception:
                continue
            if not isinstance(res, dict) or not res.get("ok"):
                continue
            code = res.get("status_code")
            if code not in (200, 301, 302, 401, 403):
                continue
            body = str(res.get("body") or "")
            is_backup = p in _BACKUP_PATH_DICT or any(
                p.endswith(sfx) for sfx in (".zip", ".rar", ".bak", ".sql", ".git", ".svn", ".env", ".DS_Store")
            )
            # 备份/源码泄露类：body 必须含特征关键词才算真泄露，避免框架 404 页误报。
            if is_backup and code == 200:
                low = body.lower()
                if not any(m in low for m in _BACKUP_HIT_MARKERS):
                    continue
            hits.append({
                "path": "/" + p,
                "status": code,
                "length": len(body),
                "title": str(res.get("title") or "")[:120],
                "snippet": body[:300],
                "backup": is_backup,
            })
            time.sleep(0.08)  # 限速防 DoS
        hits.sort(key=lambda h: (0 if h["backup"] else 1, h["status"]))
        return {
            "ok": True,
            "base": origin,
            "probed": probed,
            "hit_count": len(hits),
            "hits": hits[:40],
            "guidance": "命中只是「路径存在/有响应」信号，必须用 http_request 复现取证确认实际危害后再 submit_finding。"
                        "备份/源码泄露类（.git/.env/www.zip 等）命中后优先验证能否下载读取敏感内容。",
        }

    def injection_probe(
        self,
        url: str = "",
        param_name: str = "",
        method: str = "GET",
        probe_types: Optional[list[str]] = None,
        timeout: int = 12,
    ) -> dict[str, Any]:
        """CORS/SSRF/命令注入/SSTI/XXE 五类注入探针（只读无害，限量限速）。"""
        try:
            check_task_forbidden(f"{method} {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _injection_probe(self, url=url, param_name=param_name, method=method,
                                    probe_types=probe_types, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"injection_probe 异常: {type(e).__name__}: {e}"}

    def access_boundary(
        self,
        url: str = "",
        method: str = "GET",
        data: str = "",
        timeout: int = 12,
    ) -> dict[str, Any]:
        """权限边界测试（无认证 vs 当前会话，只读无害）。"""
        try:
            check_task_forbidden(f"{method} {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _access_boundary(self, url=url, method=method, data=data, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"access_boundary 异常: {type(e).__name__}: {e}"}

    def capture_evidence(
        self,
        url: str = "",
        method: str = "GET",
        data: str = "",
        timeout: int = 15,
    ) -> dict[str, Any]:
        """存证快照：抓取指定页面 HTTP 快照并持久化，返回 evidence_ref（只读无害）。"""
        try:
            check_task_forbidden(f"{method} {url}", self._forbidden_ops)
        except CommandBlocked as e:
            return {"ok": False, "blocked": True, "error": str(e)}
        try:
            return _capture_evidence_tool(self, url=url, method=method, data=data, timeout=timeout)
        except Exception as e:
            return {"ok": False, "error": f"capture_evidence 异常: {type(e).__name__}: {e}"}

    @staticmethod
    def _read_limited_response(resp: httpx.Response) -> tuple[str, bool]:
        chunks: list[bytes] = []
        total = 0
        truncated = False
        try:
            for chunk in resp.iter_bytes():
                if not chunk:
                    continue
                if total + len(chunk) > _HTTP_MAX_BYTES:
                    room = max(0, _HTTP_MAX_BYTES - total)
                    if room:
                        chunks.append(chunk[:room])
                    truncated = True
                    break
                chunks.append(chunk)
                total += len(chunk)
        finally:
            resp.close()
        body = b"".join(chunks).decode(resp.encoding or "utf-8", "replace")
        if truncated:
            body += f"\n\n...[响应超过 {_HTTP_MAX_BYTES} 字节，已截断以保护内存]..."
        return body, truncated

    # ---- http_request 响应自动分析 ----
    # 帮 worker 单轮拿到更多信息：JSON 字段名/敏感信息/技术栈，减少重复请求与解析轮次。
    _JSON_FIELD_MAX = 24
    _ID_CARD_RE = re.compile(r"\b\d{17}[\dXx]\b")
    _PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
    _SENSITIVE_KEYWORDS = (
        "token", "secret", "apikey", "api_key", "accesskey", "access_key",
        "password", "passwd", "authorization", "privatekey", "私钥", "密钥",
    )
    _TECH_BODY_MARKERS = {
        "thinkphp": "ThinkPHP", "laravel": "Laravel", "spring": "Spring",
        "shiro": "Shiro", "django": "Django", "flask": "Flask",
        "ruoyi": "RuoYi", "若依": "RuoYi", "nacos": "Nacos", "druid": "Druid",
        "swagger": "Swagger", "wordpress": "WordPress", "actuator": "SpringBoot-Actuator",
    }

    @classmethod
    def _json_field_names(cls, value: Any, depth: int = 0) -> list[str]:
        out: list[str] = []
        if depth > 2 or not isinstance(value, (dict, list)) or len(out) >= cls._JSON_FIELD_MAX:
            return out
        if isinstance(value, dict):
            for k in list(value.keys())[: cls._JSON_FIELD_MAX]:
                out.append(str(k))
                if len(out) >= cls._JSON_FIELD_MAX:
                    break
        elif value:
            out.extend(cls._json_field_names(value[0], depth + 1))
        return out

    # ---- 业务类型自动识别（侦察后动态修正画像）----
    _HTML_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
    _HTML_META_RE = re.compile(
        r'<meta[^>]+(?:name|property)=["\'](?:description|keywords|og:title)["\'][^>]*content=["\']([^"\']+)["\']',
        re.I,
    )

    def _detect_business_from_html(self, url: str, body: str) -> dict[str, Any] | None:
        """从 HTML 响应提取业务特征并识别业务类型（host 级缓存，只识别一次）。

        手动清单只给 URL 时，编排层静态画像常缺失；Worker 侦察到真实页面后，
        用页面标题/meta/可见文本自动识别业务，动态注入业务逻辑测试引导。
        """
        try:
            host = (httpx.URL(url).host or "").lower()
        except Exception:
            host = ""
        if host and host in self._business_cache:
            return self._business_cache[host] or None
        title = ""
        m = self._HTML_TITLE_RE.search(body)
        if m:
            title = re.sub(r"<[^>]+>", "", m.group(1)).strip()[:200]
        metas = [mm.group(1).strip()[:200] for mm in self._HTML_META_RE.finditer(body)]
        visible = re.sub(r"<script.*?</script>|<style.*?</style>", " ", body, flags=re.I | re.S)
        visible = re.sub(r"<[^>]+>", " ", visible)
        visible = re.sub(r"\s+", " ", visible).strip()[:600]
        biz = profile_business(
            url=url,
            title=title,
            priority_reason=" ".join(x for x in (*(m for m in metas), visible) if x)[:600],
        )
        if not biz or biz.confidence < 0.5:
            self._business_cache[host] = None
            return None
        out = {
            "biz_id": biz.biz_id,
            "label": biz.label,
            "confidence": round(biz.confidence, 2),
            "evidence": list(biz.evidence),
            "block": render_business_block(biz),
        }
        self._business_cache[host] = out
        return out

    @staticmethod
    def _analyze_http_response(body: str, headers: dict[str, str]) -> dict[str, Any]:
        """从响应体/响应头提取结构化线索，附加到 http_request 返回，提升单轮信息密度。"""
        analysis: dict[str, Any] = {}
        # 1) JSON 结构：提取字段名，帮 worker 快速定位可用字段
        try:
            parsed = json.loads(body)
            fields = ToolExecutor._json_field_names(parsed)
            if fields:
                analysis["json_fields"] = fields
        except Exception:
            pass
        # 2) 敏感信息：身份证/手机号/敏感字段名
        hits: list[str] = []
        if ToolExecutor._ID_CARD_RE.search(body):
            hits.append("id_card")
        if ToolExecutor._PHONE_RE.search(body):
            hits.append("phone")
        low = body.lower()
        if any(k in low for k in ToolExecutor._SENSITIVE_KEYWORDS):
            hits.append("secret_or_token")
        if hits:
            analysis["sensitive_hits"] = hits
        # 3) 技术栈指纹：响应头 + 高置信框架特征
        tech: list[str] = []
        for hk in ("server", "x-powered-by", "x-aspnet-version"):
            v = headers.get(hk) or headers.get(hk.title()) or ""
            if v:
                tech.append(f"{hk}={v[:60]}")
        for marker, name in ToolExecutor._TECH_BODY_MARKERS.items():
            if marker in low:
                tech.append(name)
        if tech:
            analysis["tech"] = tech[:6]
        return analysis

    @staticmethod
    def _raw_request(req: httpx.Request, data: Optional[str], json_body: Any) -> str:
        lines = [f"{req.method} {req.url.raw_path.decode('latin-1')} HTTP/1.1"]
        lines.append(f"Host: {req.url.host}")
        for k, v in req.headers.items():
            if k.lower() == "host":
                continue
            lines.append(f"{k}: {v}")
        body = ""
        if req.content:
            try:
                body = req.content.decode("utf-8", "replace")
            except Exception:
                body = "<binary>"
        return "\n".join(lines) + "\n\n" + body

    # ---- analyze_javascript（条件开放给 worker）----
    def analyze_javascript(
        self,
        url: str = "",
        text: str = "",
        max_depth: int = 2,
        max_assets: int = 80,
    ) -> dict[str, Any]:
        """分析入口 URL 或 JS 文本，返回高价值链路和统一接口清单。"""
        try:
            safe_depth = max(0, min(int(max_depth or 2), 4))
            safe_assets = max(1, min(int(max_assets or 80), 150))
            if url:
                result = analyze_js_url(url, max_depth=safe_depth, max_assets=safe_assets)
            elif text:
                result = analyze_js_text(text[:800_000], base_url=self.target, source="worker_text")
            else:
                return {
                    "ok": False,
                    "kind": "arg_error",
                    "error": "analyze_javascript 需要 url 或 text",
                    "guidance": "传入口 URL 或已抓到的 JS 文本；不要空调用。",
                }
            return {
                "ok": True,
                "summary": result.get("summary", {}),
                "chains": result.get("chains", [])[:8],
                "endpoint_inventory": result.get("endpoint_inventory", [])[:80],
                "state_machines": result.get("state_machines", [])[:6],
                "assets": result.get("assets", [])[:30],
                "fetch_errors": result.get("fetch_errors", [])[:20],
                "guidance": self._js_analyze_guidance(result),
            }
        except Exception as e:
            return {"ok": False, "error": f"JS 分析异常: {type(e).__name__}: {e}"}

    @staticmethod
    def _js_analyze_guidance(result: dict[str, Any]) -> str:
        chains = result.get("chains") or []
        kinds = {c.get("kind") for c in chains if isinstance(c, dict)}
        base = (
            "这些只是 JS 静态线索。优先按 chains 里的 probes 用 http_request/run_shell 做真实验证；"
            "没有实证危害不要 submit_finding。"
        )
        if "client_signed_encrypted_api" in kinds:
            return (
                base
                + " 已命中「客户端签名+AES 加密请求体」链路：立刻提取 ClientAppID/ClientAppSecret/AES 口令，"
                "按前端算法构造 HeadJson + PWDDATA_ 加密 body，POST Admin/Client* 接口并解密 Model 取证；"
                "只发现密钥不算洞。"
            )
        if "frontend_secret_followup" in kinds:
            return base + " 发现高价值 secret：继续搜索签名/加密函数并伪造一次受限调用。"
        if "business_state_machine" in kinds:
            return (
                base
                + " 已命中「业务状态机/多步流」链路：按 state_machines 的 probes 实测步骤跳过"
                "（直接请求第 N 步）、状态篡改（status 待审批→已通过/未支付→已支付）、"
                "步骤令牌删除/复用、并发竞态；必须用 http_request 实证状态真实变化。"
            )
        return base

    # ---- suggest_waf_bypass（纯本地，不发网络）----
    def suggest_waf_bypass(
        self,
        payload: str,
        status_code: int | None = None,
        response_headers: Optional[dict[str, Any]] = None,
        response_body: str = "",
        context: str = "generic",
    ) -> dict[str, Any]:
        try:
            return _suggest_waf_bypass(
                payload=payload,
                status_code=status_code,
                response_headers=response_headers,
                response_body=response_body,
                context=context,
            )
        except Exception as e:
            return {"ok": False, "error": f"WAF 建议生成异常: {type(e).__name__}: {e}"}
