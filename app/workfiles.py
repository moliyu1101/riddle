"""工作目录静态文件安全服务（替代裸 StaticFiles 挂载）。

背景：/workfiles 之前直接挂载整个 work_root，既不鉴权、又按扩展名回
Content-Type，导致两类问题：
1. 证据泄露：evidence_trail（含请求/响应明文、泄露凭据）、截图、目标下载
   文件对可达网络完全公开；
2. 同源存储型 XSS：worker 会把目标站下载的 .html/.svg 等落入 workdir，
   同源 + text/html 渲染可直接偷走控制台令牌（localStorage + 非 HttpOnly
   cookie）。

修复策略（鉴权由 main.py 的 security_middleware 统一处理，本模块负责内容安全）：
- 只放行 work_root 内的常规文件，拒绝路径穿越 / 符号链接逃逸 / 目录；
- 仅栅格图片（<img> 需要的 png/jpg/gif/webp/avif/ico）以内联方式返回，
  并强制 X-Content-Type-Options: nosniff；
- 其它一切扩展名（html/svg/js/json/text/…）一律降级为
  application/octet-stream + Content-Disposition: attachment，浏览器只能
  下载无法渲染，堵死同源存储型 XSS 链。
"""
from __future__ import annotations

from pathlib import Path

from fastapi import HTTPException
from fastapi.responses import FileResponse

# <img> 可安全内联渲染的栅格位图扩展名（无脚本执行能力）。
SAFE_INLINE_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".ico"})

_NOSNIFF = {"X-Content-Type-Options": "nosniff"}


def resolve_workfile(root: Path, rel: str) -> Path | None:
    """解析 /workfiles 相对路径；越界/不存在/非文件一律返回 None。

    resolve() 会同时解析 .. 与符号链接，配合 relative_to 防止任何形式的
    目录逃逸（含 symlink 指向根外、绝对路径、编码后的 ..）。
    """
    if not isinstance(rel, str) or not rel or rel.startswith("/"):
        return None
    try:
        root_resolved = Path(root).resolve()
        target = (root_resolved / rel).resolve()
        target.relative_to(root_resolved)
    except (ValueError, OSError):
        return None
    if not target.is_file():
        return None
    return target


def workfile_response(root: Path, rel: str) -> FileResponse:
    """构建安全的 workfiles 文件响应；非法路径抛 404。"""
    target = resolve_workfile(root, rel)
    if target is None:
        raise HTTPException(status_code=404, detail="Not Found")
    ext = target.suffix.lower()
    if ext in SAFE_INLINE_EXTS:
        return FileResponse(
            target,
            headers=dict(_NOSNIFF),
            content_disposition_type="inline",
        )
    return FileResponse(
        target,
        media_type="application/octet-stream",
        headers=dict(_NOSNIFF),
        filename=target.name,
        content_disposition_type="attachment",
    )
