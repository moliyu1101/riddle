"""FOFA 搜索引擎适配。支持多账号自动切换：api_key 可传逗号分隔的多个 key，
主号 → backup → backup2 依次尝试，遇限流/账号错误自动切下一个，全部失败才抛错。"""
from __future__ import annotations

import base64
from typing import Any

import httpx

from app.engines.base import EngineResult, SearchEngine, register_engine

BASE = "https://fofa.info"


class FofaError(Exception):
    def __init__(self, message: str, account_error: bool = False):
        super().__init__(message)
        self.account_error = account_error


_FOFA_ACCOUNT_ERROR_MARKERS = (
    "820000", "820001", "-700", "账号无效", "账号已过期", "账号过期",
    "无效的fofa", "无效的 fofa", "f点不足", "f币不足", "余额不足", "配额",
    "权限不足", "没有权限", "会员", "account invalid", "invalid key",
    "expired", "insufficient", "quota", "permission", "unauthorized", "forbidden",
)

# 限流/配额耗尽标记（对齐 clown-src fofa.py）：命中即切下一个账号
_FOFA_RATE_LIMIT_MARKERS = (
    "429", "too many", "rate", "820041", "今日", "上限", "f点", "fpoint",
    "请求频繁", "访问频率", "频繁",
)


def _is_account_error(errmsg: str) -> bool:
    text = str(errmsg or "").lower()
    return any(m in text for m in _FOFA_ACCOUNT_ERROR_MARKERS)


def _is_rate_limited(errmsg: str, status_code: int | None = None) -> bool:
    if status_code in (429, 403):
        return True
    text = str(errmsg or "").lower()
    return any(m in text for m in _FOFA_RATE_LIMIT_MARKERS)


def _split_keys(api_key: str) -> list[str]:
    """把逗号分隔的多 key 拆成列表；单 key 原样返回。"""
    parts = [k.strip() for k in (api_key or "").split(",") if k.strip()]
    return parts or []


def _qbase64(query: str) -> str:
    return base64.b64encode(query.encode("utf-8")).decode("ascii")


@register_engine
class FofaEngine(SearchEngine):
    @property
    def name(self) -> str:
        return "fofa"

    @property
    def display_name(self) -> str:
        return "FOFA"

    @property
    def env_key_name(self) -> str:
        return "FOFA"

    def get_default_base_url(self) -> str:
        return BASE

    async def search(
        self,
        api_key: str,
        query: str,
        page: int = 1,
        page_size: int = 100,
        base_url: str | None = None,
        cursor: str | None = None,
    ) -> EngineResult:
        keys = _split_keys(api_key)
        if not keys:
            raise FofaError("缺少 FOFA key")
        base = (base_url or BASE).rstrip("/")
        # 不再对 FOFA base_url 做本地白名单/SSRF 拦截：私有部署、内网镜像、自建代理均可直连。

        fields = "host,ip,port,title,domain,org"
        last_error: FofaError | None = None
        tried: list[str] = []
        for idx, key in enumerate(keys):
            tried.append(f"#{idx + 1}")
            params = {
                "key": key, "qbase64": _qbase64(query),
                "fields": fields, "page": str(page), "size": str(page_size), "full": "false",
            }
            try:
                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.get(f"{base}/api/v1/search/all", params=params)
                    try:
                        data = resp.json()
                    except Exception:
                        raise FofaError(f"FOFA 返回非 JSON (HTTP {resp.status_code}): {resp.text[:200]}")
            except FofaError:
                raise
            except httpx.HTTPError as e:
                raise FofaError(f"FOFA 请求失败: {type(e).__name__}: {e}") from e

            if data.get("error"):
                errmsg = data.get("errmsg")
                # 限流/账号错误：切下一个账号重试
                if _is_rate_limited(errmsg, resp.status_code) or _is_account_error(errmsg):
                    last_error = FofaError(f"FOFA 错误: {errmsg}", account_error=_is_account_error(errmsg))
                    continue
                raise FofaError(f"FOFA 错误: {errmsg}", account_error=_is_account_error(errmsg))

            return EngineResult(
                fields=fields.split(","),
                results=data.get("results", []),
                size=data.get("size", 0),
                page=page,
                engine="fofa",
            )

        if last_error is not None:
            raise FofaError(
                f"FOFA 错误: {last_error}（已尝试 {len(tried)} 个账号）",
                account_error=last_error.account_error,
            )
        raise FofaError("FOFA 查询失败：所有账号均不可用")