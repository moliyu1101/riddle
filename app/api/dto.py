"""API 请求/响应 DTO。"""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class ModelConfigDTO(BaseModel):
    inherit_global: Optional[bool] = None
    base_url: str = "https://api.deepseek.com/v1"
    api_key: str = ""
    model: str = "deepseek-chat"
    # 单端点多模型灾备：models = 主模型 + 灾备模型，同供应商下失败自动顶替
    models: list[str] = Field(default_factory=list)
    protocol: str = "auto"
    temperature: Optional[float] = None
    prompt_version: str = ""
    # 任务级端点池：非空时覆盖单端点字段，走池化调度
    providers: Optional[list[dict[str, Any]]] = None


class FofaConfigDTO(BaseModel):
    key: str = ""
    base_url: str = ""
    max_pages: int = 20
    page_size: int = 100
    intent_mode: str = ""
    skip_site_recon: bool = False   # 单站协作：跳过入口盘点(site_map)侦察，省 token


class EngineConfigDTO(BaseModel):
    """多引擎配置。"""
    key: str = ""
    base_url: str = ""


class AuthBindingDTO(BaseModel):
    """一条用户凭据绑定：可绑 URL/host/*，字段可空，由后端 normalize 分辨类型。"""
    target: str = "*"
    username: str = ""
    password: str = ""
    cookie: str = ""
    authorization: str = ""
    login_url: str = ""
    raw: str = ""
    note: str = ""


class CreateTaskRequest(BaseModel):
    name: str
    src_type: str = "edusrc"
    vuln_types: list[str] = Field(default_factory=list)
    src_rules: str = ""
    target_source: str = "fofa"
    engine: str = ""                                           # 搜索引擎：fofa/quake/hunter/...
    fofa_query: str = ""
    manual_targets: list[str] = Field(default_factory=list)
    auth_bindings: list[AuthBindingDTO] = Field(default_factory=list)
    model_config_data: ModelConfigDTO = Field(default_factory=ModelConfigDTO)
    fofa_config: FofaConfigDTO = Field(default_factory=FofaConfigDTO)
    engine_config: EngineConfigDTO = Field(default_factory=EngineConfigDTO)  # 引擎 Key/URL
    concurrency: int = 3
    deepen_cap: int = 2


class PartialModelConfigDTO(BaseModel):
    inherit_global: Optional[bool] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    models: Optional[list[str]] = None
    protocol: Optional[str] = None
    prompt_version: Optional[str] = None
    providers: Optional[list[dict[str, Any]]] = None


class ParseTargetsRequest(BaseModel):
    text: str = ""


class ParseTargetsResponse(BaseModel):
    total_lines: int = 0
    valid: int = 0
    domains: int = 0
    ips: int = 0
    with_note: int = 0
    ignored: list[str] = Field(default_factory=list)
    ignored_total: int = 0
    targets: list[dict[str, Any]] = Field(default_factory=list)


class ParseQueryRequest(BaseModel):
    engine: str = "fofa"
    query: str = ""
    src_type: str = "edusrc"
    intent_mode: str = ""


class ParseQueryResponse(BaseModel):
    looks_like_syntax: bool = False
    token_count: int = 0
    joins: list[str] = Field(default_factory=list)
    fields: list[str] = Field(default_factory=list)
    keywords: dict[str, list[str]] = Field(default_factory=dict)
    issues: list[str] = Field(default_factory=list)
    summary: str = ""
    engine_hint: str = ""
    syntax_mismatch: str = ""
    field_sheet: list[dict[str, str]] = Field(default_factory=list)
    tokens_detail: list[dict[str, str]] = Field(default_factory=list)


class ParseAuthBatchRequest(BaseModel):
    text: str = ""


class ParseAuthBatchResponse(BaseModel):
    total_lines: int = 0
    parsed: int = 0
    bindings: list[dict[str, Any]] = Field(default_factory=list)
    ignored: list[str] = Field(default_factory=list)
    ignored_total: int = 0
    by_kind: dict[str, int] = Field(default_factory=dict)


class ParseForbiddenOpsRequest(BaseModel):
    text: str = ""


class ParseForbiddenOpsResponse(BaseModel):
    forbidden: list[dict[str, str]] = Field(default_factory=list)
    count: int = 0
    labels: str = ""


class TaskModelsProbeRequest(BaseModel):
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    key_ref: Optional[str] = None
    protocol: Optional[str] = None


class PartialFofaConfigDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None
    max_pages: Optional[int] = None
    page_size: Optional[int] = None
    intent_mode: Optional[str] = None
    skip_site_recon: Optional[bool] = None


class PartialEngineConfigDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None


class UpdateTaskRequest(BaseModel):
    name: Optional[str] = None
    src_type: Optional[str] = None
    vuln_types: Optional[list[str]] = None
    src_rules: Optional[str] = None
    target_source: Optional[str] = None
    engine: Optional[str] = None                                 # 切换引擎
    fofa_query: Optional[str] = None
    manual_targets: Optional[list[str]] = None
    auth_bindings: Optional[list[AuthBindingDTO]] = None
    model_config_data: Optional[PartialModelConfigDTO] = None
    fofa_config: Optional[PartialFofaConfigDTO] = None
    engine_config: Optional[PartialEngineConfigDTO] = None
    concurrency: Optional[int] = None
    deepen_cap: Optional[int] = None


class DirectiveRequest(BaseModel):
    """向运行中 worker 注入的人工实时指令。"""
    directive: str = Field(..., min_length=1, max_length=2000)


class TaskStats(BaseModel):
    queued: int = 0
    scanning: int = 0
    done: int = 0
    dead: int = 0
    skipped: int = 0
    findings_total: int = 0
    pending_review: int = 0
    accepted: int = 0
    ignored: int = 0
    deepen: int = 0
    killsweep: int = 0
    review_pending: int = 0
    submit_ready: int = 0
    rejected: int = 0
    archived: int = 0
    archived_write: int = 0


class TaskResponse(BaseModel):
    id: str
    name: str
    status: str
    src_type: str
    vuln_types: list[str]
    target_source: str
    engine: str = ""
    fofa_query: str
    concurrency: int
    deepen_cap: int = 2
    src_rules: str = ""
    manual_targets: list[str] = Field(default_factory=list)
    auth_bindings: list[dict] = Field(default_factory=list)
    model_config_data: dict = Field(default_factory=dict)
    fofa_config: dict = Field(default_factory=dict)
    engine_config: dict = Field(default_factory=dict)
    llm_usage: dict = Field(default_factory=dict)
    created_at: str
    updated_at: str
    stats: Optional[TaskStats] = None
    pending_user_review: int = 0
    total_targets: int = 0
    total_vulns: int = 0
    progress: int = 0


class LLMSettingsDTO(BaseModel):
    mode: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None
    models: Optional[list[str]] = None  # 单端点多模型灾备：主模型 + 灾备模型
    protocol: Optional[str] = None
    temperature: Optional[float] = None
    providers: Optional[list[dict[str, Any]]] = None


class FofaSettingsDTO(BaseModel):
    key: Optional[str] = None
    base_url: Optional[str] = None
    max_pages: Optional[int] = None
    page_size: Optional[int] = None
    default_intent_mode: Optional[str] = None


class EngineSettingsDTO(BaseModel):
    """单个搜索引擎的设置。"""
    key: Optional[str] = None
    base_url: Optional[str] = None


class DefaultsSettingsDTO(BaseModel):
    concurrency: Optional[int] = None
    deepen_cap: Optional[int] = None
    skip_score_threshold: Optional[float] = None
    worker_prompt_version: Optional[str] = None
    engine: Optional[str] = None


class UiSettingsDTO(BaseModel):
    theme: Optional[str] = None
    accentHue: Optional[int] = None
    accent2Hue: Optional[int] = None
    bgHue: Optional[int] = None
    glow: Optional[float] = None
    uiScale: Optional[float] = None
    motion: Optional[str] = None
    wallpaperKind: Optional[str] = None
    wallpaperUrl: Optional[str] = None
    wallpaperFit: Optional[str] = None
    wallpaperDim: Optional[float] = None
    saved: Optional[bool] = None


class AuthSettingsDTO(BaseModel):
    """访问令牌设置。空串=清除该令牌；脱敏占位=保持不变。"""
    full_token: Optional[str] = None
    read_token: Optional[str] = None
    observer_token: Optional[str] = None


class SettingsUpdateRequest(BaseModel):
    llm: Optional[LLMSettingsDTO] = None
    fofa: Optional[FofaSettingsDTO] = None
    engines: Optional[dict[str, EngineSettingsDTO]] = None   # 按引擎名索引
    defaults: Optional[DefaultsSettingsDTO] = None
    ui: Optional[UiSettingsDTO] = None
    auth: Optional[AuthSettingsDTO] = None
