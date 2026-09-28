// 全平台默认 LLM 端点（默认供应商 DeepSeek）：与后端 app/config.py 的
// DEFAULT_LLM_BASE_URL / DEFAULT_LLM_MODEL 保持一致（跨语言无法共享常量，改动时两边同步）。
export const DEFAULT_LLM_BASE_URL = "https://api.deepseek.com/v1";
export const DEFAULT_LLM_MODEL = "deepseek-chat";
