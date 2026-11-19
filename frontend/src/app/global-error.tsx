"use client";

import * as React from "react";

// 根错误边界：layout / 全局 provider 这一层抛出时，app/error.tsx 兜不住，
// 必须由 global-error.tsx 接住（它要自带 <html>/<body>）。
// 这里刻意只用内联样式：走到这一步时样式系统本身可能就是坏的。
type ErrorProps = {
  error: Error & { digest?: string };
  reset: () => void;
};

export default function GlobalError({ error, reset }: ErrorProps) {
  React.useEffect(() => {
    console.error("[riddle] 应用级错误:", error);
  }, [error]);

  const text = [error?.name, error?.message].filter(Boolean).join(": ") || String(error);
  return (
    <html lang="zh-CN">
      <body
        style={{
          margin: 0,
          minHeight: "100vh",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontFamily: "system-ui, -apple-system, sans-serif",
          background: "#0b0b0c",
          color: "#e5e5e5",
          padding: 24,
        }}
      >
        <div style={{ maxWidth: 720, width: "100%" }}>
          <h1 style={{ fontSize: 18, margin: "0 0 8px" }}>应用启动失败</h1>
          <p style={{ fontSize: 13, color: "#a3a3a3", margin: "0 0 16px" }}>
            页面在初始化时抛了异常。以下信息可用于定位（可直接截图反馈）。
          </p>
          <pre
            style={{
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              fontSize: 12,
              lineHeight: 1.5,
              background: "#171717",
              border: "1px solid #2a2a2a",
              borderRadius: 8,
              padding: 12,
              maxHeight: 260,
              overflow: "auto",
            }}
          >
            {text}
          </pre>
          <button
            type="button"
            onClick={() => reset()}
            style={{
              marginTop: 16,
              padding: "8px 14px",
              borderRadius: 8,
              border: "1px solid #3a3a3a",
              background: "#1f1f1f",
              color: "#e5e5e5",
              cursor: "pointer",
            }}
          >
            重试
          </button>
        </div>
      </body>
    </html>
  );
}
