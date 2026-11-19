import type { Metadata } from "next";
import type { ReactNode } from "react";

// 认证页（登录/初始化）是公网上唯一无需密码即可见的界面：文档标题与可见
// 文案一律使用中性身份，不带产品名——部署身份的防指纹从这一层开始。
export const metadata: Metadata = {
  title: "Console",
  description: "Sign in",
};

export default function AuthLayout({ children }: { readonly children: ReactNode }) {
  return <>{children}</>;
}
