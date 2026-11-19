"use client";

import { useEffect } from "react";
import { useRouter } from "next/navigation";

// 根路由跳转到主工作台。注意：不能用服务端 redirect()——`next build` 静态导出
// （NEXT_EXPORT=1）不支持它，redirect 会被丢弃、根路由被导出成 not-found 页
// （v0.3.87 及之前的实际行为：打开 http://host:8787/ 直接 404）。客户端跳转
// 在 SSG 下正常导出，hydrate 后立即 replace，不产生历史记录。
export default function Home() {
  const router = useRouter();
  useEffect(() => {
    router.replace("/function/tasks");
  }, [router]);
  return (
    <div className="flex h-dvh items-center justify-center text-muted-foreground">
      正在进入工作台…
    </div>
  );
}
