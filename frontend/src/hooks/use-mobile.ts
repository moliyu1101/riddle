import * as React from "react";

import { listenMedia } from "@/lib/media-query";

const MOBILE_BREAKPOINT = 768;

export function useIsMobile() {
  // 初始保持 undefined（渲染为 false），由 effect 按真实视口纠正：静态导出的
  // 首帧 HTML 是在没有 window 的环境里生成的，这里若直接读 innerWidth 会造成
  // hydration 不一致。
  const [isMobile, setIsMobile] = React.useState<boolean | undefined>(undefined);

  React.useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mql = window.matchMedia(`(max-width: ${MOBILE_BREAKPOINT - 1}px)`);
    const onChange = () => setIsMobile(window.innerWidth < MOBILE_BREAKPOINT);
    onChange();
    return listenMedia(mql, onChange);
  }, []);

  return !!isMobile;
}
