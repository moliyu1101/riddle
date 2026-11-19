import * as React from "react";

import { listenMedia } from "@/lib/media-query";

const LG_BREAKPOINT = 1024;

export function useIsLg() {
  const [isLg, setIsLg] = React.useState<boolean | undefined>(undefined);

  React.useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mql = window.matchMedia(`(min-width: ${LG_BREAKPOINT}px)`);
    const onChange = () => setIsLg(window.innerWidth >= LG_BREAKPOINT);
    onChange();
    return listenMedia(mql, onChange);
  }, []);

  return !!isLg;
}
