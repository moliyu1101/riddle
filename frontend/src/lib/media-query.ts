// MediaQueryList 的兼容监听。
//
// addEventListener 要 Safari 14 / Chrome 84 起才支持。国产手机上常见的微信/QQ
// 内置浏览器（X5 内核）与较老的 Android WebView 仍可能是 Chrome 77 一代，那里
// 只有 addListener/removeListener。直接调 addEventListener 会抛 TypeError ——
// 在 useEffect 里抛出就足以让整页变成
// "Application error: a client-side exception has occurred"
// （症状：手机打开页面就报错，电脑正常）。
export function listenMedia(mql: MediaQueryList, fn: () => void): () => void {
  const modern = mql as unknown as { addEventListener?: unknown; removeEventListener?: unknown };
  if (typeof modern.addEventListener === "function") {
    mql.addEventListener("change", fn);
    return () => mql.removeEventListener("change", fn);
  }
  const legacy = mql as unknown as {
    addListener?: (cb: () => void) => void;
    removeListener?: (cb: () => void) => void;
  };
  legacy.addListener?.(fn);
  return () => legacy.removeListener?.(fn);
}

// matchesMedia 是 matchMedia 的安全包装：环境没有 matchMedia 时返回 false，
// 而不是抛错。
export function matchesMedia(query: string): boolean {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return false;
  return window.matchMedia(query).matches;
}
