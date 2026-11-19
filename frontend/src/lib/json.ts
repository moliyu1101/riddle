// structuredClone 要 Chrome 98 / Safari 15.4；旧 WebView（部分微信 X5 内核、
// 老 Android WebView）里不存在，直接调用会抛 ReferenceError 把整页带崩。
// 这些场景深拷贝的都是纯 JSON 结构，用 JSON 往返是等价且安全的降级。
export function cloneJson<T>(value: T): T {
  if (typeof structuredClone === "function") return structuredClone(value);
  return JSON.parse(JSON.stringify(value)) as T;
}
