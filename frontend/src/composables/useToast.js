import { readonly, ref } from "vue";

const _toast = ref(null);
let _seq = 0;
let _timer = null;

/**
 * 全局非阻塞通知总线：统一替代阻塞式 window.alert()。
 * type 支持 info / ok / warn / danger。
 */
export function showToast(message, type = "info", ms = 3000) {
  const msg = String(message || "").trim();
  if (!msg) return;
  const id = ++_seq;
  _toast.value = { id, message: msg, type: type || "info" };
  clearTimeout(_timer);
  if (ms > 0) {
    _timer = setTimeout(() => {
      if (_toast.value?.id === id) _toast.value = null;
    }, ms);
  }
}

export function dismissToast() {
  clearTimeout(_timer);
  _toast.value = null;
}

export function useToast() {
  return {
    toastState: readonly(_toast),
    showToast,
    dismissToast,
  };
}
