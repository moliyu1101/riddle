import { ref, watch, onMounted } from "vue";

/** 数字滚动：监听目标值变化，平滑滚动到新值，返回动画中的显示值 */
export function useCountUp(target, duration = 650) {
  const display = ref(0);
  let raf = null;

  function animate() {
    const to = Number(target.value) || 0;
    const from = display.value;
    if (from === to) return;
    const start = performance.now();
    cancelAnimationFrame(raf);
    raf = requestAnimationFrame(function tick(now) {
      const p = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      display.value = Math.round(from + (to - from) * eased);
      if (p < 1) raf = requestAnimationFrame(tick);
    });
  }

  watch(target, animate, { immediate: false });
  onMounted(animate);
  return display;
}
