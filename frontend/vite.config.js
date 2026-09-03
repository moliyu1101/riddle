import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [vue()],
  // 构建产物输出到后端托管目录
  build: {
    outDir: "../web/dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": { target: "http://localhost:8000", changeOrigin: true, ws: true },
      // 真实浏览器截图静态目录（后端 /workfiles 挂载工作目录根）
      "/workfiles": { target: "http://localhost:8000", changeOrigin: true },
    },
  },
});
