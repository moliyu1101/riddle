import { cpSync, existsSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, "out");
const distDir = resolve(here, "..", "web", "dist");

if (!existsSync(outDir)) {
  console.error(`[sync-dist] missing static export dir: ${outDir}`);
  process.exit(1);
}

rmSync(distDir, { recursive: true, force: true });
mkdirSync(distDir, { recursive: true });
cpSync(outDir, distDir, { recursive: true });
console.log(`[sync-dist] synced ${outDir} -> ${distDir}`);
