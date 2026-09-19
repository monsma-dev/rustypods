import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import tailwindcss from "@tailwindcss/vite";

// Tauri dev expectations: fixed port, no auto-open, relative asset paths.
// All-Rust toolchain under the hood: SWC for TS/JSX, LightningCSS for CSS.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  base: "./",
  server: {
    port: 1420,
    strictPort: true,
  },
  css: {
    transformer: "lightningcss",
  },
  build: {
    target: "es2021",
    outDir: "dist",
    cssMinify: "lightningcss",
  },
});
