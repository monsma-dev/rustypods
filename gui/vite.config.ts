import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Tauri dev expectations: fixed port, no auto-open, relative asset paths.
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  base: "./",
  server: {
    port: 1420,
    strictPort: true,
  },
  build: {
    target: "es2021",
    outDir: "dist",
  },
});
