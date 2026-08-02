import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  root: ".",
  publicDir: "public",
  server: {
    port: 5173,
    proxy: {
      "/auth": "http://localhost:3000",
      "/vault/entries": "http://localhost:3000",
    },
  },
  build: {
    outDir: "dist/ui",
    sourcemap: false,
  },
  test: {
    include: ["src/**/*.test.ts"],
  },
});
