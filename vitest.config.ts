// vitest.config.ts
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/**/*.test.ts"],
    testTimeout: 20000,   // real Argon2id chains need real time
    hookTimeout: 20000,
  },
});