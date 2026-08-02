/**
 * Vitest configuration for integration tests.
 *
 * These tests exercise the REAL Express server (via supertest) against the
 * REAL PostgreSQL test database (zkm_test). They are run explicitly with:
 *   npm run test:integration
 *
 * They are excluded from the default `npm test` run (which only executes pure
 * unit tests) via the INTEGRATION_TESTS gate in the test file itself.
 */

import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: [
      "src/server/__tests__/integration.test.ts",
      "src/server/__tests__/security.test.ts",
    ],
    env: {
      // Enables the describe blocks gated behind this flag.
      INTEGRATION_TESTS: "1",
    },
    // Integration tests make real DB connections; give them a generous budget.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    sequence: {
      concurrent: false,
    },
    // All integration files share the same zkm_test database and truncate it
    // in beforeEach — they MUST run one file at a time.
    fileParallelism: false,
  },
});
