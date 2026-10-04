/**
 * Server entry point.
 *
 * Starts the Express server and connects to PostgreSQL via Prisma.
 * Graceful shutdown on SIGTERM/SIGINT: close Prisma connection, then exit.
 */

import { createApp } from "./app.js";
import { config } from "./config.js";
import { prisma } from "./db.js";
import { runMigrations } from "./migrate.js";

async function main() {
  // Verify database connectivity before accepting traffic.
  await prisma.$connect();
  console.log("[zkm] Connected to PostgreSQL via Prisma");

  // Ensure all database tables and schema migrations are applied.
  await runMigrations();

  const app = createApp();

  const server = app.listen(config.port, () => {
    console.log(
      `[zkm] Server listening on port ${config.port} (env: ${config.nodeEnv})`,
    );
  });

  // ── Graceful shutdown ────────────────────────────────────────────────
  async function shutdown(signal: string) {
    console.log(`\n[zkm] ${signal} received — shutting down gracefully…`);
    server.close(async () => {
      await prisma.$disconnect();
      console.log("[zkm] Disconnected from database. Goodbye.");
      process.exit(0);
    });

    // Force exit after 10s if graceful shutdown stalls.
    setTimeout(() => {
      console.error("[zkm] Forced exit after timeout.");
      process.exit(1);
    }, 10_000).unref();
  }

  process.on("SIGTERM", () => shutdown("SIGTERM"));
  process.on("SIGINT", () => shutdown("SIGINT"));
}

main().catch((err) => {
  console.error("[zkm] Fatal startup error:", err);
  process.exit(1);
});
