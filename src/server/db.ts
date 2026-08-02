/**
 * Prisma client singleton.
 *
 * In development we attach to globalThis to prevent connection pool exhaustion
 * during hot-reload (each reload would create a new PrismaClient otherwise).
 * In production a single instance is created at startup.
 */

import { PrismaClient } from "@prisma/client";

const globalForPrisma = globalThis as unknown as { __prisma?: PrismaClient };

export const prisma =
  globalForPrisma.__prisma ??
  new PrismaClient({
    log:
      process.env.NODE_ENV === "development"
        ? ["warn", "error"]
        : ["error"],
  });

if (process.env.NODE_ENV !== "production") {
  globalForPrisma.__prisma = prisma;
}
