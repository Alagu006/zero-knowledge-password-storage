/**
 * Global Express error handler.
 *
 * Operational errors (AppError subclasses) are returned to the client with
 * their status code and message. Programming errors (anything else) return
 * a generic 500 with no details.
 *
 * CRITICAL: This handler MUST NOT log request bodies — they may contain
 * passwords, keys, or vault content. Only the error message and path are
 * logged.
 */

import type { Request, Response, NextFunction } from "express";
import { AppError } from "../utils/errors.js";
import { LockedError } from "../utils/errors.js";

export function errorHandler(
  err: Error,
  req: Request,
  res: Response,
  _next: NextFunction,
): void {
  // Never log request bodies (may contain secrets).
  console.error(
    `[${new Date().toISOString()}] ${req.method} ${req.path} — ${err.message}`,
  );

  if (err instanceof LockedError) {
    res.setHeader("Retry-After", String(err.retryAfterSeconds));
    res.status(err.statusCode).json({ error: err.message });
    return;
  }

  if (err instanceof AppError) {
    res.status(err.statusCode).json({ error: err.message });
    return;
  }

  // Zod validation errors — return a clean 400.
  if (err.name === "ZodError") {
    res.status(400).json({ error: "Invalid input" });
    return;
  }

  // Unknown error — never leak stack traces or internals.
  res.status(500).json({ error: "Internal server error" });
}
