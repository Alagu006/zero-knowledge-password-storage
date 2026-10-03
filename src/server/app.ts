/**
 * Express application setup.
 *
 * SECURITY LAYER ORDER:
 *   1. Helmet — security headers
 *   2. CORS — restricts origins
 *   3. Body parsing — request size limit
 *   4. TLS enforcement
 *   5. Health check
 *   6. API routes
 *   7. Frontend static files
 *   8. 404 handler
 *   9. Global error handler
 */

import "express-async-errors";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./config.js";
import authRoutes from "./routes/auth.js";
import vaultRoutes from "./routes/vault.js";
import { errorHandler } from "./middleware/errorHandler.js";

export function createApp() {
  const app = express();

  // ── 1. Security headers ──────────────────────────────────────────────

  const baseDirectives = {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    styleSrc: ["'self'", "'unsafe-inline'"],
    connectSrc: ["'self'"],
    imgSrc: ["'self'", "data:"],
    fontSrc: ["'self'"],
    objectSrc: ["'none'"],
    baseUri: ["'self'"],
    formAction: ["'self'"],
    frameAncestors: ["'none'"],
    workerSrc: ["'none'"],
  } as const;

  const cspDirectives =
    config.nodeEnv === "production"
      ? { ...baseDirectives, upgradeInsecureRequests: [] }
      : baseDirectives;

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: cspDirectives,
      },
      hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
      },
      noSniff: true,
      frameguard: { action: "deny" },
      referrerPolicy: {
        policy: "strict-origin-when-cross-origin",
      },
    }),
  );

  // ── 1b. Additional security headers ─────────────────────────────────

  app.use((_req, res, next) => {
    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
    );
    next();
  });

  // ── 2. CORS ──────────────────────────────────────────────────────────

  app.use(
    cors({
      origin: config.corsOrigins,
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,
      maxAge: 86400,
    }),
  );

  // ── 3. Body parsing ─────────────────────────────────────────────────

  app.use(express.json({ limit: "100kb" }));

  // ── 4. TLS enforcement ───────────────────────────────────────────────

  if (config.nodeEnv === "production") {
    app.use((req, res, next) => {
      const proto = req.headers["x-forwarded-proto"];

      if (proto && proto !== "https") {
        res
          .status(301)
          .setHeader(
            "Location",
            `https://${req.headers.host}${req.url}`,
          )
          .end();
        return;
      }

      if (!proto && req.protocol !== "https") {
        res
          .status(301)
          .setHeader(
            "Location",
            `https://${req.headers.host}${req.url}`,
          )
          .end();
        return;
      }

      next();
    });
  }

  // ── 5. Health check ──────────────────────────────────────────────────

  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // ── 6. API routes ────────────────────────────────────────────────────

  app.use("/auth", authRoutes);
  app.use("/vault", vaultRoutes);

  // ── 7. Frontend ──────────────────────────────────────────────────────
  //
  // Vite outputs the frontend to:
  //
  //   dist/ui/index.html
  //
  // After TypeScript compilation this file is:
  //
  //   dist/server/app.js
  //
  // Therefore "../ui" resolves to:
  //
  //   dist/ui

  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const frontendPath = path.resolve(__dirname, "../ui");

  // Serve static frontend files.
  app.use(express.static(frontendPath));

  // SPA fallback.
  //
  // This allows frontend routes such as /login, /register, etc.
  // to load index.html instead of returning a server 404.
  app.use((req, res, next) => {
    if (req.method !== "GET") {
      next();
      return;
    }

    // Don't turn unknown API routes into frontend pages.
    if (
      req.path === "/health" ||
      req.path.startsWith("/auth/") ||
      req.path.startsWith("/vault/")
    ) {
      next();
      return;
    }

    res.sendFile(path.join(frontendPath, "index.html"), (err) => {
      if (err) {
        next(err);
      }
    });
  });

  // ── 8. 404 for unknown routes ────────────────────────────────────────

  app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  // ── 9. Global error handler ─────────────────────────────────────────

  app.use(errorHandler);

  return app;
}
