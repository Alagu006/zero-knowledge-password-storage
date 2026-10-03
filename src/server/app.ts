```ts
/**
 * Express application setup.
 *
 * SECURITY LAYER ORDER (matters):
 *   1. Helmet — sets security headers (HSTS, CSP, X-Frame-Options, etc.)
 *   2. CORS — restricts origin
 *   3. Body parsing — with size limit to prevent memory exhaustion
 *   4. TLS enforcement
 *   5. Health check
 *   6. API routes
 *   7. Frontend static files
 *   8. Error handler
 *
 * TLS enforcement:
 *   In production (NODE_ENV=production), the server expects to run behind
 *   Render's TLS-terminating reverse proxy, which sets X-Forwarded-Proto.
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
  // The Vite build produces:
  //
  //   dist/ui/index.html
  //   dist/ui/assets/...
  //
  // After TypeScript compilation, this file is located at:
  //
  //   dist/server/app.js
  //
  // Therefore "../ui" resolves to:
  //
  //   dist/ui
  //
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = path.dirname(__filename);
  const frontendPath = path.resolve(__dirname, "../ui");

  // Serve Vite-generated static files.
  app.use(express.static(frontendPath));

  // SPA fallback.
  //
  // Using a middleware instead of app.get("*") avoids wildcard-route
  // compatibility issues between Express versions.
  app.use((req, res, next) => {
    // Only handle GET requests that weren't handled by:
    // - /health
    // - /auth/*
    // - /vault/*
    // - static frontend files
    if (req.method !== "GET") {
      next();
      return;
    }

    // API routes should remain JSON 404s.
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
```

Then run:

```bash
git add src/server/app.ts
git commit -m "serve frontend from Express"
git push
```

Render should automatically deploy the new commit.

After it finishes, open:

**https://zero-knowledge-password-storage.onrender.com**

You should now get the **ZKM frontend instead of `{"error":"Not found"}`**.

Also, your `/health` endpoint should continue returning:

```json
{"status":"ok"}
```

The important part is that this version serves the existing `dist/ui` output from your Vite build; it does **not** require changing your Dockerfile again.
