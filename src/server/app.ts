/**
 * Express application setup.
 *
 * SECURITY LAYER ORDER (matters):
 *   1. Helmet — sets security headers (HSTS, CSP, X-Frame-Options, etc.)
 *   2. CORS — restricts origin
 *   3. Body parsing — with size limit to prevent memory exhaustion
 *   4. Rate limiting — on auth endpoints
 *   5. Routes — business logic
 *   6. Error handler — catch-all, always last
 *
 * TLS enforcement:
 *   In production (NODE_ENV=production), the server REJECTS plaintext HTTP.
 *   It is expected to run behind a TLS-terminating reverse proxy (nginx,
 *   AWS ALB, Cloudflare, etc.) that sets X-Forwarded-Proto: https.
 *   The HSTS header (max-age=31536000; includeSubDomains; preload)
 *   tells browsers to never use HTTP again for this domain.
 */

// MUST be imported before any Router is created. Express 4 does NOT forward
// rejections from async route handlers / middleware to the error middleware —
// an async `throw` becomes an unhandledRejection (which terminates the process
// on Node 15+ and hangs the request otherwise). This side-effect import patches
// Express to route async rejections into the errorHandler below. Every route
// handler in this app is async, so without this patch ALL error paths (401,
// 409, 400, 429, …) are broken.
import "express-async-errors";
import express from "express";
import helmet from "helmet";
import cors from "cors";
import { config } from "./config.js";
import authRoutes from "./routes/auth.js";
import vaultRoutes from "./routes/vault.js";
import { errorHandler } from "./middleware/errorHandler.js";

export function createApp() {
  const app = express();

  // ── 1. Security headers (Helmet) ──────────────────────────────────────
  // Helmet sets: Strict-Transport-Security, X-Content-Type-Options,
  // X-Frame-Options, X-XSS-Protection, Referrer-Policy, etc.
  //
  // CSP policy — strict, no inline scripts, no eval:
  //   - default-src 'self': only load resources from same origin
  //   - script-src 'self': no inline scripts (blocks XSS vectors)
  //   - style-src 'self' 'unsafe-inline': allow styles (needed for some CSS-in-JS)
  //   - connect-src 'self': only allow fetch/XHR to same origin
  //   - img-src 'self' data: allow images (for UI icons)
  //   - object-src 'none': no plugins (Flash, Java, etc.)
  //   - base-uri 'self': prevent base tag injection
  //   - form-action 'self': prevent form hijacking
  //   - frame-ancestors 'none': prevent clickjacking
  // In production, also add upgrade-insecure-requests to force HTTPS.
  // In development, omit it so local HTTP dev servers work without TLS.
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
      // Explicitly enable these (Helmet defaults, but declared for audit):
      noSniff: true,                     // X-Content-Type-Options: nosniff
      frameguard: { action: "deny" },    // X-Frame-Options: DENY (redundant with frame-ancestors CSP)
      referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    }),
  );

  // ── 1b. Additional security headers (not set by Helmet) ────────────────
  // Permissions-Policy: restrict browser features this app doesn't use.
  // Prevents embedding, camera, microphone, geolocation, etc.
  app.use((_req, res, next) => {
    res.setHeader(
      "Permissions-Policy",
      "camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
    );
    next();
  });

  // ── 2. CORS ───────────────────────────────────────────────────────────
  app.use(
    cors({
      origin: config.corsOrigins,
      methods: ["GET", "POST", "PUT", "DELETE"],
      allowedHeaders: ["Content-Type", "Authorization"],
      credentials: true,
      maxAge: 86400, // preflight cache: 24 hours
    }),
  );

  // ── 3. Body parsing with size limit ───────────────────────────────────
  // 100 KB limit — vault entries are small encrypted blobs. A 1 MB request
  // body is almost certainly an attack. This prevents memory-exhaustion
  // DoS via large payloads.
  app.use(express.json({ limit: "100kb" }));

  // ── 4. TLS enforcement (production only) ──────────────────────────────
  // If running behind a reverse proxy, X-Forwarded-Proto is set by the proxy.
  // Reject any request that arrived over plain HTTP.
  if (config.nodeEnv === "production") {
    app.use((req, res, next) => {
      const proto = req.headers["x-forwarded-proto"];
      if (proto && proto !== "https") {
        res
          .status(301)
          .setHeader("Location", `https://${req.headers.host}${req.url}`)
          .end();
        return;
      }
      // If no X-Forwarded-Proto (direct connection), reject.
      if (!proto && req.protocol !== "https") {
        res
          .status(301)
          .setHeader("Location", `https://${req.headers.host}${req.url}`)
          .end();
        return;
      }
      next();
    });
  }

  // ── 5. Health check (unauthenticated) ─────────────────────────────────
  app.get("/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  // ── 6. API routes ─────────────────────────────────────────────────────
  app.use("/auth", authRoutes);
  app.use("/vault", vaultRoutes);

  // ── 7. 404 for unknown routes ─────────────────────────────────────────
  app.use((_req, res) => {
    res.status(404).json({ error: "Not found" });
  });

  // ── 8. Global error handler (must be last) ────────────────────────────
  app.use(errorHandler);

  return app;
}
