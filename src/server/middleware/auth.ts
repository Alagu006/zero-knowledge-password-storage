/**
 * JWT authentication middleware.
 *
 * The JWT payload contains ONLY non-secret identifiers:
 *   { userId: string, email: string }
 *
 * NO key material, NO vault data, NO derived secrets are placed in the token.
 * The token is signed with HMAC-SHA256 (HS256) using a server-side secret
 * that is never transmitted.
 *
 * Token lifetime is short (default 15 min). Refresh is handled by issuing
 * a new token on each successful authenticated request (sliding window).
 *
 * KEY ROTATION:
 *   New tokens are always signed with config.jwtSecret (current key).
 *   Verification tries the current key first, then falls back to
 *   config.jwtSecretPrev (previous key) if set. This allows zero-downtime
 *   key rotation: set JWT_SECRET_PREV = old key, JWT_SECRET = new key,
 *   deploy, then clear JWT_SECRET_PREV after old tokens expire.
 */

import type { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { createHash } from "node:crypto";
import { config } from "../config.js";
import { prisma } from "../db.js";
import { UnauthorizedError } from "../utils/errors.js";

/** Shape of the JWT payload — non-secret identifiers only. */
export interface AuthPayload {
  userId: string;
  email: string;
}

// Extend Express Request to carry the authenticated user.
declare global {
  namespace Express {
    interface Request {
      user?: AuthPayload;
    }
  }
}

/**
 * Verify a JWT token against the current signing key, falling back to the
 * previous key during rotation. Returns the decoded payload.
 */
function verifyTokenWithRotation(token: string): AuthPayload {
  // Try current key first (most tokens will use this)
  try {
    const payload = jwt.verify(token, config.jwtSecret, {
      algorithms: ["HS256"],
    }) as AuthPayload;
    return payload;
  } catch {
    // If there's no previous key, or the current key worked (re-throw),
    // or neither key worked — fall through to prev key check.
    if (!config.jwtSecretPrev) {
      throw new UnauthorizedError("Invalid or expired token");
    }
  }

  // Try previous key (tokens signed before rotation)
  try {
    const payload = jwt.verify(token, config.jwtSecretPrev, {
      algorithms: ["HS256"],
    }) as AuthPayload;
    return payload;
  } catch {
    throw new UnauthorizedError("Invalid or expired token");
  }
}

/**
 * Middleware: require a valid Bearer token in the Authorization header.
 * Attaches the decoded payload to `req.user`.
 */
export async function requireAuth(
  req: Request,
  _res: Response,
  next: NextFunction,
): Promise<void> {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    throw new UnauthorizedError("Missing or invalid authorization header");
  }

  const token = header.slice(7);

  try {
    const payload = verifyTokenWithRotation(token);

    // Minimal sanity check: payload must have the expected shape.
    if (
      typeof payload.userId !== "string" ||
      typeof payload.email !== "string"
    ) {
      throw new UnauthorizedError("Malformed token payload");
    }

    // Verify session has not been revoked (e.g., after password change or logout).
    // Hash the JWT and check for a matching active session record.
    const tokenHash = createHash("sha256").update(token).digest();
    const session = await prisma.authSession.findFirst({
      where: { tokenHash },
      select: { expiresAt: true },
    });

    // Reject if no session record or session has expired.
    if (!session || session.expiresAt <= new Date()) {
      throw new UnauthorizedError("Session expired or revoked");
    }

    req.user = payload;
    next();
  } catch (err) {
    if (err instanceof UnauthorizedError) throw err;
    throw new UnauthorizedError("Invalid or expired token");
  }
}

/**
 * Helper: sign a new JWT for the given user.
 * Called after successful authentication.
 */
export function signToken(payload: AuthPayload): string {
  // Cast the string duration ("15m") to satisfy the `StringValue` branded
  // type from the `ms` package. The runtime validates the format.
  return jwt.sign(
    payload,
    config.jwtSecret,
    { algorithm: "HS256", expiresIn: config.jwtExpiresIn } as jwt.SignOptions,
  );
}

/**
 * Helper: sign a short-lived temporary token for the 2FA step.
 *
 * The temp token is issued after successful password verification when
 * 2FA is enabled. It has a very short lifetime (5 min) and a different
 * signing secret than the main JWT. It carries only { userId, email, step: "2fa" }.
 *
 * This prevents a stolen temp token from being used as a full session token
 * (different secret, shorter expiry, limited scope).
 */
export function signTempToken(payload: AuthPayload): string {
  return jwt.sign(
    { ...payload, step: "2fa" },
    config.tempTokenSecret,
    { algorithm: "HS256", expiresIn: config.tempTokenExpiresIn } as jwt.SignOptions,
  );
}

/**
 * Middleware: require a valid temporary token (2FA step).
 * Similar to requireAuth but uses the temp token secret.
 */
export function requireTempToken(
  req: Request,
  _res: Response,
  next: NextFunction,
): void {
  const header = req.headers.authorization;
  if (!header?.startsWith("Bearer ")) {
    throw new UnauthorizedError("Missing or invalid authorization header");
  }

  const token = header.slice(7);

  try {
    const payload = jwt.verify(token, config.tempTokenSecret, {
      algorithms: ["HS256"],
    }) as AuthPayload & { step: string };

    if (payload.step !== "2fa") {
      throw new UnauthorizedError("Invalid token scope");
    }

    if (
      typeof payload.userId !== "string" ||
      typeof payload.email !== "string"
    ) {
      throw new UnauthorizedError("Malformed token payload");
    }

    req.user = { userId: payload.userId, email: payload.email };
    next();
  } catch (err) {
    if (err instanceof UnauthorizedError) throw err;
    throw new UnauthorizedError("Invalid or expired token");
  }
}
