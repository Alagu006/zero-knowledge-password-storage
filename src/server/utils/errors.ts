/**
 * Application-level error classes.
 *
 * Operational errors (4xx) are safe to return to clients.
 * Programming errors (5xx) should not leak internals.
 */

export class AppError extends Error {
  public readonly statusCode: number;
  public readonly isOperational: boolean;

  constructor(statusCode: number, message: string, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** 400 — malformed input, validation failure. */
export class BadRequestError extends AppError {
  constructor(message = "Bad request") {
    super(400, message);
  }
}

/**
 * 401 — generic auth failure.
 * Message is intentionally vague to prevent user enumeration:
 * always "Invalid credentials" regardless of whether the email exists.
 */
export class UnauthorizedError extends AppError {
  constructor(message = "Invalid credentials") {
    super(401, message);
  }
}

/** 403 — authenticated but not authorized for this resource. */
export class ForbiddenError extends AppError {
  constructor(message = "Forbidden") {
    super(403, message);
  }
}

/** 404 — resource not found. */
export class NotFoundError extends AppError {
  constructor(message = "Not found") {
    super(404, message);
  }
}

/** 409 — duplicate resource (e.g. email already registered). */
export class ConflictError extends AppError {
  constructor(message = "Conflict") {
    super(409, message);
  }
}

/**
 * 423 — account locked due to too many failed auth attempts.
 * Returns the same generic "Invalid credentials" to an outside observer,
 * but the handler can add a Retry-After header.
 */
export class LockedError extends AppError {
  constructor(
    message = "Invalid credentials",
    public readonly retryAfterSeconds: number = 900,
  ) {
    super(421, message);
  }
}

/** 429 — IP-level rate limit exceeded. */
export class TooManyRequestsError extends AppError {
  constructor(message = "Too many requests") {
    super(429, message);
  }
}

/** 500 — catch-all for programming errors. Never return details to client. */
export class InternalError extends AppError {
  constructor(message = "Internal server error") {
    super(500, message, false);
  }
}
