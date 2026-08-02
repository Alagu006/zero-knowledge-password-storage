# =============================================================================
# Multi-stage Dockerfile for ZKM server
#
# Stage 1: Install dependencies (cached layer)
# Stage 2: Build TypeScript
# Stage 3: Production image (minimal, non-root)
#
# Build:
#   docker build -t zkm-server .
#
# Run:
#   docker run -p 3000:3000 --env-file .env zkm-server
# =============================================================================

# ── Stage 1: Dependencies ────────────────────────────────────────────────────
FROM node:22-alpine AS deps

WORKDIR /app

# Copy only package files first (Docker layer cache optimization)
COPY package.json package-lock.json* ./
COPY prisma ./prisma/

# Install production + dev dependencies (need prisma generate)
RUN npm ci

# Generate Prisma client
RUN npx prisma generate

# ── Stage 2: Build ──────────────────────────────────────────────────────────
FROM node:22-alpine AS build

WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./
COPY . .

# Build TypeScript
RUN npx tsc -p tsconfig.server.json

# Build client (Vite)
RUN npx vite build

# ── Stage 3: Production ─────────────────────────────────────────────────────
FROM node:22-alpine AS production

# Security: add tini for proper PID 1 signal handling
RUN apk add --no-cache tini

# Security: run as non-root user
RUN addgroup -g 1001 -S zkm && \
    adduser -S zkm -u 1001 -G zkm

WORKDIR /app

# Copy only what's needed for runtime
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./
COPY --from=build /app/dist ./dist
COPY prisma ./prisma/
COPY migrations ./migrations/

# Security: remove dev dependencies, build tools, and unnecessary files
RUN rm -rf /app/node_modules/.cache /app/node_modules/.package-lock.json && \
    find /app/node_modules -name "*.md" -o -name "LICENSE*" -o -name "CHANGELOG*" | xargs rm -f 2>/dev/null || true

# Set ownership to non-root user
RUN chown -R zkm:zkm /app

USER zkm

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/health || exit 1

# Use tini as entrypoint for proper signal handling
ENTRYPOINT ["/sbin/tini", "--"]

CMD ["node", "dist/server/index.js"]
