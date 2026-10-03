# =============================================================================
# Multi-stage Dockerfile for ZKM server
#
# Stage 1: Install dependencies
# Stage 2: Build TypeScript + Vite client
# Stage 3: Production image
#
# Build:
#   docker build -t zkm-server .
#
# Run:
#   docker run -p 3000:3000 --env-file .env zkm-server
# =============================================================================


# ── Stage 1: Dependencies ────────────────────────────────────────────────────
FROM node:22-slim AS deps

WORKDIR /app

# Copy package files first for better Docker layer caching
COPY package.json package-lock.json* ./

# Prisma schema is needed for prisma generate
COPY prisma ./prisma/

# Install dependencies
RUN npm ci

# Generate Prisma client
RUN npx prisma generate


# ── Stage 2: Build ───────────────────────────────────────────────────────────
FROM node:22-slim AS build

WORKDIR /app

# Reuse installed dependencies and generated Prisma client
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./

# Copy application source
COPY . .

# Build TypeScript server
RUN npx tsc -p tsconfig.server.json

# Build Vite client
RUN npx vite build


# ── Stage 3: Production ─────────────────────────────────────────────────────
FROM node:22-slim AS production

# Install:
# - tini: proper PID 1 / signal handling
# - openssl: required by Prisma
# - wget: required by the Docker health check
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tini \
        openssl \
        wget && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1001 zkm && \
    useradd --uid 1001 --gid 1001 --create-home zkm

WORKDIR /app

# Copy production dependencies
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./

# Copy compiled application
COPY --from=build /app/dist ./dist

# Copy Prisma schema and migrations
COPY prisma ./prisma/
COPY migrations ./migrations/

# Remove unnecessary cache/documentation files
RUN rm -rf /app/node_modules/.cache \
           /app/node_modules/.package-lock.json && \
    find /app/node_modules \
        \( -name "*.md" -o -name "LICENSE*" -o -name "CHANGELOG*" \) \
        -delete 2>/dev/null || true

# Give application user ownership
RUN chown -R zkm:zkm /app

# Run as non-root
USER zkm

# Application port
EXPOSE 3000

# Docker health check
HEALTHCHECK --interval=30s \
            --timeout=5s \
            --start-period=10s \
            --retries=3 \
    CMD wget --no-verbose \
            --tries=1 \
            --spider \
            http://localhost:3000/health || exit 1

# Use tini as PID 1
ENTRYPOINT ["/usr/bin/tini", "--"]

# Start application
CMD ["node", "dist/server/index.js"]
