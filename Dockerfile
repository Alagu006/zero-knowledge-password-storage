```dockerfile
# =============================================================================
# Multi-stage Dockerfile for ZKM server
#
# Stage 1: Install dependencies + generate Prisma client
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

# Install OpenSSL 3 so Prisma generates the correct Debian engine
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

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

COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./
COPY . .

RUN npx tsc -p tsconfig.server.json
RUN npx vite build

# ── Stage 3: Production ─────────────────────────────────────────────────────
FROM node:22-slim AS production

# Install runtime dependencies
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

# Copy application files
COPY --from=deps /app/node_modules ./node_modules
COPY --from=deps /app/package.json ./
COPY --from=build /app/dist ./dist
COPY prisma ./prisma/
COPY migrations ./migrations/

# Remove unnecessary files
RUN rm -rf /app/node_modules/.cache \
           /app/node_modules/.package-lock.json && \
    find /app/node_modules \
        \( -name "*.md" -o -name "LICENSE*" -o -name "CHANGELOG*" \) \
        -delete 2>/dev/null || true

# Give application user ownership
RUN chown -R zkm:zkm /app

USER zkm

EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s \
            --timeout=5s \
            --start-period=10s \
            --retries=3 \
    CMD wget --no-verbose \
            --tries=1 \
            --spider \
            http://localhost:3000/health || exit 1

ENTRYPOINT ["/usr/bin/tini", "--"]

# Apply Prisma migrations before starting the server.
# This creates/updates the tables in the Neon PostgreSQL database.
CMD ["sh", "-c", "npx prisma migrate deploy && node dist/server/index.js"]
```
