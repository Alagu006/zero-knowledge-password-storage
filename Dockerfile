# =============================================================================
# Multi-stage Dockerfile for ZKM server
# =============================================================================

# ── Stage 1: Dependencies ────────────────────────────────────────────────────
FROM node:22-slim AS deps

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl && \
    rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json* ./
COPY prisma ./prisma/

RUN npm ci

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

# Install runtime dependencies:
# - tini: proper signal handling
# - openssl: Prisma runtime
# - wget: health check
# - postgresql-client: psql for SQL migrations
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tini \
        openssl \
        wget \
        postgresql-client && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd --gid 1001 zkm && \
    useradd --uid 1001 --gid 1001 --create-home zkm

WORKDIR /app

# Application files
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

# Run the project's SQL migrations, then start the server.
#
# The SQL files are intentionally executed in order:
#   001_init.sql
#   002_password_change_recovery.sql
#   003_2fa.sql
#   004_kdf_version.sql
#   005_sessions.sql
#
# ON_ERROR_STOP=1 makes PostgreSQL stop immediately if a migration fails.
CMD ["sh", "-c", "psql \"$DATABASE_URL\" -v ON_ERROR_STOP=1 -f migrations/SQL/001_init.sql && psql \"$DATABASE_URL\" -v ON_ERROR_STOP=1 -f migrations/SQL/002_password_change_recovery.sql && psql \"$DATABASE_URL\" -v ON_ERROR_STOP=1 -f migrations/SQL/003_2fa.sql && psql \"$DATABASE_URL\" -v ON_ERROR_STOP=1 -f migrations/SQL/004_kdf_version.sql && psql \"$DATABASE_URL\" -v ON_ERROR_STOP=1 -f migrations/SQL/005_sessions.sql && node dist/server/index.js"]
