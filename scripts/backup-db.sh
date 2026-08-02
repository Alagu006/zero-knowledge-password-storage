#!/bin/bash
# =============================================================================
# ZKM Database Backup Script
#
# Usage:
#   ./scripts/backup-db.sh [output_dir]
#
# Creates an encrypted backup of the PostgreSQL database.
# The backup contains ONLY ciphertext/salts/verifiers — no plaintext.
#
# Requirements:
#   - pg_dump (from PostgreSQL client)
#   - gpg (for encryption at rest)
#   - DATABASE_URL environment variable
#
# The backup is encrypted with a symmetric key derived from a passphrase.
# The passphrase should be stored in a secrets manager (Vault, AWS SSM, etc.)
# and passed via BACKUP_PASSPHRASE environment variable.
# =============================================================================

set -euo pipefail

OUTPUT_DIR="${1:-./backups}"
TIMESTAMP=$(date -u +"%Y%m%dT%H%M%SZ")
BACKUP_FILE="${OUTPUT_DIR}/zkm-backup-${TIMESTAMP}.sql.gz.gpg"

# Validate prerequisites
if [ -z "${DATABASE_URL:-}" ]; then
  echo "ERROR: DATABASE_URL not set" >&2
  exit 1
fi

if [ -z "${BACKUP_PASSPHRASE:-}" ]; then
  echo "ERROR: BACKUP_PASSPHRASE not set (use secrets manager)" >&2
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "[backup] Starting database backup at ${TIMESTAMP}"

# 1. Create SQL dump
#    --no-owner: don't include role info (roles are managed separately)
#    --no-privileges: don't include GRANT/REVOKE
#    --clean: include DROP statements for idempotent restore
pg_dump \
  --no-owner \
  --no-privileges \
  --clean \
  --if-exists \
  "${DATABASE_URL}" \
  | gzip \
  | gpg --batch --yes --symmetric \
    --cipher-algo AES256 \
    --passphrase "${BACKUP_PASSPHRASE}" \
    --output "${BACKUP_FILE}"

# 2. Verify the backup file exists and has content
if [ ! -s "${BACKUP_FILE}" ]; then
  echo "ERROR: Backup file is empty or was not created" >&2
  exit 1
fi

BACKUP_SIZE=$(stat -f%z "${BACKUP_FILE}" 2>/dev/null || stat -c%s "${BACKUP_FILE}" 2>/dev/null)
echo "[backup] Backup created: ${BACKUP_FILE} (${BACKUP_SIZE} bytes)"

# 3. Log what was backed up (for audit trail)
echo "[backup] Database: zkm"
echo "[backup] Timestamp: ${TIMESTAMP}"
echo "[backup] Encrypted with: AES-256 (symmetric)"
echo "[backup] Contents: ciphertext, salts, verifiers (no plaintext secrets)"
echo "[backup] Done."
