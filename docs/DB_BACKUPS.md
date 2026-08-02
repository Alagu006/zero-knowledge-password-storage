# DB Backup Verification

## What is stored in the database

The ZKM database stores **only ciphertext, salts, and verification hashes**.
It never stores plaintext passwords, vault keys, or any data reversible to plaintext
without the user's master password.

### Schema contents (per user row)

| Column              | Contents                                         | Reversible to plaintext? |
|---------------------|--------------------------------------------------|--------------------------|
| `email`             | Email address (plaintext)                        | Yes (not secret)         |
| `salt_enc`          | 32-byte Argon2id salt for master key derivation  | No                       |
| `salt_auth`         | 32-byte Argon2id salt for auth key derivation    | No                       |
| `auth_verifier`     | 32-byte SHA-256 of auth key (stored for compare) | No                       |
| `wrapped_vk`        | AES-256-GCM encrypted vault key (48 + 12 + 16 bytes) | No (needs master key) |
| `wrapped_vk_iv`     | 12-byte AES-GCM initialization vector            | No                       |
| `wrapped_vk_tag`    | 16-byte AES-GCM authentication tag               | No                       |
| `recovery_wrapped_vk`| AES-256-GCM encrypted vault key (recovery copy) | No (needs recovery code) |
| `recovery_wrapped_vk_iv` | IV for recovery wrapping                  | No                       |
| `recovery_wrapped_vk_tag`| Auth tag for recovery wrapping              | No                       |
| `totp_secret`       | 20-byte TOTP secret (encrypted at rest via column encryption) | No (only for 2FA) |
| `totp_enabled`      | Boolean flag                                     | N/A                      |
| `created_at`        | Account creation timestamp                       | N/A                      |
| `updated_at`        | Last update timestamp                            | N/A                      |

### Vault entries table

| Column        | Contents                          | Reversible to plaintext? |
|---------------|-----------------------------------|--------------------------|
| `id`          | UUID primary key                  | N/A                      |
| `user_id`     | Foreign key to users              | N/A                      |
| `ciphertext`  | AES-256-GCM encrypted entry      | No (needs vault key)     |
| `iv`          | 12-byte initialization vector     | No                       |
| `auth_tag`    | 16-byte authentication tag        | No                       |
| `created_at`  | Creation timestamp                | N/A                      |
| `updated_at`  | Last update timestamp             | N/A                      |

### Backup codes table

| Column      | Contents                           | Reversible to plaintext? |
|-------------|------------------------------------|--------------------------|
| `id`        | UUID primary key                   | N/A                      |
| `user_id`   | Foreign key to users               | N/A                      |
| `code_hash` | SHA-256 hash of backup code        | No (one-way hash)        |
| `used`      | Boolean — whether code was consumed| N/A                      |
| `created_at`| Creation timestamp                 | N/A                      |

## Backup verification checklist

When performing a backup:

- [ ] **Confirm database contains no plaintext secrets**: Query for any columns
      that could contain reversible data. All crypto material is either encrypted
      (wrapped_vk, recovery_wrapped_vk) or a one-way derivation output
      (auth_verifier, salt_enc, salt_auth, code_hash).

- [ ] **Encrypt backups at rest** (defense in depth):
  - **PostgreSQL**: Use `pg_dump` with `--no-owner --no-privileges` and pipe through
    `gpg --symmetric --cipher-algo AES256` before storage.
  - **AWS RDS**: Enable automated backups (encrypted with KMS).
  - **Docker volume**: Bind-mount to an encrypted filesystem (LUKS, dm-crypt).
  - **Offsite**: Use encrypted S3 bucket (SSE-KMS) or equivalent.

- [ ] **Test restoration**: Periodically restore a backup to an isolated
      environment and verify data integrity (Prisma migrate, read counts).

- [ ] **Rotation of backup encryption keys**: If using GPG or KMS for backup
      encryption, rotate the encryption key at least annually.

## Why vault contents remain safe even if backups are compromised

A compromised backup exposes:
1. `wrapped_vk` — the vault key encrypted under the master key
2. `recovery_wrapped_vk` — the vault key encrypted under the recovery key
3. `auth_verifier` — a hash of the auth key (used for login, not vault access)

To decrypt any vault entry, an attacker would need to:
1. Derive the master key from the user's password (requires Argon2id with 256 MiB memory,
   4 iterations — takes ~1-3 seconds on modern hardware per guess)
2. Use the master key to unwrap the vault key (AES-256-GCM)
3. Use the vault key to decrypt the entry (AES-256-GCM)

With the KDF parameters from Prompt 1 (Argon2id, 256 MiB, 4 iterations):
- **Offline brute-force rate**: ~0.3-1 guess/second per GPU core
- **Cost per guess**: ~256 MiB RAM (parallelism-limited)
- **12-character random password**: ~95^12 ≈ 5.4 × 10^23 combinations → infeasible
- **Common 12-char password**: still requires dictionary attack with ~10^6 candidates → ~12 days on 1 GPU

The recovery code (128-bit random) is even harder: 2^128 combinations.

**Bottom line**: Without the user's master password (or recovery code), the encrypted
vault key is computationally infeasible to derive from the backup data.
