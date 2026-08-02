# Incident Response Runbook

## ZKM Security Incident Response

This document covers the procedure when a security incident occurs,
specifically a **database breach** (unauthorized access to the PostgreSQL
database or its backups).

---

## TL;DR — Why vault contents remain safe

If the database is breached, vault contents remain encrypted. The attacker
gains access to:

- **Encrypted vault keys** (`wrapped_vk`) — locked under the user's master key
- **Encrypted recovery keys** (`recovery_wrapped_vk`) — locked under the recovery code
- **Auth verifiers** (`auth_verifier`) — one-way hashes, not useful for vault decryption
- **Salts** (`salt_enc`, `salt_auth`) — random, not secret per Kerckhoffs's principle
- **TOTP secrets** (`totp_secret`) — useful for 2FA bypass if session tokens are also stolen, but NOT for vault decryption

**None of these reveal the master password, master key, vault key, or any
vault entry plaintext.**

The claim holds because:
1. The master key is derived via **Argon2id** (256 MiB memory, 4 iterations)
   — making offline brute-force ~0.3-1 guess/second per GPU core.
2. The vault key is wrapped with **AES-256-GCM** — computationally infeasible
   to brute-force without the master key.
3. Vault entries are encrypted with **AES-256-GCM** — a different key
   (the vault key) than what the attacker can attempt to derive.
4. The auth verifier is a **SHA-256** hash of the auth key — even if cracked,
   the auth key is independent of the master key (different KDF with
   different salt and domain separation string).

---

## Incident Response Procedure

### Phase 1: Containment (0-1 hours)

#### 1.1 Confirm the breach

- [ ] Check database access logs for unauthorized connections
- [ ] Review application audit logs for suspicious patterns
- [ ] Verify no unauthorized IP ranges have database access
- [ ] Confirm whether the breach is active or historical

#### 1.2 Immediately rotate the JWT signing key

This **invalidates all active sessions** — users must re-authenticate.

```bash
# Generate new JWT secret
NEW_JWT_SECRET=$(openssl rand -base64 64)
NEW_TEMP_TOKEN_SECRET=$(openssl rand -base64 64)

# Set previous key for graceful transition (optional — for rolling deploys)
# In .env:
#   JWT_SECRET_PREV=<current JWT_SECRET value>
#   JWT_SECRET=<NEW_JWT_SECRET>
#   TEMP_TOKEN_SECRET=<NEW_TEMP_TOKEN_SECRET>
```

Deploy the new configuration. All existing session tokens are immediately
invalidated (or remain valid for JWT_EXPIRES_IN if using JWT_SECRET_PREV).

#### 1.3 Force all users to re-authenticate

After rotating the JWT key, all session tokens are invalidated. Users will
be prompted to log in again on their next request. No user action is required.

#### 1.4 Rotate database credentials

```bash
# PostgreSQL
ALTER USER zkm WITH PASSWORD 'new-strong-password';
# Update DATABASE_URL in .env
```

#### 1.5 Rotate backup encryption keys

If backups are encrypted at rest (GPG, KMS, etc.), rotate the encryption key.

---

### Phase 2: Assessment (1-24 hours)

#### 2.1 Determine scope

- [ ] Which tables were accessed?
- [ ] How many user records were exposed?
- [ ] Were vault entries (ciphertext) exfiltrated?
- [ ] Were backup files accessed?
- [ ] Time window of unauthorized access

#### 2.2 Identify attack vector

- [ ] SQL injection? (Unlikely — parameterized queries via Prisma ORM)
- [ ] Compromised credentials?
- [ ] Misconfigured access control?
- [ ] Compromised server/container?

#### 2.3 Assess impact on vault contents

Since all vault data is encrypted:
- **Encrypted vault keys** → safe without master password
- **Encrypted entries** → safe without vault key
- **Auth verifiers** → safe (one-way hash, independent of master key)
- **TOTP secrets** → can be used to bypass 2FA IF attacker has user's
  email and can intercept the login flow — but this does NOT help
  decrypt vault contents

**Vault contents remain cryptographically secure** unless the attacker
also obtains the user's master password through other means (phishing,
keylogger, etc.).

---

### Phase 3: Notification (24-72 hours)

#### 3.1 Notify affected users

Even though vault contents are safe, users should be notified because:

1. **TOTP secrets may be compromised** — users should re-enroll 2FA
2. **Auth verifiers may be used for offline brute-force** — users with
   weak passwords should change them immediately
3. **Email addresses are exposed** — phishing risk increases

**Recommended notification template:**

> Subject: Security Incident — Action Required
>
> We detected unauthorized access to our database on [DATE]. We want to
> assure you that your vault contents (passwords, notes, etc.) remain
> encrypted and secure. The encryption key is derived from your master
> password, which is never stored on our servers.
>
> **What you should do:**
> 1. Log in and change your master password (Settings → Change Password)
> 2. Re-enroll two-factor authentication (Settings → 2FA Setup)
> 3. Review your recovery code (Settings → Recovery)
>
> **Why your data is safe:** Your vault is encrypted with AES-256-GCM.
> The encryption key is derived from your master password using Argon2id
> (memory-hard KDF). Without your password, the encrypted data is
> computationally infeasible to decrypt.

#### 3.2 Notify regulators (if required)

Under GDPR, notify the supervisory authority within 72 hours if personal
data breach is likely to result in risk to individuals. The email addresses
in the database constitute personal data.

---

### Phase 4: Remediation (1-2 weeks)

#### 4.1 Patch the vulnerability

- [ ] Fix the root cause (e.g., SQL injection, misconfiguration)
- [ ] Deploy the fix
- [ ] Verify the fix with penetration testing

#### 4.2 Force password resets (if warranted)

If the auth verifiers were exfiltrated and weak passwords are suspected:
- [ ] Invalidate all auth verifiers (set `auth_verifier` to NULL)
- [ ] Force all users to reset their master password on next login
- [ ] This also invalidates all vault keys (since master key changes)

#### 4.3 Re-encrypt database backups

If backups were exposed:
- [ ] Re-encrypt with new keys
- [ ] Delete old encrypted backups
- [ ] Verify backup integrity

#### 4.4 Post-incident review

- [ ] Document timeline
- [ ] Identify root cause
- [ ] Implement preventive measures
- [ ] Update this runbook with lessons learned

---

## Key Hierarchy Reference

```
Master Password
    ↓ Argon2id(salt_enc, 256MiB, 4 iter, domain="zkm-master-v1")
Master Key (AES-256)
    ↓ AES-256-GCM wrap
Vault Key (32 bytes, CSPRNG)
    ↓ AES-256-GCM encrypt
Vault Entries (ciphertext)

Master Password
    ↓ Argon2id(salt_auth, 256MiB, 4 iter, domain="zkm-auth-v1")
Auth Key (32 bytes, SHA-256)
    → Sent to server, stored as SHA-256 hash (auth_verifier)
    → Used only for login verification, NOT vault access

Recovery Code (128-bit, CSPRNG)
    ↓ SHA-256(code || "zkm-recovery-v1")
Recovery Wrap Key (AES-256)
    ↓ AES-256-GCM wrap
Vault Key (same key, separate copy)
```

**Critical property**: The auth key and master key are derived from the
same password but with **different salts, different KDF parameters, and
different domain separation strings**. Compromising the auth verifier
(used for login) does NOT help derive the master key (used for vault
decryption).
