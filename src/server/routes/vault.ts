/**
 * Vault entry routes — CRUD for encrypted blobs.
 *
 * The server stores ONLY opaque encrypted data. It never sees plaintext.
 * All entries are scoped to the authenticated user via the JWT's userId.
 *
 * WHAT THE SERVER STORES PER ENTRY:
 *   entry_id   — opaque UUID
 *   user_id    — owner (from JWT, not user-supplied)
 *   nonce      — 12-byte AES-GCM random IV (not secret, but unique)
 *   ciphertext — encrypted vault data (opaque to server)
 *   auth_tag   — 16-byte GCM authentication tag (tamper detection)
 *   entry_type — plaintext category label ("login", "ssh-key", etc.)
 *   version    — integer counter for optimistic concurrency + AAD binding
 *
 * WHAT THE SERVER NEVER SEES:
 *   The actual password, username, URL, notes, or any other secret
 *   inside the vault entry. That data is encrypted client-side under
 *   the Vault Key, which is itself encrypted under the Master Key.
 */

import { Router } from "express";
import { prisma } from "../db.js";
import { requireAuth } from "../middleware/auth.js";
import {
  createEntrySchema,
  updateEntrySchema,
  uuidParamSchema,
} from "../utils/validation.js";
import { auditLog } from "../utils/audit.js";
import { NotFoundError } from "../utils/errors.js";

const router = Router();

// All vault routes require authentication.
router.use(requireAuth);

// ---------------------------------------------------------------------------
// GET /vault/entries
// Returns all entries for the authenticated user.
// Server returns: { entries: [ { id, entryType, nonce, ciphertext, authTag, version, createdAt, updatedAt } ] }
// The client decrypts locally using the Vault Key (derived from MK + wrapped VK).
// ---------------------------------------------------------------------------

router.get("/entries", async (req, res) => {
  const userId = req.user!.userId;

  const entries = await prisma.vaultEntry.findMany({
    where: { userId },
    select: {
      id: true,
      entryType: true,
      nonce: true,
      ciphertext: true,
      authTag: true,
      version: true,
      createdAt: true,
      updatedAt: true,
    },
    orderBy: { updatedAt: "desc" },
  });

  await auditLog({
    userId,
    eventType: "entry_list",
    ipAddress: req.ip,
    userAgent: req.get("user-agent"),
    details: { count: entries.length },
  });

  res.json({
    entries: entries.map((e) => ({
      id: e.id,
      entryType: e.entryType,
      nonce: e.nonce.toString("hex"),
      ciphertext: e.ciphertext.toString("hex"),
      authTag: e.authTag.toString("hex"),
      version: e.version,
      createdAt: e.createdAt.toISOString(),
      updatedAt: e.updatedAt.toISOString(),
    })),
  });
});

// ---------------------------------------------------------------------------
// POST /vault/entries
// Create a new encrypted entry. The ciphertext is already encrypted by the
// client — the server just stores the blob.
// ---------------------------------------------------------------------------

router.post("/entries", async (req, res) => {
  const userId = req.user!.userId;
  const parsed = createEntrySchema.parse(req.body);

  const entry = await prisma.vaultEntry.create({
    data: {
      userId,
      entryType: parsed.entryType,
      nonce: Buffer.from(parsed.nonce, "hex"),
      ciphertext: Buffer.from(parsed.ciphertext, "hex"),
      authTag: Buffer.from(parsed.authTag, "hex"),
      version: 1,
    },
  });

  await auditLog({
    userId,
    eventType: "entry_create",
    ipAddress: req.ip,
    userAgent: req.get("user-agent"),
    details: { entryId: entry.id, entryType: parsed.entryType },
  });

  res.status(201).json({
    id: entry.id,
    entryType: entry.entryType,
    nonce: entry.nonce.toString("hex"),
    ciphertext: entry.ciphertext.toString("hex"),
    authTag: entry.authTag.toString("hex"),
    version: entry.version,
    createdAt: entry.createdAt.toISOString(),
    updatedAt: entry.updatedAt.toISOString(),
  });
});

// ---------------------------------------------------------------------------
// PUT /vault/entries/:id
// Update an existing entry. Enforces ownership + optimistic concurrency
// via the version field.
// ---------------------------------------------------------------------------

router.put("/entries/:id", async (req, res) => {
  const userId = req.user!.userId;
  const { id } = uuidParamSchema.parse(req.params);
  const parsed = updateEntrySchema.parse(req.body);

  // Fetch existing entry scoped to this user (prevents ID enumeration).
  // Both "entry doesn't exist" and "entry belongs to another user" return 404.
  const existing = await prisma.vaultEntry.findFirst({
    where: { id, userId },
  });

  if (!existing) {
    throw new NotFoundError("Entry not found");
  }

  // Optimistic concurrency: the submitted version must match the current
  // version. This prevents lost-update races and ensures the client is
  // working from the latest state.
  if (parsed.version !== existing.version) {
    throw new NotFoundError(
      `Version mismatch: expected ${existing.version}, got ${parsed.version}`,
    );
  }

  const updated = await prisma.vaultEntry.update({
    where: { id },
    data: {
      nonce: Buffer.from(parsed.nonce, "hex"),
      ciphertext: Buffer.from(parsed.ciphertext, "hex"),
      authTag: Buffer.from(parsed.authTag, "hex"),
      version: { increment: 1 },
    },
  });

  await auditLog({
    userId,
    eventType: "entry_update",
    ipAddress: req.ip,
    userAgent: req.get("user-agent"),
    details: { entryId: id },
  });

  res.json({
    id: updated.id,
    entryType: updated.entryType,
    nonce: updated.nonce.toString("hex"),
    ciphertext: updated.ciphertext.toString("hex"),
    authTag: updated.authTag.toString("hex"),
    version: updated.version,
    createdAt: updated.createdAt.toISOString(),
    updatedAt: updated.updatedAt.toISOString(),
  });
});

// ---------------------------------------------------------------------------
// DELETE /vault/entries/:id
// Permanent deletion. Client should have decrypted and re-encrypted if the
// user wanted to "move" the entry. This is a hard delete.
// ---------------------------------------------------------------------------

router.delete("/entries/:id", async (req, res) => {
  const userId = req.user!.userId;
  const { id } = uuidParamSchema.parse(req.params);

  // Fetch entry scoped to this user (prevents ID enumeration).
  const existing = await prisma.vaultEntry.findFirst({
    where: { id, userId },
  });

  if (!existing) {
    throw new NotFoundError("Entry not found");
  }

  await prisma.vaultEntry.delete({ where: { id } });

  await auditLog({
    userId,
    eventType: "entry_delete",
    ipAddress: req.ip,
    userAgent: req.get("user-agent"),
    details: { entryId: id, entryType: existing.entryType },
  });

  res.status(204).end();
});

export default router;
