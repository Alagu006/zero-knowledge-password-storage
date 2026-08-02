/**
 * Structured vault entry payload.
 *
 * Before encryption, all fields are serialized to a JSON string. After
 * decryption, the JSON is parsed back into this structure.
 *
 * SECURITY: Every field in this type is user-controlled and MUST be
 * escaped via escapeHtml() before rendering. Never use
 * dangerouslySetInnerHTML with any of these fields.
 */
export type VaultEntryPayload = {
  label: string;
  url: string;
  username: string;
  notes: string;
  secret: string;
};

export const EMPTY_ENTRY_PAYLOAD: VaultEntryPayload = {
  label: "",
  url: "",
  username: "",
  notes: "",
  secret: "",
};

/**
 * Serialize a VaultEntryPayload to a JSON string for encryption.
 * The JSON is compact (no pretty-printing) to minimize ciphertext size.
 */
export function serializePayload(payload: VaultEntryPayload): string {
  return JSON.stringify(payload);
}

/**
 * Deserialize a JSON string back into a VaultEntryPayload.
 * Missing fields default to empty strings for forward compatibility.
 */
export function deserializePayload(json: string): VaultEntryPayload {
  const raw = JSON.parse(json) as unknown;
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("Invalid vault entry payload: expected JSON object");
  }
  const obj = raw as Record<string, unknown>;
  return {
    label: typeof obj.label === "string" ? obj.label : "",
    url: typeof obj.url === "string" ? obj.url : "",
    username: typeof obj.username === "string" ? obj.username : "",
    notes: typeof obj.notes === "string" ? obj.notes : "",
    secret: typeof obj.secret === "string" ? obj.secret : "",
  };
}
