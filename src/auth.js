// Sign-in tokens. Each person gets a random token. The server keeps only a
// SHA-256 hash of each token, and maps the hash to a name.

import { createHash, randomBytes } from "node:crypto";

export function hashToken(token) {
  return createHash("sha256").update(String(token)).digest("hex");
}

export function newToken() {
  return randomBytes(24).toString("base64url");
}

// doc: { users: [{ name, tokenHash }] }. Returns Map(tokenHash -> name).
export function loadUsers(doc) {
  const users = new Map();
  for (const u of doc?.users ?? []) {
    if (typeof u.name !== "string" || typeof u.tokenHash !== "string") {
      throw new Error("Users file: each user needs a name and a tokenHash.");
    }
    users.set(u.tokenHash, u.name);
  }
  return users;
}

// Returns the signed-in name for a valid "Authorization: Bearer <token>" header, or null.
// Nothing else in the request (other headers, the body) can set the name.
export function userFromAuthHeader(header, users) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  if (!token) return null;
  return users.get(hashToken(token)) ?? null;
}
