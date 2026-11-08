// Creates data/users.json with one sign-in token per person. The tokens are
// printed once. Only their hashes are saved.
// Run with: npm run setup   (add --force to replace an existing file)

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { hashToken, newToken } from "../src/auth.js";

// Simulated people. Replace these with your own test names if you like.
const NAMES = [
  "priya.n", "marcus.t", "chen.w", "alex.k", "sam.o", "jordan.p",
  "dan.lee", "ana.r", "lee.m", "rachel.s", "maya.c",
];

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const file = process.env.ARA_USERS ?? join(root, "data", "users.json");
const force = process.argv.includes("--force");

let exists = true;
try {
  await readFile(file);
} catch {
  exists = false;
}
if (exists && !force) {
  console.error(`${file} already exists. Use --force to replace it. Existing tokens will stop working.`);
  process.exit(1);
}

const people = NAMES.map((name) => ({ name, token: newToken() }));
const doc = { users: people.map(({ name, token }) => ({ name, tokenHash: hashToken(token) })) };

await mkdir(dirname(file), { recursive: true });
await writeFile(file, JSON.stringify(doc, null, 2) + "\n");

console.log(`Wrote ${file}`);
console.log("\nSave these tokens now. They are shown only once.\n");
for (const { name, token } of people) console.log(`${name.padEnd(12)} ${token}`);
