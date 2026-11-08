import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { once } from "node:events";
import { createApp } from "../src/server.js";
import { AccessRiskService } from "../src/service.js";
import { MemoryStore } from "../src/memory-store.js";
import { hashToken } from "../src/auth.js";

// Test-only tokens. Nothing here is a real credential.
const TOKENS = {
  "priya.n": "test-token-priya",
  "dan.lee": "test-token-dan",
  "chen.w": "test-token-chen",
};
const users = new Map(Object.entries(TOKENS).map(([name, token]) => [hashToken(token), name]));

let server;
let base;

before(async () => {
  const service = new AccessRiskService({ store: new MemoryStore() });
  server = createApp({ service, users });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

async function call(path, { user, method = "GET", body, raw, headers = {} } = {}) {
  const h = { ...headers };
  if (user) h.authorization = `Bearer ${TOKENS[user]}`;
  if (body !== undefined) h["content-type"] = "application/json";
  const res = await fetch(base + path, {
    method,
    headers: h,
    body: raw ?? (body !== undefined ? JSON.stringify(body) : undefined),
  });
  const text = await res.text();
  let data = null;
  try {
    data = JSON.parse(text);
  } catch {
    // Not JSON (for example the page itself).
  }
  return { status: res.status, data, text, type: res.headers.get("content-type") };
}

const high = {
  jobTitle: "Software Engineer",
  employmentType: "employee",
  requestedRoles: ["repo-read", "db-admin"],
  durationDays: 30,
  justification: "A sufficiently long business justification.",
  approver: "dan.lee",
};

test("API calls without a valid token get 401", async () => {
  assert.equal((await call("/api/requests")).status, 401);
  assert.equal((await call("/api/requests", { headers: { authorization: "Bearer wrong" } })).status, 401);
});

test("a name in a header cannot stand in for a token", async () => {
  const r = await call("/api/requests", { headers: { "x-user": "dan.lee", "x-forwarded-user": "dan.lee" } });
  assert.equal(r.status, 401);
});

test("the requester comes from the token, not the request body", async () => {
  const sent = await call("/api/requests", { user: "priya.n", method: "POST", body: { ...high, requester: "dan.lee" } });
  assert.equal(sent.status, 201);
  const list = await call("/api/requests", { user: "priya.n" });
  const mine = list.data.find((x) => x.id === sent.data.id);
  assert.equal(mine.requester, "priya.n");
});

test("two different people approve over HTTP; a repeat approval is refused and a locked request is not changed", async () => {
  const sent = await call("/api/requests", { user: "priya.n", method: "POST", body: high });
  const decide = (user, body) =>
    call(`/api/requests/${sent.data.id}/decision`, { user, method: "POST", body });

  const first = await decide("dan.lee", { decision: "approve", note: "ok" });
  assert.equal(first.status, 200);
  assert.equal(first.data.status, "pending");

  const repeat = await decide("dan.lee", { decision: "approve" });
  assert.equal(repeat.status, 409);

  const second = await decide("chen.w", { decision: "approve" });
  assert.equal(second.data.status, "approved");

  const locked = await decide("dan.lee", { decision: "deny" });
  assert.equal(locked.status, 409);
});

test("the requester cannot review their own request", async () => {
  const sent = await call("/api/requests", { user: "priya.n", method: "POST", body: high });
  const r = await call(`/api/requests/${sent.data.id}/decision`, {
    user: "priya.n",
    method: "POST",
    body: { decision: "approve" },
  });
  assert.equal(r.status, 403);
});

test("a decision payload naming someone else is ignored", async () => {
  const sent = await call("/api/requests", { user: "priya.n", method: "POST", body: high });
  await call(`/api/requests/${sent.data.id}/decision`, {
    user: "dan.lee",
    method: "POST",
    body: { decision: "escalate", reviewer: "chen.w" },
  });
  const audit = await call("/api/audit?limit=5", { user: "dan.lee" });
  const entry = audit.data.find((e) => e.requestId === sent.data.id && e.action === "escalate");
  assert.equal(entry.actor, "dan.lee");
});

test("invalid input returns 400 with the rule that failed", async () => {
  const r = await call("/api/requests", { user: "priya.n", method: "POST", body: { ...high, durationDays: 366 } });
  assert.equal(r.status, 400);
  assert.match(r.data.error, /1 to 365/);
});

test("malformed JSON is rejected", async () => {
  const r = await call("/api/requests", {
    user: "priya.n",
    method: "POST",
    raw: "{not json",
    headers: { "content-type": "application/json" },
  });
  assert.equal(r.status, 400);
});

test("the page is served, and files outside public/ are not", async () => {
  const page = await call("/");
  assert.equal(page.status, 200);
  assert.match(page.type, /text\/html/);
  assert.match(page.text, /Access Risk Analyzer/);
  assert.equal((await call("/%2e%2e/package.json")).status, 404);
  assert.equal((await call("/../package.json")).status, 404);
});
