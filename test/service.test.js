import { test } from "node:test";
import assert from "node:assert/strict";
import { AccessRiskService } from "../src/service.js";
import { MemoryStore } from "../src/memory-store.js";
import { ReviewError } from "../src/review.js";

const START = Date.parse("2026-11-07T12:00:00Z");

// Each call to the clock moves time forward one second, so audit times are distinct.
function makeService(store = new MemoryStore()) {
  let t = START;
  const service = new AccessRiskService({
    store,
    now: () => {
      t += 1000;
      return t;
    },
  });
  return { service, store };
}

const high = {
  jobTitle: "Software Engineer",
  employmentType: "employee",
  requestedRoles: ["repo-read", "db-admin"],
  durationDays: 30,
  justification: "A sufficiently long business justification.",
  approver: "lead.one",
  lastLogin: null,
};

test("seeding loads the demo requests once", async () => {
  const { service } = makeService();
  assert.deepEqual(await service.seedDemo(), { added: 6 });
  assert.deepEqual(await service.seedDemo(), { added: 0 });
  assert.equal((await service.list()).length, 6);
});

test("submit takes the requester from the signed-in user and ignores payload fields", async () => {
  const { service } = makeService();
  await service.submit("priya.n", high);
  const { id } = await service.submit("priya.n", {
    ...high,
    requester: "dan.lee",
    status: "approved",
    approvals: [{ reviewer: "chen.w" }],
    id: "AR-0001",
    createdAt: "2000-01-01T00:00:00.000Z",
  });
  assert.equal(id, "AR-0002");
  const stored = (await service.list()).find((r) => r.id === id);
  assert.equal(stored.requester, "priya.n");
  assert.equal(stored.status, "pending");
  assert.equal(stored.approvals.length, 0);
  assert.ok(stored.createdAt.startsWith("2026-11-07"));
});

test("decisions use the signed-in reviewer, not a name in the payload", async () => {
  const { service } = makeService();
  const { id } = await service.submit("priya.n", high);
  await service.decide("dan.lee", id, { decision: "approve", reviewer: "chen.w", note: "" });
  const entry = (await service.audit(10)).find((e) => e.action === "approve");
  assert.equal(entry.actor, "dan.lee");
  const stored = (await service.list()).find((r) => r.id === id);
  assert.deepEqual(stored.approvals.map((a) => a.reviewer), ["dan.lee"]);
});

test("two different people approve a high-risk request; the audit shows each one in order", async () => {
  const { service } = makeService();
  const { id } = await service.submit("priya.n", high);

  await service.decide("dan.lee", id, { decision: "approve", note: "scope ok" });
  assert.equal((await service.list()).find((r) => r.id === id).status, "pending");

  await service.decide("chen.w", id, { decision: "approve", note: "second check" });
  const end = (await service.list()).find((r) => r.id === id);
  assert.equal(end.status, "approved");
  assert.equal(end.decidedBy, "chen.w");

  const all = await service.audit(50);
  const trail = all.filter((e) => e.requestId === id).reverse().map((e) => [e.action, e.actor]);
  assert.deepEqual(trail, [
    ["submit", "priya.n"],
    ["approve", "dan.lee"],
    ["approve", "chen.w"],
  ]);
  const newestFirst = all.every((e, i) => i === 0 || Date.parse(all[i - 1].at) >= Date.parse(e.at));
  assert.equal(newestFirst, true);
});

test("refused decisions are written to the audit log and leave the request unchanged", async () => {
  const { service } = makeService();
  const { id } = await service.submit("priya.n", high);
  await service.decide("dan.lee", id, { decision: "approve" });

  await assert.rejects(
    () => service.decide("dan.lee", id, { decision: "approve" }),
    (e) => e instanceof ReviewError && e.code === "DUPLICATE"
  );
  await assert.rejects(
    () => service.decide("priya.n", id, { decision: "approve" }),
    (e) => e instanceof ReviewError && e.code === "SELF_REVIEW"
  );

  const refused = (await service.audit(50)).filter((e) => e.action === "decision-rejected");
  assert.equal(refused.length, 2);
  assert.equal(refused[0].actor, "priya.n"); // newest first
  assert.equal(refused[1].actor, "dan.lee");
  assert.equal((await service.list()).find((r) => r.id === id).approvals.length, 1);
});

test("an unknown request id returns not-found", async () => {
  const { service } = makeService();
  await assert.rejects(
    () => service.decide("dan.lee", "AR-9999", { decision: "approve" }),
    (e) => e.code === "NOT_FOUND" && e.status === 404
  );
});

test("simultaneous approvals by the same person are counted once", async () => {
  const { service } = makeService();
  const { id } = await service.submit("priya.n", high);
  const results = await Promise.allSettled(
    [1, 2, 3].map(() => service.decide("dan.lee", id, { decision: "approve" }))
  );
  assert.equal(results.filter((r) => r.status === "fulfilled").length, 1);
  assert.equal((await service.list()).find((r) => r.id === id).approvals.length, 1);
});

test("simultaneous approvals by two different people are both kept", async () => {
  const { service } = makeService();
  const { id } = await service.submit("priya.n", high);
  await Promise.all([
    service.decide("dan.lee", id, { decision: "approve" }),
    service.decide("chen.w", id, { decision: "approve" }),
  ]);
  const stored = (await service.list()).find((r) => r.id === id);
  assert.equal(stored.approvals.length, 2);
  assert.equal(stored.status, "approved");
});

test("state lives in the store, so a new service on the same store sees earlier work", async () => {
  const store = new MemoryStore();
  await makeService(store).service.submit("priya.n", high);
  const later = makeService(store).service;
  assert.equal((await later.list()).length, 1);
});
