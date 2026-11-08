import { test } from "node:test";
import assert from "node:assert/strict";
import { applyDecision, ReviewError } from "../src/review.js";

// Fixed clock: 2026-11-07 12:00 UTC.
const NOW = Date.parse("2026-11-07T12:00:00Z");

const request = (over) => ({
  id: "AR-0001",
  requester: "req.one",
  jobTitle: "Software Engineer",
  employmentType: "employee",
  requestedRoles: ["repo-read"],
  durationDays: 30,
  lastLogin: "2026-11-06",
  approver: "lead.one",
  justification: "A sufficiently long business justification.",
  status: "pending",
  approvals: [],
  createdAt: "2026-11-01T00:00:00.000Z",
  ...over,
});

const HIGH = () => request({ requestedRoles: ["repo-read", "db-admin"] }); // score 35, high, two approvers
const CRITICAL = () => request({ employmentType: "contractor", requestedRoles: ["prod-deploy", "db-admin"] }); // 73
const MEDIUM = () => request({ durationDays: null }); // 15
const LOW = () => request({}); // 0

const act = (req, decision, reviewer, note = "") => applyDecision(req, { decision, reviewer, note, now: NOW });

function expectError(fn, code, status) {
  assert.throws(fn, (err) => err instanceof ReviewError && err.code === code && err.status === status);
}

test("high risk needs two different approvers before it is approved", () => {
  const first = act(HIGH(), "approve", "rev.alpha");
  assert.equal(first.request.status, "pending");
  assert.equal(first.result.approvals, 1);
  assert.equal(first.result.required, 2);

  const second = act(first.request, "approve", "rev.beta");
  assert.equal(second.request.status, "approved");
  assert.equal(second.request.decidedBy, "rev.beta");
  assert.equal(second.result.approvals, 2);
});

test("critical risk also needs two approvers, and each approval is flagged as against the recommendation", () => {
  const first = act(CRITICAL(), "approve", "rev.alpha");
  assert.equal(first.request.status, "pending");
  assert.equal(first.result.againstRecommendation, true);

  const second = act(first.request, "approve", "rev.beta");
  assert.equal(second.request.status, "approved");
});

test("medium and low risk need one approver", () => {
  assert.equal(act(MEDIUM(), "approve", "rev.alpha").request.status, "approved");
  assert.equal(act(LOW(), "approve", "rev.alpha").request.status, "approved");
});

test("the same reviewer cannot approve twice, including case and spacing changes", () => {
  const first = act(HIGH(), "approve", "rev.alpha");
  expectError(() => act(first.request, "approve", "rev.alpha"), "DUPLICATE", 409);
  expectError(() => act(first.request, "approve", "REV.ALPHA"), "DUPLICATE", 409);
  expectError(() => act(first.request, "approve", "  rev.alpha "), "DUPLICATE", 409);
});

test("requesters cannot review their own request", () => {
  expectError(() => act(HIGH(), "approve", "req.one"), "SELF_REVIEW", 403);
  expectError(() => act(LOW(), "deny", "REQ.ONE"), "SELF_REVIEW", 403);
});

test("approved and denied requests cannot be changed", () => {
  const approved = act(LOW(), "approve", "rev.alpha").request;
  for (const d of ["approve", "deny", "escalate"]) expectError(() => act(approved, d, "rev.beta"), "LOCKED", 409);

  const denied = act(MEDIUM(), "deny", "rev.alpha", "not needed").request;
  assert.equal(denied.status, "denied");
  for (const d of ["approve", "deny", "escalate"]) expectError(() => act(denied, d, "rev.beta"), "LOCKED", 409);
});

test("an escalated request stays open and can still be approved", () => {
  const escalated = act(MEDIUM(), "escalate", "rev.alpha", "needs a look").request;
  assert.equal(escalated.status, "escalated");
  assert.equal(act(escalated, "approve", "rev.beta").request.status, "approved");
});

test("bad decisions, reviewer names, and notes are rejected; a 500-character note is accepted", () => {
  expectError(() => act(LOW(), "APPROVE", "rev.alpha"), "BAD_DECISION", 400);
  expectError(() => act(LOW(), "approve", "a"), "BAD_REVIEWER", 400);
  expectError(() => act(LOW(), "approve", "rev.alpha", "n".repeat(501)), "BAD_NOTE", 400);
  assert.equal(act(LOW(), "approve", "rev.alpha", "n".repeat(500)).request.status, "approved");
});

test("applyDecision does not modify the request it is given", () => {
  const req = HIGH();
  const before = JSON.stringify(req);
  act(req, "approve", "rev.alpha");
  assert.equal(JSON.stringify(req), before);
});

test("the audit entry records the reviewer, action, request, score, level, and time", () => {
  const out = act(HIGH(), "approve", "rev.alpha", "checked scope");
  assert.deepEqual(out.audit, {
    at: new Date(NOW).toISOString(),
    actor: "rev.alpha",
    action: "approve",
    requestId: "AR-0001",
    detail: "Score 35, level high. Approval 1 of 2. Note: checked scope",
  });
});
