import { test } from "node:test";
import assert from "node:assert/strict";
import { validateRequest, ValidationError } from "../src/validate.js";

// Fixed clock: 2026-11-07 12:00 UTC.
const NOW = Date.parse("2026-11-07T12:00:00Z");
const user = "tester.one";
const good = {
  jobTitle: "Software Engineer",
  employmentType: "employee",
  requestedRoles: ["repo-read"],
  durationDays: 30,
  justification: "A sufficiently long business justification.",
  lastLogin: null,
  approver: null,
};

const check = (over) => validateRequest({ ...good, ...over }, { user, now: NOW });

function rejects(over, text) {
  assert.throws(
    () => check(over),
    (err) => err instanceof ValidationError && err.status === 400 && (text === undefined || err.message.includes(text))
  );
}

const DURATION = "whole number of days from 1 to 365";

test("duration boundaries: 0 and 366 are rejected; 1 and 365 are accepted", () => {
  rejects({ durationDays: 0 }, DURATION);
  rejects({ durationDays: 366 }, DURATION);
  assert.equal(check({ durationDays: 1 }).durationDays, 1);
  assert.equal(check({ durationDays: 365 }).durationDays, 365);
});

test("other duration inputs: negative, decimal, text, and objects are rejected", () => {
  rejects({ durationDays: -1 }, DURATION);
  rejects({ durationDays: 1.5 }, DURATION);
  rejects({ durationDays: "abc" }, DURATION);
  rejects({ durationDays: {} }, DURATION);
});

test("a blank duration means permanent", () => {
  assert.equal(check({ durationDays: "" }).durationDays, null);
  assert.equal(check({ durationDays: null }).durationDays, null);
  assert.equal(check({ durationDays: undefined }).durationDays, null);
});

test("the requester is always the signed-in user, even if the input names someone else", () => {
  const clean = validateRequest({ ...good, requester: "someone.else" }, { user, now: NOW });
  assert.equal(clean.requester, user);
});

test("justification: 1000 characters is accepted, 1001 is rejected", () => {
  assert.equal(check({ justification: "x".repeat(1000) }).justification.length, 1000);
  rejects({ justification: "x".repeat(1001) }, "1000 characters");
});

test("last login: today is accepted; tomorrow, wrong format, and non-dates are rejected", () => {
  assert.equal(check({ lastLogin: "2026-11-07" }).lastLogin, "2026-11-07");
  rejects({ lastLogin: "2026-11-08" }, "past date");
  rejects({ lastLogin: "2026/11/07" }, "past date");
  rejects({ lastLogin: "not-a-date" }, "past date");
});

test("job titles that aren't in the list are rejected, including inherited names", () => {
  for (const title of ["__proto__", "constructor", "toString", "software engineer"]) {
    rejects({ jobTitle: title }, "known job title");
  }
});

test("roles: empty, non-list, unknown, and inherited names are rejected; duplicates collapse", () => {
  rejects({ requestedRoles: [] }, "at least one role");
  rejects({ requestedRoles: "repo-read" }, "at least one role");
  rejects({ requestedRoles: ["nope"] }, "Unknown roles");
  rejects({ requestedRoles: ["toString"] }, "Unknown roles");
  assert.equal(check({ requestedRoles: ["repo-read", "repo-read"] }).requestedRoles.length, 1);
});

test("employment type is case-sensitive and must be employee or contractor", () => {
  rejects({ employmentType: "Employee" }, "employee or contractor");
});

test("approver: one character is rejected; blank means none", () => {
  rejects({ approver: "x" }, "Approver must be");
  assert.equal(check({ approver: "" }).approver, null);
  assert.equal(check({ approver: "boss.one" }).approver, "boss.one");
});
