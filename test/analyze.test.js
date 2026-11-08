import { test } from "node:test";
import assert from "node:assert/strict";
import { analyze } from "../src/analyze.js";

// Fixed clock: 2026-11-07 12:00 UTC.
const NOW = Date.parse("2026-11-07T12:00:00Z");

const base = {
  requester: "tester.one",
  jobTitle: "Software Engineer",
  employmentType: "employee",
  requestedRoles: ["repo-read"],
  durationDays: 30,
  lastLogin: "2026-11-06",
  approver: "boss.one",
  justification: "A sufficiently long business justification.",
};
const run = (over) => analyze({ ...base, ...over }, NOW);
const flags = (a) => a.findings.map((f) => f.id);

test("a clean request scores 0, is low, and needs one approver", () => {
  const a = run({});
  assert.equal(a.score, 0);
  assert.equal(a.level, "low");
  assert.equal(a.requiredApprovals, 1);
  assert.deepEqual(a.findings, []);
});

test("permanent access scores 15 and is medium", () => {
  const a = run({ durationDays: null });
  assert.equal(a.score, 15);
  assert.equal(a.level, "medium");
  assert.deepEqual(flags(a), ["permanent"]);
});

test("one admin role on a normal job scores 35 and is high, needing two approvers", () => {
  const a = run({ requestedRoles: ["repo-read", "db-admin"] });
  assert.equal(a.score, 35);
  assert.equal(a.level, "high");
  assert.equal(a.requiredApprovals, 2);
});

test("a contractor with production and admin access scores 73 and is critical", () => {
  const a = run({ employmentType: "contractor", requestedRoles: ["prod-deploy", "db-admin"] });
  assert.equal(a.score, 73);
  assert.equal(a.level, "critical");
  assert.equal(a.requiredApprovals, 2);
});

test("any privileged role makes the request at least high", () => {
  for (const role of ["db-admin", "domain-admin", "edr-admin", "payroll-write"]) {
    const a = run({ requestedRoles: ["repo-read", role] });
    assert.ok(["high", "critical"].includes(a.level), `${role} gave ${a.level}`);
  }
});

test("long access: 90 days is not flagged, 91 days is", () => {
  assert.ok(!flags(run({ durationDays: 90 })).includes("long-duration"));
  assert.ok(flags(run({ durationDays: 91 })).includes("long-duration"));
});

test("thin justification: 19 characters is flagged, 20 is not", () => {
  assert.ok(flags(run({ justification: "x".repeat(19) })).includes("weak-justification"));
  assert.ok(!flags(run({ justification: "x".repeat(20) })).includes("weak-justification"));
});

test("dormant account: 90 days is not flagged, 91 days is", () => {
  // The clock is 2026-11-07 12:00 UTC. A login on 2026-08-09 is 90.5 days earlier,
  // and a login on 2026-08-08 is 91.5 days earlier.
  assert.ok(!flags(run({ lastLogin: "2026-08-09" })).includes("dormant"));
  assert.ok(flags(run({ lastLogin: "2026-08-08" })).includes("dormant"));
});

test("the score is capped at 100 even when every rule fires", () => {
  const a = run({
    employmentType: "contractor",
    requestedRoles: ["repo-write", "prod-deploy", "db-admin"],
    durationDays: null,
    justification: "",
    lastLogin: "2026-04-21",
    approver: "tester.one",
  });
  const uncapped = a.findings.reduce((sum, f) => sum + f.weight, 0);
  assert.equal(uncapped, 163);
  assert.equal(a.score, 100);
  assert.equal(a.level, "critical");
});

test("the same input always gives the same result", () => {
  const input = { ...base, requestedRoles: ["repo-read", "edr-admin"], employmentType: "contractor" };
  assert.deepEqual(analyze(input, NOW), analyze(input, NOW));
});

test("scores stay in 0-100, and levels and approver counts follow the thresholds, across 500 generated requests", () => {
  let seed = 42;
  const rand = () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const pick = (xs) => xs[Math.floor(rand() * xs.length)];
  const jobs = ["Software Engineer", "Support Analyst", "Finance Analyst", "Security Analyst", "HR Specialist"];
  const roles = [
    "repo-read", "repo-write", "staging-deploy", "prod-deploy", "db-admin", "domain-admin", "edr-admin",
    "edr-read", "siem-read", "ticket-read", "ticket-write", "erp-read", "expense-approve", "payroll-read",
    "payroll-write", "hris-read", "hris-write",
  ];
  const privilegedRoles = ["db-admin", "domain-admin", "edr-admin", "payroll-write"];
  const byScore = (s) => (s >= 60 ? "critical" : s >= 35 ? "high" : s >= 15 ? "medium" : "low");

  for (let i = 0; i < 500; i++) {
    const picked = new Set();
    const n = 1 + Math.floor(rand() * 6);
    while (picked.size < n) picked.add(pick(roles));
    const a = analyze(
      {
        requester: `rnd${i}`,
        jobTitle: pick(jobs),
        employmentType: pick(["employee", "contractor"]),
        requestedRoles: [...picked],
        durationDays: pick([null, 1, 30, 91, 365]),
        justification: "x".repeat(Math.floor(rand() * 41)),
        lastLogin: pick([null, "2026-01-01"]),
        approver: pick([null, "other.person"]),
      },
      NOW
    );
    assert.ok(Number.isInteger(a.score) && a.score >= 0 && a.score <= 100, `score ${a.score}`);
    const privileged = [...picked].some((r) => privilegedRoles.includes(r));
    let expected = byScore(a.score);
    if (privileged && (expected === "low" || expected === "medium")) expected = "high";
    assert.equal(a.level, expected);
    assert.equal(a.requiredApprovals, expected === "high" || expected === "critical" ? 2 : 1);
  }
});
