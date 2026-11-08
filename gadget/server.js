import { DurableObject } from "cloudflare:workers";

// Access Risk Analyzer: server side.
//
// Stores simulated access requests and an audit log, scores each request
// against a small policy, and records review decisions. All employee data
// here is simulated.

const STATE_KEY = "state";
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_DURATION_DAYS = 365;
const MAX_JUSTIFICATION = 1000;
const MAX_NOTE = 500;
const MAX_ROLES = 20;
const NAME_PATTERN = /^[a-z0-9._-]{2,40}$/i;
const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
const OPEN_STATUSES = ["pending", "escalated"];
const DECISIONS = { approve: "approved", deny: "denied", escalate: "escalated" };

// Plain-object lookups also find inherited names such as "constructor" and
// "toString". Always check that the key is the object's own property.
function has(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

// Roles a job normally needs. Anything requested beyond this is "over-scope".
const BASELINE = {
  "Software Engineer": ["repo-read", "repo-write", "staging-deploy"],
  "Support Analyst": ["ticket-read", "ticket-write"],
  "Finance Analyst": ["erp-read", "expense-approve"],
  "Security Analyst": ["siem-read", "edr-read", "ticket-write"],
  "HR Specialist": ["hris-read", "hris-write"],
};

// What each role is and how risky it is on its own.
//   sensitive: touches sensitive data (people data, money, production)
//   privileged: admin-level, affects many systems at once
const ROLE_INFO = {
  "repo-read": { sensitive: false },
  "repo-write": { sensitive: false },
  "staging-deploy": { sensitive: false },
  "prod-deploy": { sensitive: true },
  "db-admin": { sensitive: true, privileged: true },
  "domain-admin": { sensitive: true, privileged: true },
  "edr-admin": { sensitive: true, privileged: true },
  "edr-read": { sensitive: false },
  "siem-read": { sensitive: false },
  "ticket-read": { sensitive: false },
  "ticket-write": { sensitive: false },
  "erp-read": { sensitive: false },
  "expense-approve": { sensitive: true },
  "payroll-read": { sensitive: true },
  "payroll-write": { sensitive: true, privileged: true },
  "hris-read": { sensitive: true },
  "hris-write": { sensitive: true },
};

// Score thresholds. The first row whose min is <= the score wins.
const LEVELS = [
  {
    min: 60,
    level: "critical",
    action: "Deny by default and escalate to the security team. If approved anyway, two different reviewers must sign off.",
  },
  {
    min: 35,
    level: "high",
    action: "Manual review by the resource owner and the security team. Needs two different approvers.",
  },
  { min: 15, level: "medium", action: "Manual review by the requester's manager." },
  { min: 0, level: "low", action: "Quick approval by one reviewer, keeping the audit trail." },
];

// High and critical requests need two different approvers. Everything else
// needs one.
function requiredApprovals(level) {
  return level === "high" || level === "critical" ? 2 : 1;
}

function roleInfo(role) {
  return has(ROLE_INFO, role) ? ROLE_INFO[role] : {};
}

// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------

// Checks one request against the policy. Returns a score (0-100), a level,
// the findings behind it, and a plain-language explanation.
function analyze(req, now = Date.now()) {
  const findings = [];
  const roles = req.requestedRoles || [];
  const baseline = has(BASELINE, req.jobTitle) ? BASELINE[req.jobTitle] : [];

  // 1. Least privilege: roles the job doesn't normally need.
  const extra = roles.filter((r) => !baseline.includes(r));
  if (extra.length) {
    findings.push({
      id: "over-scope",
      weight: Math.min(30, 10 * extra.length),
      title: "Roles beyond the job's baseline",
      detail: `${req.jobTitle} roles don't normally include: ${extra.join(", ")}.`,
      fix: "Remove roles outside the job's baseline, or document why each one is needed.",
    });
  }

  // 2. Privileged (admin-level) roles.
  const privileged = roles.filter((r) => roleInfo(r).privileged);
  if (privileged.length) {
    findings.push({
      id: "privileged",
      weight: 25,
      forceHigh: true,
      title: "Privileged role requested",
      detail: `Admin-level access: ${privileged.join(", ")}. Misuse or a mistake here can affect many systems.`,
      fix: "Use time-limited, just-in-time elevation instead of standing admin access.",
    });
  }

  // 3. Sensitive data, excluding roles already counted as privileged.
  const sensitive = roles.filter((r) => roleInfo(r).sensitive && !roleInfo(r).privileged);
  if (sensitive.length) {
    findings.push({
      id: "sensitive",
      weight: Math.min(20, 8 * sensitive.length),
      title: "Sensitive data access",
      detail: `Touches sensitive data: ${sensitive.join(", ")}.`,
      fix: "Limit access to the data the job actually needs.",
    });
  }

  // 4. Contractors with sensitive access.
  if (req.employmentType === "contractor" && roles.some((r) => roleInfo(r).sensitive)) {
    findings.push({
      id: "contractor",
      weight: 20,
      title: "Contractor requesting sensitive access",
      detail: "Contractors usually need explicit owner sign-off and a shorter review cycle.",
      fix: "Get explicit sign-off from the internal owner and set a shorter end date.",
    });
  }

  // 5. Time limits.
  if (req.durationDays == null) {
    findings.push({
      id: "permanent",
      weight: 15,
      title: "Permanent access",
      detail: "No end date was given. Access should be time-limited and re-checked.",
      fix: "Set an end date and re-certify the access regularly.",
    });
  } else if (req.durationDays > 90) {
    findings.push({
      id: "long-duration",
      weight: 10,
      title: "Long access window",
      detail: `Requested for ${req.durationDays} days.`,
      fix: "Shorten the request to 90 days or less, and renew if still needed.",
    });
  }

  // 6. Justification quality. A very short reason can't be reviewed.
  if ((req.justification || "").trim().length < 20) {
    findings.push({
      id: "weak-justification",
      weight: 15,
      title: "Thin justification",
      detail: "The business reason is missing or too short to review.",
      fix: "Explain the specific business need and the task it supports.",
    });
  }

  // 7. Dormant account: the person hasn't logged in for a long time.
  if (req.lastLogin) {
    const days = Math.floor((now - Date.parse(req.lastLogin)) / DAY_MS);
    if (days > 90) {
      findings.push({
        id: "dormant",
        weight: 15,
        title: "Dormant account",
        detail: `Last login was ${days} days ago.`,
        fix: "Confirm the person still needs access, or disable the account.",
      });
    }
  }

  // 8. Separation of duties: the requester is also the approver.
  if (req.approver && req.approver.trim().toLowerCase() === req.requester.trim().toLowerCase()) {
    findings.push({
      id: "self-approval",
      weight: 30,
      title: "Requester is the approver",
      detail: "Separation of duties is broken. Someone else must approve this.",
      fix: "Have a different person approve this request.",
    });
  }

  // 9. A toxic combination: one person can change code and push it to production.
  if (roles.includes("prod-deploy") && roles.includes("repo-write")) {
    findings.push({
      id: "write-and-deploy",
      weight: 15,
      title: "Can change code and deploy it",
      detail: "Without a review step, one person could ship unreviewed changes to production.",
      fix: "Split these roles between two people, or require a code review before deploy.",
    });
  }

  // The sum can exceed 100, so it is capped here.
  const score = Math.min(100, findings.reduce((sum, f) => sum + f.weight, 0));
  let band = LEVELS.find((l) => score >= l.min);
  // Privileged access is always at least "high", whatever the score.
  if (findings.some((f) => f.forceHigh) && (band.level === "low" || band.level === "medium")) {
    band = LEVELS.find((l) => l.level === "high");
  }

  const analysis = {
    score,
    level: band.level,
    action: band.action,
    requiredApprovals: requiredApprovals(band.level),
    findings,
    baselineRoles: baseline,
    extraRoles: extra,
  };
  analysis.explanation = explain(req, analysis);
  return analysis;
}

// Builds the explanation text.
//
// This is rule-based: it turns the findings into sentences. It is not a live
// AI model. To use a real model, replace the body of this function with a
// model call that returns text, and keep the same return type (a string).
function explain(req, a) {
  const roles = req.requestedRoles || [];
  const lines = [];
  lines.push(
    `${req.requester} asks for ${roles.length} role${roles.length === 1 ? "" : "s"} (${roles.join(", ")}) as ${req.jobTitle}.`
  );

  if (a.findings.length === 0) {
    lines.push(
      "Everything here matches the usual access for this job, the time limit is reasonable, and the justification is clear. A quick approval by one reviewer is reasonable."
    );
    return lines.join("\n");
  }

  lines.push(`The main concern${a.findings.length > 1 ? "s are" : " is"}: ${a.findings.map((f) => f.title.toLowerCase()).join("; ")}.`);
  for (const f of a.findings.slice(0, 3)) lines.push(`- ${f.title}: ${f.detail}`);
  lines.push(`Overall risk is ${a.level} (score ${a.score}/100). Recommended action: ${a.action}`);
  const fixes = a.findings.map((f) => f.fix).filter(Boolean);
  if (fixes.length) lines.push(`To lower the risk: ${fixes.join(" ")}`);
  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

// Checks a new request and returns a cleaned copy. Throws a readable error
// for the first problem found.
function validateRequest(input) {
  const requester = String(input.requester ?? "").trim();
  if (!requester) throw new Error("Requester is required.");
  if (!NAME_PATTERN.test(requester)) {
    throw new Error("Requester must be 2-40 characters: letters, numbers, dots, dashes, or underscores.");
  }

  const approver = String(input.approver ?? "").trim();
  if (approver && !NAME_PATTERN.test(approver)) {
    throw new Error("Approver must be 2-40 characters: letters, numbers, dots, dashes, or underscores.");
  }

  const jobTitle = String(input.jobTitle ?? "");
  if (!has(BASELINE, jobTitle)) throw new Error("Pick a known job title.");

  if (input.employmentType !== "employee" && input.employmentType !== "contractor") {
    throw new Error("Employment type must be employee or contractor.");
  }

  if (!Array.isArray(input.requestedRoles)) throw new Error("Pick at least one role.");
  const roles = [...new Set(input.requestedRoles)];
  if (roles.length === 0) throw new Error("Pick at least one role.");
  if (roles.length > MAX_ROLES) throw new Error(`Pick no more than ${MAX_ROLES} roles.`);
  const unknown = roles.filter((r) => typeof r !== "string" || !has(ROLE_INFO, r));
  if (unknown.length) throw new Error(`Unknown roles: ${unknown.map(String).join(", ")}`);

  let durationDays = null;
  if (input.durationDays !== null && input.durationDays !== undefined && input.durationDays !== "") {
    const n = Number(input.durationDays);
    if (!Number.isInteger(n) || n < 1 || n > MAX_DURATION_DAYS) {
      throw new Error(`Duration must be a whole number of days from 1 to ${MAX_DURATION_DAYS}, or blank for permanent.`);
    }
    durationDays = n;
  }

  let lastLogin = null;
  if (input.lastLogin) {
    const s = String(input.lastLogin);
    const t = Date.parse(s);
    if (!DATE_PATTERN.test(s) || Number.isNaN(t) || t > Date.now()) {
      throw new Error("Last login must be a past date in YYYY-MM-DD format, or left blank.");
    }
    lastLogin = s;
  }

  const justification = String(input.justification ?? "").trim();
  if (justification.length > MAX_JUSTIFICATION) {
    throw new Error(`Justification must be ${MAX_JUSTIFICATION} characters or fewer.`);
  }

  return {
    requester,
    approver: approver || null,
    jobTitle,
    employmentType: input.employmentType,
    requestedRoles: roles,
    durationDays,
    lastLogin,
    justification,
  };
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

async function load(storage) {
  return (await storage.get(STATE_KEY)) ?? { requests: {}, audit: [], nextId: 1 };
}

async function save(storage, state) {
  await storage.put(STATE_KEY, state);
}

function addAudit(state, entry) {
  state.audit.unshift({ at: new Date().toISOString(), ...entry });
  if (state.audit.length > 500) state.audit.length = 500;
}

// ---------------------------------------------------------------------------
// Demo data (all simulated)
// ---------------------------------------------------------------------------

function demoRequests(now) {
  const daysAgo = (d) => new Date(now - d * DAY_MS).toISOString();
  return [
    {
      requester: "priya.n",
      jobTitle: "Software Engineer",
      employmentType: "employee",
      requestedRoles: ["repo-read", "repo-write", "staging-deploy"],
      durationDays: 30,
      lastLogin: daysAgo(2),
      approver: "dan.lee",
      justification: "Working on the checkout service for the Q4 release. Needs write access to the repo and staging deploys.",
    },
    {
      requester: "marcus.t",
      jobTitle: "Support Analyst",
      employmentType: "employee",
      requestedRoles: ["ticket-read", "ticket-write", "payroll-read"],
      durationDays: null,
      lastLogin: daysAgo(5),
      approver: "ana.r",
      justification: "Need access to help with tickets.",
    },
    {
      requester: "chen.w",
      jobTitle: "Software Engineer",
      employmentType: "contractor",
      requestedRoles: ["repo-write", "prod-deploy", "db-admin"],
      durationDays: 180,
      lastLogin: daysAgo(1),
      approver: "chen.w",
      justification: "Contract work on the data migration. Needs production access to run it.",
    },
    {
      requester: "alex.k",
      jobTitle: "Finance Analyst",
      employmentType: "employee",
      requestedRoles: ["erp-read", "expense-approve"],
      durationDays: 60,
      lastLogin: daysAgo(200),
      approver: "rachel.s",
      justification: "Month-end close support for the Q4 reconciliations.",
    },
    {
      requester: "sam.o",
      jobTitle: "Security Analyst",
      employmentType: "employee",
      requestedRoles: ["siem-read", "edr-admin", "ticket-write"],
      durationDays: 14,
      lastLogin: daysAgo(0),
      approver: "lee.m",
      justification: "Investigating a suspected endpoint incident (INC-1042) and need to isolate hosts.",
    },
    {
      requester: "jordan.p",
      jobTitle: "HR Specialist",
      employmentType: "employee",
      requestedRoles: ["hris-read", "hris-write", "payroll-read"],
      durationDays: 60,
      lastLogin: daysAgo(3),
      approver: "maya.c",
      justification: "Covering onboarding for the new hire cohort, including payroll setup checks.",
    },
  ];
}

// ---------------------------------------------------------------------------
// The Gadget
// ---------------------------------------------------------------------------

export class Gadget extends DurableObject {
  // Adds the simulated requests, but only if there are none yet.
  async seedDemo() {
    const state = await load(this.ctx.storage);
    if (Object.keys(state.requests).length > 0) return { added: 0 };
    const now = Date.now();
    const demo = demoRequests(now);
    for (const r of demo) {
      const id = `AR-${String(state.nextId++).padStart(4, "0")}`;
      state.requests[id] = { id, ...r, status: "pending", approvals: [], createdAt: new Date(now).toISOString() };
    }
    addAudit(state, { actor: "system", action: "seed-demo", detail: "Loaded simulated requests" });
    await save(this.ctx.storage, state);
    return { added: demo.length };
  }

  // Validates and stores a new request.
  async submitRequest(input) {
    const clean = validateRequest(input ?? {});
    const state = await load(this.ctx.storage);
    const id = `AR-${String(state.nextId++).padStart(4, "0")}`;
    state.requests[id] = {
      id,
      ...clean,
      status: "pending",
      approvals: [],
      createdAt: new Date().toISOString(),
    };
    addAudit(state, {
      actor: clean.requester,
      action: "submit",
      requestId: id,
      detail: `Requested ${clean.requestedRoles.join(", ")}`,
    });
    await save(this.ctx.storage, state);
    return { id };
  }

  // Returns every request with its analysis, highest score first.
  async listRequests() {
    const state = await load(this.ctx.storage);
    const now = Date.now();
    return Object.values(state.requests)
      .map((r) => ({ ...r, approvals: r.approvals || [], analysis: analyze(r, now) }))
      .sort((a, b) => b.analysis.score - a.analysis.score);
  }

  // Records a review decision and enforces the review rules:
  //   - only open requests (pending or escalated) can change
  //   - the requester can't review their own request
  //   - high and critical requests need two different approvers
  //   - one reviewer can approve a request only once
  async decide(id, decision, reviewerInput, noteInput) {
    if (!has(DECISIONS, decision)) throw new Error("Decision must be approve, deny, or escalate.");

    const reviewer = String(reviewerInput ?? "").trim();
    if (!NAME_PATTERN.test(reviewer)) {
      throw new Error("Reviewer name must be 2-40 characters: letters, numbers, dots, dashes, or underscores.");
    }
    const note = String(noteInput ?? "").trim();
    if (note.length > MAX_NOTE) throw new Error(`Note must be ${MAX_NOTE} characters or fewer.`);

    const state = await load(this.ctx.storage);
    if (!has(state.requests, id)) throw new Error(`No request ${id}.`);
    const req = state.requests[id];

    if (!OPEN_STATUSES.includes(req.status)) {
      throw new Error(`${id} is already ${req.status}. Decisions can't be changed.`);
    }
    const same = (a, b) => a.trim().toLowerCase() === b.trim().toLowerCase();
    if (same(reviewer, req.requester)) throw new Error("Requesters can't review their own request.");

    const analysis = analyze(req);
    const required = analysis.requiredApprovals;
    const now = new Date().toISOString();
    req.approvals = req.approvals || [];
    let againstRecommendation = false;

    if (decision === "approve") {
      if (req.approvals.some((a) => same(a.reviewer, reviewer))) {
        throw new Error("This reviewer has already approved this request.");
      }
      req.approvals.push({ reviewer, at: now, note });
      againstRecommendation = analysis.level === "critical";
      if (req.approvals.length >= required) {
        req.status = "approved";
        req.decidedBy = reviewer;
        req.decidedAt = now;
        req.decisionNote = note;
      }
    } else if (decision === "deny") {
      req.status = "denied";
      req.decidedBy = reviewer;
      req.decidedAt = now;
      req.decisionNote = note;
    } else {
      req.status = "escalated";
    }

    const progress = decision === "approve" ? ` Approval ${req.approvals.length} of ${required}.` : "";
    addAudit(state, {
      actor: reviewer,
      action: decision,
      requestId: id,
      detail:
        (againstRecommendation ? "Approved a critical-risk request, against the recommendation. " : "") +
        `Score ${analysis.score}, level ${analysis.level}.${progress}` +
        (note ? ` Note: ${note}` : ""),
    });
    await save(this.ctx.storage, state);

    return {
      id,
      decision,
      status: req.status,
      approvals: req.approvals.length,
      required,
      againstRecommendation,
    };
  }

  // The audit log, newest first.
  async getAudit(limit = 100) {
    const state = await load(this.ctx.storage);
    const n = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 500) : 100;
    return state.audit.slice(0, n);
  }

  // The policy the analyzer uses, so people can see the rules.
  async getPolicy() {
    return {
      baseline: BASELINE,
      roles: ROLE_INFO,
      levels: LEVELS.map(({ level, min, action }) => ({ level, min, action })),
    };
  }
}
