// Scores one request. Pure: the same request and clock always give the same result.

import {
  BASELINE,
  DAY_MS,
  DORMANT_DAYS,
  LEVELS,
  LONG_DURATION_DAYS,
  MIN_JUSTIFICATION,
  has,
  requiredApprovals,
  roleInfo,
} from "./policy.js";

export function analyze(req, now = Date.now()) {
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
  } else if (req.durationDays > LONG_DURATION_DAYS) {
    findings.push({
      id: "long-duration",
      weight: 10,
      title: "Long access window",
      detail: `Requested for ${req.durationDays} days.`,
      fix: `Shorten the request to ${LONG_DURATION_DAYS} days or less, and renew if still needed.`,
    });
  }

  // 6. Justification quality. A very short reason can't be reviewed.
  if ((req.justification || "").trim().length < MIN_JUSTIFICATION) {
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
    if (days > DORMANT_DAYS) {
      findings.push({
        id: "dormant",
        weight: 15,
        title: "Dormant account",
        detail: `Last login was ${days} days ago.`,
        fix: "Confirm the person still needs access, or disable the account.",
      });
    }
  }

  // 8. Separation of duties: the requester is also the named approver.
  if (req.approver && req.approver.trim().toLowerCase() === req.requester.trim().toLowerCase()) {
    findings.push({
      id: "self-approval",
      weight: 30,
      title: "Requester is the approver",
      detail: "Separation of duties is broken. Someone else must approve this.",
      fix: "Have a different person approve this request.",
    });
  }

  // 9. A combination that lets one person change code and ship it.
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

// Turns the findings into plain sentences. This is rule-based text, not a
// language model. To use a real model, replace this function and keep the
// same return type (a string).
function explain(req, a) {
  const roles = req.requestedRoles || [];
  const lines = [
    `${req.requester} asks for ${roles.length} role${roles.length === 1 ? "" : "s"} (${roles.join(", ")}) as ${req.jobTitle}.`,
  ];

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
