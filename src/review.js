// Applies one review decision to a request and enforces the review rules.
// Pure: it returns a new request and never changes the one it is given.

import { DECISIONS, MAX_NOTE, NAME_PATTERN, OPEN_STATUSES } from "./policy.js";
import { analyze } from "./analyze.js";

export class ReviewError extends Error {
  constructor(code, status, message) {
    super(message);
    this.name = "ReviewError";
    this.code = code;
    this.status = status;
  }
}

const same = (a, b) => a.trim().toLowerCase() === b.trim().toLowerCase();

export function applyDecision(req, { decision, reviewer, note, now }) {
  if (!DECISIONS.includes(decision)) {
    throw new ReviewError("BAD_DECISION", 400, "Decision must be approve, deny, or escalate.");
  }
  const who = String(reviewer ?? "").trim();
  if (!NAME_PATTERN.test(who)) {
    throw new ReviewError("BAD_REVIEWER", 400, "Reviewer name must be 2-40 characters: letters, numbers, dots, dashes, or underscores.");
  }
  const text = String(note ?? "").trim();
  if (text.length > MAX_NOTE) throw new ReviewError("BAD_NOTE", 400, `Note must be ${MAX_NOTE} characters or fewer.`);

  if (!OPEN_STATUSES.includes(req.status)) {
    throw new ReviewError("LOCKED", 409, `${req.id} is already ${req.status}. Decisions can't be changed.`);
  }
  if (same(who, req.requester)) {
    throw new ReviewError("SELF_REVIEW", 403, "Requesters can't review their own request.");
  }

  const analysis = analyze(req, now);
  const required = analysis.requiredApprovals;
  const at = new Date(now).toISOString();
  const next = JSON.parse(JSON.stringify(req));
  next.approvals = Array.isArray(next.approvals) ? next.approvals : [];
  let againstRecommendation = false;

  if (decision === "approve") {
    if (next.approvals.some((a) => same(a.reviewer, who))) {
      throw new ReviewError("DUPLICATE", 409, "This reviewer has already approved this request.");
    }
    next.approvals.push({ reviewer: who, at, note: text });
    againstRecommendation = analysis.level === "critical";
    if (next.approvals.length >= required) {
      next.status = "approved";
      next.decidedBy = who;
      next.decidedAt = at;
      next.decisionNote = text;
    }
  } else if (decision === "deny") {
    next.status = "denied";
    next.decidedBy = who;
    next.decidedAt = at;
    next.decisionNote = text;
  } else {
    next.status = "escalated";
  }

  const progress = decision === "approve" ? ` Approval ${next.approvals.length} of ${required}.` : "";
  const detail =
    (againstRecommendation ? "Approved a critical-risk request, against the recommendation. " : "") +
    `Score ${analysis.score}, level ${analysis.level}.${progress}` +
    (text ? ` Note: ${text}` : "");

  return {
    request: next,
    audit: { at, actor: who, action: decision, requestId: req.id, detail },
    result: {
      id: req.id,
      decision,
      status: next.status,
      approvals: next.approvals.length,
      required,
      againstRecommendation,
    },
  };
}
