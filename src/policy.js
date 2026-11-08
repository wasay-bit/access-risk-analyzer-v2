// Policy: the rules the analyzer uses. Every value here is illustrative,
// not a real company's policy. Change the numbers here to change behavior.

export const DAY_MS = 24 * 60 * 60 * 1000;

// Roles a job normally needs. Anything requested beyond this is "over-scope".
export const BASELINE = {
  "Software Engineer": ["repo-read", "repo-write", "staging-deploy"],
  "Support Analyst": ["ticket-read", "ticket-write"],
  "Finance Analyst": ["erp-read", "expense-approve"],
  "Security Analyst": ["siem-read", "edr-read", "ticket-write"],
  "HR Specialist": ["hris-read", "hris-write"],
};

// What each role is and how risky it is on its own.
//   sensitive: touches sensitive data (people data, money, production)
//   privileged: admin-level, affects many systems at once
export const ROLE_INFO = {
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

// Score thresholds, highest first. The first row whose min is <= the score wins.
export const LEVELS = [
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

export const MAX_DURATION_DAYS = 365;
export const LONG_DURATION_DAYS = 90;
export const DORMANT_DAYS = 90;
export const MIN_JUSTIFICATION = 20;
export const MAX_JUSTIFICATION = 1000;
export const MAX_NOTE = 500;
export const MAX_ROLES = 20;
export const NAME_PATTERN = /^[a-z0-9._-]{2,40}$/i;
export const DATE_PATTERN = /^\d{4}-\d{2}-\d{2}$/;
export const OPEN_STATUSES = ["pending", "escalated"];
export const DECISIONS = ["approve", "deny", "escalate"];

// Plain-object lookups also find inherited names such as "constructor".
// Always check that the key is the object's own property.
export function has(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key);
}

export function roleInfo(role) {
  return has(ROLE_INFO, role) ? ROLE_INFO[role] : {};
}

// High and critical requests need two different approvers. Everything else needs one.
export function requiredApprovals(level) {
  return level === "high" || level === "critical" ? 2 : 1;
}
