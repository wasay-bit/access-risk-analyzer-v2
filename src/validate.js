// Checks a new access request and returns a cleaned copy.

import {
  BASELINE,
  DATE_PATTERN,
  MAX_DURATION_DAYS,
  MAX_JUSTIFICATION,
  MAX_ROLES,
  NAME_PATTERN,
  ROLE_INFO,
  has,
} from "./policy.js";

export class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = "ValidationError";
    this.status = 400;
  }
}

// The requester is always the signed-in user. Any requester field in the input is ignored.
export function validateRequest(input, { user, now = Date.now() }) {
  if (!NAME_PATTERN.test(String(user ?? ""))) throw new ValidationError("Signed-in user name is not valid.");
  const data = input && typeof input === "object" ? input : {};

  const approver = String(data.approver ?? "").trim();
  if (approver && !NAME_PATTERN.test(approver)) {
    throw new ValidationError("Approver must be 2-40 characters: letters, numbers, dots, dashes, or underscores.");
  }

  const jobTitle = String(data.jobTitle ?? "");
  if (!has(BASELINE, jobTitle)) throw new ValidationError("Pick a known job title.");

  if (data.employmentType !== "employee" && data.employmentType !== "contractor") {
    throw new ValidationError("Employment type must be employee or contractor.");
  }

  if (!Array.isArray(data.requestedRoles)) throw new ValidationError("Pick at least one role.");
  const roles = [...new Set(data.requestedRoles)];
  if (roles.length === 0) throw new ValidationError("Pick at least one role.");
  if (roles.length > MAX_ROLES) throw new ValidationError(`Pick no more than ${MAX_ROLES} roles.`);
  const unknown = roles.filter((r) => typeof r !== "string" || !has(ROLE_INFO, r));
  if (unknown.length) throw new ValidationError(`Unknown roles: ${unknown.map(String).join(", ")}`);

  const durationMessage = `Duration must be a whole number of days from 1 to ${MAX_DURATION_DAYS}, or blank for permanent.`;
  let durationDays = null;
  if (data.durationDays !== null && data.durationDays !== undefined && data.durationDays !== "") {
    if (typeof data.durationDays !== "number" && typeof data.durationDays !== "string") throw new ValidationError(durationMessage);
    const n = Number(data.durationDays);
    if (!Number.isInteger(n) || n < 1 || n > MAX_DURATION_DAYS) throw new ValidationError(durationMessage);
    durationDays = n;
  }

  let lastLogin = null;
  if (data.lastLogin) {
    const s = String(data.lastLogin);
    const t = Date.parse(s);
    if (!DATE_PATTERN.test(s) || Number.isNaN(t) || t > now) {
      throw new ValidationError("Last login must be a past date in YYYY-MM-DD format, or left blank.");
    }
    lastLogin = s;
  }

  const justification = String(data.justification ?? "").trim();
  if (justification.length > MAX_JUSTIFICATION) {
    throw new ValidationError(`Justification must be ${MAX_JUSTIFICATION} characters or fewer.`);
  }

  return {
    requester: user,
    approver: approver || null,
    jobTitle,
    employmentType: data.employmentType,
    requestedRoles: roles,
    durationDays,
    lastLogin,
    justification,
  };
}
