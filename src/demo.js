// Simulated requests for trying the app. None of these people or details are real.

const DAY_MS = 24 * 60 * 60 * 1000;

export function demoRequests(now) {
  const daysAgo = (d) => new Date(now - d * DAY_MS).toISOString().slice(0, 10);
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
