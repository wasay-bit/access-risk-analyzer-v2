# Threat model: Access Risk Analyzer

This is a practice project. The threat model shows the kind of thinking a real access-review tool needs, and it says plainly what the project does not protect against.

## What the tool protects

- **Self-approval.** A requester can't approve or deny their own request.
- **Single-person sign-off on high risk.** High and critical requests need two different reviewers.
- **Changing decided requests.** Approved, denied, and locked requests can't be changed.
- **Silent edits.** Every submission and decision is written to an audit log with who, what, when, and why.

## Assets

- The list of access requests and their decisions.
- The audit log.
- Sign-in tokens (standalone version) and the reviewer names used in decisions.

## Actors and threats

| Threat | Example | Current control | Status |
| --- | --- | --- | --- |
| Insider approves own request | Requester enters their own name as reviewer | Name check, case- and space-insensitive | Covered |
| Two-person rule bypassed | One person approves twice under two names | Duplicate check is by name only | **Partial.** Only works if names are tied to real people. |
| Impersonating a reviewer | Typing another person's name in the Gadget | None in the Gadget. Standalone uses one token per person. | **Gap in the Gadget.** Standalone covered only if tokens stay private. |
| Tampering with the audit log | Editing history after the fact | Log is append-only in the code, but not signed or stored elsewhere | **Gap.** Anyone with storage access can edit it. |
| Hiding rejected attempts | Retrying blocked actions without a trace | Standalone logs refused decisions. The Gadget does not. | **Gap in the Gadget.** |
| Malformed input | Huge text, bad dates, odd job titles | Input checks with tested limits | Covered |
| Prototype lookups | Job title "constructor" breaking the scoring | Own-property checks | Covered |
| Token theft (standalone) | Copying a token from another person's browser | Tokens kept in the tab only; server stores hashes | Partial. No token expiry or rotation. |

## Out of scope

- Real identity (single sign-on, multi-factor sign-in).
- Encryption at rest and network security beyond the hosting platform.
- Real employee data. The tool is only for simulated data.
- Scoring accuracy against real-world access incidents. The rules are illustrative.

## Known next steps

1. Tie reviewers to a real sign-in provider, so names can't be typed.
2. Log refused decisions in the Gadget, matching the standalone version.
3. Sign or copy the audit log to a second store, so edits leave a trace.
4. Add token expiry and a way to revoke a token.
