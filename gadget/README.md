# Access Risk Analyzer (Cloudflare OS Gadget version)

> **Practice project.** Written by AI (Claude) to test Cloudflare OS. Not a production tool and not based on any real company's systems or data.

This folder is the same app as the rest of the repo, built as a Cloudflare OS Gadget. It runs only inside Cloudflare OS, not on your computer. To run it locally, use the standalone project in the root of this repo.

## Files

- `server.js`: the policy, scoring, input checks, review rules, storage, and audit log. Stored in Cloudflare OS's Durable Object storage.
- `client.js`: the browser interface, built with plain JavaScript and no build step.
- `sample-data.json`: a read-only snapshot of the Gadget's data (simulated) for reference. The Gadget does not load this file.

## Data

The Gadget's data lives in its own storage, not in this repo. The snapshot here has six simulated access requests (all pending) and one audit entry from setup. To recreate a record, copy its details into the Submit form.

## Differences from the standalone project

- Sign-in: the Gadget has no tokens. Reviewers type their own name.
- Storage: Durable Object storage instead of `data/state.json`.
- The rules, scores, and review checks are the same.

## Known limits

- Reviewer names are typed, not verified. Anyone can type any name, so the two-approver rule relies on people being honest.
- The explanations are rule-based text, not a live AI model.
- All data is simulated. Don't enter real employee names or access details.
