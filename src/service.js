// The application logic: stores requests and the audit log, and runs every
// change through the same checks. The HTTP layer calls these methods.

import { analyze } from "./analyze.js";
import { validateRequest } from "./validate.js";
import { applyDecision, ReviewError } from "./review.js";
import { demoRequests } from "./demo.js";
import { LEVELS, BASELINE, ROLE_INFO } from "./policy.js";

const MAX_AUDIT = 500;

function emptyState() {
  return { requests: {}, audit: [], nextId: 1 };
}

export class AccessRiskService {
  // store: an object with async read() and write(value).
  // now: returns the current time in milliseconds (replaceable in tests).
  constructor({ store, now = () => Date.now() }) {
    this.store = store;
    this.now = now;
    this.queue = Promise.resolve();
  }

  // Runs one write at a time, so two requests can't overwrite each other.
  serial(task) {
    const run = this.queue.then(task);
    this.queue = run.catch(() => {});
    return run;
  }

  async read() {
    return (await this.store.read()) ?? emptyState();
  }

  addAudit(state, entry) {
    state.audit.unshift({ at: new Date(this.now()).toISOString(), ...entry });
    if (state.audit.length > MAX_AUDIT) state.audit.length = MAX_AUDIT;
  }

  nextId(state) {
    return `AR-${String(state.nextId++).padStart(4, "0")}`;
  }

  seedDemo() {
    return this.serial(async () => {
      const state = await this.read();
      if (Object.keys(state.requests).length > 0) return { added: 0 };
      const demo = demoRequests(this.now());
      for (const r of demo) {
        const id = this.nextId(state);
        state.requests[id] = {
          id,
          ...r,
          status: "pending",
          approvals: [],
          createdAt: new Date(this.now()).toISOString(),
        };
      }
      this.addAudit(state, { actor: "system", action: "seed-demo", detail: `Loaded ${demo.length} simulated requests` });
      await this.store.write(state);
      return { added: demo.length };
    });
  }

  submit(user, input) {
    return this.serial(async () => {
      const clean = validateRequest(input, { user, now: this.now() });
      const state = await this.read();
      const id = this.nextId(state);
      state.requests[id] = {
        id,
        ...clean,
        status: "pending",
        approvals: [],
        createdAt: new Date(this.now()).toISOString(),
      };
      this.addAudit(state, {
        actor: user,
        action: "submit",
        requestId: id,
        detail: `Requested ${clean.requestedRoles.join(", ")}`,
      });
      await this.store.write(state);
      return { id };
    });
  }

  // Every request with its analysis, highest score first.
  async list() {
    const state = await this.read();
    const now = this.now();
    return Object.values(state.requests)
      .map((r) => ({ ...r, approvals: r.approvals ?? [], analysis: analyze(r, now) }))
      .sort((a, b) => b.analysis.score - a.analysis.score || a.id.localeCompare(b.id));
  }

  // The reviewer is always the signed-in user. The body supplies only the decision and note.
  decide(user, id, body) {
    return this.serial(async () => {
      const state = await this.read();
      const found = Object.prototype.hasOwnProperty.call(state.requests, id);
      const decision = body?.decision;
      const note = body?.note;
      let outcome;
      try {
        if (!found) throw new ReviewError("NOT_FOUND", 404, `No request ${String(id).slice(0, 40)}.`);
        outcome = applyDecision(state.requests[id], { decision, reviewer: user, note, now: this.now() });
      } catch (err) {
        if (err instanceof ReviewError) {
          this.addAudit(state, {
            actor: user,
            action: "decision-rejected",
            requestId: String(id).slice(0, 40),
            detail: `${String(decision).slice(0, 20)} refused: ${err.message}`,
          });
          await this.store.write(state);
        }
        throw err;
      }
      state.requests[id] = outcome.request;
      this.addAudit(state, outcome.audit);
      await this.store.write(state);
      return outcome.result;
    });
  }

  async audit(limit = 100) {
    const state = await this.read();
    const n = Number.isInteger(limit) && limit > 0 ? Math.min(limit, MAX_AUDIT) : 100;
    return state.audit.slice(0, n);
  }

  policy() {
    return {
      baseline: BASELINE,
      roles: ROLE_INFO,
      levels: LEVELS.map(({ level, min, action }) => ({ level, min, action })),
    };
  }
}
