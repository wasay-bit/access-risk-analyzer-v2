// Access Risk Analyzer: browser side.
//
// Shows a queue of simulated access requests, each with a risk score,
// findings, a least-privilege comparison, and an explanation. Reviewers
// record decisions; high and critical requests need two approvers. Every
// decision is written to the audit log.

// Small helper for building DOM nodes safely (text is never parsed as HTML).
function h(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return node;
}

// Risk badge colors. These mark severity, so they stay separate from the
// blue-and-orange page theme.
const LEVEL_COLORS = { low: "#1565c0", medium: "#fb923c", high: "#c2410c", critical: "#7c2d12" };
const LEVEL_TEXT = { low: "#fff", medium: "#14213d", high: "#fff", critical: "#fff" };
const OPEN = ["pending", "escalated"];

const style = h("style", {}, `
  body { font-family: system-ui, sans-serif; margin: 0; background: #f3f7fc; color: #14213d; }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 16px; }
  header { background: #1565c0; color: #fff; border-radius: 12px; padding: 12px 16px; display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px; margin-bottom: 12px; }
  h1 { font-size: 20px; margin: 0; }
  header nav button { margin-left: 4px; background: transparent; color: #fff; border-color: rgba(255,255,255,.6); }
  header nav button.active { background: #fff; color: #1565c0; border-color: #fff; }
  button { font: inherit; padding: 8px 12px; border-radius: 6px; border: 1px solid #90b4e0; background: #fff; color: #0d47a1; cursor: pointer; }
  button:hover { background: #e8f2fd; }
  button.primary { background: #c2410c; border-color: #c2410c; color: #fff; }
  button.primary:hover { background: #9a3412; }
  button.danger { color: #b42318; border-color: #f0b4ae; }
  button:disabled { opacity: .5; cursor: default; }
  .panel { background: #fff; border: 1px solid #cfdcea; border-radius: 10px; padding: 16px; margin-bottom: 12px; }
  .grid { display: grid; grid-template-columns: 1.2fr 1fr; gap: 12px; }
  @media (max-width: 800px) { .grid { grid-template-columns: 1fr; } }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 8px; border-bottom: 1px solid #e3ebf5; vertical-align: top; }
  th { color: #0d47a1; }
  tr.row { cursor: pointer; }
  tr.row:hover { background: #eef5ff; }
  tr.selected { background: #fff1e6; }
  tr.selected td:first-child { box-shadow: inset 4px 0 0 #c2410c; }
  .badge { display: inline-block; color: #fff; border-radius: 999px; padding: 2px 8px; font-size: 12px; font-weight: 600; }
  .muted { color: #4a5b78; font-size: 13px; }
  .explain { white-space: pre-wrap; background: #eef5ff; border-left: 4px solid #1565c0; border-radius: 8px; padding: 12px; font-size: 14px; line-height: 1.5; }
  .finding { border-left: 4px solid #90b4e0; padding: 6px 10px; margin: 8px 0; }
  .finding.forced { border-left-color: #c2410c; }
  .finding .w { float: right; font-weight: 600; color: #4a5b78; }
  .approvals { background: #fff7ed; border-left: 4px solid #c2410c; border-radius: 8px; padding: 10px 12px; margin: 10px 0; font-size: 14px; }
  label.field { display: block; font-size: 14px; margin: 10px 0; }
  label.field input, label.field select, label.field textarea { display: block; width: 100%; box-sizing: border-box; padding: 8px; font: inherit; border: 1px solid #b6c9e0; border-radius: 6px; margin-top: 4px; background: #fff; }
  input:focus, select:focus, textarea:focus { outline: 2px solid #1565c0; outline-offset: 1px; }
  .roles { display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 6px; }
  .roles label { font-size: 14px; display: flex; gap: 6px; align-items: center; }
  .msg { font-size: 14px; min-height: 20px; margin-top: 8px; }
  .msg.err { color: #b42318; }
  .msg.ok { color: #0d47a1; }
`);
document.head.appendChild(style);

const app = h("div", { class: "wrap" });
document.body.appendChild(app);

let view = "queue";
let requests = [];
let selectedId = null;
let policy = null;
let message = { text: "", kind: "" };

function setMessage(text, kind = "") {
  message = { text, kind };
}

function levelBadge(level) {
  return h("span", { class: "badge", style: `background:${LEVEL_COLORS[level]};color:${LEVEL_TEXT[level]}` }, level);
}

async function refresh() {
  requests = await gadget.listRequests();
  if (!policy) policy = await gadget.getPolicy();
}

function statusText(r) {
  const needed = r.analysis.requiredApprovals;
  if (OPEN.includes(r.status) && needed > 1) {
    return `${r.status} (${r.approvals.length} of ${needed} approvals)`;
  }
  return r.status;
}

// ---------------------------------------------------------------------------
// Queue view
// ---------------------------------------------------------------------------

function queueView() {
  const wrap = h("div");
  if (requests.length === 0) {
    wrap.append(
      h("div", { class: "panel" },
        h("p", {}, "No requests yet."),
        h("button", { class: "primary", onclick: async () => { await gadget.seedDemo(); await refresh(); render(); } }, "Load simulated requests")
      )
    );
    return wrap;
  }

  const table = h("table", {},
    h("thead", {}, h("tr", {}, h("th", {}, "Request"), h("th", {}, "Score"), h("th", {}, "Risk"), h("th", {}, "Status"))),
    h("tbody", {},
      requests.map((r) =>
        h("tr", {
          class: `row${r.id === selectedId ? " selected" : ""}`,
          onclick: () => { selectedId = r.id; render(); },
        },
          h("td", {}, h("div", {}, `${r.id} · ${r.requester}`), h("div", { class: "muted" }, `${r.jobTitle}, ${r.employmentType}`)),
          h("td", {}, String(r.analysis.score)),
          h("td", {}, levelBadge(r.analysis.level)),
          h("td", {}, statusText(r))
        )
      )
    )
  );

  const selected = requests.find((r) => r.id === selectedId) || requests[0];
  wrap.append(
    h("div", { class: "grid" },
      h("div", { class: "panel" }, h("h2", { style: "font-size:16px;margin-top:0" }, "Access queue (highest risk first)"), table),
      detailPanel(selected)
    )
  );
  return wrap;
}

function detailPanel(r) {
  const a = r.analysis;
  const needed = a.requiredApprovals;
  const panel = h("div", { class: "panel" });

  panel.append(
    h("h2", { style: "font-size:16px;margin-top:0" }, `${r.id} · ${r.requester}`),
    h("div", { class: "muted" }, `${r.jobTitle} · ${r.employmentType} · ${r.durationDays == null ? "permanent" : r.durationDays + " days"} · approver: ${r.approver || "none"}`),
    h("p", {}, "Justification: ", h("em", {}, r.justification || "(none)")),
    h("p", {}, "Risk: ", levelBadge(a.level), ` score ${a.score}/100`)
  );

  if (OPEN.includes(r.status) || r.status === "approved") {
    panel.append(
      h("div", { class: "approvals" },
        h("strong", {}, needed > 1
          ? `Two different approvers required (${r.approvals.length} of ${needed} so far)`
          : "One approver required"),
        r.approvals.length
          ? h("div", { class: "muted" }, `Approved by: ${r.approvals.map((x) => x.reviewer).join(", ")}`)
          : null
      )
    );
  }

  panel.append(
    h("h3", { style: "font-size:14px" }, "Explanation"),
    h("div", { class: "explain" }, a.explanation),
    h("h3", { style: "font-size:14px" }, "Findings"),
    a.findings.length === 0
      ? h("p", { class: "muted" }, "No findings.")
      : a.findings.map((f) =>
          h("div", { class: `finding${f.forceHigh ? " forced" : ""}` },
            h("span", { class: "w" }, `+${f.weight}`),
            h("strong", {}, f.title), h("div", {}, f.detail),
            h("div", { class: "muted" }, `To lower risk: ${f.fix}`)
          )
        ),
    h("h3", { style: "font-size:14px" }, "Least privilege check"),
    h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Requested role"), h("th", {}, "Usual for this job?"))),
      h("tbody", {},
        r.requestedRoles.map((role) =>
          h("tr", {}, h("td", {}, role), h("td", {}, a.baselineRoles.includes(role) ? "Yes" : "No, review"))
        )
      )
    )
  );

  if (!OPEN.includes(r.status)) {
    panel.append(h("p", { class: "muted", style: "margin-top:12px" },
      `Final: ${r.status} by ${r.decidedBy} on ${new Date(r.decidedAt).toLocaleString()}${r.decisionNote ? ". Note: " + r.decisionNote : ""}`));
    return panel;
  }

  const reviewer = h("input", { type: "text", maxlength: "40", placeholder: "Your name (recorded in the audit log)" });
  const note = h("textarea", { rows: "2", maxlength: "500", placeholder: "Reviewer note (saved to the audit log)" });

  const decide = (decision) => async () => {
    try {
      const res = await gadget.decide(r.id, decision, reviewer.value, note.value);
      if (res.status === "approved") {
        setMessage(
          res.againstRecommendation
            ? "Approved. This is a critical-risk request, so the approval is logged as against the recommendation."
            : "Approved.",
          res.againstRecommendation ? "err" : "ok"
        );
      } else if (res.decision === "approve") {
        setMessage(`Approval ${res.approvals} of ${res.required} recorded. A second, different reviewer is needed.`, "ok");
      } else {
        setMessage(`Request ${res.status}.`, "ok");
      }
      note.value = "";
    } catch (e) {
      setMessage(String(e.message || e), "err");
    }
    await refresh();
    render();
  };

  panel.append(
    h("label", { class: "field" }, "Reviewer", reviewer),
    h("label", { class: "field" }, "Note", note),
    h("p", { class: "muted" }, needed > 1
      ? "This risk level needs two different approvers. Requesters can't review their own request."
      : "Requesters can't review their own request."),
    h("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
      h("button", { class: "primary", onclick: decide("approve") }, "Approve"),
      h("button", { onclick: decide("escalate") }, "Escalate"),
      h("button", { class: "danger", onclick: decide("deny") }, "Deny")
    )
  );
  return panel;
}

// ---------------------------------------------------------------------------
// Submit view
// ---------------------------------------------------------------------------

function submitView() {
  const panel = h("div", { class: "panel" });
  const today = new Date().toISOString().slice(0, 10);
  const fields = {
    requester: h("input", { type: "text", maxlength: "40", placeholder: "e.g. jordan.p" }),
    jobTitle: h("select", {}, Object.keys(policy.baseline).map((t) => h("option", { value: t }, t))),
    employmentType: h("select", {}, h("option", { value: "employee" }, "Employee"), h("option", { value: "contractor" }, "Contractor")),
    durationDays: h("input", { type: "number", min: "1", max: "365", placeholder: "Leave blank for permanent" }),
    lastLogin: h("input", { type: "date", max: today }),
    approver: h("input", { type: "text", maxlength: "40", placeholder: "Who approves this?" }),
    justification: h("textarea", { rows: "3", maxlength: "1000", placeholder: "The business reason and the task it supports" }),
  };
  const roleBoxes = Object.keys(policy.roles).map((role) => ({
    role,
    box: h("input", { type: "checkbox", value: role }),
  }));

  const submit = async () => {
    const requestedRoles = roleBoxes.filter((b) => b.box.checked).map((b) => b.role);
    try {
      const res = await gadget.submitRequest({
        requester: fields.requester.value,
        jobTitle: fields.jobTitle.value,
        employmentType: fields.employmentType.value,
        durationDays: fields.durationDays.value,
        lastLogin: fields.lastLogin.value || null,
        approver: fields.approver.value,
        justification: fields.justification.value,
        requestedRoles,
      });
      selectedId = res.id;
      setMessage(`Submitted as ${res.id}.`, "ok");
      await refresh();
      view = "queue";
      render();
    } catch (e) {
      setMessage(String(e.message || e), "err");
      render();
    }
  };

  panel.append(
    h("h2", { style: "font-size:16px;margin-top:0" }, "Submit a simulated access request"),
    h("p", { class: "muted" }, "Use fake names. The analyzer scores the request as soon as it's submitted."),
    h("label", { class: "field" }, "Requester", fields.requester),
    h("label", { class: "field" }, "Job title", fields.jobTitle),
    h("label", { class: "field" }, "Employment type", fields.employmentType),
    h("label", { class: "field" }, "Duration (days, 1-365)", fields.durationDays),
    h("label", { class: "field" }, "Last login", fields.lastLogin),
    h("label", { class: "field" }, "Approver", fields.approver),
    h("label", { class: "field" }, "Justification", fields.justification),
    h("div", { class: "field" }, "Roles requested",
      h("div", { class: "roles", style: "margin-top:6px" }, roleBoxes.map((b) => h("label", {}, b.box, b.role)))
    ),
    h("button", { class: "primary", onclick: submit }, "Submit request")
  );
  return panel;
}

// ---------------------------------------------------------------------------
// Audit and policy views
// ---------------------------------------------------------------------------

async function auditView() {
  const entries = await gadget.getAudit(200);
  return h("div", { class: "panel" },
    h("h2", { style: "font-size:16px;margin-top:0" }, "Audit history (newest first)"),
    entries.length === 0
      ? h("p", { class: "muted" }, "Nothing logged yet.")
      : h("table", {},
          h("thead", {}, h("tr", {}, h("th", {}, "When"), h("th", {}, "Who"), h("th", {}, "Action"), h("th", {}, "Request"), h("th", {}, "Detail"))),
          h("tbody", {}, entries.map((e) =>
            h("tr", {},
              h("td", { class: "muted" }, new Date(e.at).toLocaleString()),
              h("td", {}, e.actor),
              h("td", {}, e.action),
              h("td", {}, e.requestId || ""),
              h("td", {}, e.detail)
            )
          ))
        )
  );
}

function policyView() {
  return h("div", {},
    h("div", { class: "panel" },
      h("h2", { style: "font-size:16px;margin-top:0" }, "Usual access by job title (baseline)"),
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Job title"), h("th", {}, "Roles"))),
        h("tbody", {}, Object.entries(policy.baseline).map(([t, roles]) => h("tr", {}, h("td", {}, t), h("td", {}, roles.join(", ")))))
      )
    ),
    h("div", { class: "panel" },
      h("h2", { style: "font-size:16px;margin-top:0" }, "Risk levels"),
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Level"), h("th", {}, "From score"), h("th", {}, "Recommended action"))),
        h("tbody", {}, policy.levels.map((l) => h("tr", {}, h("td", {}, levelBadge(l.level)), h("td", {}, String(l.min)), h("td", {}, l.action))))
      )
    )
  );
}

// ---------------------------------------------------------------------------
// Page frame
// ---------------------------------------------------------------------------

const TABS = [
  ["queue", "Queue"],
  ["submit", "Submit"],
  ["audit", "Audit"],
  ["policy", "Policy"],
];

async function render() {
  const header = h("header", {},
    h("h1", {}, "Access Risk Analyzer"),
    h("nav", {}, TABS.map(([id, label]) =>
      h("button", { class: view === id ? "active" : "", onclick: async () => { view = id; await render(); } }, label)
    ))
  );

  let body;
  if (view === "queue") body = queueView();
  else if (view === "submit") body = submitView();
  else if (view === "audit") body = await auditView();
  else body = policyView();

  const msg = message.text ? h("div", { class: `msg ${message.kind}` }, message.text) : null;
  app.replaceChildren(header, msg || "", body, h("p", { class: "muted" }, "All employees and requests here are simulated."));
}

await refresh();
await render();
