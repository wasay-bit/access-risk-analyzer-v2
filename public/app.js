// Access Risk Analyzer: browser interface. Talks to the JSON API under /api.
// Every call sends the sign-in token. The server decides who you are from it.

const TOKEN_KEY = "ara-token";
const OPEN = ["pending", "escalated"];
const TABS = [
  ["queue", "Queue"],
  ["submit", "Submit"],
  ["audit", "Audit"],
  ["policy", "Policy"],
];
const app = document.getElementById("app");

const state = {
  token: sessionStorage.getItem(TOKEN_KEY) || "",
  me: null,
  view: "queue",
  requests: [],
  policy: null,
  selectedId: null,
  message: { text: "", kind: "" },
};

// Builds DOM nodes. Text is always inserted as text, never as HTML.
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

async function api(path, { method = "GET", body } = {}) {
  const res = await fetch(path, {
    method,
    headers: {
      authorization: `Bearer ${state.token}`,
      ...(body ? { "content-type": "application/json" } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    // Empty or non-JSON response; handled below.
  }
  if (!res.ok) {
    const err = new Error(data?.error || `Request failed (${res.status}).`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function setMessage(text, kind = "") {
  state.message = { text, kind };
}

function clearSession() {
  sessionStorage.removeItem(TOKEN_KEY);
  state.token = "";
  state.me = null;
  state.requests = [];
  state.policy = null;
}

function signOut(note = "") {
  clearSession();
  setMessage(note, note ? "err" : "");
  render();
}

async function loadAll() {
  [state.policy, state.requests] = await Promise.all([api("/api/policy"), api("/api/requests")]);
}

async function signIn(token) {
  state.token = token;
  state.me = await api("/api/me");
  sessionStorage.setItem(TOKEN_KEY, token);
  await loadAll();
}

function levelBadge(level) {
  return h("span", { class: `badge badge-${level}` }, level);
}

function statusText(r) {
  const needed = r.analysis.requiredApprovals;
  if (OPEN.includes(r.status) && needed > 1) {
    return `${r.status} (${r.approvals.length} of ${needed} approvals)`;
  }
  return r.status;
}

function loginView() {
  const input = h("input", { type: "password", placeholder: "Your access token", autocomplete: "off", "aria-label": "Access token" });
  const go = async () => {
    const token = input.value.trim();
    if (!token) {
      setMessage("Enter your access token.", "err");
      render();
      return;
    }
    try {
      await signIn(token);
      setMessage("");
    } catch (e) {
      clearSession();
      setMessage(e.status === 401 ? "That token isn't recognized." : e.message, "err");
    }
    render();
  };
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") go();
  });
  return h("div", { class: "panel narrow" },
    h("h2", { class: "panel-title" }, "Sign in"),
    h("p", { class: "muted" }, "Paste the access token your administrator gave you. It is kept only in this browser tab."),
    h("label", { class: "field" }, "Token", input),
    h("button", { class: "primary", onclick: go }, "Sign in"),
  );
}

function queueView() {
  if (state.requests.length === 0) {
    return h("div", { class: "panel narrow" },
      h("p", {}, "No requests yet."),
      h("button", {
        class: "primary",
        onclick: async () => {
          await api("/api/seed", { method: "POST" });
          await loadAll();
          render();
        },
      }, "Load simulated requests"),
    );
  }
  const selected = state.requests.find((r) => r.id === state.selectedId) || state.requests[0];
  return h("div", { class: "grid" },
    h("div", { class: "panel" },
      h("h2", { class: "panel-title" }, "Access queue (highest risk first)"),
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Request"), h("th", {}, "Score"), h("th", {}, "Risk"), h("th", {}, "Status"))),
        h("tbody", {}, state.requests.map((r) =>
          h("tr", {
            class: `row${r.id === selected.id ? " selected" : ""}`,
            onclick: () => {
              state.selectedId = r.id;
              render();
            },
          },
            h("td", {}, h("div", {}, `${r.id} · ${r.requester}`), h("div", { class: "muted" }, `${r.jobTitle}, ${r.employmentType}`)),
            h("td", {}, String(r.analysis.score)),
            h("td", {}, levelBadge(r.analysis.level)),
            h("td", {}, statusText(r)),
          )
        )),
      ),
    ),
    detailPanel(selected),
  );
}

function detailPanel(r) {
  const a = r.analysis;
  const needed = a.requiredApprovals;
  const panel = h("div", { class: "panel" });

  panel.append(
    h("h2", { class: "panel-title" }, `${r.id} · ${r.requester}`),
    h("div", { class: "muted" }, `${r.jobTitle} · ${r.employmentType} · ${r.durationDays == null ? "permanent" : r.durationDays + " days"} · approver: ${r.approver || "none"}`),
    h("p", {}, "Justification: ", h("em", {}, r.justification || "(none)")),
    h("p", {}, "Risk: ", levelBadge(a.level), ` score ${a.score}/100`),
  );

  if (OPEN.includes(r.status) || r.status === "approved") {
    panel.append(h("div", { class: "approvals" },
      h("strong", {}, needed > 1
        ? `Two different approvers required (${r.approvals.length} of ${needed} so far)`
        : "One approver required"),
      r.approvals.length
        ? h("div", { class: "muted" }, `Approved by: ${r.approvals.map((x) => x.reviewer).join(", ")}`)
        : null,
    ));
  }

  panel.append(
    h("h3", { class: "panel-title" }, "Explanation"),
    h("div", { class: "explain" }, a.explanation),
    h("h3", { class: "panel-title" }, "Findings"),
    a.findings.length === 0
      ? h("p", { class: "muted" }, "No findings.")
      : a.findings.map((f) =>
          h("div", { class: `finding${f.forceHigh ? " forced" : ""}` },
            h("span", { class: "w" }, `+${f.weight}`),
            h("strong", {}, f.title),
            h("div", {}, f.detail),
            h("div", { class: "muted" }, `To lower risk: ${f.fix}`),
          )
        ),
    h("h3", { class: "panel-title" }, "Least privilege check"),
    h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Requested role"), h("th", {}, "Usual for this job?"))),
      h("tbody", {}, r.requestedRoles.map((role) =>
        h("tr", {}, h("td", {}, role), h("td", {}, a.baselineRoles.includes(role) ? "Yes" : "No, review"))
      )),
    ),
  );

  if (!OPEN.includes(r.status)) {
    panel.append(h("p", { class: "muted" },
      `Final: ${r.status} by ${r.decidedBy} on ${new Date(r.decidedAt).toLocaleString()}${r.decisionNote ? ". Note: " + r.decisionNote : ""}`));
    return panel;
  }

  const note = h("textarea", { rows: "2", maxlength: "500", placeholder: "Note (saved to the audit log)" });
  const decide = (decision) => async () => {
    try {
      const res = await api(`/api/requests/${encodeURIComponent(r.id)}/decision`, { method: "POST", body: { decision, note: note.value } });
      if (res.status === "approved") {
        setMessage(
          res.againstRecommendation
            ? "Approved. This is a critical-risk request, so the approval is logged as against the recommendation."
            : "Approved.",
          res.againstRecommendation ? "err" : "ok",
        );
      } else if (decision === "approve") {
        setMessage(`Approval ${res.approvals} of ${res.required} recorded. A second, different reviewer is needed.`, "ok");
      } else {
        setMessage(`Request ${res.status}.`, "ok");
      }
    } catch (e) {
      if (e.status === 401) return signOut("Your session ended. Sign in again.");
      setMessage(e.message, "err");
    }
    await loadAll();
    render();
  };

  panel.append(
    h("label", { class: "field" }, "Note", note),
    h("p", { class: "muted" }, needed > 1
      ? "This risk level needs two different approvers. You can't review your own request."
      : "You can't review your own request."),
    h("div", { style: "display:flex;gap:8px;flex-wrap:wrap" },
      h("button", { class: "primary", onclick: decide("approve") }, "Approve"),
      h("button", { onclick: decide("escalate") }, "Escalate"),
      h("button", { class: "danger", onclick: decide("deny") }, "Deny"),
    ),
  );
  return panel;
}

function submitView() {
  const today = new Date().toISOString().slice(0, 10);
  const fields = {
    jobTitle: h("select", {}, Object.keys(state.policy.baseline).map((t) => h("option", { value: t }, t))),
    employmentType: h("select", {}, h("option", { value: "employee" }, "Employee"), h("option", { value: "contractor" }, "Contractor")),
    durationDays: h("input", { type: "number", min: "1", max: "365", placeholder: "Leave blank for permanent" }),
    lastLogin: h("input", { type: "date", max: today }),
    approver: h("input", { type: "text", maxlength: "40", placeholder: "Who approves this? (not you)" }),
    justification: h("textarea", { rows: "3", maxlength: "1000", placeholder: "The business reason and the task it supports" }),
  };
  const roleBoxes = Object.keys(state.policy.roles).map((role) => ({
    role,
    box: h("input", { type: "checkbox", value: role }),
  }));

  const submit = async () => {
    const body = {
      jobTitle: fields.jobTitle.value,
      employmentType: fields.employmentType.value,
      durationDays: fields.durationDays.value,
      lastLogin: fields.lastLogin.value || null,
      approver: fields.approver.value,
      justification: fields.justification.value,
      requestedRoles: roleBoxes.filter((b) => b.box.checked).map((b) => b.role),
    };
    try {
      const res = await api("/api/requests", { method: "POST", body });
      state.selectedId = res.id;
      state.view = "queue";
      await loadAll();
      setMessage(`Submitted as ${res.id}.`, "ok");
    } catch (e) {
      if (e.status === 401) return signOut("Your session ended. Sign in again.");
      setMessage(e.message, "err");
    }
    render();
  };

  return h("div", { class: "panel narrow" },
    h("h2", { class: "panel-title" }, "Submit an access request"),
    h("p", { class: "muted" }, `Requesting as ${state.me.name}. Use simulated details only.`),
    h("label", { class: "field" }, "Job title", fields.jobTitle),
    h("label", { class: "field" }, "Employment type", fields.employmentType),
    h("label", { class: "field" }, "Duration (days, 1-365)", fields.durationDays),
    h("label", { class: "field" }, "Last login", fields.lastLogin),
    h("label", { class: "field" }, "Approver", fields.approver),
    h("label", { class: "field" }, "Justification", fields.justification),
    h("div", { class: "field" }, "Roles requested",
      h("div", { class: "roles" }, roleBoxes.map((b) => h("label", {}, b.box, b.role))),
    ),
    h("button", { class: "primary", onclick: submit }, "Submit request"),
  );
}

async function auditView() {
  const entries = await api("/api/audit?limit=200");
  return h("div", { class: "panel" },
    h("h2", { class: "panel-title" }, "Audit history (newest first)"),
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
              h("td", {}, e.detail),
            )
          )),
        ),
  );
}

function policyView() {
  return h("div", {},
    h("div", { class: "panel" },
      h("h2", { class: "panel-title" }, "Usual access by job title (baseline)"),
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Job title"), h("th", {}, "Roles"))),
        h("tbody", {}, Object.entries(state.policy.baseline).map(([t, roles]) =>
          h("tr", {}, h("td", {}, t), h("td", {}, roles.join(", ")))
        )),
      ),
    ),
    h("div", { class: "panel" },
      h("h2", { class: "panel-title" }, "Risk levels"),
      h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Level"), h("th", {}, "From score"), h("th", {}, "Recommended action"))),
        h("tbody", {}, state.policy.levels.map((l) =>
          h("tr", {}, h("td", {}, levelBadge(l.level)), h("td", {}, String(l.min)), h("td", {}, l.action))
        )),
      ),
    ),
  );
}

function messageNode() {
  return state.message.text ? h("div", { class: `msg ${state.message.kind}` }, state.message.text) : "";
}

function footer() {
  return h("p", { class: "muted" }, "All people and requests here are simulated. Practice project; not for real access decisions.");
}

async function render() {
  if (!state.me) {
    app.replaceChildren(
      h("header", {}, h("h1", {}, "Access Risk Analyzer")),
      messageNode(),
      loginView(),
      footer(),
    );
    return;
  }

  const header = h("header", {},
    h("div", {}, h("h1", {}, "Access Risk Analyzer"), h("div", { class: "who" }, `Signed in as ${state.me.name}`)),
    h("nav", {},
      TABS.map(([id, label]) =>
        h("button", {
          class: state.view === id ? "active" : "",
          onclick: async () => {
            state.view = id;
            if (id === "queue") await loadAll();
            render();
          },
        }, label)
      ),
      h("button", { class: "ghost", onclick: () => signOut() }, "Sign out"),
    ),
  );

  let body;
  try {
    if (state.view === "queue") body = queueView();
    else if (state.view === "submit") body = submitView();
    else if (state.view === "audit") body = await auditView();
    else body = policyView();
  } catch (e) {
    if (e.status === 401) return signOut("Your session ended. Sign in again.");
    body = h("div", { class: "panel" }, e.message);
  }
  app.replaceChildren(header, messageNode(), body, footer());
}

async function start() {
  if (state.token) {
    try {
      await signIn(state.token);
    } catch {
      clearSession();
      setMessage("Sign in again.", "err");
    }
  }
  render();
}

start();
